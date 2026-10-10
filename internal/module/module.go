// Package module definiert das Modulsystem des Agents.
//
// Der Kern (Web-UI, Datenbank, Benachrichtigungen, Sync, Audit) laeuft immer.
// Alles andere sind Module mit einheitlichem Lebenszyklus: Ein deaktiviertes
// Modul ist nicht gestartet, hat keine Goroutines, keine Ports, keine
// Hintergrundjobs und keinen Menuepunkt. Nur seine Konfiguration in der
// Datenbank bleibt erhalten.
package module

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ipv64net/agent/internal/store"
)

// Info beschreibt ein Modul fuer Navigation und Einstellungen.
type Info struct {
	// Name ist der technische Schluessel (healthchecks, dyndns, ...).
	Name string
	// TitleKey ist der i18n-Schluessel des Menuetitels.
	TitleKey string
	// Icon ist eine Bootstrap-Icon-Klasse, z. B. "bi-heart-pulse".
	Icon string
	// Path ist der Einstiegspfad in der Oberflaeche.
	Path string
	// Available false = Platzhalter ("demnaechst"), kann nicht aktiviert werden.
	Available bool
	// Order bestimmt die Reihenfolge im Menue.
	Order int
}

// Module ist das Interface, das jedes Modul erfuellt.
type Module interface {
	Info() Info
	// Migrations liefert die Datenbankaenderungen des Moduls (eigener Scope).
	Migrations() []store.Migration
	// Routes registriert die HTTP-Handler. g.Enabled umhuellt jeden Handler und
	// antwortet mit 404, solange das Modul deaktiviert ist; g.Auth verlangt
	// eine Anmeldung (Sitzung oder API-Key).
	Routes(mux *http.ServeMux, g Guards)
	// Start startet Hintergrundarbeit; ctx wird bei Stop abgebrochen.
	Start(ctx context.Context) error
	// Stop beendet alles sauber. Nach Stop laufen keine Goroutines mehr.
	Stop(ctx context.Context) error
}

// Guards sind die Middleware-Funktionen, die der Kern den Modulen gibt.
type Guards struct {
	Enabled func(http.Handler) http.Handler
	Auth    func(http.Handler) http.Handler
}

// Status ist der Zustand eines Moduls fuer die Anzeige.
type Status struct {
	Info      Info
	Enabled   bool
	Running   bool
	StartedAt time.Time
	LastError string
}

var (
	ErrUnknown      = errors.New("unknown module")
	ErrNotAvailable = errors.New("module not available yet")
)

type entry struct {
	mod       Module
	cancel    context.CancelFunc
	running   bool
	startedAt time.Time
	lastErr   string
}

// Registry verwaltet Module, ihren Zustand und das Starten/Stoppen zur Laufzeit.
type Registry struct {
	mu      sync.Mutex
	st      *store.Store
	log     *slog.Logger
	entries map[string]*entry
	order   []string
	stopTO  time.Duration
}

func NewRegistry(st *store.Store, log *slog.Logger) *Registry {
	return &Registry{st: st, log: log.With("module", "core"), entries: map[string]*entry{}, stopTO: 10 * time.Second}
}

// Register meldet ein Modul an. Muss vor Routes und StartEnabled passieren.
func (r *Registry) Register(m Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := m.Info().Name
	if _, dup := r.entries[name]; dup {
		panic("module registered twice: " + name)
	}
	r.entries[name] = &entry{mod: m}
	r.order = append(r.order, name)
	sort.SliceStable(r.order, func(i, j int) bool {
		return r.entries[r.order[i]].mod.Info().Order < r.entries[r.order[j]].mod.Info().Order
	})
}

// Routes registriert die Handler aller Module. Der Guard liefert 404, solange
// ein Modul deaktiviert ist; so bleiben die Pfade stabil.
func (r *Registry) Routes(mux *http.ServeMux, notFound http.Handler, auth func(http.Handler) http.Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range r.order {
		e := r.entries[name]
		guard := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if !r.IsRunning(name) {
					notFound.ServeHTTP(w, req)
					return
				}
				next.ServeHTTP(w, req)
			})
		}
		e.mod.Routes(mux, Guards{Enabled: guard, Auth: auth})
	}
}

// IsRunning sagt, ob das Modul gerade laeuft.
func (r *Registry) IsRunning(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[name]
	return ok && e.running
}

// StartEnabled startet beim Programmstart alle in der DB aktivierten Module.
func (r *Registry) StartEnabled(ctx context.Context) {
	for _, name := range r.names() {
		enabled, err := r.st.ModuleEnabled(ctx, name)
		if err != nil {
			r.log.Error("module state could not be read", "name", name, "err", err)
			continue
		}
		if !enabled {
			continue
		}
		if err := r.start(ctx, name); err != nil {
			r.log.Error("module failed to start", "name", name, "err", err)
		}
	}
}

// Enable aktiviert ein Modul dauerhaft und startet es sofort.
func (r *Registry) Enable(ctx context.Context, name string) error {
	e, err := r.get(name)
	if err != nil {
		return err
	}
	if !e.mod.Info().Available {
		return ErrNotAvailable
	}
	if err := r.st.SetModuleEnabled(ctx, name, true); err != nil {
		return err
	}
	return r.start(ctx, name)
}

// Disable stoppt ein Modul und merkt sich den Zustand dauerhaft.
func (r *Registry) Disable(ctx context.Context, name string) error {
	if _, err := r.get(name); err != nil {
		return err
	}
	if err := r.st.SetModuleEnabled(ctx, name, false); err != nil {
		return err
	}
	return r.stop(name)
}

// StopAll stoppt alle laufenden Module (beim Herunterfahren).
func (r *Registry) StopAll() {
	for _, name := range r.names() {
		if err := r.stop(name); err != nil {
			r.log.Error("module failed to stop", "name", name, "err", err)
		}
	}
}

// List liefert alle Module in Menuereihenfolge mit Zustand.
func (r *Registry) List(ctx context.Context) []Status {
	var out []Status
	for _, name := range r.names() {
		r.mu.Lock()
		e := r.entries[name]
		s := Status{Info: e.mod.Info(), Running: e.running, StartedAt: e.startedAt, LastError: e.lastErr}
		r.mu.Unlock()
		s.Enabled, _ = r.st.ModuleEnabled(ctx, name)
		out = append(out, s)
	}
	return out
}

// Get liefert das Modul selbst (fuer Dashboard-Daten u. ae.).
func (r *Registry) Get(name string) (Module, bool) {
	e, err := r.get(name)
	if err != nil {
		return nil, false
	}
	return e.mod, true
}

func (r *Registry) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.order...)
}

func (r *Registry) get(name string) (*entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknown, name)
	}
	return e, nil
}

func (r *Registry) start(ctx context.Context, name string) error {
	e, err := r.get(name)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if e.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	// Migrationen des Moduls erst beim ersten Aktivieren anwenden
	if err := r.st.Migrate(ctx, name, e.mod.Migrations()); err != nil {
		r.setErr(e, err)
		return fmt.Errorf("migrate %s: %w", name, err)
	}
	mctx, cancel := context.WithCancel(context.Background())
	if err := e.mod.Start(mctx); err != nil {
		cancel()
		r.setErr(e, err)
		return fmt.Errorf("start %s: %w", name, err)
	}
	r.mu.Lock()
	e.cancel = cancel
	e.running = true
	e.startedAt = time.Now()
	e.lastErr = ""
	r.mu.Unlock()
	r.log.Info("module started", "name", name)
	return nil
}

func (r *Registry) stop(name string) error {
	e, err := r.get(name)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if !e.running {
		r.mu.Unlock()
		return nil
	}
	e.running = false
	cancel := e.cancel
	e.cancel = nil
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	ctx, done := context.WithTimeout(context.Background(), r.stopTO)
	defer done()
	err = e.mod.Stop(ctx)
	if err != nil {
		r.setErr(e, err)
		return fmt.Errorf("stop %s: %w", name, err)
	}
	r.log.Info("module stopped", "name", name)
	return nil
}

func (r *Registry) setErr(e *entry, err error) {
	r.mu.Lock()
	e.lastErr = err.Error()
	r.mu.Unlock()
}

// Placeholder ist ein noch nicht verfuegbares Modul, das nur im Menue als
// "demnaechst" erscheint.
type Placeholder struct{ I Info }

func (p Placeholder) Info() Info                  { i := p.I; i.Available = false; return i }
func (Placeholder) Migrations() []store.Migration { return nil }
func (Placeholder) Routes(*http.ServeMux, Guards) {}
func (Placeholder) Start(context.Context) error   { return ErrNotAvailable }
func (Placeholder) Stop(context.Context) error    { return nil }

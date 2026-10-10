// Package healthchecks ist das Modul Health-Checks: Datenhaltung, Scheduler-
// Anbindung, lokale JSON-API und (ab Phase 3) die Oberflaeche.
package healthchecks

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ipv64net/agent/internal/checks"
	"github.com/ipv64net/agent/internal/module"
	"github.com/ipv64net/agent/internal/scheduler"
	"github.com/ipv64net/agent/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const Name = "healthchecks"

// Module implementiert module.Module.
type Module struct {
	core     *store.Store
	st       *Store
	log      *slog.Logger
	notifier scheduler.Notifier
	version  string

	g module.Guards

	mu     sync.Mutex
	sched  *scheduler.Scheduler
	cancel context.CancelFunc
	wg     sync.WaitGroup
	push   *pushLimiter
}

// New erzeugt das Modul. notifier darf nil sein (dann nur Log).
func New(core *store.Store, log *slog.Logger, notifier scheduler.Notifier, version string) *Module {
	m := &Module{core: core, st: NewStore(core), log: log.With("module", Name), notifier: notifier, version: version, push: newPushLimiter()}
	if notifier == nil {
		m.notifier = logNotifier{log: m.log}
	}
	return m
}

// Store gibt die Datenhaltung frei (Dashboard, Tests).
func (m *Module) Store() *Store { return m.st }

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.healthchecks", Icon: "bi-heart-pulse", Path: "/healthchecks", Available: true, Order: 10}
}

func (m *Module) Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Start laedt alle Checks in den Scheduler und startet Verdichtung.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, m.cancel = context.WithCancel(ctx)
	m.st.reloadMaintenance(ctx)
	runner := checks.NewRunner()
	m.sched = scheduler.New(m.st, m.notifier, runner, m.log, scheduler.Options{})
	list, err := m.st.Checks(ctx)
	if err != nil {
		return err
	}
	for _, c := range list {
		rt := c.Runtime
		m.sched.Upsert(c.SchedulerCheck(), &rt)
	}
	m.sched.Start(ctx)
	m.wg.Add(1)
	go m.housekeeping(ctx)
	m.log.Info("health checks loaded", "count", len(list))
	return nil
}

// Stop haelt Scheduler und Hintergrundjobs an.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel, sched := m.cancel, m.sched
	m.cancel, m.sched = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sched != nil {
		sched.Stop()
	}
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (m *Module) scheduler() *scheduler.Scheduler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sched
}

// housekeeping verdichtet stuendlich und laedt Wartungsfenster neu.
func (m *Module) housekeeping(ctx context.Context) {
	defer m.wg.Done()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	m.aggregate(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.aggregate(ctx)
			m.st.reloadMaintenance(ctx)
		}
	}
}

func (m *Module) aggregate(ctx context.Context) {
	start := time.Now()
	if err := m.st.Aggregate(ctx, time.Now()); err != nil {
		m.log.Error("aggregation failed", "err", err)
		return
	}
	m.log.Debug("aggregation done", "took_ms", time.Since(start).Milliseconds())
}

// Routes registriert API und Seiten. Die Push-URL ist oeffentlich.
func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/checks", api(m.apiList))
	mux.Handle("POST /api/checks", api(m.apiCreate))
	mux.Handle("GET /api/checks/{token}", api(m.apiGet))
	mux.Handle("PUT /api/checks/{token}", api(m.apiUpdate))
	mux.Handle("DELETE /api/checks/{token}", api(m.apiDelete))
	mux.Handle("POST /api/checks/{token}/pause", api(m.apiPause))
	mux.Handle("POST /api/checks/{token}/resume", api(m.apiResume))
	mux.Handle("POST /api/checks/{token}/run", api(m.apiRun))
	mux.Handle("POST /api/checks/{token}/clone", api(m.apiClone))
	mux.Handle("GET /api/checks/{token}/measurements", api(m.apiMeasurements))
	mux.Handle("GET /api/checks/{token}/events", api(m.apiEvents))
	mux.Handle("GET /api/checks/{token}/incidents", api(m.apiIncidents))
	mux.Handle("GET /api/checks/{token}/stats", api(m.apiStats))
	mux.Handle("GET /api/events", api(m.apiAllEvents))
	mux.Handle("GET /api/incidents", api(m.apiAllIncidents))
	mux.Handle("GET /api/maintenance", api(m.apiMaintenanceList))
	mux.Handle("POST /api/maintenance", api(m.apiMaintenanceCreate))
	mux.Handle("PUT /api/maintenance/{id}", api(m.apiMaintenanceUpdate))
	mux.Handle("DELETE /api/maintenance/{id}", api(m.apiMaintenanceDelete))
	mux.Handle("GET /api/check-types", api(m.apiTypes))
	// Heartbeat: ohne Anmeldung, Antwort verraet nichts ueber den Token
	mux.Handle("GET /api/push/{token}", g.Enabled(http.HandlerFunc(m.apiPush)))
	mux.Handle("POST /api/push/{token}", g.Enabled(http.HandlerFunc(m.apiPush)))
	m.uiRoutes(mux, g)
}

// logNotifier schreibt Ereignisse nur ins Log (bis Phase 4).
type logNotifier struct{ log *slog.Logger }

func (n logNotifier) Notify(_ context.Context, e scheduler.Event, c scheduler.Check) {
	if e.Silent {
		return
	}
	n.log.Info("notification", "check", c.Name, "token", c.Token, "kind", e.Kind, "reason", e.Reason, "message", e.Message, "event_id", e.ID)
}

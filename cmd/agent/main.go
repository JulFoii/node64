// ipv64 Agent: ein Binary mit Weboberflaeche, SQLite und Modulen.
//
// Befehle:
//
//	agent              startet den Agent
//	agent healthcheck  prueft die lokale UI (fuer Docker HEALTHCHECK), Exit 0 = gesund
//	agent version      zeigt die Version
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // Zeitzonen im Binary, das Laufzeit-Image hat keine

	"github.com/ipv64net/agent/internal/config"
	"github.com/ipv64net/agent/internal/i18n"
	"github.com/ipv64net/agent/internal/logging"
	"github.com/ipv64net/agent/internal/module"
	"github.com/ipv64net/agent/internal/store"
	agentsync "github.com/ipv64net/agent/internal/sync"
	"github.com/ipv64net/agent/internal/web"
)

// Version wird beim Build gesetzt: -ldflags "-X main.Version=1.2.3"
var Version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("ipv64 agent", Version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := logging.New(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	defer logger.Close()
	log := logger.Slog().With("module", "core")
	logger.OnChange(func() { log.Info("log level changed", "level", logging.LevelName(logger.Level())) })
	log.Info("ipv64 agent starting", "version", Version, "data", cfg.DataDir)

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data dir %s: %w", cfg.DataDir, err)
	}
	if err := ensureSecretKey(cfg.SecretKeyPath()); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath(), cfg.BackupDir(), logger.Slog())
	if err != nil {
		return err
	}
	defer st.Close()
	core, err := store.CoreMigrations()
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx, "core", core); err != nil {
		return err
	}
	if err := firstAdminFromEnv(ctx, cfg, st, log); err != nil {
		return err
	}

	bundle, err := i18n.Load()
	if err != nil {
		return err
	}

	modules := module.NewRegistry(st, logger.Slog())
	registerModules(modules)
	modules.StartEnabled(ctx)
	defer modules.StopAll()

	srv, err := web.New(web.Deps{
		Cfg: cfg, Store: st, Log: logger, I18n: bundle, Modules: modules,
		Sync: agentsync.NoOp{}, Version: Version, StartedAt: time.Now(),
	})
	if err != nil {
		return err
	}
	err = srv.Run(ctx)
	log.Info("ipv64 agent stopped")
	return err
}

// registerModules meldet alle Module an. Im ersten Entwurf sind alle ausser
// Health-Checks Platzhalter; Health-Checks folgt in Phase 2.
func registerModules(r *module.Registry) {
	r.Register(module.Placeholder{I: module.Info{Name: "healthchecks", TitleKey: "nav.healthchecks", Icon: "bi-heart-pulse", Path: "/healthchecks", Order: 10}})
	r.Register(module.Placeholder{I: module.Info{Name: "dyndns", TitleKey: "nav.dyndns", Icon: "bi-globe", Path: "/dyndns", Order: 20}})
	r.Register(module.Placeholder{I: module.Info{Name: "proxy", TitleKey: "nav.proxy", Icon: "bi-diagram-3", Path: "/proxy", Order: 30}})
	r.Register(module.Placeholder{I: module.Info{Name: "link", TitleKey: "nav.link", Icon: "bi-cloud", Path: "/link", Order: 90}})
}

// ensureSecretKey erzeugt beim ersten Start den Schluessel, mit dem spaeter
// Geheimnisse (Kanal-Tokens, SMTP-Passwoerter) in der Datenbank verschluesselt
// werden. Er bleibt nur unter /data.
func ensureSecretKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, key, 0o600)
}

// firstAdminFromEnv legt den Administrator aus AGENT_ADMIN_USER/PASSWORD an,
// aber nur, solange noch kein Benutzer existiert.
func firstAdminFromEnv(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) error {
	if cfg.AdminUser == "" {
		return nil
	}
	n, err := st.UserCount(ctx)
	if err != nil || n > 0 {
		return err
	}
	hash, err := web.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, cfg.AdminUser, hash, "", "UTC"); err != nil {
		return fmt.Errorf("create admin from environment: %w", err)
	}
	host, _ := os.Hostname()
	_ = st.SetSetting(ctx, web.SettingAgentName, host)
	_ = st.Audit(ctx, store.AuditEntry{Actor: cfg.AdminUser, Action: "setup", Details: "admin created from environment"})
	log.Info("admin user created from environment", "user", cfg.AdminUser)
	return nil
}

// healthcheck ruft /api/health der eigenen Oberflaeche auf (Docker HEALTHCHECK).
func healthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/health", cfg.HTTPPort)
	client := &http.Client{Timeout: 4 * time.Second}
	if cfg.HTTPPort == 0 {
		url = fmt.Sprintf("https://127.0.0.1:%d/api/health", cfg.HTTPSPort)
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // eigenes selbstsigniertes Zertifikat
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: status", resp.StatusCode)
		return 1
	}
	fmt.Println("healthy")
	return 0
}

package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLevelsAndModules(t *testing.T) {
	var out bytes.Buffer
	l := New("info", "text", &out)
	log := l.Slog()
	log.Debug("hidden")
	log.Info("shown")
	if strings.Contains(out.String(), "hidden") || !strings.Contains(out.String(), "shown") {
		t.Fatalf("level filter: %s", out.String())
	}
	// Modul-Level: nur das Modul "web" auf Debug
	lvl := slog.LevelDebug
	l.SetModuleLevel("web", &lvl)
	log.With("module", "web").Debug("web-debug")
	log.With("module", "store").Debug("store-debug")
	log.Debug("core-debug", "module", "web")
	s := out.String()
	if !strings.Contains(s, "web-debug") || strings.Contains(s, "store-debug") || !strings.Contains(s, "core-debug") {
		t.Fatalf("module level: %s", s)
	}
	// Globales Debug mit automatischem Reset
	l.SetLevel(slog.LevelDebug, 50*time.Millisecond)
	if l.ResetAt().IsZero() {
		t.Fatal("reset time expected")
	}
	time.Sleep(120 * time.Millisecond)
	if l.Level() != slog.LevelInfo {
		t.Fatalf("level should have reset to info, got %v", l.Level())
	}
}

func TestSecretsAreMasked(t *testing.T) {
	var out bytes.Buffer
	l := New("debug", "text", &out)
	l.Slog().Info("login", "user", "bob", "password", "hunter2", "api_token", "abc", "Authorization", "Bearer x")
	s := out.String()
	if strings.Contains(s, "hunter2") || strings.Contains(s, "abc") || strings.Contains(s, "Bearer") {
		t.Fatalf("secret leaked: %s", s)
	}
	if !strings.Contains(s, "bob") || !strings.Contains(s, Masked) {
		t.Fatalf("unexpected output: %s", s)
	}
}

func TestRing(t *testing.T) {
	r := NewRing(3)
	for _, s := range []string{"a\n", "b\nc\n", "d\n"} {
		r.Write([]byte(s))
	}
	got := r.Last(0)
	if strings.Join(got, ",") != "b,c,d" {
		t.Fatalf("ring: %v", got)
	}
	if got := r.Last(2); strings.Join(got, ",") != "c,d" {
		t.Fatalf("ring last 2: %v", got)
	}
	l := New("info", "json", &bytes.Buffer{})
	l.Slog().Info("x")
	if lines := l.Lines(10); len(lines) != 1 || !strings.Contains(lines[0], `"msg":"x"`) {
		t.Fatalf("ring via logger: %v", lines)
	}
}

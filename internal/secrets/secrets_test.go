package secrets

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	b, err := Load(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	enc := b.Encrypt("hunter2")
	if !strings.HasPrefix(enc, "enc:v1:") || strings.Contains(enc, "hunter2") {
		t.Fatalf("not encrypted: %s", enc)
	}
	if enc2 := b.Encrypt("hunter2"); enc2 == enc {
		t.Fatal("nonce must differ")
	}
	got, err := b.Decrypt(enc)
	if err != nil || got != "hunter2" {
		t.Fatalf("decrypt: %q %v", got, err)
	}
	if got, _ := b.Decrypt("plain"); got != "plain" {
		t.Fatal("plaintext must pass through")
	}
	if b.Encrypt("") != "" {
		t.Fatal("empty stays empty")
	}
	// Gleicher Schluessel aus Datei: weiterhin lesbar
	b2, err := Load(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := b2.Decrypt(enc); got != "hunter2" {
		t.Fatal("reloaded key must decrypt")
	}
	// Anderer Schluessel: Fehler statt Muell
	b3, _ := Load(filepath.Join(t.TempDir(), "secret.key"))
	if _, err := b3.Decrypt(enc); err == nil {
		t.Fatal("wrong key must fail")
	}
	if Mask("abcdefgh") != "••••efgh" || Mask("ab") != "••••" || Mask("") != "" {
		t.Fatal("mask")
	}
}

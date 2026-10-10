// Package secrets verschluesselt Geheimnisse (Kanal-Tokens, SMTP-Passwoerter)
// fuer die Datenbank mit AES-256-GCM. Der Schluessel liegt nur unter
// /data/secret.key und wird beim ersten Start erzeugt.
//
// Verschluesselte Werte haben das Praefix "enc:v1:" und sind damit von
// Klartext unterscheidbar; Decrypt gibt Klartext unveraendert zurueck.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const prefix = "enc:v1:"

var ErrKeyLength = errors.New("secret key must have 32 bytes")

// Box ver- und entschluesselt mit einem festen Schluessel.
type Box struct{ aead cipher.AEAD }

// New erzeugt eine Box aus einem 32-Byte-Schluessel.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Load liest den Schluessel aus der Datei oder legt ihn an.
func Load(path string) (*Box, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s: %w", path, ErrKeyLength)
	}
	return New(key)
}

// Encrypt liefert "enc:v1:<base64>"; leere Werte bleiben leer.
func (b *Box) Encrypt(plain string) string {
	if plain == "" || b == nil {
		return plain
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := b.aead.Seal(nil, nonce, []byte(plain), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(append(nonce, ct...))
}

// Decrypt entschluesselt; Klartext ohne Praefix kommt unveraendert zurueck.
func (b *Box) Decrypt(value string) (string, error) {
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	if b == nil {
		return "", errors.New("no secret key loaded")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", errors.New("decryption failed (wrong secret.key?)")
	}
	return string(plain), nil
}

// IsEncrypted sagt, ob ein Wert verschluesselt gespeichert ist.
func IsEncrypted(value string) bool { return strings.HasPrefix(value, prefix) }

// Mask zeigt nur die letzten Zeichen eines Geheimnisses.
func Mask(plain string) string {
	if plain == "" {
		return ""
	}
	if len(plain) <= 4 {
		return "••••"
	}
	return "••••" + plain[len(plain)-4:]
}

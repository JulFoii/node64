package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// ---------------------------------------------------------------- Passwoerter (argon2id)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword erzeugt einen argon2id-Hash im ueblichen PHC-Format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword prueft ein Passwort gegen einen Hash aus HashPassword.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var errWeakPassword = errors.New("weak password")

// checkPassword prueft die Mindestanforderung: 10 Zeichen.
func checkPassword(pw string) error {
	if len(pw) < 10 {
		return errWeakPassword
	}
	return nil
}

// ---------------------------------------------------------------- Login-Ratelimit

// loginLimiter begrenzt Fehlversuche je IP und je Benutzername: ein Token-
// Bucket mit 5 Versuchen, der sich alle 30 Sekunden um einen Versuch fuellt.
type loginLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	loginBurst  = 5.0
	loginRefill = 1.0 / 30.0 // Tokens pro Sekunde
)

func newLoginLimiter() *loginLimiter { return &loginLimiter{buckets: map[string]*bucket{}} }

// retryAfter liefert 0, wenn ein Versuch erlaubt ist, sonst die Wartezeit.
func (l *loginLimiter) retryAfter(keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		b := l.get(k, now)
		if b.tokens < 1 {
			w := time.Duration((1 - b.tokens) / loginRefill * float64(time.Second))
			if w > wait {
				wait = w
			}
		}
	}
	return wait
}

// fail verbraucht nach einem Fehlversuch je einen Token.
func (l *loginLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		b := l.get(k, now)
		if b.tokens >= 1 {
			b.tokens--
		}
	}
}

func (l *loginLimiter) get(k string, now time.Time) *bucket {
	b, ok := l.buckets[k]
	if !ok {
		b = &bucket{tokens: loginBurst, last: now}
		l.buckets[k] = b
		return b
	}
	b.tokens += now.Sub(b.last).Seconds() * loginRefill
	if b.tokens > loginBurst {
		b.tokens = loginBurst
	}
	b.last = now
	return b
}

func (l *loginLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if time.Since(b.last) > time.Hour {
			delete(l.buckets, k)
		}
	}
}

package web

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected format: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") || VerifyPassword("", "") {
		t.Fatal("invalid password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt must differ")
	}
}

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < 5; i++ {
		if l.retryAfter("ip:1") != 0 {
			t.Fatalf("attempt %d should be allowed", i)
		}
		l.fail("ip:1")
	}
	wait := l.retryAfter("ip:1")
	if wait <= 0 || wait > 31*time.Second {
		t.Fatalf("expected wait of up to 30s, got %v", wait)
	}
	if l.retryAfter("ip:2") != 0 {
		t.Fatal("other key must not be affected")
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{"": "/", "/settings": "/settings", "//evil.com": "/", "https://evil.com": "/", "/a\r\nb": "/"}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

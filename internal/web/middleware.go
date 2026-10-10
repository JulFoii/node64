package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ipv64net/agent/internal/store"
)

const (
	sessionCookie = "agent_session"
	csrfCookie    = "agent_csrf"
	flashCookie   = "agent_flash"
	themeCookie   = "agent_theme"
	langCookie    = "agent_lang"

	sessionIdle = 12 * time.Hour
	sessionMax  = 7 * 24 * time.Hour
)

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
	ctxCSRF
)

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", "err", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				s.errorPage(w, r, http.StatusInternalServerError, "errors.internal")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

// session laedt Sitzung und Benutzer, stellt den CSRF-Token bereit und prueft
// ihn bei allen aendernden Anfragen.
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var sess *store.Session
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			sess, _ = s.Store.SessionByID(ctx, c.Value)
			if sess != nil && time.Since(sess.CreatedAt) > sessionMax {
				_ = s.Store.DeleteSession(ctx, sess.ID)
				sess = nil
			}
		}
		if sess != nil {
			u, err := s.Store.UserByID(ctx, sess.UserID)
			if err != nil || u == nil {
				sess = nil
			} else {
				ctx = context.WithValue(ctx, ctxSession, sess)
				ctx = context.WithValue(ctx, ctxUser, u)
				if time.Since(sess.LastSeenAt) > 5*time.Minute {
					_ = s.Store.TouchSession(ctx, sess.ID, time.Now().Add(sessionIdle))
				}
			}
		}
		if sess == nil {
			if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
				s.clearCookie(w, r, sessionCookie)
			}
		}

		// CSRF: Double-Submit-Cookie, bei Sitzung zusaetzlich an die Sitzung gebunden
		csrf := ""
		if sess != nil {
			csrf = sess.CSRF
		} else if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
			csrf = c.Value
		}
		if csrf == "" {
			csrf = randomToken(32)
		}
		if c, err := r.Cookie(csrfCookie); err != nil || c.Value != csrf {
			s.setCookie(w, r, csrfCookie, csrf, 0)
		}
		ctx = context.WithValue(ctx, ctxCSRF, csrf)
		r = r.WithContext(ctx)

		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("Authorization") != "" {
				break // API-Key-Auth (spaetere Phase) braucht kein CSRF
			}
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("_csrf")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(csrf)) != 1 {
				s.log.Warn("csrf check failed", "path", r.URL.Path, "ip", s.clientIP(r))
				s.errorPage(w, r, http.StatusForbidden, "errors.csrf")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// auth verlangt eine Sitzung; sonst Weiterleitung zu Login oder Setup.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r) == nil {
			if n, _ := s.Store.UserCount(r.Context()); n == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	})
}

func currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func currentSession(r *http.Request) *store.Session {
	s, _ := r.Context().Value(ctxSession).(*store.Session)
	return s
}

func csrfToken(r *http.Request) string {
	t, _ := r.Context().Value(ctxCSRF).(string)
	return t
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// clientIP liefert die Adresse des Aufrufers; X-Forwarded-For nur, wenn
// AGENT_TRUST_PROXY gesetzt ist.
func (s *Server) clientIP(r *http.Request) string {
	if s.Cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// startSession legt nach erfolgreichem Login eine neue Sitzung an.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	now := time.Now()
	sess := &store.Session{
		ID: randomToken(32), UserID: userID, CSRF: randomToken(32),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(sessionIdle),
		IP: s.clientIP(r), UserAgent: truncate(r.UserAgent(), 200),
	}
	if err := s.Store.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	s.setCookie(w, r, sessionCookie, sess.ID, int(sessionMax.Seconds()))
	s.setCookie(w, r, csrfCookie, sess.CSRF, 0)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

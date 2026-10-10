package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// TCPParams gelten fuer die Typen tcp und port.
type TCPParams struct {
	Port int `json:"port,omitempty"` // alternativ host:port im Ziel
	// tcp: optional etwas senden und eine Antwort (Teilstring) erwarten
	Send   string `json:"send,omitempty"`
	Expect string `json:"expect,omitempty"`
	TLS    bool   `json:"tls,omitempty"` // tcp: TLS-Handshake nach dem Verbinden
	// port: "open" (Standard) oder "closed"
	// Bei port steht der erwartete Zustand ebenfalls in Expect.
}

type tcpChecker struct{}

func (tcpChecker) Type() Type { return TypeTCP }

func (tcpChecker) Check(ctx context.Context, def Definition, ip net.IP) Result {
	var p TCPParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	port, err := portOf(def, p.Port)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	details := map[string]any{"port": port}
	start := time.Now()
	conn, err := dialIP(ctx, ip, port, def.Timeouts.Connect)
	lat := time.Since(start)
	if err != nil {
		if isTimeout(err) {
			return fail(ReasonTimeout, "connect timeout", lat, details)
		}
		return fail(ReasonConnectFailed, shortErr(err), lat, details)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	var rw io.ReadWriter = conn
	if p.TLS {
		host := TargetHost(def)
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // nur Erreichbarkeit, Zertifikat prueft der cert-Check
		if err := tc.HandshakeContext(ctx); err != nil {
			return fail(ReasonTLSFailed, shortErr(err), time.Since(start), details)
		}
		rw = tc
	}
	if p.Send != "" {
		if _, err := io.WriteString(rw, unescape(p.Send)); err != nil {
			return fail(ReasonConnectFailed, "send: "+shortErr(err), time.Since(start), details)
		}
	}
	if p.Expect != "" {
		buf := make([]byte, 4096)
		r := bufio.NewReader(rw)
		var got strings.Builder
		for got.Len() < 64<<10 {
			n, err := r.Read(buf)
			got.Write(buf[:n])
			if strings.Contains(got.String(), p.Expect) {
				break
			}
			if err != nil {
				break
			}
		}
		banner := strings.TrimSpace(got.String())
		if len(banner) > 200 {
			banner = banner[:200]
		}
		details["banner"] = banner
		lat = time.Since(start)
		if !strings.Contains(got.String(), p.Expect) {
			return fail(ReasonBannerMismatch, fmt.Sprintf("expected %q in response", p.Expect), lat, details)
		}
	}
	return ok(fmt.Sprintf("port %d open", port), lat, details)
}

// unescape erlaubt \r \n \t in Send-Strings.
func unescape(s string) string {
	return strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(s)
}

type portChecker struct{}

func (portChecker) Type() Type { return TypePort }

func (portChecker) Check(ctx context.Context, def Definition, ip net.IP) Result {
	var p TCPParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	port, err := portOf(def, p.Port)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	expectOpen := p.Expect != "closed"
	details := map[string]any{"port": port, "expect": map[bool]string{true: "open", false: "closed"}[expectOpen]}
	start := time.Now()
	conn, err := dialIP(ctx, ip, port, def.Timeouts.Connect)
	lat := time.Since(start)
	state := "open"
	if err != nil {
		switch {
		case isRefused(err):
			state = "closed"
		case isTimeout(err):
			state = "filtered"
		default:
			state = "unreachable"
		}
	} else {
		conn.Close()
	}
	details["state"] = state
	if expectOpen {
		if state == "open" {
			return ok(fmt.Sprintf("port %d open", port), lat, details)
		}
		return fail(ReasonPortClosed, fmt.Sprintf("port %d %s", port, state), lat, details)
	}
	if state == "open" {
		return fail(ReasonPortOpen, fmt.Sprintf("port %d is open but expected closed", port), lat, details)
	}
	return ok(fmt.Sprintf("port %d %s", port, state), lat, details)
}

// isRefused erkennt eine abgelehnte Verbindung auf allen Plattformen, auch
// bei lokalisierten Windows-Fehlertexten (WSAECONNREFUSED = 10061).
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && uintptr(errno) == 10061 {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

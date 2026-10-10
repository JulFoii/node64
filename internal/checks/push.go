package checks

import "encoding/json"

// PushParams gelten fuer den Typ push (Heartbeat). Der Dienst meldet sich
// selbst per URL; bleibt die Meldung laenger als Periode plus Kulanz aus,
// gilt der Check als down. Die Bewertung macht der Scheduler per Watchdog.
type PushParams struct {
	PeriodSeconds int  `json:"period_seconds,omitempty"` // erwarteter Abstand, Standard 3600
	GraceSeconds  *int `json:"grace_seconds,omitempty"`  // Kulanz, Standard 600; 0 = keine
}

const (
	DefaultPushPeriod = 3600
	DefaultPushGrace  = 600
)

// PushWindow liefert Periode und Kulanz in Sekunden mit Standardwerten.
func PushWindow(params json.RawMessage) (period, grace int) {
	var p PushParams
	_ = decode(params, &p)
	period = p.PeriodSeconds
	if period <= 0 {
		period = DefaultPushPeriod
	}
	grace = DefaultPushGrace
	if p.GraceSeconds != nil && *p.GraceSeconds >= 0 {
		grace = *p.GraceSeconds
	}
	return period, grace
}

func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

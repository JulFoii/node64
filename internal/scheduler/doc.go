// Package scheduler fuehrt Checks nach Intervall aus: Ticker mit Jitter,
// begrenzter Worker-Pool, Retry und der Zustandsautomat je Check
// (up, down, stabilisierend, flatternd). Umsetzung folgt in Phase 2.
package scheduler

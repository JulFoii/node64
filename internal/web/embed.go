package web

import "embed"

// Alle Assets und Templates liegen im Binary. Nichts wird von aussen geladen,
// die Oberflaeche funktioniert komplett offline.

//go:embed static
var staticFS embed.FS

//go:embed templates
var templateFS embed.FS

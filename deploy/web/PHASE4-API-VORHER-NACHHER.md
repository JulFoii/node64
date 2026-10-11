# Phase 4 – API v2 für Healthchecks 2.0

Neue Datei `api_v2_hc2.php` (ins Hauptverzeichnis neben `api_v2.php`). Sie hängt die Pfade `/hc2/...` an die bestehende API v2.
`api_v2.php` bekommt **eine** neue Zeile, direkt vor dem Start-Block am Dateiende.

## api_v2.php – Vorher
```php
// ===================================================================
//  Start
// ===================================================================
try {
	dispatch();
```

## api_v2.php – Nachher
```php
// ===================================================================
//  Start
// ===================================================================
require __DIR__ . '/api_v2_hc2.php';   // Healthchecks 2.0: Pfade /hc2/...
try {
	dispatch();
```

Außerdem: `api_v2_openapi.json` durch die neue Version ersetzen (enthält die alten Pfade unverändert plus `/hc2/...`).
Voraussetzung: `healthchecks2/hc2_lib.php` liegt bereits (Phase 4 Seiten).

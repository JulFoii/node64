# Honeypot64 – Phase H2 einspielen (ipv64.net)

Annahme der Meldungen der Honeypot64-Sensoren (Node64, alle 10 Minuten), Tabellen `hp_*` und eine schlanke Seite
„Honeypot64 – deine Sensoren“. Vertrag (Format `schema: 1`, Antwortcodes, Grenzen):
`internal/honeypot/report_types.go`; Planung: `docs/PLAN-NODE64-HONEYPOT64.md` (Abschnitte 4, 5, 10, 13).

Getestet in einer abgeschotteten Testumgebung auf der Testbox (MariaDB 10.5, PHP 8.3, echte `api_v2.php` mit dieser
Datei, Builtin-Server, Verbindung wie live mit `SET NAMES 'utf8'`): 85 Prüfungen, alle grün
(`deploy/web/honeypot/tests/run_agentbox.sh`).

## 1. SQL einspielen (Hauptdatenbank ipv64)

Datei `deploy/sql/honeypot.sql` – mehrfach ausführbar (`IF NOT EXISTS`), ändert keine bestehende Tabelle.
Legt an: `hp_sensors`, `hp_reports`, `hp_report_sources`, `hp_sources_archive`, `hp_archive_days`, `hp_daily`,
`hp_samples_creds`, `hp_samples_paths`, `hp_samples_uas`, `hp_samples_payloads`.

```bash
mysql ipv64 < honeypot.sql
```

## 2. Dateien hochladen

| Datei im Repo | Ziel im Webroot |
|---|---|
| `deploy/web/api_v2_honeypot.php` | neben `api_v2.php` |
| `deploy/web/honeypot/index.php` | `honeypot/index.php` (neuer Ordner) |
| `deploy/web/bots/honeypot_cleanup.php` | `bots/honeypot_cleanup.php` |
| `deploy/web/api_v2_openapi.json` | ersetzt die bisherige (nur drei Pfade, ein Tag und Schemas `Honeypot*` dazu, Rest unverändert) |

**Nicht hochladen:** `deploy/web/honeypot/tests/` (Test-Stubs und Testskripte, nur für die lokale Prüfung).

## 3. `api_v2.php`: Datei einbinden

VORHER (am Ende der Datei):

```php
// ===================================================================
//  Start
// ===================================================================
try {
	dispatch();
```

NACHHER (Zeile vor dem Start-Block; stehen dort schon `api_v2_hc2.php`/`api_v2_cdn64o.php`, direkt darunter):

```php
require __DIR__ . '/api_v2_honeypot.php';

// ===================================================================
//  Start
// ===================================================================
try {
	dispatch();
```

## 4. Cron für die Fristen

Einmal täglich (Uhrzeit egal, z. B. nachts):

```
40 3 * * * php /var/www/clients/client1/web58/web/bots/honeypot_cleanup.php > /dev/null 2>&1
```

`php honeypot_cleanup.php --dry` zeigt nur an, was passieren würde.

## 5. Prüfen

Auf einem Rechner mit PHP (Repo-Ordner), Beispiel-Meldung auf die aktuelle Zeit schieben und mit neuer Sensor-ID
schicken (`sample_report.json` hat feste Zeiten von 2026-10-20; ältere als 7 Tage nimmt die API nicht an):

```bash
php deploy/web/honeypot/tests/fresh_report.php --new-sensor > /tmp/hp_report.json
curl -s -X POST -H "Authorization: Bearer <API-Key>" -H "Content-Type: application/json" \
  --data-binary @/tmp/hp_report.json https://ipv64.net/api/v2/honeypot/reports
```

Erwartet `202` mit `{"data":{"accepted":3,"rejected":1,"rejected_reasons":{"not_public":1},"report_id":"…"}}`
(192.0.2.10 ist ein Dokumentationsnetz und wird verworfen).

Dieselbe Meldung gepackt noch einmal – beweist gzip und die Erkennung doppelter Meldungen:

```bash
gzip -c /tmp/hp_report.json | curl -s -X POST -H "Authorization: Bearer <API-Key>" -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" --data-binary @- https://ipv64.net/api/v2/honeypot/reports
```

Erwartet `200` mit `{"data":{"duplicate":true,"report_id":"…"}}`.

```bash
curl -s -H "Authorization: Bearer <API-Key>" https://ipv64.net/api/v2/honeypot/sensors
curl -s -H "Authorization: Bearer <API-Key>" https://ipv64.net/api/v2/honeypot/stats
```

Erwartet: der Test-Sensor `online: true`, `sources_24h: 2`; in `stats` `top_kinds` mit `ssh:bruteforce`,
`timeline` mit 7 Tagen. Danach eingeloggt `https://ipv64.net/honeypot/` aufrufen.

Testdaten wieder entfernen (`<sensor-id>` aus der Datei bzw. Antwort):

```sql
DELETE FROM hp_report_sources WHERE sensor_id = '<sensor-id>';
DELETE FROM hp_reports WHERE sensor_id = '<sensor-id>';
DELETE FROM hp_daily WHERE sensor_id = '<sensor-id>';
DELETE FROM hp_sensors WHERE sensor_id = '<sensor-id>';
-- Proben sind Summen ueber alle Sensoren: solange noch kein echter Sensor gemeldet hat, einfach leeren
TRUNCATE hp_samples_creds; TRUNCATE hp_samples_paths; TRUNCATE hp_samples_uas; TRUNCATE hp_samples_payloads;
```

## 6. Menü (erst nach Freigabe)

Die Seite ist ohne Menülink nur per URL erreichbar. Vorschlag für später (nicht eingebaut): unter „Secure“ bzw. neben
den Blocklisten ein Eintrag „Honeypot64“ → `/honeypot/`.

## Was die Dateien machen (Kurzfassung)

- **`POST /api/v2/honeypot/reports`** (API-Key wie alle v2-Routen, auch `users.apikey`): JSON, optional
  `Content-Encoding: gzip` (stückweise entpackt, Grenze 2 MiB greift auch bei gzip-Bomben). Strenge Prüfung → `422`:
  `schema == 1`, `report_id == <sensor.id>-<period.start unix>`, Sensor-ID als UUID, Version/Profil/Modus, Zeiten
  RFC 3339 (bis Nanosekunden, mit Zone), Ende höchstens 5 min in der Zukunft, Zeitraum höchstens 7 Tage und nicht
  älter als 7 Tage, Ports 0–65535, Anzahlen ≥ 1, Texte in den Grenzen von `types.go`. `413` bei mehr als 2 MiB,
  5000 Quellen oder 500 Proben je Art. Bekannte `report_id` → `200 {"duplicate": true}`.
- **Verworfen und gezählt** (Antwort `rejected_reasons`, Spalte `hp_reports.rejected`): private/reservierte/
  Dokumentations-/CGNAT-/Multicast-Adressen, IPv4-mapped IPv6, die IP des Sensors selbst und die letzten IPs aller
  Sensoren des Accounts, Arten/Dienste außerhalb der festen Liste (so bricht ein neuerer Sensor mit neuer Art nicht die
  ganze Meldung), Zeiten außerhalb des Zeitraums.
- **Grenzen:** höchstens eine Meldung je Sensor in 2 Minuten (`429` mit `Retry-After`, aus der Datenbank, also über
  Neustarts hinweg), höchstens 50 Sensoren je Account (`403 sensor_limit`); `hp_sensors.disabled = 1` sperrt einen
  Sensor (`403 sensor_disabled`).
- **Speichern** in einer Transaktion: Sensor (Version, Profil, Modus, letzte IP – intern, nie ausgegeben), Meldung,
  Quellen mit voller IP, Tagesstatistik je Account/Sensor/Art/Port, Proben als laufende Summen je Tag (Zugangsdaten
  im Klartext + SHA-256 als Schlüssel + SHA-1 des Passworts für die spätere Passwortprüfung, Pfade, User-Agents,
  Payload-Anfang). 4-Byte-Zeichen (Emoji) werden ersetzt, weil die Verbindung mit `SET NAMES 'utf8'` läuft.
- **`GET /api/v2/honeypot/sensors`** und **`GET /api/v2/honeypot/stats`**: eigene Sensoren und eigener Beitrag
  (Ereignisse/Quell-IPs 24 h/7 d, Top-Arten, Top-Ports, Verlauf 7 Tage, `contributor` für den späteren Live-Stand).
- **`honeypot/index.php`:** dieselben Zahlen für den angemeldeten Account, ohne IPs, Link auf
  `node64.de/docs/honeypot/`.
- **`bots/honeypot_cleanup.php`:** volle IPs 90 Tage, dann je Tag verdichtet nach `hp_sources_archive` (IPv4 /24,
  IPv6 /48, Ereignisse, IPs, Accounts) und in Blöcken gelöscht; `hp_reports` nach 90 Tagen weg; Archiv und
  `hp_daily` 24 Monate; Proben unbegrenzt.

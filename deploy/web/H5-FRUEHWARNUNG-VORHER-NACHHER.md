# Honeypot64 – Phase H5, Teil Frühwarnung + Limits einspielen (ipv64.net)

Frühwarnung für eigene Netze (Plan Abschnitt 11): Accounts tragen öffentliche Netze ein, ihre DynDNS-Adressen werden
automatisch überwacht; fällt eine Adresse daraus bei der Bewertung als Angreifer auf, gibt es einen Treffer (API für
Node64, Seite, Mail). Dazu Limits je Account-Klasse (Netze, Sensoren) und der Dienst `vpn` für den Log-Sensor.
Planung: `docs/PLAN-NODE64-HONEYPOT64.md` (Abschnitte 8, 11, „H5 Umsetzung“).

Getestet in einer abgeschotteten Testumgebung auf der Testbox (MariaDB 10.5, PHP 8.3, echte `api_v2.php` mit
`api_v2_honeypot.php`, `api_v2_threat.php` und `api_v2_threat_watch.php`, Seite, Cron, `send_mail` als Stub):
112 Prüfungen, alle grün (`deploy/web/honeypot/tests/h5_watch/run_agentbox.sh`), danach alles entfernt.

## Was es macht

| Teil | Inhalt |
|---|---|
| Netze | Je Account eigene Netze (`hp_watch`), IPv4 bis /16, IPv6 bis /32, nur öffentliche Netze. **Standard (`user_class` = 1): 3 Netze, alle anderen Klassen: 50.** Host-Bits werden entfernt, eine einzelne IP wird /32 bzw. /128. |
| Nachweis | Netze ohne Nachweis (`verified = 0`, Standard) bekommen **nur Treffer für gelistete IPs** (v64 Blocklist, ohnehin öffentlich – kein Datenleck). Mit Nachweis meldet jede Sichtung. `verified` setzt nur ein Admin per SQL (siehe Abschnitt 6). |
| DynDNS | Die aktuellen DynDNS-IPs des Accounts gelten als nachgewiesen: **jede Sichtung** ergibt einen Treffer. Quelle wie `reason customer_ip` der Bewertung: `subdomain_records` A/AAAA mit `deactivated = 0`, ohne CDN-Hilfseinträge (`cdn_tmp != 0`, die zeigen auf die Edge-Server), nur öffentliche Adressen. Steht eine IP in Records von **mehr als 3 Accounts** (geteilte Hosting-/Proxy-Adresse), zählt sie nicht als Nachweis (dann nur gelistet). |
| Cron | `bots/honeypot_watch.php` alle 30 Minuten, 5 Minuten nach der Bewertung. Grundlage ist `hp_scores` (alle Sichtungen der letzten 14 Tage **ohne Sensor-IPs** und ohne private Adressen – die Frühwarnung verrät also keine Sensoren). Kandidaten: Sichtung in den letzten 2 Tagen oder frisch gelistet. Netze per Bereichsvergleich (`LENGTH(ip_start) = LENGTH(ip_bin) AND ip_start <= ip_bin AND ip_end >= ip_bin`, je Netz eine Bereichssuche im Primärschlüssel von `hp_scores`), DynDNS per Abgleich im Speicher. |
| Wiederholung | Je Account und IP **höchstens ein Treffer in 24 h, außer die IP wird neu gelistet**; nach 24 h nur bei neuer Sichtung. Passt eine IP mehrfach: DynDNS vor Netz, kleineres Netz vor größerem. Höchstens 100 neue Treffer je Account und Lauf (gelistete und hohe Werte zuerst, der Rest im nächsten Lauf). |
| Mail | Je Account **eine Mail je Lauf** an die Account-Adresse mit allen noch nicht gemeldeten Treffern der letzten 24 h (höchstens 25 IPs im Text, Rest als Anzahl). Schlägt der Versand fehl, holt der nächste Lauf ihn nach. Absender wie die Freigabe-Mails (`hpr_mail`, „IPv64.net Honeypot64“). |
| API | `GET/POST /threat/watch`, `DELETE /threat/watch/{id}`, `GET /threat/watch/alerts?since=` (Vertrag mit Node64, Abschnitt 5). Limit wie `GET /threat/ip` mit Key (120 sofort, dann 2 je Sekunde je Account), eigener Topf. |
| Seite | `/honeypot/watch.php` (eingeloggt, ohne Menülink): Netze anzeigen/eintragen/löschen, DynDNS-Adressen, letzte 50 Treffer, Hinweis auf Node64. Deutsch, `?lang=en` Englisch, CSRF wie die anderen Honeypot-Seiten. |
| Sensoren | `api_v2_honeypot.php`: neue Sensoren je Account **Standard 5, sonst 25**; es zählen Sensoren mit Meldung in den letzten 30 Tagen. Bekannte Sensoren werden immer angenommen. Sonst `403 sensor_limit` (mit `limit`). Dienst `vpn` (Log-Sensor) wird angenommen. |
| Fristen | Treffer nach 90 Tagen gelöscht (im Cron). |

**Limits – woher:** `user_class` hat keine passenden Spalten (`dyndns_limit` wäre für Standard zufällig 3, für VIP aber
10 und für Company 256). Darum Konstanten zentral in `honeypot/hp_limits_lib.php` (`HPL_NETS_STANDARD`,
`HPL_NETS_OTHER`, `HPL_MIN_PREFIX_V4/V6`, `HPL_SENSORS_STANDARD`, `HPL_SENSORS_OTHER`, `HPL_SENSOR_ACTIVE`).

## 1. SQL einspielen (Hauptdatenbank ipv64) – ZUERST

Voraussetzung: `honeypot.sql` (H2) und `honeypot_h3_scoring.sql` (H3, `hp_scores`) sind drin. Dann
`deploy/sql/honeypot_h5.sql` – mehrfach ausführbar, ändert keine bestehende Tabelle. Legt an: `hp_watch`,
`hp_watch_alerts`.

```bash
mysql ipv64 < honeypot_h5.sql
```

## 2. Dateien hochladen

| Datei im Repo | Ziel im Webroot (`/var/www/clients/client1/web58/web/`) |
|---|---|
| `deploy/web/honeypot/hp_limits_lib.php` | `honeypot/hp_limits_lib.php` (neu) – **vor** `api_v2_honeypot.php` |
| `deploy/web/api_v2_threat_watch.php` | `api_v2_threat_watch.php` (neu) |
| `deploy/web/honeypot/watch.php` | `honeypot/watch.php` (neu) |
| `deploy/web/bots/honeypot_watch.php` | `bots/honeypot_watch.php` (neu, Cron) |
| `deploy/web/api_v2_honeypot.php` | `api_v2_honeypot.php` (ersetzt: `'vpn'` in `HP_SERVICES`, ein Block beim Sensor-Limit, Kommentar an `HP_MAX_SENSORS`) |
| `deploy/web/api_v2_openapi.json` | `api_v2_openapi.json` (ersetzt: vier Pfade, `ThreatWatch`, `ThreatWatchNetwork`, `ThreatWatchAlert`, `ThreatWatchAlerts`; Text zum Sensor-Limit bei `POST /honeypot/reports`) |

Benötigt außerdem das vorhandene `honeypot/hp_release_lib.php` (H3).
**Nicht hochladen:** `deploy/web/honeypot/tests/` (Stubs und Testskripte).

Änderung in `api_v2_honeypot.php` (Block in `hp_store`):

VORHER:

```php
			$n = (int)q1("SELECT count(*) c FROM hp_sensors WHERE userid = :u AND sensor_id != :s", array('u' => $u, 's' => $sid))['c'];
			if($n >= HP_MAX_SENSORS) { fail(403, 'sensor_limit', 'At most ' . HP_MAX_SENSORS . ' honeypot sensors per account.'); }
```

NACHHER:

```php
			// H5: Limit je Klasse (honeypot/hp_limits_lib.php: Standard 5, sonst 25), es zaehlen nur Sensoren mit Meldung in 30 Tagen
			if(is_file(__DIR__ . '/honeypot/hp_limits_lib.php')) { require_once __DIR__ . '/honeypot/hp_limits_lib.php'; }
			[$max, $act] = function_exists('hpl_sensor_limit') ? array(hpl_sensor_limit((int)($GLOBALS['ME']['user_class'] ?? 1)), HPL_SENSOR_ACTIVE) : array(HP_MAX_SENSORS, 3650 * 86400);
			$n = (int)q1("SELECT count(*) c FROM hp_sensors WHERE userid = :u AND sensor_id != :s AND last_seen >= :d", array('u' => $u, 's' => $sid, 'd' => hp_dt($now - $act)))['c'];
			if($n >= $max) { fail(403, 'sensor_limit', "At most $max active honeypot sensors per account (account class).", array('limit' => $max)); }
```

Die Bibliothek wird nur geladen, wenn sie da ist: Fehlt sie (falsche Reihenfolge beim Hochladen), gilt das alte Limit
50 und die übrige API v2 läuft weiter.

## 3. `api_v2.php`: eine Zeile vor dem Start-Block

VORHER (seit H4):

```php
require __DIR__ . '/api_v2_honeypot.php';
require __DIR__ . '/api_v2_threat.php';
require __DIR__ . '/api_v2_honeypot_stats.php';

// ===================================================================
//  Start
```

NACHHER:

```php
require __DIR__ . '/api_v2_honeypot.php';
require __DIR__ . '/api_v2_threat.php';
require __DIR__ . '/api_v2_honeypot_stats.php';
require __DIR__ . '/api_v2_threat_watch.php';

// ===================================================================
//  Start
```

## 4. Cron

```cron
# Honeypot64 Frühwarnung (5 Minuten nach der Bewertung um 7 und 37)
12,42 * * * * php /var/www/clients/client1/web58/web/bots/honeypot_watch.php > /dev/null
```

Einmal von Hand prüfen (zuerst ohne Schreiben):

```bash
php /var/www/clients/client1/web58/web/bots/honeypot_watch.php --dry   # Zahlen und die ersten 50 Treffer, nichts geschrieben, keine Mail
php /var/www/clients/client1/web58/web/bots/honeypot_watch.php
```

Hinweis zum ersten Lauf: Alle DynDNS-Kunden, deren IP in den letzten 2 Tagen von einem Sensor gesehen wurde, bekommen
gleich eine Mail. `--dry` zeigt vorher, wie viele es sind.

## 5. Vertrag mit Node64 (API)

Auth wie alle v2-Pfade (`Authorization: Bearer <API-Key>`), Antworten `{"data": …}`, Fehler als `problem+json` mit
`code` (über `fail()`).

| Aufruf | Antwort |
|---|---|
| `GET /threat/watch` | `{"limits":{"max":3,"min_prefix_v4":16,"min_prefix_v6":32},"networks":[{"id","cidr","label","verified","created_at"}],"dyndns":[{"ip","domain"}]}` |
| `POST /threat/watch` `{"cidr","label"}` | `201` Netz; `422 invalid_cidr`, `prefix_too_large`, `not_public`; `409 duplicate`; `403 limit_reached` |
| `DELETE /threat/watch/{id}` | `204`; `404` (auch fremde Netze); frühere Treffer bleiben |
| `GET /threat/watch/alerts?since=` | `{"alerts":[{"id","ip","cidr","network_id","source","label","listed","score","kinds","first_seen","last_seen","created_at"}],"next"}` |

Zu `alerts` (präzisiert mit dem Node64-Agenten):

- Sortierung `created_at, id`, höchstens 100 je Abruf.
- `next` ist ein für den Client **undurchsichtiger Cursor**, derzeit `"<RFC3339>_<id>"` des letzten Treffers, z. B.
  `2026-10-20T12:12:03Z_42`. Die Node gibt ihn unverändert als `since` zurück und verwirft doppelte IDs.
- `since` nimmt so einen Cursor (Bedingung `(created_at, id) > (Zeit, id)`) oder ein reines RFC 3339
  (`created_at > Zeit`, Offset und Bruchteile erlaubt); leer = alle (90 Tage). So gehen auch mehr als 100 Treffer mit
  gleichem `created_at` (ein Lauf) nicht verloren.
- Keine neuen Treffer: `next` = der übergebene Stand; bei leerem `since` die aktuelle Zeit **minus 5 Minuten**
  (ein laufender Cron-Lauf könnte gerade noch schreiben; doppelte IDs verwirft die Node ohnehin).
- `network_id` ist `null` bei `source = "dyndns"`; `cidr` ist dann die IP als /32 bzw. /128. `label` (Netzname bzw.
  Domain) kommt zusätzlich zum Vertrag dazu. `first_seen`/`last_seen` als Tag (`Y-m-d`, UTC), `created_at` RFC 3339.
- Ungültiges `since` → `400 invalid_parameter`.

## 6. Prüfschritte

```bash
K=<API-Key eines Test-Accounts>
curl -s -H "Authorization: Bearer $K" https://ipv64.net/api/v2/threat/watch
curl -s -H "Authorization: Bearer $K" -H 'Content-Type: application/json' -d '{"cidr":"<oeffentliches Netz>/24","label":"Test"}' https://ipv64.net/api/v2/threat/watch
curl -s -H "Authorization: Bearer $K" -H 'Content-Type: application/json' -d '{"cidr":"10.0.0.0/16"}' https://ipv64.net/api/v2/threat/watch     # 422 not_public
curl -s -H "Authorization: Bearer $K" https://ipv64.net/api/v2/threat/watch/alerts
curl -s -H "Authorization: Bearer $K" "https://ipv64.net/api/v2/threat/watch/alerts?since=<next aus der vorigen Antwort>"
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE -H "Authorization: Bearer $K" https://ipv64.net/api/v2/threat/watch/<id>   # 204
```

Seite: `https://ipv64.net/honeypot/watch.php` (eingeloggt), `?lang=en`.

Nachweis für ein Netz setzen (z. B. nach RIR-Eintrag oder Mail an die Abuse-Adresse), dann meldet jede Sichtung:

```sql
UPDATE hp_watch SET verified = 1 WHERE id = <id>;
```

Treffer ansehen: `SELECT userid, ip, source, cidr, label, listed, score, created_at, mailed_at FROM hp_watch_alerts ORDER BY id DESC LIMIT 20;`

## 7. Bitte bestätigen (Dennis)

- **Limits:** Netze Standard 3 / sonst 50, IPv4 bis /16, IPv6 bis /32, Sensoren Standard 5 / sonst 25 – als Konstanten
  in `honeypot/hp_limits_lib.php`. Zusätzlich gewählt: beim Sensor-Limit zählen nur Sensoren mit Meldung in den
  letzten 30 Tagen (es gibt kein Löschen von Sensoren; ohne das wären Standard-Accounts nach fünf Neuinstallationen
  dauerhaft gesperrt).
- **DynDNS-Mails automatisch an alle Accounts**, deren DynDNS-IP gesehen wird (auch nicht gelistet), höchstens einmal
  je IP und 24 h – ohne eigenen Schalter zum Abbestellen. Alternative: Mail nur für gelistete DynDNS-IPs oder ein
  Schalter je Account.
- **Geteilte DynDNS-IPs:** ab mehr als 3 Accounts mit derselben IP kein Nachweis (`HPW_SHARED_MAX`).
- **Mailtext** (`bots/honeypot_watch.php`, Abschnitt 5), Betreff „Honeypot64 Frühwarnung: <IP> ist als Angreifer
  aufgefallen“ bzw. „… <n> Adressen sind als Angreifer aufgefallen“:

  > Honeypot64-Sensoren haben Angriffe von Adressen aus deinen Netzen bzw. von deinen DynDNS-Adressen gesehen. Meist
  > steckt ein befallenes Gerät dahinter (Kamera, Router, NAS, alter PC). „gelistet“ heißt: Die Adresse steht auf der
  > v64 Blocklist.
  >
  > - 203.0.113.9 – 203.0.113.0/24 (Büro) – gelistet / listed, ssh:bruteforce
  >   https://ipv64.net/honeypot/ip.php?ip=203.0.113.9
  > - 198.51.100.7 – DynDNS x.ipv64.net – gesehen / seen, generic:portscan
  >   https://ipv64.net/honeypot/ip.php?ip=198.51.100.7
  >
  > Was tun: Geräte im Netz prüfen, Firmware aktualisieren, Standard-Passwörter ändern. Bei neu zugeteilten Adressen
  > kann es auch der Vorbesitzer gewesen sein. Steht eine Adresse auf der Liste und ist das Problem behoben, kannst du
  > über die IP-Auskunft eine Freigabe beantragen.
  > Netze verwalten und alle Treffer: https://ipv64.net/honeypot/watch.php (oder in Node64 unter Honeypot64).
  >
  > English: Honeypot64 sensors have seen attacks from addresses in your networks or from your DynDNS addresses (list
  > above). Usually an infected device is behind it. Check your devices; manage your networks at
  > https://ipv64.net/honeypot/watch.php?lang=en

## 8. Hinweise

- **Datenschutz:** Netze ohne Nachweis sehen nur, was ohnehin öffentlich ist. Für DynDNS-IPs (jede Sichtung) gilt:
  Wer eine beliebige IP als A-Record einträgt, erfährt, ob Sensoren sie gesehen haben (Arten, Wert, Tag) – keine
  Sensoren, keine Accounts, keine Ports. Geteilte IPs (mehr als 3 Accounts) sind ausgenommen.
- **H2-/H4-Testskripte** kopieren `api_v2_honeypot.php` ohne `hp_limits_lib.php`; dort greift das alte Limit 50,
  die Tests bleiben gültig.
- `deploy/web/H2-HONEYPOT-VORHER-NACHHER.md` nennt noch „höchstens 50 Sensoren je Account“ (Stand H2).

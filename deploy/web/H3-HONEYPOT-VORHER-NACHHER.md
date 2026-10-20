# Honeypot64 – Phase H3, Teil Bewertung + Listen einspielen (ipv64.net)

Bewertung der gemeldeten IPs alle 30 Minuten (`hp_scores`), **v64 Blocklist** mit Teillisten (Tagesstand frei,
Live-Stand mit Listen-Token), Listen-Token im Account, echte Zeile auf der Listenseite. Planung:
`docs/PLAN-NODE64-HONEYPOT64.md` (Abschnitte 6, 7, 8, „H3 Umsetzung“). Den Teil **IP-Auskunft + Freigaben**
(`hp_allowlist`, `hp_release_requests`, `ip.php`, …) beschreibt eine eigene Anleitung; die Bewertung liest dessen
Tabellen nur und läuft auch ohne sie (Meldung „Warnung: hp_allowlist nicht lesbar“).

Getestet in einer abgeschotteten Testumgebung auf der Testbox (MariaDB 10.5, PHP 8.3, Builtin-Server mit der
Rewrite-Regel unten): 92 Prüfungen, alle grün (`deploy/web/honeypot/tests/h3_scoring/run_agentbox.sh`).

## 1. SQL einspielen (Hauptdatenbank ipv64)

Voraussetzung: `deploy/sql/honeypot.sql` (H2) ist drin. Dann `deploy/sql/honeypot_h3_scoring.sql` – mehrfach
ausführbar (`IF NOT EXISTS`), ändert keine bestehende Tabelle. Legt an: `hp_scores`, `hp_list_tokens`,
`hp_list_token_files`.

```bash
mysql ipv64 < honeypot_h3_scoring.sql
```

## 2. Dateien hochladen

| Datei im Repo | Ziel im Webroot (`/var/www/clients/client1/web58/web/`) |
|---|---|
| `deploy/web/blocklists/site/bots/blocklist/honeypot_score.php` | `bots/blocklist/honeypot_score.php` (neu) |
| `deploy/web/blocklists/site/bots/blocklist/create_blocklists_v2.php` | `bots/blocklist/create_blocklists_v2.php` (ersetzt) |
| `deploy/web/blocklists/site/v64_blocklists.php` | `v64_blocklists.php` (ersetzt) |
| `deploy/web/blocklists/live.php` | `blocklists/live.php` (neu, in den Ordner der Listen) |
| `deploy/web/honeypot/token.php` | `honeypot/token.php` (neu) |
| `deploy/web/honeypot/index.php` | `honeypot/index.php` (ersetzt: nur Karte „Live-Listen“ und ein Satz geändert) |

**Nicht hochladen:** `deploy/web/honeypot/tests/` (Stubs und Testskripte).

**Live-Ordner:** Der Generator legt den Live-Stand in `/var/www/clients/client1/web58/private/blocklists_live/` ab
(ISPConfig-Ordner `private/` neben `web/`, nicht über HTTP erreichbar) und legt den Ordner beim ersten Lauf an.
Der Benutzer des Crons muss dort schreiben, PHP (Webserver-Benutzer) lesen dürfen – Ordner `0755`, Dateien `0644`
macht der Generator selbst. Läuft der Cron als root, danach einmal prüfen: `ls -ld .../private/blocklists_live`.

## 3. Rewrite-Regel für `/blocklists/live/<token>/<datei>`

`.htaccess` im Webroot – VORHER (Anfang der Datei):

```apache
RewriteEngine On 
RewriteBase /

RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)/$ /$1 [L,R]
```

NACHHER (eine Regel direkt nach `RewriteBase`, vor allen anderen):

```apache
RewriteEngine On 
RewriteBase /

# Honeypot64: Live-Stand der v64 Blocklist mit Listen-Token (32 Zeichen A-Za-z0-9)
RewriteRule ^/?blocklists/live/([A-Za-z0-9]{32})/([A-Za-z0-9_.-]+)$ /blocklists/live.php?t=$1&f=$2 [L]

RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)/$ /$1 [L,R]
```

Falls im Ordner `blocklists/` eine eigene `.htaccess` mit `RewriteEngine On` liegt, greift die Regel aus dem Webroot
dort nicht – dann dieselbe Regel in diese Datei, ohne `blocklists/`:
`RewriteRule ^live/([A-Za-z0-9]{32})/([A-Za-z0-9_.-]+)$ /blocklists/live.php?t=$1&f=$2 [L]`.

Falls stattdessen nginx (ISPConfig: „nginx Directives“ der Website):

```nginx
rewrite ^/blocklists/live/([A-Za-z0-9]{32})/([A-Za-z0-9_.-]+)$ /blocklists/live.php?t=$1&f=$2 last;
```

## 4. Cron

VORHER: Blocklisten-Cron (`read_blocklists.php`, `create_blocklists_v2.php`) wie bisher – bleibt unverändert.

NACHHER: zusätzlich alle 30 Minuten Bewertung und direkt danach nur die v64-Listen:

```
7,37 * * * * php /var/www/clients/client1/web58/web/bots/blocklist/honeypot_score.php > /dev/null 2>&1 && php /var/www/clients/client1/web58/web/bots/blocklist/create_blocklists_v2.php --only=v64 > /dev/null 2>&1
```

- `--only=v64` schreibt nur die v64-Dateien und ersetzt in `index.json` nur die Einträge der Kategorie `honeypot`
  (Sekunden statt Minuten). Der normale volle Lauf schreibt die v64-Listen ebenfalls mit.
- Tagesstand: der erste Lauf eines UTC-Tages kopiert den Live-Stand nach `blocklists/` (öffentlich);
  `--v64-daily` erzwingt das sofort (z. B. nach dem ersten Einspielen).
- `php honeypot_score.php --dry` rechnet nur und zeigt die Zahlen.

## 5. Prüfen

```bash
php bots/blocklist/honeypot_score.php --dry
php bots/blocklist/honeypot_score.php && php bots/blocklist/create_blocklists_v2.php --only=v64 --v64-daily
curl -s https://ipv64.net/blocklists/ipv64_blocklist_v64.txt | head
curl -s https://ipv64.net/blocklists/index.json | grep -A3 '"honeypot"'
```

Erwartet: Zeile `Aktive Accounts (7 Tage): …, Schwelle: …`, danach `hp_scores: … geschrieben`; der Generator
`v64 … Netze … live + Tagesstand` und `index.json: 7 v64-Listen eingetragen`. Solange nur wenige Sensoren melden,
sind die Listen leer oder fast leer – das ist richtig (Schwelle: mindestens 2 unabhängige Accounts mit Login/Exploit).

Eingeloggt `https://ipv64.net/honeypot/token.php` → Token erzeugen, dann:

```bash
curl -si https://ipv64.net/blocklists/live/<token>/ipv64_blocklist_v64.txt | head -12
```

Erwartet `200`, Kopfzeilen `X-IPv64-List: live` (Klasse ≠ Standard oder Beitragende/r) bzw. `daily`, `ETag`.
Derselbe Aufruf sofort noch einmal: `429` mit `Retry-After`; mit `-H 'If-None-Match: <ETag>'`: `304`.
`https://ipv64.net/blocklists/live/<token>/../dbconnect.php` und unbekannte Dateinamen: `404`.
Listenseite `https://ipv64.net/v64_blocklists`: erste Zeile „v64 Blocklist (Honeypot64)“ mit Teillisten.

## 6. Menü (erst nach Freigabe, nicht eingebaut)

`header.php`, Menü „Secure“ – VORHER:

```html
<a class="dropdown-item" href="https://ipv64.net/v64_blocklists"><i class="fa-solid fa-road-barrier fa-sm"></i> IPv64 Blocklists</a>
```

NACHHER (Vorschlag):

```html
<a class="dropdown-item" href="https://ipv64.net/v64_blocklists"><i class="fa-solid fa-road-barrier fa-sm"></i> IPv64 Blocklists</a>
<a class="dropdown-item" href="https://ipv64.net/honeypot/"><i class="fa-solid fa-bug fa-sm"></i> Honeypot64</a>
<a class="dropdown-item" href="https://ipv64.net/honeypot/token.php"><i class="fa-solid fa-key fa-sm"></i> Live-Listen (Token)</a>
```

## Was die Dateien machen (Kurzfassung)

**`honeypot_score.php`** (Fenster 14 Tage aus `hp_report_sources`, alle Zeiten UTC):

- **Accounts statt Sensoren:** zehn Sensoren eines Accounts zählen einmal. Accounts, deren Sensoren (IP aus
  `hp_reports.ip` bzw. `hp_sensors.last_ip`) im selben /24 (IPv6: /48) stehen, bilden eine Gruppe und zählen einmal.
- **Vertrauen je Sensor** (bewusst einfach): 1.0; halbiert für Accounts jünger als 7 Tage (`users.reg_date`) und für
  Sensoren, deren IPs fast nie bestätigt werden (ab 50 gemeldeten IPs, unter 5 % auch von einer anderen Gruppe
  gemeldet; greift erst ab 3 Gruppen, sonst kann niemand bestätigen); 0 für gesperrte Sensoren und Accounts mit
  `account_status` ≠ 1. Eine Gruppe zählt je IP mit dem höchsten Vertrauen ihrer meldenden Sensoren.
- **Schwelle** nach aktiven Accounts (Meldung in 7 Tagen), gewichtet: unter 20 → 2 Accounts mit Login/Exploit
  (`*:bruteforce`, `http:exploit*`) oder 3 Accounts; 20–200 → 3; über 200 → 2 %, mindestens 3, höchstens 10.
  `scanner:research` zählt getrennt (nur Liste `research`, nie in `v64`), Schwelle wie ohne Login/Exploit.
- **Vertrauenswert 0–100:** S = Σ je Gruppe Vertrauen × Art × Quelle × Alter, Wert = 100·(1 − e^(−S/1,5)).
  Art: Login/Exploit 1,0 · Scan/User-Agent/Research 0,6 · bloßer Verbindungsaufbau 0,3; Quelle: Honeypot 1,0 ·
  Log 0,8 · Syslog 0,7; Alter: bis 1 Tag 1,0, dann linear bis 0,25 nach 14 Tagen. Beispiele: 2 Accounts mit
  frischem Login → 74, 3 Accounts Scan → 70, 3 Accounts nur Verbindungsaufbau → 45. Der Wert ist Auskunft
  (IP-Auskunft, Sortierung); **ob gelistet wird, entscheidet die Schwelle** – so bleibt eine IP bis 14 Tage nach dem
  letzten Treffer stabil gelistet.
- **Nie listen:** nicht öffentliche Adressen und **IPs der Sensoren** (`hp_sensors.last_ip`, `hp_reports.ip` der
  letzten 30 Tage; IPv6 als /64) stehen gar nicht in `hp_scores` – so kann die IP-Auskunft keinen Sensor verraten.
  Trotz Schwelle nicht gelistet (`listed = 0`, Grund in `reason`): Infrastruktur (`infra`: `hp_allowlist`
  source `infra`, Server aus `cdn_server`, `vpn_gw_server`, `dns64_server`, Konstante `HPS_INFRA_NETS`),
  Cloudflare (`cdn`: Liste `bl_cloudflare`, `hp_allowlist` source `cdn`), Freigaben (`allowlist`: `hp_allowlist`
  mit `until` leer oder in der Zukunft, `hp_release_requests.protected_until` > jetzt), **Kunden-IPs**
  (`customer_ip`: aktive A/AAAA-Records in `subdomain_records.content` – die aktuelle DynDNS-IP –, und
  `vpn_public_ips`; binär verglichen, Schreibweise egal). Kunden werden noch nicht gewarnt (TODO, Ausgabe im Cron-Log).
- **Rausfallen:** Zeilen ohne Treffer in 14 Tagen werden gelöscht; `listed_since` bleibt, solange gelistet.
- `lists`: `v64` (Hauptliste) und Teillisten `ssh` (ssh/telnet), `web` (`http:*`), `mail` (`mail:*`), `rdp`
  (`rdp:*`), `scanner` (`generic:portscan`, `generic:probe`, `http:bad-useragent`), `research`
  (`scanner:research`). `db:*`, `vpn:*` nur in der Hauptliste.

**`create_blocklists_v2.php`** (Abschnitt 0 neu, Rest unverändert): liest `hp_scores` mit `listed = 1`, schreibt
je Liste `ipv64_blocklist_<id>.txt`, `_v4_`, `_v6_`, `v64_mikrotik_v4_<id>.rsc`/`v6` (MikroTik-Liste `IPv64-<id>`)
für `v64`, `v64_ssh`, `v64_web`, `v64_mail`, `v64_rdp`, `v64_scanner`, `v64_research`: bei jedem Lauf nach
`private/blocklists_live/`, beim ersten Lauf eines UTC-Tages auch nach `blocklists/`. `index.json`: sieben Einträge
in `lists` mit `category: "honeypot"`, `in_all: false`, `live: true`, Zahlen/Stand des Tagesstands, dazu oben
`"live": {"base": "https://ipv64.net/blocklists/live/{token}/", …}` für Node64/PROXY64. Nicht in `all`/`all_notor`.

**`blocklists/live.php`:** Token genau 32 Zeichen `[A-Za-z0-9]` (Groß-/Kleinschreibung zählt), unbekannt oder
Account inaktiv → `404`. Live-Stand für `user_class` ≠ 1 oder Beitragende (ein nicht gesperrter Sensor mit
`last_seen` in 7 Tagen), bei jedem Abruf geprüft; sonst Tagesstand (`200`, `X-IPv64-List: daily`). Nur die 35
Dateinamen der v64-Listen (feste Liste, kein Pfad aus der Anfrage). Je Token und Datei höchstens alle 5 Minuten
(`429` + `Retry-After`), `If-None-Match` mit passendem `ETag` → immer `304`, höchstens 60 Abrufe je 5 Minuten über alle
Dateien. `last_used` wird gesetzt.

**`honeypot/token.php`:** eingeloggt; Token anzeigen (maskiert, aufdecken, kopieren), erzeugen/neu erzeugen (alter
sofort ungültig, Abrufsperren zurückgesetzt), löschen; Beispieladressen (maskiert); Hinweis, wer Live bekommt und
welchen Stand der Account gerade hat. CSRF-Token in der Sitzung wie `cdn64.php`. Einträge im Account-Log.

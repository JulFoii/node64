# Honeypot64 – Phase H3, IP-Auskunft + Freigaben einspielen (ipv64.net)

Öffentliche IP-Auskunft „Warum ist diese IP gelistet?“ (Seite und API `GET /threat/ip/{ip}`), Freigabe-Anträge mit
automatischer Prüfung, Admin-Seite für eskalierte Anträge und die Freigabeliste. Planung:
`docs/PLAN-NODE64-HONEYPOT64.md` (Abschnitte 7, 9, 13 und „H3 Umsetzung (Schnittstellen)“).

Die Tabelle `hp_scores` gehört zum Teil **Bewertung + Listen** (`deploy/sql/honeypot_h3_scoring.sql`); dieser Teil liest
sie nur. Solange sie fehlt, meldet die Auskunft jede IP als „nicht gelistet“ (Fehler nur im PHP-Log), Freigaben und
Anträge funktionieren trotzdem. Reihenfolge also egal, sinnvoll: erst Bewertung, dann dieser Teil.

Getestet in einer abgeschotteten Testumgebung auf der Testbox (MariaDB 10.5, PHP 8.3, echte `api_v2.php` mit
`api_v2_honeypot.php` und dieser Datei, Builtin-Server mit Sitzungen, Stub-Tabelle `hp_scores` laut Schnittstelle,
`send_mail()` als Stub): 103 Prüfungen, alle grün (`deploy/web/honeypot/tests/h3_release/run_agentbox.sh`).

## 1. SQL einspielen (Hauptdatenbank ipv64)

Datei `deploy/sql/honeypot_h3_release.sql` – mehrfach ausführbar (`IF NOT EXISTS`, `INSERT IGNORE`), ändert keine
bestehende Tabelle. Legt an: `hp_allowlist`, `hp_release_requests`; dazu Startwerte `source = 'infra'` für srv07/srv08
(CDN64) und hc-srv01/hc-srv02 (hubs), je IPv4 einzeln und das IPv6-/64 des Servers.

```bash
mysql ipv64 < honeypot_h3_release.sql
```

**Bitte ergänzen** (in der Datei als Platzhalter-Kommentar): Webserver ipv64.net, DNS-Server, Mailserver, altes CDN
srv01–srv06, weitere eigene Netze (x64, VPN-Gateways). Entweder nach dem Muster in der SQL-Datei oder später auf der
Admin-Seite (Quelle `infra`).

## 2. Dateien hochladen

| Datei im Repo | Ziel im Webroot |
|---|---|
| `deploy/web/api_v2_threat.php` | neben `api_v2.php` |
| `deploy/web/honeypot/hp_release_lib.php` | `honeypot/hp_release_lib.php` (gemeinsame Funktionen, keine Ausgabe) |
| `deploy/web/honeypot/ip.php` | `honeypot/ip.php` |
| `deploy/web/honeypot/admin.php` | `honeypot/admin.php` |
| `deploy/web/bots/honeypot_release.php` | `bots/honeypot_release.php` |
| `deploy/web/api_v2_openapi.json` | ersetzt die bisherige (nur ein Pfad, ein Tag `Threat` und das Schema `ThreatIp` dazu, Rest unverändert) |

**Nicht hochladen:** `deploy/web/honeypot/tests/` (Test-Stubs und Testskripte).

## 3. `api_v2.php`: Datei einbinden

VORHER (Zeilen vor dem Start-Block, seit H2):

```php
require __DIR__ . '/api_v2_honeypot.php';

// ===================================================================
//  Start
// ===================================================================
```

NACHHER:

```php
require __DIR__ . '/api_v2_honeypot.php';
require __DIR__ . '/api_v2_threat.php';

// ===================================================================
//  Start
// ===================================================================
```

## 4. Cron (stündlich)

```
15 * * * * php /var/www/clients/client1/web58/web/bots/honeypot_release.php > /dev/null 2>&1
```

`php honeypot_release.php --dry` zeigt nur an, was passieren würde (keine Änderung, keine Mail).

## 5. Mail an Dennis

Eskalationen gehen an alle Accounts mit `users.admin = 1`. Soll es nur eine feste Adresse sein: in
`honeypot/hp_release_lib.php` `const HPR_NOTIFY = '';` auf die Adresse setzen. Versand über `send_mail()` aus
`dbconnect.php` (wie Healthchecks 2.0: mit dem 9. Parameter, falls vorhanden, sonst die alte Form).

## 6. Prüfen

```bash
curl -s https://ipv64.net/api/v2/threat/ip/91.99.98.96                      # Infrastruktur: "status":"allowlisted"
curl -s https://ipv64.net/api/v2/threat/ip/10.0.0.1                         # 422 not_public_ip
curl -s -H "Authorization: Bearer <API-Key>" https://ipv64.net/api/v2/threat/ip/<gelistete IP>
```

Seite: `https://ipv64.net/honeypot/ip.php?ip=<gelistete IP>` (Antragsformular erscheint nur bei gelisteten IPs),
englisch mit `&lang=en`. Admin: eingeloggt als Admin `https://ipv64.net/honeypot/admin.php`.
Testanträge danach wieder löschen: `DELETE FROM hp_release_requests WHERE id = <id>;` und, falls freigegeben,
`DELETE FROM hp_allowlist WHERE source = 'request' AND cidr = '<ip>/32';`.

## 7. Menü (erst nach Freigabe, nicht eingebaut)

Vorschlag in `header.php`, Menü „Secure“:

VORHER:

```php
					<a class="dropdown-item" href="https://ipv64.net/v64_blocklists"><i class="fa-solid fa-road-barrier fa-sm"></i> IPv64 Blocklists</a>
				</div>
```

NACHHER:

```php
					<a class="dropdown-item" href="https://ipv64.net/v64_blocklists"><i class="fa-solid fa-road-barrier fa-sm"></i> IPv64 Blocklists</a>
					<a class="dropdown-item" href="https://ipv64.net/honeypot/ip.php"><i class="fa-solid fa-magnifying-glass fa-sm"></i> IP-Auskunft (v64 Blocklist)</a>
				</div>
```

Die Admin-Seite bekommt bewusst keinen Menüpunkt (Lesezeichen).

## Schnittstelle zur Bewertung (`honeypot_score.php`)

- Gültige Freigaben: `SELECT ip_start, ip_end FROM hp_allowlist WHERE until IS NULL OR until > UTC_TIMESTAMP()`;
  eine IP ist frei, wenn `LENGTH(ip_start) = LENGTH(ip_bin) AND ip_start <= ip_bin AND ip_end >= ip_bin`.
  `until` ist UTC wie alle `hp_*`-Zeiten. Quellen: `manual`, `request` (befristet, aus Anträgen), `infra`, `cdn`.
- `protected_until` in `hp_release_requests` steht zusätzlich als `until` in `hp_allowlist` – die Bewertung muss nur
  `hp_allowlist` lesen. Nach Ablauf wird die IP wieder normal bewertet (Plan Abschnitt 9).
- Gelesen wird aus `hp_scores`: `listed`, `score`, `accounts`, `kinds`, `lists`, `first_seen`, `last_seen`; falls es
  später Spalten `country` (ISO-2) und `asn` gibt, erscheinen sie automatisch in der Auskunft (sonst `null`).

## Was die Dateien machen (Kurzfassung)

- **`GET /api/v2/threat/ip/{ip}`** (öffentlich): ohne Key Limit je Client-IP (10 sofort, dann 1 je Minute), mit Key je
  Account (120 sofort, dann 2 je Sekunde); ungültiger Key → `401`. Nur genau eine IP (kein Netz, keine Zone) → sonst
  `422 invalid_ip`, private/reservierte → `422 not_public_ip`. Antwort: `listed`, `status` (`listed`, `not_listed`,
  `released`, `allowlisted`), `score`, `lists`, `kinds`, `ports`, `first_seen`/`last_seen` (Tag, UTC), `accounts`
  (Anzahl), `country`/`asn` (oder `null`), `release` (`none`, `in_review`, `released`, `allowlisted`, `rejected`,
  `protected_until`), `details` (Link auf die Seite).
- **Schutz vor Rückschlüssen:** keine Sensor-IDs, keine Accounts, keine Zugangsdaten; für nicht gelistete IPs keine
  Einzelheiten (gleiche Antwort, ob Sensoren sie gesehen haben oder nicht); Sichtungen nur auf den Tag; Ports nur,
  wenn mindestens 2 Accounts sie gemeldet haben. Seite und API teilen sich das Limit.
- **`honeypot/ip.php`:** dieselbe Auskunft verständlich für Laien (Deutsch, `&lang=en` Englisch), Hinweise auf
  Fehlalarme und was man tun kann. Antrag nur für gelistete IPs: Begründung (10–2000 Zeichen), anonym E-Mail mit
  Bestätigungslink (48 h gültig, der Link zeigt einen Knopf, damit Link-Scanner nichts bestätigen), eingeloggt sofort
  gültig. CSRF-Token aus der Sitzung, Bot-Feld, Drossel ohne Captcha: höchstens 3 Anträge in 24 h je Absender-IP und
  je E-Mail/Account. Gespeichert wird nur IP, Begründung, E-Mail (nur anonym), Status und ein Hash der Absender-IP
  (nach 2 Tagen geleert). Statusseite je Antrag über `?request=<token>`.
- **`bots/honeypot_release.php`** (stündlich): 24 h nach der Bestätigung ohne neue Berührung → `released`,
  30 Tage geschützt, Eintrag in `hp_allowlist` (`source = request`, `until`), Bescheid per Mail. Eskaliert (Mail an
  Admins, Entscheidung auf der Admin-Seite): greift weiter an, weitere Anträge für dieselbe IP in 90 Tagen, ein
  Absender mit Anträgen für 5+ IPs in 30 Tagen, Provider-/Cloud-Netz (Listen mit `blocklisten.category = 'cloud'`,
  z. B. AWS, Google Cloud). Fristen: unbestätigte Anträge 48 h, E-Mail 90 Tage nach Entscheidung, Anträge 365 Tage,
  abgelaufene Freigaben aus Anträgen 7 Tage nach Ablauf.
- **`honeypot/admin.php`** (nur `users.admin = 1`): offene/eskalierte Anträge mit Prüfangaben (gelistet, Score,
  Berührungen seit Bestätigung, weitere Anträge, Provider-Netz), freigeben (30/90/365 Tage oder dauerhaft) oder
  ablehnen, jeweils mit Bescheid an den Antragsteller; Freigabeliste pflegen (IP/CIDR, IPv4 ab /8, IPv6 ab /16,
  Quelle `manual`/`infra`/`cdn`, Frist oder dauerhaft, löschen).

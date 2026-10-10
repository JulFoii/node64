# Healthchecks 2.0 bei ipv64.net: Server, Sync, Webseite, Integrationen

Detailplan, Stand 2026-10-10. Ziel: Der Agent (standalone fertig) wird mit ipv64.net verknüpft, die Healthcheck-Seiten des Portals werden neu gebaut, die Integrationen werden auf denselben Unterbau wie im Agent gestellt. Dieser Plan ist die Vorlage für die Umsetzung; Abweichungen werden hier eingetragen.

Ergänzt das Konzept („ipv64 Agent – Konzept & Funktionsumfang“) und ersetzt die Kurzfassung in `SYNC.md`.

---

## 0. Leitentscheidungen

| Nr. | Entscheidung | Begründung |
| --- | --- | --- |
| L1 | **Ein Check-Bot in Go** für Agent und Server (`internal/checks`, `internal/scheduler`, `internal/notify` aus dem Agent-Repo). Die PHP-Bots `healthcheck_*_live.php`, `healthcheck_alarm.php` werden abgelöst. | Gleiche Logik, gleiche Fehlergründe, gleiche Zustandsmaschine überall. |
| L2 | **Neuer Dienst `ipv64-checkd`** auf den ipv64-Servern neben dem Altsystem (Strangler-Fig). Neue Tabellen mit Präfix `hc2_`. Freischaltung je Account per Flag. | Kein Big Bang, Rollback per Flag. |
| L3 | **Server ist führend** für Konfiguration (Checks, Kanäle, Wartungsfenster), sobald ein Agent verknüpft ist. **Agent ist führend** für seine Messergebnisse (append-only). | Konzept, Abschnitt Synchronisation. |
| L4 | **Alle Agent-Aufrufe über die API v2** (`api_v2.php`), authentifiziert mit einem Agent-Token. Die Dauerverbindung ist ein Long-Poll-Endpunkt der API v2 (`/agents/me/pull`), kein WebSocket. | PHP kann keine WebSockets halten; Long-Poll erfüllt „ausgehende Dauerverbindung, keine offenen Ports“ und ist in 100 Zeilen fertig. Ein WebSocket-Stream über `checkd` kann später als Option dazu. |
| L5 | **Rohe Messpunkte der Online-Checks nur 7 Tage in MySQL** (partitioniert), Stunden- und Tageswerte in MySQL. Influx wird nicht mehr für Healthchecks gebraucht. | Ein Datenmodell für Agent und Server, gleiche Charts. Influx bleibt für CDN/Statistiken. |
| L6 | **Integrationen werden zu Kanälen** (`hc2_channels`), gleiche Typen wie im Agent plus `ipv64_mail`, `ipv64_sms`, `pushover`, `app`. Alte `integrations` werden einmalig migriert, die Verifizierung per Mail/SMS bleibt. | Gleicher Versandcode (Go) auf Server und Agent; die bekannten Lücken im alten PHP (activate_integration ohne Login) verschwinden. |
| L7 | **Push-URLs bleiben stabil**: `https://ipv64.net/health.php?token=...` und der neue Pfad `/api/v2/push/{token}` funktionieren beide, auch nach der Migration. | Tausende Geräte rufen die alte URL. |
| L8 | Lokale Checks eines Agents zählen **nicht** gegen `healthcheck_limit`; Online-Checks und „beides“ zählen. Anzahl Agents je Account nach Tarif (Free 1, VIP 3, Business 10, Vorschlag). | Konzept. |

---

## 1. Zielarchitektur

```
Browser ──► Portal (PHP, neue Seiten /healthchecks2 ...) ──► MySQL hc2_*  ◄── ipv64-checkd (Go)
                                                                   ▲              │  führt Online-Checks aus,
Agent ──► api_v2.php /agents/* (REST + Long-Poll) ─────────────────┘              │  Zustandsmaschine, Versand
                                                                                  ▼
Geräte ──► health.php?token= / api_v2.php /push/{token} ──► hc2_measurements + Redis "hc2:push"
```

**ipv64-checkd** (Go, aus dem Agent-Repo gebaut, `cmd/checkd`):
- lädt alle `hc2_checks` mit `execution IN ('online','both')` und `paused = 0`, plant sie wie der Agent (Worker-Pool, Jitter, Retry, Stabilisierung, Flattern, Abhängigkeiten, Wartungsfenster),
- schreibt Messpunkte, Zustände, Ereignisse, Störungen in `hc2_*`,
- bewertet Push-Checks per Watchdog (Push-Eingang kommt aus PHP, Signal über Redis),
- verschickt Benachrichtigungen (Server-Kanäle und `ipv64_mail`/`ipv64_sms`), erzeugt Sendeaufträge für Agent-Kanäle,
- verdichtet (stündlich) und räumt auf,
- erkennt Agent-Ausfälle (Heartbeat) und meldet sie,
- bekommt Konfigurationsänderungen vom Portal über `hc2_config_log` (Polling alle 2 s) oder Redis-Pub/Sub `hc2:config`.

Zwei Instanzen auf zwei Servern mit Lease-Tabelle (`hc2_leases`: `name, owner, until`): die aktive Instanz prüft, die zweite übernimmt nach 30 s ohne Lease-Verlängerung. Standorte (Falkenstein/Nürnberg) für „von außen“-Messungen kommen später als `location`-Spalte und zweiter Scheduler.

**Portal (PHP)**: neue Seiten lesen und schreiben `hc2_*` direkt über PDO (wie der Rest des Portals), jede Änderung erhöht `revision` und schreibt eine Zeile in `hc2_config_log`. Charts holen Aggregate über die API v2.

**API v2 (PHP)**: Endpunkte für Portal-JS, Fremdsoftware und Agents. Agent-Endpunkte unter `/api/v2/agents/...`.

---

## 2. Datenmodell auf dem Server (DDL)

Alle Zeiten `DATETIME(3)` in UTC (abweichend vom Rest des Portals, das Europe/Berlin speichert; die neuen Tabellen sind UTC, die API gibt ISO 8601 mit Zeitzone aus).

```sql
-- Accounts-Flag fuer die Umstellung
ALTER TABLE users ADD hc2 TINYINT NOT NULL DEFAULT 0;

CREATE TABLE hc2_agents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userid INT NOT NULL,
  agent_id VARCHAR(32) NOT NULL UNIQUE,      -- vom Agent erzeugt (settings agent.id)
  name VARCHAR(100) NOT NULL,
  location VARCHAR(100) NOT NULL DEFAULT '',
  version VARCHAR(32) NOT NULL DEFAULT '',
  timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
  modules VARCHAR(255) NOT NULL DEFAULT '',  -- aktive Module, kommagetrennt
  remote_mgmt ENUM('off','read','full') NOT NULL DEFAULT 'read',
  last_seen DATETIME(3) NULL, last_sync DATETIME(3) NULL,
  last_ack_seq BIGINT NOT NULL DEFAULT 0,    -- hoechste bestaetigte Messpunkt-Nummer
  outbox_size INT NOT NULL DEFAULT 0,        -- vom Agent gemeldet
  online TINYINT NOT NULL DEFAULT 0,         -- von checkd gepflegt (Heartbeat)
  created_at DATETIME(3) NOT NULL, revoked_at DATETIME(3) NULL,
  INDEX (userid)
);
CREATE TABLE hc2_agent_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  agent_id VARCHAR(32) NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,       -- sha256(token), Token selbst nur einmal sichtbar
  created_at DATETIME(3) NOT NULL, last_used DATETIME(3) NULL, revoked_at DATETIME(3) NULL,
  INDEX (agent_id)
);
CREATE TABLE hc2_link_codes (
  code CHAR(8) PRIMARY KEY,                  -- A-Z2-9 ohne 0/O/1/I, z. B. "K7PQ-4MZB" wird ohne Bindestrich gespeichert
  agent_id VARCHAR(32) NOT NULL, agent_name VARCHAR(100) NOT NULL, agent_version VARCHAR(32) NOT NULL,
  poll_secret CHAR(32) NOT NULL,             -- nur der Agent kennt es, verhindert Fremd-Polling
  created_at DATETIME(3) NOT NULL, expires_at DATETIME(3) NOT NULL,
  userid INT NULL, location VARCHAR(100) NULL, consumed_at DATETIME(3) NULL
);

CREATE TABLE hc2_checks (
  token CHAR(32) PRIMARY KEY,                -- wie healthchecks.healthtoken
  userid INT NOT NULL,
  agent_id VARCHAR(32) NULL,                 -- Besitzer-Agent bei execution local/both
  execution ENUM('local','online','both') NOT NULL DEFAULT 'online',
  type ENUM('http','keyword','icmp','tcp','port','cert','push') NOT NULL,
  name VARCHAR(200) NOT NULL, target VARCHAR(500) NOT NULL DEFAULT '', params JSON NOT NULL,
  interval_sec INT NOT NULL DEFAULT 60, retry_interval_sec INT NOT NULL DEFAULT 20, retries TINYINT NOT NULL DEFAULT 1,
  connect_timeout_ms INT NOT NULL DEFAULT 5000, total_timeout_ms INT NOT NULL DEFAULT 10000,
  invert TINYINT NOT NULL DEFAULT 0, stabilize TINYINT NOT NULL DEFAULT 3, ip_mode ENUM('auto','ipv4','ipv6','both') NOT NULL DEFAULT 'auto',
  tags VARCHAR(255) NOT NULL DEFAULT '', description TEXT, paused TINYINT NOT NULL DEFAULT 0,
  parent_token CHAR(32) NULL, critical TINYINT NOT NULL DEFAULT 0,
  notify_down TINYINT NOT NULL DEFAULT 1, notify_up TINYINT NOT NULL DEFAULT 1, channels VARCHAR(255) NOT NULL DEFAULT '', repeat_minutes INT NOT NULL DEFAULT 0,
  revision BIGINT NOT NULL DEFAULT 1, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, updated_by VARCHAR(100) NOT NULL DEFAULT '',
  deleted_at DATETIME(3) NULL,               -- Tombstone: bleibt 90 Tage, damit Agents das Loeschen sehen
  -- Laufzeitzustand je Ausfuehrungsort (local = vom Agent gemeldet, online = checkd)
  state_local ENUM('pending','up','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending',
  state_online ENUM('pending','up','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending',
  state ENUM('pending','up','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending', -- Gesamt (siehe 3.5)
  state_since DATETIME(3) NULL, last_check_at DATETIME(3) NULL, next_check_at DATETIME(3) NULL,
  last_status ENUM('up','down') NULL, last_latency_ms FLOAT NULL, last_reason VARCHAR(64) NULL, last_message VARCHAR(500) NULL,
  last_push_at DATETIME(3) NULL, down_since DATETIME(3) NULL, incident_id BIGINT NULL,
  INDEX (userid, deleted_at), INDEX (agent_id), INDEX idx_due (execution, paused, next_check_at), INDEX (parent_token)
);

-- Messpunkte: Online (agent_id = '') und Agent (agent_id gesetzt), 7 Tage roh
CREATE TABLE hc2_measurements (
  token CHAR(32) NOT NULL, agent_id VARCHAR(32) NOT NULL DEFAULT '', agent_seq BIGINT NOT NULL DEFAULT 0,
  time DATETIME(3) NOT NULL, status TINYINT NOT NULL, latency_ms FLOAT NOT NULL DEFAULT 0,
  reason VARCHAR(64) NOT NULL DEFAULT '', message VARCHAR(500) NOT NULL DEFAULT '', family CHAR(4) NOT NULL DEFAULT '',
  details JSON NULL, flags TINYINT NOT NULL DEFAULT 0, received_at DATETIME(3) NOT NULL,
  PRIMARY KEY (token, agent_id, time, agent_seq),  -- idempotent: Agent-Punkte sind ueber (agent_id, agent_seq) eindeutig
  INDEX (agent_id, agent_seq), INDEX (time)
) PARTITION BY RANGE (TO_DAYS(time)) (...tagesweise, 8 Partitionen rollierend...);

CREATE TABLE hc2_hourly (token CHAR(32), agent_id VARCHAR(32) NOT NULL DEFAULT '', hour DATETIME NOT NULL,
  count INT, up_count INT, min_ms FLOAT, avg_ms FLOAT, max_ms FLOAT, PRIMARY KEY (token, agent_id, hour));
CREATE TABLE hc2_daily  (token CHAR(32), agent_id VARCHAR(32) NOT NULL DEFAULT '', day DATE NOT NULL,
  count INT, up_count INT, min_ms FLOAT, avg_ms FLOAT, max_ms FLOAT, PRIMARY KEY (token, agent_id, day));

CREATE TABLE hc2_events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, event_id CHAR(32) NOT NULL UNIQUE,
  token CHAR(32) NOT NULL, userid INT NOT NULL, agent_id VARCHAR(32) NOT NULL DEFAULT '',
  kind VARCHAR(20) NOT NULL, time DATETIME(3) NOT NULL, from_state VARCHAR(12), to_state VARCHAR(12),
  reason VARCHAR(64), message VARCHAR(500), duration_sec INT NOT NULL DEFAULT 0, flaps SMALLINT NOT NULL DEFAULT 0,
  flags TINYINT NOT NULL DEFAULT 0, incident_id BIGINT NULL, notified_at DATETIME(3) NULL,
  INDEX (token, time), INDEX (userid, time)
);
CREATE TABLE hc2_incidents (id BIGINT AUTO_INCREMENT PRIMARY KEY, token CHAR(32), userid INT, agent_id VARCHAR(32) NOT NULL DEFAULT '',
  started_at DATETIME(3), ended_at DATETIME(3) NULL, reason VARCHAR(64), message VARCHAR(500), INDEX (token, started_at), INDEX (userid, started_at));

CREATE TABLE hc2_channels (
  id INT AUTO_INCREMENT PRIMARY KEY, userid INT NOT NULL,
  agent_id VARCHAR(32) NULL,                 -- NULL = Server-Kanal (gesendet von checkd), sonst Agent-Kanal (gesendet vom Agent)
  type VARCHAR(20) NOT NULL,                 -- smtp, telegram, discord, ntfy, gotify, webhook, pushover, app, ipv64_mail, ipv64_sms
  name VARCHAR(100) NOT NULL, config_enc TEXT NOT NULL,   -- JSON, Geheimnisse mit Server-Schluessel (AES-GCM) verschluesselt
  secret_only_local TINYINT NOT NULL DEFAULT 0,          -- Agent-Kanal: Server kennt nur Typ und Name
  enabled TINYINT NOT NULL DEFAULT 1, is_default TINYINT NOT NULL DEFAULT 0, lang CHAR(2) NOT NULL DEFAULT 'de',
  notify_down TINYINT NOT NULL DEFAULT 1, notify_up TINYINT NOT NULL DEFAULT 1,
  verified TINYINT NOT NULL DEFAULT 1, verify_key CHAR(16) NULL, verify_expires DATETIME(3) NULL, -- email/sms wie heute
  revision BIGINT NOT NULL DEFAULT 1, created_at DATETIME(3), updated_at DATETIME(3), deleted_at DATETIME(3) NULL,
  last_used DATETIME(3) NULL, last_error VARCHAR(500) NOT NULL DEFAULT '', legacy_integration_id INT NULL,
  INDEX (userid, deleted_at), INDEX (agent_id)
);
CREATE TABLE hc2_deliveries (id BIGINT AUTO_INCREMENT PRIMARY KEY, event_id CHAR(32), channel_id INT, userid INT, agent_id VARCHAR(32) NOT NULL DEFAULT '',
  time DATETIME(3), kind VARCHAR(20), ok TINYINT, error VARCHAR(500), UNIQUE (event_id, channel_id), INDEX (userid, time));
CREATE TABLE hc2_send_orders (                -- Sendeauftraege fuer Agent-Kanaele, holt der Agent per Pull
  id BIGINT AUTO_INCREMENT PRIMARY KEY, agent_id VARCHAR(32), channel_id INT, event_id CHAR(32), payload JSON,
  created_at DATETIME(3), fetched_at DATETIME(3) NULL, done_at DATETIME(3) NULL, INDEX (agent_id, done_at));

CREATE TABLE hc2_maintenance (id INT AUTO_INCREMENT PRIMARY KEY, userid INT, agent_id VARCHAR(32) NULL, name VARCHAR(200),
  start_at DATETIME(3), end_at DATETIME(3), `repeat` ENUM('none','daily','weekly','monthly') DEFAULT 'none', repeat_until DATETIME(3) NULL,
  tokens TEXT, active TINYINT DEFAULT 1, revision BIGINT DEFAULT 1, created_at DATETIME(3), updated_at DATETIME(3), deleted_at DATETIME(3) NULL, INDEX (userid));

-- Aenderungsprotokoll der Konfiguration: Quelle der Deltas fuer Agents und checkd
CREATE TABLE hc2_config_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, userid INT NOT NULL, agent_id VARCHAR(32) NULL,   -- NULL = betrifft alle Agents des Accounts
  entity ENUM('check','channel','maintenance','agent') NOT NULL, entity_id VARCHAR(32) NOT NULL,
  op ENUM('upsert','delete') NOT NULL, revision BIGINT NOT NULL, origin ENUM('portal','api','agent','system') NOT NULL,
  time DATETIME(3) NOT NULL, INDEX (userid, id), INDEX (agent_id, id)
);
CREATE TABLE hc2_leases (name VARCHAR(32) PRIMARY KEY, owner VARCHAR(64), until DATETIME(3));
```

**Mapping Alt → Neu** (Migrationsskript, pro Account beim Setzen von `users.hc2 = 1`):

| alt `healthchecks` | neu `hc2_checks` |
| --- | --- |
| `healthtoken` | `token` |
| `type` health / ping / web / tcp / keyword | `push` / `icmp` / `http` / `tcp` / `keyword` |
| `zeit1`,`zeit2` (1=min,2=h,3=d), `grace1`,`grace2` | push: `params.period_seconds`, `params.grace_seconds` |
| `type_options` JSON: `hostnameip`, `preferv4`, `tcpport`, `url`, `ssltrust`, `keyword`, `checkintervall1/2` (0=s,1=min,2=h), `fehlerintervall1/2`, `checkcount` | `target`, `ip_mode` (preferv4 → `ipv4`), `params.port`, `params.insecure_tls = !ssltrust`, `params.keyword`, `interval_sec`, `retry_interval_sec`, `retries = checkcount-1` |
| `alarm_down`, `alarm_up`, `integration` (csv von `integrations.id`, 0 = Account-Mail) | `notify_down`, `notify_up`, `channels` (neue IDs aus `hc2_channels.legacy_integration_id`; 0 → Standardkanal `ipv64_mail`) |
| `status` 0 new / 1 up / 2 paused / 3 warning / 4 down / 5 stabilizing | `state` pending / up / paused / down (warning gibt es nicht mehr: Karenz = Retry-Phase) / down / stabilizing |
| `healthcheck_events` (`status`, `text`, `latency`, `payload`) | letzte 7 Tage → `hc2_measurements` (status 1 → up, 3/4 → down), ältere → `hc2_daily` aus den Tageswerten |
| `healthcheck_incidents` + `_events` | `hc2_incidents` (Events-Text geht in `hc2_events`) |
| `integrations` (telegram, gotify, ntfy, pushover, discord, webhook, email, sms, mobil) | `hc2_channels` gleiche Typen (`mobil` → `app`), `options` → `config_enc`, `status 0` → `verified 0`, `default_inte` → `is_default` |
| `status_pages.healthchecks` (csv `healthchecks.id`) | Spalte wird auf Tokens umgestellt (`status_pages.hc2_tokens`), die Seite liest je nach `users.hc2` alt oder neu |
| `dns_failover_monitors.healthtoken` | unverändert, Failover liest `state` aus `hc2_checks` statt `status` aus `healthchecks` (Mapping down/flapping/dependent → 4) |

---

## 3. Synchronisationsprotokoll

### 3.1 Identitäten und Nummern

- `agent_id`: 32 Zeichen, vom Agent beim ersten Start erzeugt, unveränderlich.
- Check-`token`: 32 Zeichen, erzeugt dort, wo der Check angelegt wird. Bei der Erstverknüpfung prüft der Server Eindeutigkeit; bei Kollision vergibt er einen neuen Token und schickt `{old_token, new_token}` zurück, der Agent benennt um (Messdaten, Ereignisse, Push-URL).
- `revision`: pro Entität (Check, Kanal, Wartungsfenster) eine ganze Zahl. **Der Server vergibt sie** aus einem Zähler je Account (`MAX(revision)+1` in einer Transaktion); damit sind Revisionen innerhalb eines Accounts streng steigend und ein Agent kann mit „alles seit Revision R“ fragen.
- `agent_seq`: laufende Nummer je Agent für Messpunkte, nie wiederverwendet (SQLite `AUTOINCREMENT`).
- `event_id`: 32 Hex, vom Erzeuger (Agent oder checkd) vergeben.

### 3.2 Erstverknüpfung (Device-Code)

```
Agent                                   api_v2.php                              Portal (Nutzer)
  │ POST /agents/link/start {agent_id,name,version}
  │──────────────────────────────────────►│ legt hc2_link_codes an (8 Zeichen, 10 min gueltig)
  │◄──────────────────────────────────────│ {code:"K7PQ4MZB", poll_secret, expires_at, interval:5}
  │ zeigt "Gehe zu ipv64.net/link und gib K7PQ-4MZB ein"                                  │
  │ alle 5 s: POST /agents/link/poll {code, poll_secret}                                  │
  │◄── 202 {status:"pending"} ────────────│                                               │
  │                                       │   Nutzer meldet sich an, /link: Code, Standort, Name, Remote-Verwaltung
  │                                       │◄──────────────────────────────────────────────│
  │                                       │ userid, location in hc2_link_codes, Limit Agents je Tarif pruefen
  │ POST /agents/link/poll                │
  │◄── 200 {agent_token, account:{id,email,plan}, location, name, remote_mgmt} ──────────│
  │ speichert agent_token verschluesselt (secrets.Box), Status "verknuepft"
  │ POST /agents/me/bootstrap  ► siehe 3.6 Erstabgleich
```

- Der Code wird dem Nutzer mit Bindestrich gezeigt, gespeichert ohne. Alphabet ohne 0/O/1/I. 10 Minuten gültig, einmal einlösbar.
- `poll_secret` schützt vor Fremden, die einen Code erraten und dann pollen.
- Alternative ohne Browser am Agent: Token aus dem Portal (Seite Agents → „Token erzeugen“) als `AGENT_IPV64_TOKEN` beim Start.
- Token-Format: `ipv64ag_` + 40 Zeichen Base64url. Server speichert `sha256`. Widerruf im Portal → nächste Anfrage 401 `token_revoked` → Agent zeigt „Verknüpfung getrennt“, arbeitet standalone weiter.

### 3.3 Konfiguration: Server → Agent

- Jede Änderung im Portal/API schreibt die Entität mit neuer Revision und eine Zeile in `hc2_config_log`.
- Agent hält `last_revision` (höchste verarbeitete Revision des Accounts).
- Long-Poll `GET /agents/me/pull?since=<last_revision>&wait=25`: antwortet sofort, wenn es Einträge mit `revision > since` gibt (oder Sendeaufträge, oder Kommandos), sonst wartet PHP bis 25 s (Schleife mit `usleep`, Abfrage alle 2 s; bei `hc2_config_log` reicht ein `SELECT MAX(id)`), dann `204`. Ein Zyklus pro 30 s ist der Keepalive aus dem Konzept.
- Antwort: `{revision: <neu>, changes:[{entity, id, op, revision, data}], send_orders:[...], commands:[...]}`. `data` ist die vollständige Entität (keine Diffs), `op: delete` ohne `data`.
- Agent wendet an: Check upsert → Scheduler `Upsert` (Zustand behalten, wenn Typ gleich); delete → `Remove` + lokale Tombstone-Zeile.
- Lücke (Agent-`last_revision` kleiner als die kleinste noch vorhandene Log-Revision, Log wird nach 30 Tagen gekürzt) → Server antwortet `409 {error:"revision_gap"}` → Agent macht Vollabgleich (3.6).
- Betrifft ein Check-Eintrag einen anderen Agent (`agent_id` ≠ eigener, `execution local`), bekommt der Agent ihn trotzdem als **read-only Sicht** (Portal-Feature „alle Checks des Accounts sehen“), markiert `owner: other`.

### 3.4 Konfiguration: Agent → Server (Vorschläge)

- Lokale Änderung bei bestehender Verbindung: Agent sendet `PUT /agents/me/checks/{token}` mit `base_revision` (die Revision, die er zuletzt gesehen hat) und dem vollen Objekt. Server: wenn `base_revision == aktuelle revision` → speichern, neue Revision, Antwort mit dem gespeicherten Objekt; der Agent übernimmt die Antwort (Write-Through). Erst dann gilt die Änderung lokal; die Oberfläche zeigt bis dahin „wird gespeichert“.
- Ohne Verbindung: Änderung in die lokale Outbox (`hc_outbox`: `kind=check_upsert|check_delete|channel_upsert|...`, `payload`, `base_revision`), Oberfläche zeigt „ausstehend“. Beim Wiederverbinden Replay in Reihenfolge.
- Konflikt (`base_revision` veraltet): `409 {error:"conflict", server: {...}, revision}`. Agent speichert beide Versionen in `hc_conflicts` und zeigt sie dem Nutzer: „Server behalten“ (lokal überschreiben) oder „Meine Version senden“ (erneut PUT mit der aktuellen Server-Revision als Basis). **Nie stilles Überschreiben.**
- Löschen: `DELETE /agents/me/checks/{token}` mit `base_revision`; Server setzt `deleted_at` (Tombstone), Log-Eintrag `delete`. Umgekehrt: Server-Löschung kommt als `delete` im Pull; der Agent löscht lokal **inklusive Messdaten** erst nach Bestätigung aller offenen Messpunkte (sonst Outbox leeren zuerst).
- Dieselben Regeln für Kanäle (`/agents/me/channels/{id}`) und Wartungsfenster.

### 3.5 Messergebnisse: Agent → Server

- Agent sammelt Messpunkte in der Outbox (`hc_measurements` selbst ist die Outbox: alles mit `agent_seq > last_ack_seq` ist unbestätigt).
- Alle 30 s oder ab 100 Punkten: `POST /agents/me/measurements` mit `[{seq, token, time, status, latency_ms, reason, message, family, details, flags}]`, höchstens 500 je Batch.
- Server: `INSERT IGNORE` (Primärschlüssel enthält `agent_seq`), verwirft Punkte mit `time > now + 5 min` (`reason: future`), antwortet `{ack_seq: <höchste verarbeitete seq>, rejected:[seq...]}`. Agent speichert `ack_seq`.
- Zustand: Der Agent ist für `state_local` zuständig und meldet Statuswechsel als Ereignisse (`POST /agents/me/events`, idempotent über `event_id`; Antwort `{accepted:[...], duplicates:[...]}`). Der Server leitet aus Ereignissen `state_local`, `down_since`, `incident_id` ab. checkd pflegt `state_online`.
- **Gesamtzustand** `state` eines Checks mit `execution both`: down, wenn einer der beiden down ist; Diagnose im Portal: „intern OK, extern gestört → Router/Freigabe/CDN“.
- Rückwirkende Punkte (Agent war offline): werden nach `time` einsortiert; Aggregate der betroffenen Stunden/Tage werden von checkd nachgerechnet (Markierung in `hc2_dirty_hours`).
- Zeit: Agent sendet UTC aus NTP-Zeit; `received_at` setzt der Server. Abweichung > 5 min → Warnung im Portal und im Agent („Uhr des Agents weicht ab“).

### 3.6 Vollabgleich (Repair)

Auslöser: `revision_gap`, Erstverknüpfung, nach Wiederherstellung der Agent-Datenbank, manuell.

1. Outbox hochladen (Messpunkte und Ereignisse), bis `ack_seq` aktuell ist. Offene Konfigurations-Vorschläge als Konflikte vorlegen, nicht verwerfen.
2. `GET /agents/me/config` liefert alles: Checks (eigene und Sicht auf andere), Kanäle (Server-Kanäle nur Typ/Name/Flags, eigene Agent-Kanäle mit entschlüsselter Konfiguration, außer `secret_only_local`), Wartungsfenster, Agent-Einstellungen, `revision`.
3. Agent ersetzt seine Konfiguration (lokale Zustände und Messdaten bleiben), setzt `last_revision`.
4. `GET /agents/me/results?since=<time>` holt Online-Ergebnisse (Aggregate und letzte Ereignisse) für die lokale Ansicht; roh nur die letzten 24 h.

Erstverknüpfung = Repair mit vorherigem `POST /agents/me/bootstrap`: der Agent lädt seine lokalen Checks, Kanäle und Wartungsfenster hoch, der Server legt sie mit `execution local`, `agent_id` an (Token-Kollisionen siehe 3.1), ohne Limitprüfung. Danach gilt der Server als führend.

### 3.7 Heartbeat und Agent-Ausfall

- Jeder Pull aktualisiert `last_seen`. checkd setzt `online = 0`, wenn `last_seen` älter als 3 Minuten ist, und erzeugt ein Ereignis `agent_offline` (Kanäle: Server-Kanäle des Accounts, `ipv64_mail` als Standard). Rückkehr: `agent_online` mit Dauer.
- Während ein Agent offline ist, bleiben seine lokalen Checks im letzten Zustand und werden im Portal grau mit „Agent offline seit …“ gezeigt; sie lösen keine eigenen Alarme aus.

### 3.8 Kommandos Server → Agent (`commands` im Pull)

`run_check {token}`, `pause {token}`, `resume {token}`, `set_log_level {level, minutes}`, `enable_module {name}`, `disable_module {name}`, `set_remote_mgmt`, `update_available {version, url}`, `repair`. Der Agent führt nur aus, was sein lokaler Schalter „Remote-Verwaltung“ erlaubt (`off`: nichts, `read`: nur `update_available`/`repair`, `full`: alles) und antwortet mit `POST /agents/me/commands/{id}/result`.

---

## 4. API v2: Endpunkte für Agents (Ergänzung zu api_v2.php)

Auth: `Authorization: Bearer ipv64ag_...`. Antworten wie in der API v2 (`{data, meta}`, Fehler RFC 9457). Ratenbegrenzung: eigener Bucket je Agent-Token (600/min), Batchgrößen begrenzt.

| Methode | Pfad | Body / Antwort |
| --- | --- | --- |
| POST | `/agents/link/start` | `{agent_id, name, version}` → `{code, poll_secret, expires_at, interval}` (ohne Auth, 5/min je IP) |
| POST | `/agents/link/poll` | `{code, poll_secret}` → `202 pending` oder `{agent_token, account, name, location, remote_mgmt}` |
| GET | `/agents/me` | Agent-Daten, Limits, `remote_mgmt`, `server_time` |
| PATCH | `/agents/me` | `{name, location, version, timezone, modules, outbox_size}` |
| POST | `/agents/me/bootstrap` | `{checks:[...], channels:[...], maintenance:[...]}` → `{renamed:[{old_token,new_token}], revision}` |
| GET | `/agents/me/config` | Vollabgleich (3.6) |
| GET | `/agents/me/pull?since=&wait=` | Long-Poll (3.3): Änderungen, Sendeaufträge, Kommandos; `204` ohne Neuigkeiten; `409 revision_gap` |
| PUT/DELETE | `/agents/me/checks/{token}` | mit `base_revision` (3.4); `409 conflict` liefert Server-Version |
| PUT/DELETE | `/agents/me/channels/{id}`, `/agents/me/maintenance/{id}` | wie Checks |
| POST | `/agents/me/measurements` | Batch ≤ 500 → `{ack_seq, rejected}` |
| POST | `/agents/me/events` | Batch → `{accepted, duplicates}` |
| POST | `/agents/me/deliveries` | Zustellprotokoll der Agent-Kanäle (append-only, idempotent über `event_id+channel_id`) |
| POST | `/agents/me/send-orders/{id}/done` | `{ok, error}` |
| POST | `/agents/me/commands/{id}/result` | `{ok, output}` |
| GET | `/agents/me/results?since=` | Online-Ergebnisse für die lokale Ansicht |
| POST | `/agents/me/unlink` | Entkoppeln (Token widerrufen, Checks bleiben beim Account mit `execution online` oder werden gelöscht, Parameter `keep_checks`) |
| GET | `/push/{token}` und `POST` | Heartbeat (ersetzt `health.php`, der weiter funktioniert) |
| GET | `/agent/latest.json` | Versionsdatei (statisch) |

Portal/Fremdsoftware (Session oder API-Key) bekommen dieselben Ressourcen unter `/healthchecks2/...` (Vorschlag: nach der Umstellung übernimmt der Pfad `/healthchecks` der API v2 das neue Modell; bis dahin v2-Pfad `/hc2/checks` usw.). Die Agent-eigene JSON-API bleibt identisch zur Serverseite (gleiche Feldnamen), damit Skripte lokal und online gleich aussehen.

---

## 5. Benachrichtigungen (hybrid)

| Ereignis | Standalone | Verknüpft, Agent online | Verknüpft, Agent offline |
| --- | --- | --- | --- |
| Lokaler Check down/up | Agent sendet über Agent-Kanäle | Agent meldet Ereignis an Server; **Server** sendet Server-Kanäle und `ipv64_mail`/`ipv64_sms`; Agent-Kanäle sendet der Agent selbst sofort (kein Umweg, kein Sendeauftrag nötig) | Agent sendet Agent-Kanäle lokal (Fallback) und meldet das Ereignis später nach; Server sendet seine Kanäle beim Nachmelden **nur, wenn das Ereignis jünger als 15 min ist** (sonst nur Protokoll) |
| Online-Check down/up | – | checkd sendet Server-Kanäle; Agent-Kanäle als Sendeauftrag an den Agent (Pull) | Sendeauftrag bleibt liegen, verfällt nach 1 h |
| Agent offline/online | – | checkd über Server-Kanäle | – |

- Deduplizierung über `event_id` in `hc2_deliveries (event_id, channel_id)` und im Agent `nf_deliveries`.
- `ipv64_mail`: Absender wie heute (`send_mail`), Empfänger Account-Adresse oder verifizierte Adresse eines Kanals vom Typ `ipv64_mail` mit `config.email`. Nach der Verknüpfung automatisch angelegt und Standard.
- `ipv64_sms`: wie `send_sms` heute, Nummer verifiziert, Tageslimit `sms_limit`.
- Ruhezeiten, Sammelmeldungen, Wiederholungen, Flattern: gleiche Regeln wie im Agent, Einstellungen je Account (`hc2_settings` oder `settings`-Tabelle, Schlüssel `notify.*`).
- Agent-Paket `notify` bekommt zwei weitere Sender: `pushover` und `app` (Firebase, wie heute `mobil`), damit die Typen auf beiden Seiten gleich sind.

---

## 6. Neue Healthcheck-Webseite bei ipv64.net

Pfade während der Umstellung unter `/healthchecks2/...`, nach Abschluss übernehmen sie `/healthcheck`. Technik: PHP wie das Portal (Bootstrap 4, bestehende Pillen-CSS `beat2/gros-bar`), Charts mit Chart.js über die API v2. Die Seiten werden den Agent-Seiten nachempfunden, damit Nutzer sich zurechtfinden.

| Seite | Inhalt |
| --- | --- |
| Übersicht `/healthchecks2` | Kacheln OK/gestört/pausiert/sonstige (je Ausführungsort getrennt zählbar), Tabelle mit Status, Name, Tags, **Badge Ausführungsort** (Online / Agent „Pi im Keller“ / Beides), Typ, Latenz, Pillen (letzte 30 Messungen), letzte Änderung; Filter Status/Typ/Tag/Agent/Ausführungsort, Sortierung, Suche, Massenaktionen; Account-Status-Karte mit Zähler Online-Checks vs. Limit |
| Neu/Bearbeiten `/healthchecks2/new`, `/{token}/edit` | Formular wie im Agent (Typen http, keyword, icmp, tcp, port, cert, push), **Ausführungsort** (Online, Agent X, Beides) mit Testlauf vor dem Umschalten (3.9), Kanäle, Abhängigkeit, Tags, kritisch, Wiederholung |
| Detail `/healthchecks2/{token}` | Pillenleiste groß, Verfügbarkeit 24 h/30 d/1 Jahr, Latenz-Chart (bei „beides“ innen und außen im selben Chart), Ereignisse, Störungen, letzte Messung roh, Push-URL (online **und** lokal, wenn ein Agent zuständig ist), Diagnose-Hinweis bei Abweichung innen/außen |
| Wartungsfenster `/healthchecks2/maintenance` | wie Agent |
| Störungen `/healthchecks2/incidents` | Liste aller Störungen des Accounts (ersetzt `incidents.php`) |
| Benachrichtigungen `/notifications` | Kanäle (ersetzt `integrations.php`): Liste, Anlegen je Typ, Test, Standard, Verifizierung Mail/SMS per Code **nach Login** (kein Link mehr ohne Anmeldung), Ruhezeiten, Zustellprotokoll |
| Agents `/agents` | Liste: Name, Standort, online/offline seit, Version, letzte Synchronisation, Module, Outbox; Detail mit Reitern Healthchecks (Checks dieses Agents, Umwandeln, Remote-Checks anlegen), DynDNS, Reverse-Proxy (später); Aktionen umbenennen, Standort, Token widerrufen, entfernen; Seite `/link` für den Device-Code |
| Statusseiten | bestehende `statuspage.php`/`status.php` liest Zustände aus `hc2_*` (Tokens statt IDs), Design unverändert |
| Öffentliche Seite | `healthcheck_updater_api.php` erweitern um die neue Push-URL und die Agent-Doku |

### 3.9 Umwandeln lokal ↔ online (Portal und Agent)

- lokal → online: Server prüft Limit, führt über checkd einen Testlauf aus (`hc2_testruns`, Ergebnis innerhalb 30 s), private Ziele (RFC 1918, `.local`, `localhost`) werden abgewiesen mit Hinweis auf CDN. Erfolg → `execution = online`, `agent_id` bleibt als Herkunft, Messhistorie bleibt (Zeitleiste markiert „ab hier online“).
- online → lokal: Nutzer wählt Agent; Agent bekommt den Check per Pull, führt Testlauf aus, meldet Ergebnis; erst dann `execution = local`.
- beides: beide Seiten messen, zwei Zustände, ein Gesamtzustand.

---

## 7. Migration und Rollout (Strangler-Fig)

| Schritt | Inhalt | Rückweg |
| --- | --- | --- |
| M0 | Tabellen `hc2_*` anlegen, `users.hc2` Flag, `latest.json` ausliefern | – |
| M1 | `ipv64-checkd` deployen (Go, systemd, zwei Server, Lease), zunächst ohne Nutzer | Dienst stoppen |
| M2 | Migrationsskript `bots/hc2_migrate.php <userid>`: kopiert Checks, Events (7 Tage), Incidents, Integrationen; setzt `users.hc2 = 1`; alte Bots überspringen Accounts mit `hc2 = 1` (`JOIN users ... WHERE hc2 = 0`) | Flag auf 0, alte Bots übernehmen wieder (hc2-Daten bleiben) |
| M3 | Neue Portalseiten unter `/healthchecks2`, Menü zeigt je nach Flag alt oder neu; `health.php` schreibt bei `hc2 = 1` nach `hc2_measurements` + Redis | Flag |
| M4 | API v2: Agent-Endpunkte, Device-Code, `/link`; Agent-Release mit Sync | Agent entkoppeln |
| M5 | Testaccounts (Dennis, Beta-Nutzer) umstellen, zwei Wochen Schattenbetrieb: alte Bots laufen für diese Accounts **zusätzlich weiter, aber ohne Alarme** (Schattenmodus-Flag), Vergleich der Zustände in einem Bot `hc2_compare.php` | Flag |
| M6 | Alle Accounts in Wellen (Free zuletzt), Vergleich beobachten | Flag je Account |
| M7 | Alte Bots abschalten, alte Seiten auf neue umleiten, `integrations.php` abschalten, API v2 Healthcheck-Pfade auf neues Modell | Backup der alten Tabellen bleibt 90 Tage |

Push-URL `health.php?token=` bleibt dauerhaft; sie prüft `hc2` des Besitzers und schreibt entsprechend.

---

## 8. Sicherheit

- Agent-Token nur gehasht, einzeln widerrufbar, Scope auf den eigenen Agent (`agent_id` aus dem Token, nie aus dem Body).
- Alle Agent-Endpunkte prüfen Besitz: Check-Token muss zum Account gehören; fremde Tokens → 404.
- Ratenlimits: Link-Start 5/min je IP, Poll 20/min je Code, Pull 4/min je Agent, Messpunkte 500 je Batch und 60 Batches/min, ungültige Tokens 20/min je IP.
- Remote-Verwaltung: Schalter am Agent, Standard `read`; remote angelegte Checks nur auf freigegebene Subnetze (Agent-Einstellung).
- Geheimnisse von Kanälen: Server-Schlüssel in einer Datei außerhalb des Webroots, AES-GCM wie im Agent; `secret_only_local` respektieren.
- Verifizierung Mail/SMS nur eingeloggt mit Code-Eingabe (Lücke `activate_integration` schließen).
- Datenschutz-Hinweis beim Verknüpfen (interne Ziele landen bei ipv64).

---

## 9. Arbeitspakete, Reihenfolge, Abnahme

| # | Paket | Repo | Abnahme |
| --- | --- | --- | --- |
| 1 | `latest.json` + Versionsprüfung | ipv64 | Agent zeigt Version |
| 2 | `hc2_*` DDL, Migrationsskript, `users.hc2` | ipv64 | Testaccount migriert, Vergleich alt/neu identisch |
| 3 | `cmd/checkd`: MySQL-Store-Adapter für `scheduler.Store`, Lease, Konfig-Log-Polling, Push-Watchdog, Aggregation | Agent-Repo | Online-Checks eines Testaccounts laufen über checkd, Pillen im Portal |
| 4 | `notify`: Sender `pushover`, `app`, `ipv64_mail`, `ipv64_sms` (Server-Backends über HTTP-Hook in PHP oder direkt SMTP/SMS-Gateway) | Agent-Repo | Testnachrichten je Typ |
| 5 | Portal: `/notifications` (Kanäle), Verifizierung | ipv64 | Alte Integrationen migriert, Test-Button |
| 6 | Portal: `/healthchecks2` Übersicht, Detail, Formular, Wartung, Störungen, Statusseite auf `hc2` | ipv64 | Feature-Parität zur alten Seite plus neue Typen |
| 7 | API v2: Agent-Endpunkte, Device-Code, `/link`, `/agents` | ipv64 | Postman-Durchlauf nach Abschnitt 4 |
| 8 | Agent: `internal/sync` echter Client (Link, Pull, Push, Outbox, Konflikte, Repair), UI „ipv64-Verknüpfung“, Ausführungsort-Badge | Agent-Repo | Verknüpfen, offline arbeiten, nachmelden, Konflikt auflösen |
| 9 | Schattenbetrieb und Vergleichsbot | ipv64 | Zwei Wochen ohne Abweichung |
| 10 | Rollout in Wellen, Abschaltung alt | ipv64 | Alte Bots aus |

Reihenfolge: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10. Pakete 3/4 (Go) und 5/6 (PHP) können parallel laufen.

---

## 10. Offene Entscheidungen (bitte festlegen)

1. **Rohdaten der Online-Checks:** 7 Tage in MySQL wie geplant, oder weiter Influx? (Plan: MySQL.)
2. **Agents je Tarif:** Free 1, VIP 3, Business 10, Company 25? Und zählen Checks mit `execution both` doppelt? (Plan: einfach.)
3. **Pfad der neuen Seiten:** `/healthchecks2` während der Umstellung, danach `/healthcheck`? Oder gleich `/monitoring`?
4. **Pushover und App im Agent:** jetzt mit aufnehmen (gleiche Typen überall) oder nur serverseitig?
5. **DNS-Failover** liest künftig `hc2_checks.state`. Soll der Failover-Monitor auch lokale Agent-Checks als Quelle erlauben? (Plan: ja, Zustand kommt ohnehin an.)
6. **Standorte für Online-Checks** (zweiter checkd an anderem Ort) in dieser Runde oder später? (Plan: später, Spalte `location` jetzt schon.)
7. **Long-Poll vs. WebSocket:** Long-Poll über PHP wie geplant; WebSocket nur, wenn die PHP-Worker knapp werden.

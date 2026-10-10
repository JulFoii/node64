# ipv64 Agent

Ein leichtgewichtiger Docker-Container für das Heimnetz: Health-Checks (als Uptime-Kuma-Alternative), später DynDNS-Updater und Reverse-Proxy, standalone oder verknüpft mit einem [ipv64.net](https://ipv64.net)-Account.

Ein einziges Go-Binary, SQLite, eingebettete Weboberfläche, keine externen Abhängigkeiten zur Laufzeit. Läuft auf amd64 und arm64, auch auf einem Raspberry Pi.

**Stand: Phase 4 (Benachrichtigungen).** Fertig sind der Kern (Setup, Login, Modulsystem, Datenbank, Einstellungen, Audit-Log, Logs), alle Check-Typen mit Scheduler, Verdichtung und JSON-API, die Oberfläche für Health-Checks (Liste mit Pillen, Formular, Detailseite mit Chart, Dashboard) und die Benachrichtigungen: E-Mail (SMTP), Telegram, Discord, ntfy, Gotify und Webhook mit verschlüsselten Geheimnissen, Standardkanälen, Kanalwahl je Check, Ruhezeiten, Wiederholung bei anhaltender Störung, Sammelmeldungen, Ratenbegrenzung und Zustellprotokoll. Wartungsfenster-Seite, Backup, Export und 2FA folgen in Phase 5.

## Benachrichtigungen

Kanäle werden unter *Benachrichtigungen* angelegt und getestet. Standardkanäle bekommen alle Checks, die keine eigene Auswahl haben. Texte gehen in der Sprache des Kanals raus (Deutsch oder Englisch). Geheimnisse wie Bot-Tokens oder SMTP-Passwörter liegen verschlüsselt in der Datenbank, der Schlüssel in `/data/secret.key`.

Webhooks bekommen standardmäßig ein JSON mit `event_id`, `kind` (down, up, flapping_start, flapping_end, reminder, summary, test), `status`, `check` (token, name, type, target), `reason`, `message`, `duration_seconds`, `agent` und `url`. Ein eigener Body mit Platzhaltern wie `{{name}}` oder `{{status}}` ist möglich.

Gegen Alarmrauschen wirken Wiederholungen vor Alarm, Stabilisierung, Flatter-Erkennung, Sammelmeldungen ab drei gleichzeitigen Störungen, Ruhezeiten (nur kritische Checks alarmieren) und höchstens 60 Nachrichten je Kanal und Stunde. Links in Nachrichten brauchen die externe Adresse des Agents in den Einstellungen der Benachrichtigungen.

## Schnellstart

```bash
docker run -d --name ipv64-agent \
  -p 8080:8080 \
  -v ipv64-agent-data:/data \
  --restart unless-stopped \
  ghcr.io/ipv64net/agent:latest
```

Danach `http://<host>:8080` öffnen. Beim ersten Start führt ein Assistent durch Sprache und Admin-Konto. Es gibt kein Standardpasswort.

### docker compose

```yaml
services:
  agent:
    image: ghcr.io/ipv64net/agent:latest
    container_name: ipv64-agent
    restart: unless-stopped
    ports:
      - "8080:8080"
      # - "8443:8443"   # optional HTTPS, dazu AGENT_HTTPS_PORT=8443 setzen
    volumes:
      - ipv64-agent-data:/data
    environment:
      AGENT_LOG_LEVEL: info
      # AGENT_HTTPS_PORT: 8443
      # AGENT_ADMIN_USER: admin            # nur beim allerersten Start
      # AGENT_ADMIN_PASSWORD: change-me    # nur beim allerersten Start
    read_only: true
    tmpfs:
      - /tmp
    # Für ICMP-Checks ohne Root: unprivilegiertes Ping erlauben
    sysctls:
      - net.ipv4.ping_group_range=0 65535
volumes:
  ipv64-agent-data:
```

## Health-Checks per API

Das Modul wird in den Einstellungen aktiviert. Die API nutzt die Sitzung der Oberfläche (später zusätzlich API-Keys). Check-Typen: `http`, `keyword`, `icmp`, `tcp`, `port`, `cert`, `push`.

```bash
# Check anlegen
curl -X POST http://localhost:8080/api/checks -H "Content-Type: application/json" -d '{
  "name": "Webseite", "type": "http", "target": "https://example.com/",
  "interval_seconds": 60, "retries": 1, "stabilize": 3,
  "params": {"accept_status": "200-299"}
}'
# Liste, Details, Messpunkte, Ereignisse, Statistik
curl http://localhost:8080/api/checks
curl http://localhost:8080/api/checks/<token>/measurements?limit=50
curl http://localhost:8080/api/checks/<token>/stats?range=24h
# Heartbeat (Push-Check): der Dienst meldet sich selbst
curl http://localhost:8080/api/push/<token>
curl "http://localhost:8080/api/push/<token>?status=down&msg=backup+failed"
```

Weitere Endpunkte: `PUT`/`DELETE /api/checks/{token}`, `POST .../pause|resume|run|clone`, `GET .../events|incidents`, `GET /api/events`, `GET /api/incidents`, `GET|POST /api/maintenance`, `PUT|DELETE /api/maintenance/{id}`.

ICMP-Checks brauchen im Container entweder unprivilegiertes Ping (`sysctls: net.ipv4.ping_group_range=0 65535`, siehe compose oben) oder `cap_add: NET_RAW`.

## Umgebungsvariablen

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `AGENT_DATA_DIR` | `/data` | Einziges beschreibbares Verzeichnis: Datenbank, Backups, Schlüssel, Zertifikat |
| `AGENT_HTTP_PORT` | `8080` | Port der Oberfläche, `0` = aus |
| `AGENT_HTTPS_PORT` | `0` | Port für HTTPS mit selbstsigniertem Zertifikat, `0` = aus |
| `AGENT_BIND_ADDR` | leer (alle) | Bind-Adresse |
| `AGENT_TLS_CERT` / `AGENT_TLS_KEY` | leer | Eigenes Zertifikat statt des selbstsignierten |
| `AGENT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`; zur Laufzeit im UI änderbar |
| `AGENT_LOG_FORMAT` | `text` | `text` oder `json` |
| `AGENT_ADMIN_USER` / `AGENT_ADMIN_PASSWORD` | leer | Admin beim allerersten Start anlegen; danach ignoriert |
| `AGENT_TRUST_PROXY` | `false` | `X-Forwarded-For` auswerten, nur hinter eigenem Reverse Proxy |

## Sicherheit

- Laufzeit-Image `FROM scratch`: kein OS, keine Shell, nur das Binary. Nicht-Root (UID 65532), Root-FS read-only, nur `/data` beschreibbar.
- Passwörter mit argon2id, Sitzungen in der Datenbank, CSRF-Schutz, Login-Ratelimit, Security-Header, Content-Security-Policy ohne externe Quellen.
- Geheimnisse (später Kanal-Tokens, SMTP-Passwörter) werden mit einem Schlüssel aus `/data/secret.key` verschlüsselt. Im Log werden sie maskiert.
- Vor jeder Datenbank-Migration wird automatisch ein Backup nach `/data/backups` geschrieben.
- Keine Telemetrie. Versionsprüfung gegen ipv64 nur nach Opt-in (folgt).

## Entwicklung

Voraussetzung: Go 1.27 oder neuer. Kein CGO nötig.

```bash
make build          # Binary nach bin/agent
make test           # Tests
make run            # lokal mit ./data und Debug-Log
make docker         # Image für die eigene Architektur
make docker-multiarch PUSH=--push   # amd64 + arm64 über buildx
```

Projektstruktur:

```
cmd/agent/          main, Subcommands (healthcheck, version)
internal/checks/    Check-Bot (Phase 2), ohne Abhängigkeit zu web/store/scheduler/notify
internal/scheduler/ Intervalle, Retry, Worker-Pool, Zustandsautomat (Phase 2)
internal/store/     SQLite, Migrationen je Scope, Backups
internal/notify/    Benachrichtigungskanäle (Phase 4)
internal/web/       Handler, Templates, Sessions, Static (alles eingebettet)
internal/module/    Modulsystem mit Start/Stop zur Laufzeit
internal/i18n/      Sprachdateien de und en
internal/sync/      Stub für die spätere ipv64-Anbindung
internal/config/    Umgebungsvariablen
internal/logging/   slog mit Laufzeit-Level, Ringpuffer und Maskierung
```

## Lizenz

Apache-2.0, siehe [LICENSE](LICENSE).

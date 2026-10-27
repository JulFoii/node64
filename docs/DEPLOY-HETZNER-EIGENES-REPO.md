# Node64 auf Hetzner aus dem eigenen Repository betreiben

Diese Anleitung baut Node64 direkt aus deinem Git-Repository auf dem Hetzner-Server. Sie verwendet nicht das vorgefertigte Image `ghcr.io/ipv64net/node64:latest`. Änderungen in deinem Branch – etwa die Netzwerkübersicht – sind nach dem Build unmittelbar enthalten.

Die Beispiele gelten für Debian/Ubuntu mit Docker Engine und Docker Compose Plugin.

## Einmalig einrichten

Docker installieren und prüfen:

```bash
docker --version
docker compose version
```

### Go für Tests installieren (optional)

Der Docker-Build verwendet den Go-Builder aus dem `Dockerfile`; für `go test ./...` und `go vet ./...` auf dem
Server ist Go nur zusätzlich nötig. Node64 baut derzeit mit Go 1.27. Ersetze die Patch-Version unten gegebenenfalls
durch die aktuelle 1.27-Version von [go.dev/dl](https://go.dev/dl/).

```bash
sudo apt update
sudo apt install -y curl ca-certificates

# x86_64 bei den meisten Hetzner-Cloud-Servern; für ARM-Server: ARCH=arm64
ARCH=amd64
GO_VERSION=1.27.0
curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"

# Nur eine vorhandene manuelle Go-Installation an dieser Stelle ersetzen.
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${ARCH}.tar.gz"
rm "go${GO_VERSION}.linux-${ARCH}.tar.gz"

echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
source /etc/profile.d/go.sh
go version
```

Mit `uname -m` lässt sich die Architektur prüfen: `x86_64` entspricht `amd64`, `aarch64` entspricht `arm64`.

Das Repository in ein dauerhaftes Verzeichnis klonen. Für private Repositories sollte der Server einen ausschließlich lesenden Deploy-Key verwenden.

```bash
sudo mkdir -p /opt/node64
sudo chown "$USER":"$USER" /opt/node64
git clone <DEINE-REPOSITORY-URL> /opt/node64
cd /opt/node64
```

Lege im Repository `compose.yaml` an:

```yaml
services:
  node:
    # Dieses Image wird aus dem lokalen Checkout gebaut.
    image: ${NODE64_IMAGE:-node64:local}
    build:
      context: .
      dockerfile: Dockerfile
    container_name: node64
    restart: unless-stopped
    ports:
      # Sicherer Standard für einen Reverse Proxy auf demselben Server:
      - "127.0.0.1:8080:8080"
      # - "127.0.0.1:8443:8443" # mit NODE64_HTTPS_PORT=8443
    volumes:
      - node64-data:/data
      # Nur für Docker-Container-Checks:
      # - /var/run/docker.sock:/var/run/docker.sock:ro
    # group_add:
    #   - "${DOCKER_GID}"
    environment:
      NODE64_LOG_LEVEL: info
    read_only: true
    tmpfs:
      - /tmp
    sysctls:
      - net.ipv4.ping_group_range=0 65535

volumes:
  node64-data:
```

Das Docker-Volume `node64-data` enthält die produktiven Node64-Daten und bleibt bei Image-, Container- und Repository-Updates erhalten.

## Eigenes Image bauen und starten

Die Tests sind optional und benötigen Go auf dem Server. Der Docker-Build selbst bringt seinen Go-Builder bereits mit.

```bash
cd /opt/node64
go test ./...
go vet ./...
```

Das Image bekommt den aktuellen Commit als Tag und wird danach gestartet:

```bash
export NODE64_IMAGE="node64:$(git rev-parse --short HEAD)"
docker compose build --pull node
docker compose up -d --no-build node
docker compose ps
docker compose logs -f node
```

Beim ersten Start Node64 über den Reverse Proxy öffnen und den Einrichtungsassistenten abschließen. Ohne Proxy kannst du für die kurze Einrichtung `127.0.0.1:8080:8080` temporär zu `8080:8080` ändern und danach wieder zurückstellen.

## Reverse Proxy und Firewall

Die Verwaltungsoberfläche sollte nicht direkt über Port 8080 öffentlich sein. Die Compose-Datei bindet sie daher nur an `127.0.0.1`; ein vorhandener Caddy-, nginx- oder Traefik-Proxy leitet intern auf `http://127.0.0.1:8080` weiter.

In der Hetzner-Firewall nur die Ports des Reverse Proxys (gewöhnlich TCP 80/443) und SSH aus vertrauenswürdigen Netzen freigeben. Für die Verwaltungsoberfläche sind VPN oder eine Zugriffsliste im Reverse Proxy empfehlenswert.

DNS64, DoT und DoQ benötigen bei Verwendung zusätzliche Ports und Netzwerkkonfiguration; sie werden nicht durch diese Compose-Datei veröffentlicht.

## Netzwerkübersicht aktivieren

1. Bei Node64 anmelden.
2. Unter **Einstellungen → Module** **Healthchecks** aktivieren.
3. **Healthchecks → Netzwerkübersicht** öffnen.

Docker- und Proxmox-Knoten erscheinen, sobald ihre vorhandene Überwachung eingerichtet ist und Daten abgefragt hat. Die Übersicht führt keine Port-, ARP- oder SNMP-Scans aus.

## Update aus deinem Branch

Vor einem Update ein verschlüsseltes Node64-Backup über **Einstellungen → Daten & Sicherung** erstellen und außerhalb des Servers ablegen. Danach aktualisieren und bauen:

```bash
cd /opt/node64
current_image="$(docker inspect -f '{{.Config.Image}}' node64)"
docker image tag "$current_image" node64:previous
git fetch --prune origin
git switch main
git pull --ff-only

export NODE64_IMAGE="node64:$(git rev-parse --short HEAD)"
docker compose build --pull node
docker compose up -d --no-build --force-recreate node
docker compose logs --tail=100 node
```

Die Daten im Volume bleiben erhalten. Nicht mehr benötigte Images erst löschen, wenn der neue Container stabil läuft.

### Rollback

Falls der neue Build nicht sauber startet, wird nur das Image zurückgedreht – nicht das Datenvolume:

```bash
cd /opt/node64
NODE64_IMAGE=node64:previous docker compose up -d --no-build --force-recreate node
docker compose logs -f node
```

Bei Datenbankmigrationen kann für ein vollständiges Rollback zusätzlich das zuvor erzeugte Node64-Backup nötig sein.

## Optional: Docker-Container in der Netzwerkübersicht

Aktiviere Socket-Mount und Socket-Gruppe nur, wenn Node64 Docker-Container überwachen soll:

```bash
cd /opt/node64
printf 'DOCKER_GID=%s\n' "$(stat -c %g /var/run/docker.sock)" >> .env
```

Entferne anschließend die Kommentarzeichen vor Socket-Mount und `group_add` in `compose.yaml` und starte neu:

```bash
export NODE64_IMAGE="$(docker inspect -f '{{.Config.Image}}' node64)"
docker compose up -d --no-build --force-recreate node
```

Der Mount ist schreibgeschützt, gewährt aber Einblick in Docker-Metadaten. Er sollte nur auf einem Server verwendet werden, dessen Docker-Umgebung du verwaltest.

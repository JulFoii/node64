#!/bin/bash
# Baut cmd/hub fuer Linux/amd64 und spielt es auf die hub-Server (SSH-Hosts hub1 hub2) ein.
# Rolling: ein Server nach dem anderen, Rollback mit hub.prev moeglich.
# Aufruf: bash deploy/server/hub-deploy.sh [version] [hosts...]
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${1:-$(git describe --tags --always 2>/dev/null || echo dev)}
shift || true
HOSTS=${*:-"hub1 hub2"}
export PATH="/c/Program Files/Go/bin:$PATH"
echo "== build $VERSION"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o build/hub-linux-amd64 ./cmd/hub
for H in $HOSTS; do
  echo "== $H"
  scp -q build/hub-linux-amd64 "$H:/opt/ipv64-hub/hub.new"
  ssh "$H" 'set -e; cd /opt/ipv64-hub; chmod 755 hub.new; [ -f hub ] && mv -f hub hub.prev || true; mv hub.new hub; chown root:root hub
    systemctl restart ipv64-hub; sleep 3; systemctl is-active ipv64-hub >/dev/null || { echo "START FAILED, rollback"; journalctl -u ipv64-hub -n 20 --no-pager; [ -f hub.prev ] && mv -f hub.prev hub && systemctl restart ipv64-hub; exit 1; }
    curl -s http://127.0.0.1:9000/v1/health; echo'
done
echo "== done"

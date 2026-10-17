#!/bin/bash
# Baut cmd/cdn64-edge fuer Linux/amd64 und spielt es auf die CDN64-Server (SSH-Hosts cdn7 cdn8) ein.
# Rolling: ein Server nach dem anderen; startet der neue Dienst nicht oder antwortet /health nicht, geht der Server
# auf die vorige Version zurueck und das Deploy bricht ab (der naechste Server bleibt unberuehrt).
# Aufruf: bash deploy/server/edge-deploy.sh [version] [hosts...]
# BIN=<datei> nimmt ein fertiges Binary statt zu bauen (z. B. fuer den Rollback-Test).
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${1:-$(git describe --tags --always 2>/dev/null || echo dev)}
shift || true
HOSTS=${*:-"cdn7 cdn8"}
export PATH="/c/Program Files/Go/bin:$PATH"
if [ -z "${BIN:-}" ]; then
  echo "== build $VERSION"
  mkdir -p build
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o build/cdn64-edge-linux-amd64 ./cmd/cdn64-edge
  BIN=build/cdn64-edge-linux-amd64
fi
for H in $HOSTS; do
  echo "== $H"
  scp -q "$BIN" "$H:/opt/cdn64-edge/cdn64-edge.new"
  ssh "$H" 'set -e; cd /opt/cdn64-edge; chmod 755 cdn64-edge.new; chown root:root cdn64-edge.new
    [ -f cdn64-edge ] && cp -f cdn64-edge cdn64-edge.prev || true; mv -f cdn64-edge.new cdn64-edge
    systemctl restart cdn64-edge
    ok=""; for i in $(seq 1 20); do sleep 0.5; systemctl is-active -q cdn64-edge && curl -sf -m 2 http://127.0.0.1/health >/dev/null && { ok=1; break; }; done
    if [ -z "$ok" ]; then
      echo "START FAILED, rollback"; journalctl -u cdn64-edge -n 15 --no-pager || true
      if [ -f cdn64-edge.prev ]; then cp -f cdn64-edge.prev cdn64-edge; systemctl restart cdn64-edge; sleep 2; curl -s -m 2 http://127.0.0.1/health; echo; fi
      exit 1
    fi
    curl -s -m 2 http://127.0.0.1/health; echo'
done
echo "== done"

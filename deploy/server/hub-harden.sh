#!/bin/bash
# Haertung eines hub-Servers (Debian 13). Idempotent, mehrfach ausfuehrbar; legt vor jeder Aenderung eine Sicherung
# (*.bak-harden-<Zeit>) an und prueft jede Konfiguration vor dem Neuladen (nginx -t, sshd -t, nft -c).
# Aufruf auf dem hub: bash hub-harden.sh "<IPs aller hubs, Leerzeichen-getrennt>"
#   - nginx: Anfragen- und Verbindungslimits je IP (andere hubs ausgenommen), kurze Timeouts (server_tokens off steht
#     schon in Debians nginx.conf)
#   - SSH: nur Schluessel, wenige Versuche; nftables bremst neue SSH-Verbindungen je Quell-IP
# Die Site wird aus nginx-hub.conf.tmpl neu erzeugt (liegt neben diesem Skript).
set -euo pipefail
HUB_IPS=${1:?IPs aller hubs}
DIR=$(cd "$(dirname "$0")" && pwd)
TS=$(date +%Y%m%d-%H%M%S)
HOST=$(awk '/^public_host:/ {print $2}' /etc/ipv64-hub/config.yaml)
[ -n "$HOST" ] || { echo "public_host fehlt in /etc/ipv64-hub/config.yaml"; exit 1; }
bak() { [ -f "$1" ] && cp -a "$1" "$1.bak-harden-$TS" || true; }

# ---- nginx
LIM=/etc/nginx/conf.d/hub-limits.conf
SITE=/etc/nginx/sites-available/hub.conf
bak "$LIM"; bak "$SITE"
{
  echo "# hub-harden.sh: Limits je IP, andere hubs ausgenommen (leerer Schluessel = kein Limit)"
  echo "geo \$hub_limited {"
  echo "    default 1;"
  for ip in $HUB_IPS; do echo "    $ip 0;"; done
  echo "    127.0.0.1 0;"
  echo "    ::1 0;"
  echo "}"
  cat <<'EOF'
map $hub_limited $hub_key {
    0 "";
    1 $binary_remote_addr;
}
limit_req_zone  $hub_key zone=hub_req:20m  rate=20r/s;  # API, WebSocket, Push
limit_req_zone  $hub_key zone=hub_misc:10m rate=2r/s;   # Infoseite, Scanner, Port 80
limit_conn_zone $hub_key zone=hub_conn:20m;
limit_req_status  429;
limit_conn_status 429;
limit_req_log_level warn;
# langsame Verbindungen (Slowloris) nicht ewig offen halten
client_header_timeout 15s;
client_body_timeout   15s;
send_timeout          30s;
keepalive_timeout     30s;
EOF
} > "$LIM.new"
sed "s/__HOST__/$HOST/g" "$DIR/nginx-hub.conf.tmpl" > "$SITE.new"
mv "$LIM.new" "$LIM"; mv "$SITE.new" "$SITE"
ln -sf "$SITE" /etc/nginx/sites-enabled/hub.conf
if ! nginx -t 2>/tmp/nginx-t.log; then
  cat /tmp/nginx-t.log; echo "nginx-Konfiguration fehlerhaft – Sicherung zurueck"
  [ -f "$LIM.bak-harden-$TS" ] && mv -f "$LIM.bak-harden-$TS" "$LIM" || rm -f "$LIM"
  [ -f "$SITE.bak-harden-$TS" ] && mv -f "$SITE.bak-harden-$TS" "$SITE"
  exit 1
fi
systemctl reload nginx
echo "nginx: Limits aktiv"

# ---- SSH: nur Schluessel (root ohnehin nur mit Schluessel), wenige Versuche
SSHD=/etc/ssh/sshd_config.d/00-ipv64-hardening.conf
bak "$SSHD"
cat > "$SSHD" <<'EOF'
# hub-harden.sh (erste Angabe gewinnt, daher 00-)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
EOF
if ! sshd -t; then
  echo "sshd-Konfiguration fehlerhaft – zurueck"; rm -f "$SSHD"; [ -f "$SSHD.bak-harden-$TS" ] && mv -f "$SSHD.bak-harden-$TS" "$SSHD"; exit 1
fi
systemctl reload ssh
echo "ssh: nur Schluessel"

# ---- nftables: neue SSH-Verbindungen je Quell-IP bremsen (Brute Force), Rest unveraendert
NFT=/etc/nftables.conf
if ! grep -q "meter ssh4" "$NFT"; then
  bak "$NFT"
  sed "s/^\(\s*\)tcp dport 22 accept$/\1tcp dport 22 ct state new meter ssh4 size 65535 { ip saddr limit rate over 20\/minute burst 40 packets } counter drop\n\1tcp dport 22 ct state new meter ssh6 size 65535 { ip6 saddr limit rate over 20\/minute burst 40 packets } counter drop\n\1tcp dport 22 accept/" "$NFT" > "$NFT.new"
  grep -q "meter ssh4" "$NFT.new" || { echo "Regel 'tcp dport 22 accept' nicht gefunden – nftables unveraendert"; rm -f "$NFT.new"; exit 1; }
  if nft -c -f "$NFT.new"; then
    mv "$NFT.new" "$NFT"; nft -f "$NFT"; echo "nftables: SSH-Bremse aktiv"
  else
    rm -f "$NFT.new"; echo "nftables-Pruefung fehlgeschlagen – unveraendert"; exit 1
  fi
else
  echo "nftables: SSH-Bremse schon da"
fi
echo "fertig ($HOST)"

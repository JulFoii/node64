#!/bin/bash
# Grundeinrichtung eines hub-Servers (Debian 13). Idempotent, mehrfach ausfuehrbar.
# Aufruf: bash setup-hub.sh <location: fsn|nbg> <oeffentlicher Hostname> <private IP> [redis: yes|no]
# Macht KEINE Firewall-Aenderungen an Port 22 ausser "offen" und startet den hub nicht (Binary kommt spaeter).
set -euo pipefail
LOCATION=${1:?location}; HOST=${2:?hostname}; PRIV=${3:?private ip}; REDIS=${4:-no}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx certbot python3-certbot-nginx nftables mariadb-client curl jq ca-certificates redis-server >/dev/null
timedatectl set-timezone UTC || true
systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true

# Dienstbenutzer und Verzeichnisse
id -u ipv64-hub >/dev/null 2>&1 || useradd --system --home /var/lib/ipv64-hub --shell /usr/sbin/nologin ipv64-hub
install -d -o root -g ipv64-hub -m 750 /etc/ipv64-hub
install -d -o ipv64-hub -g ipv64-hub -m 750 /var/lib/ipv64-hub
install -d -o root -g root -m 755 /opt/ipv64-hub

# Konfigurationsgeruest (Geheimnisse traegt Dennis bzw. das Deploy ein)
if [ ! -f /etc/ipv64-hub/config.yaml ]; then
cat > /etc/ipv64-hub/config.yaml <<EOF
# ipv64-hub Konfiguration (root:ipv64-hub 640). Geheimnisse nur hier, nie im Repo.
node_name: $(hostname)
location: ${LOCATION}
public_host: ${HOST}
listen: 127.0.0.1:9000
roles: [checker, gateway]
mysql:
  dsn: "HUBUSER:HUBPASS@tcp(10.100.0.110:3306)/HC2DB?parseTime=true&loc=UTC&tls=preferred"
redis:
  addr: "10.10.0.11:6379"
  password: ""
secret_key_file: /var/lib/ipv64-hub/secret.key
limits:
  max_connections: 20000
  checker_workers: 200
EOF
chown root:ipv64-hub /etc/ipv64-hub/config.yaml; chmod 640 /etc/ipv64-hub/config.yaml
fi

# systemd-Unit (Start erst, wenn /opt/ipv64-hub/hub liegt)
cat > /etc/systemd/system/ipv64-hub.service <<'EOF'
[Unit]
Description=ipv64 hub (Healthchecks 2.0: gateway + checker)
After=network-online.target
Wants=network-online.target

[Service]
User=ipv64-hub
Group=ipv64-hub
ExecStart=/opt/ipv64-hub/hub -config /etc/ipv64-hub/config.yaml
Restart=always
RestartSec=2
LimitNOFILE=200000
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/ipv64-hub
Environment=GOMAXPROCS=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# nginx: nur /v1/* an den hub, Rest 404; TLS kommt per certbot (HTTP-01) dazu
cat > /etc/nginx/sites-available/hub.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${HOST};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
ln -sf /etc/nginx/sites-available/hub.conf /etc/nginx/sites-enabled/hub.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t >/dev/null && systemctl reload nginx

# Redis: nur auf dem Redis-Knoten (nbg) aktiv, privat gebunden, Passwort in Datei
if [ "$REDIS" = "yes" ]; then
  if [ ! -f /etc/ipv64-hub/redis.pass ]; then
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 > /etc/ipv64-hub/redis.pass
    chown root:ipv64-hub /etc/ipv64-hub/redis.pass; chmod 640 /etc/ipv64-hub/redis.pass
  fi
  PASS=$(cat /etc/ipv64-hub/redis.pass)
  cat > /etc/redis/redis.conf.d-ipv64.conf 2>/dev/null <<EOF || true
EOF
  sed -i "s/^bind .*/bind 127.0.0.1 ::1 ${PRIV}/" /etc/redis/redis.conf
  grep -q '^requirepass' /etc/redis/redis.conf && sed -i "s/^requirepass .*/requirepass ${PASS}/" /etc/redis/redis.conf || echo "requirepass ${PASS}" >> /etc/redis/redis.conf
  sed -i 's/^save .*/save ""/; s/^appendonly .*/appendonly no/; s/^# maxmemory <bytes>/maxmemory 256mb/; s/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
  grep -q '^maxmemory ' /etc/redis/redis.conf || echo 'maxmemory 256mb' >> /etc/redis/redis.conf
  grep -q '^maxmemory-policy ' /etc/redis/redis.conf || echo 'maxmemory-policy allkeys-lru' >> /etc/redis/redis.conf
  systemctl enable --now redis-server >/dev/null; systemctl restart redis-server
else
  systemctl disable --now redis-server >/dev/null 2>&1 || true
fi

# Firewall: 22 offen (Admin-IPs spaeter einschraenken), 80/443 offen, Redis nur aus 10.10.0.0/24, ICMP erlaubt
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    tcp dport 22 accept
    tcp dport { 80, 443 } accept
    ip saddr 10.10.0.0/24 tcp dport 6379 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
EOF
nft -f /etc/nftables.conf && systemctl enable nftables >/dev/null

echo "setup ok: $(hostname) location=${LOCATION} host=${HOST} priv=${PRIV} redis=${REDIS}"

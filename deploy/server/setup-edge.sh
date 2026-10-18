#!/bin/bash
# Grundeinrichtung eines CDN64-Servers (srv07/srv08.cdn64.de, Debian 13). Idempotent, mehrfach ausfuehrbar.
# Aufruf: bash setup-edge.sh <name: srv07|srv08> <location: nbg|fsn> <oeffentlicher Hostname> [Nachbar-IPv4] [Nachbar-IPv6]
# Aendert sshd nicht und startet den Dienst erst, wenn das Binary liegt (edge-deploy.sh).
# Planung: docs/CDN64-ONLINE.md (Abschnitt 10, Phase T0).
set -euo pipefail
NAME=${1:?name}; LOCATION=${2:?location}; HOST=${3:?hostname}; PEER4=${4:-}; PEER6=${5:-}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables curl jq ca-certificates unattended-upgrades >/dev/null
timedatectl set-timezone UTC || true
systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true

# Sicherheitsupdates automatisch (nur Debian-Security, ohne automatischen Neustart)
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

# Dienstbenutzer und Verzeichnisse
id -u cdn64-edge >/dev/null 2>&1 || useradd --system --home /var/lib/cdn64-edge --shell /usr/sbin/nologin cdn64-edge
install -d -o root -g cdn64-edge -m 750 /etc/cdn64-edge
install -d -o cdn64-edge -g cdn64-edge -m 750 /var/lib/cdn64-edge
install -d -o root -g root -m 755 /opt/cdn64-edge

# Konfigurationsgeruest (Geheimnisse kommen ab T3 dazu, nur hier, nie im Repo)
if [ ! -f /etc/cdn64-edge/config.yaml ]; then
cat > /etc/cdn64-edge/config.yaml <<EOF
# cdn64-edge Konfiguration (root:cdn64-edge 640)
name: ${NAME}
location: ${LOCATION}
public_host: ${HOST}
listen_http: ":80"
data_dir: /var/lib/cdn64-edge
log_level: info
EOF
chown root:cdn64-edge /etc/cdn64-edge/config.yaml; chmod 640 /etc/cdn64-edge/config.yaml
fi

# Kernel: grosse UDP-Puffer fuer QUIC, SYN-Cookies, Warteschlangen, Conntrack fuer viele Verbindungen
cat > /etc/sysctl.d/90-cdn64-edge.conf <<'EOF'
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
net.ipv4.tcp_syncookies = 1
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384
net.ipv4.ip_local_port_range = 10240 65535
net.netfilter.nf_conntrack_max = 524288
EOF
modprobe nf_conntrack 2>/dev/null || true
sysctl -q --system >/dev/null || echo "sysctl: nicht alle Werte gesetzt"

# systemd-Unit (Start erst, wenn /opt/cdn64-edge/cdn64-edge liegt)
cat > /etc/systemd/system/cdn64-edge.service <<'EOF'
[Unit]
Description=CDN64 edge (Eingang und Tunnel-Ende fuer CDN64 online)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/cdn64-edge/cdn64-edge

[Service]
User=cdn64-edge
Group=cdn64-edge
ExecStart=/opt/cdn64-edge/cdn64-edge -config /etc/cdn64-edge/config.yaml
Restart=always
RestartSec=2
TimeoutStopSec=30
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
ReadWritePaths=/var/lib/cdn64-edge

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable cdn64-edge >/dev/null 2>&1 || true

# Firewall: 22 (neue Verbindungen je Absender gebremst), 80/443 TCP, 443 UDP (HTTP/3, Tunnel per ALPN), 7844 TCP/UDP (Tunnel),
# 7845 TCP nur vom Nachbarserver, 50000-62000 TCP/UDP (Portmapper, Modus 3), ICMP; alles andere zu.
PEERRULES=""
[ -n "$PEER4" ] && PEERRULES="${PEERRULES}    ip saddr ${PEER4} tcp dport 7845 accept
"
[ -n "$PEER6" ] && PEERRULES="${PEERRULES}    ip6 saddr ${PEER6} tcp dport 7845 accept
"
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  # SSH: neue Verbindungen je Absender begrenzt (Scanner aus dem Internet sperren so nicht den Admin aus)
  set ssh4 { type ipv4_addr; flags dynamic, timeout; timeout 10m; size 65536; }
  set ssh6 { type ipv6_addr; flags dynamic, timeout; timeout 10m; size 65536; }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } limit rate 50/second accept
    ip6 nexthdr icmpv6 accept
    tcp dport 22 ct state new add @ssh4 { ip saddr limit rate 10/minute burst 20 packets } accept
    tcp dport 22 ct state new add @ssh6 { ip6 saddr limit rate 10/minute burst 20 packets } accept
    tcp dport { 80, 443, 7844 } accept
    udp dport { 443, 7844 } accept
    meta l4proto { tcp, udp } th dport 50000-62000 accept
${PEERRULES}  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
EOF
nft -c -f /etc/nftables.conf
nft -f /etc/nftables.conf && systemctl enable nftables >/dev/null 2>&1

echo "setup ok: $(hostname) name=${NAME} location=${LOCATION} host=${HOST}"

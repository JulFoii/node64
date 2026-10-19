#!/bin/sh
# IPv64.net blocklist for nftables (IPv4 + IPv6) - https://ipv64.net/v64_blocklist_integration_guide
# Usage: ipv64-blocklist-nft.sh [list]   (default: firehole_l1, see https://ipv64.net/v64_blocklists)
# Run as root. Replaces table "inet ipv64" atomically; on a failed download the old sets stay active.
set -eu
LIST="${1:-firehole_l1}"
BASE="https://ipv64.net/blocklists"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for v in 4 6; do
	curl -fsS --max-time 120 -o "$TMP/raw$v" "$BASE/ipv64_blocklist_v${v}_${LIST}.txt"
	# only keep lines that look like an address or network
	grep -E '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' "$TMP/raw$v" > "$TMP/v$v" || true
done
if [ ! -s "$TMP/v4" ] && [ ! -s "$TMP/v6" ]; then
	echo "ipv64-blocklist: download empty, keeping the active sets" >&2
	exit 1
fi

elements() { # file -> "elements = { a, b, ... }" (nothing for an empty file)
	[ -s "$1" ] || return 0
	printf '\t\telements = { '
	paste -sd, "$1" | sed 's/,/, /g'
	printf ' }\n'
}

{
	echo "table inet ipv64"
	echo "delete table inet ipv64"
	echo "table inet ipv64 {"
	printf '\tset bl4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n'
	elements "$TMP/v4"
	printf '\t}\n\tset bl6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n'
	elements "$TMP/v6"
	printf '\t}\n'
	# drop traffic FROM listed networks to this host and to forwarded/NATed hosts (routers, Docker)
	printf '\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n\t\tip saddr @bl4 counter drop\n\t\tip6 saddr @bl6 counter drop\n\t}\n'
	printf '\tchain forward {\n\t\ttype filter hook forward priority -10; policy accept;\n\t\tip saddr @bl4 counter drop\n\t\tip6 saddr @bl6 counter drop\n\t}\n'
	echo "}"
} > "$TMP/ipv64.nft"

nft -f "$TMP/ipv64.nft"
echo "ipv64-blocklist: $LIST loaded ($(wc -l < "$TMP/v4") IPv4, $(wc -l < "$TMP/v6") IPv6 entries)"

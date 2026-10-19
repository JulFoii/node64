#!/bin/sh
# IPv64.net blocklist for iptables + ipset (IPv4 + IPv6) - https://ipv64.net/v64_blocklist_integration_guide
# Usage: ipv64-blocklist-ipset.sh [list]   (default: firehole_l1, see https://ipv64.net/v64_blocklists)
# Run as root. Loads the list into a new set and swaps it in; on a failed download the old set stays active.
set -eu
LIST="${1:-firehole_l1}"
BASE="https://ipv64.net/blocklists"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for v in 4 6; do
	fam=inet; ipt=iptables
	[ "$v" = 6 ] && { fam=inet6; ipt=ip6tables; }
	set="ipv64-v$v"; new="ipv64-v$v-new"
	curl -fsS --max-time 120 -o "$TMP/raw" "$BASE/ipv64_blocklist_v${v}_${LIST}.txt"
	grep -E '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' "$TMP/raw" > "$TMP/list" || true
	n=$(wc -l < "$TMP/list")
	if [ "$n" -eq 0 ] && [ "$v" = 4 ]; then
		echo "ipv64-blocklist: IPv4 download empty, keeping the active set" >&2
		exit 1
	fi
	ipset create -exist "$set" hash:net family "$fam" maxelem 1048576
	ipset destroy "$new" 2>/dev/null || true
	{ echo "create $new hash:net family $fam maxelem 1048576"; sed "s/^/add $new /" "$TMP/list"; } | ipset restore -exist
	ipset swap "$new" "$set"
	ipset destroy "$new"
	# rules only once: -C checks whether the rule exists already
	for chain in INPUT FORWARD; do
		$ipt -C "$chain" -m set --match-set "$set" src -j DROP 2>/dev/null || $ipt -I "$chain" -m set --match-set "$set" src -j DROP
	done
	# Docker publishes ports through DOCKER-USER, not INPUT
	if $ipt -nL DOCKER-USER >/dev/null 2>&1; then
		$ipt -C DOCKER-USER -m set --match-set "$set" src -j DROP 2>/dev/null || $ipt -I DOCKER-USER -m set --match-set "$set" src -j DROP
	fi
	echo "ipv64-blocklist: $set ($LIST) loaded with $n entries"
done

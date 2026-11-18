#!/usr/bin/env bash
# Real-traffic tests for fwg (tier 3 in STACK_NOTES.md).
#
# Run as root of a fresh user + network namespace, never on the host:
#   unshare -rn bash fwg/tests/netns/traffic.sh path/to/fwg
#
# The network (server here, client in a child namespace) comes from
# tests/netns/harness.sh.
set -euo pipefail

FWG_BIN="$(realpath "$1")"
# shellcheck source=../../../tests/netns/harness.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../../tests/netns/harness.sh"

fwg() { "$FWG_BIN" --config-dir "$WORK/etc" "$@" >/dev/null; }

# --- tests -------------------------------------------------------------------
echo "no firewall"
check "tcp 2222 reachable" OPEN "$(in4 tcp 2222)"

echo "enable with default deny incoming"
fwg enable --force
check "tcp 2222 dropped (v4)" TIMEOUT "$(in4 tcp 2222)"
check "tcp 2222 dropped (v6)" TIMEOUT "$(in6 tcp 2222)"
check "udp 5353 dropped" TIMEOUT "$(in4 udp 5353)"
check "outgoing still allowed" OPEN "$(out4 9090)"

echo "allow rules"
fwg allow 2222/tcp
fwg allow 5353/udp
check "allow 2222/tcp (v4)" OPEN "$(in4 tcp 2222)"
check "allow 2222/tcp (v6)" OPEN "$(in6 tcp 2222)"
check "allow 5353/udp" OPEN "$(in4 udp 5353)"
check "tcp 8080 still dropped" TIMEOUT "$(in4 tcp 8080)"

echo "reject rule"
fwg reject 8080/tcp
check "reject 8080/tcp answers with a reset" REFUSED "$(in4 tcp 8080)"
fwg delete reject 8080/tcp

echo "rule order: deny the client's IPv4 address first"
fwg insert 1 deny from 10.99.0.2
check "v4 client denied" TIMEOUT "$(in4 tcp 2222)"
check "v6 client unaffected" OPEN "$(in6 tcp 2222)"
fwg delete 1
check "v4 client allowed again" OPEN "$(in4 tcp 2222)"

echo "interface rule"
fwg allow in on veth-srv 8080/tcp
check "allow on veth-srv" OPEN "$(in4 tcp 8080)"
fwg delete allow in on veth-srv 8080/tcp

echo "limit: about 6 new connections per source, then blocked"
fwg limit 2223/tcp
mapfile -t burst < <(burst4 2223 8)
opened=$(printf '%s\n' "${burst[@]}" | grep -c OPEN || true)
check "first 6 of 8 connections accepted" 6 "$opened"
check "7th connection dropped" TIMEOUT "${burst[6]}"
check "IPv6 source counted separately" OPEN "$(in6 tcp 2223)"

echo "outgoing policy"
fwg default deny outgoing
check "outgoing 9090 dropped" TIMEOUT "$(out4 9090)"
check "replies to incoming still flow" OPEN "$(in4 tcp 2222)"
fwg allow out 9090/tcp
check "allow out 9090/tcp" OPEN "$(out4 9090)"
fwg default allow outgoing

echo "default reject"
fwg default reject incoming
check "unmatched tcp gets a reset" REFUSED "$(in4 tcp 8080)"
check "unmatched udp gets port unreachable" REFUSED "$(in4 udp 5354)"
fwg default deny incoming

echo "logging, reload, status"
fwg logging on
fwg reload
check "rules survive reload" OPEN "$(in4 tcp 2222)"
status="$("$FWG_BIN" --config-dir "$WORK/etc" status)"
check "status reports active" "Status: active" "$(head -1 <<<"$status")"

echo "disable"
fwg disable
check "everything reachable again" OPEN "$(in4 tcp 8080)"
check "table removed" 0 "$(nft list tables | grep -c 'inet fwg' || true)"
status="$("$FWG_BIN" --config-dir "$WORK/etc" status)"
check "status reports inactive" "Status: inactive" "$(head -1 <<<"$status")"

report

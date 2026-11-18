#!/usr/bin/env bash
# Real-traffic tests for the ban table. Run by `tests/ban.rs`:
#   unshare -rn bash crates/fwg-nft/tests/netns/ban_traffic.sh DIR
# DIR holds the batches the library generated: rules.json (allows tcp 2222),
# ensure.json, ban.json (client v4, 1 h), short_ban.json (client v4, 2 s),
# unban.json (client v4), teardown.json.
set -euo pipefail

BATCHES="$(realpath "$1")"
# shellcheck source=../../../../tests/netns/harness.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../../../tests/netns/harness.sh"

nft_apply() { nft -j -f "$BATCHES/$1"; }

nft_apply rules.json
nft_apply ensure.json
echo "firewall allows tcp 2222"
check "client reaches 2222 (v4)" OPEN "$(in4 tcp 2222)"

echo "ban the client's IPv4 address"
nft_apply ban.json
check "banned client blocked despite allow rule" TIMEOUT "$(in4 tcp 2222)"
check "IPv6 address of the same client unaffected" OPEN "$(in6 tcp 2222)"

echo "bans survive firewall changes"
nft_apply rules.json
nft_apply ensure.json
check "still blocked after rebuilding both tables" TIMEOUT "$(in4 tcp 2222)"
nft_apply teardown.json
check "still blocked with the firewall off" TIMEOUT "$(in4 tcp 2222)"
nft_apply rules.json

echo "unban"
nft_apply unban.json
check "client reaches 2222 again" OPEN "$(in4 tcp 2222)"
nft_apply unban.json
check "unbanning twice is harmless" OPEN "$(in4 tcp 2222)"

echo "kernel lifts bans by itself"
nft_apply short_ban.json
check "blocked during a 2 s ban" TIMEOUT "$(in4 tcp 2222)"
sleep 2.5
check "reachable once it expired" OPEN "$(in4 tcp 2222)"

report

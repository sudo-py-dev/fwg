#!/usr/bin/env bash
# End-to-end test of fwgd. Run by tests/daemon.rs as root of a fresh user + network
# namespace (never on the host):
#   unshare -rn bash fwgd/tests/netns/daemon.sh path/to/fwgd path/to/filters
#
# Uses a file jail with the shipped sshd filter, writes failed-login lines into the
# log, and checks the kernel ban set and the control socket.
set -euo pipefail

FWGD="$(realpath "$1")"
FILTERS="$(realpath "$2")"
WORK="$(mktemp -d)"
LOG="$WORK/auth.log"
SOCK="$WORK/run/fwgd.sock"
FAILURES=0
pid=""

cleanup() { [[ -n "$pid" ]] && kill "$pid" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

check() { # check DESCRIPTION EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then printf '  ok    %-56s %s\n' "$1" "$3"
  else printf '  FAIL  %-56s expected %s, got %s\n' "$1" "$2" "$3"; FAILURES=$((FAILURES + 1)); fi
}

mkdir -p "$WORK/etc/jails.d"
touch "$LOG"
cat > "$WORK/etc/jails.d/sshd.toml" <<TOML
[sshd]
log = "$LOG"
max_retry = 3
find_time = "10m"
ban_time = "1h"
TOML

start() {
  "$FWGD" --config-dir "$WORK/etc" --filter-dir "$FILTERS" --state-dir "$WORK/state" --socket "$SOCK" \
    2>>"$WORK/fwgd.log" &
  pid=$!
  for _ in $(seq 100); do [[ -S "$SOCK" ]] && return; sleep 0.05; done
  echo "fwgd did not start:"; cat "$WORK/fwgd.log"; exit 1
}
# Not in $(…): a subshell cannot wait for this shell's child. Sets $STATUS.
stop() { kill -TERM "$pid"; STATUS=0; wait "$pid" || STATUS=$?; pid=""; }
ask() { python3 -I -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(sys.argv[2].encode()+b"\n")
print(s.makefile().readline().strip())' "$SOCK" "$1"; }
failed_login() { echo "$(date -u +%Y-%m-%dT%H:%M:%S.000000+00:00) testhost sshd[$RANDOM]: Invalid user admin from $1 port 22" >> "$LOG"; }
banned() { nft list set inet fwg_ban ban4 2>/dev/null | grep -c "$1" || true; }
wait_banned() { for _ in $(seq 40); do [[ "$(banned "$1")" == 1 ]] && break; sleep 0.1; done; banned "$1"; }

echo "configuration check"
check "--check accepts the config" "configuration OK: 1 jail(s) sshd" \
  "$("$FWGD" --check --config-dir "$WORK/etc" --filter-dir "$FILTERS" 2>&1)"

echo "start"
start
check "control socket is 0600" 600 "$(stat -c %a "$SOCK")"
check "socket directory is 0700" 700 "$(stat -c %a "$(dirname "$SOCK")")"
check "state directory is 0700" 700 "$(stat -c %a "$WORK/state")"
check "ban table created" 1 "$(nft list tables | grep -c 'inet fwg_ban')"

echo "banning from the log"
failed_login 198.51.100.7; failed_login 198.51.100.7
sleep 1.2
check "2 failures: not banned yet" 0 "$(banned 198.51.100.7)"
failed_login 198.51.100.7
check "3rd failure: banned" 1 "$(wait_banned 198.51.100.7)"
for _ in 1 2 3 4; do failed_login 127.0.0.1; done
sleep 1.2
check "loopback is never banned" 0 "$(banned 127.0.0.1)"

echo "control socket"
check "status lists the jail" 1 "$(ask '{"cmd":"status"}' | grep -c '"name":"sshd"')"
check "banned shows the jail" 1 "$(ask '{"cmd":"banned"}' | grep -c '"addr":"198.51.100.7","jail":"sshd"')"
check "manual ban" '{"result":"done","message":"banned 203.0.113.9 for 600s"}' \
  "$(ask '{"cmd":"ban","addr":"203.0.113.9","seconds":600}')"
check "manual ban is in the kernel" 1 "$(banned 203.0.113.9)"
check "unban" '{"result":"done","message":"unbanned 203.0.113.9"}' "$(ask '{"cmd":"unban","addr":"203.0.113.9"}')"
check "unbanned address left the kernel" 0 "$(banned 203.0.113.9)"
check "bad request is an error" 1 "$(ask '{"cmd":"reboot"}' | grep -c '"result":"error"')"
check "loopback ban refused" 1 "$(ask '{"cmd":"ban","addr":"127.0.0.1","seconds":60}' | grep -c 'refusing')"

echo "restart after a reboot"
stop
check "SIGTERM stops cleanly" 0 "$STATUS"
check "socket removed on stop" no "$([[ -e "$SOCK" ]] && echo yes || echo no)"
nft delete table inet fwg_ban   # what a reboot does to the kernel sets
start
check "running ban restored" 1 "$(banned 198.51.100.7)"
check "unbanned address stays unbanned" 0 "$(banned 203.0.113.9)"
check "second fwgd refuses the busy socket" 1 \
  "$("$FWGD" --config-dir "$WORK/etc" --filter-dir "$FILTERS" --state-dir "$WORK/state2" --socket "$SOCK" 2>&1 | grep -c 'another fwgd')"
stop
check "SIGTERM stops cleanly again" 0 "$STATUS"

echo
if (( FAILURES > 0 )); then echo "$FAILURES check(s) failed"; echo "--- fwgd log"; cat "$WORK/fwgd.log"; exit 1; fi
echo "all checks passed"

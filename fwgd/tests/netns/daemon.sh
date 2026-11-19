#!/usr/bin/env bash
# End-to-end test of fwgd and the fwg commands that talk to it. Run by
# tests/daemon.rs as root of a fresh user + network namespace (never on the host):
#   unshare -rn bash fwgd/tests/netns/daemon.sh path/to/fwgd path/to/filters path/to/fwg
#
# Uses a file jail with the shipped sshd filter, writes failed-login lines into the
# log, and checks the kernel ban set, the control socket and the fwg CLI.
set -euo pipefail

FWGD="$(realpath "$1")"
FILTERS="$(realpath "$2")"
FWG="$(realpath "$3")"
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
fwg() { "$FWG" --socket "$SOCK" --config-dir "$WORK/etc" "$@" 2>&1; }
fwg_loaded() { nft list tables | grep -c '^table inet fwg$' || true; }
has_ssh_rule() { nft list table inet fwg 2>/dev/null | grep -c 'tcp dport 22 accept' || true; }
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

echo "control socket (raw)"
check "status lists the jail" 1 "$(ask '{"cmd":"status"}' | grep -c '"name":"sshd"')"
check "bad request is an error" 1 "$(ask '{"cmd":"reboot"}' | grep -c '"result":"error"')"

echo "fwg commands"
check "jail list" "sshd  sshd    $LOG  0        1" "$(fwg jail list | sed -n 2p)"
check "jail status: settings" "Bans when: 3 failures within 10m" "$(fwg jail status sshd | grep 'Bans when')"
check "jail status: its ban" 1 "$(fwg jail status sshd | grep -c '^198.51.100.7  ')"
check "jail status: unknown jail" "fwg: no jail \`web\` is running (running: sshd)" "$(fwg jail status web)"
check "banned shows address and jail" 1 "$(fwg banned | grep -cE '^198\.51\.100\.7 +sshd +(59m|1h)')"
check "ban" "banned 203.0.113.9 for 10m" "$(fwg ban 203.0.113.9 --time 10m)"
check "manual ban is in the kernel" 1 "$(banned 203.0.113.9)"
check "banned shows the manual ban" 1 "$(fwg banned | grep -cE '^203\.0\.113\.9 +manual +(9m|10m)')"
check "ban IPv6" "banned 2001:db8::9 for 1h" "$(fwg ban 2001:db8::9)"
check "IPv6 ban is in the kernel" 1 "$(nft list set inet fwg_ban ban6 | grep -c '2001:db8::9')"
check "unban" "unbanned 203.0.113.9" "$(fwg unban 203.0.113.9)"
check "unbanned address left the kernel" 0 "$(banned 203.0.113.9)"
check "unbanned address left the list" 0 "$(fwg banned | grep -c 203.0.113.9 || true)"
check "loopback ban refused" 1 "$(fwg ban 127.0.0.1 | grep -c 'fwg: fwgd: refusing')"
check "bad ban time refused" 1 "$(fwg ban 203.0.113.9 --time 400d | grep -c 'fwg: fwgd: ')"

echo "fwg --confirm (fwgd undoes unconfirmed changes)"
check "enable --confirm" 1 "$(fwg --confirm 5 enable --force | grep -c 'Run `fwg confirm` within 5 s')"
check "change is live" 1 "$(fwg_loaded)"
check "pending change saved" yes "$([[ -f "$WORK/etc/pending.toml" ]] && echo yes || echo no)"
check "other changes refused while pending" 1 "$(fwg allow 80/tcp | grep -c 'rolls back in')"
sleep 6.5
check "unconfirmed enable undone: table gone" 0 "$(fwg_loaded)"
check "unconfirmed enable undone: saved as disabled" 1 "$(grep -c '^enabled = false' "$WORK/etc/rules.toml")"
check "pending change removed" no "$([[ -f "$WORK/etc/pending.toml" ]] && echo yes || echo no)"
check "fwgd logged the rollback" 1 "$(grep -c 'not confirmed in time' "$WORK/fwgd.log")"

fwg allow 22/tcp >/dev/null
fwg enable --force >/dev/null
check "rule loaded" 1 "$(has_ssh_rule)"
fwg --confirm 5 delete allow 22/tcp >/dev/null
check "--confirm delete is live" 0 "$(has_ssh_rule)"
check "fwg confirm" "Change confirmed; it stays." "$(fwg confirm)"
sleep 6.5
check "confirmed change stays" 0 "$(has_ssh_rule)"

fwg allow 22/tcp >/dev/null
fwg --confirm 5 delete allow 22/tcp >/dev/null
stop                                   # fwgd is down when the deadline passes
sleep 6
check "rule still gone while fwgd is down" 0 "$(has_ssh_rule)"
start
sleep 1.5
check "fwgd rolls back a missed deadline at start" 1 "$(has_ssh_rule)"
check "the rules file has the rule back" 1 "$(grep -c '^to_port = "22"$' "$WORK/etc/rules.toml")"
fwg disable >/dev/null

echo "restart after a reboot"
stop
check "SIGTERM stops cleanly" 0 "$STATUS"
check "socket removed on stop" no "$([[ -e "$SOCK" ]] && echo yes || echo no)"
nft delete table inet fwg_ban   # what a reboot does to the kernel sets
check "fwg says when fwgd is not running" 1 "$(fwg banned | grep -c 'fwgd is not running')"
start
check "running ban restored" 1 "$(banned 198.51.100.7)"
check "unbanned address stays unbanned" 0 "$(banned 203.0.113.9)"
check "fwg banned after the restart" "198.51.100.7 sshd" "$(fwg banned | awk '$1 == "198.51.100.7" {print $1, $2}')"
check "second fwgd refuses the busy socket" 1 \
  "$("$FWGD" --config-dir "$WORK/etc" --filter-dir "$FILTERS" --state-dir "$WORK/state2" --socket "$SOCK" 2>&1 | grep -c 'another fwgd')"
stop
check "SIGTERM stops cleanly again" 0 "$STATUS"

echo
if (( FAILURES > 0 )); then echo "$FAILURES check(s) failed"; echo "--- fwgd log"; cat "$WORK/fwgd.log"; exit 1; fi
echo "all checks passed"

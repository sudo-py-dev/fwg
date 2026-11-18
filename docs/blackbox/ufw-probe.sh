#!/usr/bin/env bash
# Black-box probe of ufw. Runs inside the Ubuntu test VM as a sudo user:
#   vm/fwg-vm push ubuntu docs/blackbox/ufw-probe.sh
#   vm/fwg-vm push ubuntu tests/netns/netprobe.py
#   vm/fwg-vm ssh ubuntu 'bash ufw-probe.sh' > ufw-observed.txt
#
# Observes only behaviour: kernel rules after each command, command output, and
# connection results from a client namespace. Never reads ufw's files.
set -euo pipefail

PROBE=(python3 -I "$HOME/netprobe.py")
SNAP=/tmp/ufw-probe; mkdir -p "$SNAP"
IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')

# Kernel rules without comments, blank lines and packet counters ("|| true": may be empty).
ruleset() { sudo nft list ruleset | { grep -vE '^\s*(#|$)' || true; } | sed 's/ counter packets [0-9]* bytes [0-9]*//'; }

step() { # step TITLE COMMAND...: run a ufw command, show output and the kernel rule diff
  local title="$1"; shift
  echo; echo "### $title"; echo '$ '"$*"
  ruleset > "$SNAP/before"
  { "$@" 2>&1 || echo "(exit status $?)"; } | sed 's/^/  > /'
  ruleset > "$SNAP/after"
  echo "kernel rule changes:"
  local changes
  changes=$(diff "$SNAP/before" "$SNAP/after" | grep -E '^[<>]' || true)
  if [[ -n "$changes" ]]; then sed 's/^/  /' <<<"$changes"; else echo "  (none)"; fi
}

echo "## Versions"
ufw version | head -1; nft --version; uname -r

echo; echo "## Before ufw is enabled"
echo "tables: $(sudo nft list tables | tr '\n' ' ')"

sudo ufw --force reset >/dev/null
step "allow SSH while disabled" sudo ufw allow 22/tcp
step "enable" sudo ufw --force enable
echo "tables after enable: $(sudo nft list tables | tr '\n' ' ')"
echo "chain count: $(ruleset | grep -c '^\s*chain ')"
echo "rule count: $(ruleset | grep -cvE '^\s*(table|chain|type|policy|\}|set|elements|flags|$)')"
echo "base chains (hook, priority, policy):"
ruleset | grep -E 'type filter hook' | sort | uniq -c | sed 's/^/  /'

step "simple port list" sudo ufw allow 80,443/tcp
step "port range needs protocol?" sudo ufw allow 60000:61000
step "port range with protocol" sudo ufw allow 60000:61000/udp
step "port without protocol" sudo ufw allow 53
step "full form" sudo ufw allow from 10.0.0.0/8 to any port 5432 proto tcp
step "IPv6 source" sudo ufw allow from 2001:db8::/32 to any port 53
step "outgoing deny" sudo ufw deny out 25
step "reject" sudo ufw reject 2323
step "limit" sudo ufw limit 2222/tcp
step "interface" sudo ufw allow in on "$IFACE" to any port 8080
step "comment" sudo ufw allow 9000/tcp comment 'probe comment'
step "duplicate rule" sudo ufw allow 80,443/tcp
step "insert at 1" sudo ufw insert 1 deny from 192.0.2.1
step "delete by rule" sudo ufw delete allow 53
step "default reject incoming" sudo ufw default reject incoming
step "default deny incoming" sudo ufw default deny incoming
step "default deny routed" sudo ufw default deny routed
step "logging on" sudo ufw logging on

echo; echo "## status"; sudo ufw status | sed 's/^/  /'
echo; echo "## status numbered"; sudo ufw status numbered | sed 's/^/  /'
echo; echo "## status verbose"; sudo ufw status verbose | sed 's/^/  /'

echo; echo "## Errors"
for args in "allow 70000" "allow foo" "limit out 22" "delete 99" "allow from 10.0.0.1 to ::1" "default maybe"; do
  echo '$ ufw '"$args"; sudo ufw $args 2>&1 | sed 's/^/  > /' || true
done

echo; echo "## Connection behaviour (client namespace 10.200.0.2 -> 10.200.0.1)"
sudo ip netns add atk
sudo ip link add veth-host type veth peer name veth-atk netns atk
sudo ip addr add 10.200.0.1/24 dev veth-host; sudo ip link set veth-host up
sudo ip netns exec atk ip addr add 10.200.0.2/24 dev veth-atk
sudo ip netns exec atk ip link set veth-atk up; sudo ip netns exec atk ip link set lo up
"${PROBE[@]}" serve tcp 2222 8080 2323 > "$SNAP/srv" & srv=$!
"${PROBE[@]}" serve udp 2323 > "$SNAP/srv-udp" & srv_udp=$!
until grep -q ready "$SNAP/srv" && grep -q ready "$SNAP/srv-udp"; do sleep 0.05; done
atk() { sudo ip netns exec atk "${PROBE[@]}" "$@"; }
echo "reject 2323/tcp (server listening): $(atk probe tcp 10.200.0.1 2323)"
echo "reject 2323/udp (server listening): $(atk probe udp 10.200.0.1 2323)"
echo "unlisted 8081 (default deny): $(atk probe tcp 10.200.0.1 8081)"
echo "limit 2222/tcp, 12 quick connections:"
atk burst tcp 10.200.0.1 2222 12 | nl | sed 's/^/  /'
echo "recovery: wait quietly, then one probe (each probe may itself count as an attempt):"
for wait in 10 20 30 35; do
  atk burst tcp 10.200.0.1 2222 8 >/dev/null   # trip the limit again
  sleep "$wait"
  echo "  after ${wait}s quiet: $(atk probe tcp 10.200.0.1 2222)"
done
echo "does a blocked client that keeps retrying stay blocked? (probe every 3 s for 45 s)"
atk burst tcp 10.200.0.1 2222 8 >/dev/null
for _ in $(seq 15); do atk probe tcp 10.200.0.1 2222; sleep 3; done | sort | uniq -c | sed 's/^/  /'
echo "connections allowed when spaced 7 s apart (6 tries, after 40 s quiet):"
sleep 40
for _ in 1 2 3 4 5 6; do atk probe tcp 10.200.0.1 2222; sleep 7; done | nl | sed 's/^/  /'

kill "$srv" "$srv_udp"
sudo ip netns del atk; sudo ip link del veth-host 2>/dev/null || true
sudo ufw --force disable >/dev/null
echo; echo "## After disable"
echo "tables: $(sudo nft list tables | tr '\n' ' ')"
echo "rules left in ufw chains: $(ruleset | grep -c 'ufw' || true)"

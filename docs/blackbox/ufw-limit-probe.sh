#!/usr/bin/env bash
# Focused probe of `ufw limit`: kernel parameters (iptables-save view), the
# xt_recent state in /proc, and recovery timing, with a server-alive control.
# Runs inside the Ubuntu test VM (needs netprobe.py in $HOME).
set -euo pipefail
PROBE=(python3 -I "$HOME/netprobe.py")
sudo ufw --force reset >/dev/null
sudo ufw allow 22/tcp >/dev/null
sudo ufw limit 2222/tcp >/dev/null
sudo ufw --force enable >/dev/null

echo "## Kernel rules for the limit (iptables-save view, IPv4)"
sudo iptables-save | grep -E 'user-limit|dport 2222' | sed 's/^/  /'

sudo ip netns add atk
sudo ip link add veth-host type veth peer name veth-atk netns atk
sudo ip addr add 10.200.0.1/24 dev veth-host; sudo ip link set veth-host up
sudo ip netns exec atk ip addr add 10.200.0.2/24 dev veth-atk
sudo ip netns exec atk ip link set veth-atk up
"${PROBE[@]}" serve tcp 2222 > /tmp/srv & srv=$!
until grep -q ready /tmp/srv; do sleep 0.05; done
atk() { sudo ip netns exec atk "${PROBE[@]}" "$@"; }
alive() { "${PROBE[@]}" probe tcp 127.0.0.1 2222; }   # loopback is never limited
recent() { for f in /proc/net/xt_recent/*; do echo "  $f: $(sudo cat "$f" | tr '\n' ' ' | cut -c1-200)"; done; }

echo; echo "## Burst of 8"
atk burst tcp 10.200.0.1 2222 8 | tr '\n' ' '; echo
echo "server alive (loopback): $(alive)"
echo "xt_recent state:"; recent
for wait in 15 31 45; do
  sleep "$wait"
  echo; echo "## After ${wait}s more quiet: $(atk probe tcp 10.200.0.1 2222)  (server alive: $(alive))"
  recent
done

kill "$srv"; sudo ip netns del atk; sudo ip link del veth-host 2>/dev/null || true
sudo ufw --force disable >/dev/null

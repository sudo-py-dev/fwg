# Shared setup for the real-traffic tests. Source it, never run it directly,
# as root of a fresh user + network namespace (`unshare -rn bash script.sh`).
#
# This namespace plays the server; a child namespace plays the client, joined
# by a veth pair: server 10.99.0.1 / fd99::1, client 10.99.0.2 / fd99::2.
# Servers: TCP 2222 2223 8080 and UDP 5353 here, TCP 9090 on the client.
#
# Provides: check, report, in4, in6, out4, on_client, $WORK.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE=(python3 -I "$HARNESS_DIR/netprobe.py")
WORK="$(mktemp -d)"
FAILURES=0
harness_pids=()

harness_cleanup() { kill "${harness_pids[@]}" 2>/dev/null || true; rm -rf "$WORK"; }
trap harness_cleanup EXIT

check() { # check DESCRIPTION EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then
    printf '  ok    %-58s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-58s expected %s, got %s\n' "$1" "$2" "$3"
    FAILURES=$((FAILURES + 1))
  fi
}

report() { # prints the summary and exits non-zero if any check failed
  echo
  if (( FAILURES > 0 )); then
    echo "$FAILURES check(s) failed"
    exit 1
  fi
  echo "all checks passed"
}

unshare -n sleep 600 & CLIENT=$!; harness_pids+=("$CLIENT")
sleep 0.2
# --no-fork: the command replaces nsenter, so killing its PID really stops it.
on_client() { nsenter --no-fork -t "$CLIENT" -n "$@"; }

ip link set lo up
ip link add veth-srv type veth peer name veth-cli netns "$CLIENT"
ip addr add 10.99.0.1/24 dev veth-srv
ip addr add fd99::1/64 dev veth-srv nodad
ip link set veth-srv up
on_client ip link set lo up
on_client ip addr add 10.99.0.2/24 dev veth-cli
on_client ip addr add fd99::2/64 dev veth-cli nodad
on_client ip link set veth-cli up

"${PROBE[@]}" serve tcp 2222 2223 8080 > "$WORK/srv-tcp" & harness_pids+=($!)
"${PROBE[@]}" serve udp 5353 > "$WORK/srv-udp" & harness_pids+=($!)
# Not via on_client: a backgrounded function would make $! a subshell, not the server.
nsenter --no-fork -t "$CLIENT" -n "${PROBE[@]}" serve tcp 9090 > "$WORK/cli-tcp" & harness_pids+=($!)
for f in srv-tcp srv-udp cli-tcp; do
  until grep -q ready "$WORK/$f" 2>/dev/null; do sleep 0.05; done
done

in4()  { on_client "${PROBE[@]}" probe "$1" 10.99.0.1 "$2"; }
in6()  { on_client "${PROBE[@]}" probe "$1" fd99::1 "$2"; }
out4() { "${PROBE[@]}" probe tcp 10.99.0.2 "$1"; }
burst4() { on_client "${PROBE[@]}" burst tcp 10.99.0.1 "$1" "$2"; }

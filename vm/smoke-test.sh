#!/usr/bin/env bash
# Full-system smoke test (tier 4): install fwg in a test VM, check the SSH
# lockout guard over a real SSH login, every rule kind on that distro's nft,
# ufw coexistence, and that the rules come back after a reboot.
#
#   vm/smoke-test.sh [debian|ubuntu ...]     (default: both)
#
# Each run starts from a factory-fresh VM (vm/fwg-vm reset).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM="$ROOT/vm/fwg-vm"
REBOOT_TIMEOUT_SECS=180

run_vm() {
  local name="$1"
  echo "=== $name"
  "$VM" reset "$name" >/dev/null
  "$VM" up "$name" >/dev/null
  for f in "$ROOT/target/release/fwg" "$ROOT/dist/fwg.service" "$ROOT/vm/guest-checks.sh"; do
    "$VM" push "$name" "$f" >/dev/null
  done

  local failed=0
  for phase in install enable rules ufw; do
    echo "[$phase]"
    "$VM" ssh "$name" "bash guest-checks.sh $phase" || failed=1
  done

  echo "[new SSH login with the firewall on]"
  if "$VM" ssh "$name" true; then echo "  ok    ssh still works"; else echo "  FAIL  ssh blocked"; failed=1; fi

  echo "[reboot]"
  "$VM" ssh "$name" 'sudo systemctl reboot' 2>/dev/null || true
  sleep 5
  local deadline=$((SECONDS + REBOOT_TIMEOUT_SECS))
  until "$VM" ssh "$name" true 2>/dev/null; do
    (( SECONDS < deadline )) || { echo "  FAIL  no SSH after reboot"; return 1; }
    sleep 3
  done
  "$VM" ssh "$name" "bash guest-checks.sh after-reboot" || failed=1

  "$VM" down "$name" >/dev/null
  return "$failed"
}

cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml" -p fwg

vms=("$@")
(( ${#vms[@]} )) || vms=(debian ubuntu)
status=0
for name in "${vms[@]}"; do
  run_vm "$name" || status=1
done
echo
if (( status == 0 )); then echo "smoke test passed"; else echo "smoke test FAILED"; fi
exit "$status"

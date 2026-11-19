#!/usr/bin/env bash
# Full-system smoke test (tier 4): install fwg and fwgd in a test VM, check the
# SSH lockout guard over a real SSH login, every rule kind on that distro's nft,
# ufw coexistence, that failed SSH logins get banned (from a network namespace
# inside the VM), that the nginx, Dovecot and Postfix jails ban real failed logins,
# that `--confirm` undoes a change that locks out SSH, and that
# rules and bans come back after a reboot.
#
#   vm/smoke-test.sh [debian|ubuntu ...]     (default: both)
#
# Each run starts from a factory-fresh VM (vm/fwg-vm reset). What that VM's sshd
# logged for each kind of failed login is saved to vm/state/<vm>-sshd-capture.txt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM="$ROOT/vm/fwg-vm"
REBOOT_TIMEOUT_SECS=180

run_vm() {
  local name="$1"
  echo "=== $name"
  "$VM" reset "$name" >/dev/null
  "$VM" up "$name" >/dev/null
  for f in "$ROOT/target/release/fwg" "$ROOT/target/release/fwgd" "$ROOT/dist/fwg.service" \
           "$ROOT/dist/fwgd.service" "$ROOT/vm/guest-checks.sh"; do
    "$VM" push "$name" "$f" >/dev/null
  done
  # Both are called sshd.toml; guest-checks.sh installs them under that name.
  "$VM" push "$name" "$ROOT/filters/sshd.toml" sshd-filter.toml >/dev/null
  "$VM" push "$name" "$ROOT/dist/jails.d/sshd.toml" sshd-jail.toml >/dev/null
  "$VM" ssh "$name" 'mkdir -p apps filters jails' >/dev/null
  for f in "$ROOT"/apps/*.toml; do "$VM" push "$name" "$f" apps/ >/dev/null; done
  for f in "$ROOT"/filters/*.toml; do "$VM" push "$name" "$f" filters/ >/dev/null; done
  for f in "$ROOT"/dist/jails.d/*.toml; do "$VM" push "$name" "$f" jails/ >/dev/null; done

  local failed=0
  for phase in install enable rules ufw sshd-capture fwgd-install bans services confirm-keep; do
    echo "[$phase]"
    "$VM" ssh "$name" "bash guest-checks.sh $phase" || failed=1
  done

  echo "[new SSH login with the firewall on]"
  if "$VM" ssh "$name" true; then echo "  ok    ssh still works"; else echo "  FAIL  ssh blocked"; failed=1; fi

  echo "[--confirm undoes a change that locks out SSH]"
  "$VM" ssh "$name" "bash guest-checks.sh confirm-lockout" || failed=1
  if "$VM" ssh "$name" true 2>/dev/null; then
    echo "  FAIL  new SSH logins still work without the SSH rule"; failed=1
  else
    echo "  ok    new SSH logins are blocked"
  fi
  local started=$SECONDS
  until "$VM" ssh "$name" true 2>/dev/null; do
    (( SECONDS - started < 60 )) || break
    sleep 2
  done
  if "$VM" ssh "$name" true 2>/dev/null; then
    echo "  ok    SSH works again after the rollback ($((SECONDS - started)) s later)"
    "$VM" ssh "$name" "bash guest-checks.sh confirm-after" || failed=1
  else
    echo "  FAIL  SSH still blocked 60 s later"; failed=1
  fi

  echo "[reboot]"
  "$VM" ssh "$name" 'sudo systemctl reboot' 2>/dev/null || true
  sleep 5
  local deadline=$((SECONDS + REBOOT_TIMEOUT_SECS))
  until "$VM" ssh "$name" true 2>/dev/null; do
    (( SECONDS < deadline )) || { echo "  FAIL  no SSH after reboot"; return 1; }
    sleep 3
  done
  "$VM" ssh "$name" "bash guest-checks.sh after-reboot" || failed=1
  echo "[import]"
  "$VM" ssh "$name" "bash guest-checks.sh import" || failed=1
  "$VM" pull "$name" sshd-capture.txt "$ROOT/vm/state/$name-sshd-capture.txt" >/dev/null || failed=1

  "$VM" down "$name" >/dev/null
  return "$failed"
}

cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml" -p fwg -p fwgd

vms=("$@")
(( ${#vms[@]} )) || vms=(debian ubuntu)
status=0
for name in "${vms[@]}"; do
  run_vm "$name" || status=1
done
echo
if (( status == 0 )); then echo "smoke test passed"; else echo "smoke test FAILED"; fi
exit "$status"

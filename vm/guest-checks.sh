#!/usr/bin/env bash
# Runs inside a test VM as the `fwg` user (over SSH); vm/smoke-test.sh drives it.
#   guest-checks.sh install         install binary + unit, check a fresh boot-time reload
#   guest-checks.sh enable          SSH lockout guard, then enable with SSH allowed
#   guest-checks.sh rules           every rule kind loads on this distro's nft
#   guest-checks.sh ufw             refuses to run alongside ufw (skipped if absent)
#   guest-checks.sh after-reboot    rules came back at boot
set -euo pipefail

FAILURES=0
check() { # check DESCRIPTION COMMAND...
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  ok    %s\n' "$desc"
  else
    printf '  FAIL  %s\n' "$desc"
    FAILURES=$((FAILURES + 1))
  fi
}
contains() { grep -qF -- "$2" <<<"$1"; }
fwg_loaded() { sudo nft list tables | grep -qx 'table inet fwg'; }

case "${1:-}" in
  install)
    sudo install -m 0755 ~/fwg /usr/sbin/fwg
    sudo install -m 0644 ~/fwg.service /etc/systemd/system/fwg.service
    sudo rm -rf /etc/fwg
    sudo systemctl daemon-reload
    check "unit enables" sudo systemctl enable fwg.service
    check "unit starts with no config yet" sudo systemctl start fwg.service
    check "unit is active" systemctl is-active fwg.service
    check "config dir created 0750" test "$(sudo stat -c %a /etc/fwg)" = 750
    check "nothing loaded while disabled" bash -c '! sudo nft list tables | grep -q fwg'
    ;;
  enable)
    out="$(sudo fwg enable 2>&1 || true)"
    check "enable over SSH refused without an SSH rule" contains "$out" "you are connected over SSH"
    check "refusal names port 22" contains "$out" "TCP port 22"
    check "firewall stayed off" bash -c '! sudo nft list tables | grep -q fwg'
    sudo fwg allow 22/tcp >/dev/null
    check "enable succeeds once SSH is allowed" sudo fwg enable
    check "table loaded" fwg_loaded
    check "status active" contains "$(sudo fwg status)" "Status: active"
    ;;
  rules)
    sudo fwg allow 80,443/tcp
    sudo fwg allow 60000:61000/udp
    sudo fwg limit 2222/tcp
    sudo fwg reject from 192.0.2.0/24
    sudo fwg allow from 2001:db8::/32 to any port 53
    sudo fwg allow out on lo 9999/udp
    sudo fwg deny in on eth0 proto tcp from 10.0.0.0/8 port 1024:65535 to 10.0.0.1 port 5432 comment 'db guard'
    sudo fwg logging on
    sudo fwg default reject incoming
    check "all rule kinds load (nft $(sudo nft --version | awk '{print $2}'))" sudo fwg reload
    check "limit set exists" contains "$(sudo nft list ruleset)" "set limit4_"
    check "comment kept" contains "$(sudo nft list ruleset)" 'comment "db guard"'
    sudo fwg default deny incoming >/dev/null
    ;;
  ufw)
    if ! command -v ufw >/dev/null; then
      echo "  skip  ufw not installed"
      exit 0
    fi
    sudo fwg disable >/dev/null
    sudo ufw allow 22/tcp >/dev/null
    sudo ufw --force enable >/dev/null
    out="$(sudo fwg enable 2>&1 || true)"
    check "enable refused while ufw is on" contains "$out" "ufw is enabled"
    sudo ufw disable >/dev/null
    check "enable works after ufw disable" sudo fwg enable
    ;;
  after-reboot)
    check "unit active after boot" systemctl is-active fwg.service
    check "rules loaded at boot" fwg_loaded
    check "status active" contains "$(sudo fwg status)" "Status: active"
    check "no unit errors in journal" bash -c '! sudo journalctl -b -u fwg.service -p err --no-pager -q | grep -q .'
    ;;
  *)
    echo "usage: $0 install|enable|rules|ufw|after-reboot" >&2
    exit 2
    ;;
esac

exit $(( FAILURES > 0 ))

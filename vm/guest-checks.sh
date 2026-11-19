#!/usr/bin/env bash
# Runs inside a test VM as the `fwg` user (over SSH); vm/smoke-test.sh drives it.
#   guest-checks.sh install         install binary + unit, check a fresh boot-time reload
#   guest-checks.sh enable          SSH lockout guard, then enable with SSH allowed
#   guest-checks.sh rules           every rule kind loads on this distro's nft
#   guest-checks.sh ufw             refuses to run alongside ufw (skipped if absent)
#   guest-checks.sh sshd-capture    record what this OpenSSH logs for each kind of failure
#   guest-checks.sh fwgd-install    install fwgd, its unit, the sshd filter and jail
#   guest-checks.sh bans            failed SSH logins get banned; fwg ban/unban/banned/jail
#   guest-checks.sh after-reboot    rules and bans came back at boot
#
# The SSH "attacker" is a network namespace inside this VM (10.200.0.0/24), never
# the host: host connections arrive from 10.0.2.2, and banning that address would
# cut off the test harness's own SSH.
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

readonly SERVER=10.200.0.1
readonly ASKPASS=/tmp/fwg-wrong-password
in_kernel() { sudo nft list set inet fwg_ban "ban$([[ $1 == *:* ]] && echo 6 || echo 4)" | grep -qwF -- "$1"; }
not() { ! "$@"; }
listed() { sudo fwg banned | awk -v addr="$1" -v jail="$2" '$1 == addr && $2 == jail {found = 1} END {exit !found}'; }
can_connect() { sudo ip netns exec attacker timeout 3 bash -c "</dev/tcp/$SERVER/22"; }

# The attacker namespace: the VM is 10.200.0.1, attackers use .2 and up.
attacker_net() {
  sudo ip netns add attacker
  sudo ip link add veth-vm type veth peer name veth-att netns attacker
  sudo ip addr add "$SERVER/24" dev veth-vm
  sudo ip link set veth-vm up
  sudo ip netns exec attacker ip link set lo up
  for host in 2 3 11 12 13 14 15 16; do
    sudo ip netns exec attacker ip addr add "10.200.0.$host/24" dev veth-att
  done
  sudo ip netns exec attacker ip link set veth-att up
}

# One SSH login attempt from SOURCE as USER; every password it sends is wrong.
attack() { # attack SOURCE USER [ssh options...]
  local source="$1" user="$2"; shift 2
  sudo ip netns exec attacker env SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force \
    timeout 20 ssh -F /dev/null -b "$source" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=QUIET "$@" \
    "$user@$SERVER" true </dev/null >/dev/null 2>&1 || true
}
with_password() { attack "$@" -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1; }
with_key() { attack "$@" -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -i /tmp/fwg-unknown-key; }

# Journal lines since CURSOR that mention ADDRESS, as `_COMM | MESSAGE`.
sshd_lines() { # sshd_lines CURSOR ADDRESS
  sudo journalctl --after-cursor="$1" -o json | python3 -I -c '
import json, sys
for line in sys.stdin:
    entry = json.loads(line)
    message = entry.get("MESSAGE", "")
    if isinstance(message, str) and sys.argv[1] in message and entry.get("_COMM") != "sudo":
        print(entry.get("_COMM"), "|", message)' "$2"
}
# Repeats an attack until ADDRESS is banned or SECONDS pass; sets $tries.
# OpenSSH 9.8+ (PerSourcePenalties) refuses a source for a while after ~3 failed
# logins without logging it, so attempts need time, not just a count.
attack_until_banned() { # attack_until_banned ADDRESS SECONDS COMMAND...
  local addr="$1" deadline=$((SECONDS + $2)); shift 2
  tries=0
  until in_kernel "$addr" || (( SECONDS >= deadline )); do
    "$@"; tries=$((tries + 1)); sleep 2
  done
}

cursor() { sudo journalctl -n 0 --show-cursor -q | sed -n 's/^-- cursor: //p'; }

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
  sshd-capture)
    # Runs before fwgd is installed, so no capture attempt is cut short by a ban.
    attacker_net
    # Password logins are off in the cloud images; this file sorts first, so it wins.
    echo 'PasswordAuthentication yes' | sudo tee /etc/ssh/sshd_config.d/00-fwg-test.conf >/dev/null
    sudo systemctl reload ssh
    printf '#!/bin/sh\necho wrong-password\n' > "$ASKPASS"; chmod 0755 "$ASKPASS"
    rm -f /tmp/fwg-unknown-key*; ssh-keygen -q -t ed25519 -N '' -f /tmp/fwg-unknown-key
    out=~/sshd-capture.txt
    { echo "# $(ssh -V 2>&1)"; echo "# kind | _COMM | MESSAGE"; } > "$out"
    capture() { # capture KIND SOURCE COMMAND...
      local kind="$1" source="$2" start; shift 2
      start="$(cursor)"; "$@"; sleep 1
      sshd_lines "$start" "$source" | sed "s/^/$kind | /" >> "$out"
    }
    capture wrong-password       10.200.0.11 with_password 10.200.0.11 fwg
    capture unknown-user         10.200.0.12 with_password 10.200.0.12 no-such-user
    capture key-only             10.200.0.13 with_key 10.200.0.13 fwg
    capture key-only-unknown     10.200.0.14 with_key 10.200.0.14 no-such-user
    capture too-many-passwords   10.200.0.15 attack 10.200.0.15 fwg -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=10
    capture old-client           10.200.0.16 attack 10.200.0.16 fwg -o KexAlgorithms=diffie-hellman-group1-sha1
    check "sshd logged the failures ($(grep -vc '^#' "$out") lines)" test "$(grep -vc '^#' "$out")" -ge 10
    check "every kind was logged" test "$(grep -v '^#' "$out" | cut -d' ' -f1 | sort -u | wc -l)" = 6
    ;;
  fwgd-install)
    sudo install -m 0755 ~/fwgd /usr/sbin/fwgd
    sudo install -m 0644 ~/fwgd.service /etc/systemd/system/fwgd.service
    sudo install -D -m 0644 ~/sshd-filter.toml /usr/share/fwg/filters/sshd.toml
    sudo install -d -m 0750 /etc/fwg/jails.d
    sudo install -m 0644 ~/sshd-jail.toml /etc/fwg/jails.d/sshd.toml
    sudo systemctl daemon-reload
    check "fwgd --check accepts the shipped jail" sudo fwgd --check
    check "fwgd unit enables and starts" sudo systemctl enable --now fwgd.service
    sleep 1
    check "fwgd is active" systemctl is-active fwgd.service
    check "jail list shows sshd on the journal" contains "$(sudo fwg jail list)" "sshd  sshd    journal"
    out="$(/usr/sbin/fwg banned 2>&1 || true)"
    check "non-root user is told to use sudo" contains "$out" "run \`sudo fwg ...\`"
    ;;
  bans)
    attack_until_banned 10.200.0.2 60 with_password 10.200.0.2 admin
    check "failed logins banned 10.200.0.2 (after $tries connections)" in_kernel 10.200.0.2
    check "it can no longer reach port 22" not can_connect
    check "fwg banned lists it under sshd" listed 10.200.0.2 sshd
    check "jail status lists it" contains "$(sudo fwg jail status sshd)" "10.200.0.2"
    check "jail status counts the ban" contains "$(sudo fwg jail status sshd)" "Bans:      1 since fwgd started"
    check "the harness address 10.0.2.2 is not banned" not in_kernel 10.0.2.2
    sudo systemctl restart fwgd.service; sleep 1
    check "fwgd active after restart" systemctl is-active fwgd.service
    check "ban kept across restart" in_kernel 10.200.0.2
    check "fwg banned still lists it under sshd" listed 10.200.0.2 sshd
    check "fwg unban" contains "$(sudo fwg unban 10.200.0.2)" "unbanned 10.200.0.2"
    check "unbanned: gone from the kernel" not in_kernel 10.200.0.2
    check "unbanned: gone from fwg banned" bash -c '! sudo fwg banned | grep -qw 10.200.0.2'
    check "unbanned: can connect again" can_connect
    # Bans that must come back after the reboot: one from the jail, one by hand.
    attack_until_banned 10.200.0.3 120 with_key 10.200.0.3 fwg
    check "key-only failures banned 10.200.0.3 (after $tries connections)" in_kernel 10.200.0.3
    check "fwg ban by hand" contains "$(sudo fwg ban 192.0.2.50 --time 2h)" "banned 192.0.2.50 for 2h"
    check "fwg ban IPv6 by hand" contains "$(sudo fwg ban 2001:db8::50 --time 2h)" "banned 2001:db8::50 for 2h"
    check "manual ban listed as manual" listed 192.0.2.50 manual
    check "no fwgd errors" bash -c '! sudo journalctl -u fwgd.service -p err --no-pager -q | grep -q .'
    ;;
  after-reboot)
    check "unit active after boot" systemctl is-active fwg.service
    check "rules loaded at boot" fwg_loaded
    check "status active" contains "$(sudo fwg status)" "Status: active"
    check "no unit errors in journal" bash -c '! sudo journalctl -b -u fwg.service -p err --no-pager -q | grep -q .'
    check "fwgd active after boot" systemctl is-active fwgd.service
    check "jail ban restored in the kernel" in_kernel 10.200.0.3
    check "manual ban restored in the kernel" in_kernel 192.0.2.50
    check "IPv6 ban restored in the kernel" in_kernel 2001:db8::50
    check "fwg banned lists the jail ban" listed 10.200.0.3 sshd
    check "fwg banned lists the manual ban" listed 192.0.2.50 manual
    check "unbanned address stayed unbanned" not in_kernel 10.200.0.2
    check "no fwgd errors in journal" bash -c '! sudo journalctl -b -u fwgd.service -p err --no-pager -q | grep -q .'
    ;;
  *)
    echo "usage: $0 install|enable|rules|ufw|sshd-capture|fwgd-install|bans|after-reboot" >&2
    exit 2
    ;;
esac

exit $(( FAILURES > 0 ))

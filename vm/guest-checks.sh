#!/usr/bin/env bash
# Runs inside a test VM as the `fwg` user (over SSH); vm/smoke-test.sh drives it.
#   guest-checks.sh install         install binary + unit, check a fresh boot-time reload
#   guest-checks.sh enable          SSH lockout guard, then enable with SSH allowed
#   guest-checks.sh rules           every rule kind loads on this distro's nft
#   guest-checks.sh ufw             refuses to run alongside ufw (skipped if absent)
#   guest-checks.sh sshd-capture    record what this OpenSSH logs for each kind of failure
#   guest-checks.sh fwgd-install    install fwgd, its unit, the sshd filter and jail
#   guest-checks.sh bans            failed SSH logins get banned; fwg ban/unban/banned/jail
#   guest-checks.sh services        nginx, Dovecot and Postfix jails ban real failed logins
#   guest-checks.sh confirm-keep    a confirmed --confirm change stays
#   guest-checks.sh confirm-lockout delete the SSH rule with --confirm (the host then checks
#                                   new logins fail, and work again after the rollback)
#   guest-checks.sh confirm-after   the rollback put the SSH rule back
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
# No `grep -q` after a pipe here: it exits at the first match, nft then dies of
# SIGPIPE if it had more to write, and pipefail turns the match into a failure.
fwg_loaded() { sudo nft list tables | grep -x 'table inet fwg' >/dev/null; }

readonly SERVER=10.200.0.1 SERVER6=fd20::1
readonly ASKPASS=/tmp/fwg-wrong-password
in_kernel() { sudo nft list set inet fwg_ban "ban$([[ $1 == *:* ]] && echo 6 || echo 4)" | grep -wF -- "$1" >/dev/null; }
not() { ! "$@"; }
listed() { sudo fwg banned | awk -v addr="$1" -v jail="$2" '$1 == addr && $2 == jail {found = 1} END {exit !found}'; }
can_connect() { sudo ip netns exec attacker timeout 3 bash -c "</dev/tcp/${1:-$SERVER}/22"; }

# The attacker namespace: the VM is 10.200.0.1 and fd20::1, attackers use .2 and
# up, and fd20::2. nodad: the addresses are usable at once, not after DAD.
attacker_net() {
  sudo ip netns add attacker
  sudo ip link add veth-vm type veth peer name veth-att netns attacker
  sudo ip addr add "$SERVER/24" dev veth-vm
  sudo ip addr add "$SERVER6/64" dev veth-vm nodad
  sudo ip link set veth-vm up
  sudo ip netns exec attacker ip link set lo up
  for host in 2 3 11 12 13 14 15 16 31 32 33; do
    sudo ip netns exec attacker ip addr add "10.200.0.$host/24" dev veth-att
  done
  sudo ip netns exec attacker ip addr add fd20::2/64 dev veth-att nodad
  sudo ip netns exec attacker ip link set veth-att up
}

# One SSH login attempt from SOURCE as USER; every password it sends is wrong.
attack() { # attack SOURCE USER [ssh options...]
  local source="$1" user="$2" server="$SERVER"; shift 2
  [[ "$source" == *:* ]] && server="$SERVER6"
  sudo ip netns exec attacker env SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force \
    timeout 20 ssh -F /dev/null -b "$source" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=QUIET "$@" \
    "$user@$server" true </dev/null >/dev/null 2>&1 || true
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
    sudo install -d -m 0755 /usr/share/fwg/apps
    sudo install -m 0644 ~/apps/*.toml /usr/share/fwg/apps/
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
    check "app list shows the shipped profiles" contains "$(/usr/sbin/fwg app list)" "Nginx Full"
    check "rule from a profile" contains "$(sudo fwg allow 'Nginx Full')" "allow 443/udp (Nginx Full)"
    check "profile rule loaded: TCP ports" contains "$(sudo nft list table inet fwg)" "tcp dport { 80, 443 } accept"
    check "profile rule loaded: UDP port" contains "$(sudo nft list table inet fwg)" "udp dport 443 accept"
    check "status names the profile" contains "$(sudo fwg status)" "80,443/tcp (Nginx Full)"
    check "delete by profile" contains "$(sudo fwg delete allow 'nginx full')" "deleted: allow 443/udp (Nginx Full)"
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
    capture ipv6-unknown-user    fd20::2     with_password fd20::2 no-such-user
    check "sshd logged the failures ($(grep -vc '^#' "$out") lines)" test "$(grep -vc '^#' "$out")" -ge 10
    check "every kind was logged" test "$(grep -v '^#' "$out" | cut -d' ' -f1 | sort -u | wc -l)" = 7
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
    # A login user's copy of logger named like sshd logs with _COMM=sshd; only
    # its _UID gives it away. 8 fake failures would be enough for a ban.
    for name in sshd sshd-session; do
      cp "$(command -v logger)" "/tmp/$name"
      for i in 1 2 3 4; do "/tmp/$name" -t sshd "Invalid user fake$i from 192.0.2.77 port 22"; done
    done
    sleep 2
    check "a login user's fake sshd lines ban nobody" not in_kernel 192.0.2.77
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
    attack_until_banned fd20::2 60 with_password fd20::2 admin
    check "IPv6 failed logins banned fd20::2 (after $tries connections)" in_kernel fd20::2
    check "it can no longer reach port 22 over IPv6" not can_connect "$SERVER6"
    check "IPv4 from the same attacker still allowed" can_connect
    check "fwg banned lists the IPv6 address under sshd" listed fd20::2 sshd
    check "fwg ban by hand" contains "$(sudo fwg ban 192.0.2.50 --time 2h)" "banned 192.0.2.50 for 2h"
    check "fwg ban IPv6 by hand" contains "$(sudo fwg ban 2001:db8::50 --time 2h)" "banned 2001:db8::50 for 2h"
    check "manual ban listed as manual" listed 192.0.2.50 manual
    check "no fwgd errors" bash -c '! sudo journalctl -u fwgd.service -p err --no-pager -q | grep -q .'
    report="$(sudo journalctl _COMM=sshd _COMM=sshd-session -o cat --no-pager | /usr/sbin/fwgd --test-filter sshd)"
    check "fwgd --test-filter counts the real journal's failures" \
      bash -c "grep -qE '^  failures: +[1-9][0-9]*  from [1-9]' <<<\"\$1\"" _ "$report"
    check "fwgd --test-filter names the attacker" contains "$report" "10.200.0.2 "
    ;;
  services)
    # Real servers with real auth failures; each attacked from its own address.
    export DEBIAN_FRONTEND=noninteractive
    echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
    echo "postfix postfix/mailname string fwg-test.example" | sudo debconf-set-selections
    sudo apt-get -o DPkg::Lock::Timeout=300 install -y -q nginx apache2-utils dovecot-imapd \
      dovecot-pop3d postfix >/tmp/apt.log 2>&1 || { tail -5 /tmp/apt.log; exit 1; }
    sudo htpasswd -bc /etc/nginx/.htpasswd alice right-password >/dev/null 2>&1
    echo 'server { listen 80 default_server; location / { auth_basic "test"; auth_basic_user_file /etc/nginx/.htpasswd; root /var/www/html; } }' \
      | sudo tee /etc/nginx/sites-enabled/default >/dev/null
    sudo systemctl restart nginx
    # Cleartext logins from the namespace (2.4 and 2.3 spell it differently), and
    # the SASL socket Postfix uses.
    if /usr/sbin/dovecot --version | grep -q '^2\.4'; then clear='auth_allow_cleartext = yes'; else clear='disable_plaintext_auth = no'; fi
    printf '%s\n%s\n' "$clear" 'service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}' | sudo tee /etc/dovecot/conf.d/99-fwg-test.conf >/dev/null
    sudo useradd -m bob 2>/dev/null || true
    echo 'bob:right-password' | sudo chpasswd
    sudo systemctl restart dovecot
    sudo /usr/sbin/postconf -e smtpd_sasl_type=dovecot smtpd_sasl_path=private/auth \
      smtpd_sasl_auth_enable=yes smtpd_tls_auth_only=no
    sudo systemctl restart postfix
    for f in dovecot postfix-sasl nginx-http-auth; do
      sudo install -m 0644 ~/filters/$f.toml /usr/share/fwg/filters/$f.toml
      sed 's/^enabled = false/enabled = true/' ~/jails/$f.toml | sudo tee /etc/fwg/jails.d/$f.toml >/dev/null
    done
    # The firewall is on with incoming denied: open the mail ports, by profile.
    check "allow the mail services by profile" bash -c 'sudo fwg allow "Dovecot IMAP" && sudo fwg allow Postfix'
    check "fwgd --check accepts the service jails" sudo fwgd --check
    sudo systemctl restart fwgd.service; sleep 2
    check "jail list shows the three services" bash -c '[[ $(sudo fwg jail list | grep -cE "^(dovecot|postfix-sasl|nginx-http-auth) ") == 3 ]]'
    sleep 2
    attack_until_banned 10.200.0.31 60 sudo ip netns exec attacker \
      curl -s -o /dev/null --interface 10.200.0.31 -u alice:wrong http://$SERVER/
    check "nginx basic-auth failures banned 10.200.0.31 (after $tries requests)" in_kernel 10.200.0.31
    check "listed under nginx-http-auth" listed 10.200.0.31 nginx-http-auth
    # One wrong password from SOURCE: curl speaks IMAP and SMTP AUTH, and
    # --interface picks the source address.
    mail_login() { # mail_login SOURCE imap|smtp
      local url="imap://$SERVER/" extra=()
      [[ $2 == smtp ]] && { url="smtp://$SERVER/"; extra=(--mail-from a@x.example --mail-rcpt b@x.example --upload-file /dev/null); }
      sudo ip netns exec attacker curl -s -m 15 --interface "$1" -u bob:wrong "${extra[@]}" "$url" >/dev/null 2>&1 || true
    }
    attack_until_banned 10.200.0.32 90 mail_login 10.200.0.32 imap
    check "Dovecot failures banned 10.200.0.32 (after $tries logins)" in_kernel 10.200.0.32
    check "listed under dovecot" listed 10.200.0.32 dovecot
    attack_until_banned 10.200.0.33 90 mail_login 10.200.0.33 smtp
    check "Postfix SMTP AUTH failures banned 10.200.0.33 (after $tries logins)" in_kernel 10.200.0.33
    check "listed under postfix-sasl" listed 10.200.0.33 postfix-sasl
    report="$(sudo /usr/sbin/fwgd --test-filter nginx-http-auth /var/log/nginx/access.log)"
    check "--test-filter counts the real access.log" contains "$report" "10.200.0.31 "
    ;;
  confirm-keep)
    check "--confirm change" contains "$(sudo fwg --confirm 5 allow 8080/tcp)" "Run \`fwg confirm\` within 5 s"
    check "status shows it pending" contains "$(sudo fwg status)" "rolls back in"
    check "fwg confirm" contains "$(sudo fwg confirm)" "Change confirmed"
    sleep 7
    check "confirmed change stays" contains "$(sudo fwg status)" "8080/tcp"
    sudo fwg delete allow 8080/tcp >/dev/null
    ;;
  confirm-lockout)
    check "--confirm delete of the SSH rule" contains "$(sudo fwg --confirm 20 delete allow 22/tcp)" "within 20 s"
    check "SSH rule gone from the kernel" not bash -c "sudo nft list table inet fwg | grep -q 'tcp dport 22 accept'"
    ;;
  confirm-after)
    check "SSH rule back in the kernel" bash -c "sudo nft list table inet fwg | grep -q 'tcp dport 22 accept'"
    check "SSH rule back in the rules file" contains "$(sudo fwg status)" "22/tcp"
    check "nothing pending" not test -e /etc/fwg/pending.toml
    check "fwgd logged the rollback" bash -c "sudo journalctl -u fwgd.service --no-pager -q | grep -q 'not confirmed in time'"
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
    check "IPv6 jail ban restored in the kernel" in_kernel fd20::2
    check "fwg banned lists the IPv6 jail ban" listed fd20::2 sshd
    check "fwg banned lists the jail ban" listed 10.200.0.3 sshd
    check "fwg banned lists the manual ban" listed 192.0.2.50 manual
    check "unbanned address stayed unbanned" not in_kernel 10.200.0.2
    check "no fwgd errors in journal" bash -c '! sudo journalctl -b -u fwgd.service -p err --no-pager -q | grep -q .'
    ;;
  *)
    echo "usage: $0 install|enable|rules|ufw|sshd-capture|fwgd-install|bans|confirm-keep|confirm-lockout|confirm-after|after-reboot" >&2
    exit 2
    ;;
esac

exit $(( FAILURES > 0 ))

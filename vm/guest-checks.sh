#!/usr/bin/env bash
# Runs inside a test VM as the `fwg` user (over SSH); vm/smoke-test.sh drives it.
#   guest-checks.sh install         install both packages and verify their units start
#   guest-checks.sh enable          SSH lockout guard, then enable with SSH allowed
#   guest-checks.sh rules           every rule kind loads on this distro's nft
#   guest-checks.sh ufw             refuses to run alongside ufw (skipped if absent)
#   guest-checks.sh sshd-capture    record what this OpenSSH logs for each kind of failure
#   guest-checks.sh fwgd-install    check fwgd and the shipped jails
#   guest-checks.sh bans            failed SSH logins get banned; fwg ban/unban/banned/jail
#   guest-checks.sh services        nginx, Dovecot and Postfix jails ban real failed logins
#   guest-checks.sh confirm-keep    a confirmed --confirm change stays
#   guest-checks.sh confirm-lockout delete the SSH rule with --confirm (the host then checks
#                                   new logins fail, and work again after the rollback)
#   guest-checks.sh confirm-after   the rollback put the SSH rule back
#   guest-checks.sh after-reboot    rules and bans came back at boot
#   guest-checks.sh import          fwg import ufw/fail2ban agree with what ufw and
#                                   fail2ban themselves report
#   guest-checks.sh lifecycle       verify package upgrades, removal and purge
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
listed() { sudo /usr/sbin/fwg banned | awk -v addr="$1" -v jail="$2" '$1 == addr && $2 == jail {found = 1} END {exit !found}'; }
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

apt_install() {
  local attempt
  for attempt in 1 2; do
    if sudo apt-get -o DPkg::Lock::Timeout=300 update -q > /tmp/fwg-package-apt.log 2>&1 &&
       sudo env DEBIAN_FRONTEND=noninteractive apt install -y -o Dpkg::Options::=--force-confold \
         "$@" >> /tmp/fwg-package-apt.log 2>&1; then
      return 0
    fi
  done
  cat /tmp/fwg-package-apt.log >&2
  return 1
}

package_version() {
  dpkg-query -W -f='${Version}' "$1"
}

case "${1:-}" in
  install)
    apt_install ./packages/fwg_*.deb ./packages/fwgd_*.deb
    check "firewall unit is enabled" systemctl is-enabled --quiet fwg.service
    check "firewall unit is active" systemctl is-active fwg.service
    check "daemon unit is enabled" systemctl is-enabled --quiet fwgd.service
    check "daemon unit is active" systemctl is-active fwgd.service
    check "config dir created 0750" test "$(sudo stat -c %a /etc/fwg)" = 750
    check "installation leaves the firewall disabled" not fwg_loaded
    ;;
  enable)
    out="$(sudo /usr/sbin/fwg enable 2>&1 || true)"
    check "enable over SSH refused without an SSH rule" contains "$out" "you are connected over SSH"
    check "refusal names port 22" contains "$out" "TCP port 22"
    check "firewall stayed off" not fwg_loaded
    sudo /usr/sbin/fwg allow 22/tcp >/dev/null
    check "enable succeeds once SSH is allowed" sudo /usr/sbin/fwg enable
    check "table loaded" fwg_loaded
    check "status active" contains "$(sudo /usr/sbin/fwg status)" "Status: active"
    ;;
  rules)
    sudo /usr/sbin/fwg allow 80,443/tcp
    sudo /usr/sbin/fwg allow 60000:61000/udp
    sudo /usr/sbin/fwg limit 2222/tcp
    sudo /usr/sbin/fwg reject from 192.0.2.0/24
    sudo /usr/sbin/fwg allow from 2001:db8::/32 to any port 53
    sudo /usr/sbin/fwg allow out on lo 9999/udp
    sudo /usr/sbin/fwg deny in on eth0 proto tcp from 10.0.0.0/8 port 1024:65535 to 10.0.0.1 port 5432 comment 'db guard'
    sudo /usr/sbin/fwg logging on
    sudo /usr/sbin/fwg default reject incoming
    check "all rule kinds load (nft $(sudo nft --version | awk '{print $2}'))" sudo /usr/sbin/fwg reload
    check "limit set exists" contains "$(sudo nft list ruleset)" "set limit4_"
    check "comment kept" contains "$(sudo nft list ruleset)" 'comment "db guard"'
    check "app list shows the shipped profiles" contains "$(/usr/sbin/fwg app list)" "Nginx Full"
    check "rule from a profile" contains "$(sudo /usr/sbin/fwg allow 'Nginx Full')" "allow 443/udp (Nginx Full)"
    check "profile rule loaded: TCP ports" contains "$(sudo nft list table inet fwg)" "tcp dport { 80, 443 } accept"
    check "profile rule loaded: UDP port" contains "$(sudo nft list table inet fwg)" "udp dport 443 accept"
    check "status names the profile" contains "$(sudo /usr/sbin/fwg status)" "80,443/tcp (Nginx Full)"
    check "delete by profile" contains "$(sudo /usr/sbin/fwg delete allow 'nginx full')" "deleted: allow 443/udp (Nginx Full)"
    sudo /usr/sbin/fwg default deny incoming >/dev/null
    ;;
  ufw)
    if ! command -v ufw >/dev/null; then
      echo "  skip  ufw not installed"
      exit 0
    fi
    sudo /usr/sbin/fwg disable >/dev/null
    sudo ufw allow 22/tcp >/dev/null
    sudo ufw --force enable >/dev/null
    out="$(sudo /usr/sbin/fwg enable 2>&1 || true)"
    check "enable refused while ufw is on" contains "$out" "ufw is enabled"
    sudo ufw disable >/dev/null
    check "enable works after ufw disable" sudo /usr/sbin/fwg enable
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
    check "fwgd --check accepts the shipped jails" sudo /usr/sbin/fwgd --check
    check "fwgd is active" systemctl is-active fwgd.service
    check "jail list shows sshd on the journal" contains "$(sudo /usr/sbin/fwg jail list)" "sshd  sshd    journal"
    check "only sshd is enabled out of the box" test \
      "$(sudo /usr/sbin/fwg jail list | awk 'NR > 1 {print $1}')" = sshd
    out="$(/usr/sbin/fwg banned 2>&1 || true)"
    check "non-root user is told to use sudo" contains "$out" "run \`sudo fwg ...\`"
    ;;
  bans)
    attack_until_banned 10.200.0.2 60 with_password 10.200.0.2 admin
    check "failed logins banned 10.200.0.2 (after $tries connections)" in_kernel 10.200.0.2
    check "it can no longer reach port 22" not can_connect
    check "fwg banned lists it under sshd" listed 10.200.0.2 sshd
    check "jail status lists it" contains "$(sudo /usr/sbin/fwg jail status sshd)" "10.200.0.2"
    check "jail status counts the ban" contains "$(sudo /usr/sbin/fwg jail status sshd)" "Bans:      1 since fwgd started"
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
    check "fwg unban" contains "$(sudo /usr/sbin/fwg unban 10.200.0.2)" "unbanned 10.200.0.2"
    check "unbanned: gone from the kernel" not in_kernel 10.200.0.2
    check "unbanned: gone from fwg banned" bash -c '! sudo /usr/sbin/fwg banned | grep -wF 10.200.0.2 >/dev/null'
    check "unbanned: can connect again" can_connect
    # Bans that must come back after the reboot: one from the jail, one by hand.
    attack_until_banned 10.200.0.3 120 with_key 10.200.0.3 fwg
    check "key-only failures banned 10.200.0.3 (after $tries connections)" in_kernel 10.200.0.3
    attack_until_banned fd20::2 60 with_password fd20::2 admin
    check "IPv6 failed logins banned fd20::2 (after $tries connections)" in_kernel fd20::2
    check "it can no longer reach port 22 over IPv6" not can_connect "$SERVER6"
    check "IPv4 from the same attacker still allowed" can_connect
    check "fwg banned lists the IPv6 address under sshd" listed fd20::2 sshd
    check "fwg ban by hand" contains "$(sudo /usr/sbin/fwg ban 192.0.2.50 --time 2h)" "banned 192.0.2.50 for 2h"
    check "fwg ban IPv6 by hand" contains "$(sudo /usr/sbin/fwg ban 2001:db8::50 --time 2h)" "banned 2001:db8::50 for 2h"
    check "manual ban listed as manual" listed 192.0.2.50 manual
    check "no fwgd errors" bash -c '! sudo journalctl -u fwgd.service -p err --no-pager -q | grep . >/dev/null'
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
    # The package index from first boot goes stale (mirrors drop old versions), and
    # downloads sometimes fail: refresh it, and try twice.
    for try in 1 2; do
      sudo apt-get -o DPkg::Lock::Timeout=300 update -q >/tmp/apt.log 2>&1
      sudo apt-get -o DPkg::Lock::Timeout=300 install -y -q nginx apache2-utils dovecot-imapd \
        dovecot-pop3d postfix >>/tmp/apt.log 2>&1 && break
      (( try == 2 )) && { tail -5 /tmp/apt.log; exit 1; }
    done
    sudo htpasswd -bc /etc/nginx/.htpasswd alice right-password >/dev/null 2>&1
    echo 'server { listen 80 default_server; location / { auth_basic "test"; auth_basic_user_file /etc/nginx/.htpasswd; root /var/www/html; } }' \
      | sudo tee /etc/nginx/sites-enabled/default >/dev/null
    sudo systemctl restart nginx
    # Cleartext logins from the namespace (2.4 and 2.3 spell it differently), and
    # the SASL socket Postfix uses.
    if /usr/sbin/dovecot --version | grep '^2\.4' >/dev/null; then clear='auth_allow_cleartext = yes'; else clear='disable_plaintext_auth = no'; fi
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
      sudo sed -i 's/^enabled = false/enabled = true/' "/etc/fwg/jails.d/$f.toml"
    done
    # The firewall is on with incoming denied: open the mail ports, by profile.
    check "allow the mail services by profile" bash -c 'sudo /usr/sbin/fwg allow "Dovecot IMAP" && sudo /usr/sbin/fwg allow Postfix'
    check "fwgd --check accepts the service jails" sudo /usr/sbin/fwgd --check
    sudo systemctl restart fwgd.service; sleep 2
    check "jail list shows the three services" bash -c '[[ $(sudo /usr/sbin/fwg jail list | grep -cE "^(dovecot|postfix-sasl|nginx-http-auth) ") == 3 ]]'
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
    check "--confirm change" contains "$(sudo /usr/sbin/fwg --confirm 5 allow 8080/tcp)" "Run \`fwg confirm\` within 5 s"
    check "status shows it pending" contains "$(sudo /usr/sbin/fwg status)" "rolls back in"
    check "fwg confirm" contains "$(sudo /usr/sbin/fwg confirm)" "Change confirmed"
    sleep 7
    check "confirmed change stays" contains "$(sudo /usr/sbin/fwg status)" "8080/tcp"
    sudo /usr/sbin/fwg delete allow 8080/tcp >/dev/null
    ;;
  confirm-lockout)
    check "--confirm delete of the SSH rule" contains "$(sudo /usr/sbin/fwg --confirm 20 delete allow 22/tcp)" "within 20 s"
    check "SSH rule gone from the kernel" not bash -c "sudo nft list table inet fwg | grep -F 'tcp dport 22 accept' >/dev/null"
    ;;
  confirm-after)
    check "SSH rule back in the kernel" bash -c "sudo nft list table inet fwg | grep -F 'tcp dport 22 accept' >/dev/null"
    check "SSH rule back in the rules file" contains "$(sudo /usr/sbin/fwg status)" "22/tcp"
    check "nothing pending" not test -e /etc/fwg/pending.toml
    check "fwgd logged the rollback" bash -c "sudo journalctl -u fwgd.service --no-pager -q | grep -F 'not confirmed in time' >/dev/null"
    ;;
  after-reboot)
    check "unit active after boot" systemctl is-active fwg.service
    check "rules loaded at boot" fwg_loaded
    check "status active" contains "$(sudo /usr/sbin/fwg status)" "Status: active"
    check "no unit errors in journal" bash -c '! sudo journalctl -b -u fwg.service -p err --no-pager -q | grep . >/dev/null'
    check "fwgd active after boot" systemctl is-active fwgd.service
    check "jail ban restored in the kernel" in_kernel 10.200.0.3
    check "manual ban restored in the kernel" in_kernel 192.0.2.50
    check "IPv6 ban restored in the kernel" in_kernel 2001:db8::50
    check "IPv6 jail ban restored in the kernel" in_kernel fd20::2
    check "fwg banned lists the IPv6 jail ban" listed fd20::2 sshd
    check "fwg banned lists the jail ban" listed 10.200.0.3 sshd
    check "fwg banned lists the manual ban" listed 192.0.2.50 manual
    check "unbanned address stayed unbanned" not in_kernel 10.200.0.2
    check "no fwgd errors in journal" bash -c '! sudo journalctl -b -u fwgd.service -p err --no-pager -q | grep . >/dev/null'
    ;;
  import)
    export DEBIAN_FRONTEND=noninteractive
    # A freshly installed fail2ban would start and ban too; keep it from starting.
    printf '#!/bin/sh\nexit 101\n' | sudo tee /usr/sbin/policy-rc.d >/dev/null
    sudo chmod 0755 /usr/sbin/policy-rc.d
    for try in 1 2; do
      sudo apt-get -o DPkg::Lock::Timeout=300 update -q >/tmp/apt.log 2>&1
      sudo apt-get -o DPkg::Lock::Timeout=300 install -y -q ufw fail2ban >>/tmp/apt.log 2>&1 && break
      (( try == 2 )) && { tail -5 /tmp/apt.log; sudo rm -f /usr/sbin/policy-rc.d; exit 1; }
    done
    sudo rm -f /usr/sbin/policy-rc.d
    cfg=/tmp/fwg-import
    sudo rm -rf "$cfg"
    # ufw stays disabled: its commands only write its rule files.
    sudo ufw --force reset >/dev/null 2>&1
    {
      sudo ufw allow 22/tcp
      sudo ufw allow 80,443/tcp
      sudo ufw limit 2222/tcp
      sudo ufw deny from 192.0.2.0/24
      sudo ufw allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'office db'
      sudo ufw allow out 53
      sudo ufw reject 23
      sudo ufw allow in on eth0 to any port 8080
      sudo ufw allow OpenSSH
      sudo ufw allow 60000:61000/udp
      sudo ufw allow from 2001:db8::/32
      sudo ufw deny out on eth0 to 198.51.100.7 port 25 proto tcp
      sudo ufw route allow in on eth0 out on eth1 to 10.0.0.0/8 port 443 proto tcp
      sudo ufw insert 1 deny from 198.51.100.66
      sudo ufw default reject incoming
    } >/dev/null 2>&1
    check "import ufw --apply" sudo /usr/sbin/fwg --config-dir "$cfg" import ufw --apply
    # ufw's own list, minus the route rule fwg does not import yet.
    expected=$(sudo ufw show added | grep -c '^ufw ' || true)
    expected=$((expected - $(sudo ufw show added | grep -c '^ufw route' || true)))
    got=$(sudo grep -c '^\[\[rules\]\]' "$cfg/rules.toml" || true)
    check "every ufw rule but the route rule imported ($got of $expected)" test "$got" = "$expected"
    check "comment kept" sudo grep -q 'comment = "office db"' "$cfg/rules.toml"
    check "OpenSSH profile kept as a label" sudo grep -q 'app = "OpenSSH"' "$cfg/rules.toml"
    check "default policy imported" sudo grep -q 'incoming = "reject"' "$cfg/rules.toml"
    sudo ip netns add fwg-import 2>/dev/null || true
    check "the imported rules load into a real kernel" bash -c \
      "sudo /usr/sbin/fwg --config-dir $cfg show | sudo ip netns exec fwg-import nft -j -f -"
    sudo ip netns del fwg-import
    # fail2ban: the jail.local whose effective values fail2ban-client -d reports.
    sudo tee /etc/fail2ban/jail.local >/dev/null <<'JAILS'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
           192.0.2.0/24

[sshd]
enabled = true
maxretry = 3

[postfix-sasl]
enabled  = true
bantime  = 2h

[dovecot]
enabled = true
findtime: 600

[nginx-http-auth]
enabled = true
bantime.increment = true
bantime.maxtime = 1w

[recidive]
enabled = true
JAILS
    check "import fail2ban --apply" sudo /usr/sbin/fwg --config-dir "$cfg" import fail2ban --apply
    check "fwgd accepts the imported jails" sudo /usr/sbin/fwgd --check --config-dir "$cfg" --filter-dir /usr/share/fwg/filters
    sudo fail2ban-client -d > /tmp/f2b-dump 2>/dev/null
    check "imported values match fail2ban-client -d" sudo python3 -I -c '
import ast, sys, tomllib
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
def secs(v):
    v = str(v)
    return int(v) if v.isdigit() else int(v[:-1]) * UNITS[v[-1]]
fwg = tomllib.load(open(sys.argv[1], "rb"))
f2b = {}
for line in open(sys.argv[2]):
    if line.startswith("["):
        item = ast.literal_eval(line.strip())
        if item[0] == "set" and len(item) >= 4:
            f2b.setdefault(item[1], {})[item[2]] = item[3:]
bad = []
for name, jail in fwg.items():
    want = f2b[name]
    pairs = [("max_retry", jail["max_retry"], int(want["maxretry"][0])),
             ("find_time", secs(jail["find_time"]), secs(want["findtime"][0])),
             ("ban_time", secs(jail["ban_time"]), secs(want["bantime"][0])),
             ("ignore", jail.get("ignore", []), list(want.get("addignoreip", [])))]
    if "bantime.maxtime" in want:
        pairs.append(("ban_time_max", secs(jail["ban_time_max"]), secs(want["bantime.maxtime"][0])))
    bad += [f"{name} {k}: fwg {a} fail2ban {b}" for k, a, b in pairs if a != b]
print("\n".join(bad)); sys.exit(1 if bad or len(fwg) != 4 else 0)
' "$cfg/jails.d/imported-fail2ban.toml" /tmp/f2b-dump
    check "fail2ban never started" not systemctl is-active fail2ban
    ;;
  lifecycle)
    # Finish the fresh-install smoke test before resetting the configuration.
    sudo /usr/sbin/fwg disable
    sudo apt-get purge -y fwg fwgd
    check "purging a fresh install removes shared configuration" not sudo test -e /etc/fwg

    # Give the old package a different default so dpkg must handle a conffile
    # changed by both the maintainer and the administrator during the upgrade.
    old_deb=(./old-packages/fwgd_*.deb)
    old_stage=$(mktemp -d)
    trap 'rm -rf "$old_stage"' EXIT
    dpkg-deb --raw-extract "${old_deb[0]}" "$old_stage"
    sed -i 's/^max_retry = 5$/max_retry = 4/' "$old_stage/etc/fwg/jails.d/sshd.toml"
    dpkg-deb --root-owner-group --build "$old_stage" "${old_deb[0]}" >/dev/null

    apt_install ./old-packages/fwg_*.deb "${old_deb[0]}"
    check "old package has its own jail default" sudo grep -Fx 'max_retry = 4' /etc/fwg/jails.d/sshd.toml
    old=$(package_version fwgd)
    old_invocation=$(systemctl show -p InvocationID --value fwgd.service)
    sudo /usr/sbin/fwg allow 22/tcp
    sudo sed -i 's/^max_retry = 4$/max_retry = 6/' /etc/fwg/jails.d/sshd.toml
    jail_sum=$(sudo sha256sum /etc/fwg/jails.d/sshd.toml)
    rules_sum=$(sudo sha256sum /etc/fwg/rules.toml)

    apt_install ./packages/fwg_*.deb ./packages/fwgd_*.deb
    version=$(dpkg-deb -f ./packages/fwgd_*.deb Version)
    check "old package version precedes the new one" dpkg --compare-versions "$old" lt "$version"
    check "firewall package upgraded" test "$(package_version fwg)" = "$version"
    check "daemon package upgraded" test "$(package_version fwgd)" = "$version"
    new_invocation=$(systemctl show -p InvocationID --value fwgd.service)
    check "daemon service restarted" bash -c \
      '[[ -n $1 && $1 != "$2" ]] && systemctl is-active --quiet fwgd.service' \
      _ "$new_invocation" "$old_invocation"
    check "firewall service active after upgrade" systemctl is-active fwg.service
    check "daemon service active after upgrade" systemctl is-active fwgd.service
    check "edited jail kept on upgrade" test "$(sudo sha256sum /etc/fwg/jails.d/sshd.toml)" = "$jail_sum"
    check "rules kept on upgrade" test "$(sudo sha256sum /etc/fwg/rules.toml)" = "$rules_sum"

    sudo apt-get remove -y fwg fwgd
    check "firewall binary removed" not test -e /usr/sbin/fwg
    check "daemon binary removed" not test -e /usr/sbin/fwgd
    check "firewall unit stopped on remove" not systemctl is-active fwg.service
    check "daemon unit stopped on remove" not systemctl is-active fwgd.service
    check "edited jail kept on remove" test "$(sudo sha256sum /etc/fwg/jails.d/sshd.toml)" = "$jail_sum"
    check "rules kept on remove" test "$(sudo sha256sum /etc/fwg/rules.toml)" = "$rules_sum"

    sudo apt-get purge -y fwgd
    check "purging daemon removes its jail conffiles" not sudo test -e /etc/fwg/jails.d/sshd.toml
    check "purging daemon removes its database" not sudo test -e /var/lib/fwg
    check "purging daemon keeps the firewall's rules" test "$(sudo sha256sum /etc/fwg/rules.toml)" = "$rules_sum"
    sudo apt-get purge -y fwg
    check "purging the last package removes /etc/fwg" not sudo test -e /etc/fwg
    ;;
  *)
    echo "usage: $0 install|enable|rules|ufw|sshd-capture|fwgd-install|bans|confirm-keep|confirm-lockout|confirm-after|after-reboot|import|lifecycle" >&2
    exit 2
    ;;
esac

exit $(( FAILURES > 0 ))

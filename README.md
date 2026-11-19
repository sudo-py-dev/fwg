# fwg

A simple, fast firewall for Linux, written in Rust on top of nftables.
`fwg` (short for *fwguard*) uses ufw-style commands, and its daemon `fwgd` bans
addresses that keep failing to log in, in the style of fail2ban.

> **Status:** early development (0.1 alpha). Not yet ready for production.

## Usage

```bash
sudo fwg allow 22/tcp                 # allow SSH first if you are connected over SSH
sudo fwg allow 80,443/tcp
sudo fwg allow "Nginx Full"           # an application profile: fwg app list, fwg app info NAME
sudo fwg limit 2222/tcp               # ~6 new connections per source, then throttled
sudo fwg allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'office db'
sudo fwg deny out 25
sudo fwg default deny incoming
sudo fwg enable
sudo fwg status --numbered
sudo fwg delete 2
```

Rules are kept in `/etc/fwg/rules.toml` and loaded as one nftables table, `inet fwg`.
Every change is applied atomically: the kernel gets the whole new ruleset or nothing.

`fwg enable` refuses to run (unless `--force`) when it would block new SSH logins, or
when ufw or firewalld is also active.

Any change can be made on trial with `--confirm SECS`: unless you run `fwg confirm`
in time, `fwgd` puts the previous rules back, so a rule that cuts off your SSH session
undoes itself. `fwg rollback` undoes it at once.

```bash
sudo fwg --confirm 60 default deny incoming
sudo fwg confirm                      # from a new SSH login, to show it still works
```

Run `fwg --help` for all commands.

## Banning (`fwgd`)

`fwgd` reads logs (the systemd journal by default), counts failures per source
address with *filters*, and bans repeat offenders in the kernel according to
*jails*. Bans live in their own nftables table, `inet fwg_ban`, so `fwg reload`
and `fwg disable` never lift them; they expire in the kernel by themselves and are
restored after a reboot.

| What | Where |
|---|---|
| Jails (yours to edit) | `/etc/fwg/jails.d/*.toml` — example: [`dist/jails.d/sshd.toml`](dist/jails.d/sshd.toml) |
| Shipped filters | `/usr/share/fwg/filters/*.toml` — from [`filters/`](filters) |
| Your own filters, or overrides of shipped ones (same name wins) | `/etc/fwg/filters/*.toml` |
| Ban history | `/var/lib/fwg/fwg.db` |
| Control socket (root only) | `/run/fwg/fwgd.sock` |

```bash
sudo fwg banned                       # banned addresses, their jail and the time left
sudo fwg ban 192.0.2.7 --time 1d      # ban by hand (default 1h)
sudo fwg unban 192.0.2.7
sudo fwg jail list
sudo fwg jail status sshd
sudo fwgd --check                     # validate jails and filters without starting
sudo journalctl _COMM=sshd _COMM=sshd-session -o cat | fwgd --test-filter sshd   # what a filter counts
```

Shipped filters: `sshd`, `dovecot` (IMAP/POP3), `postfix-sasl` (SMTP AUTH) and
`nginx-http-auth` (basic auth, from `access.log`). `dist/jails.d/` has a jail for each;
only `sshd` is enabled, the others say `enabled = false` until you change it.

Add your own management network to a jail's `ignore` list so a mistyped password
cannot lock you out.

## Install from source

Requires Rust 1.89+ and the `nftables` package.

```bash
cargo build --release
sudo install -m 0755 target/release/fwg target/release/fwgd /usr/sbin/
sudo install -m 0644 dist/fwg.service dist/fwgd.service /etc/systemd/system/
sudo install -d -m 0755 /usr/share/fwg/filters
sudo install -m 0644 filters/*.toml /usr/share/fwg/filters/
sudo install -d -m 0755 /usr/share/fwg/apps
sudo install -m 0644 apps/*.toml /usr/share/fwg/apps/
sudo install -d -m 0750 /etc/fwg /etc/fwg/jails.d
sudo install -m 0644 dist/jails.d/*.toml /etc/fwg/jails.d/
sudo systemctl daemon-reload
sudo systemctl enable fwg.service     # loads the rules at boot
sudo systemctl enable --now fwgd.service
```

## Development

```bash
cargo test --workspace     # includes real-traffic tests in network namespaces, no root needed
vm/smoke-test.sh           # full-system test in throwaway Debian/Ubuntu VMs (QEMU/KVM)
```

Design decisions, the test strategy and the roadmap are in [STACK_NOTES.md](STACK_NOTES.md).

## License

MIT OR Apache-2.0

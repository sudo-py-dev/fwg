# fwg

A simple, fast firewall for Linux, written in Rust on top of nftables.
`fwg` (short for *fwguard*) uses ufw-style commands; log-based banning in the
style of fail2ban is planned next.

> **Status:** early development (Phase 1: the firewall CLI). Not yet ready for production.

## Usage

```bash
sudo fwg allow 22/tcp                 # allow SSH first if you are connected over SSH
sudo fwg allow 80,443/tcp
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

Run `fwg --help` for all commands.

## Install from source

Requires Rust 1.89+ and the `nftables` package.

```bash
cargo build --release
sudo install -m 0755 target/release/fwg /usr/sbin/fwg
sudo install -m 0644 dist/fwg.service /etc/systemd/system/fwg.service
sudo systemctl enable fwg.service     # loads the rules at boot
```

## Development

```bash
cargo test --workspace     # includes real-traffic tests in network namespaces, no root needed
vm/smoke-test.sh           # full-system test in throwaway Debian/Ubuntu VMs (QEMU/KVM)
```

Design decisions, the test strategy and the roadmap are in [STACK_NOTES.md](STACK_NOTES.md).

## License

MIT OR Apache-2.0

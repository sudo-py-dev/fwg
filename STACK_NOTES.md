# fwg — Stack Notes

Decisions for **fwg** (long name: *fwguard*), a Rust firewall manager (ufw-style) plus
log-based intrusion banning (fail2ban-style) on top of nftables.

Every decision lists **what**, **why**, and **what was verified** on a Linux x86_64
development machine (nftables 1.0.9, stable Rust) on 2026-11-18.
If a decision changes, update this file in the same commit.

---

## 1. Ground rules (non-negotiable)

| Rule | How it is enforced |
|---|---|
| No `unsafe` in our code | `unsafe_code = "forbid"` in `[workspace.lints.rust]` |
| If `unsafe` is ever truly unavoidable | Only in one isolated crate, every block has `// SAFETY:` (`clippy::undocumented_unsafe_blocks = "deny"`), plus tests. Needs a note in this file first. |
| Every public item documented | `missing_docs = "deny"` |
| No panics in production paths | `clippy::unwrap_used`, `expect_used`, `panic` = `deny` (allowed in tests only) |
| Typed errors in libraries | `thiserror` — every library crate exposes its own `Error` enum |
| Contextual errors in binaries | `anyhow` + `.context("…")` at every I/O boundary |
| Lints and formatting clean | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (pedantic on) |
| Untrusted input parsed once at the edge | CLI args, config files, log lines → typed values; inner code never re-validates |
| No shell strings | External programs (`nft`, `journalctl`) run via `std::process::Command` with an argument array, never `sh -c` |
| The dev machine's real firewall is never touched by tests | All firewall tests run in unprivileged network namespaces (§6) or in a VM |

## 2. Language and toolchain

- **Rust edition 2024**, stable channel.
- **MSRV: 1.88** — the highest MSRV among planned dependencies (`notify` 8.2, `proptest` 1.12).
  Edition 2024 alone needs 1.85.
  *Packaging note:* official Debian/Ubuntu packaging later needs their archive's rustc
  to be ≥ 1.88; re-check when we get there.
- `Cargo.lock` is committed (this is an application).

## 3. Config format: **TOML** (decided)

| Format | Verdict | Reason |
|---|---|---|
| **TOML** | ✅ chosen | Comments allowed, strict types (no implicit conversions), no indentation traps, the Rust ecosystem standard (users know it from `Cargo.toml`), `toml` crate is maintained and serde-native. Our config is shallow, which is where TOML shines. |
| YAML | ❌ | Indentation errors are silent and dangerous in a firewall; implicit typing (`no` → `false`, `010` → octal); `serde_yaml` is archived/unmaintained. |
| JSON | ❌ for humans | No comments, noisy to hand-edit. **Used only as a machine format**: the nftables wire format and CLI↔daemon IPC. |
| INI (fail2ban style) | ❌ | No types, many dialects; we only *read* it in the future `fwg import fail2ban`. |

### File layout

| Path | Owner | Format | Purpose |
|---|---|---|---|
| `/etc/fwg/fwg.toml` | **Human** (CLI never rewrites it) | TOML | Global settings: IPv6 on/off, logging level, safety options |
| `/etc/fwg/rules.toml` | **CLI** (`fwg allow …` writes it) | TOML | Firewall rules + default policies + enabled flag. Has `version = 1` for future migrations and a "managed by fwg" header. Hand edits are allowed but comments are not preserved. |
| `/etc/fwg/jails.d/*.toml` | Human | TOML | (Phase 2) jail definitions |
| `/usr/share/fwg/filters/*.toml` | Package | TOML | (Phase 2) shipped clean-room filters |
| `/etc/fwg/filters/*.toml` | Human | TOML | (Phase 2) local filter overrides, same name wins |
| `/var/lib/fwg/fwg.db` | Daemon | Turso (SQLite format) | (Phase 2) ban history, events, stats |
| `/run/fwg/fwgd.sock` | Daemon | JSON lines | (Phase 2) CLI ↔ daemon IPC, mode `0600`, root only |

Writes to any file fwg owns are **atomic**: write a temp file in the same directory,
`fsync`, then `rename` (via `tempfile::NamedTempFile::persist`). Files are created `0640`.
Every path can be overridden (`--config-dir` / `FWG_CONFIG_DIR`) so tests never touch `/etc`.

Unknown keys in config files are **rejected** (`#[serde(deny_unknown_fields)]`) so typos
fail loudly instead of being ignored.

## 4. nftables backend (decided — changed from the earlier plan)

**Decision: our own small, typed JSON schema module inside `fwg-nft`, applied with
`nft -j -f -` (ruleset on stdin). We do *not* use the `nftables` crate.**

Why the change (verified 2026-11-18 against `nftables` crate 0.6.3):

1. The crate's `Set` statement has no `stmt` field, so it **cannot express per-source rate
   limiting** (`update @set { ip saddr limit rate over 6/minute } drop`), which `fwg limit`
   needs.
2. Worse, because the crate does not reject unknown fields, **reading such a rule back
   silently drops the limit**. A firewall tool must never misreport rules.
3. The only workaround in the crate is the `meter` statement, which nftables marks
   deprecated (nft 1.0.9 still accepts it — verified — but we won't build on it).
4. Our own module covers exactly the subset we generate (~20 types), adds fewer
   dependencies (the crate pulls `schemars`, `strum`, …), and every type is tested against
   the real `nft` binary (§6, tier 2).

Backend rules:

- Exactly one table per role, family `inet` (IPv4 + IPv6 in one table):
  - `inet fwg` — static rules (the ufw part). **Rebuilt atomically** on every change with
    one batch: `add table` → `delete table` → `add table` → chains → sets → rules. The
    leading `add` makes `delete` safe when the table does not exist. One `nft` batch =
    one kernel transaction: either everything applies or nothing does.
    ✅ Verified: first apply and re-apply give exactly one copy of each rule; a batch with
    an error is rejected as a whole and the previous rules stay active.
  - `inet fwg_ban` — (Phase 2) ban sets with kernel timeouts and a drop chain at a
    higher priority (earlier) than `fwg`. **Never rebuilt** by rule changes, so bans
    survive `fwg reload`.
    ✅ Verified with real traffic: with `fwg` allowing port 2222, a banned source (priority
    `filter - 10`) was blocked, stayed blocked while `fwg` was rebuilt, and was let through
    again automatically when the kernel timeout expired.
- Base policy (generated in this order in `input`):
  1. `ct state established,related accept`
  2. `ct state invalid drop`
  3. `iif "lo" accept`
  4. `meta l4proto { icmp, ipv6-icmp } accept` (IPv6 breaks without neighbour discovery;
     path-MTU discovery needs ICMP too)
  5. DHCP client replies (`udp sport 67 dport 68`, `udp sport 547 dport 546`)
  6. user rules, in order
  7. optional rate-limited `log` (when logging is on)
  8. if default is `reject`: `tcp reject with tcp reset`, then `reject` (ICMPX
     port-unreachable). Chain policy itself is always `drop` or `accept` (nftables has no
     `reject` policy).
- `limit` rules: per-rule dynamic sets `limit4_<n>` / `limit6_<n>` (`flags dynamic,timeout`,
  `timeout 1m`, `size 65535`) — counts are per rule and per source, never shared.
- Interface names, comments and other strings are validated (length, allowed charset)
  before they reach nft — no injection through `iifname`/`comment`.
- Minimum supported versions (**to verify in the VM matrix**, §6 tier 4):
  nftables ≥ 1.0.2 (Ubuntu 22.04), kernel ≥ 5.10.

Exact JSON for every construct above was captured from real nft output on this machine
(`unshare -rn nft -j list ruleset`) and is the reference for the schema module.

## 5. Crates (planned, pinned to exact versions in `Cargo.lock`)

| Area | Crate | Version | Licence | Phase |
|---|---|---|---|---|
| Errors (libs) | `thiserror` | 2.0.21 | MIT/Apache | 1 |
| Errors (bins) | `anyhow` | 1.0.104 | MIT/Apache | 1 |
| CLI | `clap` (derive) | 4.6.8 | MIT/Apache | 1 |
| IP networks | `ipnet` (serde) | 2.12.2 | MIT/Apache | 1 |
| Serialization | `serde`, `serde_json` | 1.0.229 / 1.0.154 | MIT/Apache | 1 |
| Config | `toml` | 1.2.1 | MIT/Apache | 1 |
| Atomic writes | `tempfile` | 3.27.0 | MIT/Apache | 1 |
| Async runtime | `tokio` | 1.54.1 | MIT | 2 |
| Logging | `tracing`, `tracing-subscriber` | 0.1.44 / 0.3.23 | MIT | 2 |
| File watching | `notify` | 8.2.2 | CC0 | 2 |
| Regex | `regex` | 1.13.2 | MIT/Apache | 2 — **linear time, ReDoS-safe** on attacker-controlled log lines |
| Dates | `jiff` | 1.0.1 | Unlicense/MIT | 2 |
| Database | `turso` **pinned `=0.8.3`** | 0.8.3 | MIT | 2 |
| Tests | `insta` (snapshots), `proptest`, `assert_cmd` | 1.49.0 / 1.12.0 / 2.2.2 | Apache / MIT/Apache | 1 |

No crate is added without a line in this table.

### Turso (pinned, behind a trait)
- `turso = "=0.8.3"`, upgraded only on purpose, with the crash-recovery tests passing.
- Lives only in `fwg-store`, behind a `Store` trait. Nothing else imports `turso`.
- **The firewall never depends on the DB.** Active bans live in the kernel (`fwg_ban` sets
  with timeouts). If the DB is broken, protection keeps working; the daemon rebuilds state.
- Phase 2 spike before use: check the default features (0.8.3 pulls `hyper`/`rustls` for
  sync — disable them with `default-features = false` if possible), check it builds with
  our MSRV, and test kill-during-write recovery.
- `forbid(unsafe_code)` covers *our* crates only; dependencies (including Turso) contain
  `unsafe` internally. That is audited with `cargo-deny` (advisories) and reviewed on
  upgrades.

### journald
Read with `journalctl -f -o json --cursor-file …` as a child process (argument array)
instead of the `systemd` crate's C bindings — keeps us free of FFI `unsafe`.

## 6. Testing environment (verified on this machine)

Five tiers. Tiers 0–3 need **no root** and run on every `cargo test`.

| Tier | What | Tool | Verified |
|---|---|---|---|
| 0 | Unit tests: rule parser, rule model, policy logic | `cargo test` | — |
| 1 | Snapshot of generated nft JSON for every rule kind | `insta` | — |
| 2 | **Real nft load**: apply the generated ruleset inside an unprivileged user+network namespace, read it back with `nft -j list`, compare | `unshare -rn` | ✅ works (`unshare -rn nft …` loads rulesets as non-root) |
| 3 | **Real traffic**: two namespaces joined by a veth pair; servers on the "host" side, client probes from the other side; assert open / blocked / RST / ICMP / rate-limited, IPv4 and IPv6 | `unshare -rn` + nested `unshare -n` + `ip link … veth` + `nsenter` | ✅ works — with "allow 2222" only, port 2222 was OPEN and 8080 BLOCKED |
| 4 | **Full system**: systemd unit, boot persistence, real `sshd` lockout protection, `.deb` install, coexistence with ufw, distro matrix (Debian 12/13, Ubuntu 22.04/24.04) | QEMU + KVM, cloud images, cloud-init seeded over HTTP (`-smbios type=1,serial=ds=nocloud;s=http://10.0.2.2:PORT/`) so no ISO tools are needed | ✅ Debian 13 and Ubuntu 24.04 VMs boot, provision and restart (see §6.1) |
| 5 | CI | GitHub Actions (runners have root, so tiers 2–3 also run as real root) | to set up |

Available for traffic tests: `ip`, `tc` (latency/loss injection), `socat`, `nc`, `python3`.
Missing on the host but optional: `conntrack`, `hping3`, `iperf3` (`conntrack` is installed
inside the test VMs).

Rust dev tools to install (`cargo install`): `cargo-nextest`,
`cargo-insta`, `cargo-deny`, `cargo-llvm-cov`. `cargo-fuzz` also needs a nightly toolchain
(`rustup toolchain install nightly`) — only for fuzzing the parsers, Phase 2.

**Safety rule:** never run `sudo fwg enable` on the dev machine. Real-root testing happens
in the VM (tier 4) or CI only.

### 6.1 Test VMs (`vm/fwg-vm`)

Why VMs and not Docker: containers share the host kernel, so a firewall test inside a
container is a test of the *host* firewall; Docker also rewrites the host's own
iptables/nftables rules, and containers don't run systemd or a real `sshd`. A VM is a
separate machine with its own kernel — breaking its firewall costs nothing.

| VM | Image (official, checksum-verified) | Kernel | nftables | SSH |
|---|---|---|---|---|
| `debian` | `debian-13-genericcloud-amd64.qcow2` (cloud.debian.org, SHA-512) | 6.12 | **1.1.3** | `127.0.0.1:2201` |
| `ubuntu` | `noble-server-cloudimg-amd64.img` (cloud-images.ubuntu.com, SHA-256) | 6.8 | **1.0.9** | `127.0.0.1:2202` |

- Two nftables versions (1.0.9 and 1.1.3) are covered from day one.
- Ubuntu ships `ufw` (inactive) — used for the coexistence tests.
- Base images are read-only (`chmod 444`); each VM writes to a copy-on-write overlay in
  `vm/state/`, so `vm/fwg-vm reset <vm>` returns a factory-fresh machine.
- Provisioning: cloud-init seeded over HTTP from `127.0.0.1` (no ISO tools). User `fwg`,
  key-only SSH, passwordless sudo, plus `nftables`, `socat`, `netcat`, `conntrack`, `python3`.
- No root needed on the host: QEMU user-mode networking, SSH forwarded to `127.0.0.1` only.
- Resources: 2 vCPU, 2 GB RAM each; overlays ~320–570 MB after provisioning.
  First boot ~2–3 min (package install), later boots ~20 s.
- Checksums were fetched over HTTPS from the same servers as the images (protects against
  corruption and relies on TLS for authenticity; GPG signatures were not checked).
- `vm/images/` and `vm/state/` (images, overlays, the test SSH key, console logs) are
  git-ignored and never leave this machine.
- On Debian, `/usr/sbin` is not in a normal user's `PATH`. fwg runs as root, but the
  backend must still find `nft` reliably: look in `/usr/sbin/nft` and `/sbin/nft` before
  falling back to `PATH`.

```bash
vm/fwg-vm up debian            # boot (first time provisions)
vm/fwg-vm push debian target/release/fwg
vm/fwg-vm ssh debian 'sudo ./fwg status'
vm/fwg-vm down debian          # or: reset debian
```

## 7. Workspace layout

```
fwg/
├── Cargo.toml            # workspace, shared lints, pinned deps
├── STACK_NOTES.md        # this file
├── crates/
│   ├── fwg-core/         # rule model, CLI-independent parsing, config + rules files (TOML)
│   ├── fwg-nft/          # typed nft JSON schema, ruleset builder, `Backend` trait + `nft` runner
│   ├── fwg-store/        # (Phase 2) `Store` trait + Turso implementation
│   ├── fwg-watch/        # (Phase 2) log sources, filters, jails
│   └── fwg-ipc/          # (Phase 2) socket protocol types
├── fwg/                  # CLI binary (clap + anyhow)
├── fwgd/                 # (Phase 2) daemon binary (tokio + anyhow)
├── tests/netns/          # tier 2–3 harness
└── dist/                 # systemd units, packaging config
```

Boundaries: `fwg-core` knows nothing about nftables; `fwg-nft` depends on `fwg-core`;
binaries are thin (parse args → call libraries → print). The `Backend` trait in `fwg-nft`
lets the CLI be tested with a fake backend.

## 8. Phase 1 scope (CLI firewall, no daemon)

Commands: `enable`, `disable`, `reload`, `status [--verbose|--numbered]`,
`allow|deny|reject|limit [in|out] [on IFACE] <rule>`, `delete <N>`, `insert <N> <rule>`,
`default <allow|deny|reject> [incoming|outgoing|routed]`, `logging <on|off>`, `reset`,
`show` (print the generated ruleset without applying — dry run).

Rule grammar (ufw-compatible subset):
`22`, `22/tcp`, `80,443/tcp`, `1000:2000/udp`,
`from <addr|cidr|any> [port P] to <addr|cidr|any> [port P] [proto tcp|udp]`.

Safety in Phase 1:
- `enable` refuses when running over SSH (`SSH_CONNECTION` set) and no rule allows the SSH
  port, unless `--force`.
- `enable` warns and refuses if ufw or firewalld is active, unless `--force`
  (two firewalls both filter every packet, which confuses users).
- Phase 2 adds `enable --confirm 60` (auto-rollback unless confirmed), done by the daemon.

Not in Phase 1: route/forward rules (only the `routed` default policy), app profiles,
NAT.

## 9. Licence

Default: **MIT OR Apache-2.0** (clean-room: no ufw/fail2ban code, regex, or test files
copied). Change before the first public release if another licence is preferred.

## 10. Open items

- [x] Download VM images (Debian 13 + Ubuntu 24.04 cloud images) for tier 4.
- [ ] Add older targets to the VM matrix (Debian 12, Ubuntu 22.04 for nft 1.0.2).
- [ ] Install the dev tools listed in §6.
- [ ] Verify nft ≥ 1.0.2 / kernel ≥ 5.10 support in the VM matrix.
- [ ] Turso spike (features, MSRV, crash recovery) at the start of Phase 2.

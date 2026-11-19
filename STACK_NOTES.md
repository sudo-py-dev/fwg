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
| No panics in production paths | `clippy::unwrap_used`, `expect_used`, `panic` = `deny`; `clippy.toml` allows them in `#[test]` code, and integration-test files allow them for their helpers |
| Typed errors in libraries | `thiserror` — every library crate exposes its own `Error` enum |
| Contextual errors in binaries | `anyhow` + `.context("…")` at every I/O boundary |
| Lints and formatting clean | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (pedantic on) |
| Untrusted input parsed once at the edge | CLI args, config files, log lines → typed values; inner code never re-validates |
| No shell strings | External programs (`nft`, `journalctl`) run via `std::process::Command` with an argument array, never `sh -c` |
| The dev machine's real firewall is never touched by tests | All firewall tests run in unprivileged network namespaces (§6) or in a VM |
| Every commit is signed; `main` changes only through pull requests | Commits are signed with an SSH key (`gpg.format ssh`); the `protect` ruleset on `main` requires signed commits, a PR review and blocks force pushes and deletion |

## 2. Language and toolchain

- **Rust edition 2024**, stable channel.
- **MSRV: 1.89** — needed for `std::fs::File::lock` (the rules-file lock, no extra crate).
  Other dependencies need at most 1.88 (`proptest` 1.12). CI checks it.
  *Packaging note:* official Debian/Ubuntu packaging later needs their archive's rustc
  to be ≥ 1.89; re-check when we get there.
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
| `/etc/fwg/fwg.toml` | **Human** (CLI never rewrites it) | TOML | (Phase 2) daemon settings. Not needed in Phase 1: everything there is CLI-managed state in `rules.toml`. |
| `/etc/fwg/rules.toml` | **CLI** (`fwg allow …` writes it) | TOML | Firewall rules + default policies + enabled flag. Has `version = 1` for future migrations and a "managed by fwg" header. Hand edits are allowed but comments are not preserved. |
| `/etc/fwg/jails.d/*.toml` | Human | TOML | (Phase 2) jail definitions |
| `/usr/share/fwg/filters/*.toml` | Package | TOML | (Phase 2) shipped clean-room filters |
| `/etc/fwg/filters/*.toml` | Human | TOML | (Phase 2) local filter overrides, same name wins |
| `/var/lib/fwg/fwg.db` | Daemon | Turso (SQLite format) | (Phase 2) ban history, events, stats |
| `/run/fwg/fwgd.sock` | Daemon | JSON lines | (Phase 2) CLI ↔ daemon IPC, mode `0600`, root only |

Writes to any file fwg owns are **atomic**: write a temp file in the same directory,
`fsync`, then `rename` (via `tempfile::NamedTempFile::persist`), then `fsync` the directory.
Files are created `0640`, `/etc/fwg` `0750`. Every access holds a lock on `/etc/fwg/.lock`
(shared to read, exclusive to write — the write guard type is required to save), so
concurrent `fwg` runs never lose changes. Files over 1 MiB are refused, and the format
`version` is checked before the rest is parsed. `fwg reset` keeps
`rules.toml.<unix-seconds>.bak`.
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
- `output` mirrors it: conntrack, `oif lo`, ICMPv6 (neighbour discovery must work even with
  `default deny outgoing`), DHCP client requests, user `out` rules, reject tail.
- **Routed traffic defaults to `disabled`: no `forward` chain at all.** A drop in our own
  forward chain would be final even if Docker/libvirt/LXD accept the packet in their
  tables, so fwg only filters forwarding when the user sets `fwg default deny routed`.
- `reject` rules: TCP gets `reject with tcp reset`, everything else ICMP port-unreachable
  (two nft rules when the rule covers both protocols).
- `limit` rules: per-rule dynamic sets `limit4_<n>` / `limit6_<n>` (`flags dynamic,timeout`,
  `timeout 1m`, `size 65535`) — counts are per rule and per source, never shared.
  `ct state new update @set { ip saddr limit rate over 6/minute burst 6 packets } drop`,
  then the accept rule: 6 new connections at once, then 1 per 10 s per source.
  ✅ Verified with traffic: 6 of 8 quick connections accepted; IPv6 counted separately.
- `nft` is run from fixed paths only (`/usr/sbin/nft`, `/sbin/nft`, `/usr/bin/nft`,
  `/bin/nft`), never looked up in `PATH`, because fwg runs as root. Cleared environment,
  `LC_ALL=C`, 30 s timeout.
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
| Regex | `regex` | 1.13.2 | MIT/Apache | 2 — **linear time, ReDoS-safe** on attacker-controlled log lines |
| Database | `turso` **pinned `=0.8.3`** | 0.8.3 | MIT | 2 |
| Tests | `insta` (snapshots), `proptest`, `assert_cmd` | 1.49.0 / 1.12.0 / 2.2.2 | Apache / MIT/Apache | 1 |

No crate is added without a line in this table.

### Turso (pinned, behind a trait)
- `turso = "=0.8.3"`, upgraded only on purpose, with the crash-recovery tests passing.
- Lives only in `fwg-store`, behind a `Store` trait. Nothing else imports `turso`.
- **The firewall never depends on the DB.** Active bans live in the kernel (`fwg_ban` sets
  with timeouts). If the DB is broken, protection keeps working; the daemon rebuilds state.
- Used with `default-features = false`: drops `mimalloc` (a C allocator that would replace
  the global allocator) and `fts` (full-text search). Network sync (`hyper`, `rustls`) is
  already opt-in and stays off.
- ✅ Spike (2026-11-18): a writer committing 2-row transactions was `kill -9`ed at random
  30 times. Every reported commit survived, at most the one in-flight commit appeared,
  no transaction was ever half-written, `PRAGMA integrity_check` stayed `ok`.
  This covers process crashes, not power loss (page cache survives `kill -9`); a VM
  hard-reset test is still open.
- ⚠️ Cost: 234 crates and ~4 min for a debug build. Acceptable because **only the daemon
  (`fwgd`) links it**; the `fwg` CLI asks the daemon over the socket and stays small.
- Turso declares no `rust-version`; the CI MSRV job is the check.
- Licences it adds beyond MIT/Apache: BSD-3-Clause (`subtle`, `sha1_smol`, `bindgen`) and
  ISC (`libloading`), both permissive and now allowed in `deny.toml`; `cfg_block` ships only
  an Apache-2.0 notice, declared with a `clarify` entry pinned to the file's hash.
- `bindgen` is a build-dependency of `turso_sdk_kit`, but its build script exits at once on
  non-Windows targets: on Linux no libclang or C compiler is needed (checked in `build.rs`).
- Verified on 0.8.3 before use: tuples as parameters, `IF NOT EXISTS` indexes, upsert
  (`ON CONFLICT … DO UPDATE`), row counts from `UPDATE`/`DELETE`, `BEGIN`/`ROLLBACK`, and
  that `Database`, `Connection` and their futures are `Send + Sync`.
- `forbid(unsafe_code)` covers *our* crates only; dependencies (including Turso) contain
  `unsafe` internally. That is audited with `cargo-deny` (advisories) and reviewed on
  upgrades.

### journald
Read with `journalctl --follow --output=json --lines=0 [--after-cursor=C] _COMM=p …` as a
child process (argument array) instead of the `systemd` crate's C bindings — keeps us free
of FFI `unsafe`. Verified on systemd 255:
- `--lines=0` starts at the end; `--after-cursor` resumes exactly after an entry, including
  entries logged while fwg was stopped (the two flags combine correctly).
- Each entry has `__CURSOR`, so **the daemon stores the last cursor itself** instead of
  `--cursor-file`, which journalctl writes only on a clean exit (std can only SIGKILL).
- Messages that are not valid UTF-8 arrive as a JSON array of bytes; handled.
- **Matching uses the trusted `_COMM` field** (the real process name, set by journald), not
  `SYSLOG_IDENTIFIER`/`-t`, which any local user can set. Verified: `logger -t sshd` has
  `_COMM=logger` and is not matched. Tested in `crates/fwg-watch/tests/journal.rs`.
- The event time is journald's `__REALTIME_TIMESTAMP`, so no date parsing is needed.
- The reader blocks on a thread; dropping its `JournalHandle` kills journalctl, which ends
  the blocked read cleanly.

**Log files cannot be trusted the same way.** Anything a local user sends to syslog with
`logger -t sshd` lands in `auth.log` looking exactly like sshd. Jails should use
`log = "journal"` (the default); a file source trusts every local user not to forge lines.

## 6. Testing environment (verified on this machine)

Five tiers. Tiers 0–3 need **no root** and run on every `cargo test`.

| Tier | What | Tool | Verified |
|---|---|---|---|
| 0 | Unit tests: values, parser, rule set, rules file, nft runner, CLI logic against a fake backend, CLI binary end to end | `cargo test`, `proptest`, `assert_cmd` | ✅ |
| 1 | Snapshots: generated nft JSON for every rule kind, the `rules.toml` format, the `status` table | `insta` | ✅ |
| 2 | **Real nft load**: apply the generated ruleset inside an unprivileged user+network namespace, read it back with `nft -j list`, compare | `unshare -rn` (`crates/fwg-nft/tests/ruleset.rs`, `backend.rs` tests re-run themselves inside a namespace) | ✅ every scenario loads, twice, without duplicating the table |
| 3 | **Real traffic**: two namespaces joined by a veth pair; servers on the "host" side, client probes from the other side; assert open / blocked / RST / ICMP / rate-limited, IPv4 and IPv6 | `fwg/tests/netns/traffic.sh` (firewall, 28 checks) and `crates/fwg-nft/tests/netns/ban_traffic.sh` (bans, 9 checks) sharing `tests/netns/harness.sh`, and `fwgd/tests/netns/daemon.sh` (daemon end to end with the real `fwg` CLI as client, 33 checks); run by `cargo test` (~7 s each) | ✅ breaking `limit`, the ban rule or `fwg unban` on purpose makes them fail |
| 4 | **Full system**: systemd units, boot persistence, real `sshd` lockout protection, coexistence with ufw, every rule kind on each distro's nft, real SSH brute force banned by `fwgd` | `vm/smoke-test.sh` (fresh VM each run, ~12 min for both) | ✅ Debian 13 (nft 1.1.3) and Ubuntu 24.04 (nft 1.0.9): all checks pass, incl. rules and bans back after reboot |
| 5 | CI: fmt, clippy, all tests with `FWG_REQUIRE_NETNS=1` (never skip), MSRV 1.89 check, `cargo-deny` | `.github/workflows/ci.yml`, `deny.toml` | ✅ set up |

Available for traffic tests: `ip`, `tc` (latency/loss injection), `socat`, `nc`, `python3`.
Missing on the host but optional: `conntrack`, `hping3`, `iperf3` (`conntrack` is installed
inside the test VMs).

Optional local dev tools (`cargo install`): `cargo-nextest`, `cargo-insta` (reviewing
snapshots; `INSTA_UPDATE=always cargo test` works without it), `cargo-deny` (CI runs it),
`cargo-llvm-cov`. `cargo-fuzz` also needs a nightly toolchain — only for fuzzing the log
parsers, Phase 2.

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
- SSH attacks in the smoke test come from a network namespace *inside* the VM
  (`10.200.0.0/24` on a veth pair), never from the host: host connections arrive from
  `10.0.2.2`, and banning that would cut off the harness's own SSH.
- `fwg-vm up` checks the cloud-init packages are really installed: when apt cannot
  reach the mirror, cloud-init still reports `done` with no errors (seen once on Debian).
- On Debian, `/usr/sbin` is not in a normal user's `PATH`; fwg finds `nft` through its
  fixed path list (§4), so this does not matter.

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
│   ├── fwg-watch/        # filters, jails, failure tracking (log sources: 2c)
│   └── fwg-ipc/          # control socket protocol (JSON lines)
├── fwg/                  # CLI binary (clap + anyhow)
│   └── tests/netns/      # tier 3: firewall traffic checks
├── fwgd/                 # daemon binary (tokio + anyhow)
├── filters/              # shipped clean-room filters (TOML)
├── tests/netns/          # tier 3: shared namespace harness and probe tool
├── vm/                   # tier 4: test VMs and the smoke test
└── dist/                 # systemd unit, packaging config
```

Boundaries: `fwg-core` knows nothing about nftables; `fwg-nft` depends on `fwg-core`;
binaries are thin (parse args → call libraries → print). The `Backend` trait in `fwg-nft`
lets the CLI be tested with a fake backend.

## 8. Phase 1 scope (CLI firewall, no daemon)

Commands: `enable`, `disable`, `reload`, `status [--verbose|--numbered]`,
`allow|deny|reject|limit [in|out] [on IFACE] <rule> [comment TEXT]`,
`delete <N | ACTION RULE>`, `insert <N> <ACTION> <rule>`,
`default <allow|deny|reject> [incoming|outgoing|routed]`, `logging <on|off>`, `reset`,
`show` (print the generated ruleset without applying — dry run).

Rule grammar (ufw-compatible subset):
`22`, `22/tcp`, `80,443/tcp`, `1000:2000/udp`,
`from <addr|cidr|any> [port P] to <addr|cidr|any> [port P] [proto tcp|udp]`.

Safety in Phase 1:
- `enable` refuses when running over SSH and no rule allows the SSH port, unless
  `--force`. The port comes from `SSH_CONNECTION`; `sudo` usually removes it, so fwg also
  walks up `/proc/<pid>/stat` looking for an `sshd`/`sshd-session` ancestor and then
  assumes port 22 (the message says "assumed"). Existing sessions are never cut
  (`ct state established` is accepted first); the risk is new logins.
- `enable` refuses if ufw (`ENABLED=yes` in `/etc/ufw/ufw.conf`) or firewalld (its nft
  table) is active, unless `--force` — two firewalls both filter every packet.
- Every change is loaded into the kernel first and saved only if that worked; if saving
  fails, the previous rules are loaded again.
- Phase 2 adds `enable --confirm 60` (auto-rollback unless confirmed), done by the daemon.

Not in Phase 1: route/forward rules (only the `routed` default policy), app profiles,
NAT.

## 9. Phase 2 design (log watching and banning)

The fail2ban part. A daemon, `fwgd`, reads logs, matches failures per source address and
bans repeat offenders in the kernel. Built in PR-sized steps:

| Step | What | Where |
|---|---|---|
| 2a ✅ | Ban table in the kernel: `inet fwg_ban`, sets `ban4`/`ban6` (`flags timeout`, `size 262144`), chain `input` at `priority filter - 10` dropping `@ban4`/`@ban6`. Ban = add-delete-add of the element in one batch (replaces any earlier timeout), unban = add-delete (never fails on a missing address). Ban time 1 s to 365 days. Re-creating the table keeps existing bans; `fwg reload`/`disable` never touch it. | `fwg-nft` |
| 2b ✅ | Filters (TOML: `description`, `programs`, `failures`, `ignore`; patterns must be anchored `^…$` and have exactly one `<HOST>`), jails (`log`, `max_retry` 5, `find_time` 10m, `ban_time` 1h, optional doubling up to `ban_time_max` 1w, `ignore`), sliding-window tracker (bounded, evicts the oldest tenth when full), `Watcher` tying them together. Pure logic. Clean-room `filters/sshd.toml` from OpenSSH message formats — **to verify against real sshd output in the VM (2f)**. | `fwg-watch` |
| 2c ✅ | Log sources: `FileTail` (polling; starts at the end; rotation drains the old file first; truncation restarts at 0; a file that appears later is read from its start; lines over 8 KiB skipped), syslog line parsing (rsyslog ISO and traditional timestamps), and `JournalReader` (journal, see §5). | `fwg-watch` |
| 2d ✅ | `Store` trait (record ban, count earlier bans, active bans — latest per address, end bans on unban, prune, journal cursors) with `TursoStore` (schema v1 created in one transaction; a newer schema is refused; bad rows are reported, not trusted) and `MemoryStore`. One contract test runs against both; Turso also tested for reopen and `kill -9` mid-write. | `fwg-store` |
| 2e ✅ | `fwgd`: loads jails (local filters override shipped ones), opens the DB, creates the ban table and restores running bans, then one loop handles log events, control requests (`status`, `banned`, `ban`, `unban`), saving journal cursors every 5 s and pruning history older than 90 d. Repeat offences counted over 30 d. Sources run on threads; SIGTERM saves cursors, stops them and removes the socket. Socket `0600` in a `0700` dir, peer uid checked, one request per connection, 1 MiB / 5 s limits. `dist/fwgd.service` (`systemd-analyze security`: 4.1 OK). | `fwgd`, `fwg-ipc` |
| 2f ✅ | CLI: `fwg ban IP [--time 1h]`, `fwg unban IP`, `fwg banned`, `fwg jail list`, `fwg jail status NAME`, over the control socket (`--socket`/`FWG_SOCKET` to override; 10 s limit to connect and again for the exchange — the connect runs on a thread because `UnixStream` has no connect timeout; plain errors for "not running" and "not root"). Example jail `dist/jails.d/sshd.toml`. VM test: failed SSH logins over IPv4 and IPv6 from a network namespace *inside* the VM get banned, shown by the CLI, lifted by `unban`, and kept across `systemctl restart fwgd` and a reboot. `filters/sshd.toml` verified against real OpenSSH output (§9.1). | `fwg`, `vm/` |

Decisions:

- **Kernel holds the truth for active bans.** Timeouts expire in the kernel, so a crashed
  daemon never leaves a ban stuck and never lifts one early. The DB is history plus a
  copy used to restore bans after a reboot (kernel sets are empty at boot).
- **Event time:** journald's timestamp; for files, the time the line was read. fwgd only
  follows new lines (it starts at the end of a file), so read time is accurate and no
  log date parsing is needed. Reading old log backlogs is out of scope.
- **File tailing by polling** (every 500 ms: compare inode and size, reopen on rotation,
  seek to 0 on truncation) instead of `notify`/inotify. Simpler, no extra dependency,
  works the same on every filesystem; 500 ms latency is fine for banning.
  `notify` is dropped from the crate list.
- **Regex:** `regex` crate only (linear time, safe on attacker-controlled log lines),
  1 MiB compiled-size limit per pattern. `<HOST>` expands to a named group; the match
  must also parse as an IP address; IPv4-mapped IPv6 is treated as IPv4.
- **Patterns must be anchored (`^…$`), enforced when a filter loads.** Log messages hold
  attacker-chosen text (user names); an unanchored pattern could match an address the
  attacker typed and ban someone else. Tested with injection attempts.
- **Memory bounds:** each jail tracks at most 100 000 source addresses; when full, the
  oldest are dropped. Log lines longer than 8 KiB are skipped.
- **Never banned:** loopback, plus each jail's `ignore` list (addresses and CIDRs).
- **Increasing ban time:** optional per jail: each repeat ban doubles the time, capped by
  `ban_time_max`.
- **Control socket:** `/run/fwg/fwgd.sock`, mode `0600`, and the daemon also checks the
  peer's uid is 0 (`SO_PEERCRED` through tokio's safe API). JSON lines, one request per line.
- **Config:** jails in `/etc/fwg/jails.d/*.toml` (human-owned, never rewritten); shipped
  filters in `/usr/share/fwg/filters/`, local overrides in `/etc/fwg/filters/`.
  `fwgd --check` validates everything without starting.

### 9.1 Real OpenSSH output (verified 2026-11-19 in the test VMs)

Captured from the journal by `vm/guest-checks.sh sshd-capture` (saved to
`vm/state/<vm>-sshd-capture.txt`, git-ignored); the lines, with documentation addresses,
are in `crates/fwg-watch/tests/sshd_filter.rs`. Every failure line matched the shipped
filter as written; no pattern needed a change.

What one failed connection logs (lines the filter counts):

| Kind | Lines | Counted |
|---|---|---|
| Wrong password, existing user | `Failed password for U from A port P ssh2`, `Connection closed by authenticating user U A port P [preauth]` | 2 |
| Wrong password, unknown user | `Invalid user U from A port P`, `Failed password for invalid user U …`, `Connection closed by invalid user U …` | 3 |
| Key not accepted, existing user (key-only) | `Connection closed by authenticating user U A port P [preauth]` only — **no** `Failed publickey` line at the default `LogLevel INFO` | 1 |
| Key not accepted, unknown user | `Invalid user …`, `Connection closed by invalid user …` | 2 |
| Out of attempts (`MaxAuthTries` 6) | 6 × `Failed password …`, `error: maximum authentication attempts exceeded for … [preauth]`, `Disconnecting authenticating\|invalid user U A port P: Too many authentication failures [preauth]` | 8 |
| Only outdated algorithms | `Unable to negotiate with A port P: no matching key exchange method found. Their offer: … [preauth]` | 1 |

Not counted, on purpose: `pam_unix(sshd:auth): authentication failure; … rhost=A user=U`
and `PAM N more authentication failures; …` — they repeat a `Failed password` line, and
`user=` at the end is attacker-chosen text after the address.

So `max_retry = 5` bans after 2–3 password guesses, or 5 key-only attempts.

**OpenSSH 9.8+ throttles on its own (`PerSourcePenalties`, on by default; Debian 13
has `authfail:5 … min:15`):** each failed login adds a 5 s penalty, and once 15 s have
built up sshd refuses new connections from that source for a while, **without logging
them at `INFO`**. Verified: 8 key-only attempts 1 s apart logged only 4 failures. So
on these systems a slow attacker needs longer to reach `max_retry`, but each refused
attempt costs them nothing either; fwg's ban still follows once enough failures are
logged. The VM test therefore retries for a time budget, not a fixed count.
Ubuntu 24.04 (OpenSSH 9.6) has no penalties.

Process names (`_COMM`, which the journal source matches):

| VM | OpenSSH | `_COMM` of every line above |
|---|---|---|
| Debian 13 | 10.0p2 | `sshd-session` (no line came from the new `sshd-auth` helper) |
| Ubuntu 24.04 | 9.6p1 | `sshd` |

Both are in the filter's `programs`; the message texts are identical on both. Over
IPv6 the lines are the same with the bare address (`from fd20::2 port P`, no brackets);
the VM test bans an IPv6 attacker too (in `ban6`, IPv4 from the same host still let in,
restored after reboot).

## 10. Licence

Default: **MIT OR Apache-2.0** (clean-room: no ufw/fail2ban code, regex, or test files
copied). Change before the first public release if another licence is preferred.

## 11. Open items

- [x] Download VM images (Debian 13 + Ubuntu 24.04 cloud images) for tier 4.
- [ ] Add older targets to the VM matrix (Debian 12, Ubuntu 22.04 for nft 1.0.2).
- [ ] Verify nft ≥ 1.0.2 / kernel ≥ 5.10 support in the VM matrix (1.0.9 and 1.1.3 verified).
- [ ] `.deb`/`.rpm` packaging (Phase 1 installs from source; see README).
- [x] Turso spike (features, crash recovery) — see §5. MSRV checked by CI.
- [ ] Turso power-loss test (VM hard reset during writes).

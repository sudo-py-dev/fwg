# Black-box study of ufw and fail2ban

fwg is written clean-room: no code, configuration, regular expressions or test
files are copied from ufw or fail2ban. To match their behaviour where users expect
it, we observe what the real tools *do* and record it here.

## Rules

Allowed:

- Running the tools in a throwaway test VM (`vm/fwg-vm`) and recording:
  - kernel state they create (`nft list ruleset`, `iptables-save`),
  - their command-line output (`status`, `--help`, error messages),
  - timings (when a connection is limited, when a ban starts and ends),
  - which log lines lead to a ban.
- Asking a running tool for its effective settings (`fail2ban-client get …`).
- Reading the installed man pages and `--help` text for what options mean.
- Recording log lines that **OpenSSH itself** writes; those are the programs' output,
  not part of ufw or fail2ban.

Not allowed:

- Opening their source code (Python modules) or their shipped rule, filter, action
  and jail files (`/etc/ufw/*.rules`, `/etc/fail2ban/filter.d`, `action.d`,
  `jail.conf`, …), even to read.
- Copying text from their documentation beyond short facts about behaviour.

Each finding below says how it was observed. The scripts that produced them are in
this directory and can be re-run.

Honest note: the model writing fwg may have seen these projects' public source in its
training data. The rules above keep that from turning into copying; what fwg does is
decided from the observations recorded here.

## Findings

- [ufw.md](ufw.md)
- [fail2ban.md](fail2ban.md)
- [sshd-log-lines.md](sshd-log-lines.md) — real OpenSSH messages, the basis of fwg's sshd filter

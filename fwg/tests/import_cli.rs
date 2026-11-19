//! `fwg import ufw` and `fwg import fail2ban` end to end, on copies of files that
//! real ufw 0.36.2 and fail2ban 1.0.2 wrote or read in the test VMs. Nothing here
//! needs root or touches the kernel (the firewall stays disabled).

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

const USER_RULES: &str = "\
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
### tuple ### deny any any 0.0.0.0/0 any 192.0.2.0/24 in
### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=6f6666696365206462
### tuple ### route:allow tcp 443 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_eth1
";
const USER6_RULES: &str = "\
### tuple ### allow tcp 22 ::/0 any ::/0 in
### tuple ### allow any any ::/0 any 2001:db8::/32 in
";
const JAIL_LOCAL: &str = "\
[DEFAULT]
bantime = 1h
ignoreip = 127.0.0.1/8 ::1
[sshd]
enabled = true
maxretry = 3
[dovecot]
enabled = true
[recidive]
enabled = true
";

struct Setup {
    dir: TempDir,
}

impl Setup {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("ufw")).unwrap();
        fs::write(root.join("ufw/user.rules"), USER_RULES).unwrap();
        fs::write(root.join("ufw/user6.rules"), USER6_RULES).unwrap();
        fs::write(root.join("ufw/ufw.conf"), "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        fs::write(
            root.join("default-ufw"),
            "DEFAULT_INPUT_POLICY=\"REJECT\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("fail2ban/jail.d")).unwrap();
        fs::write(root.join("fail2ban/jail.conf"), "[DEFAULT]\nmaxretry = 5\n").unwrap();
        fs::write(root.join("fail2ban/jail.local"), JAIL_LOCAL).unwrap();
        Self { dir }
    }

    fn path(&self, p: &str) -> std::path::PathBuf {
        self.dir.path().join(p)
    }

    fn fwg(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("fwg").unwrap();
        cmd.arg("--config-dir").arg(self.path("fwg")).args(args);
        cmd
    }

    fn ufw(&self, apply: bool) -> Command {
        let mut cmd = self.fwg(&["import", "ufw", "--from"]);
        cmd.arg(self.path("ufw"))
            .arg("--defaults")
            .arg(self.path("default-ufw"));
        if apply {
            cmd.arg("--apply");
        }
        cmd
    }

    fn fail2ban(&self, apply: bool) -> Command {
        let mut cmd = self.fwg(&["import", "fail2ban", "--from"]);
        cmd.arg(self.path("fail2ban"));
        if apply {
            cmd.arg("--apply");
        }
        cmd
    }
}

fn stdout(cmd: &mut Command) -> String {
    String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap()
}

#[test]
fn ufw_dry_run_shows_and_changes_nothing() {
    let s = Setup::new();
    let out = stdout(&mut s.ufw(false));
    assert!(
        out.starts_with(&format!(
            "Read {}: 4 rule(s); ufw is disabled.",
            s.path("ufw").display()
        )),
        "{out}"
    );
    for line in [
        "  fwg allow 22/tcp\n",
        "  fwg deny from 192.0.2.0/24\n",
        "  fwg allow proto tcp from 10.0.0.0/8 to any port 5432 comment \"office db\"\n",
        "  fwg allow from 2001:db8::/32\n",
        "Default incoming policy: reject\n",
        "route (forwarding) rules are not supported yet",
        "Nothing was changed.",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
    assert!(!s.path("fwg/rules.toml").exists());
}

#[test]
fn ufw_apply_imports_once() {
    let s = Setup::new();
    let out = stdout(&mut s.ufw(true));
    assert!(
        out.contains("Imported 4 rule(s) (0 already there)."),
        "{out}"
    );
    let rules = fs::read_to_string(s.path("fwg/rules.toml")).unwrap();
    assert!(rules.contains("incoming = \"reject\""), "{rules}");
    assert!(rules.contains("logging = true"), "{rules}");
    assert!(rules.contains("comment = \"office db\""), "{rules}");
    let again = stdout(&mut s.ufw(true));
    assert!(
        again.contains("Imported 0 rule(s) (4 already there)."),
        "{again}"
    );
}

#[test]
fn fail2ban_writes_a_jail_file_that_loads_and_keeps_existing_jails() {
    let s = Setup::new();
    // An sshd jail already exists, as after a normal install.
    fs::create_dir_all(s.path("fwg/jails.d")).unwrap();
    fs::write(s.path("fwg/jails.d/sshd.toml"), "[sshd]\n").unwrap();

    let dry = stdout(&mut s.fail2ban(false));
    assert!(dry.contains("Would write"), "{dry}");
    assert!(dry.contains("Jail `sshd` is already defined"), "{dry}");
    assert!(
        dry.contains("max_retry = 3"),
        "sshd's values are shown: {dry}"
    );
    assert!(
        dry.contains("[recidive] — fwg has no recidive jail"),
        "{dry}"
    );
    assert!(!s.path("fwg/jails.d/imported-fail2ban.toml").exists());

    stdout(&mut s.fail2ban(true));
    let written = fs::read_to_string(s.path("fwg/jails.d/imported-fail2ban.toml")).unwrap();
    assert!(
        written.contains("[dovecot]") && !written.contains("[sshd]"),
        "{written}"
    );
    assert!(written.contains("ban_time = \"1h\""), "{written}");
    assert_eq!(
        fs::read_to_string(s.path("fwg/jails.d/sshd.toml")).unwrap(),
        "[sshd]\n"
    );
    let jails = fwg_watch_jails(&written);
    assert_eq!(jails, ["dovecot"]);

    let err = String::from_utf8(
        s.fail2ban(true)
            .assert()
            .failure()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(err.contains("already exists"), "{err}");
}

#[test]
fn missing_setups_are_clear_errors() {
    let s = Setup::new();
    let mut cmd = s.fwg(&["import", "ufw", "--from", "/nonexistent"]);
    let err = String::from_utf8(cmd.assert().failure().get_output().stderr.clone()).unwrap();
    assert!(err.contains("no ufw rules found in /nonexistent"), "{err}");
    let mut cmd = s.fwg(&["import", "fail2ban", "--from", "/nonexistent"]);
    let err = String::from_utf8(cmd.assert().failure().get_output().stderr.clone()).unwrap();
    assert!(err.contains("no fail2ban configuration found"), "{err}");
}

/// Jail names in a jails.d file, read the way fwgd reads them.
fn fwg_watch_jails(text: &str) -> Vec<String> {
    fwg_watch::Jail::parse_file(text)
        .unwrap()
        .iter()
        .map(|j| j.name().to_owned())
        .collect()
}

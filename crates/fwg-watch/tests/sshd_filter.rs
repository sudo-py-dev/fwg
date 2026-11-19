//! The shipped sshd filter against OpenSSH message formats.
//!
//! Addresses are from the documentation ranges (RFC 5737, RFC 3849).

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::IpAddr;

use fwg_watch::Filter;

fn sshd() -> Filter {
    Filter::from_toml("sshd", include_str!("../../../filters/sshd.toml")).unwrap()
}

fn source(message: &str) -> Option<IpAddr> {
    sshd().failure_source(message)
}

#[test]
fn counts_failures() {
    let cases = [
        (
            "Failed password for root from 192.0.2.10 port 50122 ssh2",
            "192.0.2.10",
        ),
        (
            "Failed password for invalid user admin from 192.0.2.11 port 50122 ssh2",
            "192.0.2.11",
        ),
        (
            "Failed publickey for git from 2001:db8::12 port 50122 ssh2: ED25519 SHA256:AbCdEf0123456789",
            "2001:db8::12",
        ),
        (
            "Failed keyboard-interactive/pam for root from 192.0.2.13 port 2222 ssh2",
            "192.0.2.13",
        ),
        (
            "Failed none for invalid user test from 192.0.2.14 port 40000 ssh2",
            "192.0.2.14",
        ),
        (
            "Invalid user oracle from 198.51.100.20 port 40404",
            "198.51.100.20",
        ),
        (
            "Invalid user  from 198.51.100.21 port 40404",
            "198.51.100.21",
        ),
        (
            "error: maximum authentication attempts exceeded for root from 198.51.100.22 port 2 ssh2 [preauth]",
            "198.51.100.22",
        ),
        (
            "error: maximum authentication attempts exceeded for invalid user x from 198.51.100.23 port 2 ssh2 [preauth]",
            "198.51.100.23",
        ),
        (
            "Disconnecting authenticating user root 203.0.113.30 port 22: Too many authentication failures [preauth]",
            "203.0.113.30",
        ),
        (
            "Disconnecting invalid user pi 203.0.113.31 port 22: Too many authentication failures [preauth]",
            "203.0.113.31",
        ),
        (
            "Connection closed by authenticating user root 203.0.113.32 port 51515 [preauth]",
            "203.0.113.32",
        ),
        (
            "Connection reset by invalid user ubnt 203.0.113.33 port 51515 [preauth]",
            "203.0.113.33",
        ),
        (
            "Connection closed by invalid user admin 2001:db8::34 port 51515 [preauth]",
            "2001:db8::34",
        ),
        (
            "Unable to negotiate with 203.0.113.35 port 41000: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]",
            "203.0.113.35",
        ),
        (
            "Invalid user admin from ::ffff:192.0.2.36 port 40404",
            "192.0.2.36",
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(
            source(message),
            Some(expected.parse().unwrap()),
            "{message}"
        );
    }
}

#[test]
fn ignores_normal_operation() {
    let messages = [
        "Accepted publickey for fwg from 192.0.2.1 port 50122 ssh2: ED25519 SHA256:AbCdEf0123456789",
        "Accepted password for fwg from 192.0.2.1 port 50122 ssh2",
        "pam_unix(sshd:session): session opened for user fwg(uid=1000) by fwg(uid=0)",
        "Received disconnect from 192.0.2.1 port 50122:11: disconnected by user",
        "Disconnected from user fwg 192.0.2.1 port 50122",
        "Connection closed by 192.0.2.1 port 50122",
        "Server listening on 0.0.0.0 port 22.",
        "Connection from 192.0.2.1 port 50122 on 192.0.2.2 port 22 rdomain \"\"",
    ];
    for message in messages {
        assert_eq!(source(message), None, "{message}");
    }
}

#[test]
fn attacker_chosen_names_cannot_plant_an_address() {
    let victim: IpAddr = "198.51.100.99".parse().unwrap();
    let attempts = [
        "Invalid user x from 198.51.100.99 port 1 from 203.0.113.7 port 22",
        "Failed password for x from 198.51.100.99 port 1 ssh2 from 203.0.113.7 port 22 ssh2",
        "Connection closed by authenticating user x 198.51.100.99 port 1 [preauth] 203.0.113.7 port 22 [preauth]",
    ];
    for message in attempts {
        assert_ne!(source(message), Some(victim), "{message}");
    }
}

#[test]
fn programs() {
    let f = sshd();
    assert!(f.handles_program("sshd") && f.handles_program("sshd-session"));
    assert!(!f.handles_program("sudo"));
}

#[test]
fn shipped_jail_uses_the_journal_and_the_defaults() {
    let jails =
        fwg_watch::Jail::parse_file(include_str!("../../../dist/jails.d/sshd.toml")).unwrap();
    let [jail] = jails.as_slice() else {
        panic!("expected one jail, got {}", jails.len())
    };
    assert_eq!(jail.name(), "sshd");
    assert_eq!(jail.filter(), "sshd");
    assert_eq!(jail.log(), &fwg_watch::LogSource::Journal);
    assert_eq!(jail.max_retry(), 5);
    assert_eq!(jail.find_time().as_secs(), 600);
    assert_eq!(jail.ban_time_for(0).as_secs(), 3600);
    assert_eq!(
        jail.ban_time_for(3).as_secs(),
        3600,
        "no increment by default"
    );
}

/// Real lines, captured from the journal in the test VMs (`vm/smoke-test.sh` saves
/// them to `vm/state/<vm>-sshd-capture.txt`), with the address and port replaced.
/// Each group is what one failed connection logs, in order; `true` marks a line
/// that counts as a failure.
const REAL_OPENSSH: &[(&str, bool)] = &[
    // OpenSSH 10.0p2 (Debian 13, `_COMM=sshd-session`) and 9.6p1 (Ubuntu 24.04,
    // `_COMM=sshd`) log exactly these texts; only the process name differs.
    // Wrong password for an existing user: 2 failures.
    (
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1  user=fwg",
        false,
    ),
    (
        "Failed password for fwg from 192.0.2.1 port 45533 ssh2",
        true,
    ),
    (
        "Connection closed by authenticating user fwg 192.0.2.1 port 45533 [preauth]",
        true,
    ),
    // Wrong password for a user that does not exist: 3 failures.
    ("Invalid user nosuchuser from 192.0.2.1 port 37307", true),
    (
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1",
        false,
    ),
    (
        "Failed password for invalid user nosuchuser from 192.0.2.1 port 37307 ssh2",
        true,
    ),
    (
        "Connection closed by invalid user nosuchuser 192.0.2.1 port 37307 [preauth]",
        true,
    ),
    // A key the server does not accept, existing user: 1 failure.
    (
        "Connection closed by authenticating user fwg 192.0.2.1 port 44435 [preauth]",
        true,
    ),
    // ... and a user that does not exist: 2 failures.
    ("Invalid user nosuchuser from 192.0.2.1 port 42373", true),
    (
        "Connection closed by invalid user nosuchuser 192.0.2.1 port 42373 [preauth]",
        true,
    ),
    // Out of attempts (MaxAuthTries 6): 6 "Failed password" lines, then these.
    (
        "error: maximum authentication attempts exceeded for fwg from 192.0.2.1 port 58537 ssh2 [preauth]",
        true,
    ),
    (
        "Disconnecting authenticating user fwg 192.0.2.1 port 58537: Too many authentication failures [preauth]",
        true,
    ),
    (
        "PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1  user=fwg",
        false,
    ),
    (
        "error: maximum authentication attempts exceeded for invalid user nobody2 from 192.0.2.1 port 45187 ssh2 [preauth]",
        true,
    ),
    (
        "Disconnecting invalid user nobody2 192.0.2.1 port 45187: Too many authentication failures [preauth]",
        true,
    ),
    // A client with only outdated algorithms: 1 failure.
    (
        "Unable to negotiate with 192.0.2.1 port 49683: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1,ext-info-c,kex-strict-c-v00@openssh.com [preauth]",
        true,
    ),
];

fn check_real_lines(lines: &[(&str, bool)]) {
    assert!(lines.len() > 10);
    let expected: IpAddr = "192.0.2.1".parse().unwrap();
    for (message, counts) in lines {
        let found = source(message);
        if *counts {
            assert_eq!(found, Some(expected), "should count: {message}");
        } else {
            assert_eq!(found, None, "should not count: {message}");
        }
    }
}

#[test]
fn real_openssh_lines() {
    check_real_lines(REAL_OPENSSH);
}

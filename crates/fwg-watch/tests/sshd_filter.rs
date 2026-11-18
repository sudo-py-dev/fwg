//! The shipped sshd filter against OpenSSH message formats.
//!
//! Addresses are from the documentation ranges (RFC 5737, RFC 3849).

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used)]

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

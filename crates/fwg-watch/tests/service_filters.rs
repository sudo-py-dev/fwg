//! The shipped Dovecot, Postfix and nginx filters against real log lines.
//!
//! Captured in the test VMs (Debian 13: Dovecot 2.4.1, Postfix 3.10.13, nginx 1.26.3;
//! Ubuntu 24.04: Dovecot 2.3.21, Postfix 3.8.6, nginx 1.24.0) from failed logins made
//! from a network namespace, including user names crafted to plant another address.
//! The attacker's address is replaced by 192.0.2.1 and planted ones by 203.0.113.x
//! (documentation ranges, RFC 5737); nothing else is changed.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::net::IpAddr;

use fwg_watch::Filter;

fn filter(name: &str, text: &str) -> Filter {
    Filter::from_toml(name, text).unwrap()
}

fn dovecot() -> Filter {
    filter("dovecot", include_str!("../../../filters/dovecot.toml"))
}

fn postfix() -> Filter {
    filter(
        "postfix-sasl",
        include_str!("../../../filters/postfix-sasl.toml"),
    )
}

fn nginx() -> Filter {
    filter(
        "nginx-http-auth",
        include_str!("../../../filters/nginx-http-auth.toml"),
    )
}

const ATTACKER: &str = "192.0.2.1";

/// Each line with whether it counts as a failure from [`ATTACKER`].
fn check(filter: &Filter, lines: &[(&str, bool)]) {
    let attacker: IpAddr = ATTACKER.parse().unwrap();
    for (line, counts) in lines {
        let found = filter.failure_source(line);
        if *counts {
            assert_eq!(found, Some(attacker), "should count: {line}");
        } else {
            assert_eq!(found, None, "should not count: {line}");
        }
    }
}

#[test]
fn dovecot_2_4_debian_13() {
    check(
        &dovecot(),
        &[
            (
                "imap-login: Login aborted: Connection closed (auth failed, 1 attempts in 11 secs) (auth_failed): user=<bob>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<K52qkp9gpNsKyAAV>",
                true,
            ),
            (
                "pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 16 secs) (auth_failed): user=<bob>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<tavbkp9gMrYKyAAV>",
                true,
            ),
            (
                "imap-login: Login aborted: Connection closed (auth failed, 1 attempts in 20 secs) (auth_failed): user=<nosuchuser>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<t5FWk59gDq4KyAAV>",
                true,
            ),
            (
                "pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 39 secs) (auth_failed): user=<y rip=203.0.113.4,>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<06odlZ9gmJ4KyAAV>",
                true,
            ),
            // A connection that never tried to log in: a scanner, not a failed login.
            (
                "imap-login: Login aborted: Connection closed (no auth attempts in 10 secs) (no_auth_attempts): user=<>, rip=192.0.2.1, lip=10.200.0.1, session=<NIeElJ9gTN4KyAAV>",
                false,
            ),
            // PAM's summary of the same failure: the attempt is counted once, above.
            (
                "pam_unix(dovecot:auth): authentication failure; logname= uid=0 euid=0 tty=dovecot ruser=bob rhost=192.0.2.1  user=bob",
                false,
            ),
        ],
    );
}

#[test]
fn dovecot_2_3_ubuntu_24_04() {
    check(
        &dovecot(),
        &[
            (
                "imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 11 secs): user=<bob>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<+DEHDZ5gLJcKyAAV>",
                true,
            ),
            (
                "pop3-login: Disconnected: Connection closed (auth failed, 1 attempts in 12 secs): user=<nosuchuser>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<P3oiDp5guIkKyAAV>",
                true,
            ),
            (
                "pop3-login: Disconnected: Connection closed (auth failed, 1 attempts in 39 secs): user=<y rip=203.0.113.4,>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<dr5rD55giucKyAAV>",
                true,
            ),
            (
                "imap-login: Disconnected: Connection closed (no auth attempts in 10 secs): user=<>, rip=192.0.2.1, lip=10.200.0.1, session=<V6ZrD55gVOQKyAAV>",
                false,
            ),
        ],
    );
}

#[test]
fn dovecot_names_cannot_plant_an_address() {
    let planted: IpAddr = "203.0.113.5".parse().unwrap();
    // Real lines: the name was `x>, method=PLAIN, rip=203.0.113.5, lip=1`; Dovecot did
    // not escape the `>`. The line must not give the planted address.
    for line in [
        "pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 10 secs) (auth_failed): user=<x>, method=PLAIN, rip=203.0.113.5, lip=1>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<e6WElJ9gFp0KyAAV>",
        "pop3-login: Disconnected: Connection closed (auth failed, 1 attempts in 10 secs): user=<x>, method=PLAIN, rip=203.0.113.5, lip=1>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<J8TSDp5gMtIKyAAV>",
        // A name that also fakes the end of the line.
        "imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 1 secs): user=<a>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, TLS, session=<b>, method=PLAIN, rip=192.0.2.1, lip=10.200.0.1, session=<c>",
    ] {
        assert_ne!(dovecot().failure_source(line), Some(planted), "{line}");
    }
}

#[test]
fn postfix_sasl() {
    check(
        &postfix(),
        &[
            (
                "warning: unknown[192.0.2.1]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=bob",
                true,
            ),
            (
                "warning: unknown[192.0.2.1]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=nosuchuser",
                true,
            ),
            // The name was `z, sasl_username=q from unknown[203.0.113.3]`: it comes after the address.
            (
                "warning: unknown[192.0.2.1]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=z, sasl_username=q from unknown[203.0.113.3]",
                true,
            ),
            (
                "warning: mail.example.org[192.0.2.1]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=bob",
                true,
            ),
            // Dovecot was not reachable: not the client's fault.
            (
                "warning: unknown[192.0.2.1]: SASL PLAIN authentication failed: Connection lost to authentication server, sasl_username=(unavailable)",
                false,
            ),
            ("connect from unknown[192.0.2.1]", false),
            (
                "NOQUEUE: lost connection after AUTH from unknown[192.0.2.1]",
                false,
            ),
            (
                "disconnect from unknown[192.0.2.1] ehlo=1 auth=0/1 commands=1/2",
                false,
            ),
        ],
    );
    let v6 = "warning: unknown[2001:db8::7]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=bob";
    assert_eq!(
        postfix().failure_source(v6),
        Some("2001:db8::7".parse().unwrap())
    );
}

#[test]
fn nginx_access_log() {
    check(
        &nginx(),
        &[
            (
                r#"192.0.2.1 - alice [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "curl/8.14.1""#,
                true,
            ),
            (
                r#"192.0.2.1 - nobody [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "curl/8.14.1""#,
                true,
            ),
            // Real escaping of the injection attempts: `"` as \x22, newline as \x0A.
            (
                r#"192.0.2.1 - x\x22, client [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "curl/8.14.1""#,
                true,
            ),
            (
                r#"192.0.2.1 - alice [19/Nov/2026:11:38:50 +0000] "GET /a\x22,%20client:%20203.0.113.7,%20server:%20b HTTP/1.1" 401 172 "-" "curl/8.14.1""#,
                true,
            ),
            (
                r#"192.0.2.1 - a\x0Ab [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "curl/8.14.1""#,
                true,
            ),
            // No credentials sent: a browser's first request, not a failure.
            (
                r#"192.0.2.1 - - [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "Mozilla/5.0""#,
                false,
            ),
            (
                r#"192.0.2.1 - - [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 400 150 "-" "-""#,
                false,
            ),
            (
                r#"192.0.2.1 - alice [19/Nov/2026:11:38:51 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/8.14.1""#,
                false,
            ),
        ],
    );
    // Whatever a user name holds, the address is the line's first field.
    let line = r#"192.0.2.1 - a 203.0.113.9 - b [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 1 "-" "-" [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "curl/8.14.1""#;
    assert_eq!(
        nginx().failure_source(line),
        Some(ATTACKER.parse().unwrap())
    );
    let v6 = r#"2001:db8::7 - alice [19/Nov/2026:11:38:50 +0000] "GET / HTTP/1.1" 401 172 "-" "curl/8.14.1""#;
    assert_eq!(
        nginx().failure_source(v6),
        Some("2001:db8::7".parse().unwrap())
    );
}

#[test]
fn programs() {
    assert!(dovecot().handles_program("log") && dovecot().handles_program("dovecot"));
    assert!(postfix().handles_program("smtpd") && postfix().handles_program("postfix/smtpd"));
    assert!(!postfix().handles_program("postfix/qmgr"));
    assert!(nginx().handles_program(""), "plain lines name no program");
}

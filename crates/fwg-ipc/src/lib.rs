//! The control socket protocol between the `fwg` CLI and the `fwgd` daemon.
//!
//! One connection carries one request and one response, each a single line of JSON.
//! The socket is `/run/fwg/fwgd.sock`, mode `0600`; the daemon also checks that the
//! peer is root.
//!
//! ```text
//! → {"cmd":"ban","addr":"192.0.2.7","seconds":3600}
//! ← {"result":"done","message":"banned 192.0.2.7 for 1h"}
//! ```

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Default socket path.
pub const SOCKET_PATH: &str = "/run/fwg/fwgd.sock";
/// Longest request or response line accepted; larger input is rejected.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// A request from the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    // Empty structs rather than unit variants: serde's `deny_unknown_fields` does
    // not check unit variants of an internally tagged enum.
    /// Jails and their state.
    Status {},
    /// Addresses banned right now.
    Banned {},
    /// Ban an address by hand.
    Ban {
        /// The address.
        addr: IpAddr,
        /// Length of the ban.
        seconds: u64,
    },
    /// Lift a ban.
    Unban {
        /// The address.
        addr: IpAddr,
    },
}

/// The daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Answer to [`Request::Status`].
    Status {
        /// One entry per running jail.
        jails: Vec<JailStatus>,
    },
    /// Answer to [`Request::Banned`].
    Banned {
        /// Current bans.
        bans: Vec<BanInfo>,
    },
    /// The request was carried out.
    Done {
        /// What happened, for the user.
        message: String,
    },
    /// The request failed.
    Error {
        /// Why, for the user.
        message: String,
    },
}

/// One running jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailStatus {
    /// Jail name.
    pub name: String,
    /// Filter it uses.
    pub filter: String,
    /// `journal` or a file path.
    pub log: String,
    /// Failures needed for a ban.
    pub max_retry: u32,
    /// Window for those failures, in seconds.
    pub find_time_secs: u64,
    /// Length of a first ban, in seconds (repeat bans may be longer).
    pub ban_time_secs: u64,
    /// Addresses with recent failures.
    pub tracked: usize,
    /// Bans this jail made since the daemon started.
    pub bans_since_start: u64,
}

/// One active ban.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanInfo {
    /// The banned address.
    pub addr: IpAddr,
    /// The jail that banned it, `manual`, or `unknown` if it is not in the history.
    pub jail: String,
    /// Length of the ban, in seconds.
    pub time_secs: u64,
    /// Seconds until it ends.
    pub remaining_secs: u64,
}

/// Encodes a message as one line (with the trailing newline).
///
/// # Errors
/// Only if serialization fails, which these types cannot trigger in practice.
pub fn encode<T: Serialize>(message: &T) -> serde_json::Result<String> {
    let mut line = serde_json::to_string(message)?;
    line.push('\n');
    Ok(line)
}

/// Decodes one line (with or without the trailing newline).
///
/// # Errors
/// If the line is not a valid message of type `T`.
pub fn decode<'a, T: Deserialize<'a>>(line: &'a str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end_matches('\n'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for request in [
            Request::Status {},
            Request::Banned {},
            Request::Ban {
                addr: "192.0.2.7".parse().unwrap(),
                seconds: 3600,
            },
            Request::Unban {
                addr: "2001:db8::7".parse().unwrap(),
            },
        ] {
            let line = encode(&request).unwrap();
            assert!(line.ends_with('\n') && !line[..line.len() - 1].contains('\n'));
            assert_eq!(decode::<Request>(&line).unwrap(), request);
        }
    }

    #[test]
    fn wire_format_is_stable() {
        let ban = Request::Ban {
            addr: "192.0.2.7".parse().unwrap(),
            seconds: 60,
        };
        assert_eq!(
            encode(&ban).unwrap(),
            "{\"cmd\":\"ban\",\"addr\":\"192.0.2.7\",\"seconds\":60}\n"
        );
        assert_eq!(
            encode(&Request::Status {}).unwrap(),
            "{\"cmd\":\"status\"}\n"
        );
        let done = Response::Done {
            message: "ok".into(),
        };
        assert_eq!(
            encode(&done).unwrap(),
            "{\"result\":\"done\",\"message\":\"ok\"}\n"
        );
    }

    #[test]
    fn rejects_bad_requests() {
        for line in [
            "",
            "{}",
            r#"{"cmd":"reboot"}"#,
            r#"{"cmd":"ban","addr":"not-an-ip","seconds":1}"#,
            r#"{"cmd":"ban","addr":"192.0.2.7"}"#,
            r#"{"cmd":"status","extra":1}"#,
        ] {
            assert!(decode::<Request>(line).is_err(), "accepted {line:?}");
        }
    }
}

//! Parsing ufw-style rule arguments.
//!
//! Grammar (after the action word):
//!
//! ```text
//! [in|out] [on IFACE] PORTS[/PROTO]                       [comment TEXT]
//! [in|out] [on IFACE] [proto P] [from A [port P]] [to A [port P]] [comment TEXT]
//! ```
//!
//! `proto`, `from`, `to` and `comment` may come in any order, each at most once.

use crate::rule::{Action, Direction, Rule, RuleError, RuleParts, RulePartsError};
use crate::value::{Address, Ports, Protocol, ValueError};

/// Why rule arguments could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Nothing to match on.
    #[error("missing rule, e.g. `22/tcp` or `from 10.0.0.0/8 to any port 22`")]
    Empty,
    /// A keyword at the end with no value after it.
    #[error("`{0}` needs a value")]
    MissingValue(&'static str),
    /// A keyword given twice.
    #[error("`{0}` given more than once")]
    Duplicate(&'static str),
    /// A word that does not fit the grammar.
    #[error("unexpected `{0}`")]
    Unexpected(String),
    /// A value is malformed.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// The rule breaks an invariant.
    #[error(transparent)]
    Rule(#[from] RuleError),
}

/// Parses the words after the action into a validated rule.
///
/// # Errors
/// Returns a [`ParseError`] describing the first problem found.
pub fn parse_rule<S: AsRef<str>>(action: Action, args: &[S]) -> Result<Rule, ParseError> {
    let mut words = Words::new(args);
    let mut parts = RuleParts {
        action: Some(action),
        ..RuleParts::default()
    };

    match words.peek() {
        Some("in") => {
            words.next();
        }
        Some("out") => {
            words.next();
            parts.direction = Direction::Out;
        }
        _ => {}
    }
    if words.peek() == Some("on") {
        words.next();
        parts.interface = Some(words.value("on")?.parse()?);
    }

    let mut has_criteria = parts.interface.is_some();
    match words.peek() {
        Some(word) if !is_keyword(word) => {
            words.next();
            parse_simple(word, &mut parts)?;
            has_criteria = true;
            if let Some(word) = words.next() {
                if word != "comment" {
                    return Err(ParseError::Unexpected(word.to_owned()));
                }
                parts.comment = Some(words.value("comment")?.parse()?);
            }
        }
        _ => has_criteria |= parse_full(&mut words, &mut parts)?,
    }

    if let Some(word) = words.next() {
        return Err(ParseError::Unexpected(word.to_owned()));
    }
    if !has_criteria {
        return Err(ParseError::Empty);
    }
    Rule::try_from(parts).map_err(|e| match e {
        RulePartsError::Invalid(e) => e.into(),
        // `action` is always set above.
        RulePartsError::MissingAction => ParseError::Empty,
    })
}

/// `PORTS[/PROTO]`, e.g. `22`, `22/tcp`, `80,443/tcp`.
fn parse_simple(word: &str, parts: &mut RuleParts) -> Result<(), ParseError> {
    let (port_list, protocol) = match word.split_once('/') {
        Some((list, name)) => (list, parse_protocol(name)?),
        None => (word, None),
    };
    parts.to_port = Some(port_list.parse::<Ports>()?);
    parts.protocol = protocol;
    Ok(())
}

/// The keyword form. Returns whether any criterion was given.
fn parse_full<S: AsRef<str>>(
    words: &mut Words<'_, S>,
    parts: &mut RuleParts,
) -> Result<bool, ParseError> {
    let (mut seen_proto, mut seen_from, mut seen_to, mut seen_comment) =
        (false, false, false, false);
    while let Some(word) = words.next() {
        match word {
            "proto" => {
                once(&mut seen_proto, "proto")?;
                parts.protocol = parse_protocol(words.value("proto")?)?;
            }
            "from" => {
                once(&mut seen_from, "from")?;
                (parts.from, parts.from_port) = parse_endpoint(words, "from")?;
            }
            "to" => {
                once(&mut seen_to, "to")?;
                (parts.to, parts.to_port) = parse_endpoint(words, "to")?;
            }
            "comment" => {
                once(&mut seen_comment, "comment")?;
                parts.comment = Some(words.value("comment")?.parse()?);
            }
            _ => return Err(ParseError::Unexpected(word.to_owned())),
        }
    }
    Ok(seen_proto || seen_from || seen_to)
}

/// `ADDR [port PORTS]`.
fn parse_endpoint<S: AsRef<str>>(
    words: &mut Words<'_, S>,
    keyword: &'static str,
) -> Result<(Address, Option<Ports>), ParseError> {
    let addr = words.value(keyword)?.parse()?;
    let ports = if words.peek() == Some("port") {
        words.next();
        Some(words.value("port")?.parse()?)
    } else {
        None
    };
    Ok((addr, ports))
}

/// `tcp`, `udp`, or `any` (no restriction).
fn parse_protocol(s: &str) -> Result<Option<Protocol>, ValueError> {
    if s == "any" {
        Ok(None)
    } else {
        s.parse().map(Some)
    }
}

fn once(seen: &mut bool, keyword: &'static str) -> Result<(), ParseError> {
    if std::mem::replace(seen, true) {
        Err(ParseError::Duplicate(keyword))
    } else {
        Ok(())
    }
}

fn is_keyword(word: &str) -> bool {
    matches!(word, "proto" | "from" | "to" | "port" | "comment")
}

/// A cursor over the argument words.
struct Words<'a, S> {
    args: &'a [S],
    pos: usize,
}

impl<'a, S: AsRef<str>> Words<'a, S> {
    const fn new(args: &'a [S]) -> Self {
        Self { args, pos: 0 }
    }

    fn peek(&self) -> Option<&'a str> {
        self.args.get(self.pos).map(AsRef::as_ref)
    }

    fn next(&mut self) -> Option<&'a str> {
        let word = self.peek()?;
        self.pos += 1;
        Some(word)
    }

    /// The value after `keyword`; keywords are never accepted as values.
    fn value(&mut self, keyword: &'static str) -> Result<&'a str, ParseError> {
        match self.next() {
            Some(word) if !is_keyword(word) || keyword == "comment" => Ok(word),
            _ => Err(ParseError::MissingValue(keyword)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Family;

    fn parse(action: Action, s: &str) -> Result<Rule, ParseError> {
        let args: Vec<&str> = s.split_whitespace().collect();
        parse_rule(action, &args)
    }

    fn ok(s: &str) -> Rule {
        parse(Action::Allow, s).unwrap_or_else(|e| panic!("{s:?} failed: {e}"))
    }

    #[test]
    fn simple_forms() {
        let r = ok("22/tcp");
        assert_eq!(r.protocol(), Some(Protocol::Tcp));
        assert_eq!(r.to().ports.as_ref().unwrap().to_string(), "22");
        assert!(r.from().is_any() && r.to().addr.is_any());

        assert_eq!(ok("53").protocol(), None);
        assert_eq!(
            ok("80,443/tcp").to().ports.as_ref().unwrap().items().len(),
            2
        );
        assert_eq!(ok("60000:61000/udp").protocol(), Some(Protocol::Udp));
        assert_eq!(ok("22/any").protocol(), None);
    }

    #[test]
    fn direction_and_interface() {
        let r = ok("out on wg0 51820/udp");
        assert_eq!(r.direction(), Direction::Out);
        assert_eq!(r.interface().unwrap().as_str(), "wg0");
        assert_eq!(ok("in 22").direction(), Direction::In);
        assert!(ok("in on eth0").interface().is_some());
    }

    #[test]
    fn full_forms() {
        let r = ok("from 10.0.0.0/8 to any port 22 proto tcp");
        assert_eq!(r.from().addr.family(), Some(Family::V4));
        assert!(r.to().ports.as_ref().unwrap().contains(22));
        assert_eq!(r.protocol(), Some(Protocol::Tcp));

        let r = ok("proto udp from 2001:db8::/32 port 53 to 2001:db8::1");
        assert!(r.from().ports.as_ref().unwrap().contains(53));
        assert_eq!(r.to().addr.to_string(), "2001:db8::1");

        assert!(ok("from 192.0.2.7").to().is_any());
        assert!(ok("proto tcp").from().is_any());
    }

    #[test]
    fn comments() {
        let args = ["22/tcp", "comment", "ssh from office"];
        let r = parse_rule(Action::Allow, &args).unwrap();
        assert_eq!(r.comment().unwrap().as_str(), "ssh from office");

        let args = ["comment", "web", "to", "any", "port", "443"];
        assert!(
            parse_rule(Action::Allow, &args)
                .unwrap()
                .comment()
                .is_some()
        );

        // A comment may itself be a keyword-like word.
        let args = ["22", "comment", "from"];
        assert_eq!(
            parse_rule(Action::Allow, &args)
                .unwrap()
                .comment()
                .unwrap()
                .as_str(),
            "from"
        );
    }

    #[test]
    fn errors() {
        let cases: &[(&str, ParseError)] = &[
            ("", ParseError::Empty),
            ("in", ParseError::Empty),
            ("comment x", ParseError::Empty),
            ("on", ParseError::MissingValue("on")),
            ("from", ParseError::MissingValue("from")),
            ("from to any", ParseError::MissingValue("from")),
            ("to any port", ParseError::MissingValue("port")),
            ("proto", ParseError::MissingValue("proto")),
            ("22 comment", ParseError::MissingValue("comment")),
            ("proto tcp proto udp", ParseError::Duplicate("proto")),
            ("from any from any", ParseError::Duplicate("from")),
            ("22 23", ParseError::Unexpected("23".into())),
            ("22 from any", ParseError::Unexpected("from".into())),
            ("port 22", ParseError::Unexpected("port".into())),
            ("from any bogus", ParseError::Unexpected("bogus".into())),
            (
                "22/icmp",
                ParseError::Value(ValueError::InvalidProtocol("icmp".into())),
            ),
            ("0", ParseError::Value(ValueError::InvalidPort("0".into()))),
            (
                "from 10.0.0.1 to ::1",
                ParseError::Rule(RuleError::FamilyMismatch),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse(Action::Allow, input).as_ref(),
                Err(expected),
                "input {input:?}"
            );
        }
        assert_eq!(
            parse(Action::Limit, "out 22"),
            Err(ParseError::Rule(RuleError::LimitOutgoing))
        );
    }

    #[test]
    fn display_and_args_round_trip() {
        let inputs = [
            "22/tcp",
            "53",
            "out on wg0 51820/udp",
            "from 10.0.0.0/8 to any port 22 proto tcp",
            "proto udp from 2001:db8::/32 port 53 to 2001:db8::1",
            "on eth0",
            "from 192.0.2.7",
            "to 10.1.2.3/16",
            "proto tcp",
        ];
        for action in [Action::Allow, Action::Deny, Action::Reject] {
            for input in inputs {
                let rule = parse(action, input).unwrap();
                assert_eq!(
                    parse_rule(action, &rule.to_args()).unwrap(),
                    rule,
                    "{input:?}"
                );
            }
        }
        let rule = parse_rule(Action::Allow, &["22/tcp", "comment", "ssh access"]).unwrap();
        assert_eq!(rule.to_string(), "allow 22/tcp comment \"ssh access\"");
        assert_eq!(parse_rule(Action::Allow, &rule.to_args()).unwrap(), rule);
        assert_eq!(
            ok("from 10.1.2.3/8 to any port 22").to_string(),
            "allow from 10.0.0.0/8 to any port 22"
        );
    }

    #[test]
    fn ssh_lockout_check() {
        assert!(ok("22/tcp").allows_incoming_tcp(22));
        assert!(ok("22").allows_incoming_tcp(22));
        assert!(ok("from 10.0.0.0/8").allows_incoming_tcp(22));
        assert!(
            parse(Action::Limit, "22/tcp")
                .unwrap()
                .allows_incoming_tcp(22)
        );
        assert!(!ok("22/udp").allows_incoming_tcp(22));
        assert!(!ok("2222/tcp").allows_incoming_tcp(22));
        assert!(!ok("out 22/tcp").allows_incoming_tcp(22));
        assert!(
            !parse(Action::Deny, "22/tcp")
                .unwrap()
                .allows_incoming_tcp(22)
        );
    }
}

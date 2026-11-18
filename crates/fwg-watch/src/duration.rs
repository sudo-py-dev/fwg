//! Human-friendly durations for jail settings: `30s`, `10m`, `1h`, `1d`, `1w`.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A duration written as a whole number and one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Span(Duration);

/// A malformed [`Span`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid duration `{0}` (expected a number and a unit, e.g. 30s, 10m, 1h, 1d, 1w)")]
pub struct SpanError(String);

const UNITS: [(char, u64); 5] = [
    ('s', 1),
    ('m', 60),
    ('h', 3600),
    ('d', 86_400),
    ('w', 604_800),
];

impl Span {
    /// A span of `secs` seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    /// The span as a [`Duration`].
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

impl FromStr for Span {
    type Err = SpanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || SpanError(s.to_owned());
        let unit = s.chars().last().ok_or_else(err)?;
        let (_, factor) = UNITS.iter().find(|(u, _)| *u == unit).ok_or_else(err)?;
        let digits = &s[..s.len() - unit.len_utf8()];
        // Digits only: no sign, no spaces, no empty number.
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err());
        }
        let n: u64 = digits.parse().map_err(|_| err())?;
        let secs = n.checked_mul(*factor).ok_or_else(err)?;
        Ok(Self::from_secs(secs))
    }
}

/// Shortest exact form, e.g. 7200 s is shown as `2h`.
impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let (unit, factor) = UNITS
            .iter()
            .rev()
            .find(|(_, factor)| secs != 0 && secs.is_multiple_of(*factor))
            .copied()
            .unwrap_or(('s', 1));
        write!(f, "{}{unit}", secs / factor)
    }
}

impl TryFrom<String> for Span {
    type Error = SpanError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Span> for String {
    fn from(s: Span) -> Self {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_units() {
        assert_eq!(
            "30s".parse::<Span>().unwrap().duration(),
            Duration::from_secs(30)
        );
        assert_eq!(
            "10m".parse::<Span>().unwrap().duration(),
            Duration::from_secs(600)
        );
        assert_eq!(
            "1h".parse::<Span>().unwrap().duration(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            "2d".parse::<Span>().unwrap().duration(),
            Duration::from_secs(172_800)
        );
        assert_eq!(
            "1w".parse::<Span>().unwrap().duration(),
            Duration::from_secs(604_800)
        );
        assert_eq!("0s".parse::<Span>().unwrap().duration(), Duration::ZERO);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "10",
            "m",
            "1.5h",
            "-1h",
            " 1h",
            "1 h",
            "1H",
            "1y",
            "١h",
            "99999999999999999999s",
            "18446744073709551615w",
        ] {
            assert!(bad.parse::<Span>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn displays_shortest_form() {
        assert_eq!(Span::from_secs(7200).to_string(), "2h");
        assert_eq!(Span::from_secs(90).to_string(), "90s");
        assert_eq!(Span::from_secs(1_209_600).to_string(), "2w");
        assert_eq!(Span::from_secs(0).to_string(), "0s");
    }

    proptest! {
        #[test]
        fn round_trips(secs in 0u64..10_000_000_000) {
            let span = Span::from_secs(secs);
            prop_assert_eq!(span.to_string().parse::<Span>().unwrap(), span);
        }
    }
}

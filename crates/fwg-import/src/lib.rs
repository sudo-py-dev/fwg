//! Reading an existing ufw or fail2ban setup, so a machine can move to fwg
//! without retyping it (`fwg import ufw`, `fwg import fail2ban`).
//!
//! Only configuration *settings* are read. Nothing here runs ufw or fail2ban, and
//! fail2ban's filter regexes are never used: fwg's filters stay its own (see
//! `STACK_NOTES.md` §9.2).

mod fail2ban;
mod ini;
mod ufw;

pub use fail2ban::{Fail2banError, Fail2banSetup, ImportedJail, read_fail2ban};
pub use ufw::{Skipped, UfwError, UfwSetup, parse_tuples, read_ufw};

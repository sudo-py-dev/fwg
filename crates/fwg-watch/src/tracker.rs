//! Counting recent failures per address and deciding when an address is banned.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

/// Default number of addresses one jail tracks at once.
pub const MAX_TRACKED_ADDRESSES: usize = 100_000;
/// When full, this share of the oldest entries is dropped at once (1/10), so a
/// flood of new addresses costs amortized O(1) per failure, not a scan each time.
const EVICT_DIVISOR: usize = 10;

/// Failure times per address within a sliding window.
///
/// Times are durations since the Unix epoch, as given by the log source; events
/// may arrive slightly out of order.
#[derive(Debug, Clone)]
pub struct Tracker {
    max_retry: usize,
    find_time: Duration,
    capacity: usize,
    recent: HashMap<IpAddr, VecDeque<Duration>>,
}

impl Tracker {
    /// A tracker that bans after `max_retry` failures within `find_time`.
    #[must_use]
    pub fn new(max_retry: u32, find_time: Duration) -> Self {
        Self::with_capacity(max_retry, find_time, MAX_TRACKED_ADDRESSES)
    }

    /// As [`new`](Self::new), tracking at most `capacity` addresses.
    #[must_use]
    pub fn with_capacity(max_retry: u32, find_time: Duration, capacity: usize) -> Self {
        Self {
            max_retry: usize::try_from(max_retry).unwrap_or(usize::MAX).max(1),
            find_time,
            capacity: capacity.max(1),
            recent: HashMap::new(),
        }
    }

    /// Records a failure from `addr` at `at`.
    ///
    /// Returns the number of failures in the window when it reaches `max_retry`;
    /// the address is then forgotten, so the next ban needs fresh failures.
    pub fn record(&mut self, addr: IpAddr, at: Duration) -> Option<usize> {
        let addr = addr.to_canonical();
        if !self.recent.contains_key(&addr) && self.recent.len() >= self.capacity {
            self.make_room(at);
        }
        let times = self.recent.entry(addr).or_default();
        let pos = times.partition_point(|t| *t <= at);
        times.insert(pos, at);
        let newest = times.back().copied().unwrap_or(at);
        let window_start = newest.saturating_sub(self.find_time);
        while times.front().is_some_and(|t| *t < window_start) || times.len() > self.max_retry {
            times.pop_front();
        }
        if times.len() >= self.max_retry {
            let count = times.len();
            self.recent.remove(&addr);
            Some(count)
        } else {
            None
        }
    }

    /// Stops tracking `addr`, e.g. after a manual ban or unban.
    pub fn forget(&mut self, addr: IpAddr) {
        self.recent.remove(&addr.to_canonical());
    }

    /// Number of addresses being tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recent.len()
    }

    /// Whether no address is being tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recent.is_empty()
    }

    /// Drops expired entries; if still full, drops the oldest tenth.
    fn make_room(&mut self, now: Duration) {
        let window_start = now.saturating_sub(self.find_time);
        self.recent
            .retain(|_, times| times.back().is_some_and(|t| *t >= window_start));
        if self.recent.len() < self.capacity {
            return;
        }
        let mut newest: Vec<Duration> = self
            .recent
            .values()
            .filter_map(|t| t.back().copied())
            .collect();
        if newest.is_empty() {
            return;
        }
        let evict = (self.capacity / EVICT_DIVISOR).max(1).min(newest.len() - 1);
        let (_, cutoff, _) = newest.select_nth_unstable(evict);
        let cutoff = *cutoff;
        self.recent
            .retain(|_, times| times.back().is_some_and(|t| *t >= cutoff));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn bans_after_max_retry_within_window() {
        let mut t = Tracker::new(3, secs(60));
        let a = ip("192.0.2.1");
        assert_eq!(t.record(a, secs(0)), None);
        assert_eq!(t.record(a, secs(10)), None);
        assert_eq!(t.record(a, secs(20)), Some(3));
        assert!(t.is_empty(), "forgotten after the ban");
        assert_eq!(
            t.record(a, secs(21)),
            None,
            "a new ban needs fresh failures"
        );
    }

    #[test]
    fn old_failures_fall_out_of_the_window() {
        let mut t = Tracker::new(3, secs(60));
        let a = ip("192.0.2.1");
        t.record(a, secs(0));
        t.record(a, secs(30));
        assert_eq!(t.record(a, secs(61)), None, "the failure at 0 s expired");
        assert_eq!(t.record(a, secs(70)), Some(3));
    }

    #[test]
    fn addresses_are_counted_separately_and_mapped_v4_is_v4() {
        let mut t = Tracker::new(2, secs(60));
        assert_eq!(t.record(ip("192.0.2.1"), secs(0)), None);
        assert_eq!(t.record(ip("192.0.2.2"), secs(1)), None);
        assert_eq!(t.record(ip("::ffff:192.0.2.1"), secs(2)), Some(2));
    }

    #[test]
    fn late_events_are_ordered() {
        let mut t = Tracker::new(3, secs(60));
        let a = ip("2001:db8::1");
        t.record(a, secs(100));
        t.record(a, secs(30)); // older than the window relative to 100 s: dropped
        assert_eq!(t.record(a, secs(90)), None);
        assert_eq!(t.record(a, secs(95)), Some(3));
    }

    #[test]
    fn memory_stays_bounded_under_a_flood() {
        let capacity = 1000;
        let mut t = Tracker::with_capacity(5, secs(600), capacity);
        for i in 0..50_000u32 {
            let addr = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            t.record(addr, secs(u64::from(i)));
            assert!(t.len() <= capacity);
        }
        // The newest attacker is still tracked and can be banned.
        let last = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + 49_999));
        for s in 0..4 {
            t.record(last, secs(50_000 + s));
        }
        assert!(t.len() <= capacity);
    }

    #[test]
    fn forget() {
        let mut t = Tracker::new(2, secs(60));
        t.record(ip("192.0.2.1"), secs(0));
        t.forget(ip("192.0.2.1"));
        assert_eq!(t.record(ip("192.0.2.1"), secs(1)), None);
    }
}

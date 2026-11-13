//! M-5: the daemon enforces a burst's byte cap itself.
//!
//! A burst (a latched node reaching out to a few named peers) has a byte
//! cap. The embedder used to read the per-peer counters about once a second
//! and end the burst when their sum passed the cap, so a peer sending at
//! line speed got seconds of traffic through first. Now the cap rides on the
//! burst's lease (`POST /agents/connect` with `max_bytes`) and the daemon
//! checks it in its own task, every 10 ms near the cap and up to every 250 ms
//! far from it ([`burst_cap_tick`]): once the bytes moved
//! since the cap was armed pass it, every link is closed, the demand leases
//! end, and no further leased dial runs until the next latch call ends the
//! burst.
//!
//! This module is the accounting only: what counts toward the cap.
//! - Every connection counts, by (peer, connection stable id): the bytes it
//!   moved (UDP sent plus received) since the cap was armed. A connection up
//!   when the cap was armed counts from its counters at that moment; one that
//!   came up later counts from zero.
//! - A connection that went away keeps the bytes it was last seen with, so a
//!   closed link cannot take its share out of the sum. Counters that go
//!   backwards under the same key (a new connection) retire the old share
//!   into a running total instead of overwriting it.
//!
//! What the sum cannot see: bytes in the last tick of a connection that
//! closed between two reads, and packets that reach the socket after the
//! links are closed. Overshoot is therefore bounded by the link rate times
//! one tick plus the time to close, plus what the peers had in flight.

use std::collections::HashMap;
use std::time::Duration;

/// The fastest counter read, used near the cap (and while tripped).
pub(crate) const BURST_CAP_TICK: Duration = Duration::from_millis(10);

/// The slowest counter read, used far from the cap.
pub(crate) const BURST_CAP_SLOW_TICK: Duration = Duration::from_millis(250);

/// The worst-case line rate the tick assumes: 125 MB/s (1 Gbit/s), above any
/// phone link and the loopback rate the full-speed test reaches.
pub(crate) const BURST_CAP_ASSUMED_RATE: u64 = 125_000_000;

/// How long until the next counter read, with `headroom` bytes left before
/// the cap: `clamp(headroom / BURST_CAP_ASSUMED_RATE, 10 ms, 250 ms)`.
///
/// Above the 10 ms floor, a link at the assumed rate cannot move more than
/// the headroom before the next read, so the cap is never passed between two
/// reads; overshoot can only build up in the last 10 ms tick, as with a fixed
/// 10 ms tick. Far from the cap the task wakes up to 25 times less often.
pub(crate) fn burst_cap_tick(headroom: u64) -> Duration {
    let micros = u128::from(headroom) * 1_000_000 / u128::from(BURST_CAP_ASSUMED_RATE);
    let micros = u64::try_from(micros).unwrap_or(u64::MAX);
    Duration::from_micros(micros).clamp(BURST_CAP_TICK, BURST_CAP_SLOW_TICK)
}

/// One connection: a peer's machine id and the connection's stable id.
pub(crate) type LinkKey = ([u8; 32], usize);

/// The bytes counted toward an armed cap.
#[derive(Debug, Clone)]
pub(crate) struct BurstCapCount {
    max_bytes: u64,
    /// Counters at arming time for the connections up then.
    base: HashMap<LinkKey, u64>,
    /// Bytes each connection has moved since arming, as last seen.
    moved: HashMap<LinkKey, u64>,
    /// Shares of connections whose key came back with lower counters.
    retired: u64,
}

impl BurstCapCount {
    /// Arm a cap of `max_bytes`, with the counters (sent plus received) of
    /// every connection up now.
    pub(crate) fn arm(max_bytes: u64, now: impl IntoIterator<Item = (LinkKey, u64)>) -> Self {
        Self {
            max_bytes,
            base: now.into_iter().collect(),
            moved: HashMap::new(),
            retired: 0,
        }
    }

    /// The cap.
    pub(crate) fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Lower the cap (a later lease in the same burst asked for less). A
    /// higher value is ignored.
    pub(crate) fn lower_to(&mut self, max_bytes: u64) {
        self.max_bytes = self.max_bytes.min(max_bytes);
    }

    /// Record one connection's current counters (sent plus received).
    pub(crate) fn observe(&mut self, link: LinkKey, total: u64) {
        let base = self.base.get(&link).copied().unwrap_or(0);
        let previous = self.moved.get(&link).copied().unwrap_or(0);
        if total < base.saturating_add(previous) {
            // Counters went backwards: a new connection under a reused key.
            // Its predecessor's share is kept; the new one counts from zero.
            self.retired = self.retired.saturating_add(previous);
            self.base.insert(link, 0);
            self.moved.insert(link, total);
            return;
        }
        self.moved.insert(link, total - base);
    }

    /// Bytes moved since arming, over every connection seen.
    pub(crate) fn counted(&self) -> u64 {
        self.moved
            .values()
            .fold(self.retired, |sum, bytes| sum.saturating_add(*bytes))
    }

    /// Whether the counted bytes reached the cap.
    pub(crate) fn reached(&self) -> bool {
        self.counted() >= self.max_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(byte: u8, stable_id: usize) -> LinkKey {
        ([byte; 32], stable_id)
    }

    #[test]
    fn a_link_up_at_arming_counts_from_its_counters_then() {
        let mut count = BurstCapCount::arm(1000, [(link(1, 1), 5000)]);
        count.observe(link(1, 1), 5400);
        assert_eq!(count.counted(), 400);
        assert!(!count.reached());
        count.observe(link(1, 1), 6000);
        assert_eq!(count.counted(), 1000);
        assert!(count.reached());
    }

    #[test]
    fn a_link_that_came_up_later_counts_from_zero() {
        let mut count = BurstCapCount::arm(1000, []);
        count.observe(link(2, 7), 300);
        count.observe(link(3, 1), 200);
        assert_eq!(count.counted(), 500);
    }

    #[test]
    fn a_closed_link_keeps_its_share() {
        let mut count = BurstCapCount::arm(1000, []);
        count.observe(link(2, 1), 600);
        // The link closed: it is no longer observed, its bytes stay.
        count.observe(link(2, 2), 500);
        assert_eq!(count.counted(), 1100);
        assert!(count.reached());
    }

    #[test]
    fn counters_that_go_backwards_count_from_zero() {
        let mut count = BurstCapCount::arm(1000, [(link(4, 1), 900)]);
        count.observe(link(4, 1), 100);
        assert_eq!(count.counted(), 100);
    }

    #[test]
    fn a_new_connection_under_a_reused_key_keeps_the_old_share() {
        let mut count = BurstCapCount::arm(10_000, []);
        count.observe(link(5, 9), 700);
        // The same key comes back with lower counters: a new connection.
        count.observe(link(5, 9), 200);
        assert_eq!(count.counted(), 900, "700 retired plus 200 new");
        count.observe(link(5, 9), 450);
        assert_eq!(count.counted(), 1150);
    }

    #[test]
    fn a_link_up_at_arming_never_counts_its_history() {
        // Tens of MB moved before the burst; only bytes since arming count.
        let mut count = BurstCapCount::arm(1000, [(link(6, 3), 40_000_000)]);
        count.observe(link(6, 3), 40_000_100);
        assert_eq!(count.counted(), 100);
        assert!(!count.reached());
    }

    #[test]
    fn the_tick_is_slow_far_from_the_cap_and_10_ms_near_it() {
        assert_eq!(burst_cap_tick(u64::MAX), BURST_CAP_SLOW_TICK, "far away");
        assert_eq!(burst_cap_tick(100_000_000), BURST_CAP_SLOW_TICK);
        assert_eq!(burst_cap_tick(5_000_000), Duration::from_millis(40));
        assert_eq!(burst_cap_tick(1_000_000), BURST_CAP_TICK, "near");
        assert_eq!(burst_cap_tick(0), BURST_CAP_TICK);
    }

    #[test]
    fn a_link_at_the_assumed_rate_never_passes_the_cap_between_reads() {
        // Above the 10 ms floor, the bytes the assumed rate moves in one tick
        // stay within the headroom; at the floor they stay within one 10 ms
        // tick's worth, the documented bound.
        let floor_bytes = BURST_CAP_ASSUMED_RATE / 100;
        let mut headroom = 1u64;
        while headroom < 1 << 40 {
            let tick = burst_cap_tick(headroom);
            assert!(tick >= BURST_CAP_TICK && tick <= BURST_CAP_SLOW_TICK);
            let moved = u128::from(BURST_CAP_ASSUMED_RATE) * tick.as_micros() / 1_000_000;
            assert!(
                moved <= u128::from(headroom.max(floor_bytes)),
                "headroom {headroom}: {moved} bytes in {tick:?}"
            );
            headroom = headroom * 3 / 2 + 1;
        }
    }

    #[test]
    fn a_later_lease_can_only_lower_the_cap() {
        let mut count = BurstCapCount::arm(1000, []);
        count.lower_to(5000);
        assert_eq!(count.max_bytes(), 1000);
        count.lower_to(400);
        assert_eq!(count.max_bytes(), 400);
    }
}

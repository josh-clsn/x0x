//! Join artifacts over a slow gossip inbox: how long their frames live,
//! and the windows that keep them from being asked for or sent again into
//! the same congestion.
//!
//! A metered phone's gossip inbox is tens of seconds to minutes one way
//! (field test 2026-11-04: 35 s to 156 s). So:
//! - a joiner request that took the gossip inbox (a Welcome FetchRequest,
//!   a join-result poll) is not sent again over it for [`GOSSIP_REFRESH`],
//!   counted from its publish;
//! - an owner answer that went out over the gossip inbox is not sent again
//!   for a repeat that arrives while it is still going out, or within
//!   [`OWNER_REPEAT_TAIL`] of its last frame. The tail is short so that a
//!   refresh whose trip was faster than the original request's is still
//!   answered.
//!
//! Both apply only while there is no live direct connection to the peer;
//! the callers check that. Raw QUIC keeps its behaviour.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// The lifetime of every gossip-carried join-artifact frame, in either
/// direction: above the observed one-way latency (156 s), with room for
/// skew.
pub(super) const SLOW_INBOX_LIFETIME_MS: u64 = crate::dm_send::ADMITTED_PUBLISH_LIFETIME_MS;

/// A joiner asks again over the gossip inbox at most once per this window
/// (half the frame lifetime).
pub(super) const GOSSIP_REFRESH: Duration = Duration::from_millis(SLOW_INBOX_LIFETIME_MS / 2);

/// How long after the last frame of a gossip-carried answer the owner still
/// treats a repeat request as a duplicate. Two requests the joiner's
/// refresh lets through arrive at least `GOSSIP_REFRESH` minus the spread
/// of one-way latencies apart (150 s - 121 s = 29 s in the field), so a
/// shorter tail never swallows a needed refresh there.
pub(super) const OWNER_REPEAT_TAIL: Duration = Duration::from_secs(20);

/// The overall deadline of a slow-inbox pull, counted from its start: two
/// frame lifetimes, one for a request to reach the owner and one for the
/// answer to come back, so a refresh sent just before its window closes is
/// still answered into the same pull.
pub(super) const SLOW_INBOX_DEADLINE: Duration = Duration::from_millis(2 * SLOW_INBOX_LIFETIME_MS);

/// Process-local request and answer windows, keyed by the artifact.
#[derive(Debug, Default)]
pub(in crate::server) struct GossipWindows {
    /// Joiner: when a request last took the gossip inbox.
    requested: Mutex<HashMap<String, Instant>>,
    /// Owner: when a frame of an answer last took the gossip inbox.
    served: Mutex<HashMap<String, Instant>>,
}

fn note(map: &Mutex<HashMap<String, Instant>>, key: &str, now: Instant) {
    if let Ok(mut map) = map.lock() {
        map.retain(|_, at| now.saturating_duration_since(*at) < GOSSIP_REFRESH);
        map.insert(key.to_string(), now);
    }
}

fn within(
    map: &Mutex<HashMap<String, Instant>>,
    key: &str,
    now: Instant,
    window: Duration,
) -> bool {
    map.lock().is_ok_and(|map| {
        map.get(key)
            .is_some_and(|at| now.saturating_duration_since(*at) < window)
    })
}

impl GossipWindows {
    /// A joiner request for `key` took the gossip inbox now.
    pub(super) fn note_requested(&self, key: &str, now: Instant) {
        note(&self.requested, key, now);
    }

    /// A joiner request for `key` took the gossip inbox inside the refresh
    /// window.
    pub(super) fn requested_recently(&self, key: &str, now: Instant) -> bool {
        within(&self.requested, key, now, GOSSIP_REFRESH)
    }

    /// A frame of the owner's answer for `key` took the gossip inbox now.
    pub(super) fn note_served(&self, key: &str, now: Instant) {
        note(&self.served, key, now);
    }

    /// The owner's answer for `key` is going out over the gossip inbox, or
    /// its last frame did within the tail.
    pub(super) fn served_recently(&self, key: &str, now: Instant) -> bool {
        within(&self.served, key, now, OWNER_REPEAT_TAIL)
    }

    /// A frame of the answer for `key` took the gossip inbox at or after
    /// `since` (the start of the stream asking).
    pub(super) fn served_since(&self, key: &str, since: Instant) -> bool {
        self.served
            .lock()
            .is_ok_and(|served| served.get(key).is_some_and(|last| *last >= since))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_joiner_asks_once_per_refresh_window() {
        let windows = GossipWindows::default();
        let now = Instant::now();
        assert!(!windows.requested_recently("r", now));
        windows.note_requested("r", now);
        assert!(windows.requested_recently("r", now + GOSSIP_REFRESH - Duration::from_secs(1)));
        assert!(!windows.requested_recently("r", now + GOSSIP_REFRESH));
    }

    #[tokio::test(start_paused = true)]
    async fn an_owner_skips_repeats_only_while_its_answer_goes_out_and_a_short_tail() {
        let windows = GossipWindows::default();
        let now = Instant::now();
        assert!(!windows.served_recently("w", now));
        windows.note_served("w", now);
        windows.note_served("w", now + Duration::from_secs(10));
        let last = now + Duration::from_secs(10);
        assert!(windows.served_recently("w", last + OWNER_REPEAT_TAIL - Duration::from_secs(1)));
        assert!(!windows.served_recently("w", last + OWNER_REPEAT_TAIL));
        assert!(windows.served_since("w", last));
        assert!(!windows.served_since("w", last + Duration::from_secs(1)));
        assert!(
            OWNER_REPEAT_TAIL < GOSSIP_REFRESH - Duration::from_secs(121),
            "the tail stays under the field's closest refresh arrivals"
        );
    }
}

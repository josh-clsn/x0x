//! A Welcome transfer over a slow gossip inbox.
//!
//! On a metered phone the gossip inbox is tens of seconds to minutes one
//! way (field test 2026-11-04: 35 s to 156 s), longer than a joiner's
//! bounded fetch attempt. So:
//! - a joiner keeps a Welcome receive it asked for over gossip across its
//!   attempts ([`WelcomeRetention`]), and keeps a Welcome that completed
//!   between attempts until the next one takes it;
//! - while such a request is younger than [`WELCOME_GOSSIP_REFRESH`] the
//!   joiner does not ask again, and an owner that streamed the Welcome over
//!   gossip inside that window does not stream it again
//!   ([`WelcomeGossipState`]).
//!
//! Raw QUIC keeps its behaviour: nothing here applies to a request that
//! did not take the gossip inbox.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// The lifetime of a gossip-carried Welcome frame, in either direction:
/// above the observed one-way latency (156 s), with room for skew.
pub(super) const WELCOME_GOSSIP_LIFETIME: Duration =
    Duration::from_millis(crate::dm_send::ADMITTED_PUBLISH_LIFETIME_MS);

/// While a gossip-carried request is younger than this, a joiner does not
/// ask again, and an owner does not stream the Welcome again.
pub(super) const WELCOME_GOSSIP_REFRESH: Duration =
    Duration::from_millis(crate::dm_send::ADMITTED_PUBLISH_LIFETIME_MS / 2);

/// How long a joiner keeps a gossip-carried receive across attempts: two
/// full lifetimes, one for the request to reach the owner and one for the
/// stream to come back, so a request sent at the last moment before a
/// refresh is still answered into the same receive.
pub(super) const RETAINED_WELCOME_TTL: Duration = Duration::from_secs(600);

/// The most retained receives, and separately completed Welcomes, a joiner
/// holds.
pub(super) const MAX_RETAINED_WELCOMES: usize = 8;

/// The most bytes the retained receives (or the completed Welcomes) hold.
pub(super) const MAX_RETAINED_WELCOME_BYTES: u64 = 8 * 1024 * 1024;

/// A joiner receive's life across bounded fetch attempts.
#[derive(Debug, Clone, Copy)]
pub(in crate::server) struct WelcomeRetention {
    /// When the receive began (the first attempt that registered it).
    pub(super) started_at: Instant,
    /// When a FetchRequest for it last took the gossip inbox.
    pub(super) gossip_fetch_sent_at: Option<Instant>,
    /// No attempt is waiting on it: it outlived the attempt that began it.
    pub(super) retained: bool,
}

impl Default for WelcomeRetention {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            gossip_fetch_sent_at: None,
            retained: false,
        }
    }
}

impl WelcomeRetention {
    /// A gossip-carried request is still on its way or being answered.
    pub(super) fn gossip_fetch_recent(&self, now: Instant) -> bool {
        self.gossip_fetch_sent_at
            .is_some_and(|sent| now.saturating_duration_since(sent) < WELCOME_GOSSIP_REFRESH)
    }

    /// The receive may outlive its attempt: it was asked for over gossip,
    /// and its overall deadline has not passed.
    pub(super) fn may_retain(&self, now: Instant) -> bool {
        self.gossip_fetch_sent_at.is_some() && !self.past_deadline(now)
    }

    pub(super) fn past_deadline(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started_at) >= RETAINED_WELCOME_TTL
    }
}

/// The ids to drop, oldest first, so that `entries` (id, start, bytes)
/// stays within [`MAX_RETAINED_WELCOMES`] and [`MAX_RETAINED_WELCOME_BYTES`].
pub(super) fn over_cap(entries: &[(String, Instant, u64)]) -> Vec<String> {
    let mut sorted: Vec<&(String, Instant, u64)> = entries.iter().collect();
    sorted.sort_by_key(|(_, started, _)| *started);
    let mut count = sorted.len();
    let mut bytes: u64 = sorted.iter().map(|(_, _, b)| *b).sum();
    let mut drop = Vec::new();
    for (id, _, b) in sorted {
        if count <= MAX_RETAINED_WELCOMES && bytes <= MAX_RETAINED_WELCOME_BYTES {
            break;
        }
        drop.push(id.clone());
        count -= 1;
        bytes = bytes.saturating_sub(*b);
    }
    drop
}

/// Process-local Welcome state for the gossip inbox: a joiner's Welcomes
/// that completed between attempts, and the owner's gossip-carried
/// streams.
#[derive(Debug, Default)]
pub(in crate::server) struct WelcomeGossipState {
    completed: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
    /// Per Welcome: when its refresh window opened, and when a frame of it
    /// last took the gossip inbox.
    streamed: Mutex<HashMap<String, (Instant, Instant)>>,
}

impl WelcomeGossipState {
    /// Keep a Welcome that completed with no attempt waiting. Returns the
    /// ids dropped to stay within the caps (the oldest; possibly this one).
    pub(super) fn keep_completed(
        &self,
        welcome_id: &str,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Vec<String> {
        let Ok(mut completed) = self.completed.lock() else {
            return vec![welcome_id.to_string()];
        };
        completed.retain(|_, (_, at)| now.saturating_duration_since(*at) < RETAINED_WELCOME_TTL);
        completed.insert(welcome_id.to_string(), (bytes, now));
        let entries: Vec<(String, Instant, u64)> = completed
            .iter()
            .map(|(id, (bytes, at))| (id.clone(), *at, bytes.len() as u64))
            .collect();
        let dropped = over_cap(&entries);
        for id in &dropped {
            completed.remove(id);
        }
        dropped
    }

    /// Take a Welcome that completed between attempts, if one is held and
    /// still inside its deadline.
    pub(super) fn take_completed(&self, welcome_id: &str, now: Instant) -> Option<Vec<u8>> {
        let mut completed = self.completed.lock().ok()?;
        completed.retain(|_, (_, at)| now.saturating_duration_since(*at) < RETAINED_WELCOME_TTL);
        completed.remove(welcome_id).map(|(bytes, _)| bytes)
    }

    /// The owner streamed `welcome_id` over the gossip inbox inside the
    /// refresh window.
    pub(super) fn streamed_recently(&self, welcome_id: &str, now: Instant) -> bool {
        self.streamed.lock().is_ok_and(|streamed| {
            streamed.get(welcome_id).is_some_and(|(opened, _)| {
                now.saturating_duration_since(*opened) < WELCOME_GOSSIP_REFRESH
            })
        })
    }

    /// A frame of `welcome_id` took the gossip inbox at or after `since`
    /// (the start of the stream asking).
    pub(super) fn streamed_since(&self, welcome_id: &str, since: Instant) -> bool {
        self.streamed.lock().is_ok_and(|streamed| {
            streamed
                .get(welcome_id)
                .is_some_and(|(_, last)| *last >= since)
        })
    }

    /// A frame of the owner's stream for `welcome_id` took the gossip
    /// inbox: its refresh window opens now, unless one is already open.
    pub(super) fn note_streamed(&self, welcome_id: &str, now: Instant) {
        if let Ok(mut streamed) = self.streamed.lock() {
            streamed.retain(|_, (opened, _)| {
                now.saturating_duration_since(*opened) < WELCOME_GOSSIP_REFRESH
            });
            let entry = streamed.entry(welcome_id.to_string()).or_insert((now, now));
            entry.1 = now;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn entry(id: &str, at: Instant, bytes: u64) -> (String, Instant, u64) {
        (id.to_string(), at, bytes)
    }

    #[tokio::test(start_paused = true)]
    async fn the_oldest_entries_go_first_to_keep_within_the_caps() {
        let start = Instant::now();
        let mut entries: Vec<_> = (0..MAX_RETAINED_WELCOMES + 2)
            .map(|i| entry(&format!("w{i}"), start + Duration::from_secs(i as u64), 10))
            .collect();
        assert_eq!(over_cap(&entries), vec!["w0".to_string(), "w1".to_string()]);
        entries.truncate(2);
        entries.push(entry(
            "big",
            start + Duration::from_secs(99),
            MAX_RETAINED_WELCOME_BYTES,
        ));
        assert_eq!(over_cap(&entries), vec!["w0".to_string(), "w1".to_string()]);
        assert!(over_cap(&entries[..2]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_retained_receive_has_an_overall_deadline() {
        let now = Instant::now();
        assert!(
            !WelcomeRetention::default().may_retain(now),
            "never asked over gossip"
        );
        let retention = WelcomeRetention {
            gossip_fetch_sent_at: Some(now),
            ..WelcomeRetention::default()
        };
        assert!(retention.may_retain(now));
        assert!(retention.gossip_fetch_recent(now));
        assert!(!retention.gossip_fetch_recent(now + WELCOME_GOSSIP_REFRESH));
        assert!(retention.may_retain(now + RETAINED_WELCOME_TTL - Duration::from_secs(1)));
        assert!(!retention.may_retain(now + RETAINED_WELCOME_TTL));
        assert!(retention.past_deadline(now + RETAINED_WELCOME_TTL));
    }

    #[tokio::test(start_paused = true)]
    async fn completed_welcomes_are_capped_and_expire() {
        let state = WelcomeGossipState::default();
        let now = Instant::now();
        for i in 0..MAX_RETAINED_WELCOMES + 1 {
            let dropped = state.keep_completed(
                &format!("w{i}"),
                vec![0; 4],
                now + Duration::from_secs(i as u64),
            );
            if i < MAX_RETAINED_WELCOMES {
                assert!(dropped.is_empty());
            } else {
                assert_eq!(dropped, vec!["w0".to_string()]);
            }
        }
        assert!(state.take_completed("w0", now).is_none());
        assert_eq!(state.take_completed("w1", now), Some(vec![0; 4]));
        assert!(state.take_completed("w1", now).is_none(), "taken once");
        assert!(state
            .take_completed("w2", now + RETAINED_WELCOME_TTL + Duration::from_secs(3))
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn an_owner_streams_once_per_refresh_window() {
        let state = WelcomeGossipState::default();
        let now = Instant::now();
        assert!(!state.streamed_recently("w", now));
        state.note_streamed("w", now);
        state.note_streamed("w", now + Duration::from_secs(10));
        assert!(state.streamed_recently("w", now + WELCOME_GOSSIP_REFRESH - Duration::from_secs(1)));
        assert!(!state.streamed_recently("w", now + WELCOME_GOSSIP_REFRESH));
        assert!(state.streamed_since("w", now + Duration::from_secs(10)));
        assert!(!state.streamed_since("w", now + Duration::from_secs(11)));
    }
}

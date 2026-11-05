//! A Welcome transfer over a slow gossip inbox.
//!
//! On a metered phone the gossip inbox is tens of seconds to minutes one
//! way (field test 2026-11-04: 35 s to 156 s), longer than a joiner's
//! bounded fetch attempt. So a joiner keeps a Welcome receive it asked for
//! over gossip across its attempts ([`WelcomeRetention`]), and keeps a
//! Welcome that completed between attempts until the next one takes it
//! ([`WelcomeGossipState`]), each within the receive's overall deadline.
//! The request and answer windows are in [`super::gossip_window`].
//!
//! Raw QUIC keeps its behaviour: nothing here applies to a request that
//! did not take the gossip inbox.

use super::gossip_window::{GOSSIP_REFRESH, SLOW_INBOX_DEADLINE};
use std::collections::HashMap;
use std::sync::Mutex;
#[cfg(test)]
use std::time::Duration;
use tokio::time::Instant;

/// How long a joiner keeps a gossip-carried receive across attempts,
/// counted from the attempt that began it.
pub(super) const RETAINED_WELCOME_TTL: std::time::Duration = SLOW_INBOX_DEADLINE;

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
            .is_some_and(|sent| now.saturating_duration_since(sent) < GOSSIP_REFRESH)
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

/// A Welcome that completed with no attempt waiting.
#[derive(Debug)]
struct CompletedWelcome {
    group_id: String,
    bytes: Vec<u8>,
    /// When its receive began: the receive's overall deadline still holds.
    started_at: Instant,
}

/// A joiner's Welcomes that completed between attempts.
#[derive(Debug, Default)]
pub(in crate::server) struct WelcomeGossipState {
    completed: Mutex<HashMap<String, CompletedWelcome>>,
}

fn live(entry: &CompletedWelcome, now: Instant) -> bool {
    now.saturating_duration_since(entry.started_at) < RETAINED_WELCOME_TTL
}

impl WelcomeGossipState {
    /// Keep a Welcome that completed with no attempt waiting, until the
    /// deadline of the receive that began at `started_at`. Returns the ids
    /// dropped to stay within the caps (the oldest; possibly this one).
    pub(super) fn keep_completed(
        &self,
        welcome_id: &str,
        group_id: &str,
        bytes: Vec<u8>,
        started_at: Instant,
        now: Instant,
    ) -> Vec<String> {
        let Ok(mut completed) = self.completed.lock() else {
            return vec![welcome_id.to_string()];
        };
        completed.retain(|_, entry| live(entry, now));
        let entry = CompletedWelcome {
            group_id: group_id.to_string(),
            bytes,
            started_at,
        };
        if !live(&entry, now) {
            return vec![welcome_id.to_string()];
        }
        completed.insert(welcome_id.to_string(), entry);
        let entries: Vec<(String, Instant, u64)> = completed
            .iter()
            .map(|(id, entry)| (id.clone(), entry.started_at, entry.bytes.len() as u64))
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
        completed.retain(|_, entry| live(entry, now));
        completed.remove(welcome_id).map(|entry| entry.bytes)
    }

    /// Drop every held Welcome whose group `matches`; returns their ids.
    pub(super) fn purge_groups(&self, matches: impl Fn(&str) -> bool) -> Vec<String> {
        let Ok(mut completed) = self.completed.lock() else {
            return Vec::new();
        };
        let ids: Vec<String> = completed
            .iter()
            .filter(|(_, entry)| matches(&entry.group_id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            completed.remove(id);
        }
        ids
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
        assert!(!retention.gossip_fetch_recent(now + GOSSIP_REFRESH));
        assert!(retention.may_retain(now + RETAINED_WELCOME_TTL - Duration::from_secs(1)));
        assert!(!retention.may_retain(now + RETAINED_WELCOME_TTL));
        assert!(retention.past_deadline(now + RETAINED_WELCOME_TTL));
    }

    #[tokio::test(start_paused = true)]
    async fn completed_welcomes_are_capped_and_expire() {
        let state = WelcomeGossipState::default();
        let now = Instant::now();
        for i in 0..MAX_RETAINED_WELCOMES + 1 {
            let at = now + Duration::from_secs(i as u64);
            let dropped = state.keep_completed(&format!("w{i}"), "g", vec![0; 4], at, at);
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

    /// WHY (review L2): a Welcome that completes late keeps its receive's
    /// overall deadline; it does not start a fresh one.
    #[tokio::test(start_paused = true)]
    async fn a_completed_welcome_keeps_its_receives_deadline() {
        let state = WelcomeGossipState::default();
        let started = Instant::now();
        let late = started + RETAINED_WELCOME_TTL - Duration::from_secs(10);
        assert!(state
            .keep_completed("w", "g", vec![1], started, late)
            .is_empty());
        assert!(
            state
                .take_completed("w", started + RETAINED_WELCOME_TTL)
                .is_none(),
            "held past the receive's deadline"
        );
        assert_eq!(
            state.keep_completed("x", "g", vec![1], started, started + RETAINED_WELCOME_TTL),
            vec!["x".to_string()],
            "a Welcome completing after its deadline is not kept"
        );
    }

    /// WHY (review L4): a group purge drops its held Welcomes.
    #[tokio::test(start_paused = true)]
    async fn a_group_purge_drops_its_completed_welcomes() {
        let state = WelcomeGossipState::default();
        let now = Instant::now();
        state.keep_completed("a", "g1", vec![1], now, now);
        state.keep_completed("b", "g2", vec![1], now, now);
        assert_eq!(
            state.purge_groups(|group| group == "g1"),
            vec!["a".to_string()]
        );
        assert!(state.take_completed("a", now).is_none());
        assert!(state.take_completed("b", now).is_some());
    }
}

//! F-D: a connection the peer closes straight away is a failed attempt.
//!
//! A latched (mesh-quiesced) peer completes the QUIC handshake of every
//! inbound dial, because ant-quic finishes it before x0x's accept loop can
//! look, and then closes the connection. To the dialler the redial looked
//! successful: its `PeerConnected` aborted the reconnect ladder before the
//! failure cooldown, and the close that followed started a fresh ladder at
//! its first, 1 s step. That is about one handshake a second for as long as
//! the latch holds.
//!
//! This table remembers, per peer, the reconnect ladder's last dial step and
//! when the latest connection to the peer came up. It lives outside the
//! ladder task, so the abort on `PeerConnected` does not clear it.
//! - The ladder notes each dial with its step ([`RedialFlaps::note_dial`]).
//! - Every `PeerConnected`, whichever path dialled (the ladder, a repair, a
//!   join or demand dial, an inbound accept), re-stamps the time
//!   ([`RedialFlaps::note_connected`]). The settle time is measured from the
//!   connection, so a slow, hole-punched redial is judged the same as a
//!   fast one.
//! - A disconnect within [`REDIAL_SETTLE_WINDOW`] of that stamp resumes the
//!   backoff one step on, and holds the failure cooldown once the steps run
//!   out.
//!
//! Cost, on record: a real peer on a link whose connections keep dying
//! within the settle window also reaches the cooldown after five flaps, and
//! proactive reconnect to it then waits up to 60 s. A peer that comes back
//! by any path (`PeerConnected`) ends the hold, demand dials are never
//! held, and an identity announcement from the peer, which a latched node
//! never sends, lifts the backoff ([`RedialFlaps::lift`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// How long a connection must live before its close counts as an ordinary
/// drop rather than the peer refusing it.
pub(crate) const REDIAL_SETTLE_WINDOW: Duration = Duration::from_secs(5);

/// How long a ladder dial's step is carried onto a connection that comes up
/// after it. Longer than any dial the ladder makes (Phase 1 candidates at
/// 5 s each plus Phase 2's cached addresses); a connection after that is
/// not that dial's and starts from the first step.
const DIAL_SPAN: Duration = Duration::from_secs(120);

/// Bound on remembered peers. Entries older than [`DIAL_SPAN`] carry no
/// information and are pruned first.
const MAX_TRACKED_REDIALS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Redial {
    at: Instant,
    step: usize,
}

/// Where a new reconnect ladder starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LadderStart {
    /// Hold the failure cooldown before the first attempt.
    pub(crate) cooldown_first: bool,
    /// Index into the backoff delays of the first attempt.
    pub(crate) first_step: usize,
}

/// Per-peer record of the reconnect ladder's last dial and connection.
#[derive(Debug, Default)]
pub(crate) struct RedialFlaps {
    last: Mutex<HashMap<[u8; 32], Redial>>,
    /// Per-peer count of [`Self::lift`] calls, read by a held ladder.
    lifts: Mutex<HashMap<[u8; 32], u64>>,
    lifted: Notify,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl RedialFlaps {
    fn upsert(&self, peer: [u8; 32], now: Instant, update: impl FnOnce(Option<Redial>) -> Redial) {
        let mut last = locked(&self.last);
        if last.len() >= MAX_TRACKED_REDIALS && !last.contains_key(&peer) {
            last.retain(|_, redial| now.saturating_duration_since(redial.at) < DIAL_SPAN);
            if last.len() >= MAX_TRACKED_REDIALS {
                return;
            }
        }
        let next = update(last.get(&peer).copied());
        last.insert(peer, next);
    }

    /// The ladder is about to dial `peer` at backoff index `step`.
    pub(crate) fn note_dial(&self, peer: [u8; 32], step: usize, now: Instant) {
        self.upsert(peer, now, |_| Redial { at: now, step });
    }

    /// A connection to `peer` came up, by any path. It keeps the step of a
    /// ladder dial made within [`DIAL_SPAN`]; otherwise it counts as the
    /// first step.
    pub(crate) fn note_connected(&self, peer: [u8; 32], now: Instant) {
        self.upsert(peer, now, |previous| {
            let step = previous
                .filter(|redial| now.saturating_duration_since(redial.at) < DIAL_SPAN)
                .map_or(0, |redial| redial.step);
            Redial { at: now, step }
        });
    }

    /// Where a ladder for `peer`, scheduled at `now` by a disconnect, starts.
    ///
    /// A disconnect inside [`REDIAL_SETTLE_WINDOW`] of the last stamp
    /// resumes one step past it; past the last of `steps` it holds the
    /// cooldown first and then starts over. Anything else starts at once
    /// from the first step and forgets the old record.
    pub(crate) fn ladder_start(&self, peer: [u8; 32], steps: usize, now: Instant) -> LadderStart {
        let mut last = locked(&self.last);
        let flapped = last
            .get(&peer)
            .filter(|redial| now.saturating_duration_since(redial.at) < REDIAL_SETTLE_WINDOW)
            .map(|redial| redial.step + 1);
        match flapped {
            Some(next) if next < steps => LadderStart {
                cooldown_first: false,
                first_step: next,
            },
            Some(_) => {
                last.remove(&peer);
                LadderStart {
                    cooldown_first: true,
                    first_step: 0,
                }
            }
            None => {
                last.remove(&peer);
                LadderStart {
                    cooldown_first: false,
                    first_step: 0,
                }
            }
        }
    }

    fn lift_count(&self, peer: &[u8; 32]) -> u64 {
        locked(&self.lifts).get(peer).copied().unwrap_or(0)
    }

    /// The peer is meshed again (it announced): forget its record and end a
    /// held cooldown now.
    pub(crate) fn lift(&self, peer: [u8; 32]) {
        locked(&self.last).remove(&peer);
        {
            let mut lifts = locked(&self.lifts);
            if lifts.len() >= MAX_TRACKED_REDIALS && !lifts.contains_key(&peer) {
                // A cleared count reads as a lift to a held ladder: it only
                // starts that ladder early.
                lifts.clear();
            }
            let count = lifts.entry(peer).or_insert(0);
            *count = count.wrapping_add(1);
        }
        self.lifted.notify_waiters();
    }

    /// Hold `peer`'s ladder for `duration`, or until [`Self::lift`] is
    /// called for it. Returns whether it was lifted.
    pub(crate) async fn hold(&self, peer: [u8; 32], duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        let before = self.lift_count(&peer);
        loop {
            let notified = self.lifted.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.lift_count(&peer) != before {
                return true;
            }
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return false,
                () = &mut notified => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 32] = [7; 32];
    const STEPS: usize = 5;

    fn fresh() -> LadderStart {
        LadderStart {
            cooldown_first: false,
            first_step: 0,
        }
    }

    #[test]
    fn a_peer_never_dialled_starts_the_ladder_at_once() {
        let flaps = RedialFlaps::default();
        assert_eq!(flaps.ladder_start(PEER, STEPS, Instant::now()), fresh());
    }

    #[test]
    fn a_dial_closed_at_once_resumes_one_step_on_until_the_cooldown() {
        let flaps = RedialFlaps::default();
        let now = Instant::now();
        for step in 0..STEPS - 1 {
            flaps.note_dial(PEER, step, now);
            flaps.note_connected(PEER, now);
            assert_eq!(
                flaps.ladder_start(PEER, STEPS, now + Duration::from_millis(50)),
                LadderStart {
                    cooldown_first: false,
                    first_step: step + 1,
                }
            );
        }
        flaps.note_dial(PEER, STEPS - 1, now);
        flaps.note_connected(PEER, now);
        assert_eq!(
            flaps.ladder_start(PEER, STEPS, now + Duration::from_millis(50)),
            LadderStart {
                cooldown_first: true,
                first_step: 0,
            }
        );
        // The cooldown consumed the record: the ladder after it is fresh.
        assert_eq!(flaps.ladder_start(PEER, STEPS, now), fresh());
    }

    /// I-1: a slow redial (the connection comes up 30 s after the dial
    /// started) that the peer closes at once still resumes one step on.
    #[test]
    fn the_settle_time_runs_from_the_connection_not_the_dial() {
        let flaps = RedialFlaps::default();
        let dial = Instant::now();
        flaps.note_dial(PEER, 2, dial);
        let up = dial + Duration::from_secs(30);
        flaps.note_connected(PEER, up);
        assert_eq!(
            flaps.ladder_start(PEER, STEPS, up + Duration::from_millis(50)),
            LadderStart {
                cooldown_first: false,
                first_step: 3,
            }
        );
    }

    /// L-1: a connection no ladder dial made (a repair, a join or demand
    /// dial) that the peer closes at once counts as the first failed step.
    #[test]
    fn a_connection_from_any_path_closed_at_once_counts() {
        let flaps = RedialFlaps::default();
        let up = Instant::now();
        flaps.note_connected(PEER, up);
        assert_eq!(
            flaps
                .ladder_start(PEER, STEPS, up + Duration::from_millis(50))
                .first_step,
            1
        );
    }

    #[test]
    fn a_connection_long_after_the_last_dial_does_not_inherit_its_step() {
        let flaps = RedialFlaps::default();
        let dial = Instant::now();
        flaps.note_dial(PEER, 3, dial);
        let up = dial + DIAL_SPAN;
        flaps.note_connected(PEER, up);
        assert_eq!(flaps.ladder_start(PEER, STEPS, up).first_step, 1);
    }

    #[test]
    fn a_connection_that_outlived_the_window_starts_over() {
        let flaps = RedialFlaps::default();
        let now = Instant::now();
        flaps.note_dial(PEER, 3, now);
        flaps.note_connected(PEER, now);
        assert_eq!(
            flaps.ladder_start(PEER, STEPS, now + REDIAL_SETTLE_WINDOW),
            fresh()
        );
        // And the stale record is gone.
        assert_eq!(flaps.ladder_start(PEER, STEPS, now), fresh());
    }

    #[test]
    fn peers_are_tracked_apart() {
        let flaps = RedialFlaps::default();
        let now = Instant::now();
        flaps.note_dial(PEER, 2, now);
        assert_eq!(flaps.ladder_start([8; 32], STEPS, now), fresh());
        assert_eq!(flaps.ladder_start(PEER, STEPS, now).first_step, 3);
    }

    #[test]
    fn the_table_is_bounded_and_prunes_stale_entries_first() {
        let flaps = RedialFlaps::default();
        let start = Instant::now();
        for i in 0..MAX_TRACKED_REDIALS {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(i as u64).to_le_bytes());
            flaps.note_dial(peer, 0, start);
        }
        let later = start + DIAL_SPAN;
        flaps.note_dial(PEER, 1, later);
        assert_eq!(locked(&flaps.last).len(), 1, "stale entries were pruned");
        assert_eq!(flaps.ladder_start(PEER, STEPS, later).first_step, 2);
    }

    /// L-2: an announcement from the peer forgets its record and ends a
    /// held cooldown; another peer's lift does not.
    #[tokio::test(start_paused = true)]
    async fn a_lift_ends_the_hold_and_forgets_the_record() {
        let flaps = std::sync::Arc::new(RedialFlaps::default());
        let held = tokio::spawn({
            let flaps = std::sync::Arc::clone(&flaps);
            async move { flaps.hold(PEER, Duration::from_secs(60)).await }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        flaps.lift([8; 32]);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!held.is_finished(), "another peer's lift leaves the hold");
        flaps.note_dial(PEER, 4, Instant::now());
        flaps.lift(PEER);
        assert!(held.await.expect("hold task"), "the lift ends the hold");
        assert_eq!(flaps.ladder_start(PEER, STEPS, Instant::now()), fresh());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unlifted_hold_runs_its_full_time() {
        let flaps = RedialFlaps::default();
        let start = Instant::now();
        assert!(!flaps.hold(PEER, Duration::from_secs(60)).await);
        assert!(Instant::now() >= start + Duration::from_secs(60));
    }
}

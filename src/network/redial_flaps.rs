//! F-D: a proactive redial the peer closes straight away is a failed attempt.
//!
//! A latched (mesh-quiesced) peer completes the QUIC handshake of every
//! inbound dial, because ant-quic finishes it before x0x's accept loop can
//! look, and then closes the connection. To the dialler the redial looked
//! successful: its `PeerConnected` aborted the reconnect ladder before the
//! failure cooldown, and the close that followed started a fresh ladder at
//! its first, 1 s step. That is about one handshake a second for as long as
//! the latch holds.
//!
//! This table remembers, per peer, when the reconnect ladder last started a
//! dial and at which step. It lives outside the ladder task, so the abort on
//! `PeerConnected` does not clear it. A disconnect that arrives within
//! [`REDIAL_FLAP_WINDOW`] of that dial means the connection did not survive
//! its settle time, and the next ladder resumes the backoff one step on,
//! taking the failure cooldown once the steps run out.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// How soon after a proactive dial starts a disconnect counts as the peer
/// closing that dial at once: the per-candidate dial timeout (5 s) plus a
/// 5 s settle window.
pub(crate) const REDIAL_FLAP_WINDOW: Duration = Duration::from_secs(10);

/// Bound on remembered dials. Entries older than [`REDIAL_FLAP_WINDOW`] carry
/// no information and are pruned first.
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

/// Per-peer record of the reconnect ladder's last dial.
#[derive(Debug, Default)]
pub(crate) struct RedialFlaps {
    last: Mutex<HashMap<[u8; 32], Redial>>,
}

impl RedialFlaps {
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Redial>> {
        match self.last.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The ladder is about to dial `peer` at backoff index `step`.
    pub(crate) fn note_dial(&self, peer: [u8; 32], step: usize, now: Instant) {
        let mut last = self.guard();
        if last.len() >= MAX_TRACKED_REDIALS && !last.contains_key(&peer) {
            last.retain(|_, redial| now.saturating_duration_since(redial.at) < REDIAL_FLAP_WINDOW);
            if last.len() >= MAX_TRACKED_REDIALS {
                return;
            }
        }
        last.insert(peer, Redial { at: now, step });
    }

    /// Where a ladder for `peer`, scheduled at `now` by a disconnect, starts.
    ///
    /// A disconnect inside [`REDIAL_FLAP_WINDOW`] of the last ladder dial
    /// resumes one step past it; past the last of `steps` it holds the
    /// cooldown first and then starts over. Anything else starts at once
    /// from the first step and forgets the old dial.
    pub(crate) fn ladder_start(&self, peer: [u8; 32], steps: usize, now: Instant) -> LadderStart {
        let mut last = self.guard();
        let flapped = last
            .get(&peer)
            .filter(|redial| now.saturating_duration_since(redial.at) < REDIAL_FLAP_WINDOW)
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
            assert_eq!(
                flaps.ladder_start(PEER, STEPS, now + Duration::from_millis(50)),
                LadderStart {
                    cooldown_first: false,
                    first_step: step + 1,
                }
            );
        }
        flaps.note_dial(PEER, STEPS - 1, now);
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

    #[test]
    fn a_connection_that_outlived_the_window_starts_over() {
        let flaps = RedialFlaps::default();
        let now = Instant::now();
        flaps.note_dial(PEER, 3, now);
        assert_eq!(
            flaps.ladder_start(PEER, STEPS, now + REDIAL_FLAP_WINDOW),
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
    fn the_table_is_bounded_and_prunes_stale_dials_first() {
        let flaps = RedialFlaps::default();
        let start = Instant::now();
        for i in 0..MAX_TRACKED_REDIALS {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(i as u64).to_le_bytes());
            flaps.note_dial(peer, 0, start);
        }
        let later = start + REDIAL_FLAP_WINDOW;
        flaps.note_dial(PEER, 1, later);
        assert_eq!(flaps.guard().len(), 1, "stale dials were pruned");
        assert_eq!(flaps.ladder_start(PEER, STEPS, later).first_step, 2);
    }
}

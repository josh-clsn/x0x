//! A catch-up ask never holds up the apply or the listener that needs it
//! (survivor re-key A12; see `docs/adr/transient/T-catchup-off-the-apply-path.md`).
//!
//! An apply that finds a TreeKEM membership event ahead of this member's
//! head parks the event in `treekem_pending_events` and asks peers for the
//! commits in between. The asks used to run inside the apply, under the
//! room's membership lock, one peer after another. A peer that does not
//! answer costs a whole direct-message timeout (about 24 s), so one event
//! could hold the room for minutes. Now:
//!
//! - the event is parked first, as before;
//! - each ask is registered before the apply returns: the throttle is
//!   stamped, and the ask joins the room's flight, keyed by the peer and the
//!   head it is asked from. An ask already in flight from the same head is
//!   skipped, so two gaps at one head make one ask per peer. A gap after the
//!   head moved asks again at once;
//! - each ask is sent in its own task, under [`ASK_TIMEOUT`], so a silent
//!   peer delays no other ask;
//! - the parked events replay when a page arrives
//!   (`handle_treekem_catchup_response`) or when a live apply lands the
//!   commit they wait for, in commit order.
//!
//! A truncated page's follow-up ask goes the same way: in its own task, at
//! most one in flight per (room, peer, head), so the catch-up listener that
//! read the page never waits on it, and a page that moved the head always
//! asks for the next one (fix round 2, N-1).

use super::{
    request_treekem_catchup_page, signed_catchup, stamp_catchup_throttle, AppState,
    TreeKemCatchupRequest, TREEKEM_CATCHUP_RESPONSE_EVENT_CAP, TREEKEM_CATCHUP_THROTTLE,
};
use crate::identity::AgentId;
use crate::logging::LogHexId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

/// The longest one ask may take before its flight forgets it. A direct
/// send gives up after about 24 s; this bounds a send that never returns.
pub(super) const ASK_TIMEOUT: Duration = Duration::from_secs(30);

/// One ask: the peer, and the head (signed revision, TreeKEM epoch) it is
/// asked from.
type AskKey = (AgentId, u64, u64);

/// The asks in flight, by room (`named_groups` key), and the follow-up page
/// asks in flight, by (room, peer, head).
#[derive(Debug, Default)]
pub(in crate::server) struct GapCatchups {
    rooms: HashMap<String, HashSet<AskKey>>,
    follow_ups: HashSet<(String, AskKey)>,
}

/// What [`GapCatchups::begin_ask`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Begin {
    /// The same ask is in flight.
    InFlight,
    /// Registered; the room had no ask in flight, so this starts its flight.
    StartsFlight,
    /// Registered in the room's running flight.
    Joins,
}

impl GapCatchups {
    fn begin_ask(&mut self, room: &str, key: AskKey) -> Begin {
        let starts = !self.rooms.contains_key(room);
        if !self.rooms.entry(room.to_string()).or_default().insert(key) {
            return Begin::InFlight;
        }
        if starts {
            Begin::StartsFlight
        } else {
            Begin::Joins
        }
    }

    fn end_ask(&mut self, room: &str, key: &AskKey) {
        if let Some(asks) = self.rooms.get_mut(room) {
            asks.remove(key);
            if asks.is_empty() {
                self.rooms.remove(room);
            }
        }
    }

    /// Whether `room` has an ask in flight (tests).
    #[cfg(test)]
    pub(in crate::server) fn in_flight(&self, room: &str) -> bool {
        self.rooms.contains_key(room)
    }

    /// The follow-up page asks in flight (tests).
    #[cfg(test)]
    pub(in crate::server) fn follow_ups_in_flight(&self) -> usize {
        self.follow_ups.len()
    }
}

fn lock(state: &AppState) -> std::sync::MutexGuard<'_, GapCatchups> {
    state
        .treekem_gap_catchups
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Removes an ask or a follow-up from the registry when its task ends,
/// however it ends.
enum Registered {
    Ask(String, AskKey),
    FollowUp(String, AskKey),
}

struct EndOnDrop {
    state: Arc<AppState>,
    registered: Registered,
}

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        let mut catchups = lock(&self.state);
        match &self.registered {
            Registered::Ask(room, key) => catchups.end_ask(room, key),
            Registered::FollowUp(room, key) => {
                catchups.follow_ups.remove(&(room.clone(), *key));
            }
        }
    }
}

/// Ask each of `peers` for a catch-up page from this member's head in
/// `room`, each in its own task. Every ask is registered, and the throttle
/// stamped, before this returns. A peer asked from the same head inside
/// [`TREEKEM_CATCHUP_THROTTLE`], or with that ask still in flight, is
/// skipped. Nothing here waits on the network.
pub(super) async fn request_treekem_catchup_for_gap(
    state: &Arc<AppState>,
    room: &str,
    peers: Vec<AgentId>,
    missing_prev_state_hash: Option<String>,
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (from_revision, from_epoch, current_state_hash) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(room) else {
            return;
        };
        if info.withdrawn {
            return;
        }
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
        )
    };
    for peer in peers {
        let key = (peer, from_revision, from_epoch);
        let peer_hex = hex::encode(peer.as_bytes());
        let throttle_key = format!("{room}:{peer_hex}:{from_revision}:{from_epoch}");
        {
            let mut throttle = state.treekem_catchup_throttle.write().await;
            if throttle
                .get(&throttle_key)
                .is_some_and(|last| last.elapsed() < TREEKEM_CATCHUP_THROTTLE)
            {
                continue;
            }
            let begin = lock(state).begin_ask(room, key);
            if begin == Begin::InFlight {
                continue;
            }
            stamp_catchup_throttle(&mut throttle, throttle_key, tokio::time::Instant::now());
            #[cfg(test)]
            {
                if begin == Begin::StartsFlight {
                    state
                        .named_group_test_recorders
                        .gap_catchup_flights
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                if let Ok(mut asks) = state.named_group_test_recorders.gap_asks.lock() {
                    asks.push((peer_hex.clone(), from_revision));
                }
            }
        }
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: room.to_string(),
            requester_agent_id: local_agent_hex.clone(),
            from_revision,
            from_treekem_epoch: from_epoch,
            current_state_hash: current_state_hash.clone(),
            missing_prev_state_hash: missing_prev_state_hash.clone(),
            target_member_id: None,
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
            signed_by: None,
            head_challenge: None,
        };
        let end = EndOnDrop {
            state: Arc::clone(state),
            registered: Registered::Ask(room.to_string(), key),
        };
        tokio::spawn(async move {
            // Survivor re-key A5: signed, for a responder that cannot verify
            // this member's transport.
            let sent = tokio::time::timeout(
                ASK_TIMEOUT,
                signed_catchup::send_page_request(&end.state, &peer, request),
            )
            .await;
            match sent {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(
                    group_id = %LogHexId::group(&end.registered_room()),
                    peer = %LogHexId::agent(&peer_hex),
                    "TreeKEM catch-up request failed: {error}"
                ),
                Err(_) => tracing::debug!(
                    group_id = %LogHexId::group(&end.registered_room()),
                    peer = %LogHexId::agent(&peer_hex),
                    "TreeKEM catch-up request timed out"
                ),
            }
        });
    }
}

impl EndOnDrop {
    fn registered_room(&self) -> String {
        match &self.registered {
            Registered::Ask(room, _) | Registered::FollowUp(room, _) => room.clone(),
        }
    }
}

/// Ask `peer` for the next page in `room` from `head` (the signed revision
/// and TreeKEM epoch after the page applied), in its own task, unless the
/// same follow-up, to the same peer from the same head, is still in flight.
/// Returns whether it started one.
pub(super) fn spawn_follow_up(
    state: &Arc<AppState>,
    room: &str,
    peer: AgentId,
    head: (u64, u64),
) -> bool {
    let key = (peer, head.0, head.1);
    if !lock(state).follow_ups.insert((room.to_string(), key)) {
        return false;
    }
    #[cfg(test)]
    state
        .named_group_test_recorders
        .follow_ups_started
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let end = EndOnDrop {
        state: Arc::clone(state),
        registered: Registered::FollowUp(room.to_string(), key),
    };
    let room = room.to_string();
    tokio::spawn(async move {
        if tokio::time::timeout(
            ASK_TIMEOUT,
            request_treekem_catchup_page(&end.state, &room, &peer),
        )
        .await
        .is_err()
        {
            tracing::debug!(group_id = %LogHexId::group(&room), "paged TreeKEM catch-up request timed out");
        }
    });
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn peer(byte: u8) -> AgentId {
        AgentId([byte; 32])
    }

    #[test]
    fn one_ask_per_peer_and_head_and_the_room_ends_with_its_last_ask() {
        let mut flights = GapCatchups::default();
        assert_eq!(
            flights.begin_ask("room", (peer(1), 5, 2)),
            Begin::StartsFlight
        );
        assert_eq!(flights.begin_ask("room", (peer(1), 5, 2)), Begin::InFlight);
        assert_eq!(
            flights.begin_ask("room", (peer(1), 6, 3)),
            Begin::Joins,
            "a moved head asks again"
        );
        assert_eq!(flights.begin_ask("room", (peer(2), 5, 2)), Begin::Joins);
        assert_eq!(
            flights.begin_ask("other", (peer(1), 5, 2)),
            Begin::StartsFlight
        );
        flights.end_ask("room", &(peer(1), 5, 2));
        flights.end_ask("room", &(peer(1), 6, 3));
        assert!(flights.in_flight("room"));
        flights.end_ask("room", &(peer(2), 5, 2));
        assert!(!flights.in_flight("room"));
        assert!(flights.in_flight("other"));
    }
}

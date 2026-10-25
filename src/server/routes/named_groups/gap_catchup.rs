//! A gap catch-up never holds up the apply that found the gap (survivor
//! re-key A12; see `docs/adr/transient/T-catchup-off-the-apply-path.md`).
//!
//! An apply that finds a TreeKEM membership event ahead of this member's
//! head parks the event in `treekem_pending_events` and asks peers for the
//! commits in between. The asks used to run inside the apply, under the
//! room's membership lock, one peer after another. A peer that does not
//! answer costs a whole direct-message timeout (about 24 s), so one event
//! could hold the room for minutes. Now:
//!
//! - the event is parked first, as before, and the apply returns;
//! - one flight per room sends the asks, in its own task, to every peer of a
//!   batch at once;
//! - an event that needs a catch-up while its room's flight runs adds its
//!   peers to that flight, and the flight asks each peer once;
//! - the parked events replay when a page arrives
//!   (`handle_treekem_catchup_response`), as before, in commit order.

use super::{
    request_treekem_catchup_for_gap, treekem_membership_event_frontier, AppState,
    NamedGroupMetadataEvent,
};
use crate::identity::AgentId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError};

/// One room's flight.
#[derive(Debug, Default)]
struct Flight {
    /// Asks not yet sent: the peer, and the predecessor hash its event named.
    pending: Vec<(AgentId, Option<String>)>,
    /// Every peer this flight has asked or will ask.
    asked: HashSet<AgentId>,
}

/// The rooms with a gap catch-up in flight, by `named_groups` key.
#[derive(Debug, Default)]
pub(in crate::server) struct GapCatchups {
    rooms: HashMap<String, Flight>,
}

impl GapCatchups {
    /// Add `peers` to `room`'s flight. Returns whether this starts the
    /// flight, so the caller runs it.
    fn join(&mut self, room: &str, peers: Vec<AgentId>, missing: Option<&String>) -> bool {
        let starts = !self.rooms.contains_key(room);
        let flight = self.rooms.entry(room.to_string()).or_default();
        for peer in peers {
            if flight.asked.insert(peer) {
                flight.pending.push((peer, missing.cloned()));
            }
        }
        if starts && flight.pending.is_empty() {
            self.rooms.remove(room);
            return false;
        }
        starts
    }

    /// The flight's next asks. `None` ends the flight.
    fn next(&mut self, room: &str) -> Option<Vec<(AgentId, Option<String>)>> {
        let flight = self.rooms.get_mut(room)?;
        if flight.pending.is_empty() {
            self.rooms.remove(room);
            return None;
        }
        Some(std::mem::take(&mut flight.pending))
    }

    /// Whether `room` has a flight (tests).
    #[cfg(test)]
    pub(in crate::server) fn in_flight(&self, room: &str) -> bool {
        self.rooms.contains_key(room)
    }
}

/// Ends a flight whose task stopped early (a panic), so the room's next
/// gap starts a new one.
struct EndOnDrop {
    state: Arc<AppState>,
    room: String,
    armed: bool,
}

impl EndOnDrop {
    /// The task ended on its own and removed its entry.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.state
                .treekem_gap_catchups
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .rooms
                .remove(&self.room);
        }
    }
}

/// Ask `peers` for the commits before `event` in `room`, off the caller's
/// path: join the room's flight, or start one.
pub(super) fn spawn(
    state: &Arc<AppState>,
    room: &str,
    event: &NamedGroupMetadataEvent,
    peers: Vec<AgentId>,
) {
    let Some(frontier) = treekem_membership_event_frontier(event) else {
        return;
    };
    let starts = state
        .treekem_gap_catchups
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join(room, peers, frontier.commit.prev_state_hash.as_ref());
    if !starts {
        return;
    }
    #[cfg(test)]
    state
        .named_group_test_recorders
        .gap_catchup_flights
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut end = EndOnDrop {
        state: Arc::clone(state),
        room: room.to_string(),
        armed: true,
    };
    tokio::spawn(async move {
        loop {
            let asks = end
                .state
                .treekem_gap_catchups
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .next(&end.room);
            let Some(asks) = asks else {
                end.disarm();
                return;
            };
            request_treekem_catchup_for_gap(&end.state, &end.room, asks).await;
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn peer(byte: u8) -> AgentId {
        AgentId([byte; 32])
    }

    #[test]
    fn a_second_gap_joins_the_flight_and_each_peer_is_asked_once() {
        let mut flights = GapCatchups::default();
        let hash = "h".to_string();
        assert!(flights.join("room", vec![peer(1), peer(2)], Some(&hash)));
        assert!(!flights.join("room", vec![peer(2), peer(3)], None));
        let asks = flights.next("room").expect("the first batch");
        let asked: Vec<AgentId> = asks.iter().map(|(peer, _)| *peer).collect();
        assert_eq!(asked, vec![peer(1), peer(2), peer(3)]);
        assert!(!flights.join("room", vec![peer(1)], None), "already asked");
        assert!(flights.next("room").is_none(), "nothing left ends it");
        assert!(!flights.in_flight("room"));
        assert!(flights.join("room", vec![peer(1)], None), "a new flight");
    }

    #[test]
    fn a_gap_with_no_peer_starts_no_flight() {
        let mut flights = GapCatchups::default();
        assert!(!flights.join("room", Vec::new(), None));
        assert!(!flights.in_flight("room"));
    }
}

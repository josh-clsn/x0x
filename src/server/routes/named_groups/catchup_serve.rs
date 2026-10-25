//! The catch-up listener answers requests side by side (survivor re-key
//! A12; see `docs/adr/transient/T-catchup-off-the-apply-path.md`).
//!
//! An answer ends in a direct send, and a requester that went away costs
//! that send its whole timeout (about 24 s). One listener task used to
//! answer every request in turn, so one such requester held up every other
//! member's catch-up, and the listener's queue, which drops its oldest
//! messages when it is full, filled behind it. Now the listener hands each
//! message to [`on_direct_message`]: a request goes to [`dispatch`], which
//! never waits, and a response is applied there, in arrival order, with its
//! follow-up ask sent in its own task.
//!
//! - **Only a proven requester gets a queue.** A request over a transport
//!   that verified its sender is queued under that sender. Any other request
//!   must carry its requester's signature (the A5 page-request or the #398
//!   member-keyed one), checked here, and is queued under the requester it
//!   proves. A request that proves no one is dropped here; the answer would
//!   refuse it anyway. So a peer that claims another member's id cannot
//!   touch that member's queue.
//! - at most [`SERVE_SLOTS`] answers run at once;
//! - a requester has at most one answer running, and at most one request
//!   waiting per (room, kind): a page, a head challenge, or a member-keyed
//!   fetch for one member. A newer request of the same kind for the same
//!   room takes the waiting one's place. A requester has at most
//!   [`PER_PEER_QUEUE`] waiting; past that, a request for a further room is
//!   dropped, never another room's only request;
//! - slots are handed out in the order requesters asked for one (tokio's
//!   semaphore is fair), so a requester waits behind at most the answers
//!   already waiting;
//! - at most [`MAX_WAITING_PEERS`] requesters and [`MAX_WAITING_BYTES`] of
//!   requests wait at once; past either, a request that needs a new place is
//!   dropped, as an overfull listener queue dropped it before;
//! - the answer is `handle_treekem_catchup_request`, unchanged.
//!
//! **Why four slots.** An answer holds one page (one direct message, under
//! `x0x::dm::MAX_PAYLOAD_BYTES`), may sign one head proof, and holds one
//! send for up to its timeout. Four lets four requesters that went away
//! time out together while a fifth waits at most one send timeout, where it
//! used to wait for every request queued ahead of it. It keeps a phone's
//! catch-up work to a few pages in memory and a few signatures at once, and
//! it matches the re-key obligation worker's sends in flight
//! (`rekey_obligations::MAX_IN_FLIGHT`).

use super::{
    handle_treekem_catchup_request, handle_treekem_catchup_response, member_keyed_request_signed,
    parse_agent_id_hex, signed_catchup, AppState, TreeKemCatchupRequest, TreeKemCatchupResponse,
};
use crate::direct::DirectMessage;
use crate::identity::AgentId;
use crate::logging::LogHexId;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::Semaphore;

/// Answers running at once.
pub(in crate::server) const SERVE_SLOTS: usize = 4;
/// Requests one requester may have waiting (each for a different room or
/// kind).
pub(in crate::server) const PER_PEER_QUEUE: usize = 8;
/// Requesters that may have requests waiting at once.
pub(in crate::server) const MAX_WAITING_PEERS: usize = 256;
/// Bytes of requests (as received) that may wait at once.
pub(in crate::server) const MAX_WAITING_BYTES: usize = 8 * 1024 * 1024;

/// What a waiting request is for: its room, and a page, a head challenge or
/// a member-keyed fetch for one member.
type Slot = (String, String);

#[derive(Debug)]
struct Waiting {
    slot: Slot,
    /// The transport's sender, which the answer checks again.
    sender: AgentId,
    verified: bool,
    request: TreeKemCatchupRequest,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Queues {
    /// Waiting requests by proven requester. A requester has an entry while
    /// its task runs.
    peers: HashMap<AgentId, VecDeque<Waiting>>,
    bytes: usize,
}

/// The listener's answer slots and each requester's waiting requests.
#[derive(Debug)]
pub(in crate::server) struct CatchupServe {
    slots: Arc<Semaphore>,
    queues: Mutex<Queues>,
}

impl Default for CatchupServe {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(SERVE_SLOTS)),
            queues: Mutex::default(),
        }
    }
}

/// What [`dispatch`] did with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum Dispatched {
    /// The requester's task starts with it.
    Started,
    /// It waits behind the requester's running answer.
    Queued,
    /// It took the place of the requester's waiting request of the same kind
    /// for the same room.
    Replaced,
    /// It proves no requester, or there is no room for it.
    Dropped,
}

fn slot_of(request: &TreeKemCatchupRequest) -> Slot {
    let kind = match (&request.target_member_id, &request.head_challenge) {
        (Some(target), _) => format!("member:{target}"),
        (None, Some(_)) => "challenge".to_string(),
        (None, None) => "page".to_string(),
    };
    (request.group_id.clone(), kind)
}

/// The requester `request` proves: the transport-verified sender, or the
/// requester whose signature it carries.
fn proven_requester(
    sender: AgentId,
    verified: bool,
    request: &TreeKemCatchupRequest,
) -> Option<AgentId> {
    if verified {
        return Some(sender);
    }
    let signed = if request.target_member_id.is_some() {
        member_keyed_request_signed(request)
    } else {
        signed_catchup::page_request_signed(request)
    };
    signed
        .then(|| parse_agent_id_hex(&request.requester_agent_id).ok())
        .flatten()
}

impl CatchupServe {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn admit(&self, requester: AgentId, waiting: Waiting) -> Dispatched {
        let mut queues = self.lock();
        let Queues { peers, bytes } = &mut *queues;
        if let Some(queue) = peers.get_mut(&requester) {
            if let Some(held) = queue.iter_mut().find(|held| held.slot == waiting.slot) {
                if (*bytes - held.bytes).saturating_add(waiting.bytes) > MAX_WAITING_BYTES {
                    return Dispatched::Dropped;
                }
                *bytes = *bytes - held.bytes + waiting.bytes;
                *held = waiting;
                return Dispatched::Replaced;
            }
            if queue.len() >= PER_PEER_QUEUE
                || bytes.saturating_add(waiting.bytes) > MAX_WAITING_BYTES
            {
                return Dispatched::Dropped;
            }
            *bytes += waiting.bytes;
            queue.push_back(waiting);
            return Dispatched::Queued;
        }
        if peers.len() >= MAX_WAITING_PEERS
            || bytes.saturating_add(waiting.bytes) > MAX_WAITING_BYTES
        {
            return Dispatched::Dropped;
        }
        *bytes += waiting.bytes;
        peers.insert(requester, VecDeque::from([waiting]));
        Dispatched::Started
    }

    /// The requester's next waiting request. `None` ends its task.
    fn next(&self, requester: &AgentId) -> Option<Waiting> {
        let mut queues = self.lock();
        let next = queues
            .peers
            .get_mut(requester)
            .and_then(VecDeque::pop_front);
        match &next {
            Some(waiting) => queues.bytes -= waiting.bytes,
            None => {
                queues.peers.remove(requester);
            }
        }
        next
    }

    fn forget(&self, requester: &AgentId) {
        let mut queues = self.lock();
        if let Some(queue) = queues.peers.remove(requester) {
            let freed: usize = queue.iter().map(|waiting| waiting.bytes).sum();
            queues.bytes -= freed;
        }
    }

    /// Answer slots free now (tests).
    #[cfg(test)]
    pub(in crate::server) fn free_slots(&self) -> usize {
        self.slots.available_permits()
    }

    /// The (room, kind) of each request `requester` has waiting (tests).
    #[cfg(test)]
    pub(in crate::server) fn waiting(&self, requester: &AgentId) -> Option<Vec<Slot>> {
        self.lock()
            .peers
            .get(requester)
            .map(|queue| queue.iter().map(|waiting| waiting.slot.clone()).collect())
    }
}

/// Ends a requester's entry when its task stops early (a panic).
struct EndOnDrop {
    state: Arc<AppState>,
    requester: AgentId,
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
            self.state.treekem_catchup_serve.forget(&self.requester);
        }
    }
}

/// Hand a catch-up request to its proven requester's task, starting the
/// task when none runs. `bytes` is the request's size as received. Never
/// waits.
pub(in crate::server) fn dispatch(
    state: &Arc<AppState>,
    sender: AgentId,
    verified: bool,
    request: TreeKemCatchupRequest,
    bytes: usize,
) -> Dispatched {
    let Some(requester) = proven_requester(sender, verified, &request) else {
        tracing::debug!(
            claimed_sender = %LogHexId::agent(&hex::encode(sender.as_bytes())),
            "TreeKEM catch-up request dropped: it proves no requester"
        );
        return Dispatched::Dropped;
    };
    let waiting = Waiting {
        slot: slot_of(&request),
        sender,
        verified,
        request,
        bytes,
    };
    let dispatched = state.treekem_catchup_serve.admit(requester, waiting);
    match dispatched {
        Dispatched::Started => {
            let mut end = EndOnDrop {
                state: Arc::clone(state),
                requester,
                armed: true,
            };
            tokio::spawn(async move {
                loop {
                    let Some(waiting) = end.state.treekem_catchup_serve.next(&end.requester) else {
                        end.disarm();
                        return;
                    };
                    let slots = Arc::clone(&end.state.treekem_catchup_serve.slots);
                    let Ok(_slot) = slots.acquire_owned().await else {
                        return;
                    };
                    handle_treekem_catchup_request(
                        &end.state,
                        &waiting.sender,
                        waiting.verified,
                        waiting.request,
                    )
                    .await;
                }
            });
        }
        Dispatched::Queued | Dispatched::Replaced => {}
        Dispatched::Dropped => {
            tracing::debug!(
                requester = %LogHexId::agent(&hex::encode(requester.as_bytes())),
                "TreeKEM catch-up request dropped: no room for it"
            );
        }
    }
    dispatched
}

/// The catch-up listener's handling of one direct message: a request is
/// dispatched, a response applied. Neither waits on the network.
pub(in crate::server) async fn on_direct_message(state: &Arc<AppState>, msg: &DirectMessage) {
    if let Ok(request) = serde_json::from_slice::<TreeKemCatchupRequest>(&msg.payload) {
        if request.message_type == "treekem_catchup_request" {
            dispatch(state, msg.sender, msg.verified, request, msg.payload.len());
        }
        return;
    }
    if let Ok(response) = serde_json::from_slice::<TreeKemCatchupResponse>(&msg.payload) {
        if response.message_type == "treekem_catchup_response" {
            handle_treekem_catchup_response(state, &msg.sender, msg.verified, response).await;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn request(room: &str, from_revision: u64) -> TreeKemCatchupRequest {
        TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: room.to_string(),
            requester_agent_id: String::new(),
            from_revision,
            from_treekem_epoch: 0,
            current_state_hash: String::new(),
            missing_prev_state_hash: None,
            target_member_id: None,
            limit: 1,
            signed_by: None,
            head_challenge: None,
        }
    }

    fn waiting(room: &str, from_revision: u64, bytes: usize) -> Waiting {
        let request = request(room, from_revision);
        Waiting {
            slot: slot_of(&request),
            sender: AgentId([1; 32]),
            verified: true,
            request,
            bytes,
        }
    }

    #[test]
    fn a_newer_request_for_a_room_takes_the_waiting_ones_place_and_other_rooms_stay() {
        let serve = CatchupServe::default();
        let peer = AgentId([1; 32]);
        assert_eq!(serve.admit(peer, waiting("a", 0, 10)), Dispatched::Started);
        assert_eq!(serve.admit(peer, waiting("b", 1, 10)), Dispatched::Queued);
        assert_eq!(serve.admit(peer, waiting("c", 2, 10)), Dispatched::Queued);
        for n in 3..20 {
            assert_eq!(serve.admit(peer, waiting("c", n, 10)), Dispatched::Replaced);
        }
        for room in ["d", "e", "f", "g", "h"] {
            assert_eq!(serve.admit(peer, waiting(room, 0, 10)), Dispatched::Queued);
        }
        assert_eq!(
            serve.admit(peer, waiting("i", 0, 10)),
            Dispatched::Dropped,
            "a ninth room is refused; no other room's request is pushed out"
        );
        let mut served = Vec::new();
        while let Some(next) = serve.next(&peer) {
            served.push((next.request.group_id, next.request.from_revision));
        }
        assert_eq!(
            &served[..3],
            &[("a".into(), 0), ("b".into(), 1), ("c".into(), 19)]
        );
        assert_eq!(served.len(), 8);
        assert_eq!(serve.lock().bytes, 0, "every byte is given back");
    }

    #[test]
    fn requesters_and_bytes_past_their_caps_are_dropped() {
        let serve = CatchupServe::default();
        for n in 0..MAX_WAITING_PEERS {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            assert_eq!(
                serve.admit(AgentId(id), waiting("a", 0, 1)),
                Dispatched::Started
            );
        }
        assert_eq!(
            serve.admit(AgentId([0xff; 32]), waiting("a", 0, 1)),
            Dispatched::Dropped
        );

        let serve = CatchupServe::default();
        let peer = AgentId([2; 32]);
        assert_eq!(
            serve.admit(peer, waiting("a", 0, MAX_WAITING_BYTES)),
            Dispatched::Started
        );
        assert_eq!(serve.admit(peer, waiting("b", 0, 1)), Dispatched::Dropped);
        assert_eq!(
            serve.admit(AgentId([3; 32]), waiting("a", 0, 1)),
            Dispatched::Dropped
        );
        serve.forget(&peer);
        assert_eq!(serve.lock().bytes, 0);
    }

    #[test]
    fn an_unverified_unsigned_request_proves_no_requester() {
        let claimed = AgentId([4; 32]);
        let mut unsigned = request("a", 0);
        unsigned.requester_agent_id = hex::encode(claimed.as_bytes());
        assert_eq!(proven_requester(claimed, false, &unsigned), None);
        assert_eq!(proven_requester(claimed, true, &unsigned), Some(claimed));
    }
}

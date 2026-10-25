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
//! - **Unverified requests are rate-limited per machine before the check**
//!   (fix round 2, N-3): each QUIC-authenticated machine may have
//!   [`UNVERIFIED_BURST`] signatures checked at once, refilling at
//!   [`UNVERIFIED_PER_SEC`] a second, so a flood cannot spend this daemon's
//!   CPU on signature checks.
//! - **The requester must be on the room's roster** (N-4): an active member,
//!   or a joiner the room's cached add names, as the answer requires. So a
//!   self-made identity cannot take waiting space.
//! - **A waiting request is replaced only by one at least as fresh** (N-2):
//!   a page from the same or a later (epoch, revision), a challenge with the
//!   same or a later counter. A replayed older request is dropped.
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
//! - the answer is `handle_treekem_catchup_request`, unchanged, except that
//!   its send is handed off ([`send_answer`], survivor re-key A14): the answer
//!   frees its slot, and the requester's next request is answered, while the
//!   send waits on its acknowledgement. At most [`ANSWER_SENDS`] sends, and
//!   [`ANSWER_SENDS_PER_PEER`] to one requester, wait at once; past either,
//!   the answer sends inline, as before.
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
    handle_treekem_catchup_request, handle_treekem_catchup_response, head_proof,
    member_keyed_request_signed, parse_agent_id_hex, signed_catchup, AppState,
    NamedGroupMetadataEvent, TreeKemCatchupRequest, TreeKemCatchupResponse,
};
use crate::direct::DirectMessage;
use crate::identity::{AgentId, MachineId};
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
/// Answer sends waiting on their acknowledgement at once (A14).
pub(in crate::server) const ANSWER_SENDS: usize = 32;
/// Answer sends to one requester waiting at once (A14).
pub(in crate::server) const ANSWER_SENDS_PER_PEER: usize = 8;
/// Unverified requests one machine may have checked at once.
pub(in crate::server) const UNVERIFIED_BURST: f64 = 16.0;
/// How many more unverified requests a machine may have checked each second.
pub(in crate::server) const UNVERIFIED_PER_SEC: f64 = 8.0;
/// Machines the rate limiter remembers at most.
const RATE_TABLE_CAP: usize = 4096;

/// One machine's allowance for unverified requests.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: tokio::time::Instant,
}

impl Bucket {
    fn refilled(self, now: tokio::time::Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        (self.tokens + elapsed * UNVERIFIED_PER_SEC).min(UNVERIFIED_BURST)
    }
}

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
    rates: Mutex<HashMap<MachineId, Bucket>>,
    sends: Arc<Semaphore>,
    sends_per_peer: Mutex<HashMap<AgentId, usize>>,
}

impl Default for CatchupServe {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(SERVE_SLOTS)),
            queues: Mutex::default(),
            rates: Mutex::default(),
            sends: Arc::new(Semaphore::new(ANSWER_SENDS)),
            sends_per_peer: Mutex::default(),
        }
    }
}

/// A handed-off answer send's place in [`CatchupServe`]'s send bounds.
struct SendTicket {
    state: Arc<AppState>,
    to: AgentId,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for SendTicket {
    fn drop(&mut self) {
        let mut per_peer = self
            .state
            .treekem_catchup_serve
            .sends_per_peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = per_peer.get_mut(&self.to) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_peer.remove(&self.to);
            }
        }
    }
}

fn reserve_send(state: &Arc<AppState>, to: AgentId) -> Option<SendTicket> {
    let serve = &state.treekem_catchup_serve;
    let mut per_peer = serve
        .sends_per_peer
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let count = per_peer.entry(to).or_insert(0);
    if *count >= ANSWER_SENDS_PER_PEER {
        return None;
    }
    let permit = Arc::clone(&serve.sends).try_acquire_owned().ok()?;
    *count += 1;
    Some(SendTicket {
        state: Arc::clone(state),
        to,
        _permit: permit,
    })
}

async fn deliver_answer(
    state: &AppState,
    to: AgentId,
    payload: Vec<u8>,
    group_id: &str,
    what: &str,
) {
    #[cfg(test)]
    {
        state
            .named_group_test_recorders
            .answer_sends_started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let hold = state
            .named_group_test_recorders
            .answer_send_hold
            .lock()
            .ok()
            .and_then(|hold| hold.clone());
        if let Some(hold) = hold {
            let _released = hold.acquire().await;
            return;
        }
    }
    if let Err(e) = state
        .agent
        .send_direct_with_config(&to, payload, super::named_group_direct_delivery_config())
        .await
    {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            requester = %LogHexId::agent(&hex::encode(to.as_bytes())),
            what,
            "failed to send a TreeKEM catch-up answer: {e}"
        );
    }
}

/// Send an answer to `to` in its own task, so the answer's slot is free
/// while the send waits on its acknowledgement (survivor re-key A14). Past
/// [`ANSWER_SENDS`] or [`ANSWER_SENDS_PER_PEER`], it sends here, as before.
pub(super) async fn send_answer(
    state: &Arc<AppState>,
    to: AgentId,
    payload: Vec<u8>,
    group_id: &str,
    what: &'static str,
) {
    match reserve_send(state, to) {
        Some(ticket) => {
            let group_id = group_id.to_string();
            tokio::spawn(async move {
                deliver_answer(&ticket.state, to, payload, &group_id, what).await;
                drop(ticket);
            });
        }
        None => deliver_answer(state, to, payload, group_id, what).await,
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

/// Whether `incoming` may take `held`'s waiting place: it is at least as
/// fresh. A member-keyed fetch replays identically, so it always may.
fn at_least_as_fresh(incoming: &TreeKemCatchupRequest, held: &TreeKemCatchupRequest) -> bool {
    if incoming.target_member_id.is_some() {
        return true;
    }
    let order = |request: &TreeKemCatchupRequest| {
        (
            request
                .head_challenge
                .as_deref()
                .and_then(head_proof::challenge_counter)
                .unwrap_or(0),
            request.from_treekem_epoch,
            request.from_revision,
        )
    };
    order(incoming) >= order(held)
}

/// Whether `requester_hex` may ask about `request`'s room here, as the answer
/// decides it: an active member, or a joiner with no roster entry that the
/// room's cached add names. A lock another task holds right now leaves the
/// decision to the answer.
fn may_ask(state: &AppState, request: &TreeKemCatchupRequest, requester_hex: &str) -> bool {
    let Ok(groups) = state.named_groups.try_read() else {
        return true;
    };
    let Some((key, info)) = groups.get_key_value(&request.group_id).or_else(|| {
        groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == request.group_id)
    }) else {
        return false;
    };
    if info.has_active_member(requester_hex) {
        return true;
    }
    if info.members_v2.contains_key(requester_hex) {
        return false;
    }
    let Ok(logs) = state.treekem_event_log.try_read() else {
        return true;
    };
    [
        request.group_id.as_str(),
        key.as_str(),
        info.stable_group_id(),
    ]
    .iter()
    .any(|alias| {
        logs.get(*alias).is_some_and(|events| {
            events.iter().any(|event| match event {
                NamedGroupMetadataEvent::MemberAdded { agent_id, .. } => {
                    agent_id.eq_ignore_ascii_case(requester_hex)
                }
                NamedGroupMetadataEvent::JoinRequestApproved {
                    requester_agent_id, ..
                } => requester_agent_id.eq_ignore_ascii_case(requester_hex),
                _ => false,
            })
        })
    })
}

impl CatchupServe {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take one unverified request's check from `machine`'s allowance.
    fn take_unverified(&self, machine: MachineId, now: tokio::time::Instant) -> bool {
        let mut rates = self.rates.lock().unwrap_or_else(PoisonError::into_inner);
        if !rates.contains_key(&machine) && rates.len() >= RATE_TABLE_CAP {
            rates.retain(|_, bucket| bucket.refilled(now) < UNVERIFIED_BURST);
            if rates.len() >= RATE_TABLE_CAP {
                return false;
            }
        }
        let bucket = rates.entry(machine).or_insert(Bucket {
            tokens: UNVERIFIED_BURST,
            at: now,
        });
        let tokens = bucket.refilled(now);
        if tokens < 1.0 {
            bucket.tokens = tokens;
            bucket.at = now;
            return false;
        }
        bucket.tokens = tokens - 1.0;
        bucket.at = now;
        true
    }

    fn admit(&self, requester: AgentId, waiting: Waiting) -> Dispatched {
        let mut queues = self.lock();
        let Queues { peers, bytes } = &mut *queues;
        if let Some(queue) = peers.get_mut(&requester) {
            if let Some(held) = queue.iter_mut().find(|held| held.slot == waiting.slot) {
                if !at_least_as_fresh(&waiting.request, &held.request)
                    || (*bytes - held.bytes).saturating_add(waiting.bytes) > MAX_WAITING_BYTES
                {
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

    /// Whether no handed-off answer send is outstanding (tests).
    #[cfg(test)]
    pub(in crate::server) fn sends_idle(&self) -> bool {
        self.sends.available_permits() == ANSWER_SENDS
    }

    /// Answer slots free now (tests).
    #[cfg(test)]
    pub(in crate::server) fn free_slots(&self) -> usize {
        self.slots.available_permits()
    }

    /// The room, kind and revision of each request `requester` has waiting
    /// (tests).
    #[cfg(test)]
    pub(in crate::server) fn waiting(
        &self,
        requester: &AgentId,
    ) -> Option<Vec<(String, String, u64)>> {
        self.lock().peers.get(requester).map(|queue| {
            queue
                .iter()
                .map(|waiting| {
                    (
                        waiting.slot.0.clone(),
                        waiting.slot.1.clone(),
                        waiting.request.from_revision,
                    )
                })
                .collect()
        })
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
/// task when none runs. `machine` is the QUIC-authenticated machine it came
/// from, and `bytes` its size as received. Never waits.
pub(in crate::server) fn dispatch(
    state: &Arc<AppState>,
    sender: AgentId,
    machine: MachineId,
    verified: bool,
    request: TreeKemCatchupRequest,
    bytes: usize,
) -> Dispatched {
    if !verified
        && !state
            .treekem_catchup_serve
            .take_unverified(machine, tokio::time::Instant::now())
    {
        tracing::debug!(
            claimed_sender = %LogHexId::agent(&hex::encode(sender.as_bytes())),
            "TreeKEM catch-up request dropped: its machine is over the unverified-request rate"
        );
        return Dispatched::Dropped;
    }
    #[cfg(test)]
    if !verified {
        state
            .named_group_test_recorders
            .catchup_signature_checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let Some(requester) = proven_requester(sender, verified, &request) else {
        tracing::debug!(
            claimed_sender = %LogHexId::agent(&hex::encode(sender.as_bytes())),
            "TreeKEM catch-up request dropped: it proves no requester"
        );
        return Dispatched::Dropped;
    };
    if !may_ask(state, &request, &hex::encode(requester.as_bytes())) {
        tracing::debug!(
            requester = %LogHexId::agent(&hex::encode(requester.as_bytes())),
            "TreeKEM catch-up request dropped: the requester is not on the room's roster"
        );
        return Dispatched::Dropped;
    }
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
            dispatch(
                state,
                msg.sender,
                msg.machine_id,
                msg.verified,
                request,
                msg.payload.len(),
            );
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
    fn an_older_request_never_takes_a_fresher_ones_place() {
        let serve = CatchupServe::default();
        let peer = AgentId([5; 32]);
        assert_eq!(serve.admit(peer, waiting("a", 0, 10)), Dispatched::Started);
        assert_eq!(serve.admit(peer, waiting("b", 7, 10)), Dispatched::Queued);
        assert_eq!(serve.admit(peer, waiting("b", 3, 10)), Dispatched::Dropped);
        assert_eq!(serve.admit(peer, waiting("b", 7, 10)), Dispatched::Replaced);
        assert_eq!(serve.admit(peer, waiting("b", 9, 10)), Dispatched::Replaced);
        let mut challenge = request("b", 9);
        challenge.head_challenge = Some(head_proof::challenge_nonce(4));
        let mut older = challenge.clone();
        older.head_challenge = Some(head_proof::challenge_nonce(3));
        older.from_revision = 20;
        assert!(at_least_as_fresh(&challenge, &older));
        assert!(
            !at_least_as_fresh(&older, &challenge),
            "the counter decides first"
        );
    }

    #[test]
    fn a_machine_over_its_unverified_allowance_is_refused_until_it_refills() {
        let serve = CatchupServe::default();
        let machine = MachineId([6; 32]);
        let now = tokio::time::Instant::now();
        for _ in 0..16 {
            assert!(serve.take_unverified(machine, now));
        }
        assert!(!serve.take_unverified(machine, now));
        assert!(
            serve.take_unverified(MachineId([7; 32]), now),
            "another machine"
        );
        let later = now + std::time::Duration::from_millis(250);
        assert!(serve.take_unverified(machine, later), "two refilled");
        assert!(serve.take_unverified(machine, later));
        assert!(!serve.take_unverified(machine, later));
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

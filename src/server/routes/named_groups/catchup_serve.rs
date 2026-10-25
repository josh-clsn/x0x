//! The catch-up listener answers requests side by side (survivor re-key
//! A12; see `docs/adr/transient/T-catchup-off-the-apply-path.md`).
//!
//! An answer ends in a direct send, and a requester that went away costs
//! that send its whole timeout (about 24 s). One listener task used to
//! answer every request in turn, so one such requester held up every other
//! member's catch-up, and the listener's queue, which drops its oldest
//! messages when it is full, filled behind it. Now the listener hands each
//! request to [`dispatch`] and reads on:
//!
//! - at most [`SERVE_SLOTS`] answers run at once;
//! - one requester has at most one answer running and at most
//!   [`PER_PEER_QUEUE`] waiting; a newer request pushes out its oldest
//!   waiting one, so a requester that floods holds one slot, never all;
//! - slots are handed out in the order requesters asked for one (tokio's
//!   semaphore is fair), so a requester waits behind at most the answers
//!   already waiting;
//! - at most [`MAX_WAITING_PEERS`] requesters wait at once; past that, a
//!   request from a new requester is dropped, as an overfull listener
//!   queue dropped it before;
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

use super::{handle_treekem_catchup_request, AppState, TreeKemCatchupRequest};
use crate::identity::AgentId;
use crate::logging::LogHexId;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::Semaphore;

/// Answers running at once.
pub(in crate::server) const SERVE_SLOTS: usize = 4;
/// Requests one requester may have waiting.
pub(in crate::server) const PER_PEER_QUEUE: usize = 8;
/// Requesters that may have requests waiting at once.
pub(in crate::server) const MAX_WAITING_PEERS: usize = 256;

/// One waiting request: whether its transport verified the sender, and the
/// request.
type Waiting = (bool, TreeKemCatchupRequest);

/// The listener's answer slots and each requester's waiting requests. A
/// requester has an entry while its task runs.
#[derive(Debug)]
pub(in crate::server) struct CatchupServe {
    slots: Arc<Semaphore>,
    peers: Mutex<HashMap<AgentId, VecDeque<Waiting>>>,
}

impl Default for CatchupServe {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(SERVE_SLOTS)),
            peers: Mutex::default(),
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
    /// Too many requesters wait already.
    Dropped,
}

impl CatchupServe {
    fn admit(&self, sender: AgentId, waiting: Waiting) -> Dispatched {
        let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(queue) = peers.get_mut(&sender) {
            if queue.len() >= PER_PEER_QUEUE {
                queue.pop_front();
            }
            queue.push_back(waiting);
            return Dispatched::Queued;
        }
        if peers.len() >= MAX_WAITING_PEERS {
            return Dispatched::Dropped;
        }
        peers.insert(sender, VecDeque::from([waiting]));
        Dispatched::Started
    }

    /// The requester's next waiting request. `None` ends its task.
    fn next(&self, sender: &AgentId) -> Option<Waiting> {
        let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        let next = peers.get_mut(sender).and_then(VecDeque::pop_front);
        if next.is_none() {
            peers.remove(sender);
        }
        next
    }

    fn forget(&self, sender: &AgentId) {
        self.peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(sender);
    }
}

/// Ends a requester's entry when its task stops early (a panic).
struct EndOnDrop {
    state: Arc<AppState>,
    sender: AgentId,
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
            self.state.treekem_catchup_serve.forget(&self.sender);
        }
    }
}

/// Hand a catch-up request to its requester's task, starting the task when
/// none runs. Never waits.
pub(in crate::server) fn dispatch(
    state: &Arc<AppState>,
    sender: AgentId,
    verified: bool,
    request: TreeKemCatchupRequest,
) -> Dispatched {
    let dispatched = state
        .treekem_catchup_serve
        .admit(sender, (verified, request));
    match dispatched {
        Dispatched::Started => {
            let mut end = EndOnDrop {
                state: Arc::clone(state),
                sender,
                armed: true,
            };
            tokio::spawn(async move {
                loop {
                    let Some((verified, request)) =
                        end.state.treekem_catchup_serve.next(&end.sender)
                    else {
                        end.disarm();
                        return;
                    };
                    let slots = Arc::clone(&end.state.treekem_catchup_serve.slots);
                    let Ok(_slot) = slots.acquire_owned().await else {
                        return;
                    };
                    handle_treekem_catchup_request(&end.state, &end.sender, verified, request)
                        .await;
                }
            });
        }
        Dispatched::Queued => {}
        Dispatched::Dropped => {
            tracing::debug!(
                requester = %LogHexId::agent(&hex::encode(sender.as_bytes())),
                "TreeKEM catch-up request dropped: too many requesters waiting"
            );
        }
    }
    dispatched
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn request(n: u64) -> TreeKemCatchupRequest {
        TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: "g".to_string(),
            requester_agent_id: String::new(),
            from_revision: n,
            from_treekem_epoch: 0,
            current_state_hash: String::new(),
            missing_prev_state_hash: None,
            target_member_id: None,
            limit: 1,
            signed_by: None,
            head_challenge: None,
        }
    }

    #[test]
    fn a_flooding_requester_keeps_only_its_newest_waiting_requests() {
        let serve = CatchupServe::default();
        let flooder = AgentId([1; 32]);
        assert_eq!(
            serve.admit(flooder, (true, request(0))),
            Dispatched::Started
        );
        for n in 1..=20 {
            assert_eq!(serve.admit(flooder, (true, request(n))), Dispatched::Queued);
        }
        let mut waiting = Vec::new();
        while let Some((_, request)) = serve.next(&flooder) {
            waiting.push(request.from_revision);
        }
        let newest: Vec<u64> = (13..=20).collect();
        assert_eq!(waiting, newest);
        assert!(serve.peers.lock().unwrap().is_empty(), "drained ends it");
    }

    #[test]
    fn requesters_past_the_cap_are_dropped() {
        let serve = CatchupServe::default();
        for n in 0..MAX_WAITING_PEERS {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            assert_eq!(
                serve.admit(AgentId(id), (true, request(0))),
                Dispatched::Started
            );
        }
        assert_eq!(
            serve.admit(AgentId([0xff; 32]), (true, request(0))),
            Dispatched::Dropped
        );
    }
}

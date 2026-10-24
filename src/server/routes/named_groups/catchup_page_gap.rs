//! A catch-up page never leaves a member stuck behind a hole (survivor
//! re-key A5, from the A4 review's n-1; see
//! `docs/adr/transient/T-signed-catchup-pages.md`).
//!
//! Every commit must link to the head it is applied on, so a member never
//! applies past a missing commit. What could happen is quieter: a responder
//! whose log does not hold the commit right after the requester's head
//! served a later one, the requester could not use it, and nothing made it
//! ask anyone else. Now:
//!
//! - **A responder serves only a run that starts right after the
//!   requester's head**, at `from_revision + 1`, and stops at the first
//!   hole. When the first event it holds past the head is later than that,
//!   it serves nothing and says so in `log_evicted_through`, the field it
//!   already sets when its log dropped those events.
//! - **A requester asks other members** when a member it can authenticate
//!   reports a hole after its head: a signed (or transport-verified)
//!   `log_evicted_through` past the head, or, over a verified transport, an
//!   older responder's page that carried a commit past the one the head
//!   needs. It asks active members, admins first, at most [`GAP_ASK_PEERS`]
//!   at a time. A member asked about a head is asked about it again only
//!   after a window that doubles each time ([`gap_ask_window`]), so a
//!   member that was away is asked again, and a hole no member can fill
//!   costs a few requests per member, spread out.

use super::{
    commit_bearing_event_frontier, commit_bearing_event_sort_key, parse_agent_id_hex,
    signed_catchup, AppState, NamedGroupMetadataEvent, TREEKEM_CATCHUP_THROTTLE,
};
use crate as x0x;
use crate::identity::AgentId;
use crate::logging::LogHexId;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// The most members one hole makes a requester ask at once.
pub(super) const GAP_ASK_PEERS: usize = 3;

/// The page a responder serves.
pub(super) struct ServedPage {
    pub(super) events: Vec<NamedGroupMetadataEvent>,
    pub(super) truncated: bool,
    /// Set, with no events, when this log cannot serve the commit right
    /// after the requester's head: it holds nothing at or below this
    /// revision that the requester needs.
    pub(super) gap_through: Option<u64>,
}

fn revision_of(event: &NamedGroupMetadataEvent) -> Option<u64> {
    commit_bearing_event_frontier(event).map(|frontier| frontier.revision)
}

/// The page for a requester at `from_revision`, from the events `held`.
/// `evicted_through` is the highest revision this log lost.
///
/// An event at or below the requester's revision is never served, whatever
/// its epoch: a commit applies only at the revision after the head, so the
/// requester could not use it, and it would sort ahead of the one it can.
pub(super) fn serve_page(
    held: Vec<NamedGroupMetadataEvent>,
    from_revision: u64,
    evicted_through: Option<u64>,
    limit: usize,
) -> ServedPage {
    if let Some(through) = evicted_through.filter(|through| from_revision < *through) {
        return ServedPage {
            events: Vec::new(),
            truncated: false,
            gap_through: Some(through),
        };
    }
    let mut events: Vec<NamedGroupMetadataEvent> = held
        .into_iter()
        .filter(|event| revision_of(event).is_some_and(|revision| revision > from_revision))
        .collect();
    events.sort_by_key(commit_bearing_event_sort_key);
    let mut reached = from_revision;
    let mut run = 0;
    for event in &events {
        let revision = revision_of(event).unwrap_or_default();
        if revision > reached.saturating_add(1) {
            break;
        }
        reached = revision;
        run += 1;
    }
    if run == 0 {
        if let Some(first) = events.first().and_then(revision_of) {
            return ServedPage {
                events: Vec::new(),
                truncated: false,
                gap_through: Some(first.saturating_sub(1)),
            };
        }
    }
    let keep = run.min(limit);
    let truncated = events.len() > keep;
    events.truncate(keep);
    ServedPage {
        events,
        truncated,
        gap_through: None,
    }
}

/// Whether a page left this member, now at `head_revision`, behind a hole:
/// the responder said its log does not reach back to the head, or a served
/// commit still sits past the one the head needs.
pub(super) fn page_leaves_gap(
    head_revision: u64,
    served: &[u64],
    gap_through: Option<u64>,
) -> bool {
    let next = head_revision.saturating_add(1);
    gap_through.is_some_and(|through| through > head_revision)
        || served.iter().any(|revision| *revision > next)
}

/// The revisions of the commits a page carries.
pub(super) fn served_revisions(events: &[NamedGroupMetadataEvent]) -> Vec<u64> {
    events.iter().filter_map(revision_of).collect()
}

/// The longest a requester waits before asking a member about the same
/// head again: the window doubles from [`TREEKEM_CATCHUP_THROTTLE`] up to
/// this.
pub(super) const GAP_ASK_MAX_WINDOW: Duration = Duration::from_secs(320);

/// How long after its `attempts`-th ask about one head a member may be
/// asked again.
pub(super) fn gap_ask_window(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(6);
    TREEKEM_CATCHUP_THROTTLE
        .saturating_mul(1 << doublings)
        .min(GAP_ASK_MAX_WINDOW)
}

#[derive(Debug, Clone, Copy)]
struct PeerAsk {
    attempts: u32,
    /// When this member may be asked about the head again.
    next: Instant,
}

#[derive(Debug, Default)]
struct RoomAsks {
    /// The head (revision, epoch) the asks are about.
    head: (u64, u64),
    peers: HashMap<AgentId, PeerAsk>,
}

/// Which members a requester asked about a hole after its head, and when it
/// may ask each again (A5 review I-2). One entry per room and member: a new
/// head starts the room afresh, and a wipe drops it.
#[derive(Debug, Default)]
pub(in crate::server) struct GapAsks {
    rooms: HashMap<String, RoomAsks>,
}

impl GapAsks {
    /// Up to [`GAP_ASK_PEERS`] of `candidates` (in preference order) that
    /// may be asked about `head` at `now`. Each is reserved for one window.
    pub(super) fn choose(
        &mut self,
        room: &str,
        head: (u64, u64),
        candidates: &[AgentId],
        now: Instant,
    ) -> Vec<AgentId> {
        let asks = self.rooms.entry(room.to_string()).or_default();
        if asks.head != head {
            asks.head = head;
            asks.peers.clear();
        }
        asks.peers.retain(|peer, _| candidates.contains(peer));
        let chosen: Vec<AgentId> = candidates
            .iter()
            .filter(|peer| asks.peers.get(peer).is_none_or(|ask| ask.next <= now))
            .take(GAP_ASK_PEERS)
            .copied()
            .collect();
        for peer in &chosen {
            let ask = asks.peers.entry(*peer).or_insert(PeerAsk {
                attempts: 0,
                next: now,
            });
            ask.attempts = ask.attempts.saturating_add(1);
            ask.next = now + gap_ask_window(ask.attempts);
        }
        chosen
    }

    /// The request to `peer` was handed to the transport at `now`: its
    /// window runs from here.
    pub(super) fn sent(&mut self, room: &str, head: (u64, u64), peer: &AgentId, now: Instant) {
        if let Some(ask) = self
            .rooms
            .get_mut(room)
            .filter(|asks| asks.head == head)
            .and_then(|asks| asks.peers.get_mut(peer))
        {
            ask.next = now + gap_ask_window(ask.attempts);
        }
    }

    /// No request went to `peer`: give back its reservation.
    pub(super) fn not_sent(&mut self, room: &str, head: (u64, u64), peer: &AgentId) {
        if let Some(asks) = self.rooms.get_mut(room).filter(|asks| asks.head == head) {
            if let Some(ask) = asks.peers.get_mut(peer) {
                ask.attempts = ask.attempts.saturating_sub(1);
                if ask.attempts == 0 {
                    asks.peers.remove(peer);
                }
            }
        }
    }

    /// Whether no member of `room` is reserved or waiting.
    #[cfg(test)]
    pub(in crate::server) fn is_empty_for(&self, room: &str) -> bool {
        self.rooms
            .get(room)
            .is_none_or(|asks| asks.peers.is_empty())
    }

    /// Forget a room (it was wiped).
    pub(in crate::server) fn wipe(&mut self, room: &str) {
        self.rooms.remove(room);
    }
}

/// Ask other members for the commits after this member's head, in a task
/// of its own so the catch-up listener does not wait on the sends.
pub(super) fn spawn_ask_another_member(state: &Arc<AppState>, group_key: &str) {
    let task_state = Arc::clone(state);
    let group_key = group_key.to_string();
    let mut shutdown = state.shutdown_notify.subscribe();
    if *shutdown.borrow() {
        return;
    }
    tokio::spawn(async move {
        tokio::select! {
            () = ask_another_member(&task_state, &group_key) => {}
            _ = shutdown.wait_for(|stopping| *stopping) => {}
        }
    });
}

async fn ask_another_member(state: &Arc<AppState>, group_key: &str) {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (key, revision, epoch, candidates) = {
        let groups = state.named_groups.read().await;
        let Some((key, info)) = groups.get_key_value(group_key).or_else(|| {
            groups
                .iter()
                .find(|(_, info)| info.stable_group_id() == group_key)
        }) else {
            return;
        };
        if info.withdrawn || !info.has_active_member(&local_hex) {
            return;
        }
        let mut candidates: Vec<(bool, AgentId)> = info
            .active_members()
            .filter(|member| !member.agent_id.eq_ignore_ascii_case(&local_hex))
            .filter_map(|member| {
                parse_agent_id_hex(&member.agent_id)
                    .ok()
                    .map(|peer| (!member.role.at_least(x0x::groups::GroupRole::Admin), peer))
            })
            .collect();
        // Admins first: they sign the commits, so they hold them.
        candidates.sort_by_key(|(not_admin, peer)| (*not_admin, peer.0));
        candidates.dedup_by_key(|(_, peer)| *peer);
        (
            key.clone(),
            info.state_revision,
            info.secret_epoch,
            candidates
                .into_iter()
                .map(|(_, peer)| peer)
                .collect::<Vec<_>>(),
        )
    };
    let head = (revision, epoch);
    let chosen = state
        .treekem_gap_asks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .choose(&key, head, &candidates, Instant::now());
    if chosen.is_empty() {
        tracing::debug!(
            group_id = %LogHexId::group(&key),
            revision,
            "TreeKEM catch-up: every member was asked about this head within its window"
        );
        return;
    }
    tracing::info!(
        group_id = %LogHexId::group(&key),
        revision,
        asking = chosen.len(),
        "TreeKEM catch-up: a member reported a hole after this member's head; asking other members"
    );
    let _sent = futures::future::join_all(chosen.iter().map(|peer| {
        let key = &key;
        async move {
            let Some(request) = signed_catchup::page_request(state, key, None).await else {
                state
                    .treekem_gap_asks
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .not_sent(key, head, peer);
                return;
            };
            if let Err(e) = signed_catchup::send_page_request(state, peer, request).await {
                tracing::debug!(group_id = %LogHexId::group(key), peer = %LogHexId::agent(&hex::encode(peer.as_bytes())), "hole catch-up request failed: {e}");
            }
            state
                .treekem_gap_asks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .sent(key, head, peer, Instant::now());
        }
    }))
    .await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn rename_at(revision: u64) -> NamedGroupMetadataEvent {
        let commit = x0x::groups::GroupStateCommit {
            group_id: "g".to_string(),
            revision,
            prev_state_hash: Some(format!("state-{}", revision.saturating_sub(1))),
            roster_root: String::new(),
            policy_hash: String::new(),
            public_meta_hash: String::new(),
            security_binding: None,
            state_hash: format!("state-{revision}"),
            withdrawn: false,
            committed_by: "ab".repeat(32),
            committed_at: revision,
            signer_public_key: String::new(),
            signature: String::new(),
        };
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "g".to_string(),
            revision,
            actor: "ab".repeat(32),
            name: Some(format!("name-{revision}")),
            description: None,
            commit: Some(commit),
        }
    }

    fn revisions(page: &ServedPage) -> Vec<u64> {
        served_revisions(&page.events)
    }

    #[test]
    fn a_page_starts_right_after_the_head() {
        let page = serve_page(vec![rename_at(7), rename_at(6), rename_at(5)], 5, None, 1);
        assert_eq!(revisions(&page), vec![6]);
        assert!(page.truncated);
        assert_eq!(page.gap_through, None);
    }

    #[test]
    fn a_log_that_starts_past_the_head_serves_nothing_and_says_so() {
        let page = serve_page(vec![rename_at(8), rename_at(9)], 5, None, 1);
        assert!(page.events.is_empty());
        assert!(!page.truncated);
        assert_eq!(page.gap_through, Some(7));
    }

    #[test]
    fn a_page_stops_at_a_hole() {
        let page = serve_page(vec![rename_at(6), rename_at(7), rename_at(9)], 5, None, 8);
        assert_eq!(revisions(&page), vec![6, 7]);
        assert!(page.truncated, "the next page meets the hole and says so");
        let next = serve_page(vec![rename_at(6), rename_at(7), rename_at(9)], 7, None, 8);
        assert!(next.events.is_empty());
        assert_eq!(next.gap_through, Some(8));
    }

    #[test]
    fn a_lost_revision_past_the_head_serves_nothing() {
        let page = serve_page(vec![rename_at(6)], 5, Some(6), 1);
        assert!(page.events.is_empty());
        assert_eq!(page.gap_through, Some(6));
        let past = serve_page(vec![rename_at(7)], 6, Some(6), 1);
        assert_eq!(revisions(&past), vec![7]);
    }

    #[test]
    fn nothing_newer_is_not_a_hole() {
        let page = serve_page(vec![rename_at(4), rename_at(5)], 5, None, 1);
        assert!(page.events.is_empty());
        assert_eq!(page.gap_through, None);
    }

    fn peer(byte: u8) -> AgentId {
        AgentId([byte; 32])
    }

    #[test]
    fn a_member_asked_about_a_hole_is_asked_again_after_a_doubling_window() {
        let mut asks = GapAsks::default();
        let candidates: Vec<AgentId> = (1..=4).map(peer).collect();
        let t0 = Instant::now();
        let first = asks.choose("g", (5, 2), &candidates, t0);
        assert_eq!(first, candidates[..GAP_ASK_PEERS].to_vec());
        for p in &first {
            asks.sent("g", (5, 2), p, t0);
        }
        assert_eq!(
            asks.choose("g", (5, 2), &candidates, t0),
            vec![peer(4)],
            "the next report asks the member not yet asked"
        );
        asks.sent("g", (5, 2), &peer(4), t0);
        let early = t0 + gap_ask_window(1) - Duration::from_millis(1);
        assert!(asks.choose("g", (5, 2), &candidates, early).is_empty());
        let later = t0 + gap_ask_window(1);
        let again = asks.choose("g", (5, 2), &candidates, later);
        assert_eq!(again, candidates[..GAP_ASK_PEERS].to_vec(), "asked again");
        for p in &again {
            asks.sent("g", (5, 2), p, later);
        }
        assert!(
            asks.choose("g", (5, 2), &candidates[..1], later + gap_ask_window(1))
                .is_empty(),
            "the second window is twice as long"
        );
        assert_eq!(
            asks.choose("g", (5, 2), &candidates[..1], later + gap_ask_window(2)),
            vec![peer(1)]
        );
        assert_eq!(
            asks.choose("g", (6, 2), &candidates, later),
            candidates[..GAP_ASK_PEERS].to_vec(),
            "a new head starts afresh"
        );
    }

    #[test]
    fn a_reservation_with_no_request_is_given_back() {
        let mut asks = GapAsks::default();
        let candidates = vec![peer(1)];
        let t0 = Instant::now();
        assert_eq!(asks.choose("g", (1, 1), &candidates, t0), candidates);
        asks.not_sent("g", (1, 1), &peer(1));
        assert!(asks.is_empty_for("g"));
        assert_eq!(asks.choose("g", (1, 1), &candidates, t0), candidates);
        asks.wipe("g");
        assert!(asks.is_empty_for("g"));
    }

    #[test]
    fn the_window_doubles_up_to_its_cap() {
        assert_eq!(gap_ask_window(1), TREEKEM_CATCHUP_THROTTLE);
        assert_eq!(gap_ask_window(2), TREEKEM_CATCHUP_THROTTLE * 2);
        assert_eq!(gap_ask_window(u32::MAX), GAP_ASK_MAX_WINDOW);
    }

    #[test]
    fn a_requester_sees_a_hole_from_the_signal_or_from_the_page() {
        assert!(page_leaves_gap(5, &[], Some(6)));
        assert!(
            !page_leaves_gap(6, &[], Some(6)),
            "the hole is behind the head"
        );
        assert!(page_leaves_gap(5, &[7], None), "an older responder's page");
        assert!(!page_leaves_gap(5, &[6], None), "a refused next commit");
        assert!(!page_leaves_gap(6, &[6], None), "applied");
        assert!(!page_leaves_gap(5, &[], None));
    }
}

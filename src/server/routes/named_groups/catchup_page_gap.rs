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
//! - **A requester asks other members** when a page leaves it behind a
//!   hole: the responder said so, or (an older responder) the page carried
//!   a commit past the one its head needs. It asks the active members it
//!   has not asked about this head, admins first, at most
//!   [`GAP_ASK_PEERS`] at a time and each member once per head, so a hole
//!   no member can fill ends the asking.

use super::{
    commit_bearing_event_frontier, commit_bearing_event_sort_key, parse_agent_id_hex,
    request_treekem_catchup_page, AppState, NamedGroupMetadataEvent,
};
use crate as x0x;
use crate::identity::AgentId;
use crate::logging::LogHexId;
use std::sync::Arc;

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

fn gap_ask_key(group_key: &str, peer: &AgentId, revision: u64, epoch: u64) -> String {
    format!(
        "gap-ask:{group_key}:{}:{revision}:{epoch}",
        hex::encode(peer.as_bytes())
    )
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
    let chosen: Vec<AgentId> = {
        let mut asked = state.treekem_catchup_throttle.write().await;
        let chosen: Vec<AgentId> = candidates
            .into_iter()
            .filter(|peer| !asked.contains_key(&gap_ask_key(&key, peer, revision, epoch)))
            .take(GAP_ASK_PEERS)
            .collect();
        let now = tokio::time::Instant::now();
        for peer in &chosen {
            asked.insert(gap_ask_key(&key, peer, revision, epoch), now);
        }
        chosen
    };
    if chosen.is_empty() {
        tracing::debug!(
            group_id = %LogHexId::group(&key),
            revision,
            "TreeKEM catch-up: every member was asked about this head; waiting for new traffic"
        );
        return;
    }
    tracing::info!(
        group_id = %LogHexId::group(&key),
        revision,
        asking = chosen.len(),
        "TreeKEM catch-up: a page left a hole after this member's head; asking other members"
    );
    let _sent = futures::future::join_all(
        chosen
            .iter()
            .map(|peer| request_treekem_catchup_page(state, &key, peer)),
    )
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

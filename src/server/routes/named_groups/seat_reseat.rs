//! Re-seat a member whose seat can no longer be delivered (survivor re-key
//! A13 fix round 1; see `docs/adr/transient/T-seat-obligation.md`).
//!
//! An unproven seat is delivered from the catch-up log, and its Welcome stays
//! staged while it is owed (`seat_welcome_pin`). When the log no longer
//! reaches back to the seat, or its Welcome is lost, the seat cannot be sent
//! as it was. A Welcome cannot be minted for the current epoch without a
//! commit, because later commits set path secrets on the member's leaf path
//! that only a commit can hand on. So the member is re-seated with commits,
//! the returning-member pattern:
//!
//! - the stale leaf is removed, with the member's KeyPackage on the roster
//!   (derived from its seed, so it is the same KeyPackage);
//! - the member is added again with it, which stages a fresh Welcome, owes
//!   the new seat and pins its Welcome;
//! - the survivors are owed both commits, as for any removal and add;
//! - the removal goes to the survivors only: the member never took its seat,
//!   and a removal it applied would make it depart before the new seat came.
//!
//! At most one re-seat per member and room in [`RESEAT_EVERY`], and only by
//! a daemon that is an admin of the room.

use super::{
    add_treekem_named_group_member, group_membership_lock, now_millis_u64, parse_agent_id_hex,
    rekey_obligations, remove_treekem_named_group_member_with, AddNamedGroupMemberRequest,
    AppState,
};
use crate::logging::LogHexId;
use axum::http::StatusCode;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

/// The least time between two re-seats of one member in one room.
pub(in crate::server) const RESEAT_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How a re-seat ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) enum Reseat {
    Done,
    /// Within [`RESEAT_EVERY`] of the member's last re-seat.
    TooSoon,
    /// The member is not active, has no KeyPackage on the roster, or this
    /// daemon is not an admin of the room.
    NotPossible(&'static str),
    Failed(String),
}

/// Take `member_hex`'s re-seat allowance in `group_key`, if it has one.
fn take_allowance(state: &AppState, group_key: &str, member_hex: &str, now_ms: u64) -> bool {
    let mut last = state
        .seat_reseats
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let key = (group_key.to_string(), member_hex.to_ascii_lowercase());
    let every = u64::try_from(RESEAT_EVERY.as_millis()).unwrap_or(u64::MAX);
    if last
        .get(&key)
        .is_some_and(|at| now_ms.saturating_sub(*at) < every)
    {
        return false;
    }
    last.insert(key, now_ms);
    true
}

/// Re-seat `member_hex` in `group_key`. The caller holds the room's
/// membership lock.
pub(super) async fn reseat_locked(
    state: &Arc<AppState>,
    group_key: &str,
    member_hex: &str,
) -> Reseat {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (package, display_name) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_key) else {
            return Reseat::NotPossible("room_unknown");
        };
        if !info
            .caller_role(&local_hex)
            .is_some_and(|role| role.at_least(crate::groups::GroupRole::Admin))
        {
            return Reseat::NotPossible("not_an_admin");
        }
        if !info.has_active_member(member_hex) {
            return Reseat::NotPossible("member_not_active");
        }
        let Some(member) = info.members_v2.get(member_hex) else {
            return Reseat::NotPossible("member_not_active");
        };
        let Some(package) = member.treekem_key_package_b64.clone() else {
            return Reseat::NotPossible("no_key_package");
        };
        (package, member.display_name.clone())
    };
    let Ok(member_id) = parse_agent_id_hex(member_hex) else {
        return Reseat::NotPossible("bad_member_id");
    };
    if !take_allowance(state, group_key, member_hex, now_millis_u64()) {
        #[cfg(test)]
        state
            .named_group_test_recorders
            .reseats_too_soon
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        return Reseat::TooSoon;
    }
    let (status, body) = remove_treekem_named_group_member_with(
        Arc::clone(state),
        group_key.to_string(),
        member_hex.to_string(),
        local_hex,
        false,
    )
    .await;
    if status != StatusCode::OK {
        return Reseat::Failed(format!("removal: {}", body.0));
    }
    rekey_obligations::forget(state, group_key, member_hex).await;
    let (status, body) = Box::pin(add_treekem_named_group_member(
        Arc::clone(state),
        group_key.to_string(),
        member_id,
        AddNamedGroupMemberRequest {
            agent_id: member_hex.to_string(),
            display_name,
            treekem_key_package_b64: Some(package),
        },
    ))
    .await;
    if status != StatusCode::OK {
        return Reseat::Failed(format!("add: {}", body.0));
    }
    rekey_obligations::count_reseat(state).await;
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        member = %LogHexId::agent(member_hex),
        "re-seated a member whose seat could no longer be delivered"
    );
    Reseat::Done
}

/// [`reseat_locked`] in its own task, under the room's membership lock.
pub(super) fn spawn(state: &Arc<AppState>, group_key: &str, member_hex: &str) {
    let state = Arc::clone(state);
    let group_key = group_key.to_string();
    let member_hex = member_hex.to_string();
    tokio::spawn(async move {
        let lock = group_membership_lock(&state, &group_key).await;
        let _guard = lock.lock().await;
        let outcome = reseat_locked(&state, &group_key, &member_hex).await;
        if outcome != Reseat::Done {
            tracing::debug!(
                group_id = %LogHexId::group(&group_key),
                member = %LogHexId::agent(&member_hex),
                ?outcome,
                "seat not re-sealed"
            );
        }
    });
}

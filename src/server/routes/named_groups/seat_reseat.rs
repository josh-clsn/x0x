//! Re-seat a member whose seat can no longer be delivered (survivor re-key
//! A13 fix rounds 1 and 2; see `docs/adr/transient/T-seat-obligation.md`).
//!
//! An unproven seat is delivered from the catch-up log, and its Welcome stays
//! staged while it is owed (`seat_welcome_pin`). When the log no longer
//! reaches back to the seat, or its Welcome is lost, the seat cannot be sent
//! as it was. A Welcome cannot be minted for the current epoch without a
//! commit, because later commits set path secrets on the member's leaf path
//! that only a commit can hand on. So the member is re-seated with commits,
//! the returning-member pattern:
//!
//! - the member's role is read first;
//! - the stale leaf is removed, with the member's KeyPackage on the roster
//!   (derived from its seed, so it is the same KeyPackage);
//! - the member is added again with it, which stages a fresh Welcome, owes
//!   the new seat and pins its Welcome;
//! - a role other than Member is restored with a signed role update, as the
//!   returning-member re-key restores it (a legacy Owner comes back Admin);
//! - the survivors are owed both commits, as for any removal and add. The
//!   removal's direct sends go to the survivors only (its gossip publish
//!   reaches everyone; a member that never took its seat cannot link it).
//!
//! At most one re-seat per member and room in [`RESEAT_EVERY`], kept on disk
//! with the join-result staging file, and only by an admin of the room. An
//! add that fails after the removal is tried once more; if it fails again the
//! allowance is given back, the failure is counted, and the member stays
//! removed until it asks to be admitted again (a plain add then works).
//!
//! This restores the owner's side only. A member whose roster base predates
//! its first seat cannot link the re-seat; that needs a member-side seat
//! re-base (task A15).

use super::{
    add_treekem_named_group_member, group_membership_lock, now_millis_u64, parse_agent_id_hex,
    persist_join_result_staging, persist_named_group_info, publish_named_group_metadata_event,
    rekey_obligations, remember_commit_bearing_event, remove_treekem_named_group_member_with,
    seal_commit_owner_certified, spawn_group_control_event_redelivery,
    spawn_named_group_event_delivery_to_active_members, AddNamedGroupMemberRequest, AppState,
    AtomicWriteOutcome, NamedGroupMetadataEvent,
};
use crate::groups::GroupRole;
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
/// Returns the stamp it replaced, to give back on a failure.
fn take_allowance(
    state: &AppState,
    group_key: &str,
    member_hex: &str,
    now_ms: u64,
) -> Option<Option<u64>> {
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
        return None;
    }
    Some(last.insert(key, now_ms))
}

/// Give back an allowance taken for a re-seat that failed.
async fn give_back(state: &AppState, group_key: &str, member_hex: &str, before: Option<u64>) {
    {
        let mut last = state
            .seat_reseats
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = (group_key.to_string(), member_hex.to_ascii_lowercase());
        match before {
            Some(at) => last.insert(key, at),
            None => last.remove(&key),
        };
    }
    persist_join_result_staging(state).await;
}

/// The role to restore after a re-seat: anything but Member, a legacy
/// Owner capped at Admin, as the returning-member re-key does.
fn role_to_restore(role: GroupRole) -> Option<GroupRole> {
    match role {
        GroupRole::Owner => Some(GroupRole::Admin),
        GroupRole::Member => None,
        other => Some(other),
    }
}

/// Seal and send a role update restoring `role` to `member_hex`. The caller
/// holds the room's membership lock.
async fn restore_role_locked(
    state: &Arc<AppState>,
    group_key: &str,
    member_hex: &str,
    role: GroupRole,
) -> Result<(), String> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let Some(mut next) = state.named_groups.read().await.get(group_key).cloned() else {
        return Err("room gone".to_string());
    };
    next.set_member_role(member_hex, role);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    let commit = seal_commit_owner_certified(state, &mut next, signing_kp, now_millis_u64())
        .await
        .map_err(|e| format!("seal: {e}"))?;
    if !matches!(
        persist_named_group_info(state, group_key, next.clone()).await,
        Ok(AtomicWriteOutcome::Durable)
    ) {
        return Err("the role restore is not durable".to_string());
    }
    let event = NamedGroupMetadataEvent::MemberRoleUpdated {
        group_id: next.stable_group_id().to_string(),
        revision,
        actor: local_hex,
        agent_id: member_hex.to_string(),
        role,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(state, &next.metadata_topic, &event).await;
    remember_commit_bearing_event(state, &event).await;
    spawn_named_group_event_delivery_to_active_members(state, &next, &event, &[]);
    spawn_group_control_event_redelivery(state, &next.metadata_topic, &next, &event, &[], None);
    Ok(())
}

async fn add_back(
    state: &Arc<AppState>,
    group_key: &str,
    member_id: crate::identity::AgentId,
    member_hex: &str,
    package: &str,
    display_name: Option<String>,
) -> Result<(), String> {
    let (status, body) = Box::pin(add_treekem_named_group_member(
        Arc::clone(state),
        group_key.to_string(),
        member_id,
        AddNamedGroupMemberRequest {
            agent_id: member_hex.to_string(),
            display_name,
            treekem_key_package_b64: Some(package.to_string()),
        },
    ))
    .await;
    if status == StatusCode::OK {
        Ok(())
    } else {
        Err(body.0.to_string())
    }
}

/// Re-seat `member_hex` in `group_key`. The caller holds the room's
/// membership lock.
pub(super) async fn reseat_locked(
    state: &Arc<AppState>,
    group_key: &str,
    member_hex: &str,
) -> Reseat {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (package, display_name, role) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_key) else {
            return Reseat::NotPossible("room_unknown");
        };
        if !info
            .caller_role(&local_hex)
            .is_some_and(|role| role.at_least(GroupRole::Admin))
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
        (package, member.display_name.clone(), member.role)
    };
    let Ok(member_id) = parse_agent_id_hex(member_hex) else {
        return Reseat::NotPossible("bad_member_id");
    };
    let Some(before) = take_allowance(state, group_key, member_hex, now_millis_u64()) else {
        #[cfg(test)]
        state
            .named_group_test_recorders
            .reseats_too_soon
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        return Reseat::TooSoon;
    };
    persist_join_result_staging(state).await;
    let (status, body) = remove_treekem_named_group_member_with(
        Arc::clone(state),
        group_key.to_string(),
        member_hex.to_string(),
        local_hex,
        false,
    )
    .await;
    if status != StatusCode::OK {
        give_back(state, group_key, member_hex, before).await;
        return Reseat::Failed(format!("removal: {}", body.0));
    }
    rekey_obligations::forget(state, group_key, member_hex).await;
    let mut added = add_back(
        state,
        group_key,
        member_id,
        member_hex,
        &package,
        display_name.clone(),
    )
    .await;
    if added.is_err() {
        added = add_back(
            state,
            group_key,
            member_id,
            member_hex,
            &package,
            display_name,
        )
        .await;
    }
    if let Err(error) = added {
        give_back(state, group_key, member_hex, before).await;
        rekey_obligations::count_reseat_failure(state).await;
        tracing::error!(
            group_id = %LogHexId::group(group_key),
            member = %LogHexId::agent(member_hex),
            "a re-seat removed the member but could not add it back; it stays removed until it asks again: {error}"
        );
        return Reseat::Failed(format!("add: {error}"));
    }
    if let Some(role) = role_to_restore(role) {
        if let Err(error) = restore_role_locked(state, group_key, member_hex, role).await {
            tracing::warn!(
                group_id = %LogHexId::group(group_key),
                member = %LogHexId::agent(member_hex),
                "a re-seated member's role was not restored: {error}"
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_other_than_member_is_restored_and_an_owner_comes_back_admin() {
        assert_eq!(role_to_restore(GroupRole::Member), None);
        assert_eq!(role_to_restore(GroupRole::Admin), Some(GroupRole::Admin));
        assert_eq!(role_to_restore(GroupRole::Owner), Some(GroupRole::Admin));
    }
}

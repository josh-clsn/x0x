//! A seat's Welcome stays staged while the seat is owed (survivor re-key
//! A13 fix round 1; see `docs/adr/transient/T-seat-obligation.md`).
//!
//! A member seated by a direct add or an approval is owed its seat until it
//! proves it holds it. The seat names a Welcome staged at this daemon, which
//! used to expire after `PENDING_WELCOME_TTL` (24 h). A member away longer got
//! its seat and could not fetch the Welcome. Now the Welcome a seat obligation
//! names is pinned:
//!
//! - every expiry check (the staging prune, the load at start-up, and the
//!   serve and stream checks) treats a pinned Welcome as live;
//! - the pin is written with the staging file, so a restart keeps it;
//! - the obligation worker's step drops the pin once no unproven seat names
//!   that member in that room: the seat settled, the member left, or the
//!   room was wiped.
//!
//! The Welcome joins at the seat's epoch however old it is: the joiner's
//! KeyPackage secret is re-derived from its seed, and TreeKEM does not
//! enforce KeyPackage lifetimes. The member then applies the commits since
//! from the catch-up log.

use super::{
    persist_join_result_staging, rekey_obligations, staging_entry_fresh, AppState,
    NamedGroupMetadataEvent, WelcomeRef, PENDING_WELCOME_TTL,
};
use std::collections::HashSet;
use std::sync::PoisonError;

/// Whether the staged Welcome `welcome_id` is pinned by an unproven seat.
pub(super) fn pinned(state: &AppState, welcome_id: &str) -> bool {
    state
        .seat_welcome_pins
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(welcome_id)
}

/// Whether a Welcome staged at `created_at_ms` is still live: inside the
/// TTL, or pinned.
pub(super) fn welcome_live(
    state: &AppState,
    welcome_id: &str,
    created_at_ms: u64,
    now_ms: u64,
) -> bool {
    staging_entry_fresh(created_at_ms, PENDING_WELCOME_TTL, now_ms) || pinned(state, welcome_id)
}

/// The deadline a staged Welcome's serve may run to: the TTL from staging,
/// and for a pinned Welcome at least the TTL from now.
pub(super) fn deadline(
    state: &AppState,
    welcome_id: &str,
    created_at: std::time::Instant,
) -> std::time::Instant {
    let staged = created_at + PENDING_WELCOME_TTL;
    if pinned(state, welcome_id) {
        staged.max(std::time::Instant::now() + PENDING_WELCOME_TTL)
    } else {
        staged
    }
}

/// The Welcome reference a seat event names.
pub(super) fn welcome_ref_of(seat: &NamedGroupMetadataEvent) -> Option<&WelcomeRef> {
    match seat {
        NamedGroupMetadataEvent::MemberAdded { welcome_ref, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { welcome_ref, .. } => welcome_ref.as_ref(),
        _ => None,
    }
}

/// Whether `event` is `member_hex`'s own seat: an add or an approval naming it.
pub(super) fn names_seat(event: &NamedGroupMetadataEvent, member_hex: &str) -> bool {
    match event {
        NamedGroupMetadataEvent::MemberAdded { agent_id, .. } => {
            agent_id.eq_ignore_ascii_case(member_hex)
        }
        NamedGroupMetadataEvent::JoinRequestApproved {
            requester_agent_id, ..
        } => requester_agent_id.eq_ignore_ascii_case(member_hex),
        _ => false,
    }
}

/// Pin the Welcome `seat` names, on disk.
pub(super) async fn pin_seat(state: &AppState, seat: &NamedGroupMetadataEvent) {
    let Some(welcome) = welcome_ref_of(seat) else {
        return;
    };
    let added = state
        .seat_welcome_pins
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(welcome.welcome_id.clone());
    if added {
        persist_join_result_staging(state).await;
    }
}

/// Whether `seat` can still seat its member: its Welcome is inline, or
/// staged and live here.
pub(super) async fn seat_welcome_staged(state: &AppState, seat: &NamedGroupMetadataEvent) -> bool {
    if let NamedGroupMetadataEvent::MemberAdded {
        treekem_welcome_b64: Some(_),
        ..
    }
    | NamedGroupMetadataEvent::JoinRequestApproved {
        treekem_welcome_b64: Some(_),
        ..
    } = seat
    {
        return true;
    }
    let Some(welcome) = welcome_ref_of(seat) else {
        return false;
    };
    let now_ms = super::now_millis_u64();
    state
        .pending_welcomes
        .read()
        .await
        .get(&welcome.welcome_id)
        .is_some_and(|pending| {
            welcome_live(state, &welcome.welcome_id, pending.created_at_ms, now_ms)
        })
}

/// Drop every pin no unproven seat stands behind, on disk when any went.
pub(super) async fn reconcile(state: &AppState) {
    let pins: Vec<String> = {
        let pins = state
            .seat_welcome_pins
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if pins.is_empty() {
            return;
        }
        pins.iter().cloned().collect()
    };
    let seats = rekey_obligations::seats(state).await;
    let owed: HashSet<(String, String)> = {
        let groups = state.named_groups.read().await;
        seats
            .into_iter()
            .flat_map(|(room, member)| {
                let mut aliases = vec![room.clone()];
                if let Some(info) = groups.get(&room) {
                    aliases.push(info.stable_group_id().to_string());
                    aliases.push(info.mls_group_id.clone());
                }
                aliases
                    .into_iter()
                    .map(move |alias| (alias, member.to_ascii_lowercase()))
            })
            .collect()
    };
    let stale: Vec<String> = {
        let welcomes = state.pending_welcomes.read().await;
        pins.into_iter()
            .filter(|id| {
                !welcomes.get(id).is_some_and(|pending| {
                    owed.contains(&(
                        pending.group_id.clone(),
                        pending.joiner_agent.to_ascii_lowercase(),
                    ))
                })
            })
            .collect()
    };
    if stale.is_empty() {
        return;
    }
    {
        let mut pins = state
            .seat_welcome_pins
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for id in &stale {
            pins.remove(id);
        }
    }
    persist_join_result_staging(state).await;
}

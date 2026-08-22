//! Self-leave re-key: a member who leaves a TreeKEM group still holds a live
//! leaf until one designated member commits its removal. These controls pin
//! that exactly one member re-keys, once, including after a restart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// Stage a TreeKEM group holding a member who has already self-left: the
/// roster records the departure but, as a self-leave carries no commit, the
/// leaf is still live and the epoch has not moved. Returns the departed
/// member's hex id, their KeyPackage, and the shared group handle.
async fn staged_self_leave(
    state: &Arc<AppState>,
    group_id: &str,
    committer: AgentId,
) -> Result<(String, Vec<u8>, Arc<Mutex<x0x::mls::TreeKemMlsGroup>>)> {
    use base64::Engine as _;

    let group_id_bytes = hex::decode(group_id)?;
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut group =
        x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), local, &local_seed)?;

    let leaver = AgentId([0x6b; 32]);
    let leaver_hex = hex::encode(leaver.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(leaver, &[0x6b; 32])?;
    let leaver_kp = prepared.key_package_bytes().to_vec();
    group.add_member(leaver, &leaver_kp)?;

    let mut info = treekem_metadata_group_info(committer, group_id, group_id);
    let committer_hex = hex::encode(committer.as_bytes());
    if committer != local {
        info.add_member(
            local_hex,
            x0x::groups::GroupRole::Member,
            Some(committer_hex.clone()),
            None,
        );
    }
    info.add_member(
        leaver_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(committer_hex),
        None,
    );
    info.set_member_treekem_key_package(
        &leaver_hex,
        base64::engine::general_purpose::STANDARD.encode(&leaver_kp),
    );
    // The self-leave exactly as a remaining member applies it: roster-only,
    // no TreeKEM commit, epoch untouched.
    info.remove_member(&leaver_hex, Some(leaver_hex.clone()));
    info.secret_epoch = group.epoch();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);

    let group = Arc::new(Mutex::new(group));
    state
        .treekem_groups
        .write()
        .await
        .insert(group_id.to_string(), Arc::clone(&group));
    assert!(
        group.lock().await.has_leaf_for_key_package(&leaver_kp),
        "precondition: a self-leave leaves the departed leaf live"
    );
    Ok((leaver_hex, leaver_kp, group))
}

/// The gap ADR-0014 left open. The crypto that excludes a departed member
/// already worked — an admin remove rotates them out fine. What was missing
/// was anything *triggering* it after a voluntary leave: the empirical
/// three-arm run polled a fully-online group 30 times over five minutes and
/// saw the epoch pinned at 2 the whole way, while the leaver's restored
/// snapshot read post-departure traffic in the clear.
#[tokio::test]
async fn self_leave_advances_the_epoch_and_rotates_the_leaver_out() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "6a".repeat(32);
    let group_id = group_id_storage.as_str();
    let local = state.agent.agent_id();
    let (leaver_hex, leaver_kp, group) = staged_self_leave(&state, group_id, local).await?;
    let epoch_before = group.lock().await.epoch();

    state.named_group_test_recorders.publish_attempts
        .lock()
        .expect("publish-attempt recorder poisoned")
        .clear();

    let rotated = reconcile_treekem_self_leave_rekeys(&state, group_id, "test").await;

    assert_eq!(rotated, 1, "the designated committer must issue the rekey");
    assert_eq!(
        group.lock().await.epoch(),
        epoch_before.saturating_add(1),
        "a self-leave must advance the group epoch — a roster-only fix leaves the leaver reading"
    );
    assert!(
        !group.lock().await.has_leaf_for_key_package(&leaver_kp),
        "the departed member's leaf must be blanked, not merely marked Removed"
    );
    let groups = state.named_groups.read().await;
    let info = groups.get(group_id).expect("group retained");
    assert_eq!(
        info.secret_epoch,
        epoch_before.saturating_add(1),
        "the published roster must bind to the new epoch"
    );
    drop(groups);
    assert!(
        state.named_group_test_recorders.publish_attempts
            .lock()
            .expect("publish-attempt recorder poisoned")
            .iter()
            .any(|(_, gid, _)| gid == group_id),
        "remaining members must be told, or they cannot converge to the new epoch"
    );
    assert!(!leaver_hex.is_empty());
    Ok(())
}

/// Upstream's #370 join-approval flow seeds PENDING roster mirrors, which
/// also read `!is_active()` — the self-leave reconcile's trigger set. A
/// pending joiner carries a KeyPackage but never a ratchet-tree leaf, so
/// the `has_leaf_for_key_package` guard must skip them: rotating "out" a
/// member who was never in would burn an epoch per pending join and
/// re-key against nothing.
#[tokio::test]
async fn a_pending_joiner_with_a_key_package_is_never_a_rekey_candidate() -> Result<()> {
    use base64::Engine as _;

    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "6d".repeat(32);
    let group_id = group_id_storage.as_str();
    let group_id_bytes = hex::decode(group_id)?;
    let local = state.agent.agent_id();
    let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), local, &local_seed)?;
    let epoch_before = group.epoch();

    // A seeded pending joiner: KeyPackage published, no leaf in the tree.
    let pending = AgentId([0x6e; 32]);
    let pending_hex = hex::encode(pending.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(pending, &[0x6e; 32])?;
    let pending_kp = prepared.key_package_bytes().to_vec();

    let mut info = treekem_metadata_group_info(local, group_id, group_id);
    let local_hex = hex::encode(local.as_bytes());
    info.add_member(
        pending_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(local_hex),
        None,
    );
    info.members_v2
        .get_mut(&pending_hex)
        .expect("pending entry")
        .state = x0x::groups::GroupMemberState::Pending;
    info.set_member_treekem_key_package(
        &pending_hex,
        base64::engine::general_purpose::STANDARD.encode(&pending_kp),
    );
    info.secret_epoch = group.epoch();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    let group = Arc::new(Mutex::new(group));
    state
        .treekem_groups
        .write()
        .await
        .insert(group_id.to_string(), Arc::clone(&group));

    let rotated = reconcile_treekem_self_leave_rekeys(&state, group_id, "test-pending").await;

    assert_eq!(rotated, 0, "a pending joiner must never trigger a rekey");
    assert_eq!(
        group.lock().await.epoch(),
        epoch_before,
        "no epoch may advance for a member who never held a leaf"
    );
    Ok(())
}

/// Re-applying the same leave must not commit twice. Each extra commit is
/// another epoch the rest of the group has to converge on, and a pile-up is
/// how this subsystem wedges.
#[tokio::test]
async fn repeated_self_leave_yields_one_epoch_advance_not_two() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "6c".repeat(32);
    let group_id = group_id_storage.as_str();
    let local = state.agent.agent_id();
    let (_leaver_hex, _kp, group) = staged_self_leave(&state, group_id, local).await?;
    let epoch_before = group.lock().await.epoch();

    let first = reconcile_treekem_self_leave_rekeys(&state, group_id, "test-first").await;
    let epoch_after_first = group.lock().await.epoch();
    let second = reconcile_treekem_self_leave_rekeys(&state, group_id, "test-repeat").await;

    assert_eq!(first, 1, "the first pass owes one rotation");
    assert_eq!(second, 0, "the second pass owes nothing");
    assert_eq!(
        epoch_after_first,
        epoch_before.saturating_add(1),
        "one advance"
    );
    assert_eq!(
        group.lock().await.epoch(),
        epoch_after_first,
        "a repeat pass must not advance the epoch again"
    );
    Ok(())
}

/// Every remaining member observes the same self-leave. Only the designated
/// committer may act on it — if all of them did, they would each commit at
/// the same epoch and the group would wedge on duelling commits.
#[tokio::test]
async fn a_member_who_is_not_the_designated_committer_does_not_rekey() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "6d".repeat(32);
    let group_id = group_id_storage.as_str();
    // The group's admin/creator is someone else, so this node is a plain
    // member and must stay out of the way.
    let other_admin = AgentId([0x01; 32]);
    let (_leaver_hex, leaver_kp, group) =
        staged_self_leave(&state, group_id, other_admin).await?;
    let epoch_before = group.lock().await.epoch();

    let rotated = reconcile_treekem_self_leave_rekeys(&state, group_id, "test").await;

    assert_eq!(rotated, 0, "a non-designated member must not commit");
    assert_eq!(
        group.lock().await.epoch(),
        epoch_before,
        "a bystander must not advance the epoch"
    );
    assert!(
        group.lock().await.has_leaf_for_key_package(&leaver_kp),
        "the rotation is still owed — by the designated committer, not this node"
    );
    Ok(())
}

/// ADR-0014 §4. If the rekey only ever fired on the live event, a leave
/// that happened while the committer was down would never rotate and the
/// hole would stay open indefinitely. The trigger is reconstructed from
/// persisted roster state instead, so coming back up closes it.
#[tokio::test]
async fn a_leave_missed_while_down_is_rekeyed_on_the_next_startup_pass() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "6e".repeat(32);
    let group_id = group_id_storage.as_str();
    let local = state.agent.agent_id();
    // No live event is delivered here at all — this is the state a daemon
    // finds on disk after being offline for the departure.
    let (_leaver_hex, leaver_kp, group) = staged_self_leave(&state, group_id, local).await?;
    let epoch_before = group.lock().await.epoch();

    reconcile_treekem_self_leave_rekeys_all_groups(&state).await;

    assert_eq!(
        group.lock().await.epoch(),
        epoch_before.saturating_add(1),
        "the startup sweep must close a rekey owed from an unwitnessed leave"
    );
    assert!(
        !group.lock().await.has_leaf_for_key_package(&leaver_kp),
        "the departed leaf must be gone after catch-up"
    );
    Ok(())
}

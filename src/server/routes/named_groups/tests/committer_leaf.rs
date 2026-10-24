//! Survivor re-key A2: a TreeKEM commit applies only when its committer
//! leaf is the leaf of the event's actor. See
//! `docs/adr/transient/T-treekem-committer-leaf.md`.
//!
//! Each case has its own rule: a commit from another member's leaf, the
//! actor's own leaf, a removal that carries the removed member's commit, an
//! actor whose package this member holds only as a hash, an actor with no
//! committed package, and a self-leave that carries a commit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::epoch_ahead_catchup::{
    catchup_relay_fixture, catchup_request_from, encrypt, legacy_bound_removal, live_epoch,
    live_treekem_group, published_removal_event, signed_self_leave, swap_treekem_commit,
    two_member_treekem_group, wait_until, CatchupRelay, LeaveFixture,
};
use super::*;

fn admin_hex(cast: &CatchupRelay) -> String {
    hex::encode(cast.fixture.state.agent.agent_id().as_bytes())
}

async fn roster(state: &AppState, group_id: &str) -> x0x::groups::GroupInfo {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group")
}

/// The admin's signed removal of the leaver whose binding names `commit`
/// at `epoch`. The admin's own tree does not move: the bytes are another
/// leaf's, and the binding names them, so only the committer leaf differs
/// from a genuine removal.
async fn admin_removal_naming(
    fixture: &LeaveFixture,
    commit: &[u8],
    epoch: u64,
) -> Result<NamedGroupMetadataEvent> {
    let state = &fixture.state;
    let admin_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let mut next = roster(state, &fixture.group_id).await;
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&member_hex, Some(admin_hex.clone()));
    next.secret_epoch = epoch;
    next.security_binding = treekem_removal_bytes_binding(epoch, commit);
    assert!(next.security_binding.is_some(), "setup: a digest binding");
    let commit_record =
        next.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    Ok(NamedGroupMetadataEvent::MemberRemoved {
        group_id: fixture.group_id.clone(),
        revision,
        actor: admin_hex,
        agent_id: member_hex,
        treekem_commit_b64: Some(BASE64.encode(commit)),
        treekem_epoch: Some(epoch),
        secret_epoch: None,
        commit: Some(commit_record),
    })
}

/// The admin removes the leaver through the route and publishes it.
async fn genuine_removal(cast: &CatchupRelay) -> NamedGroupMetadataEvent {
    let member_hex = hex::encode(cast.fixture.member_id.as_bytes());
    let response = remove_named_group_member(
        State(Arc::clone(&cast.fixture.state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((cast.fixture.group_id.clone(), member_hex)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the admin removes");
    published_removal_event(&cast.fixture.state).expect("published removal")
}

/// The victim reads the admin's next message and the removed member does
/// not.
async fn victim_follows_the_admin(cast: &mut CatchupRelay, text: &[u8]) -> Result<()> {
    let group_id = &cast.fixture.group_id;
    assert_eq!(
        live_epoch(&cast.victim_state, group_id).await,
        live_epoch(&cast.fixture.state, group_id).await
    );
    let ciphertext = encrypt(&cast.fixture.state, group_id, text).await?;
    let opened = {
        let group = live_treekem_group(&cast.victim_state, group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(opened, text);
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "the removed member must not read it"
    );
    Ok(())
}

/// The commit bytes are member B's own update, and the admin's signed
/// binding names exactly those bytes, so A1's check passes. The committer
/// leaf is B's, not the admin's: refused, nothing installed.
#[tokio::test]
async fn a_commit_from_another_members_leaf_is_refused() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let epoch = cast.epoch_before + 1;
    let foreign = admin_removal_naming(&cast.fixture, &cast.attacker_commit, epoch).await?;
    let roster_before = roster(&cast.victim_state, &group_id).await;

    let refused =
        apply_named_group_metadata_event(&cast.victim_state, foreign.clone(), admin_id, true, None)
            .await;
    assert!(
        !refused.accepted,
        "a commit from another member's leaf must be refused: {refused:?}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );
    let roster_after = roster(&cast.victim_state, &group_id).await;
    assert_eq!(roster_after.state_hash, roster_before.state_hash);
    assert!(roster_after.has_active_member(&hex::encode(cast.fixture.member_id.as_bytes())));

    // The refusal is this rule's, at the door every TreeKEM commit uses.
    let group = live_treekem_group(&cast.victim_state, &group_id).await;
    let err = process_treekem_commit_after_crypto_recheck(
        &cast.victim_state,
        &group_id,
        &roster_after,
        group,
        &admin_hex(&cast),
        &cast.attacker_commit,
        epoch,
        "test_foreign_leaf",
    )
    .await
    .expect_err("another member's leaf is refused");
    assert!(
        err.to_string().contains("committer_leaf_not_actor"),
        "got {err}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );

    let genuine = genuine_removal(&cast).await;
    let installed =
        apply_named_group_metadata_event(&cast.victim_state, genuine, admin_id, true, None).await;
    assert!(
        installed.accepted,
        "the genuine removal installs: {installed:?}"
    );
    victim_follows_the_admin(&mut cast, b"after the genuine removal").await?;
    cast.shutdown().await;
    Ok(())
}

/// The positive control: the admin's own removal, from the admin's leaf,
/// installs; and at the door, member B's own commit passes as B's.
#[tokio::test]
async fn a_commit_from_the_actors_leaf_applies() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let genuine = genuine_removal(&cast).await;
    let (epoch, commit_bytes) = match &genuine {
        NamedGroupMetadataEvent::MemberRemoved {
            treekem_epoch: Some(epoch),
            treekem_commit_b64: Some(b64),
            ..
        } => (*epoch, BASE64.decode(b64)?),
        other => panic!("not a TreeKEM removal: {other:?}"),
    };
    let admin_leaf = live_treekem_group(&cast.fixture.state, &group_id)
        .await
        .lock()
        .await
        .leaf_of(&admin_id)
        .expect("the admin's own leaf");
    assert_eq!(
        x0x::mls::TreeKemMlsGroup::committer_leaf_of(&commit_bytes),
        Some(admin_leaf)
    );
    let installed =
        apply_named_group_metadata_event(&cast.victim_state, genuine, admin_id, true, None).await;
    assert!(
        installed.accepted,
        "the actor's own commit installs: {installed:?}"
    );
    assert_eq!(live_epoch(&cast.victim_state, &group_id).await, epoch);
    victim_follows_the_admin(&mut cast, b"from the actor's leaf").await?;
    cast.shutdown().await;
    Ok(())
}

/// At the door, B's update is refused under the admin's name and accepted
/// under B's own, whose package the roster holds.
#[tokio::test]
async fn the_door_ties_each_commit_to_its_named_actor() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let info = roster(&cast.victim_state, &group_id).await;
    let epoch = cast.epoch_before + 1;
    let group = live_treekem_group(&cast.victim_state, &group_id).await;
    let as_admin = process_treekem_commit_after_crypto_recheck(
        &cast.victim_state,
        &group_id,
        &info,
        Arc::clone(&group),
        &admin_hex(&cast),
        &cast.attacker_commit,
        epoch,
        "test_named_actor",
    )
    .await;
    assert!(as_admin.is_err(), "B's commit is not the admin's");
    let b_hex = hex::encode(cast.member_b.as_bytes());
    process_treekem_commit_after_crypto_recheck(
        &cast.victim_state,
        &group_id,
        &info,
        group,
        &b_hex,
        &cast.attacker_commit,
        epoch,
        "test_named_actor",
    )
    .await
    .expect("B's commit installs as B's");
    assert_eq!(live_epoch(&cast.victim_state, &group_id).await, epoch);
    cast.shutdown().await;
    Ok(())
}

/// I-1's shape: the admin's genuine legacy-bound removal of R, delivered
/// under the admin's name (as the engine-A doors do) with R's own commit in
/// place of the admin's. The legacy binding names no bytes, so only the
/// committer leaf stops it.
#[tokio::test]
async fn a_legacy_removal_carrying_the_removed_members_commit_is_refused() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let genuine = legacy_bound_removal(&cast.fixture).await?;
    let removed_members_commit = cast.fixture.leaver_group.update()?;
    let substituted = swap_treekem_commit(&genuine, &removed_members_commit);

    let refused =
        apply_named_group_metadata_event(&cast.victim_state, substituted, admin_id, true, None)
            .await;
    assert!(
        !refused.accepted,
        "the removed member's commit must be refused: {refused:?}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );

    let installed =
        apply_named_group_metadata_event(&cast.victim_state, genuine, admin_id, true, None).await;
    assert!(
        installed.accepted,
        "the genuine removal installs: {installed:?}"
    );
    // The leaver's own update moved its copy off the group's epoch; the
    // check that it cannot read is what matters.
    victim_follows_the_admin(&mut cast, b"after the legacy removal").await?;
    cast.shutdown().await;
    Ok(())
}

/// A member who joined after the admin holds the admin's package only as
/// its committed hash (`invite_join_group_info` seats existing members that
/// way). It cannot tie the commit to a leaf, so it refuses, installs
/// nothing and asks for the package. Once the package lands on the #398
/// lane, the same event installs.
#[tokio::test]
async fn a_member_holding_only_the_actors_package_hash_refuses_then_heals() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let admin = admin_hex(&cast);
    let admin_package = roster(&cast.victim_state, &group_id)
        .await
        .members_v2
        .get(&admin)
        .and_then(|seat| seat.treekem_key_package_b64.clone())
        .expect("setup: the creator's package");
    let hash_before = roster(&cast.victim_state, &group_id).await.state_hash;
    {
        let mut groups = cast.victim_state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        let seat = info.members_v2.get_mut(&admin).expect("admin seat");
        seat.treekem_key_package_b64 = None;
        assert!(seat.treekem_key_package_hash.is_some());
        info.recompute_state_hash();
        assert_eq!(info.state_hash, hash_before, "the hash alone is committed");
    }

    let genuine = genuine_removal(&cast).await;
    let refused =
        apply_named_group_metadata_event(&cast.victim_state, genuine.clone(), admin_id, true, None)
            .await;
    assert!(
        !refused.accepted,
        "an actor tied to no leaf must be refused: {refused:?}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );
    let throttle_prefix = format!("{group_id}:member:{admin}:");
    let asked = || {
        cast.victim_state
            .treekem_catchup_throttle
            .try_read()
            .is_ok_and(|throttle| throttle.keys().any(|k| k.starts_with(&throttle_prefix)))
    };
    wait_until(&asked).await;
    assert!(asked(), "the refusal asks a peer for the actor's package");

    assert!(
        apply_targeted_member_key_package(&cast.victim_state, &group_id, &admin, &admin_package)
            .await,
        "the hash-anchored package lands"
    );
    let installed =
        apply_named_group_metadata_event(&cast.victim_state, genuine, admin_id, true, None).await;
    assert!(
        installed.accepted,
        "the same event now installs: {installed:?}"
    );
    victim_follows_the_admin(&mut cast, b"after the package landed").await?;
    cast.shutdown().await;
    Ok(())
}

/// A seat with no committed package at all cannot be tied to any leaf.
/// The commit is refused, however it is delivered.
#[tokio::test]
async fn an_actor_without_a_committed_package_is_refused() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin = admin_hex(&cast);
    let mut info = roster(&cast.victim_state, &group_id).await;
    let seat = info.members_v2.get_mut(&admin).expect("admin seat");
    seat.treekem_key_package_b64 = None;
    seat.treekem_key_package_hash = None;
    let group = live_treekem_group(&cast.victim_state, &group_id).await;
    let commit_bytes = {
        let admin_group = live_treekem_group(&cast.fixture.state, &group_id).await;
        let mut guard = admin_group.lock().await;
        guard.remove_member_verified(cast.fixture.member_id, &cast.fixture.member_key_package)?
    };
    let err = process_treekem_commit_after_crypto_recheck(
        &cast.victim_state,
        &group_id,
        &info,
        group,
        &admin,
        &commit_bytes,
        cast.epoch_before + 1,
        "test_no_package",
    )
    .await
    .expect_err("no committed package, no leaf");
    assert!(
        err.to_string().contains("actor_key_package_uncommitted"),
        "got {err}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );
    cast.shutdown().await;
    Ok(())
}

/// A self-leave never carries a commit (ADR-0014: a remaining admin
/// rotates the leaver out). One that does, even from the leaver's own
/// leaf, is refused before the committer-leaf rule is reached, and the
/// leaver stays on the roster and in the tree.
#[tokio::test]
async fn a_self_leave_carrying_a_commit_is_refused() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let leaver = cast.fixture.member_id;
    let leaver_commit = cast.fixture.leaver_group.update()?;
    let mut carrying = signed_self_leave(&cast.fixture).await?;
    if let NamedGroupMetadataEvent::MemberRemoved {
        treekem_commit_b64,
        treekem_epoch,
        ..
    } = &mut carrying
    {
        *treekem_commit_b64 = Some(BASE64.encode(&leaver_commit));
        *treekem_epoch = Some(cast.epoch_before + 1);
    }
    let refused =
        apply_named_group_metadata_event(&cast.victim_state, carrying, leaver, true, None).await;
    assert!(
        !refused.accepted,
        "a self-leave carrying a commit is refused: {refused:?}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );
    assert!(roster(&cast.victim_state, &group_id)
        .await
        .has_active_member(&hex::encode(leaver.as_bytes())));
    cast.shutdown().await;
    Ok(())
}

/// The normal path is not degraded. J1 and J2 join the authority's group by
/// invite, after the authority created it, so their invite rosters hold the
/// authority's package by hash alone. Each seats it from its Welcome, and J2
/// applies the authority's first removal (of J1) with no refusal and no
/// request for a package.
#[tokio::test]
async fn a_member_who_joined_by_invite_applies_the_creators_first_removal() -> Result<()> {
    use super::adr0107_stuck_join_rearm::{
        build, deliver, hex_of, keyed, local_state, serve_result, serve_welcome, welcome_id_of,
        with_pulled_welcome,
    };
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let authority_hex = hex_of(&s.authority);
    for (joiner, attempt, add) in [
        (&s.j1, &s.j1_attempt, &s.j1_add),
        (&s.j2, &s.j2_attempt, &s.j2_add),
    ] {
        let served = serve_result(&s.authority, joiner, &s.stable, attempt, Some(s.base))
            .await
            .expect("the join result is served");
        let welcome_id = welcome_id_of(add).expect("welcome ref");
        assert!(serve_welcome(&s.authority, joiner, &s.stable, &welcome_id).await);
        let served = with_pulled_welcome(&s.authority, joiner, &s.stable, served).await;
        deliver(joiner, &s.authority_id, served, attempt).await;
        assert_eq!(local_state(joiner, &s.group_key).await, "active");
        assert!(keyed(joiner, &s.group_key).await);
        let seat = roster(joiner, &s.group_key).await.members_v2[&authority_hex].clone();
        assert!(
            current_member_treekem_key_package(&seat).is_some(),
            "the Welcome seats the creator's package on {}",
            hex_of(joiner)
        );
    }

    s.j2.treekem_catchup_throttle.write().await.clear();
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), hex_of(&s.j1))),
    )
    .await
    .into_response();
    assert!(removed.status().is_success(), "the authority removes J1");
    let removal = published_removal_event(&s.authority).expect("published removal");
    let applied =
        apply_named_group_metadata_event(&s.j2, removal, s.authority_id, true, None).await;
    assert!(
        applied.accepted,
        "J2 applies the first removal: {applied:?}"
    );
    assert_eq!(
        live_epoch(&s.j2, &s.group_key).await,
        live_epoch(&s.authority, &s.group_key).await
    );
    assert!(
        !s.j2
            .treekem_catchup_throttle
            .read()
            .await
            .keys()
            .any(|key| key.contains(":member:")),
        "no package was missing, so none was requested"
    );
    for state in [&s.j1, &s.j2, &s.authority] {
        state.shutdown_notify.send_replace(true);
        state.agent.shutdown().await;
    }
    Ok(())
}

/// Strip the victim's copy of the admin's package, keeping its committed
/// hash: the roster of a member who joined before survivor re-key A2.
async fn victim_holds_the_admin_by_hash(cast: &CatchupRelay) {
    let admin = admin_hex(cast);
    let mut groups = cast.victim_state.named_groups.write().await;
    let info = groups.get_mut(&cast.fixture.group_id).expect("group");
    let hash_before = info.state_hash.clone();
    let seat = info.members_v2.get_mut(&admin).expect("admin seat");
    seat.treekem_key_package_b64 = None;
    assert!(seat.treekem_key_package_hash.is_some());
    info.recompute_state_hash();
    assert_eq!(info.state_hash, hash_before, "the hash alone is committed");
}

/// The page of missed commits the admin serves to the victim, through the
/// real serve path.
async fn admin_page_for_victim(cast: &CatchupRelay) -> Result<TreeKemCatchupResponse> {
    let group_id = &cast.fixture.group_id;
    let victim_id = cast.victim_state.agent.agent_id();
    let request = {
        let groups = cast.victim_state.named_groups.read().await;
        catchup_request_from(groups.get(group_id).expect("group"), group_id, &victim_id)
    };
    handle_treekem_catchup_request(&cast.fixture.state, &victim_id, true, request).await;
    let served = cast
        .fixture
        .state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .last()
        .cloned()
        .expect("the admin serves a page");
    Ok(serde_json::from_slice(&served)?)
}

/// Fix round 1 (I-1): a member holding the admin's package by hash alone
/// refuses the admin's removal, and the refusal itself starts what heals
/// it. The epoch-ahead catch-up starts, the admin's package arrives through
/// the real catch-up response handler, and the next page of missed commits
/// installs the removal. The admin never sends the removal again.
#[tokio::test]
async fn a_refused_removal_heals_by_catch_up_without_a_resend() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let victim_id = cast.victim_state.agent.agent_id();
    victim_holds_the_admin_by_hash(&cast).await;
    cast.victim_state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let genuine = genuine_removal(&cast).await;
    let refused =
        apply_named_group_metadata_event(&cast.victim_state, genuine, admin_id, true, None).await;
    assert!(
        !refused.accepted,
        "the first delivery is refused: {refused:?}"
    );
    let pulling = || {
        cast.victim_state
            .treekem_epoch_ahead_targets
            .try_lock()
            .is_ok_and(|targets| targets.contains_key(&group_id))
    };
    wait_until(&pulling).await;
    assert!(pulling(), "the refusal starts the epoch-ahead catch-up");

    // A page that lands before the package is refused again.
    let early = admin_page_for_victim(&cast).await?;
    assert!(!early.events.is_empty(), "the page carries the removal");
    handle_treekem_catchup_response(&cast.victim_state, &admin_id, true, early).await;
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );

    // The package, as the admin's #398 lane serves it.
    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: hex::encode(victim_id.as_bytes()),
        from_revision: 0,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: Some(admin_hex(&cast)),
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        signed_by: None,
    };
    let package = member_keyed_treekem_catchup_response(
        &cast.fixture.state,
        std::slice::from_ref(&group_id),
        &request,
    )
    .await
    .expect("the admin serves its package");
    assert!(package.target_member_key_package_b64.is_some());
    handle_treekem_catchup_response(&cast.victim_state, &admin_id, true, package).await;

    // The next round's page installs the removal.
    let page = admin_page_for_victim(&cast).await?;
    handle_treekem_catchup_response(&cast.victim_state, &admin_id, true, page).await;
    victim_follows_the_admin(&mut cast, b"healed without a resend").await?;
    cast.shutdown().await;
    Ok(())
}

/// Fix round 1 (I-1): once the mesh is up, a member asks for every package
/// it holds by hash alone, and only those.
#[tokio::test]
async fn the_mesh_sweep_asks_for_each_package_held_by_hash_alone() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin = admin_hex(&cast);
    victim_holds_the_admin_by_hash(&cast).await;
    request_hash_only_treekem_key_packages(&cast.victim_state).await;
    let asked_for = |member: &str| {
        let prefix = format!("{group_id}:member:{member}:");
        cast.victim_state
            .treekem_catchup_throttle
            .try_read()
            .is_ok_and(|throttle| throttle.keys().any(|k| k.starts_with(&prefix)))
    };
    wait_until(|| asked_for(&admin)).await;
    assert!(asked_for(&admin), "the admin's package is requested");
    for held in [
        hex::encode(cast.member_b.as_bytes()),
        hex::encode(cast.fixture.member_id.as_bytes()),
    ] {
        assert!(!asked_for(&held), "a package already held is not requested");
    }
    cast.shutdown().await;
    Ok(())
}

/// Fix round 1 (I-2): a member whose own seat commits no package (a group
/// made before 2026-07-11) refuses to seal. Receivers would refuse its
/// commit and the group would split while the admin saw success. The route
/// says why, and nothing changes.
#[tokio::test]
async fn a_sealer_whose_seat_commits_no_package_refuses_to_seal() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let group_id = &fixture.group_id;
    let admin = hex::encode(state.agent.agent_id().as_bytes());
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group");
        let seat = info.members_v2.get_mut(&admin).expect("admin seat");
        seat.treekem_key_package_b64 = None;
        seat.treekem_key_package_hash = None;
        info.recompute_state_hash();
    }
    let before = roster(state, group_id).await;
    let epoch_before = live_epoch(state, group_id).await;

    let response = remove_named_group_member(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), member_hex.clone())),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "sealer_key_package_uncommitted");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("2026-07-11")),
        "the error names the limit: {body}"
    );
    assert_eq!(live_epoch(state, group_id).await, epoch_before);
    let after = roster(state, group_id).await;
    assert_eq!(after.state_hash, before.state_hash);
    assert!(after.has_active_member(&member_hex));
    assert!(
        published_removal_event(state).is_none(),
        "nothing is published"
    );
    state.shutdown_notify.send_replace(true);
    state.agent.shutdown().await;
    Ok(())
}

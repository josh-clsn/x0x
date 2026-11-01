//! Catch-up relay fixtures for the survivor re-key, and the relayed-removal
//! cases under bindings that name their bytes (A1). The fixtures follow
//! upstream's `tests/issue1113_self_leave_rekey.rs`; the epoch-ahead tests
//! themselves are upstream's (cherry-picked 40e0f5d4, 522911ff) and live
//! there.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

pub(super) struct LeaveFixture {
    pub(super) state: Arc<AppState>,
    _dir: tempfile::TempDir,
    pub(super) group_id: String,
    pub(super) member_kp: x0x::identity::AgentKeypair,
    pub(super) member_id: x0x::identity::AgentId,
    pub(super) member_key_package: Vec<u8>,
    pub(super) leaver_group: x0x::mls::TreeKemMlsGroup,
}

pub(super) async fn two_member_treekem_group() -> Result<LeaveFixture> {
    let group_id = "cd".repeat(16);
    let (state, dir) = secure_endpoint_test_state().await?;
    let admin_id = state.agent.agent_id();
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    // As `create_named_group` does: the creator's leaf and its roster seat
    // hold the same KeyPackage bytes (survivor re-key A2).
    let admin_package = x0x::mls::TreeKemMlsGroup::prepare_member(admin_id, &seed)?;
    let admin_package_b64 =
        base64::engine::general_purpose::STANDARD.encode(admin_package.key_package_bytes());
    let mut admin_group =
        x0x::mls::TreeKemMlsGroup::create_prepared(group_id_bytes, admin_package)?;
    let member_kp = x0x::identity::AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[9u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "leave-rekey".to_string(),
        String::new(),
        admin_id,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.set_member_treekem_key_package(&hex::encode(admin_id.as_bytes()), admin_package_b64);
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(hex::encode(admin_id.as_bytes())),
        None,
    );
    info.set_member_treekem_key_package(
        &member_hex,
        base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
    );
    info.secret_epoch = epoch_before;
    info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
    info.recompute_state_hash();

    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    state.treekem_groups.write().await.insert(
        group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(admin_group)),
    );

    Ok(LeaveFixture {
        state,
        _dir: dir,
        group_id,
        member_kp,
        member_id,
        member_key_package: kp_bytes,
        leaver_group,
    })
}

pub(super) async fn live_treekem_group(
    state: &AppState,
    group_id: &str,
) -> Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>> {
    let map = state.treekem_groups.read().await;
    let group = map.get(group_id).cloned().expect("live treekem group");
    drop(map);
    group
}

pub(super) async fn live_epoch(state: &AppState, group_id: &str) -> u64 {
    let group = live_treekem_group(state, group_id).await;
    let guard = group.lock().await;
    guard.epoch()
}

pub(super) async fn encrypt(state: &AppState, group_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let group = live_treekem_group(state, group_id).await;
    let mut guard = group.lock().await;
    Ok(guard.encrypt_message(plaintext)?)
}

pub(super) fn published_removal_event(state: &AppState) -> Option<NamedGroupMetadataEvent> {
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder");
    published.iter().rev().find_map(|(_, bytes)| {
        let event = serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok()?;
        match &event {
            NamedGroupMetadataEvent::MemberRemoved {
                treekem_commit_b64: Some(_),
                ..
            } => Some(event),
            _ => None,
        }
    })
}

pub(super) async fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !ready() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// The admin's removal of the leaver as a daemon from before survivor re-key
/// A1 sealed it: the legacy `treekem:epoch=<n>` binding, which names no
/// TreeKEM bytes. Every seal site now names them, so only this fixture still
/// makes the legacy form.
pub(super) async fn legacy_bound_removal(
    fixture: &LeaveFixture,
) -> Result<NamedGroupMetadataEvent> {
    let state = &fixture.state;
    let admin_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let mut next = {
        let groups = state.named_groups.read().await;
        groups.get(&fixture.group_id).cloned().expect("group")
    };
    let group = live_treekem_group(state, &fixture.group_id).await;
    let mut guard = group.lock().await;
    let treekem_commit =
        guard.remove_member_verified(fixture.member_id, &fixture.member_key_package)?;
    let treekem_epoch = guard.epoch();
    drop(guard);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&member_hex, Some(admin_hex.clone()));
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let commit = next.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    state
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), next);
    Ok(NamedGroupMetadataEvent::MemberRemoved {
        group_id: fixture.group_id.clone(),
        revision,
        actor: admin_hex,
        agent_id: member_hex,
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(treekem_commit)),
        treekem_epoch: Some(treekem_epoch),
        secret_epoch: None,
        commit: Some(commit),
    })
}

pub(super) struct CatchupRelay {
    pub(super) fixture: LeaveFixture,
    pub(super) victim_state: Arc<AppState>,
    _victim_dir: tempfile::TempDir,
    pub(super) member_b: x0x::identity::AgentId,
    pub(super) member_b_group: x0x::mls::TreeKemMlsGroup,
    pub(super) attacker_commit: Vec<u8>,
    pub(super) epoch_before: u64,
}

impl CatchupRelay {
    /// Stop both states, so nothing outlives the test. The fork has no
    /// detached-task drain (#1269): the shutdown signal ends a running
    /// epoch-ahead catch-up task.
    pub(super) async fn shutdown(self) {
        for state in [&self.victim_state, &self.fixture.state] {
            state.shutdown_notify.send_replace(true);
            state.agent.shutdown().await;
        }
    }
}

pub(super) async fn catchup_relay_fixture() -> Result<CatchupRelay> {
    let mut fixture = two_member_treekem_group().await?;
    let member_b_kp = x0x::identity::AgentKeypair::generate()?;
    let member_b = member_b_kp.agent_id();
    let (victim_state, victim_dir) = secure_endpoint_test_state().await?;
    let victim_id = victim_state.agent.agent_id();

    let b_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_b, &[4u8; 32])?;
    let b_pkg = b_prepared.key_package_bytes().to_vec();
    let b_added = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(member_b, &b_pkg)?
    };
    fixture.leaver_group.process_commit(&b_added.commit)?;
    let mut member_b_group =
        x0x::mls::TreeKemMlsGroup::join_from_welcome(b_prepared, &b_added.welcome)?;

    let victim_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(victim_id, &[5u8; 32])?;
    let victim_pkg = victim_prepared.key_package_bytes().to_vec();
    let victim_added = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(victim_id, &victim_pkg)?
    };
    fixture.leaver_group.process_commit(&victim_added.commit)?;
    member_b_group.process_commit(&victim_added.commit)?;
    let victim_group =
        x0x::mls::TreeKemMlsGroup::join_from_welcome(victim_prepared, &victim_added.welcome)?;

    let epoch_before = live_epoch(&fixture.state, &fixture.group_id).await;
    let b_hex = hex::encode(member_b.as_bytes());
    let victim_hex = hex::encode(victim_id.as_bytes());
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
        info.add_member(
            b_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(
            &b_hex,
            base64::engine::general_purpose::STANDARD.encode(&b_pkg),
        );
        info.add_member(
            victim_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        info.set_member_treekem_key_package(
            &victim_hex,
            base64::engine::general_purpose::STANDARD.encode(&victim_pkg),
        );
        info.secret_epoch = epoch_before;
        info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
        info.recompute_state_hash();
    }
    let shared = {
        let groups = fixture.state.named_groups.read().await;
        groups.get(&fixture.group_id).expect("group").clone()
    };
    victim_state
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), shared);
    victim_state.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(victim_group)),
    );
    let attacker_commit = member_b_group.update()?;
    Ok(CatchupRelay {
        fixture,
        victim_state,
        _victim_dir: victim_dir,
        member_b,
        member_b_group,
        attacker_commit,
        epoch_before,
    })
}

pub(super) fn swap_treekem_commit(
    event: &NamedGroupMetadataEvent,
    commit: &[u8],
) -> NamedGroupMetadataEvent {
    let mut relayed = event.clone();
    if let NamedGroupMetadataEvent::MemberRemoved {
        treekem_commit_b64, ..
    } = &mut relayed
    {
        *treekem_commit_b64 = Some(base64::engine::general_purpose::STANDARD.encode(commit));
    }
    relayed
}

pub(super) async fn deliver_catchup(
    state: &Arc<AppState>,
    sender: &x0x::identity::AgentId,
    group_id: &str,
    event: NamedGroupMetadataEvent,
) {
    handle_treekem_catchup_response(
        state,
        sender,
        true,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.to_string(),
            events: vec![event],
            truncated: false,
            target_member_id: None,
            target_member_key_package_b64: None,
            signed_by: None,
            responder_state_hash: None,
            log_evicted_through: None,
        },
    )
    .await;
}

pub(super) async fn group_is_quarantined(state: &AppState, group_id: &str) -> bool {
    let groups = state.named_groups.read().await;
    groups.get(group_id).expect("group").is_fork_quarantined()
}

pub(super) fn catchup_request_from(
    info: &x0x::groups::GroupInfo,
    group_id: &str,
    requester: &x0x::identity::AgentId,
) -> TreeKemCatchupRequest {
    TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.to_string(),
        requester_agent_id: hex::encode(requester.as_bytes()),
        from_revision: info.state_revision,
        from_treekem_epoch: info.secret_epoch,
        current_state_hash: info.state_hash.clone(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        signed_by: None,
        head_challenge: None,
    }
}

/// A member may relay an admin's signed removal. It may not attach its own
/// TreeKEM commit. The victim stays on the pre-rekey epoch, then the genuine
/// rekey installs and the leaver cannot read it.
#[tokio::test]
async fn relayed_removal_rejects_another_members_treekem_commit() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let epoch_before = cast.epoch_before;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        epoch_before,
        "setup: the victim starts at the pre-rekey epoch"
    );
    let member_hex = hex::encode(cast.fixture.member_id.as_bytes());
    let removed = remove_named_group_member(
        State(Arc::clone(&cast.fixture.state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((cast.fixture.group_id.clone(), member_hex)),
    )
    .await
    .into_response();
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "the admin remove route must seal"
    );
    let genuine = published_removal_event(&cast.fixture.state).expect("digest-bound removal");
    let genuine_hash = named_group_metadata_event_commit(&genuine)
        .expect("signed commit")
        .state_hash
        .clone();
    let relayed = swap_treekem_commit(&genuine, &cast.attacker_commit);
    let relayed_hash = named_group_metadata_event_commit(&relayed)
        .expect("signed commit")
        .state_hash
        .clone();
    assert_eq!(genuine_hash, relayed_hash, "roster_hash_equal");

    let admin_id = cast.fixture.state.agent.agent_id();
    let rejected =
        apply_named_group_metadata_event(&cast.victim_state, relayed, admin_id, true, None).await;
    assert!(
        !rejected.accepted,
        "a relayed TreeKEM commit from another member must be rejected: {rejected:?}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        epoch_before,
        "the victim must stay on the pre-rekey epoch"
    );

    let installed =
        apply_named_group_metadata_event(&cast.victim_state, genuine, admin_id, true, None).await;
    assert!(
        installed.accepted,
        "the genuine rekey must still install: {installed:?}"
    );
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        live_epoch(&cast.fixture.state, &cast.fixture.group_id).await
    );
    let ciphertext = encrypt(
        &cast.fixture.state,
        &cast.fixture.group_id,
        b"after-genuine",
    )
    .await?;
    let victim_opened = {
        let group = live_treekem_group(&cast.victim_state, &cast.fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(victim_opened, b"after-genuine");
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "the leaver must not read the victim's new traffic"
    );
    assert!(
        cast.member_b_group.decrypt_message(&ciphertext).is_err(),
        "the other member's own update must not read the genuine epoch"
    );
    cast.shutdown().await;
    Ok(())
}

/// A removal sealed under `treekem:epoch=N` (a daemon from before survivor
/// re-key A1). A third party cannot relay those bytes, substituted or
/// genuine. The author can.
#[tokio::test]
async fn catchup_legacy_binding_stays_with_the_author() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let genuine = legacy_bound_removal(&cast.fixture).await?;
    let binding = named_group_metadata_event_commit(&genuine)
        .expect("signed commit")
        .security_binding
        .clone()
        .expect("legacy binding");
    assert!(
        binding.starts_with("treekem:epoch=") && !binding.contains(":commit="),
        "setup: the fixture seals the legacy binding, got {binding}"
    );
    let substituted = swap_treekem_commit(&genuine, &cast.attacker_commit);
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        substituted,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "a substituted legacy relay must not advance the epoch"
    );
    assert!(
        !group_is_quarantined(&cast.victim_state, &cast.fixture.group_id).await,
        "a rejected legacy relay must not quarantine the group"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        genuine.clone(),
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "a third party must not install a legacy TreeKEM commit"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.fixture.state.agent.agent_id(),
        &cast.fixture.group_id,
        genuine,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        live_epoch(&cast.fixture.state, &cast.fixture.group_id).await,
        "the author must still deliver the legacy removal"
    );
    let ciphertext = encrypt(&cast.fixture.state, &cast.fixture.group_id, b"author-epoch").await?;
    let victim_opened = {
        let group = live_treekem_group(&cast.victim_state, &cast.fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(victim_opened, b"author-epoch");
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "the removed member must not read the author's new ciphertext"
    );
    cast.shutdown().await;
    Ok(())
}

/// The leaver's own signed roster-only leave, as it publishes it.
pub(super) async fn signed_self_leave(fixture: &LeaveFixture) -> Result<NamedGroupMetadataEvent> {
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let groups = fixture.state.named_groups.read().await;
    let mut leaving = groups.get(&fixture.group_id).cloned().expect("group");
    drop(groups);
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(&fixture.member_kp, now_millis_u64())?;
    Ok(NamedGroupMetadataEvent::MemberRemoved {
        group_id: fixture.group_id.clone(),
        revision,
        actor: member_hex.clone(),
        agent_id: member_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    })
}

/// A digest-bound rekey can be relayed. Substituted bytes cannot.
/// Upstream #1337; the fork's post-leave rekey runs in its own task, so the
/// test waits for it to publish.
#[tokio::test]
async fn catchup_third_party_relays_a_digest_bound_rekey() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let leave = signed_self_leave(&cast.fixture).await?;
    let applied = apply_named_group_metadata_event(
        &cast.fixture.state,
        leave.clone(),
        cast.fixture.member_id,
        true,
        None,
    )
    .await;
    assert!(
        applied.accepted,
        "the admin must seal the leave: {applied:?}"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        leave,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "the roster leave must not advance the epoch"
    );
    wait_until(|| published_removal_event(&cast.fixture.state).is_some()).await;
    let genuine = published_removal_event(&cast.fixture.state).expect("digest rekey");
    let binding = named_group_metadata_event_commit(&genuine)
        .expect("signed commit")
        .security_binding
        .clone()
        .expect("digest binding");
    assert!(
        binding.contains(":commit="),
        "the self-leave rekey must name the TreeKEM digest, got {binding}"
    );
    let substituted = swap_treekem_commit(&genuine, &cast.attacker_commit);
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        substituted,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "a substituted digest relay must not install"
    );
    assert!(
        !group_is_quarantined(&cast.victim_state, &cast.fixture.group_id).await,
        "a rejected digest relay must not quarantine the group"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        genuine,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        live_epoch(&cast.fixture.state, &cast.fixture.group_id).await,
        "a third party must relay the genuine digest-bound rekey"
    );
    let ciphertext = encrypt(&cast.fixture.state, &cast.fixture.group_id, b"digest-epoch").await?;
    let victim_opened = {
        let group = live_treekem_group(&cast.victim_state, &cast.fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(victim_opened, b"digest-epoch");
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "the leaver must not read the relayed epoch"
    );
    cast.shutdown().await;
    Ok(())
}

/// The owner, one survivor that saw the removal (S2) and one that did not
/// (S1). Every daemon's tree uses its own agent seed.
pub(super) struct SurvivorRelay {
    pub(super) fixture: LeaveFixture,
    pub(super) s2: Arc<AppState>,
    _s2_dir: tempfile::TempDir,
    pub(super) s1: Arc<AppState>,
    _s1_dir: tempfile::TempDir,
}

impl SurvivorRelay {
    /// S2's data directory, for a restart (survivor re-key A4).
    pub(super) fn s2_dir(&self) -> &std::path::Path {
        self._s2_dir.path()
    }

    pub(super) async fn shutdown(self) {
        for state in [&self.s1, &self.s2, &self.fixture.state] {
            state.shutdown_notify.send_replace(true);
            state.agent.shutdown().await;
        }
    }
}

pub(super) async fn survivor_relay_fixture() -> Result<SurvivorRelay> {
    let mut fixture = two_member_treekem_group().await?;
    let (s2, s2_dir) = secure_endpoint_test_state().await?;
    let (s1, s1_dir) = secure_endpoint_test_state().await?;
    let group_id_bytes = hex::decode(&fixture.group_id)?;
    let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
    let mut joined: Vec<(Arc<AppState>, x0x::mls::TreeKemMlsGroup, Vec<u8>)> = Vec::new();
    for state in [&s2, &s1] {
        let id = state.agent.agent_id();
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(id, &seed)?;
        let package = prepared.key_package_bytes().to_vec();
        let added = {
            let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
            let mut guard = group.lock().await;
            guard.add_member(id, &package)?
        };
        fixture.leaver_group.process_commit(&added.commit)?;
        for (_, tree, _) in &mut joined {
            tree.process_commit(&added.commit)?;
        }
        let tree = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
        joined.push((Arc::clone(state), tree, package));
    }
    let epoch = live_epoch(&fixture.state, &fixture.group_id).await;
    let shared = {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        for (state, _, package) in &joined {
            let hex_id = hex::encode(state.agent.agent_id().as_bytes());
            info.add_member(
                hex_id.clone(),
                x0x::groups::GroupRole::Member,
                Some(admin_hex.clone()),
                None,
            );
            info.set_member_treekem_key_package(
                &hex_id,
                base64::engine::general_purpose::STANDARD.encode(package),
            );
        }
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
        info.clone()
    };
    for (state, tree, _) in joined {
        state
            .named_groups
            .write()
            .await
            .insert(fixture.group_id.clone(), shared.clone());
        state.treekem_groups.write().await.insert(
            fixture.group_id.clone(),
            Arc::new(tokio::sync::Mutex::new(tree)),
        );
    }
    Ok(SurvivorRelay {
        fixture,
        s2,
        _s2_dir: s2_dir,
        s1,
        _s1_dir: s1_dir,
    })
}

pub(super) async fn roster_head(
    state: &AppState,
    group_id: &str,
    member_hex: &str,
) -> (u64, String, bool) {
    let groups = state.named_groups.read().await;
    let info = groups.get(group_id).expect("group");
    (
        info.state_revision,
        info.state_hash.clone(),
        info.has_active_member(member_hex),
    )
}

/// The owner removes R. S2 applies it. S1 was away: it asks only S2, and
/// the page S2 serves brings S1 to the owner's epoch and roster.
#[tokio::test]
async fn a_survivor_relays_an_admin_removal_by_catch_up() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let s1_id = cast.s1.agent.agent_id();
    let s2_id = cast.s2.agent.agent_id();
    let epoch_before = live_epoch(&cast.s1, group_id).await;
    let removed_hex = hex::encode(cast.fixture.member_id.as_bytes());
    let response = remove_named_group_member(
        State(Arc::clone(owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), removed_hex.clone())),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner removes R");
    let removal = published_removal_event(owner).expect("the owner publishes the removal");
    let applied = apply_named_group_metadata_event(&cast.s2, removal, owner_id, true, None).await;
    assert!(applied.accepted, "S2 applies the removal: {applied:?}");
    let owner_epoch = live_epoch(owner, group_id).await;
    assert_eq!(live_epoch(&cast.s2, group_id).await, owner_epoch);
    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        epoch_before,
        "S1 missed the removal"
    );

    let request = {
        let groups = cast.s1.named_groups.read().await;
        let info = groups.get(group_id).expect("group on S1");
        catchup_request_from(info, group_id, &s1_id)
    };
    handle_treekem_catchup_request(&cast.s2, &s1_id, true, request).await;
    let served = cast
        .s2
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .last()
        .cloned()
        .expect("S2 serves a catch-up page");
    let page: TreeKemCatchupResponse = serde_json::from_slice(&served)?;
    assert!(!page.events.is_empty(), "the page carries the removal");
    handle_treekem_catchup_response(&cast.s1, &s2_id, true, page).await;

    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        owner_epoch,
        "S1 reaches the owner's epoch from S2 alone"
    );
    let owner_head = roster_head(owner, group_id, &removed_hex).await;
    assert!(!owner_head.2, "R is gone on the owner");
    assert_eq!(
        roster_head(&cast.s1, group_id, &removed_hex).await,
        owner_head,
        "S1's roster is the owner's"
    );
    let ciphertext = encrypt(owner, group_id, b"after-removal").await?;
    let opened = {
        let group = live_treekem_group(&cast.s1, group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(opened, b"after-removal");
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "R must not read the new epoch"
    );
    cast.shutdown().await;
    Ok(())
}

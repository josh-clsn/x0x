//! #1427 epoch-ahead catch-up (upstream #1449, #1464) and #1337's rule for
//! relayed removals, ported from upstream's
//! `tests/issue1113_self_leave_rekey.rs` with a small relay fixture of
//! their own. #1337's self-leave harness is not ported. See
//! `docs/adr/transient/T-survivor-a0-upstream-catchup-port.md`.

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
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
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
    // Group creation seats the creator's package (`create_named_group`), so
    // every member can tie the creator's commits to its leaf (survivor
    // re-key A2).
    let admin_package = x0x::mls::TreeKemMlsGroup::prepare_member(admin_id, &seed)?;
    info.set_member_treekem_key_package(
        &hex::encode(admin_id.as_bytes()),
        base64::engine::general_purpose::STANDARD.encode(admin_package.key_package_bytes()),
    );
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
struct SurvivorRelay {
    fixture: LeaveFixture,
    s2: Arc<AppState>,
    _s2_dir: tempfile::TempDir,
    s1: Arc<AppState>,
    _s1_dir: tempfile::TempDir,
}

impl SurvivorRelay {
    async fn shutdown(self) {
        for state in [&self.s1, &self.s2, &self.fixture.state] {
            state.shutdown_notify.send_replace(true);
            state.agent.shutdown().await;
        }
    }
}

async fn survivor_relay_fixture() -> Result<SurvivorRelay> {
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

async fn roster_head(state: &AppState, group_id: &str, member_hex: &str) -> (u64, String, bool) {
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

/// #1427: a member that missed a removal commit, and sees no later
/// membership event, asks for catch-up when it gets a later-epoch
/// ciphertext. The page that a peer serves brings it to the new epoch.
#[tokio::test]
async fn epoch_ahead_ciphertext_requests_catchup_and_converges() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let admin = &cast.fixture.state;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let admin_id = admin.agent.agent_id();
    let victim_id = victim.agent.agent_id();
    let member_hex = hex::encode(cast.fixture.member_id.as_bytes());
    let removed = remove_named_group_member(
        State(Arc::clone(admin)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), member_hex)),
    )
    .await
    .into_response();
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "the admin remove must seal"
    );
    let admin_epoch = live_epoch(admin, group_id).await;
    assert!(
        admin_epoch > cast.epoch_before,
        "the removal advances the epoch"
    );
    // The victim was offline: it never got the removal.
    assert_eq!(live_epoch(victim, group_id).await, cast.epoch_before);

    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let ahead = encrypt(admin, group_id, b"after-removal").await?;
    let (status, _) = treekem_group_decrypt(
        victim,
        group_id,
        None,
        &base64::engine::general_purpose::STANDARD.encode(&ahead),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the old epoch cannot read");
    let asked = || {
        victim
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("catch-up recorder")
            .iter()
            .any(|recorded| recorded == group_id.as_bytes())
    };
    wait_until(asked).await;
    assert!(
        asked(),
        "a later-epoch ciphertext must start a TreeKEM catch-up request"
    );

    // The peer serves the request the victim sent; the victim applies it.
    let request = {
        let groups = victim.named_groups.read().await;
        let info = groups.get(group_id).expect("group on the victim");
        catchup_request_from(info, group_id, &victim_id)
    };
    handle_treekem_catchup_request(admin, &victim_id, true, request).await;
    let served = admin
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .last()
        .cloned()
        .expect("the peer serves a catch-up page");
    let page: TreeKemCatchupResponse = serde_json::from_slice(&served)?;
    assert!(
        !page.events.is_empty(),
        "the page carries the missed removal"
    );
    handle_treekem_catchup_response(victim, &admin_id, true, page).await;
    assert_eq!(
        live_epoch(victim, group_id).await,
        admin_epoch,
        "the returning member reaches the new epoch"
    );
    let next = encrypt(admin, group_id, b"caught-up").await?;
    let (status, body) = treekem_group_decrypt(
        victim,
        group_id,
        None,
        &base64::engine::general_purpose::STANDARD.encode(&next),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "decrypt after catch-up: {body:?}");
    cast.shutdown().await;
    Ok(())
}

/// #1427: a group-store record from a later epoch starts the same catch-up
/// request. A record from an older epoch does not.
#[tokio::test]
async fn epoch_ahead_store_record_requests_catchup() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let info = victim
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("group on the victim")
        .clone();
    let protector =
        crate::server::routes::stores::treekem_task_list_protector(victim, group_id, &info)
            .expect("shared TreeKEM protector");
    let store_id = x0x::kv::KvStoreId::new([7; 32]);
    let record = |epoch: u64| x0x::kv::TreeKemKvStoreRecordV1 {
        version: 1,
        group_id: info.stable_group_id().as_bytes().to_vec(),
        store_id: *store_id.as_bytes(),
        epoch,
        reader_only: false,
        ciphertext: Vec::new(),
    };
    let asked = || {
        victim
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("catch-up recorder")
            .len()
    };

    let stale = protector
        .open_record(&store_id, &record(cast.epoch_before - 1))
        .await;
    assert!(stale.is_err(), "an older-epoch record must not open");
    // The older-epoch arm spawns nothing, so this reads a settled count.
    assert_eq!(
        asked(),
        0,
        "an older-epoch record must not request catch-up"
    );

    let ahead = protector
        .open_record(&store_id, &record(cast.epoch_before + 1))
        .await;
    assert!(ahead.is_err(), "a later-epoch record cannot open yet");
    wait_until(|| asked() > 0).await;
    assert!(
        asked() > 0,
        "a later-epoch store record must start a TreeKEM catch-up request"
    );
    cast.shutdown().await;
    Ok(())
}

/// #1427 (W3-H determinism red): the catch-up throttle window runs on the
/// runtime clock. On the wall clock, a paused runtime never let a peer out
/// of its window: a recovery that asked the signer before it knew the
/// signer's identity never asked it again.
#[tokio::test(start_paused = true)]
async fn epoch_ahead_catchup_window_runs_on_the_runtime_clock() {
    let peer = AgentId([7; 32]);
    let asked = tokio::time::Instant::now();
    assert!(
        epoch_ahead_catchup_peers(vec![peer], |_| Some(asked)).is_empty(),
        "a peer asked now is inside its window"
    );
    tokio::time::advance(TREEKEM_CATCHUP_THROTTLE).await;
    assert_eq!(
        epoch_ahead_catchup_peers(vec![peer], |_| Some(asked)),
        vec![peer],
        "the window ends one throttle period later on the runtime clock"
    );
}

/// #1427: one epoch-ahead observation asks at most three peers. The next
/// observation asks the peers not yet asked, so a reachable fourth peer
/// (for example the removal's signer) is tried after three silent ones.
#[test]
fn epoch_ahead_catchup_rotates_past_unanswered_peers() {
    let peers: Vec<AgentId> = (1..=5u8).map(|byte| AgentId([byte; 32])).collect();
    let mut asked: Vec<(AgentId, tokio::time::Instant)> = Vec::new();
    let last = |asked: &[(AgentId, tokio::time::Instant)], peer: &AgentId| {
        asked
            .iter()
            .find(|(seen, _)| seen == peer)
            .map(|(_, at)| *at)
    };

    let first = epoch_ahead_catchup_peers(peers.clone(), |peer| last(&asked, peer));
    assert_eq!(
        first,
        peers[..3],
        "the first observation keeps preference order"
    );
    let now = tokio::time::Instant::now();
    asked.extend(first.iter().map(|peer| (*peer, now)));

    let second = epoch_ahead_catchup_peers(peers.clone(), |peer| last(&asked, peer));
    assert_eq!(
        second,
        peers[3..],
        "the next observation asks the peers outside the first three"
    );
    asked.extend(second.iter().map(|peer| (*peer, now)));
    assert!(
        epoch_ahead_catchup_peers(peers.clone(), |peer| last(&asked, peer)).is_empty(),
        "every peer is inside the throttle window"
    );

    // After the window, the least recently asked go first.
    let older = now
        .checked_sub(TREEKEM_CATCHUP_THROTTLE * 3)
        .expect("monotonic clock past three windows");
    let old = now
        .checked_sub(TREEKEM_CATCHUP_THROTTLE * 2)
        .expect("monotonic clock past two windows");
    let asked: Vec<(AgentId, tokio::time::Instant)> = peers
        .iter()
        .enumerate()
        .map(|(index, peer)| (*peer, if index < 2 { old } else { older }))
        .collect();
    assert_eq!(
        epoch_ahead_catchup_peers(peers.clone(), |peer| last(&asked, peer)),
        peers[2..],
        "the least recently asked peers are asked first"
    );
}

/// #1427 (Codex RC2): one later-epoch record, then silence. The three
/// members asked first never answer and the signer ranks fourth. The
/// single observation must still go on to the signer, with no further
/// traffic to start a new request.
#[tokio::test]
async fn single_epoch_ahead_observation_reaches_the_fourth_ranked_signer() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let signer = cast.fixture.state.agent.agent_id();
    let signer_hex = hex::encode(signer.as_bytes());
    // Admins rank first by agent id, so these three rank before the signer.
    let silent: Vec<AgentId> = (1..=3u8)
        .map(|last| {
            let mut id = [0u8; 32];
            id[31] = last;
            AgentId(id)
        })
        .collect();
    {
        let mut groups = victim.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group on the victim");
        for peer in &silent {
            info.add_member(
                hex::encode(peer.as_bytes()),
                x0x::groups::GroupRole::Admin,
                Some(signer_hex.clone()),
                None,
            );
        }
    }
    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::pause();

    spawn_treekem_epoch_ahead_catchup(victim, group_id, cast.epoch_before + 1);

    let asked = |peer: &AgentId| {
        let prefix = format!("{group_id}:{}:", hex::encode(peer.as_bytes()));
        let throttle = victim.treekem_catchup_throttle.try_read();
        throttle.is_ok_and(|throttle| throttle.keys().any(|key| key.starts_with(&prefix)))
    };
    wait_until(|| asked(&signer)).await;
    for peer in &silent {
        assert!(asked(peer), "the first round asks the three silent admins");
    }
    assert!(
        asked(&signer),
        "one observation must go on to the fourth-ranked signer"
    );
    assert!(
        asked(&cast.fixture.member_id) && asked(&cast.member_b),
        "the later round asks the remaining members too"
    );
    cast.shutdown().await;
    Ok(())
}

/// #1427 (Codex RC3): a recovery for epoch e+1 asks every member. An
/// e+2 record then arrives, with every member inside the throttle
/// window. A delayed, terminal page that serves only e+1 then arrives.
/// The e+2 observation must not be lost: the recovery must ask again from
/// e+1.
#[tokio::test]
async fn newer_epoch_observation_survives_a_late_older_epoch_page() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let admin = &cast.fixture.state;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let admin_id = admin.agent.agent_id();
    let victim_id = victim.agent.agent_id();
    let remove = |member: AgentId| {
        remove_named_group_member(
            State(Arc::clone(admin)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((group_id.clone(), hex::encode(member.as_bytes()))),
        )
    };
    let removed = remove(cast.fixture.member_id).await.into_response();
    assert_eq!(removed.status(), StatusCode::OK, "the first remove seals");
    let first_epoch = live_epoch(admin, group_id).await;

    // The page a peer at the first epoch serves; it arrives late.
    let request = {
        let groups = victim.named_groups.read().await;
        let info = groups.get(group_id).expect("group on the victim");
        catchup_request_from(info, group_id, &victim_id)
    };
    handle_treekem_catchup_request(admin, &victim_id, true, request).await;
    let served = admin
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .last()
        .cloned()
        .expect("the peer serves a catch-up page");
    let late_page: TreeKemCatchupResponse = serde_json::from_slice(&served)?;

    let removed = remove(cast.member_b).await.into_response();
    assert_eq!(removed.status(), StatusCode::OK, "the second remove seals");
    let second_epoch = live_epoch(admin, group_id).await;
    assert!(second_epoch > first_epoch && first_epoch > cast.epoch_before);

    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let sent = || {
        victim
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("catch-up recorder")
            .iter()
            .filter(|recorded| *recorded == group_id.as_bytes())
            .count()
    };
    spawn_treekem_epoch_ahead_catchup(victim, group_id, first_epoch);
    wait_until(|| sent() >= 3).await;
    assert_eq!(sent(), 3, "the first round asks all three members");

    spawn_treekem_epoch_ahead_catchup(victim, group_id, second_epoch);
    let target = || {
        victim
            .treekem_epoch_ahead_targets
            .try_lock()
            .ok()
            .and_then(|targets| targets.get(group_id).map(|target| target.epoch))
    };
    wait_until(|| target() == Some(second_epoch)).await;
    assert_eq!(
        target(),
        Some(second_epoch),
        "the running recovery takes the newer epoch"
    );

    handle_treekem_catchup_response(victim, &admin_id, true, late_page).await;
    assert_eq!(
        live_epoch(victim, group_id).await,
        first_epoch,
        "the late page brings only the older epoch"
    );
    let before = sent();
    tokio::time::pause();
    wait_until(|| sent() > before).await;
    assert!(
        sent() > before,
        "the recovery must go on asking for the newer epoch"
    );
    cast.shutdown().await;
    Ok(())
}

/// #1427 (Codex RC4): the last round of a recovery asks the signer, which
/// is offline. The signer then comes back and sends one record at the
/// same missed epoch, after that attempt and before the round ends. The
/// observation changes no target epoch, but it must not be lost: the
/// recovery must ask the signer again, with no further traffic.
#[tokio::test]
async fn same_epoch_observation_in_the_last_round_asks_again() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let signer = cast.fixture.state.agent.agent_id();
    let missed = cast.epoch_before + 1;
    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let sent = || {
        victim
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("catch-up recorder")
            .iter()
            .filter(|recorded| *recorded == group_id.as_bytes())
            .count()
    };
    let prefix = format!("{group_id}:{}:", hex::encode(signer.as_bytes()));
    let signer_asked_at = || {
        victim
            .treekem_catchup_throttle
            .try_read()
            .ok()
            .and_then(|throttle| {
                throttle
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .map(|(_, at)| *at)
                    .max()
            })
    };
    tokio::time::pause();

    spawn_treekem_epoch_ahead_catchup(victim, group_id, missed);
    wait_until(|| sent() >= 3).await;
    assert_eq!(sent(), 3, "the first round asks all three members");

    // Halfway between the rounds before the last one and the last one. The
    // throttle runs on the runtime clock, so each window passes between
    // rounds and each round asks every member again.
    let rounds = TREEKEM_EPOCH_AHEAD_CATCHUP_ROUNDS;
    let windows = u32::try_from(rounds)?;
    tokio::time::sleep(TREEKEM_CATCHUP_THROTTLE * (windows - 2) + TREEKEM_CATCHUP_THROTTLE / 2)
        .await;
    assert_eq!(
        sent(),
        3 * (rounds - 1),
        "each round after a throttle window asks every member again"
    );
    // Hold the throttle so the last round stops after it reads its target.
    let throttle = victim.treekem_catchup_throttle.write().await;
    tokio::time::sleep(TREEKEM_CATCHUP_THROTTLE).await;
    // Hold the targets so the last round stops before it ends.
    let mut targets = victim.treekem_epoch_ahead_targets.lock().await;
    drop(throttle);
    wait_until(|| sent() >= 3 * rounds).await;
    assert_eq!(sent(), 3 * rounds, "the last round asks the offline signer");
    let last_round = signer_asked_at().expect("the last round stamps the signer");

    // The signer is back and sends one record at the same epoch.
    assert!(
        !note_epoch_ahead_observation(&mut targets, group_id, missed),
        "the running recovery takes the observation"
    );
    drop(targets);

    wait_until(|| sent() > 3 * rounds).await;
    assert!(
        sent() > 3 * rounds,
        "a same-epoch observation in the last round must start a new request"
    );
    wait_until(|| signer_asked_at().is_some_and(|at| at > last_round)).await;
    assert!(
        signer_asked_at().is_some_and(|at| at > last_round),
        "the new request asks the signer"
    );
    cast.shutdown().await;
    Ok(())
}

/// #1427 (Codex RC5): eight candidates, three per round. The throttle
/// runs on the runtime clock, so each round asks the three members asked
/// least recently. The signer ranks sixth: the second round asks it, and
/// the penultimate round asks it again while it is offline. The signer
/// then comes back and sends one record at the same missed epoch. The last
/// round asks only other members. The observation must not be lost: the
/// recovery must ask the signer again, with no further traffic.
#[tokio::test]
async fn same_epoch_observation_in_the_penultimate_round_asks_the_holder_again() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let signer = cast.fixture.state.agent.agent_id();
    let signer_hex = hex::encode(signer.as_bytes());
    let missed = cast.epoch_before + 1;
    // Admins rank first by agent id, so these five rank before the signer.
    let silent: Vec<AgentId> = (1..=5u8)
        .map(|last| {
            let mut id = [0u8; 32];
            id[31] = last;
            AgentId(id)
        })
        .collect();
    {
        let mut groups = victim.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group on the victim");
        for peer in &silent {
            info.add_member(
                hex::encode(peer.as_bytes()),
                x0x::groups::GroupRole::Admin,
                Some(signer_hex.clone()),
                None,
            );
        }
    }
    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let sent = || {
        victim
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("catch-up recorder")
            .iter()
            .filter(|recorded| *recorded == group_id.as_bytes())
            .count()
    };
    let prefix = format!("{group_id}:{}:", hex::encode(signer.as_bytes()));
    let signer_asked_at = || {
        victim
            .treekem_catchup_throttle
            .try_read()
            .ok()
            .and_then(|throttle| {
                throttle
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .map(|(_, at)| *at)
                    .max()
            })
    };
    tokio::time::pause();

    spawn_treekem_epoch_ahead_catchup(victim, group_id, missed);
    wait_until(|| sent() >= 6).await;
    assert_eq!(
        sent(),
        6,
        "the first two rounds ask six of the eight members"
    );
    let second_round = signer_asked_at().expect("the second round asks the signer");

    // Between the penultimate and the last round.
    let rounds = TREEKEM_EPOCH_AHEAD_CATCHUP_ROUNDS;
    let windows = u32::try_from(rounds)?;
    tokio::time::sleep(TREEKEM_CATCHUP_THROTTLE * (windows - 3) + TREEKEM_CATCHUP_THROTTLE / 2)
        .await;
    assert_eq!(
        sent(),
        3 * (rounds - 1),
        "each round asks the three members asked least recently"
    );
    let penultimate = signer_asked_at().expect("the signer was asked");
    assert!(
        penultimate > second_round,
        "the penultimate round asks the offline signer again"
    );

    // The signer is back and sends one record at the same epoch.
    assert!(
        !note_epoch_ahead_observation(
            &mut *victim.treekem_epoch_ahead_targets.lock().await,
            group_id,
            missed,
        ),
        "the running recovery takes the observation"
    );
    wait_until(|| sent() >= 3 * rounds).await;
    assert_eq!(
        sent(),
        3 * rounds,
        "the last round asks three other members"
    );
    assert_eq!(
        signer_asked_at(),
        Some(penultimate),
        "the last round does not ask the signer"
    );

    wait_until(|| signer_asked_at().is_some_and(|at| at > penultimate)).await;
    assert!(
        signer_asked_at().is_some_and(|at| at > penultimate),
        "the recovery must ask the signer again after its observation"
    );
    cast.shutdown().await;
    Ok(())
}

/// #1427 (Codex RC3): the signer ranks after twenty silent admins, so
/// past six rounds of three. One observation must still reach it.
#[tokio::test]
async fn single_epoch_ahead_observation_asks_every_candidate() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let signer = cast.fixture.state.agent.agent_id();
    let signer_hex = hex::encode(signer.as_bytes());
    let silent: Vec<AgentId> = (1..=20u8)
        .map(|last| {
            let mut id = [0u8; 32];
            id[31] = last;
            AgentId(id)
        })
        .collect();
    {
        let mut groups = victim.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group on the victim");
        for peer in &silent {
            info.add_member(
                hex::encode(peer.as_bytes()),
                x0x::groups::GroupRole::Admin,
                Some(signer_hex.clone()),
                None,
            );
        }
    }
    victim
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::pause();

    spawn_treekem_epoch_ahead_catchup(victim, group_id, cast.epoch_before + 1);

    let asked = |peer: &AgentId| {
        let prefix = format!("{group_id}:{}:", hex::encode(peer.as_bytes()));
        let throttle = victim.treekem_catchup_throttle.try_read();
        throttle.is_ok_and(|throttle| throttle.keys().any(|key| key.starts_with(&prefix)))
    };
    let everyone: Vec<AgentId> = silent
        .iter()
        .copied()
        .chain([signer, cast.fixture.member_id, cast.member_b])
        .collect();
    wait_until(|| everyone.iter().all(&asked)).await;
    assert!(
        asked(&signer),
        "one observation must go on to the signer ranked 21st"
    );
    for peer in &everyone {
        assert!(asked(peer), "every candidate is asked");
    }
    cast.shutdown().await;
    Ok(())
}

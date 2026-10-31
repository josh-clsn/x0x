//! The engine-A relay-bridge doors: what they refuse, what they serve, and
//! that a dropped caller cannot cut an apply in half.

use super::issue1269_shutdown_apply_boundary::{leftover_temp_files, persisted_has, wait_reached};
use super::*;

const WAIT: Duration = Duration::from_secs(15);
const GROUP: &str = "engine-a-door-local-key";
const STABLE: &str = "engine-a-door-stable-id";
const RENAMED: &str = "engine-a door rename";

async fn install_group(state: &Arc<AppState>) -> Result<x0x::groups::GroupInfo> {
    let (mut info, admin_hex, _) = metadata_terminality_test_group(state, GROUP);
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        STABLE.to_string(),
        admin_hex,
        info.created_at,
        String::new(),
    ));
    info.metadata_topic = "local:engine-a-door".to_string();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP.to_string(), info.clone());
    anyhow::ensure!(
        save_named_groups(state).await,
        "the group is persisted before the door applies"
    );
    anyhow::ensure!(!persisted_has(&state.named_groups_path, RENAMED));
    Ok(info)
}

fn signed_rename(
    state: &Arc<AppState>,
    parent: &x0x::groups::GroupInfo,
) -> NamedGroupMetadataEvent {
    let mut next = parent.clone();
    next.name = RENAMED.to_string();
    next.roster_revision += 1;
    NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: STABLE.to_string(),
        revision: next.roster_revision,
        actor: hex::encode(state.agent.agent_id().as_bytes()),
        name: Some(next.name.clone()),
        description: None,
        commit: Some(sign_metadata_terminality_commit(
            parent,
            &next,
            state,
            now_millis_u64(),
        )),
    }
}

fn door_request(
    sender_hex: &str,
    event: &NamedGroupMetadataEvent,
) -> Result<ApplyMetadataEventRequest> {
    Ok(ApplyMetadataEventRequest {
        event_b64: BASE64.encode(serde_json::to_vec(event)?),
        sender_agent_id: sender_hex.to_string(),
    })
}

fn owner(durable: bool) -> Extension<crate::server::rider_auth::ActorContext> {
    Extension(crate::server::rider_auth::ActorContext::Owner { durable })
}

async fn post_apply(
    state: &Arc<AppState>,
    event: &NamedGroupMetadataEvent,
    sender_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = apply_group_metadata_event(
        State(Arc::clone(state)),
        owner(true),
        Path(event_group_of(event)),
        Json(door_request(sender_hex, event)?),
    )
    .await
    .into_response();
    body_of(response).await
}

fn event_group_of(event: &NamedGroupMetadataEvent) -> String {
    named_group_metadata_event_group_id(event).to_string()
}

async fn get_inline(
    state: &Arc<AppState>,
    group_id: &str,
    member_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = get_join_result_inline(
        State(Arc::clone(state)),
        owner(true),
        Path((group_id.to_string(), member_hex.to_string())),
    )
    .await
    .into_response();
    body_of(response).await
}

async fn body_of(response: axum::response::Response) -> Result<(StatusCode, serde_json::Value)> {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// The caller of the apply door goes away while the apply is parked inside
/// its atomic named-groups write. The apply still runs to completion: the
/// file holds the rename, no temp file is left, and memory agrees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_survives_a_dropped_caller() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state).await?;
    let path = state.named_groups_path.clone();
    let sender_hex = hex::encode(state.agent.agent_id().as_bytes());
    let request = door_request(&sender_hex, &signed_rename(&state, &parent))?;
    let pause = atomic_write_test_seam::arm(&path);

    let caller_state = Arc::clone(&state);
    let caller = tokio::spawn(async move {
        apply_group_metadata_event(
            State(caller_state),
            owner(true),
            Path(STABLE.to_string()),
            Json(request),
        )
        .await
        .into_response()
    });
    anyhow::ensure!(
        wait_reached(&pause).await,
        "the door's apply parks in its named-groups write"
    );
    caller.abort();
    anyhow::ensure!(caller.await.is_err(), "the caller was dropped mid-apply");
    pause.release();

    let deadline = tokio::time::Instant::now() + WAIT;
    while !(persisted_has(&path, RENAMED) && leftover_temp_files(&path).is_empty()) {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the dropped caller's apply must finish its write"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let name = state
        .named_groups
        .read()
        .await
        .get(GROUP)
        .map(|info| info.name.clone());
    assert_eq!(name.as_deref(), Some(RENAMED));
    Ok(())
}

/// A refused admission answers 503 once shutdown has started and 500 when the
/// apply simply did not complete; neither is mistaken for the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_tells_shutdown_from_an_apply_that_did_not_complete() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state).await?;
    let sender_hex = hex::encode(state.agent.agent_id().as_bytes());
    let event = signed_rename(&state, &parent);
    *state
        .shielded_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;

    let (status, body) = post_apply(&state, &event, &sender_hex).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    state.shutdown_started.cancel();
    let (status, body) = post_apply(&state, &event, &sender_hex).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(!persisted_has(&state.named_groups_path, RENAMED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_answers_422_with_a_reason_for_an_unsigned_event() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state).await?;
    let mut event = signed_rename(&state, &parent);
    if let NamedGroupMetadataEvent::GroupMetadataUpdated { commit, .. } = &mut event {
        *commit = None;
    }
    let sender_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (status, body) = post_apply(&state, &event, &sender_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["reason"].as_str(),
        Some("unsigned_event_needs_verified_sender")
    );
    assert!(!persisted_has(&state.named_groups_path, RENAMED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_refuses_events_that_authorize_on_the_sender_alone() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "ab".repeat(32);
    let share = NamedGroupMetadataEvent::SecureShareDelivered {
        group_id: group_id.clone(),
        recipient: admin.clone(),
        secret_epoch: 2,
        kem_ciphertext_b64: String::new(),
        aead_nonce_b64: String::new(),
        aead_ciphertext_b64: String::new(),
        actor: admin.clone(),
    };
    let card = NamedGroupMetadataEvent::GroupCardPublished {
        group_id: group_id.clone(),
        card: x0x::groups::GroupCard {
            group_id: group_id.clone(),
            name: "spoof".into(),
            description: String::new(),
            avatar_url: None,
            banner_url: None,
            tags: Vec::new(),
            policy_summary: x0x::groups::GroupPolicySummary {
                discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
                admission: x0x::groups::GroupAdmission::RequestAccess,
                confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
                read_access: x0x::groups::GroupReadAccess::MembersOnly,
                write_access: x0x::groups::GroupWriteAccess::MembersOnly,
            },
            owner_agent_id: admin.clone(),
            admin_count: 1,
            member_count: 1,
            created_at: 0,
            updated_at: 0,
            request_access_enabled: true,
            metadata_topic: None,
            revision: 1,
            state_hash: String::new(),
            prev_state_hash: None,
            issued_at: 1,
            expires_at: 2,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn: false,
            signature: String::new(),
        },
    };
    for (event, reason) in [
        (share, "secure_share_needs_verified_sender"),
        (card, "group_card_needs_verified_sender"),
    ] {
        let (status, body) = post_apply(&state, &event, &admin).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["reason"].as_str(), Some(reason), "{body}");
    }
    Ok(())
}

// ---- a TreeKEM group with one leaving member --------------------------

struct LeaveFixture {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
    group_id: String,
    member_id: x0x::identity::AgentId,
    member_kp: x0x::identity::AgentKeypair,
    epoch_before: u64,
}

async fn leave_fixture() -> Result<LeaveFixture> {
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
    admin_group.add_member(member_id, &kp_bytes)?;
    let epoch_before = admin_group.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "engine-a-leave".to_string(),
        String::new(),
        admin_id,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(hex::encode(admin_id.as_bytes())),
        None,
    );
    info.set_member_treekem_key_package(&member_hex, BASE64.encode(&kp_bytes));
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
        member_id,
        member_kp,
        epoch_before,
    })
}

/// The member's self-leave, its roster commit signed by `signer`.
async fn self_leave_signed_by(
    fixture: &LeaveFixture,
    signer: &x0x::identity::AgentKeypair,
) -> Result<NamedGroupMetadataEvent> {
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let mut leaving = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .cloned()
        .expect("group");
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(signer, now_millis_u64())?;
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

fn published_rekey(state: &AppState) -> Option<NamedGroupMetadataEvent> {
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder");
    published.iter().rev().find_map(|(_, bytes)| {
        let event = serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok()?;
        matches!(
            &event,
            NamedGroupMetadataEvent::MemberRemoved {
                treekem_commit_b64: Some(_),
                ..
            }
        )
        .then_some(event)
    })
}

async fn member_is_active(state: &AppState, group_id: &str, member_hex: &str) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .is_some_and(|info| info.has_active_member(member_hex))
}

/// Member B carries A's self-leave and signs its roster commit. The door's
/// `sender_agent_id` is only a claim, so the event's actor must be the
/// commit's signer: the forgery gets 422 and A stays seated. A's own
/// self-leave, signed by A, is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_door_refuses_a_forged_self_leave_and_applies_the_genuine_one() -> Result<()> {
    let fixture = leave_fixture().await?;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let forger = x0x::identity::AgentKeypair::generate()?;

    let forged = self_leave_signed_by(&fixture, &forger).await?;
    let (status, body) = post_apply(&fixture.state, &forged, &member_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["reason"].as_str(),
        Some("event_actor_is_not_the_commit_signer"),
        "{body}"
    );
    assert!(member_is_active(&fixture.state, &fixture.group_id, &member_hex).await);

    let genuine = self_leave_signed_by(&fixture, &fixture.member_kp).await?;
    let (status, body) = post_apply(&fixture.state, &genuine, &member_hex).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!member_is_active(&fixture.state, &fixture.group_id, &member_hex).await);
    Ok(())
}

/// A stock self-leave re-key (`treekem:epoch=<n>:commit=<d>`, signed after the
/// binding is set) delivered through the door is accepted and converges the
/// replica on the committer's state; the same removal sealed with the legacy
/// admin binding gets 422 and changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_door_applies_a_stock_self_leave_seal_and_refuses_a_legacy_removal() -> Result<()>
{
    let fixture = leave_fixture().await?;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
    let pre_leave = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .cloned()
        .expect("group");
    let survivor_seed = [7u8; 32];
    let survivor_kp = x0x::identity::AgentKeypair::generate()?;
    let survivor_id = survivor_kp.agent_id();
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(survivor_id, &survivor_seed)?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let welcome = {
        let group = fixture
            .state
            .treekem_groups
            .read()
            .await
            .get(&fixture.group_id)
            .cloned()
            .expect("tree");
        let mut guard = group.lock().await;
        guard.add_member(survivor_id, &kp_bytes)?.welcome
    };
    let survivor = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &welcome)?;
    let survivor_snap = survivor.to_snapshot_bytes()?;
    let survivor_hex = hex::encode(survivor_id.as_bytes());
    let epoch = {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(&survivor_hex, BASE64.encode(&kp_bytes));
        let group = fixture.state.treekem_groups.read().await;
        let epoch = group
            .get(&fixture.group_id)
            .expect("tree")
            .lock()
            .await
            .epoch();
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
        epoch
    };
    assert!(epoch > fixture.epoch_before);
    let pre_leave = {
        let mut info = pre_leave;
        info.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(&survivor_hex, BASE64.encode(&kp_bytes));
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
        info
    };

    let leave = self_leave_signed_by(&fixture, &fixture.member_kp).await?;
    let (status, body) = post_apply(&fixture.state, &leave, &member_hex).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let committer_hash = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .map(|info| info.state_hash.clone())
        .expect("group");
    let rekey = published_rekey(&fixture.state).expect("the lowest admin published a seal");

    let (replica, _dir) = secure_endpoint_test_state().await?;
    replica
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), pre_leave);
    let restored = x0x::mls::TreeKemMlsGroup::restore(&survivor_snap, survivor_id, &survivor_seed)?;
    replica.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(restored)),
    );

    // The legacy admin binding over the same bytes names nothing.
    let legacy = {
        let mut event = rekey.clone();
        if let NamedGroupMetadataEvent::MemberRemoved {
            commit: Some(commit),
            treekem_epoch: Some(rekey_epoch),
            ..
        } = &mut event
        {
            *commit = x0x::groups::GroupStateCommit::sign(
                commit.group_id.clone(),
                commit.revision,
                commit.prev_state_hash.clone(),
                commit.roster_root.clone(),
                commit.policy_hash.clone(),
                commit.public_meta_hash.clone(),
                Some(format!("treekem:epoch={rekey_epoch}")),
                commit.withdrawn,
                commit.committed_at,
                fixture.state.agent.identity().agent_keypair(),
            )?;
        }
        event
    };
    let (status, body) = post_apply(&replica, &leave, &member_hex).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post_apply(&replica, &legacy, &admin_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["reason"].as_str(),
        Some("needs_verified_signer_and_named_tree_bytes"),
        "{body}"
    );

    let (status, body) = post_apply(&replica, &rekey, &admin_hex).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let replica_hash = replica
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .map(|info| info.state_hash.clone())
        .expect("group");
    assert_eq!(
        replica_hash, committer_hash,
        "the replica reaches the committer's state"
    );
    Ok(())
}

// ---- the original MemberJoined ----------------------------------------

fn seat_treekem_package(
    info: &mut x0x::groups::GroupInfo,
    agent: x0x::identity::AgentId,
    seed: &[u8; 32],
) -> Result<()> {
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(agent, seed)?;
    info.set_member_treekem_key_package(
        &hex::encode(agent.as_bytes()),
        BASE64.encode(prepared.key_package_bytes()),
    );
    info.recompute_state_hash();
    Ok(())
}

/// The joiner's own self-signed `MemberJoined` is the door's core job: it is
/// applied and seats the joiner. The recovery-courier form of the same event
/// is refused with a reason and seats nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_door_applies_the_original_member_joined_and_refuses_the_courier() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "7a".repeat(32);
    let group_id_bytes = hex::decode(&group_id)?;
    let inviter = state.agent.agent_id();
    let inviter_hex = hex::encode(inviter.as_bytes());
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, inviter, &seed)?;
    state
        .treekem_groups
        .write()
        .await
        .insert(group_id.clone(), Arc::new(tokio::sync::Mutex::new(group)));
    let mut info = treekem_metadata_group_info(inviter, &group_id, &group_id);
    seat_treekem_package(&mut info, inviter, &seed)?;
    let now_ms = now_millis_u64();
    let joiner_keypair = x0x::identity::AgentKeypair::generate()?;
    let joiner_id = joiner_keypair.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let joiner_pub_b64 = BASE64.encode(joiner_keypair.public_key().as_bytes());
    let invite = "engine-a-door-invite".to_string();
    info.record_issued_invite(
        invite.clone(),
        now_ms / 1_000,
        0,
        x0x::groups::GroupRole::Member,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(joiner_id, &[0x7b; 32])?;
    let kp_b64 = BASE64.encode(prepared.key_package_bytes());
    let canonical = canonical_member_joined_bytes(
        &group_id,
        Some(&group_id),
        &joiner_hex,
        &joiner_pub_b64,
        x0x::groups::GroupRole::Member,
        None,
        &inviter_hex,
        &invite,
        now_ms,
        Some(&kp_b64),
    );
    let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        joiner_keypair.secret_key(),
        &canonical,
    )
    .map_err(|e| anyhow::anyhow!("sign MemberJoined: {e:?}"))?;
    let join = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_id.clone(),
        stable_group_id: Some(group_id.clone()),
        member_agent_id: joiner_hex.clone(),
        member_public_key_b64: joiner_pub_b64,
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: inviter_hex.clone(),
        invite_secret: invite,
        ts_ms: now_ms,
        treekem_key_package_b64: Some(kp_b64),
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: BASE64.encode(signature.as_bytes()),
        certificate_b64: None,
        kem_public_key_b64: None,
        kem_signature_b64: None,
    };

    let mut courier = join.clone();
    if let NamedGroupMetadataEvent::MemberJoined {
        recovery_authority_agent_id,
        recovery_authority_signature_b64,
        ..
    } = &mut courier
    {
        *recovery_authority_agent_id = Some(inviter_hex.clone());
        *recovery_authority_signature_b64 = Some("attestation".to_string());
    }
    let (status, body) = post_apply(&state, &courier, &joiner_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["reason"].as_str(),
        Some("recovery_courier_needs_verified_sender")
    );
    assert!(!member_is_active(&state, &group_id, &joiner_hex).await);

    let (status, body) = post_apply(&state, &join, &joiner_hex).await?;
    assert_eq!(status, StatusCode::OK, "the original join applies: {body}");
    assert!(member_is_active(&state, &group_id, &joiner_hex).await);
    Ok(())
}

// ---- GET /groups/:id/join-result/:member --------------------------------

/// The door hands out the same recovery bytes as the fetch path, so it runs
/// the ADR 0107 serving guard: an unknown group is a 404 that creates no
/// lock entry; a member with no Active seat gets 409 and its staged result is
/// purged; an Active member is served with the Welcome inlined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_join_result_get_runs_the_serving_guard() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "7b".repeat(32);
    let inviter = state.agent.agent_id();
    let inviter_hex = hex::encode(inviter.as_bytes());
    let joiner_hex = hex::encode(
        x0x::identity::AgentKeypair::generate()?
            .agent_id()
            .as_bytes(),
    );
    state.named_groups.write().await.insert(
        group_id.clone(),
        treekem_metadata_group_info(inviter, &group_id, &group_id),
    );
    let staged_add = NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.clone(),
        revision: 2,
        actor: inviter_hex,
        agent_id: joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some("commit".into()),
        treekem_welcome_b64: Some("V0VMQ09NRQ==".into()),
        welcome_ref: None,
        treekem_epoch: Some(2),
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        roster_certificates_b64: Vec::new(),
        commit: None,
    };
    let key = join_result_key(&group_id, &joiner_hex);

    let locks_before = state.group_membership_locks.read().await.len();
    let (status, body) = get_inline(&state, &"00".repeat(32), &joiner_hex).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "group_unknown");
    assert_eq!(
        state.group_membership_locks.read().await.len(),
        locks_before,
        "an unknown group creates no lock entry"
    );

    stage_join_result(&state, &group_id, &joiner_hex, staged_add.clone(), None).await;
    assert!(state.pending_join_results.read().await.contains_key(&key));
    let (status, body) = get_inline(&state, &group_id, &joiner_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "member_not_active");
    assert!(
        !state.pending_join_results.read().await.contains_key(&key),
        "a definitive refusal purges the staged result"
    );

    state
        .named_groups
        .write()
        .await
        .get_mut(&group_id)
        .expect("group")
        .add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    stage_join_result(&state, &group_id, &joiner_hex, staged_add, None).await;
    let (status, body) = get_inline(&state, &group_id, &joiner_hex).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["event"].to_string().contains("V0VMQ09NRQ=="),
        "the served event carries the inline Welcome: {body}"
    );
    Ok(())
}

/// The staged Welcome must live as long as the staged result, or the door
/// would answer `welcome_not_staged` for a seat it still owes. The long
/// non-TreeKEM poll backs off to a ceiling instead of polling every 2 s.
#[test]
fn engine_a_staging_horizon_holds_the_welcome_and_the_long_poll_backs_off() {
    assert!(PENDING_WELCOME_TTL >= PENDING_JOIN_RESULT_TTL);
    assert!(EXPECTED_JOIN_RESULT_INVITER_TTL >= JOIN_RESULT_POLL_HORIZON);
    assert_eq!(join_result_poll_delay(0), Duration::from_secs(2));
    assert_eq!(join_result_poll_delay(1), Duration::from_secs(4));
    assert_eq!(join_result_poll_delay(2), Duration::from_secs(8));
    assert_eq!(join_result_poll_delay(8), JOIN_RESULT_POLL_BACKOFF_CAP);
    assert_eq!(
        join_result_poll_delay(u32::MAX),
        JOIN_RESULT_POLL_BACKOFF_CAP
    );
}

// ---- POST /groups/:id/join-result/:member -------------------------------

async fn post_result(
    state: &Arc<AppState>,
    member_hex: &str,
    event: &NamedGroupMetadataEvent,
    sender_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = apply_join_result_endpoint(
        State(Arc::clone(state)),
        owner(true),
        Path((event_group_of(event), member_hex.to_string())),
        Json(ApplyJoinResultRequest {
            event_b64: BASE64.encode(serde_json::to_vec(event)?),
            sender_agent_id: sender_hex.to_string(),
        }),
    )
    .await
    .into_response();
    body_of(response).await
}

fn member_added_for(group_id: &str, actor: &str, member_hex: &str) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.to_string(),
        revision: 2,
        actor: actor.to_string(),
        agent_id: member_hex.to_string(),
        display_name: None,
        treekem_commit_b64: Some("commit".into()),
        treekem_welcome_b64: Some("V0VMQ09NRQ==".into()),
        welcome_ref: None,
        treekem_epoch: Some(2),
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        roster_certificates_b64: Vec::new(),
        commit: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_join_result_post_checks_the_member_and_the_expected_inviter() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "7d".repeat(32);
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let inviter_hex = "ee".repeat(32);
    let stranger_hex = "ff".repeat(32);
    state.named_groups.write().await.insert(
        group_id.clone(),
        treekem_metadata_group_info(local, &group_id, &group_id),
    );

    // The result must be for this node.
    let for_other = member_added_for(&group_id, &inviter_hex, &"aa".repeat(32));
    let (status, _) = post_result(&state, &"aa".repeat(32), &for_other, &inviter_hex).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A converged group with no armed inviter rejects the result.
    let tree_seed = agent_treekem_seed(state.agent.as_ref(), &hex::decode(&group_id)?);
    let tree = x0x::mls::TreeKemMlsGroup::create(hex::decode(&group_id)?, local, &tree_seed)?;
    state
        .treekem_groups
        .write()
        .await
        .insert(group_id.clone(), Arc::new(tokio::sync::Mutex::new(tree)));
    let for_me = member_added_for(&group_id, &inviter_hex, &local_hex);
    let (status, body) = post_result(&state, &local_hex, &for_me, &inviter_hex).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"]
        .as_str()
        .is_some_and(|e| e.contains("missing_expected_inviter")));

    // An armed inviter must be the sender.
    record_expected_join_result_inviter(
        state.as_ref(),
        join_result_key(&group_id, &local_hex),
        inviter_hex.clone(),
    );
    let (status, body) = post_result(&state, &local_hex, &for_me, &stranger_hex).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    Ok(())
}

/// A join stub that has not converged is a join this node asked for, so an
/// unarmed result from its own author passes the inviter gate (it then meets
/// the commit verification, which refuses this unsigned test event).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_join_result_post_accepts_the_unarmed_result_of_an_unconverged_stub() -> Result<()>
{
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "7e".repeat(32);
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let inviter_hex = "ee".repeat(32);
    state.named_groups.write().await.insert(
        group_id.clone(),
        treekem_metadata_group_info(local, &group_id, &group_id),
    );
    let for_me = member_added_for(&group_id, &inviter_hex, &local_hex);
    let (status, body) = post_result(&state, &local_hex, &for_me, &inviter_hex).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "past the inviter gate: {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_join_result_post_answers_503_when_shutdown_refuses_the_apply() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "7f".repeat(32);
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let inviter_hex = "ee".repeat(32);
    state.named_groups.write().await.insert(
        group_id.clone(),
        treekem_metadata_group_info(local, &group_id, &group_id),
    );
    state.shutdown_started.cancel();
    *state
        .shielded_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let for_me = member_added_for(&group_id, &inviter_hex, &local_hex);
    let (status, body) = post_result(&state, &local_hex, &for_me, &inviter_hex).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    Ok(())
}

// ---- the durable token --------------------------------------------------

/// The handlers refuse a session token on their own as well (#1228's
/// convention), for a caller that reaches them without the route layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_doors_refuse_a_session_actor_in_the_handler() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "7c".repeat(32);
    let member = "bb".repeat(32);
    let statuses = [
        apply_group_metadata_event(
            State(Arc::clone(&state)),
            owner(false),
            Path(group_id.clone()),
            Json(ApplyMetadataEventRequest {
                event_b64: BASE64.encode(b"not json"),
                sender_agent_id: member.clone(),
            }),
        )
        .await
        .into_response()
        .status(),
        get_join_result_inline(
            State(Arc::clone(&state)),
            owner(false),
            Path((group_id.clone(), member.clone())),
        )
        .await
        .into_response()
        .status(),
        apply_join_result_endpoint(
            State(Arc::clone(&state)),
            owner(false),
            Path((group_id.clone(), member.clone())),
            Json(ApplyJoinResultRequest {
                event_b64: BASE64.encode(b"not json"),
                sender_agent_id: member.clone(),
            }),
        )
        .await
        .into_response()
        .status(),
    ];
    for status in statuses {
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    Ok(())
}

/// A session bearer is refused 403 at the route layer, ahead of any body
/// parse, on every method axum routes to a door (HEAD is answered by the GET
/// handler); the durable token passes the gate and meets the handler's own
/// validation (a malformed body answers 400, never 403).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_doors_refuse_a_session_bearer_before_the_body_is_parsed() -> Result<()> {
    use axum::http::Request;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    let (state, _dir) = secure_endpoint_test_state().await?;
    let app = axum::Router::new()
        .route(
            "/groups/:id/apply-metadata-event",
            post(apply_group_metadata_event),
        )
        .route(
            "/groups/:id/join-result/:member",
            get(get_join_result_inline).post(apply_join_result_endpoint),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));
    let session = state.sessions.issue(std::time::Instant::now());
    let member = "cc".repeat(32);
    let doors = [
        ("POST", format!("/groups/{STABLE}/apply-metadata-event")),
        ("POST", format!("/groups/{STABLE}/join-result/{member}")),
        ("GET", format!("/groups/{STABLE}/join-result/{member}")),
        ("HEAD", format!("/groups/{STABLE}/join-result/{member}")),
    ];
    for (method, path) in doors {
        for (bearer, refused) in [(session.as_str(), true), ("test-token", false)] {
            let request = Request::builder()
                .method(method)
                .uri(&path)
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{not json"))?;
            let response = app.clone().oneshot(request).await?;
            if refused {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
            } else {
                assert_ne!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
            }
        }
    }
    Ok(())
}

//! #390 — the join-result staging stores must survive a daemon restart.
//!
//! Before the fix both maps were rebuilt empty on every boot while the
//! roster survived, so an authority restart between staging and delivery
//! orphaned the joiner permanently: a replayed `MemberJoined` for an
//! already-active member is rejected, nothing re-stages the Welcome, and
//! the joiner's poll pulls a permanent `join_result_not_staged` 404. These
//! controls drive the real sidecar save/load, the wipe→persist ordering
//! that keeps a banned group's staging from resurrecting (#384 invariant),
//! and the boot-time poll re-arm decision.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

/// The staged shape the fix cares about: a `MemberAdded` whose Welcome is
/// by-reference, so serving it inline requires BOTH restored maps.
fn member_added_with_welcome_ref(
    group_id: &str,
    member_hex: &str,
    inviter_hex: &str,
    welcome_ref: Option<WelcomeRef>,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.to_string(),
        revision: 1,
        actor: inviter_hex.to_string(),
        agent_id: member_hex.to_string(),
        display_name: None,
        treekem_commit_b64: Some("Y29tbWl0".to_string()),
        treekem_welcome_b64: None,
        welcome_ref,
        treekem_epoch: Some(1),
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        commit: None,
        certificate_b64: None,
    }
}

/// A fresh `AppState` over an existing data dir: the restart. The staging
/// maps start empty exactly as `src/server/mod.rs` builds them; only the
/// loader may repopulate them.
async fn restarted_state(data_dir: &FsPath) -> Result<Arc<AppState>> {
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine-restart.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent-restart.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts-restart.json"))
            .build()
            .await?,
    );
    secure_endpoint_test_state_at(data_dir, agent).await
}

/// The core #390 owner-side repair: stage a join-result + its Welcome blob,
/// restart the daemon, and the engine-A pull lane must still serve the
/// `MemberAdded` with the Welcome inlined.
#[tokio::test]
async fn staged_join_result_and_welcome_survive_restart_and_serve_inline() -> Result<()> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let group_id = "restart-390-group";
    let member_hex = "bb".repeat(32);
    let inviter_hex = "aa".repeat(32);
    let welcome_bytes = b"treekem-welcome-blob-390".to_vec();

    let welcome_ref =
        stage_treekem_welcome(&state, group_id, &member_hex, welcome_bytes.clone()).await;
    let event =
        member_added_with_welcome_ref(group_id, &member_hex, &inviter_hex, Some(welcome_ref));
    stage_join_result(&state, group_id, &member_hex, event).await;
    drop(state);

    let restarted = restarted_state(dir.path()).await?;
    assert!(
        restarted.pending_join_results.read().await.is_empty(),
        "a fresh state must start with empty staging (the pre-fix behavior)"
    );
    load_join_result_staging(&restarted).await;

    let response = get_join_result_inline(
        State(Arc::clone(&restarted)),
        Path((group_id.to_string(), member_hex.clone())),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "restored staging must serve the join-result, body: {body}"
    );
    assert_eq!(body["ok"], true);
    assert!(
        body.to_string().contains(&BASE64.encode(&welcome_bytes)),
        "the served event must carry the Welcome inlined from the restored blob store"
    );
    Ok(())
}

/// TTLs count wall-clock across restarts: entries staged longer ago than
/// their TTL must not be resurrected by the loader.
#[tokio::test]
async fn expired_staging_entries_are_not_restored() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let now = now_millis_u64();
    let stale = now.saturating_sub(PENDING_JOIN_RESULT_TTL.as_millis() as u64 + 60_000);
    let member_hex = "bb".repeat(32);
    let inviter_hex = "aa".repeat(32);
    let entry = |created_at_ms: u64| PendingJoinResult {
        event: member_added_with_welcome_ref("g", &member_hex, &inviter_hex, None),
        created_at_ms,
        delivered_at_ms: None,
        head_attestation: None,
    };
    let welcome = |created_at_ms: u64| PendingWelcome {
        group_id: "g".to_string(),
        joiner_agent: member_hex.clone(),
        bytes: vec![1, 2, 3],
        created_at_ms,
    };
    let sidecar = JoinResultStagingSidecar {
        version: JOIN_RESULT_STAGING_SIDECAR_VERSION,
        join_results: HashMap::from([
            ("g:stale".to_string(), entry(stale)),
            ("g:fresh".to_string(), entry(now)),
        ]),
        welcomes: HashMap::from([
            ("w-stale".to_string(), welcome(stale)),
            ("w-fresh".to_string(), welcome(now)),
        ]),
    };
    tokio::fs::write(
        &state.join_result_staging_path,
        serde_json::to_vec(&sidecar)?,
    )
    .await?;

    load_join_result_staging(&state).await;

    let results = state.pending_join_results.read().await;
    assert!(results.contains_key("g:fresh") && !results.contains_key("g:stale"));
    let welcomes = state.pending_welcomes.read().await;
    assert!(welcomes.contains_key("w-fresh") && !welcomes.contains_key("w-stale"));
    Ok(())
}

/// The departure/ban wipe persists the post-wipe staging, so a restart
/// cannot resurrect a wiped group's staged join-results — the same re-seed
/// class #384 closed for roster state. A second group's staging survives
/// untouched.
#[tokio::test]
async fn wiped_group_staging_does_not_resurrect_after_restart() -> Result<()> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let member_hex = "bb".repeat(32);
    let inviter_hex = "aa".repeat(32);
    for group_id in ["wiped-390-group", "kept-390-group"] {
        let welcome_ref = stage_treekem_welcome(
            &state,
            group_id,
            &member_hex,
            format!("blob-{group_id}").into_bytes(),
        )
        .await;
        let event =
            member_added_with_welcome_ref(group_id, &member_hex, &inviter_hex, Some(welcome_ref));
        stage_join_result(&state, group_id, &member_hex, event).await;
    }

    wipe_local_group_crypto_material(&state, "wiped-390-group", None, "test-departure").await;
    drop(state);

    let restarted = restarted_state(dir.path()).await?;
    load_join_result_staging(&restarted).await;

    let results = restarted.pending_join_results.read().await;
    assert!(
        !results
            .keys()
            .any(|key| key.starts_with("wiped-390-group:")),
        "wiped group's staged join-result must not survive the restart"
    );
    assert!(
        results.keys().any(|key| key.starts_with("kept-390-group:")),
        "unrelated group's staged join-result must survive the restart"
    );
    let welcomes = restarted.pending_welcomes.read().await;
    assert!(welcomes.values().all(|w| w.group_id != "wiped-390-group"));
    assert!(welcomes.values().any(|w| w.group_id == "kept-390-group"));
    Ok(())
}

/// The boot re-arm decision: only foreign-owned, locally-unconverged groups
/// get a poll — a converged group, or one this daemon owns, must not.
#[tokio::test]
async fn respawn_targets_only_unconverged_foreign_groups() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let self_hex = hex::encode(state.agent.agent_id().as_bytes());

    // G1: TreeKEM plane, foreign owner, no local TreeKEM state → re-armed.
    let (mut g1, _o1) = sole_owner_group();
    g1.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    // G2: GSS plane, foreign owner, roster lists self → converged (#297's
    // stop condition), no re-arm.
    let (mut g2, owner2_hex) = sole_owner_group();
    g2.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    g2.add_member(
        self_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(owner2_hex),
        None,
    );
    // G4: GSS plane, foreign owner, roster does NOT list self → re-armed.
    let (mut g4, _o4) = sole_owner_group();
    g4.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    // G3: our own group, keyless — we are the authority; nothing to poll.
    let mut g3 = x0x::groups::GroupInfo::with_policy(
        "G3".to_string(),
        "d".to_string(),
        state.agent.agent_id(),
        "cc".repeat(16),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    g3.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    // G5: locally BANNED — the tombstone deliberately survives departure
    // and both planes read as unconverged, but re-polling the banning admin
    // is unwanted indefinite traffic. Must never be re-armed (cross-review
    // finding 2).
    let (mut g5, owner5_hex) = sole_owner_group();
    g5.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    g5.add_member(
        self_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(owner5_hex.clone()),
        None,
    );
    g5.ban_member(&self_hex, Some(owner5_hex));
    // G6: withdrawn tombstone — the membership ended; nothing to repair.
    let (mut g6, _o6) = sole_owner_group();
    g6.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    g6.withdrawn = true;

    {
        let mut groups = state.named_groups.write().await;
        groups.insert("g1".to_string(), g1);
        groups.insert("g2".to_string(), g2);
        groups.insert("g3".to_string(), g3);
        groups.insert("g4".to_string(), g4);
        groups.insert("g5".to_string(), g5);
        groups.insert("g6".to_string(), g6);
    }

    let mut respawned = respawn_unconverged_join_polls(Arc::clone(&state)).await;
    respawned.sort();
    assert_eq!(
        respawned,
        vec!["g1".to_string(), "g4".to_string()],
        "only the unconverged foreign-owned groups get a re-armed poll; \
         own/converged/banned/withdrawn groups must all be skipped"
    );
    Ok(())
}

/// Why (cross-review finding 1): only the admin that authored the invite
/// stages the join-result, and after a restart the joiner no longer knows
/// which admin that was — the creator alone is the WRONG target whenever
/// the inviter was a different admin. The re-arm must therefore target
/// every active admin (creator included), so the true inviter is always
/// among the polled peers.
#[tokio::test]
async fn respawn_poll_targets_include_every_active_admin() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let self_agent = state.agent.agent_id();
    let self_hex = hex::encode(self_agent.as_bytes());

    let (mut info, creator_hex) = sole_owner_group();
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    // A second admin — the plausible actual inviter post-restart.
    let admin_b = x0x::identity::AgentKeypair::generate()?.agent_id();
    let admin_b_hex = hex::encode(admin_b.as_bytes());
    info.add_member(
        admin_b_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(creator_hex.clone()),
        None,
    );
    // A plain member must NOT be polled.
    let member_c_hex = "dd".repeat(32);
    info.add_member(
        member_c_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(creator_hex.clone()),
        None,
    );

    let targets = respawn_poll_targets(&info, &self_agent, &self_hex)
        .expect("foreign unbanned group must yield poll targets");
    let target_hexes: Vec<String> = targets
        .iter()
        .map(|id| hex::encode(id.as_bytes()))
        .collect();
    assert!(
        target_hexes.contains(&admin_b_hex),
        "the non-creator admin (the possible inviter) must be polled"
    );
    assert!(
        target_hexes.contains(&creator_hex),
        "the creator stays a target"
    );
    assert!(
        !target_hexes.contains(&member_c_hex),
        "plain members are never join-result authorities"
    );
    assert_eq!(targets.len(), 2, "no duplicate or extraneous targets");
    Ok(())
}

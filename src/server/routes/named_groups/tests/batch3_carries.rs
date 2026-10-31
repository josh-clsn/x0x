//! Pins carried into the named-groups tail port: the `MemberJoined` resend
//! cadence under the fetch backoff, the GET join-result door serving a
//! Welcome staged longer ago than stock's 10 minutes, and the shutdown drain
//! releasing an `AppState` held by the tail's own background tasks.

use super::*;

/// The #333 resend runs every 6 s of wall clock while the fetch backs off
/// (2 s, 4 s, 8 s, ...). Over 13.5 s that is two resends (6 s, 12 s) and
/// three fetches (0 s, 2 s, 6 s). A resend gated on the poll's own
/// iterations would land at 6 s and 14 s, so only once in the window.
#[tokio::test]
async fn member_joined_resend_keeps_six_seconds_while_the_fetch_backs_off() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (info, owner_hex) = sole_owner_group();
    let group_id = info.mls_group_id.clone();
    let event_group_id = info.stable_group_id().to_string();
    let joiner_hex = "cd".repeat(32);
    let inviter = x0x::identity::AgentKeypair::generate()?.agent_id();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    let resend_topic = format!("test.resend-cadence.{event_group_id}");
    let event = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_id.clone(),
        stable_group_id: Some(event_group_id.clone()),
        member_agent_id: joiner_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: Some("cadence pin".to_string()),
        inviter_agent_id: owner_hex,
        invite_secret: String::new(),
        ts_ms: 0,
        treekem_key_package_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),
        certificate_b64: None,
        kem_public_key_b64: None,
        kem_signature_b64: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let member_joined = Some(MemberJoinedResend {
        metadata_topic: resend_topic.clone(),
        event,
        payload,
    });
    if let Ok(mut sent) = JOIN_FETCHES_SENT_FOR_TEST.lock() {
        sent.retain(|(g, _)| g != &group_id);
    }

    poll_join_result_until_deadline(
        Arc::clone(&state),
        group_id.clone(),
        event_group_id,
        vec![inviter],
        joiner_hex,
        false,
        member_joined,
        String::new(),
        tokio::time::Instant::now() + Duration::from_millis(13_500),
    )
    .await;
    // The resend sends run in their own tasks; let the last one publish.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resends = state
        .named_group_test_recorders
        .publish_attempts
        .lock()
        .map_err(|_| anyhow::anyhow!("publish-attempt recorder poisoned"))?
        .iter()
        .filter(|(topic, _, _)| topic == &resend_topic)
        .count();
    assert_eq!(
        resends, 2,
        "the MemberJoined resend keeps its 6 s cadence under the fetch backoff"
    );
    let fetches = JOIN_FETCHES_SENT_FOR_TEST
        .lock()
        .map_err(|_| anyhow::anyhow!("fetch recorder poisoned"))?
        .iter()
        .find(|(g, _)| g == &group_id)
        .map_or(0, |(_, n)| *n);
    assert_eq!(fetches, 3, "the fetch itself still backs off");
    Ok(())
}

/// The GET door serves a staged Welcome that is older than stock's 10
/// minute Welcome TTL: the Welcome lives as long as its join result. The
/// entry is aged by its stamps, and a fresh staging runs the Welcome sweep
/// before the door is asked.
#[tokio::test]
async fn the_get_door_serves_a_welcome_staged_more_than_ten_minutes_ago() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (info, owner_hex) = sole_owner_group();
    let group_id = info.stable_group_id().to_string();
    let member_hex = "ab".repeat(32);
    {
        let mut info = info;
        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
    }
    let bytes = b"a Welcome staged eleven minutes ago".to_vec();
    let welcome = stage_treekem_welcome(&state, &group_id, &member_hex, bytes.clone()).await;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.clone(),
        revision: 2,
        actor: owner_hex,
        agent_id: member_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some("Y29tbWl0".to_string()),
        treekem_welcome_b64: None,
        welcome_ref: Some(welcome.clone()),
        treekem_epoch: Some(1),
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        commit: None,
        roster_certificates_b64: Vec::new(),
    };
    stage_join_result(&state, &group_id, &member_hex, event, None).await;

    let age = Duration::from_secs(11 * 60);
    let aged_ms = now_millis_u64().saturating_sub(age.as_millis() as u64);
    let aged_at = Instant::now()
        .checked_sub(age)
        .expect("the monotonic clock reaches back eleven minutes");
    {
        let mut welcomes = state.pending_welcomes.write().await;
        let pending = welcomes
            .get_mut(&welcome.welcome_id)
            .expect("the Welcome is staged");
        pending.created_at_ms = aged_ms;
        pending.created_at = aged_at;
    }
    {
        let mut results = state.pending_join_results.write().await;
        let pending = results
            .get_mut(&join_result_key(&group_id, &member_hex))
            .expect("the join result is staged");
        pending.created_at_ms = aged_ms;
        pending.created_at = aged_at;
    }
    // Any later staging sweeps expired Welcomes.
    stage_treekem_welcome(&state, &group_id, &"ef".repeat(32), b"another".to_vec()).await;

    let response = get_join_result_inline(
        State(Arc::clone(&state)),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), member_hex.clone())),
    )
    .await
    .into_response();
    let status = response.status();
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["event"].to_string().contains(&BASE64.encode(&bytes)),
        "the eleven-minute-old Welcome is served inline: {body}"
    );
    Ok(())
}

fn loopback_daemon_config(root: &std::path::Path) -> Result<crate::server::DaemonConfig> {
    Ok(serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.join("data"),
        "identity_dir": root.join("identity"),
        "bootstrap_peers": [],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": format!(
            "x0x.test.b3.{}.{:08x}",
            std::process::id(),
            rand::random::<u32>()
        )
    }))?)
}

fn loopback_daemon_options() -> crate::server::ServeOptions {
    crate::server::ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..crate::server::ServeOptions::default()
    }
}

/// The tail's own background work holds `AppState`: the boot-time respawned
/// join poll (up to the 24 h horizon) and the abandoned re-key sweep loop
/// (for the daemon's life). Both go through the #1269 detached-task drain,
/// so `shutdown_and_wait` releases the AppState and the Agent and a same-dir
/// relaunch succeeds (#661).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_and_wait_releases_state_held_by_respawned_polls_and_the_sweep() -> Result<()> {
    const LIFECYCLE: Duration = Duration::from_secs(60);
    let root = tempfile::tempdir()?;
    let config = loopback_daemon_config(root.path())?;
    let handle = tokio::time::timeout(
        LIFECYCLE,
        crate::server::serve_with_options(config.clone(), loopback_daemon_options()),
    )
    .await
    .context("daemon starts within 60 s")??;
    let state = handle.test_state.upgrade().context("live daemon state")?;
    let state_weak = Arc::downgrade(&state);
    let agent_weak = Arc::downgrade(&state.agent);

    // A GSS group this daemon joined but whose roster never listed it: the
    // boot respawn polls its creator for the result.
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let group_id = "b3".repeat(16);
    let info = x0x::groups::GroupInfo::new(
        "respawn probe".to_string(),
        String::new(),
        creator,
        group_id.clone(),
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    let respawned = respawn_unconverged_join_polls(Arc::clone(&state)).await;
    assert_eq!(
        respawned,
        vec![group_id],
        "the unconverged join is re-polled"
    );
    drop(state);

    tokio::time::timeout(LIFECYCLE, handle.shutdown_and_wait())
        .await
        .context("shutdown returns within 60 s")?
        .context("shutdown")?;
    assert_eq!(
        (state_weak.strong_count(), agent_weak.strong_count()),
        (0, 0),
        "the AppState and Agent are released when shutdown_and_wait returns"
    );
    let relaunched = tokio::time::timeout(
        LIFECYCLE,
        crate::server::serve_with_options(config, loopback_daemon_options()),
    )
    .await
    .context("relaunch within 60 s")??;
    tokio::time::timeout(LIFECYCLE, relaunched.shutdown_and_wait())
        .await
        .context("relaunched daemon stops within 60 s")??;
    Ok(())
}

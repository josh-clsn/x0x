//! Pins carried into the named-groups tail port: the `MemberJoined` resend
//! cadence under the fetch backoff, the GET join-result door serving a
//! Welcome staged longer ago than stock's 10 minutes, and the shutdown drain
//! releasing an `AppState` held by the tail's own background tasks.

use super::*;

/// A known group nobody answers for: the poll keeps fetching until its
/// deadline. A random id keeps the per-group fetch counter to this test.
async fn unanswered_poll_group(state: &Arc<AppState>) -> (String, String, String) {
    let owner = x0x::identity::AgentKeypair::generate().expect("keypair");
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let id = hex::encode(rand::random::<[u8; 16]>());
    let info = x0x::groups::GroupInfo::with_policy(
        "poll".to_string(),
        String::new(),
        owner.agent_id(),
        id,
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    let group_id = info.mls_group_id.clone();
    let event_group_id = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    if let Ok(mut sent) = JOIN_FETCHES_SENT_FOR_TEST.lock() {
        sent.retain(|(g, _)| g != &group_id);
    }
    (group_id, event_group_id, owner_hex)
}

fn fetches_sent(group_id: &str) -> u64 {
    JOIN_FETCHES_SENT_FOR_TEST
        .lock()
        .map(|sent| {
            sent.iter()
                .find(|(g, _)| g == group_id)
                .map_or(0, |(_, n)| *n)
        })
        .unwrap_or(0)
}

fn resend_probe(
    group_id: &str,
    event_group_id: &str,
    joiner_hex: &str,
    inviter_hex: &str,
    topic: &str,
) -> Result<MemberJoinedResend> {
    let event = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_id.to_string(),
        stable_group_id: Some(event_group_id.to_string()),
        member_agent_id: joiner_hex.to_string(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: Some("cadence pin".to_string()),
        inviter_agent_id: inviter_hex.to_string(),
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
    Ok(MemberJoinedResend {
        metadata_topic: topic.to_string(),
        event,
        payload,
    })
}

fn resends_published(state: &AppState, topic: &str) -> Result<usize> {
    Ok(state
        .named_group_test_recorders
        .publish_attempts
        .lock()
        .map_err(|_| anyhow::anyhow!("publish-attempt recorder poisoned"))?
        .iter()
        .filter(|(t, _, _)| t == topic)
        .count())
}

/// Run the join poll for an unanswered non-TreeKEM join until `window`.
async fn run_unanswered_poll(
    state: &Arc<AppState>,
    await_treekem: bool,
    resend_topic: Option<&str>,
    window: Duration,
) -> Result<String> {
    let (group_id, event_group_id, owner_hex) = unanswered_poll_group(state).await;
    let joiner_hex = hex::encode(rand::random::<[u8; 32]>());
    let inviter = x0x::identity::AgentKeypair::generate()?.agent_id();
    let member_joined = match resend_topic {
        Some(topic) => Some(resend_probe(
            &group_id,
            &event_group_id,
            &joiner_hex,
            &owner_hex,
            topic,
        )?),
        None => None,
    };
    poll_join_result_until_deadline(
        Arc::clone(state),
        group_id.clone(),
        event_group_id,
        vec![inviter],
        joiner_hex,
        await_treekem,
        member_joined,
        String::new(),
        tokio::time::Instant::now() + window,
    )
    .await;
    // The resend sends run in their own tasks; let the last one publish.
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(group_id)
}

/// N-3 / M-2: the #333 resend runs every 6 s of the runtime clock, apart
/// from the fetch schedule. Over 13.5 s that is two resends (6 s, 12 s)
/// next to seven 2 s fetches. A resend checked only on fetch iterations
/// would land once (6 s, then 14 s).
#[tokio::test(start_paused = true)]
async fn member_joined_resend_keeps_six_seconds_while_the_fetch_backs_off() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let topic = format!(
        "test.resend-cadence.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );
    let group_id =
        run_unanswered_poll(&state, false, Some(&topic), Duration::from_millis(13_500)).await?;
    assert_eq!(
        resends_published(&state, &topic)?,
        2,
        "the MemberJoined resend keeps its 6 s cadence"
    );
    assert_eq!(fetches_sent(&group_id), 7, "2 s fetches inside the window");
    Ok(())
}

/// M-2: the resend stops after `MEMBER_JOINED_RESEND_MAX_ATTEMPTS` (100,
/// that is 6 s for 10 minutes), while the poll goes on.
#[tokio::test(start_paused = true)]
async fn member_joined_resend_stops_after_one_hundred_sends() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let topic = format!("test.resend-cap.{}", hex::encode(rand::random::<[u8; 8]>()));
    run_unanswered_poll(&state, false, Some(&topic), Duration::from_secs(700)).await?;
    assert_eq!(MEMBER_JOINED_RESEND_MAX_ATTEMPTS, 100);
    assert_eq!(
        resends_published(&state, &topic)?,
        100,
        "exactly 100 resends, the last at 600 s"
    );
    Ok(())
}

/// I-1: a join poll fetches every 2 s for its first 120 s, as stock did,
/// and backs off only after that (2 s doubling: 120, 122, 126, 134 s).
#[tokio::test(start_paused = true)]
async fn the_join_poll_fetches_every_two_seconds_for_its_first_two_minutes() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let inside = run_unanswered_poll(&state, true, None, Duration::from_secs(119)).await?;
    assert_eq!(fetches_sent(&inside), 60, "0, 2, ..., 118 s");
    let past = run_unanswered_poll(&state, true, None, Duration::from_secs(140)).await?;
    assert_eq!(
        fetches_sent(&past),
        64,
        "the 2 s window, then 120, 122, 126 and 134 s"
    );
    Ok(())
}

/// I-1: an ADR 0107 re-arm polls on this loop with a 120 s deadline and no
/// MemberJoined, so the poll is its only channel. The original result
/// becomes available at 70 s (the inviter answers the first fetch after
/// it): the re-arm must still seat inside its window, burning no epoch.
#[tokio::test(start_paused = true)]
async fn a_rearm_whose_original_result_appears_at_70_s_still_seats() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (group_id, event_group_id, _owner_hex) = unanswered_poll_group(&state).await;
    let joiner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let inviter = x0x::identity::AgentKeypair::generate()?.agent_id();
    let started = tokio::time::Instant::now();
    let answer_state = Arc::clone(&state);
    let answer_group = group_id.clone();
    let answer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(70)).await;
        let before = fetches_sent(&answer_group);
        while fetches_sent(&answer_group) == before {
            if started.elapsed() >= JOIN_REARM_POLL_TIMEOUT {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The fetch reached the inviter, which now holds the original
        // result: the Welcome installs the tree.
        let Ok(bytes) = hex::decode(&answer_group) else {
            return false;
        };
        let local = answer_state.agent.agent_id();
        let seed = agent_treekem_seed(answer_state.agent.as_ref(), &bytes);
        let Ok(tree) = x0x::mls::TreeKemMlsGroup::create(bytes, local, &seed) else {
            return false;
        };
        answer_state
            .treekem_groups
            .write()
            .await
            .insert(answer_group, Arc::new(Mutex::new(tree)));
        true
    });
    poll_join_result_until_deadline(
        Arc::clone(&state),
        group_id.clone(),
        event_group_id,
        vec![inviter],
        joiner_hex,
        true,
        None,
        String::new(),
        started + JOIN_REARM_POLL_TIMEOUT,
    )
    .await;
    assert!(
        answer.await?,
        "a fetch went out after 70 s, inside the window"
    );
    assert!(
        started.elapsed() < JOIN_REARM_POLL_TIMEOUT,
        "the re-arm seated before its deadline ({:?})",
        started.elapsed()
    );
    assert!(state.treekem_groups.read().await.contains_key(&group_id));
    assert!(
        !state
            .last_join_outcomes
            .lock()
            .map_err(|_| anyhow::anyhow!("outcomes poisoned"))?
            .contains_key(&group_id),
        "no timed_out outcome"
    );
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

pub(super) fn loopback_daemon_config(
    root: &std::path::Path,
) -> Result<crate::server::DaemonConfig> {
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

pub(super) fn loopback_daemon_options() -> crate::server::ServeOptions {
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

/// M-1: a poll respawned at boot (no attempt id) finds no pending stub when
/// it times out, so the finalizer has nothing to finalize. It still ends its
/// persisted pin as a live timeout does: the pin keeps authorizing a late
/// result but no longer reads as a pending join, on disk too.
#[tokio::test(start_paused = true)]
async fn a_respawned_poll_that_times_out_ends_its_persisted_pin() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (group_id, event_group_id, owner_hex) = unanswered_poll_group(&state).await;
    let joiner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let key = join_result_key(&event_group_id, &joiner_hex);
    record_expected_join_result_inviter(state.as_ref(), key.clone(), owner_hex.clone());
    persist_join_result_pins(state.as_ref()).await;
    assert!(live_expected_join_result_inviter(state.as_ref(), &key).is_some());

    poll_join_result_until_deadline(
        Arc::clone(&state),
        group_id,
        event_group_id,
        vec![x0x::identity::AgentKeypair::generate()?.agent_id()],
        joiner_hex,
        true,
        None,
        String::new(),
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await;

    assert_eq!(
        expected_join_result_inviter(state.as_ref(), &key).as_deref(),
        Some(owner_hex.as_str()),
        "the pin still authorizes a late result"
    );
    assert!(
        live_expected_join_result_inviter(state.as_ref(), &key).is_none(),
        "the pin no longer reads as a live join"
    );
    let on_disk: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(join_result_pins::pins_path(&state)).await?)?;
    assert_eq!(
        on_disk[&key]["timed_out"],
        serde_json::Value::Bool(true),
        "the persisted pin is timed out: {on_disk}"
    );
    Ok(())
}

/// A TreeKEM group with the creator and one other member holding a leaf,
/// the roster listing that member with its committed KeyPackage.
fn rekey_selector_fixture(
    seed_byte: u8,
) -> Result<(x0x::groups::GroupInfo, x0x::mls::TreeKemMlsGroup, String)> {
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let group_id = vec![seed_byte; 16];
    let mut group = x0x::mls::TreeKemMlsGroup::create(group_id.clone(), creator, &[1; 32])?;
    let member = x0x::identity::AgentKeypair::generate()?.agent_id();
    let member_hex = hex::encode(member.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member, &[seed_byte; 32])?;
    let kp_b64 = BASE64.encode(prepared.key_package_bytes());
    group.add_member(member, prepared.key_package_bytes())?;
    let mut info = x0x::groups::GroupInfo::new(
        "selector".to_string(),
        String::new(),
        creator,
        hex::encode(&group_id),
    );
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    set_committed_key_package(&mut info, &member_hex, &kp_b64);
    Ok((info, group, member_hex))
}

fn set_committed_key_package(info: &mut x0x::groups::GroupInfo, member_hex: &str, kp_b64: &str) {
    info.set_member_treekem_key_package(member_hex, kp_b64.to_string());
}

/// M-3 (re-homed from the fork's `returning_member_is_never_a_rekey_candidate`):
/// a returning member stays Active while its re-key is in flight, even with
/// a fresh KeyPackage on its roster entry and its old leaf in the tree, so
/// upstream's self-leave selector never picks it. A removed member with a
/// live leaf is picked (positive control).
#[test]
fn a_returning_member_is_never_a_self_leave_rekey_candidate() -> Result<()> {
    let (mut info, group, member_hex) = rekey_selector_fixture(0x71)?;
    let fresh = x0x::mls::TreeKemMlsGroup::prepare_member(parse_member(&member_hex)?, &[0x72; 32])?;
    set_committed_key_package(
        &mut info,
        &member_hex,
        &BASE64.encode(fresh.key_package_bytes()),
    );
    assert!(info.has_active_member(&member_hex));
    assert_eq!(outstanding_removed_treekem_leaf(&info, &group), None);

    let (mut removed, group, member_hex) = rekey_selector_fixture(0x73)?;
    removed.remove_member(&member_hex, Some(member_hex.clone()));
    assert_eq!(
        outstanding_removed_treekem_leaf(&removed, &group).map(|(agent, _)| agent),
        Some(member_hex),
        "a removed member with a live leaf is the candidate"
    );
    Ok(())
}

/// M-3 (re-homed from the fork's
/// `a_pending_joiner_with_a_key_package_is_never_a_rekey_candidate`): a
/// pending joiner carries a KeyPackage but no leaf, and is not Removed, so
/// it is never selected.
#[test]
fn a_pending_joiner_with_a_key_package_is_never_a_self_leave_rekey_candidate() -> Result<()> {
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let group_id = vec![0x74; 16];
    let group = x0x::mls::TreeKemMlsGroup::create(group_id.clone(), creator, &[1; 32])?;
    let joiner = x0x::identity::AgentKeypair::generate()?.agent_id();
    let joiner_hex = hex::encode(joiner.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(joiner, &[0x75; 32])?;
    let mut info = x0x::groups::GroupInfo::new(
        "selector".to_string(),
        String::new(),
        creator,
        hex::encode(&group_id),
    );
    info.add_member(
        joiner_hex.clone(),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    set_committed_key_package(
        &mut info,
        &joiner_hex,
        &BASE64.encode(prepared.key_package_bytes()),
    );
    info.members_v2
        .get_mut(&joiner_hex)
        .context("joiner row")?
        .state = x0x::groups::GroupMemberState::Pending;
    assert_eq!(outstanding_removed_treekem_leaf(&info, &group), None);
    Ok(())
}

fn parse_member(hex_id: &str) -> Result<AgentId> {
    let bytes: [u8; 32] = hex::decode(hex_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent id is 32 bytes"))?;
    Ok(AgentId(bytes))
}

/// R-1: a legacy (respawned) poll that times out ends the pin only while no
/// attempt is registered for its key. A fresh invite's attempt owns the pin.
#[tokio::test]
async fn a_legacy_poll_timeout_leaves_a_newer_attempts_pin_alone() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let event_group = hex::encode(rand::random::<[u8; 16]>());
    let member = hex::encode(rand::random::<[u8; 32]>());
    let inviter = hex::encode(rand::random::<[u8; 32]>());
    let key = join_result_key(&event_group, &member);

    record_expected_join_result_inviter(&state, key.clone(), inviter.clone());
    end_legacy_poll_pin(&state, &key).await;
    assert_eq!(
        join_result_pin_view(&state, &key).map(|(_, timed_out, _)| timed_out),
        Some(true),
        "with no attempt registered, the legacy timeout ends the pin"
    );

    record_expected_join_result_inviter(&state, key.clone(), inviter.clone());
    state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            key.clone(),
            PendingJoinAttempt {
                attempt_id: "fresh-attempt".to_string(),
                local_group_key: event_group.clone(),
                invite_fingerprint: "fp".to_string(),
                invite_group_id: event_group.clone(),
                inviter_public_key_b64: String::new(),
                stored_resend: None,
                polls: Vec::new(),
                tasks: Vec::new(),
                listener_token: None,
            },
        );
    end_legacy_poll_pin(&state, &key).await;
    assert_eq!(
        join_result_pin_view(&state, &key).map(|(_, timed_out, _)| timed_out),
        Some(false),
        "a newer attempt's pin stays armed"
    );
    Ok(())
}

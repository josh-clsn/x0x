//! Survivor re-key A2 to A14: the background work these parts spawn runs in
//! the #1269 registries, so `shutdown_and_wait` releases the `AppState` and
//! the `Agent` while that work is still in flight: the KeyPackage requests
//! and sweep, the hole asks, the head-round sends, an obligation send, a
//! quiet survivor's proof, a gap ask, a follow-up ask, a listener answer
//! worker and a handed-off answer send (detached), and a re-seat (shielded,
//! so shutdown waits for it).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::batch3_carries::{loopback_daemon_config, loopback_daemon_options};
use super::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_and_wait_releases_state_held_by_survivor_rekey_tasks() -> Result<()> {
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

    // A TreeKEM room with an admin peer this daemon holds by hash alone. No
    // peer answers, so each send waits on its dial while shutdown begins.
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let peer_hex = "e7".repeat(32);
    let group_id = "b6".repeat(16);
    let mut info = x0x::groups::GroupInfo::new(
        "survivor tasks".to_string(),
        String::new(),
        local,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        peer_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(local_hex),
        None,
    );
    if let Some(seat) = info.members_v2.get_mut(&peer_hex) {
        seat.treekem_key_package_hash = Some("aa".repeat(32));
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    // The KeyPackage request parks at its send until the pause is dropped,
    // so it is still running when shutdown begins.
    let pause = super::super::detached_send_test_seam::arm(
        &super::super::detached_send_test_seam::key_package_catchup_key(&group_id, &peer_hex),
    );
    super::super::committer_leaf::request_key_packages(
        &state,
        &group_id,
        vec![peer_hex.clone()],
        4,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !pause.reached() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        pause.reached(),
        "setup: the KeyPackage request is in flight"
    );
    // The hole ask and the head-round send park at their page request.
    let seam = super::super::detached_send_test_seam::page_request_key;
    let gap_pause = super::super::detached_send_test_seam::arm(&seam(&group_id, &peer_hex, false));
    let round_pause = super::super::detached_send_test_seam::arm(&seam(&group_id, &peer_hex, true));
    super::super::committer_leaf::spawn_hash_only_key_package_sweep(&state);
    super::super::catchup_page_gap::spawn_ask_another_member(&state, &group_id);
    let _ =
        super::super::head_rounds::challenge_admins(&state, &group_id, &[], Duration::ZERO).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !(gap_pause.reached() && round_pause.reached()) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(gap_pause.reached(), "setup: the hole ask is in flight");
    assert!(
        round_pause.reached(),
        "setup: the head-round send is in flight"
    );
    let peer_id = parse_agent_id_hex(&peer_hex).map_err(anyhow::Error::msg)?;
    let seam = super::super::detached_send_test_seam::arm;
    let page_key = super::super::detached_send_test_seam::page_request_key;
    let mut held = Vec::new();

    // Each leg below has its own room, so each parks on its own seam.
    // A12: a truncated page's follow-up ask.
    let room = seat_room(&state, "b7", &peer_hex).await;
    held.push((
        "the follow-up ask",
        seam(&page_key(&room, &peer_hex, false)),
    ));
    assert!(super::super::gap_catchup::spawn_follow_up(
        &state,
        &room,
        peer_id,
        (0, 0)
    ));
    // A12: a gap ask.
    let room = seat_room(&state, "b8", &peer_hex).await;
    held.push(("the gap ask", seam(&page_key(&room, &peer_hex, false))));
    super::super::gap_catchup::request_treekem_catchup_for_gap(&state, &room, vec![peer_id], None)
        .await;
    // A10: a quiet survivor's proof.
    let room = seat_room(&state, "b9", &peer_hex).await;
    held.push(("prove_held", seam(&format!("prove-held:{room}"))));
    super::super::rekey_obligations::spawn_prove_held(
        &state,
        super::super::rekey_obligations::HeldRekey::for_test(&room, peer_id, 1),
        true,
    );
    // A9: an obligation send, held by its delivery stand-in.
    let room = seat_room(&state, "ba", &peer_hex).await;
    let attempt_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let started = Arc::clone(&attempt_started);
        super::rekey_obligations::install_deliver(
            &state,
            Arc::new(move |_recipient, _event| {
                started.store(true, std::sync::atomic::Ordering::SeqCst);
                Box::pin(std::future::pending())
            }),
        );
    }
    let owner_hex = hex::encode(local.as_bytes());
    state.treekem_event_log.write().await.insert(
        room.clone(),
        std::iter::once(NamedGroupMetadataEvent::MemberRemoved {
            group_id: room.clone(),
            revision: 2,
            actor: owner_hex.clone(),
            agent_id: "ee".repeat(32),
            treekem_commit_b64: None,
            treekem_epoch: Some(1),
            secret_epoch: None,
            commit: Some(super::fake_group_state_commit(&room, 2, &owner_hex)),
        })
        .collect(),
    );
    let refused = super::super::rekey_obligations::owe(
        &state,
        &room,
        std::slice::from_ref(&peer_hex),
        super::super::rekey_obligations::Rekey {
            epoch: 1,
            revision: 2,
        },
        super::super::rekey_obligations::Rekey {
            epoch: 1,
            revision: 2,
        },
    )
    .await;
    assert!(refused.is_empty(), "setup: the obligation is owed");
    super::rekey_obligations::skew(&state, 6_000).await;
    super::super::rekey_obligations::step(&state).await;
    // A12: a listener answer worker.
    let room = seat_room(&state, "bb", &peer_hex).await;
    let answer_hold = Arc::new(tokio::sync::Semaphore::new(0));
    *state
        .named_group_test_recorders
        .catchup_serve_hold
        .lock()
        .unwrap() = Some(Arc::clone(&answer_hold));
    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: room.clone(),
        requester_agent_id: peer_hex.clone(),
        from_revision: 0,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: 1,
        signed_by: None,
        head_challenge: None,
    };
    assert_eq!(
        super::super::catchup_serve::dispatch(
            &state,
            peer_id,
            x0x::identity::MachineId([0x5e; 32]),
            true,
            request,
            1
        ),
        super::super::catchup_serve::Dispatched::Started,
        "setup: the answer worker starts"
    );
    // A14: a handed-off catch-up answer send.
    let send_hold = Arc::new(tokio::sync::Semaphore::new(0));
    *state
        .named_group_test_recorders
        .answer_send_hold
        .lock()
        .unwrap() = Some(Arc::clone(&send_hold));
    super::super::catchup_serve::send_answer(&state, peer_id, vec![0], &room, "test").await;
    // A13: a re-seat, waiting for the room's membership lock this test holds.
    let reseat_room = seat_room(&state, "bc", &peer_hex).await;
    let room_lock = group_membership_lock(&state, &reseat_room)
        .await
        .lock_owned()
        .await;
    super::super::seat_reseat::spawn(&state, &reseat_room, &peer_hex);

    let recorders = &state.named_group_test_recorders;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let all_in_flight = || {
        held.iter().all(|(_, pause)| pause.reached())
            && attempt_started.load(std::sync::atomic::Ordering::SeqCst)
            && !recorders.catchup_serves_started.lock().unwrap().is_empty()
            && recorders
                .answer_sends_started
                .load(std::sync::atomic::Ordering::SeqCst)
                == 1
    };
    while !all_in_flight() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for (leg, pause) in &held {
        assert!(pause.reached(), "setup: {leg} is in flight");
    }
    assert!(
        all_in_flight(),
        "setup: the send, the worker and the answer are in flight"
    );
    drop(state);

    // The re-seat is shielded: shutdown waits for it past the abort grace.
    let shutdown = tokio::spawn(handle.shutdown_and_wait());
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(room_lock);
    tokio::time::timeout(LIFECYCLE, shutdown)
        .await
        .context("shutdown returns within 60 s")?
        .context("shutdown task")?
        .context("shutdown")?;
    assert_eq!(
        (state_weak.strong_count(), agent_weak.strong_count()),
        (0, 0),
        "the AppState and Agent are released when shutdown_and_wait returns"
    );
    assert!(
        super::super::seat_reseat::FINISHED_FOR_TEST
            .lock()
            .unwrap()
            .contains(&reseat_room),
        "the shielded re-seat ran to its end"
    );
    drop(pause);
    drop(gap_pause);
    drop(round_pause);
    drop(held);
    answer_hold.close();
    send_hold.close();
    Ok(())
}

/// A TreeKEM room `{tag}{tag}…` holding this daemon and `peer_hex` as an
/// admin by hash alone.
async fn seat_room(state: &AppState, tag: &str, peer_hex: &str) -> String {
    let local = state.agent.agent_id();
    let room = tag.repeat(16);
    let mut info = x0x::groups::GroupInfo::new(
        "survivor tasks".to_string(),
        String::new(),
        local,
        room.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        peer_hex.to_string(),
        x0x::groups::GroupRole::Admin,
        Some(hex::encode(local.as_bytes())),
        None,
    );
    if let Some(seat) = info.members_v2.get_mut(peer_hex) {
        seat.treekem_key_package_hash = Some("aa".repeat(32));
    }
    state.named_groups.write().await.insert(room.clone(), info);
    room
}

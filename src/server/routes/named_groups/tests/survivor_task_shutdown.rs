//! Survivor re-key A2 to A14: the background work these parts spawn (the
//! KeyPackage requests and sweep, the hole asks, the head-round sends, the
//! re-key obligation worker, the catch-up follow-up asks and the handed-off
//! catch-up answer sends) runs in the #1269 detached-task registry, so
//! `shutdown_and_wait` releases the `AppState` and the `Agent` while that
//! work is still in flight.

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
    // A12: a truncated page's follow-up ask parks at the same page request.
    let peer_id = parse_agent_id_hex(&peer_hex).map_err(anyhow::Error::msg)?;
    assert!(super::super::gap_catchup::spawn_follow_up(
        &state,
        &group_id,
        peer_id,
        (0, 0)
    ));
    // A14: a handed-off catch-up answer send parks until the hold closes.
    let answer_hold = Arc::new(tokio::sync::Semaphore::new(0));
    *state
        .named_group_test_recorders
        .answer_send_hold
        .lock()
        .unwrap() = Some(Arc::clone(&answer_hold));
    super::super::catchup_serve::send_answer(&state, peer_id, vec![0], &group_id, "test").await;
    let started = || {
        state
            .named_group_test_recorders
            .answer_sends_started
            .load(std::sync::atomic::Ordering::SeqCst)
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while started() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(started(), 1, "setup: the answer send is in flight");
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
    drop(pause);
    drop(gap_pause);
    drop(round_pause);
    answer_hold.close();
    Ok(())
}

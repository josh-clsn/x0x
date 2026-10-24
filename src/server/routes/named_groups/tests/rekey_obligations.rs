//! Survivor re-key A9: the obligation worker on a daemon's own state. The
//! network is a test stand-in (`rekey_obligation_deliver`), so a test sees
//! every send and decides how it ends. See
//! `docs/adr/transient/T-survivor-rekey-obligation.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::rekey_obligations::{
    self, ObligationState, Rekey, RekeyObligation, TestDeliver, MAX_DELAY_MS, MAX_IN_FLIGHT,
};
use super::epoch_ahead_catchup::{two_member_treekem_group, LeaveFixture};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn hex_of(id: &x0x::identity::AgentId) -> String {
    hex::encode(id.as_bytes())
}

pub(super) fn install_deliver(state: &AppState, deliver: TestDeliver) {
    *state
        .named_group_test_recorders
        .rekey_obligation_deliver
        .lock()
        .unwrap() = Some(deliver);
}

/// `state`'s obligation to `recipient` in `group_key`, if any.
pub(super) async fn owed(
    state: &AppState,
    group_key: &str,
    recipient: &str,
) -> Option<RekeyObligation> {
    state
        .rekey_obligations
        .lock()
        .await
        .get(group_key, recipient)
        .cloned()
}

/// Move the obligation clock on by `ms`.
pub(super) async fn skew(state: &AppState, ms: u64) {
    state.rekey_obligations.lock().await.skew_clock(ms);
}

/// Poll `check` for up to two seconds of real time.
pub(super) async fn eventually<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if check().await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A removal at `revision` that the owner logged, as the A4 log holds it.
fn logged_removal(fixture: &LeaveFixture, revision: u64, epoch: u64) -> NamedGroupMetadataEvent {
    let owner_hex = hex_of(&fixture.state.agent.agent_id());
    NamedGroupMetadataEvent::MemberRemoved {
        group_id: fixture.group_id.clone(),
        revision,
        actor: owner_hex.clone(),
        agent_id: "ee".repeat(32),
        treekem_commit_b64: None,
        treekem_epoch: Some(epoch),
        secret_epoch: None,
        commit: Some(super::fake_group_state_commit(
            &fixture.group_id,
            revision,
            &owner_hex,
        )),
    }
}

async fn log_events(fixture: &LeaveFixture, events: Vec<NamedGroupMetadataEvent>) {
    fixture
        .state
        .treekem_event_log
        .write()
        .await
        .insert(fixture.group_id.clone(), events.into_iter().collect());
}

/// Seat `count` more active members on the owner's roster.
async fn seat_members(fixture: &LeaveFixture, count: u8) -> Vec<String> {
    let owner_hex = hex_of(&fixture.state.agent.agent_id());
    let members: Vec<String> = (0..count)
        .map(|n| format!("{:02x}", 0x40 + n).repeat(32))
        .collect();
    let mut groups = fixture.state.named_groups.write().await;
    let info = groups.get_mut(&fixture.group_id).unwrap();
    for member in &members {
        info.add_member(
            member.clone(),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
    }
    members
}

fn rekey(epoch: u64, revision: u64) -> Rekey {
    Rekey { epoch, revision }
}

#[tokio::test]
async fn ack_without_proof_keeps_the_obligation() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let member = hex_of(&fixture.member_id);
    let removal = logged_removal(&fixture, 7, 3);
    log_events(
        &fixture,
        vec![logged_removal(&fixture, 5, 2), removal.clone()],
    )
    .await;
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&sent);
    install_deliver(
        state,
        Arc::new(move |recipient, event| {
            seen.lock().unwrap().push((recipient, event));
            Box::pin(async { Ok(()) })
        }),
    );
    let refused = rekey_obligations::owe(
        state,
        &fixture.group_id,
        std::slice::from_ref(&member),
        rekey(3, 7),
        rekey(3, 7),
    )
    .await;
    assert!(refused.is_empty());
    rekey_obligations::step(state).await;
    assert!(sent.lock().unwrap().is_empty(), "not due before 6 s");

    skew(state, 6_000).await;
    rekey_obligations::step(state).await;
    let delivered = eventually(|| async {
        owed(state, &fixture.group_id, &member)
            .await
            .is_some_and(|owed| owed.state == ObligationState::DeliveredUnproven)
    })
    .await;
    assert!(delivered, "the acknowledged send is recorded");
    let owed_now = owed(state, &fixture.group_id, &member)
        .await
        .expect("an acknowledgement is not proof: the obligation stays");
    let now = state.rekey_obligations.lock().await.clock.now_ms();
    assert!(owed_now.next_attempt_at_ms + 1_000 >= now + MAX_DELAY_MS);
    assert!(owed_now.next_attempt_at_ms <= now + MAX_DELAY_MS);
    assert_eq!(
        sent.lock().unwrap().clone(),
        vec![(member.clone(), removal)],
        "the commits the log holds from the owed revision, and nothing before it"
    );
    Ok(())
}

#[tokio::test]
async fn at_most_four_attempts_run_at_once_and_none_twice() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let members = seat_members(&fixture, 6).await;
    log_events(&fixture, vec![logged_removal(&fixture, 7, 3)]).await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let running = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (gate, running, most, started) = (
            Arc::clone(&gate),
            Arc::clone(&running),
            Arc::clone(&most),
            Arc::clone(&started),
        );
        install_deliver(
            state,
            Arc::new(move |recipient, _event| {
                started.lock().unwrap().push(recipient);
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                let (gate, running) = (Arc::clone(&gate), Arc::clone(&running));
                Box::pin(async move {
                    gate.acquire().await.unwrap().forget();
                    running.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
            }),
        );
    }
    let refused =
        rekey_obligations::owe(state, &fixture.group_id, &members, rekey(3, 7), rekey(3, 7)).await;
    assert!(refused.is_empty());
    skew(state, 6_000).await;
    rekey_obligations::step(state).await;
    assert!(
        eventually(|| async { running.load(Ordering::SeqCst) == MAX_IN_FLIGHT }).await,
        "four sends start"
    );
    rekey_obligations::step(state).await;
    rekey_obligations::step(state).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        started.lock().unwrap().len(),
        MAX_IN_FLIGHT,
        "no fifth, none twice"
    );

    gate.add_permits(MAX_IN_FLIGHT);
    assert!(
        eventually(|| async {
            let store = state.rekey_obligations.lock().await;
            members
                .iter()
                .filter(|member| {
                    store.get(&fixture.group_id, member).is_some_and(|owed| {
                        owed.state == ObligationState::DeliveredUnproven && !owed.in_flight
                    })
                })
                .count()
                == MAX_IN_FLIGHT
        })
        .await
    );
    rekey_obligations::step(state).await;
    gate.add_permits(16);
    assert!(eventually(|| async { started.lock().unwrap().len() == members.len() }).await);
    rekey_obligations::step(state).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let started = started.lock().unwrap().clone();
    let unique: std::collections::HashSet<&String> = started.iter().collect();
    assert_eq!(
        started.len(),
        members.len(),
        "each survivor once: {started:?}"
    );
    assert_eq!(unique.len(), members.len());
    assert!(most.load(Ordering::SeqCst) <= MAX_IN_FLIGHT);
    Ok(())
}

#[tokio::test]
async fn payload_missing_from_the_log_is_kept_and_said_once() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let member = hex_of(&fixture.member_id);
    // The log holds only a commit before the owed one.
    log_events(&fixture, vec![logged_removal(&fixture, 5, 2)]).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    install_deliver(
        state,
        Arc::new(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }),
    );
    rekey_obligations::owe(
        state,
        &fixture.group_id,
        std::slice::from_ref(&member),
        rekey(3, 7),
        rekey(3, 7),
    )
    .await;
    for (wait_ms, attempts) in [(6_000u64, 1u32), (15_000, 2), (30_000, 3)] {
        skew(state, wait_ms).await;
        rekey_obligations::step(state).await;
        let counted = eventually(|| async {
            owed(state, &fixture.group_id, &member)
                .await
                .is_some_and(|owed| owed.attempt_count == attempts && !owed.in_flight)
        })
        .await;
        assert!(counted, "attempt {attempts} is counted");
    }
    let kept = owed(state, &fixture.group_id, &member).await.expect("kept");
    assert_eq!(kept.state, ObligationState::Owed);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing to send");
    assert_eq!(
        state.rekey_obligations.lock().await.missing_reports(),
        1,
        "said once"
    );
    Ok(())
}

#[tokio::test]
async fn refused_obligation_keeps_the_blind_schedule() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let members = seat_members(&fixture, 3).await;
    state.rekey_obligations.lock().await.set_caps(1, 4096);
    let refused = rekey_obligations::owe(
        state,
        &fixture.group_id,
        &members[..2],
        rekey(3, 7),
        rekey(3, 7),
    )
    .await;
    assert_eq!(refused, members[1..2].to_vec(), "over the room cap");
    assert!(owed(state, &fixture.group_id, &members[0]).await.is_some());
    assert!(owed(state, &fixture.group_id, &members[1]).await.is_none());

    // A record that cannot be written is no record: the survivors keep the
    // blind schedule and nothing is held in memory.
    state.rekey_obligations.lock().await.set_caps(16, 4096);
    let blocker = state.treekem_dir.join("not-a-directory");
    std::fs::write(&blocker, b"x")?;
    state
        .rekey_obligations
        .lock()
        .await
        .set_path(blocker.join("rekey-obligations.json"));
    let refused =
        rekey_obligations::owe(state, &fixture.group_id, &members, rekey(4, 8), rekey(4, 8)).await;
    assert_eq!(refused, members);
    assert!(owed(state, &fixture.group_id, &members[2]).await.is_none());
    assert_eq!(
        owed(state, &fixture.group_id, &members[0])
            .await
            .map(|owed| owed.through_epoch),
        Some(3),
        "an unwritten change is not kept"
    );

    // A room that is gone owes nothing: every survivor keeps the blind schedule.
    let refused = rekey_obligations::owe(
        state,
        "no-such-room",
        &members[..1],
        rekey(4, 8),
        rekey(4, 8),
    )
    .await;
    assert_eq!(refused, members[..1].to_vec());
    Ok(())
}

/// A departure wipes the room's obligations from memory and disk, and an
/// `owe` that comes after it brings none back.
#[tokio::test]
async fn a_departure_wipes_the_rooms_obligations_and_none_comes_back() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let member = hex_of(&fixture.member_id);
    let refused = rekey_obligations::owe(
        state,
        &fixture.group_id,
        std::slice::from_ref(&member),
        rekey(3, 7),
        rekey(3, 7),
    )
    .await;
    assert!(refused.is_empty());
    let file = state.treekem_dir.join(rekey_obligations::OBLIGATIONS_FILE);
    assert!(std::fs::read_to_string(&file)?.contains(&member));

    // As every departure does: the roster drops the room, then the wipe runs.
    state.named_groups.write().await.remove(&fixture.group_id);
    wipe_local_group_crypto_material(state, &fixture.group_id, None, "test_departure").await;
    assert!(owed(state, &fixture.group_id, &member).await.is_none());
    assert!(
        !std::fs::read_to_string(&file)?.contains(&member),
        "and on disk"
    );

    let refused = rekey_obligations::owe(
        state,
        &fixture.group_id,
        std::slice::from_ref(&member),
        rekey(4, 8),
        rekey(4, 8),
    )
    .await;
    assert_eq!(refused, vec![member.clone()], "a gone room owes nothing");
    assert!(owed(state, &fixture.group_id, &member).await.is_none());
    Ok(())
}

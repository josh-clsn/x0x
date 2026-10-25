//! Survivor re-key A12: a catch-up never holds up the apply that needs it,
//! the catch-up listener answers requests side by side, and a member an add
//! seats keeps the bounded resend schedule. See
//! `docs/adr/transient/T-catchup-off-the-apply-path.md`.
//!
//! The cast is the survivor fixture: the owner (the only admin), the member
//! R (a key, not a daemon), and the members S1 and S2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::catchup_serve::{dispatch, Dispatched};
use super::super::signed_catchup::page_request;
use super::epoch_ahead_catchup::{
    deliver_catchup, live_epoch, roster_head, survivor_relay_fixture, two_member_treekem_group,
    SurvivorRelay,
};
use super::rekey_obligations::{eventually, hex_of};
use super::signer_delivery::{direct_add_route, newcomer, owner_extension, published};
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::Semaphore;

/// The bound an apply that needs a catch-up must return within.
const APPLY_BOUND: Duration = Duration::from_secs(1);

/// The owner removes `member_hex` through its route; the removal it sealed.
async fn remove(cast: &SurvivorRelay, member_hex: &str) -> NamedGroupMetadataEvent {
    let owner = &cast.fixture.state;
    let response = remove_named_group_member(
        State(Arc::clone(owner)),
        owner_extension(),
        Path((cast.fixture.group_id.clone(), member_hex.to_string())),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner removes");
    published(owner, |event| {
        matches!(
            event,
            NamedGroupMetadataEvent::MemberRemoved {
                agent_id,
                treekem_commit_b64: Some(_),
                ..
            } if agent_id == member_hex
        )
    })
    .expect("the removal is published")
}

/// `state`'s page requests wait, unsent, until the returned semaphore is
/// closed: every peer it asks is silent.
fn silence_peers(state: &AppState) -> Arc<Semaphore> {
    let hold = Arc::new(Semaphore::new(0));
    *state
        .named_group_test_recorders
        .catchup_page_send_hold
        .lock()
        .unwrap() = Some(Arc::clone(&hold));
    hold
}

/// How many page requests `state` sent to `peer`.
fn asked(state: &AppState, peer: &x0x::identity::AgentId) -> usize {
    let peer = hex_of(peer);
    state
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(asked, _)| *asked == peer)
        .count()
}

async fn parked(state: &AppState, group_id: &str) -> Vec<NamedGroupMetadataEvent> {
    state
        .treekem_pending_events
        .read()
        .await
        .get(group_id)
        .map(|queue| queue.iter().map(|pending| pending.event.clone()).collect())
        .unwrap_or_default()
}

/// S1 holds the owner's head, epoch and roster.
async fn s1_follows_the_owner(cast: &SurvivorRelay) {
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    for member in [
        hex_of(&cast.fixture.member_id),
        hex_of(&cast.s1.agent.agent_id()),
        hex_of(&cast.s2.agent.agent_id()),
    ] {
        assert_eq!(
            roster_head(&cast.s1, group_id, &member).await,
            roster_head(owner, group_id, &member).await,
            "S1 holds the owner's head and sees {member} as the owner does"
        );
    }
    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        live_epoch(owner, group_id).await
    );
}

/// The owner removes R, then S2. S1 gets only the second removal, while
/// every peer it asks is silent: the apply parks it and returns at once.
/// The page with the first removal then applies, and the parked one after
/// it, in order.
#[tokio::test]
async fn an_apply_that_needs_a_catch_up_returns_while_the_peers_are_silent() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&cast.s2.agent.agent_id())).await;
    let hold = silence_peers(&cast.s1);

    let applied = tokio::time::timeout(
        APPLY_BOUND,
        apply_named_group_metadata_event(&cast.s1, second.clone(), owner_id, true, None),
    )
    .await
    .expect("the apply returns while the peers it asks are silent");
    assert!(!applied.accepted, "the second removal waits for the first");
    assert_eq!(parked(&cast.s1, group_id).await, vec![second]);
    assert!(
        eventually(|| async { asked(&cast.s1, &owner_id) == 1 }).await,
        "the catch-up asks the owner, off the apply"
    );
    assert!(cast
        .s1
        .treekem_gap_catchups
        .lock()
        .unwrap()
        .in_flight(group_id));

    deliver_catchup(&cast.s1, &owner_id, group_id, first).await;
    assert!(parked(&cast.s1, group_id).await.is_empty());
    s1_follows_the_owner(&cast).await;

    hold.close();
    assert!(
        eventually(|| async {
            !cast
                .s1
                .treekem_gap_catchups
                .lock()
                .unwrap()
                .in_flight(group_id)
        })
        .await,
        "the flight ends once its asks return"
    );
    cast.shutdown().await;
    Ok(())
}

/// Two events for one room both need the catch-up while its asks are
/// unanswered: one flight runs, and it asks the owner once, even after the
/// throttle window has passed.
#[tokio::test]
async fn two_gaps_in_one_room_run_one_catch_up() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&cast.s2.agent.agent_id())).await;
    let (newcomer_id, package) = newcomer(0x51)?;
    let third = direct_add_route(owner, group_id, &hex_of(&newcomer_id), "Nan", &package).await;
    let hold = silence_peers(&cast.s1);

    for event in [second.clone(), third.clone()] {
        let applied = tokio::time::timeout(
            APPLY_BOUND,
            apply_named_group_metadata_event(&cast.s1, event, owner_id, true, None),
        )
        .await
        .expect("each apply returns while the peers it asks are silent");
        assert!(!applied.accepted);
        assert!(eventually(|| async { asked(&cast.s1, &owner_id) >= 1 }).await);
        // The owner's throttle window passes while its ask is unanswered.
        cast.s1.treekem_catchup_throttle.write().await.clear();
    }
    assert_eq!(parked(&cast.s1, group_id).await, vec![second, third]);
    assert_eq!(
        cast.s1
            .named_group_test_recorders
            .gap_catchup_flights
            .load(Ordering::SeqCst),
        1,
        "one catch-up for the room"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        asked(&cast.s1, &owner_id),
        1,
        "the owner is asked once while its answer is outstanding"
    );

    deliver_catchup(&cast.s1, &owner_id, group_id, first).await;
    assert!(parked(&cast.s1, group_id).await.is_empty());
    s1_follows_the_owner(&cast).await;
    assert!(
        roster_head(&cast.s1, group_id, &hex_of(&newcomer_id))
            .await
            .2,
        "the add applied after both removals"
    );
    hold.close();
    cast.shutdown().await;
    Ok(())
}

/// Every answer `handle_treekem_catchup_request` begins waits until the
/// returned semaphore is closed.
fn hold_answers(state: &AppState) -> Arc<Semaphore> {
    let hold = Arc::new(Semaphore::new(0));
    *state
        .named_group_test_recorders
        .catchup_serve_hold
        .lock()
        .unwrap() = Some(Arc::clone(&hold));
    hold
}

fn answers_started(state: &AppState) -> Vec<String> {
    state
        .named_group_test_recorders
        .catchup_serves_started
        .lock()
        .unwrap()
        .clone()
}

fn bare_request(requester: &x0x::identity::AgentId, from_revision: u64) -> TreeKemCatchupRequest {
    TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: "ab".repeat(16),
        requester_agent_id: hex_of(requester),
        from_revision,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: 1,
        signed_by: None,
        head_challenge: None,
    }
}

/// Five requesters ask while no answer can finish: four answers run at
/// once, the fifth waits for a slot, and the listener never waits.
#[tokio::test]
async fn the_listener_answers_requests_side_by_side() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let hold = hold_answers(&state);
    let requesters: Vec<x0x::identity::AgentId> =
        (1..=5u8).map(|n| x0x::identity::AgentId([n; 32])).collect();
    for requester in &requesters {
        assert_eq!(
            dispatch(&state, *requester, true, bare_request(requester, 0)),
            Dispatched::Started
        );
    }
    assert!(eventually(|| async { answers_started(&state).len() >= 4 }).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        answers_started(&state).len(),
        4,
        "four answers run at once, and no more"
    );
    hold.close();
    assert!(
        eventually(|| async { answers_started(&state).len() == requesters.len() }).await,
        "the fifth gets a slot when one frees"
    );
    Ok(())
}

/// One requester floods the listener while its answers cannot finish;
/// another requester asks once. The flood holds one slot, and the other
/// requester is answered beside it.
#[tokio::test]
async fn a_flooding_requester_does_not_starve_another() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let hold = hold_answers(&state);
    let flooder = x0x::identity::AgentId([7; 32]);
    let other = x0x::identity::AgentId([8; 32]);
    for n in 0..20 {
        dispatch(&state, flooder, true, bare_request(&flooder, n));
    }
    assert_eq!(
        dispatch(&state, other, true, bare_request(&other, 0)),
        Dispatched::Started
    );
    assert!(eventually(|| async { answers_started(&state).len() >= 2 }).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = answers_started(&state);
    assert_eq!(
        started,
        vec![hex_of(&flooder), hex_of(&other)],
        "the flooder holds one slot and the other requester is answered"
    );
    hold.close();
    Ok(())
}

/// The listener's answer is the answer a direct call gives.
#[tokio::test]
async fn a_dispatched_answer_is_the_direct_answer() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let s1_id = cast.s1.agent.agent_id();
    remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let request = page_request(&cast.s1, group_id, None)
        .await
        .expect("S1 asks");
    let responses = || {
        owner
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .unwrap()
            .clone()
    };
    handle_treekem_catchup_request(owner, &s1_id, true, request.clone()).await;
    let direct = responses();
    assert_eq!(direct.len(), 1, "the direct call answers");
    owner.treekem_catchup_throttle.write().await.clear();
    dispatch(owner, s1_id, true, request);
    assert!(eventually(|| async { responses().len() == 2 }).await);
    assert_eq!(responses()[1], direct[0], "the same page, byte for byte");
    cast.shutdown().await;
    Ok(())
}

/// The resend schedules `state` started, by event kind.
fn blind_schedules(state: &AppState) -> Vec<(&'static str, Vec<String>)> {
    state
        .named_group_test_recorders
        .control_redelivery_recipients
        .lock()
        .unwrap()
        .clone()
}

/// A direct add and an approved join request seat a member with no join
/// result to poll: its Welcome goes on the bounded schedule (6 to 60 s),
/// not only at +0 and +8 s.
#[tokio::test]
async fn a_member_an_add_seats_keeps_the_blind_schedule() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let (newcomer_id, package) = newcomer(0x52)?;
    direct_add_route(
        owner,
        &cast.fixture.group_id,
        &hex_of(&newcomer_id),
        "Nan",
        &package,
    )
    .await;
    assert_eq!(
        blind_schedules(owner),
        vec![("member_added", vec![hex_of(&newcomer_id)])]
    );
    cast.shutdown().await;

    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let group_id = &fixture.group_id;
    let (requester_id, requester_package) = newcomer(0x53)?;
    let requester_hex = hex_of(&requester_id);
    let request_id = {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group");
        let mut request = x0x::groups::JoinRequest::new(
            group_id.clone(),
            requester_hex.clone(),
            None,
            now_millis_u64(),
        );
        request.treekem_key_package_b64 = Some(requester_package);
        let request_id = request.request_id.clone();
        info.join_requests.insert(request_id.clone(), request);
        info.recompute_state_hash();
        request_id
    };
    let response = approve_join_request(
        State(Arc::clone(state)),
        owner_extension(),
        Path((group_id.clone(), request_id)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner approves");
    assert_eq!(
        blind_schedules(state),
        vec![("join_request_approved", vec![requester_hex])]
    );
    Ok(())
}

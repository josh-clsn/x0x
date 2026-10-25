//! Survivor re-key A12: a catch-up ask never holds up the apply or the
//! listener that needs it, the catch-up listener answers requests side by
//! side for proven requesters only, and a member an add seats keeps the
//! bounded resend schedule. See
//! `docs/adr/transient/T-catchup-off-the-apply-path.md`.
//!
//! The cast is the survivor fixture: the owner (the only admin), the member
//! R (a key, not a daemon), and the members S1 and S2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::catchup_serve::{dispatch, Dispatched};
use super::super::signed_catchup::{page_request, sign_page_request_with};
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

/// The bound an apply, or the listener's handling of one message, must
/// return within while every peer is silent.
const BOUND: Duration = Duration::from_secs(1);

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

/// The owner adds a newcomer through the direct-add route; the add.
async fn add(
    cast: &SurvivorRelay,
    seed: u8,
) -> Result<(x0x::identity::AgentId, NamedGroupMetadataEvent)> {
    let (newcomer_id, package) = newcomer(seed)?;
    let event = direct_add_route(
        &cast.fixture.state,
        &cast.fixture.group_id,
        &hex_of(&newcomer_id),
        "Nan",
        &package,
    )
    .await;
    Ok((newcomer_id, event))
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

/// The gap asks `state` registered to `peer`, by the revision asked from.
/// An ask is registered before the apply that makes it returns.
fn gap_asks(state: &AppState, peer: &x0x::identity::AgentId) -> Vec<u64> {
    let peer = hex_of(peer);
    state
        .named_group_test_recorders
        .gap_asks
        .lock()
        .unwrap()
        .iter()
        .filter(|(asked, _)| *asked == peer)
        .map(|(_, revision)| *revision)
        .collect()
}

/// How many page requests `state` handed to the transport for `peer`.
fn page_requests_to(state: &AppState, peer: &x0x::identity::AgentId) -> usize {
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

async fn head_revision(state: &AppState, group_id: &str) -> u64 {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("group")
        .state_revision
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

async fn apply_within_bound(
    state: &Arc<AppState>,
    event: NamedGroupMetadataEvent,
    sender: x0x::identity::AgentId,
) -> ApplyMetadataResult {
    tokio::time::timeout(
        BOUND,
        apply_named_group_metadata_event(state, event, sender, true, None),
    )
    .await
    .expect("the apply returns while the peers it asks are silent")
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
    let head = head_revision(&cast.s1, group_id).await;

    let applied = apply_within_bound(&cast.s1, second.clone(), owner_id).await;
    assert!(!applied.accepted, "the second removal waits for the first");
    assert_eq!(parked(&cast.s1, group_id).await, vec![second]);
    assert_eq!(
        gap_asks(&cast.s1, &owner_id),
        vec![head],
        "the owner is asked"
    );
    assert!(cast
        .s1
        .treekem_gap_catchups
        .lock()
        .unwrap()
        .in_flight(group_id));
    assert!(
        eventually(|| async { page_requests_to(&cast.s1, &owner_id) == 1 }).await,
        "the ask is handed to the transport, off the apply"
    );

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

/// Two events for one room both need the catch-up from the same head while
/// its asks are unanswered: one flight, one ask to the owner, even after the
/// throttle window has passed. A peer only the second event names is asked
/// at once, without waiting for the owner's answer.
#[tokio::test]
async fn two_gaps_at_one_head_ask_each_peer_once() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let s2_id = cast.s2.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&s2_id)).await;
    let (newcomer_id, third) = add(&cast, 0x51).await?;
    let hold = silence_peers(&cast.s1);
    let head = head_revision(&cast.s1, group_id).await;

    let applied = apply_within_bound(&cast.s1, second.clone(), owner_id).await;
    assert!(!applied.accepted);
    assert!(
        gap_asks(&cast.s1, &s2_id).is_empty(),
        "the removal does not ask S2"
    );
    // The owner's throttle window passes while its ask is unanswered.
    cast.s1.treekem_catchup_throttle.write().await.clear();
    let applied = apply_within_bound(&cast.s1, third.clone(), owner_id).await;
    assert!(!applied.accepted);

    assert_eq!(parked(&cast.s1, group_id).await, vec![second, third]);
    assert_eq!(
        cast.s1
            .named_group_test_recorders
            .gap_catchup_flights
            .load(Ordering::SeqCst),
        1,
        "one catch-up for the room"
    );
    assert_eq!(
        gap_asks(&cast.s1, &owner_id),
        vec![head],
        "the owner is asked once while its answer is outstanding"
    );
    assert_eq!(
        gap_asks(&cast.s1, &s2_id),
        vec![head],
        "S2 is asked at once"
    );
    assert!(
        eventually(|| async { page_requests_to(&cast.s1, &s2_id) == 1 }).await,
        "S2's ask goes out while the owner's waits"
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

/// The owner's first ask waits on a silent transport. A page moves S1's
/// head, and a later gap then asks the owner again, from the new head.
#[tokio::test]
async fn a_later_gap_asks_the_owner_again_from_the_new_head() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&cast.s2.agent.agent_id())).await;
    let (_, _third) = add(&cast, 0x54).await?;
    let (_, fourth) = add(&cast, 0x55).await?;
    let hold = silence_peers(&cast.s1);
    let before = head_revision(&cast.s1, group_id).await;

    apply_within_bound(&cast.s1, second, owner_id).await;
    deliver_catchup(&cast.s1, &owner_id, group_id, first).await;
    let moved = head_revision(&cast.s1, group_id).await;
    assert_eq!(moved, before + 2, "the page and the parked removal applied");

    let applied = apply_within_bound(&cast.s1, fourth.clone(), owner_id).await;
    assert!(!applied.accepted, "the second add waits for the first");
    assert_eq!(parked(&cast.s1, group_id).await, vec![fourth]);
    assert_eq!(
        gap_asks(&cast.s1, &owner_id),
        vec![before, moved],
        "the owner is asked from the new head while the old ask still waits"
    );
    hold.close();
    cast.shutdown().await;
    Ok(())
}

/// S1 parks the second removal; the first then arrives live, not by a
/// page. The parked removal applies right after it.
#[tokio::test]
async fn a_live_apply_of_the_missing_commit_replays_the_parked_one() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&cast.s2.agent.agent_id())).await;
    let hold = silence_peers(&cast.s1);

    apply_within_bound(&cast.s1, second.clone(), owner_id).await;
    assert_eq!(parked(&cast.s1, group_id).await, vec![second]);
    // This apply also replays the parked removal, so it gets more than the
    // bound.
    let applied = apply_named_group_metadata_event(&cast.s1, first, owner_id, true, None).await;
    assert!(applied.accepted, "the first removal applies live");
    assert!(parked(&cast.s1, group_id).await.is_empty());
    s1_follows_the_owner(&cast).await;
    hold.close();
    cast.shutdown().await;
    Ok(())
}

/// S1 is three events behind: two removals and an add. Every page the owner
/// serves is truncated, and every follow-up ask S1 sends waits on a silent
/// transport. The listener reads on, and each page that moves S1's head asks
/// for the next one while the earlier asks still wait (fix round 2, N-1): S1
/// pages all the way through. A page that does not move the head asks
/// nothing more, and the listener still answers the owner's request.
#[tokio::test]
async fn catch_up_pages_all_the_way_through_while_follow_ups_wait() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&cast.s2.agent.agent_id())).await;
    let (newcomer_id, third) = add(&cast, 0x56).await?;
    let hold = silence_peers(&cast.s1);
    let answers = hold_answers(&cast.s1);
    let page = |event: NamedGroupMetadataEvent| {
        let response = TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.clone(),
            events: vec![event],
            truncated: true,
            responder_state_hash: None,
            log_evicted_through: None,
            target_member_id: None,
            target_member_key_package_b64: None,
            signed_by: None,
            head_proof: None,
        };
        x0x::direct::DirectMessage::new_verified(
            owner_id,
            x0x::identity::MachineId([0; 32]),
            serde_json::to_vec(&response).unwrap(),
            true,
            None,
        )
    };
    let follow_ups = || {
        cast.s1
            .named_group_test_recorders
            .follow_ups_started
            .load(Ordering::SeqCst)
    };
    let in_flight = || {
        cast.s1
            .treekem_gap_catchups
            .lock()
            .unwrap()
            .follow_ups_in_flight()
    };

    for (n, event) in [first.clone(), second, third].into_iter().enumerate() {
        tokio::time::timeout(BOUND, on_catchup_direct_message(&cast.s1, &page(event)))
            .await
            .expect("the listener reads on while the follow-ups wait");
        assert_eq!(follow_ups(), n + 1, "page {} asks for the next", n + 1);
        assert_eq!(in_flight(), n + 1, "the earlier asks still wait");
    }
    s1_follows_the_owner(&cast).await;
    assert!(
        roster_head(&cast.s1, group_id, &hex_of(&newcomer_id))
            .await
            .2
    );

    tokio::time::timeout(BOUND, on_catchup_direct_message(&cast.s1, &page(first)))
        .await
        .expect("a replayed page is read at once");
    assert_eq!(
        follow_ups(),
        3,
        "a page that moved nothing asks nothing more"
    );

    let request = page_request(owner, group_id, None)
        .await
        .expect("the owner asks S1");
    let asked = x0x::direct::DirectMessage::new_verified(
        owner_id,
        x0x::identity::MachineId([0; 32]),
        serde_json::to_vec(&request).unwrap(),
        true,
        None,
    );
    tokio::time::timeout(BOUND, on_catchup_direct_message(&cast.s1, &asked))
        .await
        .expect("a request is dispatched at once");
    assert!(
        eventually(|| async { answers_started(&cast.s1) == vec![hex_of(&owner_id)] }).await,
        "S1 answers while its follow-ups wait"
    );
    answers.close();
    hold.close();
    cast.shutdown().await;
    Ok(())
}

/// S1 parks the second removal. While the live first removal's replay runs,
/// the add parks too, after the replay drained the queue, as a park that
/// lands during another replay does. The replay runs once more, because it
/// moved the head while an event stayed parked (fix round 2, N-5).
#[tokio::test]
async fn an_event_parked_during_a_replay_applies_when_the_replay_moves_the_head() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let first = remove(&cast, &hex_of(&cast.fixture.member_id)).await;
    let second = remove(&cast, &hex_of(&cast.s2.agent.agent_id())).await;
    let (newcomer_id, third) = add(&cast, 0x57).await?;
    let hold = silence_peers(&cast.s1);

    apply_within_bound(&cast.s1, second.clone(), owner_id).await;
    assert_eq!(parked(&cast.s1, group_id).await, vec![second]);
    *cast
        .s1
        .named_group_test_recorders
        .replay_park_during_pass
        .lock()
        .unwrap() = Some(PendingTreeKemMetadataEvent {
        event: third,
        sender: owner_id,
        queued_at: std::time::Instant::now(),
    });
    // This apply also replays two events, so it gets more than the bound.
    let applied = apply_named_group_metadata_event(&cast.s1, first, owner_id, true, None).await;
    assert!(applied.accepted);
    assert!(parked(&cast.s1, group_id).await.is_empty());
    s1_follows_the_owner(&cast).await;
    assert!(
        roster_head(&cast.s1, group_id, &hex_of(&newcomer_id))
            .await
            .2
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

/// A room `state` knows, with `members` active on its roster.
async fn room_with(state: &AppState, room: &str, members: &[x0x::identity::AgentId]) {
    let mut info = x0x::groups::GroupInfo::new(
        "room".to_string(),
        String::new(),
        state.agent.agent_id(),
        room.to_string(),
    );
    for member in members {
        info.add_member(hex_of(member), x0x::groups::GroupRole::Member, None, None);
    }
    state
        .named_groups
        .write()
        .await
        .insert(room.to_string(), info);
}

fn room(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn bare_request(
    requester: &x0x::identity::AgentId,
    room: &str,
    from_revision: u64,
) -> TreeKemCatchupRequest {
    TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: room.to_string(),
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

const MACHINE: x0x::identity::MachineId = x0x::identity::MachineId([0; 32]);

fn verified_dispatch(
    state: &Arc<AppState>,
    requester: x0x::identity::AgentId,
    room: &str,
    from_revision: u64,
) -> Dispatched {
    dispatch(
        state,
        requester,
        MACHINE,
        true,
        bare_request(&requester, room, from_revision),
        1_000,
    )
}

/// Five requesters ask while no answer can finish: four answers run at
/// once and every slot is taken, so the fifth waits; it runs when one
/// frees. The listener never waits.
#[tokio::test]
async fn the_listener_answers_requests_side_by_side() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let hold = hold_answers(&state);
    let requesters: Vec<x0x::identity::AgentId> =
        (1..=5u8).map(|n| x0x::identity::AgentId([n; 32])).collect();
    room_with(&state, &room(0xab), &requesters).await;
    for requester in &requesters {
        assert_eq!(
            verified_dispatch(&state, *requester, &room(0xab), 0),
            Dispatched::Started
        );
    }
    assert!(eventually(|| async { answers_started(&state).len() >= 4 }).await);
    assert_eq!(
        state.treekem_catchup_serve.free_slots(),
        0,
        "every slot taken"
    );
    assert_eq!(
        answers_started(&state).len(),
        4,
        "four answers run at once, and no more can start"
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
    for n in 0..20u8 {
        room_with(&state, &room(n), &[flooder, other]).await;
    }
    for n in 0..20u8 {
        verified_dispatch(&state, flooder, &room(n), 0);
    }
    assert_eq!(
        verified_dispatch(&state, other, &room(0), 0),
        Dispatched::Started
    );
    assert!(eventually(|| async { answers_started(&state).len() >= 2 }).await);
    let mut started = answers_started(&state);
    started.sort();
    assert_eq!(
        started,
        vec![hex_of(&flooder), hex_of(&other)],
        "the flooder holds one slot and the other requester is answered"
    );
    assert_eq!(
        state.treekem_catchup_serve.free_slots(),
        2,
        "the flooder's waiting requests take no slot"
    );
    hold.close();
    Ok(())
}

/// A survivor S has one answer running and one request waiting. A forger
/// that claims S's id, over a transport that cannot verify it, gets no
/// place: S's waiting request stays. A replay of S's own older signed
/// request cannot take its fresher one's place either (N-2).
#[tokio::test]
async fn a_forger_cannot_push_out_a_survivors_waiting_request() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let hold = hold_answers(&state);
    let survivor = x0x::identity::AgentKeypair::generate()?;
    let survivor_id = survivor.agent_id();
    let signed = |room: &str, from_revision: u64| {
        let mut request = bare_request(&survivor_id, room, from_revision);
        sign_page_request_with(&survivor, &mut request);
        request
    };
    let running = room(0xaa);
    let waiting_room = room(0xbb);
    room_with(&state, &running, &[survivor_id]).await;
    room_with(&state, &waiting_room, &[survivor_id]).await;
    let machine = |n: u8| x0x::identity::MachineId([n; 32]);
    let captured = signed(&waiting_room, 7);
    assert_eq!(
        dispatch(
            &state,
            survivor_id,
            machine(1),
            false,
            signed(&running, 7),
            1_000
        ),
        Dispatched::Started
    );
    assert!(eventually(|| async { answers_started(&state).len() == 1 }).await);
    assert_eq!(
        dispatch(
            &state,
            survivor_id,
            machine(1),
            false,
            signed(&waiting_room, 9),
            1_000
        ),
        Dispatched::Queued
    );

    let forger = x0x::identity::AgentKeypair::generate()?;
    for n in 0..20u8 {
        let room = if n % 2 == 0 {
            waiting_room.clone()
        } else {
            room(n)
        };
        let mut unsigned = bare_request(&survivor_id, &room, 99);
        assert_eq!(
            dispatch(
                &state,
                survivor_id,
                machine(100 + n),
                false,
                unsigned.clone(),
                1_000
            ),
            Dispatched::Dropped,
            "an unsigned claim proves no one"
        );
        sign_page_request_with(&forger, &mut unsigned);
        assert_eq!(
            dispatch(
                &state,
                survivor_id,
                machine(100 + n),
                false,
                unsigned,
                1_000
            ),
            Dispatched::Dropped,
            "another key's signature does not prove the survivor"
        );
    }
    assert_eq!(
        dispatch(&state, survivor_id, machine(2), false, captured, 1_000),
        Dispatched::Dropped,
        "a replay of the survivor's older request does not take the fresher one's place"
    );
    assert_eq!(
        state.treekem_catchup_serve.waiting(&survivor_id),
        Some(vec![(waiting_room, "page".to_string(), 9)]),
        "the survivor's own fresh request still waits"
    );
    hold.close();
    Ok(())
}

/// A flood of unverified requests from one machine has at most its burst
/// of signatures checked; another machine's request is still checked
/// (N-3).
#[tokio::test]
async fn a_machine_flooding_unverified_requests_is_checked_a_burst_at_most() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let hold = hold_answers(&state);
    let member = x0x::identity::AgentKeypair::generate()?;
    let member_id = member.agent_id();
    room_with(&state, &room(0xcc), &[member_id]).await;
    let checks = || {
        state
            .named_group_test_recorders
            .catchup_signature_checks
            .load(Ordering::SeqCst)
    };
    let flooding = x0x::identity::MachineId([9; 32]);
    for n in 0..100u64 {
        let mut request = bare_request(&member_id, &room(0xcc), n);
        sign_page_request_with(&member, &mut request);
        dispatch(&state, member_id, flooding, false, request, 1_000);
    }
    let flood_checks = checks();
    assert!(
        (16..=18).contains(&flood_checks),
        "about one burst checked, not 100: {flood_checks}"
    );
    let mut request = bare_request(&member_id, &room(0xcc), 200);
    sign_page_request_with(&member, &mut request);
    dispatch(
        &state,
        member_id,
        x0x::identity::MachineId([10; 32]),
        false,
        request,
        1_000,
    );
    assert_eq!(checks(), flood_checks + 1, "another machine is checked");
    hold.close();
    Ok(())
}

/// A requester the room's roster does not hold gets no place, whether its
/// transport is verified or its request is self-signed (N-4).
#[tokio::test]
async fn a_requester_off_the_roster_gets_no_place() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let hold = hold_answers(&state);
    let member = x0x::identity::AgentId([11; 32]);
    room_with(&state, &room(0xdd), &[member]).await;
    let sybil = x0x::identity::AgentKeypair::generate()?;
    let sybil_id = sybil.agent_id();
    let mut signed = bare_request(&sybil_id, &room(0xdd), 0);
    sign_page_request_with(&sybil, &mut signed);
    assert_eq!(
        dispatch(&state, sybil_id, MACHINE, false, signed, 1_000),
        Dispatched::Dropped
    );
    assert_eq!(
        verified_dispatch(&state, sybil_id, &room(0xdd), 0),
        Dispatched::Dropped
    );
    assert_eq!(
        verified_dispatch(&state, member, &room(0xee), 0),
        Dispatched::Dropped,
        "a room this daemon does not hold"
    );
    assert_eq!(
        verified_dispatch(&state, member, &room(0xdd), 0),
        Dispatched::Started
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
    let bytes = serde_json::to_vec(&request)?.len();
    dispatch(owner, s1_id, MACHINE, true, request, bytes);
    assert!(eventually(|| async { responses().len() == 2 }).await);
    assert_eq!(responses()[1], direct[0], "the same page, byte for byte");
    cast.shutdown().await;
    Ok(())
}

fn schedules(
    recorder: &std::sync::Mutex<Vec<(&'static str, Vec<String>)>>,
) -> Vec<(&'static str, Vec<String>)> {
    recorder.lock().unwrap().clone()
}

/// A direct add and an approved join request seat a member with no join
/// result to poll. Survivor re-key A13: the seat obligation carries its
/// seat, so it gets no blind schedule; past the obligations' cap it gets the
/// schedule's direct sends (6 to 60 s), with no room-wide republish.
#[tokio::test]
async fn a_member_an_add_seats_keeps_the_resend_schedule() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let (newcomer_id, _) = add(&cast, 0x52).await?;
    let recorders = &owner.named_group_test_recorders;
    assert!(
        super::rekey_obligations::owed(owner, &cast.fixture.group_id, &hex_of(&newcomer_id))
            .await
            .is_some(),
        "the seat is owed"
    );
    assert!(schedules(&recorders.seated_member_resends).is_empty());
    assert!(schedules(&recorders.control_redelivery_recipients).is_empty());
    cast.shutdown().await;

    // Past the cap, the seated member keeps the direct sends.
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    owner.rekey_obligations.lock().await.set_caps(0, 4096);
    let (newcomer_id, _) = add(&cast, 0x58).await?;
    let recorders = &owner.named_group_test_recorders;
    assert_eq!(
        schedules(&recorders.seated_member_resends),
        vec![("member_added", vec![hex_of(&newcomer_id)])]
    );
    let republishing = schedules(&recorders.control_redelivery_recipients);
    assert_eq!(republishing.len(), 1, "the refused survivors keep theirs");
    assert!(!republishing[0].1.contains(&hex_of(&newcomer_id)));
    cast.shutdown().await;

    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let group_id = &fixture.group_id;
    state.rekey_obligations.lock().await.set_caps(0, 4096);
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
    let recorders = &state.named_group_test_recorders;
    assert_eq!(
        schedules(&recorders.seated_member_resends),
        vec![("join_request_approved", vec![requester_hex])]
    );
    Ok(())
}

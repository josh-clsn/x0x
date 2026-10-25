//! Survivor re-key A13: a member seated by a direct add or an approved join
//! request is owed its seat until it proves it holds it. See
//! `docs/adr/transient/T-seat-obligation.md`.
//!
//! The cast is the survivor fixture (the owner, R, S1 and S2) and a sibling
//! device N, a daemon that knows the room but holds no tree, as Noetic's
//! sibling admission leaves it before its seat arrives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::rekey_obligations::{self, ObligationState};
use super::epoch_ahead_catchup::{live_epoch, survivor_relay_fixture, SurvivorRelay};
use super::rekey_obligations::{
    eventually, hex_of, idle, install_deliver, owed, set_connected, skew,
};
use super::signer_delivery::{direct_add_route, owner_extension};
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct Sibling {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
    id: x0x::identity::AgentId,
    hex: String,
    package_b64: String,
}

/// N: knows the room as the owner did before the add, with no tree, and
/// resolves the owner's Welcome references in process.
async fn sibling(cast: &SurvivorRelay) -> Result<Sibling> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let group_id = &cast.fixture.group_id;
    let id = state.agent.agent_id();
    let seed = agent_treekem_seed(state.agent.as_ref(), &hex::decode(group_id)?);
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(id, &seed)?;
    let package_b64 = BASE64.encode(prepared.key_package_bytes());
    let known = cast
        .fixture
        .state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("the owner's room");
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), known);
    *state
        .named_group_test_recorders
        .welcome_source
        .lock()
        .unwrap() = Some(Arc::clone(&cast.fixture.state));
    Ok(Sibling {
        state,
        _dir: dir,
        id,
        hex: hex_of(&id),
        package_b64,
    })
}

fn epoch_of(event: &NamedGroupMetadataEvent) -> u64 {
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            treekem_epoch: Some(epoch),
            ..
        } => *epoch,
        other => panic!("not a TreeKEM add: {other:?}"),
    }
}

/// The signed request `state`'s `prove_held` sent to `author`, once sent.
async fn held_proof(state: &AppState, author: &x0x::identity::AgentId) -> TreeKemCatchupRequest {
    let author_hex = hex_of(author);
    assert!(
        eventually(|| async {
            state
                .named_group_test_recorders
                .held_proofs_sent
                .load(Ordering::SeqCst)
                >= 1
        })
        .await,
        "a held proof goes to the author"
    );
    let payload = state
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(peer, _)| *peer == author_hex)
        .map(|(_, payload)| payload.clone())
        .expect("the held proof was recorded");
    serde_json::from_slice(&payload).expect("a page request")
}

/// Route the owner's obligation sends: to N through its direct listener
/// path while `awake`, and to S1 and S2 always.
fn route_sends(cast: &SurvivorRelay, n: &Sibling, awake: &Arc<AtomicBool>) {
    let owner_id = cast.fixture.state.agent.agent_id();
    let (awake, n_state, n_hex) = (Arc::clone(awake), Arc::clone(&n.state), n.hex.clone());
    let survivors = [Arc::clone(&cast.s1), Arc::clone(&cast.s2)];
    install_deliver(
        &cast.fixture.state,
        Arc::new(move |recipient, event| {
            let target = if recipient == n_hex {
                awake.load(Ordering::SeqCst).then(|| Arc::clone(&n_state))
            } else {
                survivors
                    .iter()
                    .find(|state| hex_of(&state.agent.agent_id()) == recipient)
                    .cloned()
            };
            Box::pin(async move {
                let Some(target) = target else {
                    return Err("unreachable".to_string());
                };
                let applied =
                    apply_direct_named_group_metadata_event(&target, event, owner_id, true).await;
                if applied.accepted {
                    Ok(())
                } else {
                    Err(format!("{applied:?}"))
                }
            })
        }),
    );
}

/// The owner's staged Welcome the seat event names.
fn welcome_id_of(seat: &NamedGroupMetadataEvent) -> String {
    match seat {
        NamedGroupMetadataEvent::MemberAdded {
            welcome_ref: Some(welcome),
            ..
        } => welcome.welcome_id.clone(),
        other => panic!("no Welcome reference: {other:?}"),
    }
}

/// Drop `seat` from the owner's catch-up log, as eviction past the room's
/// 128 events does.
async fn evict_from_log(state: &AppState, seat: &NamedGroupMetadataEvent) {
    let mut log = state.treekem_event_log.write().await;
    for events in log.values_mut() {
        events.retain(|held| held != seat);
    }
}

/// The owner's latest add naming `member`, as published.
fn latest_add(state: &AppState, member_hex: &str) -> NamedGroupMetadataEvent {
    super::signer_delivery::published(state, |event| {
        matches!(event, NamedGroupMetadataEvent::MemberAdded { agent_id, .. } if agent_id == member_hex)
    })
    .expect("the add is published")
}

async fn reseats(state: &AppState) -> u64 {
    state.rekey_obligations.lock().await.reseats
}

/// The owner restarts: its staging file and its obligations file are read
/// back into a fresh memory.
async fn restart_staging_and_obligations(owner: &Arc<AppState>) {
    save_join_result_staging(owner)
        .await
        .expect("staging written");
    owner.pending_welcomes.write().await.clear();
    owner.seat_welcome_pins.lock().unwrap().clear();
    load_join_result_staging(owner).await;
    let groups = owner.named_groups.read().await.clone();
    let loaded = load_rekey_obligations(
        &owner.treekem_dir,
        &groups,
        &hex_of(&owner.agent.agent_id()),
        &*owner.treekem_event_log.read().await,
    )
    .await;
    *owner.rekey_obligations.lock().await = loaded;
}

async fn seated(state: &AppState, group_id: &str, member_hex: &str) -> bool {
    state.treekem_groups.read().await.contains_key(group_id)
        && state
            .named_groups
            .read()
            .await
            .get(group_id)
            .is_some_and(|info| info.has_active_member(member_hex))
}

/// A request from `state` at its own head, signed by it.
async fn signed_head_request(
    state: &AppState,
    group_id: &str,
    epoch: u64,
) -> TreeKemCatchupRequest {
    let mut request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.to_string(),
        requester_agent_id: hex_of(&state.agent.agent_id()),
        from_revision: 0,
        from_treekem_epoch: epoch,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: 1,
        signed_by: None,
        head_challenge: None,
    };
    super::super::signed_catchup::sign_page_request(state, &mut request);
    request
}

/// The owner direct-adds N while N sleeps for more than ten minutes:
/// nothing reaches it. N wakes, the owner's link to it comes back, and the
/// seat obligation seats it, with no new invite. Only N's own proof then
/// settles the obligation (and m-7: an offline newcomer lands from a later
/// send).
#[tokio::test]
async fn a_sibling_asleep_past_ten_minutes_is_seated_when_it_returns() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let n = sibling(&cast).await?;
    let asleep = Arc::new(AtomicBool::new(true));
    {
        let (asleep, n_state, n_hex) = (Arc::clone(&asleep), Arc::clone(&n.state), n.hex.clone());
        let survivors = [Arc::clone(&cast.s1), Arc::clone(&cast.s2)];
        install_deliver(
            owner,
            Arc::new(move |recipient, event| {
                let target = if recipient == n_hex {
                    (!asleep.load(Ordering::SeqCst)).then(|| Arc::clone(&n_state))
                } else {
                    survivors
                        .iter()
                        .find(|state| hex_of(&state.agent.agent_id()) == recipient)
                        .cloned()
                };
                Box::pin(async move {
                    let Some(target) = target else {
                        return Err("unreachable".to_string());
                    };
                    // The direct listener's path, which answers a re-key from
                    // its author with a signed request (prove_held).
                    let applied =
                        apply_direct_named_group_metadata_event(&target, event, owner_id, true)
                            .await;
                    if applied.accepted {
                        Ok(())
                    } else {
                        Err(format!("{applied:?}"))
                    }
                })
            }),
        );
    }
    let add = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let epoch = epoch_of(&add);
    assert_eq!(
        owed(owner, group_id, &n.hex)
            .await
            .map(|owed| owed.through_epoch),
        Some(epoch),
        "the seated member is owed its seat"
    );

    // N sleeps through 6 + 15 + 30 + 60 + 120 + 240 s and three minutes more.
    for (wait_ms, attempts) in [
        (6_000u64, 1u32),
        (15_000, 2),
        (30_000, 3),
        (60_000, 4),
        (120_000, 5),
        (240_000, 6),
    ] {
        skew(owner, wait_ms).await;
        rekey_obligations::step(owner).await;
        let counted = eventually(|| async {
            owed(owner, group_id, &n.hex)
                .await
                .is_some_and(|owed| owed.attempt_count == attempts)
                && idle(owner, group_id, &n.hex).await
        })
        .await;
        assert!(counted, "attempt {attempts}");
    }
    skew(owner, 180_000).await;
    assert!(!seated(&n.state, group_id, &n.hex).await, "N is not seated");

    // N wakes and its link comes back: the obligation sends its seat at once.
    asleep.store(false, Ordering::SeqCst);
    set_connected(owner, &[&n.hex]);
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async { seated(&n.state, group_id, &n.hex).await }).await,
        "N is seated from the obligation"
    );
    assert_eq!(live_epoch(&n.state, group_id).await, epoch);
    assert!(
        eventually(|| async {
            owed(owner, group_id, &n.hex)
                .await
                .is_some_and(|owed| owed.state == ObligationState::DeliveredUnproven)
        })
        .await,
        "delivered, still unproven"
    );

    // Review S-3: N, quiet, proves its seat on its own: the seat came from
    // its author, so N answered with one signed request from its new head.
    let proof = held_proof(&n.state, &owner_id).await;
    handle_treekem_catchup_request(owner, &n.id, false, proof).await;
    assert!(
        eventually(|| async { owed(owner, group_id, &n.hex).await.is_none() }).await,
        "N's own held proof settles its seat"
    );
    cast.shutdown().await;
    Ok(())
}

/// The seat obligation settles on N's own proof at or past the seat's
/// epoch, and on nothing weaker: a request below the epoch, or one that
/// claims N without its signature.
#[tokio::test]
async fn the_seat_settles_only_on_the_members_own_proof() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let add = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let epoch = epoch_of(&add);
    let settled = || async {
        super::rekey_obligations::settles_done(owner).await;
        owed(owner, group_id, &n.hex).await.is_none()
    };

    let below = signed_head_request(&n.state, group_id, epoch - 1).await;
    handle_treekem_catchup_request(owner, &n.id, false, below).await;
    assert!(!settled().await, "a request below the seat's epoch");

    let mut claimed = signed_head_request(&n.state, group_id, epoch).await;
    claimed.signed_by = None;
    handle_treekem_catchup_request(owner, &n.id, false, claimed).await;
    assert!(!settled().await, "a claimed sender, unsigned");

    let forged = {
        let mut request = signed_head_request(&n.state, group_id, epoch).await;
        let other = x0x::identity::AgentKeypair::generate()?;
        super::super::signed_catchup::sign_page_request_with(&other, &mut request);
        request
    };
    handle_treekem_catchup_request(owner, &n.id, false, forged).await;
    assert!(!settled().await, "another key's signature");

    let proof = signed_head_request(&n.state, group_id, epoch).await;
    handle_treekem_catchup_request(owner, &n.id, false, proof).await;
    assert!(
        eventually(|| async { owed(owner, group_id, &n.hex).await.is_none() }).await,
        "N's signed request at the seat's epoch settles it"
    );
    cast.shutdown().await;
    Ok(())
}

/// A retried direct add of a member already seated answers 409 as before,
/// and delivers the seat again and makes the seat obligation due now.
#[tokio::test]
async fn a_retried_add_answers_409_and_redelivers_the_seat() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    skew(owner, 1_000).await;
    owner
        .named_group_test_recorders
        .direct_deliveries
        .lock()
        .unwrap()
        .clear();

    let response = add_named_group_member(
        State(Arc::clone(owner)),
        owner_extension(),
        Path(group_id.clone()),
        Json(AddNamedGroupMemberRequest {
            agent_id: n.hex.clone(),
            display_name: Some("Sibling".to_string()),
            treekem_key_package_b64: Some(n.package_b64.clone()),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(body["error"], "member already present");
    assert_eq!(body["redelivered"], true);
    let delivered = owner
        .named_group_test_recorders
        .direct_deliveries
        .lock()
        .unwrap()
        .clone();
    assert!(
        delivered
            .iter()
            .any(|(recipient, _, kind, _)| *recipient == n.hex && *kind == "member_added"),
        "the seat goes to N again: {delivered:?}"
    );
    // Due now: no later than the obligation clock reads after the retry.
    let due = owed(owner, group_id, &n.hex)
        .await
        .map(|owed| owed.next_attempt_at_ms)
        .expect("the seat is owed");
    let now = owner.rekey_obligations.lock().await.clock.now_ms();
    assert!(due <= now, "the seat obligation is due now ({due} > {now})");
    cast.shutdown().await;
    Ok(())
}

/// The seat obligation is on disk before the add route returns, so a
/// restart keeps it.
#[tokio::test]
async fn the_seat_obligation_survives_restart() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let add = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let groups = owner.named_groups.read().await.clone();
    let loaded = load_rekey_obligations(
        &owner.treekem_dir,
        &groups,
        &hex_of(&owner.agent.agent_id()),
        &*owner.treekem_event_log.read().await,
    )
    .await;
    assert_eq!(
        loaded.get(group_id, &n.hex).map(|owed| owed.through_epoch),
        Some(epoch_of(&add))
    );
    cast.shutdown().await;
    Ok(())
}

/// N is away for 25 hours, and the owner restarts in the middle. The seat's
/// Welcome is pinned while the seat is owed, so it survives both the TTL and
/// the restart, while an unpinned Welcome as old does not. N comes back and
/// is seated from the kept Welcome; once its proof settles the seat, the pin
/// goes.
#[tokio::test]
async fn a_member_back_after_25_hours_is_seated_from_the_kept_welcome() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let n = sibling(&cast).await?;
    let add = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let welcome_id = welcome_id_of(&add);
    assert!(
        super::super::seat_welcome_pin::pinned(owner, &welcome_id),
        "the seat pins its Welcome"
    );
    assert!(owed(owner, group_id, &n.hex)
        .await
        .is_some_and(|owed| owed.seat));

    // An unpinned Welcome as old, for contrast.
    let control = "c0".repeat(32);
    let day_and_an_hour = 25 * 60 * 60 * 1000;
    {
        let mut welcomes = owner.pending_welcomes.write().await;
        let mut stale = welcomes.get(&welcome_id).expect("staged").clone();
        stale.joiner_agent = "ab".repeat(32);
        welcomes.insert(control.clone(), stale);
        for pending in welcomes.values_mut() {
            pending.created_at_ms = pending.created_at_ms.saturating_sub(day_and_an_hour);
        }
    }
    restart_staging_and_obligations(owner).await;
    {
        let welcomes = owner.pending_welcomes.read().await;
        assert!(
            welcomes.contains_key(&welcome_id),
            "the pinned Welcome outlives the TTL and the restart"
        );
        assert!(
            !welcomes.contains_key(&control),
            "an unpinned Welcome as old does not"
        );
    }
    assert!(super::super::seat_welcome_pin::pinned(owner, &welcome_id));
    assert!(
        owed(owner, group_id, &n.hex)
            .await
            .is_some_and(|owed| owed.seat),
        "the seat obligation too"
    );

    let awake = Arc::new(AtomicBool::new(true));
    route_sends(&cast, &n, &awake);
    set_connected(owner, &[&n.hex]);
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async { seated(&n.state, group_id, &n.hex).await }).await,
        "N is seated from the kept Welcome"
    );
    assert_eq!(live_epoch(&n.state, group_id).await, epoch_of(&add));
    let proof = held_proof(&n.state, &owner_id).await;
    handle_treekem_catchup_request(owner, &n.id, false, proof).await;
    assert!(eventually(|| async { owed(owner, group_id, &n.hex).await.is_none() }).await);
    rekey_obligations::step(owner).await;
    assert!(
        !super::super::seat_welcome_pin::pinned(owner, &welcome_id),
        "a settled seat unpins its Welcome"
    );
    cast.shutdown().await;
    Ok(())
}

/// N's seat falls out of the owner's catch-up log (past the room's 128
/// events). The obligation cannot send it, so the owner re-seats N with a
/// removal and a fresh add: the survivors are owed both commits and follow
/// them, and N is owed the new seat with its Welcome pinned. (N lands from
/// it once its roster reaches the re-seat's base; see the record.)
#[tokio::test]
async fn a_seat_the_log_lost_is_re_seated_with_a_commit() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let first = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let awake = Arc::new(AtomicBool::new(false));
    route_sends(&cast, &n, &awake);
    // The survivors take the add; N is away.
    skew(owner, 6_000).await;
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async {
            live_epoch(&cast.s1, group_id).await == epoch_of(&first)
                && live_epoch(&cast.s2, group_id).await == epoch_of(&first)
                && idle(owner, group_id, &n.hex).await
        })
        .await
    );
    evict_from_log(owner, &first).await;

    skew(owner, 15_000).await;
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async { reseats(owner).await == 1 }).await,
        "the lost seat is re-seated"
    );
    let second = latest_add(owner, &n.hex);
    let new_epoch = epoch_of(&second);
    assert_eq!(new_epoch, epoch_of(&first) + 2, "a removal and an add");
    assert!(
        owed(owner, group_id, &n.hex)
            .await
            .is_some_and(|owed| owed.seat && owed.through_epoch == new_epoch),
        "N is owed its new seat"
    );
    assert!(super::super::seat_welcome_pin::pinned(
        owner,
        &welcome_id_of(&second)
    ));
    for survivor in [
        hex_of(&cast.s1.agent.agent_id()),
        hex_of(&cast.s2.agent.agent_id()),
    ] {
        assert_eq!(
            owed(owner, group_id, &survivor)
                .await
                .map(|owed| owed.through_epoch),
            Some(new_epoch),
            "survivor {survivor} is owed the re-seat"
        );
    }
    assert!(!seated(&n.state, group_id, &n.hex).await);

    // The survivors take both commits from their obligations.
    skew(owner, 6_000).await;
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async {
            live_epoch(&cast.s1, group_id).await == new_epoch
                && live_epoch(&cast.s2, group_id).await == new_epoch
        })
        .await,
        "the survivors follow the re-seat"
    );
    cast.shutdown().await;
    Ok(())
}

/// A member is re-seated at most once a day: a second lost seat, from the
/// worker or a retried add, waits. A retried add of a member whose seat the
/// log lost re-seats it the first time.
#[tokio::test]
async fn re_seats_are_limited_to_one_a_day_and_a_retry_may_trigger_one() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let first = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    evict_from_log(owner, &first).await;
    let retry = || async {
        let response = add_named_group_member(
            State(Arc::clone(owner)),
            owner_extension(),
            Path(group_id.clone()),
            Json(AddNamedGroupMemberRequest {
                agent_id: n.hex.clone(),
                display_name: Some("Sibling".to_string()),
                treekem_key_package_b64: Some(n.package_b64.clone()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")
    };
    let body = retry().await;
    assert_eq!(body["reseated"], true, "the retry re-seats the lost seat");
    assert_eq!(reseats(owner).await, 1);

    let second = latest_add(owner, &n.hex);
    evict_from_log(owner, &second).await;
    let body = retry().await;
    assert_eq!(body["reseated"], false, "not twice in a day");
    skew(owner, 6_000).await;
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async {
            owner
                .named_group_test_recorders
                .reseats_too_soon
                .load(Ordering::SeqCst)
                >= 2
        })
        .await,
        "the worker's re-seat is refused as too soon"
    );
    assert_eq!(reseats(owner).await, 1, "the worker waits too");
    assert_eq!(latest_add(owner, &n.hex), second, "no third seat");
    cast.shutdown().await;
    Ok(())
}

/// A retried direct add of N, answered 409; its body.
async fn retry_add(cast: &SurvivorRelay, n: &Sibling) -> serde_json::Value {
    let response = add_named_group_member(
        State(Arc::clone(&cast.fixture.state)),
        owner_extension(),
        Path(cast.fixture.group_id.clone()),
        Json(AddNamedGroupMemberRequest {
            agent_id: n.hex.clone(),
            display_name: Some("Sibling".to_string()),
            treekem_key_package_b64: Some(n.package_b64.clone()),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Fix round 2 (review I-F1): the owner restarts with its staging table
/// full of newer Welcomes. The pinned seat Welcome, the oldest, is not the
/// one the cap drops.
#[tokio::test]
async fn a_restart_with_a_full_staging_table_keeps_the_pinned_welcome() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let add = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let welcome_id = welcome_id_of(&add);
    {
        let mut welcomes = owner.pending_welcomes.write().await;
        let mut template = welcomes.get(&welcome_id).expect("staged").clone();
        let now = template.created_at_ms;
        welcomes.get_mut(&welcome_id).expect("staged").created_at_ms =
            now.saturating_sub(60 * 60 * 1000);
        for n in 0..300u32 {
            template.joiner_agent = format!("{n:064x}");
            welcomes.insert(format!("{n:064x}"), template.clone());
        }
    }
    restart_staging_and_obligations(owner).await;
    let welcomes = owner.pending_welcomes.read().await;
    assert!(
        welcomes.contains_key(&welcome_id),
        "the pinned Welcome survives a full table"
    );
    assert_eq!(welcomes.len(), 257, "the unpinned ones are capped at 256");
    drop(welcomes);
    cast.shutdown().await;
    Ok(())
}

/// Fix round 2 (review concern 2): the one-a-day re-seat limit is on disk.
/// A daemon that restarts, as one in a crash loop would, does not re-key
/// the room again.
#[tokio::test]
async fn a_restart_does_not_allow_a_second_re_seat_that_day() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let first = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    evict_from_log(owner, &first).await;
    assert_eq!(retry_add(&cast, &n).await["reseated"], true);
    let second = latest_add(owner, &n.hex);
    evict_from_log(owner, &second).await;

    restart_staging_and_obligations(owner).await;
    owner.seat_reseats.lock().unwrap().clear();
    load_join_result_staging(owner).await;
    assert_eq!(
        retry_add(&cast, &n).await["reseated"],
        false,
        "the restarted daemon remembers today's re-seat"
    );
    assert_eq!(latest_add(owner, &n.hex), second, "no new seat");
    cast.shutdown().await;
    Ok(())
}

/// Fix round 2 (review concern 3): a member promoted to Admin keeps its
/// role across a re-seat, as a returning member does.
#[tokio::test]
async fn an_admin_re_seated_stays_admin() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let n = sibling(&cast).await?;
    let first = direct_add_route(owner, group_id, &n.hex, "Sibling", &n.package_b64).await;
    let response = update_member_role(
        State(Arc::clone(owner)),
        owner_extension(),
        Path((group_id.clone(), n.hex.clone())),
        Json(UpdateMemberRoleRequest {
            role: "admin".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "N is promoted");
    evict_from_log(owner, &first).await;
    assert_eq!(retry_add(&cast, &n).await["reseated"], true);
    let role = owner
        .named_groups
        .read()
        .await
        .get(group_id)
        .and_then(|info| info.members_v2.get(&n.hex).map(|member| member.role));
    assert_eq!(role, Some(x0x::groups::GroupRole::Admin), "N stays Admin");
    assert!(
        super::signer_delivery::published(owner, |event| matches!(
            event,
            NamedGroupMetadataEvent::MemberRoleUpdated { agent_id, role: x0x::groups::GroupRole::Admin, .. }
                if *agent_id == n.hex
        ))
        .is_some(),
        "the restore is a signed role update the room sees"
    );
    cast.shutdown().await;
    Ok(())
}

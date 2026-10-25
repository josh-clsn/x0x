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
                    let applied =
                        apply_named_group_metadata_event(&target, event, owner_id, true, None)
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

    // N's own request from its new head proves the seat.
    let request = super::super::signed_catchup::page_request(&n.state, group_id, None)
        .await
        .expect("N asks");
    handle_treekem_catchup_request(owner, &n.id, false, request).await;
    assert!(
        eventually(|| async { owed(owner, group_id, &n.hex).await.is_none() }).await,
        "N's proof settles its seat"
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
    assert_eq!(
        owed(owner, group_id, &n.hex)
            .await
            .map(|owed| owed.next_attempt_at_ms),
        Some(0),
        "the seat obligation is due now"
    );
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

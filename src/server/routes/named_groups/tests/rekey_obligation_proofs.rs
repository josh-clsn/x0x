//! Survivor re-key A10: every re-key site owes its survivors, and only the
//! survivor's own proof ends what is owed. See
//! `docs/adr/transient/T-survivor-rekey-obligation.md`.
//!
//! The cast is the survivor fixture: the owner (the only admin), the
//! removed member R (a key, not a daemon), and the members S1 and S2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::head_rounds::next_challenge;
use super::super::rekey_obligations::{self, ObligationState};
use super::super::signed_catchup::{page_request, sign_page_request};
use super::catchup_routes::{call, sign_path};
use super::epoch_ahead_catchup::{
    deliver_catchup, encrypt, live_epoch, live_treekem_group, published_removal_event,
    signed_self_leave, survivor_relay_fixture, wait_until, SurvivorRelay,
};
use super::rekey_obligations::{
    eventually, hex_of, idle, install_deliver, owed, set_connected, settles_done, skew,
};
use super::signer_delivery::{ban_route, direct_add_route, newcomer, published};
use super::*;
use axum::http::Method;
use std::sync::atomic::{AtomicBool, Ordering};

fn owner_hex(cast: &SurvivorRelay) -> String {
    hex_of(&cast.fixture.state.agent.agent_id())
}

fn r_hex(cast: &SurvivorRelay) -> String {
    hex_of(&cast.fixture.member_id)
}

fn s1_hex(cast: &SurvivorRelay) -> String {
    hex_of(&cast.s1.agent.agent_id())
}

fn s2_hex(cast: &SurvivorRelay) -> String {
    hex_of(&cast.s2.agent.agent_id())
}

/// The TreeKEM epoch and signed revision `event` seals.
fn rekey_of(event: &NamedGroupMetadataEvent) -> (u64, u64) {
    let epoch = match event {
        NamedGroupMetadataEvent::MemberAdded { treekem_epoch, .. }
        | NamedGroupMetadataEvent::MemberRemoved { treekem_epoch, .. }
        | NamedGroupMetadataEvent::MemberBanned { treekem_epoch, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { treekem_epoch, .. } => {
            treekem_epoch.expect("a TreeKEM epoch")
        }
        _ => panic!("not a re-key: {event:?}"),
    };
    let revision = named_group_metadata_event_commit(event)
        .expect("a signed commit")
        .revision;
    (epoch, revision)
}

/// The owner removes R through its route.
async fn remove(cast: &SurvivorRelay, member_hex: &str) -> NamedGroupMetadataEvent {
    let owner = &cast.fixture.state;
    let response = remove_named_group_member(
        State(Arc::clone(owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
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

async fn applies(
    state: &Arc<AppState>,
    sender: x0x::identity::AgentId,
    event: &NamedGroupMetadataEvent,
) {
    let applied = apply_named_group_metadata_event(state, event.clone(), sender, true, None).await;
    assert!(applied.accepted, "applied: {applied:?}");
}

/// The resend schedules the owner started, by event kind, recipients sorted.
fn blind_schedules(state: &AppState) -> Vec<(&'static str, Vec<String>)> {
    state
        .named_group_test_recorders
        .control_redelivery_recipients
        .lock()
        .unwrap()
        .iter()
        .map(|(kind, recipients)| {
            let mut recipients = recipients.clone();
            recipients.sort();
            (*kind, recipients)
        })
        .collect()
}

/// The owner opens `member`'s message to the room.
async fn owner_reads(state: &Arc<AppState>, group_id: &str, ciphertext: &[u8]) -> StatusCode {
    treekem_group_decrypt(state, group_id, None, &BASE64.encode(ciphertext))
        .await
        .0
}

#[tokio::test]
async fn removal_owes_each_survivor_but_not_the_removed_member() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let removal = remove(&cast, &r_hex(&cast)).await;
    let (epoch, revision) = rekey_of(&removal);
    for survivor in [s1_hex(&cast), s2_hex(&cast)] {
        let owed = owed(owner, group_id, &survivor)
            .await
            .expect("each survivor is owed the re-key");
        assert_eq!(
            (owed.owed_epoch, owed.owed_revision, owed.through_epoch),
            (epoch, revision, epoch)
        );
        assert_eq!(owed.state, ObligationState::Owed);
    }
    assert!(owed(owner, group_id, &r_hex(&cast)).await.is_none());
    assert!(owed(owner, group_id, &owner_hex(&cast)).await.is_none());
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn obligation_is_durable_before_the_route_returns() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let removal = remove(&cast, &r_hex(&cast)).await;
    let (epoch, _) = rekey_of(&removal);
    // What a restart right after the route returned would load.
    let groups = owner.named_groups.read().await.clone();
    let loaded = load_rekey_obligations(
        &owner.treekem_dir,
        &groups,
        &owner_hex(&cast),
        &*owner.treekem_event_log.read().await,
    )
    .await;
    for survivor in [s1_hex(&cast), s2_hex(&cast)] {
        assert_eq!(
            loaded
                .get(group_id, &survivor)
                .map(|owed| owed.through_epoch),
            Some(epoch),
            "on disk before the route returned"
        );
    }
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn catchup_or_challenge_request_at_the_new_epoch_settles() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let removal = remove(&cast, &r_hex(&cast)).await;

    // S2 applies the removal and asks the owner from its new head, over a
    // transport the owner cannot verify: S2's signature is the proof.
    applies(&cast.s2, owner_id, &removal).await;
    let request = page_request(&cast.s2, group_id, None)
        .await
        .expect("S2 asks");
    handle_treekem_catchup_request(owner, &cast.s2.agent.agent_id(), false, request).await;
    assert!(
        eventually(|| async { owed(owner, group_id, &s2_hex(&cast)).await.is_none() }).await,
        "S2's signed request at the new epoch settles"
    );
    assert!(owed(owner, group_id, &s1_hex(&cast)).await.is_some());

    // S1 gets the removal and challenges the owner through the head-proof
    // route (the relay leg): its signed challenge is the proof.
    deliver_catchup(&cast.s1, &owner_id, group_id, removal).await;
    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        live_epoch(owner, group_id).await
    );
    let mut request = page_request(&cast.s1, group_id, None)
        .await
        .expect("S1 asks");
    request.head_challenge = Some(next_challenge(&cast.s1).await);
    sign_page_request(&cast.s1, &mut request);
    let (status, body) = call(
        owner,
        Method::POST,
        &sign_path(group_id),
        &owner.api_token,
        Some(serde_json::json!({ "request": request })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        eventually(|| async { owed(owner, group_id, &s1_hex(&cast)).await.is_none() }).await,
        "S1's signed challenge at the new epoch settles"
    );
    let file =
        std::fs::read_to_string(owner.treekem_dir.join(rekey_obligations::OBLIGATIONS_FILE))?;
    assert!(
        !file.contains(&s1_hex(&cast)) && !file.contains(&s2_hex(&cast)),
        "and on disk"
    );
    cast.shutdown().await;
    Ok(())
}

/// The same proof as a challenge over x0x (a page request carrying a head
/// challenge) settles too.
#[tokio::test]
async fn a_challenge_over_x0x_at_the_new_epoch_settles() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let removal = remove(&cast, &r_hex(&cast)).await;
    assert!(owed(owner, group_id, &s2_hex(&cast)).await.is_some());
    applies(&cast.s2, owner.agent.agent_id(), &removal).await;
    let mut request = page_request(&cast.s2, group_id, None)
        .await
        .expect("S2 asks");
    request.head_challenge = Some(next_challenge(&cast.s2).await);
    sign_page_request(&cast.s2, &mut request);
    handle_treekem_catchup_request(owner, &cast.s2.agent.agent_id(), false, request).await;
    assert!(eventually(|| async { owed(owner, group_id, &s2_hex(&cast)).await.is_none() }).await);
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn decrypt_from_the_survivor_at_the_new_epoch_settles() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let removal = remove(&cast, &r_hex(&cast)).await;
    // S1 is still at the old epoch: its message does not open and proves
    // nothing.
    let stale = encrypt(&cast.s1, group_id, b"from before").await?;
    assert_eq!(
        owner_reads(owner, group_id, &stale).await,
        StatusCode::BAD_REQUEST
    );
    assert!(owed(owner, group_id, &s1_hex(&cast)).await.is_some());

    applies(&cast.s2, owner.agent.agent_id(), &removal).await;
    let message = encrypt(&cast.s2, group_id, b"at the new epoch").await?;
    assert_eq!(owner_reads(owner, group_id, &message).await, StatusCode::OK);
    assert!(
        owed(owner, group_id, &s2_hex(&cast)).await.is_none(),
        "S2's message at the new epoch settles"
    );
    assert!(
        owed(owner, group_id, &s1_hex(&cast)).await.is_some(),
        "and only S2's"
    );
    cast.shutdown().await;
    Ok(())
}

/// Only the survivor's own proof counts: a request below the epoch, a
/// claimed sender, another member's signature, a removed member's
/// transport and a member-keyed request's unsigned head settle nothing, and
/// change nothing.
#[tokio::test]
async fn request_below_the_epoch_does_not_settle() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let s1_id = cast.s1.agent.agent_id();
    let removal = remove(&cast, &r_hex(&cast)).await;
    let (epoch, revision) = rekey_of(&removal);
    let before = owed(owner, group_id, &s1_hex(&cast)).await.expect("owed");

    // S1's own signed request, from its old head.
    let request = page_request(&cast.s1, group_id, None)
        .await
        .expect("S1 asks");
    assert!(request.from_treekem_epoch < epoch);
    handle_treekem_catchup_request(owner, &s1_id, false, request.clone()).await;
    handle_treekem_catchup_request(owner, &s1_id, true, request.clone()).await;

    // A claim of S1 at the new epoch: unsigned, over a transport the owner
    // cannot verify.
    let mut claimed = request.clone();
    claimed.from_treekem_epoch = epoch;
    claimed.from_revision = revision;
    claimed.signed_by = None;
    handle_treekem_catchup_request(owner, &s1_id, false, claimed.clone()).await;
    // The claim signed with S2's key.
    let mut forged = claimed.clone();
    sign_page_request(&cast.s2, &mut forged);
    handle_treekem_catchup_request(owner, &s1_id, false, forged).await;
    // The claim from R, removed, over a transport that verified R.
    handle_treekem_catchup_request(owner, &cast.fixture.member_id, true, claimed.clone()).await;
    // S1's own member-keyed request, whose signature does not cover a head.
    let mut keyed = claimed.clone();
    keyed.target_member_id = Some(s2_hex(&cast));
    keyed.signed_by = build_catchup_signer(
        &cast.s1,
        &member_keyed_request_sign_input(group_id, &s1_hex(&cast), &s2_hex(&cast)),
    );
    handle_treekem_catchup_request(owner, &s1_id, false, keyed).await;
    // The same claims through the head-proof route.
    let mut challenged = claimed.clone();
    challenged.head_challenge = Some(next_challenge(&cast.s1).await);
    let (status, _) = call(
        owner,
        Method::POST,
        &sign_path(group_id),
        &owner.api_token,
        Some(serde_json::json!({ "request": challenged })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unsigned challenge is refused"
    );

    assert!(settles_done(owner).await, "every settle spawned has run");
    assert!(
        owner
            .named_group_test_recorders
            .settles_spawned
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 2,
        "S1's own requests did reach a settle"
    );
    assert_eq!(
        owed(owner, group_id, &s1_hex(&cast)).await,
        Some(before),
        "nothing settled, moved or put off"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn survivor_leaving_or_group_withdrawn_drops_it() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    remove(&cast, &r_hex(&cast)).await;
    assert!(owed(owner, group_id, &s2_hex(&cast)).await.is_some());

    // S2 leaves: the owner applies S2's own signed leave. The next step drops
    // what S2 was owed, and the leave's own re-key owes S1 alone.
    let leave = {
        let groups = owner.named_groups.read().await;
        let mut leaving = groups.get(group_id).cloned().expect("group");
        drop(groups);
        let s2 = s2_hex(&cast);
        leaving.roster_revision = leaving.roster_revision.saturating_add(1);
        let revision = leaving.roster_revision;
        leaving.remove_member(&s2, Some(s2.clone()));
        let commit =
            leaving.seal_commit(cast.s2.agent.identity().agent_keypair(), now_millis_u64())?;
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision,
            actor: s2.clone(),
            agent_id: s2,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: Some(commit),
        }
    };
    applies(owner, cast.s2.agent.agent_id(), &leave).await;
    rekey_obligations::step(owner).await;
    assert!(
        owed(owner, group_id, &s2_hex(&cast)).await.is_none(),
        "a leaver is owed nothing"
    );
    assert!(owed(owner, group_id, &s1_hex(&cast)).await.is_some());
    let file = owner.treekem_dir.join(rekey_obligations::OBLIGATIONS_FILE);
    assert!(
        !std::fs::read_to_string(&file)?.contains(&s2_hex(&cast)),
        "and on disk"
    );

    // The owner withdraws the room: nothing is owed in it, in memory or on disk.
    let response = withdraw_group_state(
        State(Arc::clone(owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(owed(owner, group_id, &s1_hex(&cast)).await.is_none());
    assert!(!std::fs::read_to_string(&file)?.contains(&s1_hex(&cast)));
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn ban_and_post_leave_rekey_owe_survivors() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    ban_route(owner, group_id, &r_hex(&cast)).await;
    let ban = published(owner, |event| {
        matches!(
            event,
            NamedGroupMetadataEvent::MemberBanned {
                treekem_commit_b64: Some(_),
                ..
            }
        )
    })
    .expect("the ban is published");
    let (epoch, _) = rekey_of(&ban);
    for survivor in [s1_hex(&cast), s2_hex(&cast)] {
        assert_eq!(
            owed(owner, group_id, &survivor)
                .await
                .map(|owed| owed.through_epoch),
            Some(epoch),
            "a ban owes each survivor"
        );
    }
    assert!(owed(owner, group_id, &r_hex(&cast)).await.is_none());
    assert_eq!(
        blind_schedules(owner),
        vec![("member_banned", vec![r_hex(&cast)])],
        "only the banned member keeps the blind schedule"
    );
    cast.shutdown().await;

    // R leaves on its own: the owner's post-leave re-key owes S1 and S2.
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let leave = signed_self_leave(&cast.fixture).await?;
    applies(owner, cast.fixture.member_id, &leave).await;
    wait_until(|| published_removal_event(owner).is_some()).await;
    let rekey = published_removal_event(owner).expect("the post-leave re-key");
    let (epoch, _) = rekey_of(&rekey);
    for survivor in [s1_hex(&cast), s2_hex(&cast)] {
        assert_eq!(
            owed(owner, group_id, &survivor)
                .await
                .map(|owed| owed.through_epoch),
            Some(epoch),
            "the post-leave re-key owes each survivor"
        );
    }
    assert!(owed(owner, group_id, &r_hex(&cast)).await.is_none());
    assert!(
        blind_schedules(owner)
            .iter()
            .all(|(_, recipients)| recipients.is_empty()),
        "no survivor keeps the blind schedule: {:?}",
        blind_schedules(owner)
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn an_add_owes_the_members_it_did_not_add() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let (newcomer_id, package) = newcomer(0x31)?;
    let newcomer_hex = hex_of(&newcomer_id);
    let add = direct_add_route(owner, group_id, &newcomer_hex, "Nan", &package).await;
    let (epoch, _) = rekey_of(&add);
    for member in [r_hex(&cast), s1_hex(&cast), s2_hex(&cast)] {
        assert_eq!(
            owed(owner, group_id, &member)
                .await
                .map(|owed| owed.through_epoch),
            Some(epoch),
            "every member the add did not seat is owed it"
        );
    }
    // Survivor re-key A13: the newcomer has no join result to poll, so it
    // is owed its seat too.
    assert_eq!(
        owed(owner, group_id, &newcomer_hex)
            .await
            .map(|owed| owed.through_epoch),
        Some(epoch),
        "the newcomer is owed its seat"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn removed_member_keeps_the_blind_schedule_and_survivors_do_not() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    remove(&cast, &r_hex(&cast)).await;
    assert_eq!(
        blind_schedules(owner),
        vec![("member_removed", vec![r_hex(&cast)])]
    );
    cast.shutdown().await;

    // Past the room's cap, the survivor refused keeps the blind schedule.
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    owner.rekey_obligations.lock().await.set_caps(1, 4096);
    remove(&cast, &r_hex(&cast)).await;
    let schedules = blind_schedules(owner);
    assert_eq!(schedules.len(), 1);
    let (kind, recipients) = &schedules[0];
    assert_eq!(*kind, "member_removed");
    assert_eq!(
        recipients.len(),
        2,
        "R and the refused survivor: {recipients:?}"
    );
    assert!(recipients.contains(&r_hex(&cast)));
    let refused = recipients
        .iter()
        .find(|member| **member != r_hex(&cast))
        .expect("a refused survivor")
        .clone();
    assert!(owed(owner, group_id, &refused).await.is_none());
    let kept = [s1_hex(&cast), s2_hex(&cast)]
        .into_iter()
        .find(|member| *member != refused)
        .expect("the other survivor");
    assert!(owed(owner, group_id, &kept).await.is_some());
    cast.shutdown().await;
    Ok(())
}

/// S1 is away for longer than the old blind schedule's last resend. The
/// obligation keeps it owed, and its return sends the re-key at once.
#[tokio::test]
async fn survivor_away_past_the_old_horizon_gets_the_key_from_the_obligation() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let s1 = s1_hex(&cast);
    let away = Arc::new(AtomicBool::new(true));
    {
        let (away, s1_state, s2_state) = (
            Arc::clone(&away),
            Arc::clone(&cast.s1),
            Arc::clone(&cast.s2),
        );
        let (s1, s2) = (s1.clone(), s2_hex(&cast));
        install_deliver(
            owner,
            Arc::new(move |recipient, event| {
                let target = if recipient == s1 {
                    (!away.load(Ordering::SeqCst)).then(|| Arc::clone(&s1_state))
                } else if recipient == s2 {
                    Some(Arc::clone(&s2_state))
                } else {
                    None
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
    let epoch_before = live_epoch(&cast.s1, group_id).await;
    remove(&cast, &r_hex(&cast)).await;
    // Nothing the owner sends reaches S1 for 6 + 15 + 30 + 60 + 120 s.
    for (wait_ms, attempts) in [
        (6_000u64, 1u32),
        (15_000, 2),
        (30_000, 3),
        (60_000, 4),
        (120_000, 5),
    ] {
        skew(owner, wait_ms).await;
        rekey_obligations::step(owner).await;
        let counted = eventually(|| async {
            owed(owner, group_id, &s1)
                .await
                .is_some_and(|owed| owed.attempt_count == attempts)
                && idle(owner, group_id, &s1).await
        })
        .await;
        assert!(counted, "attempt {attempts}");
    }
    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        epoch_before,
        "S1 is stranded"
    );
    assert_eq!(
        owed(owner, group_id, &s1).await.map(|owed| owed.state),
        Some(ObligationState::Owed)
    );

    // S1 comes back: linked again, it is sent the re-key at once, the edge
    // floor after its last failed send having passed.
    skew(owner, rekey_obligations::EDGE_FLOOR_MS).await;
    away.store(false, Ordering::SeqCst);
    set_connected(owner, &[&s1]);
    rekey_obligations::step(owner).await;
    assert!(
        eventually(|| async {
            live_epoch(&cast.s1, group_id).await == live_epoch(owner, group_id).await
        })
        .await,
        "S1 reaches the new epoch"
    );
    assert!(
        eventually(|| async {
            owed(owner, group_id, &s1)
                .await
                .is_some_and(|owed| owed.state == ObligationState::DeliveredUnproven)
        })
        .await,
        "delivered, still unproven"
    );
    let message = encrypt(&cast.s1, group_id, b"back").await?;
    assert_eq!(owner_reads(owner, group_id, &message).await, StatusCode::OK);
    assert!(
        owed(owner, group_id, &s1).await.is_none(),
        "S1's message proves it"
    );
    cast.shutdown().await;
    Ok(())
}

/// S1 is away, and the owner restarts. S1 gets the re-key from S2, and its
/// next message settles what the restarted owner still owed it.
#[tokio::test]
async fn survivor_away_with_the_remover_restarted_gets_the_key_from_another_survivor() -> Result<()>
{
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let removal = remove(&cast, &r_hex(&cast)).await;
    applies(&cast.s2, owner.agent.agent_id(), &removal).await;

    let restarted =
        secure_endpoint_test_state_at(cast.fixture.dir(), Arc::clone(&owner.agent)).await?;
    // As startup does, the tree comes back from its snapshot.
    restarted
        .treekem_groups
        .write()
        .await
        .insert(group_id.clone(), live_treekem_group(owner, group_id).await);
    assert!(
        owed(&restarted, group_id, &s1_hex(&cast)).await.is_some(),
        "the obligation survives the restart"
    );

    // S1 asks S2, over a transport S2 cannot verify, and applies its page.
    let request = page_request(&cast.s1, group_id, None)
        .await
        .expect("S1 asks");
    let served_before = cast
        .s2
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .unwrap()
        .len();
    handle_treekem_catchup_request(&cast.s2, &cast.s1.agent.agent_id(), false, request).await;
    let page: TreeKemCatchupResponse = {
        let served = cast
            .s2
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .unwrap();
        assert_eq!(served.len(), served_before + 1, "S2 serves S1");
        serde_json::from_slice(served.last().unwrap())?
    };
    handle_treekem_catchup_response(&cast.s1, &cast.s2.agent.agent_id(), false, page).await;
    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        live_epoch(&restarted, group_id).await,
        "S1 holds the key from another survivor"
    );

    let message = encrypt(&cast.s1, group_id, b"from S1").await?;
    assert_eq!(
        owner_reads(&restarted, group_id, &message).await,
        StatusCode::OK
    );
    assert!(owed(&restarted, group_id, &s1_hex(&cast)).await.is_none());
    let groups = restarted.named_groups.read().await.clone();
    let loaded = load_rekey_obligations(
        &restarted.treekem_dir,
        &groups,
        &owner_hex(&cast),
        &*restarted.treekem_event_log.read().await,
    )
    .await;
    assert!(
        loaded.get(group_id, &s1_hex(&cast)).is_none(),
        "settled on disk"
    );
    assert!(
        loaded.get(group_id, &s2_hex(&cast)).is_some(),
        "S2 has proven nothing yet"
    );
    restarted.shutdown_notify.send_replace(true);
    cast.shutdown().await;
    Ok(())
}

/// An invite add sealed through the authority's real `MemberJoined` apply
/// owes the member already seated, and an approval owes the members it did
/// not seat. Neither owes the member it seats: that one gets its Welcome.
#[tokio::test]
async fn invite_and_approval_adds_owe_the_members_already_seated() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = super::adr0107_stuck_join_rearm::build(dir.path()).await?;
    let j1_hex = hex_of(&s.j1.agent.agent_id());
    let j2_hex = hex_of(&s.j2.agent.agent_id());
    let (epoch, revision) = rekey_of(&s.j2_add);
    let owed_j1 = owed(&s.authority, &s.group_key, &j1_hex)
        .await
        .expect("J1 is owed J2's add");
    assert_eq!(
        (
            owed_j1.owed_epoch,
            owed_j1.owed_revision,
            owed_j1.through_epoch
        ),
        (epoch, revision, epoch)
    );
    assert!(owed(&s.authority, &s.group_key, &j2_hex).await.is_none());

    let fixture = super::epoch_ahead_catchup::two_member_treekem_group().await?;
    let state = &fixture.state;
    let group_id = &fixture.group_id;
    let (requester_id, requester_package) = newcomer(0x32)?;
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
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), request_id)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner approves");
    let approval = published(state, |event| {
        matches!(event, NamedGroupMetadataEvent::JoinRequestApproved { .. })
    })
    .expect("the approval is published");
    let (epoch, _) = rekey_of(&approval);
    assert_eq!(
        owed(state, group_id, &hex_of(&fixture.member_id))
            .await
            .map(|owed| owed.through_epoch),
        Some(epoch),
        "the member already seated is owed the approval"
    );
    assert_eq!(
        owed(state, group_id, &requester_hex)
            .await
            .map(|owed| owed.through_epoch),
        Some(epoch),
        "A13: the requester the approval seats is owed its seat"
    );
    Ok(())
}

/// Fix round I-5: a survivor that applied the re-key and then says nothing
/// still settles. The author's direct send makes it answer with one signed
/// page request from its new head, and that request settles the obligation.
#[tokio::test]
async fn a_silent_survivor_settles_without_user_traffic() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let owner_hex = owner_hex(&cast);
    let s2 = s2_hex(&cast);
    {
        let (s2, s2_state) = (s2.clone(), Arc::clone(&cast.s2));
        install_deliver(
            owner,
            Arc::new(move |recipient, event| {
                let target = (recipient == s2).then(|| Arc::clone(&s2_state));
                Box::pin(async move {
                    let Some(target) = target else {
                        return Err("unreachable".to_string());
                    };
                    // As the direct-message listener applies it.
                    apply_direct_named_group_metadata_event(&target, event, owner_id, true).await;
                    Ok(())
                })
            }),
        );
    }
    let removal = remove(&cast, &r_hex(&cast)).await;
    let (epoch, _) = rekey_of(&removal);
    skew(owner, 6_000).await;
    rekey_obligations::step(owner).await;

    let asked = || -> Vec<TreeKemCatchupRequest> {
        cast.s2
            .named_group_test_recorders
            .catchup_page_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(peer, _)| *peer == owner_hex)
            .filter_map(|(_, bytes)| serde_json::from_slice(bytes).ok())
            .collect()
    };
    assert!(
        eventually(|| async { asked().len() == 1 }).await,
        "S2 answers the owner once"
    );
    assert_eq!(live_epoch(&cast.s2, group_id).await, epoch);
    let request = asked().pop().expect("S2's request");
    assert!(request.signed_by.is_some(), "signed over its head");
    // The owner takes it as off the wire, from a transport it cannot verify.
    handle_treekem_catchup_request(owner, &cast.s2.agent.agent_id(), false, request).await;
    assert!(
        eventually(|| async { owed(owner, group_id, &s2).await.is_none() }).await,
        "the quiet survivor's answer settles"
    );
    assert!(
        owed(owner, group_id, &s1_hex(&cast)).await.is_some(),
        "S1 got nothing and proved nothing"
    );

    // Once per room per gap, and only for the author over a verified transport.
    let held = rekey_obligations::held_rekey(&cast.s2, &removal, &owner_id, true)
        .expect("the author's re-key, verified");
    assert!(
        !rekey_obligations::prove_held(&cast.s2, held, true).await,
        "not again within the gap"
    );
    assert!(rekey_obligations::held_rekey(&cast.s2, &removal, &owner_id, false).is_none());
    assert!(
        rekey_obligations::held_rekey(&cast.s2, &removal, &cast.s1.agent.agent_id(), true)
            .is_none(),
        "a copy from someone who did not sign it asks nothing"
    );
    cast.shutdown().await;
    Ok(())
}

/// Fix round 2, N-1: a survivor answers only an active admin author, and
/// only after an apply that took. A failed apply, a stranger, a removed
/// member and a demoted admin get nothing and take no slot, so a real
/// admin's proof right after is still sent.
#[tokio::test]
async fn a_held_rekey_is_proved_only_to_an_active_admin_after_an_apply_that_took() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_id = owner.agent.agent_id();
    let s2 = &cast.s2;
    let (r_id, s1_id) = (cast.fixture.member_id, cast.s1.agent.agent_id());
    let stranger = x0x::identity::AgentKeypair::generate()?.agent_id();
    let removal = remove(&cast, &r_hex(&cast)).await;
    let forged_as = |author: &x0x::identity::AgentId| {
        let mut forged = removal.clone();
        if let NamedGroupMetadataEvent::MemberRemoved {
            actor,
            commit: Some(commit),
            ..
        } = &mut forged
        {
            *actor = hex_of(author);
            commit.committed_by = hex_of(author);
        }
        forged
    };
    let asked = |peer: &x0x::identity::AgentId| -> usize {
        let peer = hex_of(peer);
        s2.named_group_test_recorders
            .catchup_page_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(to, _)| *to == peer)
            .count()
    };
    let held = |event: &NamedGroupMetadataEvent, author: &x0x::identity::AgentId| {
        rekey_obligations::held_rekey(s2, event, author, true).expect("a signer's direct re-key")
    };

    // The owner's genuine re-key, but the apply did not take, and S2's
    // chain does not hold it.
    assert!(
        !rekey_obligations::prove_held(s2, held(&removal, &owner_id), false).await,
        "a failed apply"
    );
    // A stranger who signs its own copy.
    assert!(
        !rekey_obligations::prove_held(s2, held(&forged_as(&stranger), &stranger), true).await,
        "a stranger"
    );
    applies(s2, owner_id, &removal).await;
    // R, removed by that very commit.
    assert!(
        !rekey_obligations::prove_held(s2, held(&forged_as(&r_id), &r_id), true).await,
        "a removed member"
    );
    // S1, an admin once and demoted since.
    {
        let mut groups = s2.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group on S2");
        info.set_member_role(&hex_of(&s1_id), x0x::groups::GroupRole::Admin);
        info.set_member_role(&hex_of(&s1_id), x0x::groups::GroupRole::Member);
    }
    assert!(
        !rekey_obligations::prove_held(s2, held(&forged_as(&s1_id), &s1_id), true).await,
        "a demoted admin"
    );
    for peer in [&stranger, &r_id, &s1_id] {
        assert_eq!(asked(peer), 0, "nothing goes to {}", hex_of(peer));
    }

    // The real admin, right after: no slot was taken. A duplicate of a
    // commit S2's chain already holds counts as applied.
    let before = asked(&owner_id);
    assert!(rekey_obligations::prove_held(s2, held(&removal, &owner_id), false).await);
    assert_eq!(asked(&owner_id), before + 1, "the owner is answered");
    cast.shutdown().await;
    Ok(())
}

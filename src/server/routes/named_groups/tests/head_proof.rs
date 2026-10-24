//! Survivor re-key A6: an admin's daemon answers a member's fresh challenge
//! with a signed head proof (the live tree's epoch and epoch authenticator),
//! and the member records a proof only for its open round. See
//! `docs/adr/transient/T-treekem-head-proof.md`.
//!
//! The cast is the survivor fixture: the owner (the only admin), the
//! removed member R (a key, not a daemon), and the members S1 and S2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::head_proof::{
    self, answer_challenge, answer_challenge_with, challenge_admins, record_proof, round_view,
    sign_claim_with, verify, HeadProof, NotRecorded, Refusal, HEAD_PROOFS_PER_WINDOW,
};
use super::super::signed_catchup::{page_request, sign_page_request, sign_page_request_with};
use super::epoch_ahead_catchup::{
    catchup_request_from, live_epoch, live_treekem_group, survivor_relay_fixture, wait_until,
    SurvivorRelay,
};
use super::signer_delivery::{hex_id, roster, s2_applies};
use super::*;

/// `requester`'s signed page request carrying the challenge `nonce`.
async fn challenge(
    requester: &Arc<AppState>,
    group_id: &str,
    nonce: &str,
) -> TreeKemCatchupRequest {
    let mut request = page_request(requester, group_id, None)
        .await
        .expect("the requester asks from its head");
    request.head_challenge = Some(nonce.to_string());
    sign_page_request(requester, &mut request);
    request
}

/// The last response `server` sent for `request`, if any.
async fn served(
    server: &Arc<AppState>,
    sender: &x0x::identity::AgentId,
    request: TreeKemCatchupRequest,
    verified: bool,
) -> Option<TreeKemCatchupResponse> {
    let before = server
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len();
    handle_treekem_catchup_request(server, sender, verified, request).await;
    let recorded = server
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder");
    recorded
        .get(before..)
        .and_then(|sent| sent.last())
        .map(|bytes| serde_json::from_slice(bytes).expect("a catch-up response"))
}

/// The owner's proof for S1's challenge `nonce`.
async fn owner_proof(cast: &SurvivorRelay, nonce: &str) -> HeadProof {
    let request = challenge(&cast.s1, &cast.fixture.group_id, nonce).await;
    served(
        &cast.fixture.state,
        &cast.s1.agent.agent_id(),
        request,
        false,
    )
    .await
    .expect("the owner answers")
    .head_proof
    .expect("the owner's answer carries a proof")
}

async fn authenticator_hex(state: &AppState, group_id: &str) -> String {
    let group = live_treekem_group(state, group_id).await;
    let guard = group.lock().await;
    hex::encode(guard.epoch_authenticator().expect("authenticator"))
}

/// The proofs S1's open round holds, by signer.
fn s1_recorded(cast: &SurvivorRelay) -> Vec<String> {
    round_view(&cast.s1, &cast.fixture.group_id)
        .map(|round| {
            round
                .proofs
                .iter()
                .map(|proof| proof.claim.signer.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The owner's proof reaches S1 inside a page whose transport S1 could
/// not verify.
async fn deliver_proof(cast: &SurvivorRelay, proof: HeadProof) {
    let mut response = proof_only_response(&cast.fixture.group_id);
    response.head_proof = Some(proof);
    handle_treekem_catchup_response(
        &cast.s1,
        &cast.fixture.state.agent.agent_id(),
        false,
        response,
    )
    .await;
}

fn proof_only_response(group_id: &str) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: Vec::new(),
        truncated: false,
        responder_state_hash: None,
        log_evicted_through: None,
        target_member_id: None,
        target_member_key_package_b64: None,
        signed_by: None,
        head_proof: None,
    }
}

#[tokio::test]
async fn authenticator_is_read_from_the_live_tree() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let first = owner_proof(&cast, "n1").await;
    assert_eq!(first.claim.treekem_epoch, live_epoch(owner, group_id).await);
    assert_eq!(
        first.claim.epoch_authenticator,
        authenticator_hex(owner, group_id).await
    );
    assert_eq!(
        first.claim.epoch_authenticator,
        authenticator_hex(&cast.s1, group_id).await,
        "a member at the same epoch of the same tree derives the same authenticator"
    );

    // The owner's live tree moves on with no roster change at all.
    {
        let group = live_treekem_group(owner, group_id).await;
        let mut guard = group.lock().await;
        guard.update()?;
    }
    let second = owner_proof(&cast, "n2").await;
    assert_eq!(second.claim.treekem_epoch, first.claim.treekem_epoch + 1);
    assert_eq!(
        second.claim.epoch_authenticator,
        authenticator_hex(owner, group_id).await
    );
    assert_ne!(
        second.claim.epoch_authenticator, first.claim.epoch_authenticator,
        "the proof follows the live tree"
    );
    assert_eq!(
        (&second.claim.security_binding, second.claim.state_revision),
        (&first.claim.security_binding, first.claim.state_revision),
        "the roster's binding and revision did not move, so they are not the source"
    );
    assert_ne!(
        second.claim.epoch_authenticator,
        authenticator_hex(&cast.s1, group_id).await,
        "S1 missed the commit, and its authenticator differs"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn an_admin_answers_a_challenge_with_a_signed_proof() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner_hex = hex_id(&cast.fixture.state.agent.agent_id());
    let s1_hex = hex_id(&cast.s1.agent.agent_id());
    let info = roster(&cast.fixture.state, &cast.fixture.group_id).await;
    let proof = owner_proof(&cast, "fresh-nonce").await;
    assert!(verify(&proof), "the proof verifies");
    assert_eq!(proof.claim.version, 1);
    assert_eq!(proof.claim.group_id, info.stable_group_id());
    assert_eq!(proof.claim.requester, s1_hex);
    assert_eq!(proof.claim.nonce, "fresh-nonce");
    assert_eq!(proof.claim.signer, owner_hex);
    assert_eq!(proof.claim.admins, vec![owner_hex.clone()]);
    assert_eq!(proof.claim.state_revision, info.state_revision);
    assert_eq!(proof.claim.security_binding, info.security_binding);

    // The A7 route signs through the same function.
    let direct = answer_challenge(
        &cast.fixture.state,
        &cast.fixture.group_id,
        &s1_hex,
        "another",
        0,
    )
    .await
    .expect("the owner signs");
    assert!(verify(&direct));
    assert_eq!(direct.claim.nonce, "another");
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_non_admin_answers_without_a_proof() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = &cast.fixture.group_id;
    let request = challenge(&cast.s1, group_id, "n").await;
    let page = served(&cast.s2, &cast.s1.agent.agent_id(), request, false)
        .await
        .expect("S2 still serves the page");
    assert!(
        page.head_proof.is_none(),
        "a member that is not an admin signs nothing"
    );
    let refused = answer_challenge(
        &cast.s2,
        group_id,
        &hex_id(&cast.s1.agent.agent_id()),
        "n2",
        0,
    )
    .await;
    assert!(matches!(refused, Err(Refusal::NotAnAdmin)), "{refused:?}");
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_departed_requester_gets_no_proof() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let r_id = cast.fixture.member_id;
    let r_hex = hex_id(&r_id);
    let held = roster(owner, group_id).await;
    let response = remove_named_group_member(
        State(Arc::clone(owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), r_hex.clone())),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner removes R");

    let mut request = catchup_request_from(&held, group_id, &r_id);
    request.head_challenge = Some("r-asks".to_string());
    sign_page_request_with(&cast.fixture.member_kp, &mut request);
    for verified in [false, true] {
        assert!(
            served(owner, &r_id, request.clone(), verified)
                .await
                .is_none(),
            "a removed member gets no page and no proof (verified: {verified})"
        );
    }
    let refused = answer_challenge(owner, group_id, &r_hex, "r-asks", 0).await;
    assert!(
        matches!(refused, Err(Refusal::RequesterNotActive)),
        "{refused:?}"
    );
    cast.shutdown().await;
    Ok(())
}

type Mutation<'a> = Box<dyn Fn(&mut HeadProof) + 'a>;

#[tokio::test]
async fn a_proof_verifies_only_for_its_signer_key_requester_nonce_and_group() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let proof = owner_proof(&cast, "n").await;
    assert!(verify(&proof));
    let s2_hex = hex_id(&cast.s2.agent.agent_id());
    let mutations: Vec<(&str, Mutation<'_>)> = vec![
        (
            "requester",
            Box::new(|p| p.claim.requester = s2_hex.clone()),
        ),
        ("nonce", Box::new(|p| p.claim.nonce.push('x'))),
        ("group", Box::new(|p| p.claim.group_id.push('0'))),
        ("epoch", Box::new(|p| p.claim.treekem_epoch += 1)),
        (
            "authenticator",
            Box::new(|p| p.claim.epoch_authenticator = "00".repeat(32)),
        ),
        ("admins", Box::new(|p| p.claim.admins.clear())),
        ("revision", Box::new(|p| p.claim.state_revision += 1)),
        ("binding", Box::new(|p| p.claim.security_binding = None)),
        ("version", Box::new(|p| p.claim.version = 2)),
        // Re-attribution: the owner's signature, claimed by another member.
        ("signer", Box::new(|p| p.claim.signer = s2_hex.clone())),
    ];
    for (field, mutate) in mutations {
        let mut changed = proof.clone();
        mutate(&mut changed);
        assert!(!verify(&changed), "a changed {field} does not verify");
    }

    // Another key cannot sign as the owner, and a stranger's own proof
    // names the stranger.
    let stranger = x0x::identity::AgentKeypair::generate()?;
    let forged = sign_claim_with(&stranger, proof.claim.clone());
    assert!(
        !verify(&forged),
        "a key that is not the owner's cannot sign as the owner"
    );
    let mut own_claim = proof.claim.clone();
    own_claim.signer = hex_id(&stranger.agent_id());
    let own = sign_claim_with(&stranger, own_claim);
    assert!(
        verify(&own),
        "a stranger's proof verifies, but only as the stranger"
    );

    // S1 records only a proof whose signer it asked, for itself, in this
    // group, under its round's nonce.
    let round = challenge_admins(&cast.s1, &cast.fixture.group_id, &[])
        .await
        .expect("S1 opens a round");
    let mut stranger_claim = owner_proof(&cast, &round.nonce).await.claim;
    stranger_claim.signer = hex_id(&stranger.agent_id());
    assert_eq!(
        record_proof(
            &cast.s1,
            &cast.fixture.group_id,
            sign_claim_with(&stranger, stranger_claim)
        )
        .await,
        Err(NotRecorded::NotAsked)
    );
    let mut for_s2 = owner_proof(&cast, &round.nonce).await;
    for_s2.claim.requester = s2_hex.clone();
    assert!(record_proof(&cast.s1, &cast.fixture.group_id, for_s2)
        .await
        .is_err());
    let genuine = owner_proof(&cast, &round.nonce).await;
    assert_eq!(
        record_proof(&cast.s1, &cast.fixture.group_id, genuine).await,
        Ok(())
    );
    assert_eq!(
        s1_recorded(&cast),
        vec![hex_id(&cast.fixture.state.agent.agent_id())]
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_replayed_proof_for_another_nonce_is_not_recorded() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = &cast.fixture.group_id;
    let old = owner_proof(&cast, "an-old-nonce").await;
    let first = challenge_admins(&cast.s1, group_id, &[])
        .await
        .expect("S1 opens a round");
    deliver_proof(&cast, old).await;
    assert!(
        s1_recorded(&cast).is_empty(),
        "a proof for another nonce is dropped"
    );

    let answer = owner_proof(&cast, &first.nonce).await;
    deliver_proof(&cast, answer.clone()).await;
    assert_eq!(
        s1_recorded(&cast).len(),
        1,
        "the round's own proof is recorded"
    );

    // A new round replaces the old one, and the old round's proof is a replay.
    let second = challenge_admins(&cast.s1, group_id, &[])
        .await
        .expect("S1 opens another round");
    assert_ne!(second.nonce, first.nonce, "every round has a fresh nonce");
    assert!(s1_recorded(&cast).is_empty(), "a new round starts empty");
    assert_eq!(
        record_proof(&cast.s1, group_id, answer).await,
        Err(NotRecorded::OtherNonce)
    );
    assert!(s1_recorded(&cast).is_empty());
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_proof_after_the_round_deadline_is_not_recorded() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = &cast.fixture.group_id;
    let round = challenge_admins(&cast.s1, group_id, &[])
        .await
        .expect("S1 opens a round");
    let answer = owner_proof(&cast, &round.nonce).await;
    head_proof::backdate_round(&cast.s1, group_id, std::time::Duration::from_secs(61));
    assert_eq!(
        record_proof(&cast.s1, group_id, answer.clone()).await,
        Err(NotRecorded::Late)
    );
    assert!(s1_recorded(&cast).is_empty());

    head_proof::backdate_round(&cast.s1, group_id, std::time::Duration::from_secs(59));
    assert_eq!(record_proof(&cast.s1, group_id, answer).await, Ok(()));
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_challenge_right_after_a_page_request_still_gets_a_proof() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let s1_id = cast.s1.agent.agent_id();
    let page = page_request(&cast.s1, group_id, None)
        .await
        .expect("S1 asks from its head");
    assert!(
        served(owner, &s1_id, page.clone(), false).await.is_some(),
        "the owner serves S1's page"
    );
    assert!(
        served(owner, &s1_id, page, false).await.is_none(),
        "the same page inside the window is throttled (#378)"
    );

    let round = challenge_admins(&cast.s1, group_id, &[])
        .await
        .expect("S1 opens a round");
    let sent: Vec<TreeKemCatchupRequest> = cast
        .s1
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .expect("page request recorder")
        .iter()
        .map(|(_, bytes)| serde_json::from_slice(bytes).expect("a request"))
        .collect();
    let challenge = sent
        .into_iter()
        .rev()
        .find(|request| request.head_challenge.as_deref() == Some(round.nonce.as_str()))
        .expect("S1 sent the owner its challenge");
    let answer = served(owner, &s1_id, challenge, false)
        .await
        .expect("the challenge is answered inside the page window");
    assert!(
        answer.events.is_empty(),
        "the page itself is still throttled"
    );
    let proof = answer.head_proof.clone().expect("but the proof is sent");
    assert_eq!(proof.claim.nonce, round.nonce);
    handle_treekem_catchup_response(&cast.s1, &owner.agent.agent_id(), false, answer).await;
    assert_eq!(s1_recorded(&cast), vec![hex_id(&owner.agent.agent_id())]);
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_requester_gets_at_most_twelve_proofs_a_minute() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let s1_id = cast.s1.agent.agent_id();
    let mut proofs = 0;
    for n in 0..=HEAD_PROOFS_PER_WINDOW {
        let request = challenge(&cast.s1, group_id, &format!("n{n}")).await;
        if served(owner, &s1_id, request, false)
            .await
            .and_then(|response| response.head_proof)
            .is_some()
        {
            proofs += 1;
        }
    }
    assert_eq!(proofs, HEAD_PROOFS_PER_WINDOW);
    let s2_hex = hex_id(&cast.s2.agent.agent_id());
    assert!(
        answer_challenge(owner, group_id, &s2_hex, "s2", 0)
            .await
            .is_ok(),
        "the limit is per requester"
    );
    assert!(matches!(
        answer_challenge(owner, group_id, &hex_id(&s1_id), "s1", 0).await,
        Err(Refusal::Limited)
    ));
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_challenge_from_ahead_starts_the_responders_epoch_ahead_catch_up() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let r_hex = hex_id(&cast.fixture.member_id);
    let response = remove_named_group_member(
        State(Arc::clone(owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), r_hex)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner removes R");
    let removal = super::epoch_ahead_catchup::published_removal_event(owner)
        .expect("the owner publishes the removal");
    s2_applies(&cast, &removal).await;
    let ahead = live_epoch(&cast.s2, group_id).await;
    let behind = live_epoch(&cast.s1, group_id).await;
    assert!(ahead > behind, "S2 is ahead of S1");
    assert!(cast.s1.treekem_epoch_ahead_targets.lock().await.is_empty());

    let request = challenge(&cast.s2, group_id, "from-ahead").await;
    assert_eq!(request.from_treekem_epoch, ahead);
    let _ = served(&cast.s1, &cast.s2.agent.agent_id(), request, false).await;
    // The catch-up runs as its own task, which notes its target first.
    wait_until(|| {
        cast.s1
            .treekem_epoch_ahead_targets
            .try_lock()
            .is_ok_and(|targets| targets.contains_key(group_id))
    })
    .await;
    let started = cast
        .s1
        .treekem_epoch_ahead_targets
        .lock()
        .await
        .get(group_id)
        .copied();
    assert_eq!(
        started.map(|target| target.epoch),
        Some(ahead),
        "the responder starts its catch-up toward the requester's epoch"
    );
    wait_until(|| {
        !cast
            .s1
            .named_group_test_recorders
            .catchup_page_requests
            .lock()
            .expect("page request recorder")
            .is_empty()
    })
    .await;
    assert!(
        !cast
            .s1
            .named_group_test_recorders
            .catchup_page_requests
            .lock()
            .expect("page request recorder")
            .is_empty(),
        "and asks a member for the commits it missed"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_stale_roster_admin_commit_does_not_remove_an_anchor_admin_from_the_challenge_set(
) -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = &cast.fixture.group_id;
    let owner_hex = hex_id(&cast.fixture.state.agent.agent_id());
    let r_hex = hex_id(&cast.fixture.member_id);
    // On S1's stale roster, R (an admin there) removed the owner.
    {
        let mut groups = cast.s1.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group");
        info.set_member_role(&r_hex, x0x::groups::GroupRole::Admin);
        info.remove_member(&owner_hex, Some(r_hex.clone()));
        assert!(!info.has_active_member(&owner_hex));
    }
    let roster_only = challenge_admins(&cast.s1, group_id, &[])
        .await
        .expect("S1 opens a round");
    assert_eq!(
        roster_only.asked.iter().cloned().collect::<Vec<_>>(),
        vec![r_hex.clone()],
        "the roster alone names only R"
    );

    let anchored = challenge_admins(&cast.s1, group_id, &[owner_hex.clone(), r_hex.clone()])
        .await
        .expect("S1 opens a round");
    let mut expected = vec![owner_hex.clone(), r_hex.clone()];
    expected.sort();
    assert_eq!(
        anchored.asked.iter().cloned().collect::<Vec<_>>(),
        expected,
        "an admin the engine names stays in the challenge set"
    );
    let to_owner = cast
        .s1
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .expect("page request recorder")
        .iter()
        .filter(|(peer, _)| peer == &owner_hex)
        .filter_map(|(_, bytes)| serde_json::from_slice::<TreeKemCatchupRequest>(bytes).ok())
        .any(|request| {
            request.head_challenge.as_deref() == Some(anchored.nonce.as_str())
                && super::super::signed_catchup::page_request_signed(&request)
        });
    assert!(to_owner, "S1 sends the owner its signed challenge");
    let open = round_view(&cast.s1, group_id).expect("S1's round is open");
    assert_eq!(open.nonce, anchored.nonce);
    assert_eq!(open.asked, anchored.asked);
    assert!(open.opened_at <= tokio::time::Instant::now());
    assert!(open.proofs.is_empty());
    cast.shutdown().await;
    Ok(())
}

/// F-1: with the test knob's effect on, an admin signs the next epoch and
/// a random authenticator, and the proof still verifies as its own.
#[tokio::test]
async fn an_inflating_admin_signs_the_next_epoch_and_a_random_authenticator() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let s1_hex = hex_id(&cast.s1.agent.agent_id());
    let honest = answer_challenge_with(owner, group_id, &s1_hex, "h", 0, false)
        .await
        .expect("an honest proof");
    let inflated = answer_challenge_with(owner, group_id, &s1_hex, "i", 0, true)
        .await
        .expect("an inflated proof");
    assert!(verify(&inflated), "it is signed like any other");
    assert_eq!(inflated.claim.treekem_epoch, honest.claim.treekem_epoch + 1);
    assert_ne!(
        inflated.claim.epoch_authenticator,
        honest.claim.epoch_authenticator
    );
    assert_eq!(
        honest.claim.treekem_epoch,
        live_epoch(owner, group_id).await
    );
    cast.shutdown().await;
    Ok(())
}

/// A5 review r-2: every writer of the catch-up throttle drops expired keys
/// once the map is large, here the member-keyed serve.
#[tokio::test]
async fn the_member_keyed_serve_prunes_the_catchup_throttle() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let now = tokio::time::Instant::now();
    let Some(old) = now.checked_sub(std::time::Duration::from_secs(2 * 60 * 60)) else {
        cast.shutdown().await;
        return Ok(());
    };
    {
        let mut throttle = owner.treekem_catchup_throttle.write().await;
        for n in 0..1100 {
            throttle.insert(format!("g:old:{n}"), old);
        }
    }
    let s1_id = cast.s1.agent.agent_id();
    let mut request = catchup_request_from(
        &roster(&cast.s1, &cast.fixture.group_id).await,
        &cast.fixture.group_id,
        &s1_id,
    );
    request.target_member_id = Some(hex_id(&cast.s2.agent.agent_id()));
    handle_treekem_catchup_request(owner, &s1_id, true, request).await;
    let throttle = owner.treekem_catchup_throttle.read().await;
    assert!(
        !throttle.keys().any(|key| key.starts_with("g:old:")),
        "expired keys are dropped"
    );
    assert!(
        throttle.keys().any(|key| key.contains(":mk-serve:")),
        "the serve is stamped"
    );
    drop(throttle);
    cast.shutdown().await;
    Ok(())
}

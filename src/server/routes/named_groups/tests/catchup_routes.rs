//! Survivor re-key A7: the four routes the engine uses to ask a room's
//! admins where its key stands, through the auth middleware and the #1166
//! chokepoint. See `docs/adr/transient/T-treekem-head-proof.md`.
//!
//! The cast is the survivor fixture: the owner (the only admin), the
//! removed member R (a key, not a daemon), and the members S1 and S2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::head_proof::{
    challenge_nonce, sign_claim_with, verify, HeadClaim, HeadProof, HEAD_PROOF_VERSION,
};
use super::super::head_rounds::{backdate_round, next_challenge, round_view, ROUND_MIN_GAP};
use super::super::signed_catchup::{
    page_request, page_request_signed, sign_page_request, sign_page_request_with,
};
use super::epoch_ahead_catchup::{
    catchup_request_from, live_epoch, live_treekem_group, survivor_relay_fixture, wait_until,
    SurvivorRelay,
};
use super::signer_delivery::{hex_id, published, role_route, roster};
use super::*;
use axum::body::Body;
use axum::http::{Method, Request};
use axum::routing::{get, post};
use tower::ServiceExt as _;

fn app(state: &Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route(
            "/groups/:id/treekem/catch-up",
            get(treekem_catch_up_state).post(treekem_catch_up_trigger),
        )
        .route(
            "/groups/:id/treekem/head-proof",
            post(treekem_head_proof_sign),
        )
        .route(
            "/groups/:id/treekem/head-proof/accept",
            post(treekem_head_proof_accept),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            auth::auth_middleware,
        ))
        .with_state(Arc::clone(state))
}

async fn call(
    state: &Arc<AppState>,
    method: Method,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&body).expect("body"))
        }
        None => Body::empty(),
    };
    let response = app(state)
        .oneshot(request.body(body).expect("request"))
        .await
        .expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    // An extractor's own rejection is plain text.
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
    });
    (status, body)
}

fn trigger_path(group_id: &str) -> String {
    format!("/groups/{group_id}/treekem/catch-up")
}

fn state_path(group_id: &str, since: u64) -> String {
    format!("/groups/{group_id}/treekem/catch-up?since_revision={since}")
}

fn sign_path(group_id: &str) -> String {
    format!("/groups/{group_id}/treekem/head-proof")
}

fn accept_path(group_id: &str) -> String {
    format!("/groups/{group_id}/treekem/head-proof/accept")
}

async fn trigger(
    state: &Arc<AppState>,
    group_id: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    call(
        state,
        Method::POST,
        &trigger_path(group_id),
        &state.api_token,
        Some(body),
    )
    .await
}

async fn read_state(state: &Arc<AppState>, group_id: &str, since: u64) -> serde_json::Value {
    let (status, body) = call(
        state,
        Method::GET,
        &state_path(group_id, since),
        &state.api_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn sign(
    admin: &Arc<AppState>,
    group_id: &str,
    request: &TreeKemCatchupRequest,
) -> (StatusCode, serde_json::Value) {
    call(
        admin,
        Method::POST,
        &sign_path(group_id),
        &admin.api_token,
        Some(serde_json::json!({ "request": request })),
    )
    .await
}

async fn accept(
    state: &Arc<AppState>,
    group_id: &str,
    proof: &HeadProof,
) -> (StatusCode, serde_json::Value) {
    call(
        state,
        Method::POST,
        &accept_path(group_id),
        &state.api_token,
        Some(serde_json::json!({ "proof": proof })),
    )
    .await
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.as_str().expect("a string").to_string())
        .collect()
}

fn sorted(mut agents: Vec<String>) -> Vec<String> {
    agents.sort();
    agents
}

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

/// The page requests `state` sent `peer` carrying `nonce`.
fn sent_to(state: &AppState, peer: &str, nonce: &str) -> Vec<TreeKemCatchupRequest> {
    state
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .expect("page request recorder")
        .iter()
        .filter(|(to, _)| to == peer)
        .filter_map(|(_, bytes)| serde_json::from_slice::<TreeKemCatchupRequest>(bytes).ok())
        .filter(|request| request.head_challenge.as_deref() == Some(nonce))
        .collect()
}

fn the_owner(cast: &SurvivorRelay) -> String {
    hex_id(&cast.fixture.state.agent.agent_id())
}

async fn authenticator_hex(state: &AppState, group_id: &str) -> String {
    let group = live_treekem_group(state, group_id).await;
    let guard = group.lock().await;
    hex::encode(guard.epoch_authenticator().expect("authenticator"))
}

async fn rider_token(state: &AppState, group_id: &str) -> String {
    let mut tokens = state.rider_tokens.lock().await;
    tokens
        .issue(
            "83".repeat(32),
            vec![group_id.to_string()],
            None,
            60,
            "84".repeat(32),
            None,
            None,
            crate::server::rider_auth::unix_now_secs(),
        )
        .await
        .expect("rider token")
        .0
}

#[tokio::test]
async fn trigger_challenges_the_named_admins_and_roster_admins_only() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let owner_hex = the_owner(&cast);
    // An admin the engine anchored that S1's roster does not list (a
    // stale commit may have removed it); named in upper case.
    let anchored = "ab".repeat(32);
    let (status, body) = trigger(
        s1,
        group_id,
        serde_json::json!({ "challenge": [anchored.to_ascii_uppercase()] }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["catching_up"], false);
    let asked = strings(&body["asked"]);
    assert_eq!(
        asked,
        sorted(vec![owner_hex.clone(), anchored.clone()]),
        "the named agent and the roster's admin, nobody else"
    );
    for not_asked in [
        hex_id(&cast.s2.agent.agent_id()),
        hex_id(&cast.fixture.member_id),
        hex_id(&s1.agent.agent_id()),
    ] {
        assert!(!asked.contains(&not_asked), "{not_asked} is not an admin");
    }
    let round = body["round"].as_str().expect("the round").to_string();
    let open = round_view(s1, group_id).expect("S1's round is open");
    assert_eq!(open.nonce, round);
    assert_eq!(open.asked.iter().cloned().collect::<Vec<_>>(), asked);

    // The request the engine can carry over the relay is S1's own signed
    // challenge for this round.
    let request: TreeKemCatchupRequest = serde_json::from_value(body["request"].clone())?;
    assert!(page_request_signed(&request));
    assert_eq!(request.head_challenge.as_deref(), Some(round.as_str()));
    assert_eq!(request.requester_agent_id, hex_id(&s1.agent.agent_id()));

    for peer in [&owner_hex, &anchored] {
        wait_until(|| !sent_to(s1, peer, &round).is_empty()).await;
        assert!(
            sent_to(s1, peer, &round).iter().all(page_request_signed),
            "{peer} gets S1's signed challenge"
        );
    }
    for peer in [
        hex_id(&cast.s2.agent.agent_id()),
        hex_id(&cast.fixture.member_id),
    ] {
        assert!(
            sent_to(s1, &peer, &round).is_empty(),
            "a member that is not an admin is not challenged"
        );
    }

    let (status, body) = trigger(
        s1,
        group_id,
        serde_json::json!({ "challenge": ["not an agent"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "bad_challenge_agent");
    assert_eq!(body["round"], serde_json::Value::Null);
    assert_eq!(body["hold"], true);
    assert!(
        round_view(s1, group_id).is_none(),
        "a refused trigger closes the last round (review m-6)"
    );
    let _ = round;
    cast.shutdown().await;
    Ok(())
}

/// A6 review C-1 carried: when the named agents and the roster admins are
/// more than a round holds, the trigger says so and the room holds. It
/// never opens a round with fewer agents.
#[tokio::test]
async fn trigger_that_would_ask_too_many_opens_no_round_and_says_hold() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let (status, body) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let earlier = body["round"].as_str().expect("a round").to_string();
    let sent_before = s1
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .expect("page request recorder")
        .len();

    backdate_round(s1, group_id, ROUND_MIN_GAP);
    let named: Vec<String> = (0..HEAD_PROOF_MAX_ADMINS_FOR_TESTS)
        .map(|n| format!("{n:064x}"))
        .collect();
    let (status, body) = trigger(s1, group_id, serde_json::json!({ "challenge": named })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["ok"], false);
    assert_eq!(body["reason"], "challenge_set_too_large");
    assert_eq!(body["retry"], "never");
    assert_eq!(body["hold"], true);
    assert_eq!(body["round"], serde_json::Value::Null);
    assert_eq!(body["asked"], serde_json::json!([]));
    assert!(
        round_view(s1, group_id).is_none(),
        "no new round, no smaller one, and the earlier round is closed (review m-6)"
    );
    let _ = earlier;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let sent_after = s1
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .expect("page request recorder")
        .len();
    assert!(
        sent_after <= sent_before + 1,
        "nobody new is challenged (the earlier round's one send may still land)"
    );
    cast.shutdown().await;
    Ok(())
}

const HEAD_PROOF_MAX_ADMINS_FOR_TESTS: usize = super::super::head_proof::HEAD_PROOF_MAX_ADMINS;

#[tokio::test]
async fn trigger_with_an_observed_epoch_starts_the_epoch_ahead_task() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let live = live_epoch(s1, group_id).await;

    let (status, body) = trigger(
        s1,
        group_id,
        serde_json::json!({ "observed_epoch": live, "challenge": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["catching_up"], false, "not ahead: no catch-up");
    assert!(s1.treekem_epoch_ahead_targets.lock().await.is_empty());

    backdate_round(s1, group_id, ROUND_MIN_GAP);
    let (status, body) = trigger(
        s1,
        group_id,
        serde_json::json!({ "observed_epoch": live + 3, "challenge": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["catching_up"], true);
    wait_until(|| {
        s1.treekem_epoch_ahead_targets
            .try_lock()
            .is_ok_and(|targets| targets.contains_key(group_id.as_str()))
    })
    .await;
    assert_eq!(
        s1.treekem_epoch_ahead_targets
            .lock()
            .await
            .get(group_id.as_str())
            .map(|target| target.epoch),
        Some(live + 3),
        "the epoch-ahead task runs toward the observed epoch"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn get_reports_head_presence_and_round() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let owner_hex = the_owner(&cast);
    let info = roster(s1, group_id).await;

    let body = read_state(s1, group_id, info.state_revision).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["epoch"], live_epoch(s1, group_id).await);
    assert_eq!(
        body["epoch_authenticator"],
        authenticator_hex(s1, group_id).await,
        "read from the live tree"
    );
    assert_eq!(
        body["security_binding"],
        serde_json::json!(info.security_binding)
    );
    assert_eq!(body["revision"], info.state_revision);
    assert_eq!(body["state_hash"], info.state_hash.as_str());
    assert_eq!(body["admins_since_complete"], true);
    assert_eq!(body["admins_since_too_large"], false);
    let (status, other_anchor) = call(
        s1,
        Method::GET,
        &format!(
            "{}&since_state_hash=another",
            state_path(group_id, info.state_revision)
        ),
        &s1.api_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        other_anchor["admins_since_complete"], false,
        "an anchor that is not this daemon's state at that revision holds"
    );
    assert_eq!(strings(&body["admins"]), vec![owner_hex.clone()]);
    assert_eq!(body["admins_since"], serde_json::json!([]));
    assert_eq!(body["started_at_ms"], s1.started_at_ms);
    // A8 fills the presence facts; until then they fail closed.
    assert_eq!(body["connected_admins"], serde_json::json!([]));
    assert_eq!(body["suspended_since_last_get"], true);
    assert_eq!(body["round"], serde_json::Value::Null);

    let (status, opened) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{opened}");
    let round = opened["round"].as_str().expect("a round").to_string();
    let body = read_state(s1, group_id, info.state_revision).await;
    let reported = body["round"].as_object().expect("the open round");
    let mut keys: Vec<&str> = reported.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["asked", "conflicted", "heads", "round"],
        "no opening time and no age: the engine times rounds itself"
    );
    assert_eq!(reported["round"], round.as_str());
    assert_eq!(strings(&reported["asked"]), vec![owner_hex.clone()]);
    assert_eq!(reported["heads"], serde_json::json!([]));

    // The relay leg: the owner's engine has its daemon sign S1's carried
    // challenge, and S1's engine hands the proof to its daemon.
    let request: TreeKemCatchupRequest = serde_json::from_value(opened["request"].clone())?;
    let (status, signed) = sign(owner, group_id, &request).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let proof: HeadProof = serde_json::from_value(signed["proof"].clone())?;
    assert!(verify(&proof));
    let (status, recorded) = accept(s1, group_id, &proof).await;
    assert_eq!(status, StatusCode::OK, "{recorded}");
    assert_eq!(recorded["recorded"], true, "{recorded}");

    let body = read_state(s1, group_id, info.state_revision).await;
    let heads = body["round"]["heads"].as_array().expect("heads");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0]["signer"], owner_hex.as_str());
    assert_eq!(heads[0]["treekem_epoch"], body["epoch"]);
    assert_eq!(
        heads[0]["epoch_authenticator"], body["epoch_authenticator"],
        "S1 is at the owner's head"
    );
    assert_eq!(body["round"]["conflicted"], serde_json::json!([]));

    // The anchor revision is required.
    let (status, _) = call(
        s1,
        Method::GET,
        &trigger_path(group_id),
        &s1.api_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    cast.shutdown().await;
    Ok(())
}

/// M-d: one catch-up page that applies several states loses none of their
/// admins, even one who came and went inside the page.
#[tokio::test]
async fn get_reports_the_admins_of_every_state_applied_in_one_burst() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let owner_hex = the_owner(&cast);
    let s2_hex = hex_id(&cast.s2.agent.agent_id());
    let anchor = roster(s1, group_id).await.state_revision;
    let role_update = |event: &NamedGroupMetadataEvent| {
        matches!(event, NamedGroupMetadataEvent::MemberRoleUpdated { .. })
    };

    role_route(owner, group_id, &s2_hex, "admin").await;
    let promotion = published(owner, role_update).expect("the promotion");
    role_route(owner, group_id, &s2_hex, "member").await;
    let demotion = published(owner, role_update).expect("the demotion");
    let promoted_at = named_group_metadata_event_commit(&promotion)
        .expect("signed")
        .revision;

    handle_treekem_catchup_response(
        s1,
        &owner.agent.agent_id(),
        true,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.clone(),
            events: vec![promotion, demotion],
            truncated: false,
            responder_state_hash: None,
            log_evicted_through: None,
            target_member_id: None,
            target_member_key_package_b64: None,
            signed_by: None,
            head_proof: None,
        },
    )
    .await;
    let now = roster(s1, group_id).await;
    assert_eq!(
        now.state_revision,
        roster(owner, group_id).await.state_revision,
        "S1 applied the whole page"
    );

    let body = read_state(s1, group_id, anchor).await;
    assert_eq!(strings(&body["admins"]), vec![owner_hex.clone()]);
    assert_eq!(
        body["admins_since"],
        serde_json::json!([sorted(vec![owner_hex.clone(), s2_hex.clone()]), [owner_hex]]),
        "S2 was an admin in between, and is reported"
    );
    assert_eq!(body["admins_since_complete"], true);

    let body = read_state(s1, group_id, promoted_at).await;
    assert_eq!(body["admins_since"], serde_json::json!([[owner_hex]]));
    assert_eq!(body["admins_since_complete"], true);
    let body = read_state(s1, group_id, now.state_revision).await;
    assert_eq!(body["admins_since"], serde_json::json!([]));
    assert_eq!(body["admins_since_complete"], true);
    let body = read_state(s1, group_id, now.state_revision + 1).await;
    assert_eq!(
        body["admins_since_complete"], false,
        "an anchor this daemon has not reached"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn head_proof_route_refuses_a_session_bearer_and_a_rider() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let request = challenge(&cast.s1, group_id, &next_challenge(&cast.s1).await).await;
    let session = owner.sessions.issue(std::time::Instant::now());
    let rider = rider_token(owner, group_id).await;
    let posts = [
        (
            sign_path(group_id),
            serde_json::json!({ "request": request }),
        ),
        (
            trigger_path(group_id),
            serde_json::json!({ "challenge": [] }),
        ),
        (accept_path(group_id), serde_json::json!({ "proof": {} })),
    ];
    for (path, body) in &posts {
        for token in [&session, &rider] {
            let (status, refused) =
                call(owner, Method::POST, path, token, Some(body.clone())).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {refused}");
        }
    }
    assert!(
        round_view(owner, group_id).is_none(),
        "no refused bearer opened a round"
    );
    // The read: a rider is refused; a session bearer reads this daemon's
    // seat like the durable owner.
    let revision = roster(owner, group_id).await.state_revision;
    let (status, _) = call(
        owner,
        Method::GET,
        &state_path(group_id, revision),
        &rider,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = call(
        owner,
        Method::GET,
        &state_path(group_id, revision),
        &session,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The durable token signs.
    let (status, signed) = sign(owner, group_id, &request).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let proof: HeadProof = serde_json::from_value(signed["proof"].clone())?;
    assert!(verify(&proof));
    assert_eq!(proof.claim.requester, hex_id(&cast.s1.agent.agent_id()));
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn head_proof_route_refuses_a_departed_requester() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let r_id = cast.fixture.member_id;
    let held = roster(owner, group_id).await;
    let removed = remove_named_group_member(
        State(Arc::clone(owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), hex_id(&r_id))),
    )
    .await
    .into_response();
    assert_eq!(removed.status(), StatusCode::OK, "the owner removes R");

    let mut request = catchup_request_from(&held, group_id, &r_id);
    request.head_challenge = Some(challenge_nonce(u64::MAX - 1));
    sign_page_request_with(&cast.fixture.member_kp, &mut request);
    assert!(page_request_signed(&request), "R signed its own challenge");
    let (status, body) = sign(owner, group_id, &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reason"], "requester_not_active");
    assert_eq!(body["retry"], "never");
    assert!(body.get("proof").is_none());
    cast.shutdown().await;
    Ok(())
}

/// The A6 refusals each reach the engine as their own reason, so it can
/// tell "hold and retry later" from "never".
#[tokio::test]
async fn head_proof_route_maps_every_refusal_to_its_reason() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let expect = |(status, body): (StatusCode, serde_json::Value),
                  want: StatusCode,
                  reason: &str,
                  retry: &str| {
        assert_eq!(status, want, "{reason}: {body}");
        assert_eq!(body["reason"], reason, "{body}");
        assert_eq!(body["retry"], retry, "{body}");
    };

    let plain = page_request(s1, group_id, None).await.expect("a request");
    expect(
        sign(owner, group_id, &plain).await,
        StatusCode::BAD_REQUEST,
        "no_challenge",
        "never",
    );
    let older = next_challenge(s1).await;
    let newest = next_challenge(s1).await;
    let mut unsigned = challenge(s1, group_id, &newest).await;
    unsigned.signed_by = None;
    expect(
        sign(owner, group_id, &unsigned).await,
        StatusCode::BAD_REQUEST,
        "challenge_not_signed",
        "never",
    );
    let mut swapped = challenge(s1, group_id, &newest).await;
    swapped.head_challenge = Some(challenge_nonce(u64::MAX));
    expect(
        sign(owner, group_id, &swapped).await,
        StatusCode::BAD_REQUEST,
        "challenge_not_signed",
        "never",
    );
    let mut elsewhere = challenge(s1, group_id, &newest).await;
    elsewhere.group_id = "ee".repeat(32);
    sign_page_request(s1, &mut elsewhere);
    expect(
        sign(owner, group_id, &elsewhere).await,
        StatusCode::BAD_REQUEST,
        "group_mismatch",
        "never",
    );
    expect(
        sign(
            owner,
            group_id,
            &challenge(s1, group_id, "fresh-nonce").await,
        )
        .await,
        StatusCode::BAD_REQUEST,
        "bad_challenge",
        "never",
    );
    expect(
        sign(&cast.s2, group_id, &challenge(s1, group_id, &newest).await).await,
        StatusCode::CONFLICT,
        "not_an_admin",
        "never",
    );

    let current = challenge(s1, group_id, &newest).await;
    let (status, body) = sign(owner, group_id, &current).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    expect(
        sign(owner, group_id, &challenge(s1, group_id, &older).await).await,
        StatusCode::CONFLICT,
        "stale_challenge",
        "never",
    );
    let (status, again) = sign(owner, group_id, &current).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the latest is re-sent once: {again}"
    );
    assert_eq!(
        again["proof"], body["proof"],
        "from cache, not signed again"
    );
    expect(
        sign(owner, group_id, &current).await,
        StatusCode::TOO_MANY_REQUESTS,
        "repeat_too_soon",
        "later",
    );

    // Newer challenges are answered within the limit, then limited.
    let mut limited = None;
    for _ in 0..super::super::head_proof::HEAD_PROOFS_PER_WINDOW {
        let fresh = challenge(s1, group_id, &next_challenge(s1).await).await;
        let answered = sign(owner, group_id, &fresh).await;
        if answered.0 != StatusCode::OK {
            limited = Some(answered);
            break;
        }
    }
    expect(
        limited.expect("the limit is reached"),
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "new_round",
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn accept_route_records_only_a_proof_for_the_open_round() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = &cast.fixture.state;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;

    let (status, first) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let request: TreeKemCatchupRequest = serde_json::from_value(first["request"].clone())?;
    let (status, signed) = sign(owner, group_id, &request).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let proof: HeadProof = serde_json::from_value(signed["proof"].clone())?;

    let mut tampered = proof.clone();
    tampered.claim.treekem_epoch += 1;
    let (status, body) = accept(s1, group_id, &tampered).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recorded"], false);
    assert_eq!(body["reason"], "bad_signature");

    let (_, body) = accept(s1, group_id, &proof).await;
    assert_eq!(body["recorded"], true, "{body}");
    let (_, body) = accept(&cast.s2, group_id, &proof).await;
    assert_eq!(body["recorded"], false);
    assert_eq!(body["reason"], "no_round", "S2 opened no round");

    // Over HTTP, each reason a proof is refused for (review m-8).
    let round = first["round"].as_str().expect("a round").to_string();
    let stranger = crate::identity::AgentKeypair::generate()?;
    let stranger_hex = hex_id(&stranger.agent_id());
    let stranger_claim = |requester: String| HeadClaim {
        version: HEAD_PROOF_VERSION,
        group_id: proof.claim.group_id.clone(),
        requester,
        nonce: round.clone(),
        treekem_epoch: proof.claim.treekem_epoch,
        epoch_authenticator: proof.claim.epoch_authenticator.clone(),
        security_binding: None,
        state_revision: 1,
        admins: vec![stranger_hex.clone()],
        signer: stranger_hex.clone(),
    };
    let unasked = sign_claim_with(&stranger, stranger_claim(hex_id(&s1.agent.agent_id())));
    let (_, body) = accept(s1, group_id, &unasked).await;
    assert_eq!(body["reason"], "not_asked", "{body}");
    let for_s2 = sign_claim_with(&stranger, stranger_claim(hex_id(&cast.s2.agent.agent_id())));
    let (_, body) = accept(s1, group_id, &for_s2).await;
    assert_eq!(body["reason"], "not_for_this_round", "{body}");
    backdate_round(s1, group_id, std::time::Duration::from_secs(61));
    let (_, body) = accept(s1, group_id, &proof).await;
    assert_eq!(body["reason"], "late", "{body}");

    let (status, second) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{second}");
    let (_, body) = accept(s1, group_id, &proof).await;
    assert_eq!(body["recorded"], false);
    assert_eq!(
        body["reason"], "other_nonce",
        "a new round refuses the last round's proof"
    );
    assert!(round_view(s1, group_id)
        .expect("the new round")
        .heads
        .is_empty());
    cast.shutdown().await;
    Ok(())
}

/// A7 review m-5: a room opens at most one round per gap through the
/// trigger. The round opened moments ago stays open, and the answer is a
/// hold that may succeed later.
#[tokio::test]
async fn trigger_opens_at_most_one_round_per_gap() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let (status, body) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let first = body["round"].as_str().expect("a round").to_string();

    let (status, body) = trigger(
        s1,
        group_id,
        serde_json::json!({ "challenge": ["ab".repeat(32)] }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reason"], "round_too_soon");
    assert_eq!(body["retry"], "later");
    assert_eq!(body["hold"], true);
    assert_eq!(body["round"], serde_json::Value::Null);
    assert_eq!(
        round_view(s1, group_id).map(|open| open.nonce),
        Some(first),
        "the round opened moments ago stays open"
    );
    assert!(
        s1.named_group_test_recorders
            .catchup_page_requests
            .lock()
            .expect("page request recorder")
            .iter()
            .all(|(to, _)| *to != "ab".repeat(32)),
        "nobody named in the refused trigger is challenged"
    );

    backdate_round(s1, group_id, ROUND_MIN_GAP);
    let (status, body) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "after the gap: {body}");
    cast.shutdown().await;
    Ok(())
}

/// A7 review m-1 and m-2: a trigger in a room with no tree here is a hold
/// with the hold body; it may change later only on the TreeKEM plane.
#[tokio::test]
async fn trigger_without_a_tree_holds_and_says_whether_it_may_come() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    s1.treekem_groups.write().await.remove(group_id.as_str());
    for (plane, retry) in [
        (x0x::mls::SecureGroupPlane::TreeKem, "later"),
        (x0x::mls::SecureGroupPlane::Gss, "never"),
    ] {
        if let Some(info) = s1.named_groups.write().await.get_mut(group_id.as_str()) {
            info.secure_plane = plane;
        }
        let (status, body) = trigger(s1, group_id, serde_json::json!({ "challenge": [] })).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "not_a_treekem_room");
        assert_eq!(body["retry"], retry, "{plane:?}");
        assert_eq!(body["hold"], true);
        assert_eq!(body["round"], serde_json::Value::Null);
        let revision = roster(s1, group_id).await.state_revision;
        let (status, body) = call(
            s1,
            Method::GET,
            &state_path(group_id, revision),
            &s1.api_token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "not_a_treekem_room");
        assert_eq!(body["retry"], retry, "the same hint on every route");
    }
    cast.shutdown().await;
    Ok(())
}

/// A7 review I-1: the routes run in a fork-quarantined room (ADR-0066
/// control plane), so the GET says the room is quarantined, with the
/// marker's wire fields only.
#[tokio::test]
async fn get_reports_a_fork_quarantined_room() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let s1 = &cast.s1;
    let group_id = &cast.fixture.group_id;
    let revision = roster(s1, group_id).await.state_revision;
    let body = read_state(s1, group_id, revision).await;
    assert_eq!(body["fork_quarantined"], false);
    assert_eq!(body["fork_quarantine"], serde_json::Value::Null);

    {
        let mut groups = s1.named_groups.write().await;
        let info = groups.get_mut(group_id.as_str()).expect("group");
        let header = info.terminal_commit_header();
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: 9,
            state_hash: info.state_hash.clone(),
            committed_by: "87".repeat(32),
            observed_at_ms: 1_788_091_300_000,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: header.clone(),
                conflicting_commit: header,
                classification: None,
            },
            no_anchor: true,
        });
    }
    let body = read_state(s1, group_id, revision).await;
    assert_eq!(body["fork_quarantined"], true, "{body}");
    assert_eq!(
        body["fork_quarantine"],
        serde_json::json!({ "revision": 9, "no_anchor": true }),
        "the wire fields only: no snapshot, no committer"
    );
    assert_eq!(
        body["epoch"],
        live_epoch(s1, group_id).await,
        "still a head"
    );

    if let Some(info) = s1.named_groups.write().await.get_mut(group_id.as_str()) {
        info.fork_quarantine = None;
    }
    let body = read_state(s1, group_id, revision).await;
    assert_eq!(body["fork_quarantined"], false);
    cast.shutdown().await;
    Ok(())
}

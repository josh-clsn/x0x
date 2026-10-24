//! Survivor re-key A5: a phone or an agent at rest, whose direct messages
//! its peers cannot verify, pulls the commits it missed with a signed page
//! request, and applies a page it cannot verify itself. On such a page the
//! claimed sender counts for nothing. A page never leaves a member stuck
//! behind a hole (the A4 review's n-1). See
//! `docs/adr/transient/T-signed-catchup-pages.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::catchup_page_gap::GAP_ASK_PEERS;
use super::super::signed_catchup::{
    page_request, page_request_signed, sign_page_request, sign_page_request_with,
};
use super::epoch_ahead_catchup::{
    catchup_relay_fixture, catchup_request_from, deliver_catchup, encrypt, group_is_quarantined,
    legacy_bound_removal, live_epoch, live_treekem_group, published_removal_event, roster_head,
    survivor_relay_fixture, swap_treekem_commit, wait_until, CatchupRelay, SurvivorRelay,
};
use super::signer_delivery::{
    hex_id, owner_extension, published, rename_route, roster, s1_follows_the_owner, s2_applies,
};
use super::*;

/// `state` gets `events` in a page whose transport did not verify
/// `claimed`.
async fn unverified_page(
    state: &Arc<AppState>,
    claimed: &x0x::identity::AgentId,
    group_id: &str,
    events: Vec<NamedGroupMetadataEvent>,
    truncated: bool,
) {
    handle_treekem_catchup_response(
        state,
        claimed,
        false,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.to_string(),
            events,
            truncated,
            responder_state_hash: None,
            log_evicted_through: None,
            target_member_id: None,
            target_member_key_package_b64: None,
            signed_by: None,
        },
    )
    .await;
}

/// The page `server` serves for `request`, if it serves one.
async fn served_page(
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
        .map(|bytes| serde_json::from_slice(bytes).expect("a catch-up page"))
}

/// The page requests `state` sent, as `(peer hex, request)`.
fn page_requests(state: &AppState) -> Vec<(String, TreeKemCatchupRequest)> {
    state
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
        .expect("page request recorder")
        .iter()
        .map(|(peer, bytes)| {
            (
                peer.clone(),
                serde_json::from_slice(bytes).expect("a page request"),
            )
        })
        .collect()
}

/// The owner removes R through its route and S2 applies the removal. S1
/// was away.
async fn removal_s1_missed(cast: &SurvivorRelay) -> NamedGroupMetadataEvent {
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    let r_hex = hex_id(&cast.fixture.member_id);
    let response = remove_named_group_member(
        State(Arc::clone(owner)),
        owner_extension(),
        Path((group_id.clone(), r_hex)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the owner removes R");
    let removal = published_removal_event(owner).expect("the owner publishes the removal");
    s2_applies(cast, &removal).await;
    removal
}

/// The owner renames the group and S2 applies it.
async fn rename_s1_missed(cast: &SurvivorRelay) -> NamedGroupMetadataEvent {
    rename_route(&cast.fixture.state, &cast.fixture.group_id, "Family").await;
    let rename = published(&cast.fixture.state, |event| {
        matches!(event, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
    })
    .expect("the owner publishes the rename");
    s2_applies(cast, &rename).await;
    rename
}

async fn s1_head(cast: &SurvivorRelay) -> (u64, String, bool) {
    roster_head(
        &cast.s1,
        &cast.fixture.group_id,
        &hex_id(&cast.fixture.member_id),
    )
    .await
}

#[tokio::test]
async fn unverified_signed_page_request_is_served() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let s1_id = cast.s1.agent.agent_id();
    let s2_id = cast.s2.agent.agent_id();
    let request = page_request(&cast.s1, &group_id, None)
        .await
        .expect("S1 asks from its head");
    assert!(page_request_signed(&request), "S1 signs its page request");

    let page = served_page(&cast.s2, &s1_id, request, false)
        .await
        .expect("S2 serves a signed request it could not verify");
    assert_eq!(page.events.len(), 1, "the page carries the removal");

    // S1 cannot verify S2 either, and the page still heals it.
    handle_treekem_catchup_response(&cast.s1, &s2_id, false, page).await;
    s1_follows_the_owner(&mut cast, b"a phone pulled the removal").await?;
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unverified_unsigned_page_request_is_not() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let s1_id = cast.s1.agent.agent_id();
    let s2_id = cast.s2.agent.agent_id();
    let signed = page_request(&cast.s1, &group_id, None)
        .await
        .expect("S1 asks from its head");

    let mut unsigned = signed.clone();
    unsigned.signed_by = None;
    let mut tampered = signed.clone();
    tampered.from_treekem_epoch += 1;
    let mut challenged = signed.clone();
    challenged.head_challenge = Some("00".repeat(16));
    let mut someone_else = signed.clone();
    sign_page_request_with(&x0x::identity::AgentKeypair::generate()?, &mut someone_else);
    let mut member_keyed = signed.clone();
    member_keyed.target_member_id = Some(hex_id(&s2_id));
    for (request, what) in [
        (unsigned, "an unsigned request"),
        (tampered, "a request whose epoch is not the signed one"),
        (
            challenged,
            "a request whose challenge is not the signed one",
        ),
        (someone_else, "a request signed by another key"),
        (member_keyed, "a page signature on a member-keyed request"),
    ] {
        assert!(
            served_page(&cast.s2, &s1_id, request, false)
                .await
                .is_none(),
            "{what} is not served"
        );
    }
    assert!(
        served_page(&cast.s2, &s2_id, signed.clone(), false)
            .await
            .is_none(),
        "S1's signed request, claimed by another sender, is not served"
    );
    assert!(
        served_page(&cast.s2, &s1_id, signed, false).await.is_some(),
        "the signed request itself is served"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_signed_request_from_a_removed_member_is_refused() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let r_id = cast.fixture.member_id;
    let r_hex = hex_id(&r_id);
    let s1_id = cast.s1.agent.agent_id();
    // R asks from the head it held when it was removed, which S1 still
    // holds.
    let held = roster(&cast.s1, &group_id).await;
    let mut request = catchup_request_from(&held, &group_id, &r_id);
    sign_page_request_with(&cast.fixture.member_kp, &mut request);
    assert!(page_request_signed(&request), "R's own signature verifies");

    let s2_head = roster_head(&cast.s2, &group_id, &r_hex).await;
    let s2_epoch = live_epoch(&cast.s2, &group_id).await;
    for verified in [false, true] {
        assert!(
            served_page(&cast.s2, &r_id, request.clone(), verified)
                .await
                .is_none(),
            "a removed member is not served (verified: {verified})"
        );
    }
    assert_eq!(roster_head(&cast.s2, &group_id, &r_hex).await, s2_head);
    assert_eq!(live_epoch(&cast.s2, &group_id).await, s2_epoch);
    assert!(!s2_head.2, "R is removed on S2");

    let mut s1_request = catchup_request_from(&held, &group_id, &s1_id);
    sign_page_request(&cast.s1, &mut s1_request);
    assert!(
        served_page(&cast.s2, &s1_id, s1_request, false)
            .await
            .is_some(),
        "a member at the same head is served"
    );
    cast.shutdown().await;
    Ok(())
}

/// The victim's roster head (as R's row sees it) and live epoch.
async fn victim_view(cast: &CatchupRelay) -> ((u64, String, bool), u64) {
    let group_id = &cast.fixture.group_id;
    (
        roster_head(
            &cast.victim_state,
            group_id,
            &hex_id(&cast.fixture.member_id),
        )
        .await,
        live_epoch(&cast.victim_state, group_id).await,
    )
}

#[tokio::test]
async fn unverified_response_claiming_the_author_with_a_legacy_removal_is_refused() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let legacy = legacy_bound_removal(&cast.fixture).await?;
    let before = victim_view(&cast).await;
    assert!(before.0 .2, "setup: R is active on the victim");

    unverified_page(
        &cast.victim_state,
        &admin_id,
        &group_id,
        vec![legacy.clone()],
        false,
    )
    .await;
    assert_eq!(
        victim_view(&cast).await,
        before,
        "a page claiming the author installs no tree and changes no roster"
    );
    assert!(!group_is_quarantined(&cast.victim_state, &group_id).await);

    // The author itself, over a verified transport, still delivers it.
    deliver_catchup(&cast.victim_state, &admin_id, &group_id, legacy).await;
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        live_epoch(&cast.fixture.state, &group_id).await
    );
    let ciphertext = encrypt(&cast.fixture.state, &group_id, b"author-epoch").await?;
    let opened = {
        let group = live_treekem_group(&cast.victim_state, &group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(opened, b"author-epoch");
    assert!(cast
        .fixture
        .leaver_group
        .decrypt_message(&ciphertext)
        .is_err());
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unverified_response_with_swapped_treekem_bytes_installs_nothing() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    let response = remove_named_group_member(
        State(Arc::clone(&cast.fixture.state)),
        owner_extension(),
        Path((group_id.clone(), hex_id(&cast.fixture.member_id))),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the admin removes R");
    let genuine = published_removal_event(&cast.fixture.state).expect("digest-bound removal");
    let swapped = swap_treekem_commit(&genuine, &cast.attacker_commit);
    let before = victim_view(&cast).await;

    for claimed in [admin_id, cast.member_b, cast.fixture.member_id] {
        unverified_page(
            &cast.victim_state,
            &claimed,
            &group_id,
            vec![swapped.clone()],
            false,
        )
        .await;
        assert_eq!(
            victim_view(&cast).await,
            before,
            "swapped bytes install nothing, whoever is claimed"
        );
    }
    assert!(!group_is_quarantined(&cast.victim_state, &group_id).await);

    unverified_page(
        &cast.victim_state,
        &cast.member_b,
        &group_id,
        vec![genuine],
        false,
    )
    .await;
    let ciphertext = encrypt(&cast.fixture.state, &group_id, b"named bytes").await?;
    let opened = {
        let group = live_treekem_group(&cast.victim_state, &group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(opened, b"named bytes", "the genuine copy installs");
    assert!(cast
        .fixture
        .leaver_group
        .decrypt_message(&ciphertext)
        .is_err());
    assert!(cast.member_b_group.decrypt_message(&ciphertext).is_err());
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_removed_member_impersonating_the_remover_installs_nothing() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_id = cast.fixture.state.agent.agent_id();
    // R holds the genuine signed removal of itself, which names no bytes.
    let legacy = legacy_bound_removal(&cast.fixture).await?;
    // It attaches a commit from its own leaf.
    let r_commit = cast.fixture.leaver_group.update()?;
    let forged = swap_treekem_commit(&legacy, &r_commit);
    let before = victim_view(&cast).await;

    for claimed in [admin_id, cast.fixture.member_id, cast.member_b] {
        unverified_page(
            &cast.victim_state,
            &claimed,
            &group_id,
            vec![forged.clone()],
            false,
        )
        .await;
        let after = victim_view(&cast).await;
        assert_eq!(after, before, "the victim's tree and roster are unchanged");
        assert!(after.0 .2, "R stays on the victim's roster");
    }
    assert!(!group_is_quarantined(&cast.victim_state, &group_id).await);
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unverified_response_with_digest_bound_events_applies_by_signer() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let removal = removal_s1_missed(&cast).await;
    let rename = rename_s1_missed(&cast).await;
    // Nobody in the room: the claim is worth nothing, and costs nothing.
    let stranger = x0x::identity::AgentKeypair::generate()?.agent_id();
    unverified_page(&cast.s1, &stranger, &group_id, vec![removal], false).await;
    unverified_page(&cast.s1, &stranger, &group_id, vec![rename], false).await;
    assert_eq!(roster(&cast.s1, &group_id).await.name, "Family");
    s1_follows_the_owner(&mut cast, b"applied as its signer").await?;
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn an_unverified_page_is_read_one_page_of_events_deep() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let removal = removal_s1_missed(&cast).await;
    let rename = rename_s1_missed(&cast).await;
    let start = s1_head(&cast).await.0;
    let s2_id = cast.s2.agent.agent_id();
    unverified_page(&cast.s1, &s2_id, &group_id, vec![removal, rename], false).await;
    assert_eq!(s1_head(&cast).await.0, start + 1, "only the first event");
    assert_ne!(roster(&cast.s1, &group_id).await.name, "Family");
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn an_unverified_page_asks_for_more_only_after_it_moved_the_head() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let removal = removal_s1_missed(&cast).await;
    let rename = rename_s1_missed(&cast).await;
    let s2_id = cast.s2.agent.agent_id();
    let s2_hex = hex_id(&s2_id);
    let asked_s2 = || {
        page_requests(&cast.s1)
            .into_iter()
            .filter(|(peer, _)| *peer == s2_hex)
            .count()
    };

    unverified_page(&cast.s1, &s2_id, &group_id, vec![removal.clone()], true).await;
    assert_eq!(
        asked_s2(),
        1,
        "a page that moved the head asks for the next"
    );
    let (_, next) = page_requests(&cast.s1).pop().expect("the request");
    assert!(page_request_signed(&next), "the next request is signed");

    unverified_page(&cast.s1, &s2_id, &group_id, vec![removal], true).await;
    assert_eq!(asked_s2(), 1, "a replayed page asks nobody");

    let stranger = x0x::identity::AgentKeypair::generate()?.agent_id();
    unverified_page(&cast.s1, &stranger, &group_id, vec![rename], true).await;
    assert_eq!(roster(&cast.s1, &group_id).await.name, "Family");
    assert!(
        page_requests(&cast.s1)
            .iter()
            .all(|(peer, _)| *peer != hex_id(&stranger)),
        "a claimed sender outside the room is never asked"
    );
    cast.shutdown().await;
    Ok(())
}

/// S2's log lost the removal (it was not logged there), but holds the
/// rename after it.
async fn s2_log_without(cast: &SurvivorRelay, removal: &NamedGroupMetadataEvent) {
    let lost = named_group_metadata_event_commit(removal)
        .expect("a commit")
        .state_hash
        .clone();
    let mut log = cast.s2.treekem_event_log.write().await;
    for events in log.values_mut() {
        events.retain(|event| {
            named_group_metadata_event_commit(event).is_none_or(|commit| commit.state_hash != lost)
        });
    }
}

#[tokio::test]
async fn a_log_that_cannot_reach_the_requesters_head_serves_nothing_and_says_so() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let removal = removal_s1_missed(&cast).await;
    rename_s1_missed(&cast).await;
    s2_log_without(&cast, &removal).await;
    let s1_id = cast.s1.agent.agent_id();
    let head = s1_head(&cast).await.0;
    let request = page_request(&cast.s1, &group_id, None)
        .await
        .expect("a request");
    let page = served_page(&cast.s2, &s1_id, request, false)
        .await
        .expect("S2 answers");
    assert!(page.events.is_empty(), "the rename would not link");
    assert_eq!(page.log_evicted_through, Some(head + 1));
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn an_event_at_or_below_the_requesters_revision_is_never_served() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let epoch_before = live_epoch(&cast.s1, &group_id).await;
    let removal = removal_s1_missed(&cast).await;
    let rename = rename_s1_missed(&cast).await;
    let s1_id = cast.s1.agent.agent_id();
    deliver_catchup(&cast.s1, &cast.s2.agent.agent_id(), &group_id, removal).await;
    let mut request = page_request(&cast.s1, &group_id, None)
        .await
        .expect("a request");
    // A head whose epoch reads older than the removal it holds.
    request.from_treekem_epoch = epoch_before;
    sign_page_request(&cast.s1, &mut request);
    let page = served_page(&cast.s2, &s1_id, request, false)
        .await
        .expect("S2 answers");
    let served: Vec<String> = page
        .events
        .iter()
        .filter_map(named_group_metadata_event_commit)
        .map(|commit| commit.state_hash.clone())
        .collect();
    assert_eq!(
        served,
        vec![named_group_metadata_event_commit(&rename)
            .expect("a commit")
            .state_hash
            .clone()],
        "S2 serves the rename after the head, not the removal at it"
    );
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_hole_after_the_head_asks_another_member() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let owner_id = cast.fixture.state.agent.agent_id();
    let owner_hex = hex_id(&owner_id);
    let s1_id = cast.s1.agent.agent_id();
    let s2_id = cast.s2.agent.agent_id();
    let head = s1_head(&cast).await.0;

    // S2 says its log does not reach back to S1's head.
    handle_treekem_catchup_response(
        &cast.s1,
        &s2_id,
        false,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.clone(),
            events: Vec::new(),
            truncated: false,
            responder_state_hash: None,
            log_evicted_through: Some(head + 1),
            target_member_id: None,
            target_member_key_package_b64: None,
            signed_by: None,
        },
    )
    .await;
    wait_until(|| {
        page_requests(&cast.s1)
            .iter()
            .any(|(peer, _)| *peer == owner_hex)
    })
    .await;
    let asked = page_requests(&cast.s1);
    assert!(asked.len() <= GAP_ASK_PEERS);
    let (_, to_owner) = asked
        .iter()
        .find(|(peer, _)| *peer == owner_hex)
        .cloned()
        .expect("S1 asks the owner");
    assert!(page_request_signed(&to_owner));
    assert_eq!(to_owner.from_revision, head);

    // The same hole at the same head asks nobody again.
    handle_treekem_catchup_response(
        &cast.s1,
        &s2_id,
        true,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.clone(),
            events: Vec::new(),
            truncated: false,
            responder_state_hash: None,
            log_evicted_through: Some(head + 1),
            target_member_id: None,
            target_member_key_package_b64: None,
            signed_by: None,
        },
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(page_requests(&cast.s1).len(), asked.len());

    // The owner answers the request it was sent, and S1 heals.
    let page = served_page(&cast.fixture.state, &s1_id, to_owner, false)
        .await
        .expect("the owner serves S1");
    handle_treekem_catchup_response(&cast.s1, &owner_id, false, page).await;
    s1_follows_the_owner(&mut cast, b"another member filled the hole").await?;
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_page_from_an_older_responder_that_skips_a_commit_asks_another_member() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let rename = rename_s1_missed(&cast).await;
    let owner_hex = hex_id(&cast.fixture.state.agent.agent_id());
    let head = s1_head(&cast).await.0;
    deliver_catchup(&cast.s1, &cast.s2.agent.agent_id(), &group_id, rename).await;
    assert_eq!(s1_head(&cast).await.0, head, "the rename cannot link");
    wait_until(|| {
        page_requests(&cast.s1)
            .iter()
            .any(|(peer, _)| *peer == owner_hex)
    })
    .await;
    assert!(
        page_requests(&cast.s1)
            .iter()
            .any(|(peer, request)| *peer == owner_hex
                && request.from_revision == head
                && page_request_signed(request)),
        "S1 asks the owner for what comes after its head"
    );
    cast.shutdown().await;
    Ok(())
}

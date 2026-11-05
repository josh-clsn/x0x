use super::*;

// Round-5 review: the slow-inbox paths through the production send
// decisions. The fixtures are in-process; after they are built the tokio
// clock is paused, so the delays below cost no wall time. A frame is
// dropped when its envelope lifetime, as the sender built it, is shorter
// than its trip.

use super::adr0107_stuck_join_rearm::{build, welcome_id_of, Fixture};
use super::welcome_gossip_fallback::{known_recipient, welcome_ref_of};
use super::welcome_gossip_latency::{deliver_as, owner_frames};
use std::sync::atomic::{AtomicUsize, Ordering};

type SlowSink = tokio::sync::mpsc::UnboundedReceiver<(AgentId, Vec<u8>, u64)>;

fn hex_of(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

fn is_fetch_request(payload: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<WelcomeBlobMessage>(payload),
        Ok(WelcomeBlobMessage::FetchRequest { .. })
    )
}

fn is_join_result_poll(payload: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<JoinResultMessage>(payload),
        Ok(JoinResultMessage::FetchRequest { .. })
    )
}

/// The joiner's own bounded fetch attempts, a few seconds apart, each
/// sending through the production FetchRequest path, until one returns the
/// Welcome or `horizon` passes.
async fn fetch_welcome_until(
    s: &Fixture,
    reference: &WelcomeRef,
    horizon: Duration,
) -> Option<Vec<u8>> {
    let until = tokio::time::Instant::now() + horizon;
    while tokio::time::Instant::now() < until {
        let j2 = Arc::clone(&s.j2);
        let send = move |source: AgentId, request: WelcomeBlobMessage, first: bool| {
            let j2 = Arc::clone(&j2);
            async move { super::super::send_welcome_fetch_request(&j2, &source, &request, first).await }
        };
        if let Ok(bytes) =
            super::super::fetch_treekem_welcome_via(&s.j2, &s.stable, reference, send).await
        {
            return Some(bytes);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    None
}

/// The joiner's raw QUIC reaches no machine, as with no direct path in the
/// field: a raw send fails as not connected and falls back to the gossip
/// inbox.
fn no_direct_path(state: &AppState) {
    state
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    state.agent.script_pinned_standin_transport_for_testing(
        crate::PinnedTransportScript::connected_only(&[], false),
    );
}

fn abort_own_polls(s: &Fixture) {
    let mut attempts = s.j2.pending_join_attempts.lock().expect("attempt registry");
    if let Some(attempt) = attempts.get_mut(&join_result_key(&s.stable, &hex_of(&s.j2))) {
        for poll in attempt.polls.drain(..) {
            poll.abort();
        }
    }
}

/// WHY (review I1): an oversized metadata event by reference from a peer
/// reachable only over the gossip inbox has raw-only chunks, so a slow pull
/// of it can never finish; it held one of the four global fetch slots for
/// 10 min instead of the 115 s pull. Only a join result takes the slow
/// pull.
#[tokio::test]
async fn a_gossip_only_metadata_event_reference_keeps_the_short_pull() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let _sink = s.j2.agent.route_gossip_inbox_to_standin_for_testing();
    tokio::time::pause();
    let bytes = vec![7u8; x0x::dm::MAX_PAYLOAD_BYTES + 1_000];
    let reference = super::super::control_blob::test_reference(
        &bytes,
        &s.stable,
        &hex_of(&s.authority),
        &hex_of(&s.j2),
    );
    let free = s.j2.control_blobs.free_fetch_slots_for_test();
    super::super::control_blob::handle_control_blob_message(
        &s.j2,
        &s.authority_id,
        true,
        super::super::control_blob::ControlBlobMessage::Reference { reference },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let started = s.j2.control_blobs.free_fetch_slots_for_test();
    tokio::time::sleep(WELCOME_FETCH_TIMEOUT + Duration::from_secs(15)).await;
    let after = s.j2.control_blobs.free_fetch_slots_for_test();
    tokio::time::resume();
    assert_eq!(started + 1, free, "the pull started");
    assert_eq!(
        after, free,
        "a metadata-event pull still holds a global fetch slot past the 115 s pull"
    );
    Ok(())
}

/// WHY (review I2): the joiner's join-result poll was marked as sent over
/// gossip only when the send returned a gossip receipt. On a slow inbox
/// the gossip ack never comes back inside the send's wait, so the send
/// times out, nothing is marked, and the joiner polls every few seconds,
/// each poll with a 300 s envelope. At most one poll per refresh window
/// may take the gossip inbox.
#[tokio::test]
async fn a_join_result_poll_is_throttled_when_its_gossip_ack_never_comes() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let mut sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    no_direct_path(&s.j2);
    abort_own_polls(&s);
    tokio::time::pause();
    let horizon = Duration::from_secs(400);
    let poll = tokio::spawn(super::super::poll_join_result_until_deadline(
        Arc::clone(&s.j2),
        s.group_key.clone(),
        s.stable.clone(),
        vec![s.authority_id],
        hex_of(&s.j2),
        true,
        None,
        s.j2_attempt.clone(),
        tokio::time::Instant::now() + horizon,
    ));
    tokio::time::sleep(horizon - Duration::from_secs(1)).await;
    poll.abort();
    let mut polls = 0;
    while let Ok((to, payload, _)) = sink.try_recv() {
        if to == s.authority_id && is_join_result_poll(&payload) {
            polls += 1;
        }
    }
    tokio::time::resume();
    assert!(
        polls <= 3,
        "{polls} join-result polls took the gossip inbox in {horizon:?}"
    );
    Ok(())
}

/// WHY (review I3): the owner's duplicate window ran from its own first
/// gossip frame, the joiner's from its send. A refresh whose trip was
/// faster than the original request's (156 s, then 35 s) arrived inside
/// the owner's window and was dropped, although the first stream was
/// lost. The refresh must be answered.
#[tokio::test]
async fn a_refresh_that_overtakes_the_original_request_is_answered() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.authority, &s.j2).await?;
    let mut sink = s
        .authority
        .agent
        .route_gossip_inbox_to_standin_for_testing();
    tokio::time::pause();
    let request = || WelcomeBlobMessage::FetchRequest {
        group_id: s.stable.clone(),
        welcome_id: welcome_id_of(&s.j2_add).expect("welcome id"),
    };
    let j2 = s.j2.agent.agent_id();
    super::super::handle_welcome_blob_message(&s.authority, &j2, request()).await;
    // Sent a refresh window (150 s) after the first, with a trip 121 s
    // shorter: it lands 29 s after the first.
    tokio::time::sleep(Duration::from_secs(29)).await;
    super::super::handle_welcome_blob_message(&s.authority, &j2, request()).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut offers = 0;
    while let Ok((_, payload)) = sink.try_recv() {
        if matches!(
            serde_json::from_slice::<WelcomeBlobMessage>(&payload),
            Ok(WelcomeBlobMessage::Offer { .. })
        ) {
            offers += 1;
        }
    }
    tokio::time::resume();
    assert_eq!(offers, 2, "the overtaking refresh was not answered");
    Ok(())
}

/// WHY (review I3), end to end through the production sends: the first
/// request takes 156 s and its stream is lost; later trips take 35 s. The
/// joiner's refresh must be answered, so the joiner holds its Welcome
/// within two refresh windows, not a third.
#[tokio::test]
async fn a_lost_stream_is_recovered_by_the_next_refresh() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.authority, &s.j2).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let mut owner_sink: SlowSink = s
        .authority
        .agent
        .route_gossip_inbox_to_slow_standin_for_testing();
    let mut joiner_sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    let reference = welcome_ref_of(&s.j2_add).expect("J2's Welcome is staged by reference");
    tokio::time::pause();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&requests);
    let owner = Arc::clone(&s.authority);
    let j2_id = s.j2.agent.agent_id();
    let to_owner = tokio::spawn(async move {
        while let Some((_, payload, lifetime_ms)) = joiner_sink.recv().await {
            if !is_fetch_request(&payload) {
                continue;
            }
            let trip = if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                Duration::from_secs(156)
            } else {
                Duration::from_secs(35)
            };
            let owner = Arc::clone(&owner);
            tokio::spawn(async move {
                tokio::time::sleep(trip).await;
                if trip >= Duration::from_millis(lifetime_ms) {
                    return;
                }
                if let Ok(request) = serde_json::from_slice::<WelcomeBlobMessage>(&payload) {
                    super::super::handle_welcome_blob_message(&owner, &j2_id, request).await;
                }
            });
        }
    });
    let joiner = Arc::clone(&s.j2);
    let owner_id = s.authority_id;
    let owner_machine = s.authority.agent.machine_id();
    let to_joiner = tokio::spawn(async move {
        let mut streams = 0;
        while let Some((to, payload, lifetime_ms)) = owner_sink.recv().await {
            if to != joiner.agent.agent_id() {
                continue;
            }
            if matches!(
                serde_json::from_slice::<WelcomeBlobMessage>(&payload),
                Ok(WelcomeBlobMessage::Offer { .. })
            ) {
                streams += 1;
            }
            if streams <= 1 {
                continue;
            }
            let trip = Duration::from_secs(35);
            let joiner = Arc::clone(&joiner);
            tokio::spawn(async move {
                tokio::time::sleep(trip).await;
                if trip >= Duration::from_millis(lifetime_ms) {
                    return;
                }
                let message = x0x::direct::DirectMessage::new_verified(
                    owner_id,
                    owner_machine,
                    payload,
                    true,
                    None,
                );
                if let Some((sender, frame)) = decode_welcome_blob_message(&message) {
                    super::super::dispatch_welcome_blob_message(&joiner, sender, frame).await;
                }
            });
        }
    });
    let started = tokio::time::Instant::now();
    let welcome = fetch_welcome_until(&s, &reference, Duration::from_secs(900)).await;
    let took = started.elapsed();
    tokio::time::resume();
    to_owner.abort();
    to_joiner.abort();
    let welcome = welcome.ok_or_else(|| {
        anyhow::anyhow!(
            "the Welcome never arrived ({} requests)",
            requests.load(Ordering::SeqCst)
        )
    })?;
    assert_eq!(
        super::super::welcome_id_for_bytes(&welcome),
        reference.welcome_id
    );
    assert!(
        took < Duration::from_secs(300),
        "the Welcome took {took:?}: the refresh after the lost stream was dropped"
    );
    Ok(())
}

/// WHY (review I4): with a live direct connection the joiner skipped its
/// withhold, but its retries still preferred the gossip inbox, so every
/// bounded attempt sent another gossip FetchRequest. At most one per
/// refresh window may take the gossip inbox; the rest take the live
/// connection.
#[tokio::test]
async fn over_a_live_connection_retries_do_not_flood_the_gossip_inbox() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    s.j2.agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    let mut sink = s.j2.agent.route_gossip_inbox_to_standin_for_testing();
    assert!(
        s.j2.agent.has_live_direct_connection(&s.authority_id).await,
        "precondition: a live direct connection"
    );
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    tokio::time::pause();
    let welcome = fetch_welcome_until(&s, &reference, Duration::from_secs(140)).await;
    let mut gossip = 0;
    while let Ok((to, payload)) = sink.try_recv() {
        if to == s.authority_id && is_fetch_request(&payload) {
            gossip += 1;
        }
    }
    tokio::time::resume();
    assert!(welcome.is_none(), "nobody answers in this test");
    assert!(
        gossip <= 1,
        "{gossip} FetchRequests took the gossip inbox inside one refresh window"
    );
    Ok(())
}

/// One bounded attempt that asks over the slow inbox and gets nothing, so
/// its receive is retained.
async fn retained_attempt(s: &Fixture, reference: &WelcomeRef) {
    let j2 = Arc::clone(&s.j2);
    let send = move |source: AgentId, request: WelcomeBlobMessage, prefer_raw: bool| {
        let j2 = Arc::clone(&j2);
        async move { super::super::send_welcome_fetch_request(&j2, &source, &request, prefer_raw).await }
    };
    let attempt = super::super::fetch_treekem_welcome_via(&s.j2, &s.stable, reference, send).await;
    assert!(attempt.is_err(), "nothing answers");
    assert!(
        s.j2.pending_welcome_receives
            .read()
            .await
            .get(&reference.welcome_id)
            .is_some_and(|receive| receive.retention.retained),
        "the receive is retained"
    );
}

/// WHY (review L3, L8): attempts that end in retention leave no closed
/// waiters behind, and a retained receive takes frames only from the
/// Welcome's source.
#[tokio::test]
async fn retained_receives_shed_dead_waiters_and_ignore_other_sources() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let _sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    let (bytes, frames) = owner_frames(&s).await?;
    tokio::time::pause();
    for _ in 0..4 {
        retained_attempt(&s, &reference).await;
    }
    let waiters =
        s.j2.pending_welcome_waiters
            .read()
            .await
            .get(&reference.welcome_id)
            .map_or(0, Vec::len);
    deliver_as(&s, &s.j1, &frames).await;
    let foreign_taken =
        s.j2.welcome_gossip
            .take_completed(&reference.welcome_id, tokio::time::Instant::now());
    deliver_as(&s, &s.authority, &frames).await;
    let owner_taken =
        s.j2.welcome_gossip
            .take_completed(&reference.welcome_id, tokio::time::Instant::now());
    tokio::time::resume();
    assert!(waiters <= 1, "{waiters} waiters left by ended attempts");
    assert!(
        foreign_taken.is_none(),
        "frames from another source completed it"
    );
    assert_eq!(owner_taken, Some(bytes), "the source's frames complete it");
    Ok(())
}

/// WHY (review L2): a retained receive past its overall deadline takes no
/// more frames, and no Welcome completes from it.
#[tokio::test]
async fn a_retained_receive_past_its_deadline_takes_no_frames() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let _sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    let (_, frames) = owner_frames(&s).await?;
    tokio::time::pause();
    retained_attempt(&s, &reference).await;
    tokio::time::sleep(super::super::welcome_retention::RETAINED_WELCOME_TTL).await;
    let (complete, chunks) = frames.split_last().expect("frames");
    deliver_as(&s, &s.authority, chunks).await;
    let took_chunks =
        s.j2.pending_welcome_receives
            .read()
            .await
            .get(&reference.welcome_id)
            .is_some_and(|receive| !receive.chunks.is_empty());
    deliver_as(&s, &s.authority, std::slice::from_ref(complete)).await;
    let held = s.j2.welcome_gossip.take_completed(
        &reference.welcome_id,
        tokio::time::Instant::now() - Duration::from_secs(1),
    );
    let receive =
        s.j2.pending_welcome_receives
            .read()
            .await
            .contains_key(&reference.welcome_id);
    tokio::time::resume();
    assert!(!took_chunks, "the expired receive took chunks");
    assert!(
        held.is_none(),
        "a Welcome completed past its receive's deadline"
    );
    assert!(!receive, "the expired receive is dropped");
    Ok(())
}

/// WHY (review L8): a retained receive for another reference of the same
/// id is dropped as superseded when a fetch for the current one begins.
#[tokio::test]
async fn a_retained_receive_for_another_reference_is_superseded() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let _sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    tokio::time::pause();
    let retention = super::super::welcome_retention::WelcomeRetention {
        gossip_fetch_sent_at: Some(tokio::time::Instant::now()),
        retained: true,
        ..Default::default()
    };
    s.j2.pending_welcome_receives.write().await.insert(
        reference.welcome_id.clone(),
        PendingWelcomeReceive {
            group_id: s.stable.clone(),
            source: reference.source.clone(),
            byte_len: reference.byte_len + 1,
            total_chunks: 1,
            chunks: BTreeMap::new(),
            received_bytes: 0,
            ended_early: None,
            retention,
        },
    );
    let attempt = tokio::time::timeout(
        Duration::from_secs(1),
        super::super::fetch_treekem_welcome_via(&s.j2, &s.stable, &reference, |_, _, _| async {
            Ok(())
        }),
    )
    .await;
    let byte_len =
        s.j2.pending_welcome_receives
            .read()
            .await
            .get(&reference.welcome_id)
            .map(|receive| receive.byte_len);
    tokio::time::resume();
    assert!(attempt.is_err(), "the new fetch is under way, not refused");
    assert_eq!(
        byte_len,
        Some(reference.byte_len),
        "the stale receive was replaced"
    );
    Ok(())
}

/// The joiner discovers the owner's machine but holds no gossip-inbox key
/// for it, so a send to it can only take raw QUIC.
async fn discovered_without_gossip_key(sender: &AppState, recipient: &AppState) {
    let now = now_millis_u64() / 1000;
    sender
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            self_name: None,
            agent_id: recipient.agent.agent_id(),
            machine_id: recipient.agent.machine_id(),
            user_id: None,
            addresses: Vec::new(),
            announced_at: now,
            last_seen: now,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: Vec::new(),
            cert_digest: None,
        })
        .await;
}

/// WHY (review L1): a FetchRequest was marked as gossip-carried before it
/// was sent. A retry that prefers the gossip inbox still goes raw when the
/// owner has no gossip-inbox key; its receive must then not be retained as
/// if it waited on the slow inbox.
#[tokio::test]
async fn a_request_that_went_raw_is_not_marked_as_gossip_carried() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    discovered_without_gossip_key(&s.j2, &s.authority).await;
    s.j2.agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    assert!(
        s.j2.agent.has_live_direct_connection(&s.authority_id).await,
        "precondition: a live direct connection"
    );
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    let raw_before = raw_fetch_requests(&s);
    tokio::time::pause();
    let attempt = super::super::fetch_treekem_welcome_via(
        &s.j2,
        &s.stable,
        &reference,
        |source: AgentId, request: WelcomeBlobMessage, prefer_raw: bool| {
            let j2 = Arc::clone(&s.j2);
            async move {
                super::super::send_welcome_fetch_request(&j2, &source, &request, prefer_raw).await
            }
        },
    )
    .await;
    let retained =
        s.j2.pending_welcome_receives
            .read()
            .await
            .contains_key(&reference.welcome_id);
    tokio::time::resume();
    assert!(attempt.is_err(), "nobody answers");
    assert!(
        raw_fetch_requests(&s) >= raw_before + 2,
        "the first request and the retry went raw"
    );
    assert!(
        !retained,
        "a receive asked for only over raw QUIC was retained"
    );
    Ok(())
}

fn raw_fetch_requests(s: &Fixture) -> usize {
    s.j2.agent
        .general_raw_standin_deliveries_for_testing()
        .iter()
        .filter(|(to, _, payload)| *to == s.authority_id && is_fetch_request(payload))
        .count()
}

/// WHY (review N2): over a connection that reads as live but takes no
/// writes, every retry inside a gossip request's window failed raw and
/// fell back to the gossip inbox with an ack wait. Inside the window a raw
/// failure must not add gossip copies.
#[tokio::test]
async fn a_live_connection_that_takes_no_writes_does_not_flood_the_gossip_inbox(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    s.j2.agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    s.j2.agent.inject_backpressure_ack_failures_for_testing(64);
    let mut sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    assert!(
        s.j2.agent.has_live_direct_connection(&s.authority_id).await,
        "precondition: a live direct connection"
    );
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    tokio::time::pause();
    let welcome = fetch_welcome_until(&s, &reference, Duration::from_secs(140)).await;
    let mut gossip = 0;
    while let Ok((to, payload, _)) = sink.try_recv() {
        if to == s.authority_id && is_fetch_request(&payload) {
            gossip += 1;
        }
    }
    tokio::time::resume();
    assert!(welcome.is_none(), "nobody answers in this test");
    assert!(
        gossip <= 2,
        "{gossip} FetchRequests took the gossip inbox inside one refresh window"
    );
    Ok(())
}

/// WHY (review L2): a finalized join attempt drops the Welcome state it
/// left retained, instead of holding it to the deadline.
#[tokio::test]
async fn a_finalized_attempt_drops_its_retained_welcome_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.j2, &s.authority).await?;
    let _sink: SlowSink = s.j2.agent.route_gossip_inbox_to_slow_standin_for_testing();
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    tokio::time::pause();
    retained_attempt(&s, &reference).await;
    let now = tokio::time::Instant::now();
    s.j2.welcome_gossip
        .keep_completed("c".repeat(64).as_str(), &s.stable, vec![1], now, now);
    abort_own_polls(&s);
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable,
        &hex_of(&s.j2),
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    let receive =
        s.j2.pending_welcome_receives
            .read()
            .await
            .contains_key(&reference.welcome_id);
    let completed =
        s.j2.welcome_gossip
            .take_completed(&"c".repeat(64), tokio::time::Instant::now());
    tokio::time::resume();
    assert!(
        !receive,
        "the retained receive outlived its finalized attempt"
    );
    assert!(
        completed.is_none(),
        "the completed Welcome outlived its finalized attempt"
    );
    Ok(())
}

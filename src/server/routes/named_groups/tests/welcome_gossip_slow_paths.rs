use super::*;

// Round-5 review: the slow-inbox paths through the production send
// decisions. The fixtures are in-process; after they are built the tokio
// clock is paused, so the delays below cost no wall time. A frame is
// dropped when its envelope lifetime, as the sender built it, is shorter
// than its trip.

use super::adr0107_stuck_join_rearm::{build, welcome_id_of, Fixture};
use super::welcome_gossip_fallback::{known_recipient, welcome_ref_of};
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

use super::*;

// A Welcome over a gossip inbox whose one-way latency is minutes, as on a
// metered phone (field test 2026-11-04: 35 s to 156 s). The fixtures are
// in-process; after they are built the tokio clock is paused, so the
// delays below cost no wall time. The owner's gossip inbox is the
// stand-in; every frame, in either direction, reaches the other side after
// the injected delay, unless its envelope lifetime ran out on the way (as
// an honest receiver drops it).

use super::adr0107_stuck_join_rearm::{
    build, keyed, local_state, serve_result, welcome_id_of, Fixture,
};
use super::welcome_gossip_fallback::{known_recipient, welcome_ref_of, with_welcome};
use std::sync::atomic::{AtomicUsize, Ordering};

type Sink = tokio::sync::mpsc::UnboundedReceiver<(AgentId, Vec<u8>)>;

fn owner_gossip_lifetime() -> Duration {
    Duration::from_millis(x0x::dm_send::ADMITTED_PUBLISH_LIFETIME_MS)
}

fn control_gossip_lifetime() -> Duration {
    Duration::from_millis(super::super::welcome_control_gossip_lifetime_ms())
}

fn is_offer(payload: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<WelcomeBlobMessage>(payload),
        Ok(WelcomeBlobMessage::Offer { .. })
    )
}

/// Owner frames to the joiner, each delivered to the joiner's real Welcome
/// listener `delay` after it was published, unless it expired on the way.
/// Counts the Offers (one per owner stream).
fn delayed_owner_frames(
    owner: &Arc<AppState>,
    joiner: &Arc<AppState>,
    mut sink: Sink,
    delay: Duration,
) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let offers = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&offers);
    let owner_id = owner.agent.agent_id();
    let owner_machine = owner.agent.machine_id();
    let joiner = Arc::clone(joiner);
    let task = tokio::spawn(async move {
        while let Some((to, payload)) = sink.recv().await {
            if to != joiner.agent.agent_id() {
                continue;
            }
            if is_offer(&payload) {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            let joiner = Arc::clone(&joiner);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if delay >= owner_gossip_lifetime() {
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
    (offers, task)
}

/// One joiner attempt's FetchRequest sender: the request takes the gossip
/// inbox and reaches the owner's real fetch handler `delay` later, unless
/// it expired on the way.
fn delayed_fetch_sender(
    owner: &Arc<AppState>,
    joiner: &Arc<AppState>,
    delay: Duration,
    sent: &Arc<AtomicUsize>,
) -> impl FnMut(
    AgentId,
    WelcomeBlobMessage,
    bool,
) -> futures::future::BoxFuture<'static, std::result::Result<(), WelcomeFetchSendError>> {
    let owner = Arc::clone(owner);
    let joiner = Arc::clone(joiner);
    let sent = Arc::clone(sent);
    move |_, request, _| {
        let owner = Arc::clone(&owner);
        let joiner = Arc::clone(&joiner);
        let sent = Arc::clone(&sent);
        Box::pin(async move {
            if let WelcomeBlobMessage::FetchRequest { welcome_id, .. } = &request {
                super::super::note_gossip_welcome_fetch(&joiner, welcome_id).await;
            }
            sent.fetch_add(1, Ordering::SeqCst);
            let joiner_id = joiner.agent.agent_id();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if delay >= control_gossip_lifetime() {
                    return;
                }
                super::super::handle_welcome_blob_message(&owner, &joiner_id, request).await;
            });
            Ok(())
        })
    }
}

/// The joiner's join-result poll, re-driving bounded fetch attempts of the
/// production length, a few seconds apart, until one returns the Welcome or
/// `horizon` passes.
async fn poll_welcome(
    s: &Fixture,
    reference: &WelcomeRef,
    delay: Duration,
    sent: &Arc<AtomicUsize>,
    horizon: Duration,
) -> Option<Vec<u8>> {
    let until = tokio::time::Instant::now() + horizon;
    while tokio::time::Instant::now() < until {
        let send = delayed_fetch_sender(&s.authority, &s.j2, delay, sent);
        if let Ok(bytes) =
            super::super::fetch_treekem_welcome_via(&s.j2, &s.stable, reference, send).await
        {
            return Some(bytes);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    None
}

/// WHY (field test 2026-11-04): with the owner reachable only over a gossip
/// inbox whose one-way latency is 90 s or 150 s, every bounded attempt
/// ended before the owner's frames came back, dropping what had arrived,
/// and the 30 s owner frames expired on the way. The joiner never seated.
/// It must seat, with bounded attempts of the current length.
#[tokio::test]
async fn a_joiner_seats_through_a_gossip_inbox_with_minutes_of_latency() -> anyhow::Result<()> {
    for delay in [Duration::from_secs(90), Duration::from_secs(150)] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        known_recipient(&s.authority, &s.j2).await?;
        let reference = welcome_ref_of(&s.j2_add).expect("J2's Welcome is staged by reference");
        let served = serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
            .await
            .expect("the owner serves J2's join result");
        let sink = s
            .authority
            .agent
            .route_gossip_inbox_to_standin_for_testing();
        tokio::time::pause();
        let (offers, carrier) = delayed_owner_frames(&s.authority, &s.j2, sink, delay);
        let sent = Arc::new(AtomicUsize::new(0));
        let welcome = poll_welcome(&s, &reference, delay, &sent, Duration::from_secs(900)).await;
        tokio::time::resume();
        carrier.abort();
        let welcome = welcome.ok_or_else(|| {
            anyhow::anyhow!(
                "[{delay:?}] the Welcome never arrived ({} requests, {} owner streams)",
                sent.load(Ordering::SeqCst),
                offers.load(Ordering::SeqCst)
            )
        })?;
        assert_eq!(
            super::super::welcome_id_for_bytes(&welcome),
            welcome_id_of(&s.j2_add).expect("welcome id")
        );
        super::super::handle_join_result_message_bound(
            &s.j2,
            &s.authority_id,
            true,
            with_welcome(served, &welcome),
            Some(&s.j2_attempt),
        )
        .await;
        assert_eq!(
            local_state(&s.j2, &s.group_key).await,
            "active",
            "[{delay:?}]"
        );
        assert!(keyed(&s.j2, &s.group_key).await, "[{delay:?}]");
        assert!(
            sent.load(Ordering::SeqCst) <= 8,
            "[{delay:?}] a re-request storm: {} FetchRequests",
            sent.load(Ordering::SeqCst)
        );
    }
    Ok(())
}

/// The owner's real frames for J2's staged Welcome.
async fn owner_frames(s: &Fixture) -> anyhow::Result<(Vec<u8>, Vec<WelcomeBlobMessage>)> {
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome id");
    let bytes = s
        .authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .map(|pending| pending.bytes.clone())
        .ok_or_else(|| anyhow::anyhow!("staged Welcome"))?;
    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let mut frames = vec![WelcomeBlobMessage::Offer {
        group_id: s.stable.clone(),
        welcome_id: welcome_id.clone(),
        byte_len: bytes.len() as u64,
        chunk_size,
        total_chunks: x0x::files::total_chunks_for_size(bytes.len() as u64, chunk_size),
        blake3_hex: welcome_id.clone(),
    }];
    for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
        frames.push(WelcomeBlobMessage::Chunk {
            welcome_id: welcome_id.clone(),
            sequence: sequence as u64,
            data: BASE64.encode(chunk),
        });
    }
    frames.push(WelcomeBlobMessage::Complete { welcome_id });
    Ok((bytes, frames))
}

async fn deliver_from_owner(s: &Fixture, frames: &[WelcomeBlobMessage]) {
    for frame in frames {
        let message = x0x::direct::DirectMessage::new_verified(
            s.authority_id,
            s.authority.agent.machine_id(),
            serde_json::to_vec(frame).expect("frame"),
            true,
            None,
        );
        if let Some((sender, frame)) = decode_welcome_blob_message(&message) {
            super::super::dispatch_welcome_blob_message(&s.j2, sender, frame).await;
        }
    }
}

/// WHY: frames of an earlier gossip-carried request that land between two
/// bounded attempts are kept, and the next attempt completes from them
/// without asking again.
#[tokio::test]
async fn frames_landing_between_attempts_are_kept_and_used() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    let (bytes, frames) = owner_frames(&s).await?;
    tokio::time::pause();
    let sent = Arc::new(AtomicUsize::new(0));
    let silent = |sent: &Arc<AtomicUsize>| {
        let joiner = Arc::clone(&s.j2);
        let sent = Arc::clone(sent);
        move |_, request: WelcomeBlobMessage, _| {
            let joiner = Arc::clone(&joiner);
            let sent = Arc::clone(&sent);
            async move {
                if let WelcomeBlobMessage::FetchRequest { welcome_id, .. } = &request {
                    super::super::note_gossip_welcome_fetch(&joiner, welcome_id).await;
                }
                sent.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    };
    let first =
        super::super::fetch_treekem_welcome_via(&s.j2, &s.stable, &reference, silent(&sent)).await;
    assert!(first.is_err(), "nothing arrived inside the first attempt");
    let asked = sent.load(Ordering::SeqCst);
    // The Offer and the chunks land between attempts; the Complete too.
    deliver_from_owner(&s, &frames).await;
    let second = tokio::time::timeout(
        Duration::from_secs(1),
        super::super::fetch_treekem_welcome_via(&s.j2, &s.stable, &reference, silent(&sent)),
    )
    .await;
    tokio::time::resume();
    let second = second.map_err(|_| anyhow::anyhow!("the next attempt waited for nothing"))?;
    assert_eq!(second.map_err(anyhow::Error::msg)?, bytes);
    assert_eq!(
        sent.load(Ordering::SeqCst),
        asked,
        "the next attempt asked again although the Welcome was already here"
    );
    Ok(())
}

/// WHY: a joiner on a slow gossip inbox can ask more than once; each
/// FetchRequest used to restream the whole Welcome. Inside the refresh
/// window the owner streams it once; after the window, once more.
#[tokio::test]
async fn duplicate_fetch_requests_inside_the_window_stream_once() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    known_recipient(&s.authority, &s.j2).await?;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome id");
    let mut sink = s
        .authority
        .agent
        .route_gossip_inbox_to_standin_for_testing();
    tokio::time::pause();
    let request = || WelcomeBlobMessage::FetchRequest {
        group_id: s.stable.clone(),
        welcome_id: welcome_id.clone(),
    };
    let j2 = s.j2.agent.agent_id();
    let mut offers = 0;
    let mut count = |sink: &mut Sink| {
        while let Ok((_, payload)) = sink.try_recv() {
            if is_offer(&payload) {
                offers += 1;
            }
        }
        offers
    };
    for _ in 0..3 {
        super::super::handle_welcome_blob_message(&s.authority, &j2, request()).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let inside = count(&mut sink);
    tokio::time::sleep(super::super::welcome_retention::WELCOME_GOSSIP_REFRESH).await;
    super::super::handle_welcome_blob_message(&s.authority, &j2, request()).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let after = count(&mut sink);
    tokio::time::resume();
    assert_eq!(
        inside, 1,
        "duplicates inside the window restreamed the Welcome"
    );
    assert_eq!(after, 2, "a request after the window streams again");
    Ok(())
}

/// WHY: gossip-carried Welcome frames, in both directions, must outlive a
/// phone's inbox latency (156 s seen), yet one older than that lifetime is
/// still refused, and every other DM and the raw path keep theirs.
#[test]
fn gossip_welcome_frames_live_long_enough_and_no_longer() {
    let lifetime =
        u64::try_from(super::super::welcome_retention::WELCOME_GOSSIP_LIFETIME.as_millis())
            .expect("lifetime");
    assert!(lifetime >= 156_000 + x0x::dm::CLOCK_SKEW_TOLERANCE_MS);
    let request = WelcomeBlobMessage::FetchRequest {
        group_id: "g".to_string(),
        welcome_id: "w".to_string(),
    };
    let ack = WelcomeBlobMessage::ChunkAck {
        welcome_id: "w".to_string(),
        sequence: 0,
    };
    for msg in [&request, &ack] {
        for direct in [false, true] {
            let config = super::super::welcome_blob_send_config(msg, direct);
            assert_eq!(config.gossip_envelope_lifetime_ms, Some(lifetime));
            assert_eq!(
                config.raw_quic_receive_ack_timeout,
                direct_message_send_config().raw_quic_receive_ack_timeout,
                "the raw leg is unchanged"
            );
        }
    }
    assert_eq!(
        x0x::dm::DmSendConfig::default().gossip_envelope_lifetime_ms,
        None
    );
    assert_eq!(
        direct_message_send_config().gossip_envelope_lifetime_ms,
        None
    );
    let created = 1_000_000;
    assert_eq!(
        x0x::dm_send::admitted_publish_expiry(created, u64::MAX),
        Some(created + lifetime)
    );
    assert!(x0x::dm::validate_timestamp_window(
        created,
        created + lifetime,
        created + lifetime - 1
    )
    .is_ok());
    assert!(
        x0x::dm::validate_timestamp_window(created, created + lifetime, created + lifetime)
            .is_err(),
        "a frame older than its lifetime is refused"
    );
}

fn gossip_receive(group: &str) -> PendingWelcomeReceive {
    let retention = super::super::welcome_retention::WelcomeRetention {
        gossip_fetch_sent_at: Some(tokio::time::Instant::now()),
        ..Default::default()
    };
    PendingWelcomeReceive {
        group_id: group.to_string(),
        source: "ab".repeat(32),
        byte_len: 64,
        total_chunks: 1,
        chunks: BTreeMap::new(),
        received_bytes: 0,
        ended_early: None,
        retention,
    }
}

/// WHY: retained receives are bounded: at most `MAX_RETAINED_WELCOMES` are
/// kept (the oldest go first), each only until its overall deadline, and a
/// receive never asked for over gossip is not retained at all.
#[tokio::test(start_paused = true)]
async fn retained_receives_are_capped_and_expire() -> anyhow::Result<()> {
    use super::super::welcome_retention::{MAX_RETAINED_WELCOMES, RETAINED_WELCOME_TTL};
    let (state, _dir) = secure_endpoint_test_state().await?;
    let ids: Vec<String> = (0..MAX_RETAINED_WELCOMES + 2)
        .map(|i| format!("{i:064x}"))
        .collect();
    for id in &ids {
        state
            .pending_welcome_receives
            .write()
            .await
            .insert(id.clone(), gossip_receive("g"));
        super::super::retain_or_cleanup_welcome_receive(&state, id).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    {
        let receives = state.pending_welcome_receives.read().await;
        assert_eq!(receives.len(), MAX_RETAINED_WELCOMES);
        assert!(!receives.contains_key(&ids[0]) && !receives.contains_key(&ids[1]));
        assert!(receives.values().all(|receive| receive.retention.retained));
    }
    let raw = "f".repeat(64);
    let mut never_gossip = gossip_receive("g");
    never_gossip.retention.gossip_fetch_sent_at = None;
    state
        .pending_welcome_receives
        .write()
        .await
        .insert(raw.clone(), never_gossip);
    super::super::retain_or_cleanup_welcome_receive(&state, &raw).await;
    assert!(
        !state
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&raw),
        "a raw-only receive is cleaned up as before"
    );
    tokio::time::sleep(RETAINED_WELCOME_TTL).await;
    super::super::prune_retained_welcome_receives(&state).await;
    assert!(
        state.pending_welcome_receives.read().await.is_empty(),
        "retained receives end at their overall deadline"
    );
    Ok(())
}

fn control_frame(payload: &[u8]) -> Option<super::super::control_blob::ControlBlobMessage> {
    serde_json::from_slice(payload).ok()
}

type FrameCounts = Arc<StdMutex<HashMap<&'static str, usize>>>;

/// Frames from `from`'s gossip stand-in to `to`, each handed to `to`'s
/// real control-blob listener `delay` after it was published, unless its
/// envelope lifetime (`lifetime`) ran out on the way. Counts the control
/// frames of each kind as published.
fn delayed_control_frames(
    from: &Arc<AppState>,
    to: &Arc<AppState>,
    mut sink: Sink,
    delay: Duration,
    lifetime: Duration,
) -> (FrameCounts, tokio::task::JoinHandle<()>) {
    let counts: FrameCounts = Arc::default();
    let counted = Arc::clone(&counts);
    let from_id = from.agent.agent_id();
    let to = Arc::clone(to);
    let task = tokio::spawn(async move {
        while let Some((recipient, payload)) = sink.recv().await {
            if recipient != to.agent.agent_id() {
                continue;
            }
            let Some(frame) = control_frame(&payload) else {
                continue;
            };
            let (kind, reference) = match &frame {
                super::super::control_blob::ControlBlobMessage::Reference { reference } => {
                    ("reference", reference)
                }
                super::super::control_blob::ControlBlobMessage::Fetch { reference, .. } => {
                    ("fetch", reference)
                }
                super::super::control_blob::ControlBlobMessage::Chunk { reference, .. } => {
                    ("chunk", reference)
                }
                super::super::control_blob::ControlBlobMessage::Release { reference } => {
                    ("release", reference)
                }
            };
            // Only the join result's pull is counted; the owner's oversized
            // metadata events travel by reference too.
            let join_result =
                serde_json::to_value(reference).is_ok_and(|value| value["kind"] == "join_result");
            if let (true, Ok(mut counts)) = (join_result, counted.lock()) {
                *counts.entry(kind).or_default() += 1;
            }
            let to = Arc::clone(&to);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if delay >= lifetime {
                    return;
                }
                super::super::control_blob::handle_control_blob_message(&to, &from_id, true, frame)
                    .await;
            });
        }
    });
    (counts, task)
}

fn count(counts: &Arc<StdMutex<HashMap<&'static str, usize>>>, kind: &str) -> usize {
    counts
        .lock()
        .map(|counts| counts.get(kind).copied().unwrap_or(0))
        .unwrap_or(0)
}

fn control_fetch_gossip_lifetime() -> Duration {
    Duration::from_millis(super::super::control_blob::control_fetch_gossip_lifetime_ms())
}

/// WHY (round 5): a join result over `MAX_PAYLOAD_BYTES` (a Noetic room of
/// 4 members, or a joiner whose invite predates other joins) is pulled as
/// a control blob, chunk by chunk, with 30 s chunk waits inside a 115 s
/// fetch. Over a gossip inbox with 90 s or 150 s of one-way latency no
/// chunk could come back in time. The pull must complete (the joiner sends
/// its Release after the digest verifies), without a re-request storm.
#[tokio::test]
async fn an_oversized_join_result_is_pulled_through_minutes_of_gossip_latency() -> anyhow::Result<()>
{
    for delay in [Duration::from_secs(90), Duration::from_secs(150)] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        known_recipient(&s.authority, &s.j2).await?;
        known_recipient(&s.j2, &s.authority).await?;
        let owner_sink = s
            .authority
            .agent
            .route_gossip_inbox_to_standin_for_testing();
        let joiner_sink = s.j2.agent.route_gossip_inbox_to_standin_for_testing();
        tokio::time::pause();
        let (owner_counts, owner_task) = delayed_control_frames(
            &s.authority,
            &s.j2,
            owner_sink,
            delay,
            owner_gossip_lifetime(),
        );
        let (joiner_counts, joiner_task) = delayed_control_frames(
            &s.j2,
            &s.authority,
            joiner_sink,
            delay,
            control_fetch_gossip_lifetime(),
        );
        assert!(
            serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
                .await
                .is_some()
        );
        let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
        let byte_len = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(reference) = s
                    .authority
                    .control_blobs
                    .staged_join_result_refs_for_test(&j2_hex)
                    .into_iter()
                    .next()
                {
                    return serde_json::to_value(&reference)
                        .ok()
                        .and_then(|value| value["byte_len"].as_u64())
                        .unwrap_or(0);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let total = usize::try_from(byte_len.div_ceil(x0x::files::DEFAULT_CHUNK_SIZE as u64))?;
        let released = tokio::time::timeout(Duration::from_secs(1_200), async {
            while count(&joiner_counts, "release") == 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .is_ok();
        tokio::time::resume();
        owner_task.abort();
        joiner_task.abort();
        let (fetches, chunks) = (
            count(&joiner_counts, "fetch"),
            count(&owner_counts, "chunk"),
        );
        assert!(
            released,
            "[{delay:?}] the join result never arrived ({fetches} chunk fetches, {chunks} chunks sent, {total} chunks)"
        );
        assert!(
            fetches <= 3 * total && chunks <= 2 * total,
            "[{delay:?}] a re-request storm: {fetches} fetches, {chunks} chunks for {total} chunks"
        );
    }
    Ok(())
}

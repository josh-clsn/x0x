//! A joiner's Welcome never waits on a slow delivery receipt. On a metered
//! leaf the gossip-inbox receipt for the joiner's own control frames rides
//! only its inbox topic and can take minutes; the owner's frames arrive in
//! milliseconds. Awaiting those receipts inline held the single Welcome
//! listener and the bounded fetch until the fetch expired, discarded the
//! receive and the join-result poll began again (the UI drills' leaf runs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// Park every `ChunkAck` for `welcome_id`, as a send whose receipt never
/// arrives does.
fn park_chunk_acks(welcome_id: &str) -> Arc<WelcomeChunkAckTestGate> {
    let gate = Arc::new(WelcomeChunkAckTestGate::default());
    WELCOME_CHUNK_ACK_TEST_GATES
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .expect("ack gates")
        .insert(welcome_id.to_string(), Arc::clone(&gate));
    gate
}

fn unpark_chunk_acks(welcome_id: &str) {
    if let Some(gates) = WELCOME_CHUNK_ACK_TEST_GATES.get() {
        gates.lock().expect("ack gates").remove(welcome_id);
    }
}

/// A Welcome of `chunks` chunks, its reference and the owner's frames for
/// it, in the order the owner's stream sends them.
fn staged_welcome(
    owner: &AppState,
    group_id: &str,
    chunks: usize,
) -> (Vec<u8>, WelcomeRef, Vec<WelcomeBlobMessage>) {
    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let len = chunk_size * (chunks - 1) + 4096;
    let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let welcome_id = welcome_id_for_bytes(&bytes);
    let welcome_ref = WelcomeRef {
        welcome_id: welcome_id.clone(),
        byte_len: bytes.len() as u64,
        source: hex::encode(owner.agent.agent_id().as_bytes()),
    };
    let mut frames = vec![WelcomeBlobMessage::Offer {
        group_id: group_id.to_string(),
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
    (bytes, welcome_ref, frames)
}

async fn chunk_acks_settle(state: &AppState) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while state.welcome_chunk_ack_admission.in_flight() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every ChunkAck send ends within its budget");
}

/// The drill's livelock: no ChunkAck receipt ever arrives, yet the one
/// Welcome listener goes on to the next chunk and the Complete, and the
/// joiner assembles the Welcome at once, inside its bounded fetch.
#[tokio::test]
async fn welcome_completes_while_chunk_ack_receipts_never_arrive() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let owner_id = owner.agent.agent_id();
    let group_id = "e1".repeat(32);
    // Two chunks, as the drill's Welcome had.
    let (bytes, welcome_ref, frames) = staged_welcome(&owner, &group_id, 2);
    let gate = park_chunk_acks(&welcome_ref.welcome_id);
    tokio::time::pause();
    let started = tokio::time::Instant::now();

    let listener_state = Arc::clone(&joiner);
    let listener_done = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&listener_done);
    let fetched = fetch_treekem_welcome_via(
        &joiner,
        &group_id,
        &welcome_ref,
        move |source, request, _| {
            let state = Arc::clone(&listener_state);
            let frames = frames.clone();
            let done = Arc::clone(&done);
            async move {
                assert_eq!(source, owner_id);
                assert!(matches!(request, WelcomeBlobMessage::FetchRequest { .. }));
                // The owner answers on the joiner's single Welcome
                // listener: each frame is dispatched in order and awaited,
                // as the listener loop in `server::run` does.
                tokio::spawn(async move {
                    for frame in frames {
                        dispatch_welcome_blob_message(&state, &owner_id, frame).await;
                    }
                    done.store(true, Ordering::SeqCst);
                });
                Ok(())
            }
        },
    )
    .await
    .map_err(anyhow::Error::msg)?;

    assert_eq!(fetched, bytes, "the joiner assembles the exact Welcome");
    // The paused clock moves only in millisecond ticks between polls.
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "no frame waited on a ChunkAck receipt"
    );
    tokio::task::yield_now().await;
    assert!(listener_done.load(Ordering::SeqCst));
    assert!(
        gate.started.load(Ordering::SeqCst) <= 2,
        "one ack per chunk"
    );
    // The assembled Welcome released its acks still waiting on receipts.
    assert_eq!(joiner.welcome_ack_tasks.in_flight(), 0);
    assert_eq!(joiner.welcome_chunk_ack_admission.in_flight(), 0);
    unpark_chunk_acks(&welcome_ref.welcome_id);
    Ok(())
}

/// The ack sends the listener spawns are bounded: a group gets at most its
/// share. A stalled burst never blocks a restream: a chunk received again
/// releases its earlier ack's slot and is acked again, and the end of the
/// fetch releases them all. Each send also ends within its budget.
#[tokio::test]
async fn chunk_ack_sends_are_bounded_and_end_within_their_budget() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let owner_id = owner.agent.agent_id();
    let group_id = "e2".repeat(32);
    let chunks = WELCOME_CHUNK_ACK_PER_GROUP_CAP + 4;
    let (_bytes, welcome_ref, frames) = staged_welcome(&owner, &group_id, chunks);
    let welcome_id = welcome_ref.welcome_id.clone();
    let gate = park_chunk_acks(&welcome_id);
    let register = || PendingWelcomeReceive {
        group_id: group_id.clone(),
        source: welcome_ref.source.clone(),
        byte_len: welcome_ref.byte_len,
        total_chunks: chunks as u64,
        chunks: BTreeMap::new(),
        received_bytes: 0,
        ended_early: false,
    };
    joiner
        .pending_welcome_receives
        .write()
        .await
        .insert(welcome_id.clone(), register());
    tokio::time::pause();

    let chunk_frames: Vec<_> = frames
        .into_iter()
        .filter(|frame| matches!(frame, WelcomeBlobMessage::Chunk { .. }))
        .collect();
    let deliver = |frames: Vec<WelcomeBlobMessage>| {
        let joiner = Arc::clone(&joiner);
        async move {
            for frame in frames {
                tokio::time::timeout(
                    Duration::from_millis(1),
                    dispatch_welcome_blob_message(&joiner, &owner_id, frame),
                )
                .await
                .expect("a chunk never holds the Welcome listener");
            }
            tokio::task::yield_now().await;
        }
    };
    let share = WELCOME_CHUNK_ACK_PER_GROUP_CAP;

    deliver(chunk_frames.clone()).await;
    assert_eq!(
        gate.started.load(Ordering::SeqCst),
        share,
        "the share caps the acks"
    );
    assert_eq!(joiner.welcome_ack_tasks.in_flight(), share);
    assert_eq!(joiner.welcome_chunk_ack_admission.in_flight(), share);
    let stored = joiner
        .pending_welcome_receives
        .read()
        .await
        .get(&welcome_id)
        .map(|receive| receive.chunks.len());
    assert_eq!(stored, Some(chunks), "every chunk is kept, acked or not");

    // The owner restreams while the first acks are stuck: each re-received
    // chunk's ack replaces its predecessor, so the restream is acked.
    deliver(chunk_frames[..share].to_vec()).await;
    assert_eq!(
        gate.started.load(Ordering::SeqCst),
        2 * share,
        "the restream's acks went out"
    );
    assert_eq!(joiner.welcome_ack_tasks.in_flight(), share);
    assert_eq!(joiner.welcome_chunk_ack_admission.in_flight(), share);

    // The fetch ends: its acks are released at once.
    cleanup_welcome_fetch_state(&joiner, &welcome_id).await;
    assert_eq!(joiner.welcome_ack_tasks.in_flight(), 0);
    assert_eq!(joiner.welcome_chunk_ack_admission.in_flight(), 0);

    // A new fetch's acks: each send still ends within its budget.
    joiner
        .pending_welcome_receives
        .write()
        .await
        .insert(welcome_id.clone(), register());
    deliver(chunk_frames[..2].to_vec()).await;
    assert_eq!(joiner.welcome_ack_tasks.in_flight(), 2);
    tokio::time::sleep(WELCOME_CHUNK_ACK_BUDGET).await;
    chunk_acks_settle(&joiner).await;
    assert_eq!(joiner.welcome_ack_tasks.in_flight(), 0);
    unpark_chunk_acks(&welcome_id);
    Ok(())
}

/// A Complete that arrives before every chunk (a replaced stream's, or one
/// whose chunk was lost) never fails the fetch: the receive stays, the
/// fetch asks again at its next attempt although bytes had arrived, and the
/// restream assembles the Welcome.
#[tokio::test]
async fn an_early_complete_never_fails_the_fetch() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let owner_id = owner.agent.agent_id();
    let group_id = "e6".repeat(32);
    let (bytes, welcome_ref, frames) = staged_welcome(&owner, &group_id, 2);
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let sends = Arc::new(AtomicUsize::new(0));
    let sent = Arc::clone(&sends);
    let listener_state = Arc::clone(&joiner);

    let fetched = tokio::time::timeout(
        Duration::from_secs(60),
        fetch_treekem_welcome_via(&joiner, &group_id, &welcome_ref, move |_, _, _| {
            let state = Arc::clone(&listener_state);
            let attempt = sent.fetch_add(1, Ordering::SeqCst);
            // The first stream loses its last chunk; the restream is whole.
            let frames: Vec<_> = if attempt == 0 {
                let (complete, rest) = frames.split_last().expect("frames");
                let mut early = rest[..rest.len() - 1].to_vec();
                early.push(complete.clone());
                early
            } else {
                frames.clone()
            };
            async move {
                tokio::spawn(async move {
                    for frame in frames {
                        dispatch_welcome_blob_message(&state, &owner_id, frame).await;
                    }
                });
                Ok(())
            }
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("the fetch never settled"))?
    .map_err(anyhow::Error::msg)?;

    assert_eq!(fetched, bytes);
    assert_eq!(
        sends.load(Ordering::SeqCst),
        2,
        "the early end prompted a retry"
    );
    assert!(started.elapsed() < WELCOME_FETCH_UNDER_GUARD_TIMEOUT);
    Ok(())
}

/// A fetch that joins one already in flight sends its first FetchRequest
/// as the retry it is (`first` is false), so it takes the gossip inbox; a
/// fetch of its own sends its first one as first.
#[tokio::test]
async fn joining_a_fetch_in_flight_sends_its_first_request_as_a_retry() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let group_id = "e7".repeat(32);
    let (_bytes, welcome_ref, _frames) = staged_welcome(&owner, &group_id, 1);
    tokio::time::pause();
    let schedule = [Duration::ZERO, Duration::from_millis(10)];
    let firsts = Arc::new(StdMutex::new(Vec::new()));
    let fetch = |state: Arc<AppState>| {
        let firsts = Arc::clone(&firsts);
        let welcome_ref = welcome_ref.clone();
        let group_id = group_id.clone();
        async move {
            fetch_treekem_welcome_via_schedule(
                &state,
                &group_id,
                &welcome_ref,
                move |_, _, first| {
                    firsts.lock().expect("firsts").push(first);
                    std::future::ready(Ok(()))
                },
                &schedule,
                Duration::from_millis(50),
            )
            .await
        }
    };

    // Its own fetch: the first scheduled request is first, the retry is not.
    let own = fetch(Arc::clone(&joiner)).await;
    assert!(own.is_err(), "nothing streams in this test");
    assert_eq!(*firsts.lock().expect("firsts"), vec![true, false]);

    // Joining: another fetch already registered this receive.
    firsts.lock().expect("firsts").clear();
    let in_flight = fetch(Arc::clone(&joiner));
    let joined = fetch(Arc::clone(&joiner));
    let (_, _) = tokio::join!(in_flight, joined);
    let recorded = firsts.lock().expect("firsts").clone();
    assert_eq!(
        recorded.iter().filter(|first| **first).count(),
        1,
        "only the fetch that registered the receive sends a first request: {recorded:?}"
    );
    Ok(())
}

/// A FetchRequest whose receipt is minutes away no longer holds the fetch:
/// the chunks it asked for stay in the pending receive, and the Complete is
/// taken when it lands, not after the receipt wait.
#[tokio::test]
async fn late_fetch_request_receipt_keeps_the_pending_receive() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let owner_id = owner.agent.agent_id();
    let group_id = "e3".repeat(32);
    let (bytes, welcome_ref, frames) = staged_welcome(&owner, &group_id, 2);
    tokio::time::pause();
    let started = tokio::time::Instant::now();

    let listener_state = Arc::clone(&joiner);
    let welcome_id = welcome_ref.welcome_id.clone();
    let fetched = tokio::time::timeout(
        Duration::from_secs(300),
        fetch_treekem_welcome_via(&joiner, &group_id, &welcome_ref, move |_, _, _| {
            let state = Arc::clone(&listener_state);
            let frames = frames.clone();
            let welcome_id = welcome_id.clone();
            async move {
                tokio::spawn(async move {
                    let (complete, streamed) = frames.split_last().expect("frames");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    for frame in streamed {
                        dispatch_welcome_blob_message(&state, &owner_id, frame.clone()).await;
                    }
                    tokio::time::sleep(Duration::from_secs(8)).await;
                    let kept = state
                        .pending_welcome_receives
                        .read()
                        .await
                        .get(&welcome_id)
                        .map(|receive| receive.chunks.len());
                    assert_eq!(kept, Some(2), "the receive outlives the receipt wait");
                    dispatch_welcome_blob_message(&state, &owner_id, complete.clone()).await;
                });
                // The request's gossip-inbox receipt lands two minutes on.
                tokio::time::sleep(Duration::from_secs(120)).await;
                Err(WelcomeFetchSendError::ReceiptUnconfirmed(
                    "timed out after 1 retries over 24.0s".to_string(),
                ))
            }
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("the fetch waited on its FetchRequest's receipt"))?
    .map_err(anyhow::Error::msg)?;

    assert_eq!(fetched, bytes);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(10) && elapsed < Duration::from_millis(10_100),
        "the Complete was taken while the receipt was outstanding: {elapsed:?}"
    );
    assert!(joiner.pending_welcome_receives.read().await.is_empty());
    assert!(joiner.pending_welcome_waiters.read().await.is_empty());
    Ok(())
}

/// The fetch keeps its bound while a FetchRequest's outcome never comes:
/// it ends at its deadline and releases the receive and its waiter.
#[tokio::test]
async fn fetch_ends_at_its_deadline_while_a_request_is_outstanding() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let group_id = "e4".repeat(32);
    let (_bytes, welcome_ref, _frames) = staged_welcome(&owner, &group_id, 1);
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let sends = Arc::new(AtomicUsize::new(0));
    let sent = Arc::clone(&sends);

    let result = tokio::time::timeout(
        Duration::from_secs(300),
        fetch_treekem_welcome_via(&joiner, &group_id, &welcome_ref, move |_, _, _| {
            sent.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<std::result::Result<(), WelcomeFetchSendError>>()
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("the fetch outlived its deadline"))?;

    assert!(matches!(
        result,
        Err(ref error) if error == "timed out waiting for TreeKEM Welcome blob"
    ));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= WELCOME_FETCH_UNDER_GUARD_TIMEOUT
            && elapsed < WELCOME_FETCH_UNDER_GUARD_TIMEOUT + Duration::from_millis(100),
        "the fetch ended at its deadline: {elapsed:?}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        2,
        "the stalled retry still went out while the first request was pending"
    );
    assert!(joiner.pending_welcome_receives.read().await.is_empty());
    assert!(joiner.pending_welcome_waiters.read().await.is_empty());
    Ok(())
}

/// The raw deliveries `from`'s strict stand-in made to `to`'s machine.
fn raw_frames_to(from: &AppState, to: &AppState) -> Vec<Vec<u8>> {
    from.agent
        .general_raw_standin_deliveries_for_testing()
        .into_iter()
        .filter(|(agent, machine, _)| {
            *agent == to.agent.agent_id() && *machine == to.agent.machine_id()
        })
        .map(|(_, _, payload)| payload)
        .collect()
}

/// Over a live direct connection to the owner, the joiner's FetchRequest and
/// ChunkAck take raw QUIC although the owner's gossip-inbox advert is known.
/// Without one they keep the gossip inbox, and so does a stalled retry.
#[tokio::test]
async fn welcome_control_frames_take_raw_quic_over_a_live_connection() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let owner_id = owner.agent.agent_id();
    let owner_machine = owner.agent.machine_id();
    // A gossip-capable owner: a gossip-preferred frame never touches raw
    // QUIC (and this agent has no gossip runtime, so it fails instead).
    let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
    assert!(joiner.agent.capability_store().insert(
        owner_id,
        owner_machine,
        x0x::dm::DmCapabilities::v1_gossip_ready(kem.public_bytes.clone()),
        x0x::dm::now_unix_ms(),
    ));
    let now = now_millis_u64() / 1000;
    joiner
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            self_name: None,
            agent_id: owner_id,
            machine_id: owner_machine,
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
    joiner
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    let live_machines = [owner_machine];
    let connected = |live: bool| {
        joiner.agent.script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(
                if live { &live_machines[..] } else { &[] },
                false,
            ),
        );
    };

    let request = WelcomeBlobMessage::FetchRequest {
        group_id: "e5".repeat(32),
        welcome_id: "f5".repeat(32),
    };
    let ack = WelcomeBlobMessage::ChunkAck {
        welcome_id: "f5".repeat(32),
        sequence: 0,
    };
    connected(true);
    let fetched = send_welcome_fetch_request(&joiner, &owner_id, &request, true).await;
    assert!(fetched.is_ok(), "{fetched:?}");
    let acked = send_welcome_blob_message(&joiner, &owner_id, &ack)
        .await
        .map_err(anyhow::Error::msg)?;
    assert!(matches!(acked.path, x0x::dm::DmPath::RawQuic));
    assert_eq!(
        raw_frames_to(&joiner, &owner),
        vec![
            welcome_blob_payload(&request).map_err(anyhow::Error::msg)?,
            welcome_blob_payload(&ack).map_err(anyhow::Error::msg)?,
        ],
        "both frames went over the live connection"
    );

    // A stalled retry hedges on the gossip inbox, even over the connection.
    assert!(
        send_welcome_fetch_request(&joiner, &owner_id, &request, false)
            .await
            .is_err()
    );
    // No live connection: the gossip inbox stays preferred.
    connected(false);
    assert!(
        send_welcome_fetch_request(&joiner, &owner_id, &request, true)
            .await
            .is_err()
    );
    assert!(send_welcome_blob_message(&joiner, &owner_id, &ack)
        .await
        .is_err());
    assert_eq!(raw_frames_to(&joiner, &owner).len(), 2, "no raw send since");

    joiner
        .agent
        .set_pinned_standin_strict_resolution_for_testing(false);
    Ok(())
}

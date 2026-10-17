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
    let fetched =
        fetch_treekem_welcome_via(&joiner, &group_id, &welcome_ref, move |source, request| {
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
        })
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
    assert_eq!(
        gate.started.load(Ordering::SeqCst),
        2,
        "each chunk was acked"
    );
    assert_eq!(joiner.welcome_chunk_ack_admission.in_flight(), 2);

    // Every parked send ends within its budget.
    tokio::time::sleep(WELCOME_CHUNK_ACK_BUDGET).await;
    chunk_acks_settle(&joiner).await;
    unpark_chunk_acks(&welcome_ref.welcome_id);
    Ok(())
}

/// The ack sends the listener spawns are bounded: a re-sent chunk whose ack
/// is in flight does not add one, and a group gets at most its share.
#[tokio::test]
async fn chunk_ack_sends_are_bounded_and_end_within_their_budget() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let owner_id = owner.agent.agent_id();
    let group_id = "e2".repeat(32);
    let chunks = WELCOME_CHUNK_ACK_PER_GROUP_CAP + 4;
    let (_bytes, welcome_ref, frames) = staged_welcome(&owner, &group_id, chunks);
    let gate = park_chunk_acks(&welcome_ref.welcome_id);
    joiner.pending_welcome_receives.write().await.insert(
        welcome_ref.welcome_id.clone(),
        PendingWelcomeReceive {
            group_id: group_id.clone(),
            source: welcome_ref.source.clone(),
            byte_len: welcome_ref.byte_len,
            total_chunks: chunks as u64,
            chunks: BTreeMap::new(),
            received_bytes: 0,
        },
    );
    tokio::time::pause();

    let chunk_frames: Vec<_> = frames
        .into_iter()
        .filter(|frame| matches!(frame, WelcomeBlobMessage::Chunk { .. }))
        .collect();
    // The first chunk twice (an owner restream), then every chunk.
    for frame in std::iter::once(chunk_frames[0].clone()).chain(chunk_frames) {
        tokio::time::timeout(
            Duration::from_millis(1),
            dispatch_welcome_blob_message(&joiner, &owner_id, frame),
        )
        .await
        .expect("a chunk never holds the Welcome listener");
    }
    tokio::task::yield_now().await;

    assert_eq!(
        gate.started.load(Ordering::SeqCst),
        WELCOME_CHUNK_ACK_PER_GROUP_CAP,
        "a duplicate coalesces and the group's share caps the rest"
    );
    assert_eq!(
        joiner.welcome_chunk_ack_admission.in_flight(),
        WELCOME_CHUNK_ACK_PER_GROUP_CAP
    );
    let stored = joiner
        .pending_welcome_receives
        .read()
        .await
        .get(&welcome_ref.welcome_id)
        .map(|receive| receive.chunks.len());
    assert_eq!(stored, Some(chunks), "every chunk is kept, acked or not");

    tokio::time::sleep(WELCOME_CHUNK_ACK_BUDGET).await;
    chunk_acks_settle(&joiner).await;
    unpark_chunk_acks(&welcome_ref.welcome_id);
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
        fetch_treekem_welcome_via(&joiner, &group_id, &welcome_ref, move |_, _| {
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
        fetch_treekem_welcome_via(&joiner, &group_id, &welcome_ref, move |_, _| {
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

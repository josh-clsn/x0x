use super::*;

// The gossip leg's own ADR 0107 admission (no stream abort involved), the
// kind allowlist, and the production chain on real loopback agents.

use super::adr0107_stuck_join_rearm::{build, hex_of, serve_result, welcome_id_of, Fixture};
use super::welcome_gossip_fallback::{
    admit_all, clone_fixture, invalidate, known_recipient, transports_to, Invalidation, WAIT,
};

type Sink = tokio::sync::mpsc::UnboundedReceiver<(AgentId, Vec<u8>)>;

#[test]
fn only_class_r_kinds_may_ride_gossip() {
    for kind in super::super::GOSSIP_CAPABLE_JOIN_ARTIFACTS {
        assert!(super::super::join_artifact_may_use_gossip(kind));
        assert!(!super::super::RAW_ONLY_JOIN_ARTIFACTS.contains(&kind));
    }
    for kind in super::super::RAW_ONLY_JOIN_ARTIFACTS {
        assert!(!super::super::join_artifact_may_use_gossip(kind));
    }
    assert!(!super::super::join_artifact_may_use_gossip("unknown_kind"));
}

fn drain(sink: &mut Sink) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Ok((_, payload)) = sink.try_recv() {
        out.push(payload);
    }
    out
}

const FRAME: &[u8] = b"admission-probe-frame";

/// The three real class-R admissions for J2, built as their egress builds
/// them (J2's result must already be served, so its copy is staged).
async fn j2_admissions(
    s: &Fixture,
) -> anyhow::Result<Vec<(&'static str, x0x::dm::ArtifactAdmission)>> {
    let j2_hex = hex_of(&s.j2);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome id");
    let staged_at = s
        .authority
        .pending_join_results
        .read()
        .await
        .get(&join_result_key(&s.stable, &j2_hex))
        .map(|pending| pending.created_at)
        .ok_or_else(|| anyhow::anyhow!("J2's result is staged"))?;
    let reference = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(reference) = s
                .authority
                .control_blobs
                .staged_join_result_refs_for_test(&j2_hex)
                .into_iter()
                .next()
            {
                return reference;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("J2's result copy was never staged"))?;
    Ok(vec![
        (
            "welcome_frame",
            super::super::welcome_frame_admission(&s.authority, &welcome_id, &j2_hex),
        ),
        (
            "join_result",
            super::super::join_result_admission(&s.authority, &s.stable, &j2_hex, staged_at),
        ),
        (
            "join_result_chunk",
            super::super::join_result_chunk_admission(&s.authority, &reference),
        ),
    ])
}

async fn gossip_send(
    s: &Fixture,
    kind: &'static str,
    admission: x0x::dm::ArtifactAdmission,
) -> std::result::Result<(), String> {
    super::super::send_join_artifact(
        &s.authority,
        &s.j2.agent.agent_id(),
        FRAME,
        &s.stable,
        kind,
        admission,
        Instant::now() + Duration::from_secs(60),
    )
    .await
}

fn refused(sent: &std::result::Result<(), String>) -> bool {
    sent.as_ref()
        .is_err_and(|reason| reason.contains(x0x::dm::PINNED_ADMISSION_REFUSED))
}

/// A served fixture whose owner carries J2's frames on the gossip stand-in.
async fn served(dir: &std::path::Path) -> anyhow::Result<(Fixture, Sink)> {
    let s = build(dir).await?;
    known_recipient(&s.authority, &s.j2).await?;
    let mut sink = s
        .authority
        .agent
        .route_gossip_inbox_to_standin_for_testing();
    anyhow::ensure!(
        serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
            .await
            .is_some(),
        "J2 is served"
    );
    // The serve's own egress (the result reference) goes out first.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drain(&mut sink);
    Ok((s, sink))
}

/// WHY (review F2): with no stream to abort, a committed ban or removal is
/// refused by the gossip leg's own admission. The real Welcome-frame,
/// join-result and result-chunk admissions each refuse, and nothing is
/// published; before the invalidation the same admissions publish.
#[tokio::test]
async fn a_committed_invalidation_is_refused_by_the_gossip_admission() -> anyhow::Result<()> {
    for how in [Invalidation::Ban, Invalidation::Removal] {
        let dir = tempfile::tempdir()?;
        let (s, mut sink) = served(dir.path()).await?;
        for (kind, admission) in j2_admissions(&s).await? {
            let sent = gossip_send(&s, kind, admission).await;
            assert!(sent.is_ok(), "[{how:?}] control {kind}: {sent:?}");
        }
        assert_eq!(
            drain(&mut sink)
                .iter()
                .filter(|frame| *frame == FRAME)
                .count(),
            3,
            "[{how:?}] the controls were published"
        );
        let admissions = j2_admissions(&s).await?;
        assert!(
            invalidate(&s, how).await.is_success(),
            "[{how:?}] committed"
        );
        for (kind, admission) in admissions {
            let sent = gossip_send(&s, kind, admission).await;
            assert!(refused(&sent), "[{how:?}] {kind}: {sent:?}");
        }
        assert!(
            drain(&mut sink).iter().all(|frame| frame != FRAME),
            "[{how:?}] a frame was published after the invalidation"
        );
    }
    Ok(())
}

type Between = Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

/// The real admission `inner`, with `between` run after its pre-phase has
/// passed and before its seam runs.
fn between_phases(
    inner: x0x::dm::ArtifactAdmission,
    between: Between,
    passed: Arc<std::sync::atomic::AtomicUsize>,
) -> x0x::dm::ArtifactAdmission {
    Arc::new(move || {
        let inner = Arc::clone(&inner);
        let between = Arc::clone(&between);
        let passed = Arc::clone(&passed);
        Box::pin(async move {
            let seam = inner().await?;
            passed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            between().await;
            Some(seam)
        })
    })
}

/// WHY (review F2): an invalidation that commits after a gossip frame's
/// pre-phase passed and before its seam runs is refused at the seam, for
/// each real admission; nothing is published.
#[tokio::test]
async fn an_invalidation_between_the_admission_phases_is_refused_at_the_seam() -> anyhow::Result<()>
{
    for how in [Invalidation::Ban, Invalidation::Removal] {
        for index in 0..3 {
            let dir = tempfile::tempdir()?;
            let (s, mut sink) = served(dir.path()).await?;
            let (kind, inner) = j2_admissions(&s)
                .await?
                .into_iter()
                .nth(index)
                .expect("an admission");
            let fixture = Arc::new(clone_fixture(&s));
            let between: Between = Arc::new(move || {
                let fixture = Arc::clone(&fixture);
                Box::pin(async move {
                    assert!(invalidate(&fixture, how).await.is_success());
                })
            });
            let passed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let sent = gossip_send(
                &s,
                kind,
                between_phases(inner, between, Arc::clone(&passed)),
            )
            .await;
            assert_eq!(
                passed.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "[{how:?}] {kind}: the pre-phase passed before the invalidation"
            );
            assert!(refused(&sent), "[{how:?}] {kind}: {sent:?}");
            assert!(
                drain(&mut sink).iter().all(|frame| frame != FRAME),
                "[{how:?}] {kind}: a frame was published past the seam"
            );
        }
    }
    Ok(())
}

async fn networked_agent(dir: &std::path::Path, name: &str) -> anyhow::Result<Arc<Agent>> {
    Ok(Arc::new(
        Agent::builder()
            .with_machine_key(dir.join(format!("{name}-machine.key")))
            .with_agent_key_path(dir.join(format!("{name}-agent.key")))
            .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
            .with_peer_cache_disabled()
            .with_network_config(x0x::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback bind address")),
                bootstrap_nodes: Vec::new(),
                port_mapping_enabled: false,
                mdns_enabled: false,
                ..x0x::network::NetworkConfig::default()
            })
            .build()
            .await?,
    ))
}

/// Two meshed loopback agents; the owner holds the joiner's signed
/// gossip-inbox capability advert.
async fn meshed(owner: &Agent, joiner: &Agent) -> anyhow::Result<()> {
    const PHASE: Duration = Duration::from_secs(15);
    for agent in [owner, joiner] {
        let kem = Arc::new(x0x::groups::kem_envelope::AgentKemKeypair::generate()?);
        agent
            .start_dm_inbox(kem, x0x::dm_inbox::DmInboxConfig::default())
            .await?;
        agent.join_network().await?;
    }
    let addr = joiner
        .network()
        .ok_or_else(|| anyhow::anyhow!("joiner network"))?
        .bound_addr()
        .await
        .ok_or_else(|| anyhow::anyhow!("joiner bound"))?;
    tokio::time::timeout(
        PHASE,
        owner
            .network()
            .ok_or_else(|| anyhow::anyhow!("owner network"))?
            .connect_addr(addr),
    )
    .await??;
    for agent in [owner, joiner] {
        agent
            .gossip_runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime"))?
            .pubsub()
            .refresh_topic_peers()
            .await;
    }
    let signing = x0x::gossip::SigningContext::from_keypair(joiner.identity().agent_keypair());
    let advert = x0x::dm_capability_service::build_signed_advert(
        &signing,
        joiner.agent_id(),
        joiner.machine_id(),
        joiner.current_dm_capabilities(),
    )?;
    tokio::time::timeout(PHASE, async {
        while !owner
            .capability_store()
            .lookup_binding(&joiner.agent_id())
            .is_some_and(|binding| binding.capabilities.gossip_inbox)
        {
            let _ = joiner
                .publish(x0x::dm_capability::DM_CAPABILITY_TOPIC, advert.clone())
                .await;
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    })
    .await?;
    Ok(())
}

/// WHY (review F7): the production chain on real agents. The owner's
/// `send_join_artifact` makes its own path choice and key selection; each
/// raw exchange fails as not connected before any write (scripted), so it
/// publishes on the real gossip inbox; the joiner's real DM inbox opens
/// the envelope, its direct channel names the authenticated owner, and the
/// Welcome listener's decode and dispatch assemble the exact bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_real_agents_a_not_connected_welcome_reaches_the_joiner_by_gossip() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let owner_agent = networked_agent(dir.path(), "owner").await?;
    let joiner_agent = networked_agent(dir.path(), "joiner").await?;
    let outcome = async {
        meshed(&owner_agent, &joiner_agent).await?;
        let owner_dir = dir.path().join("owner-state");
        let joiner_dir = dir.path().join("joiner-state");
        tokio::fs::create_dir_all(&owner_dir).await?;
        tokio::fs::create_dir_all(&joiner_dir).await?;
        let owner = secure_endpoint_test_state_at(&owner_dir, Arc::clone(&owner_agent)).await?;
        let joiner = secure_endpoint_test_state_at(&joiner_dir, Arc::clone(&joiner_agent)).await?;
        let joiner_id = joiner_agent.agent_id();

        // The joiner's Welcome listener, as `server::run` spawns it.
        let listener = {
            let joiner = Arc::clone(&joiner);
            let mut rx = joiner.agent.subscribe_direct();
            tokio::spawn(async move {
                while let Some(message) = rx.recv().await {
                    if let Some((sender, frame)) = decode_welcome_blob_message(&message) {
                        super::super::dispatch_welcome_blob_message(&joiner, sender, frame).await;
                    }
                }
            })
        };
        let bytes: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let welcome_id = super::super::welcome_id_for_bytes(&bytes);
        let group = "e7".repeat(32);
        let reference = WelcomeRef {
            welcome_id: welcome_id.clone(),
            byte_len: bytes.len() as u64,
            source: hex::encode(owner_agent.agent_id().as_bytes()),
        };
        let pull = {
            let joiner = Arc::clone(&joiner);
            let group = group.clone();
            tokio::spawn(async move {
                super::super::fetch_treekem_welcome_via(
                    &joiner,
                    &group,
                    &reference,
                    |_, _, _| async { Ok(()) },
                )
                .await
            })
        };
        tokio::time::timeout(WAIT, async {
            while !joiner
                .pending_welcome_receives
                .read()
                .await
                .contains_key(&welcome_id)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
        let mut frames = vec![(
            "welcome_offer",
            WelcomeBlobMessage::Offer {
                group_id: group.clone(),
                welcome_id: welcome_id.clone(),
                byte_len: bytes.len() as u64,
                chunk_size,
                total_chunks: x0x::files::total_chunks_for_size(bytes.len() as u64, chunk_size),
                blake3_hex: welcome_id.clone(),
            },
        )];
        for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
            frames.push((
                "welcome_frame",
                WelcomeBlobMessage::Chunk {
                    welcome_id: welcome_id.clone(),
                    sequence: sequence as u64,
                    data: BASE64.encode(chunk),
                },
            ));
        }
        frames.push((
            "welcome_complete",
            WelcomeBlobMessage::Complete {
                welcome_id: welcome_id.clone(),
            },
        ));
        // The joiner announces itself, so the owner's authority stores
        // confirm its machine and the direct connection counts as live.
        tokio::time::timeout(Duration::from_secs(15), async {
            while !owner_agent.has_live_direct_connection(&joiner_id).await {
                let _ = joiner_agent.announce_identity(false, false).await;
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        })
        .await?;
        owner_agent.fail_pinned_sends_as_disconnected_for_testing(frames.len());
        for (kind, frame) in &frames {
            let payload = welcome_blob_payload(frame).map_err(anyhow::Error::msg)?;
            let sent = super::super::send_join_artifact(
                &owner,
                &joiner_id,
                &payload,
                &group,
                kind,
                admit_all(),
                Instant::now() + Duration::from_secs(60),
            )
            .await;
            anyhow::ensure!(sent.is_ok(), "{kind}: {sent:?}");
        }
        let pulled = tokio::time::timeout(Duration::from_secs(15), pull).await??;
        listener.abort();
        anyhow::ensure!(
            pulled.map_err(anyhow::Error::msg)? == bytes,
            "the exact Welcome arrived through the real chain"
        );
        let transports = transports_to(&owner, &hex::encode(joiner_id.as_bytes()));
        anyhow::ensure!(
            transports
                .iter()
                .filter(|(_, transport)| *transport == "gossip_single_publish")
                .count()
                == frames.len(),
            "every frame fell back to the gossip inbox: {transports:?}"
        );
        anyhow::Ok(())
    }
    .await;
    owner_agent.shutdown().await;
    joiner_agent.shutdown().await;
    outcome
}

#![cfg(test)]

//! The admitted gossip-inbox leg of a recovery response (ADR 0107), with
//! real Agents on loopback: one admitted publish, sealed to the recipient,
//! delivered under the gossip envelope's authenticated sender.
use super::*;
use futures::FutureExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PHASE: Duration = Duration::from_secs(15);

async fn node(dir: &std::path::Path, name: &str) -> Agent {
    Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine")))
        .with_agent_key_path(dir.join(format!("{name}-agent")))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_network_config(network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
            bootstrap_nodes: vec![],
            port_mapping_enabled: false,
            mdns_enabled: false,
            ..Default::default()
        })
        .build()
        .await
        .expect("real Agent setup")
}

/// Two meshed agents; `sender` holds `recipient`'s signed gossip-inbox
/// capability advert.
async fn meshed(sender: &Agent, recipient: &Agent) {
    for agent in [sender, recipient] {
        let kem = std::sync::Arc::new(
            groups::kem_envelope::AgentKemKeypair::generate().expect("real KEM"),
        );
        agent
            .start_dm_inbox(kem, dm_inbox::DmInboxConfig::default())
            .await
            .expect("real inbox");
        agent.join_network().await.expect("join actual runtime");
    }
    let addr = recipient
        .network()
        .expect("network")
        .bound_addr()
        .await
        .expect("bound address");
    tokio::time::timeout(PHASE, sender.network().expect("network").connect_addr(addr))
        .await
        .expect("connect deadline")
        .expect("real connect");
    for agent in [sender, recipient] {
        agent
            .gossip_runtime
            .as_ref()
            .expect("runtime")
            .pubsub()
            .refresh_topic_peers()
            .await;
    }
    let ready = recipient.current_dm_capabilities();
    assert!(ready.gossip_inbox);
    let signing = gossip::SigningContext::from_keypair(recipient.identity.agent_keypair());
    let advert = dm_capability_service::build_signed_advert(
        &signing,
        recipient.agent_id(),
        recipient.machine_id(),
        ready,
    )
    .expect("signed advert");
    let learned = || {
        sender
            .capability_store
            .lookup_binding(&recipient.agent_id())
            .is_some_and(|binding| binding.capabilities.gossip_inbox)
    };
    tokio::time::timeout(PHASE, async {
        while !learned() {
            recipient
                .publish(dm_capability::DM_CAPABILITY_TOPIC, advert.clone())
                .await
                .expect("own advert publish");
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    })
    .await
    .expect("sender learns the recipient's capability");
}

/// An admission whose pre-phase and seam answer as given, counting the
/// pre-phase runs.
fn admission(pre: bool, seam: bool, runs: Arc<AtomicUsize>) -> dm::ArtifactAdmission {
    std::sync::Arc::new(move || {
        let runs = Arc::clone(&runs);
        Box::pin(async move {
            runs.fetch_add(1, Ordering::SeqCst);
            pre.then(|| Box::new(move || seam) as dm::SeamAdmission)
        })
    })
}

fn deadline_ms(within: Duration) -> u64 {
    dm::now_unix_ms() + u64::try_from(within.as_millis()).unwrap_or(u64::MAX)
}

async fn received(
    inbox: &mut direct::DirectMessageReceiver,
    payload: &[u8],
    within: Duration,
) -> Option<direct::DirectMessage> {
    tokio::time::timeout(within, async {
        loop {
            let message = inbox.recv().await?;
            if message.payload == payload {
                return Some(message);
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn run(test: impl std::future::Future<Output = ()>, agents: [&Agent; 2]) {
    let outcome = std::panic::AssertUnwindSafe(test).catch_unwind().await;
    for agent in agents {
        agent.shutdown().await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// WHY: with no direct path, an owner's Welcome frame must reach the joiner
/// over the gossip inbox. The recipient's direct channel must name the
/// gossip envelope's authenticated sender and mark it verified, which is
/// what the Welcome and join-result listeners require.
#[tokio::test]
async fn an_admitted_gossip_publish_reaches_the_recipient_from_its_authenticated_sender() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let sender = node(dir.path(), "sender").await;
    let recipient = node(dir.path(), "recipient").await;
    run(
        async {
            meshed(&sender, &recipient).await;
            assert!(sender.gossip_inbox_reachable(&recipient.agent_id()).await);
            let mut inbox = recipient.subscribe_direct();
            let runs = Arc::new(AtomicUsize::new(0));
            let payload = b"{\"type\":\"complete\",\"welcome_id\":\"w\"}".to_vec();
            let receipt = sender
                .send_direct_gossip_admitted(
                    &recipient.agent_id(),
                    &payload,
                    &admission(true, true, Arc::clone(&runs)),
                    deadline_ms(Duration::from_secs(60)),
                )
                .await
                .expect("the admitted publish is handed to gossip");
            assert_eq!(receipt.path, dm::DmPath::GossipInbox);
            assert_eq!(runs.load(Ordering::SeqCst), 1, "one admission, one publish");
            let delivered = received(&mut inbox, &payload, PHASE)
                .await
                .expect("the recipient receives the frame");
            assert_eq!(delivered.sender, sender.agent_id());
            assert!(delivered.verified, "the sender is authenticated");
        },
        [&sender, &recipient],
    )
    .await;
}

/// WHY (ADR 0107 per-frame admission): a refusal at either admission phase
/// publishes nothing, and an artifact whose deadline has passed is never
/// published.
#[tokio::test]
async fn a_refused_or_expired_gossip_publish_sends_nothing() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let sender = node(dir.path(), "sender").await;
    let recipient = node(dir.path(), "recipient").await;
    run(
        async {
            meshed(&sender, &recipient).await;
            let mut inbox = recipient.subscribe_direct();
            let to = recipient.agent_id();
            let refused_pre = b"refused-at-pre-phase".to_vec();
            let refused_seam = b"refused-at-seam".to_vec();
            let expired = b"past-its-deadline".to_vec();
            let runs = Arc::new(AtomicUsize::new(0));
            for (payload, admit, by) in [
                (
                    &refused_pre,
                    admission(false, true, Arc::clone(&runs)),
                    deadline_ms(Duration::from_secs(60)),
                ),
                (
                    &refused_seam,
                    admission(true, false, Arc::clone(&runs)),
                    deadline_ms(Duration::from_secs(60)),
                ),
                (
                    &expired,
                    admission(true, true, Arc::clone(&runs)),
                    dm::now_unix_ms().saturating_sub(1),
                ),
            ] {
                let sent = sender
                    .send_direct_gossip_admitted(&to, payload, &admit, by)
                    .await;
                assert!(sent.is_err(), "nothing is published: {sent:?}");
            }
            let control = b"admitted-control".to_vec();
            sender
                .send_direct_gossip_admitted(
                    &to,
                    &control,
                    &admission(true, true, Arc::clone(&runs)),
                    deadline_ms(Duration::from_secs(60)),
                )
                .await
                .expect("the control is published");
            let seen = tokio::time::timeout(PHASE, async {
                let mut seen = Vec::new();
                while let Some(message) = inbox.recv().await {
                    let done = message.payload == control;
                    seen.push(message.payload);
                    if done {
                        break;
                    }
                }
                seen
            })
            .await
            .expect("the control arrives");
            for refused in [&refused_pre, &refused_seam, &expired] {
                assert!(
                    !seen.contains(refused),
                    "a refused frame was delivered: {}",
                    String::from_utf8_lossy(refused)
                );
            }
        },
        [&sender, &recipient],
    )
    .await;
}

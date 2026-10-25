#![cfg(test)]

//! Survivor re-key A14 with real Agents on loopback: a leaf recipient's v1
//! DM acknowledgement reaches the sender over live Direct when its gossip
//! frame is lost, so the sender does not wait out its 24 s ACK budget.
use super::*;
use futures::FutureExt;
use std::time::Duration;

const PHASE: Duration = Duration::from_secs(15);

/// The bound a v1 send to a leaf whose gossip ACK is lost must finish
/// within: well under one 8 s attempt.
const ACK_BOUND: Duration = Duration::from_secs(5);

async fn leaf(dir: &std::path::Path, name: &str) -> Agent {
    let mut gossip_config = gossip::GossipConfig::default();
    let _ = gossip_config.apply_caps_consume_only(true);
    Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine")))
        .with_agent_key_path(dir.join(format!("{name}-agent")))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_gossip_config(gossip_config)
        // What `leaf_mode = true` runs with: no legacy DM bus, so a v1 ACK
        // has one gossip route.
        .with_skip_legacy_dm_bus(true)
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

/// WHY (A14): a leaf answers a v1 DM with one eager frame on the sender's
/// inbox topic. When that frame is lost (here: dropped at the recipient,
/// as a non-forwarding leaf bystander drops it), the sender used to wait
/// 8 s, back off 8 s, resend and wait 8 s more, then fail, although the DM
/// had arrived. The Direct hedge carries the same ACK at once.
#[tokio::test]
async fn a_leaf_v1_ack_reaches_the_sender_over_direct_when_its_gossip_frame_is_lost() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let sender = leaf(dir.path(), "sender").await;
    let recipient = leaf(dir.path(), "recipient").await;
    let outcome = std::panic::AssertUnwindSafe(async {
        for agent in [&sender, &recipient] {
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
        for agent in [&sender, &recipient] {
            agent
                .gossip_runtime
                .as_ref()
                .expect("runtime")
                .pubsub()
                .refresh_topic_peers()
                .await;
        }

        // The sender learns the recipient's gossip-inbox capability.
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

        dm_inbox::V1_GOSSIP_ACK_DROPPED_FROM
            .lock()
            .expect("drop list")
            .push(recipient.agent_id());
        // The sender checks a Direct ACK against the recipient's announced
        // key, as it would for a member it shares a room with.
        sender
            .start_identity_listener()
            .await
            .expect("identity listener");
        let announced = || async {
            sender
                .identity_discovery_cache
                .read()
                .await
                .contains_key(&recipient.agent_id())
        };
        tokio::time::timeout(PHASE, async {
            while !announced().await {
                recipient
                    .announce_identity(false, false)
                    .await
                    .expect("announce");
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        })
        .await
        .expect("the sender learns the recipient's announced key");

        let before = sender.direct_messaging().diagnostics_snapshot().stats;
        let mut inbox = recipient.subscribe_direct();
        let payload = b"v1 dm to a leaf whose gossip ack is lost".to_vec();
        let started = std::time::Instant::now();
        let receipt = tokio::time::timeout(
            ACK_BOUND,
            sender.send_direct_with_config(
                &recipient.agent_id(),
                payload.clone(),
                dm::DmSendConfig {
                    timeout_per_attempt: Duration::from_secs(8),
                    require_gossip: true,
                    require_gossip_ack: true,
                    require_durable_app_ack: false,
                    ..dm::DmSendConfig::default()
                },
            ),
        )
        .await
        .expect("the sender does not wait out its ACK budget")
        .expect("the v1 send is acknowledged");
        assert_eq!(receipt.path, dm::DmPath::GossipInbox);
        let waited = started.elapsed();

        let delivered = tokio::time::timeout(PHASE, async {
            loop {
                let message = inbox.recv().await.expect("delivery channel open");
                if message.payload == payload {
                    return message;
                }
            }
        })
        .await
        .expect("the recipient receives the DM");
        assert_eq!(delivered.sender, sender.agent_id());

        let after = sender.direct_messaging().diagnostics_snapshot().stats;
        assert_eq!(after.v1_ack_waits, before.v1_ack_waits + 1);
        assert_eq!(after.v1_ack_wait_timeouts, before.v1_ack_wait_timeouts);
        let wait_ms = after.v1_ack_wait_ms - before.v1_ack_wait_ms;
        assert!(
            wait_ms <= u64::try_from(waited.as_millis()).unwrap_or(u64::MAX) + 50
                && wait_ms < 5_000,
            "the counter shows a short wait: {wait_ms} ms"
        );
    })
    .catch_unwind()
    .await;
    if let Ok(mut dropped) = dm_inbox::V1_GOSSIP_ACK_DROPPED_FROM.lock() {
        dropped.retain(|agent| *agent != recipient.agent_id());
    }
    sender.shutdown().await;
    recipient.shutdown().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

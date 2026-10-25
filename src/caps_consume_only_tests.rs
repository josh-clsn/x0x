#![cfg(test)]

//! `[gossip] caps_consume_only` with real Agents on loopback: a capability
//! learned through the caps topics on a consume-only leaf still carries a
//! strict DM.
use super::*;
use futures::FutureExt;
use std::time::Duration;

const PHASE: Duration = Duration::from_secs(15);

async fn consume_only_leaf(dir: &std::path::Path, name: &str) -> Agent {
    // What a `leaf_mode = true` daemon runs with when the key is unset.
    let mut gossip_config = gossip::GossipConfig::default();
    assert_eq!(gossip_config.apply_caps_consume_only(true), None);
    assert_eq!(gossip_config.caps_consume_only, Some(true));
    Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine")))
        .with_agent_key_path(dir.join(format!("{name}-agent")))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_gossip_config(gossip_config)
        // Durable history is what makes a node advertise v2 durable ACKs.
        .with_history(history::HistoryConfig {
            enabled: true,
            db_path: Some(dir.join(format!("{name}-history.db"))),
            ..Default::default()
        })
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

fn caps_counters(agent: &Agent) -> (u64, u64) {
    let pubsub = agent.gossip_runtime.as_ref().expect("runtime").pubsub();
    let diag = pubsub.relay_fanout_diagnostics();
    assert_eq!(diag["consume_only"], true, "the leaf runs consume-only");
    let steady =
        saorsa_gossip_types::TopicId::from_entity(dm_capability::DM_CAPABILITY_TOPIC.as_bytes());
    let sg_deliver_only = pubsub
        .stage_stats()
        .validator
        .by_topic
        .get(&steady.to_string())
        .map_or(0, |meter| meter.deliver_only);
    (
        diag["consume_only_msgs_by_topic"][dm_capability::DM_CAPABILITY_TOPIC]
            .as_u64()
            .expect("per-topic consume-only counter"),
        sg_deliver_only,
    )
}

/// WHY (`[gossip] caps_consume_only`, design §1.2-§1.3): the reason the leaf
/// keeps *subscribing* to caps instead of dropping them is strict DMs to
/// contacts and strangers, whose key and durable-ACK binding only arrive by
/// caps. Two consume-only leaves, directly connected: the recipient's own
/// signed advert reaches the sender only through a `DeliverOnly` verdict,
/// and that capability must still clear the strict gate and carry the DM
/// to the recipient. Without the change the counters below do not move.
#[tokio::test]
async fn strict_dm_goes_out_on_a_capability_learned_by_a_consume_only_leaf() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let sender = consume_only_leaf(dir.path(), "sender").await;
    let recipient = consume_only_leaf(dir.path(), "recipient").await;
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
        let connected =
            tokio::time::timeout(PHASE, sender.network().expect("network").connect_addr(addr))
                .await
                .expect("connect deadline")
                .expect("real connect");
        assert_eq!(connected.0, recipient.machine_id().0);
        for agent in [&sender, &recipient] {
            agent
                .gossip_runtime
                .as_ref()
                .expect("runtime")
                .pubsub()
                .refresh_topic_peers()
                .await;
        }

        // The recipient's capability, as its own advert service signs it.
        let ready = recipient.current_dm_capabilities();
        assert!(ready.supports_durable_app_ack() && ready.gossip_inbox);
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
                .is_some_and(|binding| {
                    binding.machine_id == recipient.machine_id()
                        && binding.capabilities.supports_durable_app_ack()
                })
        };
        // A best-effort publish can reach zero eager peers, so republish
        // inside the window (the #1135 pattern), as the service would.
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
        .expect("sender learns the recipient's capability through caps");

        let (consume_only_msgs, sg_deliver_only) = caps_counters(&sender);
        assert!(
            consume_only_msgs >= 1 && sg_deliver_only >= consume_only_msgs,
            "the advert arrived under the consume-only DeliverOnly verdict \
             (x0x {consume_only_msgs}, sg {sg_deliver_only})"
        );

        let mut inbox = recipient.subscribe_direct();
        let payload = b"strict dm through consume-only caps".to_vec();
        let receipt = tokio::time::timeout(
            PHASE,
            sender.send_direct_with_config(
                &recipient.agent_id(),
                payload.clone(),
                dm::DmSendConfig {
                    require_gossip: true,
                    require_durable_app_ack: true,
                    ..dm::DmSendConfig::default()
                },
            ),
        )
        .await
        .expect("strict send deadline")
        .expect("strict send is durably acknowledged");
        assert_eq!(receipt.path, dm::DmPath::GossipInbox);

        let delivered = tokio::time::timeout(PHASE, async {
            loop {
                let message = inbox.recv().await.expect("delivery channel open");
                if message.payload == payload {
                    return message;
                }
            }
        })
        .await
        .expect("recipient receives the strict DM");
        assert_eq!(delivered.sender, sender.agent_id());
    })
    .catch_unwind()
    .await;
    sender.shutdown().await;
    recipient.shutdown().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

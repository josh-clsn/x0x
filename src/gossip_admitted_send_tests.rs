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
        // No heartbeat re-announcement inside a test: a direct-origin
        // announcement would write the same binding store an attested DM
        // writes (re-review N4).
        .with_heartbeat_interval(3_600)
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
    connected(sender, recipient).await;
    learn_advert(sender, recipient).await;
}

/// Two agents with DM inboxes and a live connection between them.
async fn connected(sender: &Agent, recipient: &Agent) {
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
}

/// `sender` learns `recipient`'s signed gossip-inbox capability advert.
async fn learn_advert(sender: &Agent, recipient: &Agent) {
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

/// `holder` knows `agent`'s gossip-inbox key only from a contact card.
async fn card_key(holder: &Agent, agent: &Agent) {
    holder.contacts().write().await.add(contacts::Contact {
        agent_id: agent.agent_id(),
        trust_level: contacts::TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: contacts::IdentityType::Known,
        machines: Vec::new(),
        dm_capabilities: Some(agent.current_dm_capabilities()),
    });
}

/// WHY (re-review N1, the field state): the owner holds no capability
/// advert for the joiner, no discovery entry and no announcement binding;
/// it knows the joiner's key from a contact card, and the joiner's machine
/// only from the machine-key attestation on a DM the joiner sent over the
/// gossip inbox (its FetchRequest). The gossip leg takes that verified
/// binding's machine, runs its checks against it, and the frame reaches
/// the joiner. Before the fix the card key needed a discovery entry, so the
/// frame was unreachable by gossip and stayed on the failing raw path.
#[tokio::test]
async fn a_card_key_with_only_an_attested_inbound_dm_binding_rides_gossip() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let owner = node(dir.path(), "owner").await;
    let joiner = node(dir.path(), "joiner").await;
    run(
        async {
            connected(&owner, &joiner).await;
            card_key(&owner, &joiner).await;
            card_key(&joiner, &owner).await;
            let joiner_id = joiner.agent_id();
            // The field state: nothing names the joiner's machine but what
            // its own attested DM will write.
            owner.capability_store.forget_for_testing(&joiner_id);
            owner
                .identity_discovery_cache
                .write()
                .await
                .remove(&joiner_id);
            *owner.announced_machine_bindings.write().await =
                dm_inbox::AuthenticatedMachineBindingCache::default();
            *owner.authenticated_machine_bindings.write().await =
                dm_inbox::AuthenticatedMachineBindingCache::default();
            assert!(owner.pinned_binding_now(&joiner_id).await.is_none());

            // The joiner's FetchRequest, over the gossip inbox.
            let request = br#"{"type":"fetch_request","group_id":"g","welcome_id":"w"}"#.to_vec();
            joiner
                .send_direct_with_config(
                    &owner.agent_id(),
                    request,
                    dm::DmSendConfig {
                        require_gossip: true,
                        require_gossip_ack: false,
                        ..dm::DmSendConfig::default()
                    },
                )
                .await
                .expect("the joiner's request is published");
            let bound = tokio::time::timeout(PHASE, async {
                loop {
                    if let Some(binding) = owner.pinned_binding_now(&joiner_id).await {
                        return binding;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("the attested request binds the joiner's machine");
            assert_eq!(bound.machine, joiner.machine_id());
            assert_eq!(bound.source, PinnedMachineSource::AuthenticatedBinding);
            assert_binding_is_the_attested_dm(&owner, &joiner).await;
            // An advert or announcement the joiner sent meanwhile would hide
            // the field state; drop them again (the attested binding stays).
            owner.capability_store.forget_for_testing(&joiner_id);
            owner
                .identity_discovery_cache
                .write()
                .await
                .remove(&joiner_id);
            assert!(owner.capability_store.lookup_binding(&joiner_id).is_none());
            assert!(owner
                .identity_discovery_cache
                .read()
                .await
                .get(&joiner_id)
                .is_none());

            assert!(owner.gossip_inbox_reachable(&joiner_id).await);
            assert_eq!(
                owner.gossip_recipient_source_for_testing(&joiner_id),
                Some(GossipRecipientSource::CardWithAuthenticatedBinding)
            );
            assert!(
                owner.gossip_capability_refresh_requested_for_testing(&joiner_id),
                "with no cached advert, the owner asks the joiner for one"
            );
            let mut inbox = joiner.subscribe_direct();
            let payload = br#"{"type":"complete","welcome_id":"w"}"#.to_vec();
            owner
                .send_direct_gossip_admitted(
                    &joiner_id,
                    &payload,
                    &admission(true, true, Arc::new(AtomicUsize::new(0))),
                    deadline_ms(Duration::from_secs(60)),
                )
                .await
                .expect("the frame rides gossip");
            let delivered = received(&mut inbox, &payload, PHASE)
                .await
                .expect("the joiner receives the frame");
            assert_eq!(delivered.sender, owner.agent_id());
            assert!(delivered.verified);
        },
        [&owner, &joiner],
    )
    .await;
}

/// WHY (re-review N1): a revoked machine named by the verified binding
/// blocks the gossip leg as it blocks the raw path.
#[tokio::test]
async fn a_card_key_bound_to_a_revoked_machine_is_refused() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let owner = node(dir.path(), "owner").await;
    let joiner = node(dir.path(), "joiner").await;
    run(
        async {
            connected(&owner, &joiner).await;
            card_key(&owner, &joiner).await;
            let joiner_id = joiner.agent_id();
            owner.capability_store.forget_for_testing(&joiner_id);
            owner
                .identity_discovery_cache
                .write()
                .await
                .remove(&joiner_id);
            *owner.announced_machine_bindings.write().await =
                dm_inbox::AuthenticatedMachineBindingCache::default();
            *owner.authenticated_machine_bindings.write().await =
                dm_inbox::AuthenticatedMachineBindingCache::default();
            dm_inbox::record_authenticated_machine_binding(
                &owner.authenticated_machine_bindings,
                joiner_id,
                joiner.machine_id(),
                dm::now_unix_ms() / 1000,
            )
            .await;
            assert!(
                owner.gossip_inbox_reachable(&joiner_id).await,
                "control: the verified binding names a machine"
            );
            owner
                .revocation_set
                .write()
                .await
                .revoke_machine_for_testing(joiner.machine_id());
            let sent = owner
                .send_direct_gossip_admitted(
                    &joiner_id,
                    b"to-a-revoked-machine",
                    &admission(true, true, Arc::new(AtomicUsize::new(0))),
                    deadline_ms(Duration::from_secs(60)),
                )
                .await;
            assert!(sent.is_err(), "{sent:?}");
        },
        [&owner, &joiner],
    )
    .await;
}

/// The owner's binding for `joiner` is the one the joiner's attested DM
/// wrote: no verified identity announcement was processed since the stores
/// were cleared (a direct-origin announcement would also land in the
/// announced store), and the stored stamp and machine are the attested
/// DM's (its envelope `created_at`, in seconds).
async fn assert_binding_is_the_attested_dm(owner: &Agent, joiner: &Agent) {
    let joiner_id = joiner.agent_id();
    assert!(
        owner
            .announced_machine_bindings
            .read()
            .await
            .peek(&joiner_id)
            .is_none(),
        "an identity announcement from the joiner was processed"
    );
    let stored = owner
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&joiner_id)
        .expect("a stored binding");
    let attested = dm_inbox::ATTESTED_DM_BINDING_WRITES
        .lock()
        .expect("attested writes")
        .iter()
        .rev()
        .find(|(agent, _, _)| *agent == joiner_id)
        .copied()
        .expect("the joiner's DM wrote an attested binding");
    assert_eq!(attested.1, joiner.machine_id());
    assert_eq!(
        (stored.machine_id, stored.announced_at),
        (attested.1, attested.2),
        "the stored binding is the attested DM's"
    );
    assert!(stored.network_authenticated && !stored.local_pin);
}

/// WHY (re-review N3): a card import pins the card's machine, which may be
/// an unsigned card field. That pin alone never names the gossip leg's
/// machine (the raw path's selection still sees it). Once the joiner's
/// attested DM names the same machine, the binding is network-authenticated
/// and the gossip leg uses it.
#[tokio::test]
async fn a_card_pin_alone_never_names_the_gossip_machine() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let owner = node(dir.path(), "owner").await;
    let joiner = node(dir.path(), "joiner").await;
    run(
        async {
            connected(&owner, &joiner).await;
            card_key(&owner, &joiner).await;
            card_key(&joiner, &owner).await;
            let joiner_id = joiner.agent_id();
            owner.capability_store.forget_for_testing(&joiner_id);
            owner
                .identity_discovery_cache
                .write()
                .await
                .remove(&joiner_id);
            *owner.announced_machine_bindings.write().await =
                dm_inbox::AuthenticatedMachineBindingCache::default();
            *owner.authenticated_machine_bindings.write().await =
                dm_inbox::AuthenticatedMachineBindingCache::default();
            let now = dm::now_unix_ms() / 1000;
            owner
                .pin_card_binding(DiscoveredAgent {
                    self_name: None,
                    agent_id: joiner_id,
                    machine_id: joiner.machine_id(),
                    user_id: None,
                    addresses: Vec::new(),
                    announced_at: now.saturating_sub(60),
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
            owner.capability_store.forget_for_testing(&joiner_id);
            assert!(
                owner.pinned_binding_now(&joiner_id).await.is_some(),
                "the raw path's selection is unchanged: it sees the pin"
            );
            assert_eq!(
                owner.gossip_inbox_reach(&joiner_id).await,
                Err(GOSSIP_UNREACHABLE_NO_MACHINE),
                "a card pin alone names no gossip machine"
            );

            let request = br#"{"type":"fetch_request","group_id":"g","welcome_id":"w2"}"#.to_vec();
            joiner
                .send_direct_with_config(
                    &owner.agent_id(),
                    request,
                    dm::DmSendConfig {
                        require_gossip: true,
                        require_gossip_ack: false,
                        ..dm::DmSendConfig::default()
                    },
                )
                .await
                .expect("the joiner's request is published");
            tokio::time::timeout(PHASE, async {
                while !owner
                    .authenticated_machine_bindings
                    .read()
                    .await
                    .peek(&joiner_id)
                    .is_some_and(|binding| binding.network_authenticated)
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("the attested request confirms the pinned machine");
            owner.capability_store.forget_for_testing(&joiner_id);
            owner
                .identity_discovery_cache
                .write()
                .await
                .remove(&joiner_id);
            assert_eq!(owner.gossip_inbox_reach(&joiner_id).await, Ok(()));
            assert_eq!(
                owner.gossip_recipient_source_for_testing(&joiner_id),
                Some(GossipRecipientSource::CardWithAuthenticatedBinding)
            );
        },
        [&owner, &joiner],
    )
    .await;
}

//! How many times one gossip-inbox send publishes its envelope.
//!
//! A default send publishes on the recipient's inbox topic, republishes on the
//! legacy DM bus after a short no-ACK delay, and repeats both on its retry. A
//! caller asking for `skip_legacy_bus_fallback` never publishes on the bus;
//! with no retry that is exactly one publish, which still reports the ACK or
//! the timeout. (A daemon's `skip_legacy_dm_bus` opt-out deliberately keeps
//! the sender-side fallback; `legacy_bus_interop_tests` pins that.)
//!
//! One real Agent with a real gossip runtime and no peers (a publish fans out
//! to nobody); the recipient never answers unless the test resolves its ACK.
//! Run with a temporary X0X_HOME.
use super::*;
use crate::dm::{DmAckOutcome, DmError, DmPath, DmSendConfig, DurableSendStages};
use crate::dm_send::{self, DmSendContext};
use crate::gossip::SigningContext;
use crate::groups::kem_envelope::AgentKemKeypair;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

const ATTEMPT: Duration = Duration::from_millis(600);

#[derive(Default)]
struct Fields {
    stage: Option<String>,
    request_id: Option<String>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "stage" => self.stage = Some(value.to_owned()),
            "request_id" => self.request_id = Some(value.to_owned()),
            _ => {}
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "request_id" {
            self.request_id = Some(format!("{value:?}"));
        }
    }
}

/// Counts this request's inbox publishes and legacy-bus publishes.
#[derive(Clone)]
struct PublishWitness {
    request: String,
    counts: Arc<Mutex<(usize, usize)>>,
}

impl<S: tracing::Subscriber> Layer<S> for PublishWitness {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "dm.trace" {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.request_id.as_deref() != Some(self.request.as_str()) {
            return;
        }
        if let Ok(mut counts) = self.counts.lock() {
            match fields.stage.as_deref() {
                Some("inbox_publish") => counts.0 += 1,
                Some("legacy_bus_fallback_publish") => counts.1 += 1,
                _ => {}
            }
        }
    }
}

async fn sender(dir: &std::path::Path) -> Agent {
    Agent::builder()
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key_path(dir.join("agent.key"))
        .with_contact_store_path(dir.join("contacts.json"))
        .with_peer_cache_disabled()
        .with_network_config(network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
            bootstrap_nodes: Vec::new(),
            port_mapping_enabled: false,
            mdns_enabled: false,
            ..network::NetworkConfig::default()
        })
        .build()
        .await
        .expect("agent with a gossip runtime")
}

fn pubsub(agent: &Agent) -> Arc<gossip::PubSubManager> {
    Arc::clone(
        agent
            .gossip_runtime
            .as_ref()
            .expect("gossip runtime")
            .pubsub(),
    )
}

/// One gossip-inbox send of a fresh request under `config`; when `ack` is
/// set the recipient's ACK is resolved while the send waits. Returns the
/// send's result and its (inbox, bus) publish counts.
async fn send(
    agent: &Agent,
    mut config: DmSendConfig,
    ack: bool,
) -> (Result<dm::DmReceipt, DmError>, (usize, usize)) {
    let id = dm_send::fresh_request_id();
    config.logical_request_id = Some(id);
    config.timeout_per_attempt = ATTEMPT;
    let recipient = identity::AgentKeypair::generate()
        .expect("recipient")
        .agent_id();
    let recipient_machine = identity::MachineId([0xD7; 32]);
    let key = AgentKemKeypair::generate().expect("recipient KEM");
    let witness = PublishWitness {
        request: hex::encode(id),
        counts: Arc::new(Mutex::new((0, 0))),
    };
    let inflight = agent.dm_inflight_acks();
    let resolver = ack.then(|| {
        let inflight = Arc::clone(&inflight);
        tokio::spawn(async move {
            loop {
                if inflight.resolve(&id, recipient, recipient_machine, DmAckOutcome::Accepted) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    });
    let signing = SigningContext::from_keypair(agent.identity.agent_keypair());
    let mut stages = DurableSendStages::default();
    let result = dm_send::send_via_gossip(
        DmSendContext {
            pubsub: pubsub(agent),
            signing: &signing,
            self_agent_id: agent.agent_id(),
            self_machine_id: agent.machine_id(),
            machine_keypair: agent.identity.machine_keypair(),
            inflight,
            stages: &mut stages,
        },
        recipient,
        Some(recipient_machine),
        &key.public_bytes,
        b"piece".to_vec(),
        &config,
        None,
    )
    .with_subscriber(tracing_subscriber::registry().with(witness.clone()))
    .await;
    if let Some(resolver) = resolver {
        resolver.abort();
    }
    let counts = *witness.counts.lock().expect("witness");
    (result, counts)
}

fn single_publish() -> DmSendConfig {
    DmSendConfig {
        skip_legacy_bus_fallback: true,
        max_retries: 0,
        ..DmSendConfig::default()
    }
}

/// Today's default, pinned: two attempts, each an inbox publish and a
/// legacy-bus republish, then a timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_default_send_without_an_ack_publishes_four_times() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let agent = sender(dir.path()).await;
    let (result, counts) = send(&agent, DmSendConfig::default(), false).await;
    assert!(
        matches!(result, Err(DmError::Timeout { retries: 1, .. })),
        "{result:?}"
    );
    assert_eq!(counts, (2, 2));
}

/// A single-publish send publishes exactly once and reports the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_publish_send_publishes_once_and_times_out() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let agent = sender(dir.path()).await;
    let (result, counts) = send(&agent, single_publish(), false).await;
    assert!(
        matches!(result, Err(DmError::Timeout { retries: 0, .. })),
        "{result:?}"
    );
    assert_eq!(counts, (1, 0), "one inbox publish, no bus, no republish");
}

/// A single-publish send still returns the recipient's ACK.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_publish_send_reports_its_ack() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let agent = sender(dir.path()).await;
    let (result, counts) = send(&agent, single_publish(), true).await;
    let receipt = result.expect("the ACK resolves the send");
    assert_eq!(receipt.path, DmPath::GossipInbox);
    assert_eq!(receipt.retries_used, 0);
    assert_eq!(counts, (1, 0));
}

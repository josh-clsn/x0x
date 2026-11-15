//! T-self-evidence-lookup: real loopback daemons, no gossip joined and no
//! announcement sent. The receiver starts with nothing about the sender.

use super::*;
use crate::{dm::DmSendConfig, Agent};

async fn node(dir: &std::path::Path, name: &str) -> Agent {
    let path = dir.join(name);
    std::fs::create_dir_all(&path).unwrap();
    let agent = Agent::builder()
        .with_identity_dir(&path)
        .with_machine_key(path.join("machine.key"))
        .with_agent_key_path(path.join("agent.key"))
        .with_user_key_path(path.join("user.key"))
        .with_agent_cert_path(path.join("agent.cert"))
        .with_contact_store_path(path.join("contacts.json"))
        .with_peer_cache_disabled()
        .with_network_config(crate::network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..Default::default()
        })
        .build()
        .await
        .unwrap();
    // No relationship with anyone: a Noetic DM partner is an x0x stranger.
    agent
        .start_peer_evidence(
            path.join("evidence"),
            Default::default(),
            Arc::new(|_| Some(false)),
        )
        .unwrap();
    assert!(agent.peer_evidence().wait(0).await);
    agent
        .dm_capabilities_tx
        .send_replace(crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]));
    agent.start_stream_accept_loop();
    agent.start_direct_listener();
    agent
}

fn raw() -> DmSendConfig {
    DmSendConfig {
        prefer_raw_quic_if_connected: true,
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(8)),
        ..DmSendConfig::default()
    }
}

/// `from` holds `to`'s class A record, as after hearing it announce.
async fn knows(from: &Agent, to: &Agent) {
    let mut addr = to.network().unwrap().bound_addr().await.unwrap();
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let mut entry =
        crate::discovered_agent_fixture(1, crate::Agent::unix_timestamp_secs(), &[], None);
    entry.agent_id = to.agent_id();
    entry.machine_id = to.machine_id();
    entry.addresses = vec![addr];
    entry.can_receive_direct = Some(true);
    from.insert_discovered_agent_for_testing(entry).await;
}

fn counter(agent: &Agent, name: &str) -> u64 {
    agent.peer_evidence().diagnostics()[name]
        .as_u64()
        .unwrap_or(0)
}

fn publishes(agent: &Agent) -> Option<u64> {
    agent.gossip_stats().map(|stats| stats.publish_total)
}

/// Every file under `dir` with its length and modification time.
fn snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                out.push((entry.path(), meta.len(), meta.modified().unwrap()));
            }
        }
    }
    out.sort();
    out
}

async fn receive(rx: &mut crate::direct::DirectMessageReceiver) -> crate::direct::DirectMessage {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a frame arrives")
        .expect("the stream is open")
}

/// The drill-x shape: the device announced before the receiver's daemon
/// started, so the receiver holds nothing about it. The device dials and
/// writes; the receiver's reply goes raw within two seconds, with no
/// announcement or capability publish on either side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_daemon_answers_a_device_it_never_heard_announce() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    assert!(friend
        .identity_discovery_cache
        .read()
        .await
        .get(&device.agent_id())
        .is_none());
    let before = (publishes(&device), publishes(&friend));

    let mut friend_rx = friend.subscribe_direct();
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .expect("the device writes raw");
    let first = receive(&mut friend_rx).await;
    assert!(!first.verified, "the triggering frame stays unverified");

    let mut device_rx = device.subscribe_direct();
    let started = std::time::Instant::now();
    let reply = friend
        .send_direct_with_config(&device.agent_id(), b"reply".to_vec(), raw())
        .await;
    let waited = started.elapsed();
    assert!(reply.is_ok(), "the reply goes raw: {reply:?}");
    assert!(waited < Duration::from_secs(2), "took {waited:?}");
    assert_eq!(receive(&mut device_rx).await.payload, b"reply");

    device
        .send_direct_with_config(&friend.agent_id(), b"again".to_vec(), raw())
        .await
        .unwrap();
    let later = receive(&mut friend_rx).await;
    assert!(
        later.verified,
        "a later frame is verified by the self-evidence"
    );

    assert_eq!(
        (publishes(&device), publishes(&friend)),
        before,
        "recovery publishes nothing on any topic"
    );
    assert_eq!(counter(&friend, "evidence_self_lookup_sent"), 1);
    assert_eq!(counter(&friend, "evidence_self_lookup_accepted"), 1);
    assert_eq!(counter(&device, "evidence_self_lookup_served"), 1);
    assert_eq!(counter(&device, "evidence_own_answer_mints"), 1);
}

/// A stranger's accepted self-evidence is held in memory only: no file
/// under the receiver's directory changes, the evidence store has no
/// record, and a restarted daemon has no binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_self_evidence_is_never_written_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    let friend_dir = dir.path().join("friend");
    let files = snapshot(&friend_dir);

    let mut friend_rx = friend.subscribe_direct();
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .unwrap();
    receive(&mut friend_rx).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while friend
            .authenticated_machine_bindings
            .read()
            .await
            .peek(&device.agent_id())
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the self-evidence lands in memory");
    assert_eq!(
        friend
            .identity_discovery_cache
            .read()
            .await
            .get(&device.agent_id())
            .map(|entry| entry.machine_id),
        Some(device.machine_id())
    );
    assert!(friend
        .capability_store
        .lookup_binding(&device.agent_id())
        .is_some_and(|binding| binding.machine_id == device.machine_id()));
    assert!(friend.has_live_direct_connection(&device.agent_id()).await);

    let now = dm_capability::now_unix_ms();
    assert!(friend
        .peer_evidence()
        .usable_agent(device.agent_id(), now)
        .is_none());
    assert_eq!(snapshot(&friend_dir), files, "no file was written");
    let policy = Arc::new(crate::peer_evidence::RuntimePolicy::new(
        friend.agent_id(),
        friend.owner_trust.clone(),
        Arc::clone(&friend.revocation_set),
    ));
    let reopened = crate::peer_evidence::PeerEvidenceStore::open(
        &friend_dir.join("evidence"),
        Default::default(),
        policy,
        now,
    )
    .unwrap();
    assert!(reopened.usable_agent(device.agent_id(), now).is_none());
    assert!(reopened
        .agents_on_machine(device.machine_id(), 16)
        .is_empty());

    friend.shutdown().await;
    let restarted = node(dir.path(), "friend").await;
    assert!(restarted
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&device.agent_id())
        .is_none());
    assert!(restarted
        .identity_discovery_cache
        .read()
        .await
        .get(&device.agent_id())
        .is_none());
}

/// A latched device still answers the machine it just wrote to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_latched_device_answers_the_machine_it_wrote_to() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    device.quiesce_mesh().await.unwrap();
    let (outcome, _) = device
        .connect_to_agent_leased(&friend.agent_id(), Duration::from_secs(120))
        .await
        .unwrap();
    assert!(outcome.is_live_path(), "{outcome:?}");

    let mut friend_rx = friend.subscribe_direct();
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .unwrap();
    receive(&mut friend_rx).await;
    let mut device_rx = device.subscribe_direct();
    let reply = friend
        .send_direct_with_config(&device.agent_id(), b"reply".to_vec(), raw())
        .await;
    assert!(reply.is_ok(), "{reply:?}");
    assert_eq!(receive(&mut device_rx).await.payload, b"reply");
    assert!(device.mesh_quiesced());
    assert_eq!(counter(&device, "evidence_self_lookup_served"), 1);
}

/// Revocation still applies: with the device's binding retired at the
/// receiver, no self-lookup is sent, nothing is accepted and the reply
/// stays undiscovered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_binding_gets_no_self_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    friend.revocation_set.write().await.union_bundle_retired(&[
        crate::revocation::AgentMachineBinding {
            agent: device.agent_id(),
            machine: device.machine_id(),
            move_epoch: 1,
        },
    ]);
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reply = friend
        .send_direct_with_config(&device.agent_id(), b"reply".to_vec(), raw())
        .await;
    assert!(reply.is_err(), "{reply:?}");
    assert_eq!(counter(&friend, "evidence_self_lookup_sent"), 0);
    assert_eq!(counter(&friend, "evidence_self_lookup_accepted"), 0);
    assert!(friend
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&device.agent_id())
        .is_none());
}

fn context(agent: &Agent) -> Arc<Context> {
    Arc::new(Context {
        bindings: Arc::clone(&agent.authenticated_machine_bindings),
        runtime: Arc::clone(agent.peer_evidence()),
        capture: Arc::clone(&agent.capability_store.evidence_wire),
        network: Arc::clone(agent.network.as_ref().unwrap()),
        identity: Arc::clone(&agent.identity),
        template: agent.build_announcement(false, false).unwrap(),
        own_cert: Arc::clone(&agent.own_cert_pair),
        capabilities: Arc::clone(&agent.dm_capabilities_tx),
        caps: Arc::clone(&agent.capability_store),
        discovery: Arc::clone(&agent.identity_discovery_cache),
        machines: Arc::clone(&agent.machine_discovery_cache),
        owner: agent.owner_trust.clone(),
        revoked: Arc::clone(&agent.revocation_set),
        stores: agent.self_lookup_stores(),
    })
}

/// A self-only answer that names another machine than the one it came
/// over is refused, and nothing is written. Revoked agents, machines and
/// bindings are refused at acceptance too, even after verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_evidence_for_another_machine_or_a_revoked_pairing_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    let answer = context(&device).own_answer(true).unwrap();
    let record = decode::found(&codec().serialize(&answer).unwrap()).unwrap();
    let receiver = context(&friend);
    let store = friend.peer_evidence().store().unwrap();
    let now = dm_capability::now_unix_ms();
    let elsewhere = MachineId([0x5a; 32]);
    assert!(self_lookup::verify_self_found(
        &store,
        &Limits::default(),
        device.agent_id(),
        elsewhere,
        record.clone(),
        now,
    )
    .is_err());
    let self_lookup::SelfFound::Stranger(view) = self_lookup::verify_self_found(
        &store,
        &Limits::default(),
        device.agent_id(),
        device.machine_id(),
        record,
        now,
    )
    .unwrap() else {
        panic!("a stranger's answer is not stored");
    };
    assert!(!receiver.accept_self_evidence(&view, elsewhere).await);
    friend
        .revocation_set
        .write()
        .await
        .revoke_machine_for_testing(device.machine_id());
    assert!(
        !receiver
            .accept_self_evidence(&view, device.machine_id())
            .await
    );
    assert!(friend
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&device.agent_id())
        .is_none());
    assert!(friend.identity_discovery_cache.read().await.is_empty());
    assert!(friend
        .capability_store
        .lookup_binding(&device.agent_id())
        .is_none());
    assert!(store.usable_agent(device.agent_id(), now).is_none());

    let fresh = node(dir.path(), "fresh").await;
    let receiver = context(&fresh);
    assert!(
        receiver
            .accept_self_evidence(&view, device.machine_id())
            .await
    );
    assert_eq!(
        fresh
            .authenticated_machine_bindings
            .read()
            .await
            .peek(&device.agent_id())
            .map(|binding| binding.machine_id),
        Some(device.machine_id())
    );
}

/// An agent with no network whose raw sends run the production resolver
/// over the strict in-process stand-in.
async fn offline(dir: &std::path::Path) -> Agent {
    let agent = Agent::builder()
        .with_identity_dir(dir)
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key_path(dir.join("agent.key"))
        .with_contact_store_path(dir.join("contacts.json"))
        .with_peer_cache_disabled()
        .build()
        .await
        .unwrap();
    agent.set_pinned_standin_strict_resolution_for_testing(true);
    agent
}

/// The receive side's Lookup has reached the responder hook.
async fn frame_arrived(calls: &std::sync::atomic::AtomicUsize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// A device without this change, or a lost answer: the reply comes back
/// `recipient_undiscovered` after about 1.5 s, never later.
#[tokio::test]
async fn the_send_waits_at_most_one_and_a_half_seconds_for_a_silent_self_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let device = (AgentId([0xd1; 32]), MachineId([0xd2; 32]));
    let runtime = Arc::clone(friend.peer_evidence());
    // The frame's Lookup gets no answer. An agent-only Lookup (the
    // connector's) has no route and returns at once, as in production.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |_| {
            let first = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            Box::pin(async move {
                if first {
                    futures::future::pending::<()>().await;
                }
            })
        }))
        .is_ok());
    runtime.spawn_lookup(device.0, device.1);
    frame_arrived(&seen).await;
    let started = std::time::Instant::now();
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    let waited = started.elapsed();
    assert!(
        matches!(sent, Err(crate::error::NetworkError::AgentNotFound(_))),
        "{sent:?}"
    );
    assert!(waited >= Duration::from_millis(1400), "{waited:?}");
    assert!(waited < Duration::from_millis(2500), "{waited:?}");
}

/// The send re-reads authority after the self-lookup lands, and goes raw
/// to the machine it proved.
#[tokio::test]
async fn the_send_goes_raw_once_the_self_lookup_lands() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let device = (AgentId([0xe1; 32]), MachineId([0xe2; 32]));
    let runtime = Arc::clone(friend.peer_evidence());
    let bindings = Arc::clone(&friend.authenticated_machine_bindings);
    let direct = Arc::clone(&friend.direct_messaging);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |agent| {
            let bindings = Arc::clone(&bindings);
            let direct = Arc::clone(&direct);
            let first = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            Box::pin(async move {
                if !first {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                crate::dm_inbox::record_authenticated_machine_binding(
                    &bindings,
                    agent,
                    device.1,
                    crate::Agent::unix_timestamp_secs(),
                )
                .await;
                direct.mark_connected(agent, device.1).await;
            })
        }))
        .is_ok());
    runtime.spawn_lookup(device.0, device.1);
    frame_arrived(&seen).await;
    let started = std::time::Instant::now();
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    assert!(started.elapsed() < Duration::from_millis(1400));
    assert_eq!(
        friend
            .general_raw_standin_deliveries_for_testing()
            .iter()
            .filter(|(to, _, _)| *to == device.0)
            .map(|(_, machine, _)| *machine)
            .collect::<Vec<_>>(),
        vec![device.1]
    );
}

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
    let answer = context(&device).own_answer().unwrap();
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

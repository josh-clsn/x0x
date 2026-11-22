//! T-self-evidence-lookup: real loopback daemons, no gossip joined and no
//! announcement sent. The receiver starts with nothing about the sender.

use super::*;
use crate::{dm::DmSendConfig, Agent};

async fn node(dir: &std::path::Path, name: &str) -> Agent {
    node_with(dir, name, false, false).await
}

/// `user`: an owner key, so the agent holds an owner-signed certificate.
/// `peers`: the bootstrap peer cache is on, in the node's directory.
async fn node_with(dir: &std::path::Path, name: &str, user: bool, peers: bool) -> Agent {
    let path = dir.join(name);
    std::fs::create_dir_all(&path).unwrap();
    let mut builder = Agent::builder()
        .with_identity_dir(&path)
        .with_machine_key(path.join("machine.key"))
        .with_agent_key_path(path.join("agent.key"))
        .with_user_key_path(path.join("user.key"))
        .with_agent_cert_path(path.join("agent.cert"))
        .with_contact_store_path(path.join("contacts.json"))
        .with_network_config(crate::network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..Default::default()
        });
    if user {
        builder = builder.with_user_key(crate::identity::UserKeypair::generate().unwrap());
    }
    builder = if peers {
        builder.with_peer_cache_dir(path.join("peers"))
    } else {
        builder.with_peer_cache_disabled()
    };
    let agent = builder.build().await.unwrap();
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

/// Every file under `dir` with its length and modification time, except
/// the bootstrap peer cache, which the transport connection itself updates
/// and saves on its own schedule. The peer cache is checked separately
/// (`self_evidence_never_reaches_the_peer_cache`).
fn snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                if entry.file_name() != "peers" {
                    stack.push(entry.path());
                }
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
    // publish_total counts every local publish on every topic, identity
    // and caps included; both daemons have a live gossip runtime.
    assert!(before.0.is_some() && before.1.is_some());

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
    let friend = node_with(dir.path(), "friend", false, true).await;
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

/// A minted answer as the requester decodes it.
fn decoded(answer: &lookup::Found) -> EvidenceRecordV1 {
    decode::found(&codec().serialize(answer).unwrap()).unwrap()
}

/// C-1: a stranger's answer carries the user id and the owner certificate
/// only when the heartbeat would. A relationship answer is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_self_answer_discloses_only_what_the_heartbeat_would() {
    let dir = tempfile::tempdir().unwrap();
    let device = node_with(dir.path(), "device", true, false).await;
    assert!(device.identity.agent_certificate().is_some());
    let responder = context(&device);
    let anonymous = crate::announce_v3::anonymous_cert_digest();
    let public = decoded(&responder.own_answer(true).unwrap());
    assert!(public.certificate.is_none());
    assert_eq!(
        crate::announce_v3::deserialize_v3(&public.announcement)
            .unwrap()
            .cert_digest,
        anonymous
    );
    let related = decoded(&responder.own_answer(false).unwrap());
    assert!(
        related.certificate.is_some(),
        "relationship answers keep it"
    );
    device
        .user_identity_consented
        .store(true, std::sync::atomic::Ordering::Release);
    let consented = decoded(&responder.own_answer(true).unwrap());
    assert!(consented.certificate.is_some());
    assert_ne!(
        crate::announce_v3::deserialize_v3(&consented.announcement)
            .unwrap()
            .cert_digest,
        anonymous
    );
}

/// C-1 end to end: an unconsented device's answer names no owner at the
/// receiver, which still accepts it and replies raw. L-8: no verified
/// certificate event fires for self-evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unconsented_device_is_answered_without_its_owner() {
    for consented in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let device = node_with(dir.path(), "device", true, false).await;
        device
            .user_identity_consented
            .store(consented, std::sync::atomic::Ordering::Release);
        let friend = node(dir.path(), "friend").await;
        knows(&device, &friend).await;
        let mut certificates = friend.subscribe_verified_certificates();
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
        let entry = friend
            .identity_discovery_cache
            .read()
            .await
            .get(&device.agent_id())
            .cloned()
            .unwrap();
        assert_eq!(entry.agent_certificate.is_some(), consented);
        assert_eq!(entry.user_id.is_some(), consented);
        assert!(
            certificates.try_recv().is_err(),
            "self-evidence fires no certificate event"
        );
    }
}

/// The record a former machine of `device`'s agent can still present: a
/// fresh announcement signed by that machine and the agent's advert naming
/// it, signed `advert_age` ago.
fn former_machine_record(
    device: &Agent,
    machine: &crate::identity::MachineKeypair,
    advert_age: Duration,
) -> EvidenceRecordV1 {
    let now = dm_capability::now_unix_ms();
    let agent = device.agent_id();
    let machine_id = MachineId::from_public_key(machine.public_key());
    let v2 = crate::IdentityAnnouncement {
        self_name: None,
        agent_id: agent,
        machine_id,
        user_id: None,
        agent_certificate: None,
        machine_public_key: machine.public_key().as_bytes().to_vec(),
        machine_signature: vec![],
        agent_public_key: device
            .identity
            .agent_keypair()
            .public_key()
            .as_bytes()
            .to_vec(),
        addresses: vec![],
        announced_at: now / 1000,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![],
        relay_candidates: vec![],
    };
    let v3 =
        announce_v3::IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0).unwrap();
    let signing = crate::gossip::SigningContext::from_keypair(device.identity.agent_keypair());
    let wire = crate::dm_capability_service::build_signed_advert(
        &signing,
        agent,
        machine_id,
        crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
    )
    .unwrap();
    let mut advert = crate::dm_capability::CapabilityAdvert::decode_evidence(&wire)
        .unwrap()
        .0;
    advert.created_at_unix_ms = now - advert_age.as_millis() as u64;
    advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        device.identity.agent_keypair().secret_key(),
        &advert.signed_bytes().unwrap(),
    )
    .unwrap()
    .as_bytes()
    .to_vec();
    EvidenceRecordV1 {
        announcement: announce_v3::serialize_v3(&v3).unwrap(),
        advert: postcard::to_stdvec(&advert).unwrap(),
        certificate: None,
        relation: 0,
        stored_at_ms: 0,
    }
}

/// I-1: a former machine replaying a 14-minute-old advert cannot move the
/// agent off the machine a newer class A binding names; raw sends still go
/// to the current machine. Where nothing names a machine, the answer fills
/// the gap, ranked by the agent-signed advert time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_former_machine_cannot_displace_the_current_binding() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&friend, &device).await;
    knows(&device, &friend).await;
    let former = crate::identity::MachineKeypair::generate().unwrap();
    let former_id = MachineId::from_public_key(former.public_key());
    let record = former_machine_record(&device, &former, Duration::from_secs(14 * 60));
    let now = dm_capability::now_unix_ms();
    let store = friend.peer_evidence().store().unwrap();
    let self_lookup::SelfFound::Stranger(view) = self_lookup::verify_self_found(
        &store,
        &Limits::default(),
        device.agent_id(),
        former_id,
        record.clone(),
        now,
    )
    .unwrap() else {
        panic!("a stranger's answer is not stored");
    };
    assert!(
        !context(&friend)
            .accept_self_evidence(&view, former_id)
            .await
    );
    assert_eq!(
        friend.authority_machine(&device.agent_id()).await,
        Some(device.machine_id())
    );
    let mut device_rx = device.subscribe_direct();
    friend
        .send_direct_with_config(&device.agent_id(), b"still here".to_vec(), raw())
        .await
        .unwrap();
    assert_eq!(receive(&mut device_rx).await.payload, b"still here");

    let fresh = node(dir.path(), "fresh").await;
    assert!(context(&fresh).accept_self_evidence(&view, former_id).await);
    let binding = fresh
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&device.agent_id())
        .unwrap();
    assert_eq!(binding.machine_id, former_id);
    assert_eq!(binding.announced_at, view.advert.created_at_unix_ms / 1000);
}

/// M-3: the latch itself, not a hand-set flag, closes the public rule;
/// a machine our agent wrote to is still answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mesh_latch_closes_the_public_rule() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let responder = context(&device);
    let asker = MachineId([0x61; 32]);
    assert_eq!(
        responder.grant(asker, device.agent_id()).await,
        Some(lookup::Grant::SelfEvidence)
    );
    device.quiesce_mesh().await.unwrap();
    assert!(device.mesh_quiesced());
    assert_eq!(responder.grant(asker, device.agent_id()).await, None);
    device.peer_evidence().self_lookup.note_sent(asker);
    assert_eq!(
        responder.grant(asker, device.agent_id()).await,
        Some(lookup::Grant::SelfEvidence)
    );
}

/// M-4: a revoked agent is refused at acceptance even after verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_agent_is_refused_at_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    let record = decoded(&context(&device).own_answer(true).unwrap());
    let store = friend.peer_evidence().store().unwrap();
    let self_lookup::SelfFound::Stranger(view) = self_lookup::verify_self_found(
        &store,
        &Limits::default(),
        device.agent_id(),
        device.machine_id(),
        record,
        dm_capability::now_unix_ms(),
    )
    .unwrap() else {
        panic!("a stranger's answer is not stored");
    };
    friend
        .revocation_set
        .write()
        .await
        .revoke_agent_for_testing(device.agent_id());
    assert!(
        !context(&friend)
            .accept_self_evidence(&view, device.machine_id())
            .await
    );
    assert!(friend
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&device.agent_id())
        .is_none());
}

/// I-2: the admission window closes again. A discovered Unknown machine is
/// admitted for EvidenceV1 only while our agent wrote to it in the last
/// 15 min.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_admission_for_a_written_to_machine_expires() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    let admitted = || async {
        Agent::gate_peer_machine_inbound_for_evidence(
            &device.identity_discovery_cache,
            &device.contact_store,
            &device.revocation_set,
            &device.move_state,
            &device.connect_policy,
            &device.owner_trust,
            &friend.machine_id(),
            None,
            true,
        )
        .await
        .is_ok()
    };
    assert!(!admitted().await, "a discovered Unknown machine is refused");
    let runtime = device.peer_evidence();
    runtime.self_lookup.note_sent(friend.machine_id());
    assert!(admitted().await, "written to within the window");
    runtime
        .self_lookup
        .backdate_sends(Duration::from_millis(crate::peer_evidence::W_MS));
    assert!(!admitted().await, "the window has closed");
}

/// M-1, M-2(c): one claimant machine claiming many agent ids costs one
/// self-only Lookup per interval, and claims that never left this node do
/// not cool their targets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_claimant_flooding_agent_ids_costs_one_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    device.connect_to_agent(&friend.agent_id()).await.unwrap();
    let runtime = Arc::clone(friend.peer_evidence());
    for i in 0..100u8 {
        runtime
            .lookup_from_frame(AgentId([i; 32]), device.machine_id())
            .await;
    }
    assert_eq!(counter(&friend, "evidence_self_lookup_sent"), 1);
    let cooling = (0..100u8)
        .filter(|i| {
            runtime
                .wire_limits
                .target_cooling(AgentId([*i; 32]), Some(device.machine_id()))
        })
        .count();
    assert_eq!(
        cooling, 1,
        "only the claim that sent a request cools its target"
    );
}

/// A responder hook whose `nth` call (1-based) runs `then`; every other
/// call returns at once, as an agent-only Lookup with no route does.
fn hook_on_call<F>(
    runtime: &crate::peer_evidence::EvidenceRuntime,
    nth: usize,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    then: F,
) where
    F: Fn(AgentId) -> futures::future::BoxFuture<'static, ()> + Send + Sync + 'static,
{
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |agent| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if call == nth {
                then(agent)
            } else {
                Box::pin(async {})
            }
        }))
        .is_ok());
}

/// L-2: with a hint but no Lookup in flight and no cooldown, the send
/// starts the self-lookup itself and goes raw once it lands.
#[tokio::test]
async fn the_send_starts_the_self_lookup_when_none_is_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let device = (AgentId([0xf1; 32]), MachineId([0xf2; 32]));
    let runtime = Arc::clone(friend.peer_evidence());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bindings = Arc::clone(&friend.authenticated_machine_bindings);
    let direct = Arc::clone(&friend.direct_messaging);
    // Call 1 is the connector's agent-only Lookup; call 2 is the send's.
    hook_on_call(&runtime, 2, Arc::clone(&calls), move |agent| {
        let bindings = Arc::clone(&bindings);
        let direct = Arc::clone(&direct);
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            crate::dm_inbox::record_authenticated_machine_binding(
                &bindings,
                agent,
                device.1,
                crate::Agent::unix_timestamp_secs(),
            )
            .await;
            direct.mark_connected(agent, device.1).await;
        })
    });
    runtime.lookup_hints.record(device.0, device.1);
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// L-2: a Lookup for the recipient within its cooldown and none in flight:
/// the send does not wait and starts nothing.
#[tokio::test]
async fn the_send_does_not_wait_while_the_target_cools() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let device = (AgentId([0xf3; 32]), MachineId([0xf4; 32]));
    let runtime = Arc::clone(friend.peer_evidence());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    hook_on_call(&runtime, 2, Arc::clone(&calls), |_| {
        Box::pin(futures::future::pending())
    });
    runtime.lookup_hints.record(device.0, device.1);
    assert!(runtime
        .wire_limits
        .claim_target_for_test(device.0, Some(device.1)));
    let started = std::time::Instant::now();
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(
        matches!(sent, Err(crate::error::NetworkError::AgentNotFound(_))),
        "{sent:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// L-3: when the self-only answer comes from a relationship peer it lands
/// in the evidence store, and the waiting send reads it there.
#[tokio::test]
async fn the_send_reads_evidence_stored_by_the_self_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let peer = crate::identity::Identity::new(
        crate::identity::MachineKeypair::generate().unwrap(),
        crate::identity::AgentKeypair::generate().unwrap(),
    );
    let device = (peer.agent_id(), peer.machine_id());
    friend
        .start_peer_evidence(
            dir.path().join("evidence"),
            Default::default(),
            Arc::new(move |agent| Some(agent == device.0)),
        )
        .unwrap();
    let runtime = Arc::clone(friend.peer_evidence());
    assert!(runtime.wait(0).await);
    let template = crate::IdentityAnnouncement {
        self_name: None,
        agent_id: device.0,
        machine_id: device.1,
        user_id: None,
        agent_certificate: None,
        machine_public_key: peer.machine_keypair().public_key().as_bytes().to_vec(),
        machine_signature: vec![],
        agent_public_key: peer.agent_keypair().public_key().as_bytes().to_vec(),
        addresses: vec![],
        announced_at: dm_capability::now_unix_ms() / 1000,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![],
        relay_candidates: vec![],
    };
    let record = mint_hello(
        &peer,
        template,
        &crate::announce_blob::shared_cert_pair(None, None),
        crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
        None,
        true,
    )
    .unwrap()
    .into_record();
    let store = runtime.store().unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    hook_on_call(&runtime, 2, Arc::clone(&calls), move |_| {
        let store = Arc::clone(&store);
        let record = record.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            store
                .ingest(record, IngestSource::Gossip, dm_capability::now_unix_ms())
                .unwrap();
        })
    });
    runtime.lookup_hints.record(device.0, device.1);
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
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

/// `from` dials `to` by address only: no discovery entry, so `from` stays
/// an undiscovered machine at `to`.
async fn dial(from: &Agent, to: &Agent) {
    let mut addr = to.network().unwrap().bound_addr().await.unwrap();
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    from.network().unwrap().connect_addr(addr).await.unwrap();
    let seen = ant_quic::PeerId(from.machine_id().0);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !to
            .network()
            .unwrap()
            .connected_peers()
            .await
            .contains(&seen)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the dialled side sees the connection");
}

async fn bound_to(agent: &Agent, target: AgentId, machine: MachineId) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while agent
            .authenticated_machine_bindings
            .read()
            .await
            .peek(&target)
            .map(|binding| binding.machine_id)
            != Some(machine)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the self-evidence lands");
}

/// R1-L1: accepting a stranger's self-evidence puts nothing in the
/// bootstrap peer cache, in memory or after a save. The receiver is not
/// connected to that machine, so only the self-evidence path could add it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_evidence_never_reaches_the_peer_cache() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let fresh = node_with(dir.path(), "fresh", false, true).await;
    let cache = Arc::clone(fresh.bootstrap_cache.as_ref().unwrap());
    let before = cache.peer_count().await;
    let record = decoded(&context(&device).own_answer(true).unwrap());
    let store = fresh.peer_evidence().store().unwrap();
    let self_lookup::SelfFound::Stranger(view) = self_lookup::verify_self_found(
        &store,
        &Limits::default(),
        device.agent_id(),
        device.machine_id(),
        record,
        dm_capability::now_unix_ms(),
    )
    .unwrap() else {
        panic!("a stranger's answer is not stored");
    };
    assert!(
        context(&fresh)
            .accept_self_evidence(&view, device.machine_id())
            .await
    );
    let peer = ant_quic::PeerId(device.machine_id().0);
    assert!(cache.get_peer(&peer).await.is_none());
    assert_eq!(cache.peer_count().await, before);
    cache.save().await.unwrap();
    assert!(cache.get_peer(&peer).await.is_none());
}

/// R1-L3(a): three Sybil claimants of the device's agent whose Lookups
/// went out first do not cool the device's own route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sybil_claimants_cannot_cool_the_devices_route() {
    let dir = tempfile::tempdir().unwrap();
    let friend = node(dir.path(), "friend").await;
    let device = node(dir.path(), "device").await;
    dial(&device, &friend).await;
    let runtime = Arc::clone(friend.peer_evidence());
    let mut sybils = Vec::new();
    for i in 0..3 {
        let sybil = node(dir.path(), &format!("sybil-{i}")).await;
        dial(&sybil, &friend).await;
        runtime
            .lookup_from_frame(device.agent_id(), sybil.machine_id())
            .await;
        sybils.push(sybil);
    }
    assert!(counter(&friend, "evidence_self_lookup_sent") >= 1);
    runtime
        .lookup_from_frame(device.agent_id(), device.machine_id())
        .await;
    bound_to(&friend, device.agent_id(), device.machine_id()).await;
}

/// R1-L3(b): four strangers holding the whole stranger allocation pool do
/// not block the self-only pull to the frame's own machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stranger_pool_holders_cannot_block_the_frames_pull() {
    let dir = tempfile::tempdir().unwrap();
    let friend = node(dir.path(), "friend").await;
    let device = node(dir.path(), "device").await;
    dial(&device, &friend).await;
    let limits = Arc::clone(&friend.peer_evidence().wire_limits);
    let held: Vec<_> = (0..4u8)
        .map(|i| limits.admit(MachineId([0x90 + i; 32]), false).unwrap())
        .collect();
    assert!(limits.admit(MachineId([0x9f; 32]), false).is_none());
    friend
        .peer_evidence()
        .lookup_from_frame(device.agent_id(), device.machine_id())
        .await;
    bound_to(&friend, device.agent_id(), device.machine_id()).await;
    drop(held);
}

/// R1-L3(c): sixteen machines flooding claims cannot flush the device's
/// hint, so a send still finds it, starts the self-lookup and goes raw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hint_flushers_cannot_hide_the_devices_machine() {
    let dir = tempfile::tempdir().unwrap();
    let friend = node(dir.path(), "friend").await;
    let device = node(dir.path(), "device").await;
    dial(&device, &friend).await;
    let hints = &friend.peer_evidence().lookup_hints;
    hints.record(device.agent_id(), device.machine_id());
    for flusher in 0..16u8 {
        for claim in 0..8u8 {
            hints.record(AgentId([claim; 32]), MachineId([0xa0 + flusher; 32]));
        }
    }
    let mut device_rx = device.subscribe_direct();
    let sent = friend
        .send_direct_with_config(&device.agent_id(), b"found you".to_vec(), raw())
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    assert_eq!(receive(&mut device_rx).await.payload, b"found you");
}

/// R1-L4: a relationship that ends while its full answer is being minted
/// never lets that answer leave, though the node is public.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relationship_ending_mid_sign_never_sends_the_full_answer() {
    let dir = tempfile::tempdir().unwrap();
    let responder = node_with(dir.path(), "responder", true, false).await;
    let requester = node(dir.path(), "requester").await;
    dial(&requester, &responder).await;
    crate::dm_inbox::record_authenticated_machine_binding(
        &responder.authenticated_machine_bindings,
        requester.agent_id(),
        requester.machine_id(),
        crate::Agent::unix_timestamp_secs(),
    )
    .await;
    let related = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let pair = [responder.agent_id(), requester.agent_id()];
    let flag = Arc::clone(&related);
    responder
        .peer_evidence()
        .set_group_context(Arc::new(move |a, b| {
            Some(
                flag.load(std::sync::atomic::Ordering::SeqCst)
                    && pair.contains(&a)
                    && pair.contains(&b),
            )
        }));
    let ask = || {
        let network = Arc::clone(requester.network().unwrap());
        let limits = Arc::clone(&requester.peer_evidence().wire_limits);
        let (machine, target) = (responder.machine_id(), responder.agent_id());
        async move {
            let (mut send, mut recv) = network.open_bi(&ant_quic::PeerId(machine.0)).await.unwrap();
            send.write_u8(StreamProtocol::EvidenceV1.as_u8())
                .await
                .unwrap();
            let body = codec().serialize(&target).unwrap();
            write_message(&mut send, &limits, machine, LOOKUP, &body)
                .await
                .unwrap();
            read_message(&mut recv, &limits).await.unwrap()
        }
    };
    let (kind, body) = ask().await;
    assert_eq!(kind, FOUND, "control: the relationship gets its answer");
    assert!(decode::found(&body).unwrap().certificate.is_some());

    // The responder takes one Lookup per machine per 2 s.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (reached_tx, reached) = std::sync::mpsc::channel();
    let (resume, resume_rx) = std::sync::mpsc::channel();
    *responder
        .peer_evidence()
        .self_lookup
        .mint_pause
        .lock()
        .unwrap() = Some((reached_tx, resume_rx));
    let pending = tokio::spawn(ask());
    tokio::task::spawn_blocking(move || reached.recv().unwrap())
        .await
        .unwrap();
    related.store(false, std::sync::atomic::Ordering::SeqCst);
    resume.send(()).unwrap();
    let (kind, _) = pending.await.unwrap();
    assert_eq!(kind, NOT_FOUND, "the full answer must not leave");
}

/// R1-L5: the share-grant gate's Lookup (`EvidenceRuntime::lookup`) keeps
/// its routing hint but never asks the connecting machine for its own
/// evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_share_grant_lookup_never_takes_the_self_only_route() {
    let dir = tempfile::tempdir().unwrap();
    let friend = node(dir.path(), "friend").await;
    let device = node(dir.path(), "device").await;
    dial(&device, &friend).await;
    let runtime = friend.peer_evidence();
    runtime
        .lookup(device.agent_id(), Some(device.machine_id()))
        .await;
    assert_eq!(counter(&friend, "evidence_self_lookup_sent"), 0);
    assert_eq!(
        runtime.lookup_hints.machines(device.agent_id()),
        vec![device.machine_id()]
    );
    assert!(friend
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&device.agent_id())
        .is_none());
}

/// R1-L5: a binding only self-evidence wrote does not satisfy share-grant
/// access; the same pairing from a network announcement does.
#[tokio::test]
async fn a_self_evidence_binding_does_not_satisfy_share_grant_access() {
    use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
    let local = AgentId([0x31; 32]);
    let peer = (AgentId([0x32; 32]), MachineId([0x33; 32]));
    let owner = crate::identity::UserKeypair::generate().unwrap();
    let now = crate::Agent::unix_timestamp_secs();
    let grants = ShareGrantStore::in_memory(local, Some(owner.user_id()));
    grants
        .accept(
            ShareGrant::sign(
                &owner,
                [0x34; 32],
                Grantee::Agent(peer.0),
                vec![local],
                vec![ShareCap::Dm],
                now - 1,
                now + 60,
            )
            .unwrap(),
            now,
        )
        .await
        .unwrap();
    let bindings = Arc::new(tokio::sync::RwLock::new(
        crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
    ));
    let discovery = tokio::sync::RwLock::new(HashMap::new());
    let revoked = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
    let access = || {
        crate::share_grant::evaluate_grant_access_with_evidence(
            &grants, &bindings, &discovery, &revoked, &peer.0, &peer.1, now, None,
        )
    };
    crate::dm_inbox::record_self_evidence_machine_binding(&bindings, peer.0, peer.1, now, None)
        .await;
    assert!(access().await.is_empty(), "self-evidence grants nothing");
    crate::dm_inbox::record_authenticated_machine_binding(&bindings, peer.0, peer.1, now).await;
    assert!(access().await.dm, "a network announcement still does");
    crate::dm_inbox::record_self_evidence_machine_binding(&bindings, peer.0, peer.1, now + 1, None)
        .await;
    assert!(
        access().await.dm,
        "a later self-evidence refresh does not undo the announcement"
    );
}

/// R1-L2: a binding that lands during the send's wait (a heartbeat naming
/// the current machine) wins over the stored evidence for an older machine.
#[tokio::test]
async fn a_binding_landing_during_the_wait_beats_stored_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let peer = crate::identity::Identity::new(
        crate::identity::MachineKeypair::generate().unwrap(),
        crate::identity::AgentKeypair::generate().unwrap(),
    );
    let agent = peer.agent_id();
    let (old_machine, new_machine) = (peer.machine_id(), MachineId([0xc1; 32]));
    friend
        .start_peer_evidence(
            dir.path().join("evidence"),
            Default::default(),
            Arc::new(move |a| Some(a == agent)),
        )
        .unwrap();
    let runtime = Arc::clone(friend.peer_evidence());
    assert!(runtime.wait(0).await);
    let template = crate::IdentityAnnouncement {
        self_name: None,
        agent_id: agent,
        machine_id: old_machine,
        user_id: None,
        agent_certificate: None,
        machine_public_key: peer.machine_keypair().public_key().as_bytes().to_vec(),
        machine_signature: vec![],
        agent_public_key: peer.agent_keypair().public_key().as_bytes().to_vec(),
        addresses: vec![],
        announced_at: dm_capability::now_unix_ms() / 1000,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![],
        relay_candidates: vec![],
    };
    let record = mint_hello(
        &peer,
        template,
        &crate::announce_blob::shared_cert_pair(None, None),
        crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
        None,
        true,
    )
    .unwrap()
    .into_record();
    let store = runtime.store().unwrap();
    let discovery = Arc::clone(&friend.identity_discovery_cache);
    let announced = Arc::clone(&friend.announced_machine_bindings);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    hook_on_call(&runtime, 2, Arc::clone(&calls), move |_| {
        let (store, record) = (Arc::clone(&store), record.clone());
        let (discovery, announced) = (Arc::clone(&discovery), Arc::clone(&announced));
        Box::pin(async move {
            let now = crate::Agent::unix_timestamp_secs();
            store
                .ingest(record, IngestSource::Gossip, dm_capability::now_unix_ms())
                .unwrap();
            announced
                .write()
                .await
                .record_announcement(agent, new_machine, now, None, None);
            let mut entry = crate::discovered_agent_fixture(1, now, &[], None);
            entry.agent_id = agent;
            entry.machine_id = new_machine;
            discovery.write().await.insert(agent, entry);
        })
    });
    runtime.lookup_hints.record(agent, old_machine);
    let sent = friend
        .send_direct_raw_quic(&agent, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    assert_eq!(
        friend
            .general_raw_standin_deliveries_for_testing()
            .iter()
            .filter(|(to, _, _)| *to == agent)
            .map(|(_, machine, _)| *machine)
            .collect::<Vec<_>>(),
        vec![new_machine]
    );
}

/// R2-L-2: a relationship-only Lookup in flight (the share-grant gate's,
/// or an agent-only one) does not stop the send from starting the
/// self-only Lookup.
#[tokio::test]
async fn a_relationship_lookup_in_flight_does_not_mask_the_send() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let device = (AgentId([0xd5; 32]), MachineId([0xd6; 32]));
    let runtime = Arc::clone(friend.peer_evidence());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let bindings = Arc::clone(&friend.authenticated_machine_bindings);
    let direct = Arc::clone(&friend.direct_messaging);
    // Call 1: the held relationship-only Lookup. Call 2: the connector's
    // agent-only Lookup. Call 3: the send's self-only Lookup.
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |agent| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let (bindings, direct) = (Arc::clone(&bindings), Arc::clone(&direct));
            Box::pin(async move {
                match call {
                    1 => futures::future::pending::<()>().await,
                    3 => {
                        crate::dm_inbox::record_authenticated_machine_binding(
                            &bindings,
                            agent,
                            device.1,
                            crate::Agent::unix_timestamp_secs(),
                        )
                        .await;
                        direct.mark_connected(agent, device.1).await;
                    }
                    _ => {}
                }
            })
        }))
        .is_ok());
    let held = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.lookup(device.0, Some(device.1)).await })
    };
    frame_arrived(&seen).await;
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    held.abort();
}

/// Bindings and a share grant for `peer` held by `local`, for the
/// share-grant access tests.
async fn granted(local: AgentId, peer: AgentId, now: u64) -> crate::share_grant::ShareGrantStore {
    use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
    let owner = crate::identity::UserKeypair::generate().unwrap();
    let grants = ShareGrantStore::in_memory(local, Some(owner.user_id()));
    grants
        .accept(
            ShareGrant::sign(
                &owner,
                [0x35; 32],
                Grantee::Agent(peer),
                vec![local],
                vec![ShareCap::Dm],
                now - 1,
                now + 60,
            )
            .unwrap(),
            now,
        )
        .await
        .unwrap();
    grants
}

/// R2-L-3: an older card pin, or an older attested write, naming the same
/// machine clears the self-evidence mark, so share-grant access is what
/// it was before the lane.
#[tokio::test]
async fn an_older_pin_or_attestation_clears_the_self_evidence_mark() {
    let local = AgentId([0x41; 32]);
    let peer = (AgentId([0x42; 32]), MachineId([0x43; 32]));
    let now = crate::Agent::unix_timestamp_secs();
    let grants = granted(local, peer.0, now).await;
    let discovery = tokio::sync::RwLock::new(HashMap::new());
    let revoked = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
    for pin in [true, false] {
        let bindings = Arc::new(tokio::sync::RwLock::new(
            crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
        ));
        // The device's advert time can run ahead of our clock.
        crate::dm_inbox::record_self_evidence_machine_binding(
            &bindings,
            peer.0,
            peer.1,
            now + 100,
            None,
        )
        .await;
        if pin {
            crate::dm_inbox::record_local_pin_binding(&bindings, peer.0, peer.1, now).await;
        } else {
            crate::dm_inbox::record_authenticated_machine_binding(&bindings, peer.0, peer.1, now)
                .await;
        }
        let access = crate::share_grant::evaluate_grant_access_with_evidence(
            &grants, &bindings, &discovery, &revoked, &peer.0, &peer.1, now, None,
        )
        .await;
        assert!(access.dm, "pin: {pin}");
    }
}

/// R2-L-4: with two connected claimants, the send starts its self-only
/// Lookup with the newest one whose own route is not cooling.
#[tokio::test]
async fn the_send_asks_the_newest_claimant_that_is_not_cooling() {
    let dir = tempfile::tempdir().unwrap();
    let friend = offline(dir.path()).await;
    let device = (AgentId([0xd7; 32]), MachineId([0xd8; 32]));
    let sybil = MachineId([0xd9; 32]);
    let runtime = Arc::clone(friend.peer_evidence());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bindings = Arc::clone(&friend.authenticated_machine_bindings);
    let direct = Arc::clone(&friend.direct_messaging);
    hook_on_call(&runtime, 2, Arc::clone(&calls), move |agent| {
        let (bindings, direct) = (Arc::clone(&bindings), Arc::clone(&direct));
        Box::pin(async move {
            crate::dm_inbox::record_authenticated_machine_binding(
                &bindings,
                agent,
                device.1,
                crate::Agent::unix_timestamp_secs(),
            )
            .await;
            direct.mark_connected(agent, device.1).await;
        })
    });
    runtime.lookup_hints.record(device.0, device.1);
    runtime.lookup_hints.record(device.0, sybil);
    assert!(runtime
        .wire_limits
        .claim_target_for_test(device.0, Some(sybil)));
    let sent = friend
        .send_direct_raw_quic(&device.0, b"reply", None, Duration::ZERO, None)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    assert_eq!(
        *runtime.self_lookup.transports.lock().unwrap(),
        vec![(device.0, device.1)]
    );
}

/// The drill shape: the device holds the friend as a Known contact
/// (AcceptWithFlag), as a linked desktop holds its user's DM partners.
/// The friend's self-only Lookup is admitted and the reply goes raw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_daemon_answers_a_device_that_holds_it_as_a_known_contact() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    device
        .contact_store
        .write()
        .await
        .set_trust(&friend.agent_id(), crate::contacts::TrustLevel::Known);

    let mut friend_rx = friend.subscribe_direct();
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .expect("the device writes raw");
    assert!(!receive(&mut friend_rx).await.verified);

    let mut device_rx = device.subscribe_direct();
    let started = std::time::Instant::now();
    let reply = friend
        .send_direct_with_config(&device.agent_id(), b"reply".to_vec(), raw())
        .await;
    let waited = started.elapsed();
    assert!(reply.is_ok(), "the reply goes raw: {reply:?}");
    assert!(waited < Duration::from_secs(2), "took {waited:?}");
    assert_eq!(receive(&mut device_rx).await.payload, b"reply");
    assert_eq!(counter(&friend, "evidence_self_lookup_sent"), 1);
    assert_eq!(counter(&friend, "evidence_self_lookup_accepted"), 1);
    assert_eq!(counter(&device, "evidence_self_lookup_served"), 1);
}

/// The requester holds the device as a Trusted contact (Accept). Its own
/// contact trust neither replaces nor skips the self-only Lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requester_that_trusts_the_device_still_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    friend
        .contact_store
        .write()
        .await
        .set_trust(&device.agent_id(), crate::contacts::TrustLevel::Trusted);

    let mut friend_rx = friend.subscribe_direct();
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .expect("the device writes raw");
    assert!(!receive(&mut friend_rx).await.verified);

    let mut device_rx = device.subscribe_direct();
    let started = std::time::Instant::now();
    let reply = friend
        .send_direct_with_config(&device.agent_id(), b"reply".to_vec(), raw())
        .await;
    let waited = started.elapsed();
    assert!(reply.is_ok(), "the reply goes raw: {reply:?}");
    assert!(waited < Duration::from_secs(2), "took {waited:?}");
    assert_eq!(receive(&mut device_rx).await.payload, b"reply");
    assert_eq!(counter(&friend, "evidence_self_lookup_accepted"), 1);
}

async fn evidence_admitted(device: &Agent, friend: &Agent) -> bool {
    Agent::gate_peer_machine_inbound_for_evidence(
        &device.identity_discovery_cache,
        &device.contact_store,
        &device.revocation_set,
        &device.move_state,
        &device.connect_policy,
        &device.owner_trust,
        &friend.machine_id(),
        None,
        true,
    )
    .await
    .is_ok()
}

/// I-2 for a Known contact (AcceptWithFlag): admitted for EvidenceV1 while
/// our agent wrote to its machine within the window, as a stranger is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_admission_for_a_written_to_known_contact() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    device
        .contact_store
        .write()
        .await
        .set_trust(&friend.agent_id(), crate::contacts::TrustLevel::Known);
    assert!(
        !evidence_admitted(&device, &friend).await,
        "a Known contact not written to is refused"
    );
    let runtime = device.peer_evidence();
    runtime.self_lookup.note_sent(friend.machine_id());
    assert!(
        evidence_admitted(&device, &friend).await,
        "a Known contact written to within the window is admitted"
    );
    runtime
        .self_lookup
        .backdate_sends(Duration::from_millis(crate::peer_evidence::W_MS));
    assert!(
        !evidence_admitted(&device, &friend).await,
        "the window has closed"
    );
}

/// Controls: with the machine written to, a Blocked contact and a Known
/// contact pinned to another machine are still refused. A Trusted contact
/// passes the ordinary gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_admission_still_refuses_blocked_and_pin_mismatch() {
    use crate::contacts::{MachineRecord, TrustLevel};
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    device
        .peer_evidence()
        .self_lookup
        .note_sent(friend.machine_id());
    let contacts = &device.contact_store;
    let other = crate::identity::MachineKeypair::generate()
        .unwrap()
        .machine_id();
    {
        let mut store = contacts.write().await;
        store.set_trust(&friend.agent_id(), TrustLevel::Known);
        store.add_machine(&friend.agent_id(), MachineRecord::new(other, None));
        assert!(store.pin_machine(&friend.agent_id(), &other));
    }
    assert!(
        !evidence_admitted(&device, &friend).await,
        "a Known contact pinned to another machine is refused"
    );
    assert!(contacts
        .write()
        .await
        .unpin_machine(&friend.agent_id(), &other));
    contacts
        .write()
        .await
        .set_trust(&friend.agent_id(), TrustLevel::Blocked);
    assert!(
        !evidence_admitted(&device, &friend).await,
        "a Blocked contact is refused"
    );
    contacts
        .write()
        .await
        .set_trust(&friend.agent_id(), TrustLevel::Trusted);
    assert!(
        evidence_admitted(&device, &friend).await,
        "a Trusted contact is admitted"
    );
}

/// A refused self-only Lookup is refused at the responder's admission: the
/// requester wrote its request, the responder's gate refuses the machine it
/// wrote to, and no byte of the request reaches the responder's acceptor.
/// Checked by the gate and by counters, not by captured log lines, which a
/// thread-local subscriber can miss in a parallel run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_self_lookup_stops_at_the_responders_admission() {
    let dir = tempfile::tempdir().unwrap();
    let device = node(dir.path(), "device").await;
    let friend = node(dir.path(), "friend").await;
    knows(&device, &friend).await;
    device
        .contact_store
        .write()
        .await
        .set_trust(&friend.agent_id(), crate::contacts::TrustLevel::Blocked);
    let mut friend_rx = friend.subscribe_direct();
    device
        .send_direct_with_config(&friend.agent_id(), b"hello".to_vec(), raw())
        .await
        .expect("the device writes raw");
    receive(&mut friend_rx).await;
    let reply = friend
        .send_direct_with_config(&device.agent_id(), b"reply".to_vec(), raw())
        .await;
    assert!(reply.is_err(), "{reply:?}");
    assert_eq!(counter(&friend, "evidence_self_lookup_sent"), 1);
    assert!(
        !evidence_admitted(&device, &friend).await,
        "the written-to Blocked machine is refused at admission"
    );
    for name in [
        "evidence_bytes_in",
        "evidence_lookup_refused",
        "evidence_lookup_unauthorized",
        "evidence_self_lookup_refused",
        "evidence_self_lookup_served",
    ] {
        assert_eq!(counter(&device, name), 0, "{name}");
    }
}

/// M4, the field path of NAT-B: the desktop is gone from the phone's
/// discovery cache and known only by peer evidence (a relationship
/// record whose address is now silent), the engine hands back the
/// coordinator it kept, and the latched phone's leased connect reaches the
/// desktop through the punch. The punch lands after the evidence dial's own
/// 3 s slice, so the dial must run on the connect's budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_reaches_a_contact_known_only_by_evidence_through_a_handed_back_introducer() {
    let dir = tempfile::tempdir().unwrap();
    let desktop = node(dir.path(), "desktop").await;
    let public = node(dir.path(), "public").await;
    let mut public_addr = public.network().unwrap().bound_addr().await.unwrap();
    if public_addr.ip().is_unspecified() {
        public_addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    desktop
        .network()
        .unwrap()
        .connect_addr(public_addr)
        .await
        .expect("the desktop links to the public node");

    // The phone keeps a relationship record for the desktop.
    let path = dir.path().join("phone");
    std::fs::create_dir_all(&path).unwrap();
    let phone = Agent::builder()
        .with_identity_dir(&path)
        .with_machine_key(path.join("machine.key"))
        .with_agent_key_path(path.join("agent.key"))
        .with_user_key_path(path.join("user.key"))
        .with_agent_cert_path(path.join("agent.cert"))
        .with_contact_store_path(path.join("contacts.json"))
        .with_network_config(crate::network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..Default::default()
        })
        .with_peer_cache_disabled()
        .build()
        .await
        .unwrap();
    let desktop_id = desktop.agent_id();
    phone
        .start_peer_evidence(
            path.join("evidence"),
            Default::default(),
            Arc::new(move |agent| Some(agent == desktop_id)),
        )
        .unwrap();
    assert!(phone.peer_evidence().wait(0).await);
    phone.set_leaf_mode(true);

    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let now = dm_capability::now_unix_ms();
    let template = crate::IdentityAnnouncement {
        self_name: None,
        agent_id: desktop.agent_id(),
        machine_id: desktop.machine_id(),
        user_id: None,
        agent_certificate: None,
        machine_public_key: desktop
            .identity
            .machine_keypair()
            .public_key()
            .as_bytes()
            .to_vec(),
        machine_signature: vec![],
        agent_public_key: desktop
            .identity
            .agent_keypair()
            .public_key()
            .as_bytes()
            .to_vec(),
        addresses: vec![silent_addr],
        announced_at: now / 1000,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![],
        relay_candidates: vec![],
    };
    let record = mint_hello(
        &desktop.identity,
        template,
        &crate::announce_blob::shared_cert_pair(None, None),
        crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
        None,
        true,
    )
    .unwrap()
    .into_record();
    phone
        .peer_evidence()
        .store()
        .unwrap()
        .ingest(record, IngestSource::Gossip, now)
        .unwrap();
    assert!(phone
        .identity_discovery_cache
        .read()
        .await
        .get(&desktop.agent_id())
        .is_none());
    assert!(phone
        .peer_evidence()
        .usable_agent(desktop.agent_id(), now)
        .is_some());
    phone.quiesce_mesh().await.unwrap();

    let started = std::time::Instant::now();
    let (result, steps) = crate::DIAL_STEPS
        .scope(std::cell::RefCell::new(Vec::new()), async {
            let result = phone
                .connect_to_agent_burst(
                    &desktop.agent_id(),
                    Duration::from_secs(120),
                    None,
                    &[public_addr],
                )
                .await;
            (
                result,
                crate::DIAL_STEPS.with(|steps| steps.borrow().clone()),
            )
        })
        .await;
    let took = started.elapsed();
    let (outcome, leased) = result.unwrap();
    assert!(outcome.is_live_path(), "{outcome:?} after {took:?}");
    assert!(leased, "the lease was recorded");
    assert!(
        steps
            .iter()
            .any(|(step, got)| *step == "evidence" && *got > crate::EVIDENCE_CONNECT_DIAL_TIMEOUT),
        "the evidence dial ran on the budget: {steps:?}"
    );
    assert!(
        took > crate::EVIDENCE_CONNECT_DIAL_TIMEOUT && took < crate::LEASED_DIAL_BUDGET,
        "the punch landed past the evidence slice, inside the budget: {took:?}"
    );
    let snap = phone.network().unwrap().relay_client_snapshot();
    assert_eq!(snap.introducer_dials, 1, "{snap:?}");
    assert_eq!(snap.introducer_punch_successes, 1, "{snap:?}");
    drop(silent);
}

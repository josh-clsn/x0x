#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for the connectivity module.
//!
//! Tests ReachabilityInfo heuristics, ConnectOutcome behaviour, and the
//! `connect_to_agent()` / `reachability()` methods on `Agent`.

use tempfile::TempDir;
use x0x::connectivity::{ConnectOutcome, ReachabilityInfo};
use x0x::{network::NetworkConfig, Agent, DiscoveredAgent};

/// Explicit test-only network config (#417/#337): loopback bind, no
/// seeds, discovery/port-mapping off. Still a real socket constructor.
fn test_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn build_agent(dir: &TempDir) -> Agent {
    Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_user_key_path(dir.path().join("user.key"))
        .with_agent_cert_path(dir.path().join("agent.cert"))
        .with_identity_dir(dir.path())
        .with_contact_store_path(dir.path().join("contacts.json"))
        .with_peer_cache_dir(dir.path().join("peers"))
        .with_network_config(test_network_config())
        .build()
        .await
        .unwrap()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fake_discovered(
    id_byte: u8,
    addresses: Vec<std::net::SocketAddr>,
    nat_type: Option<&str>,
    can_receive_direct: Option<bool>,
    is_relay: Option<bool>,
    is_coordinator: Option<bool>,
) -> DiscoveredAgent {
    let now = now_secs();
    DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id: x0x::identity::AgentId([id_byte; 32]),
        machine_id: x0x::identity::MachineId([id_byte + 100; 32]),
        user_id: None,
        addresses,
        announced_at: now,
        last_seen: now,
        machine_public_key: vec![],
        nat_type: nat_type.map(str::to_string),
        can_receive_direct,
        is_relay,
        is_coordinator,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// ReachabilityInfo unit tests
// ---------------------------------------------------------------------------

#[test]
fn likely_direct_with_can_receive_direct_true() {
    let da = fake_discovered(
        1,
        vec!["127.0.0.1:9000".parse().unwrap()],
        None,
        Some(true),
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(info.likely_direct());
    assert!(!info.needs_coordination());
}

#[test]
fn not_likely_direct_with_can_receive_direct_false() {
    let da = fake_discovered(
        2,
        vec!["127.0.0.1:9000".parse().unwrap()],
        None,
        Some(false),
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.needs_coordination());
}

#[test]
fn likely_direct_for_full_cone_nat_is_false_without_peer_verification() {
    let da = fake_discovered(
        3,
        vec!["127.0.0.1:9000".parse().unwrap()],
        Some("FullCone"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(info.needs_coordination());
}

#[test]
fn not_likely_direct_for_symmetric_nat() {
    let da = fake_discovered(
        4,
        vec!["127.0.0.1:9000".parse().unwrap()],
        Some("Symmetric"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.needs_coordination());
}

#[test]
fn not_likely_direct_without_addresses() {
    let da = fake_discovered(5, vec![], None, Some(true), None, None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct(), "no addresses means no direct path");
}

#[test]
fn unknown_reachability_still_attempts_direct() {
    let da = fake_discovered(
        6,
        vec!["192.168.1.1:9000".parse().unwrap()],
        None,
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(
        info.should_attempt_direct(),
        "unknown peers still get a direct probe"
    );
    assert!(info.needs_coordination());
}

#[test]
fn is_relay_returns_false_when_none() {
    let da = fake_discovered(7, vec![], None, None, None, None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.is_relay());
}

#[test]
fn is_relay_returns_true_when_some_true() {
    let da = fake_discovered(8, vec![], None, None, Some(true), None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(info.is_relay());
}

#[test]
fn is_coordinator_returns_false_when_none() {
    let da = fake_discovered(9, vec![], None, None, None, None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.is_coordinator());
}

#[test]
fn is_coordinator_returns_true_when_some_true() {
    let da = fake_discovered(10, vec![], None, None, None, Some(true));
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(info.is_coordinator());
}

// ---------------------------------------------------------------------------
// ConnectOutcome unit tests
// ---------------------------------------------------------------------------

#[test]
fn connect_outcome_display() {
    let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
    assert_eq!(
        ConnectOutcome::Direct(addr).to_string(),
        format!("direct({addr})")
    );
    assert_eq!(
        ConnectOutcome::Coordinated(addr).to_string(),
        format!("coordinated({addr})")
    );
    assert_eq!(ConnectOutcome::Unreachable.to_string(), "unreachable");
    assert_eq!(ConnectOutcome::NotFound.to_string(), "not_found");
}

#[test]
fn connect_outcome_equality() {
    let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
    assert_eq!(ConnectOutcome::Direct(addr), ConnectOutcome::Direct(addr));
    assert_eq!(ConnectOutcome::Unreachable, ConnectOutcome::Unreachable);
    assert_ne!(ConnectOutcome::Direct(addr), ConnectOutcome::Unreachable);
    assert_ne!(
        ConnectOutcome::Direct(addr),
        ConnectOutcome::Coordinated(addr)
    );
    assert_ne!(ConnectOutcome::NotFound, ConnectOutcome::Unreachable);
}

// ---------------------------------------------------------------------------
// Agent::connect_to_agent() integration tests
// ---------------------------------------------------------------------------

/// Connecting to a non-existent agent returns NotFound.
#[tokio::test]
async fn connect_to_unknown_agent_returns_not_found() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::AgentId([200u8; 32]);
    let outcome = agent.connect_to_agent(&unknown_id).await.unwrap();
    assert_eq!(outcome, ConnectOutcome::NotFound);
}

/// Connecting to a non-existent machine returns NotFound.
#[tokio::test]
async fn connect_to_unknown_machine_returns_not_found() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::MachineId([201u8; 32]);
    let outcome = agent.connect_to_machine(&unknown_id).await.unwrap();
    assert_eq!(outcome, ConnectOutcome::NotFound);
}

/// An agent with no addresses returns Unreachable.
#[tokio::test]
async fn connect_to_agent_with_no_addresses_returns_unreachable() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let da = fake_discovered(100, vec![], None, Some(true), None, None);
    let target_id = da.agent_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let outcome = agent.connect_to_agent(&target_id).await.unwrap();
    assert_eq!(
        outcome,
        ConnectOutcome::Unreachable,
        "no addresses means unreachable"
    );
}

/// Without a network started, connecting returns Unreachable (not an error).
#[tokio::test]
async fn connect_without_network_returns_unreachable() {
    let dir = TempDir::new().unwrap();
    // Build agent WITHOUT a bind address (no network)
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        // No network config = no network started
        .build()
        .await
        .unwrap();

    let da = fake_discovered(
        101,
        vec!["127.0.0.1:9999".parse().unwrap()],
        None,
        Some(true),
        None,
        None,
    );
    let target_id = da.agent_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let outcome = agent.connect_to_agent(&target_id).await.unwrap();
    assert_eq!(
        outcome,
        ConnectOutcome::Unreachable,
        "no network started → Unreachable, not an error"
    );
}

// ---------------------------------------------------------------------------
// Agent::reachability() integration tests
// ---------------------------------------------------------------------------

/// reachability() returns None for an agent not in the cache.
#[tokio::test]
async fn reachability_none_for_unknown_agent() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::AgentId([201u8; 32]);
    assert!(agent.reachability(&unknown_id).await.is_none());
}

/// reachability() returns correct info for an agent in the cache.
#[tokio::test]
async fn reachability_returns_correct_info_from_cache() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let da = fake_discovered(
        102,
        vec!["10.0.0.2:8080".parse().unwrap()],
        Some("FullCone"),
        Some(true),
        Some(false),
        Some(true),
    );
    let target_id = da.agent_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let info = agent.reachability(&target_id).await;
    assert!(info.is_some());
    let info = info.unwrap();

    assert!(info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(!info.needs_coordination());
    assert!(!info.is_relay());
    assert!(info.is_coordinator());
    assert_eq!(info.addresses.len(), 1);
}

/// Inserting an agent discovery record also creates the machine endpoint link.
/// #1088 (g46r2 finding 3): a raw Direct frame whose (agent, machine)
/// binding is named by the AUTHENTICATED BINDINGS REGISTRY — evidence a
/// fresh machine-key attestation recorded — must be DELIVERED `verified`
/// even when the discovery cache is still empty (the post-restart shape;
/// the cache only refills at the peer's next identity announcement,
/// ~600 s). Before the fix the registry arm eased ROUTING only, so every
/// raw frame arrived `verified=false` and the #1070 gates (Welcome, files,
/// join-result, control-blob) dropped it for the whole window.
///
/// This is the frame-level twin of the unverified-claim test above: same
/// harness, opposite arm. The registry binding here is recorded the way
/// the inbox records it (record_authenticated_machine_binding over a
/// verified attestation); no cache entry is inserted.
#[tokio::test]
async fn raw_frame_backed_by_registry_binding_is_delivered_verified() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;
    local.join_network().await.expect("local join network");

    // A is NOT inserted into the discovery cache — the post-restart state.
    let a_id: [u8; 32] = [0x88u8; 32];
    let claimed = a_id;

    // The registry binding: the inbox records (agent -> machine) after a
    // VERIFIED fresh machine-key attestation. Record exactly that pairing
    // for m2's machine.
    let m2_machine_id = m2.machine_id();
    local
        .record_authenticated_binding_for_testing(
            x0x::identity::AgentId(a_id),
            m2_machine_id,
            now_secs(),
        )
        .await;

    let local_addr = local.bound_addr().await.expect("local bound");
    let m2_network = m2.network().expect("m2 network");
    m2_network
        .connect_addr(local_addr)
        .await
        .expect("dial local");
    let local_peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !m2_network.is_connected(&local_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local never became transport-connected to m2"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    m2_network
        .send_direct(&local_peer, &claimed, b"1088 registry-backed frame")
        .await
        .expect("registry-backed raw direct send");

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(msg) = local.recv_direct_annotated().await {
                return msg;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the registry-backed DM must be delivered");
    assert_eq!(delivered.sender.as_bytes(), &a_id);
    assert!(
        delivered.verified,
        "#1088: a raw frame whose binding the registry names for THIS machine is delivered verified"
    );
    assert_eq!(
        local
            .direct_messaging()
            .get_machine_id(&x0x::identity::AgentId(a_id))
            .await,
        Some(m2_machine_id),
        "the routing write re-binds through the same evidence"
    );
    let _ = m2_machine_id;
}

/// #1088 negative control: a registry binding for a DIFFERENT machine must
/// NOT verify the frame (and, per #898, must not rebind either).
#[tokio::test]
async fn raw_frame_from_wrong_machine_stays_unverified_with_registry_binding() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;
    local.join_network().await.expect("local join network");

    let a_id: [u8; 32] = [0x89u8; 32];
    let claimed = a_id;
    let other_machine = x0x::identity::MachineId([0x77u8; 32]);
    local
        .record_authenticated_binding_for_testing(
            x0x::identity::AgentId(a_id),
            other_machine,
            now_secs(),
        )
        .await;

    let local_addr = local.bound_addr().await.expect("local bound");
    let m2_network = m2.network().expect("m2 network");
    m2_network
        .connect_addr(local_addr)
        .await
        .expect("dial local");
    let local_peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !m2_network.is_connected(&local_peer).await {
        assert!(tokio::time::Instant::now() < deadline, "connect deadline");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    m2_network
        .send_direct(&local_peer, &claimed, b"1088 wrong machine")
        .await
        .expect("wrong-machine raw direct send");
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(msg) = local.recv_direct_annotated().await {
                return msg;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("delivered (annotated)");
    assert!(
        !delivered.verified,
        "#898 preserved: a registry binding for a DIFFERENT machine does not verify"
    );
    assert_eq!(
        local
            .direct_messaging()
            .get_machine_id(&x0x::identity::AgentId(a_id))
            .await,
        None,
        "and it never rebinds"
    );
}

/// Send real 0x10 bytes through the #898 loopback listener harness.
async fn send_registry_test_frame(local: &Agent, remote: &Agent, sender: x0x::identity::AgentId) {
    let network = remote.network().expect("remote network");
    network
        .connect_addr(local.bound_addr().await.expect("local bound"))
        .await
        .expect("dial local");
    let peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !network.is_connected(&peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "transport connect deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    network
        .send_direct(&peer, sender.as_bytes(), b"1098 retained binding")
        .await
        .expect("raw frame send");
}

/// #1098: TTL eviction must not erase a retained certificate's expiry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_frame_expired_registry_without_cache_is_dropped_1098() {
    let local_dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let remote = build_agent(&remote_dir).await;
    local.join_network().await.expect("local join network");
    let sender = x0x::identity::AgentId([0x98; 32]);
    let now = now_secs();
    local
        .record_authenticated_binding_with_expiry_for_testing(
            sender,
            remote.machine_id(),
            now - 2000,
            Some(now - 1000),
        )
        .await;
    assert!(
        local.reachability(&sender).await.is_none(),
        "no discovery entry"
    );
    let mut deliveries = local.direct_messaging().subscribe();
    send_registry_test_frame(&local, &remote, sender).await;
    // Wait for observable processing, not merely an absence timeout: the
    // baseline delivers, the fix increments the actual expiry drop counter.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let stats = local.direct_messaging().diagnostics_snapshot().stats;
            if stats.incoming_dropped_expired > 0 || stats.incoming_delivered_to_subscribe > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("frame processed by listener");
    let drops = local
        .direct_messaging()
        .diagnostics_snapshot()
        .stats
        .incoming_dropped_expired;
    let delivery = deliveries.try_recv();
    let route = local.direct_messaging().get_machine_id(&sender).await;
    local.shutdown().await;
    remote.shutdown().await;
    assert_eq!(
        drops, 1,
        "#1098: retained expired certificate must drop the raw frame"
    );
    assert!(
        delivery.is_none(),
        "expired frame must not reach subscribers"
    );
    assert_eq!(
        route, None,
        "expired sender must not establish reverse routing"
    );
}

/// #1098: discovery learned a newer move via rebroadcast; the registry
/// still names the old machine. Its frames stay unverified and never rebind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_frame_moved_agent_old_machine_is_unverified_and_never_rebinds_1098() {
    let local_dir = TempDir::new().unwrap();
    let old_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let old = build_agent(&old_dir).await;
    local.join_network().await.expect("local join network");
    let da = fake_discovered(0x61, vec![], None, Some(true), None, None);
    let sender = da.agent_id;
    let new_machine = da.machine_id;
    local
        .record_authenticated_binding_for_testing(sender, old.machine_id(), da.announced_at - 10)
        .await;
    local.insert_discovered_agent_for_testing(da).await;
    local
        .direct_messaging()
        .mark_raw_direct_sender_connected(sender, new_machine, true)
        .await;
    send_registry_test_frame(&local, &old, sender).await;
    let delivered = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        local.recv_direct_annotated(),
    )
    .await
    .expect("delivery deadline")
    .expect("frame delivered");
    let route = local.direct_messaging().get_machine_id(&sender).await;
    let reverse = local
        .direct_messaging()
        .lookup_agent(&old.machine_id())
        .await;
    local.shutdown().await;
    old.shutdown().await;
    // Check routing first so the red proves the actual rebind defect too.
    assert_eq!(
        route,
        Some(new_machine),
        "#1098: old machine must not rebind the moved agent"
    );
    assert_eq!(
        reverse, None,
        "old machine must not acquire a reverse agent mapping"
    );
    assert_eq!(delivered.sender, sender);
    assert!(
        !delivered.verified,
        "#1098: superseded registry binding must not verify"
    );
}

/// #1091 (the send-first reproduction, CI): a node whose identity
/// resolution state is COLD (the post-restart shape — discovery cache and
/// binding registry empty) must still be able to SEND FIRST to a peer it
/// is transport-connected to, within seconds. The reconnect-triggered
/// self re-announce refills the cold node's cache from the peer's
/// re-announce (the peer sees the (re)connect and re-announces too).
///
/// Cold state is produced with the test seam (clear both structures)
/// followed by a transport reconnect, so the gate fires exactly as it
/// would after a daemon restart. On the reverted tree the send fails with
/// RecipientUndiscovered for the whole announcement cadence.
#[tokio::test]
async fn cold_node_sends_first_after_reconnect_within_seconds() {
    let joined_at = tokio::time::Instant::now();
    let a_dir = TempDir::new().unwrap();
    let b_dir = TempDir::new().unwrap();
    let a = build_agent(&a_dir).await;
    let b = build_agent(&b_dir).await;
    a.join_network().await.expect("a join");
    b.join_network().await.expect("b join");
    a.announce_identity(false, false)
        .await
        .expect("a announces");
    b.announce_identity(false, false)
        .await
        .expect("b announces");

    // The fixture config has no bootstrap and no mDNS — connect the two
    // nodes explicitly (the production equivalent of the bootstrap dial),
    // or b's listener has no transport over which to hear a.
    let a_addr = a.bound_addr().await.expect("a bound");
    let b_network = b.network().expect("b network");
    b_network.connect_addr(a_addr).await.expect("b dials a");
    let a_peer = ant_quic::PeerId(a.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !b_network.is_connected(&a_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "initial dial deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Let b discover a (the warm precondition the fixture relies on).
    // Generous deadline: under CI coverage load the two-node gossip
    // mesh can take tens of seconds — this wait is fixture setup, the
    // #1091 contract is the 10 s send window after the reconnect.
    let a_id = a.agent_id();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if b.discovered_agent_for_testing(&a_id).await.is_some() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "b never discovered a"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Drain the join-time announce sources before going cold, or the test
    // could not discriminate the reconnect trigger: join_network schedules
    // a DELAYED second announce ~3 s after join (fresh message id — it
    // lands even after PlumTree dedupe). Under the D31 stopgap the join
    // storm no longer consumes any gate budget (fresh machines have no
    // absence record and never signal), so only the delayed announce
    // needs draining; after this point the heartbeat cadence (600 s) is
    // the only other announcer and the peer's absence-triggered
    // re-announce is the feature under test.
    let delayed_announce_drained = joined_at + std::time::Duration::from_secs(6);
    if tokio::time::Instant::now() < delayed_announce_drained {
        tokio::time::sleep(delayed_announce_drained - tokio::time::Instant::now()).await;
    }
    // THE COLD STATE: b's discovery cache and binding registry emptied —
    // exactly what a restart leaves behind.
    b.clear_identity_resolution_for_testing().await;
    assert!(b.discovered_agent_for_testing(&a_id).await.is_none());

    // A GENUINE reconnect — the transport shape a daemon restart
    // produces: the existing connection is torn down, then b redials.
    // A bare connect_addr while already connected emits no new
    // PeerConnected and the trigger would never fire.
    let a_addr = a.bound_addr().await.expect("a bound");
    let b_network = b.network().expect("b network");
    let a_peer = ant_quic::PeerId(a.machine_id().0);
    let b_peer = ant_quic::PeerId(b.machine_id().0);
    b_network
        .disconnect(&a_peer)
        .await
        .expect("b drops the a connection");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while b_network.is_connected(&a_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "disconnect deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // a's listener must observe the disconnect too, or the redial is not
    // a NEW machine on a's side and a would not re-announce.
    let a_network = a.network().expect("a network");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while a_network.is_connected(&b_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a-side disconnect deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // D31 r2: the trigger keys on b's last observed PeerDisconnected
    // being ≥20 s old. The accept-side transport gap means a's listener
    // may never see this fixture's clean close (production loss
    // detection records it), so the observation is noted directly — the
    // record a real 30 s restart outage would have left on a's tracker.
    a.note_peer_absent_for_testing(
        b.machine_id().0,
        std::time::Instant::now() - std::time::Duration::from_secs(30),
    );
    // Settle before the redial so no late PeerDisconnected can overwrite
    // the noted absence; a real restart separates these by minutes.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // Redial: this IS a machine that was absent for ≥20 s.
    b_network.connect_addr(a_addr).await.expect("b redials a");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !b_network.is_connected(&a_peer).await {
        assert!(tokio::time::Instant::now() < deadline, "redial deadline");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // B SENDS FIRST — within 10 s of the reconnect it must succeed.
    let send = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match b.send_direct(&a_id, b"1091 cold send".to_vec()).await {
                Ok(_) => return true,
                Err(x0x::dm::DmError::RecipientUndiscovered(_)) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(other) => panic!("unexpected send error: {other:?}"),
            }
        }
    })
    .await;
    assert!(
        send.unwrap_or(false),
        "#1091: the cold node must send first within 10 s of the reconnect"
    );
}

#[tokio::test]
async fn machine_for_agent_returns_linked_endpoint() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let da = fake_discovered(
        103,
        vec!["10.0.0.3:8080".parse().unwrap()],
        Some("FullCone"),
        Some(true),
        Some(false),
        Some(true),
    );
    let target_id = da.agent_id;
    let target_machine = da.machine_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let machine = agent
        .machine_for_agent(target_id)
        .await
        .unwrap()
        .expect("agent should resolve to a machine");
    assert_eq!(machine.machine_id, target_machine);
    assert!(machine.agent_ids.contains(&target_id));
    assert_eq!(machine.addresses.len(), 1);
}

// ---------------------------------------------------------------------------
// #927/#898: unverified claims must not reach the discovery cache via
// connect_to_agent's DirectMessaging promotion
// ---------------------------------------------------------------------------

/// #898 (promotion arm): a raw Direct payload from a LIVE machine M2 that
/// claims agent A (verified binding on M1) must not rebind A — and crucially
/// must not be PROMOTED: `connect_to_agent` rewrites A's discovery-cache
/// machine whenever `DirectMessaging` maps A to a transport-connected
/// machine, so the gate has to hold at the routing write, not just the
/// listener.
///
/// This test builds the live connection for real (so `is_connected(M2)` is
/// genuinely true and the promotion branch is reachable), makes the exact
/// listener call for a spoof (`mark_raw_direct_sender_connected(A, M2,
/// verified=false)`), and then runs `connect_to_agent(A)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unverified_raw_claim_cannot_promote_into_discovery_cache() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;

    // A real, live connection to M2 so the promotion branch's
    // `is_connected(M2)` is true — otherwise this test would prove nothing
    // (without a live M2 the promotion cannot fire even if the gate is
    // reverted).
    let m2_addr = m2.bound_addr().await.expect("m2 bound addr");
    let m2_machine = m2.machine_id();
    local
        .network()
        .expect("local network")
        .connect_addr(m2_addr)
        .await
        .expect("dial m2");
    let m2_peer = ant_quic::PeerId(m2_machine.0);
    let local_network = local.network().expect("local network");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !local_network.is_connected(&m2_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "m2 never became transport-connected"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Agent A: verified binding on M1 (fake, offline), cached in discovery.
    let da = fake_discovered(0x21, vec![], None, Some(true), None, None);
    let a_id = da.agent_id;
    let m1 = da.machine_id;
    let _ = m2_machine; // used implicitly via m2_peer above
    local.insert_discovered_agent_for_testing(da).await;
    local
        .direct_messaging()
        .mark_raw_direct_sender_connected(a_id, m1, true)
        .await;
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m1),
        "precondition: A's verified binding is M1"
    );

    // The spoof: M2 prefixes A's id; the listener computed verified=false
    // and made exactly this call. The boolean is captured, NOT asserted
    // here: with the #898 gate reverted the call both returns true and
    // rebinds, and this test's red must come from the rebind state below,
    // not from the boolean.
    let refused = local
        .direct_messaging()
        .mark_raw_direct_sender_connected(a_id, m2.machine_id(), false)
        .await;
    // The promotion: connect_to_agent reads DirectMessaging and rewrites
    // the discovery cache when the mapped machine is live. With the gate
    // held, A stays on M1 in BOTH structures.
    let _outcome = local.connect_to_agent(&a_id).await.unwrap();
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m1),
        "connect_to_agent must not promote the refused claim (#898)"
    );
    // `machine_for_agent` resolves from the discovery cache, so this pins
    // the promotion target too.
    let resolved = local
        .machine_for_agent(a_id)
        .await
        .unwrap()
        .expect("A stays in the discovery cache");
    assert_eq!(
        resolved.machine_id, m1,
        "the discovery cache must still route A to M1"
    );
    assert!(!refused, "and the unverified claim was refused");

    local.shutdown().await;
    m2.shutdown().await;
}

/// S1 (#898 review): step 4 (`direct_per_addr`) must not rebind an agent
/// whose machine is KNOWN to whichever machine answers a stale address.
/// M2 (real daemon) answers at the address the cache holds for A@M1; the
/// dial succeeds, the answered machine is NOT M1, and both the discovery
/// cache and DirectMessaging must stay on M1. Without the mismatch check
/// this test fails: A rebinds to M2, and M2's later raw claims for A
/// would compute verified=true.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_address_answered_by_a_different_machine_never_rebinds() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;

    // M2 is LIVE at X; the cache says A@M1 lives at X too.
    let x = m2.bound_addr().await.expect("m2 bound");
    let da = fake_discovered(0x31, vec![x], None, Some(true), None, None);
    let a_id = da.agent_id;
    let m1 = da.machine_id;
    assert_ne!(
        m1,
        m2.machine_id(),
        "the attacker must differ from the binding"
    );
    local.insert_discovered_agent_for_testing(da).await;
    local
        .direct_messaging()
        .mark_raw_direct_sender_connected(a_id, m1, true)
        .await;

    // Hinted dial to M1 (step 3) fails: M2 answers X but is not M1's
    // PeerId; step 4 then dials X with NO peer expectation — M2 answers.
    let _outcome = local.connect_to_agent(&a_id).await.unwrap();

    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m1),
        "step 4 must not hand A to the machine that merely answered the address (#898 S1)"
    );
    let resolved = local
        .machine_for_agent(a_id)
        .await
        .unwrap()
        .expect("A stays in the discovery cache");
    assert_eq!(
        resolved.machine_id, m1,
        "the discovery cache must still route A to M1"
    );

    local.shutdown().await;
    m2.shutdown().await;
}

/// T1 (#898 review, Rule 9): drive REAL raw Direct bytes through the
/// production listener. M2 (a live daemon) sends a Direct payload whose
/// 32-byte prefix claims A; A is cached on M1, so the listener computes
/// verified=false. The message must still be DELIVERED (annotated
/// unverified) and A must never be marked connected to M2. Reverting the
/// listener's call site to a plain `mark_connected` (the mutant that
/// survived the r1 review) makes this test FAIL at the routing assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_direct_listener_refuses_an_unverified_claim_end_to_end() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;
    // join_network starts the REAL direct listener (and the identity /
    // network-event loops) on the loopback plane.
    local.join_network().await.expect("local join network");

    let da = fake_discovered(0x41, vec![], None, Some(true), None, None);
    let a_id = da.agent_id;
    let m1 = da.machine_id;
    local.insert_discovered_agent_for_testing(da).await;

    // Connect M2 → local, then spoof: M2 sends a raw Direct frame whose
    // sender prefix claims A.
    let local_addr = local.bound_addr().await.expect("local bound");
    let m2_network = m2.network().expect("m2 network");
    m2_network
        .connect_addr(local_addr)
        .await
        .expect("dial local");
    let local_peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !m2_network.is_connected(&local_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local never became transport-connected to m2"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut claimed_sender = [0u8; 32];
    claimed_sender.copy_from_slice(a_id.as_bytes());
    m2_network
        .send_direct(&local_peer, &claimed_sender, b"898 spoof")
        .await
        .expect("spoofed raw direct send");

    // Delivery is unchanged: the message arrives, annotated UNVERIFIED.
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(msg) = local.recv_direct_annotated().await {
                return msg;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the spoofed DM must still be delivered");
    assert_eq!(delivered.sender, a_id);
    assert!(
        !delivered.verified,
        "an unverified claim is delivered annotated unverified"
    );
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        None,
        "the listener must never mark A onto the claiming machine (#898)"
    );
    let _ = m1; // binding machine; A was never marked to it either

    local.shutdown().await;
    m2.shutdown().await;
}

/// C1 (#898 review): evidence is `verified` OR an authenticated binding
/// naming THIS machine. A moved agent whose announcement updated
/// AuthenticatedMachineBindings but is too stale for the discovery cache
/// must still verify delivery and have its routing updated by the listener. Drives the same real listener path as T1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_binding_names_the_machine_and_routing_follows() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;
    local.join_network().await.expect("local join network");

    // The cache still says A@M1 (stale); the AUTHENTICATED binding says
    // A moved to M2 (announcement landed, cache insert did not).
    let mut da = fake_discovered(0x51, vec![], None, Some(true), None, None);
    da.announced_at -= 10;
    let a_id = da.agent_id;
    let _m1 = da.machine_id;
    local.insert_discovered_agent_for_testing(da).await;
    local
        .record_authenticated_machine_binding_for_testing(a_id, m2.machine_id())
        .await;

    let local_addr = local.bound_addr().await.expect("local bound");
    let m2_network = m2.network().expect("m2 network");
    m2_network
        .connect_addr(local_addr)
        .await
        .expect("dial local");
    let local_peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !m2_network.is_connected(&local_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local never became transport-connected to m2"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut sender_bytes = [0u8; 32];
    sender_bytes.copy_from_slice(a_id.as_bytes());
    m2_network
        .send_direct(&local_peer, &sender_bytes, b"898 c1 move")
        .await
        .expect("raw direct send");

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if local
                .direct_messaging()
                .get_machine_id(&a_id)
                .await
                .is_some()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the authenticated binding must let the routing write through");
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m2.machine_id()),
        "C1: a binding naming THIS machine is evidence enough to update routing"
    );

    local.shutdown().await;
    m2.shutdown().await;
}

// ---------------------------------------------------------------------------
// ReachabilityInfo: all NAT type heuristics
// ---------------------------------------------------------------------------

#[test]
fn nat_type_none_string_is_not_enough_without_peer_verification() {
    let da = fake_discovered(
        20,
        vec!["1.2.3.4:9000".parse().unwrap()],
        Some("None"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
}

#[test]
fn nat_type_address_restricted_still_attempts_direct_but_is_not_verified() {
    let da = fake_discovered(
        21,
        vec!["1.2.3.4:9000".parse().unwrap()],
        Some("AddressRestricted"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(info.needs_coordination());
}

#[test]
fn nat_type_port_restricted_still_attempts_direct_but_is_not_verified() {
    let da = fake_discovered(
        22,
        vec!["1.2.3.4:9000".parse().unwrap()],
        Some("PortRestricted"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(info.needs_coordination());
}

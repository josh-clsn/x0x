//! #1241 / D197: real streams, production admission/dispatch/Hello verification.
//! Execute only in the Linux network-isolation harness. No gossip is started.

use super::*;
use crate::{
    contacts::TrustLevel,
    peer_evidence::{PeerEvidenceStore, RuntimePolicy},
    streams::{StreamAccept, StreamAcceptor},
    Agent,
};
use futures::FutureExt;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    BeforePrefixRefused,
    ProtocolRefused,
    ApplicationDelivered,
    HelloVerified,
    HelloRefused,
}

struct Fixture {
    _dir: tempfile::TempDir,
    initiator: Agent,
    responder: Agent,
    context: Arc<Context>,
    incoming: Arc<StreamAccept>,
    evidence_acceptor: StreamAcceptor,
    app_acceptor: StreamAcceptor,
}

impl Fixture {
    async fn new(related: bool, discovered: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut agents = Vec::new();
        for name in ["initiator", "responder"] {
            let path = dir.path().join(name);
            std::fs::create_dir_all(&path).unwrap();
            agents.push(
                Agent::builder()
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
                    .unwrap(),
            );
        }
        let responder = agents.pop().unwrap();
        let initiator = agents.pop().unwrap();
        let peer = initiator.agent_id();
        let local = responder.agent_id();
        if discovered {
            let mut entry =
                crate::discovered_agent_fixture(1, dm_capability::now_unix_ms() / 1000, &[], None);
            entry.agent_id = peer;
            entry.machine_id = initiator.machine_id();
            entry.agent_public_key = initiator
                .identity
                .agent_keypair()
                .public_key()
                .as_bytes()
                .to_vec();
            entry.machine_public_key = initiator
                .identity
                .machine_keypair()
                .public_key()
                .as_bytes()
                .to_vec();
            responder
                .identity_discovery_cache
                .write()
                .await
                .insert(peer, entry);
        }
        let policy = Arc::new(RuntimePolicy::new(
            local,
            responder.owner_trust.clone(),
            Arc::clone(&responder.revocation_set),
        ));
        // Same policy adapter as named groups: both agents occupy one active
        // roster. Neither agent gets a contact, owner certificate, or grant.
        let roster = if related {
            vec![local, peer]
        } else {
            vec![local]
        };
        policy.set_groups(Arc::new(move |agent| {
            Some(roster.contains(&local) && roster.contains(&agent))
        }));
        let runtime = Arc::clone(responder.peer_evidence());
        responder.owner_trust.install_evidence(&runtime);
        runtime.start(
            dir.path().join("evidence"),
            Default::default(),
            policy,
            Arc::clone(&responder.capability_store.evidence_wire),
        );
        assert!(runtime.wait(0).await, "evidence store must finish loading");
        assert_eq!(
            runtime.store().unwrap().related(
                peer,
                initiator.machine_id(),
                None,
                dm_capability::now_unix_ms(),
            ),
            related,
        );
        assert!(responder.contact_store.read().await.get(&peer).is_none());
        assert_eq!(
            responder.contact_store.read().await.trust_level(&peer),
            TrustLevel::Unknown,
        );
        assert_eq!(
            responder
                .owner_trust
                .evaluate_pair(
                    &responder.contact_store,
                    &responder.identity_discovery_cache,
                    &responder.revocation_set,
                    &peer,
                    &initiator.machine_id(),
                )
                .await
                .decision,
            crate::trust::TrustDecision::Unknown,
            "the roster must not silently promote ordinary stream trust",
        );
        let context = Arc::new(Context {
            bindings: Arc::clone(&responder.authenticated_machine_bindings),
            runtime,
            capture: Arc::clone(&responder.capability_store.evidence_wire),
            network: Arc::clone(responder.network().unwrap()),
            identity: Arc::clone(&responder.identity),
            template: responder.build_announcement(false, false).unwrap(),
            own_cert: Arc::clone(&responder.own_cert_pair),
            capabilities: Arc::clone(&responder.dm_capabilities_tx),
            caps: Arc::clone(&responder.capability_store),
            discovery: Arc::clone(&responder.identity_discovery_cache),
            machines: Arc::clone(&responder.machine_discovery_cache),
            owner: responder.owner_trust.clone(),
            revoked: Arc::clone(&responder.revocation_set),
        });
        let incoming = Arc::new(StreamAccept::new(8));
        let evidence_acceptor = incoming.register(StreamProtocol::EvidenceV1).unwrap();
        let app_acceptor = incoming.register(StreamProtocol::SocksV1).unwrap();
        let address = responder.network().unwrap().bound_addr().await.unwrap();
        let connected = tokio::time::timeout(
            Duration::from_secs(10),
            initiator.network().unwrap().connect_addr(address),
        )
        .await
        .expect("loopback connection timeout")
        .expect("loopback connection");
        assert_eq!(connected.0, responder.machine_id().0);
        Self {
            _dir: dir,
            initiator,
            responder,
            context,
            incoming,
            evidence_acceptor,
            app_acceptor,
        }
    }

    fn store(&self) -> Arc<PeerEvidenceStore> {
        self.context.runtime.store().unwrap()
    }

    fn hello(&self) -> Hello {
        mint_hello(
            &self.initiator.identity,
            self.initiator.build_announcement(false, false).unwrap(),
            &self.initiator.own_cert_pair,
            crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
            None,
            false,
        )
        .unwrap()
    }

    async fn exchange(&mut self, protocol: StreamProtocol, hello: &Hello) -> Outcome {
        let body = codec().serialize(hello).unwrap();
        let (mut send, mut reply) = tokio::time::timeout(
            Duration::from_secs(10),
            self.initiator
                .network()
                .unwrap()
                .open_bi(&ant_quic::PeerId(self.responder.machine_id().0)),
        )
        .await
        .expect("open timeout")
        .expect("open stream");
        // Raw transport is deliberate: EvidenceV1 does not use the public
        // application opener's outbound trust gate (see Context::exchange).
        send.write_u8(protocol.as_u8()).await.unwrap();
        write_message(
            &mut send,
            &Limits::default(),
            self.responder.machine_id(),
            HELLO,
            &body,
        )
        .await
        .unwrap();
        let (peer, send, recv) = tokio::time::timeout(
            Duration::from_secs(10),
            self.responder.network().unwrap().accept_bi(),
        )
        .await
        .expect("transport must deliver stream before trust is evaluated")
        .expect("accept stream");
        assert_eq!(peer.0, self.initiator.machine_id().0);
        let r = &self.responder;
        let Some(admission) = Agent::admit_stream_before_prefix(
            &r.identity_discovery_cache,
            &r.contact_store,
            &r.revocation_set,
            &r.move_state,
            &r.connect_policy,
            &r.owner_trust,
            &self.initiator.machine_id(),
            &self.context.runtime.wire_limits,
        )
        .await
        else {
            return Outcome::BeforePrefixRefused;
        };
        Agent::dispatch_admitted_stream(
            Arc::clone(&self.incoming),
            Arc::clone(&r.identity_discovery_cache),
            Arc::clone(&r.contact_store),
            Arc::clone(&r.revocation_set),
            Arc::clone(&r.move_state),
            Arc::clone(&r.connect_policy),
            r.owner_trust.clone(),
            Arc::clone(&self.context.runtime),
            admission,
            self.initiator.machine_id(),
            send,
            recv,
        )
        .await;
        assert!(
            self.incoming.receiver().lock().await.try_recv().is_err(),
            "neither selected protocol may leak into the default channel",
        );
        if self.app_acceptor.next().now_or_never().flatten().is_some() {
            return Outcome::ApplicationDelivered;
        }
        let Some(stream) = self.evidence_acceptor.next().now_or_never().flatten() else {
            return Outcome::ProtocolRefused;
        };
        assert!(stream.evidence_lease.is_some(), "bounded admission lease");
        Arc::clone(&self.context).accept(stream).await;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            read_message(&mut reply, &Limits::default()),
        )
        .await
        .expect("Hello must be answered or reset, not left pending");
        match response {
            Ok((ACK | HELLO, _)) => Outcome::HelloVerified,
            Err(_) => Outcome::HelloRefused,
            other => panic!("unexpected Hello response: {other:?}"),
        }
    }

    async fn shutdown(&self) {
        self.initiator.network().unwrap().shutdown().await;
        self.responder.network().unwrap().shutdown().await;
    }
}

#[tokio::test]
async fn issue1241_unknown_group_peer_evidence_hello_is_verified_and_stored() {
    let mut f = Fixture::new(true, true).await;
    let hello = f.hello();
    let now = dm_capability::now_unix_ms();
    assert!(f
        .store()
        .usable(f.initiator.agent_id(), f.initiator.machine_id(), now)
        .is_none());
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &hello).await;
    f.shutdown().await;
    assert_eq!(
        outcome,
        Outcome::HelloVerified,
        "D197: discovery must not prevent an Unknown group peer's EvidenceV1 Hello"
    );
    let view = f
        .store()
        .usable(
            f.initiator.agent_id(),
            f.initiator.machine_id(),
            dm_capability::now_unix_ms(),
        )
        .expect("verified relationship evidence stored");
    assert_eq!(view.announcement.agent_id, f.initiator.agent_id());
    assert_eq!(view.announcement.machine_id, f.initiator.machine_id());
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        1
    );
    assert!(f
        .responder
        .contact_store
        .read()
        .await
        .get(&f.initiator.agent_id())
        .is_none());
}

#[tokio::test]
async fn issue1241_blocked_group_peer_evidence_is_refused() {
    let mut f = Fixture::new(true, true).await;
    f.responder
        .contact_store
        .write()
        .await
        .set_trust(&f.initiator.agent_id(), TrustLevel::Blocked);
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &f.hello()).await;
    f.shutdown().await;
    assert_eq!(outcome, Outcome::BeforePrefixRefused);
    assert!(f
        .store()
        .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
        .is_none());
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        0
    );
}

#[tokio::test]
async fn issue1241_stranger_evidence_keeps_current_admission_and_ttl_only_storage() {
    for discovered in [false, true] {
        let mut f = Fixture::new(false, discovered).await;
        let hello = f.hello();
        let outcome = f.exchange(StreamProtocol::EvidenceV1, &hello).await;
        f.shutdown().await;
        assert_eq!(
            outcome,
            if discovered {
                Outcome::BeforePrefixRefused
            } else {
                Outcome::HelloVerified
            }
        );
        let now = dm_capability::now_unix_ms();
        assert!(
            f.store()
                .usable_agent(f.initiator.agent_id(), now)
                .is_none(),
            "strangers never gain persisted authority"
        );
        assert_eq!(
            f.context.capture.get(f.initiator.agent_id(), true, now),
            (!discovered).then_some(hello.announcement)
        );
        assert_eq!(
            f.context.capture.get(f.initiator.agent_id(), false, now),
            (!discovered).then_some(hello.advert)
        );
    }
}

#[tokio::test]
async fn issue1241_unknown_group_peer_non_evidence_stream_stays_gated() {
    let mut f = Fixture::new(true, true).await;
    let outcome = f.exchange(StreamProtocol::SocksV1, &f.hello()).await;
    f.responder
        .contact_store
        .write()
        .await
        .set_trust(&f.initiator.agent_id(), TrustLevel::Trusted);
    let trusted = f.exchange(StreamProtocol::SocksV1, &f.hello()).await;
    f.shutdown().await;
    assert!(
        matches!(
            outcome,
            Outcome::BeforePrefixRefused | Outcome::ProtocolRefused
        ),
        "Unknown group peer must not reach an application acceptor: {outcome:?}"
    );
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        0
    );
    assert_eq!(
        trusted,
        Outcome::ApplicationDelivered,
        "live application acceptor control"
    );
}

#[tokio::test]
async fn issue1241_admitted_group_peer_forged_hello_is_not_ingested() {
    let mut f = Fixture::new(true, true).await;
    // Trusted here so this independent verification control reaches the body
    // on both the old and fixed code; the Unknown admission test is separate.
    f.responder
        .contact_store
        .write()
        .await
        .set_trust(&f.initiator.agent_id(), TrustLevel::Trusted);
    let mut hello = f.hello();
    let mut announcement = announce_v3::deserialize_v3(&hello.announcement).unwrap();
    announcement.announced_at -= 1; // well-formed and fresh, invalid signature
    hello.announcement = announce_v3::serialize_v3(&announcement).unwrap();
    assert!(decode::parts(&hello.announcement, &hello.advert, None).is_ok());
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &hello).await;
    f.shutdown().await;
    assert_eq!(outcome, Outcome::HelloRefused);
    assert!(f
        .store()
        .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
        .is_none());
    assert!(f
        .context
        .capture
        .get(f.initiator.agent_id(), true, dm_capability::now_unix_ms())
        .is_none());
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        0
    );
    assert_eq!(f.context.runtime.diagnostics()["evidence_hello_refused"], 1);
}

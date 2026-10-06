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
    policy: Arc<RuntimePolicy>,
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
            policy.clone(),
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
            policy,
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
        self.exchange_after_admission(protocol, hello, None).await
    }

    async fn exchange_after_admission(
        &mut self,
        protocol: StreamProtocol,
        hello: &Hello,
        denial: Option<Denial>,
    ) -> Outcome {
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
        if let Some(denial) = denial {
            self.deny(denial).await;
        }
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
    for protocol in [
        StreamProtocol::ForwardV1,
        StreamProtocol::SocksV1,
        StreamProtocol::ForwardV2,
        StreamProtocol::WebRtcV1,
        StreamProtocol::SyncV1,
    ] {
        let mut f = Fixture::new(true, true).await;
        if protocol != StreamProtocol::SocksV1 {
            drop(f.app_acceptor);
            f.app_acceptor = f.incoming.register(protocol).unwrap();
        }
        let outcome = f.exchange(protocol, &f.hello()).await;
        f.responder
            .contact_store
            .write()
            .await
            .set_trust(&f.initiator.agent_id(), TrustLevel::Trusted);
        let trusted = f.exchange(protocol, &f.hello()).await;
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

#[derive(Clone, Copy, Debug)]
enum Denial {
    Blocked,
    Known,
    MachinePin,
    AgentRevoked,
    MachineRevoked,
    BindingRevoked,
    PlacementMoved,
    Expired,
    Acl,
    CoResidentBlocked,
    RelationshipRemoved,
    DiscoveryRemoved,
}

impl Fixture {
    async fn deny(&self, denial: Denial) {
        use crate::revocation::{RevocationRecord, RevokedSubject};
        let r = &self.responder;
        let agent = self.initiator.agent_id();
        let machine = self.initiator.machine_id();
        match denial {
            Denial::Blocked | Denial::Known | Denial::MachinePin => {
                let mut contacts = r.contact_store.write().await;
                contacts.set_trust(
                    &agent,
                    match denial {
                        Denial::Blocked => TrustLevel::Blocked,
                        Denial::Known => TrustLevel::Known,
                        _ => TrustLevel::Unknown,
                    },
                );
                if matches!(denial, Denial::MachinePin) {
                    contacts.set_identity_type(&agent, crate::contacts::IdentityType::Pinned);
                }
            }
            Denial::AgentRevoked | Denial::MachineRevoked => {
                let (subject, public, secret) = if matches!(denial, Denial::AgentRevoked) {
                    (
                        RevokedSubject::Agent(agent),
                        self.initiator.identity.agent_keypair().public_key(),
                        self.initiator.identity.agent_keypair().secret_key(),
                    )
                } else {
                    (
                        RevokedSubject::Machine(machine),
                        self.initiator.identity.machine_keypair().public_key(),
                        self.initiator.identity.machine_keypair().secret_key(),
                    )
                };
                let record = RevocationRecord::sign(
                    subject,
                    public,
                    secret,
                    dm_capability::now_unix_ms() / 1000,
                    None,
                )
                .unwrap();
                r.revocation_set
                    .write()
                    .await
                    .verify_and_insert(record, None)
                    .unwrap();
            }
            Denial::BindingRevoked => {
                r.revocation_set.write().await.union_bundle_retired(&[
                    crate::revocation::AgentMachineBinding {
                        agent,
                        machine,
                        move_epoch: 1,
                    },
                ]);
            }
            Denial::PlacementMoved => {
                let owner = crate::identity::UserKeypair::generate().unwrap();
                let record = crate::key_move::PlacementRecord::sign(
                    agent,
                    owner.public_key().as_bytes(),
                    crate::key_move::Placement::Pinned(MachineId([99; 32])),
                    1,
                    dm_capability::now_unix_ms() / 1000,
                    owner.secret_key(),
                )
                .unwrap();
                r.move_state
                    .write()
                    .await
                    .cache_placement(
                        record,
                        crate::key_move::PlacementAuthority::local_owner(&owner),
                    )
                    .unwrap();
            }
            Denial::Expired => {
                r.identity_discovery_cache
                    .write()
                    .await
                    .get_mut(&agent)
                    .unwrap()
                    .cert_not_after = Some(1);
            }
            Denial::Acl => {
                r.set_connect_policy(Arc::new(crate::connect::ConnectPolicy::Enabled(
                    crate::connect::ConnectAcl {
                        loaded_from: "/test".into(),
                        loaded_at_unix_ms: 0,
                        allow: Vec::new(),
                        owner_allow: Vec::new(),
                        grant_allow: Vec::new(),
                    },
                )));
            }
            Denial::CoResidentBlocked => {
                let other = AgentId([255; 32]);
                let mut entry = r.identity_discovery_cache.read().await[&agent].clone();
                entry.agent_id = other;
                r.identity_discovery_cache
                    .write()
                    .await
                    .insert(other, entry);
                r.contact_store
                    .write()
                    .await
                    .set_trust(&other, TrustLevel::Blocked);
            }
            Denial::RelationshipRemoved => self.policy.set_groups(Arc::new(|_| Some(false))),
            Denial::DiscoveryRemoved => {
                r.identity_discovery_cache.write().await.clear();
            }
        }
    }
}

#[tokio::test]
async fn issue1241_evidence_exception_preserves_and_rechecks_denials() {
    for denial in [
        Denial::Blocked,
        Denial::Known,
        Denial::MachinePin,
        Denial::AgentRevoked,
        Denial::MachineRevoked,
        Denial::BindingRevoked,
        Denial::PlacementMoved,
        Denial::Expired,
        Denial::Acl,
        Denial::CoResidentBlocked,
        Denial::RelationshipRemoved,
        Denial::DiscoveryRemoved,
    ] {
        for after_prefix_admission in [false, true] {
            // No discovery has its existing stranger path; test its removal
            // only AFTER admission as a known Unknown relationship peer.
            if !after_prefix_admission && matches!(denial, Denial::DiscoveryRemoved) {
                continue;
            }
            let mut f = Fixture::new(true, true).await;
            if !after_prefix_admission {
                f.deny(denial).await;
            }
            let outcome = f
                .exchange_after_admission(
                    StreamProtocol::EvidenceV1,
                    &f.hello(),
                    after_prefix_admission.then_some(denial),
                )
                .await;
            f.shutdown().await;
            assert_eq!(
                outcome,
                if after_prefix_admission {
                    Outcome::ProtocolRefused
                } else {
                    Outcome::BeforePrefixRefused
                },
                "{denial:?}, after admission: {after_prefix_admission}"
            );
            assert_eq!(
                f.context.runtime.diagnostics()["evidence_hello_received"],
                0
            );
            assert!(f
                .store()
                .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
                .is_none());
        }
    }
}

#[tokio::test]
async fn issue1241_unknown_relationship_prefix_slots_are_bounded_and_released() {
    let f = Fixture::new(true, true).await;
    let r = &f.responder;
    let machine = f.initiator.machine_id();
    let admit = || {
        Agent::admit_stream_before_prefix(
            &r.identity_discovery_cache,
            &r.contact_store,
            &r.revocation_set,
            &r.move_state,
            &r.connect_policy,
            &r.owner_trust,
            &machine,
            &f.context.runtime.wire_limits,
        )
    };
    let first = admit().await.expect("first prefix slot");
    assert!(first.agents.is_none() && first.prefix.is_some() && first.evidence_only);
    let second = admit().await.expect("second prefix slot");
    assert!(
        admit().await.is_none(),
        "third same-machine prefix must reset"
    );
    drop(first);
    let replacement = admit().await.expect("dropped slot is reusable");
    let others: Vec<_> = (0..30)
        .map(|id| {
            f.context
                .runtime
                .wire_limits
                .admit_prefix(MachineId([id; 32]))
                .unwrap()
        })
        .collect();
    assert!(f
        .context
        .runtime
        .wire_limits
        .admit_prefix(MachineId([31; 32]))
        .is_none());
    drop(others);
    drop(second);
    drop(replacement);
    assert!(admit().await.is_some());
    f.shutdown().await;
}

#[tokio::test]
async fn issue1241_roster_alone_does_not_trigger_outbound_hello() {
    let mut f = Fixture::new(true, true).await;
    let machine = f.initiator.machine_id();
    assert!(
        f.context.related(machine).await,
        "fresh discovery resolves the roster peer"
    );
    f.responder.identity_discovery_cache.write().await.clear();
    assert!(f.store().related(
        f.initiator.agent_id(),
        machine,
        None,
        dm_capability::now_unix_ms()
    ));
    assert!(
        !f.context.related(machine).await,
        "a roster agent without a machine mapping cannot trigger Hello"
    );
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &f.hello()).await;
    f.shutdown().await;
    assert_eq!(outcome, Outcome::HelloVerified);
    assert!(
        f.context.related(machine).await,
        "an inbound verified Hello supplies the missing evidence"
    );
    assert!(
        f.responder
            .authenticated_machine_bindings
            .read()
            .await
            .peek(&f.initiator.agent_id())
            .is_none(),
        "Hello supplies evidence, not a live binding-cache insertion"
    );
    assert!(f
        .store()
        .usable(
            f.initiator.agent_id(),
            machine,
            dm_capability::now_unix_ms()
        )
        .is_some());
}

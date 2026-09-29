//! Inert D08 boundary tests: memory, signatures and a temporary outbox only.
use crate::dm::{CapabilityRegistry, DmCapabilities, DmError};
use crate::dm_capability::{CapabilityAdvert, CapabilityStore};
use crate::dm_capability_service::{build_signed_advert, ingest_verified_capability_advert};
use crate::gossip::{PubSubMessage, SigningContext};
use crate::identity::{AgentId, AgentKeypair, MachineId, UserKeypair};

fn message() -> PubSubMessage {
    let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
    PubSubMessage {
        topic: crate::dm_capability::DM_CAPABILITY_TOPIC.into(),
        payload: build_signed_advert(
            &signing,
            signing.agent_id,
            MachineId([2; 32]),
            DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]),
        )
        .unwrap()
        .into(),
        sender: Some(signing.agent_id),
        sender_public_key: Some(signing.public_key_bytes.clone()),
        verified: true,
        trust_level: None,
        raw_envelope: None,
    }
}

#[test]
fn d08_advertisement_round_trip_and_legacy_reader() {
    let message = message();
    // The legacy decoder and its original signature must still work.
    let base = CapabilityAdvert::from_postcard(&message.payload).unwrap();
    assert!(crate::dm_capability_service::verify_advert_signature(
        &base,
        message.sender_public_key.as_ref().unwrap()
    ));
    let store = CapabilityStore::new();
    assert!(ingest_verified_capability_advert(
        &store,
        AgentId([9; 32]),
        &message
    ));
    assert_eq!(
        store
            .lookup(&message.sender.unwrap())
            .unwrap()
            .application_registry,
        CapabilityRegistry::current()
    );
}

#[test]
fn d08_legacy_announcement_has_no_bits() {
    let mut message = message();
    let base = CapabilityAdvert::from_postcard(&message.payload).unwrap();
    // Re-encoding the frozen base drops the optional trailer, exactly the old layout.
    message.payload = postcard::to_stdvec(&base).unwrap().into();
    let store = CapabilityStore::new();
    assert!(ingest_verified_capability_advert(
        &store,
        AgentId([9; 32]),
        &message
    ));
    assert_eq!(
        store
            .lookup(&message.sender.unwrap())
            .unwrap()
            .application_registry,
        CapabilityRegistry::default()
    );
}

#[test]
fn d08_unverified_forged_stale_and_card_bits_fail_closed() {
    let message = message();
    let recipient = message.sender.unwrap();
    let local = AgentId([9; 32]);
    let store = CapabilityStore::new();
    let mut bad = message.clone();
    bad.verified = false;
    assert!(!ingest_verified_capability_advert(&store, local, &bad));
    let mut bytes = message.payload.to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    bad = message.clone();
    bad.payload = bytes.into();
    assert!(!ingest_verified_capability_advert(&store, local, &bad));
    assert!(ingest_verified_capability_advert(&store, local, &message));
    let future = std::time::Instant::now() + std::time::Duration::from_secs(901);
    assert!(store.lookup_binding_at(&recipient, future).is_none());
    let cards = CapabilityStore::new();
    assert!(cards.insert_from_card(
        recipient,
        MachineId([2; 32]),
        DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]),
        crate::dm::now_unix_ms()
    ));
    assert_eq!(
        cards.lookup(&recipient).unwrap().application_registry,
        CapabilityRegistry::default()
    );
}

#[test]
fn d08_offer_requires_bit_before_transport() {
    let store = CapabilityStore::new();
    let recipient = AgentId([3; 32]);
    let payload = b"X0X-GROUP-PREDECESSOR-RELAY-V1\nrequest";
    let mut sends = 0;
    let blocked = store.require_payload_capability(&recipient, payload);
    if blocked.is_ok() {
        sends += 1;
    }
    assert!(matches!(
        blocked,
        Err(DmError::RecipientUpgradeRequired { .. })
    ));
    assert_eq!(sends, 0);
    let mut caps = DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]);
    caps.application_registry.bits = CapabilityRegistry::SHARE_GRANT_V1;
    store.insert(
        recipient,
        MachineId([2; 32]),
        caps,
        crate::dm::now_unix_ms(),
    );
    assert!(
        store
            .require_payload_capability(&recipient, payload)
            .is_err(),
        "wrong bit must not allow an offer"
    );
    store.insert(
        recipient,
        MachineId([2; 32]),
        DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]),
        crate::dm::now_unix_ms() + 1,
    );
    store
        .require_payload_capability(&recipient, payload)
        .unwrap();
}

#[tokio::test]
async fn d08_grant_stays_queued_until_bit_arrives() {
    use crate::share_grant::{
        deliver_grant_via, outbox::GrantRedeliveryOutbox, Grantee, ShareCap, ShareGrant,
    };
    let dir = tempfile::tempdir().unwrap();
    let owner = UserKeypair::generate().unwrap();
    let recipient = AgentId([3; 32]);
    let now = crate::dm::now_unix_ms() / 1000;
    let grant = ShareGrant::sign(
        &owner,
        [1; 32],
        Grantee::Agent(recipient),
        vec![AgentId([4; 32])],
        vec![ShareCap::Dm],
        now - 1,
        now + 3600,
    )
    .unwrap();
    let revocations = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
    let outbox =
        GrantRedeliveryOutbox::load(dir.path().join("outbox"), Some(owner.user_id()), now).await;
    let store = CapabilityStore::new();
    // A 0.45 peer has usable transport-v2 material but no application bits.
    let mut legacy = DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]);
    legacy.application_registry = CapabilityRegistry::default();
    store.insert(
        recipient,
        MachineId([2; 32]),
        legacy,
        crate::dm::now_unix_ms() - 1,
    );
    let sends = std::sync::atomic::AtomicUsize::new(0);
    let send = |to, payload: Vec<u8>, _id| {
        let result = store
            .require_payload_capability(&to, &payload)
            .map_err(|e| e.to_string());
        if result.is_ok() {
            sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        std::future::ready(result)
    };
    let results = deliver_grant_via(
        &grant,
        &[recipient],
        Some(&outbox),
        &revocations,
        || now,
        send,
    )
    .await;
    assert!(!results[0].delivered && results[0].queued);
    assert!(results[0]
        .error
        .as_ref()
        .unwrap()
        .contains("recipient_upgrade_required"));
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    outbox.step(now + 300, &revocations, send).await;
    assert_eq!(outbox.len(), 1);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    store.insert(
        recipient,
        MachineId([2; 32]),
        DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]),
        crate::dm::now_unix_ms(),
    );
    let report = outbox.step(now + 600, &revocations, send).await;
    assert_eq!(report.delivered, 1);
    assert_eq!(outbox.len(), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn d08_real_egress_refuses_grants_and_offers_without_network() {
    // AgentBuilder defaults to network_config=None: no NetworkNode, gossip
    // runtime, sockets or daemon are constructed. All storage is scoped here.
    let dir = tempfile::tempdir().unwrap();
    let agent = crate::Agent::builder()
        .with_identity_dir(dir.path())
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_contact_store_path(dir.path().join("contacts.json"))
        .build()
        .await
        .unwrap();
    let recipient = AgentId([3; 32]);
    for payload in [
        crate::share_grant::SHARE_GRANT_DM_PREFIX,
        b"X0X-GROUP-PREDECESSOR-RELAY-V1\n".as_slice(),
    ] {
        let error = agent
            .send_direct_with_config(
                &recipient,
                payload.to_vec(),
                crate::dm::DmSendConfig::default(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, DmError::RecipientUpgradeRequired { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn d08_latest_legacy_advert_clears_bits_and_replay_cannot_restore() {
    let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
    let mut msg = message();
    msg.sender = Some(signing.agent_id);
    msg.sender_public_key = Some(signing.public_key_bytes.clone());
    msg.payload = build_signed_advert(
        &signing,
        signing.agent_id,
        MachineId([2; 32]),
        DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]),
    )
    .unwrap()
    .into();
    let store = CapabilityStore::new();
    let local = AgentId([9; 32]);
    assert!(ingest_verified_capability_advert(&store, local, &msg));
    let mut base = CapabilityAdvert::from_postcard(&msg.payload).unwrap();
    base.created_at_unix_ms += 1;
    base.signature = signing.sign(&base.signed_bytes().unwrap()).unwrap();
    let mut legacy = msg.clone();
    legacy.payload = postcard::to_stdvec(&base).unwrap().into();
    assert!(ingest_verified_capability_advert(&store, local, &legacy));
    assert_eq!(
        store
            .lookup(&signing.agent_id)
            .unwrap()
            .application_registry,
        CapabilityRegistry::default()
    );
    assert!(!ingest_verified_capability_advert(&store, local, &msg));
    assert!(store
        .require_payload_capability(&signing.agent_id, crate::share_grant::SHARE_GRANT_DM_PREFIX)
        .is_err());
}

use super::*;

// An owner with no direct QUIC path to a joiner carries its Welcome frames
// and its join-result response over the gossip inbox (the signed DM
// envelope), under the same ADR 0107 admission, eligibility and deadline as
// the raw path. Raw QUIC stays preferred over a live connection.
//
// The fixtures are in-process (no network). The owner's gossip inbox is the
// test stand-in (`route_gossip_inbox_to_standin_for_testing`): every
// admitted publish is handed to a channel, and the frames are delivered to
// the joiner the way its gossip-inbox listener delivers them, as a verified
// direct message from the envelope's authenticated sender.

use super::adr0107_stuck_join_rearm::{
    build, hex_of, keyed, local_state, serve_result, serve_welcome, welcome_id_of, Fixture,
};

type Frames = Arc<StdMutex<Vec<Vec<u8>>>>;

const WAIT: Duration = Duration::from_secs(10);

fn transports_to(state: &AppState, recipient: &str) -> Vec<(&'static str, &'static str)> {
    state
        .named_group_test_recorders
        .join_artifact_transports
        .lock()
        .expect("transport witness")
        .iter()
        .filter(|(to, _, _)| to == recipient)
        .map(|(_, kind, transport)| (*kind, *transport))
        .collect()
}

fn welcome_ref_of(event: &NamedGroupMetadataEvent) -> Option<WelcomeRef> {
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            welcome_ref: Some(reference),
            ..
        } => Some(reference.clone()),
        _ => None,
    }
}

/// What a frame is to the joiner's listeners.
fn welcome_frame(payload: &[u8]) -> Option<WelcomeBlobMessage> {
    serde_json::from_slice(payload).ok()
}

fn is_offer(payload: &[u8]) -> bool {
    matches!(
        welcome_frame(payload),
        Some(WelcomeBlobMessage::Offer { .. })
    )
}

fn is_chunk(payload: &[u8]) -> bool {
    matches!(
        welcome_frame(payload),
        Some(WelcomeBlobMessage::Chunk { .. })
    )
}

/// Drain the owner's gossip stand-in. Every frame for the joiner is logged;
/// with `deliver`, Welcome frames go to the joiner's real listener dispatch
/// as its gossip inbox hands them over (a verified message from the owner),
/// and each Chunk's ChunkAck goes back to the owner's real handler.
fn carry(
    owner: &Arc<AppState>,
    joiner: &Arc<AppState>,
    mut sink: tokio::sync::mpsc::UnboundedReceiver<(AgentId, Vec<u8>)>,
    deliver: bool,
) -> (Frames, tokio::task::JoinHandle<()>) {
    let frames: Frames = Arc::new(StdMutex::new(Vec::new()));
    let log = Arc::clone(&frames);
    let owner = Arc::clone(owner);
    let joiner = Arc::clone(joiner);
    let task = tokio::spawn(async move {
        let owner_id = owner.agent.agent_id();
        let owner_machine = owner.agent.machine_id();
        let joiner_id = joiner.agent.agent_id();
        while let Some((to, payload)) = sink.recv().await {
            if to != joiner_id {
                continue;
            }
            log.lock().expect("frame log").push(payload.clone());
            if !deliver {
                continue;
            }
            let message = x0x::direct::DirectMessage::new_verified(
                owner_id,
                owner_machine,
                payload,
                true,
                None,
            );
            let Some((sender, frame)) = decode_welcome_blob_message(&message) else {
                continue;
            };
            let ack = match &frame {
                WelcomeBlobMessage::Chunk {
                    welcome_id,
                    sequence,
                    ..
                } => Some(WelcomeBlobMessage::ChunkAck {
                    welcome_id: welcome_id.clone(),
                    sequence: *sequence,
                }),
                _ => None,
            };
            super::super::dispatch_welcome_blob_message(&joiner, sender, frame).await;
            if let Some(ack) = ack {
                super::super::handle_welcome_blob_message(&owner, &joiner_id, ack).await;
            }
        }
    });
    (frames, task)
}

fn logged(frames: &Frames) -> Vec<Vec<u8>> {
    frames.lock().expect("frame log").clone()
}

async fn wait_for_frame(
    frames: &Frames,
    within: Duration,
    matches: impl Fn(&[u8]) -> bool,
) -> bool {
    tokio::time::timeout(within, async {
        while !logged(frames).iter().any(|frame| matches(frame)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// The joiner's real Welcome fetch; its FetchRequest reaches the owner's
/// real fetch handler (in the field it travelled by gossip inbox too).
async fn fetch_welcome(s: &Fixture, reference: &WelcomeRef) -> anyhow::Result<Vec<u8>> {
    let owner = Arc::clone(&s.authority);
    let joiner_id = s.j2.agent.agent_id();
    let fetch = super::super::fetch_treekem_welcome_via(
        &s.j2,
        &s.stable,
        reference,
        move |_, request, _| {
            let owner = Arc::clone(&owner);
            async move {
                super::super::handle_welcome_blob_message(&owner, &joiner_id, request).await;
                Ok(())
            }
        },
    );
    tokio::time::timeout(Duration::from_secs(20), fetch)
        .await
        .map_err(|_| anyhow::anyhow!("the Welcome never arrived over the gossip inbox"))?
        .map_err(|e| anyhow::anyhow!("Welcome fetch failed: {e}"))
}

/// The join result the owner carried to J2 over the gossip inbox: inline,
/// or as a control-blob reference whose chunks J2 pulls (the test sends
/// J2's chunk fetches to the owner's real handler).
async fn carried_join_result(s: &Fixture, frames: &Frames) -> anyhow::Result<JoinResultMessage> {
    let found = tokio::time::timeout(WAIT, async {
        loop {
            for frame in logged(frames) {
                if let Ok(result @ JoinResultMessage::Result { .. }) =
                    serde_json::from_slice::<JoinResultMessage>(&frame)
                {
                    return Ok(result);
                }
                if let Ok(super::super::control_blob::ControlBlobMessage::Reference { reference }) =
                    serde_json::from_slice(&frame)
                {
                    return Err(reference);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("no join result reached the gossip inbox"))?;
    let reference = match found {
        Ok(result) => return Ok(result),
        Err(reference) => reference,
    };
    let byte_len = serde_json::to_value(&reference)?["byte_len"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("reference byte_len"))?;
    let chunks = u32::try_from(x0x::files::total_chunks_for_size(
        byte_len,
        x0x::files::DEFAULT_CHUNK_SIZE,
    ))?;
    let mut bytes = Vec::new();
    for sequence in 0..chunks {
        super::super::control_blob::handle_control_blob_message(
            &s.authority,
            &s.j2.agent.agent_id(),
            true,
            super::super::control_blob::ControlBlobMessage::Fetch {
                reference: reference.clone(),
                sequence,
            },
        )
        .await;
        let data = tokio::time::timeout(WAIT, async {
            loop {
                for frame in logged(frames) {
                    if let Ok(super::super::control_blob::ControlBlobMessage::Chunk {
                        sequence: got,
                        data_b64,
                        ..
                    }) = serde_json::from_slice(&frame)
                    {
                        if got == sequence {
                            return data_b64;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("join-result chunk {sequence} never reached the gossip inbox")
        })?;
        bytes.extend(BASE64.decode(data)?);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// The served result with its Welcome reference replaced by the bytes the
/// joiner fetched (the joiner's own apply-time pull needs a network).
fn with_welcome(result: JoinResultMessage, welcome: &[u8]) -> JoinResultMessage {
    match result {
        JoinResultMessage::Result {
            mut event,
            chain,
            head_attestation,
            roster_certificates_b64,
            intervening_events,
            signed_by,
        } => {
            if let NamedGroupMetadataEvent::MemberAdded {
                treekem_welcome_b64,
                welcome_ref,
                ..
            } = event.as_mut()
            {
                if welcome_ref.take().is_some() {
                    *treekem_welcome_b64 = Some(BASE64.encode(welcome));
                }
            }
            JoinResultMessage::Result {
                signed_by,
                event,
                chain,
                head_attestation,
                roster_certificates_b64,
                intervening_events,
            }
        }
        other => other,
    }
}

async fn encrypt(state: &Arc<AppState>, group: &str, plaintext: &[u8]) -> serde_json::Value {
    let (status, body) = secure_group_encrypt(
        State(Arc::clone(state)),
        Path(group.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(SecureEncryptRequest {
            payload_b64: BASE64.encode(plaintext),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner encrypt: {}", body.0);
    body.0
}

async fn decrypt(
    state: &Arc<AppState>,
    group: &str,
    ciphertext: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = secure_group_decrypt(
        State(Arc::clone(state)),
        Path(group.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(SecureDecryptRequest {
            ciphertext_b64: ciphertext["ciphertext_b64"]
                .as_str()
                .expect("ciphertext")
                .to_string(),
            nonce_b64: String::new(),
            secret_epoch: 0,
        }),
    )
    .await;
    (status, body.0)
}

/// WHY (field failure 2026-11-04): the joiner reached the owner only over
/// the gossip inbox; every owner Welcome frame and the join-result response
/// failed raw-only as "agent not connected", so the joiner was never
/// seated and `/secure/decrypt` answered 403. With no direct connection,
/// the owner now carries them over the gossip inbox: the joiner verifies
/// the Welcome, is seated, and decrypts an owner group message.
#[tokio::test]
async fn without_a_direct_path_the_welcome_and_join_result_ride_the_gossip_inbox(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    assert!(
        !s.authority
            .agent
            .has_live_direct_connection(&s.j2.agent.agent_id())
            .await,
        "precondition: no direct path to the joiner"
    );
    let sink = s
        .authority
        .agent
        .route_gossip_inbox_to_standin_for_testing();
    let (frames, carrier) = carry(&s.authority, &s.j2, sink, true);
    let reference = welcome_ref_of(&s.j2_add).expect("J2's Welcome is staged by reference");

    let welcome = fetch_welcome(&s, &reference).await?;
    assert_eq!(
        super::super::welcome_id_for_bytes(&welcome),
        welcome_id_of(&s.j2_add).expect("welcome id"),
        "the exact staged Welcome arrived and verified"
    );
    let served = serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
        .await
        .expect("the owner serves J2's join result");
    let carried = carried_join_result(&s, &frames).await?;
    assert_eq!(
        serde_json::to_value(&carried)?,
        serde_json::to_value(&served)?,
        "the gossip inbox carried the served join result"
    );
    // The joiner applies it as its control-blob receive does: from the
    // authenticated owner, bound to the attempt the reference names.
    super::super::handle_join_result_message_bound(
        &s.j2,
        &s.authority_id,
        true,
        with_welcome(carried, &welcome),
        Some(&s.j2_attempt),
    )
    .await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(keyed(&s.j2, &s.group_key).await, "the Welcome installed");

    let ciphertext = encrypt(&s.authority, &s.group_key, b"owner says hello").await;
    let (status, body) = decrypt(&s.j2, &s.group_key, &ciphertext).await;
    assert_eq!(status, StatusCode::OK, "joiner decrypt: {body}");
    assert_eq!(
        body["payload_b64"].as_str(),
        Some(BASE64.encode(b"owner says hello").as_str())
    );

    let transports = transports_to(&s.authority, &j2_hex);
    assert!(
        transports
            .iter()
            .any(|(kind, _)| kind.starts_with("welcome"))
            && transports
                .iter()
                .all(|(_, transport)| *transport == "gossip_single_publish"),
        "every owner frame took the admitted gossip publish: {transports:?}"
    );
    carrier.abort();
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Invalidation {
    Ban,
    Removal,
}

async fn invalidate(s: &Fixture, how: Invalidation) -> StatusCode {
    let member = hex_of(&s.j2);
    let extension =
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true });
    match how {
        Invalidation::Ban => ban_group_member(
            State(Arc::clone(&s.authority)),
            extension,
            Path((s.group_key.clone(), member)),
        )
        .await
        .into_response()
        .status(),
        Invalidation::Removal => remove_named_group_member(
            State(Arc::clone(&s.authority)),
            extension,
            Path((s.group_key.clone(), member)),
        )
        .await
        .into_response()
        .status(),
    }
}

/// WHY (ADR 0107 per-frame eligibility): a gossip-carried Welcome stream
/// is stopped by a ban or a removal that lands mid-stream: after its Offer
/// went out by gossip, no chunk leaves once the invalidation commits.
#[tokio::test]
async fn a_ban_or_removal_mid_stream_stops_a_gossip_carried_welcome() -> anyhow::Result<()> {
    for how in [Invalidation::Ban, Invalidation::Removal] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        let sink = s
            .authority
            .agent
            .route_gossip_inbox_to_standin_for_testing();
        let (frames, carrier) = carry(&s.authority, &s.j2, sink, false);
        let frame = super::super::join_egress_test_barrier::arm(&j2_hex, "welcome_frame");
        let purge = super::super::join_egress_test_barrier::arm(&j2_hex, "purge");
        assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
        assert!(
            wait_for_frame(&frames, WAIT, is_offer).await,
            "[{how:?}] the Offer never reached the gossip inbox"
        );
        let reached = tokio::time::timeout(WAIT, async {
            while !frame.gate.reached() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "[{how:?}] the first chunk never reached egress"
        );
        let mutation = {
            let fixture = clone_fixture(&s);
            tokio::spawn(async move { invalidate(&fixture, how).await })
        };
        tokio::time::timeout(WAIT, async {
            while !(mutation.is_finished() || purge.gate.reached()) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        drop(frame);
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(purge);
        assert!(
            mutation.await?.is_success(),
            "[{how:?}] the invalidation committed"
        );
        assert!(
            !logged(&frames).iter().any(|frame| is_chunk(frame)),
            "[{how:?}] a Welcome chunk reached the gossip inbox after the invalidation"
        );
        carrier.abort();
    }
    Ok(())
}

fn clone_fixture(s: &Fixture) -> Fixture {
    Fixture {
        dir: s.dir.clone(),
        authority: Arc::clone(&s.authority),
        authority_id: s.authority_id,
        group_key: s.group_key.clone(),
        stable: s.stable.clone(),
        base: s.base,
        j1: Arc::clone(&s.j1),
        j2: Arc::clone(&s.j2),
        j2_kp: s.j2_kp.clone(),
        j1_attempt: s.j1_attempt.clone(),
        j2_attempt: s.j2_attempt.clone(),
        j1_add: s.j1_add.clone(),
        j2_add: s.j2_add.clone(),
    }
}

/// An admission whose phases both pass.
fn admit_all() -> x0x::dm::ArtifactAdmission {
    Arc::new(|| Box::pin(async { Some(Box::new(|| true) as x0x::dm::SeamAdmission) }))
}

fn refuse_at_seam() -> x0x::dm::ArtifactAdmission {
    Arc::new(|| Box::pin(async { Some(Box::new(|| false) as x0x::dm::SeamAdmission) }))
}

/// The sender knows the recipient by a class A record and a gossip-inbox
/// capability advert.
async fn known_recipient(sender: &AppState, recipient: &AppState) -> anyhow::Result<()> {
    let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
    assert!(sender.agent.capability_store().insert(
        recipient.agent.agent_id(),
        recipient.agent.machine_id(),
        x0x::dm::DmCapabilities::v1_gossip_ready(kem.public_bytes.clone()),
        x0x::dm::now_unix_ms(),
    ));
    let now = now_millis_u64() / 1000;
    sender
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            self_name: None,
            agent_id: recipient.agent.agent_id(),
            machine_id: recipient.agent.machine_id(),
            user_id: None,
            addresses: Vec::new(),
            announced_at: now,
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
    Ok(())
}

/// WHY (path choice): raw QUIC over a live direct connection (it is
/// faster); the gossip inbox when there is none, or when the raw exchange
/// fails as not connected. Class-K shares never take gossip, and a refused
/// admission publishes nothing.
#[tokio::test]
async fn join_artifacts_prefer_raw_and_fall_back_to_the_gossip_inbox() -> anyhow::Result<()> {
    let (sender, _sender_dir) = secure_endpoint_test_state().await?;
    let (recipient, _recipient_dir) = secure_endpoint_test_state().await?;
    let to = recipient.agent.agent_id();
    let to_hex = hex_of(&recipient);
    known_recipient(&sender, &recipient).await?;
    let mut sink = sender.agent.route_gossip_inbox_to_standin_for_testing();
    let deadline = Instant::now() + Duration::from_secs(60);
    let send = |payload: &'static [u8], kind: &'static str, admission| {
        let sender = Arc::clone(&sender);
        async move {
            super::super::send_join_artifact(
                &sender, &to, payload, "group", kind, admission, deadline,
            )
            .await
        }
    };
    let take = |sink: &mut tokio::sync::mpsc::UnboundedReceiver<(AgentId, Vec<u8>)>| {
        let mut out = Vec::new();
        while let Ok((_, payload)) = sink.try_recv() {
            out.push(payload);
        }
        out
    };
    let clear = || {
        sender
            .named_group_test_recorders
            .join_artifact_transports
            .lock()
            .expect("transport witness")
            .clear();
    };
    let live_machine = [recipient.agent.machine_id()];
    let connected = |live: bool| {
        sender.agent.script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(
                if live { &live_machine[..] } else { &[] },
                false,
            ),
        );
    };
    sender
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);

    // No direct connection: the gossip inbox.
    connected(false);
    assert!(!sender.agent.has_live_direct_connection(&to).await);
    clear();
    let sent = send(b"no-path", "welcome_frame", admit_all()).await;
    assert!(sent.is_ok(), "{sent:?}");
    assert_eq!(
        transports_to(&sender, &to_hex),
        vec![("welcome_frame", "gossip_single_publish")]
    );
    assert_eq!(take(&mut sink), vec![b"no-path".to_vec()]);

    // A live connection: raw QUIC, nothing on gossip.
    connected(true);
    assert!(sender.agent.has_live_direct_connection(&to).await);
    clear();
    let _ = send(b"live", "join_result", admit_all()).await;
    assert_eq!(
        transports_to(&sender, &to_hex),
        vec![("join_result", "pinned_single_exchange")]
    );
    assert!(take(&mut sink).is_empty(), "nothing rode gossip");

    // Live, but the raw exchange fails as not connected: the gossip inbox.
    sender
        .agent
        .fail_pinned_sends_as_disconnected_for_testing(1);
    clear();
    let sent = send(b"raw-lost", "welcome_complete", admit_all()).await;
    assert!(sent.is_ok(), "{sent:?}");
    assert_eq!(
        transports_to(&sender, &to_hex),
        vec![
            ("welcome_complete", "pinned_single_exchange"),
            ("welcome_complete", "gossip_single_publish"),
        ]
    );
    assert_eq!(take(&mut sink), vec![b"raw-lost".to_vec()]);

    // A class-K share stays raw-only, even with no direct connection.
    connected(false);
    clear();
    let _ = send(b"share", "secure_share", admit_all()).await;
    assert_eq!(
        transports_to(&sender, &to_hex),
        vec![("secure_share", "pinned_single_exchange")]
    );
    assert!(take(&mut sink).is_empty(), "a share never rides gossip");

    // A refused admission publishes nothing.
    clear();
    let sent = send(b"refused", "welcome_frame", refuse_at_seam()).await;
    assert!(
        sent.as_ref()
            .is_err_and(|reason| reason.contains(x0x::dm::PINNED_ADMISSION_REFUSED)),
        "{sent:?}"
    );
    assert!(take(&mut sink).is_empty(), "a refused frame was published");

    sender
        .agent
        .set_pinned_standin_strict_resolution_for_testing(false);
    Ok(())
}

/// WHY: Welcome frames and join results that arrive by gossip inbox are
/// accepted only from the authenticated owner. The gossip-inbox listener
/// names the envelope's signed sender (`dm_inbox`: the envelope sender must
/// equal the gossip-layer signer) and marks it verified; the Welcome
/// listener drops an unverified frame, the receive accepts frames only
/// from the Welcome reference's source, and a join result only from the
/// pinned inviter. No payload field names the sender.
#[tokio::test]
async fn gossip_carried_frames_from_anyone_but_the_owner_are_refused() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let reference = welcome_ref_of(&s.j2_add).expect("welcome ref");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome id");
    let bytes = s
        .authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .map(|pending| pending.bytes.clone())
        .ok_or_else(|| anyhow::anyhow!("staged Welcome"))?;
    // J2 starts its fetch; the request goes nowhere.
    let pull = {
        let joiner = Arc::clone(&s.j2);
        let stable = s.stable.clone();
        let reference = reference.clone();
        tokio::spawn(async move {
            super::super::fetch_treekem_welcome_via(&joiner, &stable, &reference, |_, _, _| async {
                Ok(())
            })
            .await
        })
    };
    tokio::time::timeout(WAIT, async {
        while !s
            .j2
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&welcome_id)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total = x0x::files::total_chunks_for_size(bytes.len() as u64, chunk_size);
    let mut frames = vec![WelcomeBlobMessage::Offer {
        group_id: s.stable.clone(),
        welcome_id: welcome_id.clone(),
        byte_len: bytes.len() as u64,
        chunk_size,
        total_chunks: total,
        blake3_hex: welcome_id.clone(),
    }];
    for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
        frames.push(WelcomeBlobMessage::Chunk {
            welcome_id: welcome_id.clone(),
            sequence: sequence as u64,
            data: BASE64.encode(chunk),
        });
    }
    frames.push(WelcomeBlobMessage::Complete {
        welcome_id: welcome_id.clone(),
    });
    let deliver_from = |sender: AgentId, machine: x0x::identity::MachineId, verified: bool| {
        let joiner = Arc::clone(&s.j2);
        let frames = frames.clone();
        async move {
            let mut decoded = 0;
            for frame in frames {
                let message = x0x::direct::DirectMessage::new_verified(
                    sender,
                    machine,
                    serde_json::to_vec(&frame).expect("frame"),
                    verified,
                    None,
                );
                if let Some((from, frame)) = decode_welcome_blob_message(&message) {
                    decoded += 1;
                    super::super::dispatch_welcome_blob_message(&joiner, from, frame).await;
                }
            }
            decoded
        }
    };
    let received = || async {
        s.j2.pending_welcome_receives
            .read()
            .await
            .get(&welcome_id)
            .map_or(0, |receive| receive.received_bytes)
    };

    // A verified member that is not the owner.
    let other = s.j1.agent.agent_id();
    assert!(deliver_from(other, s.j1.agent.machine_id(), true).await > 0);
    assert_eq!(received().await, 0, "a non-owner's chunks were accepted");
    assert!(!pull.is_finished(), "a non-owner's frames ended the fetch");
    // The owner's id, unverified: the listener never decodes it.
    assert_eq!(
        deliver_from(s.authority_id, s.authority.agent.machine_id(), false).await,
        0
    );
    assert_eq!(received().await, 0);
    // Control: the authenticated owner's frames complete it.
    deliver_from(s.authority_id, s.authority.agent.machine_id(), true).await;
    let pulled = tokio::time::timeout(WAIT, pull).await??;
    assert_eq!(pulled.map_err(anyhow::Error::msg)?, bytes);

    // A join result from a verified member other than the pinned inviter.
    let served = serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
        .await
        .expect("served");
    super::super::handle_join_result_message_bound(
        &s.j2,
        &other,
        true,
        with_welcome(served.clone(), &bytes),
        Some(&s.j2_attempt),
    )
    .await;
    assert_ne!(
        local_state(&s.j2, &s.group_key).await,
        "active",
        "a join result from a non-inviter seated the joiner"
    );
    assert!(!keyed(&s.j2, &s.group_key).await);
    // Control: the same result from the owner seats it.
    super::super::handle_join_result_message_bound(
        &s.j2,
        &s.authority_id,
        true,
        with_welcome(served, &bytes),
        Some(&s.j2_attempt),
    )
    .await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    Ok(())
}

/// WHY: a gossip-carried frame must fit the DM envelope. The largest Welcome
/// chunk and the largest join-result chunk (`DEFAULT_CHUNK_SIZE` bytes,
/// base64 in JSON) fit `MAX_PAYLOAD_BYTES`, and the sealed, signed envelope
/// that carries them fits `MAX_ENVELOPE_BYTES` and decodes.
#[test]
fn the_largest_chunk_frames_fit_the_gossip_dm_envelope() -> anyhow::Result<()> {
    let data = vec![0xffu8; x0x::files::DEFAULT_CHUNK_SIZE];
    let id = "f".repeat(64);
    let welcome = welcome_blob_payload(&WelcomeBlobMessage::Chunk {
        welcome_id: id.clone(),
        sequence: u64::MAX,
        data: BASE64.encode(&data),
    })
    .map_err(anyhow::Error::msg)?;
    let reference: super::super::control_blob::ControlBlobRef =
        serde_json::from_value(serde_json::json!({
            "kind": "join_result",
            "group_id": id,
            "source": id,
            "recipient": id,
            "digest": id,
            "byte_len": u64::MAX,
            "join_attempt_id": "a".repeat(64),
        }))?;
    let control = super::super::control_blob::encode_message(
        &super::super::control_blob::ControlBlobMessage::Chunk {
            reference,
            sequence: u32::MAX,
            data_b64: BASE64.encode(&data),
        },
    )
    .map_err(anyhow::Error::msg)?;
    let sender = x0x::identity::AgentKeypair::generate()?;
    let machine = x0x::identity::MachineKeypair::generate()?;
    let recipient_kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
    for payload in [welcome, control] {
        assert!(
            payload.len() <= x0x::dm::MAX_PAYLOAD_BYTES,
            "{} > {}",
            payload.len(),
            x0x::dm::MAX_PAYLOAD_BYTES
        );
        let created = x0x::dm::now_unix_ms();
        let envelope = x0x::dm::EnvelopeBuilder::build_payload_envelope_with_version(
            x0x::dm::DM_PROTOCOL_V1,
            [7u8; 16],
            &sender.agent_id(),
            &machine.machine_id(),
            &machine,
            &x0x::identity::AgentId([9u8; 32]),
            &recipient_kem.public_bytes,
            created,
            created + x0x::dm::MAX_ENVELOPE_LIFETIME_MS,
            payload,
            |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(sender.secret_key(), bytes)
                    .map(|sig| sig.as_bytes().to_vec())
                    .map_err(|e| e.to_string())
            },
        )?;
        let wire = envelope.to_wire_bytes()?;
        assert!(
            wire.len() <= x0x::dm::MAX_ENVELOPE_BYTES,
            "{} > {}",
            wire.len(),
            x0x::dm::MAX_ENVELOPE_BYTES
        );
        assert!(x0x::dm::DmEnvelope::from_wire_bytes(&wire).is_ok());
    }
    Ok(())
}

//! #377 — the join-result and Welcome-blob DM receive handlers must honour the
//! transport `verified` annotation before acting on `sender`.
//!
//! On the raw-QUIC direct path the wire envelope is
//! `[0x10][sender_agent_id: 32][payload]` and only the `MachineId` is
//! authenticated by the QUIC handshake — the 32-byte `sender_agent_id` prefix
//! is self-asserted (`crate::direct::DirectMessage::sender`). `verified` is the
//! annotation that says the claimed AgentId→MachineId binding was confirmed
//! against the identity discovery cache; when it is `false` the AgentId is an
//! attacker-chosen string, so every `sender_hex == …` authority comparison in
//! these handlers proves nothing.
//!
//! These controls drive the real handlers. They are RED while the handlers
//! ignore `verified` (the unverified message is acted on) and GREEN once the
//! gate lands. Each control also asserts the verified polarity, so a gate that
//! over-blocks legitimate delivery fails here too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

/// Minimal staged join result: the shape `stage_join_result` records and the
/// `FetchRequest` arm serves back.
fn staged_member_added(
    group_id: &str,
    member_hex: &str,
    inviter_hex: &str,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.to_string(),
        revision: 1,
        actor: inviter_hex.to_string(),
        agent_id: member_hex.to_string(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: Some(1),
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        commit: None,
        certificate_b64: None,
    }
}

/// A staged join result is group state: it carries the authority's `MemberAdded`
/// (and, in production, the TreeKEM Welcome reference for that member). The only
/// thing gating who may pull it is `sender_hex == member_agent_id`, so an
/// unverified requester — whose AgentId is a self-asserted wire prefix — must
/// not be served.
#[tokio::test]
async fn join_result_fetch_request_requires_verified_sender() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let inviter_hex = "aa".repeat(32);
    let group_id = "sec377-join-result-group";

    stage_join_result(
        &state,
        group_id,
        &local_hex,
        staged_member_added(group_id, &local_hex, &inviter_hex),
    )
    .await;

    let mut rx = state.agent.subscribe_direct();
    let fetch = JoinResultMessage::FetchRequest {
        group_id: group_id.to_string(),
        member_agent_id: local_hex.clone(),
        signed_by: None,
        from_revision: None,
        base_state_hash: None,
    };

    // Unverified: the AgentId is attacker-chosen, so the member check is
    // vacuous. Nothing may be sent back.
    handle_join_result_message(&state, &local, false, fetch.clone()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .is_err(),
        "staged join result was served to a requester whose AgentId the transport could not verify"
    );

    // Verified: the legitimate joiner still gets its staged result.
    handle_join_result_message(&state, &local, true, fetch).await;
    let served = tokio::time::timeout(Duration::from_millis(2_000), rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("verified join-result fetch was not served"))?
        .ok_or_else(|| anyhow::anyhow!("direct subscriber closed"))?;
    assert!(
        matches!(
            serde_json::from_slice::<JoinResultMessage>(&served.payload)?,
            JoinResultMessage::Result { .. }
        ),
        "verified fetch must be answered with the staged Result"
    );

    Ok(())
}

/// A mismatching `Offer` aborts an in-flight Welcome fetch: it drops the pending
/// receive and fails every waiter, which fails the joiner's group join. The only
/// gate is `receive.source == sender_hex`, so an unverified peer that guesses (or
/// observes) a `welcome_id` could grief any join. An unverified offer must be
/// ignored outright.
#[tokio::test]
async fn welcome_blob_offer_requires_verified_sender() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let source = AgentId([7_u8; 32]);
    let source_hex = hex::encode(source.as_bytes());
    let welcome_id = "sec377-welcome-id".to_string();

    let stage_receive = || async {
        state.pending_welcome_receives.write().await.insert(
            welcome_id.clone(),
            PendingWelcomeReceive {
                group_id: "sec377-welcome-group".to_string(),
                source: source_hex.clone(),
                byte_len: 8,
                total_chunks: 1,
                chunks: BTreeMap::new(),
                received_bytes: 0,
            },
        );
    };

    // An offer that does not match the requested reference — the abort path.
    let bad_offer = WelcomeBlobMessage::Offer {
        group_id: "sec377-other-group".to_string(),
        welcome_id: welcome_id.clone(),
        byte_len: 8,
        chunk_size: x0x::files::DEFAULT_CHUNK_SIZE,
        total_chunks: 1,
        blake3_hex: welcome_id.clone(),
    };

    stage_receive().await;
    handle_welcome_blob_message(&state, &source, false, bad_offer.clone()).await;
    assert!(
        state
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&welcome_id),
        "an unverified peer aborted an in-flight Welcome fetch"
    );

    // Verified: the genuine source can still abort a mismatched transfer.
    handle_welcome_blob_message(&state, &source, true, bad_offer).await;
    assert!(
        !state
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&welcome_id),
        "a verified mismatching offer must still clear the pending receive"
    );

    Ok(())
}

/// The transport-verified bypass admits ONLY self-authenticating shapes.
/// A phone-embedded engine has no discovery presence, so its events always
/// arrive `verified=false`; shapes whose apply arms re-prove authorship
/// cryptographically must reach those arms (a self-delivered original join,
/// admin moderation with a signed state commit), and everything else must
/// keep failing closed at the gate (#377).
#[test]
fn transport_verified_bypass_admits_only_self_authenticating_shapes() {
    let dummy_commit = x0x::groups::GroupStateCommit {
        group_id: "g".to_string(),
        revision: 1,
        prev_state_hash: None,
        roster_root: String::new(),
        policy_hash: String::new(),
        public_meta_hash: String::new(),
        security_binding: None,
        state_hash: String::new(),
        withdrawn: false,
        committed_by: "aa".repeat(32),
        committed_at: 1,
        signer_public_key: String::new(),
        signature: String::new(),
    };
    let member_joined = |recovery: Option<String>| NamedGroupMetadataEvent::MemberJoined {
        group_id: "g".to_string(),
        stable_group_id: None,
        member_agent_id: "bb".repeat(32),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: "aa".repeat(32),
        invite_secret: "s".to_string(),
        ts_ms: 1,
        treekem_key_package_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: recovery,
        recovery_authority_commit: None,
        signature_b64: String::new(),
    };
    assert!(metadata_event_bypasses_transport_verified(&member_joined(
        None
    )));
    assert!(
        !metadata_event_bypasses_transport_verified(&member_joined(Some("x".to_string()))),
        "the recovery-courier shape trusts the transport sender claim and must stay gated"
    );

    let banned =
        |commit: Option<x0x::groups::GroupStateCommit>| NamedGroupMetadataEvent::MemberBanned {
            group_id: "g".to_string(),
            revision: 1,
            actor: "aa".repeat(32),
            agent_id: "bb".repeat(32),
            secret_epoch: None,
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit,
        };
    assert!(metadata_event_bypasses_transport_verified(&banned(Some(
        dummy_commit.clone()
    ))));
    assert!(!metadata_event_bypasses_transport_verified(&banned(None)));

    assert!(metadata_event_bypasses_transport_verified(
        &NamedGroupMetadataEvent::MemberUnbanned {
            group_id: "g".to_string(),
            revision: 1,
            actor: "aa".repeat(32),
            agent_id: "bb".repeat(32),
            commit: Some(dummy_commit.clone()),
        }
    ));
    assert!(metadata_event_bypasses_transport_verified(
        &NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: "g".to_string(),
            revision: 1,
            actor: "aa".repeat(32),
            agent_id: "bb".repeat(32),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(dummy_commit),
        }
    ));

    assert!(
        !metadata_event_bypasses_transport_verified(
            &NamedGroupMetadataEvent::GroupMetadataUpdated {
                group_id: "g".to_string(),
                revision: 1,
                actor: "aa".repeat(32),
                name: Some("x".to_string()),
                description: None,
                commit: None,
            }
        ),
        "non-self-authenticating events keep the #377 fail-closed gate"
    );
}

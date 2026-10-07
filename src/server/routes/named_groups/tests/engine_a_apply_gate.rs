//! The engine-A local-apply endpoint (`POST /groups/:id/apply-metadata-event`)
//! applies with the transport gate cleared for a caller-asserted sender, so it
//! must never admit a shape that trusts that sender. It admits commit-signed
//! events and the self-signed original `MemberJoined` (what fetch>it relays:
//! the bridged join and the group log's commit-only `MemberAdded`), and
//! refuses the recovery courier, `SecureShareDelivered`, `GroupCardPublished`
//! and any commit-less event.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

async fn post_apply(
    state: &Arc<AppState>,
    group_id: &str,
    event: &NamedGroupMetadataEvent,
    sender_hex: &str,
) -> Result<(StatusCode, String)> {
    let response = apply_group_metadata_event(
        State(Arc::clone(state)),
        Path(group_id.to_string()),
        Json(ApplyMetadataEventRequest {
            event_b64: BASE64.encode(serde_json::to_vec(event)?),
            sender_agent_id: sender_hex.to_string(),
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body =
        String::from_utf8_lossy(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)
            .to_string();
    Ok((status, body))
}

#[tokio::test]
async fn engine_a_apply_refuses_the_recovery_courier_and_admits_the_original_join() -> Result<()> {
    use base64::Engine as _;

    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "7a".repeat(32);
    let group_id = group_id_storage.as_str();
    let group_id_bytes = hex::decode(group_id)?;
    let inviter = state.agent.agent_id();
    let inviter_hex = hex::encode(inviter.as_bytes());
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), inviter, &seed)?;
    let group = Arc::new(Mutex::new(group));
    state
        .treekem_groups
        .write()
        .await
        .insert(group_id.to_string(), Arc::clone(&group));
    let mut info = treekem_metadata_group_info(inviter, group_id, group_id);
    let now_ms = now_millis_u64();
    let joiner_keypair = x0x::identity::AgentKeypair::generate()?;
    let joiner_id = joiner_keypair.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let joiner_pub_b64 = BASE64.encode(joiner_keypair.public_key().as_bytes());
    let invite1 = "rekey-333-invite-1".to_string();
    info.record_issued_invite(
        invite1.clone(),
        now_ms / 1_000,
        0,
        x0x::groups::GroupRole::Member,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);

    let signed_join = |invite_secret: &str, kp_b64: &str, ts_ms: u64| -> Result<_> {
        let canonical = canonical_member_joined_bytes(
            group_id,
            Some(group_id),
            &joiner_hex,
            &joiner_pub_b64,
            x0x::groups::GroupRole::Member,
            None,
            &inviter_hex,
            invite_secret,
            ts_ms,
            Some(kp_b64),
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            joiner_keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign MemberJoined: {e:?}"))?;
        Ok(NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.to_string(),
            stable_group_id: Some(group_id.to_string()),
            member_agent_id: joiner_hex.clone(),
            member_public_key_b64: joiner_pub_b64.clone(),
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: inviter_hex.clone(),
            invite_secret: invite_secret.to_string(),
            ts_ms,
            treekem_key_package_b64: Some(kp_b64.to_string()),
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
            certificate_b64: None,
            kem_public_key_b64: None,
            kem_signature_b64: None,
        })
    };

    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(joiner_id, &[0x7b; 32])?;
    let kp_b64 = BASE64.encode(prepared.key_package_bytes());
    let join = signed_join(&invite1, &kp_b64, now_ms)?;

    let mut courier = join.clone();
    if let NamedGroupMetadataEvent::MemberJoined {
        recovery_authority_agent_id,
        recovery_authority_signature_b64,
        ..
    } = &mut courier
    {
        *recovery_authority_agent_id = Some(inviter_hex.clone());
        *recovery_authority_signature_b64 = Some("attestation".to_string());
    }
    let (status, body) = post_apply(&state, group_id, &courier, &joiner_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body.contains("recovery_courier_needs_verified_sender"),
        "{body}"
    );
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group")
            .has_active_member(&joiner_hex),
        "the refused courier must not seat anybody"
    );

    let (status, body) = post_apply(&state, group_id, &join, &joiner_hex).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the original join must still apply: {body}"
    );
    assert!(state
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("group")
        .has_active_member(&joiner_hex));
    let _ = group;
    Ok(())
}

#[tokio::test]
async fn engine_a_apply_refuses_events_that_authorize_on_the_sender_alone() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "ab".repeat(32);
    let share = NamedGroupMetadataEvent::SecureShareDelivered {
        group_id: group_id.clone(),
        recipient: admin.clone(),
        secret_epoch: 2,
        kem_ciphertext_b64: String::new(),
        aead_nonce_b64: String::new(),
        aead_ciphertext_b64: String::new(),
        actor: admin.clone(),
    };
    let card = NamedGroupMetadataEvent::GroupCardPublished {
        group_id: group_id.clone(),
        card: x0x::groups::GroupCard {
            group_id: group_id.clone(),
            name: "spoof".into(),
            description: String::new(),
            avatar_url: None,
            banner_url: None,
            tags: Vec::new(),
            policy_summary: x0x::groups::GroupPolicySummary {
                discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
                admission: x0x::groups::GroupAdmission::RequestAccess,
                confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
                read_access: x0x::groups::GroupReadAccess::MembersOnly,
                write_access: x0x::groups::GroupWriteAccess::MembersOnly,
            },
            owner_agent_id: admin.clone(),
            admin_count: 1,
            member_count: 1,
            created_at: 0,
            updated_at: 0,
            request_access_enabled: true,
            metadata_topic: None,
            revision: 1,
            state_hash: String::new(),
            prev_state_hash: None,
            issued_at: 1,
            expires_at: 2,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn: false,
            signature: String::new(),
        },
    };
    let unsigned_rename = NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: group_id.clone(),
        revision: 1,
        actor: admin.clone(),
        name: Some("spoof".into()),
        description: None,
        commit: None,
    };
    for (event, reason) in [
        (share, "secure_share_needs_verified_sender"),
        (card, "group_card_needs_verified_sender"),
        (unsigned_rename, "unsigned_event_needs_verified_sender"),
    ] {
        let (status, body) = post_apply(&state, &group_id, &event, &admin).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains(reason), "{body}");
    }
    Ok(())
}

async fn get_inline(
    state: &Arc<AppState>,
    group_id: &str,
    member_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = get_join_result_inline(
        State(Arc::clone(state)),
        Path((group_id.to_string(), member_hex.to_string())),
    )
    .await
    .into_response();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&body)?))
}

/// The bridged `GET /groups/:id/join-result/:member` door hands out the same
/// recovery bytes as the fetch path, so it runs the ADR 0107 serving guard:
/// a member with no Active seat on the current roster gets nothing, and its
/// staged result is purged; an Active member is served; an unknown group is
/// a 404 that creates no lock-registry entry.
#[tokio::test]
async fn get_join_result_inline_runs_the_serving_guard() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id_storage = "7b".repeat(32);
    let group_id = group_id_storage.as_str();
    let inviter = state.agent.agent_id();
    let inviter_hex = hex::encode(inviter.as_bytes());
    let joiner_hex = hex::encode(
        x0x::identity::AgentKeypair::generate()?
            .agent_id()
            .as_bytes(),
    );
    state.named_groups.write().await.insert(
        group_id.to_string(),
        treekem_metadata_group_info(inviter, group_id, group_id),
    );
    let staged_add = NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.to_string(),
        revision: 2,
        actor: inviter_hex.clone(),
        agent_id: joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some("commit".into()),
        treekem_welcome_b64: Some("V0VMQ09NRQ==".into()),
        welcome_ref: None,
        treekem_epoch: Some(2),
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        roster_certificates_b64: Vec::new(),
        commit: None,
    };
    let key = join_result_key(group_id, &joiner_hex);

    let (status, body) = get_inline(&state, &"00".repeat(32), &joiner_hex).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "group_unknown");

    // Staged for a member the roster does not seat: refused and purged.
    stage_join_result(&state, group_id, &joiner_hex, staged_add.clone(), None).await;
    assert!(state.pending_join_results.read().await.contains_key(&key));
    let (status, body) = get_inline(&state, group_id, &joiner_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "member_not_active");
    assert!(
        !state.pending_join_results.read().await.contains_key(&key),
        "a definitive refusal purges the staged result"
    );

    // Seated on the current roster: served, with the inline Welcome intact.
    state
        .named_groups
        .write()
        .await
        .get_mut(group_id)
        .expect("group")
        .add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    stage_join_result(&state, group_id, &joiner_hex, staged_add, None).await;
    let (status, body) = get_inline(&state, group_id, &joiner_hex).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["event"].to_string().contains("V0VMQ09NRQ=="),
        "the served event carries the inline Welcome: {body}"
    );
    Ok(())
}

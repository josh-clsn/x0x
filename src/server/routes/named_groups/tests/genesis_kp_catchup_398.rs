//! #398 — a genesis/base-roster member's TreeKEM KeyPackage must be
//! recoverable by an invited admin.
//!
//! The targeted member-key catch-up served only from the cached
//! `MemberJoined` store, and the group creator never emitted a
//! `MemberJoined` — so every response came back empty, the requester's
//! removal pre-check 424'd (`member_key_package_pending`) forever, and an
//! invited admin could never ban a genesis member (found live in the
//! gov-trio device test). These controls drive the roster-fallback serve
//! lane and the hash-anchored requester-side apply.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

const FAKE_KP_B64: &str = "ZmFrZS10cmVla2VtLWtleS1wYWNrYWdlLWJ5dGVz";

fn group_with_creator_kp(
    creator: AgentId,
    kp_b64: Option<&str>,
) -> (x0x::groups::GroupInfo, String) {
    let creator_hex = hex::encode(creator.as_bytes());
    let mut info = x0x::groups::GroupInfo::with_policy(
        "g398".to_string(),
        "d".to_string(),
        creator,
        "ee".repeat(16),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    if let Some(kp) = kp_b64 {
        info.set_member_treekem_key_package(&creator_hex, kp.to_string());
    }
    (info, creator_hex)
}

/// The serve half: with the join-event cache empty (the permanent state for
/// a genesis member), the targeted response must carry the roster-fallback
/// KeyPackage and echo the target member id.
#[tokio::test]
async fn targeted_catchup_serves_roster_fallback_for_genesis_member() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let (info, creator_hex) = group_with_creator_kp(creator, Some(FAKE_KP_B64));
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: "bb".repeat(32),
        from_revision: 1,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: Some(creator_hex.clone()),
        limit: 8,
        signed_by: None,
    };
    let response = member_keyed_treekem_catchup_response(&state, &[group_id], &request)
        .await
        .expect("targeted request against a known group must produce a response");
    assert!(
        response.events.is_empty(),
        "no MemberJoined ever existed for a genesis member"
    );
    assert_eq!(
        response.target_member_id.as_deref(),
        Some(creator_hex.as_str())
    );
    assert_eq!(
        response.target_member_key_package_b64.as_deref(),
        Some(FAKE_KP_B64),
        "the roster-fallback lane must serve the full KeyPackage"
    );
    Ok(())
}

/// A member whose roster entry has no full package on the RESPONDER either
/// yields no fallback — the response degrades to the old empty shape.
#[tokio::test]
async fn targeted_catchup_serves_nothing_without_roster_package() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let (info, creator_hex) = group_with_creator_kp(creator, None);
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: "bb".repeat(32),
        from_revision: 1,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: Some(creator_hex),
        limit: 8,
        signed_by: None,
    };
    let response = member_keyed_treekem_catchup_response(&state, &[group_id], &request)
        .await
        .expect("response still produced");
    assert!(response.target_member_key_package_b64.is_none());
    Ok(())
}

/// The apply half: a fallback package matching the locally-anchored hash is
/// stored, after which the removal pre-check resolves instead of 424ing.
#[tokio::test]
async fn targeted_kp_applies_on_hash_match_and_unblocks_removal() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let (mut info, creator_hex) = group_with_creator_kp(creator, None);
    // The invite-derived state: hash anchor only, no package bytes — the
    // exact phone-side roster shape from the device test.
    let anchor = blake3::hash(FAKE_KP_B64.as_bytes()).to_hex().to_string();
    info.set_member_treekem_key_package_hash(&creator_hex, anchor);
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    assert!(
        apply_targeted_member_key_package(&state, &group_id, &creator_hex, FAKE_KP_B64).await,
        "a hash-matching fallback package must be stored"
    );
    let resolved = resolve_member_treekem_kp_for_removal(&state, &group_id, &creator_hex)
        .await
        .expect("removal pre-check must now resolve the package");
    assert_eq!(resolved, FAKE_KP_B64);
    Ok(())
}

/// A package that does not match the anchor is refused and nothing is
/// stored — a hostile responder cannot substitute its own key material.
#[tokio::test]
async fn targeted_kp_refuses_hash_mismatch() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let (mut info, creator_hex) = group_with_creator_kp(creator, None);
    info.set_member_treekem_key_package_hash(
        &creator_hex,
        blake3::hash(b"a different package").to_hex().to_string(),
    );
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    assert!(!apply_targeted_member_key_package(&state, &group_id, &creator_hex, FAKE_KP_B64).await);
    let groups = state.named_groups.read().await;
    let member = groups[&group_id].members_v2.get(&creator_hex).unwrap();
    assert!(member.treekem_key_package_b64.is_none(), "nothing stored");
    Ok(())
}

/// The signer attachment proves the claimed agent authored the canonical
/// input: right key + right input accepted; wrong claimed id, tampered
/// input, and garbage signatures all refused.
#[tokio::test]
async fn catchup_signer_verifies_and_refuses() -> Result<()> {
    let kp = x0x::identity::AgentKeypair::generate()?;
    let agent_hex = hex::encode(kp.agent_id().as_bytes());
    let input = member_keyed_request_sign_input("g", &agent_hex, "t");
    let signature =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(kp.secret_key(), &input)
            .expect("sign");
    let signer = CatchupSigner {
        public_key_b64: BASE64.encode(kp.public_key().as_bytes()),
        signature_b64: BASE64.encode(signature.as_bytes()),
    };
    assert!(catchup_signer_matches(&signer, &agent_hex, &input));
    assert!(
        !catchup_signer_matches(&signer, &"ab".repeat(32), &input),
        "key does not derive the claimed agent id"
    );
    assert!(
        !catchup_signer_matches(
            &signer,
            &agent_hex,
            &member_keyed_request_sign_input("g", &agent_hex, "other")
        ),
        "signature does not cover a different input"
    );
    let garbage = CatchupSigner {
        public_key_b64: signer.public_key_b64.clone(),
        signature_b64: BASE64.encode([7u8; 64]),
    };
    assert!(!catchup_signer_matches(&garbage, &agent_hex, &input));
    Ok(())
}

/// The serve half attaches a signer that verifies against the responder's
/// own agent id and binds the served package's blake3 digest — the shape
/// the requester-side gate demands before an unverified-transport apply.
#[tokio::test]
async fn targeted_response_carries_valid_signer() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let (info, creator_hex) = group_with_creator_kp(creator, Some(FAKE_KP_B64));
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: "bb".repeat(32),
        from_revision: 1,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: Some(creator_hex.clone()),
        limit: 8,
        signed_by: None,
    };
    let response =
        member_keyed_treekem_catchup_response(&state, std::slice::from_ref(&group_id), &request)
            .await
            .expect("response");
    let signer = response.signed_by.expect("targeted responses are signed");
    let responder_hex = hex::encode(state.agent.agent_id().as_bytes());
    let kp_hash = blake3::hash(FAKE_KP_B64.as_bytes()).to_hex().to_string();
    assert!(catchup_signer_matches(
        &signer,
        &responder_hex,
        &member_keyed_response_sign_input(&group_id, &creator_hex, &kp_hash),
    ));
    Ok(())
}

/// Build a valid signer over `input` for `kp`.
fn signer_for(kp: &x0x::identity::AgentKeypair, input: &[u8]) -> CatchupSigner {
    let signature =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(kp.secret_key(), input)
            .expect("sign");
    CatchupSigner {
        public_key_b64: BASE64.encode(kp.public_key().as_bytes()),
        signature_b64: BASE64.encode(signature.as_bytes()),
    }
}

/// Request gate: an unverified-transport member-keyed request with a valid
/// signer is admitted (observable: the member-keyed serve throttle entry is
/// taken), while the same request without a signer is dropped at the gate.
#[tokio::test]
async fn request_gate_admits_signed_and_drops_unsigned_when_unverified() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let kp = x0x::identity::AgentKeypair::generate()?;
    let creator = kp.agent_id();
    let (info, creator_hex) = group_with_creator_kp(creator, Some(FAKE_KP_B64));
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let target = "cc".repeat(32);
    let mut request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: creator_hex.clone(),
        from_revision: 1,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: Some(target.clone()),
        limit: 8,
        signed_by: None,
    };
    handle_treekem_catchup_request(&state, &creator, false, request.clone()).await;
    let throttle_key = format!("{group_id}:mk-serve:{creator_hex}:{target}");
    assert!(
        !state
            .treekem_catchup_throttle
            .read()
            .await
            .contains_key(&throttle_key),
        "unsigned unverified request must be dropped before the serve lane"
    );

    request.signed_by = Some(signer_for(
        &kp,
        &member_keyed_request_sign_input(&group_id, &creator_hex, &target),
    ));
    handle_treekem_catchup_request(&state, &creator, false, request).await;
    assert!(
        state
            .treekem_catchup_throttle
            .read()
            .await
            .contains_key(&throttle_key),
        "signed unverified request must reach the member-keyed serve lane"
    );
    Ok(())
}

/// Response gate: an unverified-transport targeted response with a valid
/// signer is admitted into the hash-anchored KeyPackage apply — the full
/// phone-side heal in miniature — and, per the #377 posture, leaves no
/// trace of membership-event processing (`targeted_only` returns before
/// the events loop; the pending-event queue stays empty).
#[tokio::test]
async fn response_gate_applies_signed_kp_without_touching_events() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let kp = x0x::identity::AgentKeypair::generate()?;
    let creator = kp.agent_id();
    let (mut info, creator_hex) = group_with_creator_kp(creator, None);
    let anchor = blake3::hash(FAKE_KP_B64.as_bytes()).to_hex().to_string();
    info.set_member_treekem_key_package_hash(&creator_hex, anchor);
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let kp_hash = blake3::hash(FAKE_KP_B64.as_bytes()).to_hex().to_string();
    let mut response = TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.clone(),
        events: vec![NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: group_id.clone(),
            revision: 99,
            actor: creator_hex.clone(),
            name: Some("hijacked".to_string()),
            description: None,
            commit: None,
        }],
        truncated: false,
        target_member_id: Some(creator_hex.clone()),
        target_member_key_package_b64: Some(FAKE_KP_B64.to_string()),
        signed_by: None,
    };

    // Unsigned + unverified: dropped at the gate — nothing stored.
    handle_treekem_catchup_response(&state, &creator, false, response.clone()).await;
    {
        let groups = state.named_groups.read().await;
        assert!(
            groups[&group_id].members_v2[&creator_hex]
                .treekem_key_package_b64
                .is_none(),
            "unsigned unverified response must not store"
        );
    }

    response.signed_by = Some(signer_for(
        &kp,
        &member_keyed_response_sign_input(&group_id, &creator_hex, &kp_hash),
    ));
    handle_treekem_catchup_response(&state, &creator, false, response).await;
    let groups = state.named_groups.read().await;
    assert_eq!(
        groups[&group_id].members_v2[&creator_hex]
            .treekem_key_package_b64
            .as_deref(),
        Some(FAKE_KP_B64),
        "signed unverified response must reach the anchored apply"
    );
    assert_eq!(
        groups[&group_id].name, "g398",
        "membership events from an unverified transport must not apply"
    );
    assert!(
        state
            .treekem_pending_events
            .read()
            .await
            .get(&group_id)
            .is_none_or(|q| q.is_empty()),
        "targeted-only handling must not queue events either"
    );
    Ok(())
}

/// The join-result wire's signer acceptance: a fetch signed by the member
/// it names is admitted; wrong signer identity, wrong input binding, and
/// unsigned messages are all refused — same matrix as the catch-up wire.
#[tokio::test]
async fn join_result_signer_matrix() -> Result<()> {
    let kp = x0x::identity::AgentKeypair::generate()?;
    let member_hex = hex::encode(kp.agent_id().as_bytes());

    let signed_fetch = JoinResultMessage::FetchRequest {
        group_id: "g".to_string(),
        member_agent_id: member_hex.clone(),
        signed_by: Some(signer_for(
            &kp,
            &join_result_fetch_sign_input("g", &member_hex),
        )),
    };
    assert!(join_result_signed_ok(&signed_fetch, &member_hex));
    assert!(
        !join_result_signed_ok(&signed_fetch, &"ab".repeat(32)),
        "signer must prove the transport-claimed sender"
    );

    let unsigned_fetch = JoinResultMessage::FetchRequest {
        group_id: "g".to_string(),
        member_agent_id: member_hex.clone(),
        signed_by: None,
    };
    assert!(!join_result_signed_ok(&unsigned_fetch, &member_hex));

    let cross_group = JoinResultMessage::FetchRequest {
        group_id: "other".to_string(),
        member_agent_id: member_hex.clone(),
        signed_by: Some(signer_for(
            &kp,
            &join_result_fetch_sign_input("g", &member_hex),
        )),
    };
    assert!(
        !join_result_signed_ok(&cross_group, &member_hex),
        "signature is bound to the group id"
    );
    Ok(())
}

/// A member with no local hash anchor is unverifiable — refuse rather than
/// trust a bare peer-supplied package.
#[tokio::test]
async fn targeted_kp_refuses_without_local_anchor() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let creator = x0x::identity::AgentKeypair::generate()?.agent_id();
    let (info, creator_hex) = group_with_creator_kp(creator, None);
    let group_id = info.mls_group_id.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    assert!(!apply_targeted_member_key_package(&state, &group_id, &creator_hex, FAKE_KP_B64).await);
    Ok(())
}

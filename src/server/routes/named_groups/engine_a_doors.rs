//! What the engine-A apply door refuses before it applies anything.
//!
//! The door takes the sender from its caller and clears the transport gate,
//! so it admits only events whose authority does not rest on that claim: an
//! event carrying a signed state commit (its arm verifies the signature, the
//! chain link and the state hash against the local roster) and the joiner's
//! own self-signed `MemberJoined`. Everything else authorizes on the sender
//! alone and is refused with a `reason`.
//!
//! The caller's `sender_agent_id` is a claim the door cannot check, so the
//! event's `actor` must be the verified signer of its commit: a member cannot
//! carry another member's self-leave, or sign in another's name.
//!
//! A removal or ban that carries TreeKEM bytes is admitted only when its
//! signed binding names those bytes. Upstream's self-leave seal does
//! (`treekem:epoch=<n>:commit=<d>`); the admin removal (`treekem:epoch=<n>`)
//! does not, so a deliverer could swap its bytes.

use super::{named_group_metadata_event_commit, treekem_commit_binding, NamedGroupMetadataEvent};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

pub(super) const UNNAMED_BYTES_REASON: &str = "needs_verified_signer_and_named_tree_bytes";
pub(super) const ACTOR_NOT_SIGNER_REASON: &str = "event_actor_is_not_the_commit_signer";
pub(super) const AUTHOR_ONLY_REASON: &str = "author_only_event_needs_verified_sender";

/// The join-request lifecycle stays with its author: each applies fields its
/// commit does not cover.
fn author_only(event: &NamedGroupMetadataEvent) -> bool {
    matches!(
        event,
        NamedGroupMetadataEvent::JoinRequestCreated { .. }
            | NamedGroupMetadataEvent::JoinRequestRejected { .. }
            | NamedGroupMetadataEvent::JoinRequestCancelled { .. }
    )
}

fn actor_of(event: &NamedGroupMetadataEvent) -> Option<&str> {
    match event {
        NamedGroupMetadataEvent::MemberAdded { actor, .. }
        | NamedGroupMetadataEvent::MemberRemoved { actor, .. }
        | NamedGroupMetadataEvent::MemberBanned { actor, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { actor, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { actor, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { actor, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { actor, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { actor, .. }
        | NamedGroupMetadataEvent::GroupDeleted { actor, .. } => Some(actor),
        _ => None,
    }
}

/// The event's `actor` is the verified signer of its commit.
fn actor_signed_the_commit(event: &NamedGroupMetadataEvent) -> bool {
    let Some(commit) = named_group_metadata_event_commit(event) else {
        return false;
    };
    actor_of(event).is_some_and(|actor| actor == commit.committed_by)
        && commit.verify_structure().is_ok()
}

/// Whether the removal's or ban's signed binding names the TreeKEM bytes it
/// carries. An event with no TreeKEM bytes has none to swap.
fn removal_names_its_bytes(
    event: &NamedGroupMetadataEvent,
    commit_b64: Option<&String>,
    epoch: Option<u64>,
) -> bool {
    match (commit_b64, epoch) {
        (None, None) => true,
        (Some(commit_b64), Some(epoch)) => {
            let Ok(bytes) = BASE64.decode(commit_b64) else {
                return false;
            };
            named_group_metadata_event_commit(event)
                .and_then(|commit| commit.security_binding.as_deref())
                .is_some_and(|binding| binding == treekem_commit_binding(epoch, &bytes))
        }
        _ => false,
    }
}

/// The `reason` the door refuses `event` with, or `None` to admit it.
pub(super) fn apply_refusal(event: &NamedGroupMetadataEvent) -> Option<&'static str> {
    match event {
        NamedGroupMetadataEvent::MemberJoined {
            recovery_authority_signature_b64: Some(_),
            ..
        } => return Some("recovery_courier_needs_verified_sender"),
        NamedGroupMetadataEvent::MemberJoined { .. } => return None,
        NamedGroupMetadataEvent::SecureShareDelivered { .. } => {
            return Some("secure_share_needs_verified_sender");
        }
        NamedGroupMetadataEvent::GroupCardPublished { .. } => {
            return Some("group_card_needs_verified_sender");
        }
        other if named_group_metadata_event_commit(other).is_some() => {}
        _ => return Some("unsigned_event_needs_verified_sender"),
    }
    if author_only(event) {
        return Some(AUTHOR_ONLY_REASON);
    }
    if !actor_signed_the_commit(event) {
        return Some(ACTOR_NOT_SIGNER_REASON);
    }
    match event {
        NamedGroupMetadataEvent::MemberRemoved {
            treekem_commit_b64,
            treekem_epoch,
            ..
        }
        | NamedGroupMetadataEvent::MemberBanned {
            treekem_commit_b64,
            treekem_epoch,
            ..
        } if !removal_names_its_bytes(event, treekem_commit_b64.as_ref(), *treekem_epoch) => {
            Some(UNNAMED_BYTES_REASON)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn signer() -> crate::identity::AgentKeypair {
        crate::identity::AgentKeypair::generate().unwrap()
    }

    fn hex_id(kp: &crate::identity::AgentKeypair) -> String {
        hex::encode(kp.agent_id().as_bytes())
    }

    fn commit(
        kp: &crate::identity::AgentKeypair,
        binding: Option<String>,
    ) -> crate::groups::GroupStateCommit {
        crate::groups::GroupStateCommit::sign(
            "g".into(),
            2,
            None,
            String::new(),
            String::new(),
            String::new(),
            binding,
            false,
            0,
            kp,
        )
        .unwrap()
    }

    fn removal(
        kp: &crate::identity::AgentKeypair,
        bytes: Option<&[u8]>,
        epoch: Option<u64>,
        binding: Option<String>,
    ) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".into(),
            revision: 2,
            actor: hex_id(kp),
            agent_id: "bb".into(),
            treekem_commit_b64: bytes.map(|b| BASE64.encode(b)),
            treekem_epoch: epoch,
            secret_epoch: None,
            commit: Some(commit(kp, binding)),
        }
    }

    fn update(kp: &crate::identity::AgentKeypair, signed: bool) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "g".into(),
            revision: 2,
            actor: hex_id(kp),
            name: Some("n".into()),
            description: None,
            commit: signed.then(|| commit(kp, None)),
        }
    }

    #[test]
    fn stock_self_leave_rekey_is_admitted() {
        let kp = signer();
        let bytes = b"treekem commit bytes";
        let binding = treekem_commit_binding(7, bytes);
        let event = removal(&kp, Some(bytes), Some(7), Some(binding));
        assert_eq!(apply_refusal(&event), None);
    }

    #[test]
    fn stock_legacy_admin_removal_is_refused_with_a_reason() {
        let kp = signer();
        let event = removal(
            &kp,
            Some(b"treekem commit bytes"),
            Some(7),
            Some("treekem:epoch=7".into()),
        );
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn a_removal_whose_binding_names_other_bytes_is_refused() {
        let kp = signer();
        let binding = treekem_commit_binding(7, b"other bytes");
        let event = removal(&kp, Some(b"treekem commit bytes"), Some(7), Some(binding));
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn a_removal_with_half_its_tree_fields_is_refused() {
        let kp = signer();
        let event = removal(&kp, Some(b"bytes"), None, Some("treekem:epoch=7".into()));
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn a_removal_without_tree_bytes_is_admitted() {
        let kp = signer();
        assert_eq!(apply_refusal(&removal(&kp, None, None, None)), None);
    }

    #[test]
    fn a_ban_carrying_tree_bytes_is_refused() {
        let kp = signer();
        let event = NamedGroupMetadataEvent::MemberBanned {
            group_id: "g".into(),
            revision: 2,
            actor: hex_id(&kp),
            agent_id: "bb".into(),
            secret_epoch: None,
            treekem_commit_b64: Some(BASE64.encode(b"bytes")),
            treekem_epoch: Some(3),
            commit: Some(commit(&kp, Some("treekem:epoch=3".into()))),
        };
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn the_join_request_lifecycle_stays_with_its_author() {
        let kp = signer();
        let event = NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: "g".into(),
            request_id: "r".into(),
            requester_agent_id: "bb".into(),
            message: None,
            ts: 1,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: None,
            commit: Some(commit(&kp, None)),
        };
        assert_eq!(apply_refusal(&event), Some(AUTHOR_ONLY_REASON));
    }

    #[test]
    fn an_unsigned_event_is_refused() {
        assert_eq!(
            apply_refusal(&update(&signer(), false)),
            Some("unsigned_event_needs_verified_sender")
        );
    }

    #[test]
    fn a_signed_metadata_update_is_admitted() {
        assert_eq!(apply_refusal(&update(&signer(), true)), None);
    }

    #[test]
    fn an_event_whose_actor_did_not_sign_its_commit_is_refused() {
        let (author, forger) = (signer(), signer());
        let mut event = removal(&forger, None, None, None);
        if let NamedGroupMetadataEvent::MemberRemoved { actor, .. } = &mut event {
            *actor = hex_id(&author);
        }
        assert_eq!(apply_refusal(&event), Some(ACTOR_NOT_SIGNER_REASON));
    }

    #[test]
    fn a_commit_that_does_not_verify_is_refused() {
        let kp = signer();
        let mut event = update(&kp, true);
        if let NamedGroupMetadataEvent::GroupMetadataUpdated {
            commit: Some(commit),
            ..
        } = &mut event
        {
            commit.signature = "00".repeat(8);
        }
        assert_eq!(apply_refusal(&event), Some(ACTOR_NOT_SIGNER_REASON));
    }

    #[test]
    fn a_recovery_courier_member_joined_is_refused() {
        let event = member_joined(true);
        assert_eq!(
            apply_refusal(&event),
            Some("recovery_courier_needs_verified_sender")
        );
    }

    #[test]
    fn the_original_member_joined_is_not_refused_here() {
        assert_eq!(apply_refusal(&member_joined(false)), None);
    }

    fn member_joined(courier: bool) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::MemberJoined {
            group_id: "g".into(),
            stable_group_id: None,
            member_agent_id: "bb".into(),
            member_public_key_b64: String::new(),
            role: crate::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: "aa".into(),
            invite_secret: String::new(),
            ts_ms: 1,
            treekem_key_package_b64: None,
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: courier.then(|| "attestation".to_string()),
            recovery_authority_commit: None,
            signature_b64: String::new(),
            certificate_b64: None,
            kem_public_key_b64: None,
            kem_signature_b64: None,
        }
    }

    #[test]
    fn a_secure_share_is_refused() {
        let event = NamedGroupMetadataEvent::SecureShareDelivered {
            group_id: "g".into(),
            recipient: "aa".into(),
            secret_epoch: 2,
            kem_ciphertext_b64: String::new(),
            aead_nonce_b64: String::new(),
            aead_ciphertext_b64: String::new(),
            actor: "aa".into(),
        };
        assert_eq!(
            apply_refusal(&event),
            Some("secure_share_needs_verified_sender")
        );
    }

    #[test]
    fn a_group_card_is_refused() {
        let event = NamedGroupMetadataEvent::GroupCardPublished {
            group_id: "g".into(),
            card: crate::groups::GroupCard {
                group_id: "g".into(),
                name: "spoof".into(),
                description: String::new(),
                avatar_url: None,
                banner_url: None,
                tags: Vec::new(),
                policy_summary: crate::groups::GroupPolicySummary {
                    discoverability: crate::groups::GroupDiscoverability::PublicDirectory,
                    admission: crate::groups::GroupAdmission::RequestAccess,
                    confidentiality: crate::groups::GroupConfidentiality::MlsEncrypted,
                    read_access: crate::groups::GroupReadAccess::MembersOnly,
                    write_access: crate::groups::GroupWriteAccess::MembersOnly,
                },
                owner_agent_id: "aa".into(),
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
        assert_eq!(
            apply_refusal(&event),
            Some("group_card_needs_verified_sender")
        );
    }

    /// Batch 6 (A1/A3): an add's TreeKEM bytes are named by the signed add
    /// binding, which upstream's binding does not do. Until that lands the
    /// door admits an add on its commit alone, so a deliverer could swap the
    /// Welcome. This must pass when the add binding does.
    #[test]
    #[ignore = "batch 6: the add binding that names Welcome bytes arrives with A1/A3"]
    fn batch6_an_add_whose_binding_does_not_name_its_welcome_is_refused() {
        let kp = signer();
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: "g".into(),
            revision: 2,
            actor: hex_id(&kp),
            agent_id: "bb".into(),
            display_name: None,
            treekem_commit_b64: Some(BASE64.encode(b"commit")),
            treekem_welcome_b64: Some(BASE64.encode(b"swapped welcome")),
            welcome_ref: None,
            treekem_epoch: Some(2),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            certificate_b64: None,
            owner_mandate: None,
            roster_certificates_b64: Vec::new(),
            commit: Some(commit(&kp, Some("treekem:epoch=2".into()))),
        };
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }
}

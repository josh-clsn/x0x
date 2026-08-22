//! What the engine-A apply door refuses before it applies anything.
//!
//! The door takes the sender from its caller and clears the transport gate,
//! so it admits only events whose authority does not rest on that claim: an
//! event carrying a signed state commit (its arm verifies the signature, the
//! chain link and the state hash against the local roster) and the joiner's
//! own self-signed `MemberJoined`. Everything else authorizes on the sender
//! alone and is refused with a `reason`.
//!
//! A removal or ban that carries TreeKEM bytes is admitted only when its
//! signed binding names those bytes. Upstream's self-leave seal does
//! (`treekem:epoch=<n>:commit=<d>`); the admin removal (`treekem:epoch=<n>`)
//! does not, so a deliverer could swap its bytes.

use super::{named_group_metadata_event_commit, treekem_commit_binding, NamedGroupMetadataEvent};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

pub(super) const UNNAMED_BYTES_REASON: &str = "needs_verified_signer_and_named_tree_bytes";
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

    fn commit(binding: Option<String>) -> crate::groups::GroupStateCommit {
        crate::groups::GroupStateCommit {
            group_id: "g".into(),
            revision: 2,
            prev_state_hash: None,
            roster_root: String::new(),
            policy_hash: String::new(),
            public_meta_hash: String::new(),
            security_binding: binding,
            state_hash: String::new(),
            withdrawn: false,
            committed_by: "aa".into(),
            committed_at: 0,
            signer_public_key: String::new(),
            signature: String::new(),
        }
    }

    fn removal(
        bytes: Option<&[u8]>,
        epoch: Option<u64>,
        binding: Option<String>,
    ) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".into(),
            revision: 2,
            actor: "aa".into(),
            agent_id: "bb".into(),
            treekem_commit_b64: bytes.map(|b| BASE64.encode(b)),
            treekem_epoch: epoch,
            secret_epoch: None,
            commit: Some(commit(binding)),
        }
    }

    #[test]
    fn stock_self_leave_rekey_is_admitted() {
        let bytes = b"treekem commit bytes";
        let binding = treekem_commit_binding(7, bytes);
        let event = removal(Some(bytes), Some(7), Some(binding));
        assert_eq!(apply_refusal(&event), None);
    }

    #[test]
    fn stock_legacy_admin_removal_is_refused_with_a_reason() {
        let bytes = b"treekem commit bytes";
        let event = removal(Some(bytes), Some(7), Some("treekem:epoch=7".into()));
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn a_removal_whose_binding_names_other_bytes_is_refused() {
        let binding = treekem_commit_binding(7, b"other bytes");
        let event = removal(Some(b"treekem commit bytes"), Some(7), Some(binding));
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn a_removal_with_half_its_tree_fields_is_refused() {
        let event = removal(Some(b"bytes"), None, Some("treekem:epoch=7".into()));
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn a_removal_without_tree_bytes_is_admitted() {
        let event = removal(None, None, None);
        assert_eq!(apply_refusal(&event), None);
    }

    #[test]
    fn a_ban_carrying_tree_bytes_is_refused() {
        let event = NamedGroupMetadataEvent::MemberBanned {
            group_id: "g".into(),
            revision: 2,
            actor: "aa".into(),
            agent_id: "bb".into(),
            secret_epoch: None,
            treekem_commit_b64: Some(BASE64.encode(b"bytes")),
            treekem_epoch: Some(3),
            commit: Some(commit(Some("treekem:epoch=3".into()))),
        };
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn the_join_request_lifecycle_stays_with_its_author() {
        let event = NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: "g".into(),
            request_id: "r".into(),
            requester_agent_id: "bb".into(),
            message: None,
            ts: 1,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: None,
            commit: Some(commit(None)),
        };
        assert_eq!(apply_refusal(&event), Some(AUTHOR_ONLY_REASON));
    }

    #[test]
    fn an_unsigned_event_is_refused() {
        let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "g".into(),
            revision: 2,
            actor: "aa".into(),
            name: Some("n".into()),
            description: None,
            commit: None,
        };
        assert_eq!(
            apply_refusal(&event),
            Some("unsigned_event_needs_verified_sender")
        );
    }

    #[test]
    fn a_signed_metadata_update_is_admitted() {
        let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "g".into(),
            revision: 2,
            actor: "aa".into(),
            name: Some("n".into()),
            description: None,
            commit: Some(commit(None)),
        };
        assert_eq!(apply_refusal(&event), None);
    }
}

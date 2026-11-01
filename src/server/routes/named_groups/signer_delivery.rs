//! Any member may hand on a signed, commit-bearing event, which then applies
//! as its verified signer (survivor re-key A3,
//! `docs/adr/transient/T-any-member-delivers-signed-commits.md`).
//!
//! Before this, an event applied only from its author, so a member who was
//! away when someone was removed, banned or added had to reach that author.
//! Now any member can serve it. What decides is the signature on the roster
//! commit, never the deliverer:
//!
//! - the event's `actor` must be the commit's verified signer;
//! - TreeKEM bytes in a copy the author did not deliver must be named by the
//!   signed binding (survivor re-key A1);
//! - a field no signature covers is dropped from such a copy (F-2).
//!
//! The join-request lifecycle events stay with their author.

use super::treekem_binding::{
    add_binding_names_bytes, add_extras_digest, parse_treekem_binding, removal_binding_names_bytes,
    WelcomeContent,
};
use super::{named_group_metadata_event_commit, parse_agent_id_hex, NamedGroupMetadataEvent};
use crate::identity::AgentId;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

/// The events any member may hand on. Each carries a roster commit that a
/// receiver checks against its own roster, and the actor is its signer.
fn signer_delivered(event: &NamedGroupMetadataEvent) -> bool {
    matches!(
        event,
        NamedGroupMetadataEvent::MemberAdded { .. }
            | NamedGroupMetadataEvent::MemberRemoved { .. }
            | NamedGroupMetadataEvent::MemberBanned { .. }
            | NamedGroupMetadataEvent::MemberUnbanned { .. }
            | NamedGroupMetadataEvent::MemberRoleUpdated { .. }
            | NamedGroupMetadataEvent::JoinRequestApproved { .. }
            | NamedGroupMetadataEvent::GroupMetadataUpdated { .. }
            | NamedGroupMetadataEvent::PolicyUpdated { .. }
            | NamedGroupMetadataEvent::GroupDeleted { .. }
    )
}

/// The join-request lifecycle. None of these advances an epoch, and each
/// applies fields its commit does not cover (the request's message, KEM key
/// and KeyPackage), so only its author delivers it.
pub(super) fn author_only(event: &NamedGroupMetadataEvent) -> bool {
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

/// The verified signer of a signer-delivered event: its commit's signature
/// verifies, and its `actor` names that signer.
fn verified_signer(event: &NamedGroupMetadataEvent) -> Option<AgentId> {
    let commit = named_group_metadata_event_commit(event)?;
    if actor_of(event)? != commit.committed_by {
        return None;
    }
    commit.verify_structure().ok()?;
    parse_agent_id_hex(&commit.committed_by).ok()
}

/// Who a catch-up or relayed copy of `event` applies as, or `None` to refuse
/// it. `verified` says whether the transport authenticated
/// `transport_sender`. When it did not, the sender is a claim, and nothing
/// is decided on it.
///
/// - A signer-delivered event applies as its verified signer. Its author's
///   own copy over a verified transport applies as before, a legacy binding
///   included. Any other copy must name its TreeKEM bytes.
/// - Every other event applies as its verified transport sender, so the
///   apply arms keep it with its author. With no verified sender it is
///   refused.
pub(super) fn catchup_apply_sender(
    event: &NamedGroupMetadataEvent,
    transport_sender: &AgentId,
    verified: bool,
) -> Option<AgentId> {
    if !signer_delivered(event) {
        return verified.then_some(*transport_sender);
    }
    let signer = verified_signer(event)?;
    if verified && *transport_sender == signer {
        return Some(signer);
    }
    non_author_copy_names_its_bytes(event).then_some(signer)
}

/// Whether the signed binding names the TreeKEM bytes this copy carries,
/// and, for an add, the fields its extras cover. A copy that carries no
/// TreeKEM bytes has none to swap.
fn non_author_copy_names_its_bytes(event: &NamedGroupMetadataEvent) -> bool {
    let Some(commit) = named_group_metadata_event_commit(event) else {
        return false;
    };
    let binding = commit
        .security_binding
        .as_deref()
        .and_then(parse_treekem_binding);
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
        } => match (treekem_commit_b64, treekem_epoch) {
            (None, None) => true,
            (Some(commit_b64), Some(epoch)) => {
                let Ok(bytes) = BASE64.decode(commit_b64) else {
                    return false;
                };
                binding.is_some_and(|binding| {
                    binding.commit.is_some()
                        && removal_binding_names_bytes(&binding, *epoch, &bytes)
                })
            }
            _ => false,
        },
        NamedGroupMetadataEvent::MemberAdded {
            treekem_commit_b64,
            treekem_epoch,
            display_name,
            treekem_key_package_hash,
            treekem_welcome_b64,
            welcome_ref,
            owner_mandate,
            ..
        } => add_names_its_bytes(
            binding,
            treekem_commit_b64.as_deref(),
            *treekem_epoch,
            AddExtras {
                display_name: display_name.as_deref(),
                key_package_hash: treekem_key_package_hash.as_deref(),
                welcome_b64: treekem_welcome_b64.as_deref(),
                welcome_ref: welcome_ref.as_ref(),
                owner_mandate: owner_mandate.as_ref(),
            },
        ),
        NamedGroupMetadataEvent::JoinRequestApproved {
            treekem_commit_b64,
            treekem_epoch,
            treekem_key_package_hash,
            treekem_welcome_b64,
            welcome_ref,
            ..
        } => add_names_its_bytes(
            binding,
            treekem_commit_b64.as_deref(),
            *treekem_epoch,
            AddExtras {
                display_name: None,
                key_package_hash: treekem_key_package_hash.as_deref(),
                welcome_b64: treekem_welcome_b64.as_deref(),
                welcome_ref: welcome_ref.as_ref(),
                owner_mandate: None,
            },
        ),
        _ => true,
    }
}

/// The fields an add's extras digest covers, as this copy carries them.
struct AddExtras<'a> {
    display_name: Option<&'a str>,
    key_package_hash: Option<&'a str>,
    welcome_b64: Option<&'a str>,
    welcome_ref: Option<&'a super::WelcomeRef>,
    owner_mandate: Option<&'a crate::groups::OwnerMandate>,
}

fn add_names_its_bytes(
    binding: Option<super::treekem_binding::TreeKemBinding<'_>>,
    commit_b64: Option<&str>,
    epoch: Option<u64>,
    extras: AddExtras<'_>,
) -> bool {
    let (commit_b64, epoch) = match (commit_b64, epoch) {
        (None, None) => return true,
        (Some(commit_b64), Some(epoch)) => (commit_b64, epoch),
        _ => return false,
    };
    let Some(binding) = binding.filter(|b| b.commit.is_some() && b.extras.is_some()) else {
        return false;
    };
    let Ok(bytes) = BASE64.decode(commit_b64) else {
        return false;
    };
    let Ok(welcome) = WelcomeContent::of_event(extras.welcome_b64, extras.welcome_ref) else {
        return false;
    };
    add_extras_digest(
        extras.display_name,
        extras.key_package_hash,
        welcome.as_ref(),
        extras.owner_mandate,
    )
    .is_some_and(|digest| add_binding_names_bytes(&binding, epoch, &bytes, &digest))
}

/// A copy its author did not deliver keeps only what its signer bound. An
/// add that carries no TreeKEM bytes (the shared-secret plane) has no
/// binding over its display name, KeyPackage hash or Welcome, so they go.
pub(super) fn non_author_copy(mut event: NamedGroupMetadataEvent) -> NamedGroupMetadataEvent {
    match &mut event {
        NamedGroupMetadataEvent::MemberAdded {
            treekem_commit_b64: None,
            display_name,
            treekem_key_package_hash,
            treekem_welcome_b64,
            welcome_ref,
            ..
        } => {
            *display_name = None;
            *treekem_key_package_hash = None;
            *treekem_welcome_b64 = None;
            *welcome_ref = None;
        }
        NamedGroupMetadataEvent::JoinRequestApproved {
            treekem_commit_b64: None,
            treekem_key_package_hash,
            treekem_welcome_b64,
            welcome_ref,
            ..
        } => {
            *treekem_key_package_hash = None;
            *treekem_welcome_b64 = None;
            *welcome_ref = None;
        }
        _ => {}
    }
    event
}

/// [`catchup_apply_sender`] and [`non_author_copy`] together: the sender a
/// door applies `event` as, and the copy it applies. `None` refuses it.
pub(super) fn admit(
    event: NamedGroupMetadataEvent,
    transport_sender: &AgentId,
    verified: bool,
) -> Option<(AgentId, NamedGroupMetadataEvent)> {
    let apply_as = catchup_apply_sender(&event, transport_sender, verified)?;
    if verified && apply_as == *transport_sender {
        Some((apply_as, event))
    } else {
        Some((apply_as, non_author_copy(event)))
    }
}

/// Why an engine-A door refuses an event: no copy it applies can rest on its
/// caller's sender claim (422).
pub(super) const UNNAMED_BYTES_REASON: &str = "needs_verified_signer_and_named_tree_bytes";
pub(super) const ACTOR_NOT_SIGNER_REASON: &str = "event_actor_is_not_the_commit_signer";
pub(super) const AUTHOR_ONLY_REASON: &str = "author_only_event_needs_verified_sender";

/// The engine-A doors (`apply-metadata-event`, `join-result/:member`) take
/// the sender from their caller, so it is a claim: [`admit`] with
/// `verified = false`, and the reason a refusal answers 422 with. The
/// joiner's self-signed original `MemberJoined` is the one event whose
/// authority does not rest on a sender or a roster commit; its own
/// signature is checked against the claimed sender by its arm.
pub(super) fn door_admit(
    event: NamedGroupMetadataEvent,
    claimed_sender: &AgentId,
) -> Result<(AgentId, NamedGroupMetadataEvent), &'static str> {
    match &event {
        NamedGroupMetadataEvent::MemberJoined {
            recovery_authority_signature_b64: Some(_),
            ..
        } => return Err("recovery_courier_needs_verified_sender"),
        NamedGroupMetadataEvent::MemberJoined { .. } => return Ok((*claimed_sender, event)),
        NamedGroupMetadataEvent::SecureShareDelivered { .. } => {
            return Err("secure_share_needs_verified_sender");
        }
        NamedGroupMetadataEvent::GroupCardPublished { .. } => {
            return Err("group_card_needs_verified_sender");
        }
        other if named_group_metadata_event_commit(other).is_none() => {
            return Err("unsigned_event_needs_verified_sender");
        }
        _ => {}
    }
    if author_only(&event) {
        return Err(AUTHOR_ONLY_REASON);
    }
    if verified_signer(&event).is_none() {
        return Err(ACTOR_NOT_SIGNER_REASON);
    }
    admit(event, claimed_sender, false).ok_or(UNNAMED_BYTES_REASON)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate as x0x;
    use crate::identity::AgentKeypair;

    fn hex_of(keypair: &AgentKeypair) -> String {
        hex::encode(keypair.agent_id().as_bytes())
    }

    /// A one-admin roster, sealed by `admin`, with `binding` as its signed
    /// security binding.
    fn sealed_commit(
        admin: &AgentKeypair,
        binding: Option<String>,
    ) -> x0x::groups::GroupStateCommit {
        let mut info = x0x::groups::GroupInfo::new(
            "signer-delivery".to_string(),
            String::new(),
            admin.agent_id(),
            hex::encode([0x3a; 16]),
        );
        info.security_binding = binding;
        info.seal_commit(admin, 1).expect("seal")
    }

    fn rename(actor: &str, commit: x0x::groups::GroupStateCommit) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "g".to_string(),
            revision: 1,
            actor: actor.to_string(),
            name: Some("Family".to_string()),
            description: None,
            commit: Some(commit),
        }
    }

    fn removal(
        actor: &str,
        bytes: &[u8],
        epoch: u64,
        commit: x0x::groups::GroupStateCommit,
    ) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".to_string(),
            revision: 1,
            actor: actor.to_string(),
            agent_id: "ab".repeat(32),
            treekem_commit_b64: Some(BASE64.encode(bytes)),
            treekem_epoch: Some(epoch),
            secret_epoch: None,
            commit: Some(commit),
        }
    }

    #[test]
    fn a_signed_commit_applies_as_its_signer_from_any_member() {
        let admin = AgentKeypair::generate().unwrap();
        let deliverer = AgentKeypair::generate().unwrap().agent_id();
        let event = rename(&hex_of(&admin), sealed_commit(&admin, None));
        assert_eq!(
            catchup_apply_sender(&event, &deliverer, true),
            Some(admin.agent_id())
        );
        assert_eq!(
            catchup_apply_sender(&event, &admin.agent_id(), true),
            Some(admin.agent_id()),
            "the author's own copy"
        );
        assert_eq!(
            catchup_apply_sender(&event, &deliverer, false),
            Some(admin.agent_id()),
            "a claimed sender changes nothing"
        );
    }

    #[test]
    fn an_actor_that_is_not_the_signer_authorises_nothing() {
        let admin = AgentKeypair::generate().unwrap();
        let other = AgentKeypair::generate().unwrap();
        let event = rename(&hex_of(&other), sealed_commit(&admin, None));
        for sender in [admin.agent_id(), other.agent_id()] {
            assert_eq!(catchup_apply_sender(&event, &sender, true), None);
            assert_eq!(catchup_apply_sender(&event, &sender, false), None);
        }
    }

    #[test]
    fn a_tampered_commit_has_no_signer() {
        let admin = AgentKeypair::generate().unwrap();
        let mut commit = sealed_commit(&admin, None);
        commit.roster_root = "00".repeat(32);
        let event = rename(&hex_of(&admin), commit);
        assert_eq!(catchup_apply_sender(&event, &admin.agent_id(), true), None);
    }

    #[test]
    fn treekem_bytes_from_a_non_author_must_be_named() {
        let admin = AgentKeypair::generate().unwrap();
        let deliverer = AgentKeypair::generate().unwrap().agent_id();
        let bytes = b"tree commit".to_vec();
        let named = super::super::treekem_binding::treekem_removal_bytes_binding(7, &bytes);
        let event = removal(
            &hex_of(&admin),
            &bytes,
            7,
            sealed_commit(&admin, Some(named)),
        );
        assert_eq!(
            catchup_apply_sender(&event, &deliverer, true),
            Some(admin.agent_id())
        );
        let swapped = removal(
            &hex_of(&admin),
            b"other bytes",
            7,
            named_group_metadata_event_commit(&event).unwrap().clone(),
        );
        assert_eq!(catchup_apply_sender(&swapped, &deliverer, true), None);

        let legacy = removal(
            &hex_of(&admin),
            &bytes,
            7,
            sealed_commit(&admin, Some("treekem:epoch=7".to_string())),
        );
        assert_eq!(
            catchup_apply_sender(&legacy, &deliverer, true),
            None,
            "a legacy binding names no bytes"
        );
        assert_eq!(
            catchup_apply_sender(&legacy, &admin.agent_id(), false),
            None,
            "a claimed author is not the author"
        );
        assert_eq!(
            catchup_apply_sender(&legacy, &admin.agent_id(), true),
            Some(admin.agent_id()),
            "the verified author still delivers it"
        );
    }

    #[test]
    fn join_request_lifecycle_events_stay_with_their_author() {
        let admin = AgentKeypair::generate().unwrap();
        let deliverer = AgentKeypair::generate().unwrap().agent_id();
        let commit = sealed_commit(&admin, None);
        let events = [
            NamedGroupMetadataEvent::JoinRequestCreated {
                group_id: "g".to_string(),
                request_id: "r".to_string(),
                requester_agent_id: hex_of(&admin),
                message: None,
                ts: 1,
                requester_kem_public_key_b64: None,
                treekem_key_package_b64: None,
                commit: Some(commit.clone()),
            },
            NamedGroupMetadataEvent::JoinRequestRejected {
                group_id: "g".to_string(),
                request_id: "r".to_string(),
                actor: hex_of(&admin),
                requester_agent_id: "cd".repeat(32),
                commit: Some(commit.clone()),
            },
            NamedGroupMetadataEvent::JoinRequestCancelled {
                group_id: "g".to_string(),
                request_id: "r".to_string(),
                requester_agent_id: hex_of(&admin),
                commit: Some(commit),
            },
        ];
        for event in &events {
            assert!(author_only(event));
            assert_eq!(
                catchup_apply_sender(event, &deliverer, true),
                Some(deliverer),
                "applied as the deliverer, whom the arm refuses: never as the signer"
            );
            assert_eq!(catchup_apply_sender(event, &admin.agent_id(), false), None);
        }
    }

    #[test]
    fn a_non_author_add_without_tree_bytes_drops_its_unbound_fields() {
        let added = NamedGroupMetadataEvent::MemberAdded {
            group_id: "g".to_string(),
            revision: 1,
            actor: "a".to_string(),
            agent_id: "b".to_string(),
            display_name: Some("Mom".to_string()),
            treekem_commit_b64: None,
            treekem_welcome_b64: Some("d2VsY29tZQ==".to_string()),
            welcome_ref: None,
            treekem_epoch: None,
            treekem_key_package_hash: Some("ab".repeat(32)),
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            certificate_b64: None,
            owner_mandate: None,
            roster_certificates_b64: Vec::new(),
            commit: None,
        };
        match non_author_copy(added) {
            NamedGroupMetadataEvent::MemberAdded {
                display_name,
                treekem_key_package_hash,
                treekem_welcome_b64,
                welcome_ref,
                ..
            } => {
                assert_eq!(display_name, None);
                assert_eq!(treekem_key_package_hash, None);
                assert_eq!(treekem_welcome_b64, None);
                assert!(welcome_ref.is_none());
            }
            other => panic!("not an add: {other:?}"),
        }
    }
}

/// The engine-A door cases, moved from `engine_a_doors.rs` when its rules
/// folded into [`door_admit`].
#[cfg(test)]
mod door_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::super::{
        add_extras_digest, treekem_ban_bytes_binding, treekem_bytes_binding,
        treekem_commit_binding, WelcomeContent,
    };
    use super::*;

    /// The reason a door refuses `event` with, or `None` to admit it. The
    /// claimed sender is nobody in particular: nothing rests on it.
    fn apply_refusal(event: &NamedGroupMetadataEvent) -> Option<&'static str> {
        let claimed = AgentId([0x5c; 32]);
        door_admit(event.clone(), &claimed).err()
    }

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

    fn add(kp: &crate::identity::AgentKeypair, binding: String) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::MemberAdded {
            group_id: "g".into(),
            revision: 2,
            actor: hex_id(kp),
            agent_id: "bb".into(),
            display_name: None,
            treekem_commit_b64: Some(BASE64.encode(b"commit")),
            treekem_welcome_b64: Some(BASE64.encode(b"welcome")),
            welcome_ref: None,
            treekem_epoch: Some(2),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            certificate_b64: None,
            owner_mandate: None,
            roster_certificates_b64: Vec::new(),
            commit: Some(commit(kp, Some(binding))),
        }
    }

    fn named_add_binding(welcome: &[u8]) -> String {
        let extras = add_extras_digest(None, None, Some(&WelcomeContent::of_bytes(welcome)), None)
            .expect("extras");
        treekem_bytes_binding(2, b"commit", &extras)
    }

    #[test]
    fn an_add_whose_binding_names_nothing_is_refused() {
        let kp = signer();
        let event = add(&kp, "treekem:epoch=2".into());
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn an_add_whose_binding_names_another_welcome_is_refused() {
        let kp = signer();
        let event = add(&kp, named_add_binding(b"another welcome"));
        assert_eq!(apply_refusal(&event), Some(UNNAMED_BYTES_REASON));
    }

    #[test]
    fn an_add_whose_binding_names_its_bytes_is_admitted() {
        let kp = signer();
        let event = add(&kp, named_add_binding(b"welcome"));
        assert_eq!(apply_refusal(&event), None);
    }

    #[test]
    fn a_ban_whose_binding_names_its_bytes_is_admitted() {
        let kp = signer();
        let bytes = b"bytes";
        let event = NamedGroupMetadataEvent::MemberBanned {
            group_id: "g".into(),
            revision: 2,
            actor: hex_id(&kp),
            agent_id: "bb".into(),
            secret_epoch: None,
            treekem_commit_b64: Some(BASE64.encode(bytes)),
            treekem_epoch: Some(3),
            commit: Some(commit(&kp, treekem_ban_bytes_binding(3, bytes))),
        };
        assert_eq!(apply_refusal(&event), None);
    }
}

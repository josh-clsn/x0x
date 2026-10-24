//! A TreeKEM commit applies only when its committer leaf is the leaf of the
//! event's actor (survivor re-key A2,
//! `docs/adr/transient/T-treekem-committer-leaf.md`).
//!
//! The actor signs the roster commit. The TreeKEM commit is signed by a
//! leaf key. Without this rule any member could hand on the actor's event
//! with a commit from its own leaf, and a receiver would install a tree that
//! member chose. The actor's leaf is the live leaf that matches the actor's
//! KeyPackage, whose hash the signed roster commits to.

use super::{
    current_member_treekem_key_package, join_result_key, request_member_key_package_catchup,
    AppState, NamedGroupMetadataEvent,
};
use crate as x0x;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// Why a commit was not tied to its actor's leaf. Every case refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommitterLeafRefusal {
    /// The commit bytes do not decode, so they name no committer.
    CommitterLeafUnreadable,
    /// The roster commits to no KeyPackage for the actor, so nothing ties
    /// the actor to any leaf. No peer can supply one that this member would
    /// trust.
    ActorKeyPackageUncommitted,
    /// The roster commits to the actor's KeyPackage hash, but this member
    /// holds no bytes that hash to it. A peer can supply them (#398).
    ActorKeyPackagePending,
    /// The actor's KeyPackage matches no live leaf in this member's tree.
    ActorHasNoLeaf,
    /// The commit came from another leaf.
    CommitterLeafNotActor,
}

impl CommitterLeafRefusal {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::CommitterLeafUnreadable => "committer_leaf_unreadable",
            Self::ActorKeyPackageUncommitted => "actor_key_package_uncommitted",
            Self::ActorKeyPackagePending => "actor_key_package_pending",
            Self::ActorHasNoLeaf => "actor_has_no_leaf",
            Self::CommitterLeafNotActor => "committer_leaf_not_actor",
        }
    }
}

/// The actor's KeyPackage bytes, checked against the hash `info` commits
/// to: the roster's copy, else this member's cached recovery record for the
/// actor under any of the group's ids.
pub(super) async fn actor_committed_key_package(
    state: &AppState,
    group_ids: &[&str],
    info: &x0x::groups::GroupInfo,
    actor_hex: &str,
) -> Result<Vec<u8>, CommitterLeafRefusal> {
    let Some(seat) = info.members_v2.get(actor_hex) else {
        return Err(CommitterLeafRefusal::ActorKeyPackageUncommitted);
    };
    let Some(committed_hash) = seat.treekem_key_package_hash.clone() else {
        return Err(CommitterLeafRefusal::ActorKeyPackageUncommitted);
    };
    let held = match current_member_treekem_key_package(seat) {
        Some(b64) => Some(b64),
        None => cached_package_matching(state, group_ids, actor_hex, &committed_hash).await,
    };
    held.and_then(|b64| BASE64.decode(b64).ok())
        .ok_or(CommitterLeafRefusal::ActorKeyPackagePending)
}

async fn cached_package_matching(
    state: &AppState,
    group_ids: &[&str],
    actor_hex: &str,
    committed_hash: &str,
) -> Option<String> {
    for group_id in group_ids {
        let cached = state
            .treekem_member_key_packages
            .get(&join_result_key(group_id, actor_hex))
            .await;
        if let Some(NamedGroupMetadataEvent::MemberJoined {
            member_agent_id,
            treekem_key_package_b64: Some(b64),
            ..
        }) = cached
        {
            if member_agent_id.eq_ignore_ascii_case(actor_hex)
                && blake3::hash(b64.as_bytes()).to_hex().as_str() == committed_hash
            {
                return Some(b64);
            }
        }
    }
    None
}

/// Ask peers for the packages of `members`, which this member holds by
/// hash alone. The #398 lane serves them and checks each against the hash.
pub(super) fn request_key_packages(state: &Arc<AppState>, group_id: &str, members: Vec<String>) {
    if members.is_empty() {
        return;
    }
    let state = Arc::clone(state);
    let group_id = group_id.to_string();
    tokio::spawn(async move {
        for member in members {
            request_member_key_package_catchup(&state, &group_id, &member).await;
        }
    });
}

/// True the first time this process refuses `actor_hex` in `group_id` for
/// a seat with no committed package, so that refusal is logged loudly once
/// rather than on every delivery.
pub(super) fn first_uncommitted_refusal(group_id: &str, actor_hex: &str) -> bool {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    WARNED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(format!("{group_id}:{actor_hex}"))
}

/// Whether `commit` names the leaf that `actor_key_package` occupies in
/// `group`. Run under the group's lock, on the tree the commit will be
/// processed against, before `process_commit`.
pub(super) fn committer_is_actor(
    group: &x0x::mls::TreeKemMlsGroup,
    commit: &[u8],
    actor_key_package: &[u8],
) -> Result<(), CommitterLeafRefusal> {
    let committer = x0x::mls::TreeKemMlsGroup::committer_leaf_of(commit)
        .ok_or(CommitterLeafRefusal::CommitterLeafUnreadable)?;
    let actor_leaf = group
        .leaf_for_key_package(actor_key_package)
        .ok_or(CommitterLeafRefusal::ActorHasNoLeaf)?;
    if committer == actor_leaf {
        Ok(())
    } else {
        Err(CommitterLeafRefusal::CommitterLeafNotActor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::AgentId;
    use crate::mls::TreeKemMlsGroup;

    fn member(id: u8) -> (AgentId, [u8; 32]) {
        (AgentId([id; 32]), [id; 32])
    }

    fn package(id: u8) -> Vec<u8> {
        let (agent, seed) = member(id);
        TreeKemMlsGroup::prepare_member(agent, &seed)
            .expect("prepare")
            .key_package_bytes()
            .to_vec()
    }

    #[test]
    fn each_case_has_its_own_refusal() {
        let (alice, alice_seed) = member(1);
        let (bob, bob_seed) = member(2);
        let mut alice_group =
            TreeKemMlsGroup::create(b"committer-leaf".to_vec(), alice, &alice_seed)
                .expect("create");
        let bob_prepared = TreeKemMlsGroup::prepare_member(bob, &bob_seed).expect("prepare");
        let added = alice_group
            .add_member(bob, bob_prepared.key_package_bytes())
            .expect("add bob");
        let mut bob_group =
            TreeKemMlsGroup::join_from_welcome(bob_prepared, &added.welcome).expect("join");
        let bob_update = bob_group.update().expect("bob rotates");

        assert_eq!(
            committer_is_actor(&alice_group, &bob_update, &package(2)),
            Ok(())
        );
        assert_eq!(
            committer_is_actor(&alice_group, &bob_update, &package(1)),
            Err(CommitterLeafRefusal::CommitterLeafNotActor)
        );
        assert_eq!(
            committer_is_actor(&alice_group, b"not a commit", &package(1)),
            Err(CommitterLeafRefusal::CommitterLeafUnreadable)
        );
        assert_eq!(
            committer_is_actor(&alice_group, &bob_update, &package(3)),
            Err(CommitterLeafRefusal::ActorHasNoLeaf),
            "a package on no live leaf ties the actor to nothing"
        );
        assert_eq!(
            committer_is_actor(&alice_group, &bob_update, b"not a package"),
            Err(CommitterLeafRefusal::ActorHasNoLeaf)
        );
    }

    #[test]
    fn an_uncommitted_actor_is_warned_once_per_group() {
        assert!(first_uncommitted_refusal("g-warn-1", "actor"));
        assert!(!first_uncommitted_refusal("g-warn-1", "actor"));
        assert!(first_uncommitted_refusal("g-warn-2", "actor"));
    }

    #[test]
    fn refusal_reasons_are_distinct() {
        let all = [
            CommitterLeafRefusal::CommitterLeafUnreadable,
            CommitterLeafRefusal::ActorKeyPackageUncommitted,
            CommitterLeafRefusal::ActorKeyPackagePending,
            CommitterLeafRefusal::ActorHasNoLeaf,
            CommitterLeafRefusal::CommitterLeafNotActor,
        ];
        let reasons: std::collections::HashSet<_> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(reasons.len(), all.len());
    }
}

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
    spawn_treekem_epoch_ahead_catchup, AppState, NamedGroupMetadataEvent,
};
use crate as x0x;
use crate::logging::LogHexId;
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::{HashMap, HashSet};
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

/// A member's KeyPackage bytes, checked against the hash `info` commits
/// to: the roster's copy, else this member's cached recovery record for it
/// under any of the group's ids. Used for a commit's actor and for the
/// member a removal or ban takes out.
pub(super) async fn member_committed_key_package(
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

/// How many members the startup sweep asks for each package: the member's
/// adder first when it is active, then the others in roster order. Any one
/// holder is enough, and a refused commit still asks every member.
pub(in crate::server) const KEY_PACKAGE_SWEEP_CANDIDATES: usize = 4;

/// Ask peers for the packages of `members`, which this member holds by
/// hash alone. The #398 lane serves them and checks each against the hash.
/// Each request goes to at most `max_candidates` active members.
pub(super) fn request_key_packages(
    state: &Arc<AppState>,
    group_id: &str,
    members: Vec<String>,
    max_candidates: usize,
) {
    if members.is_empty() {
        return;
    }
    let state = Arc::clone(state);
    let group_id = group_id.to_string();
    tokio::spawn(async move {
        for member in members {
            request_member_key_package_catchup(&state, &group_id, &member, max_candidates).await;
        }
    });
}

/// The active members of `info`, other than `local_hex`, whose package
/// this member holds by its committed hash alone: neither the roster nor
/// the recovery cache has bytes that match.
pub(super) async fn hash_only_seats(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
    local_hex: &str,
) -> Vec<String> {
    let group_ids = [
        group_key,
        info.stable_group_id(),
        info.mls_group_id.as_str(),
    ];
    let mut hash_only = Vec::new();
    for (member_hex, seat) in &info.members_v2 {
        if !seat.is_active()
            || member_hex.eq_ignore_ascii_case(local_hex)
            || current_member_treekem_key_package(seat).is_some()
        {
            continue;
        }
        let Some(hash) = seat.treekem_key_package_hash.as_deref() else {
            continue;
        };
        if cached_package_matching(state, &group_ids, member_hex, hash)
            .await
            .is_none()
        {
            hash_only.push(member_hex.clone());
        }
    }
    hash_only
}

/// Ask for every package this member holds by hash alone, in every TreeKEM
/// group it is active in. Run once the mesh is up, at startup and after a
/// deferred mesh join: a member that joined before survivor re-key A2 holds
/// earlier members this way, and their first commit would otherwise be
/// refused until the package arrived.
pub(super) async fn request_hash_only_key_packages(state: &Arc<AppState>) {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups: Vec<(String, x0x::groups::GroupInfo)> = state
        .named_groups
        .read()
        .await
        .iter()
        .filter(|(_, info)| {
            !info.withdrawn
                && info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                && info.has_active_member(&local_hex)
        })
        .map(|(key, info)| (key.clone(), info.clone()))
        .collect();
    for (group_key, info) in groups {
        let hash_only = hash_only_seats(state, &group_key, &info, &local_hex).await;
        if !hash_only.is_empty() {
            tracing::info!(
                group_id = %LogHexId::group(&group_key),
                members = hash_only.len(),
                "requesting TreeKEM KeyPackages held by hash alone"
            );
        }
        request_key_packages(state, &group_key, hash_only, KEY_PACKAGE_SWEEP_CANDIDATES);
    }
}

/// Run [`request_hash_only_key_packages`] in its own task, so its caller
/// (the startup join, before its rendezvous advertisement) never waits on
/// the roster.
pub(super) fn spawn_hash_only_key_package_sweep(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        request_hash_only_key_packages(&state).await;
    });
}

/// Per group key, the TreeKEM epoch that a refusal for a missing KeyPackage
/// last pulled the group's commits again for (A2 re-review r-1). Without it
/// a page refused after the pull's rounds ended would start another, and a
/// member that can serve the event but not the package would keep a group
/// polling. An entry lives until the group's next package lands.
#[derive(Debug, Default)]
pub(in crate::server) struct PackageRepulls {
    pulled: HashMap<String, u64>,
}

impl PackageRepulls {
    /// Note a refusal at `epoch`. True when nothing was pulled again for
    /// this epoch, or a later one, since the group's last package landed.
    pub(super) fn note_refusal(&mut self, group_key: &str, epoch: u64) -> bool {
        match self.pulled.get(group_key) {
            Some(&pulled) if pulled >= epoch => false,
            _ => {
                self.pulled.insert(group_key.to_string(), epoch);
                true
            }
        }
    }

    /// A package landed for the group: the refused epoch to pull again for,
    /// once.
    pub(super) fn take_landed(&mut self, group_key: &str) -> Option<u64> {
        self.pulled.remove(group_key)
    }
}

/// After a commit was refused for a package this member did not hold: pull
/// the group's missed commits again once the package can have landed. The
/// epoch-ahead catch-up asks the other members round by round, one throttle
/// window apart, until this member reaches `epoch`, so the refused event
/// comes back without waiting on its sealer's resend. It pulls once per
/// refused epoch ([`PackageRepulls`]); the package's arrival pulls once
/// more ([`pull_again_now_a_package_landed`]). A task that is already
/// running for the group covers it; starting another would count every
/// refusal during its rounds as new traffic.
pub(super) async fn pull_again_after_package(state: &Arc<AppState>, group_key: &str, epoch: u64) {
    let first = state
        .treekem_package_repulls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .note_refusal(group_key, epoch);
    if !first
        || state
            .treekem_epoch_ahead_targets
            .lock()
            .await
            .contains_key(group_key)
    {
        return;
    }
    spawn_treekem_epoch_ahead_catchup(state, group_key, epoch);
}

/// A KeyPackage landed for `group_key`: pull again, once, for the epoch a
/// refusal was waiting on.
pub(super) fn pull_again_now_a_package_landed(state: &Arc<AppState>, group_key: &str) {
    let epoch = state
        .treekem_package_repulls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take_landed(group_key);
    if let Some(epoch) = epoch {
        spawn_treekem_epoch_ahead_catchup(state, group_key, epoch);
    }
}

/// Whether this member may seal a TreeKEM commit in `info`. Receivers tie a
/// commit to its sealer's leaf through the KeyPackage hash the sealer's own
/// seat commits. With none (a group made before 2026-07-11), every other
/// member refuses the commit while this member moves on, and the group
/// splits.
pub(super) fn sealer_seat_commits_package(info: &x0x::groups::GroupInfo, local_hex: &str) -> bool {
    info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem
        || info
            .members_v2
            .get(local_hex)
            .is_some_and(|seat| seat.treekem_key_package_hash.is_some())
}

/// The plain explanation a refused seal gives.
pub(super) const SEALER_PACKAGE_UNCOMMITTED: &str = "this member's seat commits no TreeKEM key package (the group was made before 2026-07-11), so no other member can accept a key change it makes; nothing was changed, and the group must be made again to add or remove members";

/// Log a refused seal at WARN and return the route's error.
pub(super) fn sealer_package_uncommitted(
    group_id: &str,
    what: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    tracing::warn!(
        group_id = %LogHexId::group(group_id),
        what,
        "refusing to seal a TreeKEM commit: {SEALER_PACKAGE_UNCOMMITTED}"
    );
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "ok": false,
            "error": "sealer_key_package_uncommitted",
            "detail": SEALER_PACKAGE_UNCOMMITTED,
        })),
    )
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
    fn a_sealer_needs_its_own_committed_package_only_on_the_treekem_plane() {
        let (sealer, _) = member(1);
        let sealer_hex = hex::encode(sealer.as_bytes());
        let mut info = x0x::groups::GroupInfo::new(
            "seal".to_string(),
            String::new(),
            sealer,
            hex::encode([0x5b; 16]),
        );
        assert!(
            sealer_seat_commits_package(&info, &sealer_hex),
            "the shared-secret plane has no leaves to tie"
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        assert!(!sealer_seat_commits_package(&info, &sealer_hex));
        assert!(!sealer_seat_commits_package(&info, "not-a-member"));
        info.set_member_treekem_key_package_hash(&sealer_hex, "ab".repeat(32));
        assert!(
            sealer_seat_commits_package(&info, &sealer_hex),
            "a committed hash is enough: receivers fetch the bytes"
        );
    }

    #[test]
    fn a_refused_epoch_is_pulled_again_once_until_its_package_lands() {
        let mut repulls = PackageRepulls::default();
        assert!(repulls.note_refusal("g", 5), "the first refusal pulls");
        assert!(!repulls.note_refusal("g", 5), "the same epoch waits");
        assert!(!repulls.note_refusal("g", 4), "an earlier epoch waits");
        assert!(repulls.note_refusal("other", 5), "groups are apart");
        assert!(repulls.note_refusal("g", 6), "a later epoch pulls");
        assert_eq!(repulls.take_landed("g"), Some(6), "the package pulls once");
        assert_eq!(repulls.take_landed("g"), None);
        assert!(
            repulls.note_refusal("g", 6),
            "after it landed, a refusal pulls"
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

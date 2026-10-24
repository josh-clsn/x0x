//! Head proofs (survivor re-key A6, `docs/adr/transient/T-treekem-head-proof.md`).
//!
//! A member that was away asks each admin of its room where the room's key
//! stands, with a fresh nonce. An admin's daemon answers with a **head
//! proof**: the live TreeKEM tree's epoch and epoch authenticator, signed
//! with its agent key over the nonce, the requester, the group and the
//! signer. The member compares the proof with its own tree (the engine's
//! verdict, plan task C3), so a proof is worth only what the live tree
//! says. Nothing else on the catch-up wire (`responder_state_hash`, a
//! request's `current_state_hash`) is evidence of freshness.
//!
//! - **Who signs.** Only a daemon that is an active admin on its own
//!   roster, and only for a requester that is active there.
//! - **What it signs.** The epoch and authenticator, read together under
//!   the tree's lock ([`x0x::mls::TreeKemMlsGroup::head`]).
//! - **When.** A challenge rides on a signed page request
//!   (`head_challenge`). It is answered before the #378 page throttle, with
//!   its own limit of [`HEAD_PROOFS_PER_WINDOW`] per [`HEAD_PROOF_WINDOW`]
//!   per (group, requester), so a page served a moment earlier never stops
//!   the proof.
//! - **What a member records.** A proof that verifies, for itself, in this
//!   group, from a signer it asked, under its open round's nonce, within
//!   [`HEAD_ROUND_DEADLINE`] of the round opening.

use super::{
    build_catchup_signer, catchup_signer_matches, named_group_direct_delivery_config,
    parse_agent_id_hex, signed_catchup, spawn_treekem_epoch_ahead_catchup, AppState, CatchupSigner,
    TreeKemCatchupResponse,
};
use crate as x0x;
use crate::identity::AgentId;
use crate::logging::LogHexId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, LazyLock, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// The domain of a head proof's signature.
pub(in crate::server) const HEAD_PROOF_DOMAIN: &str = "x0x/treekem-head-proof/v1";

/// The head proof format this daemon signs and accepts.
pub(in crate::server) const HEAD_PROOF_VERSION: u32 = 1;

/// How many challenges one requester may have answered per group in one
/// [`HEAD_PROOF_WINDOW`]. Each costs an ML-DSA-65 signature (about 1 ms).
pub(in crate::server) const HEAD_PROOFS_PER_WINDOW: usize = 12;

/// The window of [`HEAD_PROOFS_PER_WINDOW`].
pub(in crate::server) const HEAD_PROOF_WINDOW: Duration = Duration::from_secs(60);

/// How long after a round opens its proofs are recorded.
pub(in crate::server) const HEAD_ROUND_DEADLINE: Duration = Duration::from_secs(60);

/// The most admins a proof names. A room with more is not answered.
pub(in crate::server) const HEAD_PROOF_MAX_ADMINS: usize = 512;

/// Above this many (group, requester) entries, a new answer first drops
/// the entries with nothing inside the window.
const HEAD_PROOF_LIMIT_PRUNE_AT: usize = 1024;

/// Test-only: when set to exactly `1`, this daemon signs its head proofs
/// with the live epoch plus one and a random authenticator. The rig plays a
/// removed admin running a modified app with it (design F-1). Never set in
/// production; read once per process.
pub(in crate::server) const INFLATE_KNOB: &str = "X0X_TEST_HEAD_PROOF_INFLATE";

static INFLATE: LazyLock<bool> =
    LazyLock::new(|| inflate_requested(std::env::var(INFLATE_KNOB).ok().as_deref()));

/// Whether the value of [`INFLATE_KNOB`] turns the knob on: only `1` does.
fn inflate_requested(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Whether [`INFLATE_KNOB`] is on in this process.
pub(in crate::server) fn inflate_knob() -> bool {
    *INFLATE
}

/// What a head proof states. Every field is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::server) struct HeadClaim {
    /// [`HEAD_PROOF_VERSION`].
    pub(in crate::server) version: u32,
    /// The room's stable group id on the signer.
    pub(in crate::server) group_id: String,
    /// The member that asked (agent id, lowercase hex).
    pub(in crate::server) requester: String,
    /// The requester's challenge, as it sent it.
    pub(in crate::server) nonce: String,
    /// The signer's live TreeKEM epoch.
    pub(in crate::server) treekem_epoch: u64,
    /// The signer's live epoch authenticator (32 bytes, lowercase hex).
    pub(in crate::server) epoch_authenticator: String,
    /// The signer's roster binding. Information only.
    #[serde(default)]
    pub(in crate::server) security_binding: Option<String>,
    /// The signer's roster revision. Information only.
    pub(in crate::server) state_revision: u64,
    /// The active admins on the signer's roster, sorted, no repeats.
    pub(in crate::server) admins: Vec<String>,
    /// The signer's agent id (lowercase hex). The carried key must derive it.
    pub(in crate::server) signer: String,
}

/// A [`HeadClaim`] with its signer's signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct HeadProof {
    #[serde(flatten)]
    pub(in crate::server) claim: HeadClaim,
    pub(in crate::server) signed_by: CatchupSigner,
}

fn is_agent_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn authenticator_bytes(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    let bytes = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
    (hex::encode(bytes) == value).then_some(bytes)
}

fn nonce_ok(nonce: &str) -> bool {
    !nonce.is_empty() && nonce.len() <= signed_catchup::HEAD_CHALLENGE_MAX_BYTES
}

impl HeadClaim {
    /// The bytes the signature covers. `u64` values are big-endian, and
    /// every byte string is preceded by its length as a big-endian `u64`:
    ///
    /// ```text
    /// len ‖ "x0x/treekem-head-proof/v1"
    /// version (u64)
    /// len ‖ group_id
    /// len ‖ requester
    /// len ‖ nonce
    /// treekem_epoch (u64)
    /// len ‖ epoch_authenticator (the 32 raw bytes)
    /// security_binding: 0x00, or 0x01 ‖ len ‖ binding
    /// state_revision (u64)
    /// admin count (u64), then len ‖ admin for each
    /// len ‖ signer
    /// ```
    ///
    /// `None` when the authenticator is not 32 bytes of lowercase hex.
    fn sign_input(&self) -> Option<Vec<u8>> {
        let authenticator = authenticator_bytes(&self.epoch_authenticator)?;
        let push = signed_catchup::push_field;
        let mut input = Vec::with_capacity(512 + 72 * self.admins.len());
        push(&mut input, HEAD_PROOF_DOMAIN.as_bytes());
        input.extend_from_slice(&u64::from(self.version).to_be_bytes());
        push(&mut input, self.group_id.as_bytes());
        push(&mut input, self.requester.as_bytes());
        push(&mut input, self.nonce.as_bytes());
        input.extend_from_slice(&self.treekem_epoch.to_be_bytes());
        push(&mut input, &authenticator);
        match &self.security_binding {
            None => input.push(0),
            Some(binding) => {
                input.push(1);
                push(&mut input, binding.as_bytes());
            }
        }
        input.extend_from_slice(&self.state_revision.to_be_bytes());
        input.extend_from_slice(&(self.admins.len() as u64).to_be_bytes());
        for admin in &self.admins {
            push(&mut input, admin.as_bytes());
        }
        push(&mut input, self.signer.as_bytes());
        Some(input)
    }

    /// Whether every field is in its one canonical form.
    fn well_formed(&self) -> bool {
        self.version == HEAD_PROOF_VERSION
            && is_agent_hex(&self.requester)
            && is_agent_hex(&self.signer)
            && nonce_ok(&self.nonce)
            && self.admins.len() <= HEAD_PROOF_MAX_ADMINS
            && self.admins.iter().all(|admin| is_agent_hex(admin))
            && self.admins.windows(2).all(|pair| pair[0] < pair[1])
    }
}

/// Whether `proof` is well formed and signed by the key of its claimed
/// signer. The key is self-certifying: the signer's agent id must derive
/// from it, so a proof cannot be re-attributed to another agent.
pub(in crate::server) fn verify(proof: &HeadProof) -> bool {
    proof.claim.well_formed()
        && proof.claim.sign_input().is_some_and(|input| {
            catchup_signer_matches(&proof.signed_by, &proof.claim.signer, &input)
        })
}

/// Sign `claim` with `keypair`. A test plays a signer that is not a daemon
/// with it.
#[cfg(test)]
pub(in crate::server) fn sign_claim_with(
    keypair: &crate::identity::AgentKeypair,
    claim: HeadClaim,
) -> HeadProof {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let input = claim.sign_input().unwrap_or_default();
    // A failed signature is left empty, so the proof does not verify.
    let signature_b64 =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(keypair.secret_key(), &input)
            .map(|signature| BASE64.encode(signature.as_bytes()))
            .unwrap_or_default();
    HeadProof {
        claim,
        signed_by: CatchupSigner {
            public_key_b64: BASE64.encode(keypair.public_key().as_bytes()),
            signature_b64,
        },
    }
}

/// Why a challenge got no proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum Refusal {
    /// The challenge is empty or longer than
    /// [`signed_catchup::HEAD_CHALLENGE_MAX_BYTES`].
    BadChallenge,
    /// This daemon has no live roster or tree for the room.
    NoRoom,
    /// The requester is not an active member on this daemon's roster.
    RequesterNotActive,
    /// The requester used up its answers for this window.
    Limited,
    /// This daemon is not an active admin on its own roster.
    NotAnAdmin,
    /// Signing failed, or the roster kept moving while it was read.
    Unavailable,
}

/// The roster facts a proof carries, read in one go.
struct RosterHead {
    key: String,
    stable_group_id: String,
    state_revision: u64,
    state_hash: String,
    security_binding: Option<String>,
    admins: Vec<String>,
    local_is_admin: bool,
}

async fn roster_head(state: &AppState, group_id: &str) -> Option<RosterHead> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let (key, info) = groups.get_key_value(group_id).or_else(|| {
        groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == group_id)
    })?;
    if info.withdrawn {
        return None;
    }
    let mut admins: Vec<String> = info
        .active_members()
        .filter(|member| member.role.at_least(x0x::groups::GroupRole::Admin))
        .map(|member| member.agent_id.to_ascii_lowercase())
        .collect();
    admins.sort();
    admins.dedup();
    Some(RosterHead {
        key: key.clone(),
        stable_group_id: info.stable_group_id().to_string(),
        state_revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        security_binding: info.security_binding.clone(),
        admins,
        local_is_admin: !info.is_banned(&local_hex)
            && info
                .caller_role(&local_hex)
                .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin)),
    })
}

/// How many times [`answer_challenge`] reads the roster and the tree again
/// when the roster moved while it read the tree.
const HEAD_READ_ATTEMPTS: usize = 3;

/// Answer `requester`'s challenge `nonce` in `group_id` with this daemon's
/// signed head proof. `requester_epoch` is the epoch the requester holds:
/// when it is ahead of the live tree, this daemon starts its own epoch-ahead
/// catch-up, whether or not it is an admin.
///
/// The page serve (`handle_treekem_catchup_request`) calls this after its
/// gates, before its #378 throttle. The A7 route calls it too.
pub(in crate::server) async fn answer_challenge(
    state: &Arc<AppState>,
    group_id: &str,
    requester: &str,
    nonce: &str,
    requester_epoch: u64,
) -> Result<HeadProof, Refusal> {
    answer_challenge_with(
        state,
        group_id,
        requester,
        nonce,
        requester_epoch,
        inflate_knob(),
    )
    .await
}

/// [`answer_challenge`], with [`INFLATE_KNOB`]'s effect given as `inflate`.
pub(in crate::server) async fn answer_challenge_with(
    state: &Arc<AppState>,
    group_id: &str,
    requester: &str,
    nonce: &str,
    requester_epoch: u64,
    inflate: bool,
) -> Result<HeadProof, Refusal> {
    if !nonce_ok(nonce) {
        return Err(Refusal::BadChallenge);
    }
    let requester = requester.to_ascii_lowercase();
    let key = {
        let groups = state.named_groups.read().await;
        let (key, info) = groups
            .get_key_value(group_id)
            .or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == group_id)
            })
            .ok_or(Refusal::NoRoom)?;
        if info.withdrawn {
            return Err(Refusal::NoRoom);
        }
        if !is_agent_hex(&requester) || !info.has_active_member(&requester) {
            return Err(Refusal::RequesterNotActive);
        }
        key.clone()
    };
    if !state
        .treekem_head_proofs
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .allow_answer(&key, &requester, Instant::now())
    {
        return Err(Refusal::Limited);
    }
    let tree = state
        .treekem_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or(Refusal::NoRoom)?;
    let mut ahead_noted = false;
    for _ in 0..HEAD_READ_ATTEMPTS {
        let roster = roster_head(state, &key).await.ok_or(Refusal::NoRoom)?;
        // The epoch and the authenticator come from one borrow of the live
        // tree, under its lock, so they cannot be torn.
        let (epoch, authenticator) = {
            let guard = tree.lock().await;
            guard.head().map_err(|_| Refusal::Unavailable)?
        };
        if requester_epoch > epoch && !ahead_noted {
            ahead_noted = true;
            tracing::info!(
                group_id = %LogHexId::group(&key),
                requester = %LogHexId::agent(&requester),
                local_epoch = epoch,
                requester_epoch,
                "a member that challenged this daemon holds a later epoch; catching up"
            );
            spawn_treekem_epoch_ahead_catchup(state, &key, requester_epoch);
        }
        if !roster.local_is_admin {
            return Err(Refusal::NotAnAdmin);
        }
        if roster.admins.len() > HEAD_PROOF_MAX_ADMINS {
            return Err(Refusal::Unavailable);
        }
        // The roster's facts are information only, but they must belong to
        // the head the tree reports: read again, and retry if they moved.
        let still = roster_head(state, &key).await.ok_or(Refusal::NoRoom)?;
        if (
            still.state_revision,
            &still.state_hash,
            still.local_is_admin,
        ) != (roster.state_revision, &roster.state_hash, true)
        {
            continue;
        }
        return sign_head(
            state,
            roster,
            &requester,
            nonce,
            epoch,
            authenticator,
            inflate,
        )
        .ok_or(Refusal::Unavailable);
    }
    Err(Refusal::Unavailable)
}

fn sign_head(
    state: &AppState,
    roster: RosterHead,
    requester: &str,
    nonce: &str,
    epoch: u64,
    authenticator: [u8; 32],
    inflate: bool,
) -> Option<HeadProof> {
    let (epoch, authenticator) = if inflate {
        tracing::warn!(
            group_id = %LogHexId::group(&roster.key),
            "{INFLATE_KNOB}=1: signing a head proof with the next epoch and a random authenticator (test-only)"
        );
        (epoch.saturating_add(1), rand::random::<[u8; 32]>())
    } else {
        (epoch, authenticator)
    };
    let claim = HeadClaim {
        version: HEAD_PROOF_VERSION,
        group_id: roster.stable_group_id,
        requester: requester.to_string(),
        nonce: nonce.to_string(),
        treekem_epoch: epoch,
        epoch_authenticator: hex::encode(authenticator),
        security_binding: roster.security_binding,
        state_revision: roster.state_revision,
        admins: roster.admins,
        signer: hex::encode(state.agent.agent_id().as_bytes()),
    };
    let signed_by = build_catchup_signer(state, &claim.sign_input()?)?;
    Some(HeadProof { claim, signed_by })
}

/// A response that carries only `proof`: the page itself was throttled,
/// or did not fit beside the proof.
pub(in crate::server) fn proof_only_response(
    group_id: &str,
    proof: HeadProof,
) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: Vec::new(),
        truncated: false,
        responder_state_hash: None,
        log_evicted_through: None,
        target_member_id: None,
        target_member_key_package_b64: None,
        signed_by: None,
        head_proof: Some(proof),
    }
}

/// Whether `response` carries nothing but a head proof.
pub(in crate::server) fn is_proof_only(response: &TreeKemCatchupResponse) -> bool {
    response.events.is_empty()
        && !response.truncated
        && response.log_evicted_through.is_none()
        && response.target_member_id.is_none()
        && response.target_member_key_package_b64.is_none()
}

/// Send `proof` to `requester` on its own.
pub(in crate::server) async fn send_proof_only(
    state: &AppState,
    requester: &AgentId,
    group_id: &str,
    proof: HeadProof,
) {
    let payload = match serde_json::to_vec(&proof_only_response(group_id, proof)) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(group_id), "failed to serialize a head proof: {e}");
            return;
        }
    };
    #[cfg(test)]
    if let Ok(mut recorded) = state.named_group_test_recorders.catchup_responses.lock() {
        recorded.push(payload.clone());
    }
    if let Err(e) = state
        .agent
        .send_direct_with_config(requester, payload, named_group_direct_delivery_config())
        .await
    {
        tracing::warn!(group_id = %LogHexId::group(group_id), requester = %LogHexId::agent(&hex::encode(requester.as_bytes())), "failed to send a head proof: {e}");
    }
}

/// Why a proof was not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum NotRecorded {
    /// No such room here, or no open round in it.
    NoRound,
    /// The proof answers another challenge.
    OtherNonce,
    /// The proof came after [`HEAD_ROUND_DEADLINE`].
    Late,
    /// The proof is for another group or another requester.
    NotForThisRound,
    /// This member did not challenge the signer in this round.
    NotAsked,
    /// The proof is malformed or its signature does not verify.
    BadSignature,
}

/// An open round: one nonce, the agents it challenged, and the proofs they
/// returned, one per signer (the latest).
#[derive(Debug, Clone)]
pub(in crate::server) struct HeadRound {
    pub(in crate::server) nonce: String,
    pub(in crate::server) opened_at: Instant,
    pub(in crate::server) asked: BTreeSet<String>,
    proofs: BTreeMap<String, HeadProof>,
}

/// What [`round_view`] reports about a room's open round.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))] // A7's GET reports it.
pub(in crate::server) struct RoundView {
    pub(in crate::server) nonce: String,
    pub(in crate::server) opened_at: Instant,
    pub(in crate::server) asked: BTreeSet<String>,
    pub(in crate::server) proofs: Vec<HeadProof>,
}

/// Per daemon: each room's open round, and the answers given to each
/// (room, requester) in the current window.
#[derive(Debug, Default)]
pub(in crate::server) struct HeadProofs {
    rounds: HashMap<String, HeadRound>,
    answered: HashMap<(String, String), VecDeque<Instant>>,
}

impl HeadProofs {
    /// Whether `requester` may have another challenge in `key` answered
    /// now, and if so, count it.
    fn allow_answer(&mut self, key: &str, requester: &str, now: Instant) -> bool {
        if self.answered.len() >= HEAD_PROOF_LIMIT_PRUNE_AT {
            self.answered.retain(|_, stamps| {
                stamps
                    .back()
                    .is_some_and(|last| now.saturating_duration_since(*last) < HEAD_PROOF_WINDOW)
            });
        }
        let stamps = self
            .answered
            .entry((key.to_string(), requester.to_string()))
            .or_default();
        while stamps
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= HEAD_PROOF_WINDOW)
        {
            stamps.pop_front();
        }
        if stamps.len() >= HEAD_PROOFS_PER_WINDOW {
            return false;
        }
        stamps.push_back(now);
        true
    }

    /// Open a round in `key`, replacing any open one and its proofs.
    fn open_round(&mut self, key: &str, nonce: String, asked: BTreeSet<String>, now: Instant) {
        self.rounds.insert(
            key.to_string(),
            HeadRound {
                nonce,
                opened_at: now,
                asked,
                proofs: BTreeMap::new(),
            },
        );
    }

    /// Record `proof` in the open round of `key`, whose stable group id is
    /// `stable_group_id`, for this member `me`.
    fn record(
        &mut self,
        key: &str,
        stable_group_id: &str,
        me: &str,
        proof: HeadProof,
        now: Instant,
    ) -> Result<(), NotRecorded> {
        let round = self.rounds.get_mut(key).ok_or(NotRecorded::NoRound)?;
        if proof.claim.nonce != round.nonce {
            return Err(NotRecorded::OtherNonce);
        }
        if now.saturating_duration_since(round.opened_at) > HEAD_ROUND_DEADLINE {
            return Err(NotRecorded::Late);
        }
        if proof.claim.group_id != stable_group_id || proof.claim.requester != me {
            return Err(NotRecorded::NotForThisRound);
        }
        if !round.asked.contains(&proof.claim.signer) {
            return Err(NotRecorded::NotAsked);
        }
        if !verify(&proof) {
            return Err(NotRecorded::BadSignature);
        }
        round.proofs.insert(proof.claim.signer.clone(), proof);
        Ok(())
    }

    /// Drop the room `alias`: its round and its answer counts.
    pub(in crate::server) fn wipe(&mut self, alias: &str) {
        self.rounds.remove(alias);
        self.answered.retain(|(key, _), _| key != alias);
    }
}

/// The agents a round challenges: every agent the engine `named` (its
/// anchored admin set), plus every active admin on this member's roster,
/// never this member itself. A named admin stays in the set even when this
/// member's roster no longer lists it: a stale commit applied here may
/// have removed it, and only its answer can show that.
pub(in crate::server) fn challenge_set(
    named: &[String],
    roster_admins: &[String],
    me: &str,
) -> BTreeSet<String> {
    let mut asked: BTreeSet<String> = roster_admins
        .iter()
        .map(|admin| admin.to_ascii_lowercase())
        .filter(|admin| is_agent_hex(admin))
        .collect();
    for agent in named
        .iter()
        .map(|agent| agent.to_ascii_lowercase())
        .filter(|agent| is_agent_hex(agent))
    {
        if asked.len() >= HEAD_PROOF_MAX_ADMINS {
            break;
        }
        asked.insert(agent);
    }
    asked.remove(me);
    asked
}

/// The round [`challenge_admins`] opened.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))] // A7's trigger reports it.
pub(in crate::server) struct OpenedRound {
    pub(in crate::server) nonce: String,
    pub(in crate::server) asked: BTreeSet<String>,
}

/// Open a round in `group_id` and send each agent of the
/// [`challenge_set`] this member's signed page request carrying the round's
/// fresh nonce. `None` when this member is not active in the room.
#[cfg_attr(not(test), allow(dead_code))] // A7's trigger route calls it.
pub(in crate::server) async fn challenge_admins(
    state: &Arc<AppState>,
    group_id: &str,
    named: &[String],
) -> Option<OpenedRound> {
    let me = hex::encode(state.agent.agent_id().as_bytes());
    let (key, roster_admins) = {
        let groups = state.named_groups.read().await;
        let (key, info) = groups.get_key_value(group_id).or_else(|| {
            groups
                .iter()
                .find(|(_, info)| info.stable_group_id() == group_id)
        })?;
        if info.withdrawn || !info.has_active_member(&me) {
            return None;
        }
        let admins: Vec<String> = info
            .active_members()
            .filter(|member| member.role.at_least(x0x::groups::GroupRole::Admin))
            .map(|member| member.agent_id.clone())
            .collect();
        (key.clone(), admins)
    };
    let asked = challenge_set(named, &roster_admins, &me);
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let mut request = signed_catchup::page_request(state, &key, None).await?;
    request.head_challenge = Some(nonce.clone());
    signed_catchup::sign_page_request(state, &mut request);
    state
        .treekem_head_proofs
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .open_round(&key, nonce.clone(), asked.clone(), Instant::now());
    tracing::info!(
        group_id = %LogHexId::group(&key),
        asked = asked.len(),
        "TreeKEM head: challenging the room's admins"
    );
    let _sent = futures::future::join_all(asked.iter().filter_map(|agent| {
        let peer = parse_agent_id_hex(agent).ok()?;
        let request = request.clone();
        let key = &key;
        Some(async move {
            if let Err(e) = signed_catchup::send_page_request(state, &peer, request).await {
                tracing::debug!(group_id = %LogHexId::group(key), peer = %LogHexId::agent(&hex::encode(peer.as_bytes())), "head challenge failed: {e}");
            }
        })
    }))
    .await;
    Some(OpenedRound { nonce, asked })
}

/// Record `proof`, which arrived for `group_id`, in this member's open
/// round there. The transport and the claimed sender play no part: the
/// proof is checked against its own signer's key.
pub(in crate::server) async fn record_proof(
    state: &AppState,
    group_id: &str,
    proof: HeadProof,
) -> Result<(), NotRecorded> {
    let me = hex::encode(state.agent.agent_id().as_bytes());
    let (key, stable_group_id) = {
        let groups = state.named_groups.read().await;
        let (key, info) = groups
            .get_key_value(group_id)
            .or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == group_id)
            })
            .ok_or(NotRecorded::NoRound)?;
        (key.clone(), info.stable_group_id().to_string())
    };
    state
        .treekem_head_proofs
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .record(&key, &stable_group_id, &me, proof, Instant::now())
}

/// The open round in `group_id` (a room key), with its recorded proofs.
#[cfg_attr(not(test), allow(dead_code))] // A7's GET reports it.
pub(in crate::server) fn round_view(state: &AppState, group_id: &str) -> Option<RoundView> {
    let book = state
        .treekem_head_proofs
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    book.rounds.get(group_id).map(|round| RoundView {
        nonce: round.nonce.clone(),
        opened_at: round.opened_at,
        asked: round.asked.clone(),
        proofs: round.proofs.values().cloned().collect(),
    })
}

/// Move the open round's opening `by` into the past, for a deadline test.
#[cfg(test)]
pub(in crate::server) fn backdate_round(state: &AppState, group_id: &str, by: Duration) {
    let mut book = state
        .treekem_head_proofs
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(round) = book.rounds.get_mut(group_id) {
        if let Some(earlier) = Instant::now().checked_sub(by) {
            round.opened_at = earlier;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn agent_hex(keypair: &crate::identity::AgentKeypair) -> String {
        hex::encode(keypair.agent_id().as_bytes())
    }

    type Change = Box<dyn Fn(&mut HeadClaim)>;

    fn claim(signer: &str, requester: &str, nonce: &str) -> HeadClaim {
        HeadClaim {
            version: HEAD_PROOF_VERSION,
            group_id: "group".to_string(),
            requester: requester.to_string(),
            nonce: nonce.to_string(),
            treekem_epoch: 7,
            epoch_authenticator: "ab".repeat(32),
            security_binding: Some("treekem:epoch=7".to_string()),
            state_revision: 3,
            admins: vec![signer.to_string()],
            signer: signer.to_string(),
        }
    }

    #[test]
    fn the_inflate_knob_is_off_unless_set() {
        assert!(!inflate_requested(None));
        for value in ["", "0", "true", "yes", "1 ", " 1", "on", "11"] {
            assert!(
                !inflate_requested(Some(value)),
                "{value:?} turns nothing on"
            );
        }
        assert!(inflate_requested(Some("1")));
        assert_eq!(INFLATE_KNOB, "X0X_TEST_HEAD_PROOF_INFLATE");
        assert!(
            std::env::var_os(INFLATE_KNOB).is_none(),
            "the test process does not set the knob"
        );
        assert!(!inflate_knob(), "unset, the knob is off");
    }

    #[test]
    fn the_sign_input_names_its_domain_and_every_field() {
        let base = claim(&"a".repeat(64), &"b".repeat(64), "n");
        let input = base.sign_input().unwrap();
        assert!(input
            .windows(HEAD_PROOF_DOMAIN.len())
            .any(|window| window == HEAD_PROOF_DOMAIN.as_bytes()));
        let changes: Vec<Change> = vec![
            Box::new(|c| c.version = 2),
            Box::new(|c| c.group_id.push('x')),
            Box::new(|c| c.requester = "c".repeat(64)),
            Box::new(|c| c.nonce.push('x')),
            Box::new(|c| c.treekem_epoch += 1),
            Box::new(|c| c.epoch_authenticator = "cd".repeat(32)),
            Box::new(|c| c.security_binding = None),
            Box::new(|c| c.security_binding = Some(String::new())),
            Box::new(|c| c.state_revision += 1),
            Box::new(|c| c.admins.push("c".repeat(64))),
            Box::new(|c| c.signer = "c".repeat(64)),
        ];
        for change in changes {
            let mut other = base.clone();
            change(&mut other);
            assert_ne!(other.sign_input().unwrap(), input);
        }
        // Bytes moved between fields change the encoding.
        let mut left = base.clone();
        left.group_id = "ab".to_string();
        left.nonce = "c".to_string();
        let mut right = base.clone();
        right.group_id = "a".to_string();
        right.nonce = "bc".to_string();
        assert_ne!(left.sign_input(), right.sign_input());
        // The authenticator is signed as its 32 raw bytes, in one form only.
        let mut upper = base.clone();
        upper.epoch_authenticator = "AB".repeat(32);
        assert!(upper.sign_input().is_none());
        let mut short = base;
        short.epoch_authenticator = "ab".repeat(31);
        assert!(short.sign_input().is_none());
    }

    #[test]
    fn a_proof_verifies_only_in_canonical_form_and_for_its_signer_key() {
        let admin = crate::identity::AgentKeypair::generate().unwrap();
        let stranger = crate::identity::AgentKeypair::generate().unwrap();
        let requester = "b".repeat(64);
        let genuine = sign_claim_with(&admin, claim(&agent_hex(&admin), &requester, "n"));
        assert!(verify(&genuine));

        let as_admin_by_stranger =
            sign_claim_with(&stranger, claim(&agent_hex(&admin), &requester, "n"));
        assert!(
            !verify(&as_admin_by_stranger),
            "another key cannot sign as the admin"
        );
        let mut moved = genuine.clone();
        moved.claim.signer = agent_hex(&stranger);
        assert!(
            !verify(&moved),
            "the admin's signature cannot be re-attributed"
        );

        let mut unsorted = claim(&agent_hex(&admin), &requester, "n");
        unsorted.admins = vec!["f".repeat(64), "0".repeat(64)];
        assert!(!verify(&sign_claim_with(&admin, unsorted)));
        let mut repeated = claim(&agent_hex(&admin), &requester, "n");
        repeated.admins = vec!["0".repeat(64), "0".repeat(64)];
        assert!(!verify(&sign_claim_with(&admin, repeated)));
        let mut upper = claim(&agent_hex(&admin), &requester, "n");
        upper.requester = "B".repeat(64);
        assert!(!verify(&sign_claim_with(&admin, upper)));
        let mut long = claim(&agent_hex(&admin), &requester, "n");
        long.nonce = "n".repeat(signed_catchup::HEAD_CHALLENGE_MAX_BYTES + 1);
        assert!(!verify(&sign_claim_with(&admin, long)));
        let empty = claim(&agent_hex(&admin), &requester, "");
        assert!(!verify(&sign_claim_with(&admin, empty)));
    }

    #[test]
    fn a_round_records_only_its_own_nonce_requester_group_and_asked_signers_in_time() {
        let admin = crate::identity::AgentKeypair::generate().unwrap();
        let other = crate::identity::AgentKeypair::generate().unwrap();
        let me = "b".repeat(64);
        let now = Instant::now();
        let mut book = HeadProofs::default();
        let proof = |keypair: &crate::identity::AgentKeypair, nonce: &str| {
            sign_claim_with(keypair, claim(&agent_hex(keypair), &me, nonce))
        };
        assert_eq!(
            book.record("k", "group", &me, proof(&admin, "n"), now),
            Err(NotRecorded::NoRound)
        );
        book.open_round(
            "k",
            "n".to_string(),
            BTreeSet::from([agent_hex(&admin)]),
            now,
        );
        assert_eq!(
            book.record("k", "group", &me, proof(&admin, "m"), now),
            Err(NotRecorded::OtherNonce)
        );
        assert_eq!(
            book.record("k", "other", &me, proof(&admin, "n"), now),
            Err(NotRecorded::NotForThisRound)
        );
        assert_eq!(
            book.record("k", "group", &"c".repeat(64), proof(&admin, "n"), now),
            Err(NotRecorded::NotForThisRound)
        );
        assert_eq!(
            book.record("k", "group", &me, proof(&other, "n"), now),
            Err(NotRecorded::NotAsked)
        );
        let mut tampered = proof(&admin, "n");
        tampered.claim.treekem_epoch += 1;
        assert_eq!(
            book.record("k", "group", &me, tampered, now),
            Err(NotRecorded::BadSignature)
        );
        assert_eq!(
            book.record(
                "k",
                "group",
                &me,
                proof(&admin, "n"),
                now + HEAD_ROUND_DEADLINE + Duration::from_millis(1)
            ),
            Err(NotRecorded::Late)
        );
        assert_eq!(
            book.record(
                "k",
                "group",
                &me,
                proof(&admin, "n"),
                now + HEAD_ROUND_DEADLINE
            ),
            Ok(())
        );
        assert_eq!(book.rounds["k"].proofs.len(), 1);

        book.open_round(
            "k",
            "n2".to_string(),
            BTreeSet::from([agent_hex(&admin)]),
            now,
        );
        assert!(
            book.rounds["k"].proofs.is_empty(),
            "a new round starts empty"
        );
        assert_eq!(
            book.record("k", "group", &me, proof(&admin, "n"), now),
            Err(NotRecorded::OtherNonce)
        );
        book.wipe("k");
        assert!(book.rounds.is_empty());
    }

    #[test]
    fn a_requester_has_twelve_answers_a_minute_per_room() {
        let now = Instant::now();
        let mut book = HeadProofs::default();
        for _ in 0..HEAD_PROOFS_PER_WINDOW {
            assert!(book.allow_answer("k", "r", now));
        }
        assert!(!book.allow_answer("k", "r", now));
        assert!(!book.allow_answer("k", "r", now + Duration::from_secs(59)));
        assert!(book.allow_answer("k", "s", now), "per requester");
        assert!(book.allow_answer("j", "r", now), "per room");
        assert!(
            book.allow_answer("k", "r", now + HEAD_PROOF_WINDOW),
            "the oldest answer leaves the window"
        );
        book.wipe("k");
        assert!(book.answered.keys().all(|(key, _)| key != "k"));

        let mut big = HeadProofs::default();
        for n in 0..HEAD_PROOF_LIMIT_PRUNE_AT {
            big.allow_answer("k", &n.to_string(), now);
        }
        big.allow_answer("k", "late", now + HEAD_PROOF_WINDOW);
        assert_eq!(big.answered.len(), 1, "stale entries are dropped");
    }

    #[test]
    fn the_challenge_set_is_the_named_agents_and_the_roster_admins_but_never_me() {
        let me = "a".repeat(64);
        let roster = vec!["b".repeat(64), me.clone()];
        let named = vec![
            "C".repeat(64),
            "b".repeat(64),
            "not hex".to_string(),
            me.clone(),
        ];
        let asked = challenge_set(&named, &roster, &me);
        assert_eq!(
            asked.into_iter().collect::<Vec<_>>(),
            vec!["b".repeat(64), "c".repeat(64)]
        );
        assert!(challenge_set(&[], std::slice::from_ref(&me), &me).is_empty());
    }
}

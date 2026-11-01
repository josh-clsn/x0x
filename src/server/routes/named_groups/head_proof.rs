//! Head proofs: the wire, the signature, and the answer (survivor re-key
//! A6, `docs/adr/transient/T-treekem-head-proof.md`).
//!
//! A member that was away asks each admin of its room where the room's key
//! stands, with a fresh challenge (`head_rounds.rs`). An admin's daemon
//! answers with a **head proof**: the live TreeKEM tree's epoch and epoch
//! authenticator, signed with its agent key over the challenge, the
//! requester, the group and the signer. The member compares the proof with
//! its own tree (the engine's verdict, plan task C3), so a proof is worth
//! only what the live tree says. Nothing else on the catch-up wire
//! (`responder_state_hash`, a request's `current_state_hash`) is evidence
//! of freshness.
//!
//! - **Who signs.** Only a daemon that is an active admin on its own
//!   roster, and only for a requester that is active there, both before and
//!   after it reads the tree.
//! - **What it signs.** The epoch and authenticator, read together under
//!   the tree's lock ([`x0x::mls::TreeKemMlsGroup::head`]).
//! - **When.** A challenge rides on a signed page request
//!   (`head_challenge`), and is answered only as a [`SignedChallenge`]: one
//!   its requester signed, whatever the transport or route. It is answered
//!   before the #378 page throttle. Challenges are ordered per requester
//!   ([`challenge_counter`]): a newer one always becomes the latest, so
//!   every older one is refused uncharged; the latest one again is re-sent
//!   its proof from cache at most once per [`HEAD_PROOF_REPEAT_WINDOW`];
//!   only newer ones are charged, at most [`HEAD_PROOFS_PER_WINDOW`] per
//!   [`HEAD_PROOF_WINDOW`] per (group, requester). So a replayed challenge
//!   delays the requester by at most one window.

use super::{
    build_catchup_signer, catchup_signer_matches, named_group_direct_delivery_config,
    signed_catchup, spawn_treekem_epoch_ahead_catchup, AppState, CatchupSigner,
    TreeKemCatchupResponse,
};
use crate as x0x;
use crate::identity::AgentId;
use crate::logging::LogHexId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// The domain of a head proof's signature.
pub(in crate::server) const HEAD_PROOF_DOMAIN: &str = "x0x/treekem-head-proof/v1";

/// The head proof format this daemon signs and accepts.
pub(in crate::server) const HEAD_PROOF_VERSION: u32 = 1;

/// How many newer challenges one requester may have answered per group in
/// one [`HEAD_PROOF_WINDOW`]. Each costs an ML-DSA-65 signature (about
/// 1 ms).
pub(in crate::server) const HEAD_PROOFS_PER_WINDOW: usize = 12;

/// The window of [`HEAD_PROOFS_PER_WINDOW`].
pub(in crate::server) const HEAD_PROOF_WINDOW: Duration = Duration::from_secs(60);

/// How often the proof of a requester's latest challenge is re-sent when
/// that challenge comes again.
pub(in crate::server) const HEAD_PROOF_REPEAT_WINDOW: Duration = super::TREEKEM_CATCHUP_THROTTLE;

/// The most admins a proof names, and the most agents a round challenges.
/// A room with more is not answered, and no round is opened in it.
pub(in crate::server) const HEAD_PROOF_MAX_ADMINS: usize = 512;

/// How many hex digits open a challenge with its counter.
const CHALLENGE_COUNTER_HEX: usize = 16;

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
    /// The active admins on the signer's roster, sorted, no repeats. The
    /// signer is one of them.
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

pub(super) fn is_agent_hex(value: &str) -> bool {
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

/// A challenge: the requester's counter as 16 lowercase hex digits, then
/// 32 random bytes as hex (80 characters).
pub(in crate::server) fn challenge_nonce(counter: u64) -> String {
    format!(
        "{counter:0width$x}{}",
        hex::encode(rand::random::<[u8; 32]>()),
        width = CHALLENGE_COUNTER_HEX
    )
}

/// The counter a challenge opens with, when it is one: at most
/// [`signed_catchup::HEAD_CHALLENGE_MAX_BYTES`] long, 16 lowercase hex
/// digits, then at least one more byte.
pub(in crate::server) fn challenge_counter(nonce: &str) -> Option<u64> {
    if !nonce_ok(nonce) || nonce.len() <= CHALLENGE_COUNTER_HEX {
        return None;
    }
    let digits = nonce.get(..CHALLENGE_COUNTER_HEX)?;
    if !digits
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
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

    /// Whether every field is in its one canonical form, and the signer
    /// names itself an admin (a proof that does not is self-contradictory).
    fn well_formed(&self) -> bool {
        self.version == HEAD_PROOF_VERSION
            && is_agent_hex(&self.requester)
            && is_agent_hex(&self.signer)
            && nonce_ok(&self.nonce)
            && self.admins.len() <= HEAD_PROOF_MAX_ADMINS
            && self.admins.iter().all(|admin| is_agent_hex(admin))
            && self.admins.windows(2).all(|pair| pair[0] < pair[1])
            && self.admins.binary_search(&self.signer).is_ok()
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
    /// The challenge is not a counter-prefixed nonce ([`challenge_counter`]).
    BadChallenge,
    /// The requester has since sent a newer challenge (a replay, or one that
    /// got no proof the first time). Not charged.
    StaleChallenge,
    /// This daemon has no live roster or tree for the room. Refused before
    /// the challenge is charged, so the same challenge may be answered
    /// later.
    NoRoom,
    /// The requester is not an active member on this daemon's roster.
    RequesterNotActive,
    /// The requester used up its answers for this window.
    Limited,
    /// This daemon is not an active admin on its own roster.
    NotAnAdmin,
    /// Signing failed, the roster kept moving while it was read, or the
    /// room went away while it was read. Always after the challenge was
    /// charged and made the latest, so this challenge is spent: only the
    /// requester's next one can be answered.
    Unavailable,
    /// The latest challenge again, inside the window since its proof was
    /// last re-sent. Not charged, and nothing is sent.
    RepeatTooSoon,
}

/// A head challenge its requester signed: built only from a page request
/// whose signature verifies for its claimed requester over the group, the
/// requester, the head and the challenge (A5's page-request signature). So
/// only the requester itself can move its floor at an admin (A6 re-review
/// N-2), whatever the transport or the route.
#[derive(Debug, Clone)]
pub(in crate::server) struct SignedChallenge {
    group_id: String,
    requester: String,
    nonce: String,
    requester_epoch: u64,
}

impl SignedChallenge {
    /// The challenge `request` carries, when its requester signed it.
    pub(in crate::server) fn from_request(request: &super::TreeKemCatchupRequest) -> Option<Self> {
        let nonce = request.head_challenge.clone()?;
        signed_catchup::page_request_signed(request).then(|| Self {
            group_id: request.group_id.clone(),
            requester: request.requester_agent_id.to_ascii_lowercase(),
            nonce,
            requester_epoch: request.from_treekem_epoch,
        })
    }
}

/// What [`HeadAnswers::admit`] decides for a challenge.
#[derive(Debug, Clone)]
enum Admission {
    /// A newer challenge, now charged: answer it.
    Fresh,
    /// The latest challenge again: its proof, if it got one.
    Repeat(Option<Box<HeadProof>>),
    /// The latest challenge again, too soon after its last re-send.
    RepeatTooSoon,
    /// An older challenge, or another one with the latest counter.
    Stale,
    /// A newer challenge over the limit.
    Limited,
}

/// One requester's challenges in one room, at this daemon.
#[derive(Debug, Default)]
struct Answered {
    /// When each charged challenge in the current window came.
    stamps: VecDeque<Instant>,
    /// The latest challenge charged: its counter and nonce.
    latest: Option<(u64, String)>,
    /// The proof the latest challenge got.
    proof: Option<HeadProof>,
    /// When that proof was last re-sent for a repeat.
    last_repeat: Option<Instant>,
}

/// Per daemon, per (room, requester): the challenges answered. Entries are
/// made only for requesters active on this daemon's roster, and go with
/// the room.
#[derive(Debug, Default)]
pub(in crate::server) struct HeadAnswers {
    answered: HashMap<(String, String), Answered>,
}

impl HeadAnswers {
    /// Decide on `requester`'s challenge `nonce`, whose counter is
    /// `counter`, in `key`. A newer challenge always becomes the latest,
    /// so every older one is refused from then on, but it is charged only
    /// within the limit (A6 re-review I-1b). The latest one again is
    /// re-sent its proof at most once per [`HEAD_PROOF_REPEAT_WINDOW`]
    /// (N-1), uncharged.
    fn admit(
        &mut self,
        key: &str,
        requester: &str,
        nonce: &str,
        counter: u64,
        now: Instant,
    ) -> Admission {
        let entry = self
            .answered
            .entry((key.to_string(), requester.to_string()))
            .or_default();
        if let Some((latest, latest_nonce)) = &entry.latest {
            if counter < *latest {
                return Admission::Stale;
            }
            if counter == *latest {
                if latest_nonce != nonce {
                    return Admission::Stale;
                }
                let Some(proof) = entry.proof.clone() else {
                    return Admission::Repeat(None);
                };
                if entry.last_repeat.is_some_and(|last| {
                    now.saturating_duration_since(last) < HEAD_PROOF_REPEAT_WINDOW
                }) {
                    return Admission::RepeatTooSoon;
                }
                entry.last_repeat = Some(now);
                return Admission::Repeat(Some(Box::new(proof)));
            }
        }
        while entry
            .stamps
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= HEAD_PROOF_WINDOW)
        {
            entry.stamps.pop_front();
        }
        entry.latest = Some((counter, nonce.to_string()));
        entry.proof = None;
        entry.last_repeat = None;
        if entry.stamps.len() >= HEAD_PROOFS_PER_WINDOW {
            return Admission::Limited;
        }
        entry.stamps.push_back(now);
        Admission::Fresh
    }

    /// Keep `proof` as the answer to `requester`'s latest challenge, if
    /// `nonce` is still the latest.
    fn remember(&mut self, key: &str, requester: &str, nonce: &str, proof: &HeadProof) {
        if let Some(entry) = self
            .answered
            .get_mut(&(key.to_string(), requester.to_string()))
        {
            if entry
                .latest
                .as_ref()
                .is_some_and(|(_, latest)| latest == nonce)
            {
                entry.proof = Some(proof.clone());
            }
        }
    }

    /// Drop the room `alias`.
    pub(in crate::server) fn wipe(&mut self, alias: &str) {
        self.answered.retain(|(key, _), _| key != alias);
    }
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
    requester_active: bool,
}

impl RosterHead {
    /// The facts that must not move while the tree is read.
    fn settled(&self) -> (u64, &str, bool, bool) {
        (
            self.state_revision,
            &self.state_hash,
            self.local_is_admin,
            self.requester_active,
        )
    }
}

async fn roster_head(state: &AppState, group_id: &str, requester: &str) -> Option<RosterHead> {
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
        requester_active: is_agent_hex(requester) && info.has_active_member(requester),
    })
}

/// How many times [`answer_challenge`] reads the roster and the tree again
/// when the roster moved while it read the tree.
const HEAD_READ_ATTEMPTS: usize = 3;

/// Answer `challenge` with this daemon's signed head proof. The
/// requester's signed epoch, when ahead of the live tree, makes this daemon
/// start its own epoch-ahead catch-up, whether or not it is an admin.
///
/// The page serve (`handle_treekem_catchup_request`) calls this after its
/// gates, before its #378 throttle. The A7 route calls it too, with a
/// challenge it can only build from the requester's signed request.
pub(in crate::server) async fn answer_challenge(
    state: &Arc<AppState>,
    challenge: &SignedChallenge,
) -> Result<HeadProof, Refusal> {
    answer_challenge_with(state, challenge, inflate_knob()).await
}

/// [`answer_challenge`], with [`INFLATE_KNOB`]'s effect given as `inflate`.
pub(in crate::server) async fn answer_challenge_with(
    state: &Arc<AppState>,
    challenge: &SignedChallenge,
    inflate: bool,
) -> Result<HeadProof, Refusal> {
    let SignedChallenge {
        group_id,
        requester,
        nonce,
        requester_epoch,
    } = challenge;
    let counter = challenge_counter(nonce).ok_or(Refusal::BadChallenge)?;
    let gate = roster_head(state, group_id, requester)
        .await
        .ok_or(Refusal::NoRoom)?;
    if !gate.requester_active {
        return Err(Refusal::RequesterNotActive);
    }
    let key = gate.key;
    let admission = state
        .treekem_head_answers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(&key, requester, nonce, counter, Instant::now());
    match admission {
        Admission::Fresh => {}
        Admission::Repeat(Some(proof)) => return Ok(*proof),
        Admission::Repeat(None) | Admission::Stale => return Err(Refusal::StaleChallenge),
        Admission::RepeatTooSoon => return Err(Refusal::RepeatTooSoon),
        Admission::Limited => return Err(Refusal::Limited),
    }
    let answered = answer_fresh(state, &key, requester, nonce, *requester_epoch, inflate).await;
    if let Err(refusal) = answered {
        // A6 re-review m-r3: this challenge was charged and is now the
        // latest, so a repeat of it is refused as stale.
        tracing::debug!(
            group_id = %LogHexId::group(&key),
            requester = %LogHexId::agent(requester),
            ?refusal,
            "a charged head challenge got no proof; a repeat of it will be refused as stale"
        );
    }
    answered
}

async fn answer_fresh(
    state: &Arc<AppState>,
    key: &str,
    requester: &str,
    nonce: &str,
    requester_epoch: u64,
    inflate: bool,
) -> Result<HeadProof, Refusal> {
    for _ in 0..HEAD_READ_ATTEMPTS {
        let roster = roster_head(state, key, requester)
            .await
            .ok_or(Refusal::Unavailable)?;
        if !roster.requester_active {
            return Err(Refusal::RequesterNotActive);
        }
        #[cfg(test)]
        {
            let hook = state
                .named_group_test_recorders
                .head_answer_before_tree_read
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some((entered, release)) = hook {
                entered.notify_one();
                release.notified().await;
            }
        }
        // The tree is looked up on every attempt: a Welcome or re-join can
        // replace it.
        let tree = state
            .treekem_groups
            .read()
            .await
            .get(key)
            .cloned()
            .ok_or(Refusal::Unavailable)?;
        // The epoch and the authenticator come from one borrow of the live
        // tree, under its lock, so they cannot be torn.
        let (epoch, authenticator) = {
            let guard = tree.lock().await;
            guard.head().map_err(|_| Refusal::Unavailable)?
        };
        // The roster must not have moved while the tree was read: the
        // requester still active, this daemon still an admin, the same head.
        let still = roster_head(state, key, requester)
            .await
            .ok_or(Refusal::Unavailable)?;
        if still.settled() != roster.settled() {
            continue;
        }
        // Every path below returns, so this runs once per challenge.
        if requester_epoch > epoch {
            tracing::info!(
                group_id = %LogHexId::group(key),
                requester = %LogHexId::agent(requester),
                local_epoch = epoch,
                requester_epoch,
                "a member that challenged this daemon holds a later epoch; catching up"
            );
            spawn_treekem_epoch_ahead_catchup(state, key, requester_epoch);
        }
        if !roster.local_is_admin {
            return Err(Refusal::NotAnAdmin);
        }
        if roster.admins.len() > HEAD_PROOF_MAX_ADMINS {
            return Err(Refusal::Unavailable);
        }
        let proof = sign_head(
            state,
            roster,
            requester,
            nonce,
            epoch,
            authenticator,
            inflate,
        )
        .ok_or(Refusal::Unavailable)?;
        state
            .treekem_head_answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remember(key, requester, nonce, &proof);
        return Ok(proof);
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

/// The direct-message size a page and its proof must fit together.
pub(in crate::server) fn page_and_proof_cap(state: &AppState) -> usize {
    #[cfg(test)]
    {
        let cap = state
            .named_group_test_recorders
            .page_and_proof_cap
            .load(std::sync::atomic::Ordering::SeqCst);
        if cap > 0 {
            return cap;
        }
    }
    #[cfg(not(test))]
    let _ = state;
    x0x::dm::MAX_PAYLOAD_BYTES
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
        // Review m-2: a signer that does not name itself an admin.
        let mut not_listed = claim(&agent_hex(&admin), &requester, "n");
        not_listed.admins = vec!["0".repeat(64)];
        assert!(!verify(&sign_claim_with(&admin, not_listed)));
    }

    #[test]
    fn a_challenge_opens_with_its_counter() {
        let nonce = challenge_nonce(0x1234);
        assert_eq!(nonce.len(), 80);
        assert!(nonce.len() <= signed_catchup::HEAD_CHALLENGE_MAX_BYTES);
        assert_eq!(challenge_counter(&nonce), Some(0x1234));
        assert_eq!(
            challenge_counter(&challenge_nonce(u64::MAX)),
            Some(u64::MAX)
        );
        assert_ne!(challenge_nonce(1), challenge_nonce(1), "the tail is random");
        for bad in [
            "",
            "0000000000000001",
            "000000000000000G-tail",
            "000000000000000A-tail",
            "fresh-nonce",
        ] {
            assert_eq!(challenge_counter(bad), None, "{bad:?}");
        }
        let too_long = format!("{}{}", "0".repeat(16), "x".repeat(200));
        assert_eq!(challenge_counter(&too_long), None);
    }

    #[test]
    fn only_a_newer_challenge_is_charged_and_the_latest_is_answered_from_cache() {
        let keypair = crate::identity::AgentKeypair::generate().unwrap();
        let now = Instant::now();
        let mut book = HeadAnswers::default();
        let first = challenge_nonce(10);
        assert!(matches!(
            book.admit("k", "r", &first, 10, now),
            Admission::Fresh
        ));
        assert!(matches!(
            book.admit("k", "r", &first, 10, now),
            Admission::Repeat(None)
        ));
        let proof = sign_claim_with(&keypair, claim(&agent_hex(&keypair), "r", &first));
        book.remember("k", "r", &first, &proof);
        assert!(matches!(
            book.admit("k", "r", &first, 10, now),
            Admission::Repeat(Some(_))
        ));
        assert!(matches!(
            book.admit("k", "r", &challenge_nonce(10), 10, now),
            Admission::Stale
        ));
        assert!(matches!(
            book.admit("k", "r", &challenge_nonce(9), 9, now),
            Admission::Stale
        ));
        // Replays charge nothing: eleven newer challenges still fit.
        for counter in 11..22 {
            assert!(matches!(
                book.admit("k", "r", &challenge_nonce(counter), counter, now),
                Admission::Fresh
            ));
        }
        let thirty = challenge_nonce(30);
        assert!(matches!(
            book.admit("k", "r", &thirty, 30, now),
            Admission::Limited
        ));
        assert!(
            matches!(
                book.admit("k", "r", &challenge_nonce(25), 25, now + HEAD_PROOF_WINDOW),
                Admission::Stale
            ),
            "a limited newer challenge still raised the floor"
        );
        assert!(matches!(
            book.admit("k", "r", &thirty, 30, now + HEAD_PROOF_WINDOW),
            Admission::Repeat(None)
        ));
        assert!(matches!(
            book.admit("k", "r", &challenge_nonce(31), 31, now + HEAD_PROOF_WINDOW),
            Admission::Fresh
        ));
        assert!(matches!(
            book.admit("k", "s", &challenge_nonce(1), 1, now),
            Admission::Fresh
        ));
        assert!(matches!(
            book.admit("j", "r", &challenge_nonce(1), 1, now),
            Admission::Fresh
        ));
        book.wipe("k");
        assert!(book.answered.keys().all(|(key, _)| key != "k"));
    }

    #[test]
    fn the_latest_proof_is_re_sent_at_most_once_a_window() {
        let keypair = crate::identity::AgentKeypair::generate().unwrap();
        let now = Instant::now();
        let mut book = HeadAnswers::default();
        let nonce = challenge_nonce(5);
        assert!(matches!(
            book.admit("k", "r", &nonce, 5, now),
            Admission::Fresh
        ));
        let proof = sign_claim_with(&keypair, claim(&agent_hex(&keypair), "r", &nonce));
        book.remember("k", "r", &nonce, &proof);
        assert!(matches!(
            book.admit("k", "r", &nonce, 5, now),
            Admission::Repeat(Some(_))
        ));
        assert!(matches!(
            book.admit("k", "r", &nonce, 5, now + HEAD_PROOF_REPEAT_WINDOW / 2),
            Admission::RepeatTooSoon
        ));
        assert!(matches!(
            book.admit("k", "r", &nonce, 5, now + HEAD_PROOF_REPEAT_WINDOW),
            Admission::Repeat(Some(_))
        ));
    }

    /// A6 re-review I-1b: an admin that forgot S (a restart, or it was
    /// offline while S ran rounds) faces a replayer holding 30 of S's
    /// challenges above its floor. S's newest arrives after the twelfth:
    /// it is limited, but it fences off the rest, and S's next challenge
    /// after one window is answered.
    #[test]
    fn a_replayed_stock_of_old_challenges_delays_the_requester_at_most_one_window() {
        let now = Instant::now();
        let mut book = HeadAnswers::default();
        let stock: Vec<(u64, String)> = (1..=30).map(|c| (c, challenge_nonce(c))).collect();
        for (counter, nonce) in &stock[..HEAD_PROOFS_PER_WINDOW] {
            assert!(matches!(
                book.admit("k", "s", nonce, *counter, now),
                Admission::Fresh
            ));
        }
        let newest = challenge_nonce(100);
        assert!(matches!(
            book.admit("k", "s", &newest, 100, now),
            Admission::Limited
        ));
        for (counter, nonce) in &stock[HEAD_PROOFS_PER_WINDOW..] {
            assert!(
                matches!(
                    book.admit("k", "s", nonce, *counter, now + HEAD_PROOF_WINDOW),
                    Admission::Stale
                ),
                "the rest of the stock is fenced off"
            );
        }
        assert!(matches!(
            book.admit(
                "k",
                "s",
                &challenge_nonce(101),
                101,
                now + HEAD_PROOF_WINDOW
            ),
            Admission::Fresh
        ));
    }
}

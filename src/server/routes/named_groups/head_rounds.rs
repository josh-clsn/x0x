//! Head rounds: a member challenges its room's admins and records their
//! head proofs (survivor re-key A6, `docs/adr/transient/T-treekem-head-proof.md`).
//!
//! - **Who is challenged.** Every agent the engine names (its anchored
//!   admin set) and every active admin on this member's roster, never this
//!   member. A named agent is never left out: when the whole set would be
//!   larger than [`HEAD_PROOF_MAX_ADMINS`], no round opens at all, so the
//!   room holds (A6 review C-1).
//! - **The challenge.** A counter that only grows, then 32 random bytes,
//!   so an admin can refuse a replayed older challenge without charging it
//!   (A6 review I-1). The counter is at least the wall clock in
//!   milliseconds, and it is kept on disk ([`HeadCounter`]), so it never
//!   goes back, whatever the clock does across a restart.
//! - **What is recorded.** A proof that verifies, for this member, in this
//!   room, from a signer it challenged, under the open round's nonce,
//!   within [`HEAD_ROUND_DEADLINE`] of the round opening. Every distinct
//!   head a signer signs in a round is kept (at most
//!   [`HEADS_PER_SIGNER`]), and a signer with more than one is marked
//!   conflicted, so a conflict wins whatever order the proofs arrive in
//!   (A6 review I-2).
//!
//! [`HEAD_ROUND_DEADLINE`] runs on the process monotonic clock, which stops
//! while a device sleeps. It is not a freshness age: the engine measures
//! the round deadline and the time to live on its sleep-inclusive clock.

use super::head_proof::{
    challenge_nonce, is_agent_hex, verify, HeadClaim, HeadProof, HEAD_PROOF_MAX_ADMINS,
};
use super::{now_millis_u64, parse_agent_id_hex, signed_catchup, AppState};
use crate as x0x;
use crate::logging::LogHexId;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// How long after a round opens its proofs are recorded.
pub(in crate::server) const HEAD_ROUND_DEADLINE: Duration = Duration::from_secs(60);

/// The most distinct heads kept per signer in one round.
pub(in crate::server) const HEADS_PER_SIGNER: usize = 4;

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

/// The file, under the TreeKEM directory, that holds the last challenge
/// counter this daemon used.
const HEAD_COUNTER_FILE: &str = "head-challenge-counter";

/// This daemon's challenge counter: the last one used, kept on disk so it
/// never goes back (A6 re-review m-r1).
#[derive(Debug)]
pub(in crate::server) struct HeadCounter {
    last: u64,
    path: PathBuf,
}

/// The counter kept under `treekem_dir`. A missing or unreadable file
/// starts from zero, so the next counter is the wall clock.
pub(in crate::server) async fn load_head_counter(treekem_dir: &Path) -> HeadCounter {
    let path = treekem_dir.join(HEAD_COUNTER_FILE);
    let last = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text.trim().parse::<u64>().unwrap_or_else(|_| {
            tracing::warn!(path = %path.display(), "TreeKEM head: the challenge counter file does not parse; starting from the clock");
            0
        }),
        Err(_) => 0,
    };
    HeadCounter { last, path }
}

impl HeadCounter {
    /// The next counter: above the last one and at least `now_ms`, written
    /// to disk (atomically and durably) before it is used. `None` when it
    /// cannot be written or the counter is used up: then no round opens.
    async fn next(&mut self, now_ms: u64) -> Option<u64> {
        let next = self.last.checked_add(1)?.max(now_ms);
        if let Err(e) =
            x0x::storage::write_private_bytes_durable(&self.path, next.to_string().into_bytes())
                .await
        {
            tracing::warn!(path = %self.path.display(), "TreeKEM head: could not keep the challenge counter: {e}");
            return None;
        }
        self.last = next;
        Some(next)
    }
}

/// An open round: one nonce, the agents it challenged, and the distinct
/// heads each signer returned. A head is kept as its claim once its proof
/// verified (A6 re-review m-r2).
#[derive(Debug, Clone)]
struct HeadRound {
    nonce: String,
    opened_at: Instant,
    asked: BTreeSet<String>,
    heads: BTreeMap<String, Vec<HeadClaim>>,
    conflicted: BTreeSet<String>,
}

/// What [`round_view`] reports about a room's open round.
#[derive(Debug, Clone)]
pub(in crate::server) struct RoundView {
    pub(in crate::server) nonce: String,
    /// On the process monotonic clock: not a freshness age, and never
    /// reported (A7's GET leaves it out).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::server) opened_at: Instant,
    pub(in crate::server) asked: BTreeSet<String>,
    /// Every distinct head recorded, by signer, each from a proof that
    /// verified. A signer listed in `conflicted` never counts as a match.
    pub(in crate::server) heads: Vec<HeadClaim>,
    /// Signers that signed more than one head in this round.
    pub(in crate::server) conflicted: BTreeSet<String>,
}

/// Per daemon: each room's open round.
#[derive(Debug, Default)]
pub(in crate::server) struct HeadRounds {
    rounds: HashMap<String, HeadRound>,
}

impl HeadRounds {
    /// Open a round in `key`, replacing any open one and its proofs.
    fn open_round(&mut self, key: &str, nonce: String, asked: BTreeSet<String>, now: Instant) {
        self.rounds.insert(
            key.to_string(),
            HeadRound {
                nonce,
                opened_at: now,
                asked,
                heads: BTreeMap::new(),
                conflicted: BTreeSet::new(),
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
        let claim = proof.claim;
        let signer = claim.signer.clone();
        let heads = round.heads.entry(signer.clone()).or_default();
        let head = |c: &HeadClaim| (c.treekem_epoch, c.epoch_authenticator.clone());
        if heads.iter().any(|kept| head(kept) == head(&claim)) {
            return Ok(());
        }
        if !heads.is_empty() {
            round.conflicted.insert(signer);
        }
        if heads.len() < HEADS_PER_SIGNER {
            heads.push(claim);
        } else if let Some(lowest) = heads
            .iter_mut()
            .min_by_key(|kept| kept.treekem_epoch)
            .filter(|kept| kept.treekem_epoch < claim.treekem_epoch)
        {
            // Full: the highest epochs are the evidence that holds a room.
            *lowest = claim;
        }
        Ok(())
    }

    /// Drop the room `alias`'s round.
    pub(in crate::server) fn wipe(&mut self, alias: &str) {
        self.rounds.remove(alias);
    }
}

/// The agents a round challenges: every agent the engine `named` (its
/// anchored admin set), then every active admin on this member's roster,
/// never this member itself. A named admin stays in the set even when this
/// member's roster no longer lists it: a stale commit applied here may
/// have removed it, and only its answer can show that. `None` when the set
/// would hold more than [`HEAD_PROOF_MAX_ADMINS`]: nothing named is ever
/// dropped to fit, so no round opens and the room holds.
pub(in crate::server) fn challenge_set(
    named: &[String],
    roster_admins: &[String],
    me: &str,
) -> Option<BTreeSet<String>> {
    let mut asked: BTreeSet<String> = named
        .iter()
        .chain(roster_admins)
        .map(|agent| agent.to_ascii_lowercase())
        .filter(|agent| is_agent_hex(agent))
        .collect();
    asked.remove(me);
    (asked.len() <= HEAD_PROOF_MAX_ADMINS).then_some(asked)
}

/// The round [`challenge_admins`] opened.
#[derive(Debug, Clone)]
pub(in crate::server) struct OpenedRound {
    pub(in crate::server) nonce: String,
    pub(in crate::server) asked: BTreeSet<String>,
    /// This member's signed page request carrying the round's challenge,
    /// as every asked agent was sent it. The engine can carry it to an
    /// admin over another path (the relay), whose daemon answers it
    /// through A7's sign route.
    pub(in crate::server) request: super::TreeKemCatchupRequest,
}

/// Why [`challenge_admins`] opened no round. Every one holds the room: no
/// caller may fall back to a smaller set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum NoRound {
    /// No such room here, or it is withdrawn.
    NoRoom,
    /// This member is not active in the room.
    NotActive,
    /// The named agents and the roster admins together are more than
    /// [`HEAD_PROOF_MAX_ADMINS`].
    SetTooLarge,
    /// The challenge counter could not be kept, or is used up.
    NoCounter,
}

/// Open a round in `group_id` and send each agent of the
/// [`challenge_set`] this member's signed page request carrying the round's
/// new challenge. The sends run on their own task. No round, and a reason,
/// when this member is not active in the room, the set is too large or no
/// counter can be kept.
pub(in crate::server) async fn challenge_admins(
    state: &Arc<AppState>,
    group_id: &str,
    named: &[String],
) -> Result<OpenedRound, NoRound> {
    let me = hex::encode(state.agent.agent_id().as_bytes());
    let (key, roster_admins) = {
        let groups = state.named_groups.read().await;
        let (key, info) = groups
            .get_key_value(group_id)
            .or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == group_id)
            })
            .ok_or(NoRound::NoRoom)?;
        if info.withdrawn {
            return Err(NoRound::NoRoom);
        }
        if !info.has_active_member(&me) {
            return Err(NoRound::NotActive);
        }
        let admins: Vec<String> = info
            .active_members()
            .filter(|member| member.role.at_least(x0x::groups::GroupRole::Admin))
            .map(|member| member.agent_id.clone())
            .collect();
        (key.clone(), admins)
    };
    let Some(asked) = challenge_set(named, &roster_admins, &me) else {
        tracing::warn!(
            group_id = %LogHexId::group(&key),
            named = named.len(),
            roster_admins = roster_admins.len(),
            "TreeKEM head: more agents to challenge than a round holds; no round opened, the room holds"
        );
        return Err(NoRound::SetTooLarge);
    };
    let counter = state
        .treekem_head_counter
        .lock()
        .await
        .next(now_millis_u64())
        .await;
    let Some(counter) = counter else {
        tracing::warn!(
            group_id = %LogHexId::group(&key),
            "TreeKEM head: no challenge counter; no round opened, the room holds"
        );
        return Err(NoRound::NoCounter);
    };
    let nonce = challenge_nonce(counter);
    let mut request = signed_catchup::page_request(state, &key, None)
        .await
        .ok_or(NoRound::NoRoom)?;
    request.head_challenge = Some(nonce.clone());
    signed_catchup::sign_page_request(state, &mut request);
    state
        .treekem_head_rounds
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .open_round(&key, nonce.clone(), asked.clone(), Instant::now());
    tracing::info!(
        group_id = %LogHexId::group(&key),
        asked = asked.len(),
        "TreeKEM head: challenging the room's admins"
    );
    let task_state = Arc::clone(state);
    let peers: Vec<_> = asked
        .iter()
        .filter_map(|agent| parse_agent_id_hex(agent).ok())
        .collect();
    let sent = request.clone();
    tokio::spawn(async move {
        let state = &task_state;
        let _sent = futures::future::join_all(peers.into_iter().map(|peer| {
            let request = sent.clone();
            async move {
                if let Err(e) = signed_catchup::send_page_request(state, &peer, request).await {
                    tracing::debug!(peer = %LogHexId::agent(&hex::encode(peer.as_bytes())), "head challenge failed: {e}");
                }
            }
        }))
        .await;
    });
    Ok(OpenedRound {
        nonce,
        asked,
        request,
    })
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
        .treekem_head_rounds
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .record(&key, &stable_group_id, &me, proof, Instant::now())
}

/// The open round in `group_id` (a room key), with its recorded proofs.
pub(in crate::server) fn round_view(state: &AppState, group_id: &str) -> Option<RoundView> {
    let book = state
        .treekem_head_rounds
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    book.rounds.get(group_id).map(|round| RoundView {
        nonce: round.nonce.clone(),
        opened_at: round.opened_at,
        asked: round.asked.clone(),
        heads: round.heads.values().flatten().cloned().collect(),
        conflicted: round.conflicted.clone(),
    })
}

/// This member's next challenge, as a round would carry it.
#[cfg(test)]
pub(in crate::server) async fn next_challenge(state: &AppState) -> String {
    let counter = state
        .treekem_head_counter
        .lock()
        .await
        .next(now_millis_u64())
        .await
        .expect("a challenge counter");
    challenge_nonce(counter)
}

/// Move the open round's opening `by` into the past, for a deadline test.
#[cfg(test)]
pub(in crate::server) fn backdate_round(state: &AppState, group_id: &str, by: Duration) {
    let mut book = state
        .treekem_head_rounds
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

    use super::super::head_proof::{sign_claim_with, HeadClaim, HEAD_PROOF_VERSION};
    use super::*;

    fn agent_hex(keypair: &crate::identity::AgentKeypair) -> String {
        hex::encode(keypair.agent_id().as_bytes())
    }

    fn proof_at(
        keypair: &crate::identity::AgentKeypair,
        requester: &str,
        nonce: &str,
        epoch: u64,
        authenticator: &str,
    ) -> HeadProof {
        let signer = agent_hex(keypair);
        sign_claim_with(
            keypair,
            HeadClaim {
                version: HEAD_PROOF_VERSION,
                group_id: "group".to_string(),
                requester: requester.to_string(),
                nonce: nonce.to_string(),
                treekem_epoch: epoch,
                epoch_authenticator: authenticator.to_string(),
                security_binding: None,
                state_revision: 3,
                admins: vec![signer.clone()],
                signer,
            },
        )
    }

    #[test]
    fn a_round_records_only_its_own_nonce_requester_group_and_asked_signers_in_time() {
        let admin = crate::identity::AgentKeypair::generate().unwrap();
        let other = crate::identity::AgentKeypair::generate().unwrap();
        let me = "b".repeat(64);
        let now = Instant::now();
        let mut book = HeadRounds::default();
        let auth = "ab".repeat(32);
        let proof = |keypair: &crate::identity::AgentKeypair, nonce: &str| {
            proof_at(keypair, &me, nonce, 7, &auth)
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
        assert_eq!(book.rounds["k"].heads.len(), 1);

        book.open_round(
            "k",
            "n2".to_string(),
            BTreeSet::from([agent_hex(&admin)]),
            now,
        );
        assert!(
            book.rounds["k"].heads.is_empty(),
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
    fn every_distinct_head_of_a_signer_is_kept_whatever_the_order() {
        let admin = crate::identity::AgentKeypair::generate().unwrap();
        let me = "b".repeat(64);
        let now = Instant::now();
        let mut book = HeadRounds::default();
        book.open_round(
            "k",
            "n".to_string(),
            BTreeSet::from([agent_hex(&admin)]),
            now,
        );
        let later = proof_at(&admin, &me, "n", 8, &"cd".repeat(32));
        let earlier = proof_at(&admin, &me, "n", 7, &"ab".repeat(32));
        assert_eq!(book.record("k", "group", &me, later, now), Ok(()));
        assert_eq!(book.record("k", "group", &me, earlier.clone(), now), Ok(()));
        assert_eq!(book.record("k", "group", &me, earlier, now), Ok(()));
        let round = &book.rounds["k"];
        let epochs: Vec<u64> = round.heads[&agent_hex(&admin)]
            .iter()
            .map(|c| c.treekem_epoch)
            .collect();
        assert_eq!(
            epochs,
            vec![8, 7],
            "both heads are kept, the duplicate once"
        );
        assert!(round.conflicted.contains(&agent_hex(&admin)));

        // Full: a later epoch replaces the lowest, an earlier one is dropped.
        for (epoch, byte) in [(9, "01"), (10, "02"), (1, "03"), (11, "04")] {
            let head = proof_at(&admin, &me, "n", epoch, &byte.repeat(32));
            assert_eq!(book.record("k", "group", &me, head, now), Ok(()));
        }
        let mut epochs: Vec<u64> = book.rounds["k"].heads[&agent_hex(&admin)]
            .iter()
            .map(|c| c.treekem_epoch)
            .collect();
        epochs.sort_unstable();
        assert_eq!(epochs, vec![8, 9, 10, 11]);
    }

    #[tokio::test]
    async fn the_challenge_counter_only_grows_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut counter = load_head_counter(dir.path()).await;
        assert_eq!(counter.next(1_000).await, Some(1_000));
        assert_eq!(counter.next(1_000).await, Some(1_001));
        // A restart with the clock stepped far back.
        let mut restarted = load_head_counter(dir.path()).await;
        assert_eq!(restarted.next(10).await, Some(1_002));
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join(HEAD_COUNTER_FILE))
                .await
                .unwrap(),
            "1002"
        );
        tokio::fs::write(dir.path().join(HEAD_COUNTER_FILE), "garbage")
            .await
            .unwrap();
        assert_eq!(
            load_head_counter(dir.path()).await.next(500).await,
            Some(500)
        );
        tokio::fs::write(dir.path().join(HEAD_COUNTER_FILE), u64::MAX.to_string())
            .await
            .unwrap();
        assert_eq!(
            load_head_counter(dir.path()).await.next(500).await,
            None,
            "a used-up counter opens no round"
        );
    }

    #[test]
    fn the_challenge_set_never_drops_a_named_agent() {
        let me = "a".repeat(64);
        let roster = vec!["b".repeat(64), me.clone()];
        let named = vec![
            "C".repeat(64),
            "b".repeat(64),
            "not hex".to_string(),
            me.clone(),
        ];
        let asked = challenge_set(&named, &roster, &me).unwrap();
        assert_eq!(
            asked.into_iter().collect::<Vec<_>>(),
            vec!["b".repeat(64), "c".repeat(64)]
        );
        assert_eq!(
            challenge_set(&[], std::slice::from_ref(&me), &me),
            Some(BTreeSet::new())
        );

        // A6 review C-1: a roster padded with admins does not crowd out the
        // named one; the set is refused whole instead.
        let anchored = "d".repeat(64);
        let padded: Vec<String> = (0..HEAD_PROOF_MAX_ADMINS)
            .map(|n| format!("{n:064x}"))
            .collect();
        assert_eq!(
            challenge_set(std::slice::from_ref(&anchored), &padded, &me),
            None
        );
        let full: Vec<String> = padded[..HEAD_PROOF_MAX_ADMINS - 1].to_vec();
        let asked = challenge_set(std::slice::from_ref(&anchored), &full, &me).unwrap();
        assert!(asked.contains(&anchored));
        assert_eq!(asked.len(), HEAD_PROOF_MAX_ADMINS);
    }
}

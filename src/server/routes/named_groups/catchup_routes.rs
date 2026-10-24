//! The routes the engine uses to ask a room's admins where the room's key
//! stands (survivor re-key A7, `docs/adr/transient/T-treekem-head-proof.md`).
//!
//! - `POST /groups/:id/treekem/catch-up` opens a round: it challenges every
//!   agent the engine names (its anchored admin set) and every admin on this
//!   daemon's roster, nobody else, and with an `observed_epoch` ahead of the
//!   live tree it starts this daemon's epoch-ahead catch-up (#1449, plain
//!   page requests). When no round can open, the answer says so and the
//!   room holds: it never opens a smaller round.
//! - `GET /groups/:id/treekem/catch-up?since_revision=<r>` reports the live
//!   head, the admins of every state applied after `r`, and the open round.
//! - `POST /groups/:id/treekem/head-proof` signs this daemon's head proof
//!   for a requester's own signed challenge, as received over another path
//!   (the relay). It takes only the requester's signed page request, so
//!   nobody else can move the requester's floor (A6 re-review N-2).
//! - `POST /groups/:id/treekem/head-proof/accept` records a proof that
//!   reached the engine over another path, under the same rules as one
//!   that arrives over x0x.
//!
//! Every refusal carries a machine `reason` and a `retry`: `later` (hold;
//! the same request may succeed later) or `never` (hold; this request will
//! not succeed as it is).

use super::head_proof::{self, HeadProof, Refusal, SignedChallenge};
use super::head_rounds::{self, NoRound, NotRecorded};
use super::{spawn_treekem_epoch_ahead_catchup, AppState, TreeKemCatchupRequest};
use crate as x0x;
use crate::server::group_access::{
    admit_treekem_catch_up_state, admit_treekem_owner_route, GroupAccess,
};
use crate::server::rider_auth::ActorContext;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use std::sync::Arc;

/// How many times the read route reads the roster and the tree again when
/// the roster moved while it read the tree.
const STATE_READ_ATTEMPTS: usize = 3;

/// Whether a refused request may succeed later as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum Retry {
    /// Hold; the same request may succeed later.
    Later,
    /// Hold; this request will not succeed as it is.
    Never,
}

impl Retry {
    fn as_str(self) -> &'static str {
        match self {
            Retry::Later => "later",
            Retry::Never => "never",
        }
    }
}

/// One refusal: its status, machine reason, retry class and message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) struct Refused {
    pub(in crate::server) status: StatusCode,
    pub(in crate::server) reason: &'static str,
    pub(in crate::server) retry: Retry,
    pub(in crate::server) error: &'static str,
}

impl Refused {
    const fn new(
        status: StatusCode,
        reason: &'static str,
        retry: Retry,
        error: &'static str,
    ) -> Self {
        Self {
            status,
            reason,
            retry,
            error,
        }
    }

    fn body(self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "error": self.error,
            "reason": self.reason,
            "retry": self.retry.as_str(),
        })
    }

    fn respond(self) -> Response {
        (self.status, Json(self.body())).into_response()
    }

    /// A trigger refusal: no round opened, and the room holds.
    fn respond_hold(self) -> Response {
        let mut body = self.body();
        body["round"] = serde_json::Value::Null;
        body["asked"] = serde_json::json!([]);
        body["hold"] = serde_json::Value::Bool(true);
        (self.status, Json(body)).into_response()
    }
}

const NOT_A_TREEKEM_ROOM: Refused = Refused::new(
    StatusCode::CONFLICT,
    "not_a_treekem_room",
    Retry::Never,
    "this room has no TreeKEM tree on this daemon",
);

const UNAVAILABLE: Refused = Refused::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "unavailable",
    Retry::Later,
    "the room's roster kept moving while its head was read",
);

/// The refusal for a challenge [`head_proof::answer_challenge`] did not
/// answer.
pub(in crate::server) fn sign_refusal(refusal: Refusal) -> Refused {
    match refusal {
        Refusal::BadChallenge => Refused::new(
            StatusCode::BAD_REQUEST,
            "bad_challenge",
            Retry::Never,
            "the challenge does not open with a counter",
        ),
        Refusal::StaleChallenge => Refused::new(
            StatusCode::CONFLICT,
            "stale_challenge",
            Retry::Never,
            "the requester has since sent a newer challenge, or this one got no proof",
        ),
        Refusal::NoRoom => Refused::new(
            StatusCode::CONFLICT,
            "not_a_treekem_room",
            Retry::Later,
            "this daemon holds no live roster or tree for the room",
        ),
        Refusal::RequesterNotActive => Refused::new(
            StatusCode::FORBIDDEN,
            "requester_not_active",
            Retry::Never,
            "the requester is not an active member on this daemon's roster",
        ),
        Refusal::Limited => Refused::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Retry::Later,
            "the requester used up its answers for this window",
        ),
        Refusal::NotAnAdmin => Refused::new(
            StatusCode::CONFLICT,
            "not_an_admin",
            Retry::Never,
            "this daemon is not an active admin of the room",
        ),
        Refusal::Unavailable => Refused::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            Retry::Later,
            "signing failed, or the roster kept moving while it was read",
        ),
        Refusal::RepeatTooSoon => Refused::new(
            StatusCode::TOO_MANY_REQUESTS,
            "repeat_too_soon",
            Retry::Later,
            "this challenge's proof was sent moments ago",
        ),
    }
}

/// The refusal when [`head_rounds::challenge_admins`] opened no round.
/// Every one is a hold: the trigger never opens a smaller round.
pub(in crate::server) fn no_round_refusal(reason: NoRound) -> Refused {
    match reason {
        NoRound::NoRoom => Refused::new(
            StatusCode::NOT_FOUND,
            "group_not_found",
            Retry::Never,
            "no such room on this daemon",
        ),
        NoRound::NotActive => Refused::new(
            StatusCode::CONFLICT,
            "not_an_active_member",
            Retry::Never,
            "this daemon is not an active member of the room",
        ),
        NoRound::SetTooLarge => Refused::new(
            StatusCode::CONFLICT,
            "challenge_set_too_large",
            Retry::Never,
            "the named agents and the roster admins are more than a round holds; no round opened, the room holds",
        ),
        NoRound::NoCounter => Refused::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_challenge_counter",
            Retry::Later,
            "the challenge counter could not be kept; no round opened",
        ),
    }
}

/// The machine reason a proof was not recorded.
pub(in crate::server) fn not_recorded_reason(reason: NotRecorded) -> &'static str {
    match reason {
        NotRecorded::NoRound => "no_round",
        NotRecorded::OtherNonce => "other_nonce",
        NotRecorded::Late => "late",
        NotRecorded::NotForThisRound => "not_for_this_round",
        NotRecorded::NotAsked => "not_asked",
        NotRecorded::BadSignature => "bad_signature",
    }
}

/// The admins of every state this daemon applied after `since_revision`,
/// oldest first, each sorted, and whether that list is complete.
///
/// They come from the room's retained commits (#111, `GroupInfo::
/// commit_log`): every commit this daemon sealed or applied is retained,
/// with its roster, at one chokepoint, and the log is kept on disk with the
/// roster. A4's catch-up log holds the events, whose signed commits name
/// only a roster root, so it cannot say who the admins of a state were.
///
/// Complete only when nothing after `since_revision` can be missing: the
/// first retained state after it links by its signed `prev_state_hash` to
/// the retained state at or before it, or, when none is retained (the
/// room's first commit, or the log was trimmed), is revision
/// `since_revision + 1`, so no state can sit between them (revisions only
/// grow); each later state links to the one before; every roster
/// re-derives its commit's signed roster root; and the last one is the
/// live roster. Otherwise the engine must hold.
pub(in crate::server) fn admins_since(
    info: &x0x::groups::GroupInfo,
    since_revision: u64,
) -> (Vec<Vec<String>>, bool) {
    if since_revision > info.state_revision {
        return (Vec::new(), false);
    }
    if since_revision == info.state_revision {
        return (Vec::new(), true);
    }
    let log = &info.commit_log;
    let after: Vec<_> = log
        .iter()
        .filter(|retained| retained.commit.revision > since_revision)
        .collect();
    let admins = after
        .iter()
        .map(|retained| {
            retained
                .roster
                .iter()
                .filter(|(_, member)| {
                    member.state == x0x::groups::GroupMemberState::Active
                        && member.role.at_least(x0x::groups::GroupRole::Admin)
                })
                .map(|(agent, _)| agent.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    let base = log
        .iter()
        .rev()
        .find(|retained| retained.commit.revision <= since_revision);
    let reaches_back = match (base, after.first()) {
        (Some(base), Some(first)) => {
            first.commit.prev_state_hash.as_deref() == Some(base.commit.state_hash.as_str())
        }
        (None, Some(first)) => first.commit.revision == since_revision.saturating_add(1),
        (_, None) => false,
    };
    let linked = after.windows(2).all(|pair| {
        pair[1].commit.prev_state_hash.as_deref() == Some(pair[0].commit.state_hash.as_str())
    });
    let consistent = after
        .iter()
        .all(|retained| retained.roster_root_consistent());
    let reaches_head = after.last().is_some_and(|last| {
        last.commit.revision == info.state_revision && last.commit.state_hash == info.state_hash
    });
    (admins, reaches_back && linked && consistent && reaches_head)
}

/// Re-run the route's admission under this handler's own read of the room
/// (the `/members` pattern), and resolve whether it has a tree.
async fn admitted_tree(
    state: &AppState,
    id: &str,
    actor: &ActorContext,
    read: bool,
) -> Result<Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>, Response> {
    {
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(id) else {
            return Err(super::not_found("group not found").into_response());
        };
        let admission = if read {
            admit_treekem_catch_up_state(info, actor, &local_hex)
        } else {
            admit_treekem_owner_route(info, actor)
        };
        admission.map_err(IntoResponse::into_response)?;
    }
    state
        .treekem_groups
        .read()
        .await
        .get(id)
        .cloned()
        .ok_or_else(|| NOT_A_TREEKEM_ROOM.respond())
}

/// `POST /groups/:id/treekem/catch-up`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct TreeKemCatchUpTriggerRequest {
    /// The highest TreeKEM epoch the engine saw for this room. When it is
    /// ahead of the live tree, this daemon starts its epoch-ahead catch-up.
    #[serde(default)]
    observed_epoch: Option<u64>,
    /// The engine's anchored admin set (C3), as 64-hex agent ids. Each is
    /// challenged, with every admin on this daemon's roster.
    challenge: Vec<String>,
}

/// `POST /groups/:id/treekem/catch-up`: open a round. `202 {"ok": true,
/// "round", "asked", "request", "catching_up"}`, where `round` is the
/// round's challenge (an opaque id the GET reports back), `asked` the
/// agents challenged, `request` this member's signed page request carrying
/// the challenge (for the engine to carry to an admin over the relay), and
/// `catching_up` whether `observed_epoch` started the epoch-ahead
/// catch-up. When no round opens, a refusal with `"round": null` and
/// `"hold": true`: the room holds, and no smaller round is ever opened.
pub(in crate::server) async fn treekem_catch_up_trigger(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    // #1166: the chokepoint admits first (unknown group 404, durable token,
    // withdrawn 409); the handler re-runs the core on its own read.
    _access: GroupAccess,
    Json(body): Json<TreeKemCatchUpTriggerRequest>,
) -> Response {
    let named: Option<Vec<String>> = body
        .challenge
        .iter()
        .map(|agent| {
            (agent.len() == 64 && agent.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| agent.to_ascii_lowercase())
        })
        .collect();
    let Some(named) = named else {
        return Refused::new(
            StatusCode::BAD_REQUEST,
            "bad_challenge_agent",
            Retry::Never,
            "every challenged agent must be a 64-hex agent id",
        )
        .respond_hold();
    };
    let tree = match admitted_tree(&state, &id, &actor, false).await {
        Ok(tree) => tree,
        Err(response) => return response,
    };
    let live_epoch = tree.lock().await.epoch();
    let catching_up = body
        .observed_epoch
        .is_some_and(|observed| observed > live_epoch);
    if let Some(observed) = body.observed_epoch.filter(|_| catching_up) {
        spawn_treekem_epoch_ahead_catchup(&state, &id, observed);
    }
    match head_rounds::challenge_admins(&state, &id, &named).await {
        Ok(opened) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "ok": true,
                "round": opened.nonce,
                "asked": opened.asked,
                "request": opened.request,
                "catching_up": catching_up,
            })),
        )
            .into_response(),
        Err(reason) => no_round_refusal(reason).respond_hold(),
    }
}

/// `GET /groups/:id/treekem/catch-up` query.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct TreeKemCatchUpStateQuery {
    /// The revision of the engine's anchor: `admins_since` lists the admins
    /// of every state applied after it.
    since_revision: u64,
}

/// The roster facts the read route reports, read in one go.
struct RosterState {
    group_id: String,
    revision: u64,
    state_hash: String,
    security_binding: Option<String>,
    admins: Vec<String>,
    admins_since: Vec<Vec<String>>,
    admins_since_complete: bool,
}

async fn roster_state(
    state: &AppState,
    id: &str,
    actor: &ActorContext,
    since_revision: u64,
) -> Result<RosterState, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(super::not_found("group not found").into_response());
    };
    admit_treekem_catch_up_state(info, actor, &local_hex).map_err(IntoResponse::into_response)?;
    let mut admins: Vec<String> = info
        .active_members()
        .filter(|member| member.role.at_least(x0x::groups::GroupRole::Admin))
        .map(|member| member.agent_id.to_ascii_lowercase())
        .collect();
    admins.sort();
    admins.dedup();
    let (admins_since, admins_since_complete) = admins_since(info, since_revision);
    Ok(RosterState {
        group_id: info.stable_group_id().to_string(),
        revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        security_binding: info.security_binding.clone(),
        admins,
        admins_since,
        admins_since_complete,
    })
}

/// `GET /groups/:id/treekem/catch-up?since_revision=<r>`: where this
/// daemon's key for the room stands. `200`:
///
/// - `epoch`, `epoch_authenticator`: the live tree's, from one borrow under
///   its lock;
/// - `security_binding`, `revision`, `admins` (sorted): this daemon's
///   roster, unchanged while the tree was read;
/// - `admins_since`: the admins of every state applied after `r`, oldest
///   first ([`admins_since`]); `admins_since_complete` is false when one
///   may be missing, and the engine must then hold;
/// - `started_at_ms`: an opaque marker of this daemon run. When it
///   changes, the daemon restarted. It is not a clock reading: the engine
///   must never subtract from it;
/// - `connected_admins`, `suspended_since_last_get`: presence facts. Task
///   A8 fills them. Until then they fail closed: nobody connected, and
///   suspended;
/// - `round`: the open round or `null`: `{"round", "asked", "heads",
///   "conflicted"}`, where `round` is the challenge the trigger returned,
///   `heads` every distinct head recorded (each a verified claim), and
///   `conflicted` the signers with more than one. When the round opened is
///   not reported: the daemon's deadline runs on a clock that stops in a
///   sleep, so the engine times a round on its own sleep-inclusive clock
///   (C2), from when it triggered it.
pub(in crate::server) async fn treekem_catch_up_state(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    Query(query): Query<TreeKemCatchUpStateQuery>,
    // #1166: the chokepoint admits first (unknown group 404, rider 403,
    // withdrawn 409, this daemon's seat); the reads below re-run the core.
    _access: GroupAccess,
) -> Response {
    for _ in 0..STATE_READ_ATTEMPTS {
        let roster = match roster_state(&state, &id, &actor, query.since_revision).await {
            Ok(roster) => roster,
            Err(response) => return response,
        };
        let tree = match admitted_tree(&state, &id, &actor, true).await {
            Ok(tree) => tree,
            Err(response) => return response,
        };
        let head = {
            let guard = tree.lock().await;
            guard.head()
        };
        let Ok((epoch, authenticator)) = head else {
            return UNAVAILABLE.respond();
        };
        let still = match roster_state(&state, &id, &actor, query.since_revision).await {
            Ok(still) => still,
            Err(response) => return response,
        };
        if (still.revision, &still.state_hash) != (roster.revision, &roster.state_hash) {
            continue;
        }
        let round = head_rounds::round_view(&state, &id).map(|round| {
            serde_json::json!({
                "round": round.nonce,
                "asked": round.asked,
                "heads": round.heads,
                "conflicted": round.conflicted,
            })
        });
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "group_id": roster.group_id,
                "epoch": epoch,
                "epoch_authenticator": hex::encode(authenticator),
                "security_binding": roster.security_binding,
                "revision": roster.revision,
                "admins": roster.admins,
                "admins_since": roster.admins_since,
                "admins_since_complete": roster.admins_since_complete,
                "started_at_ms": state.started_at_ms,
                // Task A8 fills these from its presence sampler. Until
                // then they fail closed.
                "connected_admins": Vec::<String>::new(),
                "suspended_since_last_get": true,
                "round": round,
            })),
        )
            .into_response();
    }
    UNAVAILABLE.respond()
}

/// `POST /groups/:id/treekem/head-proof`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct TreeKemHeadProofRequest {
    /// The requester's signed page request carrying its challenge, exactly
    /// as it was received (the `request` a trigger returned on the
    /// requester's side).
    request: TreeKemCatchupRequest,
}

/// `POST /groups/:id/treekem/head-proof`: this daemon's signed head proof
/// for a requester's own signed challenge. `200 {"ok": true, "proof"}`.
/// Refusals: `400` `no_challenge`, `challenge_not_signed`, `bad_challenge`,
/// `group_mismatch`; `403` `requester_not_active`; `409` `not_an_admin`,
/// `stale_challenge`, `not_a_treekem_room`; `429` `rate_limited`,
/// `repeat_too_soon`; `503` `unavailable` ([`sign_refusal`]).
pub(in crate::server) async fn treekem_head_proof_sign(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    // #1166: the chokepoint admits first (unknown group 404, durable token,
    // withdrawn 409); the handler re-runs the core on its own read.
    _access: GroupAccess,
    Json(body): Json<TreeKemHeadProofRequest>,
) -> Response {
    if let Err(response) = admitted_tree(&state, &id, &actor, false).await {
        return response;
    }
    let request = body.request;
    if request.head_challenge.is_none() {
        return Refused::new(
            StatusCode::BAD_REQUEST,
            "no_challenge",
            Retry::Never,
            "the page request carries no head challenge",
        )
        .respond();
    }
    let Some(challenge) = SignedChallenge::from_request(&request) else {
        return Refused::new(
            StatusCode::BAD_REQUEST,
            "challenge_not_signed",
            Retry::Never,
            "the page request is not signed by its requester over its challenge",
        )
        .respond();
    };
    let same_room = {
        let groups = state.named_groups.read().await;
        groups
            .get_key_value(&request.group_id)
            .or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == request.group_id)
            })
            .is_some_and(|(key, _)| *key == id)
    };
    if !same_room {
        return Refused::new(
            StatusCode::BAD_REQUEST,
            "group_mismatch",
            Retry::Never,
            "the challenge is for another room",
        )
        .respond();
    }
    match head_proof::answer_challenge(&state, &challenge).await {
        Ok(proof) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "proof": proof })),
        )
            .into_response(),
        Err(refusal) => sign_refusal(refusal).respond(),
    }
}

/// `POST /groups/:id/treekem/head-proof/accept`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct TreeKemHeadProofAcceptRequest {
    /// A head proof, as an admin's daemon signed it.
    proof: HeadProof,
}

/// `POST /groups/:id/treekem/head-proof/accept`: record a proof in this
/// member's open round, under the rules of `head_rounds::record_proof`.
/// `200 {"ok": true, "recorded": true}`, or `200 {"ok": true, "recorded":
/// false, "reason"}` with `no_round`, `other_nonce`, `late`,
/// `not_for_this_round`, `not_asked` or `bad_signature`
/// ([`not_recorded_reason`]).
pub(in crate::server) async fn treekem_head_proof_accept(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    // #1166: the chokepoint admits first (unknown group 404, durable token,
    // withdrawn 409); the handler re-runs the core on its own read.
    _access: GroupAccess,
    Json(body): Json<TreeKemHeadProofAcceptRequest>,
) -> Response {
    if let Err(response) = admitted_tree(&state, &id, &actor, false).await {
        return response;
    }
    let body = match head_rounds::record_proof(&state, &id, body.proof).await {
        Ok(()) => serde_json::json!({ "ok": true, "recorded": true }),
        Err(reason) => serde_json::json!({
            "ok": true,
            "recorded": false,
            "reason": not_recorded_reason(reason),
        }),
    };
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_refusal_has_its_own_reason_and_a_retry_class() {
        let signs = [
            Refusal::BadChallenge,
            Refusal::StaleChallenge,
            Refusal::NoRoom,
            Refusal::RequesterNotActive,
            Refusal::Limited,
            Refusal::NotAnAdmin,
            Refusal::Unavailable,
            Refusal::RepeatTooSoon,
        ]
        .map(sign_refusal);
        let mut reasons: Vec<&str> = signs.iter().map(|r| r.reason).collect();
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(reasons.len(), signs.len(), "one reason per refusal");
        let pick = |refusal| sign_refusal(refusal);
        assert_eq!(
            (
                pick(Refusal::NotAnAdmin).status,
                pick(Refusal::NotAnAdmin).reason
            ),
            (StatusCode::CONFLICT, "not_an_admin")
        );
        assert_eq!(
            (
                pick(Refusal::RequesterNotActive).status,
                pick(Refusal::RequesterNotActive).reason
            ),
            (StatusCode::FORBIDDEN, "requester_not_active")
        );
        // Hold and retry later, as against never.
        for later in [
            Refusal::Limited,
            Refusal::RepeatTooSoon,
            Refusal::Unavailable,
            Refusal::NoRoom,
        ] {
            assert_eq!(pick(later).retry, Retry::Later, "{later:?}");
        }
        for never in [
            Refusal::BadChallenge,
            Refusal::StaleChallenge,
            Refusal::RequesterNotActive,
            Refusal::NotAnAdmin,
        ] {
            assert_eq!(pick(never).retry, Retry::Never, "{never:?}");
        }

        let rounds = [
            NoRound::NoRoom,
            NoRound::NotActive,
            NoRound::SetTooLarge,
            NoRound::NoCounter,
        ]
        .map(no_round_refusal);
        let mut reasons: Vec<&str> = rounds.iter().map(|r| r.reason).collect();
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(reasons.len(), rounds.len());
        assert!(rounds.iter().all(|r| !r.status.is_success()));

        let recorded = [
            NotRecorded::NoRound,
            NotRecorded::OtherNonce,
            NotRecorded::Late,
            NotRecorded::NotForThisRound,
            NotRecorded::NotAsked,
            NotRecorded::BadSignature,
        ]
        .map(not_recorded_reason);
        let mut unique = recorded.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), recorded.len());
    }

    #[test]
    fn admins_since_lists_every_retained_state_and_says_when_one_may_be_missing() {
        use x0x::groups::GroupRole;
        let keypair = x0x::identity::AgentKeypair::generate().unwrap();
        let owner = "01".repeat(32);
        let other = "02".repeat(32);
        let mut info = x0x::groups::GroupInfo::new(
            "room".to_string(),
            String::new(),
            x0x::identity::AgentId([1; 32]),
            "aabb".repeat(8),
        );
        let base = info.seal_commit(&keypair, 1).unwrap().revision;
        info.add_member(other.clone(), GroupRole::Member, None, None);
        info.seal_commit(&keypair, 2).unwrap();
        info.set_member_role(&other, GroupRole::Admin);
        info.seal_commit(&keypair, 3).unwrap();
        info.set_member_role(&other, GroupRole::Member);
        info.seal_commit(&keypair, 4).unwrap();

        let (admins, complete) = admins_since(&info, base);
        assert_eq!(
            admins,
            vec![
                vec![owner.clone()],
                vec![owner.clone(), other.clone()],
                vec![owner.clone()],
            ],
            "the admin who came and went in between is reported"
        );
        assert!(complete);
        assert_eq!(admins_since(&info, info.state_revision), (Vec::new(), true));
        assert_eq!(
            admins_since(&info, info.state_revision + 1),
            (Vec::new(), false),
            "an anchor ahead of this roster is not something it can vouch for"
        );

        // Trimmed down to the state right after the anchor: nothing can be
        // missing, since revisions only grow.
        let mut trimmed = info.clone();
        trimmed.commit_log.remove(0);
        assert_eq!(admins_since(&trimmed, base), admins_since(&info, base));
        // Trimmed past it: the first state after the anchor is gone.
        trimmed.commit_log.remove(0);
        assert!(!admins_since(&trimmed, base).1);
        // The first retained state after the anchor does not follow it.
        let mut forked = info.clone();
        if let Some(first) = forked.commit_log.get_mut(1) {
            first.commit.prev_state_hash = Some("another".to_string());
        }
        assert!(!admins_since(&forked, base).1);
        // A retained state is missing in between.
        let mut holed = info.clone();
        holed.commit_log.remove(2);
        assert!(!admins_since(&holed, base).1);
        // A retained roster no longer matches its signed root.
        let mut corrupt = info.clone();
        if let Some(last) = corrupt.commit_log.last_mut() {
            last.roster.remove(&owner);
        }
        assert!(!admins_since(&corrupt, base).1);
        // The live roster moved past the last retained state.
        let mut moved = info.clone();
        moved.add_member("03".repeat(32), GroupRole::Admin, None, None);
        moved.recompute_state_hash();
        assert!(!admins_since(&moved, base).1);
    }

    #[test]
    fn a_hold_says_no_round_and_hold() {
        let refused = no_round_refusal(NoRound::SetTooLarge);
        let mut body = refused.body();
        body["round"] = serde_json::Value::Null;
        assert_eq!(body["ok"], false);
        assert_eq!(body["reason"], "challenge_set_too_large");
        assert_eq!(body["retry"], "never");
        assert_eq!(refused.status, StatusCode::CONFLICT);
    }
}

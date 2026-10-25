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
//! **Every non-2xx answer is a hold.** A refusal these handlers produce
//! carries a machine `reason` and a `retry` hint ([`Retry`]); the
//! admission refusals (unknown group 404, bearer 403, withdrawn 409) and
//! axum's own extractor rejections (400/422, plain text) carry neither,
//! and are holds too. The hints mean:
//!
//! - `later`: hold; the **same request** may succeed if sent again later;
//! - `new_round`: hold; this request is spent and will never succeed, but
//!   a **new round** (a fresh challenge from the requester's next trigger)
//!   may succeed later;
//! - `never`: hold; neither helps until something about the room changes
//!   (a member, a role, the plane), or the request is malformed.

use super::head_proof::{self, HeadProof, Refusal, SignedChallenge};
use super::head_rounds::{self, NoRound, NotRecorded};
use super::rekey_obligations;
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

/// What a refused request's sender may do next. Every refusal is a hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum Retry {
    /// The same request may succeed if sent again later.
    Later,
    /// This request is spent; a new round, with a fresh challenge, may
    /// succeed later.
    NewRound,
    /// Nothing succeeds until something about the room changes.
    Never,
}

impl Retry {
    fn as_str(self) -> &'static str {
        match self {
            Retry::Later => "later",
            Retry::NewRound => "new_round",
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

/// The refusal when this daemon holds no TreeKEM tree for the room, on
/// every route. A room on the TreeKEM plane whose tree is not installed
/// yet (a Welcome pending, a re-join in flight) may have one later; a room
/// on another plane never will.
pub(in crate::server) fn not_a_treekem_room(treekem_plane: bool) -> Refused {
    Refused::new(
        StatusCode::CONFLICT,
        "not_a_treekem_room",
        if treekem_plane {
            Retry::Later
        } else {
            Retry::Never
        },
        "this daemon holds no TreeKEM tree for the room",
    )
}

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
        // Refused before the challenge was charged. The route has already
        // seen this room's tree, so it is a room on the TreeKEM plane.
        Refusal::NoRoom => not_a_treekem_room(true),
        Refusal::RequesterNotActive => Refused::new(
            StatusCode::FORBIDDEN,
            "requester_not_active",
            Retry::Never,
            "the requester is not an active member on this daemon's roster",
        ),
        // A limited challenge still becomes the latest, so this request is
        // refused as stale from now on; the requester's next round may be
        // answered once the window frees.
        Refusal::Limited => Refused::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Retry::NewRound,
            "the requester used up its answers for this window",
        ),
        Refusal::NotAnAdmin => Refused::new(
            StatusCode::CONFLICT,
            "not_an_admin",
            Retry::Never,
            "this daemon is not an active admin of the room",
        ),
        // Always after the challenge was charged: it is spent.
        Refusal::Unavailable => Refused::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            Retry::NewRound,
            "signing failed, or the room moved or went away while it was read",
        ),
        // The cached proof is re-sent to the same request after the window.
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
        NoRound::NoSignature => Refused::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "challenge_not_signed",
            Retry::Later,
            "this member's challenge could not be signed; no round opened",
        ),
        NoRound::TooSoon => Refused::new(
            StatusCode::TOO_MANY_REQUESTS,
            "round_too_soon",
            Retry::Later,
            "a round opened in this room moments ago; it stays open",
        ),
    }
}

/// The GET's refusal when the roster kept moving across every read.
const STATE_UNAVAILABLE: Refused = Refused::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "unavailable",
    Retry::Later,
    "the room's roster kept moving while its head was read",
);

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

/// The admins of every state applied after an anchor ([`admins_since`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct AdminsSince {
    /// Each state's active admins, oldest state first, each sorted.
    pub(in crate::server) states: Vec<Vec<String>>,
    /// Whether no state after the anchor can be missing.
    pub(in crate::server) complete: bool,
    /// The states name more distinct admins than a round could challenge:
    /// `states` is left empty and `complete` false, so the engine holds
    /// (it could not open a round for them anyway).
    pub(in crate::server) too_large: bool,
}

impl AdminsSince {
    fn incomplete() -> Self {
        Self {
            states: Vec::new(),
            complete: false,
            too_large: false,
        }
    }
}

/// The admins of every state this daemon applied after the anchor
/// `(since_revision, since_state_hash)`, oldest first, each sorted, and
/// whether that list is complete.
///
/// They come from the room's retained commits (#111, `GroupInfo::
/// commit_log`): every commit this daemon sealed or applied is retained,
/// with its roster, at one chokepoint, and the log is kept on disk with the
/// roster. A4's catch-up log holds the events, whose signed commits name
/// only a roster root, so it cannot say who the admins of a state were.
///
/// Complete only when nothing after the anchor can be missing: the first
/// retained state after it links by its signed `prev_state_hash` to the
/// retained state at or before it, or, when none is retained (the room's
/// first commit, or the log was trimmed), is revision `since_revision + 1`,
/// so no state can sit between them (revisions only grow); each later
/// state links to the one before; every roster re-derives its commit's
/// signed roster root; and the last one is the live roster. When the
/// engine gives the anchor's `since_state_hash`, the anchor must also be
/// that state: the retained base's hash, or the first state's
/// `prev_state_hash`, or the live hash when nothing was applied since (A7
/// review m-3). Otherwise the engine must hold.
pub(in crate::server) fn admins_since(
    info: &x0x::groups::GroupInfo,
    since_revision: u64,
    since_state_hash: Option<&str>,
) -> AdminsSince {
    let anchored_at = |hash: Option<&str>| since_state_hash.is_none_or(|want| hash == Some(want));
    if since_revision > info.state_revision {
        return AdminsSince::incomplete();
    }
    if since_revision == info.state_revision {
        return AdminsSince {
            states: Vec::new(),
            complete: anchored_at(Some(info.state_hash.as_str())),
            too_large: false,
        };
    }
    let log = &info.commit_log;
    let after: Vec<_> = log
        .iter()
        .filter(|retained| retained.commit.revision > since_revision)
        .collect();
    let mut union = std::collections::BTreeSet::new();
    let mut states = Vec::with_capacity(after.len());
    for retained in &after {
        let admins: Vec<String> = retained
            .roster
            .iter()
            .filter(|(_, member)| {
                member.state == x0x::groups::GroupMemberState::Active
                    && member.role.at_least(x0x::groups::GroupRole::Admin)
            })
            .map(|(agent, _)| agent.to_ascii_lowercase())
            .collect();
        union.extend(admins.iter().cloned());
        if union.len() > head_proof::HEAD_PROOF_MAX_ADMINS {
            return AdminsSince {
                too_large: true,
                ..AdminsSince::incomplete()
            };
        }
        states.push(admins);
    }
    let base = log
        .iter()
        .rev()
        .find(|retained| retained.commit.revision <= since_revision);
    let reaches_back = match (base, after.first()) {
        (Some(base), Some(first)) => {
            first.commit.prev_state_hash.as_deref() == Some(base.commit.state_hash.as_str())
                && anchored_at(Some(base.commit.state_hash.as_str()))
        }
        (None, Some(first)) => {
            first.commit.revision == since_revision.saturating_add(1)
                && anchored_at(first.commit.prev_state_hash.as_deref())
        }
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
    AdminsSince {
        states,
        complete: reaches_back && linked && consistent && reaches_head,
        too_large: false,
    }
}

/// Re-run the route's admission under this handler's own read of the room
/// (the `/members` pattern), and resolve whether it has a tree.
///
/// The trigger passes `hold`, so its `not_a_treekem_room` carries the hold
/// body like every other refusal it produces.
async fn admitted_tree(
    state: &AppState,
    id: &str,
    actor: &ActorContext,
    read: bool,
    hold: bool,
) -> Result<Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>, Response> {
    let treekem_plane = {
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
        info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
    };
    let tree = state.treekem_groups.read().await.get(id).cloned();
    tree.ok_or_else(|| {
        let refused = not_a_treekem_room(treekem_plane);
        if hold {
            refused.respond_hold()
        } else {
            refused.respond()
        }
    })
}

/// `POST /groups/:id/treekem/catch-up`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct TreeKemCatchUpTriggerRequest {
    /// The highest TreeKEM epoch the engine saw for this room. When it is
    /// ahead of the live tree, this daemon starts its epoch-ahead catch-up.
    #[serde(default)]
    observed_epoch: Option<u64>,
    /// The engine's anchored admin set (C3), as 64-hex agent ids. Each is
    /// challenged, with every admin on this daemon's roster. Absent or
    /// empty, only the roster's admins are.
    #[serde(default)]
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
/// Such a refusal also closes the room's previous round, so the GET never
/// reports a round asked of fewer agents than the engine named (A7 review
/// m-6), except `round_too_soon`, which leaves the round opened moments
/// ago in place. A room opens at most one round per
/// [`head_rounds::ROUND_MIN_GAP`] (A7 review m-5).
pub(in crate::server) async fn treekem_catch_up_trigger(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    // #1166: the chokepoint admits first (unknown group 404, durable token,
    // withdrawn 409); the handler re-runs the core on its own read.
    _access: GroupAccess,
    Json(body): Json<TreeKemCatchUpTriggerRequest>,
) -> Response {
    let tree = match admitted_tree(&state, &id, &actor, false, true).await {
        Ok(tree) => tree,
        Err(response) => {
            head_rounds::close_round(&state, &id);
            return response;
        }
    };
    let named: Option<Vec<String>> = body
        .challenge
        .iter()
        .map(|agent| {
            (agent.len() == 64 && agent.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| agent.to_ascii_lowercase())
        })
        .collect();
    let Some(named) = named else {
        head_rounds::close_round(&state, &id);
        return Refused::new(
            StatusCode::BAD_REQUEST,
            "bad_challenge_agent",
            Retry::Never,
            "every challenged agent must be a 64-hex agent id",
        )
        .respond_hold();
    };
    let live_epoch = tree.lock().await.epoch();
    let catching_up = body
        .observed_epoch
        .is_some_and(|observed| observed > live_epoch);
    if let Some(observed) = body.observed_epoch.filter(|_| catching_up) {
        spawn_treekem_epoch_ahead_catchup(&state, &id, observed);
    }
    match head_rounds::challenge_admins(&state, &id, &named, head_rounds::ROUND_MIN_GAP).await {
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
        Err(reason) => {
            if reason != NoRound::TooSoon {
                head_rounds::close_round(&state, &id);
            }
            no_round_refusal(reason).respond_hold()
        }
    }
}

/// `GET /groups/:id/treekem/catch-up` query.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct TreeKemCatchUpStateQuery {
    /// The revision of the engine's anchor: `admins_since` lists the admins
    /// of every state applied after it.
    since_revision: u64,
    /// The anchor's state hash, when the engine kept it: the anchor must
    /// then be that very state for `admins_since_complete`.
    #[serde(default)]
    since_state_hash: Option<String>,
    /// The `presence_mark` of the reader's previous GET (survivor re-key
    /// A8): `suspended_since_last_get` is measured from it.
    #[serde(default)]
    since_presence_mark: Option<String>,
}

/// The roster facts the read route reports, read in one go.
struct RosterState {
    group_id: String,
    revision: u64,
    state_hash: String,
    security_binding: Option<String>,
    admins: Vec<String>,
    admins_since: AdminsSince,
    /// The fork-quarantine marker's wire fields, `(revision, no_anchor)`,
    /// when the room is quarantined. Its forensic snapshot stays private.
    fork_quarantine: Option<(u64, bool)>,
}

/// The roster's revision and hash, admitted again: the second read that
/// checks the roster did not move while the tree was read.
async fn roster_head(
    state: &AppState,
    id: &str,
    actor: &ActorContext,
) -> Result<(u64, String), Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(super::not_found("group not found").into_response());
    };
    admit_treekem_catch_up_state(info, actor, &local_hex).map_err(IntoResponse::into_response)?;
    Ok((info.state_revision, info.state_hash.clone()))
}

async fn roster_state(
    state: &AppState,
    id: &str,
    actor: &ActorContext,
    query: &TreeKemCatchUpStateQuery,
) -> Result<RosterState, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    // #732: this read feeds the quarantine report, so it resolves both
    // spellings (the extractor already required the direct key).
    let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, id) else {
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
    Ok(RosterState {
        group_id: info.stable_group_id().to_string(),
        revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        security_binding: info.security_binding.clone(),
        admins,
        admins_since: admins_since(
            info,
            query.since_revision,
            query.since_state_hash.as_deref(),
        ),
        fork_quarantine: info
            .fork_quarantine
            .as_ref()
            .map(|marker| (marker.revision, marker.no_anchor)),
    })
}

/// `GET /groups/:id/treekem/catch-up?since_revision=<r>`: where this
/// daemon's key for the room stands. `200`:
///
/// - `epoch`, `epoch_authenticator`: the live tree's, from one borrow under
///   its lock;
/// - `security_binding`, `revision`, `state_hash`, `admins` (sorted):
///   this daemon's roster, unchanged while the tree was read;
/// - `admins_since`: the admins of every state applied after `r`, oldest
///   first ([`admins_since`]); `admins_since_complete` is false when one
///   may be missing, and the engine must then hold; `admins_since_too_large`
///   is true (with an empty list) when they name more admins than a round
///   holds, which is a hold too;
/// - `fork_quarantined`: whether the room is fork-quarantined here, and
///   when it is, `fork_quarantine: {"revision", "no_anchor"}`. Every seal
///   is refused while it is, so the engine holds and says the room needs a
///   new invite;
/// - `run_id`: 32 hex digits, different on every daemon run: when it
///   changes, the daemon restarted. `started_at_ms` is the wall clock at
///   the start, for display only: two runs can share it, and the engine
///   must never subtract from it;
/// - `connected_admins`: the admins, of the live roster and of every state
///   since the anchor, this daemon holds a live authenticated link to,
///   held to the zombie rule after a suspend ([`crate::server::presence_facts`]);
///   `admin_links` maps each of them to its link id, which changes when
///   the link drops and comes back, so a link that is not continuous
///   between two reads shows;
/// - `suspended_since_last_get`, `presence_mark`: whether this daemon was
///   suspended or frozen since the GET whose `presence_mark` the reader
///   passes as `since_presence_mark`. No mark, another run's mark, or a
///   platform without a verified suspend pair reads `true`;
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
        let roster = match roster_state(&state, &id, &actor, &query).await {
            Ok(roster) => roster,
            Err(response) => return response,
        };
        let tree = match admitted_tree(&state, &id, &actor, true, false).await {
            Ok(tree) => tree,
            Err(response) => return response,
        };
        let head = {
            let guard = tree.lock().await;
            guard.head()
        };
        let Ok((epoch, authenticator)) = head else {
            return STATE_UNAVAILABLE.respond();
        };
        let still = match roster_head(&state, &id, &actor).await {
            Ok(still) => still,
            Err(response) => return response,
        };
        if still != (roster.revision, roster.state_hash.clone()) {
            continue;
        }
        // Presence covers every admin the engine's closure can hold: the
        // live roster's and those of every state applied since the anchor.
        // One it does not list is never reported connected.
        let mut present_over: Vec<String> = roster
            .admins
            .iter()
            .chain(roster.admins_since.states.iter().flatten())
            .cloned()
            .collect();
        present_over.sort();
        present_over.dedup();
        let presence = crate::server::presence_facts::report_for(
            &state,
            query.since_presence_mark.as_deref(),
            &present_over,
        )
        .await;
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
                "state_hash": roster.state_hash,
                "admins": roster.admins,
                "admins_since": roster.admins_since.states,
                "admins_since_complete": roster.admins_since.complete,
                "admins_since_too_large": roster.admins_since.too_large,
                "fork_quarantined": roster.fork_quarantine.is_some(),
                "fork_quarantine": roster.fork_quarantine.map(|(revision, no_anchor)| {
                    serde_json::json!({ "revision": revision, "no_anchor": no_anchor })
                }),
                "started_at_ms": state.presence.started_at_ms(),
                "run_id": state.presence.run_id(),
                "connected_admins": presence.connected_admins,
                "admin_links": presence.admin_links,
                "suspended_since_last_get": presence.suspended_since_last_get,
                "presence_mark": presence.presence_mark,
                "round": round,
            })),
        )
            .into_response();
    }
    STATE_UNAVAILABLE.respond()
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
/// `stale_challenge`, `not_a_treekem_room`; `429` `rate_limited`
/// (`new_round`), `repeat_too_soon` (`later`); `503` `unavailable`
/// (`new_round`) ([`sign_refusal`]).
pub(in crate::server) async fn treekem_head_proof_sign(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    // #1166: the chokepoint admits first (unknown group 404, durable token,
    // withdrawn 409); the handler re-runs the core on its own read.
    _access: GroupAccess,
    Json(body): Json<TreeKemHeadProofRequest>,
) -> Response {
    if let Err(response) = admitted_tree(&state, &id, &actor, false, false).await {
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
    // Survivor re-key A10: the requester signed its head, so it holds that
    // epoch, and this daemon's obligation to it is settled as far.
    if let Some(proof) = rekey_obligations::request_proof(&request, false) {
        rekey_obligations::settle(&state, std::slice::from_ref(&id), &proof).await;
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
    if let Err(response) = admitted_tree(&state, &id, &actor, false, false).await {
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
        // The hint says what can succeed next (A7 review m-2): the same
        // request, only a new round, or nothing until the room changes.
        for later in [Refusal::RepeatTooSoon, Refusal::NoRoom] {
            assert_eq!(pick(later).retry, Retry::Later, "{later:?}");
        }
        for spent in [Refusal::Limited, Refusal::Unavailable] {
            assert_eq!(pick(spent).retry, Retry::NewRound, "{spent:?}");
        }
        assert_eq!(not_a_treekem_room(true).retry, Retry::Later);
        assert_eq!(not_a_treekem_room(false).retry, Retry::Never);
        assert_eq!(
            pick(Refusal::NoRoom).reason,
            not_a_treekem_room(true).reason,
            "one reason on every route"
        );
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
            NoRound::NoSignature,
            NoRound::TooSoon,
        ]
        .map(no_round_refusal);
        assert_eq!(
            no_round_refusal(NoRound::TooSoon).status,
            StatusCode::TOO_MANY_REQUESTS
        );
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

        let since = admins_since(&info, base, None);
        assert_eq!(
            since.states,
            vec![
                vec![owner.clone()],
                vec![owner.clone(), other.clone()],
                vec![owner.clone()],
            ],
            "the admin who came and went in between is reported"
        );
        assert!(since.complete && !since.too_large);
        let complete = |info: &x0x::groups::GroupInfo, hash: Option<&str>| {
            admins_since(info, base, hash).complete
        };
        let none = AdminsSince {
            states: Vec::new(),
            complete: true,
            too_large: false,
        };
        assert_eq!(admins_since(&info, info.state_revision, None), none);
        assert!(
            !admins_since(&info, info.state_revision + 1, None).complete,
            "an anchor ahead of this roster is not something it can vouch for"
        );

        // The anchor's identity (A7 review m-3).
        let base_hash = info.commit_log[0].commit.state_hash.clone();
        assert!(complete(&info, Some(&base_hash)));
        assert!(
            !complete(&info, Some("another state at that revision")),
            "the anchor must be this daemon's state, not only its revision"
        );
        assert!(admins_since(&info, info.state_revision, Some(&info.state_hash)).complete);
        assert!(!admins_since(&info, info.state_revision, Some("other")).complete);

        // Trimmed down to the state right after the anchor: nothing can be
        // missing, since revisions only grow.
        let mut trimmed = info.clone();
        trimmed.commit_log.remove(0);
        assert_eq!(admins_since(&trimmed, base, None), since);
        assert!(
            complete(&trimmed, Some(&base_hash)),
            "linked by its prev hash"
        );
        assert!(!complete(&trimmed, Some("other")));
        // Trimmed past it: the first state after the anchor is gone.
        trimmed.commit_log.remove(0);
        assert!(!complete(&trimmed, None));
        // The first retained state after the anchor does not follow it.
        let mut forked = info.clone();
        if let Some(first) = forked.commit_log.get_mut(1) {
            first.commit.prev_state_hash = Some("another".to_string());
        }
        assert!(!complete(&forked, None));
        // A retained state is missing in between.
        let mut holed = info.clone();
        holed.commit_log.remove(2);
        assert!(!complete(&holed, None));
        // A retained roster no longer matches its signed root.
        let mut corrupt = info.clone();
        if let Some(last) = corrupt.commit_log.last_mut() {
            last.roster.remove(&owner);
        }
        assert!(!complete(&corrupt, None));
        // The live roster moved past the last retained state.
        let mut moved = info.clone();
        moved.add_member("03".repeat(32), GroupRole::Admin, None, None);
        moved.recompute_state_hash();
        assert!(!complete(&moved, None));
    }

    /// A7 review m-4: states naming more admins than a round holds are not
    /// listed; the answer says so, and the engine holds.
    #[test]
    fn admins_since_too_large_to_challenge_is_a_hold() {
        use x0x::groups::GroupRole;
        let keypair = x0x::identity::AgentKeypair::generate().unwrap();
        let mut info = x0x::groups::GroupInfo::new(
            "room".to_string(),
            String::new(),
            x0x::identity::AgentId([1; 32]),
            "ccdd".repeat(8),
        );
        let base = info.seal_commit(&keypair, 1).unwrap().revision;
        for n in 0..=head_proof::HEAD_PROOF_MAX_ADMINS {
            info.add_member(format!("{:064x}", n + 1000), GroupRole::Admin, None, None);
        }
        info.seal_commit(&keypair, 2).unwrap();
        let since = admins_since(&info, base, None);
        assert!(since.too_large);
        assert!(!since.complete);
        assert!(since.states.is_empty());
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

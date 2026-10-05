//! Group-plane access admission — issue #1166 slices S1 (read family)
//! and S2 (secure-write family).
//!
//! One chokepoint owns the answer to "who may enter a group route" for
//! the group plane. Before this module every handler re-derived that
//! decision inline (durable bypass → rider 403 → session-membership 403,
//! each with its own hand-rolled body); #821/#870/#877 were all drift
//! between copies of that logic. The two halves of the design:
//!
//! - [`GROUP_PLANE_ROUTES`], a static classification table keyed by
//!   (method, path) covering EVERY group-plane route the router wires
//!   (`/groups*`, `/history*`, `/task-lists*`, `/mls/groups*`). Routes are
//!   either classified at their target [`AccessLevel`] or explicitly
//!   [`AccessClass::Unmigrated`] until their slice lands. A parity test
//!   holds the table, the axum router (`src/server/mod.rs`) and the
//!   endpoint registry (`crate::api::ENDPOINTS`) to exactly the same route
//!   set, so no group route can be added without being classified here.
//! - [`GroupAccess`], an axum extractor that resolves the `:id` group —
//!   percent-decoded through the same axum `Path` machinery the handlers
//!   used before this module existed — under the named-groups read lock,
//!   applies the route's admission rules, and either rejects with the
//!   exact status/body the inline code produced or hands the handler the
//!   resolved level plus the stable group id. Classification keys off
//!   the router's own `MatchedPath` pattern, so this module never
//!   re-implements route matching.
//!
//! Seven classified routes cannot take the extractor: the S1 details and
//! delegations handlers and all five S2 secure-write handlers are called
//! DIRECTLY with positional extractor arguments by regression tests that
//! must not be edited (the withdrawn-tombstone and lost-race tests in
//! `routes/named_groups.rs`; `routes/named_groups/tests/adr0066_delegations.rs`),
//! so their signatures are pinned. Those handlers call the same admission
//! cores ([`admit_named_group_details`], [`admit_group_delegations`],
//! [`admit_group_send`], [`admit_secure_endpoint`],
//! [`admit_open_envelope`]) with the values they already hold under their
//! own lock; the decision cannot diverge from the extractor path because
//! both ends run the same function.
//!
//! Admission runs twice where the handler re-reads group data for its
//! body (`/members`, `/state/commits`): once in the extractor (an early
//! refusal that keeps cheap rejects away from the body) and once inside
//! the handler's own lock via the same pure core, so the served roster
//! or commit log is always admitted on the snapshot it is read from —
//! no read-check-serve window between two lock takes. `GET
//! /groups/:id/messages` is the deliberate exception: its unknown-group
//! fail-open and its stable-id resolution are one snapshot by design.
//! The S2 secure-write handlers run their core ONCE, under the write
//! path's own lock take — exactly where the inline gates stood — so the
//! ADR-0066 epoch capture keeps the same guard.
//!
//! Behaviour is preserved (controller condition 3): same status codes,
//! same bodies, same precedence — 404 (unknown group; plus the withdrawn
//! 404 where today's handler 404s) → actor admission (rider 403 /
//! membership 403) → route-local policy gates (409 withdrawn, 400
//! MlsEncrypted, 403 members-only). A `:id` that does not
//! percent-decode keeps the `Path` extractor's own 400, and a missing
//! actor keeps axum's `Extension` 500 (unreachable behind the auth
//! middleware, which always inserts one). Error shapes come from the
//! shared builders in `crate::server` (`api_error`, `api_error_with_reason`,
//! `not_found`, `forbidden`, `bad_request`) or the canonical gate
//! helpers in `crate::server::routes::named_groups`
//! (`reject_fork_quarantined_for_actor`,
//! `reject_unverified_owner_certified_restore`,
//! `open_envelope_withdrawn_group_conflict`, `reject_withdrawn_group`),
//! which is what the inline code used.
//!
//! Later slices (S3 admin/mutations, S4 long tail) add the remaining
//! levels (`Admin`, `JoinSelf`) and flip `Unmigrated` rows to
//! `Level(..)`; S5 activates the `clippy.toml` ceiling that forbids the
//! absorbed helpers everywhere except this module.

use std::collections::HashMap;
use std::sync::Arc;

use crate as x0x;
use crate::server::rider_auth::ActorContext;
use crate::server::routes::named_groups::{
    local_join_membership_state, open_envelope_withdrawn_group_conflict,
    reject_fork_quarantined_for_actor, reject_unverified_owner_certified_restore,
    reject_withdrawn_group,
};
use crate::server::state::AppState;
use axum::extract::{Extension, FromRequestParts, MatchedPath, Path};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{api_error, api_error_with_reason, bad_request, forbidden, not_found};

// ─────────────────────── access levels (S1–S2) ───────────────────────
/// The local daemon's qualifying seat state for a session bearer — the
/// `local_join_membership_state` labels (#447/#458) that EARN something.
/// Refused labels (`pending`, `not_member`) are refusals, not levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MemberState {
    /// Roster lists the local agent as active.
    Active,
    /// Local join stub present, authority never committed its
    /// `MemberAdded` — the #821 limbo state that still earns the
    /// `GET /groups/:id` stub answer.
    PendingAuthorityCommit,
}

/// What a request was admitted at. S1 needs three levels; S2 adds
/// `SessionBearer`, `RiderScope` and `PublicWrite` for the
/// secure-write family; S3–S4 add `Admin` and `JoinSelf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum AccessLevel {
    /// The durable API token — full authority, subsumes every other level.
    OwnerDurable,
    /// A session bearer holding a qualifying local seat — a seat the
    /// admission core actually verified. Which seat state qualifies is
    /// the route's admission rule, not the caller's guess; a session
    /// bearer whose seat was NOT checked is [`AccessLevel::SessionBearer`].
    Member(MemberState),
    /// A session bearer on the S2 secure-write family (`send`,
    /// `secure/encrypt|decrypt|reseal`) — the bearer CLASS only, no
    /// seat verified: `send` admits seatless bearers where the write
    /// policy allows and `decrypt` still admits banned callers, the
    /// member gate/ban/write-policy checks being the handler's, in
    /// their per-route order. Never read as "holds an active seat".
    SessionBearer,
    /// A rider bearer on a write surface (`send`, `secure/encrypt`). The
    /// level LABELS the actor class — it asserts no verified token grant:
    /// the ADR-0039 grant/ban/role/delegation ladder runs in the handler
    /// under its own lock (S2 keeps it there; its per-route order is
    /// pinned by the rider tests, and `send` checks ban BEFORE the grant
    /// while `secure/encrypt` checks the grant first).
    RiderScope,
    /// No actor-based gate; the route serves its public projection (any
    /// remaining gates are local policy, not principal identity).
    PublicRead,
    /// No actor-based gate on a write surface; remaining gates are local
    /// policy (the withdrawn-record conflict on `open-envelope` — the
    /// write-side member of the no-actor class).
    PublicWrite,
}

/// An admission decision: the granted level, or the exact rejection
/// (status + body) the pre-extractor handler returned for that case.
pub(in crate::server) type Admission = Result<AccessLevel, (StatusCode, Json<serde_json::Value>)>;

// ─────────────────────── classification table ────────────────────────────

/// A route's migration state under the group-access chokepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum AccessClass {
    /// Admitted at this level by [`GroupAccess`] / the admission cores.
    /// The level is the route's NOMINAL class (the slice plan's inventory
    /// target); per-route rules (policy arms, withdrawn-shell exemptions,
    /// pending-join stubs) live in the admission cores.
    Level(AccessLevel),
    /// Wired in the router, listed for parity, but its slice has not
    /// migrated the handler yet. It must keep whatever inline checks it
    /// has today.
    Unmigrated,
}

/// One row of the group-plane classification table.
pub(in crate::server) struct RouteAccess {
    /// HTTP method.
    pub(in crate::server) method: Method,
    /// Path in router syntax (`/groups/:id/members`), identical to the
    /// axum route pattern and the `ENDPOINTS` registry path.
    pub(in crate::server) path: &'static str,
    /// Admission class.
    pub(in crate::server) class: AccessClass,
}

/// The complete group-plane route set: every `/groups*`, `/history*`,
/// `/task-lists*` and `/mls/groups*` (method, path) wired in the axum
/// router. The parity test pins this table against BOTH the router
/// (`src/server/mod.rs`) and the endpoint registry
/// (`crate::api::ENDPOINTS`).
///
/// S1 classified the read family — `GET /groups/:id`, `/members`,
/// `/messages`, `/state`, `/state/commits`, `/delegations`; S2 the
/// secure-write family — `POST /groups/:id/send`,
/// `secure/encrypt|decrypt|reseal`, `secure/open-envelope`. Everything
/// else waits for its slice as [`AccessClass::Unmigrated`].
pub(in crate::server) static GROUP_PLANE_ROUTES: &[RouteAccess] = &[
    // ── S1 read family: classified ────────────────────────────────────
    // `/groups/:id` additionally serves the pending_authority_commit stub
    // arm (200 short body); `/messages` is Member only under a MembersOnly
    // read policy — see the admission cores.
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id",
        class: AccessClass::Level(AccessLevel::Member(MemberState::Active)),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/members",
        class: AccessClass::Level(AccessLevel::Member(MemberState::Active)),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/messages",
        class: AccessClass::Level(AccessLevel::PublicRead),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/state",
        class: AccessClass::Level(AccessLevel::PublicRead),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/state/commits",
        class: AccessClass::Level(AccessLevel::Member(MemberState::Active)),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/delegations",
        class: AccessClass::Level(AccessLevel::Member(MemberState::Active)),
    },
    // ── S2 secure-write family: classified ────────────────────────────
    // The inventory target is "Member + RiderScope", but the S2 entry
    // cores verify NEITHER: no seat lookup, no token grant. The rows
    // label the bearer class honestly — SessionBearer / RiderScope —
    // because Member(..) claims a verified seat (see `AccessLevel`).
    // Ban state, write policy, send-as, the member gate and the
    // ADR-0039 grant/delegation/provenance ladder stay in the
    // handlers, under their lock, in their per-route order.
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/send",
        class: AccessClass::Level(AccessLevel::SessionBearer),
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/secure/encrypt",
        class: AccessClass::Level(AccessLevel::SessionBearer),
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/secure/decrypt",
        class: AccessClass::Level(AccessLevel::SessionBearer),
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/secure/reseal",
        class: AccessClass::Level(AccessLevel::SessionBearer),
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/secure/open-envelope",
        class: AccessClass::Level(AccessLevel::PublicWrite),
    },
    // ── S3 admin/mutation family: waiting ─────────────────────────────
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/invite",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/members",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id/members/:agent_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/groups/:id/members/:agent_id/role",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/ban/:agent_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id/ban/:agent_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/groups/:id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/groups/:id/policy",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::PUT,
        path: "/groups/:id/display-name",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/state/seal",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/state/withdraw",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/requests",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/requests",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/requests/:request_id/approve",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/requests/:request_id/reject",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id/requests/:request_id",
        class: AccessClass::Unmigrated,
    },
    // ── S4 long tail: waiting ─────────────────────────────────────────
    RouteAccess {
        method: Method::POST,
        path: "/groups",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/discover",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/discover/nearby",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/discover/subscriptions",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/discover/subscribe",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/discover/subscribe/:kind/:shard",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/cards/import",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/cards/:id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/join",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/join-status",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/quarantine/clear",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/delegate",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/stores",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/stores/:app/legacy-imports",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/stores/:app/legacy-imports/:source_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/stores/:app/legacy-imports/:source_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/history",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/message/:msg_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/scopes",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/search",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/stats",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/task-lists",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/task-lists",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/task-lists/:id/tasks",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/task-lists/:id/tasks",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/task-lists/:id/tasks/:tid",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/mls/groups",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::GET,
        path: "/mls/groups/:id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/members",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/mls/groups/:id/members/:agent_id",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/encrypt",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/decrypt",
        class: AccessClass::Unmigrated,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/welcome",
        class: AccessClass::Unmigrated,
    },
];

// ─────────────────────── table lookup ────────────────────────────────────

/// Resolve a request to its classification row plus the percent-DECODED
/// path parameters (r2/P2-2), or the exact rejection the pre-extractor
/// `Path` extractor arguments produced.
///
/// Classification keys off the router's own `MatchedPath` — the route
/// pattern (`/groups/:id/members`) axum already resolved, static-beats-
/// param priority included — so this module never re-implements route
/// matching. The lookup is a plain `(method, pattern)` comparison; the
/// parity test pins the table's pattern strings byte-for-byte to the
/// router's, so a renamed parameter cannot slip past normalisation.
///
/// Parameters decode through the same `Path` extractor the handlers had
/// as extractor arguments before this module: the axum router itself
/// percent-decodes when it captures (so a raw `/groups/%61bc…` request
/// arrives here already decoded to `abc…`, and the extractor's group
/// lookup sees the same id the old handler's `Path<String>` saw), and a
/// segment that does not decode to UTF-8 (`/groups/%FF/messages`) rejects
/// with `Path`'s own 400 — generated by the router's decoder before serde
/// is involved, hence byte-identical to the old `Path<String>` rejection.
async fn resolve_route(
    parts: &mut Parts,
) -> Result<(&'static RouteAccess, HashMap<String, String>), Response> {
    let params = match Path::<HashMap<String, String>>::from_request_parts(parts, &()).await {
        Ok(Path(params)) => params,
        Err(rejection) => return Err(rejection.into_response()),
    };
    let Some(matched) = parts.extensions.get::<MatchedPath>() else {
        return Err(unclassified(&parts.method, parts.uri.path()));
    };
    let row = GROUP_PLANE_ROUTES
        .iter()
        .find(|row| row.method == parts.method && row.path == matched.as_str());
    let Some(row) = row else {
        return Err(unclassified(&parts.method, parts.uri.path()));
    };
    Ok((row, params))
}

// ─────────────────────── admission cores (pure) ──────────────────────────

/// The membership-403 the read family shares: same status, same body,
/// same `reason` marker as the inline checks #821 pinned
/// (`routes/named_groups/tests/issue821_read_auth.rs`, the #870 session
/// tests in `routes/history.rs`).
fn membership_required() -> (StatusCode, Json<serde_json::Value>) {
    api_error_with_reason(
        StatusCode::FORBIDDEN,
        "active local group membership required",
        "group_membership_required",
    )
}

/// `GET /groups/:id` admission. Durable owners bypass; riders are refused
/// (defence in depth — the ADR-0039 middleware already denies riders this
/// route, the body is kept for parity); a session bearer needs an active
/// seat, EXCEPT that the #447/#458 `pending_authority_commit` limbo earns
/// the stub arm — the handler answers that level with the 200 short body.
pub(in crate::server) fn admit_named_group_details(
    actor: &ActorContext,
    membership_state: &str,
) -> Admission {
    match actor {
        ActorContext::Owner { durable: true } => Ok(AccessLevel::OwnerDurable),
        ActorContext::Rider { .. } => {
            Err(forbidden("rider tokens cannot read named-group details"))
        }
        ActorContext::Owner { durable: false } => match membership_state {
            "active" => Ok(AccessLevel::Member(MemberState::Active)),
            "pending_authority_commit" => {
                Ok(AccessLevel::Member(MemberState::PendingAuthorityCommit))
            }
            _ => Err(membership_required()),
        },
    }
}

/// `GET /groups/:id/members` admission. Same shape as the details route
/// minus the stub arm: a pending seat (either kind) is a refusal here —
/// the roster itself is member content (#821 pins the pending case).
pub(in crate::server) fn admit_named_group_members(
    actor: &ActorContext,
    membership_state: &str,
) -> Admission {
    match actor {
        ActorContext::Owner { durable: true } => Ok(AccessLevel::OwnerDurable),
        ActorContext::Rider { .. } => {
            Err(forbidden("rider tokens cannot read named-group members"))
        }
        ActorContext::Owner { durable: false } => match membership_state {
            "active" => Ok(AccessLevel::Member(MemberState::Active)),
            _ => Err(membership_required()),
        },
    }
}

/// `GET /groups/:id/delegations` admission (ADR-0040 list, ADR-0066 §3b
/// row 16 annotate-class). Order is today's: withdrawn → 404 (a withdrawn
/// shell exposes no delegation authority), session bearer without an
/// active seat → membership 403, rider → 403, then the group's own read
/// policy — which binds even durable owners when they hold no seat
/// (`members-only read policy`).
pub(in crate::server) fn admit_group_delegations(
    info: &x0x::groups::GroupInfo,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> Admission {
    if info.withdrawn {
        return Err(not_found("group is withdrawn"));
    }
    let is_member = info.has_active_member(local_agent_hex);
    let level = match actor {
        ActorContext::Owner { durable: true } => AccessLevel::OwnerDurable,
        ActorContext::Owner { durable: false } if is_member => {
            AccessLevel::Member(MemberState::Active)
        }
        ActorContext::Owner { durable: false } => return Err(membership_required()),
        ActorContext::Rider { .. } => {
            return Err(forbidden("rider tokens cannot read group delegations"))
        }
    };
    // Durable owners retain the existing group read policy.
    if !is_member && info.policy.read_access != x0x::groups::GroupReadAccess::Public {
        return Err(forbidden("members-only read policy"));
    }
    Ok(level)
}

/// `GET /groups/:id/state/commits` admission (#111): retained roster
/// projections are member content while the group is live; a withdrawn
/// shell stays readable so members keep their keyless audit history after
/// terminal delete.
pub(in crate::server) fn admit_state_commits(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> Admission {
    if !info.withdrawn && !info.has_active_member(local_agent_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "members only: retained state-commit history is member content",
        ));
    }
    Ok(if info.withdrawn {
        AccessLevel::PublicRead
    } else {
        AccessLevel::Member(MemberState::Active)
    })
}

/// `GET /groups/:id/messages` admission for a locally-known group. The
/// order is today's: withdrawn → 409 (`reject_withdrawn_group`'s CONFLICT,
/// not a 404), MlsEncrypted → 400 (no plaintext history exists), then the
/// MembersOnly read policy on the LOCAL daemon's seat (the actor is
/// irrelevant to these gates — this surface never had an actor check).
pub(in crate::server) fn admit_public_messages(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> Admission {
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted {
        return Err(bad_request(
            "MlsEncrypted groups do not publish a plaintext message history",
        ));
    }
    let members_only = info.policy.read_access == x0x::groups::GroupReadAccess::MembersOnly;
    if members_only && !info.has_active_member(local_agent_hex) {
        return Err(forbidden("members-only read policy"));
    }
    Ok(if members_only {
        AccessLevel::Member(MemberState::Active)
    } else {
        AccessLevel::PublicRead
    })
}

// ─────────────────────── admission cores (S2 secure-write) ───────────────

/// The ACTING PRINCIPAL's hex — the identity ban state, roster role and
/// (for riders) token grants are checked against. The send path's
/// review-fix-#1 rule: an owner bearer acts as the DAEMON's own agent
/// (the key that signs), a rider as its SUB-AGENT — so a rider can never
/// inherit the daemon-admin's privileges. Actor-less local-seat
/// surfaces (messages, state/commits) evaluate the LOCAL daemon's seat,
/// which is the same principal for every caller.
pub(in crate::server) fn acting_principal_hex(
    actor: &ActorContext,
    local_agent_hex: &str,
) -> String {
    match actor {
        ActorContext::Owner { .. } => local_agent_hex.to_string(),
        ActorContext::Rider { sub_agent_id, .. } => sub_agent_id.clone(),
    }
}

/// The S2 actor classification shared by `send` and the secure
/// encrypt/decrypt/reseal endpoints: the level LABELS the actor class
/// the request entered as — honestly: a session owner is
/// `SessionBearer`, not `Member`, because this core looks up no seat
/// (`send` admits seatless bearers where the write policy allows and
/// `decrypt` still admits banned callers) — and the acting hex names
/// the principal the handler's remaining gates evaluate. Neither
/// asserts a verified seat or grant — the member gate, ban state,
/// write policy and the ADR-0039 grant/delegation ladder keep their
/// per-route order in the handler, under its own lock.
fn secure_write_access(
    info: &x0x::groups::GroupInfo,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> GroupAccess {
    let level = match actor {
        ActorContext::Owner { durable: true } => AccessLevel::OwnerDurable,
        ActorContext::Owner { durable: false } => AccessLevel::SessionBearer,
        ActorContext::Rider { .. } => AccessLevel::RiderScope,
    };
    GroupAccess {
        level,
        stable_id: info.stable_group_id().to_string(),
        acting_hex: acting_principal_hex(actor, local_agent_hex),
    }
}

/// `POST /groups/:id/send` entry admission, in today's order: the raw-id
/// lookup (404 on a miss; the waiver sits at the site, where the
/// guard reads it) → the withdrawn 409 → the #877
/// fork-quarantine-for-actor gate (a session bearer without an active
/// local seat is refused with the bare membership 403 BEFORE any marker
/// body is built). Everything after — the SignedPublic 400, ban check,
/// write policy, send-as authorization and the rider grant/delegation/
/// provenance ladder — stays in the handler, in its order, under this
/// same lock.
///
/// The fork-quarantine gate is injected because it needs the whole
/// `AppState` (the agent id for the seat check, the diagnostics
/// counter); the public wrapper wires the canonical
/// `reject_fork_quarantined_for_actor`, the unit tests pin its position
/// in the order with a stub, and the end-to-end #877 contract is pinned
/// by `routes/named_groups/tests/issue877_error_body_session.rs`.
fn send_admission<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    actor: &ActorContext,
    local_agent_hex: &str,
    fork_quarantine: impl FnOnce(
        &x0x::groups::GroupInfo,
    ) -> Option<(StatusCode, Json<serde_json::Value>)>,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    // ADR0066-LOOKUP-WAIVER: the route's own group lookup (404 on a miss, so
    // no contested roster is ever served); the fork-quarantine gate below
    // consumes the `info` it found. Widening the route's id semantics is out
    // of #732's scope — the waiver the inline handler lookup carried pre-S2.
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if let Some(resp) = fork_quarantine(info) {
        return Err(resp);
    }
    Ok((info, secure_write_access(info, actor, local_agent_hex)))
}

/// The entry admission shared by the GSS secure endpoints
/// (`secure/encrypt`, `secure/decrypt`, `secure/reseal`), in today's
/// order: raw-id lookup 404 → withdrawn 409 → the ADR-0038
/// restore-quarantine 409 → the #877 fork-quarantine-for-actor gate.
/// The member gate (its three per-route shapes), the rider ladder and
/// the crypto follow in the handler under the same lock; the ADR-0066
/// epoch capture keeps its position immediately after this admission.
fn secure_endpoint_admission<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    actor: &ActorContext,
    local_agent_hex: &str,
    fork_quarantine: impl FnOnce(
        &x0x::groups::GroupInfo,
    ) -> Option<(StatusCode, Json<serde_json::Value>)>,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    // ADR0066-LOOKUP-WAIVER: GSS route lookup: a miss is a 404 before any
    // gate, so it fails closed, and the gates below consume this same `info`.
    // Out of #732's scope — the waiver the encrypt/decrypt/reseal handler
    // lookups carried pre-S2.
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if let Some(resp) = reject_unverified_owner_certified_restore(info) {
        return Err(resp);
    }
    if let Some(resp) = fork_quarantine(info) {
        return Err(resp);
    }
    Ok((info, secure_write_access(info, actor, local_agent_hex)))
}

/// `POST /groups/:id/send` entry admission for the handler (which holds
/// the named-groups read lock for the whole build+sign critical
/// section): runs [`send_admission`] with the canonical
/// fork-quarantine gate. `route_id` is the RAW route `:id` — the same
/// key the inline gate used for the marker body and the diagnostics
/// bump.
pub(in crate::server) fn admit_group_send<'a>(
    state: &AppState,
    route_id: &str,
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    send_admission(groups, route_id, actor, local_agent_hex, |info| {
        reject_fork_quarantined_for_actor(state, route_id, info, actor)
    })
}

/// The secure encrypt/decrypt/reseal entry admission for the handlers
/// (each holds the named-groups read lock): runs
/// [`secure_endpoint_admission`] with the canonical fork-quarantine
/// gate. `route_id` is the RAW route `:id`, as above.
pub(in crate::server) fn admit_secure_endpoint<'a>(
    state: &AppState,
    route_id: &str,
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    secure_endpoint_admission(groups, route_id, actor, local_agent_hex, |info| {
        reject_fork_quarantined_for_actor(state, route_id, info, actor)
    })
}

/// `POST /groups/secure/open-envelope` admission: the withdrawn-record
/// conflict (a withdrawn record with no live same-stable-keyed alias →
/// 409) on the BODY's `group_id` — this surface never had an actor or
/// membership gate, and an unknown group fails OPEN to the crypto (the
/// envelope itself refuses). Body of the conflict comes from the
/// canonical `open_envelope_withdrawn_group_conflict`.
pub(in crate::server) fn admit_open_envelope(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> Admission {
    if let Some(resp) = open_envelope_withdrawn_group_conflict(groups, group_id) {
        return Err(resp);
    }
    Ok(AccessLevel::PublicWrite)
}
// ─────────────────────── extractor ───────────────────────────────────────

/// The admission result handed to a handler: the resolved access level,
/// the stable group id the route's `:id` resolved to (the DECODED
/// `:id` when the messages route falls through for a group unknown
/// locally — the public-cache fail-open that predates this module), and
/// the ACTING PRINCIPAL's hex (S2) — the identity the handler's ban/
/// policy gates evaluate.
///
/// This is the extractor's admission snapshot, not the final word:
/// handlers that re-read group data for their body re-run the pure core
/// under their own lock (r2/P2-1), so what gets served is always
/// admitted on the snapshot it was read from.
pub(in crate::server) struct GroupAccess {
    level: AccessLevel,
    stable_id: String,
    acting_hex: String,
}

impl GroupAccess {
    /// The level this request was admitted at.
    // No production reader yet: S1 handlers are admitted-or-refused and
    // never branch on the level, and the S2 secure-write handlers match
    // on the `ActorContext` they already hold (their signatures are
    // pinned by positional test callers) while consuming only
    // `acting_hex`. S3+ handlers (extractor-wired) are this accessor's
    // first readers; delete the allow then.
    #[allow(dead_code)]
    pub(in crate::server) fn level(&self) -> AccessLevel {
        self.level
    }

    /// Stable id the route's `:id` resolved to.
    pub(in crate::server) fn stable_id(&self) -> &str {
        &self.stable_id
    }

    /// The ACTING PRINCIPAL's hex (S2): the local daemon's agent for
    /// owner bearers and actor-less local-seat surfaces, the sub-agent
    /// for riders — the subject of the handler-side ban/policy gates.
    pub(in crate::server) fn acting_hex(&self) -> &str {
        &self.acting_hex
    }
}

/// Fail closed when the extractor meets a request the classification
/// table does not carry — a wiring bug, not a public capability.
fn unclassified(method: &Method, path: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "ok": false,
            "error": format!("{method} {path} is not classified for group access"),
        })),
    )
        .into_response()
}

/// Fail closed when a CLASSIFIED row cannot be served by this
/// extractor: the seven pinned-signature routes run their admission
/// cores directly and never take [`GroupAccess`], and a classified row
/// without a `:id` parameter (open-envelope) is not extractor-shaped.
/// Wiring bugs, not public capabilities — the text names the wiring,
/// not the classification.
fn extractor_not_wired(method: &Method, path: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "ok": false,
            "error": format!("{method} {path} does not take the GroupAccess extractor"),
        })),
    )
        .into_response()
}

/// `GET /groups/:id/members`. The extractor's admission snapshot; the
/// handler re-runs [`admit_named_group_members`] under its own lock
/// before serving the roster (r2/P2-1), so this pass is an early
/// refusal, not the last word.
async fn admit_members_route(
    state: &AppState,
    actor: &ActorContext,
    id: &str,
) -> Result<GroupAccess, Response> {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(not_found("group not found").into_response());
    };
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Session bearers need the #447/#458 seat label; the other actors are
    // decided without it (the arm they take ignores the label).
    let level = match actor {
        ActorContext::Owner { durable: false } => {
            let label = local_join_membership_state(state, info, &local_hex).await;
            admit_named_group_members(actor, label)
        }
        _ => admit_named_group_members(actor, "not_member"),
    }
    .map_err(IntoResponse::into_response)?;
    Ok(GroupAccess {
        level,
        stable_id: info.stable_group_id().to_string(),
        acting_hex: acting_principal_hex(actor, &local_hex),
    })
}

/// `GET /groups/:id/messages` — no actor gate; an unknown group fails
/// OPEN to the public cache with the caller-supplied id as stable id,
/// exactly as the pre-extractor handler did.
async fn admit_messages_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    match groups.get(id) {
        Some(info) => {
            let level =
                admit_public_messages(info, &local_hex).map_err(IntoResponse::into_response)?;
            Ok(GroupAccess {
                level,
                stable_id: info.stable_group_id().to_string(),
                // Actor-less surface: the local daemon's seat is the
                // policy subject.
                acting_hex: local_hex.clone(),
            })
        }
        None => Ok(GroupAccess {
            level: AccessLevel::PublicRead,
            stable_id: id.to_string(),
            acting_hex: local_hex,
        }),
    }
}

/// `GET /groups/:id/state` — the public projection; unknown group 404.
async fn admit_state_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(not_found("group not found").into_response());
    };
    Ok(GroupAccess {
        level: AccessLevel::PublicRead,
        stable_id: info.stable_group_id().to_string(),
        // Actor-less public projection: the local daemon is the subject.
        acting_hex: hex::encode(state.agent.agent_id().as_bytes()),
    })
}

/// `GET /groups/:id/state/commits`.
async fn admit_state_commits_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(not_found("group not found").into_response());
    };
    let level = admit_state_commits(info, &local_hex).map_err(IntoResponse::into_response)?;
    Ok(GroupAccess {
        level,
        stable_id: info.stable_group_id().to_string(),
        // Actor-less retained history: the local daemon's seat is the
        // membership subject.
        acting_hex: local_hex,
    })
}

#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for GroupAccess {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let (row, params) = resolve_route(parts).await?;
        if matches!(row.class, AccessClass::Unmigrated) {
            return Err(unclassified(&parts.method, parts.uri.path()));
        }
        // The router's pattern is byte-identical to the row's (the
        // parity test pins it), so the group id's parameter NAME comes
        // from the row's own template: the first `:param` segment. Every
        // classified S1 route is `/groups/:id/...`.
        let id_param = row
            .path
            .strip_prefix("/groups/")
            .and_then(|rest| rest.split('/').next())
            .and_then(|segment| segment.strip_prefix(':'));
        let Some(id_param) = id_param else {
            return Err(extractor_not_wired(&parts.method, parts.uri.path()));
        };
        let Some(id) = params.get(id_param) else {
            return Err(extractor_not_wired(&parts.method, parts.uri.path()));
        };
        let id = id.clone();
        match (row.method.as_str(), row.path) {
            ("GET", "/groups/:id/members") => {
                // The actor is always present behind the auth
                // middleware, which inserts one on every admitted
                // request (auth.rs:171 durable, auth.rs:215 rider) — and
                // the members handler's own `Extension` argument runs
                // before this extractor and rejects a missing actor with
                // the same `Extension` 500 the pre-S1 handler produced,
                // so this extraction is a typed re-read, never a live
                // 401 path (r2/P3-4).
                let Extension(actor) = Extension::<ActorContext>::from_request_parts(parts, state)
                    .await
                    .map_err(|rejection| rejection.into_response())?;
                admit_members_route(state.as_ref(), &actor, &id).await
            }
            ("GET", "/groups/:id/messages") => admit_messages_route(state.as_ref(), &id).await,
            ("GET", "/groups/:id/state") => admit_state_route(state.as_ref(), &id).await,
            ("GET", "/groups/:id/state/commits") => {
                admit_state_commits_route(state.as_ref(), &id).await
            }
            // Seven classified routes deliberately have no arm: the S1
            // `GET /groups/:id` + `/delegations` and the five S2
            // secure-write handlers keep pinned signatures (tests call
            // them positionally) and run the cores directly under their
            // own lock. If a future handler wires this extractor to one
            // of them, this fails closed instead of guessing — and note
            // `send` could not take this extractor anyway without
            // reordering its body validations (kind/size/thread) after
            // the entry gates.
            _ => Err(extractor_not_wired(&parts.method, parts.uri.path())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::any;
    use tower::ServiceExt as _;

    // ────────────────── parity fixtures ──────────────────

    /// Whether a router/registry path belongs to the group plane this
    /// table governs (the slice plan's §5 predicate).
    fn is_group_plane(path: &str) -> bool {
        path == "/groups"
            || path.starts_with("/groups/")
            || path == "/history"
            || path.starts_with("/history/")
            || path == "/task-lists"
            || path.starts_with("/task-lists/")
            || path == "/mls/groups"
            || path.starts_with("/mls/groups/")
    }

    /// `:param` segments collapse to `*` so table, router and registry
    /// keys agree regardless of parameter naming.
    fn normalize(path: &str) -> String {
        path.split('/')
            .map(|segment| {
                if segment.starts_with(':') {
                    "*"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The first string literal of a `.route(..)` call body (the path).
    fn first_string_literal(call: &str) -> Option<String> {
        let bytes = call.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                let mut literal = String::new();
                let mut j = i + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' && j + 1 < bytes.len() {
                        literal.push(bytes[j] as char);
                        literal.push(bytes[j + 1] as char);
                        j += 2;
                        continue;
                    }
                    if bytes[j] == b'"' {
                        return Some(literal);
                    }
                    literal.push(bytes[j] as char);
                    j += 1;
                }
                return None;
            }
            i += 1;
        }
        None
    }

    /// The method-router names (`get(..)`, `.post(..)`, …) a `.route(..)`
    /// call wires, with string literals stripped so handler names can
    /// never be mistaken for method routers.
    fn method_routers(call: &str) -> Vec<&'static str> {
        let mut stripped = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for character in call.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
            } else if character == '"' {
                in_string = true;
            } else {
                stripped.push(character);
            }
        }
        let mut found = Vec::new();
        for name in ["get", "post", "put", "patch", "delete", "head", "options"] {
            let needle = format!("{name}(");
            let mut from = 0;
            while let Some(found_at) = stripped[from..].find(&needle) {
                let at = from + found_at;
                let preceded_by_word_char = at > 0
                    && (stripped.as_bytes()[at - 1].is_ascii_alphanumeric()
                        || stripped.as_bytes()[at - 1] == b'_');
                if !preceded_by_word_char {
                    found.push(name);
                }
                from = at + name.len();
            }
        }
        found
    }

    /// Every group-plane (METHOD, RAW path) wired in the daemon's one
    /// router builder, parsed out of `src/server/mod.rs`. RAW means the
    /// pattern literal verbatim — parameter names included — because
    /// [`resolve_route`] compares the router's `MatchedPath` pattern to the
    /// table row byte-for-byte. A group-plane `.route(..)` whose methods
    /// the parser cannot recognise fails LOUDLY here rather than
    /// vanishing from parity (r2/P3-3).
    fn router_group_plane_raw() -> Vec<(String, String)> {
        let source = include_str!("mod.rs");
        let bytes = source.as_bytes();
        let mut routes = Vec::new();
        let mut search = 0;
        while let Some(found) = source[search..].find(".route(") {
            let call_start = search + found + ".route(".len();
            let mut depth = 1usize;
            let mut in_string = false;
            let mut escaped = false;
            let mut i = call_start;
            while i < bytes.len() && depth > 0 {
                let byte = bytes[i];
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                } else if byte == b'"' {
                    in_string = true;
                } else if byte == b'(' {
                    depth += 1;
                } else if byte == b')' {
                    depth -= 1;
                }
                i += 1;
            }
            let call_end = if i > call_start { i - 1 } else { call_start };
            let call = &source[call_start..call_end];
            if let Some(path) = first_string_literal(call) {
                if is_group_plane(&path) {
                    let methods = method_routers(call);
                    assert!(
                        !methods.is_empty(),
                        "group-plane route {path} wires no method router the parity parser \
                         recognises — extend the parser, do not let the route vanish from parity"
                    );
                    for method in methods {
                        routes.push((method.to_uppercase(), path.clone()));
                    }
                }
            }
            search = i;
        }
        routes.sort();
        routes.dedup();
        routes
    }

    /// Normalized (parameter names collapsed) view of the router's
    /// group plane, for parity against the registry.
    fn router_group_plane() -> Vec<(String, String)> {
        router_group_plane_raw()
            .into_iter()
            .map(|(method, path)| (method, normalize(&path)))
            .collect()
    }

    /// The group-plane (METHOD, normalized path) set the CLI/daemon
    /// endpoint registry declares.
    fn registry_group_plane() -> Vec<(String, String)> {
        let mut routes: Vec<(String, String)> = crate::api::ENDPOINTS
            .iter()
            .filter(|endpoint| is_group_plane(endpoint.path))
            .map(|endpoint| (endpoint.method.to_string(), normalize(endpoint.path)))
            .collect();
        routes.sort();
        routes.dedup();
        routes
    }

    fn table_keys() -> Vec<(String, String)> {
        let mut keys: Vec<(String, String)> = GROUP_PLANE_ROUTES
            .iter()
            .map(|row| (row.method.as_str().to_string(), normalize(row.path)))
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    // ────────────────── parity + classification ──────────────────

    /// Controller condition 1: the classification table lives here (not
    /// in `EndpointDef`), and parity holds against BOTH the router and
    /// the registry — no group route can be wired without a row, and no
    /// row can name a route that does not exist. This is the ceiling
    /// every later slice migrates under.
    #[test]
    fn classification_table_parity_with_router_and_registry() {
        let table = table_keys();
        assert_eq!(
            table,
            router_group_plane(),
            "classification table must list exactly the group-plane routes wired in src/server/mod.rs"
        );
        assert_eq!(
            table,
            registry_group_plane(),
            "classification table must match the group-plane entries of crate::api::ENDPOINTS"
        );
    }

    /// r2/P3-3: the router-source parser sees the whole picture. A
    /// nested or merged router — or a `.route(..)` whose method wiring
    /// the parser fails to recognise — would each silently shrink the
    /// parsed plane while parity still passed against the shrunken
    /// set. The no-method case is asserted inside
    /// [`router_group_plane_raw`]; nesting/merging cannot be scoped to
    /// group paths (their subtree is opaque), so the tokens themselves
    /// are banned from the one router builder.
    #[test]
    fn parity_source_parser_blind_spots_stay_shut() {
        let source = include_str!("mod.rs");
        assert!(
            !source.contains(".nest("),
            "a nested router's group-plane routes would be invisible to the parity parser"
        );
        assert!(
            !source.contains(".merge("),
            "a merged router's group-plane routes would be invisible to the parity parser"
        );
    }

    /// r2/P2-2: the table's pattern strings are byte-identical to the
    /// router's, because [`resolve_route`] compares the router's
    /// `MatchedPath` pattern to the row with a plain string equality —
    /// a parameter rename must hit both sides or this fails.
    #[test]
    fn table_patterns_are_byte_identical_to_the_router() {
        let mut table: Vec<(String, String)> = GROUP_PLANE_ROUTES
            .iter()
            .map(|row| (row.method.as_str().to_string(), row.path.to_string()))
            .collect();
        table.sort();
        table.dedup();
        assert_eq!(
            table,
            router_group_plane_raw(),
            "MatchedPath classification compares patterns byte-for-byte"
        );
    }

    /// The slice contract: exactly the S1 read family and the S2
    /// secure-write family are classified, at honest levels (the S2
    /// rows label the bearer class — SessionBearer/RiderScope —
    /// because the cores verify no seat; see the table comment); every
    /// other group-plane route is an explicit `Unmigrated` row so
    /// parity holds without claiming a migration that has not
    /// happened.
    #[test]
    fn s1_and_s2_families_classified_and_the_rest_wait_for_their_slice() {
        let expected: &[(Method, &str, AccessLevel)] = &[
            (
                Method::GET,
                "/groups/:id",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::GET,
                "/groups/:id/members",
                AccessLevel::Member(MemberState::Active),
            ),
            (Method::GET, "/groups/:id/messages", AccessLevel::PublicRead),
            (Method::GET, "/groups/:id/state", AccessLevel::PublicRead),
            (
                Method::GET,
                "/groups/:id/state/commits",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::GET,
                "/groups/:id/delegations",
                AccessLevel::Member(MemberState::Active),
            ),
            (Method::POST, "/groups/:id/send", AccessLevel::SessionBearer),
            (
                Method::POST,
                "/groups/:id/secure/encrypt",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/:id/secure/decrypt",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/:id/secure/reseal",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/secure/open-envelope",
                AccessLevel::PublicWrite,
            ),
        ];
        let classified = GROUP_PLANE_ROUTES
            .iter()
            .filter(|row| matches!(row.class, AccessClass::Level(_)))
            .count();
        assert_eq!(
            classified,
            expected.len(),
            "exactly the S1 read and S2 secure-write families may be classified"
        );
        for (method, path, level) in expected {
            let row = GROUP_PLANE_ROUTES
                .iter()
                .find(|row| row.method == *method && row.path == *path)
                .unwrap_or_else(|| panic!("{method} {path} missing from the table"));
            assert_eq!(row.class, AccessClass::Level(*level), "{method} {path}");
        }
    }

    // ────────────────── router-level resolution (r2) ──────────────────

    /// Probe handler: runs [`resolve_route`] on the parts a REAL axum
    /// router produced (MatchedPath + captured, percent-decoded
    /// UrlParams) and answers with the resolved row pattern plus the
    /// decoded params, or the rejection response itself.
    async fn resolve_probe(request: Request<Body>) -> Response {
        let (mut parts, _) = request.into_parts();
        match resolve_route(&mut parts).await {
            Ok((row, params)) => (
                StatusCode::OK,
                Json(serde_json::json!({ "path": row.path, "params": params })),
            )
                .into_response(),
            Err(response) => response,
        }
    }

    /// The pre-extractor oracle: what the old `Path(id): Path<String>`
    /// handler arguments did with the same request.
    async fn legacy_path_probe(request: Request<Body>) -> Response {
        let (mut parts, _) = request.into_parts();
        match Path::<String>::from_request_parts(&mut parts, &()).await {
            Ok(Path(id)) => (StatusCode::OK, Json(serde_json::json!({ "id": id }))).into_response(),
            Err(rejection) => rejection.into_response(),
        }
    }

    async fn probe_body(response: Response) -> serde_json::Value {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("non-JSON body {bytes:?} ({status})"))
    }

    /// r2/P2-2: classification rides the router's own `MatchedPath`
    /// pattern — literal-vs-param priority is the real router's, not a
    /// re-implementation — and an off-table wiring fails closed.
    #[tokio::test]
    async fn classification_rides_the_routers_matched_path() {
        let app = axum::Router::new()
            .route("/groups/discover", any(resolve_probe))
            .route("/groups/:id", any(resolve_probe))
            .route("/groups/:id/members", any(resolve_probe))
            // Off-table wiring: mounted, so the probe (not the router's
            // own 404) answers.
            .route("/calls/:id", any(resolve_probe));

        // Static literal beats the parameterised row (matchit priority).
        let response = app
            .clone()
            .oneshot(
                Request::get("/groups/discover")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = probe_body(response).await;
        assert_eq!(body["path"], "/groups/discover");
        assert_eq!(body["params"], serde_json::json!({}));

        // Parameterised rows capture the decoded id by param name.
        let response = app
            .clone()
            .oneshot(
                Request::get("/groups/abc123/members")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = probe_body(response).await;
        assert_eq!(body["path"], "/groups/:id/members");
        assert_eq!(body["params"]["id"], "abc123");

        // A wired pattern whose method has no table row (PUT members —
        // POST /groups/:id/members IS a row, Unmigrated, and
        // resolve_route resolves it; the class check lives in
        // GroupAccess) and off-table wiring fail closed (403).
        for (method, path) in [("PUT", "/groups/abc123/members"), ("GET", "/calls/abc123")] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        }
    }

    /// r2/P2-2: a percent-encoded `:id` decodes to exactly the value the
    /// old `Path<String>` handler argument produced — so
    /// `/groups/%61bc…` resolves the group (and its gates) instead of
    /// slipping past the unknown-group lookup into the messages
    /// public-cache fail-open.
    #[tokio::test]
    async fn percent_encoded_ids_decode_exactly_like_the_old_path_extractor() {
        let new = axum::Router::new()
            .route("/groups/:id/messages", any(resolve_probe))
            .oneshot(
                Request::get("/groups/issue%3821-%6Bnown/messages")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let old = axum::Router::new()
            .route("/groups/:id/messages", any(legacy_path_probe))
            .oneshot(
                Request::get("/groups/issue%3821-%6Bnown/messages")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(new.status(), StatusCode::OK);
        assert_eq!(old.status(), StatusCode::OK);
        let new_body = probe_body(new).await;
        let old_body = probe_body(old).await;
        assert_eq!(new_body["params"]["id"], old_body["id"]);
        assert_eq!(new_body["params"]["id"], "issue821-known");
        assert_eq!(new_body["path"], "/groups/:id/messages");
    }

    /// r2/P2-2: an id that does not percent-decode to UTF-8 keeps the
    /// old 400 — byte-identical to the `Path<String>` rejection the
    /// pre-extractor handler argument produced (the router's own
    /// decoder rejects before serde is involved).
    #[tokio::test]
    async fn invalid_percent_encoding_keeps_the_old_400() {
        for raw in ["/groups/%FF/messages", "/groups/%C3%28/messages"] {
            let new = axum::Router::new()
                .route("/groups/:id/messages", any(resolve_probe))
                .clone()
                .oneshot(Request::get(raw).body(Body::empty()).expect("request"))
                .await
                .expect("response");
            let old = axum::Router::new()
                .route("/groups/:id/messages", any(legacy_path_probe))
                .clone()
                .oneshot(Request::get(raw).body(Body::empty()).expect("request"))
                .await
                .expect("response");
            assert_eq!(new.status(), StatusCode::BAD_REQUEST, "{raw}");
            assert_eq!(old.status(), StatusCode::BAD_REQUEST, "{raw}");
            let new_bytes = to_bytes(new.into_body(), 1 << 16).await.expect("body");
            let old_bytes = to_bytes(old.into_body(), 1 << 16).await.expect("body");
            assert_eq!(new_bytes, old_bytes, "{raw}");
        }
    }

    // ────────────────── admission bodies ──────────────────

    fn durable() -> ActorContext {
        ActorContext::Owner { durable: true }
    }

    fn session() -> ActorContext {
        ActorContext::Owner { durable: false }
    }

    fn rider() -> ActorContext {
        ActorContext::Rider {
            sub_agent_id: "aa".repeat(32),
            token_id: 1,
            token_hash: "bb".repeat(32),
            groups: Vec::new(),
        }
    }

    fn assert_refusal(admission: Admission, status: StatusCode, error: &str, reason: Option<&str>) {
        match admission {
            Ok(level) => panic!("expected refusal, admitted at {level:?}"),
            Err((actual_status, Json(body))) => {
                assert_eq!(actual_status, status, "{body}");
                assert_eq!(body["ok"], serde_json::json!(false), "{body}");
                assert_eq!(body["error"], error, "{body}");
                match reason {
                    Some(reason) => assert_eq!(body["reason"], reason, "{body}"),
                    None => assert!(body.get("reason").is_none(), "{body}"),
                }
            }
        }
    }

    fn fixture_group(id: &str) -> x0x::groups::GroupInfo {
        x0x::groups::GroupInfo::new(
            "fixture".to_string(),
            "fixture".to_string(),
            x0x::identity::AgentId([0x11; 32]),
            id.to_string(),
        )
    }

    fn local_agent_hex() -> String {
        "22".repeat(32)
    }

    fn group_with_local_seat(id: &str) -> x0x::groups::GroupInfo {
        let mut info = fixture_group(id);
        info.add_member(
            local_agent_hex(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info
    }

    /// The #821/#447 contract for `GET /groups/:id`, per actor and seat
    /// label, including the stub arm a session bearer in join limbo
    /// earns and the exact rider body.
    #[test]
    fn details_admission_reproduces_the_inline_decisions() {
        for label in [
            "active",
            "pending",
            "not_member",
            "pending_authority_commit",
        ] {
            assert_eq!(
                admit_named_group_details(&durable(), label).unwrap(),
                AccessLevel::OwnerDurable,
                "durable owner bypasses every seat label ({label})"
            );
        }
        assert_eq!(
            admit_named_group_details(&session(), "active").unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        assert_eq!(
            admit_named_group_details(&session(), "pending_authority_commit").unwrap(),
            AccessLevel::Member(MemberState::PendingAuthorityCommit),
            "the #447 limbo earns the stub arm"
        );
        for label in ["pending", "not_member"] {
            assert_refusal(
                admit_named_group_details(&session(), label),
                StatusCode::FORBIDDEN,
                "active local group membership required",
                Some("group_membership_required"),
            );
        }
        assert_refusal(
            admit_named_group_details(&rider(), "active"),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read named-group details",
            None,
        );
    }

    /// `GET /groups/:id/members`: no stub arm — a pending seat (either
    /// kind) refuses, exactly as `issue821_read_auth.rs` pins.
    #[test]
    fn members_admission_reproduces_the_inline_decisions() {
        for label in [
            "active",
            "pending",
            "not_member",
            "pending_authority_commit",
        ] {
            assert_eq!(
                admit_named_group_members(&durable(), label).unwrap(),
                AccessLevel::OwnerDurable,
                "durable owner bypasses every seat label ({label})"
            );
        }
        assert_eq!(
            admit_named_group_members(&session(), "active").unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        for label in ["pending", "not_member", "pending_authority_commit"] {
            assert_refusal(
                admit_named_group_members(&session(), label),
                StatusCode::FORBIDDEN,
                "active local group membership required",
                Some("group_membership_required"),
            );
        }
        assert_refusal(
            admit_named_group_members(&rider(), "active"),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read named-group members",
            None,
        );
    }

    /// The ADR-0040/#870 contract for `GET /groups/:id/delegations`:
    /// withdrawn 404, session-membership 403 before any payload, rider
    /// 403, and the read policy that binds even durable non-members.
    #[test]
    fn delegations_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();

        // Withdrawn shell: 404 for everyone, before any authority is read.
        let mut withdrawn = group_with_local_seat("del");
        withdrawn.withdrawn = true;
        for actor in [durable(), session(), rider()] {
            assert_refusal(
                admit_group_delegations(&withdrawn, &actor, &local_hex),
                StatusCode::NOT_FOUND,
                "group is withdrawn",
                None,
            );
        }

        // Live, local seat: every owner admitted.
        let membered = group_with_local_seat("del");
        assert_eq!(
            admit_group_delegations(&membered, &durable(), &local_hex).unwrap(),
            AccessLevel::OwnerDurable
        );
        assert_eq!(
            admit_group_delegations(&membered, &session(), &local_hex).unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        assert_refusal(
            admit_group_delegations(&membered, &rider(), &local_hex),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read group delegations",
            None,
        );

        // Live, no seat: session refused on membership; the durable owner
        // walks into the policy gate instead (issue #870's durable case
        // relied on the fixture group being Public).
        let bare = fixture_group("del");
        assert_refusal(
            admit_group_delegations(&bare, &session(), &local_hex),
            StatusCode::FORBIDDEN,
            "active local group membership required",
            Some("group_membership_required"),
        );
        assert_refusal(
            admit_group_delegations(&bare, &rider(), &local_hex),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read group delegations",
            None,
        );
        let mut members_only = fixture_group("del");
        members_only.policy.read_access = x0x::groups::GroupReadAccess::MembersOnly;
        assert_refusal(
            admit_group_delegations(&members_only, &durable(), &local_hex),
            StatusCode::FORBIDDEN,
            "members-only read policy",
            None,
        );
        let mut public = fixture_group("del");
        public.policy.read_access = x0x::groups::GroupReadAccess::Public;
        assert_eq!(
            admit_group_delegations(&public, &durable(), &local_hex).unwrap(),
            AccessLevel::OwnerDurable,
            "durable non-member retains public read policy"
        );
    }

    /// #111: live retained history is member content; a withdrawn shell
    /// keeps serving its keyless audit history.
    #[test]
    fn state_commits_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        assert_refusal(
            admit_state_commits(&fixture_group("sc"), &local_hex),
            StatusCode::FORBIDDEN,
            "members only: retained state-commit history is member content",
            None,
        );
        assert_eq!(
            admit_state_commits(&group_with_local_seat("sc"), &local_hex).unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        let mut withdrawn = fixture_group("sc");
        withdrawn.withdrawn = true;
        assert_eq!(
            admit_state_commits(&withdrawn, &local_hex).unwrap(),
            AccessLevel::PublicRead,
            "withdrawn shells keep their audit history readable"
        );
    }

    /// The messages gates in today's order: withdrawn 409 (CONFLICT, not
    /// 404) before the MlsEncrypted 400 before the MembersOnly 403; the
    /// actor never matters on this surface.
    #[test]
    fn public_messages_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut info = fixture_group("msgs");
        info.policy.read_access = x0x::groups::GroupReadAccess::Public;
        info.policy.confidentiality = x0x::groups::GroupConfidentiality::SignedPublic;
        assert_eq!(
            admit_public_messages(&info, &local_hex).unwrap(),
            AccessLevel::PublicRead,
            "public SignedPublic group serves non-members"
        );

        let mut members_only = info.clone();
        members_only.policy.read_access = x0x::groups::GroupReadAccess::MembersOnly;
        assert_refusal(
            admit_public_messages(&members_only, &local_hex),
            StatusCode::FORBIDDEN,
            "members-only read policy",
            None,
        );
        let mut membered = members_only;
        membered.add_member(
            local_agent_hex(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        assert_eq!(
            admit_public_messages(&membered, &local_hex).unwrap(),
            AccessLevel::Member(MemberState::Active),
            "MembersOnly + local seat serves at Member"
        );

        let mut mls = info;
        mls.policy.confidentiality = x0x::groups::GroupConfidentiality::MlsEncrypted;
        assert_refusal(
            admit_public_messages(&mls, &local_hex),
            StatusCode::BAD_REQUEST,
            "MlsEncrypted groups do not publish a plaintext message history",
            None,
        );
        let mut withdrawn_and_mls = mls;
        withdrawn_and_mls.withdrawn = true;
        assert_refusal(
            admit_public_messages(&withdrawn_and_mls, &local_hex),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
            // withdrawn outranks the MlsEncrypted arm — today's order.
        );
    }

    // ────────────────── S2 secure-write admission ──────────────────

    /// `assert_refusal` for the S2 cores, whose Ok side is the admitted
    /// `(group, access)` pair rather than a bare level.
    fn assert_secure_refusal<T>(
        admission: Result<T, (StatusCode, Json<serde_json::Value>)>,
        status: StatusCode,
        error: &str,
        reason: Option<&str>,
    ) {
        match admission {
            Ok(_) => panic!("expected refusal, admitted"),
            Err((actual_status, Json(body))) => {
                assert_eq!(actual_status, status, "{body}");
                assert_eq!(body["ok"], serde_json::json!(false), "{body}");
                assert_eq!(body["error"], error, "{body}");
                match reason {
                    Some(reason) => assert_eq!(body["reason"], reason, "{body}"),
                    None => assert!(body.get("reason").is_none(), "{body}"),
                }
            }
        }
    }

    /// The two #877 gate shapes the stub tests propagate verbatim.
    fn quarantine_membership_403() -> (StatusCode, Json<serde_json::Value>) {
        api_error_with_reason(
            StatusCode::FORBIDDEN,
            "active local group membership required",
            "group_membership_required",
        )
    }

    fn quarantine_marker_409() -> (StatusCode, Json<serde_json::Value>) {
        api_error_with_reason(
            StatusCode::CONFLICT,
            "fork quarantine active",
            "fork_quarantined",
        )
    }

    /// `POST /groups/:id/send` entry admission: raw-id lookup 404 →
    /// withdrawn 409 → the #877 gate (whose refusal propagates
    /// verbatim, membership 403 before marker 409), then the actor
    /// class + acting principal with NO seat or grant asserted.
    #[test]
    fn send_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        // Unknown group: the raw-id lookup 404s before any gate runs.
        assert_secure_refusal(
            send_admission(&groups, "missing", &durable(), &local_hex, |_| {
                panic!("the lookup 404 must fire before the quarantine gate")
            }),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        // Withdrawn shell: the 409 fires before the gate.
        let mut withdrawn = group_with_local_seat("send");
        withdrawn.withdrawn = true;
        groups.insert("send".to_string(), withdrawn);
        assert_secure_refusal(
            send_admission(&groups, "send", &session(), &local_hex, |_| {
                panic!("the withdrawn 409 must fire before the quarantine gate")
            }),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        groups.insert("send".to_string(), group_with_local_seat("send"));

        // A gate refusal propagates verbatim — both #877 shapes.
        assert_secure_refusal(
            send_admission(&groups, "send", &session(), &local_hex, |_| {
                Some(quarantine_membership_403())
            }),
            StatusCode::FORBIDDEN,
            "active local group membership required",
            Some("group_membership_required"),
        );
        assert_secure_refusal(
            send_admission(&groups, "send", &session(), &local_hex, |_| {
                Some(quarantine_marker_409())
            }),
            StatusCode::CONFLICT,
            "fork quarantine active",
            Some("fork_quarantined"),
        );

        // Admission: the actor class plus the acting principal. A
        // session bearer is labelled SessionBearer — NOT Member: no
        // seat lookup happened — and a rider RiderScope WITHOUT a
        // grant lookup; those gates run in the handler, in their
        // per-route order.
        let (_, access) = send_admission(&groups, "send", &durable(), &local_hex, |_| None)
            .expect("durable owner admitted");
        assert_eq!(access.level(), AccessLevel::OwnerDurable);
        assert_eq!(access.acting_hex(), local_hex);
        assert_eq!(access.stable_id(), "send");

        let (_, access) = send_admission(&groups, "send", &session(), &local_hex, |_| None)
            .expect("session bearer admitted (no seat asserted)");
        assert_eq!(access.level(), AccessLevel::SessionBearer);
        assert_eq!(access.acting_hex(), local_hex);

        let (_, access) = send_admission(&groups, "send", &rider(), &local_hex, |_| None)
            .expect("rider admitted at RiderScope");
        assert_eq!(access.level(), AccessLevel::RiderScope);
        assert_eq!(access.acting_hex(), "aa".repeat(32));
    }

    /// The secure encrypt/decrypt/reseal entry admission: raw-id lookup
    /// 404 → withdrawn 409 (outranking the restore quarantine) → the
    /// ADR-0038 restore-quarantine 409 → the #877 gate; then the same
    /// actor classification as send.
    #[test]
    fn secure_endpoint_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        // Unknown group: the raw-id lookup 404s before any gate runs.
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "missing", &durable(), &local_hex, |_| {
                panic!("the lookup 404 must fire before any gate")
            }),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        // A withdrawn shell answers "group is withdrawn" even when the
        // restore quarantine is also set — withdrawn is checked first.
        let mut withdrawn = group_with_local_seat("enc");
        withdrawn.withdrawn = true;
        withdrawn.owner_cert_reverify_required = true;
        groups.insert("enc".to_string(), withdrawn);
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "enc", &durable(), &local_hex, |_| {
                panic!("withdrawn must outrank the restore quarantine")
            }),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        // The ADR-0038 restore quarantine fires before the fork gate.
        let mut restored = group_with_local_seat("enc");
        restored.owner_cert_reverify_required = true;
        groups.insert("enc".to_string(), restored);
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "enc", &durable(), &local_hex, |_| {
                panic!("the restore quarantine must fire before the fork gate")
            }),
            StatusCode::CONFLICT,
            "owner-certified group requires state re-verification after restore: \
             POST /groups/:id/state/seal",
            None,
        );

        // Clean group: the gate refusal propagates; admission classifies
        // exactly like send.
        groups.insert("enc".to_string(), group_with_local_seat("enc"));
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "enc", &session(), &local_hex, |_| {
                Some(quarantine_membership_403())
            }),
            StatusCode::FORBIDDEN,
            "active local group membership required",
            Some("group_membership_required"),
        );
        let (_, access) = secure_endpoint_admission(&groups, "enc", &rider(), &local_hex, |_| None)
            .expect("rider admitted at RiderScope");
        assert_eq!(access.level(), AccessLevel::RiderScope);
        assert_eq!(access.acting_hex(), "aa".repeat(32));
    }

    /// `POST /groups/secure/open-envelope`: no actor gate at all — an
    /// unknown group fails OPEN to the crypto (the envelope itself
    /// refuses), and only the withdrawn-record conflict (no live keyed
    /// alias) rejects.
    #[test]
    fn open_envelope_admission_reproduces_the_inline_decisions() {
        let mut groups = HashMap::new();
        assert_eq!(
            admit_open_envelope(&groups, "unknown").unwrap(),
            AccessLevel::PublicWrite,
            "unknown group fails open to the crypto"
        );

        let mut withdrawn = fixture_group("oe");
        withdrawn.withdrawn = true;
        groups.insert("oe".to_string(), withdrawn);
        assert_refusal(
            admit_open_envelope(&groups, "oe"),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        // A live same-stable-keyed alias lifts the conflict.
        let mut live = fixture_group("oe");
        live.shared_secret = Some(vec![0x33; 32]);
        groups.insert("oe-live".to_string(), live);
        assert_eq!(
            admit_open_envelope(&groups, "oe").unwrap(),
            AccessLevel::PublicWrite,
            "a live keyed alias keeps the envelope openable"
        );
    }
}

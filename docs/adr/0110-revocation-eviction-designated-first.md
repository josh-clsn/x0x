# ADR 0110: Revocation Eviction, Designated First

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** TBD (cross-model review follows)
- **Amends:** [ADR 0016](./0016-role-based-group-authority-flat-admin.md) §6, upon acceptance: its deterministic committer discipline extends to revocation eviction.
- **Supersedes:** [ADR 0038](./0038-home-owner-certified-personal-space.md) in part, upon acceptance: its "evict at next seal" revocation path becomes bounded eviction.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** [#1113](https://github.com/saorsa-labs/x0x/issues/1113), [#1164](https://github.com/saorsa-labs/x0x/issues/1164); D16, D34(2), D40, D54, D58, D60, D63; ADR 0014, 0085, 0087, 0089, 0093, 0106, 0107.

Slice S4 of [ADR 0088](./0088-group-liveness-contract.md).
An online admin records a verified revocation as durable eviction work.
The lowest online active-admin agent ID acts first.
Another online admin may act only after the designated window expires without a completed eviction.
This proposal changes scheduling, not removal authority.
## Context

Code citations refer to baseline `8b35dd1f447774e1a952166f32910fc41b512623`.
ADR 0038 relies on a later seal to evict a revoked Home member.
The current verdict marks a positively revoked active seat `Failed` before certificate-grace handling (`src/groups/mod.rs:1543–1563`).
The explicit seal route calls the eviction engine (`src/server/routes/named_groups.rs:21785–21789`).
That engine already removes a TreeKEM leaf, seals the roster and persists both states (`src/server/routes/named_groups.rs:21548–21595`).
It can also rotate legacy GSS and build survivor envelopes (`src/server/routes/named_groups.rs:21633–21682`).
Those mechanisms do not make revocation receipt schedule a seal.
The v1 receive path verifies records, saves them asynchronously and evicts discovery entries, not group seats (`src/lib.rs:9676–9773`).

[#1113](https://github.com/saorsa-labs/x0x/issues/1113) describes the related roster-only self-leave gap.
The local leave emits no TreeKEM removal or epoch (`src/server/routes/named_groups.rs:20873–20885`).
The receiver permits that roster-only self-leave and processes a ratchet removal only when its payload exists (`src/server/routes/named_groups.rs:12036–12049`, `12139–12165`).
The admin removal path supplies that payload and advances the epoch (`src/server/routes/named_groups.rs:20979–21041`).
S4 addresses revocation eviction; it does not claim to close #1113's whole self-leave scope.
ADR 0016 §6's separate responsive self-leave rule remains in force.

An indefinite wait for an unrelated seal breaks **L1** and **L2**.
A roster-only removal does not provide the cryptographic exclusion that eviction needs.
**L4** forbids repairing either gap by accepting unsigned or unchained state.
**L3/G7** remains open in 0088; this slice proposes visible work states without deciding its general binding status.
The applicable public rulings are [D34 and D40](../design/x0x-direction.md#5-decisions-d01d55).
## Decision Drivers

- One reachable, eligible admin must be enough; no owner or original sealer is required.
- A restart must retain the revocation evidence, deadline and unfinished rekey.
- Designated-first scheduling must limit sibling commits without requiring a quorum.
- The existing removal events and verification rules should remain compatible.
## Considered Options

| Option | Reason |
|---|---|
| Durable designated-first worker | Chosen. It implements D34(2) and D40. |
| Evict only at the next explicit seal | Rejected. An idle group can retain a revoked keyholder forever. |
| Let every observer seal immediately | Rejected. It permits sibling rekeys before any timeout. |
| Wait indefinitely for the lowest roster admin | Rejected. A specific offline device would defeat L1. |
| Require an owner or admin quorum | Rejected. Neither is required by L1 or D40. |
| Remove the roster seat without rekeying | Rejected. The revoked member still holds usable group keys. |
| Add an election/lease wire protocol | Rejected for S4. D40 allows timeout races; distributed consensus is a separate decision. |
## Decision

### 1. Trigger and obligation

After full signature and issuer-authority verification, an **Agent-subject revocation** creates work for each live group that seats that agent.
Use the stable group ID, target agent ID and verified revocation hash as the obligation identity.
Store the signed record and its authorizing evidence, not a discovery-cache verdict.
Duplicates preserve the earliest observation and never extend the deadline.
The worker runs without an API request, subsequent join or unrelated seal.
Scan loaded rosters against verified revocations at startup and after catch-up; this closes missed-notification gaps.
An already removed target completes only if a committed rekey also excluded its cryptographic leaf.
An ordinary rename, roster prune or transport ACK is not completion evidence.

Machine-only, binding-only and grant revocations do not prove an Agent-subject revocation.
Keep their existing denials; do not infer a portable agent's group-wide removal from a cache mapping.
Expiry, missing certificates and anonymous announcements are not revocations under this trigger.
Their existing verdict rules remain until the slices assigned by 0088 replace them.

### 2. Designation, bound and handoff

An eligible committer is Active and Admin-or-higher on the current committed parent roster.
It must also pass current signer revocation, owner-policy and containment checks.
Order agent IDs by their raw 32 bytes; legacy `Owner` remains Admin-equivalent under 0016.
Online means authenticated, currently reachable transport, not a presence-cache entry alone.
The lowest online eligible ID is the designated committer.
Refresh reachable admins through existing authenticated group traffic during the designated window.
An unresolved lower ID reserves priority until that window ends; silence cannot authorize two early committers.
Disagreeing online views must wait for the window, rather than claim exclusive early authority.

| Proposed limit | Meaning |
|---|---|
| **2 seconds**, designated window | From the local verified observation. Only the designated admin may start the eviction before expiry. |
| **5 seconds**, completion bound | From that observation while an eligible admin and required evidence are reachable. Removal and rekey must be durably committed and delivered to reachable survivors. |

Two seconds gives the first admin time to seal and disseminate a local transition.
It leaves three seconds for another admin to recover the head and complete fallback.
The five-second total follows I7's live-session target, extended to group membership by D34(2).
These numbers are proposals, not measured guarantees; W3-H must prove the budget before code merges.

At window expiry, another online admin may act only if **no verified removal-and-rekey has landed** locally.
Re-read the committed head and revocation under the membership lock immediately before sealing.
Prefer the lowest reachable remaining admin for fallback; other admins watch its result.
Fallback needs no permission from the first admin; unrelated commits, duplicates and reconnects never restart the window.
A stale parent requires refresh, re-validation and re-signing; never publish a pre-signed stale transition.
Stop local work once the verified exclusion has applied.
If partitioned views still seal siblings after timeout, retain fork evidence and use the existing quarantine rules.
This ADR adds no fork-choice or cross-gap TreeKEM adoption rule.

### 3. Commit and egress

Serialize local roster, cryptographic state and obligation transitions under the group membership lock.
Use one ordinary signed removal per target, with the matching TreeKEM removal and epoch.
For grandfathered encrypted GSS groups, rotate once and deliver the new secret only to eligible survivors.
For SignedPublic groups, a verified roster exclusion suffices; there is no secret to rotate.
Persist the resulting roster, crypto snapshot, obligation phase and exact outgoing event before publication.
Retain committed-but-undelivered work across crashes; resend the same event, not a second rekey.
Use the shared delivery machinery; this is eviction state, not an authority catch-up log (D54).
Offline survivors catch up through the existing verified chain path; their ACKs do not delay the eviction.
S5 owns any new fetch-by-hash or oversized catch-up carrier.

Invalidate staged result/Welcome artifacts and cancel unsent key delivery to the revoked recipient.
Every survivor key delivery and resend must re-check current recipient eligibility and the current secret epoch (D60).
Do not put new key deliveries on a path whose later retries evade those checks.
Bytes already delivered and epochs previously granted cannot be recalled.
Related work only: [join-artifact serving lifecycle](https://github.com/saorsa-labs/x0x/blob/fix/1150-stuck-join-rearm/docs/design/join-artifact-serving-lifecycle.md), on [#1190](https://github.com/saorsa-labs/x0x/pull/1190), not on this baseline.
S4 must supply and validate these guards itself; it does not depend on that branch merging.

### 4. Wire and security

**Capability choice: no new bit.** S4 sends the existing signed `MemberRemoved` and crypto payloads with unchanged encoding and meaning.
Designation and obligation phases are local; no peer is asked to interpret a new field or receipt.
Any later intent, handoff or completion message needs a separate reviewed allocation before it is sent.
Existing optional EvidenceV1 lookup still uses ADR 0093 bit 2, `peer_evidence_v1`, under ADR 0089's budgets and authorization.
It does not establish committer authority or extend those lookup permissions.

**L4: no acceptance rule is added or relaxed.** Any valid current admin already has removal authority.
Keep signature, sender authority, prev-hash, owner mandate, fork, revocation and TreeKEM adoption-exclusion checks.
The current chain validator checks structure, parent linkage and parent-roster authority (`src/groups/state_commit.rs:850–913`).
The last-admin check remains (`src/groups/state_commit.rs:735–746`).
A revoked signer cannot evict itself by using its revoked key.
If no eligible admin remains, expose `waiting_for_active_admin` under 0088 §2 item 3.
Do not mint a replacement admin, weaken the last-admin invariant or restore the revoked credential.
A signed group deletion terminates work under item 5.
An unanchored ordinary-group fork waits for manual action under item 7.
Missing evidence waits under item 8 only while all eligible holders are offline; an available holder must enable progress.
Other deadline misses are defects, not new may-block-forever entries.

### 5. Versioned persistence and mixed versions

Keep obligations with their authoritative roster in the existing ordinary-group or Home-Suite store.
Today these are JSON maps, merged at startup (`src/server/routes/named_groups.rs:30504–30518`, `32746–32762`).
Propose a tagged JSON v2 envelope: `format: "x0x.named-groups.v2"`, `version: 2`, `groups`, `revocation_evictions`.
The Home-Suite envelope uses `format: "x0x.home-suite-groups.v2"` and the same versioned row shape.
V2 rows contain group/target/hash, signed evidence, first-observed time, remaining designated budget, designated ID, phase, parent head, resulting head/epoch and outgoing event bytes.
Phases are `pending`, `prepared`, `committed_delivery_pending` and `complete`; waiting causes are separate typed fields.
Do not serialize transient TreeKEM `PreparedMember` secrets.
Use frozen decoders for every released JSON layout; parse exactly and reject unknown tags, versions, corrupt bodies and trailing data.
Rewrite each store lazily on its next material persist, never by a blanket boot migration (ADR 0085).
Journal obligation, roster and crypto changes together; replay before exposing groups.
On restart, re-verify saved evidence and reconcile the recorded head/epoch before executing work.
An expired window permits immediate fallback; a clock rollback cannot grant a fresh full window.
Keep pending work until verified completion or signed deletion; resource pressure must not silently discard it.

Unknown or corrupt formats leave bytes and store entries intact and disable affected group operations.
Legacy readers reject the envelope because they expect map values to be `GroupInfo` (`src/server/routes/named_groups.rs:30321–30329`).
On this baseline that load error aborts daemon startup (`src/server/mod.rs:735–737`).
This broader downgrade outage requires David's ruling below; no transparent legacy downgrade is claimed.
Upgrading again must recover all obligations and group state without copying a stale pre-revocation roster over V2.

**Old → new:** accept valid legacy removals through unchanged validation; reconcile exclusion before completing local work.
**New → old:** send the unchanged removal/rekey event; verify real released readers apply it.
A legacy admin may remain idle; it cannot postpone a new admin beyond the designated window.
A legacy admin can still initiate its own removal race; mixed fleets retain that old scheduling limitation.
No compatible online admin means legacy behaviour, not a claim that S4's bound is met.

## Consequences

- Positive: revocation no longer needs an unrelated seal or the original admin.
- Positive: crashes retain evidence and unfinished delivery without duplicate rekeys.
- Cost: timeout races remain possible; existing fork containment remains necessary.
- Cost: versioned obligations introduce a downgrade availability decision.
- Operational: seal-time certificate re-checks stay until S7, after S4 is Accepted and shipped.

## Validation

These are **required W3-H cases**, tracked by #1164; they are specifications, not claimed test results.
Commit the harness reproduction on the unfixed tree first (D16/D54); in-process tests alone do not count.
Run multiple real protocol participants with controlled delivery, restart and time in CI's loopback-only Linux namespace.

| Case | Exact scenario and exit test |
|---|---|
| `s4_idle_revocation_one_admin` | Seat A (admin), B (member), C (survivor) in Home and an ordinary TreeKEM group. Stop owner/original sealer; A remains eligible. Deliver a valid issuer or self-revocation of B to A, with evidence available. Do not call seal or mutate the group. Before fix, B remains seated and the epoch does not advance. After fix, A commits removal plus rekey within 5 s; C decrypts new traffic and B's retained pre-removal keys cannot. |
| `s4_designated_timeout` | A < D are online admins at one head. Deliver B's revocation to both. Healthy A completes and D emits no sibling. Then stall A before durable completion while keeping its connection alive. D emits nothing before 2 s, re-reads the head, and completes by 5 s. Repeat with A offline and only D online. |
| `s4_restart_obligation` | Crash after verified durable intake, after crypto preparation, and after durable commit before delivery. Restart with the same data. The obligation remains; recovery delivers one verified exclusion and never rotates twice for the same completed work. Repeat duplicate receipt and expired-window restart. |

All three healthy exit tests include coherent roster and epoch on reachable survivors, not a publish return or transport receipt alone.
Record red/green SHAs, schedule seed, measured durations and crypto-decryption results in the implementation PR.
The harness must also cover delayed designation discovery, clock rollback and no pre-timeout competing commits.
Inject a post-timeout sibling: evidence and quarantine must survive; no arbitrary winner or cross-gap adoption is allowed.

Non-regressions: invalid signatures/issuers cause no work; revoked/demoted actors cannot commit; missing certificate evidence is not revocation.
Cover concurrent ban/removal, SignedPublic exclusion, GSS current-eligibility/epoch resends, cached Welcomes, expiry and quarantine at egress.
Cover last-admin refusal, owner-offline operation, holder-offline resume, signed delete, unanchored fork and forbidden re-admission.
Keep 0106 intervening-event carry and 0107 serving guards; characterize #1113 self-leave separately without claiming S4 fixes it.
Persisted-format checks load real released fixtures with SHA256/provenance, lazily rewrite, crash-replay, downgrade and upgrade again.
Unknown/corrupt envelopes stay byte-identical; no loader overwrites them with an empty map.
Mixed-version W3-H uses released 0.45.0 and 0.46.1 artifacts in both directions, including a legacy lower-ID admin that never evicts.
Prove unchanged removal decoding, survivor decryption, no new wire field/bit, the fallback bound and V2 refusal without data loss.

## Open questions for David

1. Accept the proposed **2 s designated window / 5 s completion bound**? The harness must substantiate both before implementation acceptance.
2. Does a machine-only or binding-only revocation require group-wide eviction of a still-valid portable agent, or only origin-specific exclusion? D60 settles key-delivery eligibility, not that seat-removal policy.
3. Is legacy **daemon-wide startup refusal** on V2 downgrade acceptable, or must S4 provide store-only unavailability through an agreed compatibility floor? ADR 0085 describes store-only refusal.
4. Does 0088 L3 bind this slice (G7)? The proposed visible waiting causes do not settle that contract-wide question.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted; Accepted ADRs remain immutable.
Land Proposed first, then obtain separate acceptance in 0088's order: S2/S8, S4/S3, S5, S6, S7.
D63 permits drafting all bound slices now; it does not waive acceptance order or harness-first.
No S4 code merges before David accepts it and W3-H reproduces its failure; one `named_groups.rs` lane at a time.

# ADR 0114: Authority Re-Welcome for Unconfirmed Join Rows

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** TBD (cross-model review follows)
- **Slice:** Slice S8 (b) of [ADR 0088](./0088-group-liveness-contract.md).
- **Supersedes:** none upon acceptance. ADR 0088's supersession table assigns no supersession to S8 (b).
- **Amends:** none upon acceptance. S4 owns the amendment to ADR 0016 §6.
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [#1146](https://github.com/saorsa-labs/x0x/issues/1146), [#1191](https://github.com/saorsa-labs/x0x/issues/1191), [#1164](https://github.com/saorsa-labs/x0x/issues/1164); ADR 0106, 0107, 0085, 0087, 0089 and 0093; S4 = ADR 0110, S3 = ADR 0109, S5 = ADR 0111, S6 = ADR 0112.

**Decision in brief.** Keep a base-seated join unconfirmed until a current, authenticated authority response arrives and the required keys are installed.
For an eligible seat whose join never confirmed, serve a usable staged Welcome first. If staging is lost, the designated admin replaces the old TreeKEM leaf and issues a new Welcome.
A confirmed Active replay remains a no-op.

The [public rulings digest](../design/x0x-direction.md) records D16, D34 and D37–D55. D63 binds S8 (b) to 0114 and directs drafting it now as Proposed.
This later ruling changes 0107's filing order, not its Accepted recovery or serving rules.
D60 requires current recipient eligibility and the current secret epoch for each class-K GSS delivery or resend still under x0x's control.
The digest does not yet include D60 or D63; their supplied rulings are recorded here without changing that digest.

## Context

Code citations below describe source behaviour at `8b35dd1f447774e1a952166f32910fc41b512623`; they are not runtime reproductions.

| Failure | Current mechanism | Contract gap |
|---|---|---|
| #1150: sealed seat, no usable keys | Active `MemberJoined` returns before staging (`src/server/routes/named_groups.rs:13544–13549`). The original result and Welcome expire after 10 minutes in memory (`src/server/routes/named_groups.rs:33211–33243`) | L1: recovery depends on the original sealer. L2: cache loss has no automatic exit |
| #1149: historical seat becomes local admission | The base-seat branch records `seated_at_revision` and persists the install (`src/server/routes/named_groups.rs:18539–18577`). The non-TreeKEM poll confirms on `has_member`, while TreeKEM confirms on map presence (`src/server/routes/named_groups.rs:35736–35747`) | L4: historical eligibility is not current authority confirmation. L2: keyless Active is not completion |
| #1146 residual: refused or timed-out row prevents a fresh attempt | The remnant clear is restricted to never-seated, non-withdrawn, non-quarantined rows (`src/server/routes/named_groups.rs:17865–17892`). This correct restriction cannot repair an authority's still-Active seat | L1/L2: legitimate later admission must have an exit |
| #1191: remove + re-invite gets 409 until restart | A seated timeout returns `NotApplicable` before removing its attempt (`src/server/routes/named_groups.rs:34254–34300`). A superseded poll returns without finalization (`src/server/routes/named_groups.rs:35906–35910`). A different invite then hits the attempt fingerprint gate (`src/server/routes/named_groups.rs:34723–34729`) | L2: local bookkeeping blocks recovery. L3: the block must explain itself; G7 remains open |

Group metadata persists as JSON, with migration from the old flat roster (`src/groups/mod.rs:551–558`).
The loader reads a raw group map and merges the authoritative Home sidecar (`src/server/routes/named_groups.rs:30318–30340`, `30504–30532`).
The committed roster projection binds role, state, KeyPackage hash and certificate digest (`src/groups/state_commit.rs:138–172`).
The TreeKEM wrapper rejects duplicate agents and duplicate leaf identities (`src/mls/treekem.rs:252–277`).
Deleting that guard would orphan a live leaf; recovery must remove the old leaf first.

ADR 0107 remains the bounded carry-remnant path, with its original-inviter check (`src/server/routes/named_groups.rs:33264–33278`).
S8 (b) supplies a separate authenticated recovery exchange after that path cannot complete.

## Decision Drivers

- Complete a never-confirmed join with any one reachable active admin that holds the required verified state.
- Keep 0107's current-roster serving guard, including its certificate source and fail-closed verdicts.
- Preserve the signed chain, TreeKEM exclusion, owner mandate and fork containment.
- Reproduce these failures in W3-H before implementing S8 (b), without D55's S8 (a) exception.

## Decision

### 1. Separate roster truth, local confirmation and attempt ownership

The signed roster remains the membership authority. Add local `Unconfirmed` and `Confirmed` join states outside its projection.
`Unconfirmed` records the verified base, local seat generation, last attempt and waiting reason.
It exposes `membership_state: unconfirmed` and grants no secure read, write or successful join outcome. Roster presence and a leftover crypto-map entry cannot confirm it.
An absent legacy confirmation field is `Unknown`, never evidence of confirmation or authority to rekey.

For a new base-seated attempt, persist `Unconfirmed` before returning success from the join request.
Only a current, attempt-bound authority response plus usable installed keys confirms an encrypted join.
A SignedPublic join needs that authority response but no key installation.
Do not clear removed, banned, withdrawn or quarantined state as an unconfirmed remnant.
Keep #1148's genuine-unseated clear and all ADR 0107 re-arm discriminators.

Every attempt exit releases only its own attempt ID, including `NotApplicable`, cancellation and a superseded poll whose group was removed.
Release its poll, tasks, inviter pin and control-blob references; retain any committed seat and outcome.
An old finalizer must not release a newer attempt or overwrite a confirmed outcome.
After cleanup, an eligible remove + re-invite starts a new attempt without a daemon restart (#1191).

### 2. Authenticated recovery and confirmation

Define `AuthorityRewelcomeV1` request, response and confirmation messages, with a domain-separated agent signature over each complete canonical message.
Bind group ID, member ID, authenticated machine, attempt ID, nonce, seat-generation commit hash, local revision/hash and KeyPackage hash.
A request carries the member-signed TreeKEM KeyPackage, or GSS recipient KEM key with its identity-binding signature, and required identity evidence. Re-verify ADR 0089 EvidenceV1 at use; stored capability bytes are not a current advert.
No new public certificate-disclosure or per-case certificate-carry rule is added; S2 and S5 own those rules.

The response binds that request digest, the selected authority, current parent/head hashes and the result or refusal. Authority comes from an active-admin seat in the verified parent roster.
This is a new recovery binding; ordinary InviteV4 and ADR 0106/0107 result bindings do not change.
The receiver checks attempt currency under its membership lock before each mutation and verifies each signed link through ordinary apply, without TreeKEM adoption across a gap.
Small eligible carries retain 0106's exact bounds; larger or non-add gaps use S5, and stale-base self-recovery uses S3.
A recovered Welcome alone cannot declare catch-up complete at a later head.

After durable key installation and confirmation, the joiner signs a receipt over the response, terminal commit, Welcome hash and seat generation.
For encrypted groups the receipt also proves possession with a domain-separated MAC under an epoch-derived confirmation key.
Use HMAC-SHA256 with an HKDF-SHA256 key derived from the exported epoch secret, group ID and `x0x/rewelcome/confirm/v1`; the terminal commit binds the epoch.
SignedPublic uses only the signed receipt. Persist before sending; retry a lost receipt instead of rekeying after a lost ACK.
Admins retain and exchange the verified receipt for that seat generation through the gated recovery exchange.
Old-generation receipts cannot confirm a replacement seat. A receipt proves completed installation, not present eligibility or permission to release keys.
Missing authority receipt state alone cannot trigger repair: require a fresh bound request from an unconfirmed joiner.
Known confirmed Active requests return confirmation without a new commit; ordinary Active `MemberJoined` replays remain no-ops.
Loss of keys after a confirmed join remains the explicit remove + re-invite remedy, outside this automatic rule.

### 3. Designated authority: serve first, then replace the leaf

Re-check the recipient's current Active seat and every §4 guard before selecting an artifact or preparing a replacement.
Serve a staged result/Welcome only if its generation, KeyPackage and epoch still fit this attempt.
Keep the original 10-minute deadlines; copies and retries cannot extend them.
Cache expiry, authority restart and a no-carry timeout are repair triggers, not permanent refusals.
Recovery of an eligible seat needs no new invite redemption; an actually unseated identity uses normal admission under S6. GSS recovery seals the current secret to the verified recipient KEM key; SignedPublic returns current-seat confirmation without keys.

For replacement, reuse S4's lowest online active-admin agent ID first.
Other online admins act only after S4's Accepted bound, `B4`, expires without a landing commit.
Reuse its online observation, obligation start, handoff and restart rules. S8 (b) code waits until those S4 rules are Accepted and implemented.
Re-check the current parent and request generation under the membership lock before sealing. A landed replacement satisfies that generation; a competitor must re-read it, not seal another sibling.
Local locks are not a distributed mutex. Timeout handoff can still race under partition, as D40 permits.
Keep fork detection and quarantine; no quorum, owner-device requirement or automatic unanchored-fork clear is added.

For TreeKEM, prepare a contiguous removal/add sequence on cloned named and native state: remove the old leaf, then add the verified KeyPackage at the next native epoch.
Use ordinary signed `MemberRemoved` and `MemberAdded` commits, with their native commits and security bindings.
If the original seat was Admin, append the ordinary `MemberRoleUpdated` restoring that role.
Preserve the group's ID, policy, data, certificate digest and terminal role; never create a duplicate leaf.
Persist the whole prepared sequence, terminal crypto snapshot and repair generation atomically before publication.
Crash replay finishes that transaction; a failed preparation or persist publishes nothing and restores the original state.
Legacy members receive the ordinary signed events in order; new recovery envelopes travel only to capable recipients.
The unconfirmed joiner verifies the contiguous sequence in a keyless state-only path, then installs only its terminal Welcome. This adds state-only handling for repair removal, without skipping a link or adopting across a gap.
Keep that bound recovery's keyless bookkeeping through the intermediate removal; it grants nothing and cannot turn an unrelated removed row into a remnant.
If removal arrives before the recovery response, only the complete verified terminal sequence may complete that bound operation; a genuine later removal cancels it.
An authority restart may lose staging, but retains the obligation and committed generation; it resumes repair from verified current state.

### 4. Security and all egress (L4, ADR 0107, D60)

**Added acceptance rule:** a fresh authenticated unconfirmed request from a currently eligible Active identity permits the designated admin to replace that identity's leaf without a new invite.
The bound response may confirm a base-seated join and permits the state-only repair removal described above.
The security argument is current entitlement plus verified authority and a complete signed chain, not historical invite possession.
Roles and certificate commitments cannot widen; signatures, prev-hash linkage, owner mandate, revocation and TreeKEM adoption exclusion remain fail-closed.
Coalesce duplicate requests into one obligation per group/member/generation under the existing membership machinery.
Retries serve the same committed result while usable; they do not themselves consume a fresh invite or cause a new rekey.

Before **each** result, blob chunk, Welcome exchange or resend, check the current roster: Active, not banned or revoked (agent or machine), and no withdrawal, deletion or quarantine.
For OwnerCertified, verify the roster-embedded certificate against owner, recipient, current revocations and time, or require a current `Clean` verdict.
`DigestPending`, `InGrace`, failed or unknown evidence fails closed. Discovery-cache evidence cannot replace the roster certificate.
Removal, ban and withdrawal linearize with artifact selection and cancellable egress under the membership lock.
Purge originals and copies and cancel unsent transfers on invalidation; keep the serving guard after purge.
No detached retry or gossip fallback may carry guarded recovery bytes after this check becomes invalid.
For class-K GSS, each delivery/resend also requires the **current secret epoch** (D60), not entitlement at the committing epoch.
Observe revocation, expiry, verdict, binding and quarantine changes again for each exchange; bytes already handed off cannot be recalled.
The [join-artifact serving lifecycle note on PR #1190](https://github.com/saorsa-labs/x0x/blob/fix/1150-stuck-join-rearm/docs/design/join-artifact-serving-lifecycle.md) is related work only.
It is not on main and is neither a dependency nor evidence that these guarantees are implemented.

### 5. Wire, persistence, bounds and mixed versions

Propose ADR 0093 registry-v1 bit **9**, `authority_rewelcome_v1`, and constant `CapabilityRegistry::AUTHORITY_REWELCOME_V1`.
It covers the request, bound response and confirmation receipt together; advertise only when all are ready. Bits 0–2 are allocated; bit 9 leaves room for the other slice proposals.
Reconcile allocations in the canonical README registry at acceptance. This draft adds only its required Proposed-list entry.
Require a current verified machine-bound advert with the bit before either side sends this protocol.
Unknown, expired, card-only or absent capability is not positive support; refresh and expose `recipient_upgrade_required`, never send an unknown typed payload.

Version the existing authoritative named-group JSON stores as `NamedGroupsV1 { format_version: 1, groups }`.
Keep confirmation receipts and one repair obligation per seat inside that versioned group state, outside the roster hash.
Freeze decoders for every released raw-map layout, including the Home sidecar. Rewrite lazily at the next ordinary persist (ADR 0085).
Change any positional repair journal layout with new magic **`X0JRW1\0\0`** and a frozen decoder for its released predecessor.
Consume bodies exactly; reject unknown versions, unknown magic, corrupt bodies and trailing bytes without overwriting files.
Persist no `PreparedMember` secrets; use 0107's deterministic identity derivation and existing crypto snapshot storage.
Before shipping, test released loaders: the old raw-map decoder must refuse the new wrapper and leave both stores intact.
The downgrade makes the affected named-group store unavailable; do not leave a legacy Active projection that bypasses `Unconfirmed`.
Re-upgrade restores state and retries the obligation; release notes name the availability cost.

Keep existing artifact byte/TTL caps and bounded control blobs for oversized responses; add at most one receipt and obligation per seat, with persistence O(change), no new background loop or authority event log.
Use `B4 + 120 s` as the proposed recovery-attempt window once a capable admin is reachable, with 120 s for terminal delivery/install after handoff.
This does not change 0107's poll windows. A timeout cleans attempt ownership but retains retryable unconfirmed state and its reason.
Admin/holder absence is a visible wait; a later eligible attempt resumes. Cache loss is not an I8 exception.

| Direction | Behaviour |
|---|---|
| Old joiner → new authority | No new protocol is sent. Ordinary Active replay remains a no-op; eligible legacy recovery uses the documented remove + re-invite exit |
| New joiner → old authority | Hold the new exchange, expose upgrade-required, and do not confirm from the invite base. Normal unseated admission retains its existing wire path |
| New authority → old other members | Disseminate the unchanged ordinary removal/add/role events, not the new recovery envelope. Validate native epoch convergence in both directions |
| New ↔ new | Bound recovery and receipt; duplicate and confirmed replays do not rekey. Full L1 recovery across stale gaps also needs S3/S5; unseated any-admin admission needs S6 |

## Considered Options

1. **Serve staged artifacts, then designated leaf replacement** (chosen): closes staging loss while retaining 0107's bounded fast path and safety checks.
2. **Persist every original result and Welcome indefinitely.** Rejected: unbounded retained key material, stale epochs and original-sealer dependence remain; D54 chooses S5, not an authority catch-up log.
3. **Re-add on every Active replay or signed lost-key claim.** Rejected: ordinary retries cause rekeys, multiple admins seal siblings, and historical or revoked seats could regain keys.
4. **Treat the invite base or crypto-map presence as confirmation.** Rejected: reproduces #1149 and cannot prove that this attempt installed keys.
5. **Require the owner or original inviter to repair.** Rejected by L1; only the existing bounded S8 (a) route retains that limitation.
6. **Manual remove + re-invite only.** Retained as a legacy and confirmed-key-loss exit, but rejected as the sole never-confirmed recovery rule under L1/L2.

## Consequences

- **Positive:** an eligible never-confirmed seat recovers after either side restarts or staging expires. Local status distinguishes a seat from a completed join.
- **Negative / Trade-offs:** cache-loss recovery costs a remove/add rekey sequence; restoring an Admin role adds a commit. A format rewrite prevents old binaries from opening the affected store.
- **Neutral / Operational:** counters record waits, repairs, duplicate suppression, confirmation and refused egress. Record bytes, verifies and writes; E-D15/E-D17 delivery gates apply to changed routes.
- Acceptance follows 0088: contract → S2 and S8 → S4 and S3 → S5 → S6 → S7. S8 acceptance does not waive the implementation dependencies above.
- The Proposed ADR must land on main before governed code merges to any branch. David must accept it before S8 (b) code merges; `named_groups.rs` uses one landing lane (0087 rule 8, 0088 §4).

## Validation

These are **required new W3-H cases under #1164**, not completed tests. Commit and run the failure cases on the unfixed tree before S8 (b) code (D16/D54).
Run CI cases only in the isolated loopback Linux namespace. In-process tests supplement them; D55 does not waive this gate.

| Case | Exact red setup and failure before the fix | Exit test after the fix |
|---|---|---|
| `s8b_1150_staging_loss` | A admits J into Home/TreeKEM. Drop J's own result and Welcome after an intermediate carry, let its poll time out. Separately expire both caches and restart A. Redeem a fresh base-seated invite; assert the existing keyless Active failure | Bound recovery installs a usable terminal Welcome within the proposed window; encrypted traffic succeeds both ways. Repeat without any carry or retained row |
| `s8b_any_admin_handoff` | Repeat the lost-result join with two admins. Take the original inviter offline; one capable promoted admin holds verified current state and keys. Show no original artifact can be fetched | Lowest online admin repairs. Stall the lowest in a separate two-online-admin run; the other acts only after B4. One terminal sequence lands in the connected run. Restart during obligation and durable installation |
| `s8b_1149_current_confirmation` | A admits J and mints a base-seated invite. J sees neither admission nor a later ban. Redeem it, with no row and with a carry remnant, separately in TreeKEM, GSS and SignedPublic | Never report confirmed Active or release keys on the stale base. Current authority refusal wins. Repeat removal, revocation, expiry, verdict change and withdrawal |
| `s8b_1191_attempt_exit` | Timeout J without carry, redeem a base-seated invite, then remove J on A and deliver removal. Re-invite on the same J fixture without restart; observe 409 from the leaked attempt | New attempt starts. Old finalizers cannot clear it. Test `NotApplicable`, superseded, cancellation and normal terminal exits |
| `s8b_1146_refusal_order` | Apply another member's signed add to J's pending base before delivering its consumed-invite refusal. If a non-member row remains, restart J and redeem a new addressed invite. Record the baseline result; #1148 may already recover this control. The still-seated authority residual is the #1150 red case above | Genuine unseated recovery starts and completes; consumed invite stays refused. Banned, removed and quarantined rows are not cleared |

Non-regressions: keep all 0106 carry, preflight, bounds and stale-attempt controls, plus 0107's carry/no-carry, inline-certificate and current-roster serving controls.
Test both serving paths, blob copies, every physical resend, cancellation races, lost receipts, and repair removal arriving before its bound response.
Confirmed Active replays seal nothing. Duplicate requests create no extra leaf or commit; failed prepare/persist leaves the original state usable.
Force handoff races and assert normal fork quarantine, not silent state adoption. Ownerless unanchored forks need manual admin action.
Test all eight 0088 §2 controls: revoked/banned; invalid owner certificate; no admin; never-admitted epochs; signed deletion; post-removal catch-up; unanchored fork; all evidence holders offline.
Only listed waits can remain without bound; restoring an admin/holder resumes eligible recovery. Removed epochs remain unreadable.
Mixed versions: use released v0.45.0 and v0.46.1 binaries against the candidate in both directions, including a legacy third member observing removal/add/role events.
Prove capability absence sends no new payload, legacy paths do not falsely report new recovery, and all surviving members converge to the terminal native epoch.
Storage: released raw-map fixtures with provenance/hash; lazy rewrite; both JSON stores; unknown/corrupt/trailing data; crash points; downgrade then re-upgrade with byte-identical refused files.
The live harness must prove durable confirmation and bidirectional encrypted traffic.

## Open questions for David

1. **G7 remains open:** does L3 bind every slice, including upgrade waits and the 120 s/10-minute S8 (a) gap, or remain a goal? This proposal supplies visible typed states without declaring G7 ruled.
2. **Recovery bound:** accept the proposed `B4 + 120 s` S8 (b) attempt window, or choose another terminal-delivery allowance? S4 alone owns B4; this proposal does not select its value.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Cross-model review remains required.
Accepted ADRs 0088, 0106 and 0107 remain unchanged; implementation claims need their own harness and review evidence.

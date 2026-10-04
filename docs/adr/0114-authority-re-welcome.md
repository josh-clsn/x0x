# ADR 0114: Authority Re-Welcome for Unconfirmed Join Rows

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S8 (b) of [ADR 0088](./0088-group-liveness-contract.md).
- **Supersedes:** none upon acceptance. ADR 0088's supersession table assigns no supersession to S8 (b).
- **Amends:** ADR 0016 §6, widened to repair rekeys alongside S4’s revocation amendment (D88, §3); and ADR 0088 §2, by one named entry (§6). Both take effect when this ADR is Accepted.
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [#1146](https://github.com/saorsa-labs/x0x/issues/1146), [#1191](https://github.com/saorsa-labs/x0x/issues/1191), [#1164](https://github.com/saorsa-labs/x0x/issues/1164); ADR 0106, 0107, 0085, 0087, 0089 and 0093; S2 = ADR 0108, S4 = ADR 0110, S3 = ADR 0109, S5 = ADR 0111, S6 = ADR 0112.

**Decision in brief.** Separate local join confirmation from the signed roster. Serve a usable staged Welcome first.
If staging is lost, a designated admin replaces a never-confirmed seat's TreeKEM leaf without a new invite, but only on recorded never-confirmed evidence (D86).
A Home repair carries a repair mandate signed by the owner device or by a promoted admin (D87).
Both are new acceptance rules with their own security argument (0088 L4); D39 and 0088 alone did not authorize them.
Confirmed Active replays remain no-ops. The #1191 fix ships with the full slice, not ahead of it (D91).

The [public rulings digest](../design/x0x-direction.md) records the rulings this ADR cites: D16, D34, D37–D55, D60, D63–D65, D81, D84–D92 and D97.
D63 binds S8(b) to 0114 and permits drafting it now as Proposed. It does not move S8(b) into the first acceptance batch.
"S8" in 0088's order means S8(a), ADR 0107 (D65). S8(b) is accepted **after S4**, as Accepted ADR 0107 requires and D88 confirms; S5 does not wait for 0114.
D60 requires current recipient eligibility and the current secret epoch for every class-K delivery or resend still under x0x's control.

## Context

Code citations below describe source behaviour at `8b35dd1f447774e1a952166f32910fc41b512623`; they are not runtime reproductions.

| Failure | Current mechanism | Contract gap |
|---|---|---|
| #1150: sealed seat, no usable keys | Active `MemberJoined` returns before staging (`src/server/routes/named_groups.rs:13544–13549`). The original result and Welcome expire after 10 minutes in memory (`src/server/routes/named_groups.rs:33211–33243`) | L1: recovery depends on the original sealer. L2: cache loss has no automatic exit |
| #1149: historical seat becomes local admission | The base-seat branch records `seated_at_revision` and persists the install (`src/server/routes/named_groups.rs:18539–18577`). The non-TreeKEM poll confirms on `has_member`, while TreeKEM confirms on map presence (`src/server/routes/named_groups.rs:35736–35747`) | L4: historical eligibility is not current authority confirmation. L2: keyless Active is not completion |
| #1146 residual: refused or timed-out row prevents a fresh attempt | The remnant clear is restricted to never-seated, non-withdrawn, non-quarantined rows (`src/server/routes/named_groups.rs:17865–17892`). This correct restriction cannot repair an authority's still-Active seat | L1/L2: legitimate later admission must have an exit |
| #1191: remove + re-invite gets 409 until restart | A seated timeout returns `NotApplicable` before removing its attempt (`src/server/routes/named_groups.rs:34254–34300`). A superseded poll returns without finalization (`src/server/routes/named_groups.rs:35906–35910`). A different invite then hits the attempt fingerprint gate (`src/server/routes/named_groups.rs:34723–34729`) | L2: local bookkeeping blocks recovery. L3, a hard rule (D64): the block must explain itself |

Group metadata persists as JSON, with migration from the old flat roster (`src/groups/mod.rs:551–558`).
The loader reads a raw group map and merges the authoritative Home sidecar (`src/server/routes/named_groups.rs:30318–30340`, `30504–30532`).
The committed roster projection binds role, state, KeyPackage hash and certificate digest (`src/groups/state_commit.rs:138–172`).
The TreeKEM wrapper rejects duplicate agents and duplicate leaf identities (`src/mls/treekem.rs:252–277`).
Deleting that guard would orphan a live leaf; recovery must remove the old leaf first.

ADR 0107 remains the bounded carry-remnant path, with its original-inviter check (`src/server/routes/named_groups.rs:33264–33278`).
S8 (b) supplies a separate authenticated recovery exchange after that path cannot complete.

S8(b) adds a **typed wire protocol and persisted local state**, beyond 0088's description of a “protocol rule”.
Released binaries parse both `named_groups.json` and `home-suite-groups.json` as raw maps (`src/server/routes/named_groups.rs:30321–30329`, `30373–30383`).
A parse failure aborts startup (`src/server/mod.rs:735–737`), the #451 downgrade brick.
`TreeKemNamedPersistJournal.named_groups_json` also embeds a raw map (`src/server/routes/named_groups.rs:27217–27221`, `27631–27701`).
Released startup scans replay `*.journal`; S8(b) must change neither that body nor the legacy JSON formats.
ADR 0094 forbids format-upgrade writes before host commit, **including lazy rewrites** (0094:262–263).

## Decision Drivers

- Complete eligible repair with any one reachable active admin that holds the required verified state.
- Keep 0107's current-roster serving guard, certificate source and fail-closed verdicts.
- Preserve signed-chain validation, TreeKEM exclusion, owner authority and fork containment.
- Reproduce each failure in W3-H before S8(b) code; D55's S8(a) exception does not apply, and #1191 gets no exception either (D91).
- Every block this slice adds or touches ends in a typed refusal or a typed wait that names its cause (L3, D64).

## Considered Options

1. **Staged-first service, then designated leaf replacement** (chosen). Closes staging loss for seats with recorded never-confirmed evidence, under D86's and D87's new acceptance rules.
2. **Persist every result and Welcome indefinitely.** Rejected: retained key material, stale epochs and original-sealer dependence; D54 chooses S5, not an authority catch-up log.
3. **Re-add on every Active replay or signed lost-key claim.** Rejected: rekey churn and sibling seals. D86 keeps the replacement trigger apart from this: it needs recorded never-confirmed evidence, so a bare signed claim never triggers it.
4. **Confirm from the invite base or crypto-map presence.** Rejected for new recovery: reproduces #1149. Legacy keyed members keep existing semantics during migration; D84 keeps today's checks toward old authorities only.
5. **Require the owner or original inviter for every repair.** Rejected by L1. The existing bounded S8(a) staged path still needs the original sealer; D87 rules Home mandate authority.
6. **Manual remove + re-invite only.** Retained as D43's final exit and the confirmed-key-loss remedy (D85); inadequate as the sole never-confirmed repair path under L1/L2.
7. **Wrap the two legacy JSON maps.** Rejected: breaks released startup and journals. Use an S8(b)-owned sidecar and an inert legacy placeholder instead.

## Decision

### 1. Roster, local confirmation and attempt ownership

The signed roster remains authoritative. Local confirmation lives outside its hash in the S8(b) sidecar.

| Local state | Meaning and allowed behaviour |
|---|---|
| `Unknown` | No new confirmation record. An existing member with usable keys keeps legacy read/write and Active semantics; absence of a receipt does not authorize replacement. |
| `Unconfirmed` | This attempt has not installed its required keys and received current authority confirmation. Expose `membership_state: "unconfirmed"` and the typed wait `waiting_for_authority_terminal`, naming the selected authority; no secure read/write or successful completed-join outcome. |
| `Confirmed` | Durable usable keys and attempt-bound authority confirmation, or a keyed legacy migration validated as below. |
| `LegacyAuthorityPending` | A new base-seated attempt finds no eligible admin on its verified roster with a current verified `authority_rewelcome_v1` advert. Expose `authority_upgrade_required`. A qualifying attempt completes as `LegacyCompatible` (D84). An encrypted keyless attempt ends at its existing poll deadline with typed `TimedOut(authority_upgrade_required)`, releases ownership and keeps a retryable local record. |
| `LegacyCompatible` | Completed under today's checks toward a legacy authority (D84). Expose `membership_state: "active"` with `authority_confirmation: "legacy_compatible"`. Never reported as `Confirmed`; never a receipt or never-confirmed evidence. A later bound confirmation probe to a capable admin moves it to `Confirmed` without rekey. |
| `ConfirmedKeysMissing` | A previously confirmed member has lost usable keys. Expose `confirmed_keys_missing`; never replace its leaf automatically (D85). End the attempt with `Refused(manual_reinvite_required)` and expose D43's remedy (§6). |

A keyed `Unknown` becomes `Confirmed` without rekey after ordinary chain verification, local key/epoch consistency checks and durable migration recording.
An optional bound confirmation probe can issue its receipt; no receipt is required to preserve the legacy member's existing service.
For SignedPublic, verify the current local chain and seat without a crypto check. Never manufacture an old authority receipt.
A keyless `Unknown` has no recorded never-confirmed evidence, so it never triggers replacement (D86). It ends in `Refused(manual_reinvite_required)`, reason `no_never_confirmed_record`, with D43's remedy (§6).
After host commit, persist new base-seated attempts as `Unconfirmed` before acknowledging that the attempt started; that acknowledgement is not join completion.
Before host commit, refuse a new base-seated attempt with `Refused(host_commit_pending)` before installing its row or acknowledging a start. Retry after ADR 0094's host commit; existing keyed members retain legacy service.
A new encrypted join needs current authority confirmation and usable installed keys. SignedPublic needs confirmation but no keys. D84's `LegacyCompatible` completion is the one exception.
Do not clear removed, banned, withdrawn or quarantined state. Keep #1148's genuine-unseated clear and 0107's re-arm discriminators.

**Old-authority completion (D84).** This is the one named exception to the confirmation rule above. J uses it only while no eligible admin on its verified roster has a current verified `authority_rewelcome_v1` advert; once one has, the new path applies.
J then completes under today's checks. A SignedPublic attempt needs no keys. An encrypted attempt also needs usable installed keys for its verified head's epoch; without them it ends `TimedOut(authority_upgrade_required)`, never keyless Active.
**Security (L4):** the exception adds no chain acceptance rule. It grants no seat or key that today's binary would not grant toward that authority, so it keeps today's exposure, including #1149's, toward legacy authorities only. SignedPublic holds no secret. A `LegacyCompatible` member that later loses its keys is treated as confirmed key loss (D85).
**Mixed versions:** today's working SignedPublic rejoins keep working against v0.45.0 and v0.46.1 authorities; encrypted keyless attempts now end typed instead of reporting keyless Active.

**Poll deadline (L3, D64).** An attempt that reaches its poll deadline (120 s for TreeKEM) without a terminal ends `TimedOut(<cause>)`, naming its last typed wait. Its local record stays retryable and shows `waiting_for_authority_terminal`.
A capable authority that reaches a terminal for that attempt after J's deadline, including a typed refusal such as #946's `certificate_evidence_unavailable`, sends it to J through the gated exchange (§2) while J is reachable. Every §4 trigger on J also re-sends the bound request. So a later refusal reaches J.

Every exit releases only its own attempt ID, including `NotApplicable`, cancellation and superseded polls after group removal.
Release polls, tasks, inviter pins and control-blob references; retain committed seats and outcomes. Old finalizers cannot release a newer attempt or overwrite confirmation.
This #1191 bookkeeping fix ships with the full S8(b) slice, not ahead of it (D91). Its W3-H case is committed and shown red on main before the slice's code merges, like every other S8(b) case. An in-process test may supplement it, never replace it. Until the slice ships, #1191's 409 `join_already_pending` stays a tracked defect.

### 2. Authenticated recovery, receipts and transports

Define canonical `AuthorityRewelcomeV1` request, response and receipt messages with separate agent-signature domains for each type.
Bind group/member IDs, authenticated machine, attempt ID, nonce, original seat-generation commit hash, local revision/hash, requested KeyPackage hash and J's recorded confirmation state for that seat generation (D86).
The request includes the member-signed TreeKEM KeyPackage, or identity-bound GSS recipient KEM key, and required identity evidence.
Re-verify ADR 0089 EvidenceV1 at use. Stored capability bytes are not a current advert; S2/S5 retain certificate-disclosure and carry ownership.
The response binds the request digest, selected authority, current parent/head hashes and terminal result or typed refusal.
Authority derives from an eligible active-admin seat in the verified parent roster; ordinary InviteV4 and 0106/0107 bindings do not change.
Check attempt currency under the membership lock before each mutation. Verify every ordinary chain link; never adopt TreeKEM state across a gap.
Small carries retain 0106's exact bounds. Larger/non-add gaps use S5; stale-base self-recovery uses S3. A Welcome alone does not prove catch-up to a later head.

After durable installation, J persists a signed receipt binding response digest, terminal commit, Welcome hash, seat generation and installed epoch.
For encrypted groups it also proves possession with a keyed BLAKE3 MAC over the canonical receipt transcript.
Derive its 32-byte key with `blake3::derive_key("x0x/authority-rewelcome/receipt-key/v1", canonical(epoch_exporter_secret, group_id, terminal_commit, seat_generation))`.
Use a separate `x0x/authority-rewelcome/receipt-mac/v1` transcript domain. Canonical fields are length-delimited; compare MACs in constant time.
SignedPublic uses only the agent signature. David ruled this BLAKE3 construction, not HMAC/HKDF-SHA256 (D92).
Persist before sending. Retry a lost receipt rather than rekey after a lost ACK. Old-generation receipts cannot confirm replacement seats.
A receipt proves past installation, not present eligibility or permission to release keys. Missing authority receipt state alone never triggers repair.
Known confirmed Active requests return confirmation without a commit; ordinary Active `MemberJoined` replays stay no-ops.

The **gated recovery exchange** is authenticated pinned direct QUIC between currently verified machines, with current `authority_rewelcome_v1` adverts, canonical signatures, bounded frames/control blobs, replay binding and fair admission.
J fans the same signed request out directly to every currently eligible reachable capable admin from its verified roster, using authenticated resolution; no gossip request fan-out.
Each observer sends the exact request to the designated admin and capable fallback admins in an admin-signed carrier, then records the hand-off.
Before verifying the carrier's admin signature, apply cheap binding/frame checks, digest deduplication and a bounded rate limit keyed by authenticated `(group, forwarding admin)`. Bound signature-verification work separately for each forwarding admin: one carrier per 30 s with a burst of two (D90).
Verify the carrier against the forwarding machine and current Admin seat. Verify the original request against J's current machine binding. Admins that never receive it start no timer.
Requests, J→authority receipts, receipt ACKs and admin→admin receipt queries/replies use registered pinned direct exchanges with deadlines, fair admission and fresh machine/pairing checks.
A receipt query names one group/member/generation/request digest. Only eligible active admins receive receipt bytes; they verify the original signature and possession binding and deduplicate by generation.
The verifying admin persists an `AuthorityReceiptVerifiedV1` record, signed in its own domain, binding the full receipt digest, seat generation, receipt epoch and verified parent/head. Receipt exchange carries this record as well as J’s original receipt.
Another admin checks J's signature, the receipt's epoch and chain binding, and the verifier's Admin authority at that head. It need not fetch or export an old epoch secret.
If it has neither local verification material nor a valid verification record, expose `receipt_evidence_unavailable` and fetch the record through the gated exchange or S5. Missing evidence proves neither a valid MAC nor permission to replace a leaf.
Any response containing class-R or class-K bytes additionally uses §4's unconditional serving admission; receipts and request metadata cannot carry hidden key material.
No inbox, metadata-topic or transport-relay copy is used by this protocol. The bound sealer→designated-admin→J staging path uses pinned direct exchanges.

### 3. Serve first, designation, mandate and atomic replacement

The designated admin checks for usable staging **before** preparing a replacement.
Only the original sealer holds the in-memory S8(a) result/Welcome (0107:71); another admin cannot recreate it from a roster entry.
For S8(b), the sealer releases staging **only on a bound request from the designated admin**, never because J's request reached it through fan-out or forwarding. Bind the lookup and sealer's signed answer to the recovery request digest, attempt, generation and selected authority.
Relay a usable staged artifact through the designated admin under §4, including current eligibility checks for both exchanges. The sealer sends no independent terminal or artifact directly to J for this recovery.
The designated admin durably selects either staged delivery or replacement before sending J a terminal. A signed staging decline or lookup deadline expiry permits it to consider replacement. The lookup deadline is the exchange cap, `min(now + 10 s, staging artifact deadline)` (D89). A late staging answer after replacement selection is discarded. If staged delivery was selected, retry that same terminal rather than replacing its leaf while delivery is outstanding.
Use only staging matching the attempt, generation, KeyPackage and current epoch; preserve the original 10-minute artifact deadline. Copies/retries never extend it.
J accepts one terminal response/sequence per attempt; duplicates are idempotent and competing terminals are rejected with fork evidence where applicable.
Cache expiry, authority restart and no-carry timeout create retryable work, subject to the repair budget below. They do not authorize unlimited fresh rekeys.
Actually unseated identities use S6. GSS recovery reseals only the current secret to the verified recipient KEM key. SignedPublic returns current-seat confirmation without rekey.

Reuse S4's **designated window**, **completion bound**, online observation, hand-off, restart and fallback ordering as finally Accepted in 0110 (D88). S8(b) has no scheduling constants of its own.
D69 sizes S4's window and completion bound from harness p99.9 measurement, and D73 sets its fallback stagger and restart sync wait; their final numbers come with S4's acceptance.

**ADR 0016 §6 amendment (D88).** For an authorized repair replacement, the eligible committer excludes the requesting seat J and any admin without current verified TreeKEM state or required evidence.
The lowest online eligible active-admin agent ID commits first, designated as S4 designates (D74: from the verified roster, without reachability data). Fallback uses S4's Accepted hand-off, window and restart rules.
This widens S4's amendment of ADR 0016 §6 from revocation evictions to repair rekeys. Re-read current parent and request generation under the lock before sealing.
After restart, synchronize the head before serving or fallback. A landed terminal satisfies that generation; competitors must re-read it, not seal siblings.
Local locks do not form a distributed mutex. Timeout partitions may still race (D40); retain fork evidence/quarantine and manual exit for unanchored forks.

**Repair bounds (D89).** The **repair bound** is S4's Accepted designated window plus its completion bound plus 120 s for terminal delivery and install.
It bounds every verified-marker hold on a receiver, J's buffered candidate and J's repair completion. Each node persists its deadline when it first verifies the marked removal.
At most three links (remove, add, role) are buffered, within the existing control-blob byte cap. Each physical exchange, including the sealer lookup, is capped at `min(now + 10 s, artifact deadline)`.
ADR 0107's poll windows and its 10-minute staging lifetime stay unchanged. The final numbers follow S4's timing ruling (D69).

**Leaf replacement acceptance rule (D86).** A designated admin may replace a seat's leaf without a new invite only on **recorded never-confirmed evidence** for that exact seat generation:
- J's S8(b) record shows the attempt for that generation as `Unconfirmed` (or `LegacyAuthorityPending`) since before its start was acknowledged, and never `Confirmed` or `LegacyCompatible`; J's signed request carries that state; and
- the designated admin holds no verified receipt and no `AuthorityReceiptVerifiedV1` record for that generation, locally or through the receipt query (§2).

Absence of a receipt alone is never evidence. A seat without such a record, including every receipt-less seat sealed before the upgrade, ends in `Refused(manual_reinvite_required)`, reason `no_never_confirmed_record`, and uses D43's manual exit (§6).
Current entitlement, current admin authority and complete chain validation are still required.
**Security (L4):** this is a new acceptance rule. D39 and 0088 say “re-Welcome”, not this removal/add rule. J's record is J's own and no other node can check it, so a dishonest J could claim it.
The receipt check refuses any generation an admin has verified as confirmed. The D90 budget bounds the rest: at most two replacement seals per seat without a receipt, then the manual exit. Replacement never admits a new identity, gives the seat a different role or skips a chain check.

**Repair mandate (D87).** `RepairMandateV1` uses its own `x0x/owner-axis/repair-mandate/v1` signature domain, never the invite-secret mandate domain.
Bind owner user ID, group/genesis, authority ID, J, request digest, original and replacement seat generations, requested KeyPackage hash, parent commit hash, expected terminal roster hash, both native epochs, certificate digest, policy hash and exact terminal role.
The original generation is the seating commit hash. Derive the replacement generation from the domain-separated request digest, parent and KeyPackage hash; it is not the hash of a commit containing the mandate. The expected terminal hash is the roster projection hash, not the enclosing state commit hash, avoiding a circular signature preimage.
The owner-device form is signed by the loaded matching owner USER key; it consumes no new or fabricated `invite_secret`.
A promoted admin without that key signs the **promoted-admin form** (D87) with its agent key, in its own `x0x/owner-axis/repair-mandate-admin/v1` domain, with the same bindings.
A receiver accepts that form only if the signer holds a current Admin seat at the owner-anchored parent, the bound policy hash matches that parent's owner policy, and every member of the expected terminal roster has a valid owner certificate against that owner. It never pretends an agent certificate delegates USER signing authority.
**Security (L4):** this is a new mandate acceptance rule, for repair only. Either form authorizes one replacement of one existing seat, bound to its request, parent, generations, KeyPackage and exact role.
It never admits a new identity, gives the seat a different role or policy, or stands in for an owner mandate on an ordinary add. The certificate check bounds the promoted-admin form to the owner's current members.
S2 (0108) is required to supply every member's certificate bytes (#1023/#1143); S5 handles unavailable evidence and owns its typed wait.
Never omit the mandate and rely on grace. A recorded-capable receiver past grace otherwise rejects `MemberAdded` as `owner_mandate_missing` (`named_groups.rs:11675–11750`).
Before replacement starts, require a current verified `authority_rewelcome_v1` advert from **every current roster member that may receive the chain**, including offline survivors. A member without a current advert is legacy for this check; cached capability cannot establish offline support. Any missing support returns `Refused(repair_receiver_upgrade_required)` without removal, naming each member without a current advert.
D87 accepts this capability floor as an explicit L1 limit in mixed groups. It is part of §6's named §2 entry, and it clears when those adverts appear.

Prepare removal/add on cloned named/native state. Remove the old leaf, then add the requested KeyPackage at the next epoch; preserve group ID, policy, data and certificate commitments.
Repair `MemberAdded` uses **`welcome_ref` only, `treekem_welcome_b64: None`**. Never put the Welcome or a key-bearing wrapper on metadata gossip.
Carry `RepairMandateV1` **inside the chain-carried repair `MemberAdded`**, in a new optional `repair_mandate` field with `#[serde(default)]`; absent on ordinary adds, ignored by legacy decoders. Group events have no signature of their own: only `GroupStateCommit` is signed, and its `signable_bytes` covers commit fields, not this additive field (`src/groups/state_commit.rs:476–497`). The mandate is protected by its own domain-separated signature and bindings. Keep it in the sealed event log and `member_recovery_history`, not only the direct response wrapper.
Mark repair `MemberRemoved` with an additive, serde-defaulted `RepairRemovalMarkerV1`. The committing actor signs its canonical, length-delimited transcript with its agent key in the separate `x0x/authority-rewelcome/removal-marker/v1` domain. Bind group ID, committing actor ID, removal target J, the removal commit's `state_hash`, `prev_state_hash` and `revision`, request digest, both seat generations and expected terminal roster hash. It identifies the matching add and any required role-restoration link.
The gated recovery response carries the complete signed sequence. On **every apply path**, first perform ordinary removal commit, chain and actor-authority validation. Hold the removal only if the marker's signature and all bindings verify against that exact commit and target, using the verified agent key of its `committed_by` actor. An absent, malformed, transplanted or otherwise failing marker is ignored and counted by reason; apply the valid commit as an **ordinary removal**, never suppress it or wait for an add because of that marker. Stripping or garbling a real marker can cause a brief ordinary removal before a valid add re-adds J under ordinary chain and mandate checks; it cannot defeat revocation.
For a verified marker, hold live roster/native state unchanged only within the repair bounds (D89), showing the typed wait `repair_pending_verification` with the missing link and the deadline, while the matching add, embedded mandate and required role restoration verify. Validate the whole sequence on clones, then persist/apply **all-or-nothing**. If the add/mandate is absent, invalid or mismatched, it cannot restore J; if the complete sequence has not verified by the bound, persist/apply the committed removal and its native exclusion state, end pending work as `RepairRemovalApplied(add_not_verified)`, and cancel J's attempt. A conflicting chain instead records fork evidence and enters typed `ForkQuarantined`; it must not continue service at the old epoch. Never hold indefinitely; retries or restart cannot extend the persisted deadline.
These rules cover direct wrappers, offline-member catch-up, chain replay, 0106 `intervening_events`, S5 holder fetch and `member_recovery_history`. A lone repair add cannot bypass a pending verified removal or ordinary chain checks. After fallback applies the removal, any late add must pass ordinary contiguous-chain, current-authority and mandate validation; the expired repair cannot grant terminal confirmation.
0106 retains its Accepted add-only carry bounds: a gap containing the marked removal requires S5, rather than widening 0106 or accepting only the add. An add-only carry still preserves and verifies the embedded mandate wherever applicable.
Do not gossip the repair pair; initially publish it by targeted pinned direct delivery. Later catch-up must carry the same signed fields and use the same atomic apply rule. Legacy decoders ignoring additive fields is decode compatibility only: any legacy or unadvertised member blocks sealing, so publish neither half to it.

| Original role | Replacement rule |
|---|---|
| `Member` | Ordinary `MemberAdded` restores Member exactly. |
| `Admin` | Append ordinary `MemberRoleUpdated(Admin)` within the atomic terminal sequence. |
| Legacy `Owner` | `Refused(repair_role_not_restorable)` with D43's remedy (§6); Owner is not assignable (`src/groups/member.rs:24–25`). |
| `Moderator` or `Guest` | Same typed refusal; current role assignment accepts only Admin/Member. In particular Guest→Member would widen privilege. |

No unsupported role enters preparation; a role changing concurrently invalidates the prepared sequence.
Persist the entire sequence, terminal crypto snapshot and generation before publication. Failed preparation/persist publishes nothing and preserves original usable state.
Crash recovery completes one recorded transaction; re-sync the head before delivery and suppress obsolete publication. Competing committed heads retain fork evidence.

J keeps keyless repair bookkeeping only for its outstanding bound request.
Treat a removal with a verified commit-and-actor-bound marker as completed repair only after the contiguous chain adds J with the requested KeyPackage and a valid bound mandate within the repair bound.
Until then buffer the candidate sequence within the same persisted bound, grant no membership or keys, and show `repair_pending_verification`. If the full sequence does not verify by the bound, apply the committed removal and native exclusion state with `RepairRemovalApplied(add_not_verified)`, or record conflicting-chain evidence as `ForkQuarantined` without old-epoch service; never retain an indefinite pending removal.
A genuine removal with an absent or failing marker is applied immediately through ordinary chain validation and cancels the attempt; ignore and count the marker. The commit authorizes removal independently of the marker, including S4 revocation eviction and ban.
J buffers at most one candidate per attempt: at most three links (remove, add, role) within the existing control-blob byte cap, for at most the repair bound (D89). No unbounded event history.
Only its terminal Welcome may be installed, without skipping links or adopting across a gap.
Epochs between the original seat and replacement were **entitled but never installed**. They are not 0088 §2 item 4's never-admitted epochs; catch-up remains subject to current eligibility and S3/S5.

### 4. All egress, repair budgets and triggers

Every class-R and class-K byte uses **`Agent::send_direct_pinned_admitted`**, or a path with the same single-exchange seam properties, unconditionally.
This includes the recovery response, staged-result wrapper, replacement Welcome, every control-blob chunk, GSS reseal and survivor share when removal rotates a secret.
Never use `send_direct_with_config`, metadata topics, inbox or relay for those bytes. Each physical retry is application-owned and admitted afresh immediately before its write; no hidden transport resend or gossip fallback.
Select artifacts and check eligibility under the membership lock. Register egress before release; ordered invalidations quiesce, abort and await all tasks/streams before committing the invalidation.
The synchronous write seam rechecks current roster, agent/machine revocation, pairing, time, staging and certificate evidence without blocking. Contention withholds, then retries through fresh admission.
Use fair per-group/global admission, duplicate coalescing, per-exchange deadlines and a whole-task deadline. Timeout resets unfinished streams and releases tickets/handles generation-safely.
Each exchange uses #1190's `min(now + 10 s, artifact deadline)` cap (D89); retries cannot extend the artifact/task horizon.

For each delivery/resend require Active, no ban/revocation, valid current machine binding, and no withdrawal, deletion or quarantine.
OwnerCertified recipients require a roster-embedded valid certificate or current `Clean` verdict; `DigestPending`, `InGrace`, invalid/unknown evidence fails closed. Discovery evidence cannot replace roster certificates.
For class K additionally require the **current secret epoch** (D60), including all survivor shares; do not reuse a join-only admission predicate for survivors.
Purge definitive invalidations and obsolete epochs; withholding retains only bounded pending work. Bytes already handed off cannot be recalled.
The [lifecycle note pinned to e645ce2](https://github.com/saorsa-labs/x0x/blob/e645ce2/docs/design/join-artifact-serving-lifecycle.md) on [PR #1190](https://github.com/saorsa-labs/x0x/pull/1190) defines the serving seam and its evidence; it is not yet proof of main's implementation.
**S8(b) code waits until that admitted path and its required lifecycle fixes are on main.**

Before ML-DSA verification, apply cheap frame/binding checks, duplicate digest lookup and a rate limit keyed by authenticated `(group, member)` (not spoofed body IDs): one request per 30 s, burst two (D90). #656 motivates limiting verify cost.
A dropped request gets an unsigned typed `RateLimited(retry_after)` on the same authenticated exchange, which costs no signature; J shows `waiting_for_rate_limit` until then.
Maintain a durable per-seat repair budget across nonce changes, attempts, expiries, replacement generations and restarts: at most two automatic replacement seals without a receipt (D90). Reset only after verified completion/receipt, not staging expiry.
A missing receipt retries the same result first. After a failed replacement delivery, back off 1 minute, then 10 minutes for each later failure (D90); J and the authority show `waiting_for_repair_backoff` with its end time.
Exhausting the budget returns `Refused(repair_budget_exhausted)` with D43's manual exit (§6). Rate-limit, budget and backoff state all survive restarts. Their retention is the open question in Rulings.
Counters include preverify rate-limit drops, verifies, duplicate/coalesced requests, staged hits/misses, replacements, missing receipts, backoff waits, budget exits, mandate/role refusals, admitted/withheld/purged bytes, deadline resets and persistence writes.

Triggers are explicit: verified request intake; the existing S4 worker after hand-off/fallback deadline; startup sidecar reconciliation after host commit; staging expiry/delivery failure; receipt retry; and a later eligible attempt resuming bounded work.
No separate unbounded recovery loop or authority history is added. S4 worker and startup scan are required, not contradicted by that statement.
Admin absence exposes `waiting_for_admin` (0088 §2 item 3) and holder absence `waiting_for_holder` (§2 item 8), each naming what it waits for. Restoration of eligibility wakes retained work; cache loss is not an I8 exception.

### 5. Capability, storage and mixed versions

Name `authority_rewelcome_v1` / `CapabilityRegistry::AUTHORITY_REWELCOME_V1`: requests, forwarding carriers, responses, receipts/verification records, repair mandate and atomic repair acceptance are implemented together.
Its number is **allocated at acceptance, in acceptance order, as the next free bit in the README registry**. No numeric bit or registry row is added now.
Require current verified machine-bound adverts before either side sends a new payload. Advertise only when the whole protocol is ready.
Unknown/expired/card-only/absent support exposes a typed upgrade reason; it never licenses a probe with an unknown payload.

Keep **both legacy JSON stores as parseable raw maps**. S4/0110 and S6/0112 each own their sidecars; no shared envelope or merged slice state.
For each `Unconfirmed` row on J, write an inert entry in **both `named_groups.json` and `home-suite-groups.json` wherever the row appears**. No real seated Home-Suite entry may override the named placeholder on released load.
The placeholder keeps `members_v2` **non-empty**, with every entry `Removed` and **no entry at all for J**. Retain a non-J roster identity as Removed; if none exists, omit the row from both files instead. An empty roster is forbidden: released `migrate_from_v1()` would seat the creator as Admin.
Keep only pending local `invite_lineage` with `seated_at_revision: None`, no withdrawal or quarantine, and no secret, key/snapshot reference or invite-minting state. Released #1148 must classify it as `UnseatedJoinRemnant`, so a fresh invite can clear it and start a new join. Never erase genuine withdrawal, removal, ban or fork evidence to manufacture this placeholder.
For Home-policy groups, preserve released-compatible Home identity/policy metadata and the canonical owner-sync pointer where present.
**Home activation (D81).** S8(b) writes a Home placeholder only after released v0.45.0 and v0.46.1 binaries, including runs with no owner-sync pointer, show no duplicate Home and no `home.json` change through reload and provisioning (Validation).
If any of those controls fails, Home activation stays blocked. Home groups then get no S8(b) placeholder or record and keep today's join paths with S8(a)'s typed outcomes, and a repair request for a Home seat ends in `Refused(home_activation_blocked)` (§6).
A default-policy, `home = None` placeholder alone never establishes safety.
Keep verified remote roster/seat-generation evidence in the S8(b) sidecar, not a forged signed projection. Authority-side rosters keep their real seats; local confirmation is separate.
Keyed `Unknown` and `Confirmed` rows retain their valid legacy membership/keys; `ConfirmedKeysMissing` exposes no secret.

Use `<data_dir>/authority-rewelcome.rwstate`, magic **`X0RWS1\0\0`**, followed by a canonical bincode `AuthorityRewelcomeStateV1` body.
The body has version 1 and bounded records keyed by `(group, member)` containing local state, verified base, generations, attempt/outcome, signed receipt, one repair obligation, budget/backoff and delivery phase.
A prepared transaction uses `<data_dir>/authority-rewelcome-<transaction_id>.rwjournal`, magic **`X0JRW1\0\0`**, and canonical bincode `AuthorityRewelcomeJournalV1 { version, transaction_id, group, expected_parent, request_digest, old_generation, replacement_generation, signed_sequence, terminal_crypto_snapshot_ref, legacy_raw_map_bytes, sidecar_state, phase }`.
There is **no released predecessor** for either type. Freeze V1 decoders once released; reject unknown magic/version, corruption or trailing bytes without overwriting files.
No `PreparedMember` secrets are serialized; use 0107's deterministic identity derivation and existing crypto-snapshot custody. Journal references must bind the snapshot hash and transaction.

Never put S8(b) state in `*.journal` or modify `TreeKemNamedPersistJournal`'s positional layout/raw-map body. Never put S8(b) state in Home's `*.hsjournal` namespace either.
First replay existing `.journal`/`.hsjournal` as today. After host commit, replay S8(b) `.rwjournal` and reconcile other slices' sidecars against the verified head before exposing repair operations.
If a legacy replay changed the head, reconcile or retain fork evidence; do not blindly overwrite it with an S8(b) snapshot.
Persist the `.rwjournal` transaction first. Publish the full terminal legacy roster/crypto pair through the existing unchanged `.journal` (and Home paired `.hsjournal`) transaction, never an intermediate removal-only view.
Embedded JSON remains a released raw map, with no S8(b) envelope or positional journal fields. Preserve the additive signed repair event fields wherever chain history is carried; legacy decoders ignore them. Then persist S8(b) state and mark delivery pending. Partial writes replay idempotently before serving.
On J, keep both legacy views inert and retain no installed legacy key/snapshot reference until durable confirmation. Prepared keys stay in the new transaction's custody.
The confirmed install uses the ordinary released-compatible roster/crypto transaction. Downgrade can therefore replay a complete compatible pair or retain J as a non-member, without needing `.rwjournal` replay.
Retire a completed transaction only after all required durable views agree. A downgrade during an incomplete transaction is an explicit W3-H crash/downgrade gate, not an assumed safe state.

**First behaviour-changing sidecar/journal write is after ADR 0094 host commit.** No startup scan, migration or lazy rewrite before that barrier. Pre-commit execution defers new repair, refuses new base-seated attempts as in §1, and writes only rollback-readable legacy state.
Old binaries ignore `.rwstate`/`.rwjournal` and parse both raw maps. Downgrade safety requires both loaded views to leave J a non-member with no keys or Active admin seat, while preserving the released fresh-invite exit; the controls below must prove this, including Home.
Old authority binaries cannot provide the new bounded recovery; they keep today's behaviour. Downgrade must not resurrect a partial repair or overwrite a newer verified head.
Re-upgrade verifies the sidecar, reconciles generation/roster/crypto state, classifies lost keys and resumes the bounded obligation. No format-induced startup refusal is acceptable.

| Direction | Behaviour |
|---|---|
| Old J → new authority | No new wire payload; ordinary Active replay remains a no-op, with D43's legacy remove/re-invite exit. |
| New J → old authority | Normal unseated admission stays legacy. Base-seated attempts use `LegacyAuthorityPending`: SignedPublic attempts, and encrypted attempts with usable keys, complete as `LegacyCompatible` (D84); encrypted keyless attempts end `TimedOut(authority_upgrade_required)`. SignedPublic rejoin compatibility is specifically tested. |
| New authority → old or unadvertised survivors | Repair returns a typed upgrade refusal before removal. Additive fields remain decodable, but neither half is sealed or delivered to unsupported receivers; never inline Welcome bytes. |
| New ↔ new | Bound confirmation/receipt, staged-first repair and one terminal per attempt. Stale gaps need S3/S5; new unseated any-admin admission needs S6. |

**Out of scope: a confirmed member behind retention (D97).** D97 treats a member behind every holder's retention as admission, through S8(b) or a later ADR.
S8(b) replaces only seats with recorded never-confirmed evidence (D86), so it does not repair a **confirmed** member behind retention. That member needs a later ADR.
Until then it shows S5's typed retention state, and its exit is D43's remedy. This ADR adds no §2 entry for it.

### 6. Typed blocks and the named §2 entry (L3, D64)

D64 makes L3 a hard rule for every slice. Every block S8(b) adds or touches ends in one of these typed states, and each names what it waits for.

| Block | Typed state | Exit |
|---|---|---|
| Attempt awaiting its authority | `waiting_for_authority_terminal`, naming the authority; at the poll deadline `TimedOut(<last wait>)` | Terminal pushed by the authority, or fetched on the next §4 trigger (§1) |
| Base-seated attempt before host commit | `Refused(host_commit_pending)` | Retry after ADR 0094's host commit |
| No capable authority | `authority_upgrade_required`; encrypted keyless: `TimedOut(authority_upgrade_required)` | A capable admin appears, `LegacyCompatible` (D84), or D43's remedy |
| Confirmed key loss | `Refused(manual_reinvite_required)`, `confirmed_keys_missing` | D43's remedy (D85) |
| No never-confirmed record | `Refused(manual_reinvite_required)`, `no_never_confirmed_record` | D43's remedy (D86) |
| Receiver without a current advert | `Refused(repair_receiver_upgrade_required)`, naming those members | Adverts appear, or D43's remedy (D87) |
| Role that cannot be restored | `Refused(repair_role_not_restorable)` | D43's remedy (open question) |
| Pre-verify rate limit | `RateLimited(retry_after)`; J shows `waiting_for_rate_limit` | The retry time (D90) |
| Failed replacement delivery | `waiting_for_repair_backoff`, with its end time | The end time (D90) |
| Repair budget spent | `Refused(repair_budget_exhausted)` | D43's remedy (D90) |
| Marked removal awaiting its add | `repair_pending_verification`, naming the missing link and the deadline | The verified sequence, or `RepairRemovalApplied(add_not_verified)` at the repair bound; a late add passes ordinary validation |
| Conflicting chain | `ForkQuarantined` | An admin's manual act (0088 §2 item 7) |
| Receipt evidence missing | `receipt_evidence_unavailable` | The record arrives through the gated exchange or S5; 0088 §2 item 8 while every holder is offline |
| No admin or no holder online | `waiting_for_admin`, `waiting_for_holder` | 0088 §2 items 3 and 8 |
| Home activation blocked | `Refused(home_activation_blocked)` | The released-binary controls pass (D81), or D43's remedy |

**Named §2 amendment.** This ADR amends ADR 0088 §2 with one named entry, ruled by David through the options he chose in D81, D84, D85, D86, D87 and D90:

- **S8(b) manual-exit repair.** Automatic repair or base-seated completion of a seat may end in a typed terminal refusal whose exit is D43's remedy, for exactly these reasons: `confirmed_keys_missing` (D85); `no_never_confirmed_record` (D86); `repair_budget_exhausted` (D90); `repair_receiver_upgrade_required` (D87); `TimedOut(authority_upgrade_required)` for an encrypted keyless attempt with no capable authority (D84); and `home_activation_blocked` (D81).
- **Exit:** D43's remedy. An admin removes the member while it is online; the member restarts and redeems a fresh invite. That is ordinary admission, which completes under L1. The two upgrade reasons also clear by themselves when the missing adverts appear, and the retained record then retries.
- In L3's terms this is a waiting entry: the refusal is typed and visible, and it names the act it waits for. 0088 is Accepted and is not edited; the entry takes effect when this ADR is Accepted. `repair_role_not_restorable` is not in it until David rules (open question).

## Consequences

### Positive

- Local status distinguishes a real seat, an installed join and missing keys without wedging keyed legacy members.
- Eligible staging-loss repair has a durable bounded exit under D86's and D87's acceptance rules.
- Legacy stores stay parseable on downgrade; S8(b) owns its new persisted state.
- Every block in this slice is typed and names its cause (D64).

### Negative / Trade-offs

- Replacement rotates TreeKEM and may need a role commit, atomic receiver support and new Home mandate validation.
- Receipt-less seats from before the upgrade cannot prove that installation never happened, so they keep the manual exit (D86). Confirmed key loss keeps it too (D85): an explicit L1 gap, recorded as §6's named §2 entry.
- `LegacyCompatible` keeps today's checks, and today's exposure, toward legacy authorities (D84).
- Users keep hitting #1191's 409 until the full slice ships (D91).
- Direct-only delivery must prove Home/mixed-version liveness; partial-transaction downgrade needs explicit evidence.

### Neutral / Operational

- 0088's order is contract → S2 and **S8(a)/0107** → S4 and S3 → S5 → S6 → S7 (D65). **S8(b) is accepted after S4** (D88), not in the first batch; S5 does not wait for it.
- S2's certificate rule is a prerequisite for Home replacement code.
- Governed code requires this ADR Proposed on main, David's acceptance, W3-H red evidence and one `named_groups.rs` landing lane.
- Repair code also waits for Accepted/implemented S4 scheduling, S2 certificates, applicable S3/S5 recovery, and the #1190 admitted egress path on main. These gates also hold the #1191 fix, which ships with the slice (D91).

## Validation

W3-H (#1164) does not yet exist. These are required specifications, **not completed tests**; recommend a dedicated tracking issue for these S8(b) cases.
Commit every red case and demonstrate it red on **main with S8(a)/#1190 merged** before S8(b) code merges. In-process tests supplement, never replace D16/D54.
Record full main SHA, #1190 merge SHA/ancestry, released artifact hashes, harness commit, schedule seed, public API transcript and exact red assertion per variant.
Current main is `3f09dda021e74c70ac3210f810193fadd43b74bc`; it does not contain `e645ce2` and is **not the eligible baseline**. No post-#1190 main SHA can yet be honestly pinned.
Selecting and recording that actual full SHA after merge is a mandatory unresolved gate; do not label this worktree or the old source-citation SHA the harness baseline.
Run only in the isolated loopback Linux namespace. All cases use a deterministic clock, explicit ordered delivery, dropped frames and restart cuts; no wall-clock sleeps as proof.

| Case / nodes | Public-API steps and delivery schedule | Exact baseline assertion → fixed assertion |
|---|---|---|
| `s8b_1150_staging_loss`: A admin, J | Create Home/TreeKEM via API; invite/join J, deliver an intermediate carry but drop J's result/Welcome. Advance past the poll deadline, then original 10-minute staging horizon. Retry via a fresh base-seated invite. Repeat no-carry, restart-A and no-retained-row variants separately. | Carry: typed `TimedOut`/`Refused`, no usable keys or bound recovery after cache loss, **not keyless Active** after S8(a). No-row variant: baseline can report Active without usable keys; no-carry variant: typed timeout and no usable repair. Assert each failing automatic-completion expectation separately. Fixed: bounded terminal confirmation, one leaf, durable keys and two-way encrypted traffic. |
| `s8b_any_admin_handoff`: A < D admins, J | Admit J, lose artifacts as above, take A offline; J fans request to D. Separate connected run sends request to both, delays designated A past 0110's Accepted window, then allows D fallback. Restart D after obligation persist and after terminal persist. | Promoted D cannot repair lost staging; J has no usable terminal Welcome by the repair bound (D89). Fixed: eligible lowest admin first, no early fallback, one connected terminal; restart re-syncs before resend. |
| `s8b_owner_mandate_past_grace`: O owner USER-key device/admin, E enforcing survivor, J | Create Home, seat E/J, record O as mandate-capable on E, advance beyond grace; lose J staging and request repair. O is designated committer. Deliver a removal with a verified marker followed by missing/invalid repair mandate in fault variants; then complete valid pair. Repeat with promoted D, O offline, all member certificates fetched through S2 APIs. **Catch-up variants:** take E offline after its current advert is verified, seal repair before that advert expires, then return E after delivery. Fetch the chain through offline-member catch-up and `member_recovery_history`; separately offer the add through 0106 `intervening_events`, then fetch the non-add gap through S5's public recovery API. Expire/remove E's advert before sealing in a separate capability control. | **Red:** baseline cannot repair; a naïve ordinary pair removes J then rejects add as `owner_mandate_missing`. Fixed on every direct/catch-up path: a verified-marker incomplete pair preserves roster/epoch only while bounded pending verification; at the bound apply removal/native exclusion with typed exit, or quarantine a conflicting chain without old-epoch service. A valid pair uses the add's embedded mandate and restores J past grace atomically. 0106 cannot skip the removal gap; S5 supplies the complete sequence. **Control:** no current E advert refuses with `repair_receiver_upgrade_required` naming E, before removal. The promoted variant uses D87's promoted-admin form; no fake USER signature or omitted mandate. **Promoted-form controls:** E rejects a form whose signer lacks a current Admin seat at the parent, whose terminal roster has a member without a valid owner certificate, or whose role or policy hash differs. |
| `s8b_removal_marker_tamper` **control**: A committer, H holder/relay, E capable survivor, J | Obtain an earlier valid repair marker for J. In separate runs, API-trigger a genuine S4 revocation eviction and a ban of J. H attaches a garbage or tampered marker, or transplants the earlier validly signed marker, onto each genuine removal without changing its commit. Include same-actor transplants and absent-marker controls; separately strip/garble a real repair marker before delivering its valid add. Exercise every applicable direct/catch-up/replay/history apply path, with E and J as receivers. | New-path safety control, not a claimed baseline red reproduction. Fixed: marker binds the exact actor, target, removal hashes and revision; tampered/transplanted markers fail and are ignored/counted, absent markers are counted separately. Genuine eviction/ban applies immediately with native exclusion and attempt cancellation; no add wait or continued old-epoch service. A stripped/garbled real marker permits at worst brief removal before a valid contiguous add re-adds J. |
| `s8b_marked_removal_no_add` **control**: A committer, E capable survivor, J | Deliver a genuine repair removal with its valid exact-commit/actor marker, drop every add, and advance the deterministic clock to the repair bound (D89). Repeat with invalid/mismatched add or mandate; retry and restart E/J while pending. Run separately with conflicting-chain evidence. | New-path safety control, not a claimed baseline red reproduction. Fixed: hold only before the persisted deadline; at the bound durably apply removal/native exclusion, expose `RepairRemovalApplied(add_not_verified)`, cancel J's attempt and release pending work. Conflict records evidence as `ForkQuarantined` without old-epoch service. Retry/restart never resets the bound; no indefinite hold. A late add requires ordinary chain/authority/mandate validation and cannot complete the expired attempt. |
| `s8b_staged_replacement_race` **control**: S original sealer, A designated admin, J | API join J through S and retain matching staging; fan J's recovery request to both S/A, delivering it to S first. A issues the bound lookup. Hold S's signed staged answer until after the 10 s lookup cap (D89); let A select and persist replacement, then release the old artifact before and after J's replacement result in separate schedules. Also deliver staging to A before the deadline, lose A's terminal ACK and retry. | Baseline has no S8(b) replacement; this is a new-path race control. Fixed: fan-out alone makes S emit no artifact to J; a late lookup answer cannot become a competing terminal or install the old leaf. One replacement terminal, one installed leaf, usable keys and two-way encrypted traffic. Staged-first variant retries the same terminal, seals no replacement and spends no replacement budget. |
| `s8b_1149_current_confirmation`: A, J | Admit J and mint base-seated invite; withhold add/ban from J. Ban J via API, redeem stale invite. Run no-row and carry variants in TreeKEM/GSS/SignedPublic. Repeat removal, agent/machine revocation, certificate expiry/verdict change and withdrawal. | No-row: baseline reports Active without a current bound authority decision (encrypted variants also lack usable keys). Carry: baseline ends typed `Refused`/`TimedOut`; assert **absence of a current request-bound authority refusal**, rather than unsafe keyed Active. Fixed: current bound terminal refusal, no keys/secure access, all variants. |
| `s8b_1191_attempt_exit`: A, J | Timeout J without carry, redeem base-seated invite, remove J on A, deliver removal, API re-invite on same running J. Schedule old finalizer after newer attempt starts. | Baseline POST join returns 409 `join_already_pending`. Fixed: new attempt starts; `NotApplicable`, superseded, cancellation and terminal cleanup cannot erase it. This case gates the slice's merge like every other case (D91); an in-process test may supplement it, never replace it. |
| `s8b_legacy_authority_compat`: A admin on released v0.46.1 (repeat on v0.45.0), J candidate | Create a SignedPublic group and a TreeKEM group on A via API; admit J, then mint invites whose base already seats J. Restart J on the candidate after simulated host commit and redeem. In the TreeKEM no-row variant drop every Welcome to J. Advance the deterministic clock past the poll deadline. Then upgrade A to the candidate after host commit and fire J's retained record. | SignedPublic is a **control**: the rejoin completes on baseline and must still complete, now shown as `authority_confirmation: legacy_compatible`, with two-way signed traffic. TreeKEM no-row is **red**: baseline reports Active without usable keys (#1149). Fixed: `TimedOut(authority_upgrade_required)` at the deadline, no keyless Active, a retryable record; after A upgrades, a bounded terminal, usable keys and two-way encrypted traffic. A `LegacyCompatible` J never counts as `Confirmed`, a receipt or never-confirmed evidence. |
| `s8b_never_confirmed_evidence` **control**: A, D admins, J | (1) Seal J's seat on released v0.46.1, drop its Welcome, then upgrade all three after host commit. (2) On the candidate, confirm J, let A verify its receipt, then delete J's keys through a fault hook. (3) Inject a J-signed never-confirmed request for (2)'s generation, delivered to D. (4) Confirm J but drop its receipt before any admin verifies it, delete its keys, and inject repeated false requests across restarts. | Control for D86's new rule, not a claimed baseline red. Fixed: (1) `Refused(manual_reinvite_required)`, `no_never_confirmed_record`, nothing sealed; D43's remedy then completes. (2) `confirmed_keys_missing`, no replacement. (3) D refuses after the receipt query; nothing sealed. (4) At most two replacement seals, then `repair_budget_exhausted`, across restarts. |
| `s8b_poll_deadline_typed`: A candidate authority, J | API join J through A; hold A's terminal past J's 120 s TreeKEM poll deadline. Make the certificate fetch fail so A stages #946's `certificate_evidence_unavailable` at its 10-minute deadline. Deliver nothing else; make no manual retry. | **Red:** on baseline J's poll ends and J never sees A's later refusal. Fixed: J shows `TimedOut(waiting_for_authority_terminal)`, then the retained typed wait, then A's pushed typed refusal, with no manual retry (D64). |
| `s8b_1146_refusal_order` **control**: A, B, J | While J pending, API add B; deliver B's signed add before J's consumed-invite refusal, restart J, redeem fresh addressed invite. Deliver genuine ban/removal/quarantine in separate negative controls. | Post-#1148/#1190 baseline may already recover genuine unseated J; preserve that behaviour and typed consumed-invite refusal. Banned/removed/quarantined rows never clear. Still-seated staging loss belongs to the #1150 red case. |
| `s8b_keyed_unknown_upgrade` **control**: A, B | Create released keyed TreeKEM/GSS/SignedPublic fixtures through APIs, restart candidate after simulated host commit with no receipt sidecar, call info/send/secure APIs and confirmation probe; restart again. | Existing keyed members stay usable and migrate Unknown→Confirmed with **zero** new membership commits/epochs. No pre-host-commit sidecar write. Deliberately missing keys become typed Unconfirmed/ConfirmedKeysMissing, never keyed Active. |

Also fix the schedule for removal-before-response: J receives one removal with a verified exact-commit/actor marker, then matching add and mandate within the repair bound; terminal confirmation requires the whole verified chain. Missing/mismatched/late add preserves pre-repair state only until the bound, then applies the committed removal/native exclusion with typed exit, or records a conflicting-chain fork in typed quarantine without old-epoch service. A genuine ordinary removal, including one carrying a failing marker, is applied immediately as a terminal-removal control.
Test every role, unsupported-role refusal before mutation, serve-first when only the original sealer has staging, one terminal per attempt and never-installed entitled epochs separately from never-admitted epochs.
A non-receipting J repeats signed requests across staging expiries, new nonces and restarts (D90): at most two replacement seals; at most one pre-verify request per 30 s, burst two, per `(group, member)` and per `(group, forwarding admin)`, each drop answered `RateLimited`; backoff of 1 then 10 minutes, shown as `waiting_for_repair_backoff`; all across restarts; then `Refused(repair_budget_exhausted)` and D43's manual exit.
Every case asserts the typed state at each block it reaches, including the poll deadline (D64).
Lost receipt/ACK retries no rekey. Confirmed Active/duplicate replay seals nothing. Failed clone/prepare/persist leaves original usable state. Atomic receiver verification preserves both roster and native epoch only within the verified-marker pending bound; its terminal fallback enforces removal or fork quarantine.
Egress covers every producer listed in §4, copies/chunks, every physical resend, deadlines, quiesce races, fair admission under floods, revocation/expiry at the seam and survivor epoch moves.
Retain all 0106 carry/preflight/bounds/stale-attempt and 0107 carry/no-carry/certificate/current-roster controls.
Force post-handoff sibling races; preserve quarantine rather than silent adoption. All eight 0088 §2 controls remain: revoked/banned, invalid certificate, no admin, never-admitted epochs, signed deletion, post-removal catch-up, unanchored fork and all evidence holders offline.
Mixed versions use released **v0.45.0 and v0.46.1**, add **v0.46.2 once shipped**, both directions and legacy survivors. Test SignedPublic rejoin compatibility, typed bounded upgrade exit, absent/expired/offline advert gating, additive repair-field decoding and terminal native convergence.
Storage uses released raw-map fixtures with provenance/hashes, both legacy files and existing embedded-journal bytes; unknown/corrupt/trailing new bodies remain intact.
Test every crash cut and downgrade with pending/committed transactions: old daemon starts, sees J non-member/no secrets, never half-seats J; re-upgrade reconciles without duplicate rekey or obsolete head overwrite.
**Released-load controls (A admin, J; non-Home and Home variants):** create the group and J's pending join through public APIs, simulate host commit, persist the candidate Unconfirmed views, and stop at each journal crash cut before durable confirmation. Restart the released v0.45.0 and v0.46.1 binaries on that same data directory. Through info/member/invite APIs assert J has no seat or keys, no Active admin exists, invite mint fails and no commit/revision advance occurs; include a creator-identity reload to exercise `migrate_from_v1`. Check both loaded files, not only `named_groups.json`. After durable confirmation, use a separate control proving the complete compatible roster/key pair reloads. These are safety controls, not claimed red reproductions.
On released **v0.46.1**, obtain a fresh addressed invite from live A and redeem it on downgraded J: **a fresh invite starts a new join**, rather than an idempotent `not_member` result or `join_already_pending`. The pending placeholder must pass #1148's never-seated/no-J-entry classifier. Re-upgrade must reconcile this later attempt without resurrecting old work.
For Home J, also invoke the Home provisioning/owner-sync APIs under a deterministic delivery schedule. Assert the canonical Home ID is unchanged, no duplicate Home is created and `home.json` bytes remain unchanged. Run on both released binaries, including the no-owner-sync-pointer case, through reload and provisioning (D81). If any released control fails, Home activation stays blocked and a Home repair request ends `Refused(home_activation_blocked)`. Test that pre-host-commit base-seated admission refuses with `host_commit_pending` before any row or sidecar write, then starts Unconfirmed after host commit.
The live harness must prove durable confirmation and bidirectional encrypted traffic; documentation/governance success does not close any runtime gate.

## Rulings and open questions

**Still blocks David's Accept:** (1) S4, ADR 0110, Accepted first (D88), with D69's measured window and completion bound, which give the repair bound its final numbers (D89); (2) the retention proposal below (D90); (3) the unrestorable-role question below.

David ruled Q1–Q10 on 2026-10-04 (D64, D65, D81, D84–D92, D97):

- **Q1, old-authority compatibility:** `LegacyCompatible` completion under today's checks, visibly marked as lacking new confirmation; encrypted keyless attempts end in a bounded typed timeout (D84). §1 states it as the one named exception, with its L4 argument.
- **Q2, confirmed key loss:** the manual exit is enough. Keep `Refused(manual_reinvite_required)` and D43's remedy (D85). This explicit L1 gap is part of §6's named §2 entry.
- **Q3, leaf replacement trigger:** only with recorded never-confirmed evidence; receipt-less older seats use the manual exit (D86). This ADR reads "this device recorded" as J's own S8(b) record, checked by the designated admin against receipt evidence (§3). A record held only by the original sealer would block the any-admin case whenever that sealer is offline.
- **Q4, Home repair mandate:** the owner-device form and the promoted-admin form (D87). The capability floor stays an explicit L1 limit in mixed groups (§3, §6).
- **Q5, scheduling:** widen ADR 0016 §6 to repair rekeys; fallback uses S4's Accepted rules; 0114 is accepted after S4 (D88). "Lowest online eligible admin" is designated as S4 designates under D74.
- **Q6, bounds:** S4's final window and completion bound plus 120 s; ADR 0107's poll windows and 10-minute staging lifetime unchanged; at most three buffered links within existing byte caps; a 10 s exchange cap that also bounds the sealer lookup (D89). The final numbers follow S4's timing ruling (D69), which waits for harness numbers.
- **Q7, abuse budget:** the recommended rates, budget and backoff, all surviving restarts (D90). Retention stays open below.
- **Q8, #1191:** ships with the full S8(b) slice, not early (D91, against the recommendation). Its W3-H case comes first, as for the rest of the slice.
- **Q9, receipt MAC:** domain-separated BLAKE3 `derive_key` and keyed MAC, as specified (D92).
- **Q10, G7:** L3 is a hard rule for every slice, including the poll and upgrade or backoff waits (D64). §6 lists this slice's typed blocks.
- **Order:** "S8" in 0088's order means S8(a), ADR 0107. 0114 follows S4, and S5 does not wait for 0114 (D65).
- **Home placeholder:** Home activation is lifted only behind the released-binary controls; any failed control blocks it (D81, §5).
- **Behind retention:** D97 treats a member behind every holder's retention as admission, through S8(b) or a later ADR. S8(b) repairs only never-confirmed seats (D86), so a **confirmed** member behind retention needs a later ADR (§5).

Still open for David:

1. **Retention of budget records (D90 asks the authors to propose).** Proposal: keep a seat's rate-limit, budget and backoff record while that seat generation is on the roster and unconfirmed. Delete it when a receipt for that generation is verified, keeping only that generation's `AuthorityReceiptVerifiedV1`. Keep an exhausted budget until an ordinary removal, a ban or a signed group deletion, so restarts, nonces and new attempts cannot reset it; D43's fresh invite then starts a new generation with a new budget. Drop limiter entries for identities that leave the roster. The sidecar then holds at most one record per current `(group, member)` and per current `(group, forwarding admin)`, plus pending removals. Needs David's ruling.
2. **Unrestorable roles.** `Refused(repair_role_not_restorable)` (legacy Owner, Moderator, Guest) leaves only D43's exit, and no ruling covers it, so as written it is a refusal outside 0088 §2. Proposal: add it to §6's named §2 entry, because Owner is not assignable and Guest→Member would widen privilege. Needs David's ruling.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Claude's cross-model r1 requested changes; r2 reported APPROVE-WITH-NITS with the final decision-text corrections addressed here.
Claude recorded David's 2026-10-04 rulings at his instruction; the Status stays Proposed. This revision still requires David's acceptance.
Accepted ADRs 0088, 0094, 0106 and 0107 remain unchanged. No governed implementation is claimed by this documentation revision. The implementing PR will update API/CLI documentation and polling behaviour under the code gates above.

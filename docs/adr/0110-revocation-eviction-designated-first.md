# ADR 0110: Revocation Eviction, Designated First

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Amends:** [ADR 0016](./0016-role-based-group-authority-flat-admin.md) §6, upon acceptance: designated-first rekey for revocation, certificate expiry and self-leave. [ADR 0088](./0088-group-liveness-contract.md) §2, upon acceptance: one named entry for legacy members across a crypto-only exclusion (D76, §6).
- **Supersedes:** [ADR 0038](./0038-home-owner-certified-personal-space.md) in part, upon acceptance: its "evict at next seal" revocation path becomes bounded eviction.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** [#1113](https://github.com/saorsa-labs/x0x/issues/1113), [#1164](https://github.com/saorsa-labs/x0x/issues/1164); D16, D34(2), D40, D54, D58, D60, D63, D64, D65, D69–D76; ADR 0014, 0038, 0064, 0085, 0087, 0089, 0093, 0094, 0106, 0107, 0113.

Slice S4 of [ADR 0088](./0088-group-liveness-contract.md).
Verified agent revocation, signed self-leave and certificate expiry (D71) create durable cryptographic-exclusion work.
The lowest eligible roster admin acts first (D74); others hand off the evidence and wait before staggered fallback.
This proposal preserves removal authority and adds a capability-gated crypto-only transition for an already-Removed seat.
W, the completion bound, Δ and the restart sync wait come from W3-H harness p99.9 measurements (D69, D73).

## Context

Code citations refer to baseline `8b35dd1f447774e1a952166f32910fc41b512623`.
ADR 0038 relies on a later seal to evict a revoked Home member.
The verdict marks a positively revoked active seat `Failed` before certificate-grace handling (`src/groups/mod.rs:1543–1551`).
The explicit seal route calls the eviction engine (`src/server/routes/named_groups.rs:21785–21789`).
That engine removes a TreeKEM leaf, seals the roster and persists both states (`21548–21595`), or rotates GSS and builds survivor envelopes (`21633–21682`).
It returns `None` for non-OwnerCertified groups (`21285–21296`); ordinary groups must reuse the admin-removal path (`20979–21041`).
Revocation intake does not schedule either path: v1 verifies records, saves best-effort asynchronously and evicts discovery entries (`src/lib.rs:9676–9773`, especially `9700–9725`).

[#1113](https://github.com/saorsa-labs/x0x/issues/1113), assigned to S4 by 0088, is the roster-only self-leave gap.
Local leave emits no TreeKEM removal or epoch (`src/server/routes/named_groups.rs:20873–20885`).
Receivers allow that self-leave, but reject a self-authored TreeKEM payload (`12036–12049`); they install crypto removal only when its payload exists (`12139–12165`).
A target that self-left before being revoked can therefore be Removed in the roster and still hold a leaf.
S4 closes both triggers; roster exclusion alone is never proof of cryptographic exclusion.
An indefinite wait breaks **L1/L2**; **L4** forbids unsigned or unchained repair.
D64 makes **L3** a hard rule for every slice: each block this ADR adds or touches ends in a typed refusal or a typed, visible wait that names its cause.

Certificate expiry is judged against the local wall clock with a 300 s tolerance (`src/identity.rs:450`, `460–465`), through `verify_cert_against_owner` (`src/groups/owner_cert.rs:378–379`).
Today an expired seat is refused key deliveries (D60) and leaves only through the explicit seal route or a routine seal re-check.
After S7 stops routine re-checks, a seated TreeKEM member with an expired certificate could derive later epochs until an admin acts (ADR 0113 Q2); D71 closes that window here.

Legacy readers parse `named_groups.json` and `home-suite-groups.json` as JSON maps; changing either envelope aborts startup (`src/server/mod.rs:735–737`).
The Home parse error even recommends removing the file (`src/server/routes/named_groups.rs:30377–30381`).
S4 must preserve #451's legacy-safe views and ADR 0094's trial rollback contract.
The existing atomic persistence path holds the global `named_groups_persistence_lock` while writing (`27371`); its `.hsjournal` precedent avoids the legacy `*.journal` scan (`27390–27400`).
Ordinary sibling commits create a no-anchor fork marker cleared only manually (`4301`); a short fallback window can turn fleet delay into indefinite quarantine.

The public [rulings digest](../design/x0x-direction.md#5-decisions-d01d55) covers D34/D40 but ends at D55. Later rulings apply inline:

- **D58 (2026-10-03):** “accept all ADRs here now” — 0088, 0094, 0095 and 0096 were Accepted as written; their Open questions remain open. This does not accept S4.
- **D60 (2026-10-03):** “G11 = require current eligibility.” Every class-K GSS envelope delivery/resend requires current recipient eligibility and current secret epoch, including after agent/machine revocation, certificate expiry, verdict change or quarantine; entitlement is not fixed at commit.
- **D63 (2026-10-04):** “bind every slice in ADR 0088” — S4 is 0110, drafted Proposed and reviewed across models; separate acceptance order and D16/D54 harness-first still bind code.
- **D64, D65, D69–D76 (2026-10-04):** recorded in [Rulings and open questions](#rulings-and-open-questions).

## Decision Drivers

- One eligible reachable admin suffices; no owner, original sealer or quorum is required.
- Restart preserves signed evidence and unfinished work without publishing a stale sibling.
- Delayed designation discovery, fsync and CPU stalls must be measured in the fallback budget.
- Downgrade starts normally with legacy-readable files and intact new sidecars.

## Considered Options

| Option | Reason |
|---|---|
| Durable designated-first worker for revocation, certificate expiry and self-leave | Chosen; implements D34(2)/D40/D71 and closes #1113. |
| Expiry as a delivery refusal only | Rejected (D71); after S7 an expired seated member reads later epochs until an admin acts. |
| Lowest reachable admin first | Rejected (D74); local reachability views differ and can cause sibling rekeys. |
| Fixed 2 s W and 5 s completion | Rejected (D69); one lost frame or stall can cause sibling rekeys and ordinary-group quarantine. |
| Hold crypto-only commits on a survivor's last advert, or commit past known legacy survivors | Rejected (D76); the first lets a dead device block removal (L1), the second strands known survivors. |
| New versioned obligation sidecar and separate journal; legacy files unchanged | Chosen; preserves #451, 0085 and 0094 rollback safety. |
| Tagged v2 envelopes in existing JSON maps, or append obligations to the postcard journal | Rejected; legacy startup and journal replay would break. |
| Evict only at the next seal, or leave roster-only | Rejected; an idle group retains a former member's keys indefinitely. |
| Every observer seals immediately | Rejected; eager races create sibling rekeys. |
| Wait indefinitely for the lowest roster admin | Rejected; an offline device defeats L1. |
| Owner/admin quorum or an election/lease protocol | Rejected for S4; no quorum is required and this slice adds no consensus. |

## Decision

### 1. Triggers, intake and obligation

After full signature and issuer-authority verification, an **Agent-subject revocation** creates work for each live group where the target has a seat or a retained cryptographic leaf.
A verified, chained **self-leave** creates the same work after the roster-only leave applies, including receipt through catch-up.
A **certificate expiry** of an Active seat in a group that requires an owner certificate creates the same bounded work (D71); §1a defines it.
Key each obligation by **(stable group ID, target agent ID)**, with a set of verified revocation hashes, self-leave commit hashes and expired-certificate digests.
Persist signed records and authorizing evidence; duplicates and extra hashes for the same excluded leaf do not create another worker, extend a window or undo that exclusion's completion.
An already-Removed target completes only with verified cryptographic exclusion on the current chain; SignedPublic needs only roster exclusion.
If the target was validly re-admitted later, reconcile its seat/leaf incarnation and current revocation before deciding completion; old exclusion cannot certify a new leaf. A still-applicable/new agent revocation opens work for that current leaf under the same (group, target) key; an old self-leave proof alone cannot remove a later valid admission.

All revocation routes share one post-verification choke point **after `verify_and_insert` returns `Ok(true)`**.
These include v1 receive (`src/lib.rs:9676`), v2 binding receive (`9860`), v3 share-grant intake (`3814`), and local `apply_and_publish_revocation` (`11709–11722`), reached by `revoke_as_owner` (`11682–11700`) and local self-revocation.
Only Agent subjects schedule seat exclusion; other subjects still invalidate affected serving immediately.
Hook startup loads (`storage::load_revocation_set`, v2/v3 loads, `src/lib.rs:16952`, `17034–17041`) and any evidence/catch-up ingestion through the same verified intake/reconciliation logic.
Do not rely on the v1 asynchronous save: the obligation and its verified evidence require a durability barrier before S4 acknowledges durable work or seals.
Release the revocation-set lock before taking membership/persistence locks; queued notifications and startup reconciliation close missed-hook gaps.
Scan loaded rosters and crypto state read-only at startup and after catch-up; defer sidecar creation/writes and S4 execution until §5's host-commit gate.
A failed persist exposes `waiting_for_durable_intake`; retain the in-memory serving denial and retry without claiming durable completion.

**Machine and binding revocations deny that device only (D70).** They block every delivery and resend to the revoked machine (§3); the portable agent keeps its seat until that agent itself is revoked.
Grant revocations do not imply group-wide Agent-subject removal either.
Missing certificates and anonymous announcements are not eviction triggers; retain their existing verdict rules until the assigned slices replace them.

#### 1a. Certificate expiry trigger and clock skew (D71)

**Scope.** Expiry creates work only in groups whose admission policy requires an owner certificate for every seat (OwnerCertified, including Home).
Ordinary and SignedPublic groups have no owner-certificate check (ADR 0107), so expiry creates no work there.
This adds to ADR 0038's seal-time expiry re-check; it does not replace it. S7 retires that re-check only once S4 is in effect (0088 §3).

**Evidence.** The evidence is the target's best verified certificate for the group's owner: the committed roster certificate, or a verified renewal (same owner, same agent, later `not_after`) that the node holds.
Its signed `not_after` is the expiry time. A certificate with no `not_after` never expires.
An expiry trigger names one certificate digest; a re-admitted seat with a new certificate needs its own expiry.

**Who decides, and against which clock.** Each admin decides expiry for itself, against its own wall clock (UTC Unix seconds).
No shared clock exists, and a monotonic clock cannot be compared with an absolute `not_after`.
Let **τ** be the expiry tolerance; Q2 proposes its value.
- **Own trigger:** an admin's own trigger fires when its wall clock passes `not_after + τ`, the same test D60's delivery refusal applies. The node schedules this check from the committed `not_after` and repeats it at wake, at startup and after catch-up, so a missed timer never loses a trigger.
- **Hand-off:** a verified expiry hand-off (§4) starts a receiver's T_obs only once the receiver's own wall clock has passed the raw `not_after`. Before that, the receiver keeps the hand-off and starts T_obs when its clock passes `not_after`.
- **Effect:** no node evicts before the certificate's signed expiry on its own clock. Skew σ between admin clocks adds nothing to the fallback budget while σ ≤ τ; beyond τ it adds σ − τ, which the W measurement must cover (§2).
- **Budgets:** from T_obs on, §2's budgets run on the suspend-inclusive monotonic clock. A later wall-clock change neither renews W nor restarts a budget.

**Renewal cancels; revocation does not.** Before every seal, re-check expiry under the membership lock with the current wall clock and current verified certificates.
If a verified renewal now makes the seat valid, or the corrected clock is no longer past `not_after`, cancel the expiry work: phase `terminated`, cause `certificate_valid`, and no commit. A revocation or self-leave on the same key is never cancelled by a renewal.
While the group's verdict rule (ADR 0038 today, S2 once Accepted) gives grace to a warranted fetch of a renewed certificate, the obligation shows `waiting_for_certificate_evidence`, naming the announced digest. It resumes when the fetch resolves or that existing grace window ends, so the wait is bounded.

**Commit.** Remove an expired seat with the ordinary signed `MemberRemoved` and its matching TreeKEM removal or GSS rotation, as for a revoked seated target (§3).
Expiry eviction records no ban. The agent may rejoin through a fresh invite with a valid certificate; 0088 §2 item 2 still refuses an expired joiner, and an old exclusion never certifies a new leaf.

**Designation ignores expiry.** Designation and fallback ranks (§2) never evaluate certificate expiry, so a clock difference cannot split the designation. The target itself is never designated or ranked.
An admin whose own certificate is expired on its clock may not seal: it marks `local_committer_ineligible`, hands off, and the next rank falls back after W.
If no admin other than the target holds an unexpired certificate, the obligation shows `waiting_for_admin_certificate_renewal`, naming those admins. Q1 asks David for its exit.

**L4 for expiry.** No acceptance rule changes.
Any current admin may already remove a member (ADR 0016), so receivers accept the resulting `MemberRemoved` under existing checks and do not re-judge expiry on their own clock.
Expiry only schedules work; it grants no authority.
A clock more than τ fast can make an admin evict early, by at most its offset minus τ. An admin could already do that by hand, so this is an availability cost to the target, not an authority gain.
A forged or replayed expiry hand-off cannot shorten another node's budget: the receiver verifies the certificate's signature, owner chain and agent binding, and acts only on its own clock.

**Mixed versions.** Old binaries keep today's expiry handling and evict an expired seat only at an explicit or routine seal.
They accept the resulting `MemberRemoved` unchanged, and a legacy admin's own removal of the seat completes the obligation if its crypto exclusion matches.
Expiry hand-off goes only to `eviction_handoff_v1` receivers.

### 2. Designation, hand-off and staggered fallback

An eligible committer is Active and Admin-or-higher on the current committed parent roster and passes current signer-revocation, owner-policy and containment checks.
For designation and ranks only, skip the certificate-expiry part of these checks (§1a).
Order IDs by raw 32 bytes; legacy `Owner` is Admin-equivalent.
**The lowest eligible roster admin is designated (D74)**, whether or not it has a direct QUIC connection; all others wait.
This gives one designation on every node with the same head; lack of a direct connection or a stale presence record never grants early authority.
A reachable higher admin waits up to W for an offline lower one; D74 accepts that delay.
This is how S4 reads 0088 §3's "lowest online active-admin" (D40): among admins that act, the lowest eligible one acts first, and an offline lower admin costs at most W.
Operationally, reachable means an authenticated direct or routed exchange with that agent succeeds against current machine/binding evidence.
`unresolved_designated_admin` means hand-off has neither reached such an exchange nor returned a definitive current routing/eligibility failure; it preserves priority through W, not forever.

Each observing admin forwards signed trigger evidence to **every eligible admin** using `EvictionHandoffV1` (§4).
Define **T_obs** for each admin as the earlier of its own first hand-off dispatch attempt and its earliest verified hand-off receipt. Record dispatch before route resolution and the admitted physical write; for the designated admin, local verified intake is self-hand-off. Unroutable/unsupported results are recorded against that attempt. Route resolution itself consumes W, so an unresolved route cannot prevent the fallback clock from starting. For expiry, §1a limits when a receipt counts.
This is not the earlier gossip-observation timestamp. Persist observation, first-dispatch and earliest verified hand-off receipt timestamps and remaining budgets; an earlier verified hand-off may shorten a budget, while duplicates, retries and unrelated commits never extend or restart it.
Hand-off is authenticated evidence transfer, not a lease or exclusive-authority receipt; the receiver verifies it independently.
Fan-out gives all eligible compatible ranks a start within one hand-off latency, even when their own observations are far apart; the measurement gate must cover this delivery/verification skew.

Let **W** be the designated window and **Δ** the fallback stagger.
Only the designated admin starts a target exclusion before W expires.
Other eligible admins are ranked from r = 1 in raw-ID order excluding the designated admin; rank r may start at **T_obs + W + (r − 1)·Δ**.
Until then each shows `waiting_for_designated_admin`, naming the designated ID and its own fallback time.

**Timing values come from measurement (D69, D73).**
- **W and the completion bound:** each is set from the W3-H harness p99.9 of hand-off delivery-and-verification skew, plus persistence (fsync), CPU-stall and seal-and-propagation time, with margin (D69). For expiry triggers, W also covers inter-admin clock skew beyond τ (§1a). The draft's 2 s / 5 s suggestion is withdrawn.
- **Δ:** at least the measured p99.9 seal-and-head-propagation time; the harness compares 2 s to 5 s (D73).
- **Restart sync wait:** at least the measured p99.9 head catch-up, provisionally 10 s to 30 s (D73).
- **Accept waits for these numbers.** `s4_timing_measurement` (Validation) produces them from main's existing primitives, so it does not need S4 code. The authors then propose each value with its margin, and David accepts the values with the ADR.

Re-derive eligibility/ranks on a verified new roster without granting a fresh W; re-read head and evidence under the membership lock before **every** seal.
No verified exclusion may have landed, and the replica must have completed a current catch-up round first.
On restart, even an expired saved budget requires a catch-up round or the bounded restart sync wait above; never fallback on an unrefreshed head.
A round can use any authenticated holder, not a particular peer or quorum. If no other holder is reachable, the bounded wait may finish discovery (D73), followed by re-loading the complete verified durable local head/crypto; no known higher/conflicting head or incomplete replay may remain unresolved. If the wait expires with unresolved head evidence, expose `waiting_for_head_sync` and continue catch-up; expiry alone cannot authorize a known stale seal. All holders of missing head evidence offline is item 8; failure to progress with an available holder is a defect.
Clock rollback cannot renew the window; preserve remaining suspend-inclusive monotonic budget and boot identity rather than trusting wall time.
The bound applies while one eligible compatible admin and required evidence are reachable; offline survivor ACKs are not part of it.

A stale parent requires refresh, re-validation and re-signing, never publication of a pre-signed stale transition.
A timeout sibling retains fork evidence and quarantine. Ordinary no-anchor forks require manual admin action under 0088 §2 item 7; S4 adds no fork choice or cross-gap adoption.

#### Amendment to ADR 0016 §6

Upon acceptance, replace its first two TreeKEM-bound committer bullets with:

- **Involuntary remove/ban without pending S4 exclusion:** the initiating admin commits the rekey, under existing authority and stale-head checks.
- **Revocation or certificate-expiry eviction, or responsive rekey after self-leave:** use ADR 0110's designated-first hand-off, window and ranked fallback. The lowest eligible roster admin on the leave/current verified revision acts first (D74); a later head re-derives eligibility without resetting the window. This replaces lazy waiting for that particular admin's next online pass.
- **Manual remove, ban or explicit seal affecting an S4 target during the window:** a non-designated admin queues and hands off the request and returns `waiting_for_designated_admin`; it must not rekey that target early. After its ranked fallback time, it re-reads the head and may seal once. A verified removal/ban from any authorized admin completes the obligation if its crypto exclusion matches, including a legacy admin's event.

Intercept incidental target eviction inside `owner_certified_seal_with_eviction` too (`src/server/routes/named_groups.rs:21789`, revocation verdict `src/groups/mod.rs:1543–1551`).
An explicit/unrelated seal that would evict the pending target must defer that seal or route it to the designated worker; it cannot bypass the discipline.
This changes local scheduling, not the receiver's authority to accept a valid admin commit, and preserves 0016's last-admin invariant and concurrency limits.

### 3. Commit, evidence, restart and egress

Serialize roster, crypto state and obligation transitions under the group membership lock and existing persistence-lock order.
For a seated revoked or expired target, reuse ordinary signed `MemberRemoved` with its matching TreeKEM removal/epoch; ordinary groups use `20979–21041`, Home may use the OwnerCertified engine.
For an already-Removed self-leaver, remove its retained leaf through the crypto-only signed transition in §4; never restore the seat to enable removal.
For grandfathered GSS, rotate once and envelope only eligible survivors. For SignedPublic, roster exclusion completes a revocation or self-leave trigger without a crypto event; expiry never applies there (§1a).
Before S5, obtain removal evidence through `resolve_member_treekem_kp_for_removal_locked` → `request_member_key_package_catchup` (`8732–8775`, `10416`).
A miss exposes `waiting_for_member_key_package`, resumes when authenticated evidence arrives, and never treats a missing package as an absent leaf.
S5 owns new fetch-by-hash/oversized carriers; S4 does not widen 0089 lookup permissions or depend on S5 for an existing available-holder route.

Persist roster, crypto snapshot, obligation phase and exact outgoing event before publication (§5).
After restart with `committed_delivery_pending`, **re-sync the head before any resend**.
If the recorded exclusion is on the verified current chain and epoch, finish its eligible delivery without another rekey.
If another exclusion landed on a competing branch, do not publish the saved event: persist fork evidence, enter `waiting_for_fork_resolution`, and name manual admin resolution for ordinary groups (existing owner-anchor recovery for Home).
If a compatible exclusion superseded it on the same chain, complete work and discard obsolete delivery; never resend old key material after an epoch change.
If the head cannot be established, retain `waiting_for_head_sync`; a crash-after-commit is not permission to publish a sibling.
Use shared verified-chain delivery, not an authority catch-up log (D54); survivor convergence, not a transport ACK, proves delivery.

Invalidate staged results/Welcomes and cancel unsent transfers to ineligible recipients. A recipient that then asks gets ADR 0107's typed refusal, naming the failed eligibility input.
Every envelope, recovery response, Welcome and class-K delivery/resend uses ADR 0107's serving guard plus D60 **under the membership lock immediately before each physical write**.
Inputs are current roster membership/role and ban/withdrawal, agent revocation, authenticated recipient machine and agent-machine binding revocation, current certificate signature/issuer/expiry and verdict where required, quarantine/containment, and current secret epoch.
Ordinary groups gain a current **agent-revocation serving gate** even though 0107 skips OwnerCertified certificate checks for them.
Machine/binding revocation blocks delivery to that origin, including envelopes/resends/Welcomes, without removing a still-valid portable agent's seat (D70). A request from that device gets a typed refusal naming the machine or binding revocation.
There is no hidden transport resend or gossip fallback for key material; each new exchange re-admits and selects the current artifact/epoch.
Already delivered bytes and previously granted epochs cannot be recalled.
The [join-artifact lifecycle work on PR #1190](https://github.com/saorsa-labs/x0x/pull/1190) is related work; S4 supplies and validates these guards without depending on that PR merging.

### 4. Wire, acceptance and visible exits

Existing seated-target `MemberRemoved` encoding and validation stay unchanged.
New wire shapes are explicitly capability-gated under ADR 0093:

- **`eviction_handoff_v1`:** understands typed authenticated `EvictionHandoffV1` on the existing direct-message carrier. Its versioned body carries stable group ID, target ID, observed parent head, and one or more of: signed revocation records with issuer evidence, signed self-leave commit/chain proof, or the target's expired certificate (§1a). It is advisory evidence; the receiver verifies every record and current chain/authority, deduplicates by §1's key, and schedules only a verified trigger. No key material travels here.
- **`crypto_exclusion_v1`:** understands signed `CryptoExclusionV1` metadata for an already-Removed target with a retained leaf. The versioned body carries group ID, actor, target, prior head, next revision, roster-removal/self-leave proof hash, target leaf KeyPackage hash (TreeKEM), TreeKEM commit and next epoch or GSS next secret epoch, and signed `GroupStateCommit`. An outer agent signature in domain `x0x.crypto-exclusion.v1` binds the canonical body including crypto payload hashes and commit header. The roster stays Removed; the chain advances and the crypto binding/epoch changes together. There is no admission or restoration.

A receiver checks an eligible current parent-roster admin signature, chained prior removal proof, target/leaf binding, exact next revision/epoch, unchanged membership, last-admin invariant, policy/containment, and cryptographic removal proof before atomic install.
This is a **new L4 acceptance rule for the crypto-only event**, not a relaxation of legacy `MemberRemoved`: only a current authorized admin may exclude a leaf of a verifiably removed target, and no membership or authority is gained.
Do not assume released readers accept repeated `MemberRemoved` on a Removed seat; use released-reader controls and this distinct gated shape.
Gate each new typed send on the recipient's current verified capability; unknown/expired support first requests an authenticated advert refresh. Missing support exposes per-recipient `waiting_for_receiver_upgrade` and retains delivery for upgrade, never false completion.
**Legacy survivors follow the draft rule (D76): hold the crypto-only commit while any Active survivor has a current verified advert lacking `crypto_exclusion_v1`, and strand the rest until they upgrade.** Expose `waiting_for_receiver_upgrade` on the obligation, naming each holding survivor, as today's limitation 9 toward legacy members. Advancing the chain revision and TreeKEM epoch past such a survivor would strand it: its frontier-gap queue would hold every later commit, violating 0088's per-slice legacy degradation and R3. Under ADR 0093 semantics, unknown/expired capability state and offline survivors do not hold the commit, preserving L1; this requires no all-member capability quorum. A stranded survivor shows on every upgraded member as per-member `waiting_for_receiver_upgrade`, naming the gap revision. Both waits are permanent for a device that never upgrades; §6 records them as a named amendment to 0088 §2. Seated-target revocations and expiry evictions are unaffected: they use the legacy `MemberRemoved`. Do not send an unsupported peer a disguised repeated `MemberRemoved` or restore the target for compatibility.
New wire bodies use distinct typed prefixes (`X0XEVH1` for hand-off and `X0XCE1` for crypto exclusion) and explicit v1 postcard shapes with exact consumption; the outer crypto signature covers that deterministic body. Crypto-only delivery/catch-up uses per-recipient gated direct metadata delivery, never ungated metadata-topic publication. Reuse current carrier size/admission limits; an oversized proof waits for the existing authorized evidence route, not an invented S5 carrier.
**The new `CryptoExclusionV1` body never goes inside a container legacy binaries decode**, including ADR 0106's `intervening_events: Vec<NamedGroupMetadataEvent>` (`src/server/routes/named_groups.rs:1213`). That enum is internally tagged with `#[serde(tag = "event")]` (`1505–1512`); an unknown variant is a hard decode error of the #451 class. Across a crypto-only gap, capable joiners use capability-gated catch-up on the distinct new carrier and verify each chain link before resuming ordinary membership-event carry. Legacy joiners receive an existing attempt-bound typed refusal where supported, or expose `waiting_for_receiver_upgrade`; never embed the new body in their join-result carry or another legacy-decoded wrapper.
A capable joiner shows `waiting_for_head_sync` while its gated catch-up crosses the gap. If the existing 120 s join poll ends first, the attempt ends in ADR 0107's typed `TimedOut`, naming the crypto-only gap, never a silent stop (D64).
Hand-off to an unsupported designated admin records the unsupported attempt and waits for W, showing `waiting_for_designated_admin` with cause `designated_admin_unsupported`; a compatible fallback can use legacy removal for a seated target.

Each new bit's number is **allocated at acceptance, in acceptance order, as the next free bit in the README registry**. No number or README registry row is added now; the accepting PR allocates and fixes each name atomically.
Existing optional `peer_evidence_v1` remains under ADR 0089's budgets/authorization and establishes no committer authority.
Keep current signature, parent-roster authority, prev-hash, owner mandate, fork, revocation and TreeKEM adoption-exclusion checks (`src/groups/state_commit.rs:850–913`); keep last-admin checks (`735–746`).

A revoked signer cannot use its revoked key to remove itself.
**Sole eligible admin revoked (D75)** is not 0088 §2 item 3: its roster seat can still be Active.
Every member shows `waiting_for_eligible_admin_revocation`, with the revoked admin ID and the blocked exclusion, and no secrets.
**Member sends are refused with that typed state**, so no new message reaches the revoked key; admission and other admin operations return the same state.
David must rule the recovery or deletion exit before implementation (Q1). Until then this wait has no exit, so S4 code that can enter it must not merge.
For a genuinely admin-empty roster, retain `waiting_for_active_admin` under item 3.
A local worker demoted, self-left, removed or revoked stops sealing/delivery immediately, marks `local_committer_ineligible`, and hands work off while still authorized; otherwise retains evidence for remaining admins without sending unauthorized traffic.
Do not erase the shared obligation or claim exclusion complete merely because this local worker stopped. An absent local membership ends its local scheduling responsibility, not the group's exclusion requirement.
Signed deletion terminates work under item 5 (phase `terminated`, cause `group_deleted`). No-anchor forks wait under item 7 as `waiting_for_fork_resolution`. All evidence holders offline waits under item 8, in the state that names the missing evidence (`waiting_for_member_key_package` or `waiting_for_head_sync`). An available holder must enable progress.
Other deadline misses are defects, not new may-block-forever entries.

### 5. Separate versioned persistence and mixed versions

**Never change either legacy JSON format:** `named_groups.json` and `home-suite-groups.json` remain released-reader-safe maps, existing #451 placeholders are left unchanged; S4 adds none. Ordinary membership changes still use their existing encoders.
Use S4's own `<data_dir>/revocation-evictions.evs` sidecar with magic **`X0XEVICT1`**, followed by its frozen v1 postcard body, consumed exactly.
Use new `<data_dir>/treekem/<stable-group-id>.evjournal` journals with distinct magic **`X0XEVJ1`**, followed by their own frozen v1 postcard body, consumed exactly. Legacy `*.journal` and `.hsjournal` scans ignore both extensions.
Do not add fields to `TreeKemNamedPersistJournal` or alter its postcard layout; it replays before load (`src/server/mod.rs:726`).
Rows hold group/target, hash sets and signed evidence (for expiry, the certificate digest and `not_after`), observation/hand-off time, boot identity/remaining W and stagger budgets, designated/ranked IDs, phase, typed waiting cause, parent/result head and epoch, and exact outgoing event.
Phases are `pending`, `prepared`, `committed_delivery_pending`, `complete`, and `terminated` (cause `group_deleted` or `certificate_valid`); waiting causes do not destroy the phase/evidence.
Never serialize transient TreeKEM `PreparedMember` secrets.
**Retention (D72):** keep each pending row and its signed evidence until verified completion or a signed group deletion. Resource pressure never drops pending work; a failed write shows `waiting_for_durable_intake`. Limits for completed rows are open (Q3).

Create or materially write S4 files **only after ADR 0094 host commit**, never after instance health alone. Outside an upgrade trial, ordinary operation may create them lazily on its first verified trigger persist.
During the trial, scan/read existing files without rewrite, enforce in-memory serving denials, retain queued work as `waiting_for_host_commit`, and re-scan on host commit; retain rollback-readable legacy revocation saves.
Do not run S4 exclusion or journal replay that mutates persisted state before this gate.
Freeze decoders for each **released new sidecar/journal layout**, not every legacy JSON map; a later positional layout gets a new magic. Rewrite lazily on a material persist, never a boot migration.

Every new file barrier uses temp write, fsync, atomic rename and directory fsync. Transaction order under membership/persistence locks: fsync a prepared `.evjournal` with evidence, exact event and matching parent/result/epoch; then use the **unchanged** legacy roster/crypto transaction and its existing `.journal`/`.hsjournal` commit barriers; fsync the reconciled S4 sidecar; only then publish and retire the S4 journal.
The S4 journal is never an independent license to install a speculative roster/crypto after-image.
Startup order: inspect S4 formats read-only to contain affected groups; run existing rollback-readable legacy TreeKEM and Home journal recovery in their current order, then load merged rosters/crypto. Reconcile `.evjournal` and `.evs` read-only against that verified state before key serving; initialize stores and report trial health without waiting for host commit. After host commit, perform S4 reconciliation writes/replay and release queued S4 execution. The host gate must not deadlock 0094's store-initialization health prerequisite.
A matching committed result promotes delivery-pending; an unchanged parent with no legacy commit evidence returns to pending and abandons speculative preparation; a different/competing head triggers catch-up/fork containment. Never replay stale S4 state over a newer roster.
Unknown/corrupt S4 magic/body/trailing data leaves bytes intact and marks affected groups `waiting_for_obligation_store_recovery`; keep daemon startup and unrelated groups available. If group identity cannot be decoded safely, contain all potentially affected group key operations and expose recovery status, not an empty-map overwrite.
Restore a verified backup or use explicit operator recovery; never auto-delete or truncate these files.

**Downgrade:** old binaries ignore S4 files and retain ADR 0038's evict-at-next-seal behaviour; daemon startup stays available. No S4 bound is claimed there.
**Re-upgrade:** reconcile saved obligations against the current roster/crypto and verified chain, including removals/rekeys that happened on the old binary; do not restore stale seats or resend obsolete epochs.
**Old → new:** verify legacy self-leave/removal normally and schedule or reconcile crypto exclusion.
**New → old:** seated-target removals retain their encoding; hand-off/new crypto-only events are gated and must not be sent to unsupported receivers or embedded in legacy-decoded containers. Active survivors with current verified adverts lacking `crypto_exclusion_v1` hold crypto-only commits with obligation-level `waiting_for_receiver_upgrade`; unknown/offline survivors do not hold them and stay stranded until they upgrade (D76, §6). Joiners crossing an existing crypto-only gap follow §4's gated catch-up or typed refusal/waiting path. Expiry triggers degrade as §1a states.
A legacy admin may stay idle or race a valid removal; new admins wait then fallback, while mixed fleets retain legacy scheduling limits. The crypto-only upgrade hold leaves seated-target revocations on legacy `MemberRemoved` unaffected. No compatible admin means legacy behaviour, not S4 completion.

### 6. Amendment to ADR 0088 §2 (D76)

This ADR amends ADR 0088 §2 with one named entry, ruled by David (D76), upon acceptance. ADR 0088 is Accepted and is not edited.

9. **A legacy member across a crypto-only exclusion.** The member runs a binary without `crypto_exclusion_v1`. Two waits follow, and both are permanent for a device that never upgrades:
   - **Hold.** While an Active survivor has a current verified advert lacking `crypto_exclusion_v1`, the crypto-only exclusion of an already-Removed target does not commit. This covers a self-leaver and a target revoked after it self-left; meanwhile that target's retained leaf can still derive new epochs. Typed state: obligation-level `waiting_for_receiver_upgrade`, naming each holding survivor, visible on every upgraded member. Exits: the survivor upgrades and refreshes its advert; it stops being Active; or its advert expires, after which the commit proceeds and the stranded wait below applies to it.
   - **Stranded.** A legacy survivor that was unknown, expired or offline when the crypto-only exclusion committed cannot cross that revision and epoch gap. Typed state: per-member `waiting_for_receiver_upgrade`, naming the member and the gap revision, visible on every upgraded member. Exit: the member upgrades, then uses §4's gated catch-up.

A released binary cannot show either new state itself; it shows today's frontier-gap behaviour. Seated-target revocations and expiry evictions use legacy `MemberRemoved` and create neither wait.

## Consequences

- Positive: revocation, certificate expiry and self-leave no longer need an unrelated seal or original admin; #1113 is in scope. After S7, an expired seated member no longer reads later epochs until an admin acts (D71).
- Positive: legacy startup remains safe; crashes retain evidence without automatic stale-event publication.
- Cost: an Active survivor whose current verified advert lacks `crypto_exclusion_v1` holds crypto-only exclusion at `waiting_for_receiver_upgrade` until upgrade or the hold no longer applies; seated-target revocations still use legacy `MemberRemoved`. A pinned device that stays online holds it forever (D76, §6). Timeout races still require containment.
- Not protected: a legacy survivor that is offline, or whose advert has expired, when the crypto-only exclusion commits does not hold it. On return it cannot cross the chain and epoch gap, because the gated catch-up is never served to it. It stays stranded until it upgrades, which a pinned install may never do. A closed laptop during a self-leave is the typical case. David accepted this (D76); §6 records it.
- Cost: measured fallback values (D69, D73) make removal slower than the withdrawn 2 s suggestion, and David's Accept waits for the harness numbers.
- Cost: while the sole eligible admin is revoked, the group stops: member sends are refused (D75), and the exit is not yet ruled.
- Cost: a seat is evicted even if its renewed certificate arrives just after the commit; the agent must rejoin with a fresh invite. An admin clock more than τ fast can evict up to its offset minus τ early.
- Operational: seal-time certificate re-checks stay until S7, after S4 is Accepted and shipped.

## Validation

[#1164](https://github.com/saorsa-labs/x0x/issues/1164) tracks the not-yet-built W3-H harness. Recommend a separate S4 case-tracking issue; no issue creation or test result is claimed here.
Each **red** case must be committed and demonstrated red on `main` before S4 code merges (D16/D54); in-process tests alone do not meet this gate. Controls pass before and after.
Use real participants in CI's fresh loopback-only Linux namespace with deterministic clock, schedule seed, crash barriers and recorded public API calls.
For each case below, create/invite/join through public group APIs; let A < D < E be admins, B the target and C a survivor. Run Home and ordinary TreeKEM, with GSS/SignedPublic variants where applicable.
Let t = 0 be trigger submission via local revoke API or authenticated revocation receive; advance a virtual clock for worker budgets. Public head/status/message APIs assert results; crash hooks observe durability barriers without fabricating obligations. Default delivery is 100 ms per frame, in send order; departures from it are named below. Control baselines use public manual seal/remove to reach existing crypto/persistence barriers on main; S4-only phase/status assertions are additional post-fix checks, not claimed passing baseline controls.
**Healthy exit H:** reachable survivors have one coherent verified roster/head and epoch, C decrypts new traffic, B's retained old keys cannot; no publish return/transport ACK substitutes for H.
**Typed states (D64):** a case passes only if the waiting side sees the named state or refusal through public status APIs; a silent wait or a bare timeout fails. Each state in this ADR has a case:
`waiting_for_durable_intake` (`s4_restart_intake_prepare`); `waiting_for_designated_admin` and `unresolved_designated_admin` (`s4_fallback_rank_manual`, `s4_designated_late_observation`); `waiting_for_head_sync` (`s4_restart_stale_head`); `waiting_for_member_key_package` (`s4_evidence_holder`); `waiting_for_fork_resolution` (`s4_crash_commit_fallback`); `waiting_for_receiver_upgrade` and the join `TimedOut` (`s4_mixed_wire`); `waiting_for_eligible_admin_revocation`, `waiting_for_active_admin` and `local_committer_ineligible` (`s4_local_authority_exit`); `waiting_for_host_commit` and `waiting_for_obligation_store_recovery` (`s4_sidecar_rollback`); machine/binding refusals (`s4_intake_and_egress`); `waiting_for_certificate_evidence`, `waiting_for_admin_certificate_renewal` and `certificate_valid` (`s4_certificate_expiry_skew`).

| Case / baseline | Nodes, deterministic delivery and public steps | Assertion |
|---|---|---|
| `s4_idle_revocation_one_admin` / red | A,B,C; stop owner/original sealer. At t=0 revoke B through issuer API, deliver verified evidence to A, deliver all later frames on fixed schedule; never call seal. | H within accepted bound; main remains seated at its old epoch. Repeat self-revocation and ordinary groups. |
| `s4_self_leave_crypto_only` / red | A,B,C; at t=0 B calls leave, deliver its roster-only commit to A/C at t=100 ms; send no other mutation. Repeat revocation arriving after that leave. | B stays Removed, one admin crypto-only transition excludes its retained leaf and H holds; main retains the leaf. |
| `s4_designated_late_observation` / control + red fallback | A,D,E,B,C; D observes at t=0, hand-off reaches A at t=100 ms, original gossip reaches A only at t=W/2. Fixed subsequent delivery; then repeat with A stalled for W+Δ and D reachable. Add a variant where E observes at t=0, sends hand-off to every eligible admin with 100 ms delivery, and D's own observation arrives at least Δ later. | No early D/E sibling is the safety control; E's hand-off sets D's T_obs within one hand-off latency, so ranked D fallback precedes E despite observation skew. Automatic healthy exclusion and stalled-A ranked D fallback must reach H (red on idle main). |
| `s4_dropped_eager_frame` / control + red | A,D,B,C; D observes first; drop initial eager revocation and hand-off frames to A, flush IHAVE at 100 ms, deliver retry only after the 1.5 s per-peer timeout floor. Repeat total A loss while D/C remain reachable. | No premature sibling in recovered schedule (control); total loss gives D fallback after W, current-head sync and H (red). |
| `s4_netem_cpu_tail` / control + red | A,D,E,B,C; run netem profiles with 375 ms Sydney or 230 ms Singapore RTT reference plus ±100 ms jitter and 1% loss from a recorded seeded delivery trace; drop an eager frame, drive public unrelated persistence writes, impose 2-vCPU contention and a deterministic t=0..30 s stall on A. Apply each reference as an RTT profile with half per direction. Clock records hand-off and lock/fsync tails; repeat A blocked past accepted W. | Controls produce no early competing seal; fallback case reaches H if reachable/evidence prerequisites hold. Report any sibling quarantine as budget failure, never a pass. Main's idle exclusion is red. |
| `s4_restart_intake_prepare` / red | A,B,C; crash A after durable trigger intake, then separately after prepared journal before legacy commit. Restart same identity/data; catch-up to C completes at t=500 ms after restart. Send duplicate triggers at t=100 ms. Add a run where A's first intake write fails, then succeeds at t=1 s. | Evidence/budgets survive, catch-up precedes seal, no duplicate crypto epoch; H. The failed write shows `waiting_for_durable_intake` while serving denial holds. Main loses or never schedules work. |
| `s4_crash_commit_fallback` / control | A,D,B,C; partition A from D/C after hand-off. Crash A after durable exclusion before publish; advance D past W, sync its pre-A head and let D commit/deliver exclusion. Restart A; deliver D's head/proof before releasing A's resend. | A publishes no saved sibling; fork evidence and typed manual-resolution exit survive. On main, public manual remove reaches the same pre-publication barrier; the no-sibling-publication/fork-containment assertions are controls. Post-fix, the durable delivery-pending recovery must meet them too. A cannot claim H across a real fork. |
| `s4_restart_stale_head` / control + red resume | A,D,B,C; save pending work on A, stop it, let D's remove/ban API commit exclusion; restart A with expired W, delay head catch-up until t=500 ms. Repeat catch-up unavailable past proposed sync wait. | No fallback before sync; learned exclusion completes without another rotation. No evidence exposes `waiting_for_head_sync`; successful resume is red on idle main. |
| `s4_fallback_rank_manual` / control + red | A,D,E,B,C; hold A past W, deliver all heads in order. D/E call target remove, ban and explicit seal APIs before W, then advance clock across W and W+Δ. | Requests queue with `waiting_for_designated_admin` naming A; D may act at W, E only at W+Δ after re-read, never if D exclusion landed. Main's non-designated manual APIs rekey immediately, so the no-early-seal/queued-resume assertion is red; after the fix D/E obey W/Δ. |
| `s4_evidence_holder` / red resume | A,B,C plus holder D; A lacks B's KeyPackage. Revoke B; hold D offline until t=W+Δ, then let authenticated existing catch-up finish on fixed delivery. | Typed `waiting_for_member_key_package`, no fake absent-leaf completion; on D's return H without an API seal. All-holders-offline is item-8 control. |
| `s4_intake_and_egress` / red + controls | A,B,C; use v1 receive, local owner revoke and restart-loaded verified agent records separately. Stage join artifacts via invite/poll APIs; after staging revoke agent, then separately machine/binding, expire certificate or quarantine; invoke result/Welcome polling and scheduled resend at fixed times. | Agent-trigger H is red. Every physical key write rechecks current inputs/epoch; affected recipients receive no keys, ordinary agent-revocation gate included. A machine- or binding-revoked device gets the typed refusal while its agent stays seated (D70). Invalid issuer/signature and eligible first joins are controls. |
| `s4_local_authority_exit` / control | A,D,B,C; pending work on A, then D's public role/remove API demotes/removes A, or A leaves, or issuer revokes A before seal admission. Repeat with A as sole admin, revoked at t=0; B and C call the send API at t=1 s. Repeat with a genuinely admin-empty roster. | A stops writes/seals as `local_committer_ineligible` without erasing evidence; D resumes. Sole admin revoked: B and C see `waiting_for_eligible_admin_revocation` naming A, and their sends are refused with it (D75); never mislabeled admin-empty. Admin-empty shows `waiting_for_active_admin`. The exit follows Q1 once ruled. |
| `s4_sidecar_rollback` / control + red durability | A,B,C; use released data-dir fixtures with provenance/SHA256. Revoke during 0094 trial; inject rollback before host commit, then repeat host commit and each S4/legacy journal fsync crash barrier. Downgrade using released 0.45.0/0.46.1, mutate via old removal/seal APIs, re-upgrade. | No trial S4 writes or legacy-format rewrite; old startup succeeds and ignores new extensions; reconcile current head without restoring stale state. Post-commit durable scheduling is red on main. Unknown/trailing/corrupt S4 bytes stay identical and fail affected operations closed. |
| `s4_mixed_wire` / control + red upgraded route | Released 0.45.0/0.46.1 A or D with a new survivor C and new member B; choose A < D admins with D new and A released in one run, and reverse artifact roles in another; self-leave or revoke via APIs. Give an Active legacy survivor a current verified advert lacking `crypto_exclusion_v1`, then upgrade receivers and refresh adverts at t=W+Δ; repeat with unknown/expired adverts and offline survivors. After a permitted crypto-only commit, join capable and legacy receivers whose from_revision predates it through ADR 0106's join-result path. | Legacy removals still decode/decrypt both directions; the known Active legacy survivor holds crypto-only revision/epoch advancement with obligation-level `waiting_for_receiver_upgrade`, while unknown/offline survivors do not hold it. No new typed body reaches an unsupported peer or legacy-decoded container, including intervening_events. Capable joiners verify gated catch-up across the gap and converge; legacy joiners get a supported typed refusal or `waiting_for_receiver_upgrade` without a decode error. Upgraded members show per-member `waiting_for_receiver_upgrade` naming each stranded or holding survivor (D76). A capable joiner whose catch-up outlasts the 120 s poll ends in typed `TimedOut` naming the gap. Upgraded H is red on main; legacy lower-ID idle admin cannot prevent compatible seated-target fallback. |
| `s4_certificate_expiry_skew` / red + controls | Home (OwnerCertified, owner user U); admins A < D < E, target B, survivor C. Each node has a fixed wall-clock offset over shared virtual time; monotonic clocks follow virtual time; 100 ms delivery. Create and admit through public APIs; issue B's certificate with `not_after` = t=60 s through the public certificate API; call no seal. Runs: (1) all offsets 0; (2) A −τ/2, D +τ/2; (3) A −(τ + W/2); (4) D +2τ; (5) U's renewal for B reaches A, D, E at t=55 s, and separately 1 s after the exclusion commits; (6) A's wall clock steps back by W after its T_obs; (7) A, D and E certificates also expire at t=60 s, then U renews A's at t=60 s + 2W. | (1)(2) H within the accepted bound with one exclusion; no node seals before its own clock passes raw `not_after`; no eviction before true t=60 s while offsets ≤ τ; D seals nothing before its T_obs + W. (3) D falls back after W; any sibling is reported as a budget failure. (4) D evicts no earlier than true t=60 s − τ, and its hand-off starts no T_obs on A or E before their clocks pass t=60 s. (5) Pre-commit renewal: no `MemberRemoved`, rows `terminated` with `certificate_valid`; post-commit renewal: B stays Removed and rejoins by fresh invite. (6) No budget renews. (7) `waiting_for_admin_certificate_renewal` names A, D, E; after renewal A evicts B and H holds. Every run: no key delivery or resend to B after each sender's own expiry point. H is red on main, which never evicts without a seal; no-early-eviction and renewal assertions are controls. |
| `s4_timing_measurement` / control (measurement) | A,D,E,B,C, Home and ordinary TreeKEM, real time on main. Netem profiles and CPU contention as in `s4_netem_cpu_tail`, with concurrent unrelated persistence writes; recorded seeds. Over at least 10,000 trials per profile, measure: direct-message delivery and verification of a signed revocation record from D to A and E (hand-off skew proxy); public manual remove to C's verified head (seal and propagation); fsync barrier time; restart of A to current head (head catch-up). | Reports each p99.9 with raw samples, seeds and host profile. The proposed W, completion bound, Δ and restart sync wait each meet or exceed the p99.9 they cover plus the stated margin. Runs on main with existing primitives; it needs no S4 code. |

Record red/control/green SHAs, artifacts, seeds, delivery schedules, netem parameters, CPU/lock/fsync traces, measured p99.9 completion/skew and decryption results in the implementation PR.
Cover clock rollback, last-admin refusal, concurrent valid legacy removal, signed delete, no-anchor fork/manual exit, owner-offline operation and forbidden re-admission.
Preserve 0106 intervening-event carry for legacy-understood events, with §4's gated catch-up or typed refusal/waiting across a crypto-only gap, and 0107 serving controls, #842 inline-certificate first joins, no serialized `PreparedMember` secrets, and no authority/evidence lookup widening.

## Rulings and open questions

**Still blocking David's Accept:** the measured values for W, the completion bound, Δ and the restart sync wait (D69, D73); the exit when no eligible admin remains (Q1, D75); and the expiry tolerance τ (Q2, D71). Q3 (D72) blocks code, not Accept.

David ruled S4's questions on 2026-10-04 (D64, D65, D69–D76):

- **Former Q7 and 0088 G7, L3 (D64):** L3 is a hard rule for every slice. Every block this ADR adds or touches ends in a typed refusal or a typed, visible wait that names its cause, including the 120 s join poll and upgrade waits (§4). Validation asserts each state.
- **Acceptance order (D65):** "S8" in 0088's order means S8(a), ADR 0107. S8(b), ADR 0114, follows S4, and S5 does not wait for 0114.
- **Former Q1, W and the completion bound (D69):** set both from the W3-H harness p99.9 of hand-off skew plus disk, CPU and propagation time, with margin (§2). The 2 s / 5 s suggestion is withdrawn, and Accept waits for the numbers. Review inputs for the measurement: a 100 ms IHAVE flush, a 1.5 s per-peer retry floor for a lost eager frame, #656's 2-vCPU stalls of up to 30 s, and about 375 ms Sydney and 230 ms Singapore RTT.
- **Former Q2, machine-only and binding-only revocation (D70):** deny that device only. The agent keeps its seat until the agent itself is revoked (§1, §3).
- **ADR 0113 Q2 and the former §1 exclusion, certificate expiry (D71):** expiry is an S4 trigger with the same bounded eviction work as a revocation (§1a). τ stays open (Q2).
- **Former Q3, retention (D72):** keep pending evidence until verified completion or a signed group deletion (§5). The authors propose completed-evidence limits in Q3.
- **Former Q4, Δ and the restart sync wait (D73):** Δ is at least the measured p99.9 seal-and-propagation time, compared at 2 s to 5 s. The restart sync wait is at least the measured p99.9 head catch-up, provisionally 10 s to 30 s. After it, a node uses its verified local head only if it found no other holder and no conflicting evidence (§2). Accept waits for the numbers.
- **Former Q5, designation (D74):** the lowest eligible roster admin is designated, reachable or not; the others wait W, then fall back in rank order (§2).
- **Former Q6, sole eligible admin revoked (D75):** every member sees `waiting_for_eligible_admin_revocation`, and member sends are blocked (§4). David rules the recovery or deletion exit before implementation (Q1).
- **Former Q8, legacy survivors (D76):** the draft rule. Hold only for known Active legacy survivors, and strand the rest until they upgrade (§4). The pinned-device hold and the stranded wait are not on 0088 §2, so §6 adds them as one named amendment.

Still open for David:

1. **Exit when no eligible admin remains (D75, D71; blocks Accept and implementation).** A revoked sole admin cannot remove itself, and no other signer has authority. The same gap opens when every admin's certificate has expired (§1a). Without an exit these waits are L2 defects. Proposal for your ruling:
   - **Owner-certified groups, including Home, with the admin revoked:** a recovery exit. The owner's user key signs a capability-gated recovery commit. It removes the revoked admin's seat and leaf and promotes one named, currently eligible member to Admin, much as ADR 0064's owner anchor resolves forks. This is a new acceptance rule (L4: the owner key authorizes a roster change with no current admin signer) and a new wire shape. No such mechanism exists yet, so if you choose it, its design blocks S4's Accept.
   - **Owner-certified groups with every admin expired:** the exit is a renewed certificate from the owner (§1a); no new mechanism is needed. We propose that member sends continue meanwhile, because expiry is not compromise.
   - **Ordinary groups:** no owner key exists, so no signer can repair the group. We propose a deletion exit: once the sole admin's revocation is verified, the group ends for every member with a typed terminal refusal, `group_admin_revoked`, and the API offers to re-create it with the current members under a new admin. That terminal state is not on 0088 §2, so it needs a second named amendment, which you would rule.
2. **Expiry tolerance τ (D71; blocks Accept).** We propose τ = 300 s, the value every expiry check uses today (`EXPIRY_CLOCK_SKEW_SECS`), so eviction and D60's delivery refusal use one test. With admin clock skew σ ≤ τ, no node evicts before true expiry, and skew adds nothing to W. A clock more than τ off counts as a fault: `s4_certificate_expiry_skew` covers it, and the W measurement assumes σ ≤ τ. A larger τ delays eviction; a smaller τ lets normal skew reach W. Needs your ruling.
3. **Limits for completed evidence (D72; blocks code).** Proposal: once a row is `complete` and its exclusion is on the verified chain, drop its signed evidence bodies after 30 days. Keep a compact record (group, target, trigger hashes, result head and epoch) until a signed group deletion, at most 4096 per group, oldest first out. This is safe: the revocation set keeps the revocation records, and §1 re-derives completion from the verified chain, so a late duplicate completes without a new rekey. Drop `terminated` rows once the deletion or cancellation is durable. One gap also needs your ruling. A node that leaves or is removed cannot verify completion (0088 §2 item 6), so under D72 its pending rows would stay forever, and they hold sealed key material. We propose that local leave or removal ends local retention once the node has handed its evidence to an eligible admin, or at once if it may no longer send.

## Follow-ups

- Clarify the host-commit gate when M2 is absent, including the current helper's health commit (§5).
- Ensure hand-off-verified revocation records also enter the RevocationSet through §1's post-verification choke point.
- Ensure a queued manual ban is still applied after the designated removal (§2).
- Consider per-group `.evs` files to reduce the blast radius of an undecodable obligation store (§5).
- Make `s4_netem_cpu_tail` a deterministic gate; `s4_timing_measurement` now does the real-time p99.9 measurement.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted; Accepted ADRs remain immutable.
Acceptance order: 0088, then S2 and **S8(a) (ADR 0107)**, then S4 and S3, then S5, S6, S7. S8(b) (ADR 0114) follows S4, as 0107 specifies; “S8” in the earlier order means S8(a) (D65).
Land S4 **Proposed on main** before governed code merges; David must accept S4 before its code merges, and each red W3-H case must be committed and shown red on main first.
No D55 exception applies to S4. D63 permits drafting bound slices now, not skipping acceptance or harness-first.
Use the single `named_groups.rs` code lane; acceptance allocates capability names/numbers together. Values and policy still open above remain recommendations until David rules them.

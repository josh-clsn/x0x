# ADR 0112: Any-Admin Invite Redemption (0088 S6)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** TBD (cross-model review)
- **Slice:** Slice S6 of [ADR 0088](./0088-group-liveness-contract.md).
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0059](./0059-invite-authentication-and-seating-provenance.md) InviteV4 inviter pinning and [ADR 0064](./0064-owner-anchored-fork-authority.md) Decision §1a mandate preimage, **upon acceptance**, as assigned by 0088 §3.
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** D16 clause 2, D34, D37, D54–D55, D58, D60, D63; ADR 0085, 0087 rule 8, 0089, 0093, 0106, 0107; slices S3/0109, S5/0111 and S8(b)/0114; [#469](https://github.com/saorsa-labs/x0x/issues/469), [#472](https://github.com/saorsa-labs/x0x/issues/472), [#818](https://github.com/saorsa-labs/x0x/issues/818), [#1139](https://github.com/saorsa-labs/x0x/issues/1139), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1164](https://github.com/saorsa-labs/x0x/issues/1164).

Use a portable signed invite and a committed redemption record so any active admin can admit its holder while the issuer is offline.
Separate the invite issuer from the redeeming admin. Retain signature, current authority, owner-certificate, chain and fork checks.
The partition-wide single-use policy in Q1 remains undecided; it is an acceptance gate.

## Context

D16 clause 2 requires any active admin to redeem an invite. The [public rulings digest](../design/x0x-direction.md) records that requirement and D54's harness-first rule.
D63 assigns this mechanism to ADR 0112 as Proposed; D58 accepted the contract, not this mechanism.

The offline-inviter gap breaks **L1**: another reachable active admin is insufficient. It also breaks **L2**: waiting for the specific inviter is absent from 0088's eight permitted indefinite blocks.
The gap is named in 0088; #469/#472 track its existing authentication and mandate constraints, rather than a separate S6 bug number.

Current behaviour on `8b35dd1f447774e1a952166f32910fc41b512623`:

| Constraint | Source |
|---|---|
| A receiver other than the inviter retains recovery evidence but does not redeem. | `src/server/routes/named_groups.rs:13436–13457` |
| The inviter must still hold an active Admin-or-higher seat. An Active joiner replay is a no-op. | `src/server/routes/named_groups.rs:13525–13548` |
| An addressed invite rejects another joiner before consumption. Consumption uses the local issued-invite map. | `src/server/routes/named_groups.rs:13609–13646` |
| The local ledger checks existence, consumption, role, creation time and expiry. It then records the consuming agent. | `src/groups/mod.rs:2410–2444` |
| The request signature includes the inviter and secret. Result verification pins both sender and actor to the expected inviter. | `src/server/routes/named_groups.rs:2788–2839`, `src/server/routes/named_groups.rs:33264–33278` |
| The join route installs that expected-inviter pin from the invite. | `src/server/routes/named_groups.rs:18752–18760` |
| Mandate production needs the policy owner's loaded USER key. The preimage binds the actual authority and issuance time. | `src/server/routes/named_groups.rs:22690–22748`, `src/groups/owner_mandate.rs:149–175` |
| The state hash has no committed invite-consumption root. | `src/groups/state_commit.rs:307–327` |
| Group persistence uses JSON maps, with a separate authoritative Home-Suite map. | `src/server/routes/named_groups.rs:30318–30329`, `src/server/routes/named_groups.rs:30369–30383`, `src/server/routes/named_groups.rs:30504–30518` |

Changing only the receiver check leaves the local ledger and result pin intact. Copying only that ledger permits another admin to consume the same token independently.
#1139/#818 require verified catch-up when the invite base is stale. #1149/#1150 distinguish a committed seat from current admission and usable keys.
S6 must preserve that distinction and cannot claim to solve re-Welcome on its own.

## Decision Drivers

- An offline issuer or owner device must not prevent an eligible admission.
- The joiner must carry verifiable authorization; no issuer lookup is required.
- A consumed invite must remain consumed after removal, restart and admin handoff.
- Widening redemption requires an explicit **L4** security argument.
- A local lock cannot establish fleet-wide single use during a partition.

## Considered Options

1. **Forward every request to the issuer.** Rejected: it preserves the L1 failure.
2. **Replicate the existing secret ledger without committed consumption.** Rejected: disconnected copies can each spend the token; restart can erase the only receipt.
3. **Drop inviter and mandate checks.** Rejected: it would admit unauthenticated requests and remove the owner's authorization boundary.
4. **Require an online owner, fixed coordinator or admin quorum.** Rejected: each adds an indefinite dependency that D16 and L1 exclude.
5. **Portable authorization plus committed redemption evidence** (chosen as the mechanism). Q1 still governs its partition semantics; no automatic fork winner is chosen here.

## Decision

### 1. Capability and portable authorization

Propose registry-v1 **bit 6**, `group_invite_any_admin_v1`, with constant `GROUP_INVITE_ANY_ADMIN_V1 = 1 << 6`.
It means support for the complete invite, redemption, commit, result and persistence contract below. The canonical [README registry](./README.md) currently allocates only bits 0–2.
Leaving 3–5 available avoids consuming the first slots ahead of earlier wire slices in 0088's acceptance order.
Bit 6 remains a proposal until reviewed and entered in that registry; reconcile allocations before acceptance. This draft adds only the required Proposed-list entry, not a premature allocation.

Use a distinct **InviteV5** canonical view, domain `x0x.invite.v5\0`, and signature domains `x0x.invite.v5.inviter\0` and `x0x.invite.v5.owner\0`. Freeze V4 signed bytes and decoders; do not append inside a positional V4 view.
V5 signs every V4 semantic field plus a random 256-bit `invite_id`, `max_role = Member`, and `redeemer_scope = active_admin`.
The issuer's agent signature and the owner USER countersignature for an owner-axis policy cover the entire view.
The secret commitment is BLAKE3 over the decoded 32 secret bytes; reject ambiguous encodings.
The owner countersignature is the portable permit to execute this invite's single admission.
It authorizes no other joiner than the intended agent, if present, and no role above Member.
Existing creation, expiry, owner pin, policy, base-consistency and size checks remain.
Use S5's single carry/fetch rule for over-budget evidence, including the #646 base-roster primitive; add no separate certificate carrier.

A V4 invite stays issuer-pinned; its signatures cannot authorize V5 scope retroactively. Re-mint it while an authorized issuer is available to gain any-admin redemption.
V5 support is positive evidence from a current verified, machine-bound ADR 0093 advert, never a version string or AgentCard.
Unknown capability triggers a bounded refresh under D35; it does not authorize a V5 send.
Never fall back to a V4 request with V5 bytes or silently change the invite's scope.

### 2. Request, authority and result binding

Send a distinct versioned redemption envelope to a reachable active admin over authenticated, encrypted point-to-point transport; never publish the bearer secret on gossip.
The joiner signs the stable group ID, complete invite digest, invite ID, secret proof, joiner ID, requested role, key-package digest, certificate digest and attempt nonce.
Bind its KEM key to those same request bytes when that key is used. Define a logical `redemption_digest` over the invite digest, joiner, role, key package and certificate; attempt nonces are outside that digest.
Carry the signed invite and required source evidence; fetch missing bytes through S5 from any eligible holder.
EvidenceV1 supplies authenticated agent/machine bindings; it does not prove group-admin authority.

Before mutation, the receiver verifies both invite signatures where required and the joiner's signature and secret proof.
It proves the issuer was authorized at issuance from the verified invite base.
It verifies the issuer's current revocation and authority status as the existing admission path requires. An offline issuer is not a failed authority check.
The receiver independently proves its own active Admin-or-higher seat at the actual predecessor head.
If it was promoted after the invite base, a verified walk must include that promotion.
It checks current policy, bans, revocations, owner certificate, withdrawal/deletion and containment before constructing a candidate.
It never infers current eligibility or confirmed membership from the invite's base-seated snapshot.

Catch up through S3/S5 and normal verified apply before seating; retain the TreeKEM across-gap adoption exclusion.
Bind a result to `(group, invite_id, request_digest, attempt_nonce, redeemer_agent_id, terminal_hash)`.
For a new seat, the authenticated result sender and terminal actor must match the selected redeemer. Verify its authority from the predecessor roster, not from the inviter field or the capability bit.
Changing redeemer starts a fresh nonce and invalidates the previous live attempt under the membership lock.
For recovery, the selected admin wraps the original signed artifacts with the fresh attempt binding; verify the original actor independently through S5. A bare old response cannot confirm the new attempt.
Bound discovery, retry and fetch work; propose the existing 120-second TreeKEM attempt window as the S6 exit budget (`src/server/routes/named_groups.rs:33245–33247`).
Budget exhaustion reports a typed retryable outcome and preserves verified progress; it never reports keyed-active.

### 3. Owner mandate: explicit L4 amendment

For V5 owner-axis redemption, replace the requirement for a fresh owner-signed terminal mandate with **two signatures**: the owner's portable invite permit and the redeemer's terminal intent.
This is a new acceptance rule, not an absent-mandate grace case.
The terminal intent uses `x0x.owner-mandate.delegated.v1` and a distinct versioned type.
Its canonical preimage retains all **13** shipped v2 bindings, including the actual authority ID and issuance time.
Add the invite digest, invite ID, request digest, attempt nonce and consumption roots before/after redemption.
Encode fields in the shipped v2 order, then those additions, using fixed-width integers and length-prefixed variable bytes.
The redeemer signs the BLAKE3 digest with its agent key; the permit supplies the independent owner authorization.
Do not substitute the issuer ID for the redeemer or sign a wildcard terminal with the owner key.

Derive the parent, next revision, post-add roster, policy/meta hashes and intended epoch from the actual pre-mutation state.
Every enforcing receiver recomputes the candidate and requires candidate, intent and terminal roster roots to agree before installation.
It also checks both consumption roots, certificate digest, request binding and exact epoch against the terminal.
The certificate must satisfy the current policy owner, revocation set and clock.
Signature, sender authority, prev-hash linkage, fork evidence, revocation and epoch entitlement remain fail-closed.
The bounded delegation widens **who executes** the owner's signed permission, not its recipient, role or policy scope.
A copied permit alone cannot create an authorized terminal: it still needs the joiner's proof and a current admin signature.
This delegated intent is **not** an owner head attestation or an independent owner fork anchor.
It cannot clear quarantine, select a sibling or evict another member; S3's self-recovery limits remain.
Legacy v2 mandate verification and §1b's per-authority grace states remain unchanged on legacy admissions.

### 4. Consumption, concurrency and crash safety

Key consumption by `(stable_group_id, invite_id)` and retain `(invite_digest, joiner_id, redemption_digest, original_request_digest, terminal_revision, redeemer_id)`.
Commit a canonical sorted consumption-map root with the membership state in a new versioned S6 commit envelope; disseminated proofs use the signed invite view and secret commitment, excluding raw bearer secrets.
Bind the terminal state hash to the old state-hash inputs plus that root and the S6 protocol version under a new domain.
Every later S6 mutation carries the root forward; legacy mutations cannot erase it.
Hash-linked snapshots must include the consumption map; do not reconstruct it from a volatile event log.

Under the membership lock, verify the predecessor and unconsumed ID, build the roster/consumption candidate, seal and persist it with the TreeKEM snapshot before publishing.
Failure installs neither a consumed-only state nor a seat without its consumption proof.
The same logical redemption on the verified chain is idempotent across fresh attempt nonces and creates no second seat, rekey or Welcome. A different joiner or logical redemption, or replay after removal, is refused as consumed; a fresh invite is required.
A new admin must verify consumption state with the head before attempting redemption.
Retain tombstones while the signed invite remains usable, including forever for a no-expiry invite; impose backpressure rather than silently dropping protection.

Two admins with the same predecessor can still sign sibling terminals before they exchange commits. Receipt dissemination and local locking reduce that race but cannot eliminate it across disconnected nodes.
Authenticate conflicting evidence and apply the existing fork rules; never merge consumption maps while ignoring conflicting roster/TreeKEM state.
An ordinary unanchored fork may wait for manual admin action under I8 item 7.
No claim of partition-wide exactly-once redemption or automatic winner selection is made pending **Q1**.

### 5. Persistence, compatibility and serving

Persist the complete S6 group state in **`X0XNGS2\0 || bincode(NamedGroupStoreV2)`** at the existing authoritative group-store path.
Include the protocol version, consumption map/root and signed redemption proofs with the roster, rather than a separately writable ledger.
Use the same versioned container for the Home-Suite store when it carries S6 state; preserve the split-store transaction.
Read every released JSON-map layout through frozen shapes and rewrite lazily at the first S6 persist, never at startup.
Version any changed TreeKEM/group transaction journal with a new magic and keep its released decoder.
Consume each body exactly; corrupt or unknown formats leave the bytes untouched and refuse the store.
Released JSON-only readers refuse the binary magic; they must not overwrite it or fall back to a legacy Home placeholder.
Their current startup propagates group-load failure (`src/server/mod.rs:735–737`), so downgrade may stop the daemon, not only one group.
Release notes must state that limit; real released-binary downgrade proof is required by ADR 0085.
Upgrade again restores the full roster and consumption state; never serialize `PreparedMember` secrets.

| Direction | Required behaviour |
|---|---|
| Old joiner → new admin | V4 uses unchanged inviter-bound admission; a non-inviter does not convert it. |
| New joiner → old admin | Use V4 only if the supplied invite is V4; V5 requires upgrade and stays retryable. |
| New ↔ new | V5 envelopes require the bit at both ends and mandatory delegated/consumption checks. |
| Old existing member | Keep legacy groups working. S6 activation/migration with offline old members is gated on Q2; do not send new envelopes on a legacy topic or let old code write S6 state. |

Use distinct S6 message tags/topics for requests, commits and results; never disguise them as legacy `MemberJoined`/`MemberAdded` fields.
Recovery from a lost response uses verified S5 artifacts or S8(b)'s separately accepted re-Welcome rule, never a second consumption.
Serve every result, blob chunk, Welcome and secret resend only to a currently eligible recipient under ADR 0107 and D60.
Re-check revocation, expiry, quarantine and current secret epoch at each key-delivery attempt; cancel unsent transfers on removal, ban or group retirement.
The [join-artifact serving lifecycle note on PR #1190](https://github.com/saorsa-labs/x0x/blob/e645ce253bac6fc36b1dffd2398836da1f0096e8/docs/design/join-artifact-serving-lifecycle.md) is **related work only**, not on main and not a dependency.
S6 must prove its own guarded egress; neither the note nor an old cache entry grants admission.
The eight I8 indefinite-block reasons remain; issuer-offline is never a ninth. Expose typed terminal policy refusals and visible retryable waits; 0088 G7 still governs whether L3 binds every slice.

## Consequences

- **Positive:** a valid V5 invite can admit through a current admin with no issuer or owner-device round trip.
- **Negative / trade-offs:** new wire and persisted formats require explicit rollout; tombstones cost storage, and partition-wide single use remains Q1.
- **Neutral / operational:** V4 remains pinned. S6 does not change Home provisioning, owner-certificate policy, revocation eviction, or S8's re-Welcome authority.

## Validation

These are **required, not yet implemented or run**, W3-H cases under #1164. Record fixture identities, base/fix SHAs, deterministic schedules, bounded assertions and red/green receipts in the implementation PR.
Run real daemon/protocol paths in CI's fresh loopback-only Linux namespace; in-process red tests alone do not count (D16/D54).

| Case | Exact schedule and exit assertion |
|---|---|
| `s6_offline_inviter_other_admin_admits` | At one committed head, A and B are active admins. A mints J's invite. Stop A before J sends any redemption. Keep B online with current keys/evidence and no A-local issued record. Red: the legacy invite cannot seat J through B. Green: the equivalent V5 invite reaches confirmed, usable TreeKEM membership through B within 120 s, without contacting A. Repeat ordinary and OwnerCertified groups; B lacks the owner USER key. |
| `s6_promoted_admin_stale_invite` | Mint at r; promote B at r+1, then stop A/owner and restart B. J starts at r. B proves its promotion and the intervening chain via S3/S5, admits and supplies usable keys. Red: inviter/result pinning blocks. Green: no quarantine for a legitimate gap, no across-gap TreeKEM adoption. |
| `s6_replay_restart_and_admin_handoff` | Redeem once through B; replay at B, then at caught-up C after restart. Remove J and replay again. Assert one consumption and no extra commit/rekey for identical retries; no re-admission from the spent token. Lose B's response separately and recover using S5/S8(b), without new consumption. |
| `s6_two_admin_double_redemption` | Deliver the same bearer invite to J and K through B and C. Run ordered delivery, same-parent concurrent delivery, and partition/heal schedules. Ordered: one spend; loser gains no keys. Concurrent: detect signed sibling evidence and exercise the Q1-ruled outcome. Do not count per-admin mutexes as a global single-use proof. |

Exit gate: both liveness red cases fail on the pinned pre-fix tree and pass on the fixed tree with the issuer continuously offline.
The conflict case must satisfy David's Q1 ruling before S6 acceptance; it cannot be skipped as a known limitation.
Non-regressions cover V4 same-inviter joins, ADR 0106 carries, ADR 0107 re-arm, current serving eligibility and S3/S5 catch-up.
Reject wrong-owner/expired/revoked certificates, removed/banned joiners, revoked/non-admin redeemers, foreign groups, altered roles/secrets/packages and transplanted mandates or attempts without state change or key egress.
Exercise all eight I8 blocks, including signed deletion, removed-member epochs, never-admitted epochs, no reachable admin/holder and manual unanchored-fork recovery.
Fault-inject before/after each journal write, snapshot replace, directory fsync and egress; restart never loses consumption or confirms without usable keys.
Use fixtures from actual released encoders; hash files before downgrade, refused startup and re-upgrade, and verify byte-identical preservation and restored consumption.
Mixed-version CI uses real v0.45/v0.46 peers in both directions, absent/stale/forged adverts and an old member across Q2's migration; no V5 byte reaches a legacy handler as V4.
Accept in 0088's order: S2 and S8, then S4/S3, then S5, then S6, then S7.
S6 must land Proposed on main and be Accepted by David before its slice code merges; one `named_groups.rs` lane at a time (0088 §4, ADR 0087 rule 8).

## Open Questions for David

1. **Q1 — single use during partitions:** must a bearer invite admit at most one distinct agent across disconnected admins, or may conflicting spends enter the existing fork/manual-recovery contract? Strict global single use needs coordination or a recipient restriction that D16 does not rule. No bearer partition policy or new fork winner is authorized by this draft.
2. **Q2 — group migration:** may an S6 group require all existing members to upgrade before activation, or must offline legacy members retain participation during activation? The capability bit gates delivery; it cannot make an old admin enforce committed consumption. No version floor or exclusion policy is chosen here.
3. **G7 inherited from 0088:** does L3 bind S6 and every other slice, including the short join poll versus later authority refusal? D58 leaves G7 open; S6 proposes visible outcomes without closing it.

## Source Reconciliation

- ADR 0064 §1a lists fewer mandate bindings than shipped. Its README errata and #472's corrected preimage comments add `version`, `authority_agent_id` and `issued_at_ms`; use the 13-field code shape cited above.
- The public digest still calls 0088 pending and ends at D55. The Accepted contract and D58/D63 govern status and slice binding; leave those read-only sources untouched.
- ADR 0093's immutable table calls bits 2–63 unallocated. ADR 0089 moved allocation to the README and allocated bit 2; use that canonical table.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs stay immutable; later decision changes require an amending or superseding ADR.

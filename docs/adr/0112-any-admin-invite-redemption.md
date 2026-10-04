# ADR 0112: Any-Admin Invite Redemption (0088 S6)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S6 of [ADR 0088](./0088-group-liveness-contract.md).
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0059](./0059-invite-authentication-and-seating-provenance.md) inviter pinning for V5; [ADR 0064](./0064-owner-anchored-fork-authority.md) Decision §1 (owner pre-mutation signature), §1a (mandate preimage) and §1b (absent-mandate machine) for V5; [ADR 0107](./0107-stuck-join-rearm-and-serving-guard.md) Decision's original-inviter binding, limited explicitly to V4; ADR 0110 (S4) and ADR 0109 (S3), limited to S6-activated groups: the activated-group state-hash boundary binds later `MemberRemoved`/eviction commits and their verification. These take effect **upon acceptance**, subject to Q6's scope ruling; the 0088 §3 row explicitly names only 0059 InviteV4 and 0064 §1a. V4 retains every existing authentication rule; activated V4 mutations use the S6 envelope.
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** D01, D16 clause 2, D34, D37, D54–D55, D58, D60, D63; ADR 0085, 0087 rule 8, 0089, 0093, 0094, 0106, 0107; slices S3/0109, S4/0110, S5/0111, S7/0113 and S8(b)/0114; [#451](https://github.com/saorsa-labs/x0x/issues/451), [#469](https://github.com/saorsa-labs/x0x/issues/469), [#472](https://github.com/saorsa-labs/x0x/issues/472), [#818](https://github.com/saorsa-labs/x0x/issues/818), [#1139](https://github.com/saorsa-labs/x0x/issues/1139), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1164](https://github.com/saorsa-labs/x0x/issues/1164).

Use a portable signed invite and a committed redemption record so any active admin can admit its holder while the issuer is offline.
Separate the invite issuer from the redeeming admin. Retain signature, current authority, owner-certificate, chain and fork checks.
The partition-wide single-use policy in Q1 remains undecided; Q1–Q6 are acceptance gates wherever this mechanism depends on their rulings.

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

Name the registry-v1 capability **`group_invite_any_admin_v1`**.
It means support for the complete invite, redemption, commit, result and persistence contract below. The canonical registry is in the [README](./README.md).
Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry.
This draft adds no registry row or numeric allocation; the accepting PR adds the row and fixes the number everywhere together.

Use a distinct **InviteV5** canonical view, domain `x0x.invite.v5\0`, and signature domains `x0x.invite.v5.inviter\0` and `x0x.invite.v5.owner\0`. Freeze V4 signed bytes and decoders; do not append inside a positional V4 view.
Keep the link's released parseable shell, `x0x://invite/<base64 JSON>`, with its required parsing fields and `version = 5`; V5 authorization uses only the distinct V5 canonical view. This lets a released V4 parser reach its typed version refusal rather than fail on an unknown URL prefix. The link carries the bearer secret, but the signed view contains only its commitment, as V4's view does.
V5 signs every V4 semantic field plus a random 256-bit `invite_id`, the base policy's canonical `policy_hash`, a `max_role` bound subject to Q4, and `redeemer_scope = active_admin`.
The issuer's agent signature and the owner USER countersignature for an owner-axis policy cover the entire view.
The secret commitment is BLAKE3 over the decoded 32 secret bytes; reject ambiguous encodings.
The owner countersignature is the portable permit to execute this invite's single admission.
It authorizes only the intended agent when addressed, and no role above its signed `max_role` or the current policy's permitted role. A Member-only cap is a recommendation in Q4, not a D16 ruling.
Existing creation, expiry, owner pin, policy, base-consistency and size checks remain.
Use S5's single carry/fetch rule for over-budget evidence; add no separate certificate carrier.
S5/0111 **Q3 — pre-member roster fetch (#646)** currently refuses a pre-member's `roster_projection` fetch. The V5 path that needs it cannot ship until that ruling authorizes the invite-bound fetch; until then it must carry sufficient authorized evidence or refuse visibly before creating a stub. S6 grants no new disclosure exception.

A V4 invite stays issuer-pinned; its signatures cannot authorize V5 scope retroactively. Re-mint it while an authorized issuer is available to gain any-admin redemption.
On an activated group, an S6-aware issuer retains V4 authentication and ledger checks but seals any resulting mutation in the S6 envelope, carrying the existing consumption root. An old binary sees only the legacy placeholder whose non-empty `members_v2` entries are all Removed, preventing creator-to-Admin migration; released-binary reload tests must prove it inert (§5).
V5 support is positive evidence from a current verified, machine-bound ADR 0093 advert, never a version string or AgentCard.
Unknown capability triggers a bounded refresh under D35; it does not authorize a V5 send.
This positive-advert gate is deliberately stricter than ADR 0093's shipped grant/offer gates, which send on unknown, expired or card-only state. Those 0093 gates remain unchanged; only S6 envelopes require positive support.
Never fall back to a V4 request with V5 bytes or silently change the invite's scope.

### 2. Request, authority and result binding

Send a distinct versioned redemption envelope to a reachable active admin over authenticated, encrypted point-to-point transport; never publish the bearer secret on gossip.
J first tries verified admins from its invite base. For an admin absent from that base, J uses candidate contact hints from existing peer relationships, ordinary group discovery or other reachable holders, then resolves the agent/machine binding with EvidenceV1. These hints confer no authority. J verifies a signed chain from the invite base through that admin's promotion to the proposed predecessor; any pre-member fetch remains gated by S5 Q3. No contact with the offline issuer is required.
ADR 0089 EvidenceV1 admission is relationship-scoped and may refuse J's binding lookup to an admin with no relationship; contact hints do not bypass that guard.
The joiner signs the stable group ID, complete invite digest, invite ID, secret proof, joiner ID, **`redeemer_agent_id`**, requested role, key-package digest, certificate digest and attempt nonce.
Here **secret proof** means possession of the canonical bearer secret: the decoded 32 bytes travel only inside this encrypted request, and the receiver checks their BLAKE3 against the V5 signed commitment. The request signature covers those bytes; this is not a zero-knowledge proof. Raw secrets never enter persisted or disseminated redemption proofs.
Bind its KEM key to those same request bytes when that key is used. `request_digest` is BLAKE3 of the canonical signed request preimage under a distinct V5 request domain; it includes the redeemer and nonce. Define a logical `redemption_digest` over the invite digest, joiner, role, key package and certificate; attempt nonces and redeemer IDs are outside that digest so one verified chain can recognize the same admission across retries.
Carry the signed invite and required source evidence; fetch missing bytes through S5 from any eligible holder.
EvidenceV1 supplies authenticated agent/machine bindings; it does not prove group-admin authority.

Before mutation, the receiver verifies both invite signatures where required and the joiner's signature and secret proof.
Its agent ID must equal the signed `redeemer_agent_id`; another admin cannot execute a relayed request addressed to this one.
It proves the issuer was authorized at issuance from the verified invite base.
It verifies the issuer's current revocation and authority status as the existing admission path requires. An offline issuer is not a failed authority check.
The receiver independently proves its own active Admin-or-higher seat at the actual predecessor head.
If it was promoted after the invite base, a verified walk must include that promotion.
It checks current policy, bans, revocations, owner certificate, withdrawal/deletion and containment before constructing a candidate.
The redeeming admin and **every enforcing member** require `permit.policy_hash == predecessor policy hash`; a mismatch refuses with typed terminal **`invite_policy_changed`**, with no consumption, seat or key egress. A fresh permit is required. Every enforcing member independently checks the complete signed permit scope against that predecessor: addressed joiner, requested role within `max_role` and policy bounds, issuer authority at issuance and its required revocation/authority status, owner authorization where required, and expiry; the admin's assertion is insufficient.
For live acceptance, each receiver uses its **local wall clock plus the Q5-ruled skew bound** to validate expiry and the signed terminal validation time. Catch-up trusts the verified chain's validated time evidence and checks expiry at that committed validation time; it never re-judges historical expiry against "now". The terminal binds that validation time so it cannot be substituted during catch-up; no skew value is selected here.
It never infers current eligibility or confirmed membership from the invite's base-seated snapshot.

Catch up through S3/S5 and normal verified apply before seating; retain the TreeKEM across-gap adoption exclusion.
Bind a result to `(group, invite_id, request_digest, attempt_nonce, redeemer_agent_id, terminal_hash)`.
For a new seat, the authenticated result sender and terminal actor must match the selected redeemer. Verify its authority from the predecessor roster, not from the inviter field or the capability bit.
Changing redeemer starts a fresh nonce and invalidates the previous live attempt under the membership lock.
J signs a new request naming the new redeemer. First query verified committed state through that admin: if the consumption is on its chain, recover the original result without another add. If the earlier admin is unreachable and consumption cannot be proved, absence of a receipt does not prove an unspent invite. Report a visible retryable `redemption_unresolved`; any fresh spend on a disconnected branch requires Q1's explicit failover ruling. Local attempt invalidation cannot cancel an already committed remote add.
`redemption_unresolved` still waits on one device when only the earlier admin holds the receipt; David must rule that L1/L2 cost via Q1.
For recovery, the selected admin wraps only the original signed **commit/result** with the fresh attempt binding; verify the original actor independently through S5. The wrapper binds the new request digest/nonce/redeemer to the original request digest and terminal, and checks their identical logical redemption; the original request's redeemer binding is not rewritten. A fetched commit alone does not satisfy the live attempt, and a bare old response cannot confirm it. S5 never serves Welcomes as objects. Lost keys require S8(b)'s separately accepted current-epoch re-Welcome authority; S6 does not turn the original Welcome into an S5 object.
Bound discovery, retry and fetch work using the budget ruled in Q3. The shipped TreeKEM **join-result poll** is 120 s (`JOIN_RESULT_POLL_TIMEOUT`, `src/server/routes/named_groups.rs:33213`); its Welcome fetch sub-budget is 115 s (`WELCOME_FETCH_TIMEOUT`, line 33247). Non-TreeKEM/GSS join-result polling is 10 minutes (`NON_TREEKEM_JOIN_RESULT_POLL_TIMEOUT`, line 33219). These are different clocks, not one existing S6 timeout.
Budget exhaustion reports a typed retryable outcome and preserves verified progress; it never reports keyed-active.

### 3. Owner mandate: explicit L4 amendment

For V5 owner-axis redemption, replace the requirement for a fresh owner-signed terminal mandate with **two signatures**: the owner's portable invite permit and the redeemer's terminal intent.
This is a new acceptance rule, not an absent-mandate grace case.
The terminal intent uses `x0x.owner-mandate.delegated.v1` and a distinct versioned type.
Its canonical preimage retains all **13** shipped v2 bindings, including the actual authority ID and issuance time.
Add the invite digest, invite ID, request digest, attempt nonce, consumption roots before/after redemption and terminal validation time.
Retain the shipped `invite_secret_hash` slot's meaning: BLAKE3 of the canonical secret **string's UTF-8 bytes**, as produced at `src/server/routes/named_groups.rs:22730`. Add the V5 commitment (BLAKE3 of the **decoded 32 bytes**) as a separately named binding in the delegated type; the two hashes are not interchangeable. V4/v2 bytes stay frozen.
Encode fields in the shipped v2 order, then those additions, using fixed-width integers and length-prefixed variable bytes.
The redeemer signs the BLAKE3 digest with its agent key; the permit supplies the independent owner authorization.
Do not substitute the issuer ID for the redeemer or sign a wildcard terminal with the owner key.

Derive the parent, next revision, post-add roster, policy/meta hashes and intended epoch from the actual pre-mutation state.
Every enforcing receiver recomputes the candidate and requires candidate, intent and terminal roster roots to agree before installation.
It also checks both consumption roots, certificate digest, request binding and exact epoch against the terminal.
Every enforcing receiver also applies the full permit-scope acceptance rule in §2, including `permit.policy_hash == predecessor policy hash`, addressed joiner, role cap, issuer authority, required owner signature and expiry; a valid intent signature cannot waive any check.
The certificate must satisfy the predecessor's policy owner and revocation set; certificate and permit expiry follow §2's live-clock/skew and verified-chain catch-up rule.
Signature, sender authority, prev-hash linkage, fork evidence, revocation and epoch entitlement remain fail-closed.
The owner's signed invite lets a different current admin carry out that specific admission. The admin cannot change its recipient, allowed role or policy.
A copied permit alone cannot create an authorized terminal: it still needs the joiner's proof and a current admin signature.
This delegated intent is **not** an owner head attestation or an independent owner fork anchor.
It cannot clear quarantine, select a sibling or evict another member; S3's self-recovery limits remain.
Legacy v2 mandate verification and §1b's per-authority grace states remain unchanged on legacy admissions.
V5 does not enter §1b's absent-mandate grace machine: missing/invalid permit or delegated intent is a terminal refusal. Q6 explicitly asks David to authorize the additional §1/§1b amendment scope.

An admin demoted on the canonical branch can remain partitioned at a predecessor where it was active. With an outstanding permit and a request signed for it, it can mint an **unanchored sibling seat**. Canonical receivers reject it on their chain; authenticated siblings are fork evidence, not a valid promotion or an automatic winner. Keys delivered on that branch cover only its sibling epoch, never canonical post-demotion epochs. This old-key availability residual is part of Q1's L4 trade-off; an owner permit is no independent owner head anchor.

### 4. Consumption, concurrency and crash safety

Key consumption by `(stable_group_id, invite_id)` and retain `(invite_digest, joiner_id, redemption_digest, original_request_digest, terminal_revision, redeemer_id)`.
Commit a canonical sorted consumption-map root with the membership state in a new versioned S6 commit envelope; disseminated proofs use the signed invite view and secret commitment, excluding raw bearer secrets.
Bind the terminal state hash to the old state-hash inputs plus that root and the S6 protocol version under a new domain.
Every later S6 mutation carries the root forward; legacy mutations cannot erase it.
For an activated group, S4 evictions retain their `MemberRemoved` semantics and payload but are sealed/applied inside the S6 commit envelope and state-hash domain. The consumption root is unchanged by removal. S4's unchanged-encoding claim applies to unactivated legacy groups, not to the enclosing activated S6 commit. A legacy admin may not seal an activated group.
S3/0109 attestation, catch-up, quarantine retirement and re-seat verify the actual versioned S6 hashes and preserve the root; they may not recompute a legacy hash or clear consumption. S7 adoption preserves these sidecars. Neither slice changes the legacy JSON layout.
The acceptance order freezes S4/0110 and S3/0109 before S5 and S6. This ADR therefore **amends 0110 and 0109 only for S6-activated groups**, subject to Q6, to bind later `MemberRemoved`/eviction commits and their S3 verification to this envelope/state-hash boundary; leave their Accepted text untouched. Record cross-slice conformance receipts before S6 acceptance, including an S4 eviction followed by S3 catch-up and spent-invite replay as an integration control.
Hash-linked snapshots must include the consumption map; do not reconstruct it from a volatile event log.

Under the membership lock, verify the predecessor and unconsumed ID, build the roster/consumption candidate, seal and persist it with the TreeKEM snapshot before publishing.
Failure installs neither a consumed-only state nor a seat without its consumption proof.
The same logical redemption on the verified chain is idempotent across fresh attempt nonces and creates no second seat, rekey or Welcome. A different joiner or logical redemption, or replay after removal, is refused as consumed; a fresh invite is required.
A new admin must verify consumption state with the head before attempting redemption.
Retain tombstones while the signed invite remains usable. Q5 recommends finite V5 expiry and its maximum lifetime/storage budget; no unruled retention value is selected here. After the ruled expiry and clock-safety checks, prune only by a **committed prune mutation from an active Admin-or-higher at the predecessor** that binds the old/new consumption roots, signed invite expiry evidence and terminal validation time. Every enforcing member verifies that authority and each pruned invite's expiry: live receivers use their local clock plus the Q5-ruled skew bound; catch-up trusts the verified chain's validated time evidence and never re-judges expiry against "now". Verifiers reject an expired invite even after its tombstone is gone, using the same §2 time rule for admission. Removal or restart alone never prunes it. Until Q5 is ruled, no bounded-retention claim is made for no-expiry invites.
**Backpressure** means refusing new mint/redemption work with a visible typed retryable storage-pressure outcome *before mutation*, while preserving every existing seat and tombstone and allowing recovery, removals and safe committed pruning. It never means evicting a tombstone to admit another joiner. Limits and the exhaustion exit need Q5's ruling; indefinite resource pressure is not an extra I8 block.

Two admins with the same predecessor can still sign sibling terminals before they exchange commits. Receipt dissemination and local locking reduce that race but cannot eliminate it across disconnected nodes.
This includes honest **same-joiner** failover: B commits J, becomes unreachable, and C at the old parent commits J again. Even an addressed invite and the same logical redemption yield two sibling seats/epochs. Idempotence above applies only on one verified chain.
Authenticate conflicting evidence and apply the existing fork rules; never merge consumption maps while ignoring conflicting roster/TreeKEM state.
An ordinary unanchored fork may wait for manual admin action under I8 item 7.
An `OwnerCertified` double-spend fork stays quarantined until an owner-anchored canonical advance under 0064; the portable permit cannot clear it. Waiting for that owner is **not** an 0088 §2 exception. Q1 must resolve that L1/L2 gap before acceptance, or explicitly seek an amendment to 0088; this draft adds no ninth exception.
No claim of partition-wide exactly-once redemption or automatic winner selection is made pending **Q1**.

### 5. Persistence, compatibility and serving

**Never change the legacy formats.** `named_groups.json` and `home-suite-groups.json` retain their released JSON-map layouts. S6 neither wraps nor replaces either file with binary or JSON-v2. Preserve unaffected entries. Released v0.45/v0.46 readers use `read_to_string` plus `serde_json`; parse errors propagate at `src/server/mod.rs:735–737` and brick startup. ADR 0085 rule 5, D01 and ADR 0094 forbid that outcome.

Put activated state in an S6-owned **per-group sidecar**, `<data_dir>/group-s6/<stable_group_id>.s6group`, encoded as **`X0XNGS6V1\0 || bincode(S6GroupStateV1)`**. It contains the group identity, protocol version, authoritative roster/head, consumption map/root, signed redemption proofs and matching crypto snapshot reference/digest. The map is never a separately writable ledger. A changed positional layout gets a new magic; keep frozen decoders for every released S6 layout and consume the body exactly.
The corresponding transaction uses **`<stable_group_id>.s6journal`** with magic **`X0XNGS6J1\0`**, and a versioned frozen body. Both magic **and extension** are new: old `*.journal` scans move undecodable entries aside, so a new magic with `.journal` is unsafe. Do not put S6 bytes into `.journal` or `.hsjournal`. Activated crypto snapshots live with the S6 transaction, outside old snapshot names/scans; never serialize transient `PreparedMember` secrets.

**Exclude Home-policy groups from S6 activation until S7 (ADR 0113) defines their downgrade.** A default-policy placeholder with `home = None` fails released v0.46.1 `find_home`/`is_home_candidate`; without an owner-sync canonical pointer, provisioning step 4 can create a duplicate Home (#449/#824). Q2 records the alternative released-binary proof; this Decision grants no Home activation exception.
At activation of an eligible non-Home group, replace its entry in each legacy view where it exists with a placeholder: preserved identity/genesis/revision/hash, default invite-only policy, **non-empty `members_v2` with every entry Removed and no Active seat**, GSS plane, `home = None` and no secrets. Released v0.45.0/v0.46.1 run `GroupInfo::migrate_from_v1()` on every entry: an empty `members_v2` would seat the creator as Admin. The non-empty all-Removed roster makes migration a no-op and leaves no admin. Apply it to every alias of the stable ID, including any eligible non-Home entry in the Home-Suite view. An old daemon can reserve the ID and load the placeholder, but has no admin seat to mint an invite or seal a membership commit after reload; it does not restore S6 authority. Prove those limits on the released load path. #451's empty-roster placeholder is safe only when a Home-Suite-aware binary replaces it; S6 must not copy that roster shape. Leave existing #451 behaviour unchanged for unactivated groups.
Journal and durably install the S6 backing state and crypto snapshot before replacing the legacy view, retaining the split-store transaction and fsync barriers. Activation remains prepared until every applicable legacy placeholder is durable and the S6 activation commit marker is durable; publish no S6 mutation/key egress before that point. Startup replays the S6 journal before serving the group, rechecking the legacy predecessor/transaction identity; an interrupted activation followed by a legacy rewrite must not clobber the newer legacy head. On S6-aware load a committed sidecar is authoritative; an unknown/corrupt sidecar or inconsistent transaction refuses **that group**, preserves bytes and placeholders, and never falls back to legacy state or aborts daemon startup.
Activation is lazy, never a startup migration. Under an ADR 0094 supervised upgrade, defer the **first behaviour-changing sidecar/placeholder write until host commit**, not provisional per-instance health. Before host commit, use rollback-readable state and defer S6 mint/redemption/activation writes; startup, gossip and polling cannot activate it.

Each slice owns its new state in its own versioned sidecar with a new magic and extension: S4 eviction obligations, S6 redemption state and S8(b) repair state must not rewrite a shared legacy container. S3/S7 operate through the verified group transaction rather than assuming activated authority remains in JSON. Compose sidecars by stable ID and committed head/transaction identity; independently choosing the newest roster and an older consumption root is forbidden. Settle this transaction contract through S6's amendments to already Accepted 0110/0109 and conformance with 0113/0114 before S6 acceptance, without editing Accepted text or assigning S6 ownership of their sidecar layouts.
Real released v0.45.0/v0.46.1 binary tests must show the daemon starts, activated non-Home placeholders have **no admin seat after reload, no invite mint and no commit**, ordinary legacy groups still work, and S6 sidecars/journals/snapshots are **verified not to be overwritten or moved aside**. Home-policy groups stay unactivated under the exclusion above. Re-upgrade restores the full S6 roster and consumption state; no old placeholder can replace it. Release notes describe group unavailability on downgrade, never daemon unavailability.

| Direction | Required behaviour |
|---|---|
| Mint API default | `POST /groups/:id/invite` continues to mint V4 by default. V5 is an explicit version request on a Q2-activated group, under the ruled Q1/Q4/Q5 policy; refuse unsupported requests before minting. No silent default-version switch. |
| Old joiner → new admin | V4 uses unchanged inviter-bound admission; a non-inviter does not convert it. |
| Old joiner given a V5 link | The parseable link shell reaches the released `version != V4` gate, returning typed HTTP 409 **`invite_unsigned`** (`src/server/routes/named_groups.rs:17999–18000`) **before any stub or new pending row**. S6-aware joiners may explain the unsupported version separately; do not claim an old daemon returns a new error code. Prove the typed refusal with actual released binaries; otherwise block V5 link distribution pending a compatibility remedy. Never reinterpret it as V4. |
| New joiner → old admin | Use V4 only if the supplied invite is V4. V5 has a visible retryable `recipient_upgrade_required` outcome naming `group_invite_any_admin_v1`; send no V5 bytes. |
| New ↔ new | V5 envelopes require the bit at both ends and mandatory delegated/consumption checks. |
| Old existing member | Keep legacy groups working. S6 activation/migration with offline old members is gated on Q2; do not send new envelopes on a legacy topic or let old code write S6 state. |

Use distinct S6 message tags/topics for requests, commits and results; never disguise them as legacy `MemberJoined`/`MemberAdded` fields.
Recovery from a lost response uses verified S5 artifacts or S8(b)'s separately accepted re-Welcome rule, never a second consumption.
Upon S6 acceptance and Q6's scope approval, 0107's “inviter must be the device that sealed the original add” rule applies **explicitly to V4 only**. V5 requires the request-selected redeemer for a new add, or the independently verified original actor plus the selected admin's fresh wrapper for commit/result recovery. Its serving guard remains unchanged.
Serve every result, blob chunk, Welcome and secret resend only to a currently eligible recipient under ADR 0107 and D60.
Immediately before **each physical transport write**, re-check eligibility and artifact selection, including revocation, expiry, quarantine and current secret epoch, **and send under the membership lock**. Every delivery/chunk/resend is a separately admitted single exchange; no hidden transport resend and no gossip or gossip-capable fallback. Cancel and await unsent/in-flight transfers on removal, ban, revocation, expiry, quarantine or group retirement; an earlier copied buffer grants nothing.
The [join-artifact serving lifecycle note on PR #1190](https://github.com/saorsa-labs/x0x/blob/e645ce253bac6fc36b1dffd2398836da1f0096e8/docs/design/join-artifact-serving-lifecycle.md) is **related work only**, not on main and not a dependency.
S6 must prove its own guarded egress; neither the note nor an old cache entry grants admission.
The eight I8 indefinite-block reasons remain; issuer-offline is never a ninth. Expose typed terminal policy refusals and visible retryable waits; 0088 G7 still governs whether L3 binds every slice.

## Consequences

### Positive

- A valid V5 invite can admit through a current admin with no issuer or owner-device round trip on a verified non-conflicting chain.
- Downgrade keeps the daemon and legacy groups running while preserving activated group state for re-upgrade.

### Negative / Trade-offs

- New wire envelopes and per-group sidecars need an explicit rollout and a shared transaction contract. Tombstones cost storage; finite expiry and committed prune are recommended in Q5.
- Same-joiner failover can fork even an addressed invite; bearer invites can also seat different joiners on siblings. Ordinary forks need manual action; OwnerCertified forks require an owner-anchored advance and expose an unresolved L1/L2 gap, not an allowed §2 block (Q1).
- If Q4 selects Member-only V5, **Admin-role invites remain inviter-pinned**, an L1 gap. **Pre-upgrade V4 invites also remain inviter-pinned** until re-minted; the default V4 mint path retains this gap. S6 must not claim all D16 admissions are covered.
- Pre-member evidence recovery depends on S5 Q3; lost-key recovery depends on separately accepted S8(b). Unknown capabilities, missing committed receipts and storage pressure produce visible waits/refusals, not keyed-active membership.

### Neutral / Operational

- V4 signatures, mandates and original-inviter cache repair remain unchanged. Q4 decides V5 role scope; Q6 decides the broader amendments.
- Home-policy groups remain excluded from S6 activation until S7 defines their downgrade. S6 preserves owner-certificate checks and revocation eviction semantics. It supplies no new re-Welcome authority or owner fork anchor.

## Validation

These are **required, not yet implemented or run**. W3-H (#1164) does not exist yet. Recommend filing an S6 tracking issue listing the cases, prerequisites and receipts before implementation; this draft does not claim an issue was filed.
Drive actual daemons through public `POST /groups/:id/invite`, `POST /groups/join`, `GET /groups/:id/join-status`, and the public group role/removal/policy APIs. Do not inject a decoded invite or call an internal redemption helper in place of mint/join. The S6 API extension must expose explicit invite version and selected redeemer; normal automatic selection is tested too.
For red-on-main receipts, mint the current default V4 through the public API and use harness delivery to make B the only reachable admin; the fixed counterpart mints V5 explicitly with the same semantic grant. Failure solely because main lacks a V5 parameter is **not** a liveness red receipt.
Record fixture identities, pinned main/fix SHAs, clock/delivery traces and assertions in the implementation PR. Each red case must be committed and shown red on **main before slice code merges**, then green on the fixed tree. In-process red tests alone do not count (D16/D54). Run in CI's fresh loopback-only Linux namespace with dropped privileges.

All cells use a deterministic fake wall/monotonic clock starting at `t=0`, fixed identity/secret fixtures and scripted delivery barriers. Fixture invite expiry is after the last scheduled step. The proposed TreeKEM test exit bound is `T=120 s` (Q3 recommendation, not a ruled protocol value); replace T with David's ruled bound before implementation. Advancing the clock never unblocks a stopped daemon or a withheld message. Repeat each specified ordinary/OwnerCertified variant. For OwnerCertified fixtures A holds the owner's USER key at mint; stop A and every other owner-key device O before redemption. B/C never hold that key.
In the conflict cells, main's control assertion is that legacy non-inviter B/C create **no seat or key egress**; their fixed V5 counterpart runs the stated commit/failover schedule. Existing V4 replay/serving controls run at the original issuer. These controls do not pretend main already has S6 consumption roots or new error bindings.

| Case / baseline | Nodes, public steps and deterministic delivery | Assertion |
|---|---|---|
| `s6_offline_inviter_other_admin_admits` — **red on main** | A/B admins, J fresh, optional O. t=0 create a common head and mint J's addressed invite at A via the invite API. t=1 stop A/O; deliver current signed adverts for B and all needed authorized evidence. t=2 J calls join; route all redemption traffic only to B, which has no issuer-local record. Deliver B↔J traffic in FIFO order, then advance to T. | On main J fails to reach usable membership. Fixed V5 reaches confirmed membership at B and J, with J decrypting B's next group message by T, no traffic to A/O and one consumption. A roster seat alone is not a pass. Repeat TreeKEM and GSS with their separately ruled budgets. |
| `s6_promoted_admin_stale_invite` — **red on main** | A admin, B initially Member, J fresh, optional O. t=0 A mints at r; t=1 public role API promotes B at r+1. t=2 stop A/O and restart B from disk. t=3 J calls join from r, discovers B via a peer contact hint absent from its base-admin set, then receives the verified promotion/chain through S3/S5 under the ruled S5 Q3 guard. Deliver links in revision order; advance to T. | Main's inviter/result pin prevents usable admission. Fixed V5 verifies B at the actual predecessor and gives J current keys without quarantine for a legitimate gap or across-gap TreeKEM snapshot adoption. Discovery hints alone never prove authority. |
| `s6_replay_restart_and_admin_handoff` — **control on main** for existing V4 replay/removal; S6 root/recovery assertions are new | A/B/C admins, J. t=0 mint and public-join once at the authority (A for V4 control, B for V5). t=1 deliver the terminal to C and restart it. t=2 repeat J's public join at that authority and at caught-up C with fresh attempts; t=3 public-remove J, deliver removal, and replay again. In a separate run drop B's first result after durable commit, restart B, then J publicly retries through C at t=2; deliver original commit/result and S8(b) key recovery as separate guarded exchanges. | One consumption on one chain; no extra add/rekey/Welcome on identical replay, and no re-admission after removal. Lost-result recovery confirms only after current usable keys and a fresh attempt binding; lost-key recovery requires S8(b), never an S5 Welcome object. |
| `s6_two_admin_double_redemption` — **control on main** (legacy pinning); required new Q1 conflict case | A/B/C admins, J/K fresh, optional O. t=0 mint one bearer invite through A. Stop A/O at t=1. Ordered run: at t=2 J joins via B, deliver B's commit to C, then t=3 K joins via C. Concurrent run: partition B/C at their common parent; t=2 J/K call public join via B/C, deliver both signed requests before either sibling commit, then heal at t=3. | Ordered run has one spend; K gets no keys. Concurrent run obeys Q1: either ruled prevention, or authenticated sibling evidence/quarantine and the ruled recovery. OwnerCertified variant cannot clear via a delegated intent or claim its owner wait is §2 item 7. No per-admin mutex is a global proof. |
| `s6_same_joiner_failover` — **control on main** (V4 cannot redeem at B/C); required new Q1 conflict case | A/B/C admins, J, optional O. t=0 mint addressed J invite. Stop A/O at t=1. t=2 J joins via B; durably commit, drop B→J/C result/commit, then stop B. t=3 J publicly retries through C, which still has the old parent, with a new nonce and signed C ID. Keep B's evidence withheld until t=4, then heal. Run both refusal and Q1-authorized fresh-spend variants. | Default unresolved-state exit is visible, with no inferred global unspent result. If Q1 permits fresh spend, same-joiner siblings are detected even for an addressed invite; never call the two epochs idempotent. Verify OwnerCertified owner-anchor exit separately. |
| `s6_guarded_delivery_and_policy_drift` — **control on main** for existing 0107 guard; new S6 bindings | A/B/C admins, J, optional O. Public-mint at t=0. Change policy through its public API at t=1, then public-join at t=2. In separate runs mutate current eligibility/epoch through public removal/ban/revocation APIs at a barrier just before a queued result/chunk/Welcome/resend write. Replay J's request signed for B at C. Partition B before its public demotion, then attempt its outstanding permit on the old head and heal. | Policy drift returns terminal `invite_policy_changed` with no mutation/key egress. C cannot execute B's signed request. Each write rechecks and sends under the membership lock, with no hidden resend/fallback. A partitioned demoted B's sibling is fork evidence; its keys cannot decrypt canonical post-demotion epochs. |

Exit gate: both liveness red cases have genuine red receipts on main and pass with the issuer continuously offline. Q1 conflict cells require David's ruling before S6 acceptance; their new-version assertions have no claimed red-on-main receipt.
Non-regressions cover V4 same-inviter joins, ADR 0106 carries, ADR 0107 re-arm, current serving eligibility and S3/S5 catch-up.
Reject wrong-owner/expired/revoked certificates, removed/banned joiners, revoked/non-admin redeemers, foreign groups, altered roles/secrets/packages and transplanted mandates or attempts without state change or key egress.
Exercise all eight I8 blocks, including signed deletion, removed-member epochs, never-admitted epochs, no reachable admin/holder and manual unanchored-fork recovery.
Persistence control: public-mint/join on A/B/J at t=0–2; inject crashes before/after each `.s6journal` write, snapshot/sidecar/placeholder replace, directory fsync and egress. Restart at t=3 and replay publicly at t=4: never lose consumption or confirm without usable keys. During an ADR 0094 trial, deliver the activation request before host commit and assert no behaviour-changing persist; release the same request after durable host commit and assert one atomic activation.
Downgrade control: A is the group's creator/admin, B an admin and J a joiner; t=0–2 use fixtures from actual released encoders and activate the non-Home group through public mint/join APIs. Hash legacy files and S6 sidecars/journals/snapshots; t=3 boot the **released v0.45.0 and v0.46.1 binaries** on candidate copies of the same data dir with A's creator identity loaded and loopback-only scripted delivery. t=4 inspect the released reload's roster and call the public invite and membership-mutation APIs; t=5 reload again, exercise an unrelated legacy group, and re-upgrade at t=6. Assert successful startup, non-empty all-Removed `members_v2`, **no admin seat after either reload, no invite mint and no commit**, byte-identical S6 files including pending journals, and restored authoritative consumption after re-upgrade. This is a required new S6 control, not a red-on-main claim. Separately attempt Home-policy activation and assert refusal before any sidecar/placeholder write; the alternative no-duplicate-Home/no-`home.json`-change proof remains Q2. Fault/corruption cells refuse one group while the daemon stays up.
Cross-slice control: A/B/C/J, mint/join via B at t=0–2, public-revoke J at t=3, let S4 seal the eviction, withhold it from C until t=4, then drive S3/S5 catch-up. Assert the S6-domain head matches, consumption survives the eviction/recovery, a public replay refuses, and S7 adoption/S8(b) repair never substitute a legacy root or shared-file rewrite. Prune control advances beyond the Q5-ruled expiry, publicly triggers the normal maintenance path, delivers the prune commit and replays: expired admission stays refused after restart/prune.
Mixed-version controls drive every table row through public mint/join, using real v0.45/v0.46 peers, absent/stale/forged adverts, an old joiner parsing a V5 link with no stub, and an old existing member across Q2's activation. No V5 bytes reach a legacy handler as V4. If a released parser lacks the required typed refusal, record the failure and block distribution; do not assume future code repairs an old binary.

Accept in 0088's order: the contract, then S2 and **S8(a)/0107**, then S4/S3, then S5, then S6, then S7. “S8” in that order means S8(a); **S8(b)/0114 is Accepted after S4**, as 0107 requires. S6's lost-key recovery additionally depends on that separate acceptance and its implementation.
S6 must land **Proposed on main**, then be **Accepted by David before its code merges**; one `named_groups.rs` code lane at a time (0088 §4, ADR 0087 rule 8). No S8(a) harness exception applies to S6.
Acceptance also requires Q1–Q6 rulings, S5 Q3 for pre-member evidence-dependent paths, and the S3/S4/S7/S8(b) sidecar/transaction/hash boundary reconciled through this ADR's S3/S4 amendments and cross-slice conformance controls, leaving Accepted text untouched. Home-policy activation remains excluded until S7 defines its downgrade. S6 code merges only after the required red-on-main receipts; key recovery cannot be declared complete until the S8(b) path and guarded exchanges pass.

## Open Questions for David

1. **Q1 — single use and honest failover:** decide both distinct-joiner bearer spends and **same-joiner sibling seats** when B commits, becomes unreachable, and J retries at C. Options: (a) **V5 any-admin only for addressed invites**, reducing distinct-agent double spend but still requiring a same-joiner failover/fork rule; (b) allow disconnected spends with authenticated fork evidence and explicitly ruled recovery; (c) require coordinated proof before a fresh failover spend, with a stated liveness cost reconciled with D16. The recommendation is to start with (a) and refuse unresolved fresh spends; `redemption_unresolved` can still wait on the earlier admin's one device, an L1/L2 cost David must rule, not silently treat as an allowed wait. In OwnerCertified groups even J→B/J→C siblings wait for an independent owner-anchored advance under 0064. Does David authorize a mechanism preventing those forks, or amend 0088 for that wait? It is not §2 item 7; neither the permit nor S3's ATA is the owner anchor. **Acceptance is blocked** until failover and both group types' outcomes are ruled; no automatic fork winner is proposed.
2. **Q2 — group activation and migration:** require all existing members to upgrade before activation, or retain offline legacy participation by another explicit compatibility rule? The capability gate cannot make an old admin enforce consumption. The recommendation is an explicit all-member upgrade/activation barrier; no version floor, member exclusion or default-mint switch is ruled here. **Q2 blocks S6 acceptance**, not just rollout: the mixed-version security contract depends on it. Activated non-Home groups become unavailable but intact on downgrade; daemon startup remains available. The Decision excludes Home-policy groups until S7 defines their downgrade; should David instead authorize activation only with a released v0.45.0/v0.46.1 binary test, without an owner-sync canonical pointer, proving **no duplicate Home and no `home.json` change** through reload/provisioning, and blocking Home activation if that test fails?
3. **Q3 — attempt/discovery/retry budgets:** recommend the shipped 120 s TreeKEM join-result window, including a 115 s Welcome-fetch sub-budget, and the shipped 10-minute GSS join-result window. What discovery/fetch limits and visible retry schedule should S6 use, especially after an unresolved first commit? These values remain recommendations, not Decisions. **G7 inherited from 0088** also remains open: does L3 bind S6 and every slice, including a short poll versus later authority refusal? S6 cannot close G7 by choosing a timeout.
4. **Q4 — V5 role cap:** D16 clause 2 sets no Member-only restriction. Recommend Member-only for the first V5 mechanism, leaving Admin-role grants on V4 until a reviewed extension; alternatively allow signed Admin-role permits now with the same current-policy/authority checks. Which serves D16? If the cap is chosen, explicitly accept or schedule closure of the residual Admin-invite L1 gap. Pre-upgrade V4 invites remain pinned under either choice and need re-minting; no signature can widen them retroactively.
5. **Q5 — expiry, tombstones and backpressure:** recommend **mandatory finite V5 expiry**, a ruled maximum lifetime and per-group storage budget, with committed prune only after expiry and clock-safety checks. What lifetime, clock-skew allowance, capacity and exhaustion exit should apply? Finite expiry bounds a tombstone's lifetime; bounded bytes also require the ruled rate/capacity and visible backpressure. If no-expiry V5 is allowed, specify durable retention without a false bounded-storage claim. No numeric retention/rate/limit is selected by this draft.
6. **Q6 — amendment scope:** 0088's S6 row names 0059 InviteV4 pinning and 0064 §1a only. This mechanism also changes **0064 §1** (the owner does not sign the terminal at pre-mutation), **0064 §1b** (V5 bypasses the absent-mandate machine and requires its permit/intent), and **0107's Decision original-inviter rule** (explicitly V4-only; V5 uses selected redeemer or verified original actor plus fresh wrapper). It also amends **0110 (S4) and 0109 (S3), only for S6-activated groups**, so the activated-group state-hash boundary binds later `MemberRemoved`/eviction commits and their verification: S4/S3 → S5 → S6 acceptance freezes those ADRs before S6. These enable any-admin redemption without removing V4 authentication checks, and are argued to be consequential parts of that row, but the wider scope is **a David question**, not an inferred authorization. Approve these amendments or narrow the mechanism before acceptance; leave all Accepted source ADRs untouched.

## Source Reconciliation

- ADR 0064 §1a lists fewer mandate bindings than shipped. Its README errata and #472's corrected preimage comments add `version`, `authority_agent_id` and `issued_at_ms`; use the 13-field code shape cited above.
- The public digest still calls 0088 pending and ends at D55. The Accepted contract and D58/D63 govern status and slice binding; leave those read-only sources untouched.
- ADR 0093's immutable allocation table predates ADR 0089's move of allocation to the README; use that canonical registry. This proposal selects no capability number and does not alter 0093's existing sender gates.
- The sibling 0110/0114 drafts' shared-store rewrite proposals conflict with the binding cross-slice sidecar rule. S6 requires conforming sidecars, not those layouts; 0109/0113 must consume the composed activated state. The acceptance order freezes 0110/0109 before S6, so S6 records their activated-group envelope/hash amendment here under Q6 instead of requiring later edits to their Accepted text. No sibling draft or Accepted ADR is edited by this change.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs stay immutable; later decision changes require an amending or superseding ADR.

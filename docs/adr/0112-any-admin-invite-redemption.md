# ADR 0112: Any-Admin Invite Redemption (0088 S6)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S6 of [ADR 0088](./0088-group-liveness-contract.md).
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0059](./0059-invite-authentication-and-seating-provenance.md) inviter pinning for V5; [ADR 0064](./0064-owner-anchored-fork-authority.md) Decision §1 (owner pre-mutation signature), §1a (mandate preimage) and §1b (absent-mandate machine) for V5; [ADR 0107](./0107-stuck-join-rearm-and-serving-guard.md) Decision's original-inviter binding, limited explicitly to V4; ADR 0110 (S4) and ADR 0109 (S3), limited to S6-activated groups: the activated-group state-hash boundary binds later `MemberRemoved`/eviction commits and their verification; [ADR 0088](./0088-group-liveness-contract.md) §2 with one named entry, `redemption_unresolved` (D99, §2 below). These take effect **upon acceptance**. The 0088 §3 row names only 0059 InviteV4 and 0064 §1a; David approved the wider scope (D105). V4 retains every existing authentication rule; activated V4 mutations use the S6 envelope.
- **Goal served:** **R3** (all my machines connected) for ordinary groups and, behind the released-binary control (D81), for Home; and the shared-places core.
- **Related:** D01, D16 clause 2, D34, D37, D54–D55, D58, D60, D63, D64, D65, D81, D95, D98, D99–D105; ADR 0085, 0087 rule 8, 0089, 0093, 0094, 0106, 0107; slices S3/0109, S4/0110, S5/0111, S7/0113 and S8(b)/0114; [#451](https://github.com/saorsa-labs/x0x/issues/451), [#469](https://github.com/saorsa-labs/x0x/issues/469), [#472](https://github.com/saorsa-labs/x0x/issues/472), [#818](https://github.com/saorsa-labs/x0x/issues/818), [#1139](https://github.com/saorsa-labs/x0x/issues/1139), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1164](https://github.com/saorsa-labs/x0x/issues/1164).

Use a portable signed invite and a committed redemption record so any active admin can admit its holder while the issuer is offline.
Separate the invite issuer from the redeeming admin. Retain signature, current authority, owner-certificate, chain and fork checks.
David ruled Q1–Q6 on 2026-10-04 (D99–D105). D100's fork-prevention design and the D102/D104 values still block Accept (see Rulings and open questions).

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
5. **Portable authorization plus committed redemption evidence** (chosen as the mechanism). D99 sets its partition semantics. D100 requires OwnerCertified fork prevention before Accept. No automatic fork winner is chosen here.

## Decision

### 1. Capability and portable authorization

Name the registry-v1 capability **`group_invite_any_admin_v1`**.
It means support for the complete invite, redemption, commit, result and persistence contract below. The canonical registry is in the [README](./README.md).
Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry.
This draft adds no registry row or numeric allocation; the accepting PR adds the row and fixes the number everywhere together.

Use a distinct **InviteV5** canonical view, domain `x0x.invite.v5\0`, and signature domains `x0x.invite.v5.inviter\0` and `x0x.invite.v5.owner\0`. Freeze V4 signed bytes and decoders; do not append inside a positional V4 view.
Keep the link's released parseable shell, `x0x://invite/<base64 JSON>`, with its required parsing fields and `version = 5`; V5 authorization uses only the distinct V5 canonical view. This lets a released V4 parser reach its typed version refusal rather than fail on an unknown URL prefix. The link carries the bearer secret, but the signed view contains only its commitment, as V4's view does.
V5 signs every V4 semantic field plus a random 256-bit `invite_id`, the base policy's canonical `policy_hash`, `max_role = Member` (D103), a mandatory addressed joiner (D99), a mandatory finite `expires_at` (D104) and `redeemer_scope = active_admin`.
The issuer's agent signature and the owner USER countersignature for an owner-axis policy cover the entire view.
The secret commitment is BLAKE3 over the decoded 32 secret bytes; reject ambiguous encodings.
The owner countersignature is the portable permit to execute this invite's single admission.
It authorizes only its addressed agent, and no role above Member or the current policy's permitted role.
The mint refuses before minting, with a typed terminal refusal: a V5 request with no addressee (`invite_v5_requires_addressee`), with a role above Member (`invite_v5_role_unsupported`), or with no expiry or an expiry above the ruled maximum (`invite_v5_lifetime_invalid`).
Bearer invites and Admin-role invites stay V4 and issuer-pinned (D99, D103). Decoders reject a V5 view with no addressee or no expiry.
Existing creation, expiry, owner pin, policy, base-consistency and size checks remain.
Use S5's single carry/fetch rule for over-budget evidence; add no separate certificate carrier.
**Pre-member roster fetch (D95).** When the base roster exceeds the shipped 20-entry invite cap (#646), the V5 view signs the base `roster_root` and omits the projection. A pending joiner that presents the signed invite binding that root may fetch that one `roster_projection` from any eligible holder under S5's serving guard and limits. It discloses only the root-covered fields the invite already binds. No other pre-member fetch is allowed; S6 adds no further disclosure.

A V4 invite stays issuer-pinned; its signatures cannot authorize V5 scope retroactively. Re-mint it while an authorized issuer is available to gain any-admin redemption.
On an activated group, an S6-aware issuer retains V4 authentication and ledger checks but seals any resulting mutation in the S6 envelope, carrying the existing consumption root. An old binary sees only the legacy placeholder whose non-empty `members_v2` entries are all Removed, preventing creator-to-Admin migration; released-binary reload tests must prove it inert (§5).
V5 support is positive evidence from a current verified, machine-bound ADR 0093 advert, never a version string or AgentCard.
Unknown capability triggers a bounded refresh under D35; it does not authorize a V5 send. While it runs, J's state is the typed wait `awaiting_capability {peer, bit}`; it ends in a send or in `recipient_upgrade_required` (§6).
This positive-advert gate is deliberately stricter than ADR 0093's shipped grant/offer gates, which send on unknown, expired or card-only state. Those 0093 gates remain unchanged; only S6 envelopes require positive support.
Never fall back to a V4 request with V5 bytes or silently change the invite's scope.

### 2. Request, authority and result binding

Send a distinct versioned redemption envelope to a reachable active admin over authenticated, encrypted point-to-point transport; never publish the bearer secret on gossip.
J first tries verified admins from its invite base. For an admin absent from that base, J uses candidate contact hints from existing peer relationships, ordinary group discovery or other reachable holders, then resolves the agent/machine binding with EvidenceV1. These hints confer no authority. Before membership J may fetch only the roster at its invite's root (D95, §1).
For a redeemer in J's invite base, the result carries the intervening events, as ADR 0106 already does.
For a redeemer absent from that base, J needs the signed chain from its invite root through that redeemer's promotion before membership. Later commits disclose joins made after the invite, so this is new disclosure. It is **not ruled**: ADR 0111 Q9 owns it, and open question 4 records it as a gate on Accept.
Until David rules it, J sends a request only to an admin in its invite base. With none reachable, J reports `no_reachable_admin`. Contact hints for admins outside the base stay unused.
Sending to a base admin is safe: the request names that redeemer and the invite names J, so no other admin can execute it. No contact with the offline issuer is required.
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
For live acceptance, each receiver uses its **local wall clock plus the skew bound** (D104; value proposed in open question 3) to validate expiry and the signed terminal validation time. Catch-up trusts the verified chain's validated time evidence and checks expiry at that committed validation time; it never re-judges historical expiry against "now". The terminal binds that validation time so it cannot be substituted during catch-up.
It never infers current eligibility or confirmed membership from the invite's base-seated snapshot.

Catch up through S3/S5 and normal verified apply before seating; retain the TreeKEM across-gap adoption exclusion.
Bind a result to `(group, invite_id, request_digest, attempt_nonce, redeemer_agent_id, terminal_hash)`.
For a new seat, the authenticated result sender and terminal actor must match the selected redeemer. Verify its authority from the predecessor roster, not from the inviter field or the capability bit.
Changing redeemer starts a fresh nonce and invalidates the previous live attempt under the membership lock.
J signs a new request naming the new redeemer. First query verified committed state through that admin: if the consumption is on its chain, recover the original result without another add.

**Failover rule (D99).** A fresh spend never runs while an earlier attempt may have committed.
- J durably records each attempt `(invite_id, redeemer, attempt_nonce, request_digest)` before it sends it. Every later request for that invite carries J's signed list of earlier attempts.
- A redeemer that cannot prove an earlier attempt's outcome on its own verified chain refuses a fresh spend. It returns the typed wait `redemption_unresolved {invite_id, earlier_redeemer, attempt, next_probe_at}`. Absence of a receipt never proves an unspent invite.
- An earlier attempt resolves only in one of two ways. Its commit reaches any holder, and J recovers the original result (below). Or its redeemer returns that commit, or a signed `redemption_not_committed` release. The redeemer signs a release only after it durably records that attempt as refused, so it can never commit it later.
- Every signed pre-mutation refusal from a redeemer is such a release. A release and a commit for one attempt from the same redeemer are signed equivocation evidence under the existing fork rules.
- Local attempt invalidation cannot cancel an already committed remote add.
- **L4:** the rule adds refusals and one signed statement; it relaxes no check. **Mixed versions:** it runs only inside S6 envelopes between nodes with the bit.

**Named amendment to 0088 §2 (D99).** This ADR amends ADR 0088 §2 with one named entry, ruled by David (D99):
**`redemption_unresolved`: an unresolved V5 redemption attempt.** It carries no ordinal, because other slices add their own named entries (for example D76 in ADR 0110 and D96 in ADR 0111). A fresh spend of a V5 invite waits while an earlier attempt at another admin may have committed, and neither that commit nor that admin's signed release is reachable.
- Typed state: the waiting entry `redemption_unresolved`, visible on J's join status. It names the earlier redeemer it waits for.
- Exits: the earlier commit reaches any holder (J recovers the original admission); the earlier redeemer returns its commit or a signed release (a fresh spend may then run at any admin); or the invite's mandatory expiry (D104) ends the attempt with the terminal refusal `invite_expired`.
- Cost: while it waits, this joiner's admission depends on one device, the earlier redeemer. L1 names the original sealer as a device no operation may depend on; David accepted this L1/L2 cost explicitly (D99). The entry covers only this V5 case. It does not cover V4's issuer-pinned waits, which stay tracked defects against L1.

For recovery, the selected admin wraps only the original signed **commit/result** with the fresh attempt binding; verify the original actor independently through S5. The wrapper binds the new request digest/nonce/redeemer to the original request digest and terminal, and checks their identical logical redemption; the original request's redeemer binding is not rewritten. A fetched commit alone does not satisfy the live attempt, and a bare old response cannot confirm it. S5 never serves Welcomes as objects. Lost keys require S8(b)'s separately accepted current-epoch re-Welcome authority; S6 does not turn the original Welcome into an S5 object.

**Attempt windows (D102).** An S6 attempt uses the shipped windows. The TreeKEM **join-result poll** is 120 s (`JOIN_RESULT_POLL_TIMEOUT`, `src/server/routes/named_groups.rs:33213`), with the 115 s Welcome fetch inside it (`WELCOME_FETCH_TIMEOUT`, line 33247). The GSS (non-TreeKEM) join-result poll is 10 minutes (`NON_TREEKEM_JOIN_RESULT_POLL_TIMEOUT`, line 33219). These are two clocks, not one S6 timeout. Discovery, fetch and retry limits are proposed in open question 2 for David's ruling.
A window that ends without a terminal answer never ends silently (D64). J moves to `redemption_unresolved`, naming the redeemer it waited for, and keeps its verified progress. The redeemer sends any refusal or wait status, such as S5's `evidence_pending`, directly within J's window; it never stages a refusal for later pickup. Budget exhaustion never reports keyed-active.

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
V5 does not enter §1b's absent-mandate grace machine: a missing or invalid permit or delegated intent is the terminal refusal `owner_permit_invalid`. David approved this §1/§1b amendment scope (D105).

An admin demoted on the canonical branch can remain partitioned at a predecessor where it was active. With an outstanding permit and a request signed for it, it can mint an **unanchored sibling seat**. Canonical receivers reject it on their chain; authenticated siblings are fork evidence, not a valid promotion or an automatic winner. Keys delivered on that branch cover only its sibling epoch, never canonical post-demotion epochs. An owner permit is no independent owner head anchor. In an OwnerCertified group this sibling is one of the fork sources D100 requires S6 to prevent (§4, open question 1); D100's own cost note says it may still fork.

### 4. Consumption, concurrency and crash safety

Key consumption by `(stable_group_id, invite_id)` and retain `(invite_digest, joiner_id, redemption_digest, original_request_digest, terminal_revision, redeemer_id)`.
Commit a canonical sorted consumption-map root with the membership state in a new versioned S6 commit envelope; disseminated proofs use the signed invite view and secret commitment, excluding raw bearer secrets.
Bind the terminal state hash to the old state-hash inputs plus that root and the S6 protocol version under a new domain.
Every later S6 mutation carries the root forward; legacy mutations cannot erase it.
For an activated group, S4 evictions retain their `MemberRemoved` semantics and payload but are sealed/applied inside the S6 commit envelope and state-hash domain. The consumption root is unchanged by removal. S4's unchanged-encoding claim applies to unactivated legacy groups, not to the enclosing activated S6 commit. A legacy admin may not seal an activated group.
S3/0109 attestation, catch-up, quarantine retirement and re-seat verify the actual versioned S6 hashes and preserve the root; they may not recompute a legacy hash or clear consumption. S7 adoption preserves these sidecars. Neither slice changes the legacy JSON layout.
The acceptance order freezes S4/0110 and S3/0109 before S5 and S6. This ADR therefore **amends 0110 and 0109 only for S6-activated groups** (approved, D105), to bind later `MemberRemoved`/eviction commits and their S3 verification to this envelope/state-hash boundary; leave their Accepted text untouched. Record cross-slice conformance receipts before S6 acceptance, including an S4 eviction followed by S3 catch-up and spent-invite replay as an integration control.
Hash-linked snapshots must include the consumption map; do not reconstruct it from a volatile event log.

Under the membership lock, verify the predecessor and unconsumed ID, build the roster/consumption candidate, seal and persist it with the TreeKEM snapshot before publishing.
Failure installs neither a consumed-only state nor a seat without its consumption proof.
The same logical redemption on the verified chain is idempotent across fresh attempt nonces and creates no second seat, rekey or Welcome. A different joiner or logical redemption, or replay after removal, is refused as consumed; a fresh invite is required.
A new admin must verify consumption state with the head before attempting redemption.
**Mandatory expiry and committed prune (D104).** Every V5 invite expires. Retain its tombstone until the invite has expired and the clock checks pass. Then prune only by a **committed prune mutation from an active Admin-or-higher at the predecessor** that binds the old/new consumption roots, signed invite expiry evidence and terminal validation time. Every enforcing member verifies that authority and each pruned invite's expiry: live receivers use their local clock plus the skew bound; catch-up trusts the verified chain's validated time evidence and never re-judges expiry against "now". Verifiers reject an expired invite even after its tombstone is gone, using the same §2 time rule for admission. Removal or restart alone never prunes it. **L4:** prune is an admin mutation that every enforcing member re-verifies; it never re-opens a spent invite. The lifetime, skew, prune margin and storage values are proposed in open question 3 for David's ruling.
**Backpressure** means refusing new mint/redemption work *before mutation* with the typed retryable wait `invite_capacity_exhausted {scope, earliest_prune_at}`, while preserving every existing seat and tombstone and allowing recovery, removals and safe committed pruning. It never means evicting a tombstone to admit another joiner. The wait names `earliest_prune_at`, the first time a prune becomes allowed. Expiry only allows a prune; it does not make one happen. So this ADR makes no bounded-wait claim; the exhaustion exit policy is proposed in open question 3.

Two admins with the same predecessor can still sign sibling terminals before they exchange commits. Receipt dissemination and local locking reduce that race but cannot eliminate it across disconnected nodes.
D99 removes the two main sources for one invite. V5 is addressed, so no second joiner can spend it. An honest joiner's failover is refused while unresolved (§2), so no second admin spends it freshly. Idempotence above applies only on one verified chain.
Authenticate conflicting evidence and apply the existing fork rules; never merge consumption maps while ignoring conflicting roster/TreeKEM state.
An ordinary unanchored fork waits for manual admin action under 0088 §2 item 7.
In an `OwnerCertified` group three fork sources remain: a joiner that hides an earlier attempt and asks two admins at once; a fresh invite for the same joiner, redeemed while the first admin's commit is withheld; and the partitioned demoted admin of §3. Each sibling would stay quarantined until an owner-anchored canonical advance under 0064, which is not on 0088 §2, and the portable permit cannot clear it. **D100 requires S6 to prevent these forks before Accept.** This draft has no prevention mechanism yet, so this **blocks Accept** (open question 1). No claim of partition-wide exactly-once redemption or automatic winner selection is made.

### 5. Persistence, compatibility and serving

**Never change the legacy formats.** `named_groups.json` and `home-suite-groups.json` retain their released JSON-map layouts. S6 neither wraps nor replaces either file with binary or JSON-v2. Preserve unaffected entries. Released v0.45/v0.46 readers use `read_to_string` plus `serde_json`; parse errors propagate at `src/server/mod.rs:735–737` and brick startup. ADR 0085 rule 5, D01 and ADR 0094 forbid that outcome.

Put activated state in an S6-owned **per-group sidecar**, `<data_dir>/group-s6/<stable_group_id>.s6group`, encoded as **`X0XNGS6V1\0 || bincode(S6GroupStateV1)`**. It contains the group identity, protocol version, authoritative roster/head, consumption map/root, signed redemption proofs and matching crypto snapshot reference/digest. The map is never a separately writable ledger. A changed positional layout gets a new magic; keep frozen decoders for every released S6 layout and consume the body exactly.
The corresponding transaction uses **`<stable_group_id>.s6journal`** with magic **`X0XNGS6J1\0`**, and a versioned frozen body. Both magic **and extension** are new: old `*.journal` scans move undecodable entries aside, so a new magic with `.journal` is unsafe. Do not put S6 bytes into `.journal` or `.hsjournal`. Activated crypto snapshots live with the S6 transaction, outside old snapshot names/scans; never serialize transient `PreparedMember` secrets.

**Activation barrier (D101).** A group activates S6 only when every Active member runs S6.
- The activating admin requires, for every Active seat on the predecessor roster, a current verified, machine-bound ADR 0093 advert that sets `group_invite_any_admin_v1`. Under the membership lock it then seals an S6 activation event through the journaled transaction below, and publishes that event only after the transaction is durable.
- Until then the group stays V4. A V5 mint refuses before minting with the typed wait `activation_awaiting_upgrade {members}`, which names each member whose advert is missing, stale or lacks the bit. Exits: each named member publishes a current advert with the bit, or an admin removes that member through the normal removal path. V4 admission keeps working, issuer-pinned. One never-upgraded device keeps the whole group on V4; David accepted that cost (D101).
- After activation, an admin admits a joiner, V4 or V5, only when the joiner's current verified advert sets the bit; the joiner may carry that advert in its request. Otherwise it refuses before mutation with the typed refusal `joiner_upgrade_required`. A released joiner cannot decode that reason and sees its released join-poll outcome; the mixed-version controls record which outcome appears.
- **L4:** only positive, machine-bound adverts count, so no old admin is ever asked to enforce consumption. **Mixed versions:** legacy groups are unaffected; an activated group has no member that cannot read its envelopes.

**Home-policy groups (D81).** Home activation is allowed only behind a released-binary control, as cross-slice rule 1b and ADR 0114 §5 require.
- The Home placeholder uses the same inert roster as any placeholder below. Unlike the non-Home placeholder, it keeps the released-compatible Home identity and policy metadata, and the canonical owner-sync pointer where one exists. A default-policy placeholder with `home = None` fails released v0.46.1 `find_home`/`is_home_candidate`; without an owner-sync pointer, provisioning step 4 can then create a duplicate Home (#449/#824).
- Before any release enables Home activation, the released v0.45.0 and v0.46.1 binaries must load candidate data dirs that hold the Home placeholder **with no owner-sync pointer**, through reload and `provision_home_steps`. They must show no duplicate Home, no `home.json` change, no admin seat, no invite mint and no commit.
- If any variant fails, Home activation stays disabled in that release. A Home activation request then refuses before any sidecar or placeholder write with the typed terminal refusal `home_activation_blocked {failed_control}`. Its exit is a later release whose control passes.
- **L4:** this adds no acceptance rule; it only gates a write. **Mixed versions:** released binaries see an inert Home they cannot act on. Home is an owner group, so Home V5 also depends on D100 (§4).

At activation of an eligible group, replace its entry in each legacy view where it exists with a placeholder: preserved identity/genesis/revision/hash, default invite-only policy (Home: its preserved Home policy and metadata, above), **non-empty `members_v2` with every entry Removed and no Active seat**, GSS plane, `home = None` for non-Home groups, and no secrets. Released v0.45.0/v0.46.1 run `GroupInfo::migrate_from_v1()` on every entry: an empty `members_v2` would seat the creator as Admin. The non-empty all-Removed roster makes migration a no-op and leaves no admin. Apply it to every alias of the stable ID, including every entry in the Home-Suite view. An old daemon can reserve the ID and load the placeholder, but has no admin seat to mint an invite or seal a membership commit after reload; it does not restore S6 authority. Prove those limits on the released load path. #451's empty-roster placeholder is safe only when a Home-Suite-aware binary replaces it; S6 must not copy that roster shape. Leave existing #451 behaviour unchanged for unactivated groups.
Journal and durably install the S6 backing state and crypto snapshot before replacing the legacy view, retaining the split-store transaction and fsync barriers. Activation remains prepared until every applicable legacy placeholder is durable and the S6 activation commit marker is durable; publish no S6 mutation/key egress before that point. Startup replays the S6 journal before serving the group, rechecking the legacy predecessor/transaction identity; an interrupted activation followed by a legacy rewrite must not clobber the newer legacy head. On S6-aware load a committed sidecar is authoritative. An unknown sidecar version refuses **that group** with the typed terminal refusal `group_state_unsupported {version}` (exit: upgrade). A corrupt sidecar or inconsistent transaction refuses it with `group_state_corrupt` (exit: operator restore). Both preserve bytes and placeholders, and never fall back to legacy state or abort daemon startup. These are local faults, not protocol waits.
Activation is lazy, never a startup migration. Under an ADR 0094 supervised upgrade, defer the **first behaviour-changing sidecar/placeholder write until host commit**, not provisional per-instance health. Before host commit, use rollback-readable state and defer S6 mint/redemption/activation writes, reporting the typed wait `activation_deferred {until: host_commit}`; startup, gossip and polling cannot activate it.

Each slice owns its new state in its own versioned sidecar with a new magic and extension: S4 eviction obligations, S6 redemption state and S8(b) repair state must not rewrite a shared legacy container. S3/S7 operate through the verified group transaction rather than assuming activated authority remains in JSON. Compose sidecars by stable ID and committed head/transaction identity; independently choosing the newest roster and an older consumption root is forbidden. Settle this transaction contract through S6's amendments to already Accepted 0110/0109 and conformance with 0113/0114 before S6 acceptance, without editing Accepted text or assigning S6 ownership of their sidecar layouts.
Real released v0.45.0/v0.46.1 binary tests must show the daemon starts, activated placeholders have **no admin seat after reload, no invite mint and no commit**, ordinary legacy groups still work, and S6 sidecars/journals/snapshots are **verified not to be overwritten or moved aside**. Home-policy groups activate only after the D81 control above passes. Re-upgrade restores the full S6 roster and consumption state; no old placeholder can replace it. Release notes describe group unavailability on downgrade, never daemon unavailability.

| Direction | Required behaviour |
|---|---|
| Mint API default | `POST /groups/:id/invite` continues to mint V4 by default. V5 is an explicit version request on an activated group (D101): addressed (D99), Member-only (D103), with a finite expiry (D104). Unsupported requests get the typed refusals in §1 or `activation_awaiting_upgrade` before minting. No silent default-version switch. |
| Old joiner → new admin | V4 uses unchanged inviter-bound admission; a non-inviter does not convert it. |
| Old joiner given a V5 link | The parseable link shell reaches the released `version != V4` gate, returning typed HTTP 409 **`invite_unsigned`** (`src/server/routes/named_groups.rs:17999–18000`) **before any stub or new pending row**. S6-aware joiners may explain the unsupported version separately; do not claim an old daemon returns a new error code. Prove the typed refusal with actual released binaries; otherwise block V5 link distribution pending a compatibility remedy. Never reinterpret it as V4. |
| New joiner → old admin | Use V4 only if the supplied invite is V4. V5 has a visible retryable `recipient_upgrade_required` outcome naming `group_invite_any_admin_v1`; send no V5 bytes. |
| New ↔ new | V5 envelopes require the bit at both ends and mandatory delegated/consumption checks. |
| Old existing member | Keep legacy groups working. A group with any member lacking a current positive advert does not activate (D101, `activation_awaiting_upgrade`). Do not send new envelopes on a legacy topic or let old code write S6 state. |
| Old joiner → activated group | Refused before mutation (`joiner_upgrade_required`); the released joiner shows its released join-poll outcome. No seat or key egress. |

Use distinct S6 message tags/topics for requests, commits and results; never disguise them as legacy `MemberJoined`/`MemberAdded` fields.
Recovery from a lost response uses verified S5 artifacts or S8(b)'s separately accepted re-Welcome rule, never a second consumption.
Upon S6 acceptance (scope approved, D105), 0107's “inviter must be the device that sealed the original add” rule applies **explicitly to V4 only**. V5 requires the request-selected redeemer for a new add, or the independently verified original actor plus the selected admin's fresh wrapper for commit/result recovery. Its serving guard remains unchanged.
Serve every result, blob chunk, Welcome and secret resend only to a currently eligible recipient under ADR 0107 and D60.
Immediately before **each physical transport write**, re-check eligibility and artifact selection, including revocation, expiry, quarantine and current secret epoch, **and send under the membership lock**. Every delivery/chunk/resend is a separately admitted single exchange; no hidden transport resend and no gossip or gossip-capable fallback. Cancel and await unsent/in-flight transfers on removal, ban, revocation, expiry, quarantine or group retirement; an earlier copied buffer grants nothing.
The [join-artifact serving lifecycle note on PR #1190](https://github.com/saorsa-labs/x0x/blob/e645ce253bac6fc36b1dffd2398836da1f0096e8/docs/design/join-artifact-serving-lifecycle.md) is **related work only**, not on main and not a dependency.
S6 must prove its own guarded egress; neither the note nor an old cache entry grants admission.

**Pre-admission replies.** ADR 0107's guard serves only an Active recipient, so it cannot carry a refusal or wait notice to an unseated joiner. S6 adds one narrow, attempt-bound serving rule for those replies. ADR 0107's full guard and D60 still govern every result, blob chunk, Welcome, key and secret resend.
- **What it covers:** the §6 typed refusals and waits, `redemption_not_committed` releases and status-probe answers. A reply carries no key material, Welcome, group secret, commit or roster. It names objects only by digests that the request or the signed invite already binds; otherwise it names only the kind.
- **Who gets it:** only the requester of a live attempt. The reply answers one authenticated request; it binds `(group, invite_id, request_digest, attempt_nonce, redeemer_agent_id)` and the redeemer signs it. It goes over that request's authenticated, encrypted point-to-point session, to the machine that J's EvidenceV1 binding names. A request replayed from another machine gets no reply.
- **How:** each reply is one admitted exchange, with no hidden transport resend and no gossip or gossip-capable fallback. Immediately before each write, under the membership lock, re-check that the attempt is live and the joiner is not banned or revoked. A banned or revoked joiner gets only its §2 refusal.
- **L4:** the rule discloses nothing beyond what the request and the invite already bind, and grants no admission. **Mixed versions:** it runs only inside S6 envelopes; released joiners keep their released refusal receipts.
0088's own §2 entries remain, with the named amendments other slices add, plus this ADR's `redemption_unresolved` (D99). Issuer-offline is never an entry.

### 6. Typed blocks (L3, D64)

L3 binds this slice as a hard rule (D64). Every block this ADR adds or touches ends in one of these typed states. Each wait names what it waits for.

| Block | Typed state | Kind | Waits for, or exit |
|---|---|---|---|
| Capability unknown during the D35 refresh | `awaiting_capability {peer, bit}` | wait | a current advert; then a send or the next row |
| Admin or joiner lacks the bit | `recipient_upgrade_required {peer, bit}`, `joiner_upgrade_required` | wait / terminal for that peer | that peer upgrades; J may try another admin |
| No reachable verified admin | `no_reachable_admin {tried, next_round_at, reason}` | wait: §2 item 3 when no admin is online; `reason: outside_invite_base` when only admins outside J's base are reachable (the 0111 Q9 gate, open question 4) | any active admin online; or the Q9 ruling |
| Pre-member roster or evidence fetch | S5 `evidence_pending` | wait, §2 item 8 | any eligible holder online |
| Window ends with no terminal answer; earlier attempt may have committed | `redemption_unresolved {invite_id, earlier_redeemer, attempt, next_probe_at}` | wait, named §2 amendment `redemption_unresolved` (D99) | its exits in §2 |
| V4 attempt by an S6-aware joiner on an activated group | `awaiting_issuer {issuer}` | wait; tracked L1 defect, not on §2 | the issuer |
| Redeemer behind and cannot catch up in its budget | signed `redeemer_behind {needed_revision}` (a release) | wait | redeemer catches up; or J tries another admin |
| Redeemer mismatch / not an active admin at the predecessor | `redeemer_mismatch`, `redeemer_not_admin` | terminal for that request | J signs for another admin |
| Policy drift | `invite_policy_changed` | terminal | a fresh invite |
| Expired, consumed, wrong joiner or role above cap | released `invite_expired`, `invite_secret_consumed`, `invite_not_addressed`, `invite_role_exceeds_cap` | terminal | a fresh invite |
| Bad signature, secret, issuer authority, permit or intent | `invite_authorization_invalid {check}`, `owner_permit_invalid` | terminal | none |
| Ban, revocation, certificate, deletion, unadmitted or post-removal epochs | the existing §2 items 1, 2, 4, 5, 6 refusals | terminal | none |
| V5 mint outside D99/D103/D104 | `invite_v5_requires_addressee`, `invite_v5_role_unsupported`, `invite_v5_lifetime_invalid` | terminal | a valid request |
| Storage pressure | `invite_capacity_exhausted {scope, earliest_prune_at}` | wait | a committed prune, allowed from `earliest_prune_at`; exit policy in open question 3 |
| Activation barrier | `activation_awaiting_upgrade {members}` | wait | named members upgrade or are removed |
| Before ADR 0094 host commit | `activation_deferred {until: host_commit}` | wait | host commit |
| Home control failed | `home_activation_blocked {failed_control}` | terminal for that release | a release whose control passes |
| Unknown or corrupt sidecar | `group_state_unsupported {version}`, `group_state_corrupt` | terminal for that group on that node | upgrade; operator restore |
| Ordinary unanchored fork | the existing quarantine | wait, §2 item 7 | an admin acts by hand |
| OwnerCertified fork | none yet | blocks Accept (D100) | open question 1 |

A released binary keeps its released outcomes. The mixed-version controls record them; S6 never relies on them as its own typed state.

## Consequences

### Positive

- A valid V5 invite can admit through a current admin with no issuer or owner-device round trip on a verified non-conflicting chain.
- Downgrade keeps the daemon and legacy groups running while preserving activated group state for re-upgrade.

### Negative / Trade-offs

- **Home L1 gap:** D81 lets Home activate only after the released-binary control passes. Until a release passes it, an owner device joining Home while its inviting device is offline stays tied to that inviter, the core R3 case. Home is an owner group, so it also waits on D100.
- New wire envelopes and per-group sidecars need an explicit rollout and a shared transaction contract. Tombstones cost storage, bounded by mandatory expiry and committed prune (D104); long-lived invites must be re-minted.
- **Device-bound wait (D99):** `redemption_unresolved` can depend on the earlier redeemer's device until its commit spreads, it signs a release, or the invite expires. David accepted this L1/L2 cost; it is the named §2 amendment `redemption_unresolved`.
- **Upgrade barrier (D101):** one never-upgraded member keeps its whole group on V4, with the offline-inviter gap.
- **Remaining issuer-pinned paths:** bearer invites (D99) and **Admin-role invites** (D103) stay V4 and inviter-pinned. **Pre-upgrade V4 invites** stay pinned until re-minted as addressed V5. The default V4 mint path keeps this gap. They stay tracked defects against L1, not §2 entries. S6 must not claim all D16 admissions are covered.
- OwnerCertified forks from an equivocating joiner, a re-invited joiner or a partitioned demoted admin have no prevention yet (D100, blocks Accept). Ordinary forks need manual admin action (§2 item 7).
- Redemption at an admin promoted after the invite waits on ADR 0111 Q9; until then J uses only base admins, which keeps an L1 gap when every base admin is offline. Lost-key recovery depends on separately accepted S8(b). Unknown capabilities, missing committed receipts and storage pressure produce typed waits/refusals (§6), not keyed-active membership.


### Follow-ups for the implementation

- **Catch-up time (D104):** catch-up trusts the validation time that the redeeming admin bound into the commit, so a partitioned admin could backdate it for receivers that only catch up later. The harm is no greater than what an admin can already do through legacy V4 admission. Open question 3 proposes a check that limits it.
- **Downgrade test:** also assert that the released reload leaves group-scoped data (KV stores, task lists) untouched.
- **Placeholder fields:** list them explicitly. Clear `issued_invites`, `join_requests` and `commit_log`, as #451's `legacy_safe_placeholder` does.

### Neutral / Operational

- V4 signatures, mandates and original-inviter cache repair remain unchanged. V5 is Member-only (D103); David approved the broader amendments (D105).
- Home-policy groups activate only behind the D81 control. S6 preserves owner-certificate checks and revocation eviction semantics. It supplies no new re-Welcome authority or owner fork anchor.

## Validation

These are **required, not yet implemented or run**. W3-H (#1164) does not exist yet. Recommend filing an S6 tracking issue listing the cases, prerequisites and receipts before implementation; this draft does not claim an issue was filed.
Drive actual daemons through public `POST /groups/:id/invite`, `POST /groups/join`, `GET /groups/:id/join-status`, and the public group role/removal/policy APIs. Do not inject a decoded invite or call an internal redemption helper in place of mint/join. The S6 API extension must expose explicit invite version and selected redeemer; normal automatic selection is tested too.
For red-on-main receipts, mint the current default V4 through the public API and use harness delivery to make B the only reachable admin; the fixed counterpart mints V5 explicitly with the same semantic grant. Failure solely because main lacks a V5 parameter is **not** a liveness red receipt.
Record fixture identities, pinned main/fix SHAs, clock/delivery traces and assertions in the implementation PR. Each red case must be committed and shown red on **main before slice code merges**, then green on the fixed tree. In-process red tests alone do not count (D16/D54). Run in CI's fresh loopback-only Linux namespace with dropped privileges.

All cells except `s6_home_released_binary` (which drives released binaries in real time) use a deterministic fake wall/monotonic clock starting at `t=0`, fixed identity/secret fixtures and scripted delivery barriers. Fixture invite expiry is after the last scheduled step, except in the expiry cells. The exit bound `T` is the window David ruled (D102): 120 s for TreeKEM and 600 s for GSS. Discovery, retry and prune times use open questions 2 and 3's proposals until David rules them, then the ruled values. Advancing the clock never unblocks a stopped daemon or a withheld message. Repeat each specified ordinary/OwnerCertified variant. For OwnerCertified fixtures A holds the owner's USER key at mint; stop A and every other owner-key device O before redemption. B/C never hold that key.
In the conflict cells, main's control assertion is that legacy non-inviter B/C create **no seat or key egress**; their fixed V5 counterpart runs the stated commit/failover schedule. Existing V4 replay/serving controls run at the original issuer. These controls do not pretend main already has S6 consumption roots or new error bindings.

| Case / baseline | Nodes, public steps and deterministic delivery | Assertion |
|---|---|---|
| `s6_offline_inviter_other_admin_admits` — **red on main** | A/B admins, J fresh, optional O. t=0 create a common head and mint J's addressed invite at A via the invite API. t=1 stop A/O; deliver current signed adverts for B and all needed authorized evidence. t=2 J calls join; route all redemption traffic only to B, which has no issuer-local record. Deliver B↔J traffic in FIFO order, then advance to T. | On main J fails to reach usable membership. Fixed V5 reaches confirmed membership at B and J, with J decrypting B's next group message by T, no traffic to A/O and one consumption. A roster seat alone is not a pass. Repeat TreeKEM and GSS with their separately ruled budgets. |
| `s6_promoted_admin_stale_invite` — **red on main; the promoted-admin run is gated on 0111 Q9 (open question 4), the D95 variant is not** | A admin, B initially Member, J fresh, optional O. t=0 A mints at r; t=1 public role API promotes B at r+1. t=2 stop A/O and restart B from disk. t=3 J calls join from r and discovers B via a peer contact hint absent from its base-admin set. Deliver links in revision order; advance to T. **Variant (D95, red on main: #646):** a 25-member base with a second base admin A2 left online. J fetches the base projection from member C under the invite-bound rule and redeems at A2, so this variant does not wait on Q9. A stranger without the invite gets `group_object_absent_v1`. | Main's inviter/result pin prevents usable admission, and main cannot mint past 20 members. Until Q9 is ruled, the fixed run sends B no request and J shows `no_reachable_admin`. Once Q9 permits the carried chain: fixed V5 verifies B at the actual predecessor from that chain and gives J current keys without quarantine for a legitimate gap or across-gap TreeKEM snapshot adoption. Discovery hints alone never prove authority. J makes no pre-member fetch other than the roster at its invite's root. |
| `s6_replay_restart_and_admin_handoff` — **control on main** for existing V4 replay/removal; S6 root/recovery assertions are new | A/B/C admins, J. t=0 mint and public-join once at the authority (A for V4 control, B for V5). t=1 deliver the terminal to C and restart it. t=2 repeat J's public join at that authority and at caught-up C with fresh attempts; t=3 public-remove J, deliver removal, and replay again. In a separate run drop B's first result after durable commit, restart B, then J publicly retries through C at t=2; deliver original commit/result and S8(b) key recovery as separate guarded exchanges. | One consumption on one chain; no extra add/rekey/Welcome on identical replay, and no re-admission after removal. Lost-result recovery confirms only after current usable keys and a fresh attempt binding; lost-key recovery requires S8(b), never an S5 Welcome object. |
| `s6_two_admin_double_redemption` — **control on main** (legacy pinning); D99/D100 conflict case | A/B/C admins, J/K fresh, optional O. t=0 mint J's addressed V5 invite through A; a bearer V5 mint request gets `invite_v5_requires_addressee`. Stop A/O at t=1. Ordered run: at t=2 J joins via B, deliver B's commit to C, then t=3 K presents J's link via C. **Equivocation run (D100):** partition B/C at their common parent; t=2 J sends signed requests for one invite to B and C, hiding the first; deliver both before either commit, then heal at t=3. | Ordered run has one spend; K gets `invite_not_addressed` and no keys. Equivocation run, ordinary group: authenticated sibling evidence and quarantine under §2 item 7. OwnerCertified variant: no delegated intent clears it, and no wait may claim §2 item 7. It stays **red until a D100 prevention design is ruled and implemented**; it is required before Accept. No per-admin mutex is a global proof. |
| `s6_same_joiner_failover` — **control on main** (V4 cannot redeem at B/C); D99 case | A/B/C admins, J, optional O. t=0 mint addressed J invite. Stop A/O at t=1. **Committed setup (runs a, c):** t=2 J joins via B; B durably commits; drop B→J/C result/commit, then stop B. t=3 J publicly retries through C, which still has the old parent, with a new nonce, signed C ID and its earlier-attempt list. (a) At t=4 deliver B's commit to C. (c) Keep B stopped and advance past the invite's expiry. **Uncommitted setup (run b):** t=2 B receives J's request, then a crash cut stops B before its first `.s6journal` write. t=3 J retries through C as above. t=4 restart B and let it answer J's probe. t=5 redeliver J's original request to B, restart B again and redeliver it once more. | In every run, C first refuses a fresh spend with `redemption_unresolved` naming B, with no seat or key egress. (a) J recovers the original admission through C; one seat, one consumption. (c) The attempt ends with `invite_expired`. (b) B durably records the refusal, then signs `redemption_not_committed`; the fresh spend at C then succeeds once. At t=5, B refuses the original request after each restart and never commits it; one seat in total. Never two siblings for one invite; never call two epochs idempotent. |
| `s6_guarded_delivery_and_policy_drift` — **control on main** for existing 0107 guard; new S6 bindings | A/B/C admins, J, optional O. Public-mint at t=0. Change policy through its public API at t=1, then public-join at t=2. In separate runs mutate current eligibility/epoch through public removal/ban/revocation APIs at a barrier just before a queued result/chunk/Welcome/resend write. Replay J's request signed for B at C. Partition B before its public demotion, then attempt its outstanding permit on the old head and heal. | Policy drift returns terminal `invite_policy_changed` with no mutation/key egress. C cannot execute B's signed request. Each write rechecks and sends under the membership lock, with no hidden resend/fallback. A partitioned demoted B's sibling is fork evidence; its keys cannot decrypt canonical post-demotion epochs. |
| `s6_typed_window_exhaustion` (D64) — **red on main** | A/B admins, member M, J. t=0 the main run mints J's V4 invite at B; the fixed run mints V5 at A and stops A. t=1 on B, withhold M's certificate bytes so B's seal blocks (#946). t=2 J joins via B. Advance to T, then to t=2+10 min. Repeat with B stopped after it receives the request and before it answers. | On main the 120 s poll ends with no typed state; the #946 refusal is staged only at 10 minutes, after J stopped polling. Fixed: J sees `evidence_pending` from B inside T; with B stopped, J shows `redemption_unresolved` naming B at T. No run ends silent or keyed-active. |
| `s6_activation_barrier` (D101) — **new control** | A/B admins, members M1 (S6) and M2 (released v0.46.1), J. t=0 create the group on S6 nodes; M2 joins via V4. t=1 A requests a V5 mint. t=2 upgrade M2 and deliver its current advert. t=3 A requests the mint again. t=4 a released joiner presents a V4 link. | t=1: `activation_awaiting_upgrade` names M2; no activation event, sidecar or placeholder. t=3: one activation event, then the mint. t=4: `joiner_upgrade_required` on the S6 side, no seat or key egress; record the released joiner's shown outcome. |
| `s6_home_released_binary` (D81) — **new control; it gates Home activation** | Home: owner install O (Home creator) and Home device A2. The candidate runs with host commit written and Home activation on by test configuration. Activate Home on A2 through the public V5 mint/join APIs, then stop A2 so its S6 Home placeholder is on disk. Variants: A2 as an owner install (user key and agent certificate) and as a non-owner device; plus O's own data dir with its S6 Home placeholder (the creator reload). Remove any stored owner-sync canonical Home pointer, and give each run no network peers. Record the group-ID set, the `home.json` sha256 and the S6 file hashes. **This case runs in real time, not on the fake clock.** On a copy of the data dir per binary, start released v0.45.0, and separately v0.46.1; wait 150 s of real time (past v0.46.1's 90 s `HOME_POINTER_SYNC_WAIT`, so its deferred provisioning pass runs); stop. Start again, wait 150 s, stop. Then start the candidate on the original data dir. | On both binaries and in every variant: the binary starts; the group-ID set is unchanged, with no new Home-policy group; `home.json` is byte-identical, or still absent; the group has no Active and no admin seat in either view; `POST /groups/:id/invite` and `POST /home/seat` are refused; the state revision does not move; the S6 file hashes are unchanged. The candidate then resumes with the Home ID unchanged. Any failure keeps Home activation off, and an activation request gets `home_activation_blocked` before any write. |
| `s6_pre_admission_reply_guard` (§5) — **new control** | A/B admins, member M, J fresh, stranger X, banned joiner K. Times in seconds. t=0 mint J's and K's addressed V5 invites at A, ban K through the public API, stop A. t=1 on B, withhold M's certificate bytes; keep them withheld until t=10. t=2 J joins via B; drop B's first reply at a barrier. t=3 X replays J's request bytes to B from X's machine. t=4 K joins via B. Advance the clock to t=8, one shipped resend interval (3 polls of 2 s) after J's request, and deliver J's resend to B, then B's reply to J, in that order. t=10 release M's certificate; let B commit J. | Up to t=10: B makes no commit. t=2: the transport never resends the dropped reply. t=8: J gets one signed `evidence_pending` in answer to its resend, bound to its attempt and sent over its request session. Each reply carries no key, Welcome, secret, commit or roster. t=3: X gets no reply. t=4: K gets only its ban refusal. t=10: B serves the result and Welcome only after J is Active on the committed roster, under ADR 0107's guard. |

Exit gate: the liveness red cases (`s6_offline_inviter_other_admin_admits`, `s6_typed_window_exhaustion`, the D95 variant of `s6_promoted_admin_stale_invite`, and, once 0111 Q9 is ruled, that case's promoted-admin run) have genuine red receipts on main and pass with the issuer continuously offline. The OwnerCertified equivocation run needs the D100 design before Accept. New-version assertions in the controls claim no red-on-main receipt.
Non-regressions cover V4 same-inviter joins, ADR 0106 carries, ADR 0107 re-arm, current serving eligibility and S3/S5 catch-up.
Reject wrong-owner/expired/revoked certificates, removed/banned joiners, revoked/non-admin redeemers, foreign groups, altered roles/secrets/packages and transplanted mandates or attempts without state change or key egress.
Exercise all eight of 0088's own §2 entries, including signed deletion, removed-member epochs, never-admitted epochs, no reachable admin/holder and manual unanchored-fork recovery, and assert each ends in its §6 typed state. The named amendment `redemption_unresolved` is covered by `s6_same_joiner_failover`.
Persistence control: public-mint/join on A/B/J at t=0–2; inject crashes before/after each `.s6journal` write, snapshot/sidecar/placeholder replace, directory fsync and egress. Restart at t=3 and replay publicly at t=4: never lose consumption or confirm without usable keys. During an ADR 0094 trial, deliver the activation request before host commit and assert `activation_deferred` and no behaviour-changing persist; release the same request after durable host commit and assert one atomic activation.
Downgrade control: A is the group's creator/admin, B an admin and J a joiner; t=0–2 use fixtures from actual released encoders and activate the non-Home group through public mint/join APIs. Hash legacy files and S6 sidecars/journals/snapshots; t=3 boot the **released v0.45.0 and v0.46.1 binaries** on candidate copies of the same data dir with A's creator identity loaded and loopback-only scripted delivery. t=4 inspect the released reload's roster and call the public invite and membership-mutation APIs; t=5 reload again, exercise an unrelated legacy group, and re-upgrade at t=6. Assert successful startup, non-empty all-Removed `members_v2`, **no admin seat after either reload, no invite mint and no commit**, byte-identical S6 files including pending journals, and restored authoritative consumption after re-upgrade. This is a required new S6 control, not a red-on-main claim. Home activation is covered by `s6_home_released_binary` (D81). Fault/corruption cells refuse one group with `group_state_unsupported` or `group_state_corrupt` while the daemon stays up.
Cross-slice control: A/B/C/J, mint/join via B at t=0–2, public-revoke J at t=3, let S4 seal the eviction, withhold it from C until t=4, then drive S3/S5 catch-up. Assert the S6-domain head matches, consumption survives the eviction/recovery, a public replay refuses, and S7 adoption/S8(b) repair never substitute a legacy root or shared-file rewrite. Prune and capacity control (D104): A/B admins, J1…Jn. Mint and redeem until the per-group capacity; the next mint gets `invite_capacity_exhausted` naming the earliest prune time, and seats and tombstones are unchanged. Advance past expiry plus the prune margin, publicly trigger the normal maintenance path, deliver the prune commit, restart and replay: expired admission stays refused, and the next mint succeeds. A mint with no expiry or above the maximum gets `invite_v5_lifetime_invalid`.
Mixed-version controls drive every table row through public mint/join, using real v0.45/v0.46 peers, absent/stale/forged adverts, an old joiner parsing a V5 link with no stub, and an old existing member across the D101 barrier. No V5 bytes reach a legacy handler as V4. If a released parser lacks the required typed refusal, record the failure and block distribution; do not assume future code repairs an old binary.

Accept in 0088's order: the contract, then S2 and **S8(a)/0107**, then S4/S3, then S5, then S6, then S7. “S8” in that order means S8(a); **S8(b)/0114 is Accepted after S4**, as 0107 requires, and S5 does not wait for 0114 (D65). S6's lost-key recovery additionally depends on that separate acceptance and its implementation.
S6 must land **Proposed on main**, then be **Accepted by David before its code merges**; one `named_groups.rs` code lane at a time (0088 §4, ADR 0087 rule 8). No S8(a) harness exception applies to S6.
Acceptance also requires the D100 design, David's rulings on open questions 2 and 3, and the S3/S4/S7/S8(b) sidecar/transaction/hash boundary reconciled through this ADR's S3/S4 amendments (D105) and cross-slice conformance controls, leaving Accepted text untouched. It also needs David's ruling on ADR 0111 Q9 (the pre-member promotion chain), recorded here as open question 4. Home activation also needs a passing `s6_home_released_binary` control (D81). S6 code merges only after the required red-on-main receipts; key recovery cannot be declared complete until the S8(b) path and guarded exchanges pass.

## Rulings and open questions

**Still blocking David's Accept:** open question 1 (D100: no fork-prevention design yet), open question 2 (D102: discovery, fetch and retry limits), open question 3 (D104: lifetime, skew, storage and exhaustion values and the exhaustion exit) and open question 4 (ADR 0111 Q9). Accept also needs the cross-slice conformance receipts (§4, §5) and follows S5/0111 in 0088's order.

David ruled Q1–Q6 on 2026-10-04 (D99–D105), with the cross-slice rulings D64, D65, D81 and D95:

- **Q1, single use and failover:** V5 any-admin redemption works only for invites addressed to one agent. Another admin refuses a fresh spend while the first may have committed, with `redemption_unresolved` (D99). David accepted that this wait can depend on the first admin's device, an L1/L2 cost. §2 records it as a named amendment to 0088 §2, `redemption_unresolved`, with its typed state and exits.
- **Q1, OwnerCertified forks:** prevent the forks; S6 must show before Accept how V5 avoids them (D100). Still open: question 1.
- **Q2, activation barrier:** a group activates only when every member runs S6 (D101, §5). One never-upgraded device keeps the whole group on V4.
- **Q2, Home activation:** lifted behind a released-binary control (D81, §5). Home activates only after released v0.45.0 and v0.46.1 binaries, with no owner-sync pointer, show no duplicate Home and no `home.json` change through reload and provisioning. A failed control blocks Home activation.
- **Q3, attempt windows:** the shipped windows: 120 s for TreeKEM, with the 115 s Welcome fetch inside it, and 10 minutes for GSS (D102, §2). The harness bound `T` uses them. Discovery, fetch and retry limits are still open: question 2.
- **Q3, G7 part:** L3 binds every slice as a hard rule, including the 120 s poll and upgrade or backoff waits (D64). §6 lists every block this ADR adds or touches, with its typed state.
- **Q4, role cap:** V5 invites are Member-only for now; Admin grants stay on V4 until a reviewed extension (D103, §1). David's choice accepts the Admin-invite offline-issuer gap. This ADR tracks it as a defect against L1, not a §2 entry.
- **Q5, expiry:** every V5 invite expires, and an admin prunes tombstones only by a committed change after expiry and clock checks (D104, §4). The values are still open: question 3.
- **Q6, amendment scope:** approved. S6 amends 0064 §1 and §1b, 0107's original-inviter rule (now V4 only), and 0110 and 0109 for S6-activated groups, leaving Accepted texts untouched (D105).
- **S5/0111 Q3:** a pending joiner with a signed invite that binds the root may fetch that roster (D95, §1). With it, §1's root-only V5 view closes #646 for V5. D95 covers only the roster at the invite's root; the promotion chain is open question 4.
- **Order:** "S8" in 0088's order means S8(a)/0107; 0114 follows S4, and S5 does not wait for 0114 (D65).

Still open for David:

1. **OwnerCertified fork prevention (D100; blocks Accept).** D99 removes two fork sources: a second joiner (V5 is addressed) and an honest joiner's failover (refused while unresolved). Three remain (§4):
   - (i) a joiner that hides an earlier attempt, or lost its attempt record, and asks two admins at once;
   - (ii) a fresh invite for the same joiner, redeemed while the first admin's commit is withheld;
   - (iii) the partitioned demoted admin of §3, which D100's cost note says may still fork.

   No local check can stop these across a partition without coordination, which D16 and D99 rule out. Each would wait for an owner-anchored advance, which is not on 0088 §2.
   **Candidate for review (not normative): replay of portable admissions.**
   - Extend the D99 attempt list from one invite to one joiner per group. An admin refuses any new admission of a joiner that declares an unresolved attempt in that group. This closes (ii) for honest joiners.
   - A V5 admission is portable: its permit binds the policy hash, not the predecessor. When authenticated siblings at one predecessor differ only by V5 admission terminals, with nothing built on them, any one active admin re-commits those admissions on the surviving head. It keeps the same consumption keys and takes a fresh attempt binding from J, as in §2's recovery wrapper. The surviving branch is the non-V5 side; if both sides are V5-only, the side with the lower terminal hash. Members of the retired sibling recover through S3 catch-up and S8(b) current-epoch re-Welcome. Data written only on the retired sibling is not merged.
   - For (i), J's two signed requests for one invite show that J equivocated or lost its record. David would rule whether J keeps the replayed seat or is removed.
   - Limits: retiring a valid sibling is a new acceptance rule and needs its own L4 argument. It does not cover a sibling with later non-V5 commits on it, so (iii) still forks when the demoted admin also commits other changes.

   David's choice: develop this candidate; require another design; or scope S6 to ordinary groups until a design exists, which leaves the OwnerCertified and Home L1 gaps open.
2. **Discovery, fetch and retry limits (D102; blocks Accept).** Proposal for David's ruling:
   - **Discovery:** each round tries at most 8 candidate admins, base admins first, with at most 3 EvidenceV1 lookups in flight and one lookup per candidate per 30 s. A round lasts at most 30 s. With no reachable verified admin, J reports `no_reachable_admin` and starts a new round every 5 minutes.
   - **Fetch:** reuse S5's ruled values unchanged (D98): 10 s inline, 115 s per blob pull, 16 outstanding fetches to 3 holders, one request per digest and holder per 30 s. The D95 roster fetch counts against S5's limit of 8 requests per requester per 10 s.
   - **Redeemer:** finish verification and catch-up, or send a signed typed refusal, within 90 s of first receipt for TreeKEM and 9 minutes for GSS, so the answer lands inside J's window.
   - **In the window:** keep the shipped 2 s poll and the request resend every 3 polls (about 6 s). Each resend is a separately admitted exchange.
   - **After an unresolved attempt:** probe the earlier redeemer and up to 3 holders at 30 s, 1, 2 and 4 minutes, then every 5 minutes, with ±10% jitter, until an exit. A probe is a status query, never a fresh spend.
3. **Lifetime, skew, storage and exhaustion values (D104; blocks Accept).** Proposal for David's ruling:
   - **Lifetime:** default 7 days, the shipped V4 default (`DEFAULT_EXPIRY_SECS`, `src/groups/invite.rs:21`); maximum 30 days. The mint refuses no expiry, or a longer one, with `invite_v5_lifetime_invalid`.
   - **Clock skew:** 5 minutes. A live receiver accepts a signed validation time only within 5 minutes of its own clock and before `expires_at`.
   - **Prune margin:** an admin may prune a tombstone only when its local time is at least `expires_at` plus 10 minutes (twice the skew).
   - **Backdating:** a terminal's validation time may not be earlier than its predecessor's validation time minus the skew. This limits a partitioned admin's backdating to its own predecessor's time; the remaining harm is no greater than legacy V4 admission. It is a new acceptance check, so it needs David's ruling.
   - **Storage:** at most 4,096 live tombstones per group, each map entry at most 256 bytes (about 1 MiB per group), and at most 16 MiB per node. Signed proofs stay in the hash-linked commits under S5 retention (D98), not in the map. At the 30-day maximum this sustains about 136 admissions per group per day.
   - **Exhaustion:** at either cap, new V5 mint and redemption refuse before mutation with `invite_capacity_exhausted {scope, earliest_prune_at}`. Seats, tombstones, recovery, removals and prune keep running.
   - **Exhaustion exit (proposal):** every active admin's maintenance path checks every 5 minutes. On the first check after `earliest_prune_at`, the designated-first admin (S4's lowest-ID rule) commits one prune of every prunable tombstone; any other online admin commits it if nothing lands within 5 minutes. So the wait ends about 10 minutes after `earliest_prune_at`, at most 30 days and 20 minutes after the oldest tombstone's mint, when one active admin is online. With no active admin online it is 0088 §2 item 3. Expiry alone never ends the wait.
4. **Pre-member promotion chain (ADR 0111 Q9; blocks Accept).** ADR 0111 owns this question; this ADR depends on it and does not rule it. A redeemer absent from J's invite base can prove its authority only with the signed chain from the invite root through its promotion, which discloses later joins. ADR 0111's proposal: S5 serves no chain to pre-members; the redeeming admin carries that chain only, and only on its own direct, guarded result path to J. Until David rules it, §2 sends requests only to base admins and otherwise reports `no_reachable_admin {reason: outside_invite_base}`, so the promoted-admin run of `s6_promoted_admin_stale_invite` cannot go green.

## Source Reconciliation

- ADR 0064 §1a lists fewer mandate bindings than shipped. Its README errata and #472's corrected preimage comments add `version`, `authority_agent_id` and `issued_at_ms`; use the 13-field code shape cited above.
- The public digest records the 2026-10-04 rulings this ADR applies (D64, D65, D81, D95, D99–D105). The Accepted contract and D58/D63 govern status and slice binding; leave those read-only sources untouched.
- ADR 0093's immutable allocation table predates ADR 0089's move of allocation to the README; use that canonical registry. This proposal selects no capability number and does not alter 0093's existing sender gates.
- ADR 0110 (S4) and ADR 0114 (S8(b)) now keep their state in their own sidecars with their own extensions (`.evs`/`.evjournal` and `.rwstate`/`.rwjournal`), as cross-slice rule 1 requires. What remains is transaction composition: one group's sidecars from every slice are composed by stable ID and committed head/transaction identity, never by taking the newest file of each kind. 0109/0113 must consume that composed activated state. The acceptance order freezes 0110/0109 before S6, so S6 records their activated-group envelope/hash amendment here, approved by D105, instead of requiring later edits to their Accepted text. No sibling draft or Accepted ADR is edited by this change.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs stay immutable; later decision changes require an amending or superseding ADR.

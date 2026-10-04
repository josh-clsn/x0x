# ADR 0109: Ownerless Attestation: Stale-Base Self-Recovery and Manual Re-seat (0088 S3)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** TBD (a cross-model review follows)
- **Slice:** S3 of [ADR 0088](./0088-group-liveness-contract.md)
- **Supersedes:** in part, upon acceptance: ADR 0064 Decision §3 and ADR 0066 §2 (as 0088 §3 assigns to S3)
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core
- **Related:** rulings D34(1), D41, D54, D16; #818 (part 2), #871, #1164 (W3-H harness), #1103 and PR #1181 (merged); ADR 0016, 0059, 0064, 0066, 0067, 0068, 0085, 0087 rule 8, 0093, 0106, 0107. Related work only: the join-artifact serving lifecycle note (`docs/design/join-artifact-serving-lifecycle.md`, on the #1190 branch, not on `main`).

## Context

A node can hold a quarantine that has no exit. Two shapes are live.

**#818 part 2: an ordinary group quarantines a legitimate gap.** A TreeKEM joiner whose invite base is stale receives its `MemberAdded` at a later revision. It never adopts across the gap (`src/server/routes/named_groups.rs:4828–4837`, TreeKEM excluded). The refused chain goes to `classify_refused_joiner_fork_chain` (`:4443`). That function exempts a gap only when the owner's v2 terminal attestation anchors it (`:4504`). By the #818 design decision (comment at `:4494–4503`), an ownerless group has nothing that tells a gap from a fork. So a walk-valid chain installs a `signer_only` marker (`:4558–4591`) with `no_anchor: true` (`:4301`). No commit ever clears that marker (`src/groups/mod.rs:347`, `:369`). The only exit is the operator's force clear (`named_groups.rs:14884`), which leaves the node at its stale base. ADR 0106 already converges a gap made only of `MemberAdded` events, up to 8, while the authority's in-memory log survives. Any other gap (a removal, a role change, more than 8 events, an authority restart) still quarantines.

Home has the same defect when the owner device is offline. Only an owner install signs the head attestation (`stage_join_result`, `:33364–33373`). A gap sealed by a promoted admin is never anchored, so the joiner stays quarantined until the owner device acts.

**#871: a forked head has no escape.** The #846 gate arms from the durable `AnchoredGapRefusal` record (`src/groups/mod.rs:122`; `armed_anchored_gap_sequence`, `named_groups.rs:10171`). While armed, each catch-up page must link from the current head and match the attested hash sequence (`:10200`, enforced at `:10282`). If the head itself forked, no page can link. The gate refuses every page and logs a warning only. It retires only when the node reaches the terminal revision (`:10343`, which deletes the record). The escape is leave and rejoin.

**Rules broken.** Both break 0088 **L2**: an indefinite quarantine that §2 does not list (a stale base is not a fork). The Home case also breaks **L1**: catch-up depends on the owner device. #871 also breaks **L3**: the wait is silent.

**Rulings.** D34(1): in ownerless groups, an active admin's signed terminal snapshot attests stale-base catch-up, as a mandate layer above ADR 0016, and gives #871 a re-seat path. D41: self-recovery only. The snapshot lets a node adopt the attested state and clear its own marker. It never marks another member forked, evicts anyone, or clears anyone else's marker. 0088 §3 separates the two cases: stale-base catch-up is automatic; a forked node is re-seated only under an admin's explicit manual authorisation (§2 item 7).

## Decision Drivers

- A stale base must converge with any one admin online (L1). It must never wait on the owner device.
- A fork must never be resolved automatically (ADR 0064 Option 3, ADR 0066 §2, 0088 §2 item 7).
- An attestation acts only on the node it names (D41).
- Each link still passes every existing apply check (L4). No adoption across a gap.
- Byte transport stays where it is. Control blobs and fetch-by-hash belong to S5 (D54).

## Considered Options

1. **Admin terminal attestation, self-recovery, manual re-seat** (chosen).
2. **Founder or creator key as the anchor.** Rejected by ADR 0066 R1. A founder has no special custody, and its key would become an eviction oracle.
3. **A quorum of admin heads.** Rejected by ADR 0064 Option 6 and ADR 0066 Option 4. A two-member quorum is the attacker.
4. **Automatic re-seat of a forked node under any admin's snapshot.** This is D41's literal text and the earlier #871 design (an automatic trigger after N minutes). Rejected: 0088 §2 item 7 keeps unanchored forks for manual action. An automatic re-seat chooses a fork, which is ADR 0064 Option 3.
5. **An expiry that disarms the #846 gate** (#871's second ask). Rejected: after expiry, unattested pages would apply. #860 removed the old queue-TTL disarm for this reason.
6. **A persisted authority catch-up log.** Rejected by D54. Missed events travel by S5's fetch-by-hash.
7. **A `retired` flag inside the live marker.** Rejected: the ADR 0066 §1 gates refuse whenever `fork_quarantine` is set. A flag would change all 26 paths and `ForkQuarantineIdentity` (ADR 0067). A sidecar keeps the live predicate unchanged.

## Decision

### §1 The admin terminal attestation (ATA)

An ATA is one signed statement by one admin about one node:

| Field | Meaning |
|---|---|
| `group` | stable group ID |
| `subject` | the agent ID of the node being recovered; no other node may use it |
| `signer`, `signer_public_key` | an ML-DSA-65 agent key; its SHA-256 must equal `signer` |
| `from_revision`, `from_state_hash` | the subject's current head |
| `sequence` | the state hash of every link after `from`, in order, ending at the attested terminal; 1 to 64 entries |
| `terminal_revision`, `terminal_epoch` | the terminal's revision and TreeKEM epoch (absent for GSS) |
| `issued_at_ms` | the signer's clock |

The preimage is `x0x.admin-terminal-attest.v1\0` followed by each field in table order, each length-prefixed (u32 LE). This follows the #818 hardening note: no NUL-separated variable fields. The domain differs from the owner join domain (`named_groups.rs:594–605`) and from `x0x.quarantine-clear-attest.v1`.

An admin issues an ATA only when all hold: it is an active admin on its own roster; its own record of the group has no marker and no armed gap record; `from` is a commit on its persisted `commit_log` (`src/groups/mod.rs:722`, cap 4096 at `:753`); and the sequence is its own chain from there. A longer gap is attested in segments of 64. An ATA is at most about 12 KB.

### §2 Automatic stale-base catch-up (self-recovery)

**Delivery.**
- *Join carry.* `JoinResultMessage::Result` (`named_groups.rs:1143`) gains a serde-default `admin_attestation`. The authority adds it only when the result carries a chain, the group has no owner v2 attestation to serve, and the joiner's current verified advert has the §5 bit. It signs once per `(attempt_id, from_revision)` and caches the ATA with the staged result. The authority is the sealer, so the signer is the terminal's committer.
- *Request path.* A node sends `group_attest_request` (§5) when it holds a marker, or an armed gap record that no page has advanced for 10 minutes. It asks the capable active admins on its own roster, lowest agent ID first (the D40 order). It sends at most one request per group per 60 s, backing off to 1 h.

**Verification by the subject.** It accepts an ATA only when: the signature verifies; `subject` is itself and `group` matches; `from` equals its own head; the signer is an active admin on its current roster and is not revoked (the check at `:10244`); and `issued_at_ms` is within 10 minutes of its own clock.

**Classification.** In `classify_refused_joiner_fork_chain`, a walk-valid served chain whose terminal and links match a verified ATA is a gap, not fork evidence. The node records `AnchoredGapRefusal` with the new reason `admin_attested_stale_base_gap` and `attested_chain_hashes = sequence`. It queues the terminal (`:11512–11523`) and requests catch-up, exactly as the owner-anchored branch does. This holds for both populations. In an owner-axis group the owner v2 attestation, when present, is used first. While an owner-attested record is armed, an ATA never re-arms it; a request then serves only to detect a fork (§3).

**Apply.** `armed_anchored_gap_sequence` arms for both reasons. Pages arrive by the existing paths: the ADR 0106 carry, TreeKEM catch-up pages, or (later) S5. Each link goes through the ordinary apply with all its checks, including the owner mandate on owner-axis `MemberAdded` links. In addition, the gate stops before a link after which the signer is no longer an active admin. The record stays armed.

**Conflict.** One ATA is armed per group at a time. A second valid ATA for the same `from` whose sequence diverges stops automatic catch-up. The node enters `reseat_required` with cause `attestation_conflict`. This adds no evidence class. Conflicting commits still install a marker through the existing evidence path.

**Self-clear.** When the node applies, under an armed ATA, the commit whose `(revision, state_hash, committed_by)` equals its marker's evidence, the evidenced commit is now on its own chain. The marker, and the matching `invite_lineage.fork_evidence`, retire with cause `attested_catchup`. On reaching the terminal, the gap record retires the same way, instead of being deleted (`:10343`). A marker from a sibling at a retained revision can never self-clear, because catch-up runs forward from the node's own head.

### §3 Forked nodes: manual re-seat only

A node needs a re-seat when an admin answers `not_on_chain` (its head is not on that admin's chain, so it is **forked**), when attestations conflict, or when every capable admin answers `base_beyond_retention`. It enters the typed waiting state `reseat_required`. Nothing changes automatically. This is the §2 item 7 wait.

A node whose head is on an admin's chain, but whose marker names a sibling it never applied, is not forked. It catches up as in §2, and its marker stays: an ATA never resolves a fork. Its state is `manual_clear_required`, and its exit is the existing local force clear (ADR 0066 §2), unchanged.

**The admin's manual act.** `POST /groups/:id/members/:agent_id/reseat`, with a non-empty `reason`, from the local API of an active admin. The CLI `x0x groups reseat` uses the same entry in `src/api/mod.rs`. No other code path builds an authorisation. The route refuses with a typed reason unless:
- the admin's own record of the group has no marker and no armed gap record;
- the subject is not Active on the admin's current roster, and is neither banned nor revoked (0088 §2 item 1). If the subject is Active, the admin removes it first through the existing removal route. That removal is an ordinary admin act, outside this ADR;
- a request from the subject is on record that this admin answered `not_on_chain` or `base_beyond_retention`, or that reports `attestation_conflict`, naming its quarantine identity.

The route then mints an InviteV4 addressed to the subject under the group's unchanged admission rules. It signs a `ReseatAuthorisation` (domain `x0x.reseat-authorisation.v1`) over the group, the subject, the quarantine identity, the invite secret hash, the invite base revision and hash, the signer, a hash of the reason, and the invite's expiry. It stores the authorisation until it is consumed or expires, one per `(group, subject)`, and sends it on the subject's next request (or at once).

**The subject's self-recovery.** It consumes an authorisation only when: the signature verifies; the signer is the invite's authenticated inviter and an active admin on the invite base roster; the subject is itself; the quarantine identity equals its live one (ADR 0067); the invite has not expired; and the base does not seat the subject. It then retires its marker and gap record with cause `reseat`. It drops the group's local key material and pending events, keeps ADR 0023 history, and redeems the invite through the ordinary join path. This is the one new exception to ADR 0107's rule that quarantined state is not a retryable remnant. It applies only under a verified authorisation.

### §4 Retired state and persistence (ADR 0085)

Retirement moves the record out of the live fields: `fork_quarantine` becomes `None`, and so do `anchored_gap_refusal` and `fork_evidence`. Every existing gate and ADR 0068's on-clear drain therefore see an ordinary clear. The retired record goes to a new sidecar, `<data_dir>/group-recovery.json`:

- `{"version": 1, "retired": {<group>: [...]}, "reseat_issued": {<group>: [...]}}`. Each retired entry holds the verbatim record, the cause, the time, and the ATA or authorisation digest that justified it. At most 16 retired entries per group are kept, oldest dropped and logged.
- A retired identity is never re-installed from the same evidence or the same refused terminal.
- **Write order.** The entry is written durably as `pending`. Then the live clear runs through `persist_named_groups_quarantine_clear_gated` (`named_groups.rs:5309`, PR #1181), durable before publish. Then the entry becomes `retired`. On load, a `pending` entry whose identity is still live is dropped; otherwise it is finalised.
- **Fail closed.** An unknown `version` or an undecodable file is refused and left byte-identical. Groups still load. The suppression list is then empty, so evidence may re-quarantine (the safe direction).
- **Downgrade.** An older binary never reads or writes the sidecar, so it stays byte-identical. Live state is consistent: no marker, head at the recovered revision. A replayed retired evidence may re-quarantine on the older binary, which is fail-closed. Upgrading again restores the list. `named_groups.json` gains no field, so an older binary's rewrite loses nothing. It gains one value, the reason `admin_attested_stale_base_gap`. An older binary does not arm its gate on that reason, so a catch-up in progress continues with today's per-link apply, and the record is kept.

### §5 Wire and the capability bit (ADR 0093)

This ADR proposes **bit 3, `group_terminal_attest_v1`**: "issues and verifies ADR 0109 attestations, answers `group_attest_request`, and consumes re-seat authorisations." Bit 3 is the lowest unallocated bit. If another slice is Accepted first with bit 3, this ADR takes the next free bit at acceptance, and the registry row is added then.

- `group_attest_request` (typed DM): group, requester, head revision and hash, and, when present, the live quarantine identity and the cause of any `reseat_required` state.
- `group_attest_response`: one of `attested {ata}`, `on_chain {admin_head}` (nothing to attest), `not_on_chain {admin_head}`, `reseat {authorisation, invite}`, or `refused {reason}` (`attester_quarantined`, `attester_behind`, `not_a_member`, `banned_or_revoked`, `base_beyond_retention`).
- Requests go only to admins whose current verified advert has the bit. Unknown, stale or card-only state is not positive support (ADR 0093), so nothing is sent and the wait names "no capable admin". All messages stay within the 49,152-byte DM budget.

| Pair | Behaviour |
|---|---|
| New joiner, old authority | No `admin_attestation`. Today's `signer_only` marker, then the request path once a capable admin is online |
| Old joiner, new authority | Joiner's advert lacks the bit, so the key is omitted. Result bytes are identical to today |
| New node, only old admins online | No request is sent. Typed `awaiting_attestation`. The force clear works as today |
| Old node | Never receives requests or authorisations. Unchanged |

### §6 Security (L4)

**Rule added.** In a group without an owner v2 attestation for the gap, a walk-valid chain matching a verified ATA from an active admin is a stale-base gap, not fork evidence. Under that ATA, a marker whose evidence the node then applies retires. This relaxes the #818 classification. For owner-axis groups it relaxes ADR 0064's owner-only clear, as 0088 §3 assigns.

**Argument.** Every adopted link is a commit the node would apply had gossip delivered it in order. ADR 0016 already lets any active admin commit, and any member applies a valid linking commit. The ATA changes only the classification of a chain the node holds. It changes no check on any link. The signer must stay an active admin through the chain. Owner mandates still bind owner-axis admissions (ADR 0064 §1b). A marker whose evidence is off the attested chain never clears.

**Unchanged.** Signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion all stay fail-closed. Re-seat adds no admission rule: the subject joins by an ordinary invite.

**D41.** An ATA and an authorisation act only on `subject`. They never install or clear a marker on the signer or on a third node, and are never gossiped. Neither causes a commit by itself. A re-seat's only commits are the admin's own removal and the ordinary join seal.

**Residual (accepted by D34(1)).** In an ownerless group, an admin who was removed on the canonical chain but is still an admin on the node's stale base can attest its own branch. The node then follows that branch. This is the same exposure gossip ordering already gives. It affects that node only. Canonical evidence arriving later installs a marker that the removed admin's ATA cannot clear.

### §7 Typed states (L3)

`GET /groups/:id` and the ADR 0066 §5 refusal body gain an additive `recovery` object. Its `state` is one of `catching_up {signer, terminal_revision}`, `awaiting_attestation {asked, next_retry_at, reason}`, `manual_clear_required {quarantine_identity}`, `reseat_required {cause, quarantine_identity}` or `reseat_authorised {signer, expires_at}`. Each names what it waits for. An admin sees pending forked members at `GET /groups/:id/recovery` (in memory, 32 per group, 24 h).

### §8 What is superseded

| ADR | Text superseded in part | Replaced by |
|---|---|---|
| 0064 Decision §3 | A marker clears only on an owner-anchored commit; a non-owner-axis marker is preserved indefinitely and its recovery is unresolved | A stale-base node also retires its own marker under §2. A forked node is re-seated only under §3. Owner-anchored clears are unchanged |
| 0066 §2 | A `no_anchor` marker is never cleared by any commit, and the manual clear is its only exit | A `no_anchor` marker also retires under §2, for its own node only (D41). The manual clear stays, and §3 adds the admin re-seat for forked nodes |

## Consequences

### Positive

- Ordinary-group stale-base joins converge instead of quarantining. Home joins converge with only a promoted admin online.
- #871 gets an audited exit that keeps the gate's protection.
- Every recovery leaves a durable record naming who attested it and why.

### Negative / Trade-offs

- The removed-admin residual (§6) is real for ownerless groups.
- A re-seat of an Active subject costs a removal and a rekey, until S8 (b) offers a re-Welcome.
- Catch-up bytes still depend on the existing transport (DM-paged TreeKEM catch-up, in-memory event logs) until S5.

### Neutral / Operational

- New counters: `admin_attest_issued`, `admin_attest_applied`, `quarantine_retired{cause}`, `reseat_authorised`.
- The release notes drop the "mint just-in-time invites" mitigation for #818 once S3 ships.

## Validation

**W3-H cases (#1164), red before the fix (D16, D54):**
- **H-S3-a (#818 part 2).** Ordinary TreeKEM group; admin A, members M1 and M2. A mints invite I at revision r. A removes M2 at r+1, a commit ADR 0106 never carries. J redeems I; A seals J at r+2. **Red:** J holds a `no_anchor` `signer_only` marker, is never Active with keys, and gets 409 on member routes.
- **H-S3-b (L1, any one admin).** As H-S3-a with a second admin B online throughout. A runs the previous release, so J is quarantined. Then A goes offline. **Red:** J stays quarantined.
- **H-S3-c (#871).** OwnerCertified group: owner O and admins A and X. X is partitioned; O removes X at r+1, and later seals J's stale-base add at r+2 with a v2 attestation, which arms J's gate. Before any page arrives, J applies X's sibling r+1'. **Red:** the gate refuses every page, J never reaches r+2, and no typed state is shown.

**Exit test.** H-S3-a: J ends Active with keys at r+2, never holding a marker. H-S3-b: J retires its own marker (cause `attested_catchup`) with only B online. H-S3-c: J shows `reseat_required` and stays there unchanged for two backoff periods. Then an admin removes J and calls the re-seat route. J retires both records (cause `reseat`), rejoins, holds keys, and applies the next commit. Each step needs only one admin online.

**Negative controls (D41, L4).** An ATA delivered to another member does nothing. Issuing or consuming any ATA produces no commit on any node. X's ATA over its own branch leaves a marker in place when the marker's evidence is not on that branch. Forged, expired, non-admin, wrong-subject or stale-identity authorisations are refused with typed reasons. A forked node never re-seats without the manual call. A node on the admin's chain that holds a sibling marker catches up and keeps the marker (`manual_clear_required`).

**Non-regressions.** These stay green unchanged: `stale_base_treekem_joiner_owner_anchored_gap_is_not_fork_evidence`, `stale_base_treekem_sibling_terminal_with_genuine_owner_attestation_quarantines`, `forking_catchup_responder_adopts_nothing_under_anchored_gap`, `honest_multicommit_gap_converges_page_by_page_under_gate` and `adr0064_s4_removed_admin_fork_to_joiner_quarantines` (`hs_f2_membership_cluster.rs`); `adr0066_ordinary_group_conflict_sets_a_no_anchor_marker` and `adr0066_unauthenticated_conflict_never_quarantines_an_ordinary_group` (`fork_quarantine.rs`); the #1103 fault cells from PR #1181; and the ADR 0106 carry tests.

**Mixed version and downgrade.** H-S3-m runs each row of the §5 table with one previous-release node. An old authority's result bytes are compared with today's. A node holding retired entries is downgraded: the sidecar must stay byte-identical, groups must load with no live marker, and upgrading again must restore the list. The sidecar also gets a fixture written by the first release that ships it (ADR 0085 rule 6).

**Governance.** This ADR stays Proposed until David accepts it. S3 code merges only after acceptance (ADR 0087 rule 8) and after the W3-H cases above are red (0088 §4).

**Review trigger.** Revisit when S5 lands catch-up as control blobs, or when S8 (b) offers a re-Welcome for the re-seat.

## Open questions for David

1. **Owner-axis forked nodes.** 0088 §3 requires manual authorisation for every forked node, including #871's owner-axis population. But §2 item 7 lists only ordinary unanchored forks. Is the owner-axis wait an item 7 entry, or should the owner's own attestation re-seat that node automatically?
2. **Subject consent.** Is the admin's manual authorisation enough, as 0088's wording implies? Or must the subject's operator also confirm the re-seat?
3. **Beyond retention.** A stale base older than every admin's 4,096-commit log gets `base_beyond_retention` and so needs a manual re-seat. Is that acceptable under L2, or must S5 complete it automatically?
4. **Who acts in §2 item 7.** ADR 0066's "manual clear" is the node's own operator. This ADR's re-seat is a group admin. The draft keeps both. Is that the intent?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

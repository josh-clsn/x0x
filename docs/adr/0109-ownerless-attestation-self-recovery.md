# ADR 0109: Ownerless Attestation: Stale-Base Self-Recovery and Manual Re-seat (0088 S3)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model review r1: REQUEST-CHANGES, 16 findings, addressed in r2); further review TBD
- **Slice:** S3 of [ADR 0088](./0088-group-liveness-contract.md)
- **Supersedes:** in part, upon acceptance: ADR 0064 Decision §3 and ADR 0066 §2 (as 0088 §3 assigns to S3)
- **Amends:** upon acceptance: [ADR 0088](./0088-group-liveness-contract.md) §2, with one named entry, "Owner-axis forked node" (D121, §3); [ADR 0085](./0085-persisted-binary-formats-are-versioned.md) rule 4, for damaged S3 sidecar files of a supported version only: automatic quarantine and rebuild (D120, §4). ADR 0085 rule 5 is not amended. ADR 0088 and ADR 0085 are Accepted and are not edited.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core
- **Related:** rulings D34(1), D41, D54, D60, D16, D43, D64, D65, D77–D83, D97, D119–D121; #818 (part 2), #871, #1164 (W3-H harness), #1103 and PR #1181 (merged), PR #1190 (ADR 0107 implementation); ADR 0012, 0016, 0023, 0064, 0066, 0067, 0068, 0085, 0087 rule 8, 0093, 0094, 0106, 0107, 0114. Related work only: the join-artifact serving lifecycle note (`docs/design/join-artifact-serving-lifecycle.md`, on the #1190 branch).

## Context

A node can hold a quarantine or a wait that has no exit. Three shapes are live.

**#818 part 2, skewed clocks: a legitimate gap is quarantined.** An invite stub seeds its state and roster clocks from the base state revision (`src/server/routes/named_groups.rs:17567–17570`). The authority bumps its roster clock only on membership changes (for example `:19407`, `:20981`). A rename bumps only the state clock. So when renames precede the mint, a later `MemberAdded` carries a roster revision at or below the stub's, and the frontier gate does not queue it (`:7324–7327`). The apply fails. A TreeKEM joiner never adopts across the gap (`:4828–4837`). The refused chain reaches `classify_refused_joiner_fork_chain` (`:4443`), which exempts a gap only under the owner's v2 terminal attestation (`:4504`). By the #818 design decision (`:4494–4503`), an ownerless group cannot tell a gap from a fork, so the joiner gets a `signer_only` marker (`:4558–4591`) with `no_anchor: true` (`:4301`). No commit clears it (`src/groups/mod.rs:347`, `:369`). The force clear (`named_groups.rs:14884`) leaves the node at its stale base. ADR 0106 never carries a gap that holds anything but `MemberAdded` events.

**#818 part 2, aligned clocks: the gap queues but cannot apply.** With aligned clocks the frontier gate queues the add as `revision_gap` (`:7349`, `:11182–11205`) and requests catch-up. The joiner is pre-Welcome. A `MemberRemoved` page needs a local TreeKEM group and is refused without one (`:12145–12150`). Only `MemberAdded` has a pre-Welcome state-only apply (`:11912–11927`). TreeKEM catch-up serves only membership events (`:7072–7132`), so a rename or a role change in the gap is never served at all. The join attempt times out.

**#871: a forked head has no escape.** The #846 gate arms from the durable `AnchoredGapRefusal` (`src/groups/mod.rs:122`; `armed_anchored_gap_sequence`, `named_groups.rs:10171`). Each page must link from the current head and match the attested sequence (`:10200`, `:10282`). A forked head can never link. The gate refuses silently, with no marker (`src/server/routes/named_groups/tests/hs_f2_membership_cluster.rs:7215`). It retires only at the terminal revision (`:10343`). The escape is leave and rejoin.

Home shares the first two defects whenever the owner install did not seal the gap. Only an owner install signs the head attestation (`:33364–33373`). Under D81, this ADR covers Home only once the released-binary gate in §4 passes.

**Rules broken.** All three break 0088 **L2**: a stale base is not a fork, and §2 does not list these waits. The Home case breaks **L1**: catch-up waits on the owner device. #871 and the aligned-clock shape break **L3**: the wait is silent.

**Rulings.** D34(1): in ownerless groups, an active admin's signed terminal snapshot attests stale-base catch-up, as a mandate layer above ADR 0016, and gives #871 a re-seat path. D41: self-recovery only. The snapshot lets a node adopt the attested state and clear its own marker. It never marks another member forked, evicts anyone, or clears anyone else's marker. 0088 §3: stale-base catch-up is automatic; a forked node is re-seated only under an admin's explicit manual authorisation (§2 item 7). David ruled this ADR's own questions on 2026-10-04 (D77–D83), and a second round that touches it (D119–D121); see Rulings and open questions.

## Decision Drivers

- A stale base converges with any one admin online (L1).
- A fork is never resolved automatically (ADR 0064 Option 3, ADR 0066 §2, 0088 §2 item 7).
- An attestation acts only on the node it names (D41).
- Every link passes every existing apply check (L4). Any rule this slice adds is named with its argument.
- Every block this slice adds or touches ends in a typed refusal or a typed wait (L3, D64).
- `named_groups.json` and `home-suite-groups.json` never change format. Released daemons parse them with `serde_json` and abort startup on error (`src/server/mod.rs:735–737`, the #451 failure).
- Byte transport stays where it is. Control blobs and fetch-by-hash belong to S5 (D54).

## Considered Options

1. **Admin terminal attestation, self-recovery, manual re-seat, own sidecar** (chosen).
2. **Founder or creator key as the anchor.** Rejected by ADR 0066 R1: an unreviewable eviction oracle.
3. **A quorum of admin heads.** Rejected by ADR 0064 Option 6 and ADR 0066 Option 4.
4. **Automatic re-seat under any admin's snapshot** (D41's literal text; the earlier #871 design), or under the owner's attestation in owner-axis groups. Rejected: 0088 §2 item 7 keeps forks for manual action, and an automatic re-seat chooses a fork (ADR 0064 Option 3). D78 keeps owner-axis forked nodes manual too, and D121 records that wait as a named §2 entry.
5. **An expiry that disarms the #846 gate** (#871's second ask). Rejected: unattested pages would then apply. #860 removed the queue-TTL disarm for this reason.
6. **A persisted authority catch-up log.** Rejected by D54.
7. **New fields or a new envelope in the legacy JSON stores.** Rejected: any reformat bricks a downgrade (#451; ADR 0085 rule 5; ADR 0094).
8. **Defer the removal gap until S5.** Rejected: S5 changes transport, not the pre-Welcome apply rule, so the aligned-clock shape would stay stuck.
9. **Membership pages only, without applying the served chain.** Rejected by David (D82): a gap holding a role change or a rename is never served by TreeKEM catch-up (`named_groups.rs:7072–7132`), so the promoted-admin case (L1) would stay stuck.
10. **Narrow who may attest** to the joiner's sealer, or to the owner in owner-axis groups. Rejected by David (D77): each narrowing brings back a wait on one device, which L1 forbids.
11. **Keep Home excluded until S7.** Rejected by David (D81): Home is the core R3 case, and a released-binary gate keeps the lift fail-closed (§4).
12. **Leave an unreadable sidecar for the operator to move aside** (ADR 0085 rule 4 today). Rejected by David (D120): that wait has no bound and is not on 0088 §2.
13. **Read owner-axis forked nodes into 0088 §2 item 7.** Rejected by David (D121): an Accepted ADR changes by amendment, not by reading.

## Decision

### §1 The admin terminal attestation (ATA)

An ATA is one signed statement by one admin about one node:

| Field | Meaning |
|---|---|
| `group` | stable group ID |
| `subject` | the agent ID of the node being recovered; only that node may use it |
| `attested_by`, `signer_public_key` | an ML-DSA-65 agent key; its SHA-256 must equal `attested_by`. It is distinct from a terminal's `committed_by` (`src/groups/mod.rs:133`) |
| `from_revision`, `from_state_hash` | the subject's head |
| `sequence` | the state hash of each link after `from`, in order: one segment of 1 to `ATA_MAX_LINKS` entries |
| `segment_terminal_revision`, `segment_terminal_epoch` | the last link's revision and TreeKEM epoch (absent for GSS) |
| `issued_at_ms` | the signer's clock |

The preimage is `x0x.admin-terminal-attest.v1\0` followed by every field in table order, each length-prefixed (u32 LE), per the #818 hardening note. The domain is distinct from the owner join domain (`named_groups.rs:594–605`) and from `x0x.quarantine-clear-attest.v1`.

**Issuance.** An admin answers only after cheap checks, in this order:
1. The DM is verified and its sender equals the requester field.
2. Limits are applied to every request, member or not, before anything else. They are a per-requester rate and responder-wide caps on requests, concurrent builds, signatures and bytes, plus a cache keyed by `(group, subject, from_state_hash)` that is reused until expiry. A request over a limit gets `refused {rate_limited}` and nothing more. The values are in §11 (D83).
3. Classification: the requester must be an Active member on the admin's current roster, not banned, with an unrevoked agent. A non-member gets `refused {not_a_member}`, or `reseat {..}` when an unconsumed authorisation names it. That path does no signing and no log walk. It adds at most one entry per requester to the bounded recovery list (§8).

Then it signs only if: it is an active admin on its own roster (else `refused {not_an_admin}`); its own record of the group has no marker and no armed gap record (else `attester_quarantined`); `from` is a commit in its persisted `commit_log` (`src/groups/mod.rs:722`, cap `:753`); and the segment is its own chain from there. A head newer than the admin's own gets `attester_behind`. A base older than its log gets `base_beyond_retention` (§3, D97).

### §2 Automatic stale-base catch-up (self-recovery)

**Delivery.**
- *Join carry.* `JoinResultMessage::Result` (`named_groups.rs:1143`) gains a serde-default `admin_attestation`. The authority adds it for the first segment of the served chain when four things hold: no owner v2 attestation is served, the joiner's current verified advert has the §5 capability, §6 admits the exchange, and, for a Home-policy group, Home activation is on (§4). It signs once per `(attempt_id, from_revision)`. The joiner then applies its served chain under the pre-Welcome rule below and replays its own terminal, with no catch-up round trip.
- *Requests.* The node sends `group_attest_request` when it holds a marker, an armed gap record with no progress for `GATE_STALL`, or an exhausted segment (below). For a Home-policy group it sends one only while Home activation is on. Targets are tried in this order: capable admins on its roster, lowest agent ID first (the D40 order); then capable members on its roster; then agents that sent it a signature-verified commit for this group. A member promoted after the stale base can therefore answer. Retries back off as set in §11 (D83). Between attempts the node shows `awaiting_attestation` (§8).

**Verification and signer eligibility.** The subject accepts an ATA only when the signature verifies, `subject` and `group` match, `from` equals its own head, `issued_at_ms` is within `ATA_ARM_WINDOW` of its clock, and `attested_by` is not revoked (the check at `:10244`). The signer is **verified** when it is an active admin on the subject's current roster. Otherwise it is **provisional**. David ruled that any active admin on the node's own roster may attest, in both group types, and accepted the exposure in §7 (D77). A provisional ATA has no gate authority: it arms nothing, blocks no page, causes no conflict and retires nothing. Its promotion path must be verified first. That path is a prefix of the ATA's own sequence, ending at a link that makes the signer an active admin, and every committer on it is checked against its predecessor roster. A joiner verifies the path by walking its kept served chain (`validate_alternate_chain`) without applying it. Any other node verifies it by applying those links through the ordinary path, ungated. Either way, the walked or applied hashes must equal the ATA's prefix. Only then does the ATA arm, for the rest of its sequence. If the signer stops being an active admin after an applied link, the gate stops there. A provisional ATA whose path does not verify is dropped, and the node shows `awaiting_attestation {reason: provisional_unverified}`.

**Arming.** A verified ATA in a join result arms the gate whether the terminal reaches the classifier or is queued first by the frontier gate (`:7349`). In the classifier, a walk-valid served chain whose first segment matches a verified ATA is a gap, not fork evidence. The node then queues the terminal, as the owner-anchored branch does (`:11512–11523`). The armed record is `AnchoredGapRefusal` with reason `admin_attested_stale_base_gap` and `attested_chain_hashes = sequence`. The full ATA is kept beside it in the S3 sidecar (§4). An owner-attested record keeps precedence. While it is armed, an ATA never re-arms it; a request then only detects a fork (§3).

**Segments.** The cursor is the subject's head. When the head equals the segment's last hash, the segment is exhausted. The gate stays armed with an empty remaining sequence, which admits nothing (`:10200`), and the node requests the next segment from its new head. Until that arrives it shows `awaiting_attestation {reason: segment_exhausted}`. A segment that does not match the served chain's next hashes, where those are known, is a conflict. An armed ATA with no progress for `ATA_ARMED_LIFETIME` is renewed from the current head; until a renewal arrives the gate stays armed and the node shows `awaiting_attestation {reason: renewal_due}`. A renewal must agree with the remaining sequence. `ATA_ARM_WINDOW` applies at arming only. The sidecar keeps the served chain, the active ATA and the queued terminal. After a restart the node re-verifies the stored ATA's signature and its signer's eligibility against the current roster, then resumes at the cursor.

**Conflict.** Two valid ATAs for one head whose sequences diverge stop automatic catch-up. Nothing past the common prefix applies. The node enters `reseat_required {attestation_conflict}`. No evidence class is added. Conflicting commits still install a marker through the existing path.

**Pre-Welcome link apply (new rule (b), §7; D82).** A pre-Welcome node (no local TreeKEM group for this group, and not Active on its roster) may apply one link state-only. The link must be in an armed attested sequence, owner or admin, whose terminal is the node's own `MemberAdded`. The link comes from a catch-up page or from the node's own served chain (`RetainedCommit`, `named_groups.rs:1186`).
- It must link from the node's head and pass every `validate_apply` check.
- A `RetainedCommit` link must also pass `validate_alternate_chain` (`src/groups/state_commit.rs:1056`), with its roster and metadata matching the commit's roots.
- A link that changes the policy hash or a GSS security binding is refused, as #458 r6 item 4 refuses it.
- The TreeKEM commit is skipped. No tree or epoch is taken from the chain; the node's keys come only from its own Welcome at the terminal.

This extends the existing `MemberAdded` rule (`:11912–11927`) to every link kind, including renames and role changes, as David ruled (D82). It is ADR 0106's deferred option 2, made per link and gated by an attestation. A joiner that installs a `signer_only` marker keeps its served chain and its refused terminal event in the sidecar, so a later ATA can use them. A stale node that is not pre-Welcome applies links by the ordinary path. Its non-membership links still wait for S5.

**Retirement, independent per record.**
- A marker, with its matching `invite_lineage.fork_evidence`, retires (cause `attested_catchup`) when the evidenced commit `(revision, state_hash, committed_by)` is durably applied under a verified ATA. A sibling marker can never meet this condition.
- The armed gap record retires only when its exact terminal `(terminal_revision, terminal_state_hash)` is durably applied. A marker's retirement never touches it.

**Join attempt (D64).** The join-timeout finalizer and the 120 s TreeKEM poll are blocks S3 touches, so David's D64 ruling binds their end. While an armed record owns the stub, the finalizer keeps the stub and its row. When the poll ends on an attempt that S3 holds (an armed record, or a marker whose served chain S3 kept), the attempt reports the join state that mirrors the `recovery` object (§8): `catching_up`, `awaiting_attestation`, `readmission_required`, `reseat_required` or `recovery_deferred`. It never reports a bare `TimedOut`. S3 does not change the poll's length. Keys still come from the authority's staged Welcome, whose 10-minute lifetime ADR 0107 bounds. If that expires, the attempt ends with ADR 0107's typed outcome and exit, and the `recovery` object keeps its own state. Authority re-Welcome is S8 (b).

### §3 Forked nodes: manual re-seat only

A node needs a re-seat when an admin answers `not_on_chain` (its head is not on that admin's chain, so it is **forked**), when attestations conflict, or when it is contained and its requests get only `not_a_member` (it was removed; 0088 §2 item 6 refuses its catch-up). It enters `reseat_required`. Nothing changes automatically. This holds in owner-axis groups too: David ruled that an admin re-seats an owner-axis forked node (#871) by hand (D78). An owner attestation never re-seats a node. 0088 §2 item 7 names only an ordinary group forked with no owner anchor, so David ruled that this wait is a named amendment, not a reading of item 7 (D121).

**Named amendment to 0088 §2 (D121).** This ADR amends ADR 0088 §2 with one named entry, ruled by David (D121): **"Owner-axis forked node."** In a group with an owner anchor, a node whose head is on no admin's chain, or whose admin attestations conflict, stays contained until an admin re-seats it by hand. No owner attestation re-seats it, and no fork is resolved automatically.
- *Kind:* a waiting entry, like item 7 (0088 L3).
- *Typed state:* `reseat_required {cause, ref, needs_owner_key: true}`, where `cause` is `not_on_chain`, `attestation_conflict` or `reseat_failed` (§8).
- *Exit:* a manual re-seat (this section) by an admin whose install holds the group owner's USER key. The re-seat mints an InviteV4, and today's mint refuses an owner-axis invite without that key (`named_groups.rs:17174–17184`). So this exit depends on an owner-key device, which 0088 L1 forbids. An admin without the key gets `owner_key_unavailable`. Whether any active admin may re-seat instead is Open question 2, which blocks Accept.
- *L4:* the entry relaxes no check. It names, and types, the wait that #871 already has in silence.
- *Mixed versions:* a released node keeps today's silent #846 gate and cannot show the state. A node with the §5 capability shows it.
- *Harness:* H-S3-c and H-S3-c2.

ADR 0088 is Accepted and is not edited.

**Beyond retention (D97, D119).** `base_beyond_retention` means the node's head is older than that admin's retained log. It is not a fork and not a re-seat trigger. The node keeps asking its other targets under the §11 backoff, because another admin may retain its base. When every admin it has reached refuses with `base_beyond_retention`, and none attests, the node enters `readmission_required {cause: base_beyond_retention}`. David ruled that this case is admission, not catch-up (D97). He then widened S8 (b), so that ADR 0114 repairs confirmed members too (D119). S3 routes the state to ADR 0114's repair for the node's seat: its never-confirmed repair for a never-confirmed seat, and its **retention re-Welcome** for a confirmed member (D119). ADR 0114 owns both designs, their acceptance rules and their typed outcomes, including which seats qualify. S3 adds no re-Welcome and never re-seats on this basis. Until that repair is Accepted and in effect, and wherever ADR 0114 gives the seat no repair or the admin lacks its capability, the exit is D43's manual remove and re-invite. The state's `exit` field names whichever applies. For a contained node, the admin can carry out that re-invite through the §3 re-seat route on a `Removal` basis. Once ADR 0114's retention re-Welcome (§7) is in effect, this case needs no §2 entry. Once S5 is in effect, the node also tries S5's catch-up walk before entering this state, and S5 reports a failed walk as `catchup_beyond_retention`, with the same exit (ADR 0111 §4). S5's bytes alone never retire a marker or open rule (b): both still need a verified ATA (§2). The state is typed and visible, and any later attestation moves the node to `catching_up`.

A node whose head is on an admin's chain, but whose marker names a sibling it never applied, is not forked. It catches up, and its marker stays: an ATA never resolves a fork. Its state is `manual_clear_required`, with the existing local force clear (ADR 0066 §2) as its exit. David ruled that both exits stay (D80): the node operator's clear serves this on-chain case, and the admin's re-seat serves a forked node.

**Recovery token and basis.** A node's live containment is a `RecoveryRef`: either `Marker(identity)`, the ADR 0067 identity, or `Gap(reason, head_state_hash, terminal_revision, terminal_state_hash)`, which covers the gate-only #871 state. A request carries the node's live `RecoveryRef`s. An authorisation names one **basis**: either one `RecoveryRef` the admin was told about, or `Removal(revision, state_hash)`, the subject's removal commit.

**The admin's manual act.** The admin calls `POST /groups/:id/members/:agent_id/reseat` with a non-empty `reason` and the `basis` it acts on, on its local API. The CLI `group reseat` uses the same entry in `src/api/mod.rs`. Nothing else builds an authorisation. The route checks the following in order and refuses with the first failing check's typed reason:
- `reason` is non-empty (`reason_required`);
- the admin's own record of the group is uncontained (`admin_contained`);
- the subject is not Active on the admin's roster (`subject_active`) and is neither banned nor revoked (`subject_banned_or_revoked`; 0088 §2 item 1). If the subject is Active, the admin first removes it through the existing removal route, an ordinary admin act outside this ADR;
- the basis is either a `RecoveryRef` from a request this admin answered with `not_on_chain`, or one the subject reported as `attestation_conflict`; or a `Removal` commit of the subject (a removal, not a ban) that is on the admin's own verified chain (`basis_unknown`). The `Removal` basis covers a removed forked node whose requests get only `not_a_member`;
- in a group with an owner axis, the admin's install holds the owner's USER key (`owner_key_unavailable`). This is today's InviteV4 mint refusal (`named_groups.rs:17174–17184`, mapped to HTTP 409 at `:17369–17372`). The route checks it before it signs or stores anything.

The route mints an InviteV4 addressed to the subject under the group's unchanged admission rules. In an owner-axis group that mint is countersigned with the owner's USER key, so only an owner-key device can re-seat there until Open question 2 is ruled. It signs a `ReseatAuthorisation` (domain `x0x.reseat-authorisation.v1`) over the group, subject, basis, invite secret hash, invite base revision and hash, signer, reason hash and expiry. It keeps the authorisation in its sidecar until consumed or expired, one per `(group, subject)`.

**The subject's self-recovery, journalled.** David ruled that the admin's authorisation is enough: the subject applies a valid one with no human step, and its operator is not asked (D79). The subject consumes an authorisation only when all hold: the signature verifies; the signer is the invite's authenticated inviter and an active admin on the invite base roster; the subject is itself; a `RecoveryRef` basis equals a live one, or a `Removal` basis is paired with any live `RecoveryRef` (the node is contained); the invite has not expired; and the base does not seat the subject. Otherwise it refuses with `authorisation_refused {cause}`, where `cause` names the failed check, and stays `reseat_required`. Then:
1. It writes a re-seat journal: the authorisation, the invite, and a digest of the full current record.
2. It joins into a **staging record** and staging TreeKEM state, outside the live map. Ordinary join validation and ADR 0107's guards apply to it. The live record keeps its marker, its gate and every ADR 0066 refusal throughout. Because the join is not against the live row, the route's idempotent-success path (`:18232–18345`) cannot short-circuit it.
3. When the staging record is Active with keys installed and durable, one transaction swaps it in. The old record goes to the retired list (cause `reseat`), and the journal closes. The swap uses the existing TreeKEM persist transaction, so a staged roster is never paired with the forked tree.
4. On failure (expiry, refusal, timeout), the staging record is discarded and the live record is unchanged. The state becomes `reseat_required {reseat_failed}`. A crash resumes from the journal's phase, and only a durable swap retires anything.

This is the one exception to ADR 0107's rule that quarantined state is not a retryable remnant. It applies only under a verified authorisation.

### §4 Persistence: the S3 sidecar (ADR 0085)

The legacy stores never change format. S3 state lives in its own files: `<data_dir>/group-recovery/<stable_group_id>.grecov`. No released scan reads that directory or extension (the scans read `treekem/*.journal` at `named_groups.rs:28410` and `*.hsjournal` at `:29945`).

- **Format.** The magic `X0GRCV1\0` is followed by a postcard `GroupRecoveryV1`, consumed exactly. Embedded `GroupInfo` records are JSON documents carried as length-prefixed bytes, because `GroupInfo` uses `skip_serializing_if`, which a positional encoding cannot carry. The fields are: `generation`, `rebuilt_from` (empty unless the file replaced a quarantined one), `served_chain`, `active_ata`, `queued_terminal`, `authoritative_record`, `reseat_journal`, `staging_record`, `issued_reseats` and `retired`.
- **Placeholder (after the #451 pattern).** While an admin-reason gap record is armed, the group's entry in each legacy file that a released binary loads is an S3 placeholder. That is `named_groups.json`, plus `home-suite-groups.json` for an OwnerCertified group, because released binaries load both and the sidecar entry wins (`named_groups.rs:30507–30536`). The placeholder starts from `legacy_safe_placeholder` (`:32794–32813`), which keeps identity, chain head and containment. Unlike it, the S3 placeholder keeps `members_v2` **non-empty with every entry Removed**, so no seat is Active. Released v0.45 and v0.46.1 run `migrate_from_v1` on every loaded entry (`:30331`, `:30413`). On an empty `members_v2` that seats the creator as Admin (`src/groups/mod.rs:2253–2282`); with a non-empty, all-Removed roster it does nothing, so no admin exists. The authoritative record is `authoritative_record`. A released daemon starts, sees an inert group with no admin, mints no invite, seals no commit and applies no page. For a Home-policy group, the `home-suite-groups.json` placeholder also keeps the group's policy and `home` metadata, which released Home-Suite binaries parse, as ADR 0114 §5 does; the `named_groups.json` entry keeps the #451 form. Home placeholders are written only under the Home gate below.
- **Home groups (D81).** A Home-policy group is one with `home` metadata, or whose policy is the Home policy for its owner (`is_home_candidate`). David ruled that S3 may cover it only behind a released-binary test (D81), as cross-slice rule 1b allows and ADR 0114 §5 requires for its own placeholder.
  - *Home activation* means writing an S3 Home placeholder, and issuing, requesting or arming an ATA for a Home-policy group. It ships switched off.
  - *Gate.* Case H-S3-home (Validation) runs the released v0.45.0 and v0.46.1 binaries on candidate data directories that hold the S3 Home placeholder in both views. No owner-sync canonical Home pointer is stored or reachable. The case covers an owner install (user key and agent certificate), a non-owner Home device, and the creator's own data directory. It runs through two reloads and every provisioning pass the released binary makes, including v0.46.1's deferred pass after `HOME_POINTER_SYNC_WAIT`. It passes only if, on both binaries and in every variant: the binary starts; no group is created, so the set of group IDs is unchanged; `home.json` stays byte-identical, or stays absent; and rule 1b's checks hold (no Active and no admin seat in either view, invite mint and `POST /home/seat` refused, no commit).
  - *Block.* A release turns Home activation on only when its own placeholder bytes pass H-S3-home on both released binaries, and its release gate sheet links that evidence. If any variant fails on either binary, Home activation stays off for every Home-policy group. The case is re-run whenever the S3 placeholder writer changes.
  - *While off.* The node keeps today's state (marker or queue) and reports `recovery_deferred {cause: home_gate_closed}`. That is a known L1/L2 gap that S3 leaves open, not a §2 entry. S7 owns the Home downgrade otherwise.
  - *Risk.* The authors' reading of the released code predicts that the owner-install variant fails. Released `find_home` needs an Active local seat (v0.46.1 `src/server/routes/home.rs:406`; v0.45.0 `:405`), which rule 1b forbids. With no pointer, the provisioning pass then creates a fresh Home (v0.46.1 step 4 at `:1142`, after the 90 s deferral; v0.45.0 `:851`, with no deferral). If the test confirms this, Home stays off until S7.
  - The §3 re-seat writes no placeholder, so this gate does not apply to it.
- **Re-upgrade.** A released binary never changes the sidecar's bytes. The re-upgraded daemon lets the sidecar replace the placeholder and unions containment (`union_containment_into`, `:29530`). A re-seat needs no placeholder, because its live record is contained in a form a released binary already enforces.
- **Transactions.** Every S3 transition runs under the group's membership lock and `named_groups_persistence_lock`. It is built as a candidate from the live record and its ADR 0067 epoch token, and it carries `generation + 1`. The order is sidecar, then legacy view, as #451 orders its writes. The sidecar entry binds the exact `before` (epoch token and `RecoveryRef`) and `after` (state revision, state hash, containment identity) of the transition. S3 publishes to the live map **only when both writes are Durable**. This is stricter than the #759 rule in the PR #1181 helper, which also publishes on `ReplacedNotDurable` (`:5369`, `:5425`). On `ReplacedNotDurable` the live record stays contained and the write is retried. On `NotReplaced` or `Err` nothing is published and the candidate is dropped. A changed epoch token at commit aborts the transition and re-evaluates it.
- **Crash reconciliation at load.** An entry whose `after` matches the loaded record is finalised. An entry that matches `before`, or matches neither, is dropped, and containment is kept. A dropped retirement is re-derived later from durable facts. This never resolves toward less containment.
- **Unreadable sidecar: quarantine and rebuild (D120).** S3 reads the format family before it decodes anything. The family is the prefix `X0GRCV`, and the next byte is the version. No S3 version writes any other prefix at this path, and a later S3 format must keep the prefix (ADR 0085 rule 1). Each file falls into one of four classes:

  | Class | What S3 does | Typed state |
  |---|---|---|
  | The read itself fails (an I/O error) | It leaves the file in place, writes nothing for the group, and retries at the next load | `recovery_deferred {cause: sidecar_read_failed}` |
  | The family at a version newer than this binary reads, including a future magic in the family | Nothing. The file stays byte-identical at its path. S3 is unavailable for that group: it sends no request, arms nothing and writes nothing, and the legacy record governs, inert if it is a placeholder. This is ADR 0085 rule 5, unchanged. Upgrading again restores the store | `recovery_deferred {cause: sidecar_newer_format, version}` |
  | A supported version that is damaged: the body does not decode, it is truncated, or bytes trail it | It quarantines and rebuilds the file, as below | `sidecar_quarantined {..}`, then the state the rebuild leaves |
  | No family prefix at all, which no S3 version writes | It treats the file as damaged, as in the row above | as above |

  David ruled that S3 quarantines and rebuilds a damaged file with no operator step (D120). After ADR 0094's host commit, under the group's membership lock:
  1. *Quarantine.* S3 renames the file to `<stable_group_id>.<unix_ms>.grecovq` in the same directory. Its bytes stay identical. S3 never deletes, truncates or rewrites a quarantined file, and no scan, old or new, reads that extension. A WARN names both paths, and the `recovery` object gains `sidecar_quarantined {file, at, lost, phase}`.
  2. *Containment first.* The legacy record, and every marker and gate in it, stay as they are. An S3 placeholder stays in place. No rebuild step reduces containment. S3 makes no transition for the group until the replacement is durable.
  3. *Rebuild.* S3 writes a fresh sidecar, with `generation` starting again at 1 and `rebuilt_from` naming the quarantined file, and re-derives each field as the table below says. It claims no rebuild that holders cannot supply.

  | Field | Rebuilt from | When it cannot be rebuilt |
  |---|---|---|
  | `active_ata` | a fresh `group_attest_request` from the current head (§2), which any capable admin can answer | `awaiting_attestation` until one answers |
  | `served_chain`, `queued_terminal` | commits that holders keep, re-fetched through catch-up pages (membership events only) and, once S5 is in effect, fetch-by-hash | before S5, a pre-Welcome joiner whose gap holds a rename or a role change cannot re-fetch it. It enters `readmission_required {cause: local_state_lost}` (§3 routing) |
  | `authoritative_record`, when the legacy view holds the real record | that record | not applicable |
  | `authoritative_record`, when the legacy view holds an S3 placeholder | nothing. Its local-only fields, such as a GSS `shared_secret`, issued invites and join requests, are on no holder, and S3 has no snapshot fetch (D54 puts fetch-by-hash in S5) | the group stays inert under its placeholder, and the node enters `readmission_required {cause: local_state_lost}`, routed as in §3 (ADR 0114, D119) |
  | `reseat_journal`, `staging_record` | nothing: local attempt state | the staging record is discarded; it was never live. If the legacy view already holds the swapped-in record, the node keeps it. Otherwise the live record is unchanged and contained, the node shows `reseat_required {reseat_failed}`, and the admin calls the route again |
  | `issued_reseats` (issuer only) | nothing | the issuing admin loses its unconsumed authorisations. Its §6 guard then refuses those re-seat exchanges, so each subject ends `reseat_required {reseat_failed}`. `GET /groups/:id/recovery` on the admin shows `issued_reseats_lost`, and the admin calls the route again |
  | `retired` | nothing: audit history | lost. No containment depends on it, and the WARN records the loss |

  4. *Repeat failure.* If a fresh sidecar is damaged at a later load, S3 quarantines it again. How many quarantined files to keep is Open question 1.
  - *Durable order.* S3 never writes a replacement until the original bytes are preserved:
    1. rename the file to its `.grecovq` name (one atomic rename in the same directory);
    2. fsync the directory;
    3. re-open the `.grecovq` file and check that its length and BLAKE3 hash equal the bytes S3 read;
    4. write the replacement to `<stable_group_id>.grecov.tmp`, fsync it, rename it to `<stable_group_id>.grecov`, and fsync the directory again.
    
    A leftover `.grecov.tmp` is never read as state; the next attempt overwrites it.
  - *Rename failure.* If step 1, 2 or 3 fails, the file stays where it is, or the check fails. S3 then writes no replacement and makes no transition, reports `recovery_deferred {cause: sidecar_quarantine_failed, step}`, and retries at the next load.
  - *Crash between the rename and the replacement.* At load, S3 finds a `.grecovq` for the group that the current `.grecov`'s `rebuilt_from` does not name, or finds no `.grecov` at all. It then shows `sidecar_quarantined {phase: rebuild_pending}`, re-checks the preserved bytes (durable step 3), and writes the replacement (durable step 4), deriving every field again. If the rename itself was lost, the original file is still at its path, and S3 quarantines it again. Either way, exactly one durable `.grecovq` holds the original bytes.
  - *Before host commit,* S3 leaves the file in place and reports `recovery_deferred {cause: host_commit_pending}`.
  - *Amendment.* This ADR amends ADR 0085 rule 4 for damaged S3 sidecar files of a supported version only, ruled by David (D120). Rule 4 leaves an unreadable file untouched, so recovery waits for an operator to move it aside. S3 moves it aside itself. It keeps the bytes and never deletes, truncates or overwrites them, as rule 4 also requires. ADR 0085 rule 5 is not amended: a newer-format file stays at its path, unchanged. ADR 0089's evidence store keeps its own rule. ADR 0085 is Accepted and is not edited.
  - *L4.* Quarantine never reduces containment. Every re-fetched link passes every §2 check and must match a fresh verified ATA. S3 never rebuilds an authoritative record from a holder's claim, so the rebuild adds no acceptance rule.
  - *Mixed versions.* Released binaries read neither `.grecov` nor `.grecovq`. A downgraded node under a placeholder stays inert, as before. An older S3 binary that meets a newer S3 format leaves it in place (`sidecar_newer_format`), so a re-upgrade restores it.
  - *Harness:* H-S3-q and H-S3-q2.
- **Downgrade.** Released binaries never open the sidecar. The legacy files stay parseable. Re-upgrading restores the state. A released binary cannot report S3 states; it shows a group with no Active seat.
- **Timing.** On a managed install, the first sidecar write that changes behaviour waits for ADR 0094's host commit (ADR 0094: no format-upgrade writes before host commit). Until then the node keeps today's state and reports `recovery_deferred {cause: host_commit_pending}`.

### §5 Wire and capability (ADR 0093)

The new capability is **`group_terminal_attest_v1`**. It means the node issues and verifies ADR 0109 attestations, answers `group_attest_request`, and consumes re-seat authorisations. Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry.

- `group_attest_request` (typed DM): group, requester, head revision and hash, and the live `RecoveryRef`s with their causes.
- `group_attest_response`: `attested {ata}`, `on_chain {admin_head}`, `not_on_chain {admin_head}`, `reseat {authorisation, invite}` or `refused {reason}`. The reasons are `attester_quarantined`, `attester_behind`, `not_an_admin`, `not_a_member`, `banned_or_revoked`, `base_beyond_retention` and `rate_limited`.
- Only an advert that is current, verified and positive counts. Unknown or card-only state sends nothing (ADR 0093). Messages fit the 49,152-byte DM budget.

| Pair | Behaviour |
|---|---|
| New joiner, old authority | No `admin_attestation`; today's marker or queue; typed `awaiting_attestation {reason: no_capable_peer}`; the request path once a capable member is online |
| Old joiner, new authority | The key is omitted; result bytes are identical to today |
| New node, no capable peer online | No request is sent; typed `awaiting_attestation {reason: no_capable_peer}`; the force clear works as today |
| New node, Home-policy group, Home activation off | Today's marker or queue; typed `recovery_deferred {cause: home_gate_closed}` |
| Old node | Receives nothing new; unchanged |

### §6 Serving and egress

Every S3 response, the join-carry ATA, and every re-seat invite and authorisation are class R under the lifecycle note. They use ADR 0107's serving guard, re-checked under the membership lock. For a re-seat, the guard's Active-seat check is replaced by "not Active, holds a current unconsumed authorisation". Each physical exchange is admitted immediately before its write, with no hidden transport resend and no gossip fallback. Removal, ban, revocation, quarantine or authorisation expiry cancels unsent exchanges. The re-seat join's own artifacts, and any later class-K delivery or resend, use the ADR 0107 guard and D60 (current recipient eligibility and current secret epoch). The dependency is ADR 0107's implementation, PR #1190.

### §7 Security (L4)

**Rules added.**
- (a) Classification: a walk-valid chain matching a verified ATA is a gap, not fork evidence. This relaxes #818's classification and, for owner-axis groups, ADR 0064's owner-only clear, as 0088 §3 assigns.
- (b) Pre-Welcome link apply inside an armed attested sequence, from pages or from the served chain, for every link kind (§2, D82). This sits beside the TreeKEM adoption exclusion: it adopts no tree and no epoch, and it never jumps a gap.
- (c) Replacement of quarantined state under a verified re-seat authorisation, with no operator step (§3, D79).

**Arguments.**
- (a) Every adopted link is a commit the node would apply if gossip had delivered it in order. ADR 0016 lets any active admin commit. The ATA changes how a held chain is classified, not any link check.
- (b) A pre-Welcome joiner holds no keys for those epochs (§2 item 4). Its keys come from its own Welcome, which is checked against the terminal's declared epoch (ADR 0064 §1a). Skipping their TreeKEM commits therefore loses nothing. Each state commit gets every check, and a policy or GSS-binding change is refused.
- (c) The swap installs only a record that joined through ordinary admission, and it needs an admin's manual act naming this node. The old record is retired, not deleted, and the node was already unusable in the group.

**Unchanged.** Signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion (there is no reconstructed jump; each link is gapless) all stay fail-closed. No fork is resolved automatically, in either group type (D78, D121).

**D41.** ATAs and authorisations act only on `subject`. They never install or clear a marker on any other node, and are never gossiped. Neither causes a commit by itself. A re-seat's only commits are the admin's removal and the ordinary join seal.

**Exposure, accepted by David (D77).**
- In an ownerless group, an admin removed on the canonical chain, but still an admin on the node's stale base, can attest its own branch. Rule (a) then lets that branch bypass the quarantine that #818's classifier would install. The node follows the branch and nothing else changes. Canonical evidence arriving later installs a marker that this ATA cannot retire.
- In an owner-axis group, the same holds when no owner v2 attestation covers the gap. Owner mandates still bind admissions where the attester is recorded-capable and past grace (ADR 0064 §1b). Removals, renames, role changes and Unknown-tier admissions carry no mandate.
- The harm stays on the one recovering node (D41), and later canonical evidence contains it.

**Home (D81).** Home activation adds no acceptance rule. It lets rules (a)–(c) apply to Home-policy groups, where owner mandates bind as above and the D77 exposure applies when no owner attestation covers the gap. The H-S3-home gate guards only the downgrade; it changes no check.

**Beyond retention (D97, D119).** S3 adds no rule for it. An admin refuses to attest past its log. The node is re-admitted only through ordinary admission or ADR 0114's repair, whose acceptance rule ADR 0114 owns.

**Unreadable sidecar (D120).** Quarantine and rebuild add no acceptance rule and never reduce containment (§4).

### §8 Typed states (L3, D64)

David ruled that L3 binds every slice as a hard rule (D64). Every block this ADR adds or touches ends in a typed refusal or in a typed, visible wait that names what it waits for. `GET /groups/:id` and the ADR 0066 §5 refusal body gain an additive `recovery` object. Its `state` is one of:

| State | Waits for | Leaves on |
|---|---|---|
| `catching_up {attested_by, verified, cursor, segment_terminal}` | the next attested link | the terminal applied |
| `awaiting_attestation {asked, next_retry_at, reason}` | an attestation. `reason` is `no_capable_peer`, `no_reply`, `segment_exhausted`, `renewal_due`, `provisional_unverified`, or the last refusal reason (§5) | an ATA (`catching_up`), or the transitions below |
| `readmission_required {cause, asked, exit}` | ADR 0114's repair for the node's seat: never-confirmed, or confirmed-member (D119). `cause` is `base_beyond_retention` (§3) or `local_state_lost` (§4). `exit` names that repair, or D43's manual remove and re-invite where the repair is not in effect or gives the seat none (D97, D119) | that repair or re-invite; for `base_beyond_retention`, also any ATA |
| `manual_clear_required {ref}` | the node operator's force clear (ADR 0066 §2, D80) | the clear |
| `reseat_required {cause, ref, last_refusal, needs_owner_key}` | an admin's manual re-seat (0088 §2 item 7; for owner-axis groups the D121 entry, §3). `cause` is `not_on_chain`, `attestation_conflict`, `not_a_member` or `reseat_failed`. `needs_owner_key` is true in an owner-axis group: only an admin holding the owner's USER key can re-seat there until Open question 2 is ruled | a valid authorisation (`reseat_in_progress`) |
| `reseat_in_progress {authorised_by, phase, expires_at}` | the staged join (§3) | the swap, or `reseat_required {reseat_failed}` |
| `recovery_deferred {cause}` | `host_commit_pending`: ADR 0094's host commit; `home_gate_closed`: a release whose H-S3-home gate passed, or S7 (§4); `sidecar_read_failed` or `sidecar_quarantine_failed {step}`: a later load at which the read or the quarantine succeeds (§4); `sidecar_newer_format {version}`: an upgrade to a binary that reads that version (ADR 0085 rule 5, §4) | host commit, Home activation, a successful load, or that upgrade |
| `recovery_refused {reason}` | nothing. `reason` is `banned_or_revoked` (0088 §2 item 1) | none (definitive) |

The typed refusals are the §5 `refused {reason}` set, the re-seat route's reasons and the subject's `authorisation_refused {cause}` (§3). After a D120 quarantine, the object also carries `sidecar_quarantined {file, at, lost}` beside whichever state the rebuild leaves (§4); an issuing admin shows `issued_reseats_lost`. `asked` lists each target asked and its last answer. The join state mirrors the object (§2). Admins see pending requesters at `GET /groups/:id/recovery`, with a bounded, in-memory list (§11).

### §9 What is superseded or amended

| ADR | Text superseded or amended in part | Replaced by |
|---|---|---|
| 0088 §2 | Item 7 names only an ordinary group forked with no owner anchor | One named entry added, "Owner-axis forked node" (§3, D121). Item 7's text is unchanged |
| 0085 rule 4 | An unreadable file is left untouched, so an operator must move it aside | For a damaged S3 sidecar of a supported version only: automatic quarantine, keeping the bytes, then rebuild (§4, D120). A newer-format file still follows rule 5, which is not amended |
| 0064 Decision §3 | A marker clears only on an owner-anchored commit; a non-owner-axis marker is preserved indefinitely, and its recovery is unresolved | A stale-base node also retires its own marker under §2. A forked node is re-seated only under §3. Owner-anchored clears are unchanged |
| 0066 §2 | A `no_anchor` marker is never cleared by any commit; the manual clear is its only exit | It also retires under §2, for its own node only (D41). The manual clear stays, and §3 adds the admin re-seat (D80) |

### §10 Gates

0088's acceptance order is: the contract, then S2 and S8, then S4 and S3, then S5, then S6, then S7. David confirmed that "S8" here means S8 (a), ADR 0107 (Accepted), and that S8 (b), ADR 0114, is accepted after S4, as ADR 0107 states (D65).

S3's code merges only after all of these:
- this ADR is Proposed on `main`;
- David has Accepted it (ADR 0087 rule 8);
- each red W3-H case below is committed and shown red on `main`;
- PR #1190 is merged, for §6.

Home activation has one more gate: H-S3-home passes for the release that turns it on (§4, D81). A failure blocks Home activation, not the merge.

S3 code lands on the single `named_groups.rs` lane.

### §11 Limits (D83)

David accepted these values (D83). They bound the signing and memory work that a request flood can cause.

| Name | Value |
|---|---|
| `ATA_MAX_LINKS` | 64 links per ATA; a longer gap takes more than one segment |
| `ATA_ARM_WINDOW` | 10 min |
| `ATA_ARMED_LIFETIME` | 30 min |
| `GATE_STALL` | 10 min |
| Request backoff | 60 s, doubling to 1 h |
| Responder limits | 1 response per requester per interval; 4 concurrent builds; 32 signatures and 1 MiB of responses per minute |
| Recovery list | 32 entries per group, kept 24 h |
| Retired records | 16 per group |

## Consequences

### Positive

- Stale-base joins converge under any one capable admin, including the removal gap and gaps with renames or role changes (D82).
- Home groups converge the same way once a release passes the §4 gate (D81).
- #871 gets an audited exit that keeps containment until the replacement is installed, in both group types (D78).
- Every S3 block is typed and visible (D64).
- An unreadable S3 sidecar no longer waits for an operator (D120).
- A confirmed member behind every admin's retained log gets an automatic exit once ADR 0114's retention re-Welcome (§7) is in effect (D119).
- Released binaries keep starting on every S3 data directory.

### Negative / Trade-offs

- The §7 exposure is accepted (D77): a removed, partitioned admin can mislead one stale node until canonical evidence quarantines it.
- Home stale-base joins keep today's behaviour until a release passes H-S3-home. The authors predict the owner-install variant fails (§4). If so, Home stays with S7.
- Until ADR 0114's retention re-Welcome (§7) is Accepted and in effect, a confirmed member behind every admin's retained log has only D43's manual remove and re-invite (D97, D119).
- An unreadable sidecar under a placeholder costs the node a re-admission: its authoritative record exists on no holder, so S3 cannot rebuild it (D120).
- A forked node waits for an admin to act by hand (D78), and its operator is not asked (D79). In owner-axis groups that wait is a named §2 entry (D121), and its exit needs an admin holding the owner's USER key until Open question 2 is ruled.
- Re-seating an Active subject costs a removal and a rekey, until S8 (b).
- Bytes still travel by today's paths (DM-paged catch-up, in-memory logs, the 10-minute staged Welcome) until S5 and S8 (b).
- During a downgrade, a group under admin-attested recovery is inert.
- Two exits (operator clear and admin re-seat) to test, and more typed states and harness cases (D80, D64).

### Neutral / Operational

- New counters: `admin_attest_issued`, `admin_attest_refused{reason}`, `quarantine_retired{cause}`, `reseat_authorised`, `reseat_swapped`.
- Release notes drop the #818 "just-in-time invites" mitigation once S3 ships.
- The release gate sheet of the release that turns Home activation on links the H-S3-home evidence.

## Validation

**Tracking.** File one issue for the S3 cases under #1164. Each red case must be committed and shown red on `main` before S3's code merges.

**Harness model.** Every node has a simulated clock that the harness alone advances. The harness holds every message and releases them only in the order listed. "Partition N" means holding everything to and from N. Steps drive the public API, and each step runs to quiescence before the next. "Inject m from N to P" means the harness builds message m, signs it with N's key unless the case names another key, and delivers it to P as a DM from N. A released binary has no simulated clock; a case that runs one says how long it waits in real time. "Control" cases are safety controls, not red reproductions; each names what `main` shows.

**Setup S0 (skewed clocks).**
1. A calls `POST /groups` to create an ordinary TreeKEM group with no owner axis.
2. A seats M1 and M2: `POST /groups/:id/invite`, then `POST /groups/join`, each run to Active.
3. A calls `PATCH /groups/:id` three times (renames).
4. A calls `POST /groups/:id/invite`, giving invite I at state revision r.

Setup S0′ is S0 without step 3, which leaves the clocks aligned.

| Case | Schedule after setup | Assertion | Baseline |
|---|---|---|---|
| H-S3-a (#818, skew) | S0. A `DELETE /groups/:id/members/M2` (r+1). J `POST /groups/join` with I; A seals J (r+2); release J's join result. Advance 130 s | Main: J has `fork_quarantine.no_anchor` and `signer_only`; `join-status` is never `active`; `POST /groups/:id/send` returns 409. Candidate: J is Active with keys at r+2, is never marked, and sends no catch-up request | red |
| H-S3-a2 (#818, aligned) | S0′, then as H-S3-a | Main: J queues `revision_gap`; the r+1 page is refused for want of a TreeKEM group; the attempt times out with no marker. Candidate: as H-S3-a | red |
| H-S3-b (L1, promoted admin, D82) | S0 with A on the previous release. A `PATCH .../members/M1/role` to admin (r+1). J joins; A seals (r+2). Advance 130 s, then one request interval | Main: J stays marked. Candidate: J asks M1, which is provisional; J walks its kept served chain, which proves M1's promotion at r+1; only then does the ATA arm; J applies r+1 (a role change), replays r+2, retires its marker (`attested_catchup`) and holds keys | red |
| H-S3-c (#871, gate only, D78, D79, D121) | OwnerCertified group: owner O (the only install with the owner's USER key), admins A and X. Invite I at r. Partition X; O removes X (r+1). J joins; O seals (r+2) with v2; J's gate arms. Hold O's gossip of r+1 from J. On X, rename (r+1′); release r+1′ to J only, then the catch-up pages. Advance 30 min. A removes J (r+3) and calls reseat with basis `Removal(r+3)`. O then calls reseat with the same basis | Main: every page refused; J stays at r+1′ with no marker and no typed state. Candidate: after `GATE_STALL`, `reseat_required {not_on_chain, Gap(..), needs_owner_key: true}`, unchanged to the end of the advance, and O's attestation re-seats nothing. A's call returns `owner_key_unavailable`, and A signs and stores nothing. After O's call, with no call on J's API, J stays contained until the swap, is Active with keys at r+4, and O's next rename applies | red |
| H-S3-c2 (both records) | H-S3-c, also releasing canonical r+1 to J by gossip | J holds a marker and the gap record; the authorisation names one; the swap retires both | red |
| H-S3-s (segments, restart) | S0 with the segment length set to 2 by test configuration. The gap is 3 links (two removals and a rename) before J's seal. Restart J between segments | A 2-link segment covers exactly 2 links; the exhausted segment admits nothing and J shows `awaiting_attestation {segment_exhausted}`; after the restart the second ATA arms from J's head; J converges | control |
| H-S3-s64 (D83 boundary) | S0. After step 4, A renames 63 times, then seals J: a 64-link gap. Repeat with 64 renames: a 65-link gap | 64 links: one ATA of 64 entries and no further request. 65 links: the first ATA holds 64 entries, the exhausted segment admits nothing, a second ATA of 1 entry arms from J's new head, and J converges | control |
| H-S3-x (conflict) | S0 with A on the previous release and admins B and C promoted before step 4. Partition B; B commits r+1′. J joins and is marked; J asks B (no reply), then C, and arms C's ATA. Heal B, and release B's late reply | Nothing past the common prefix applies; `reseat_required {attestation_conflict}` | control |
| H-S3-t (typed waits, D64) | (1) S0 with A, M1 and M2 on the previous release, then as H-S3-a; advance 130 s. (2) Restart M1 on the candidate, as a capable non-admin; advance one request interval. (3) Partition every capable peer; advance 3 h. (4) Variant: J runs on a managed install whose ADR 0094 host commit is not yet written; run (1); then write host commit. (5) Variant: A on the candidate; J catches up; hold A's staged Welcome to J for 11 min | Main: no `recovery` object, and `join-status` ends with no named cause. Candidate: (1) at 130 s, `join-status` and `recovery` both show `awaiting_attestation {no_capable_peer}`, never a bare `TimedOut`; (2) `reason: not_an_admin`; (3) `reason: no_reply`, and `next_retry_at` steps 60 s, 120 s, 240 s and stops growing at 1 h; (4) `recovery_deferred {host_commit_pending}` until host commit, then the request path; (5) ADR 0107's typed `TimedOut` or `Refused` outcome with its cause | red |
| H-S3-r (beyond retention, D97, D119) | S0 with A's commit-log cap set to 4 by test configuration, and admin B (default cap) seated after step 2. Hold every message between B and J. After step 4, A renames 6 times (r+1 to r+6); A seals J (r+7); B applies all of them. Advance 130 s and one request interval. Then release the B–J messages and advance one backoff step | Main: J is marked or times out with no typed state. Candidate: A answers `base_beyond_retention`; J shows `readmission_required {base_beyond_retention}`, with `exit` naming ADR 0114's repair for J's never-confirmed seat, or D43's remedy where that repair is not in effect; J applies no link and clears no marker; once B is reachable, B's ATA arms, J leaves the state, catches up and holds keys | red |
| H-S3-home (D81 gate) | Home: owner install O (Home creator) and promoted admin device A2. Segment length 1 by test configuration; host commit written; Home activation on by test configuration. A2 mints invite I for J at r; O renames twice (r+1, r+2); partition O; A2 seals J (r+3) with no owner attestation; J arms from A2's ATA; stop J between segments, so its S3 Home placeholder is on disk. Variants for J: an owner install (user key and agent certificate) and a non-owner device; plus O's own data directory with an S3 Home placeholder written by test configuration (the creator reload). Remove any stored owner-sync canonical Home pointer, and give each run no network peers. Record the group-ID set and the `home.json` sha256. On a copy of the data directory per binary, start released v0.45.0, then separately v0.46.1; wait 150 s of real time (past v0.46.1's `HOME_POINTER_SYNC_WAIT`); stop; start again and wait 150 s; stop. Then start the candidate on the original directory | On both binaries and in every variant: the binary starts; the group-ID set is unchanged, with no new Home-policy group; `home.json` is byte-identical, or still absent; the group has no Active and no admin seat in either view; `POST /groups/:id/invite` and `POST /home/seat` are refused; the state revision does not move; the sidecar sha256 is unchanged. The candidate then resumes, J converges and the Home ID is unchanged. Any failure keeps Home activation off (§4). The authors predict the owner-install variant fails | control |
| H-S3-d1 (D41, subject only) | S0, every node on the candidate. A `DELETE /groups/:id/members/M2` (r+1). J `POST /groups/join` with I; A seals J (r+2). Before releasing J's join result, copy its `admin_attestation` and inject it from A to M1 as a `group_attest_response`. Then release J's join result. Advance 130 s | M1 reaches r+2 by gossip only; its marker and `recovery` fields do not change, and it sends nothing in reply. No node's state revision passes r+2. J is Active at r+2 | control (main: M1 drops the unknown DM; J is marked, as in H-S3-a) |
| H-S3-d2 (D77, exposure contained) | S0, except that A seats X after step 2 and promotes it (`PATCH .../members/X/role` to admin), and X runs step 4, giving invite I_X at r. Hold every message between {X, J} and {A, M1, M2}. A `DELETE /groups/:id/members/X` (r+1). X `PATCH /groups/:id` (rename, r+1′). J `POST /groups/join` with I_X; X seals J (r+2′); release X's join result to J. Advance 130 s. Release the messages held between J and {A, M1, M2}, A's r+1 first, and keep holding everything to and from X. Advance one request interval. Inject X's join-carry ATA from X to J again | After the first advance: J is Active at r+2′ on X's branch (the accepted exposure), and A, M1 and M2 are unchanged. After the release: J holds a marker naming A's r+1. Only X's fork seats J, so A, M1 and M2 each answer J's request with `refused {not_a_member}` before any chain walk, and J shows `reseat_required {not_a_member}`. The re-injected ATA retires nothing, and no node commits because of any ATA | control (main: J is marked at r+2′ before the release) |
| H-S3-d3 (authorisation refusals) | H-S3-c up to `reseat_required {not_on_chain, Gap(..)}`, with member M1 seated before invite I. A `DELETE /groups/:id/members/J` (r+3); O `POST .../members/J/reseat` with basis `Removal(r+3)`; hold that delivery to J. Inject to J, one at a time, each from O: (1) O's authorisation with one signature byte changed; (2) one signed with M1's key; (3) one signed with O's key naming subject M1; (4) one naming a `Gap` ref that J does not hold; (5) one whose invite base is r+2, which seats J. Advance past the held authorisation's expiry, then release it. Advance 1 h with no further route call | J answers each with `authorisation_refused`, with causes `signature`, `signer`, `subject`, `basis`, `base_seats_subject` and then `expired`. After each, J stays `reseat_required`, writes no re-seat journal and keeps its live record unchanged. No re-seat happens in the last hour | control (main: the route returns 404) |
| H-S3-d4 (route refusals) | H-S3-d3's nodes at its start, plus node B, which A seats and bans before invite I, and node E, never seated. On A, call `POST .../members/:agent_id/reseat`: (1) for J with an empty `reason`; (2) for M1, which is Active; (3) for B; (4) for E; then A removes J (r+3), and (5) calls it for J with a reason and basis `Removal(r+3)` | (1) `reason_required`; (2) `subject_active`; (3) `subject_banned_or_revoked`; (4) `basis_unknown`; (5) `owner_key_unavailable`, because A holds no owner USER key. A signs and stores no authorisation and mints no invite | control (main: the route returns 404) |
| H-S3-d5 (D80, sibling marker) | S0′, with admins B and C promoted after step 2. J joins with I; A seals J (r+1). Hold every message between B and {A, C, J}. A renames (r+2); B renames (r+2′). Release A's r+2 to C and J, then B's r+2′ to C and J. Advance one request interval. C `POST /groups/:id/members/M1/reseat` with a reason. C's operator calls `POST /groups/:id/quarantine/clear` with `force` and a reason | C and J each hold a marker naming B's r+2′. A answers their requests with `on_chain`. Each shows `manual_clear_required {ref}` and keeps its marker. C refuses J's request with `attester_quarantined`, and C's reseat call returns `admin_contained`. After the force clear, C has no marker and its `POST /groups/:id/send` succeeds; J stays `manual_clear_required` | red (main: markers with no `recovery` object) |
| H-S3-d6 (provisional ATA, bogus hashes) | S0 with A on the previous release, M1 and M2 on the candidate. A `PATCH .../members/M1/role` to admin (r+1). J joins; A seals (r+2). Advance 130 s. Hold M1's and M2's replies to J's requests. Inject from M2 to J, as M2's reply, an ATA signed by M2, with `from` equal to J's head and two random sequence hashes. Then release M1's reply | After the injection, J shows `awaiting_attestation {provisional_unverified}` and has armed nothing. After M1's reply, M1's ATA arms; J applies r+1, replays r+2, retires its marker and holds keys. J never shows `reseat_required` | control (main: J stays marked, as in H-S3-b) |
| H-S3-d7 (request flood) | S0′, every node on the candidate, plus node E, never seated. Within one request interval, inject to A 50 `group_attest_request`s from M1, each naming a different random head hash, then 50 from E. Advance 1 min | A answers M1's first request with a typed refusal other than `rate_limited`, and every later one with `refused {rate_limited}`. E's first gets `not_a_member`, and the rest get `rate_limited`. `admin_attest_issued` does not move. `GET /groups/:id/recovery` on A lists at most one entry each for M1 and E | control (main: A drops the unknown DMs) |
| H-S3-d8 (`Removal` basis) | H-S3-c up to the release of r+1′ to J. Hold every message from J to A and O. A `DELETE /groups/:id/members/J` (r+3). Release J's messages. Advance `GATE_STALL` and one request interval. O `POST .../members/J/reseat` with a reason and basis `Removal(r+3)` | J's requests get only `not_a_member`, and J shows `reseat_required {not_a_member, Gap(..)}`. J consumes the authorisation (a `Removal` basis paired with its live `Gap` ref), keeps its gate until the swap, and is Active with keys at r+4 | control (main: J stays at r+1′ with no typed state, as in H-S3-c) |
| H-S3-q (unreadable sidecar, D120, D119) | Three variants. In each, stop the named node, replace its `.grecov` with 64 bytes that start `JUNKJUNK` (no family prefix), and start it on the candidate with host commit written. (1) Joiner: H-S3-s up to J stopped between segments, with its placeholder on disk. (2) Confirmed member: S0′ with admin B promoted after step 2 and segment length 1 by test configuration. J joins and is Active at r+1. Hold every message between B and {A, J}. A renames three times (r+2, r+3, r+4); B renames (r+2′). Release A's r+2 to J, then B's r+2′, so J holds a sibling marker. J asks A and arms A's one-link ATA for r+3; stop J after it applies r+3, before its next segment. (3) Issuer: H-S3-c up to O's reseat call; stop O instead of J; restart O; release the authorisation to J, and let J start its staged join | All: the old bytes sit, byte-identical, at the `.grecovq` path; a fresh `.grecov` exists; no marker or gate is cleared; no node commits because of the rebuild; `recovery.sidecar_quarantined` names the file and what was lost. (1) J stays inert under its placeholder and shows `readmission_required {local_state_lost}`, with `exit` naming ADR 0114's repair for its seat or D43's remedy. (2) J stays inert, shows `readmission_required {local_state_lost}`, and `exit` names ADR 0114's retention re-Welcome (§7) (D119), or D43's remedy while that is not in effect. (3) O's guard refuses J's staged join; J shows `reseat_required {reseat_failed}` with its live record unchanged; O's `GET /groups/:id/recovery` shows `issued_reseats_lost`; O calls the route again, and J is Active with keys | control (main: no S3 sidecar exists) |
| H-S3-q2 (quarantine boundaries, D120) | H-S3-q variant (1)'s data directory, one copy per run, with fault points set by test configuration. (a) Newer family: write `X0GRCV2\0` and 64 bytes at the `.grecov` path. (b) Read failure: make the read return an I/O error. (c) Rename failure: make the rename fail. (d) Crash after the rename, before the directory fsync. (e) Crash after the fsync, before the replacement. (f) Crash after the `.grecov.tmp` write, before its rename. Start the candidate, then, for (b) to (f), clear the fault and start it again | (a) The file stays byte-identical at its path across three restarts; no `.grecovq` exists; J shows `recovery_deferred {sidecar_newer_format, version: 2}` and sends no request. (b) The file is unchanged; `recovery_deferred {sidecar_read_failed}`; after the fault clears, quarantine runs. (c) The file is unchanged and no replacement exists; `recovery_deferred {sidecar_quarantine_failed, step}`; after the fault clears, quarantine runs. (d) After restart, either the original is still at its path and is quarantined once, or (e) applies. (e) After restart, J shows `sidecar_quarantined {phase: rebuild_pending}`, re-checks the bytes, writes the replacement with `rebuilt_from` naming the file, and ends as in H-S3-q (1). (f) The tmp file is never read as state; the replacement completes. In every run: exactly one `.grecovq` holds the original bytes, no replacement exists before the bytes are preserved, and no marker or gate is cleared | control (main: no S3 sidecar exists) |
| H-S3-m (versions) | Each §5 row with one released v0.46.x node. Stop J between segments in H-S3-s and start the released v0.46.x binary on its data directory; then start the candidate again | Old-authority bytes are unchanged. Run on the released binary: it starts; after reload the group has no Active and no admin seat in either view; `POST /groups/:id/invite` is refused; the state revision does not move (no commit); no page applies. The sidecar sha256 is unchanged. Repeat with an OwnerCertified group in both views. The candidate resumes and converges. Home is H-S3-home | control |

**Non-regressions** stay green unchanged:
- `stale_base_treekem_joiner_owner_anchored_gap_is_not_fork_evidence`, `stale_base_treekem_sibling_terminal_with_genuine_owner_attestation_quarantines`, `forking_catchup_responder_adopts_nothing_under_anchored_gap`, `honest_multicommit_gap_converges_page_by_page_under_gate` and `adr0064_s4_removed_admin_fork_to_joiner_quarantines` (all in `hs_f2_membership_cluster.rs`);
- `adr0066_ordinary_group_conflict_sets_a_no_anchor_marker` and `adr0066_unauthenticated_conflict_never_quarantines_an_ordinary_group` (in `fork_quarantine.rs`);
- PR #1181's fault cells, ADR 0106's carry tests and ADR 0107's serving-guard tests.

**Persistence.**
- Fault-inject `ReplacedNotDurable`, `NotReplaced` and `Err` on each write of each transition. Assert that nothing is published and the record stays contained.
- Kill the process between the sidecar write and the legacy write. Assert that reconciliation never reduces containment.
- No-prefix, truncated and trailing-byte sidecars of a supported version are quarantined byte-identical under `.grecovq` and rebuilt per §4, and a second corruption is quarantined again (D120). A newer-family file and an unreadable read stay in place. Before host commit every file stays in place. H-S3-q2 covers the durable-order boundaries.
- In-process boundary tests at `ATA_MAX_LINKS` and `ATA_MAX_LINKS + 1` links.
- The first release that writes the format adds a fixture written by that release (ADR 0085 rule 6).

**Review trigger.** Revisit when S5 lands control-blob catch-up, when ADR 0114's retention re-Welcome (§7) (D119) is Accepted, or when H-S3-home gives its first result.

## Rulings and open questions

**Blocking Accept:** Open question 2 (any-admin re-seat in owner-axis groups). Open question 1 blocks code only.

David ruled this ADR's questions Q1–Q7 on 2026-10-04 (D77–D83), with the cross-slice rulings D64, D65 and D97 that touch it:

- **Q1, the §7 exposure:** accepted as stated. Any active admin on the node's own roster may attest, in both group types (D77). See §2 and §7.
- **Q2, owner-axis forked nodes:** manual. An admin re-seats an owner-axis forked node by hand (D78). D121 records that wait as a named §2 amendment, not a reading of item 7. See §3.
- **Q3, subject consent:** the admin's authorisation is enough. The subject applies it with no human step (D79). See §3.
- **Q4, who acts under §2 item 7:** both. The operator's clear serves an on-chain node with a stale sibling marker, and the admin's re-seat serves a forked node (D80). See §3.
- **Q5, Home groups:** lifted behind a released-binary test. Released v0.45.0 and v0.46.1, with no owner-sync pointer, must show no duplicate Home and no `home.json` change through reload and provisioning; Home activation stays blocked if any test fails (D81). See §4 and H-S3-home.
- **Q6, rule (b) scope:** every link kind (D82). See §2 and §7.
- **Q7, values:** accepted as recommended (D83). See §11.
- **G7, L3:** a hard rule for every slice, including the 120 s poll and upgrade or backoff waits (D64). See §2, §5, §8 and H-S3-t.
- **"S8" in the order:** S8 (a), ADR 0107. S8 (b), ADR 0114, follows S4, and S5 does not wait for it (D65). See §10.
- **Beyond retention:** admission. Any admin re-Welcomes the node, through S8 (b) or a later ADR (D97). D119 later made that ADR 0114 for confirmed members too. See §3 and H-S3-r.

David ruled a second round on 2026-10-04 (D119–D121):

- **D119, a confirmed member behind every holder's retention:** S8 (b) widens now, so ADR 0114 also repairs confirmed members. This ADR routes `readmission_required` for a confirmed member to ADR 0114's retention re-Welcome (§7), which ADR 0114 owns. D43 stays the exit until that repair is in effect. See §3, §8, H-S3-r and H-S3-q.
- **D120, an unreadable sidecar:** automatic quarantine and rebuild, amending ADR 0085 rule 4 for the S3 sidecar only. Fields that no holder has are named, with their safe outcome. A record under a placeholder cannot be rebuilt, and the node is re-admitted instead. See §4, §9 and H-S3-q.
- **D121, owner-axis forked nodes:** a named amendment to 0088 §2, "Owner-axis forked node", with its typed state and exit. The exit's InviteV4 mint needs the owner's USER key today, so any-admin re-seat there is Open question 2. See §3 and §9.

Still open for David:

1. **Quarantined sidecar files (D120 detail; blocks code, not Accept).** Proposed: keep every quarantined file, because ADR 0085 rule 4 forbids deleting an unreadable file and each quarantine needs a failed load and a restart. Alternative: after 4 quarantines of one group's sidecar in 24 h, stop rebuilding it and show a definitive `recovery_refused {sidecar_repeatedly_unreadable}`, which brings back an operator stop. This needs David's ruling.
2. **Any-admin re-seat in owner-axis groups (D121 exit; blocks Accept).** The re-seat mints an InviteV4, and today's mint refuses an owner-axis invite without the owner's USER key (`named_groups.rs:17174–17184`). So the D121 entry's exit needs an owner-key device, which 0088 L1 forbids. This needs David's ruling. The options are:
   - (a) *Accept the dependency.* The D121 entry names the owner-key device as its exit, as an explicit L1 limit, with `needs_owner_key` and `owner_key_unavailable` as its typed states. No new mechanism.
   - (b) *A promoted-admin re-seat mandate (proposed).* This is modelled on ADR 0114's promoted-admin repair mandate (D87). An active admin signs, with its agent key, a `ReseatMandateV1` in its own domain, `x0x/owner-axis/reseat-mandate-admin/v1`. It binds:
     - the owner user ID and the group and genesis;
     - the signer and the subject;
     - the subject's original seating commit and its removal commit (the basis);
     - the invite base revision and hash;
     - the policy hash and the subject's last role.
     
     A receiver accepts it in place of the owner countersignature only under four conditions. The signer holds a current Admin seat at the base. The policy hash matches the base's owner policy. The subject's owner certificate verifies against that owner. The re-seat restores the same identity at a role no higher than its last. It never admits a new identity and never stands in for an owner mandate on an ordinary add. It is a new acceptance rule, it needs a capability floor among receivers (typed `reseat_receiver_upgrade_required`, as ADR 0114 does), and it needs S2's certificate delivery.
   - (c) *Reuse S6.* Re-seat through ADR 0112's any-admin V5 redemption, once S6 is in effect. This adds no new rule here, but S3's owner-axis exit then waits for S6.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

# ADR 0109: Ownerless Attestation: Stale-Base Self-Recovery and Manual Re-seat (0088 S3)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model review r1: REQUEST-CHANGES, 16 findings, addressed in r2); further review TBD
- **Slice:** S3 of [ADR 0088](./0088-group-liveness-contract.md)
- **Supersedes:** in part, upon acceptance: ADR 0064 Decision §3 and ADR 0066 §2 (as 0088 §3 assigns to S3)
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core
- **Related:** rulings D34(1), D41, D54, D60, D16; #818 (part 2), #871, #1164 (W3-H harness), #1103 and PR #1181 (merged), PR #1190 (ADR 0107 implementation); ADR 0012, 0016, 0023, 0064, 0066, 0067, 0068, 0085, 0087 rule 8, 0093, 0094, 0106, 0107. Related work only: the join-artifact serving lifecycle note (`docs/design/join-artifact-serving-lifecycle.md`, on the #1190 branch).

## Context

A node can hold a quarantine or a wait that has no exit. Three shapes are live.

**#818 part 2, skewed clocks: a legitimate gap is quarantined.** An invite stub seeds its state and roster clocks from the base state revision (`src/server/routes/named_groups.rs:17567–17570`). The authority bumps its roster clock only on membership changes (for example `:19407`, `:20981`). A rename bumps only the state clock. So when renames precede the mint, a later `MemberAdded` carries a roster revision at or below the stub's, and the frontier gate does not queue it (`:7324–7327`). The apply fails. A TreeKEM joiner never adopts across the gap (`:4828–4837`). The refused chain reaches `classify_refused_joiner_fork_chain` (`:4443`), which exempts a gap only under the owner's v2 terminal attestation (`:4504`). By the #818 design decision (`:4494–4503`), an ownerless group cannot tell a gap from a fork, so the joiner gets a `signer_only` marker (`:4558–4591`) with `no_anchor: true` (`:4301`). No commit clears it (`src/groups/mod.rs:347`, `:369`). The force clear (`named_groups.rs:14884`) leaves the node at its stale base. ADR 0106 never carries a gap that holds anything but `MemberAdded` events.

**#818 part 2, aligned clocks: the gap queues but cannot apply.** With aligned clocks the frontier gate queues the add as `revision_gap` (`:7349`, `:11182–11205`) and requests catch-up. The joiner is pre-Welcome. A `MemberRemoved` page needs a local TreeKEM group and is refused without one (`:12145–12150`). Only `MemberAdded` has a pre-Welcome state-only apply (`:11912–11927`). TreeKEM catch-up serves only membership events (`:7072–7132`), so a rename or a role change in the gap is never served at all. The join attempt times out.

**#871: a forked head has no escape.** The #846 gate arms from the durable `AnchoredGapRefusal` (`src/groups/mod.rs:122`; `armed_anchored_gap_sequence`, `named_groups.rs:10171`). Each page must link from the current head and match the attested sequence (`:10200`, `:10282`). A forked head can never link. The gate refuses silently, with no marker (`src/server/routes/named_groups/tests/hs_f2_membership_cluster.rs:7215`). It retires only at the terminal revision (`:10343`). The escape is leave and rejoin.

Home shares the first two defects whenever the owner install did not seal the gap. Only an owner install signs the head attestation (`:33364–33373`). Under §4, this ADR leaves the Home case to S7.

**Rules broken.** All three break 0088 **L2**: a stale base is not a fork, and §2 does not list these waits. The Home case breaks **L1**: catch-up waits on the owner device. #871 and the aligned-clock shape break **L3**: the wait is silent.

**Rulings.** D34(1): in ownerless groups, an active admin's signed terminal snapshot attests stale-base catch-up, as a mandate layer above ADR 0016, and gives #871 a re-seat path. D41: self-recovery only. The snapshot lets a node adopt the attested state and clear its own marker. It never marks another member forked, evicts anyone, or clears anyone else's marker. 0088 §3: stale-base catch-up is automatic; a forked node is re-seated only under an admin's explicit manual authorisation (§2 item 7).

## Decision Drivers

- A stale base converges with any one admin online (L1).
- A fork is never resolved automatically (ADR 0064 Option 3, ADR 0066 §2, 0088 §2 item 7).
- An attestation acts only on the node it names (D41).
- Every link passes every existing apply check (L4). Any rule this slice adds is named with its argument.
- `named_groups.json` and `home-suite-groups.json` never change format. Released daemons parse them with `serde_json` and abort startup on error (`src/server/mod.rs:735–737`, the #451 failure).
- Byte transport stays where it is. Control blobs and fetch-by-hash belong to S5 (D54).

## Considered Options

1. **Admin terminal attestation, self-recovery, manual re-seat, own sidecar** (chosen).
2. **Founder or creator key as the anchor.** Rejected by ADR 0066 R1: an unreviewable eviction oracle.
3. **A quorum of admin heads.** Rejected by ADR 0064 Option 6 and ADR 0066 Option 4.
4. **Automatic re-seat under any admin's snapshot** (D41's literal text; the earlier #871 design). Rejected: 0088 §2 item 7 keeps unanchored forks for manual action, and an automatic re-seat chooses a fork (ADR 0064 Option 3).
5. **An expiry that disarms the #846 gate** (#871's second ask). Rejected: unattested pages would then apply. #860 removed the queue-TTL disarm for this reason.
6. **A persisted authority catch-up log.** Rejected by D54.
7. **New fields or a new envelope in the legacy JSON stores.** Rejected: any reformat bricks a downgrade (#451; ADR 0085 rule 5; ADR 0094).
8. **Defer the removal gap until S5.** Rejected: S5 changes transport, not the pre-Welcome apply rule, so the aligned-clock shape would stay stuck.
9. **Membership pages only, without applying the served chain.** Rejected as the default: a gap holding a role change or a rename is never served by TreeKEM catch-up (`named_groups.rs:7072–7132`), so the promoted-admin case (L1) would wait for S5. Open question 6 asks David to confirm.

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
2. Limits are applied to every request, member or not, before anything else. They are a per-requester rate and responder-wide caps on requests, concurrent builds, signatures and bytes, plus a cache keyed by `(group, subject, from_state_hash)` that is reused until expiry. A request over a limit gets `refused {rate_limited}` and nothing more. Values are in Open question 7.
3. Classification: the requester must be an Active member on the admin's current roster, not banned, with an unrevoked agent. A non-member gets `refused {not_a_member}`, or `reseat {..}` when an unconsumed authorisation names it. That path does no signing and no log walk. It adds at most one entry per requester to the bounded recovery list (§8).

Then it signs only if: it is an active admin on its own roster; its own record of the group has no marker and no armed gap record; `from` is a commit in its persisted `commit_log` (`src/groups/mod.rs:722`, cap `:753`); and the segment is its own chain from there. A head newer than the admin's own gets `attester_behind`. A base older than its log gets `base_beyond_retention`.

### §2 Automatic stale-base catch-up (self-recovery)

**Delivery.**
- *Join carry.* `JoinResultMessage::Result` (`named_groups.rs:1143`) gains a serde-default `admin_attestation`. The authority adds it for the first segment of the served chain when three things hold: no owner v2 attestation is served, the joiner's current verified advert has the §5 capability, and §6 admits the exchange. It signs once per `(attempt_id, from_revision)`. The joiner then applies its served chain under the pre-Welcome rule below and replays its own terminal, with no catch-up round trip.
- *Requests.* The node sends `group_attest_request` when it holds a marker, an armed gap record with no progress for `GATE_STALL`, or an exhausted segment (below). Targets are tried in this order: capable admins on its roster, lowest agent ID first (the D40 order); then capable members on its roster; then agents that sent it a signature-verified commit for this group. A member promoted after the stale base can therefore answer. Retries back off as set in Open question 7.

**Verification and signer eligibility.** The subject accepts an ATA only when the signature verifies, `subject` and `group` match, `from` equals its own head, `issued_at_ms` is within `ATA_ARM_WINDOW` of its clock, and `attested_by` is not revoked (the check at `:10244`). The signer is **verified** when it is an active admin on the subject's current roster. Otherwise it is **provisional**. A provisional ATA has no gate authority: it arms nothing, blocks no page, causes no conflict and retires nothing. Its promotion path must be verified first. That path is a prefix of the ATA's own sequence, ending at a link that makes the signer an active admin, and every committer on it is checked against its predecessor roster. A joiner verifies the path by walking its kept served chain (`validate_alternate_chain`) without applying it. Any other node verifies it by applying those links through the ordinary path, ungated. Either way, the walked or applied hashes must equal the ATA's prefix. Only then does the ATA arm, for the rest of its sequence. If the signer stops being an active admin after an applied link, the gate stops there.

**Arming.** A verified ATA in a join result arms the gate whether the terminal reaches the classifier or is queued first by the frontier gate (`:7349`). In the classifier, a walk-valid served chain whose first segment matches a verified ATA is a gap, not fork evidence. The node then queues the terminal, as the owner-anchored branch does (`:11512–11523`). The armed record is `AnchoredGapRefusal` with reason `admin_attested_stale_base_gap` and `attested_chain_hashes = sequence`. The full ATA is kept beside it in the S3 sidecar (§4). An owner-attested record keeps precedence. While it is armed, an ATA never re-arms it; a request then only detects a fork (§3).

**Segments.** The cursor is the subject's head. When the head equals the segment's last hash, the segment is exhausted. The gate stays armed with an empty remaining sequence, which admits nothing (`:10200`), and the node requests the next segment from its new head. A segment that does not match the served chain's next hashes, where those are known, is a conflict. An armed ATA with no progress for `ATA_ARMED_LIFETIME` is renewed from the current head. A renewal must agree with the remaining sequence. `ATA_ARM_WINDOW` applies at arming only. The sidecar keeps the served chain, the active ATA and the queued terminal. After a restart the node re-verifies the stored ATA's signature and its signer's eligibility against the current roster, then resumes at the cursor.

**Conflict.** Two valid ATAs for one head whose sequences diverge stop automatic catch-up. Nothing past the common prefix applies. The node enters `reseat_required {attestation_conflict}`. No evidence class is added. Conflicting commits still install a marker through the existing path.

**Pre-Welcome link apply (new rule (b), §7).** A pre-Welcome node (no local TreeKEM group for this group, and not Active on its roster) may apply one link state-only. The link must be in an armed attested sequence, owner or admin, whose terminal is the node's own `MemberAdded`. The link comes from a catch-up page or from the node's own served chain (`RetainedCommit`, `named_groups.rs:1186`).
- It must link from the node's head and pass every `validate_apply` check.
- A `RetainedCommit` link must also pass `validate_alternate_chain` (`src/groups/state_commit.rs:1056`), with its roster and metadata matching the commit's roots.
- A link that changes the policy hash or a GSS security binding is refused, as #458 r6 item 4 refuses it.
- The TreeKEM commit is skipped. No tree or epoch is taken from the chain; the node's keys come only from its own Welcome at the terminal.

This extends the existing `MemberAdded` rule (`:11912–11927`) to every link kind. It is ADR 0106's deferred option 2, made per link and gated by an attestation. A joiner that installs a `signer_only` marker keeps its served chain and its refused terminal event in the sidecar, so a later ATA can use them. A stale node that is not pre-Welcome applies links by the ordinary path. Its non-membership links still wait for S5.

**Retirement, independent per record.**
- A marker, with its matching `invite_lineage.fork_evidence`, retires (cause `attested_catchup`) when the evidenced commit `(revision, state_hash, committed_by)` is durably applied under a verified ATA. A sibling marker can never meet this condition.
- The armed gap record retires only when its exact terminal `(terminal_revision, terminal_state_hash)` is durably applied. A marker's retirement never touches it.

**Join attempt.** While an armed record owns the stub, the join-timeout finalizer keeps the stub and its row. It reports the typed join state `catching_up`, not `TimedOut`. The 120 s poll is unchanged, and G7 is not decided. Keys still come from the authority's staged Welcome, whose 10-minute lifetime ADR 0107 bounds. If that expires, the attempt ends with ADR 0107's typed outcome and exit. Authority re-Welcome is S8 (b).

### §3 Forked nodes: manual re-seat only

A node needs a re-seat when an admin answers `not_on_chain` (its head is not on that admin's chain, so it is **forked**) or when attestations conflict. It enters `reseat_required`. Nothing changes automatically. `base_beyond_retention` is not a re-seat trigger. It stays `awaiting_attestation`, retryable, and depends on S5. S3 does not claim that case.

A node whose head is on an admin's chain, but whose marker names a sibling it never applied, is not forked. It catches up, and its marker stays: an ATA never resolves a fork. Its state is `manual_clear_required`, with the existing local force clear (ADR 0066 §2) as its exit.

**Recovery token and basis.** A node's live containment is a `RecoveryRef`: either `Marker(identity)`, the ADR 0067 identity, or `Gap(reason, head_state_hash, terminal_revision, terminal_state_hash)`, which covers the gate-only #871 state. A request carries the node's live `RecoveryRef`s. An authorisation names one **basis**: either one `RecoveryRef` the admin was told about, or `Removal(revision, state_hash)`, the subject's removal commit.

**The admin's manual act.** The admin calls `POST /groups/:id/members/:agent_id/reseat` with a non-empty `reason`, on its local API. The CLI `group reseat` uses the same entry in `src/api/mod.rs`. Nothing else builds an authorisation. The route refuses with a typed reason unless all hold:
- the admin's own record of the group is uncontained;
- the subject is not Active on the admin's roster and is neither banned nor revoked (0088 §2 item 1). If the subject is Active, the admin first removes it through the existing removal route, an ordinary admin act outside this ADR;
- the basis is either a `RecoveryRef` from a request this admin answered with `not_on_chain`, or one the subject reported as `attestation_conflict`; or a `Removal` commit of the subject (a removal, not a ban) that is on the admin's own verified chain. The `Removal` basis covers a removed forked node whose requests get only `not_a_member`.

The route mints an InviteV4 addressed to the subject under the group's unchanged admission rules. It signs a `ReseatAuthorisation` (domain `x0x.reseat-authorisation.v1`) over the group, subject, basis, invite secret hash, invite base revision and hash, signer, reason hash and expiry. It keeps the authorisation in its sidecar until consumed or expired, one per `(group, subject)`.

**The subject's self-recovery, journalled.** The subject consumes an authorisation only when all hold: the signature verifies; the signer is the invite's authenticated inviter and an active admin on the invite base roster; the subject is itself; a `RecoveryRef` basis equals a live one, or a `Removal` basis is paired with any live `RecoveryRef` (the node is contained); the invite has not expired; and the base does not seat the subject. Then:
1. It writes a re-seat journal: the authorisation, the invite, and a digest of the full current record.
2. It joins into a **staging record** and staging TreeKEM state, outside the live map. Ordinary join validation and ADR 0107's guards apply to it. The live record keeps its marker, its gate and every ADR 0066 refusal throughout. Because the join is not against the live row, the route's idempotent-success path (`:18232–18345`) cannot short-circuit it.
3. When the staging record is Active with keys installed and durable, one transaction swaps it in. The old record goes to the retired list (cause `reseat`), and the journal closes. The swap uses the existing TreeKEM persist transaction, so a staged roster is never paired with the forked tree.
4. On failure (expiry, refusal, timeout), the staging record is discarded and the live record is unchanged. The state becomes `reseat_required {reseat_failed}`. A crash resumes from the journal's phase, and only a durable swap retires anything.

This is the one exception to ADR 0107's rule that quarantined state is not a retryable remnant. It applies only under a verified authorisation.

### §4 Persistence: the S3 sidecar (ADR 0085)

The legacy stores never change format. S3 state lives in its own files: `<data_dir>/group-recovery/<stable_group_id>.grecov`. No released scan reads that directory or extension (the scans read `treekem/*.journal` at `named_groups.rs:28410` and `*.hsjournal` at `:29945`).

- **Format.** The magic `X0GRCV1\0` is followed by a postcard `GroupRecoveryV1`, consumed exactly. Embedded `GroupInfo` records are JSON documents carried as length-prefixed bytes, because `GroupInfo` uses `skip_serializing_if`, which a positional encoding cannot carry. The fields are: `generation`, `served_chain`, `active_ata`, `queued_terminal`, `authoritative_record`, `reseat_journal`, `staging_record`, `issued_reseats` and `retired`.
- **Placeholder (after the #451 pattern).** While an admin-reason gap record is armed, the group's entry in each legacy file that a released binary loads is an S3 placeholder. That is `named_groups.json`, plus `home-suite-groups.json` for an OwnerCertified group, because released binaries load both and the sidecar entry wins (`named_groups.rs:30507–30536`). The placeholder starts from `legacy_safe_placeholder` (`:32794–32813`), which keeps identity, chain head and containment. Unlike it, the S3 placeholder keeps `members_v2` **non-empty with every entry Removed**, so no seat is Active. Released v0.45 and v0.46.1 run `migrate_from_v1` on every loaded entry (`:30331`, `:30413`). On an empty `members_v2` that seats the creator as Admin (`src/groups/mod.rs:2253–2282`); with a non-empty, all-Removed roster it does nothing, so no admin exists. The authoritative record is `authoritative_record`. A released daemon starts, sees an inert group with no admin, mints no invite, seals no commit and applies no page.
- **Home groups.** A group with `home` metadata never arms admin-attested recovery under this ADR. A placeholder there would fail released `find_home`/`is_home_candidate` (`src/server/routes/home.rs:373`, `:438`) and could lead `provision_home_steps` (`:923`) to create a duplicate Home. Such a node keeps today's state (marker or queue) and reports `awaiting_attestation {reason: home_excluded}`. Lifting this needs S7, or a released-binary test proving no duplicate Home and no `home.json` change (Open question 5). The sidecar's bytes stay unchanged. The re-upgraded daemon lets the sidecar replace the placeholder and unions containment (`union_containment_into`, `:29530`). A re-seat needs no placeholder, because its live record is contained in a form a released binary already enforces.
- **Transactions.** Every S3 transition runs under the group's membership lock and `named_groups_persistence_lock`. It is built as a candidate from the live record and its ADR 0067 epoch token, and it carries `generation + 1`. The order is sidecar, then legacy view, as #451 orders its writes. The sidecar entry binds the exact `before` (epoch token and `RecoveryRef`) and `after` (state revision, state hash, containment identity) of the transition. S3 publishes to the live map **only when both writes are Durable**. This is stricter than the #759 rule in the PR #1181 helper, which also publishes on `ReplacedNotDurable` (`:5369`, `:5425`). On `ReplacedNotDurable` the live record stays contained and the write is retried. On `NotReplaced` or `Err` nothing is published and the candidate is dropped. A changed epoch token at commit aborts the transition and re-evaluates it.
- **Crash reconciliation at load.** An entry whose `after` matches the loaded record is finalised. An entry that matches `before`, or matches neither, is dropped, and containment is kept. A dropped retirement is re-derived later from durable facts. This never resolves toward less containment.
- **Fail closed.** An unknown magic, an undecodable body or trailing bytes: the file is refused, logged and left byte-identical. That group keeps its legacy record. If the legacy record is a placeholder, the group stays inert, which is contained.
- **Downgrade.** Released binaries never open the sidecar. The legacy files stay parseable. Re-upgrading restores the state.
- **Timing.** On a managed install, the first sidecar write that changes behaviour waits for ADR 0094's host commit (ADR 0094: no format-upgrade writes before host commit).

### §5 Wire and capability (ADR 0093)

The new capability is **`group_terminal_attest_v1`**. It means the node issues and verifies ADR 0109 attestations, answers `group_attest_request`, and consumes re-seat authorisations. Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry.

- `group_attest_request` (typed DM): group, requester, head revision and hash, and the live `RecoveryRef`s with their causes.
- `group_attest_response`: `attested {ata}`, `on_chain {admin_head}`, `not_on_chain {admin_head}`, `reseat {authorisation, invite}` or `refused {reason}`. The reasons are `attester_quarantined`, `attester_behind`, `not_a_member`, `banned_or_revoked`, `base_beyond_retention` and `rate_limited`.
- Only an advert that is current, verified and positive counts. Unknown or card-only state sends nothing (ADR 0093). Messages fit the 49,152-byte DM budget.

| Pair | Behaviour |
|---|---|
| New joiner, old authority | No `admin_attestation`; today's marker or queue; the request path once a capable member is online |
| Old joiner, new authority | The key is omitted; result bytes are identical to today |
| New node, no capable peer online | No request is sent; typed `awaiting_attestation`; the force clear works as today |
| Old node | Receives nothing new; unchanged |

### §6 Serving and egress

Every S3 response, the join-carry ATA, and every re-seat invite and authorisation are class R under the lifecycle note. They use ADR 0107's serving guard, re-checked under the membership lock. For a re-seat, the guard's Active-seat check is replaced by "not Active, holds a current unconsumed authorisation". Each physical exchange is admitted immediately before its write, with no hidden transport resend and no gossip fallback. Removal, ban, revocation, quarantine or authorisation expiry cancels unsent exchanges. The re-seat join's own artifacts, and any later class-K delivery or resend, use the ADR 0107 guard and D60 (current recipient eligibility and current secret epoch). The dependency is ADR 0107's implementation, PR #1190.

### §7 Security (L4)

**Rules added.**
- (a) Classification: a walk-valid chain matching a verified ATA is a gap, not fork evidence. This relaxes #818's classification and, for owner-axis groups, ADR 0064's owner-only clear, as 0088 §3 assigns.
- (b) Pre-Welcome link apply inside an armed attested sequence, from pages or from the served chain (§2). This sits beside the TreeKEM adoption exclusion: it adopts no tree and no epoch, and it never jumps a gap.
- (c) Replacement of quarantined state under a verified re-seat authorisation (§3).

**Arguments.**
- (a) Every adopted link is a commit the node would apply if gossip had delivered it in order. ADR 0016 lets any active admin commit. The ATA changes how a held chain is classified, not any link check.
- (b) A pre-Welcome joiner holds no keys for those epochs (§2 item 4). Its keys come from its own Welcome, which is checked against the terminal's declared epoch (ADR 0064 §1a). Skipping their TreeKEM commits therefore loses nothing. Each state commit gets every check, and a policy or GSS-binding change is refused.
- (c) The swap installs only a record that joined through ordinary admission, and it needs an admin's manual act naming this node.

**Unchanged.** Signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion (there is no reconstructed jump; each link is gapless) all stay fail-closed.

**D41.** ATAs and authorisations act only on `subject`. They never install or clear a marker on any other node, and are never gossiped. Neither causes a commit by itself. A re-seat's only commits are the admin's removal and the ordinary join seal.

**Exposure, not yet ruled (Open question 1).**
- In an ownerless group, an admin removed on the canonical chain, but still an admin on the node's stale base, can attest its own branch. Rule (a) then lets that branch bypass the quarantine that #818's classifier would install. The node follows the branch and nothing else changes. Canonical evidence arriving later installs a marker that this ATA cannot retire.
- In an owner-axis group, the same holds when no owner v2 attestation covers the gap. Owner mandates still bind admissions where the attester is recorded-capable and past grace (ADR 0064 §1b). Removals, renames, role changes and Unknown-tier admissions carry no mandate.

### §8 Typed states (L3)

`GET /groups/:id` and the ADR 0066 §5 refusal body gain an additive `recovery` object. Its `state` is one of:
- `catching_up {attested_by, verified, cursor, segment_terminal}`
- `awaiting_attestation {asked, next_retry_at, reason}`
- `manual_clear_required {ref}`
- `reseat_required {cause, ref}`
- `reseat_in_progress {authorised_by, phase, expires_at}`

The join state `catching_up` mirrors it. Admins see pending requesters at `GET /groups/:id/recovery`, with a bounded, in-memory list.

### §9 What is superseded

| ADR | Text superseded in part | Replaced by |
|---|---|---|
| 0064 Decision §3 | A marker clears only on an owner-anchored commit; a non-owner-axis marker is preserved indefinitely, and its recovery is unresolved | A stale-base node also retires its own marker under §2. A forked node is re-seated only under §3. Owner-anchored clears are unchanged |
| 0066 §2 | A `no_anchor` marker is never cleared by any commit; the manual clear is its only exit | It also retires under §2, for its own node only (D41). The manual clear stays, and §3 adds the admin re-seat |

### §10 Gates

0088's acceptance order is: the contract, then S2 and S8, then S4 and S3, then S5, then S6, then S7. Here "S8" means S8 (a), ADR 0107 (Accepted). S8 (b), ADR 0114, is accepted after S4, as ADR 0107 states.

S3's code merges only after all of these:
- this ADR is Proposed on `main`;
- David has Accepted it (ADR 0087 rule 8);
- each red W3-H case below is committed and shown red on `main`;
- PR #1190 is merged, for §6.

S3 code lands on the single `named_groups.rs` lane.

## Consequences

### Positive

- Stale-base joins converge under any one capable admin, including the removal gap. Home groups are excluded until S7 (§4).
- #871 gets an audited exit that keeps containment until the replacement is installed.
- Released binaries keep starting on every S3 data directory.

### Negative / Trade-offs

- The §7 exposure stands until it is ruled.
- Home stale-base joins keep today's behaviour until S7 or Open question 5 lifts the exclusion.
- Re-seating an Active subject costs a removal and a rekey, until S8 (b).
- Bytes still travel by today's paths (DM-paged catch-up, in-memory logs, the 10-minute staged Welcome) until S5 and S8 (b).
- During a downgrade, a group under admin-attested recovery is inert.

### Neutral / Operational

- New counters: `admin_attest_issued`, `admin_attest_refused{reason}`, `quarantine_retired{cause}`, `reseat_authorised`, `reseat_swapped`.
- Release notes drop the #818 "just-in-time invites" mitigation once S3 ships.

## Validation

**Tracking.** File one issue for the S3 cases under #1164. Each red case must be committed and shown red on `main` before S3's code merges.

**Harness model.** Every node has a simulated clock that the harness alone advances. The harness holds every message and releases them only in the order listed. "Partition N" means holding everything to and from N. Steps drive the public API, and each step runs to quiescence before the next.

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
| H-S3-b (L1, promoted admin) | S0 with A on the previous release. A `PATCH .../members/M1/role` to admin (r+1). J joins; A seals (r+2). Advance 130 s, then one request interval | Main: J stays marked. Candidate: J asks M1, which is provisional; J walks its kept served chain, which proves M1's promotion at r+1; only then does the ATA arm; J applies r+1, replays r+2, retires its marker (`attested_catchup`) and holds keys | red |
| H-S3-c (#871, gate only) | OwnerCertified group: owner O, admins A and X. Invite I at r. Partition X; O removes X (r+1). J joins; O seals (r+2) with v2; J's gate arms. Hold O's gossip of r+1 from J. On X, rename (r+1′); release r+1′ to J only, then the catch-up pages. Advance 30 min | Main: every page refused; J stays at r+1′ with no marker and no typed state. Candidate: after `GATE_STALL`, `reseat_required {not_on_chain, Gap(..)}`, unchanged to the end of the advance; then A removes J (r+3) and calls reseat; J stays contained until the swap, is Active with keys at r+4, and O's next rename applies | red |
| H-S3-c2 (both records) | H-S3-c, also releasing canonical r+1 to J by gossip | J holds a marker and the gap record; the authorisation names one; the swap retires both | red |
| H-S3-s (segments, restart) | S0 with the segment length set to 2 by test configuration. The gap is 3 links (two removals and a rename) before J's seal. Restart J between segments | A 2-link segment covers exactly 2 links; the exhausted segment admits nothing; after the restart the second ATA arms from J's head; J converges | control |
| H-S3-x (conflict) | S0 with A on the previous release and admins B and C promoted before step 4. Partition B; B commits r+1′. J joins and is marked; J asks B (no reply), then C, and arms C's ATA. Heal B, and release B's late reply | Nothing past the common prefix applies; `reseat_required {attestation_conflict}` | control |
| H-S3-d (D41, L4) | H-S3-a's nodes | An ATA for J delivered to M1 does nothing; no node commits because of any ATA; X's ATA leaves an off-branch marker in place; forged, expired, non-admin, wrong-subject and stale-`RecoveryRef` authorisations are refused with typed reasons; no re-seat happens without the route; a sibling marker on an on-chain node gives `manual_clear_required`; a non-admin's provisional ATA with bogus hashes blocks no page and causes no `reseat_required`; a flood from members and from non-members hits `rate_limited` before classification, with no signatures made and no recovery-list growth past one entry per requester; a removed, contained J is authorised on a `Removal` basis and recovers | control |
| H-S3-m (versions) | Each §5 row with one released v0.46.x node. Stop J between segments in H-S3-s and start the released v0.46.x binary on its data directory; then start the candidate again | Old-authority bytes are unchanged. Run on the released binary: it starts; after reload the group has no Active and no admin seat in either view; `POST /groups/:id/invite` is refused; the state revision does not move (no commit); no page applies. The sidecar sha256 is unchanged. Repeat with an OwnerCertified group in both views. The candidate resumes and converges | control |

**Non-regressions** stay green unchanged:
- `stale_base_treekem_joiner_owner_anchored_gap_is_not_fork_evidence`, `stale_base_treekem_sibling_terminal_with_genuine_owner_attestation_quarantines`, `forking_catchup_responder_adopts_nothing_under_anchored_gap`, `honest_multicommit_gap_converges_page_by_page_under_gate` and `adr0064_s4_removed_admin_fork_to_joiner_quarantines` (all in `hs_f2_membership_cluster.rs`);
- `adr0066_ordinary_group_conflict_sets_a_no_anchor_marker` and `adr0066_unauthenticated_conflict_never_quarantines_an_ordinary_group` (in `fork_quarantine.rs`);
- PR #1181's fault cells, ADR 0106's carry tests and ADR 0107's serving-guard tests.

**Persistence.**
- Fault-inject `ReplacedNotDurable`, `NotReplaced` and `Err` on each write of each transition. Assert that nothing is published and the record stays contained.
- Kill the process between the sidecar write and the legacy write. Assert that reconciliation never reduces containment.
- Unknown-magic and truncated sidecars are refused and left byte-identical.
- In-process boundary tests at `ATA_MAX_LINKS` and `ATA_MAX_LINKS + 1` links.
- The first release that writes the format adds a fixture written by that release (ADR 0085 rule 6).

**Review trigger.** Revisit when S5 lands control-blob catch-up, or when S8 (b) offers a re-Welcome.

## Open questions for David

1. **The §7 exposure.** Accept it as stated for both populations? Or narrow it, for example to ATAs signed by the joiner's own sealer, or for owner-axis groups to owner attestation only (which keeps the Home L1 gap)? A named ruling is needed.
2. **Owner-axis forked nodes.** 0088 §3 requires manual authorisation for every forked node, but §2 item 7 lists only ordinary unanchored forks. Is #871's owner-axis wait an item 7 entry, or should the owner's attestation re-seat that node automatically?
3. **Subject consent.** Is the admin's authorisation enough, or must the subject's operator also confirm a re-seat?
4. **Who acts in §2 item 7.** ADR 0066's manual clear is the node's own operator. The re-seat is a group admin. The draft keeps both. Is that the intent?
5. **Home groups.** The safe default (§4) excludes Home groups from admin-attested recovery, so S3 does not close the Home L1 case. Keep that until S7? Or lift it once a released-binary test shows no duplicate Home and no `home.json` change, and block activation if the test fails?
6. **Rule (b) scope.** Rule (b) applies the served chain per link, which is ADR 0106's deferred option 2 under an attestation. Accept it in S3? Or limit S3 to membership-event pages, leaving gaps with renames or role changes, and the promoted-admin case, to S5?
7. **Values (recommendations only):**
   - `ATA_MAX_LINKS`: 64
   - `ATA_ARM_WINDOW`: 10 min
   - `ATA_ARMED_LIFETIME`: 30 min
   - `GATE_STALL`: 10 min
   - Request backoff: 60 s, doubling to 1 h
   - Responder limits: 1 response per requester per interval; 4 concurrent builds; 32 signatures and 1 MiB of responses per minute
   - Recovery list: 32 per group, 24 h
   - Retired records: 16 per group

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

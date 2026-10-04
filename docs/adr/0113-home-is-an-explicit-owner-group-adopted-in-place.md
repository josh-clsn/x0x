# ADR 0113: Home Is an Explicit Owner Group, Adopted in Place (0088 S7)

- **Status:** Proposed
- **Date:** 2026-10-04 (r2 after cross-model review)
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model review r1: request changes; r2 pending)
- **Slice:** S7 of [ADR 0088](./0088-group-liveness-contract.md) (group liveness), bound to this number by D63.
- **Supersedes (upon acceptance):** [ADR 0060](./0060-one-home-per-owner.md) (Home is elected); [ADR 0069](./0069-home-wait-for-sync-before-auto-provisioning.md) (Home waits for owner sync); [ADR 0038](./0038-home-owner-certified-personal-space.md) in part: the auto-provisioned personal space, and the seal-time re-checks. The seal-time part takes effect only once S4 (ADR 0110) is in effect, together with the delivery guards in §4. ADR 0038 as a whole is superseded only when S2 (ADR 0108), S4 and S7 are all Accepted.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** #824, #1023, #1107, #1143, #1164, #1190, #449; rulings D16, D38, D42, D54, D60, D63; ADR 0041, 0059, 0062, 0065, 0084, 0085, 0087, 0093, 0106, 0107, 0108 (S2), 0110 (S4), 0111 (S5). Related work only: the join-artifact serving lifecycle note on the #1190 branch.

## Context

Today Home rests on three mechanisms. S7 replaces all three.

1. **Auto-provisioning (ADR 0038, ADR 0069).** At startup, `provision_home_at_startup` (`src/server/mod.rs:1451–1452`) runs `provision_home_steps` (`src/server/routes/home.rs:923`). Step 4 creates a fresh Home (`home.rs:1142–1150`). Step 3b defers that create for up to `(rank + 1) × 90 s` while owner sync runs (`home.rs:1135`, `HOME_POINTER_SYNC_WAIT` at `home.rs:791`, rank at `home.rs:846`). After the deadline the device creates anyway. The fallback trusts a timer, not proof. 0.45.0 has no wait at all.
2. **Election (ADR 0060).** The Tier-1 `(HomePointer, "home")` register (`src/owner_sync.rs:174`) names the canonical Home. A device mints over a stored value when its own Home is strictly older (`owner_sync.rs:2123`), or when it can prove the stored Home is retired (`owner_sync.rs:2108`). The merge itself is last-writer-wins by record clock (`owner_sync.rs:1437–1520`). `resolve_home` (`home.rs:320`) follows the register, so a merged value can move a device off the Home it uses.
3. **Seal-time re-check (ADR 0038).** Every OwnerCertified seal goes through `seal_commit_owner_certified` (`src/server/routes/named_groups.rs:22583`), from about 20 call sites. It evaluates `owner_cert_verdict` (`src/groups/mod.rs:1509`) over **every** active seat and refuses unless all are Clean (`named_groups.rs:22637–22668`). A revoked seat returns `OwnerCertifiedEvictionRequired`, and the explicit seal route evicts it (`named_groups.rs:21758`, `21261`). This is today's revocation path. Restored groups stay quarantined until an all-clean verdict (`named_groups.rs:30339`, `30417`, `22944`). This seal also covers seats that never passed an admission check: a policy change can opt an existing roster into OwnerCertified (`named_groups.rs:23758–23789`).

The failures, and the 0088 rule each one breaks:

| Issue | Failure | Rule |
|---|---|---|
| #824 residual | An admin device with a copied owner key, cut off from the pointer holder past its deadline, creates its own Home. `POST /home/seat` then mints into it with 200: the duplicate guard runs only when a device already holds two Homes (`home.rs:1762`). | L1: which group is "the Home" depends on reaching one particular device in time. L3: the wrong answer is a silent success. |
| Election | A device that later syncs with an older Home rewrites the register. Every device that follows it reports `adoption_pending` for the Home it uses. | L1: the outcome depends on one particular device (the holder of the oldest Home). |
| #1023 structure | An add needs a fresh Clean verdict for every seat. A promoted admin that has verified every seat still cannot admit once evidence about one unrelated seat changes. Typically the owner device re-issues its certificate and goes offline: the embedded copy becomes "stale" (`src/groups/mod.rs:1575`), and every retry refuses with `OwnerCertMemberPending` or `OwnerCertifiedEvictionRequired`. | L1: admission depends on a particular device. L2: the wait is not on the §2 list, because the joiner's admission does not need that seat's new evidence. |

Where the admin never held a seat's certificate bytes, the wait is for evidence whose holders are all offline. That is §2 item 8 and S5's case (ADR 0111; `trimmed_member_added_all_holders_offline_stays_pending`, `src/server/routes/named_groups/tests/r19_cert_carry.rs:1329`). The #1143 trigger, an anonymous announce, is S2's.

**#1107 is not an S7 issue.** Its Home half (Home seals fail after a restart until the owner consents again) comes from the anonymous announce contradicting the roster certificate. S2 (ADR 0108, D38) fixes that rule. The rest of #1107 (persisted consent, certificates on stream, exec, forward and SyncV1 opens) belongs to ADR 0089. S7 does not list #1107 as closed.

## Decision Drivers

- D42: adopt the canonical Home in place, with the same group, roster and data. Stop election and auto-provisioning. Duplicates stay until their user retires them.
- D16: Home is an explicit owner group, with the owner certificate checked at admission.
- 0088's supersession table: the seal-time re-check is today's revocation path, so it retires only once S4 is in effect.
- Retiring that re-check must not release keys to an ineligible member (L4, D60).
- No new closed-enum Tier-1 kind and no change to a signed value's shape (D42; ADR 0060's three compatibility defects). Old daemons (0.45, 0.46) that still elect or auto-provision must not fork the adopted Home.

## Considered Options

1. **A local, persisted binding plus adopt-in-place (chosen).** Each device records which group is its Home. The register stays published for old peers but no longer chooses anyone's Home.
2. **Keep the election and only stop auto-provisioning.** Rejected: D42 stops election, and an older Home could still move every device off the Home it uses.
3. **A deterministic owner-derived group id (ADR 0060 option 2).** Rejected: existing Homes have random ids, so they cannot be adopted in place.
4. **A new Tier-1 record kind, or a new field in `HomePointer`.** Rejected: D42 forbids a new closed-enum kind. Old decoders abort the whole owner-sync session on an unknown kind, and a shape change breaks signatures over serialized bytes (ADR 0060, *Deliberately not decided here*).
5. **Re-mint the adopted pointer whenever the register names another group.** Rejected: it starts a register war with old daemons, which is the #449 oscillation.
6. **Retire the seal-time re-check now, before S4 and the delivery guards.** Rejected: it would remove today's only revocation path (0088 §3) while resends still skip eligibility checks.
7. **Create a fresh explicit Home and migrate data into it.** Rejected: D42 requires adoption in place.

## Decision

### §1 Home is an explicit owner group

- A Home is a named group with the exact Home policy for its owner (`home.rs:56`) and sealed Home metadata. The shape is unchanged. Nothing new goes on the wire.
- **Auto-provisioning stops.** Startup no longer creates a Home. The deferral, `home_creator_rank`, `wait_for_owner_sync_round` and `HOME_POINTER_SYNC_WAIT` are removed. `GET /home` no longer reports `provisioning_pending`. Startup keeps restore verification and the repair of an existing Home (`home.rs:721`, steps 0–1) unchanged.
- **Explicit creation.** A new `POST /home` route and `x0x home create` CLI create a Home. They need the durable owner token, like every Home mutation (`home.rs:1676`), and an owned install with an agent certificate. Under the binding gate (§6) they refuse with 409 `home_exists` when a binding exists, 409 `binding_pending` while the §2 settle rule applies, and 409 `elsewhere` when the effective canonical pointer names a Home that is not provably retired. Otherwise they record a create intent, then create through the unchanged `create_named_group` and `stamp_and_seal_home` path, with today's linearisation against pointer arrival (`home.rs:1080–1125`). Then they bind and publish the pointer.
- **Binding.** Each device persists one answer to "which group is my Home" (§6). Three writers set it: adoption (§2), explicit creation, and completing a Home-mode join (`mode: "home"`, `named_groups.rs:473`) as an active member with keys. A Home-mode join rebinds the device, because the admin's seat plus the device's redemption is the owner's explicit choice.
- **Resolution.** `resolve_home` returns the bound group when it passes `find_home`'s trusted predicate (`home.rs:373`): Home metadata, exact Home policy, this agent active, not withdrawn, not a pending stub. Otherwise the device is unbound. A register value never moves a bound device.

### §2 Adoption in place (D42)

Adoption runs at startup after restore and §6 recovery, and again after each successful owner-sync session, while the binding is **absent**. It runs under the binding gate and reads only local state. Let C be the groups that pass `find_home`'s predicate, and P the effective canonical pointer (`home.rs:303`).

**Settle rule.** If P was empty when the daemon started and other machines are enrolled for this owner, adoption binds nothing until one owner-sync session has completed since startup. The peer publishes its pointer before the exchange (#863), so the session settles P. Until then `GET /home` reports `binding_pending`, which names the wait. Meanwhile the device publishes its candidate into an empty register before each session, as today, so old peers yield.

| Condition | Result |
|---|---|
| P names a group in C | Bind P. |
| P is empty and C is not empty | Mint the smallest stable id in C into the empty register (today's pick, `src/server/routes/sync.rs:187`), then bind it. |
| P names a group outside C, and C is not empty | Unbound. `GET /home` reports `adoption_pending`. C are duplicates. |
| C is empty | Unbound. `GET /home` reports `elsewhere` when P is known, else 404 with the next step `POST /home`. |

Adoption writes only the binding file. It makes no commit and no seal. `named_groups.json`, `home-suite-groups.json`, TreeKEM state and stores stay byte-identical. Duplicates stay until their user retires them through the existing withdraw path. They stay listed in `GET /home` `duplicates[]` (`home.rs:107`). Nothing is retired automatically. A wait in `binding_pending` lasts only while every enrolled owner machine is offline, which is §2 item 8. If a machine is gone for good, the exit is to revoke its enrollment.

### §3 Election stops

- An S7 daemon's Home never follows the register. The register stays only so that old peers keep yielding.
- A bound S7 daemon mints the `("home")` record only for its bound Home, in three cases: into an empty register; as the primary-agent refresh of the same group (`owner_sync.rs:2112–2119`); or over another group when the bound Home is strictly older under ADR 0060's `(provisioned_at_ms, group_id)` order (`owner_sync.rs:2123`). The last case keeps old peers converging on the adopted Home after a last-writer merge. The order is monotone, so it terminates. An unbound S7 daemon may mint only its §2 candidate, and only into an empty register.
- The retired-pointer rule (`owner_sync.rs:2108`) runs only inside explicit creation.
- It still publishes its pointer before each session (`owner_sync.rs:2664`), so 0.46 daemons see a populated register and yield.
- A merged value that names another group does not move a bound device. `GET /home` stays `local` and adds `pointer_conflict` with that group id. Unless its bound Home is strictly older, the device does not re-mint, so there is no register war.
- `POST /home/seat` mints only into the bound Home. It holds the binding gate across resolution and mint. An unbound device refuses with 409 `home_unbound`. This closes the #824 residual.

### §4 Admission-only certificate check (gated)

**Activation.** §4 takes effect only when all three of these are Accepted and shipped, in the same release or earlier:
- S4's revocation eviction (ADR 0110);
- ADR 0107's current-roster serving guard for join results and Welcomes;
- D60's current-eligibility rule for every GSS envelope delivery and resend. Today `publish_secure_share` publishes and schedules resends with no eligibility check (`named_groups.rs:1926–1955`).

The last two are PR #1190, planned for v0.46.2. §4's code merges after all three, on the single `named_groups.rs` lane (0088 §4). Until then today's seal-time re-check stays, with S2's verdict rule. §4 applies to every OwnerCertified group, because the seal wrapper is shared.

**Verified roster.** A node skips the re-check only on a group in which it has verified every active seat since it loaded the group. It tracks this with a new in-memory, per-group "verified roster" mark. The mark gates only the §4 skip, never any other operation.
- The mark is unset on load and on every wholesale roster install: restore, a join base and a catch-up snapshot. Only an all-clean full verdict sets it.
- While it is unset, every seal runs today's full verdict. Restore also keeps today's `owner_cert_reverify_required` quarantine unchanged; an all-clean verdict clears both, as today (`src/groups/mod.rs:1253`). Retiring this needs authenticated admission provenance per seat, which is future work outside S7.
- A seat added later is verified on entry: by the admission check (`named_groups.rs:22768`, called at `13570`, `19162`, `19376`, and bound into the roster entry at `13766`), or by the receiver's `MemberAdded` apply check (`named_groups.rs:11276`).
- A policy change that opts a group into OwnerCertified keeps its existing roster. That transition seal therefore always runs the full verdict and refuses unless every seat is Clean.

**On a verified roster:**
- Seals stop re-checking seats already verified. `seal_commit_owner_certified` no longer evaluates their evidence (bytes, digests, announce digests, grace, fetches in flight).
- An active seat whose agent or machine is in the local revocation set blocks every seal with the existing `OwnerCertifiedEvictionRequired` until S4's eviction commits.

**Delivery stays current.** Every delivery and resend of key material (GSS envelopes, Welcomes, join results) checks, at send time: current certificate validity including expiry, agent and machine revocation, containment (fork quarantine, withdrawal), and the current secret epoch. These are ADR 0107's and D60's checks. §4 keeps them unchanged and depends on them.

**Explicit eviction route.** `POST /groups/:id/state/seal` evaluates the whole roster (`named_groups.rs:21304–21314`). While the mark is unset it behaves exactly as today. On a verified roster it evicts only seats that are revoked, or whose committed certificate bytes fail verification on their own (expired, wrong owner, bad signature). It does not evict or refuse for missing or stale evidence (InGrace, DigestPending, a changed announce digest), so it no longer returns the pending refusal for those seats (`named_groups.rs:21409–21419`). Its expiry eviction stays as today until Q2 is ruled.

### §5 Security (L4)

- §1–§3 add and relax no acceptance rule. A binding only chooses among groups the device is already an active member of, under the existing trusted predicate. Creation keeps the durable-token gate and the owner-chain check (`named_groups.rs:14318`). Seating keeps the invite authority and the ADR 0059 Home-mode owner pin.
- §4 relaxes one rule: **on a verified roster, a seal no longer requires a fresh Clean verdict for seats this node already verified.** The argument:
  1. Provenance is local and explicit. A seat is skipped only after this node verified its certificate: at admission, when applying its `MemberAdded`, or in the all-clean verdict that set the mark. Wholesale installs and policy opt-ins are verified in full first. Restore keeps its quarantine.
  2. A verified certificate becomes invalid only by revocation, by expiry, or under a different owner.
  3. Revocation stays fail-closed: at every seal (local set), at every delivery and resend (D60), and by S4's bounded eviction. A different owner is a different group, because the owner axis is immutable once set (`named_groups.rs:23754–23771`).
  4. A re-issued certificate (a new announce digest) does not revoke the old one. Revocation is the tool for unbinding an agent.
  5. Expiry is still checked at every delivery and resend, and by the explicit eviction route. It is no longer checked at routine seals. A seated TreeKEM member with an expired certificate can still derive later epochs from published commits until it is removed. That is the cost; see Q2.
- The L4 fail-closed list is untouched: signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion.

### §6 Persisted state (ADR 0085) and the binding transaction

- **File.** One new file: `<data_dir>/home-binding.json`. It is a JSON object: `format` (1), `owner_user_id`, `bound` (null, or `group_id`, `source` = `adopted` | `created` | `seated`, `bound_at_ms`) and `pending` (null, or `kind` = `create` | `join`, `group_id` for a join, `started_at_ms`). It is written atomically and durably, with the sidecars' atomic-write helper, before any change is reported.
- **Three load states.** *Absent* (the file does not exist): unbound, and writers may run. *Readable*: format 1 for this owner. *Unreadable*: any read error, a body that does not decode, an unknown `format`, or another owner's binding. In the unreadable state every writer refuses: adoption does not run; `POST /home`, `POST /home/seat` and Home-mode joins refuse with 409 `binding_unreadable`; and the device mints no `("home")` record. `GET /home` reports `binding_unreadable` with the cause. The file is never rewritten. Recovery is explicit: upgrade to a binary that reads it, restore it, or remove it by hand (ADR 0085 rule 4). Unknown fields inside format 1 are ignored (rule 7).
- **One gate.** An async mutex, `home_binding_gate`, serializes every writer: adoption, creation, Home-mode join completion and startup recovery. Each writer re-reads the file and rechecks its precondition under the gate. Adoption writes only into an absent binding. Creation refuses over a bound one. A Home-mode join replaces it. Lock order: `home_binding_gate`, then owner-sync session slots (creation only), then `canonical_home_gate`, then the per-group membership lock, then `named_groups` and persistence. Owner-sync writers never take the binding gate, so there is no cycle.
- **Intents and crash recovery.** Creation durably writes `pending: create` before it creates the group. A Home-mode join writes `pending: join` with the invite's group id before redemption. The write that sets `bound` clears `pending`. At startup, under the gate and before adoption:
  - `pending: create`: count the Home-shaped groups this agent created at or after `started_at_ms`. With one, finish it (stamp and seal it if unstamped), bind it as `created`, and publish. With none, clear the intent. With more than one, enter the unreadable state with that cause. Today's startup crash recovery (step 2, `home.rs:1019`) runs only here.
  - `pending: join`: if this agent is an active member of that group and it passes the predicate, bind it as `seated`. Otherwise clear the intent and keep the old binding.
  - A crash after binding but before publication needs nothing: §3 publishes on the next pass.
- **Downgrade.** Older binaries never read this file. They run their own election and provisioning, as they always did, and leave the file intact. Re-upgrading restores the binding.
- **Unchanged:** `named_groups.json`; `home-suite-groups.json` (`HOME_SUITE_GROUPS_FILE`, `named_groups.rs:32762`); the advisory `home.json` marker, which is still written; the owner-sync record store; TreeKEM snapshots; the ADR 0062 pair.
- Rule 6: the first release that writes format 1 commits a fixture from its own encoder.

### §7 Wire, capability bit and mixed versions

S7 changes nothing on the wire. It adds no `SyncKind` or `SyncValue` variant (`owner_sync.rs:168–187`), and `HomePointer`'s signed shape is unchanged. No ADR 0093 bit is needed, so none is allocated. A later wire extension would allocate the next free bit at its own acceptance.

| Peer | Behaviour |
|---|---|
| 0.46.x device enrolled with a bound S7 device | It sees a populated register before each session and yields. It does not provision. |
| 0.45.0 device | It has the same election order (`(provisioned_at_ms, group_id)`) but no wait and no publish-before-session. It creates a Home at startup whenever its own store knows no pointer. |
| Old device that creates a duplicate (no pointer in time) | Its Home is newer. If its record wins the last-writer merge, a bound S7 device re-mints the older adopted Home, so the register returns to it. S7 devices stay bound. |
| Old device that holds a strictly older Home | Its election can rewrite the register, and old devices follow it. S7 devices stay bound, report `pointer_conflict` and do not re-mint. |
| Old admin under §4 | It still re-checks at seal, which is stricter. Its commits apply on S7 peers unchanged. |
| S7 admin's commits on old peers | Accepted. Receivers check only the added member's certificate (`named_groups.rs:11276`), never the whole roster. |

## Consequences

### Positive

- One device-local answer to "which group is my Home". The register stops moving devices.
- No startup wait and no timer-made duplicates. #824's residual closes.
- After §4 activates, an admin that has verified its roster admits while the owner device is offline, whatever later happens to other seats' evidence. #1023's structure closes.

### Negative / Trade-offs

- A new owner must create Home explicitly (see Q1).
- Legacy duplicates and old-binary duplicates stay until the user retires them. In a mixed fleet, old devices can follow a register value that S7 devices ignore (see Q3).
- After §4, a seated member whose certificate expires gets no new key deliveries but can still follow TreeKEM commits until it is removed (see Q2).
- A restarted node still needs one all-clean verdict per OwnerCertified group before §4 applies to it.

### Neutral / Operational

- `docs/api-reference.md` changes: `POST /home`; the `binding_pending` and `binding_unreadable` states; the `pointer_conflict` field; the 409 reasons `home_exists`, `home_unbound`, `binding_pending` and `binding_unreadable`; and the removal of `provisioning_pending`.
- Placement fields in Home metadata are untouched; the roaming cut is ADR 0102's (prov.).

## Validation

**Gate (D16, D54).** The W3-H harness (#1164) does not exist yet. Each red case below must be committed on `main` and fail there before any S7 code merges. It runs inside the isolated loopback namespace: `python3 scripts/dev/test-isolated.py nextest --all-features -- -E 'test(w3h_s7_)'`. The selector names are proposals for #1164. Every node is a real daemon on a harness-built data dir, and all nodes share one owner unless stated.

| Case (selector) | Nodes and preparation | Steps | Red on `main` | Green (exit test) |
|---|---|---|---|---|
| H7-1 `w3h_s7_h7_1_copied_key_creates_no_duplicate` (#824) | O holds Home H and has published its pointer. B has the copied `user.key`, an owner-issued agent certificate, mutual enrollment with O, an empty owner-sync store and no Home-shaped group. | Start B. Drop every O↔B session for 200 s. Call `POST /home/seat` on B for a third agent id. Lift the block. O seats B; B redeems in Home mode. | B holds a second Home-shaped group within 180 s. The seat returns 200 with a `group_id` other than H. | B never holds a group other than H. During the block, B's `GET /home` is `binding_pending`, `POST /home` is 409 `binding_pending` and the seat is 409 `home_unbound`. After redemption B is bound to H as `seated`. |
| H7-2a `w3h_s7_h7_2a_unbound_older_home_takes_nothing` | O and A are bound to H. L holds H0 with an older `provisioned_at_ms`. L's store is seeded with O's record for H (P = H). L has no binding file. | Start L. Enroll L with O both ways. Run two sessions in each direction. | L's election mints H0 over H. O and A report `adoption_pending`, and seats on O refuse. | L mints nothing and reports `adoption_pending`. The register stays H everywhere. O and A stay `local`, and a seat on O succeeds. |
| H7-2b `w3h_s7_h7_2b_upgraded_older_home_moves_no_device` | As H7-2a, but L's store holds its own H0 record, as its reconcile pass mints it (`owner_sync.rs:2817`). | Start L; it binds H0. Enroll and sync as above, then three more sessions. | The register flips to H0. O and A report `adoption_pending`, and seats on O refuse. | The register may hold H0. O and A stay `local` in H with `pointer_conflict` = H0, and seats into H work. L stays `local` in H0. The record version does not change over the last three sessions. |
| H7-3 `w3h_s7_h7_3_admission_ignores_unrelated_seat_evidence` (#1023) | O is the creator and owner device. P is a promoted admin that joined with O's certificate bytes and has verified every seat since load. J is an owner-certified joiner with an invite from P. | O re-issues its certificate. P receives O's new certificate-bearing announce digest but not the bytes. O goes offline. J redeems; poll for 120 s. | P refuses every retry with `OwnerCertMemberPending [O]` or `OwnerCertifiedEvictionRequired [O]`. J ends `TimedOut`. | With S2, S4, the §4 guards and §4 in place: P seals J's add within the join bound. O applies the commit when it returns. Stays red with S2 and S5 alone. |

**Safety controls.** C1–C3 must be green on the release that activates §4. They need the ADR 0107 and D60 code, so they may be red on `main` today. That is §4's prerequisite, not S7's red case.

- **C1 `w3h_s7_c1_revocation_race`:** Home {O, P, M}. O revokes M's agent, and separately M's machine, while P holds a pending GSS envelope resend and a staged Welcome and join result for M, and J's add is in flight. No key material reaches M after P holds the revocation. P's seals refuse until S4's eviction commits within its bound. M cannot decrypt the next epoch.
- **C2 `w3h_s7_c2_expiry_race`:** M's certificate expires between staging and delivery, and between two resends. Nothing is delivered or resent to M after expiry. M stays seated until Q2 is ruled.
- **C3 `w3h_s7_c3_quarantine_race`:** the group gets a fork-quarantine marker, or is withdrawn, while a resend to M is pending. The resend is dropped.

**Non-regressions.**

- An uncertified or foreign-owner joiner is still refused at admission and on apply.
- A policy opt-in into OwnerCertified with one uncertified seat is refused.
- A restarted or snapshot-installed node runs the full verdict until one all-clean seal. A fresh joiner's other operations are not gated by the mark.
- An unowned install writes no binding, no Home and no records.
- A process restart keeps the binding and the same Home.
- Two concurrent `POST /home` calls create exactly one group.
- A crash injected after group persistence and before the binding write resumes to one bound Home.
- An unreadable binding file stays byte-identical, and no writer runs.
- Adoption leaves `named_groups.json`, `home-suite-groups.json` and the TreeKEM snapshot byte-identical; the `hs451_downgrade_safety` tests stay green.
- ADR 0106 and 0107 join paths and ADR 0062 pair recovery are unchanged.
- The ADR 0069 seat tests are adapted: a seat mints only into the bound Home.

**Mixed-version check (required, D42).** Run with the real 0.45.0 and 0.46.x release binaries inside the isolated namespace.

- M1: a 0.46.x device enrolled with a bound S7 device creates no Home. With its sessions blocked past its deadline it creates a duplicate. After the block lifts, the register converges on H and S7 devices stay bound to H. M1b repeats this with 0.45.0, which creates at once.
- M2: H7-2b with L on 0.46.x, and again with L on 0.45.0. The register flips to H0. O and A stay `local` in H with `pointer_conflict` = H0, and the record version stops advancing.
- M3: frozen 0.45.0 and 0.46.x decoders decode an S7-minted `HomePointer` record and verify its owner signature. S7 decodes and verifies records minted by both release encoders, from committed fixtures. `SyncKind::ALL.len() == 4` (`owner_sync.rs:3549`).
- M4: real owner-sync sessions between S7 and each release binary, with each side initiating. Every session completes, `HomePointer` merges, and no session aborts on decode.
- M5: downgrade to 0.46.x on the same data dir and upgrade again. The old binary ignores `home-binding.json`, and the re-upgraded daemon resolves the same Home. A 0.45.0 downgrade is already governed by ADR 0085.
- M6 (§4): 0.45.0 and 0.46.x members apply an add sealed by an S7 admin that did not re-check O's seat.

**Review triggers:** S4's bound or trigger list changes; any new writer of the `("home")` register or of the binding file; a request to retire duplicates automatically.

## Open questions for David

- **Q1, explicit creation at onboarding.** Auto-provisioning stops (D42). Should the owner's setup step (creating `user.key` and certifying the first agent) also create the Home as part of the same explicit act? Or must the owner run `x0x home create` separately?
- **Q2, expiry after admission.** Routine seals stop re-checking (0088 §3). Delivery and resend still refuse an expired certificate (D60), and the explicit eviction route still evicts one. Should expiry also be automatic, as an S4 eviction trigger? If not, a seated TreeKEM member whose certificate expired can derive later epochs from published commits until an admin runs the explicit route or removes it.
- **Q3, old-binary duplicates.** Is "a 0.45 or 0.46 device can still create or follow a duplicate Home" a release-note known limitation until every owner device runs S7? Or do you want a minimum version for Home?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

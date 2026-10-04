# ADR 0113: Home Is an Explicit Owner Group, Adopted in Place (0088 S7)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** TBD (a cross-model review follows)
- **Slice:** S7 of [ADR 0088](./0088-group-liveness-contract.md) (group liveness), bound to this number by D63.
- **Supersedes (upon acceptance):** [ADR 0060](./0060-one-home-per-owner.md) (Home is elected); [ADR 0069](./0069-home-wait-for-sync-before-auto-provisioning.md) (Home waits for owner sync); [ADR 0038](./0038-home-owner-certified-personal-space.md) in part: the auto-provisioned personal space, and the seal-time re-checks. The seal-time part takes effect only once S4 (ADR 0110) is in effect. ADR 0038 as a whole is superseded only when S2 (ADR 0108), S4 and S7 are all Accepted.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** #824, #1023, #1107, #1143, #1164, #449; rulings D16, D38, D42, D54, D63; ADR 0041, 0059, 0062, 0065, 0084, 0085, 0087, 0093, 0106, 0108 (S2), 0110 (S4), 0111 (S5).

## Context

Today Home rests on three mechanisms. S7 replaces all three.

1. **Auto-provisioning (ADR 0038, ADR 0069).** At startup, `provision_home_at_startup` (`src/server/mod.rs:1451–1452`) runs `provision_home_steps` (`src/server/routes/home.rs:923`). Step 4 creates a fresh Home (`home.rs:1142–1150`). Step 3b defers that create for up to `(rank + 1) × 90 s` while owner sync runs (`home.rs:1135`, `HOME_POINTER_SYNC_WAIT` at `home.rs:791`, rank at `home.rs:846`). After the deadline the device creates anyway. The fallback trusts a timer, not proof.
2. **Election (ADR 0060).** The Tier-1 `(HomePointer, "home")` register (`src/owner_sync.rs:174`) names the canonical Home. A device mints over a stored value when its own Home is strictly older (`owner_sync.rs:2123`), or when it can prove the stored Home is retired (`owner_sync.rs:2108`). `resolve_home` (`home.rs:320`) follows the register, so a newly merged value can move a device off the Home it uses.
3. **Seal-time re-check (ADR 0038).** Every OwnerCertified seal goes through `seal_commit_owner_certified` (`src/server/routes/named_groups.rs:22583`), from about 20 call sites. It evaluates `owner_cert_verdict` (`src/groups/mod.rs:1509`) over **every** active seat and refuses unless all are Clean (`named_groups.rs:22637–22668`). A revoked seat returns `OwnerCertifiedEvictionRequired`, and the explicit seal route evicts it (`named_groups.rs:21758`, `21261`). This is today's revocation path. A restored OwnerCertified group stays quarantined until such a seal (`named_groups.rs:30339`, `22944`).

The failures, and the 0088 rule each one breaks:

| Issue | Failure | Rule |
|---|---|---|
| #824 residual | An admin device with a copied owner key, cut off from the pointer holder past its deadline, creates its own Home. `POST /home/seat` then mints into it with 200: the duplicate guard runs only when a device already holds two Homes (`home.rs:1762`). | L1: which group is "the Home" depends on reaching one particular device in time. L3: the wrong answer is a silent success. |
| Election | A device that later syncs with an older Home rewrites the register. Every device that follows it reports `adoption_pending` for the Home it uses. | L1: the outcome depends on one particular device (the holder of the oldest Home). |
| #1023 structure | An add needs a Clean verdict for every seat. A promoted admin cannot admit a joiner while evidence about an unrelated seat, usually the offline owner device, is unresolved: `OwnerCertMemberPending` repeats until the joiner gives up. The in-process analogue is `trimmed_member_added_all_holders_offline_stays_pending` (`src/server/routes/named_groups/tests/r19_cert_carry.rs:1329`). | L1: admission depends on a particular device. L2: the wait is not on the §2 list, because the joiner's admission does not need that seat's evidence. |

**#1107 is not an S7 issue.** Its Home half (Home seals fail after a restart until the owner consents again) comes from the anonymous announce contradicting the roster certificate. S2 (ADR 0108, D38) fixes that rule. The rest of #1107 (persisted consent, certificates on stream, exec, forward and SyncV1 opens) belongs to ADR 0089. S7's §4 later removes the seal's dependency on announce evidence altogether. That is a backstop, not the fix, so S7 does not list #1107 as closed. The #1143 trigger is S2's. The case where every holder of the joiner's own evidence is offline is §2 item 8 and S5's (ADR 0111).

## Decision Drivers

- D42: adopt the canonical Home in place, with the same group, roster and data. Stop election and auto-provisioning. Duplicates stay until their user retires them.
- D16: Home is an explicit owner group, with the owner certificate checked at admission.
- 0088's supersession table: the seal-time re-check is today's revocation path, so it retires only once S4 is in effect.
- No new closed-enum Tier-1 kind and no change to a signed value's shape (D42; ADR 0060's three compatibility defects).
- Old daemons that still elect or auto-provision must not fork the adopted Home.

## Considered Options

1. **A local, persisted binding plus adopt-in-place (chosen).** Each device records which group is its Home. The register becomes advisory and is still published for old peers.
2. **Keep the election and only stop auto-provisioning.** Rejected: D42 stops election, and an older Home could still move every device off the Home it uses.
3. **A deterministic owner-derived group id (ADR 0060 option 2).** Rejected: existing Homes have random ids, so they cannot be adopted in place.
4. **A new Tier-1 record kind, or a new field in `HomePointer`.** Rejected: D42 forbids a new closed-enum kind. Old decoders abort the whole owner-sync session on an unknown kind, and a shape change breaks signatures over serialized bytes (ADR 0060, *Deliberately not decided here*).
5. **Re-mint the adopted pointer whenever the register names another group.** Rejected: it starts a register war with old daemons, which is the #449 oscillation.
6. **Retire the seal-time re-check now, before S4.** Rejected: it would remove today's only revocation path (0088 §3).
7. **Create a fresh explicit Home and migrate data into it.** Rejected: D42 requires adoption in place.

## Decision

### §1 Home is an explicit owner group

- A Home is a named group with the exact Home policy for its owner (`home.rs:56`) and sealed Home metadata. The shape is unchanged. Nothing new goes on the wire.
- **Auto-provisioning stops.** Startup no longer creates a Home. The deferral, `home_creator_rank`, `wait_for_owner_sync_round` and `HOME_POINTER_SYNC_WAIT` are removed. `GET /home` no longer reports `provisioning_pending`. Startup keeps restore verification and the repair of an existing Home (`home.rs:721`, steps 0–1) unchanged.
- **Explicit creation.** A new `POST /home` route and `x0x home create` CLI create a Home. They need the durable owner token, like every Home mutation (`home.rs:1676`), and an owned install with an agent certificate. They refuse with 409 `home_exists` when this device has a valid binding. They refuse with 409 `elsewhere` when the effective canonical pointer names a Home that is not provably retired. Otherwise they first complete any unstamped Home-shaped group this agent created (today's startup step 2, `home.rs:1019`, moved here), or create one through the unchanged `create_named_group` and `stamp_and_seal_home` path. Then they write the binding and publish the pointer.
- **Binding.** Each device persists one answer to "which group is my Home" (§6). It is set in exactly three ways: adoption (§2), explicit creation, and completing a Home-mode join (`mode: "home"`, `named_groups.rs:473`) as an active member with keys. A Home-mode join rebinds the device, because the admin's seat plus the device's redemption is the owner's explicit choice.
- **Resolution.** `resolve_home` returns the bound group when it passes `find_home`'s trusted predicate (`home.rs:373`): Home metadata, exact Home policy, this agent active, not withdrawn, not a pending stub. Otherwise the device is unbound. A register value never moves a bound device.

### §2 Adoption in place (D42)

Adoption runs at startup after restore, and again after each successful owner-sync session, until a binding exists. It reads only local state. Let C be the groups that pass `find_home`'s predicate, and P the effective canonical pointer (`home.rs:303`).

**Settle rule.** If P was empty when the daemon started and other machines are enrolled for this owner, adoption binds nothing until one owner-sync session has completed since startup. The peer publishes its pointer before the exchange (#863), so the session settles P. Until then `GET /home` and `POST /home` report `binding_pending`, which names the wait. Meanwhile the device publishes its candidate into an empty register before each session, as today, so old peers yield.

| Condition | Result |
|---|---|
| P names a group in C | Bind P. |
| P is empty and C is not empty | Mint the smallest stable id in C into the empty register (today's pick, `src/server/routes/sync.rs:187`), then bind it. |
| P names a group outside C, and C is not empty | Unbound. `GET /home` reports `adoption_pending`. C are duplicates. |
| C is empty | Unbound. `GET /home` reports `elsewhere` when P is known, else 404 with the next step `POST /home`. |

Adoption writes only the binding file. It makes no commit and no seal. `named_groups.json`, `home-suite-groups.json`, TreeKEM state and stores stay byte-identical. Duplicates stay until their user retires them through the existing withdraw path. They stay listed in `GET /home` `duplicates[]` (`home.rs:107`). Nothing is retired automatically. A wait in `binding_pending` lasts only while every enrolled owner machine is offline, which is §2 item 8. If a machine is gone for good, the exit is to revoke its enrollment.

### §3 Election stops

- An S7 daemon's Home never follows the register. The register stays only so that old peers keep yielding.
- A bound S7 daemon mints the `("home")` record only for its bound Home, in three cases: into an empty register; as the primary-agent refresh of the same group (`owner_sync.rs:2112–2119`); or over another group when the bound Home is strictly older under ADR 0060's `(provisioned_at_ms, group_id)` order (`owner_sync.rs:2123`). The last case keeps old peers converging on the adopted Home. The order is monotone, so it terminates. An unbound S7 daemon may mint only its §2 candidate, and only into an empty register.
- The retired-pointer rule (`owner_sync.rs:2108`) runs only inside explicit creation.
- It still publishes its pointer before each session (`owner_sync.rs:2664`), so older daemons see a populated register and yield.
- A merged value that names another group does not move a bound device. `GET /home` stays `local` and adds `pointer_conflict` with that group id. Unless its bound Home is strictly older, the device does not re-mint, so there is no register war.
- `POST /home/seat` mints only into the bound Home. An unbound device refuses with 409 `home_unbound`. This closes the #824 residual.

### §4 Admission-only certificate check (only once S4 is in effect)

This part takes effect only when ADR 0110 (S4) is Accepted and its eviction code is merged and released. §4's code merges after that, on the single `named_groups.rs` lane (0088 §4). Until then the seal-time re-check stays, with S2's verdict rule. §4 applies to every OwnerCertified group, because the seal wrapper is shared.

- **Admission is the check.** It is unchanged: `owner_certified_admission_check` (`named_groups.rs:22768`) runs at `MemberJoined` (`13570`) and at direct adds (`19162`, `19376`), and binds the verified certificate into the roster entry (`13766`). Receivers still verify the added member's certificate on apply (`named_groups.rs:11276`).
- **Seals stop re-checking admitted seats.** `seal_commit_owner_certified` no longer evaluates certificate evidence (bytes, digests, announce digests, grace, fetches in flight) for seats already on the roster.
- **One check stays at every seal.** An active seat in the local revocation set blocks the seal with the existing `OwnerCertifiedEvictionRequired` until S4's eviction commits. This needs no evidence beyond the agent ID. It stops a rekey from giving a new epoch to a revoked member.
- **Restore quarantine.** It clears on the first seal after restart under the same rule, not on an all-clean evidence verdict.
- **Unchanged:** the signed-public bootstrap roster check (`named_groups.rs:3456`) and the explicit eviction route.

### §5 Security (L4)

- §1–§3 add and relax no acceptance rule. A binding only chooses among groups the device is already an active member of, under the existing trusted predicate. Creation keeps the durable-token gate and the owner-chain check (`named_groups.rs:14318`). Seating keeps the invite authority and the ADR 0059 Home-mode owner pin.
- §4 relaxes one rule: **a seal no longer requires a Clean verdict for seats already on the roster.** The argument:
  1. Every seat passed an admission check, and its certificate is bound into an admin-signed commit.
  2. A once-valid certificate becomes invalid only by revocation, by expiry, or under a different owner.
  3. Revocation stays fail-closed: the local revocation set blocks every seal, and S4 evicts within its bound. A different owner is a different group, because the owner axis is fixed in the signed policy.
  4. A re-issued certificate (a new announce digest) does not revoke the old one. Revocation is the tool for unbinding an agent.
  5. Expiry after admission is no longer checked at seal. That is the cost; see Q2.
- The L4 fail-closed list is untouched: signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion.

### §6 Persisted state (ADR 0085)

- One new file: `<data_dir>/home-binding.json`. It is a JSON object: `format` (1), `owner_user_id`, `group_id` (stable id), `bound_at_ms` and `source` (`adopted`, `created` or `seated`).
- It is written atomically and durably, with the sidecars' atomic-write helper, before the binding is reported.
- An unknown `format`, or a body that does not decode, is refused. The file is left untouched, and the device is unbound with the cause shown in `binding_pending`. Unknown fields inside format 1 are ignored (rule 7). A binding for a different owner is ignored, as the marker is (`home.rs:449`).
- **Downgrade.** Older binaries never read this file. They run their own election and provisioning, as they always did, and leave the file intact. Re-upgrading restores the binding.
- **Unchanged:** `named_groups.json`; `home-suite-groups.json` (`HOME_SUITE_GROUPS_FILE`, `named_groups.rs:32762`); the advisory `home.json` marker, which is still written; the owner-sync record store; TreeKEM snapshots; the ADR 0062 pair.
- Rule 6: the first release that writes format 1 commits a fixture from its own encoder.

### §7 Wire, capability bit and mixed versions

S7 changes nothing on the wire. It adds no `SyncKind` or `SyncValue` variant (`owner_sync.rs:168–187`), and `HomePointer`'s signed shape is unchanged. No ADR 0093 bit is needed, so none is allocated.

| Direction | Behaviour |
|---|---|
| Old device enrolled with a bound S7 device | It sees a populated register before each session and yields. It does not provision. |
| Old device that reaches no S7 device before its deadline | It creates a duplicate, as that binary always did. Its Home is newer. If its record wins the last-writer merge, a bound S7 device re-mints the older adopted Home, so the register returns to it. S7 devices stay bound. |
| Old device that holds a strictly older Home | Its election can rewrite the register, and old devices follow it. S7 devices stay bound, report `pointer_conflict` and do not re-mint. |
| Old admin under §4 | It still re-checks at seal, which is stricter. Its commits apply on S7 peers unchanged. |
| S7 admin's commits on old peers | Accepted. Receivers check only the added member's certificate (`named_groups.rs:11276`), never the whole roster. |

## Consequences

### Positive

- One device-local answer to "which group is my Home". The register stops moving devices.
- No startup wait and no timer-made duplicates. #824's residual closes.
- After S4 and §4, a promoted admin admits while the owner device is offline, whatever the state of other seats' evidence. #1023's structure closes.

### Negative / Trade-offs

- A new owner must create Home explicitly (see Q1).
- Legacy duplicates and old-binary duplicates stay until the user retires them. In a mixed fleet, old devices can follow a register value that S7 devices ignore (see Q3).
- After §4, an admitted member whose certificate expires stays seated until it is revoked or removed (see Q2).

### Neutral / Operational

- `docs/api-reference.md` changes: `POST /home`, the `binding_pending` state, the `pointer_conflict` field, the 409 reasons `home_exists` and `home_unbound`, and the removal of `provisioning_pending`.
- Placement fields in Home metadata are untouched; the roaming cut is ADR 0102's (prov.).

## Validation

**Harness first (D16, D54, #1164).** Each W3-H case below must be red on `main` before any S7 code merges.

- **H7-1 (#824 residual).** Owner device O holds Home H and has published the pointer. Device B gets the copied owner key and an agent certificate, enrolls with O, and restarts with an empty owner-sync store. Block every session between B and O for longer than `2 × 90 s`. Red: B creates a second Home-shaped group, and `POST /home/seat` on B returns 200 with a `group_id` other than H. Green: B creates no group. B's `GET /home` and `POST /home` report `binding_pending`, and B's seat returns 409 `home_unbound`. After the block lifts and O seats B, B binds H. The owner holds one Home-shaped group throughout.
- **H7-2 (election).** O and A are seated in H, the canonical Home. Device L, never synced, holds H0 with an older `provisioned_at_ms`. L enrolls and syncs. Red: the register flips to H0, and O and A report `adoption_pending` with seats refused. Green: L mints nothing and reports `adoption_pending`. The register stays on H. O and A stay `local`, and seats into H still work.
- **H7-3 (#1023 structure; §4).** Home with owner device O (the creator), promoted admin P and joiner J, who holds an invite from P. O goes offline. O's seat is digest-only at P, and O is its only holder. Red: P refuses J's add with `OwnerCertMemberPending [O]` on every retry until J's poll times out. Green, only with S2, S4 and §4 in place: P admits J within the join bound after verifying J's inline certificate, and O applies the commit when it returns. This case stays red after S2 and S5 alone.

**Exit test.** H7-1 and H7-2 are green after §1–§3. H7-3 is green after §4.

**Non-regressions.**

- H7-4: O revokes member M. P's next seal, including an add, refuses until S4's eviction commits within its bound. M never receives the new epoch.
- An uncertified or foreign-owner joiner is still refused at admission and on apply.
- An unowned install writes no binding, no Home and no records.
- A process restart keeps the binding and the same Home.
- Adoption leaves `named_groups.json`, `home-suite-groups.json` and the TreeKEM snapshot byte-identical; the `hs451_downgrade_safety` tests stay green.
- ADR 0106 and 0107 join paths and ADR 0062 pair recovery are unchanged.
- The ADR 0069 seat tests are adapted: a seat mints only into the bound Home.

**Mixed-version check (required, D42).**

- M1: a 0.46.x device enrolled with a bound S7 device creates no Home. With the sessions blocked past its deadline, it creates a duplicate. After the block lifts, the register converges on H and S7 devices stay bound to H.
- M2: H7-2 with L running 0.46.x. The register flips to H0. O and A stay `local` in H with `pointer_conflict` naming H0, and the record version stops advancing.
- M3: `SyncKind::ALL.len() == 4` (`owner_sync.rs:3549`), and a frozen 0.46.x decoder accepts an S7-minted `HomePointer` record.
- M4: downgrade to 0.46.x on the same data dir and upgrade again. The old binary ignores `home-binding.json`, and the re-upgraded daemon resolves the same Home.
- M5 (§4): 0.46.x members apply an add sealed by an S7 admin that did not re-check O's seat.

**Review triggers:** S4's bound or trigger list changes; any new writer of the `("home")` register; a request to retire duplicates automatically.

## Open questions for David

- **Q1, explicit creation at onboarding.** Auto-provisioning stops (D42). Should the owner's setup step (creating `user.key` and certifying the first agent) also create the Home as part of the same explicit act? Or must the owner run `x0x home create` separately?
- **Q2, expiry after admission.** Seals stop re-checking (0088 §3). Should S4 treat certificate expiry as an eviction trigger? If not, an admitted member whose certificate expires stays seated until it is revoked or removed.
- **Q3, old-binary duplicates.** Is "a 0.46.x device can still create or follow a duplicate Home" a release-note known limitation until every owner device runs S7? Or do you want a minimum version for Home?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

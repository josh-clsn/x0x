# ADR 0113: Home Is an Explicit Owner Group, Adopted in Place (0088 S7)

- **Status:** Proposed
- **Date:** 2026-10-04 (r2 after cross-model review; r3 records David's rulings D64, D65, D71, D106 and D107)
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model review r1: request changes; r2 pending)
- **Slice:** S7 of [ADR 0088](./0088-group-liveness-contract.md) (group liveness), bound to this number by D63.
- **Supersedes (upon acceptance):** [ADR 0060](./0060-one-home-per-owner.md) (Home is elected); [ADR 0069](./0069-home-wait-for-sync-before-auto-provisioning.md) (Home waits for owner sync); [ADR 0038](./0038-home-owner-certified-personal-space.md) in part: the auto-provisioned personal space, and the seal-time re-checks. The seal-time part takes effect only once S4 (ADR 0110) is in effect, together with the delivery guards in §4. ADR 0038 as a whole is superseded only when S2 (ADR 0108), S4 and S7 are all Accepted.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** #824, #1023, #1107, #1143, #1164, #1190, #449; rulings D16, D38, D42, D54, D60, D63, D64, D65, D71, D106, D107; ADR 0041, 0059, 0062, 0065, 0084, 0085, 0087, 0093, 0106, 0107, 0108 (S2), 0110 (S4), 0111 (S5). Related work only: the join-artifact serving lifecycle note on the #1190 branch.

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
- Retiring that re-check must not release keys to an ineligible member (L4, D60). Certificate expiry is an S4 eviction trigger (D71).
- D64: L3 is a hard rule. Every block this slice adds or touches ends in a typed refusal, or in a typed wait that names what it waits for.
- D106: owner setup also creates the Home, through the same create path and guards.
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
- **Auto-provisioning stops.** Startup no longer creates a Home on its own. It only runs an owner's setup request (below, D106). The deferral, `home_creator_rank`, `wait_for_owner_sync_round` and `HOME_POINTER_SYNC_WAIT` are removed. `GET /home` no longer reports `provisioning_pending`. Startup keeps restore verification and the repair of an existing Home (`home.rs:721`, steps 0–1) unchanged.
- **Explicit creation.** A new `POST /home` route and `x0x home create` CLI create a Home. They need the durable owner token, like every Home mutation (`home.rs:1676`), and an owned install with an agent certificate. Under the binding gate (§6) they refuse with 409 `home_exists` when a binding exists, 409 `binding_pending` while the §2 settle rule applies, and 409 `elsewhere` when the effective canonical pointer names a Home that is not provably retired. Otherwise they record a create intent, then create through the unchanged `create_named_group` and `stamp_and_seal_home` path, with today's linearisation against pointer arrival (`home.rs:1080–1125`). Then they bind and publish the pointer.
- **Creation at owner setup (D106).** Owner setup also creates the Home, through the same create transaction and guards. Owner setup is a successful `x0x user-id create` (random keygen or `--from-seed`, including `--rotate-owner`), then the next daemon start that loads that identity and issues its agent certificate.
  - *Request.* The CLI cannot create the group, because the daemon loads a new identity only at its next start. So the CLI writes a one-shot request beside `owner.json`, in S7's own sidecar `home-setup.hsreq` (§6). The request holds `owner_user_id` and `requested_at_ms`. The CLI writes it atomically, and only when none exists. Its output reports `home: requested`.
  - *Execution.* On that start, under the binding gate, after §6 recovery and §2 adoption, the daemon runs the explicit-creation transaction above for the request, with every guard. It runs the request only for the owner it names. No HTTP token is needed: writing the request needs write access to the identity directory, which already holds `user.key`.
  - *Outcomes.* Success binds the Home as `created` and publishes the pointer. `home_exists` (a binding is present) and `elsewhere` end the request. `binding_pending` keeps it: the daemon retries after the next owner-sync session, or after ADR 0094's host commit when that is the wait (§6). `binding_unreadable` keeps it until the next start. The daemon deletes the request once it ends. `GET /home` then reports `setup_outcome` (`created`, or the typed refusal) until the daemon restarts. A request that does not decode, or that names another owner, is left byte-identical, and `GET /home` reports `setup_request_unusable` with the cause.
  - *What the guards cannot see.* `--from-seed` derives the same identity on every machine. A further machine set up from the same seed can have no binding, no pending intent, no enrollment and an empty register. The guards then pass, and setup there creates a duplicate Home (the #824 class). David has not ruled on an exception; Q4 proposes one. Until he rules, the guards are the only check.
- **Binding.** Each device persists one answer to "which group is my Home" (§6). Three writers set it: adoption (§2), explicit creation, and completing a Home-mode join (`mode: "home"`, `named_groups.rs:473`) as an active member with keys. A Home-mode join rebinds the device, because the admin's seat plus the device's redemption is the owner's explicit choice.
- **Resolution.** `resolve_home` returns the bound group when it passes `find_home`'s trusted predicate (`home.rs:373`): Home metadata, exact Home policy, this agent active, not withdrawn, not a pending stub. Otherwise the device is unbound. A register value never moves a bound device.

### §2 Adoption in place (D42)

Adoption runs at startup after restore and §6 recovery, and again after each successful owner-sync session, while the device is **unbound** (the file is absent or an empty record; any pending intent is recovered first, §6). It runs under the binding gate and reads only local state. Let C be the groups that pass `find_home`'s predicate, and P the effective canonical pointer (`home.rs:303`).

**Settle rule.** If P was empty when the daemon started and other machines are enrolled for this owner, adoption binds nothing until one owner-sync session has completed since startup. The peer publishes its pointer before the exchange (#863), so the session settles P. Until then `GET /home` reports `binding_pending` with `waiting_for: owner_sync_session` and the enrolled machines it can sync with (D64). Meanwhile the device publishes its candidate into an empty register before each session, as today, so old peers yield.

| Condition | Result |
|---|---|
| P names a group in C | Bind P. |
| P is empty and C is not empty | Mint the smallest stable id in C into the empty register (today's pick, `src/server/routes/sync.rs:187`), then bind it. |
| P names a group outside C, and C is not empty | Unbound. `GET /home` reports `adoption_pending` with P and the next step: be seated into P (a Home-mode join). C are duplicates. |
| C is empty | Unbound. `GET /home` reports `elsewhere` with P and the same next step when P is known, else 404 `no_home` with the next step `POST /home`. |

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
- S4's revocation eviction (ADR 0110), including its certificate-expiry trigger (D71);
- ADR 0107's current-roster serving guard for join results and Welcomes;
- D60's current-eligibility rule for every GSS envelope delivery and resend. Today `publish_secure_share` publishes and schedules resends with no eligibility check (`named_groups.rs:1926–1955`).

The last two are PR #1190, planned for v0.46.2. §4's code merges after all three, on the single `named_groups.rs` lane (0088 §4). Until then today's seal-time re-check stays, with S2's verdict rule. §4 applies to every OwnerCertified group, because the seal wrapper is shared. In an OwnerCertified `SignedPublic` group, S4's eviction is the roster removal alone, with no crypto transition (ADR 0110 §1a).

**Verified roster.** A node skips the re-check only on a group in which it has verified every active seat since it loaded the group. It tracks this with a new in-memory, per-group "verified roster" mark. The mark gates only the §4 skip, never any other operation.
- The mark is unset on load and on every wholesale roster install: restore, a join base and a catch-up snapshot. Only an all-clean full verdict sets it.
- While it is unset, every seal runs today's full verdict. Restore also keeps today's `owner_cert_reverify_required` quarantine unchanged; an all-clean verdict clears both, as today (`src/groups/mod.rs:1253`). Retiring this needs authenticated admission provenance per seat, which is future work outside S7.
- A seat added later is verified on entry: by the admission check (`named_groups.rs:22768`, called at `13570`, `19162`, `19376`, and bound into the roster entry at `13766`), or by the receiver's `MemberAdded` apply check (`named_groups.rs:11276`).
- A policy change that opts a group into OwnerCertified keeps its existing roster. That transition seal therefore always runs the full verdict and refuses unless every seat is Clean.

**On a verified roster:**
- Seals stop re-checking seats already verified. `seal_commit_owner_certified` no longer evaluates their evidence (fresh bytes, digests, announce digests, grace, fetches in flight). Only the trigger tests below remain.
- An active seat that ADR 0110 makes an eviction trigger on this node holds every seal except S4's eviction of that seat. The seal refuses with the existing `OwnerCertifiedEvictionRequired`, naming the seat, until that eviction commits. The triggers are an agent in the local revocation set and, by D71, an expired selected certificate. As today, a machine or binding revocation holds no seal (ADR 0110 §1); D60 refuses every delivery to that machine.
- **Expiry uses ADR 0110 §1a's test, not a second one.** The certificate tested is ADR 0110 §1a's selected certificate: the one the current committed roster binds to the seat, as its embedded bytes or bytes that match its committed `certificate_digest`. A certificate held only in an announce or discovery cache is never selected. The seat is expired when this node's wall clock is past the selected certificate's `not_after + τ`, the test D60's delivery refusal also applies. τ is ADR 0110's expiry tolerance, open in its Q2 (proposed: 300 s, today's `EXPIRY_CLOCK_SKEW_SECS`). A certificate with no `not_after` never expires. If this node lacks the selected bytes for a digest-only seat, the seal refuses with `waiting_for_certificate_evidence`, naming the committed digest, while the existing seat-certificate fetch runs; all holders offline is 0088 §2 item 8.
- **Renewal waits on ADR 0110.** Every seal re-runs the test under the membership lock, against the current head and wall clock, as ADR 0110 §1a requires before every S4 seal. Under ADR 0110 §1a, only a verified commit that binds a renewed certificate into the seat (same owner and agent, verifying, unexpired on this node's clock) cancels expiry work. No such in-place commit exists today: `MemberJoined` refuses an Active member (`named_groups.rs:13547`), direct adds refuse an existing member (`19154`, `19365`), and `set_member_certificate` refuses a changed committed digest (`src/groups/mod.rs:1731`). ADR 0110 holds the design of an in-place certificate-rebinding commit as an open question that blocks its Accept. Until David rules it, a seat whose selected certificate expires stays held, and S4 evicts it; the agent rejoins with a fresh invite and the renewed certificate. A renewal held only in a cache releases nothing. A renewal never releases a hold caused by revocation. Q6 records how §4 changes if ADR 0110 accepts such a commit.
- **The joiner of a held add.** While an admin is online, S4's eviction commits within S4's completion bound, which is measured and accepted with ADR 0110 (D69). The held add of a joiner J then seals on J's next join volley, if J's poll is still running. S7 does not assume that this fits inside J's existing 120 s poll: the measured bounds and a certificate fetch can each exceed it. When the hold outlasts the poll, or no admin is online (§2 item 3), J's attempt ends at its poll deadline in ADR 0107's typed `TimedOut`, with cause `no_admission_result` naming the group it waited to be admitted to. J holds no seat and no key. Its exit is ADR 0107's: redeem a fresh invite once the hold ends. Meanwhile the admin shows the cause: `OwnerCertifiedEvictionRequired` or `waiting_for_certificate_evidence`, and S4's obligation state. Showing that cause to J inside its poll would need a wire change, which S7 does not make.

**Delivery stays current.** Every delivery and resend of key material (GSS envelopes, Welcomes, join results) checks, at send time: current certificate validity including expiry, agent and machine revocation, containment (fork quarantine, withdrawal), and the current secret epoch. These are ADR 0107's and D60's checks. §4 keeps them unchanged and depends on them.

**Explicit eviction route.** `POST /groups/:id/state/seal` evaluates the whole roster (`named_groups.rs:21304–21314`). While the mark is unset it behaves exactly as today. On a verified roster it evicts only seats that are revoked, or whose committed certificate bytes fail verification on their own (expired, wrong owner, bad signature). It does not evict or refuse for missing or stale evidence (InGrace, DigestPending, a changed announce digest), so it no longer returns the pending refusal for those seats (`named_groups.rs:21409–21419`). It still evicts expired seats, as today. S4's expiry trigger (D71) does the same work without a manual step.

### §5 Security (L4)

- §1–§3 add and relax no acceptance rule. A binding only chooses among groups the device is already an active member of, under the existing trusted predicate. Creation keeps the durable-token gate and the owner-chain check (`named_groups.rs:14318`). Seating keeps the invite authority and the ADR 0059 Home-mode owner pin.
- Creation at owner setup (D106) adds no acceptance rule. It runs the same guarded transaction. Its authority is write access to the identity directory, which already holds `user.key` and is stronger than the durable owner token. A duplicate Home from a further seeded machine (§1) grants no authority: it is a group of the same owner, which the user retires through the withdraw path. It costs availability, not safety (Q4).
- §4 relaxes one rule: **on a verified roster, a seal no longer requires a fresh Clean verdict for seats this node already verified.** The argument:
  1. Provenance is local and explicit. A seat is skipped only after this node verified its certificate: at admission, when applying its `MemberAdded`, or in the all-clean verdict that set the mark. Wholesale installs and policy opt-ins are verified in full first. Restore keeps its quarantine.
  2. A verified certificate becomes invalid only by revocation, by expiry, or under a different owner.
  3. Revocation and expiry stay fail-closed: at every seal (the local revocation set, and expiry on this node's clock), at every delivery and resend (D60), and by S4's bounded eviction (agent revocation, and expiry by D71). A different owner is a different group, because the owner axis is immutable once set (`named_groups.rs:23754–23771`).
  4. A re-issued certificate (a new announce digest) does not revoke the old one. Revocation is the tool for unbinding an agent.
  5. Expiry is ADR 0110 §1a's local test: the selected certificate's `not_after + τ` against this node's wall clock. Every node on the same head selects the same certificate. Expiry holds seals and opens S4's eviction (D71), and delivery and resend refuse an expired certificate by the same test. No renewal releases the hold until ADR 0110 rules an in-place rebinding commit (Q6), so §4 exempts nothing but S4's own eviction. The remaining read window is clock skew and τ: an admin whose clock has not passed `not_after + τ` can still seal a commit that the expired member can follow. ADR 0110 bounds that window.
  6. As today, a machine or binding revocation holds no seal. D60 stops every delivery to that machine, but a TreeKEM leaf held there can follow later commits until its agent is removed. That window belongs to ADR 0110's trigger list (Q5).
- The L4 fail-closed list is untouched: signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion.

### §5a Every block is typed (L3, D64)

Every block that S7 adds or touches ends in one of these typed states. None is a bare timeout or an untyped pending state.

| Block | Typed state | It names | Exit |
|---|---|---|---|
| Settle rule (§2) | Wait: `binding_pending` | `waiting_for: owner_sync_session`; the enrolled machines | One session completes. It waits without bound only while all are offline (§2 item 8); a machine gone for good has its enrollment revoked. |
| Canonical Home held elsewhere (§2) | Wait: `adoption_pending` or `elsewhere` | P; the next step | The owner seats this device into P, and it redeems in Home mode. |
| No Home (§2) | Refusal: 404 `no_home` | The next step `POST /home` | Explicit creation. |
| `POST /home`, setup's create (§1) | Refusal: 409 `home_exists`, `binding_pending`, `elsewhere`, `binding_unreadable`, `binding_intent_pending` | The binding, the wait, P, the cause or the intent | As the matching row. |
| Setup request (§1) | `setup_outcome`; `setup_request_unusable` | The outcome or the cause | As the matching row. |
| `POST /home/seat` (§3) | Refusal: 409 `home_unbound`, `binding_unreadable` | The missing binding or the cause | Bind first. |
| Unreadable binding (§6) | Refusal: `binding_unreadable` | The cause | An operator upgrades, restores or removes the file (ADR 0085 rule 4). This is local state, not a network wait. |
| Seal with a trigger seat (§4) | Wait at the admin: `OwnerCertifiedEvictionRequired`, or `waiting_for_certificate_evidence` for a digest-only seat | The seat; the committed digest | S4's eviction commits within its bound. A rebinding commit becomes a second exit only if ADR 0110 accepts one (Q6). A fetch waits without bound only while all holders are offline (§2 item 8). |
| Joiner whose add is held (§4) | Refusal at J's poll deadline: ADR 0107's `TimedOut`, cause `no_admission_result` | The group it waited to be admitted to | A fresh invite once the hold ends (ADR 0107). |
| Before ADR 0094's host commit (§6) | Wait: `binding_pending` with `waiting_for: host_commit` | The host commit | The host commit. |
| Seal while the verified-roster mark is unset (§4) | Today's `OwnerCertMemberPending` or `OwnerCertifiedEvictionRequired` | The seat | One all-clean verdict; S5's fetch from any holder; §2 item 8 while all holders are offline. |

### §6 Persisted state (ADR 0085) and the binding transaction

- **S7's own sidecars (cross-slice rule 1).** S7 adds two files and changes no legacy store. Each has its own magic and a new extension that no released binary reads or scans: neither matches the legacy `*.journal` scan, #451's `.hsjournal`, or the fixed file names that released binaries open.
  - **Binding:** `<data_dir>/home-binding.hbind`. Magic `X0HBND1\0` (8 bytes), then a JSON body, consumed exactly: `owner_user_id`, `bound` (null, or `group_id`, `source` = `adopted` | `created` | `seated`, `bound_at_ms`) and `pending` (null, or `kind` = `create` | `join`, `intent_id`, `group_id` for a join, `started_at_ms`).
  - **Setup request:** `home-setup.hsreq`, beside `owner.json` (§1, D106). Magic `X0HSRQ1\0`, then a JSON body, consumed exactly: `owner_user_id` and `requested_at_ms`. It is a one-shot request, not state: the daemon deletes it once the request ends. A crash after the binding write and before the delete is harmless: the next start finds a binding and ends the request with `home_exists`.
  - The magic is the version. A changed body gets a new magic (ADR 0085). Unknown fields inside a known body are ignored (rule 7). Both files are written with the sidecars' atomic-write helper (temp write, fsync, rename, directory fsync) before any change is reported.
- **Host commit (ADR 0094).** On a managed install, S7 writes neither file before ADR 0094's host commit. Until then it resolves the Home by the §2 rules in memory only, and every writer that must persist first (creation, the setup request, Home-mode join completion) refuses or waits with `binding_pending` and `waiting_for: host_commit`. A trial that rolls back therefore leaves no S7 file behind.
- **Load states.** *Absent* (the file does not exist) and *empty* (readable, with `bound` and `pending` both null) are the same unbound state, and writers may run. The file is never deleted: clearing an intent with no prior binding leaves the empty record. *Bound* and *pending* are readable records with the known magic for this owner. *Unreadable*: any read error, an unknown magic, a body that does not decode or has trailing bytes, or another owner's binding. In the unreadable state every writer refuses: adoption does not run; `POST /home`, `POST /home/seat` and Home-mode joins refuse with 409 `binding_unreadable`; and the device mints no `("home")` record. `GET /home` reports `binding_unreadable` with the cause. The file is never rewritten. Recovery is explicit: upgrade to a binary that reads it, restore it, or remove it by hand (ADR 0085 rule 4).
- **One gate.** An async mutex, `home_binding_gate`, serializes every writer: adoption, creation (including the setup request), Home-mode join completion and startup recovery. Each writer re-reads the file and rechecks its precondition under the gate. Adoption writes only into an unbound (absent or empty) record. Creation refuses over a bound one. A Home-mode join replaces it. **No writer overwrites a pending intent.** A writer that finds one first runs that intent's recovery (below) under the gate, then rechecks its own precondition. The one exception is a join intent still live in this process (its `intent_id` is held by the running redemption): then the writer refuses with 409 `binding_intent_pending`. A retried `POST /home` therefore resumes the earlier create and returns that Home; it never creates a second group. Lock order: `home_binding_gate`, then owner-sync session slots (creation only), then `canonical_home_gate`, then the per-group membership lock, then `named_groups` and persistence. Owner-sync writers never take the binding gate, so there is no cycle.
- **Intents and crash recovery.** Creation durably writes `pending: create` before it creates the group. A Home-mode join writes `pending: join` with the invite's group id before redemption. Creation holds the gate for its whole run. A join releases it during redemption and retakes it to bind. The write that sets `bound` clears `pending`. If that write fails after the group persisted, the intent stays on disk. Recovery runs under the gate at startup, before adoption, and inside any writer that finds an intent that is not live:
  - `pending: create`: count the Home-shaped groups this agent created at or after `started_at_ms`. With one, finish it (stamp and seal it if unstamped), bind it as `created`, and publish. With none, clear the intent. With more than one, enter the unreadable state with that cause. Today's startup crash recovery (step 2, `home.rs:1019`) runs only here.
  - `pending: join`: if this agent is an active member of that group and it passes the predicate, bind it as `seated`. Otherwise clear the intent and keep the old binding.
  - A crash after binding but before publication needs nothing: §3 publishes on the next pass.
- **Downgrade.** Older binaries never read either file. They start normally, run their own election and provisioning as they always did, and leave both files byte-identical. Re-upgrading restores the binding. A setup request left on disk then runs after adoption, finds the Home the old binary made, and ends with `home_exists`, so no second Home is created.
- **Unchanged:** `named_groups.json`; `home-suite-groups.json` (`HOME_SUITE_GROUPS_FILE`, `named_groups.rs:32762`); the advisory `home.json` marker, which is still written; the owner-sync record store; TreeKEM snapshots; the ADR 0062 pair.
- **Fixtures (rule 6).** The first release that writes either file commits a fixture of each from its own encoder, with provenance and SHA-256, and freezes that decoder. Later releases decode the committed fixtures.

### §7 Wire, capability bit and mixed versions

S7 changes nothing on the wire. It adds no `SyncKind` or `SyncValue` variant (`owner_sync.rs:168–187`), and `HomePointer`'s signed shape is unchanged. No ADR 0093 bit is needed, so none is allocated. A later wire extension would allocate the next free bit at its own acceptance.

| Peer | Behaviour |
|---|---|
| 0.46.x device enrolled with a bound S7 device | It sees a populated register before each session and yields. It does not provision. |
| 0.45.0 device | It has the same election order (`(provisioned_at_ms, group_id)`) but no wait and no publish-before-session. It creates a Home at startup whenever its own store knows no pointer. |
| Old device that creates a duplicate (no pointer in time) | Its Home is newer. If its record wins the last-writer merge, a bound S7 device re-mints the older adopted Home, so the register returns to it. S7 devices stay bound. |
| Old device that holds a strictly older Home | Its election can rewrite the register, and old devices follow it. S7 devices stay bound, report `pointer_conflict` and do not re-mint. |
| Old admin under §4 | It still re-checks at seal, which is stricter. It runs no S4 eviction, for revocation or expiry; an S7 admin does (ADR 0110). Its commits apply on S7 peers unchanged. |
| S7 admin's commits on old peers | Accepted. Receivers check only the added member's certificate (`named_groups.rs:11276`), never the whole roster. |

Creation at owner setup changes nothing on the wire. The Home it creates is an ordinary Home, and its pointer is published as in §3, so 0.46.x peers enrolled later see a populated register and yield.

**Known limitation (D107).** A 0.45 or 0.46 device of the same owner can still create a duplicate Home, or follow a register value that names one. S7 devices are not moved: they stay bound to their own Home and report `pointer_conflict`. This is a known limitation until every owner device runs S7. There is no minimum version for Home, because a floor would cut the owner's own old machines off Home (R3). Every release that ships S7 states the limitation in its release notes, with the exit: upgrade every owner device, then retire each duplicate through the withdraw path.

### §8 Gates

- **Acceptance order (0088 §4).** The contract, then S2 and S8, then S4 and S3, then S5, then S6, then S7. "S8" there means S8(a), ADR 0107 (D65). S8(b), ADR 0114, is accepted after S4, as ADR 0107 states; S7 does not wait for it.
- **Prerequisites.** ADR 0110 (S4) is Accepted with D71's expiry trigger in its trigger list before this ADR is accepted. §4's code also waits for the activation set in §4.
- **Merge rules.** This ADR is Proposed on `main` before any governed code merges. David accepts it before S7's code merges. Slice code that touches `named_groups.rs` lands on the single lane, one slice at a time.

## Consequences

### Positive

- One device-local answer to "which group is my Home". The register stops moving devices.
- No startup wait and no timer-made duplicates. #824's residual closes.
- A new owner's setup creates exactly one Home, through the same guards as `POST /home` (D106).
- After §4 activates, an admin that has verified its roster admits while the owner device is offline, whatever later happens to other seats' evidence. #1023's structure closes.

### Negative / Trade-offs

- Setup on a further machine with the same seeded identity, before it is enrolled or synced, passes the guards and creates a duplicate Home (§1). It stays until the user retires it. Q4 proposes an exception.
- Legacy duplicates and old-binary duplicates stay until the user retires them. In a mixed fleet, old devices can follow a register value that S7 devices ignore. This is a release-note known limitation until every owner device runs S7 (D107).
- After §4, near a certificate's expiry, τ and clock skew let an admin whose clock is behind seal a commit that the expired member can still follow. ADR 0110 bounds that window (D71).
- Until ADR 0110 rules an in-place certificate-rebinding commit (Q6), a renewal cannot keep an expiring seat. The seat stays held, S4 evicts it, and the agent rejoins with a fresh invite and the renewal. Today's seal verdict accepts an announced renewal; under ADR 0110 §1a that no longer keeps the seat.
- A joiner whose add waits behind an eviction or a certificate fetch longer than its 120 s poll sees only `TimedOut` with `no_admission_result`, not the admin's cause, and needs a fresh invite.
- A seat on a revoked machine holds no seal, as today. Its TreeKEM leaf can follow later commits until its agent is removed (Q5).
- A restarted node still needs one all-clean verdict per OwnerCertified group before §4 applies to it.

### Neutral / Operational

- `docs/api-reference.md` changes: `POST /home`; the `binding_pending` (with `waiting_for`), `binding_unreadable` and `setup_request_unusable` states; the `pointer_conflict` and `setup_outcome` fields; the 404 reason `no_home`; the 409 reasons `home_exists`, `home_unbound`, `binding_pending`, `binding_unreadable` and `binding_intent_pending`; the seal refusal `waiting_for_certificate_evidence`; the join cause `no_admission_result`; and the removal of `provisioning_pending`. The `x0x user-id create` output gains the `home: requested` field.
- New files: `<data_dir>/home-binding.hbind` and `home-setup.hsreq` beside `owner.json` (§6).
- Release notes for every release that ships S7 carry the D107 known limitation.
- Placement fields in Home metadata are untouched; the roaming cut is ADR 0102's (prov.).

## Validation

**Gate (D16, D54).** The W3-H harness (#1164) does not exist yet. Each red case below must be committed on `main` and fail there before any S7 code merges. It runs inside the isolated loopback namespace: `python3 scripts/dev/test-isolated.py nextest --all-features -- -E 'test(w3h_s7_)'`. The selector names are proposals for #1164; file one tracking issue for these cases. Every node is a real daemon on a harness-built data dir, and all nodes share one owner unless stated. Every case runs on the harness's deterministic fake clock and scripted delivery schedule. Every case also asserts the typed token of each refusal and wait it reaches (§5a, D64); a bare timeout or an untyped pending state fails the case.

| Case (selector) | Nodes and preparation | Steps | Red on `main` | Green (exit test) |
|---|---|---|---|---|
| H7-1 `w3h_s7_h7_1_copied_key_creates_no_duplicate` (#824) | O holds Home H and has published its pointer. B has the copied `user.key`, an owner-issued agent certificate, mutual enrollment with O, an empty owner-sync store and no Home-shaped group. | Start B. Drop every O↔B session for 200 s. Call `POST /home/seat` on B for a third agent id. Lift the block. O seats B; B redeems in Home mode. | B holds a second Home-shaped group within 180 s. The seat returns 200 with a `group_id` other than H. | B never holds a group other than H. During the block, B's `GET /home` is `binding_pending` with `waiting_for: owner_sync_session` naming O, `POST /home` is 409 `binding_pending` and the seat is 409 `home_unbound`. After redemption B is bound to H as `seated`. |
| H7-2a `w3h_s7_h7_2a_unbound_older_home_takes_nothing` | O and A are bound to H. L holds H0 with an older `provisioned_at_ms`. L's store is seeded with O's record for H (P = H). L has no binding file. | Start L. Enroll L with O both ways. Run two sessions in each direction. | L's election mints H0 over H. O and A report `adoption_pending`, and seats on O refuse. | L mints nothing and reports `adoption_pending`. The register stays H everywhere. O and A stay `local`, and a seat on O succeeds. |
| H7-2b `w3h_s7_h7_2b_upgraded_older_home_moves_no_device` | As H7-2a, but L's store holds its own H0 record, as its reconcile pass mints it (`owner_sync.rs:2817`). | Start L; it binds H0. Enroll and sync as above, then three more sessions. | The register flips to H0. O and A report `adoption_pending`, and seats on O refuse. | The register may hold H0. O and A stay `local` in H with `pointer_conflict` = H0, and seats into H work. L stays `local` in H0. The record version does not change over the last three sessions. |
| H7-3 `w3h_s7_h7_3_admission_ignores_unrelated_seat_evidence` (#1023) | O is the creator and owner device. P is a promoted admin that joined with O's certificate bytes and has verified every seat since load. J is an owner-certified joiner with an invite from P. | O re-issues its certificate. P receives O's new certificate-bearing announce digest but not the bytes. O goes offline. J redeems; poll for 120 s. | P refuses every retry with `OwnerCertMemberPending [O]` or `OwnerCertifiedEvictionRequired [O]`. J ends `TimedOut`. | With S2, S4, the §4 guards and §4 in place: P seals J's add within the join bound. O applies the commit when it returns. Stays red with S2 and S5 alone. |
| H7-4 `w3h_s7_h7_4_setup_creates_one_home` (D106) | N: fresh identity and data dirs, no owner. Clock starts at t=0. No sessions. | (a) With N stopped, run `x0x user-id create` on N. Start N. At t=10 s read `GET /home`, then call `POST /home`. Restart N and read `GET /home`. (b) Repeat (a) with a crash injected after group persistence and before the binding write. (c) With N stopped, run `x0x user-id create --from-seed X`, where X is the seed of owner machine O, which holds Home H. Seed N's owner-sync store with mutual enrollment with O. Block every O↔N session until t=200 s, then start N. | (a) and (b) are controls: `main` also ends with one Home on N. (c) is red: `main` creates a second Home on N after its deadline. | (a) The CLI reports `home: requested`. N is `local` in one Home, bound as `created`, with `setup_outcome` = `created`. `POST /home` is 409 `home_exists`. After the restart N resolves the same Home and the request file is gone. (b) One bound Home after the restart. (c) Until t=200 s, N's `GET /home` is `binding_pending` naming O, and the request stays. After the first session, the request ends with `elsewhere`, and N holds no Home-shaped group. |
| H7-5 `w3h_s7_h7_5_expired_seat_evicted_add_completes` (D71, D64) | A Home (OwnerCertified, `MlsEncrypted`) with A (Admin, lowest agent id), P (Admin), M (member) and J (owner-certified joiner with P's invite). M's committed certificate has `not_after` = T0, and no renewal exists. Let τ' = max(τ, 300 s), so the schedule is past both today's tolerance and ADR 0110's accepted τ. B is ADR 0110's accepted completion bound for expiry. Every link delivers in 50 ms, and wall clocks agree except in v1. A and P have verified every seat since load. Variant (v1): P's wall clock runs τ' + 5 s behind A's. Variant (v2): A and P stop at T0 + τ' + 1 s. | At T0 + τ' + 1 s, J redeems P's invite and polls. At T0 + τ' + 2 s, A and P each rename the group through the public API, which seals a commit. | Red: today's seal verdict refuses J's add with `OwnerCertifiedEvictionRequired [M]`, nothing evicts M, and J ends `TimedOut` at its poll deadline with M still seated. | Every seal on A and P except S4's eviction of M refuses with `OwnerCertifiedEvictionRequired [M]` until that eviction commits, within B. If the eviction and one more seal end before J's poll deadline, P seals J's add in that poll. Otherwise J's attempt ends at its deadline in typed `TimedOut` with `no_admission_result`, and a fresh invite redeemed after the eviction makes J Active inside its poll. M decrypts no epoch after the eviction. In v1, P's clock has not passed `not_after + τ`, so P's rename and J's add seal at once; M can follow those commits and none after A's eviction. In v2, J's attempt ends at its deadline in typed `TimedOut` with `no_admission_result` (§2 item 3), with no seat and no key. |
| H7-6 `w3h_s7_h7_6_expiry_hold_ends_by_eviction` (D71; cross-slice with ADR 0110 §1a) | As H7-5 without J, with M's committed certificate embedded on every roster. The harness also holds M', M's renewal from the same owner, same agent and a later `not_after`. A is the designated admin. | (a) At T0 + τ' + 1 s, P renames the group. At +2 s, deliver M' only in M's announce to A and P. At +3 s, A and P each rename. (b) As (a), but the owner also revokes M's agent at +1.5 s. (c) As (a) with A's seat also expired and P stopped, so no admin holds an unexpired certificate. | (a) Red: `main` treats the announced M' as Clean, keeps M seated and seals. (b) Red: nothing evicts M on `main`. (c) Red: on `main` every seal refuses and nothing evicts M. | (a) M' releases nothing. Seals refuse with `OwnerCertifiedEvictionRequired [M]` until S4 evicts M within B, then resume. M rejoins with a fresh invite carrying M' and is Active. (b) S4 evicts M for the revocation, and no seal other than that eviction lands while M is Active. (c) The obligation shows `waiting_for_admin_certificate_renewal` naming A, and the case then uses the exit that ADR 0110 Q1 rules. Assertions for a rebinding commit wait for ADR 0110's ruling (Q6). |

**Safety controls.** C1–C3 must be green on the release that activates §4. They need the ADR 0107 and D60 code, so they may be red on `main` today. That is §4's prerequisite, not S7's red case.

- **C1 `w3h_s7_c1_revocation_race`:** Home {O, P, M}. O revokes M's agent, and in a second run M's machine, while P holds a pending GSS envelope resend and a staged Welcome and join result for M, and J's add is in flight. No key material reaches M, or M's machine, after P holds the revocation. For the agent revocation, P's seals refuse with `OwnerCertifiedEvictionRequired [M]` until S4's eviction commits within its bound, and M cannot decrypt the next epoch. For the machine revocation, seals continue, as ADR 0110 §1 states.
- **C2 `w3h_s7_c2_expiry_race`:** M's certificate expires between staging and delivery, and between two resends. Nothing is delivered or resent to M once the sender's clock is past `not_after + τ`. S4's eviction removes M within its bound (D71), and P's other seals refuse with `OwnerCertifiedEvictionRequired [M]` until it commits.
- **C3 `w3h_s7_c3_quarantine_race`:** the group gets a fork-quarantine marker, or is withdrawn, while a resend to M is pending. The resend is dropped.

**Non-regressions.**

- An uncertified or foreign-owner joiner is still refused at admission and on apply.
- A policy opt-in into OwnerCertified with one uncertified seat is refused.
- A restarted or snapshot-installed node runs the full verdict until one all-clean seal. A fresh joiner's other operations are not gated by the mark.
- An unowned install writes no binding, no Home and no records.
- A process restart keeps the binding and the same Home.
- Two concurrent `POST /home` calls create exactly one group. So do a setup request and a concurrent `POST /home`.
- A crash injected after group persistence and before the binding write resumes to one bound Home. So does a failed binding write followed by a retried `POST /home`, which returns the same group.
- A cleared intent with no prior binding leaves an empty record, and a later owner-sync session adopts into it.
- An unreadable binding file stays byte-identical, and no writer runs. A binding or setup request with an unknown magic, a body that does not decode, or trailing bytes is refused and left byte-identical; it reports `binding_unreadable` or `setup_request_unusable` with the cause.
- Adoption leaves `named_groups.json`, `home-suite-groups.json` and the TreeKEM snapshot byte-identical; the `hs451_downgrade_safety` tests stay green.
- ADR 0106 and 0107 join paths and ADR 0062 pair recovery are unchanged.
- The ADR 0069 seat tests are adapted: a seat mints only into the bound Home.

**Mixed-version check (required, D42).** Run with the real 0.45.0 and 0.46.x release binaries inside the isolated namespace.

- M1: a 0.46.x device enrolled with a bound S7 device creates no Home. With its sessions blocked past its deadline it creates a duplicate. After the block lifts, the register converges on H and S7 devices stay bound to H. M1b repeats this with 0.45.0, which creates at once.
- M2: H7-2b with L on 0.46.x, and again with L on 0.45.0. The register flips to H0. O and A stay `local` in H with `pointer_conflict` = H0, and the record version stops advancing.
- M3: frozen 0.45.0 and 0.46.x decoders decode an S7-minted `HomePointer` record and verify its owner signature. S7 decodes and verifies records minted by both release encoders, from committed fixtures. `SyncKind::ALL.len() == 4` (`owner_sync.rs:3549`).
- M4: real owner-sync sessions between S7 and each release binary, with each side initiating. Every session completes, `HomePointer` merges, and no session aborts on decode.
- M5: downgrade to 0.46.x on the same data dir and upgrade again. The old binary starts, ignores `home-binding.hbind`, and leaves it byte-identical; the re-upgraded daemon resolves the same Home. M5b: run the S7 `x0x user-id create`, then start 0.46.x first, then S7. The old binary ignores `home-setup.hsreq`, and S7 ends the request with `home_exists`; one Home exists. M5c: released 0.45.0 and 0.46.1 each start on a data dir and identity dir that hold both files (from the candidate's encoder, and from the committed fixtures once released). Startup succeeds, and both files stay byte-identical. M5d: a managed self-update to S7 that rolls back before ADR 0094's host commit leaves neither file on disk. M5e: S7 decodes the committed fixtures of both files, and refuses each with one byte of its magic changed. A 0.45.0 downgrade is otherwise governed by ADR 0085.
- M6 (§4): 0.45.0 and 0.46.x members apply an add sealed by an S7 admin that did not re-check O's seat.

**Release check (D107).** The release notes of every release that ships S7 state the old-binary duplicate limitation and its exit (§7).

**Review triggers:** S4's bound or trigger list changes; any new writer of the `("home")` register or of the binding file; a new keygen mode in `x0x user-id create`; a request to retire duplicates automatically.

## Rulings and open questions

**Still blocks David's Accept:** Q4. The Decision follows D106 as ruled; Q4's exception would change it, and an Accepted ADR cannot change. Q6, because §4's renewal text must match ADR 0110's ruling on an in-place rebinding commit before this ADR is frozen. Q5 does not block this ADR. The acceptance order also requires ADR 0110 to be Accepted first, with D71's expiry trigger and its accepted τ and timing bounds, which H7-5 and H7-6 use (§8).

David ruled on 2026-10-04 (D64, D65, D71, D106, D107):

- **D64 (0088 G7), L3 binds every slice:** a hard rule. Every block S7 adds or touches ends in a typed refusal, or a typed wait that names what it waits for (§5a). This includes the joiner's 120 s poll when an admin holds its add (§4, H7-5).
- **D65, the acceptance order:** "S8" in 0088's order means S8(a), ADR 0107. ADR 0114 follows S4, and S7 does not wait for it (§8).
- **D71 (was Q2), expiry after admission:** certificate expiry is an S4 eviction trigger, with the same bounded eviction work as a revocation. §4 adds it to the activation set and to the seal hold, using ADR 0110 §1a's selected certificate, `not_after + τ` test and renewal rule. No in-place rebinding commit exists yet, so an expired seat stays held until S4 evicts it (Q6, H7-6). §5 states the remaining clock-skew window, which S4 bounds. ADR 0110's trigger list changes before its acceptance.
- **D106 (was Q1), Home at owner setup:** owner setup creates the Home through the same create path and guards, which refuse when a binding exists or is pending (§1).
- **D107 (was Q3), old-binary duplicates:** a release-note known limitation until every owner device runs S7. There is no minimum version for Home (§7).

Still open for David:

- **Q4, an exception to D106 for identities that may already own a Home (blocks Accept).** D106's guards refuse only when a binding exists or is pending. A further machine set up with `x0x user-id create --from-seed` can have neither, even when another machine of the same owner already holds a Home. §1, as ruled, then creates a duplicate, the #824 class that D42 stops. The authors propose an exception for your ruling:
  - (a) Proposed: the CLI writes a setup request only when it mints a new identity by random keygen on an install with no `user.key` and no `owner.json`. A seeded identity, a `--rotate-owner` replacement and a re-create of the same identity write no request. The CLI then reports `home: not_requested`, with the reason (`seeded_identity`, `rotated_owner` or `same_identity`) and the next step: enroll this machine with the owner's other machines and let adoption bind it, or run `x0x home create` on the first machine. L4: no setup creates a second Home for an owner that may already have one. Cost: an owner whose first machine is seeded runs `x0x home create` once. Harness case H7-4d: run `x0x user-id create --from-seed X` on S1 and on S2, two fresh nodes that are not enrolled with each other. Start both and advance the clock 600 s. Red on `main`: each creates a Home after its deadline, so one owner holds two Homes. Green: each CLI reports `home: not_requested` (`seeded_identity`), neither node holds a Home-shaped group, and each `GET /home` is 404 `no_home`.
  - (b) Keep §1 as ruled. Cost: every further seeded machine set up before it is enrolled creates a duplicate Home until the user retires it.
  - Recommended: (a). D106's own reason was that the guards stop duplicates; for a seeded identity they cannot.
- **Q5, machine revocation (does not block this ADR).** ADR 0110 §1 says machine and binding revocations are not eviction triggers. §4 follows it and today's seal verdict, which checks agent revocation only, so a seat on a revoked machine holds no seal. D60 stops every delivery to that machine, but a TreeKEM leaf there can follow later commits until its agent is removed: the window D71 closed for expiry. Closing it is a change to ADR 0110's trigger list before ADR 0110 is accepted. §4's seal hold follows that list, so only §4's restatement of the list would change here.
- **Q6, in-place certificate rebinding (follows ADR 0110; blocks Accept).** ADR 0110 §1a lets only a verified commit that binds a renewed certificate into a seat cancel expiry work, but no such commit exists today (§4). ADR 0110 holds its design as an open question that blocks ADR 0110's Accept. This ADR invents no mechanism. Until that question is ruled, §4 exempts only S4's eviction, and an expired seat is held until S4 evicts it. If ADR 0110 accepts a rebinding commit, including the self-rebind its Q1 proposes for when every admin has expired, the authors propose three changes here before Accept:
  - §4 exempts that commit from the hold on the seat it rebinds. Once it lands, the renewal is the selected certificate, the hold ends, and S4's work ends `terminated`, cause `certificate_valid`, with no removal.
  - §5 gains that commit's security argument by reference to ADR 0110.
  - H7-6 gains a case: at T0 + τ' + 2 s an admin commits the rebinding of M' into M's seat. Every seal after it succeeds, no node sees a `MemberRemoved` for M, and M decrypts the new epochs. Its baseline is red, because `main` has no such commit.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

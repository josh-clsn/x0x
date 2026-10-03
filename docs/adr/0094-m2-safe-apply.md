# ADR 0094: M2 safe apply with supervised self-rollback

<!-- File name: docs/adr/0094-m2-safe-apply.md -->

- **Status:** Proposed
- **Date:** 2026-10-03
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** TBD
- **Supersedes:** [ADR 0061](./0061-supervised-upgrade-restart-ownership.md) Decision §6 only, upon acceptance
- **Superseded by:** none
- **Goal served:** Charter goal **M**, Track **M-safety**, slice **M2**. M1 and M2 form the **M-safe** milestone. **R-number:** none of R1–R11 directly. R12 is the later goal-M requirement (D20). M1/M2 are fixes to shipped behaviour and need no R12 (D21).
- **Related:** [ADR 0045](./0045-decentralized-self-update.md), [ADR 0085](./0085-persisted-binary-formats-are-versioned.md), [ADR 0087](./0087-repository-and-release-governance.md); [#1115](https://github.com/saorsa-labs/x0x/issues/1115), [#1106](https://github.com/saorsa-labs/x0x/issues/1106), [#1104](https://github.com/saorsa-labs/x0x/issues/1104), [#1086](https://github.com/saorsa-labs/x0x/issues/1086), [#1144](https://github.com/saorsa-labs/x0x/issues/1144), [#261](https://github.com/saorsa-labs/x0x/issues/261); [upgrade system](../upgrade-system.md). Rulings: D20 and D21 in the [rulings digest](../design/x0x-direction.md).

## Context

Source basis: `origin/main` at `8bc197d2ad1f0c2981d3e23058df8e025dbf153c`.
`src/upgrade/apply.rs` resolves the #261 planner before replacement, then
exits under supervision without flush or rollback. Only the unsupervised
helper checks readiness. CLI replacement is outside daemon rollback.
`monitor.rs` accepts timestamp 0; the manifest has no channel.
`src/server/routes/upgrade.rs` ignores `include_prereleases` in gossip apply.
All four triggers apply immediately. `StagedRollout` is unused in production.
The process-local mutex cannot protect a shared executable's backup.

The 7b(C) rehearsal installed an AppleDouble entry and failed with
systemd `203/EXEC` (#1144). A binary that cannot execute never reaches a
boot counter. A format check and a new-binary counter cannot cover that gap.
M2 must cover both crash-loops and failed execution.

This proposal replaces ADR 0061 §6's manual-recovery boundary; §1–§5 remain.
ADR 0045's wider supersession stays with planned ADR 0097 and M3–M6.

## Decision Drivers

- Recover the previous executable without human SSH.
- Keep one lifecycle owner per instance and one binary writer per host.
- Preserve identities, roots and durable data across restart and rollback.
- Cover failure before the candidate runs any Rust code.
- Enforce release eligibility in every apply path.
- Keep installation, health commit and recovery as separate facts.

## Considered Options

1. **Manual recovery and removal of StagedRollout.** Smallest change. Rejected:
   it leaves supervised outages and immediate fleet-wide apply.
2. **New-binary counter and exec probe alone.** Rejected: neither can recover
   a failure to execute after the swap, or a crash before the counter runs.
3. **Counter, probe and native recovery hooks.** Linux [systemd `OnFailure=`](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
   needs a separate recovery unit and tested restart ordering. Separate
   platform hooks multiply the recovery state machines.
4. **Counter, probe and a stable supervisor-owned launcher; wire staging.**
   Chosen. One recovery contract covers all platforms. It costs a separate
   executable and explicit service migration.
5. **A detached helper beside the service manager.** Rejected: it recreates
   the competing lifecycle owners prohibited by ADR 0061 and #493.

## Decision

We will use option 4 for M2. The #261 planner remains the only restart path.

### 1. Release eligibility

Require signed JSON `channel`: `stable` or `prerelease`. Keep schema 1,
framing, topic, signature context and key. Verify the original bytes.
Reject missing/unknown channels, timestamp 0 and manifests older than 30 days.
Require a semver prerelease suffix only for `prerelease`; reject mismatches.

Use one eligibility check for startup, gossip, polling and authenticated
`POST /upgrade/apply`. Stable is the default. Prerelease apply requires
`include_prereleases=true`; HTTP cannot bypass it. Reject invalid manifests
before forwarding or file writes. Local channel preference restricts apply,
but permits forwarding otherwise valid manifests.

### 2. Prepare and probe before swap

The OLD daemon resolves ownership, participants, argv, cwd and roots first.
Verify the signed archive. Extract one exact regular-file basename per binary
and check platform magic (#1144). Run both candidates with `--upgrade-probe`
under the service account and launch environment. Require the expected version
and platform, with exit 0 within 5 s, before either swap.
The flag opens no store, creates no key, binds no socket, joins no network and
increments no boot counter. Spawn failure, timeout or mismatch refuses apply.
This proves execution before swap, not health or later execution.

### 3. One host transaction; daemon and CLI together

Wire **StagedRollout** (#1106). All four triggers use
`hash(MachineId) × rollout_window_minutes`; fleet default ≥60 min.
Persist first eligible receipt and due time per release. Duplicate delivery
and restart cannot reset it. Before-due apply reports pending. For shared
installs, wait until every participant is due. Zero is an explicit local
setting. Evidence-gated rings and owner policies remain M4.

Use a host-wide cross-process lock and durable journal for apply and recovery.
Inventory every instance sharing the target, including `x0xd-443`.
Refuse incomplete inventory or unresolved ownership. Participants join one
transaction. Recheck installed versions/hashes under the lock; never back up
already-new bytes as the previous release.

Reserve a same-filesystem backup namespace per instance and transaction.
Save each `<exe>.backup-<ver>` at its actual previous version, including the
managed CLI (#1104). Record paths/hashes and never overwrite rollback copies.
Daemon and CLI form one transaction. Failure of either restores both.
Journal partial swaps: two renames are not pairwise atomic.

Flush backups and prepared intent before swapping. Atomically replace journal
phases with file/directory durability barriers, or Windows equivalents.
Each `upgrade-handoff.json` names the host transaction. Pending intent reserves
it across process exit; successors reacquire the lock and reconcile first.
Cleanup cannot remove referenced backups before commit or verified recovery.

CLI install requests delegate to authenticated daemon apply and its planner.
Split/package-managed CLIs outside the declared install remain outside the
transaction. Report them as not upgraded, with reinstall hints.
`upgrade --check`, including `--force`, compares CLI, daemon and release versions.

### 4. New-binary boot counter and health commit

The NEW daemon reads `upgrade-handoff.json` before store mutation or updates.
Validate transaction, instance, target hash/version and roots. Flush its boot
counter before initialization. Allow three uncommitted boots, 30 s per attempt
and 90 s total after old-process exit. Persist the total deadline; never reset
it on restart. On exhausted boots, the next entry restores before initializing.
An expired deadline also triggers rollback. The launcher bounds failed starts
that cannot enter the reader.

The NEW binary flushes its health commit after stores initialize and M1
startup health holds for 10 s. Verify child ownership, version and roots;
HTTP 200 alone is insufficient. GitHub cannot gate startup (#1086).
Commit the host transaction only after all instances commit and CLI matches.

The counter triggers restore from its recorded per-instance `.backup-<ver>`.
Quiesce peers under the host transaction. On Unix, the NEW binary restores
both files after the launcher grants the recovery phase, then flushes and
exits. On Windows it flushes a rollback request and exits; the launcher reaps
it before restoring locked executables. The launcher starts restored bytes.

Before supervised exit, await acknowledged flush of stores, bootstrap cache,
upgrade state and logs, bounded at 5 s. Cancellation or port release is not
proof of flush. Failure or timeout aborts apply and restores installed bytes.

### 5. Recovery owned by the supervisor

Use stable `x0x-launcher`, outside the daemon/CLI swap set. It owns child
startup, bounded health observation, termination/reaping and fallback restore.
It stays alive across child exits and joins no gossip. Validate its version,
rights and loaded service binding before apply. Update it separately.

| Platform | Chosen recovery owner | Reason |
| --- | --- | --- |
| Linux systemd | Stable launcher as the unit's `ExecStart` | It sees failed exec directly and uses the same journal for crash-loop and cannot-exec recovery. It does not depend on a separate `OnFailure=` job reaching the right phase. |
| macOS launchd | Stable launcher as the loaded job's program, with verified `KeepAlive: true` | launchd keeps the launcher alive. The launcher owns its child; it neither detaches nor creates a competing launchd job. [Apple launchd guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html). |
| Windows | Stable launcher as the SCM service executable | Keep recovery in the tracked service process. Reap the child before file replacement. Do not depend on a helper escaping a wrapper's job object. [Microsoft job-object contract](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects). |

Read back the loaded manager-to-launcher-to-child binding, with roots/argv.
Migrate direct systemd/launchd jobs explicitly. Unsupported Windows wrappers
refuse apply; a marker alone is insufficient.

Spawn failure or missing commit triggers launcher rollback, including failure
before the counter runs. Reap failed children before restore or respawn.
Launchers share the host lock/journal; one process writes at a time.
Reconcile interrupted recovery after launcher crash or reboot.
Intentional service stop never triggers an upgrade restart.

Keep #261's helper for genuinely unsupervised runs, with the same pair journal.
It waits for old-process release and reaps failed candidates before restore.
Managed runs never detach it. Verify restored versions and health.
Recovery failure preserves data/backups, writes `UPGRADE_FAILED` and returns
nonzero. Persist a failed-release hold across rollback. Only a newer release
or authenticated explicit retry clears it. This is local recovery, not recall
or general downgrade permission.

### 6. Wire, storage and mixed versions

`channel` is an additive signed JSON wire field. Current old daemons ignore
unknown struct fields and verify the original bytes. They can accept the new
schema-1 manifest, but do **not** enforce its channel. Confirm this with real
released binaries. New daemons refuse old manifests without `channel`.
Publish a channel-bearing stable manifest for the transition. Keep ADR 0087's
prerelease publication ban until the supported updater population enforces
channels; the new field alone does not protect old listeners.

Version the new transaction and boot-state JSON explicitly. Preserve the
legacy handoff fields and decode released legacy records separately as
diagnostic intent, never as proof of an armed M2 transaction. Unknown or
corrupt records fail closed and remain intact. Recovery requires validated
install paths and hashes, not arbitrary paths supplied by a handoff file.
The stable launcher retains the readers needed by its supported rollback set.

M2 changes no application snapshot layout. ADR 0085 still governs any later
persisted binary change: versioned magic, frozen released decoders, lazy
rewrite and byte-preserving refusal on downgrade. Binary rollback does not
undo data writes. An old binary may leave a newer store unavailable but intact.
The rollback health check must distinguish that from failed recovery. Never
delete or rewrite an unreadable store to make a health check pass.

## Consequences

### Positive

- Supervised failures can restore service without human SSH.
- Failed exec is covered even when the boot counter never runs.
- Shared executables retain old bytes and roll back the managed CLI too.
- Staging and channel settings govern every apply trigger.

### Negative / Trade-offs

- A separate launcher and explicit service migration add maintenance work.
- Host coordination may delay every instance sharing an install.
- Strict manifest validation rejects legacy manifests without a channel.
- Rollback can preserve newer stores that the old binary cannot open.

### Neutral / Operational

- M-safe requires M1 and M2 shipped. This ADR does not authorize M3–M6.
- Report installed, pending, committed, recovered and recovery-failed states
  through M1's `/health`, `/diagnostics/upgrade` and `x0x doctor --json`.
  Retain the failed-attempt receipt after successful rollback.
- Protection is one release behind: the applying OLD binary supplies the
  probe, durable preparation and flush. The first M2 release is not proof
  that its own installation was protected by M2.

## Validation

These are implementation and release exit criteria, not tests run by this
docs-only change. Networked CI tests use the repository's isolated Linux
runner. An ephemeral test droplet canary is a separate controlled gate.

- **Eligibility and probe CI:** exercise all four triggers. Reject absent,
  unknown, mismatched and tampered channels, timestamp 0 and stale manifests.
  Reject probe spawn failure, timeout, wrong version and nonzero exit with
  both installed binaries unchanged. Prove the probe has no runtime effects.
  Load new manifests with released old binaries; test legacy handoff readers.
- **Staging and writer CI:** before-due apply remains pending across restart
  and duplicate delivery. Race two processes on one executable. Observe one
  transaction, an intact previous-version backup and both instance outcomes.
- **Transactional rollback CI:** run the real #261 unsupervised handoff with
  a signed failing candidate and a CLI companion. Exercise cannot-exec,
  unhealthy startup, partial swap and recovery failure. Interrupt each
  journal phase, including between the two swaps/restores and before commit.
  Prove restored hashes/versions, preserved sentinel data, no overlapping
  roots, and durable failure reporting. Rollback failure must return nonzero.
- **Supervised CI:** the Linux systemd job runs the real stable launcher with
  a candidate that passes the probe but crashes on normal startup. Observe
  the NEW binary's counter and automatic pair rollback. Then make a
  post-probe candidate unable to execute and prove launcher recovery without
  a counter write. Include a crash before counter initialization, a hung
  child, launcher restart, host reboot and shutdown-flush failure.
- **Platform receipts:** isolated launchd and Windows service fixtures prove
  child ownership, failed-exec recovery, locked-file rollback, preserved roots
  and intentional stop. A Linux pass does not close either platform gate.

Retain the charter's separate 7/7a/7b receipts for **every v0.46.x and the
first M2 release**. Use private test-key builds only on the test plane.
Never publish or gossip them to production. Extend 7b with both failure arms:

| Row | Required evidence |
| --- | --- |
| 7 | Ops holds the other fleet hosts; the actual previous-release updater applies the signed candidate on one host pair. Record both listeners. |
| 7a | Draft bytes boot under real configuration before publication. This proves binary health separately from apply. |
| 7b healthy | A test-signed release traverses gossip, the planner and the loaded systemd/launcher contract. Both affected instances commit at the expected version. |
| 7b crash-loop | On the test droplet, a probe-passing candidate crashes repeatedly. Its boot counter triggers recovery to the previous daemon and CLI, without human SSH or manual restore. |
| 7b cannot-exec | First reject an unexecutable candidate before swap. Then inject failed execution after a successful probe/swap; the stable launcher restores both binaries without candidate code or human SSH. |

Both failure arms must recover `/health`, preserve identity and data sentinels,
and show the failed attempt in `/health` and `x0x doctor --json`.
Record source/binary hashes, manifest, loaded policy, roots, process ownership,
counter/journal phases, companion version and elapsed recovery time.
No missing observation is a pass. Rehearse a second protected M2-to-M2 update
before claiming the applying-binary protection is active. ADR 0087 requires
this proposal on main before implementation merges to any branch, and human
acceptance before its wire change reaches main.

### Open questions for David

- Confirm three attempts, 30 s readiness, 90 s total and 10 s stable health.
  Which M1 startup verdicts must block commit on offline hosts?
- Confirm a 60 min minimum fleet window. Should managed fleet policy forbid
  zero, while allowing it on private rehearsal hosts?
- Should Windows recovery gate the first M-safe milestone, or remain refused
  until its service fixture and migration have separate receipts?
- What backup retention and disk reserve should apply after health commit?
  Pending or failed recovery backups must remain protected.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

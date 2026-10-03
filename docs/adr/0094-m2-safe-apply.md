# ADR 0094: M2 safe apply with launcher-owned rollback

<!-- File name: docs/adr/0094-m2-safe-apply.md -->

- **Status:** Proposed
- **Date:** 2026-10-03
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1)
- **Supersedes:** [ADR 0061](./0061-supervised-upgrade-restart-ownership.md) Decision §6 only for launcher-bound jobs, upon acceptance. Unmigrated jobs retain §6.
- **Amends:** ADR 0061 §3 (exit-status contract) and §5 (restart through the external owner) for launcher-bound jobs, upon acceptance.
- **Superseded by:** none
- **Goal served:** Charter goal **M**, Track **M-safety**, slice **M2**. M1 and M2 form **M-safe**. No R1–R11 directly applies. D20 places R12 later; D21 authorizes M1/M2 as fixes to shipped behaviour.
- **Related:** [ADR 0026](./0026-managed-x0xd-deployment.md), [ADR 0045](./0045-decentralized-self-update.md), [ADR 0085](./0085-persisted-binary-formats-are-versioned.md), [ADR 0087](./0087-repository-and-release-governance.md); [#1115](https://github.com/saorsa-labs/x0x/issues/1115), [#1106](https://github.com/saorsa-labs/x0x/issues/1106), [#1104](https://github.com/saorsa-labs/x0x/issues/1104), [#1086](https://github.com/saorsa-labs/x0x/issues/1086), [#1144](https://github.com/saorsa-labs/x0x/issues/1144), [#261](https://github.com/saorsa-labs/x0x/issues/261); [upgrade system](../upgrade-system.md). D20/D21 and the release canary rulings are in the [rulings digest](../design/x0x-direction.md).

## Context

Source basis: merged main at `5fdba260edbf203c18cc5d9b5b74ff4b9c80736a`.
The #261 planner resolves ownership before replacement. Supervised apply
still lacks acknowledged flush and automatic rollback. The managed CLI is
outside daemon rollback. A process-local mutex cannot protect a shared install.

There are five daemon install paths: startup check, gossip receipt, fallback
poll, authenticated `POST /upgrade/apply`, and `x0xd --check-updates`.
The fifth runs in a separate process. `run_update_check_and_report` calls
`run_startup_update_check` with runtime `None`. It downloads, verifies and swaps
the daemon and CLI without restart or the serving daemon's lock.
HTTP apply releases its mutex when the handler returns. After about 750 ms,
it resolves another restart plan. Installed bytes can change in that window.

#1144 is closed by #1179. Extraction now requires an exact basename, a regular
file, a single match and valid platform magic (`src/upgrade/apply.rs`).
Valid-magic binaries can still fail to execute: wrong architecture, missing
loader or glibc, a noexec mount, or a sandbox restriction. A candidate counter
cannot cover failure before execution.

#1086 is fixed by #1183: the startup update check runs after API bind in a
background task. Release builds have no configurable update source.
`StagedRollout` is still unused in production; its compiled window is 0.
Channel and future-timestamp checks still need a common eligibility contract.

Fleet units currently run `ExecStart=/opt/x0x/x0xd` directly. Desktop jobs
come from `x0x autostart`. M2 protection requires a separate migration.
This proposal changes ADR 0061 §3/§5/§6 only for verified launcher-bound jobs.
Unmigrated jobs retain §6's manual-recovery boundary and report unprotected.
ADR 0087 rule 7 stays in force. ADR 0045's wider supersession stays with the
planned ADR 0097 and M3–M6.

## Decision Drivers

- Restore supervised service without human SSH, including failed execution.
- Keep one lifecycle owner per instance and one binary writer per host.
- Preserve identities, roots, old bytes and durable application data.
- Apply one eligibility contract across every install path.
- Distinguish instance health from completion of the host transaction.

## Considered Options

1. **Manual recovery and removal of StagedRollout.** Rejected. It leaves
   supervised outages and immediate fleet-wide apply.
2. **Candidate counter and exec probe alone.** Rejected. They cannot recover
   a post-swap exec failure or a crash before the counter runs.
3. **Counter, probe and native recovery hooks.** Rejected. Separate recovery
   units and platform hooks need separate restart-ordering contracts.
4. **Counter, probe, stable launcher and StagedRollout.** Chosen. The launcher
   sees failed execution and owns recovery. It requires explicit migration.
5. **Detached helper beside the service manager.** Rejected. It recreates
   competing lifecycle owners prohibited by ADR 0061 and #493.

## Decision

Use option 4. Keep the #261 planner as the single restart planner.
On supervised M2 paths, only the launcher restores files and restarts children.
The candidate writes boot records and its own health commit. It never restores
itself. Windows managed apply remains **REFUSED** in M2.

### 1. Eligibility and staging

Require signed JSON `channel`: `stable` or `prerelease`. Keep schema 1,
framing, topic, signature context and key. Verify the original bytes.
Reject missing or unknown channels, timestamp 0, and manifests older than the
existing 30-day limit. Reject future timestamps beyond a bounded skew; David
must set that bound. Require a semver prerelease suffix only for `prerelease`.
Reject mismatches before forwarding or writing files.

Use one eligibility check for the four serving-daemon triggers. Stable is the
default. Prerelease apply also requires `include_prereleases=true`; HTTP cannot
bypass this. While ADR 0087's ban stands, do not forward prerelease-channel
manifests. A signed channel alone does not authorize prerelease publication.
Make the fifth path, `x0xd --check-updates`, report-only. It must not install
binaries or SKILL.md. CLI install requests delegate to authenticated daemon
apply. They cannot create another writer.

Wire **StagedRollout** (#1106) for automatic apply. Use
`calculate_delay_for_version`: hash MachineId and version, normalize the hash
to a fraction, then multiply by `rollout_window_minutes`. The fraction is in
[0, 1); it is not a raw hash multiplier. Version salt changes the order for
each release. A permanent early ring belongs to M4.
Persist the first eligible receipt, chosen delay and remaining wait per release.
Duplicate receipts and restart do not reset the wait. Count elapsed monotonic
time in a boot; retain the remaining wait across reboot without trusting a
wall-clock jump. Shared installs wait for every participant to be due.
Keep the compiled default at 0 pending David's ruling on the default and fleet
minimum. Whether HTTP apply must wait for staging is also an open question.
#1169 is out of M2 scope (announcement latency): due time starts at first
receipt, so discovery lag adds to the rollout window.

### 2. Probe, inventory and prepare

The OLD daemon resolves the restart plan before any swap. The plan contains
ownership, participants, executable paths, argv, cwd and effective roots.
Carry that exact plan through apply, HTTP response delay, flush and exit.
Do not resolve a fresh plan after replacement. Hold the host lock until the
old applying process exits, including the HTTP response window. A refusal
before mutation may release it. A durable pending intent reserves the install
across exit; launchers then acquire the lock to continue the transaction.

Each instance registers at boot under the host lock. Record its instance ID,
canonical executable, identity/data roots, PID and process start time, boot ID,
argv and loaded service/launcher binding. PID alone is not identity.
The registry is reconciled with the ADR 0026 inventory, loaded jobs and the
actual running process set. **Complete inventory** is the union of every
running instance and every configured job that can start the target install,
including stopped jobs and `x0xd-443`. Each member must have known roots,
ownership and install paths. Missing, unreadable or unattributed members refuse
M2 apply. Registration alone does not prove completeness.
Every inventoried job sharing the install must have a compatible launcher
binding. Stopped jobs retain their stop state; they need no health commit unless
the plan selects them to run. Their next start must reconcile pending intent.

Freeze the participant set in prepared intent. A newly arriving instance outside
that set waits for resolution; it cannot change the plan or start candidate
bytes outside the transaction. Each launcher drives only its own child from the
journal. One participating launcher becomes the host coordinator under the
lock. Record its PID/start time and boot ID. If it dies, a surviving or restarted
launcher takes that role under the lock after checking process identity.
After the OLD applying process exits, launchers lock host-journal changes and
release the lock while waiting for children. Each candidate writes only its
own boot/health records and registers under the lock without a parent deadlock.

Verify the signed archive and retain #1179's extraction checks. Run both
candidates with `--upgrade-probe` under the service account and launch
environment. Require exit 0 and the expected version and platform before swap.
Dispatch this flag before all initialization, as the early `--version` path
in `src/bin/x0xd.rs`, including before profiling and artifact cleanup.
The probe reads no config, takes no instance or host lock, writes no logs or
files, opens no store, creates no key, binds no socket and joins no network.
It runs no artifact sweep and increments no boot counter.
Probe spawn failure, timeout or mismatch writes a durable failed-release hold
before returning refusal. It leaves installed bytes unchanged. This prevents
restarts and repeated gossip receipts from downloading the same failure again.
The probe time bound is an open question. A passing probe proves execution in
that environment, not health or guaranteed later execution.

### 3. Host transaction and state machine

Use one cross-process host lock for apply and recovery. Recheck installed
versions and hashes under it. Never save already-new bytes as the old release.
Reserve same-filesystem backup paths by transaction and actual prior version.
Keep each `<exe>.backup-<ver>` for the daemon and managed CLI (#1104).
Record paths and hashes; never overwrite a referenced rollback copy.
Two renames are not atomic as a pair. Journal each daemon and CLI swap and
restore separately. Cleanup must retain files referenced by unresolved intent.

Stage signed SKILL.md with the release. Do not write it outside the transaction
from startup, gossip or polling. Install it atomically only after host commit,
record that result, and report a failed metadata install separately. Binary
rollback therefore leaves the previous SKILL.md in place.
Split/package-managed CLIs outside the declared install remain outside the
transaction. Report them as not upgraded, with reinstall hints.
`upgrade --check`, including `--force`, compares CLI, daemon and release versions.

A **record barrier** means: write a replacement record, fsync it, rename it,
then fsync its parent directory. A **file barrier** means: fsync the staged or
backup file, then fsync the directory after its install/backup rename.
Do not acknowledge a phase until its barriers succeed. The host journal holds
transaction ID, sequence, participant set, immutable plan, hashes, backup paths
and progress. Per-instance records bind the same transaction and generation.

| State | Transition | Owner | Durable record | Required fsync barrier |
| --- | --- | --- | --- | --- |
| staged | Eligible receipt → staged; due, verified artifacts and passing probes → probed; probe failure → failed-release hold | OLD applying daemon | Receipt, wait, manifest/artifact hashes and stage paths | Record barrier and staged file barrier before probe; hold barrier before refusal |
| probed | Preparation succeeds → prepared intent | OLD applying daemon | Probe outputs bound to both artifact hashes | Record barrier before preparation |
| prepared intent | Inventory and backups ready → swapped (daemon) | OLD applying daemon | Frozen plan, participants, previous hashes and backup paths; launcher acknowledgement | Backup file barriers and intent record barrier before first swap |
| swapped (daemon) | Daemon installed → swapped (CLI), or failure → rolling back | OLD applying daemon; coordinator reconciles after its death | Daemon swap progress and observed hash | Daemon file barrier, then progress record barrier |
| swapped (CLI) | Pair installed → per-instance handoff armed, or failure → rolling back | OLD applying daemon | CLI swap progress and observed hash | CLI file barrier, then progress record barrier |
| per-instance handoff armed | All handoffs durable, old flushes acknowledged and old children reaped → booting(n); failure → rolling back | OLD participants arm/flush; coordinator authorizes start after exit; each launcher starts its child | `upgrade-handoff.json` per instance, generation, flush/reap receipts, start authorization and budget | Every handoff, flush/reap and authorization record barrier before candidate start |
| booting(n) | Candidate health holds → health-committed per instance; failed start → next bounded attempt or rolling back | Launcher reserves attempt n before spawn; candidate writes boot record before initialization | Launch attempt, boot counter, PID/start time, boot ID and monotonic budget | Attempt record barrier before spawn; candidate boot record barrier before store mutation |
| health-committed per instance | All participants healthy and CLI hash matches → host-committed; any participant fails → rolling back | Candidate writes its health commit; host coordinator verifies the full set | Per-instance health evidence; it remains provisional until host commit | Per-instance record barrier before coordinator accepts it |
| host-committed | End binary transaction; permit format upgrades and SKILL.md install | Host coordinator launcher, under host lock | Host commit bound to all current child identities, health records and installed hashes | Host commit record barrier before announcing success or allowing new-format writes |
| rolling back | Stop/reap every participant, invalidate provisional commits → failed-release hold → restored | Host coordinator selects rollback; each launcher stops its own child; coordinator restores pair | Rollback generation, stop/reap receipts and separate restore progress | Rollback record barrier before commands; hold barrier before restored start; file/progress barriers for each restore |
| failed-release hold | Failed probe leaves old install running; rollback may proceed to restored; later clearing needs David's ruling | OLD daemon for probe refusal; coordinator launcher for apply/recovery failure | Release version and signed manifest hash, reason, transaction and recovery status | Hold record barrier before refusal or any restored child start |
| restored | Pair hashes verified and hold durable → each launcher starts its restored child; failed restore → held recovery failure | Host coordinator verifies pair; each launcher starts only its own child | Restored pair hashes, per-instance restart/health outcome and retained failure receipt | Restore file barriers and restored record barrier before start |

A per-instance health commit is provisional. If A commits and B fails, the host
coordinator records rolling back and invalidates all provisional commits by
advancing the transaction generation. A's launcher stops and reaps A too.
Only after every child is stopped may the coordinator restore the pair.
Each launcher then restarts its own instance. The candidate never arbitrates
recovery. A host commit cannot be written by the last candidate to become healthy.

### 4. Flush, health and crash recovery

Before supervised exit, await acknowledged flush of stores, bootstrap cache,
upgrade state and logs. A fired shutdown hook, cancellation or port release
is not proof of flush. Failure or timeout requests launcher rollback. If the
hook has stopped the old daemon, its launcher restarts the restored release.
If it is still alive, stop and reap it before restoration. Never assume it
can resume serving after a failed flush. The flush time bound needs a ruling.

Count candidate launch attempts, including exec failures, before spawning.
The candidate records its boot before initialization. Bound uncommitted boots,
per-attempt readiness and total time; David must set those limits. Persist boot
ID, monotonic start/deadline and attempt count before the first old shutdown
request. Flush, restart throttling and retries all count. Launcher restart in the same
boot keeps the deadline. Wall-clock changes do not alter it. On a changed boot
ID, increment a durable reboot count and roll back an uncommitted transaction;
never grant a fresh budget. Time lost during power-off cannot extend a trial.

The candidate commits health only after stores initialize and M1 startup
health holds for the agreed interval. Verify version, roots and launcher-child
ownership; HTTP 200 alone is insufficient. Update-endpoint reachability cannot
gate commit. #1183 already puts the GitHub check after bind in the background.
No persisted-format upgrade writes are allowed before host commit. Until then,
write a rollback-readable layout or defer the write, including lazy rewrites.
Instance health alone cannot release this restriction.

For each row below, inject `kill -9` into the relevant old process, new process
and launcher, and power loss at both sides of each durability barrier.
A restart reads the durable journal and checks actual file hashes before spawn.

| Crash point / fault | Required recovery |
| --- | --- |
| Staging or probe interrupted | Keep old bytes; retain receipt/wait. Do not infer a passing probe from partial records. A recorded probe failure retains its hold. |
| Prepared intent or backup interrupted, before swap | Reconcile hashes under the lock. Keep old bytes; incomplete backups cannot authorize swap. If the old process died, its launcher starts verified old bytes after resolving intent. |
| Daemon rename done, progress missing; CLI still old | Coordinator uses intent and actual hashes to detect the partial pair. Record rollback and hold, restore both; never treat the mixed pair as committed. |
| Both swaps done, handoff not written, old process dies | Launcher reads prepared intent before spawn. NEW bytes are unarmed; do not respawn them. Record rollback and hold, restore pair, then start old bytes. |
| Some handoffs armed; another arm or flush not complete | No candidate start authorization exists. Launcher coordinator rolls back the whole pair if an old process dies or preparation fails. |
| Shutdown hook fired; flush fails or process dies before acknowledgement | No flush receipt means failure. Coordinator rolls back; each launcher reaps its old child before restoration and restarts restored bytes as needed. |
| Start authorization durable; exec fails before candidate boot record | Launcher attempt record counts the failure. Retry only within the recorded budget, else coordinator rolls back. |
| Candidate boot record or health observation interrupted | Launcher reaps the child. Charge the recorded attempt; do not accept missing health evidence. Continue within budget or roll back. |
| A health-committed; B fails before host commit | Coordinator invalidates A's provisional commit. A's launcher stops/reaps A; B's launcher stops/reaps B. Coordinator restores pair; both launchers restart restored children. |
| Coordinator killed before/during host commit | Successor coordinator reacquires the lock. Missing commit requires fresh full-set validation within the original budget or rollback. Durable host commit is final; a later ordinary crash uses normal service restart. |
| Launcher killed while its child lives | systemd cgroup/launchd process-group policy removes the child. Successor checks PID/start time and reaps any survivor before spawn; no overlapping root is allowed. |
| Power loss or reboot during uncommitted health deadline; wall clock steps | Same-boot clock steps cannot change monotonic deadlines. Changed boot ID consumes a reboot record and selects rollback. Counters and budgets never reset. |
| Rollback interrupted between daemon and CLI restores | Successor checks hashes, continues idempotent restoration from protected backups, and verifies both. It does not start a mixed pair. |
| Hold write interrupted before restored child start | Do not start restored bytes until the hold record and directory are durable. A subsequent gossip receipt cannot reapply the held release. |
| Recovery itself fails, or launcher restarts in recovery-failed state | Preserve data/backups and hold; record `UPGRADE_FAILED` where writable. Launcher stays running with degraded status and no child respawn/recovery loop. On launcher restart, retry no failed recovery action automatically. Require explicit repair. |
| Restoration complete; launcher dies before/after restored child starts | Durable hold still blocks reapply. Reconcile pair and child identity, then start only a missing restored child. Retain the failed-attempt receipt. |

If a durability barrier fails, take no next destructive step. A failed hold
barrier cannot authorize a restored start. Recovery failure remains visible;
it is not converted into a successful rollback or an endless launcher exit loop.
Intentional service stop never requests an upgrade restart.
Keep #261's helper for genuinely unsupervised runs, with the same pair journal
and hold ordering. It is their recovery actor. Managed runs never detach it.

### 5. Launcher installation and migration

Install stable `x0x-launcher` outside the daemon/CLI swap set through the tracked
host installer or `x0x autostart --repair`. Distribute it as a separately signed
artifact. Verify its hash/version, account rights and journal-reader support
before binding a job. Update it only through that installer/repair route, with
no active transaction, preserving the old launcher and reading pending records
before child startup. The daemon updater must not replace its recovery actor.

| Platform | M2 contract |
| --- | --- |
| Linux systemd | Unit `ExecStart` is the stable launcher. Require `KillMode=control-group` or `mixed`; verify the loaded cgroup, launcher and child binding. No orphan child may survive launcher replacement. |
| macOS launchd | Loaded program is the launcher with `KeepAlive: true`. Do not set `AbandonProcessGroup`; verify the job, process group, launcher and child argv/roots. |
| Windows managed | Apply is REFUSED. SCM launcher design and fixtures belong to M6/#621 and require R12. M2 does not claim Windows managed recovery. |

Migrate fleet jobs through the ADR 0026 inventory. Migrate desktops with
`x0x autostart --repair`, preserving label, argv, environment and roots.
Install an M2-capable daemon first under the existing direct job. Only then
install/bind the launcher, reload the job, and verify manager → launcher →
child readback. Current pre-M2 systemd readback requires `MainPID == x0xd`
(`restart.rs:959–967`); launchd readback requires program basename == argv0
(`restart.rs:255–265`). A pre-M2 daemon behind a launcher would refuse apply.
The first M2 install therefore retains ADR 0061 §6's recovery boundary.

Unmigrated direct jobs may use their validated ADR 0061 contract, but their M1
verdict must report `upgrade.protection = unprotected` and manual recovery.
Verified launcher-bound jobs report `launcher_bound`. Unsupported Windows jobs
report `unprotected` and apply refused. A mixed protected/unprotected participant
set refuses an M2 host transaction; it cannot claim partial host protection.
For launcher-bound jobs, §3 binds the manager's launcher exit policy separately
from child upgrade exit; §5 routes child restart only through that launcher.
Readback and migration receipts, not a marker, establish this contract.

Implement M2 in these slices. Each slice retains the protection verdict until
its full platform contract is verified.

- **S1:** common eligibility, signed channel and report-only fifth path.
- **S2:** staging, host lock/inventory, carried restart plan, versioned backups
  and managed CLI transaction, including split-install reporting.
- **S3:** acknowledged flush, durable journal, counters and Linux launcher.
- **S4:** launchd launcher, repair migration and platform receipts.

### 6. Wire and rollback-readable storage

`channel` is an additive signed JSON field. Released old daemons ignore unknown
fields and verify original bytes, but do not enforce channels. Confirm this
with real released binaries. New daemons refuse old manifests without channel.
Publish a channel-bearing stable manifest for the transition. The condition
for lifting ADR 0087 rule 7 is an open question, not an M2 policy decision.

Version journal and boot-state JSON explicitly. Preserve legacy handoff fields;
decode released legacy records as diagnostic intent, not proof of an armed M2
transaction. For unknown or corrupt recovery records, **fail closed** means:
take no apply or recovery action, preserve the records, but start the configured
binary normally and report unprotected/degraded. Never brick startup on downgrade.
Recovery requires validated install paths and hashes; arbitrary paths in a
handoff cannot authorize a restore. The launcher retains readers for its
supported rollback set.

M2 changes no application snapshot layout. ADR 0085 governs later persisted
changes: versioned magic, frozen released decoders and byte-preserving refusal.
Before host commit, prohibit writes that upgrade any persisted format.
After commit, binary rollback cannot undo ordinary data writes. An old binary
may refuse a newer store and keep serving with that store unavailable.
M1 reports `stores[].verdict = refused_on_downgrade`, the store ID, format and
reason; it reports binary restoration separately. Keep the manifest entry and
file byte-identical. Never delete or rewrite the store to pass health.

## Consequences

### Positive

- Launcher recovery covers failures before any candidate code executes.
- One host journal protects old bytes, all instances and the managed CLI.
- Durable holds stop repeated apply of a known failed release.
- Migration and M1 verdicts make protection limits visible.

### Negative / Trade-offs

- Launcher installation, inventory and migration add maintenance work.
- One failed participant rolls back all participants before host commit.
- Strict channel validation rejects legacy manifests without channel.
- Recovery can leave newer stores intact but unavailable on an old binary.

### Neutral / Operational

- M-safe requires M1 and M2 shipped. This ADR does not authorize M3–M6.
- M1 `/health`, `/diagnostics/upgrade` and `x0x doctor --json` report installed,
  staged, provisional health, host commit, restored and recovery-failed facts.
- The OLD applying binary supplies protection. The first M2 installation
  does not prove that its own install was protected by M2.

## Validation

These are implementation and release exit criteria, not tests run by this
ADR-only change. Networked CI uses the fresh loopback-only Linux namespace
with dropped privileges required by the repository. The real systemd CI job
also uses `PrivateNetwork=yes` or a dedicated loopback-only netns. Test daemons
must never reach the real network. A private droplet canary is a separate gate.

- **Eligibility/probe:** cover all five paths and delegated CLI requests.
  Prove `--check-updates` is report-only. Reject absent, unknown, mismatched
  or tampered channels, zero/stale timestamps and excessive future skew.
  Block prerelease forwarding while the ban stands. Probe spawn failure,
  timeout, wrong version and nonzero exit preserve installed bytes and write
  the hold. Observe no config, locks, logs, files, sweep or runtime activity.
  Test new manifests with released old binaries and legacy/unknown records.
- **Signing seam:** the failing candidate and companion require a test signing
  key. Add a test-only verifier seam around hard-coded `RELEASE_SIGNING_KEY`.
  It must not compile into release artifacts or accept a runtime key override.
  A release check proves shipped binaries accept the production key, reject
  the test key and contain no test-key/source configuration seam. Private
  fixture builds and keys remain on the isolated test plane.
- **Staging/writers:** duplicate delivery, restart and reboot preserve receipt
  and wait. Test version-salted ordering and zero/default policy. Race two
  writers, a late instance registration and an HTTP response-delayed restart.
  Prove one immutable plan and host lock survive until old-process exit.
  Reconcile stopped jobs, stale PID reuse and incomplete inventory.
- **Pair/split installs (#1104):** test daemon+managed CLI success and rollback
  with different previous versions. Test a separate CLI path and a package
  install: it remains untouched, reports not upgraded with reinstall guidance,
  and `upgrade --check --force` reports CLI/daemon/release versions correctly.
  SKILL.md stays old before host commit and on rollback.
- **Fault matrix:** inject every listed crash at both sides of each barrier.
  Include daemon/CLI partial swap and partial restore, missing handoff, hook
  fired without flush acknowledgement, A healthy/B failed, coordinator death,
  hold fsync failure, reboot, clock step and recovery failure. Prove restored
  hashes, sentinel data, no overlapping roots, no reapply or recovery loop,
  and full failure receipts. Preserve format bytes before host commit.
- **Supervised/platform:** real systemd launcher tests probe-passing startup
  crash, post-probe exec failure, hung child and intentional stop. Test launcher
  kill with a live child, cgroup cleanup and manager readback. Isolated launchd
  fixtures prove process-group cleanup, repair order and preserved roots.
  A Linux pass does not close launchd. Windows refusal is a negative control.
- **Storage:** unknown recovery records permit normal startup without actions.
  A newer store refused after downgrade remains byte-identical, keeps its
  manifest entry and reports `refused_on_downgrade`; binary recovery is separate.

Keep the **release canary rows** 7/7a/7b for every v0.46.x and the first M2
release, as required by the rulings digest. Private test-key builds are never
published or gossiped to production. Extend the rows with both failure arms.

| Row | Required evidence |
| --- | --- |
| 7 | Ops holds the other fleet hosts. The actual previous-release updater applies the signed candidate on one host pair. Record both listeners and whether their jobs are protected. |
| 7a | Draft bytes boot under real configuration before publication. Record binary health separately from apply. |
| 7b healthy | An isolated gossip announcer supplies the test-signed manifest on the private test network. Both affected instances traverse gossip, the carried planner and loaded systemd/launcher contract. Close outbound TCP 443 before candidate boot and keep it closed through host commit. Both healthy candidates commit despite blocked GitHub egress. |
| 7b crash-loop | A probe-passing candidate repeatedly crashes on the test droplet. Launch attempts/boot records lead the launcher coordinator to restore the previous daemon and CLI without SSH. Hold is durable before either restored instance starts. |
| 7b cannot-exec | Reject an unexecutable candidate before swap. Then inject failed execution after successful probe/swap. Launcher restores both binaries without candidate code or SSH, including the missing-handoff crash point. |

Both failure arms recover `/health`, preserve identity and data sentinels,
and show the failed attempt in `/health` and `x0x doctor --json`.
Record source/binary hashes, manifest and announcer, loaded policy, roots,
process ownership, journal/counter phases, companion version and elapsed time.
No missing observation is a pass. Rehearse a second protected M2-to-M2 update
before claiming applying-binary protection. ADR 0087 requires this proposal on
main before implementation merges to any branch, and human acceptance before
its wire change reaches main.

## Open questions for David

- What probe timeout covers Defender first-exec scans and a loaded 2-vCPU host?
  The earlier 5 s proposal is not a ruling.
- What attempt count, readiness interval, total recovery budget, shutdown-flush
  bound and stable-health interval should apply? The earlier three attempts,
  30 s each, 90 s total and 10 s health leave no restart-throttling allowance.
  Which M1 startup verdicts must block commit on offline hosts?
- What bounded future-timestamp skew should eligibility permit?
- Should the compiled rollout default change from 0? Is 60 min the fleet
  minimum, and may private rehearsal hosts use zero?
- Must authenticated HTTP apply wait for staging, or may it explicitly bypass
  the rollout wait while retaining eligibility and transaction checks?
- What clears a failed-release hold: a newer release, an authenticated retry,
  explicit local repair, or another rule? Until ruled, retain the hold.
- What supported-updater population and evidence allow lifting ADR 0087
  rule 7's prerelease ban? This ADR does not lift it.
- What backup retention and disk reserve apply after host commit? Backups for
  pending transactions and failed recovery remain protected.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

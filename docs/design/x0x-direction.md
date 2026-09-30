# x0x design direction and rulings digest

- **Status:** maintained digest, not an ADR. It records the design rulings
  David Irvine made from 2026-09-28 to 2026-09-30 (decisions D01–D36 and the
  efficiency decisions E-D1–E-D17).
- **Updated:** 2026-09-30.
- **Relationship to ADRs:** ADRs remain the decision records, and only David
  marks an ADR Accepted. Where a ruling here changes what an Accepted ADR
  means in practice, the status overlay at the top of the
  [ADR README](../adr/README.md) says so. New work follows the ruling until the named successor ADR is
  decided.
- **ADR numbers marked (prov.)** are provisional. The real number is
  allocated when the ADR PR is opened on `main`.
- **Keep in sync:** a PR that changes a ruling updates this file and the ADR
  README overlay together.

## 1. What x0x is

x0x is **glue**. It binds a person, their machines and their agents into one
trusted, reachable whole, and then lets people join their wholes together.

- **We do not provide agents.** Users bring any agent, running anywhere: on
  their own machines, in a cloud, or behind a vendor API. x0x is how those
  agents find, trust and reach each other and their human.
- **Machines.** Every machine an owner enrols is connected and reachable
  (reach, ports, names). The model is Tailscale, but leaner, post-quantum,
  and with no central coordinator.
- **Agents.** Any agent joins through the local daemon. Agents form swarms and
  teams (messaging, groups, task lists, delegation, scratchpads) that do work
  for their human.
- **Humans.** People collaborate by sharing whole agent teams with each other,
  under scoped, expiring, revocable capabilities.
- **Shared places.** Scratchpads, message boards and project data, in public
  and private groups, for agents and humans alike. This is a core capability,
  not an add-on.
- **Self-explaining.** Any agent that sees x0x knows how to use it: a compact
  onboarding recipe, a JSON API with typed errors, and an event stream. Agents
  teach other agents to join.
- **Self-sustaining.** Agents keep x0x healthy and upgraded, under owner
  policy.
- **Efficient.** Idle cost, bytes per useful message, CPU per verified frame,
  memory, disk growth and battery or metered-link cost all have explicit
  budgets that releases are measured against.
- **For everyone.** David's own use, embedders already building on x0x, and
  any human or agent. Embedder field reports are first-class input.

x0x stays beneath agent protocols such as MCP and A2A and does not define what
agents mean or do. It ships as the `x0x` Rust crate, the `x0xd` daemon
(loopback REST/WS/SSE plus an embedded GUI) and the `x0x` CLI. Every machine
and agent has a self-authenticating post-quantum identity (SHA-256 of an
ML-DSA-65 key; no registry), and the human owner is the root of authority.

## 2. Goals and requirements

| Goal | Meaning |
|---|---|
| **F: it connects and works** | Machines, agents and their human are always reachable and mutually trusted, with no setup rituals. Every capability is correct, bounded and observable. |
| **A: people collaborate through agent teams** | An owner's agents across many machines trust each other with no manual contact editing. The owner shares a chosen agent or team with another person, scoped, expiring and revocable, and the teams work together (DM, groups, shared places, forwards, exec). |
| **D: shared places** | Scratchpads, message boards and project data (KV, task lists, boards, scratch stores) in public and private groups. Private groups are end-to-end encrypted, with forward secrecy on membership change (TreeKEM). Rich real-time collaborative text is a later layer on top of these primitives. |
| **E: highly efficient** | Explicit, measured budgets for bandwidth in both directions, CPU, memory, storage, log growth, radio wakeups and latency. Budgets become release criteria, and no efficiency change may lose a message. |
| **M: self-sustaining** | Health verdicts, release verification, safe upgrade and rollback under owner policy, agent-assisted install and join, and problem reporting. |

The requirement yardstick from [ADR 0072](../adr/0072-scope-freeze-deferred-and-legacy-maintenance.md)
still applies: R1 a human owner · R2 many agents · R3 all my machines
connected · R4 connectivity better than Tailscale · R5 share a subset of my
agents · R6 agents collaborate across machines · R7 machine-resident agents
reachable by my agents and sharees · R8 video/audio calling · R9 CRDT shared
notes and agent scratchpads · R10 an agent opens a GUI view for its human ·
R11 agents teach others to install and join. **R12**, "x0x is maintained by
its own agents", is agreed (D20) and is recorded by ADR 0096 (prov.) after
v0.46.0 is promoted. Every new ADR names the R or goal E it serves.

## 3. Scope

**Membership test.** A capability belongs in x0x core if people, their
machines and their agents need it to find, trust, reach, share with or
coordinate through each other, or to keep that efficient and self-sustaining.

- **In scope:** identity and owner authority (R1, R2); reach, ports and names
  (R3, R4); scoped, revocable sharing of agents and teams (R5, R7); swarm and
  team coordination: DM, groups, task lists, delegation (R6); shared places:
  scratchpads, boards, project data (the R9 primitives); agent-opened views
  (R10); onboarding (R11); self-maintenance (R12); efficiency budgets (E).
- **Lower priority, not in scope now (D19):** R8 media calling (the browser
  media gateway, voice in release builds) and the rich-text notes merge path
  (loro). Both are reconsidered after the core is efficient and proven.
- **Out of scope:** providing, hosting or running AI agents; MCP tool
  semantics; A2A task semantics beyond serving a card (#112 deferred); any
  global DHT for user data ([ADR 0006](../adr/0006-no-global-dht-for-user-and-group-data.md))
  or central registry, apart from the compiled-in release key.
- **Placement rule.** A feature that needs no new wire semantics (the calls
  lifecycle, a notes UI, GUI show) may ship inside `x0xd` as a default-off
  reference application. New protocol surface needs an ADR that names an R or
  goal E.

## 4. Invariants

Each invariant has one owning chokepoint. Several are violated today, and the
wave that fixes each is in section 7.

| # | Invariant |
|---|---|
| I1 | **Delivery.** An obligation acknowledged to a caller survives restart and is retried until ACKed, revoked or expired. Nothing is ACKed and then dropped. |
| I2 | **Delivery honesty.** A caller can always tell sent, deferred, shed and delivered apart. No "Ok but dropped" without a counter and a queryable id. |
| I3 | **Authenticity at ingress.** Nothing unsigned or unverified reaches an app or internal consumer as authenticated. |
| I4 | **Epochs and sealing.** Seal only under the currently committed epoch. Hold a future-epoch record for a bounded time, never drop it silently. Every departure, self-leave included, ends the leaver's read access at the next epoch. |
| I5 | **Admission evidence.** The evidence needed to admit (certificate, attestation, enrollment, grant) travels with the request. No gate depends on a warm gossip cache. |
| I6 | **Authorization.** Every remote decision uses one `Authority::decide`; every local owner-effect route is in one durable-owner table; group access goes through one extractor. |
| I7 | **Revocation.** A revocation never expires while the credential it kills can still verify, survives a corrupt store, and reaches every gate and every live session (group membership included, D34) within a bound. |
| I8 | **Liveness with offline peers.** Only an enumerated list of rules may block forever. Admission, catch-up and repair complete when any one active admin or holder is online. |
| I9 | **Upgrade continuity.** State written by release N−1 opens under N, and a wire change an older version mishandles is gated by a signed capability bit. |
| I10 | **Upgrade reversibility and blast radius.** Every applied release can be undone on that machine without human SSH, and no release reaches more than ring 0 before evidence exists. |
| I11 | **Released bytes equal the tested graph.** |
| I12 | **Resource bounds.** A daemon never fills its host's disk, spends a user's uplink as infrastructure, or grows queues without bound, and every bound is visible. |
| I13 | **Plane isolation.** A test or named daemon never joins production by accident. |

## 5. Decisions D01–D36

Status key: **implemented** = in effect on `main` (code, configuration or an
Accepted ADR); **ruled** = decided by David, work outstanding or ongoing;
**pending ADR** = the ruling needs the named ADR, which is not yet Accepted.

| Id | Ruling (one line) | Status |
|---|---|---|
| D01 | v0.46 failing to read v0.45 KV snapshots (C1) is a release blocker; the fail-closed downgrade of `X0XKVS2` is accepted (files kept, unreadable on 0.45). | Implemented: #1046, [ADR 0085](../adr/0085-persisted-binary-formats-are-versioned.md) |
| D02 | The v0.46.0 gate is relative to a v0.45.0 baseline, with exactly three Home gating rows, a Home stopping rule and a drop rule for should-land fixes. | Ruled; gate in progress |
| D03 | Canary: a draft-bytes deploy before publish, a 0.46→0.46.x self-upgrade rehearsal on a real systemd host, and no GitHub prerelease publishing. | Ruled; gate rows 7a/7b outstanding |
| D04 | Released bytes equal the CI-tested graph: `Cargo.lock` is tracked, `release.yml` consumes it, and prerelease tags are refused. | Implemented; recorded by ADR 0087 (Proposed) |
| D05 | Release-key protection: release build, sign, create and publish jobs, and ad-hoc SKILL.md signing, run in a protected `release` environment with David as required reviewer, limited to `v*` tags. | Implemented; recorded by ADR 0087 (Proposed) |
| D06 | #1044 (owner-sync admission on verified enrollment) is kept and recorded retroactively, amending ADR 0041; the SyncV1-acceptor machine-revocation re-check is must-land. | Implemented: [ADR 0084](../adr/0084-enrolled-owner-sync-admission.md) |
| D07 | The v0.46 should-land fix set is approved under the drop rule. The review-only model lanes may also author small fixes, each reviewed by another model family. Persisted consent moves to W3. | Ruled |
| D08 | The grant capability bit ships in v0.46 (David chose this over deferral). | Implemented: #1064, [ADR 0093](../adr/0093-capability-advert-registry.md) |
| D09 | The v0.46 known limitations and the 0.46→0.45 downgrade procedure are signed; `/calls` is labelled experimental. | Ruled; release notes outstanding |
| D10 | Three criteria changes ratified: #903 (predecessor loss is a mixed-version limitation), #952 folded into #504, and #1021's precondition barrier. | Ruled |
| D11 | ADR 0069 (Home waits for owner sync) is accepted as a record of shipped behaviour, to be superseded by ADR 0088. | Implemented: [ADR 0069](../adr/0069-home-wait-for-sync-before-auto-provisioning.md) |
| D12 | #613 stays separate from #807 and keeps its measurement row. | Ruled |
| D13 | #646 (invites stop past 20 Active+Banned members) is a product limit, not parked; fixed in W4. | Ruled |
| D14 | Testnet evidence runs on dedicated hosts, sealed from production. | Ruled |
| D15 | CI runs on PRs to every base; `main` has a ruleset with required checks and no bypass; `v*` tags are admin-only; no separate bot identity. | Implemented; recorded by ADR 0087 (Proposed) |
| D16 | Group liveness contract: a promoted admin with carried evidence may admit while the owner is offline; any active admin may redeem; stale-base gaps catch up; Home becomes an explicit owner group (OwnerCertified checked at admission, revoke by eviction). A simulation harness reproduces each failure first. | Pending ADR 0088 (prov.), W3 |
| D17 | Trust gates decide only from in-band evidence plus persisted state, through one `Authority::decide`. | Pending ADR 0089 (prov.), W3 |
| D18 | One group crypto (TreeKEM only) and one acknowledged-delivery primitive (`Outbox<T>`), enforced in CI: no new bespoke queues in fix PRs. | Pending ADRs 0090, 0091 (prov.), W3 |
| D19 | Scope (revised 2026-09-29): x0x is the glue between people, their machines and their agents and does not provide agents. Shared places, sharing whole agent teams and efficiency are core. R8 media calling and the loro notes merge path are lower priority. | Pending ADR 0095 (prov.), after promotion |
| D20 | R12, "x0x is maintained by its own agents", is agreed. | Pending ADR 0096 (prov.), after promotion; ADR 0097 (prov.) supersedes ADR 0045 |
| D21 | Track M-safety (M1 health verdict, M2 safe apply with self-rollback) starts right after v0.46.0, in parallel with W3; W3 gets a second author lane. | Ruled |
| D22 | Owner-key custody: ADR 0015 stands for now, with a rotate/recertify and lost-device runbook. After promotion, ADR 0100 (prov.) supersedes it for the owner root only, together with device delegation. | Ruled; ADR 0100 (prov.) after promotion |
| D23 | Revocation permanence and priority: no sweep before `not_after`, a Machine issuer path, Critical carriers, a fail-closed store, one listing. ADR 0080 is revised as a capability-gated single-record push. Both apply before any `shed_normal` default. | Pending ADR 0098 (prov.), W4 |
| D24 | A protocol-aware stream gate: the connect ACL governs forward and exec targets, owner protocols pass on owner trust, unregistered protocols are reset. | Pending ADR 0099 (prov.), W4 |
| D25 | An inbox policy `[dm] accept = open / contacts / owner_and_grants` on both DM paths, default open. | Pending ADR 0099 (prov.), W4 |
| D26 | The Leaf egress default (ADR 0078, Proposed) is decided after v0.46 as one bundle, in the E-D6 order, with revocation topics exempt first and a re-measurement first. | Ruled (decision deferred to W4) |
| D27 | Cuts after v0.46, as removal-only PRs: roaming (retire ADR 0037/0043), `/mls/groups`, the peer relay (reject ADR 0051) at ADR 0071's exit, the KV DM fallback once `Outbox<T>` exists, dead code. Withdraw ADR 0063. Decline grantee fetch; the number 0076 stays unused. | Ruled; ADR 0102 (prov.) retires roaming |
| D28 | ADR hygiene: ADR 0083 implementation is held after slice 1 until a cross-model review is recorded; new slices of ADR 0070, 0077 and 0079 are held until their reviews are recorded; the other "Reviewers pending" ADRs get a README note. | Implemented in the ADR README overlay |
| D29 | An ADR 0089 slice is pulled into v0.46, overriding the moratorium for this slice only: persist verified agent→machine bindings and KEM keys for relationship peers (enrolled devices, grant parties, group members); an on-connect evidence exchange; a pull lookup ("who hosts agent X; send me its signed announce"); ADR 0021's no-persistent-cache rule amended for relationship peers only. | Pending ADR 0089 (prov.); it must be Accepted before its code merges |
| D30 | v0.46 gains a restart-cold gate row backed by a CI test (DM, TreeKEM join/Welcome, file offer and owner sync after a cold restart), plus row 4b: a restarted rc sender to a 0.45 receiver within 5 minutes. | Ruled |
| D31 | PR #1092 (reconnect re-announce) is fixed, then merged as a stopgap until the D29 slice supersedes it: no debug print, per-node bytes and verifies stated including churn, a longer absence (about 5 minutes) before re-announcing, and a cross-model review. | Ruled; PR open |
| D32 | Fix the paper drift now, docs only: this digest, the ADR README status overlay, ADR 0087, #966, the missing planned issues, tracker hygiene, and W3, M-safety and W4 milestones. | In progress |
| D33 | ADR 0089's scope is a pull lookup plus persisted evidence for relationship peers, on top of D17. | Pending ADR 0089 (prov.) |
| D34 | The three D16 holes: (1) in ownerless groups, an active admin's signed terminal snapshot attests stale-base catch-up (a mandate layer above ADR 0016, which gives #871 a re-seat path); (2) any online admin that receives a revocation evicts and rekeys within a bound, and group membership joins I7's live-session rule; (3) up to K certificates travel inline and the rest by hash, fetched from any holder (ADR 0088 owns fetch-by-hash). | Pending ADR 0088 (prov.) |
| D35 | Sharing and mixed versions: a 90-day maximum ShareGrant lifetime with renewal (ADR 0098); after a restart, obligation-carrying typed sends to peers of unknown capability are held for up to one advert period; a minimum supported version and support window for embedders is published, owned by M1's census. | Ruled; lifetime pending ADR 0098 (prov.) |
| D36 | Planning: W4 is re-sequenced so A5 (scratch store plus Data capability) and a team record come right after M3; named-group fanout joins E-D17's protected delivery classes before any shed default; every review finding on a merged PR becomes an issue or a written dismissal within 24 hours. | Ruled; the review rule is recorded by ADR 0087 (Proposed) |

## 6. Efficiency decisions E-D1–E-D17 (Track E)

Levers are ranked by evidence: measure first, then quick wins with no wire
change, then structural wire work under ADRs. v0.46.0 carries no efficiency
code; it only measures.

| Id | Ruling (one line) | Status |
|---|---|---|
| E-D1 | Efficiency budgets become release criteria through an ADR drafted after promotion. v0.47 gates on exact tier-0 tests plus a relative A/B rule on a sealed mesh (N ≥ 5 deploys per arm); absolute ceilings start in the wave whose levers can reach them. | Ruled; budgets ADR after promotion |
| E-D2 | The v0.47 target column is accepted; later-wave targets are revisited after the first baseline and the first v0.47 A/B. | Ruled |
| E-D3 | The first efficiency baseline (E0) runs on a dedicated, ephemeral testnet, non-gating for v0.46, once its harness review and host-metric preconditions are met. | Ruled; run outstanding |
| E-D4 | Testnet daemons move off the production bootstrap hosts after promotion, not mid-gate. | Ruled |
| E-D5 | jemalloc ships in release builds in v0.47, after a 24-hour no-restart A/B. | Ruled |
| E-D6 | The Leaf egress bundle (D26) goes in order: unicast capability responses and capability-gated DM-bus hedges, then consume-only Leaves, then an enforced Leaf budget. Enforcement never goes first. | Ruled |
| E-D7 | Session-authenticated hop-local control frames in saorsa-gossip, in W4, after message-id-to-signer binding; legacy sessions stay signed. | Ruled; upstream design issue and ADR after promotion |
| E-D8 | Post-quantum envelope collapse is drafted after promotion and implemented in W4; the draft moves machine binding and publisher binding into the inner envelope. | Pending ADR 0101 (prov.) |
| E-D9 | Direct-first durable DM (persist-then-ACK on a live authenticated connection, gossip inbox as fallback) is W3's one delivery primitive, gated on an ADR 0093 capability bit. | Pending ADR (amends ADR 0030/0050), W3 |
| E-D10 | Gossip-learned strangers are no longer persisted as contacts; they stay in the TTL-bounded discovery cache. | Pending ADR, W3 |
| E-D11 | A metered/edge profile and an embedder power API (foreground, background, suspend) come in W4, after the transport liveness contract; embedders are asked for measurement rigs after promotion. | Ruled |
| E-D12 | SKILL.md splits into a signed core of at most 2k tokens plus on-demand topic pages, with a CI token budget, right after promotion. | Ruled |
| E-D13 | A binary size gate (1 MiB growth per PR needs sign-off) and release-profile tuning in v0.47. Release-workflow changes are merged by David. | Ruled |
| E-D14 | A new ML-DSA backend is benchmarked only; an ADR follows only for a ≥ 2× gain on x86_64 and arm64 with test vectors and a constant-time review. | Ruled |
| E-D15 | The efficiency rules apply to every PR and ADR: as a review checklist now, and as CI lints in v0.47. | Ruled; checklist in force |
| E-D16 | UDP receive buffers are recorded now and raised on production hosts after promotion; ant-quic reports the effective size in v0.47. | Ruled |
| E-D17 | A delivered/published matrix is a hard gate on every lever that sheds, prunes, gates or re-routes bytes: own-origin, inbox, targeted and revocation classes deliver 100%, and no pair falls below baseline. Named-group fanout joins the protected classes (D36). | Ruled |

**The efficiency rules in brief (E-D15).** A byte saving that loses a message
is a failure. Every topic declares its audience and rate, and request/response
and ACK traffic goes to the requester only. Costs are stated as wire bytes in
both directions, including post-quantum envelopes. Every periodic task, cache,
queue and map states its budget, is bounded and is visible. Persistence is
O(change). Signatures are used only where transferable authenticity is needed,
and every verify is counted. Compatibility carriers name a sunset.
`[profile.test]` never raises `opt-level` for x0x crates. Measurements are
repeated, sealed-mesh and stated with their evidence level.

## 7. Wave plan

Calendar figures are estimates.

| Wave | What it is | State (2026-09-30) |
|---|---|---|
| **W0: ops now** | Stop the bleeding (the log flood), seal the testnet, lock scope, answer field reports. | Started 2026-09-28 |
| **W1: land #802** | The final-acceptance candidate lands on `main` as one integration merge, with no tag. | Done (merge `952ed18`, 2026-09-28) |
| **W2: v0.46.0 gate** | Fixes only, released against the signed relative gate (D02, D03, D30). Must-land: C1 (#1046, ADR 0085), the #1044 panic follow-up, the tracked lock and prerelease refusal, the self-upgrade rehearsal, the release environment, and any regression the gate finds. Should-land fixes merge by the cutoff or drop to a signed known limitation. Efficiency is measured only. | In progress |
| **v0.47 (early W3)** | Efficiency quick wins with no wire change, counters and tier-0/1 gates; the budgets ADR and ADR 0101 drafted; the SKILL.md split. | After promotion |
| **W3: group consolidation (Track G)** | ADR 0088 liveness contract; a deterministic multi-node simulation harness that reproduces #1023, #811, #818 and #969 before they are fixed; `Outbox<T>` (ADR 0090); one seal-and-publish service; in-band evidence and `Authority::decide` (ADR 0089); a `GroupAccess` extractor; one roster-commit path; one group crypto (ADR 0091); a digest beacon for KV and task lists (ADR 0092). Efficiency rides these chokepoints. | 10–14 weeks after promotion |
| **Track M-safety (parallel with W3)** | M1 health truth (a `/health` verdict, census, `x0x doctor --json`); M2 safe apply (supervised readiness and self-rollback, one binary writer per host, StagedRollout wired or deleted; ADR 0094). Exit: a crash-looping release on a supervised host is restored by the new binary with no SSH, and reported. | M-safe about 4–6 weeks after promotion |
| **W4: goal build (A, M)** | Scope ADR 0095 and R12 (ADR 0096) first. Then one R at a time, behind default-off flags, on a weekly train: M3 recall → A5 scratch store, Data capability and a team record (D36) → A2 lost device and revocation permanence → A4 sharing completeness → A3 device delegation → M4 owner update policy and canary → A6 offline delivery → M5/M6 problem reports and install help → A7 reach. The Leaf egress bundle (D26/E-D6) and the envelope work (E-D7, E-D8) also land here. | A and M exits Q1–Q2 2027 |

**Exit tests.** Goal A: the two-human end-to-end test passes in CI, and a
restarted owner device keeps owner trust with zero manual steps. Goal M: one
release is promoted under an owner's policy with a ring-0 attestation, and one
deliberately bad canary is rolled back and recalled automatically.

## 8. Parked, frozen, deprecated and cut

- **Parked (lower priority, D19).** R8 media calling: ADR 0042 and ADR 0073
  (the `/calls` signalling lifecycle stays, labelled experimental), #892. The
  rich-text notes merge path: ADR 0081, ADR 0082 and the notes half of
  ADR 0075, #1029, PR #1035. The scratchpad half of ADR 0075 is **not**
  parked; it is core and is re-specified as a sealed scratch store (ADR 0103,
  prov.).
- **Frozen (bug and security fixes only).** The placement ledger; relay
  metering and ADR 0035 steps 2–6 (ADR 0071); fork-quarantine layers beyond
  the marker and manual clear (ADR 0059, 0064, 0066, 0067, 0068), except
  where D16/D34 supersede them; Home auto-provisioning and election
  (ADR 0038, 0060, 0069), where after promotion Home failures are known
  limitations unless they are security defects; legacy Wiki/Web import; the
  A2A binding (#112, deferred); the constitution; public-message threading
  (ADR 0029).
- **Parked issues.** #442 and #443 (won't-do, D27), #639, #871, #112, #892,
  #1029. #646 is not parked (D13).
- **Deprecated.** The legacy DM bus (after a version floor); GSS group
  creation; raw 0x10 as a silent fallback; `x0xd --check-updates` as an apply
  path.
- **Cut after v0.46 (D27, removal-only PRs).** The roaming key-move ceremony
  and `/agent/move*`; `/mls/groups` and the MlsGroup side map; the X0X-0070
  peer relay (ADR 0051 rejected) at ADR 0071's exit; the KV DM fallback once
  `Outbox<T>` exists; dead code (`EncryptedTaskListDelta`, X0K2,
  `BootstrapConnector`, FOAF scoring, `combined_to_bytes`, the ADR 0063 V3
  publish path); dead config fields; the standalone apply path of
  `x0x upgrade` when a daemon answers.

## 9. Process rules

- **Moratorium until v0.46.0 is promoted.** Only fix ADRs are admissible:
  ones that record a fix to shipped or merged behaviour, a storage format, or
  deployment governance. The D29 slice of ADR 0089 is the one exception.
- **ADRs before code** (ADR 0087, Proposed). A wire, protocol or dependency
  change has its ADR Accepted before the code merges. An ADR written after the
  fact to record shipped behaviour uses the status `Accepted (record)`.
- **Accepted ADRs are immutable.** A change is a new ADR that amends or
  supersedes, or a README erratum for a factual correction. Only David marks
  an ADR Accepted. Implementation holds are decisions, not status changes
  (D28).
- **Cross-model review.** A change is reviewed by a model family other than
  its author's. A should-land fix that is not green within two
  review rounds by the cutoff drops to a known limitation.
- **Review findings** on merged PRs become an issue or a written dismissal
  within 24 hours (D36, ADR 0087).
- **Fix PRs shrink the system.** A fix may not add an AppState map, outbox,
  background loop or per-call-site gate; prefer removing one.
- **Efficiency.** Every PR applies the E-D15 checklist.

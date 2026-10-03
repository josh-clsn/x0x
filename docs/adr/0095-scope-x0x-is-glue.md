# ADR 0095: Scope — x0x Is Glue Between People, Their Machines and Their Agents

<!-- File name: docs/adr/0095-scope-x0x-is-glue.md -->

- **Status:** Proposed
- **Date:** 2026-10-03
- **Decision owners:** David Irvine (ruling D19, revised 2026-09-29; only
  David marks this ADR Accepted)
- **Author:** Claude (Opus)
- **Reviewers:** TBD (a Codex cross-model review follows)
- **Supersedes:** [ADR 0017](./0017-x0x-as-agent-transport-layer.md)
  **in part: its positioning only.** Its interop posture stays (§2).
- **Superseded by:** none
- **Amends:** [ADR 0072](./0072-scope-freeze-deferred-and-legacy-maintenance.md)
  (re-tiers its scope rules, §6).
- **Parks (priority only, §4):** ADR 0042 and ADR 0073 (R8 media calling);
  the notes half of ADR 0075, ADR 0081 and ADR 0082 (the R9 notes merge
  path). No Accepted ADR is edited.
- **Goal served:** all goals (F, A, D, E, M). This is the scope rule that
  later ADRs are checked against. It names R1–R11, R12
  ([ADR 0096](./0096-r12-x0x-is-maintained-by-its-own-agents.md)) and goal E.
- **Related:** [`docs/design/x0x-direction.md`](../design/x0x-direction.md)
  (§1, §3, §7, §8; rulings D09, D19, D21, D28, D36, D52, E-D1, E-D15);
  ADR 0103 (prov., scratch store); ADR 0083; ADR 0087 rule 8; #112, #113,
  #892, #965, #1029, #1094, PR #1035.

## Context

- ADR 0017 (2026-06-15) positioned x0x as "the transport layer beneath
  MCP/A2A". But x0x also ships owner identity and trust, share grants,
  TreeKEM groups, KV stores, task lists, delegation, a tailnet and a GUI.
- ADR 0072 (2026-09-25) froze mechanisms that no requirement needed, and
  made every new ADR name one of R1–R11. Its list is flat. It does not rank
  R8 or R9 against sharing or efficiency.
- On 2026-09-29 David revised D19 (digest §1, §3). x0x is the glue between
  people, their machines and their agents, and it does not provide agents.
  Shared places, sharing whole agent teams and efficiency are core. R8 media
  calling and the loro notes merge path are lower priority, not in scope
  now. The D19 decision record adds: "The primary user is an AI agent
  acting for one owner with 2–5 machines."
- D19 deferred this ADR until v0.46.0 was promoted, which happened on
  2026-10-03 (D52).

## Decision Drivers

- One checkable test for "is this core?" that applies to every ADR and PR.
- State what x0x is in David's framing, and stay beneath MCP and A2A.
- Put effort on shared places, team sharing and efficiency first.
- Keep shipped behaviour working. A park is not a removal.

## Considered Options

1. **Keep ADR 0017's "transport layer" positioning and ADR 0072's flat
   list.** Rejected. It undersells identity, trust, sharing and shared
   places, and it sets no priority.
2. **"The network-and-trust layer for one owner"** (the D19 wording of
   2026-09-28). Rejected by David on 2026-09-29. It undersold shared places,
   team sharing, embedders and efficiency.
3. **A full agent platform that hosts or runs agents.** Rejected. We do not
   provide agents, and a platform would compete with the protocols x0x sits
   beneath.
4. **Glue positioning, a membership test, a placement rule, and scope tiers
   that re-tier ADR 0072.** Chosen.

## Decision

We will position x0x as glue, and scope all work with the test in §3.

### 1. Positioning (supersedes ADR 0017's positioning)

- x0x is the glue between people, their machines and their agents.
- **We do not provide agents.** People bring their own agents, running
  anywhere. x0x is how those agents find, trust and reach each other and
  their human.
- x0x stays beneath agent protocols such as MCP and A2A, and does not
  define what agents mean or do. But the glue is not "just transport": it
  includes identity, owner authority, trust, reach, sharing, groups and
  shared places.
- The primary user is an AI agent acting for one owner with 2–5 machines.
  People who share agent teams, and embedders, are also users. Embedder
  field reports are first-class input.
- Headline requirement (D19): any agent that sees x0x knows how to use it.
  A task that an agent cannot do with the JSON API, a typed error and an
  event stream is a surface defect.

### 2. ADR 0017: what is superseded, and what stays

- **Superseded:** the Decision's lead sentence as the scope boundary ("the
  transport layer beneath MCP/A2A"), and the risk note that the transport
  story must stay cleanly separable so that adopters see "just transport".
- **Stays: the interop posture.** x0x serves a signed agent card
  (`GET /agent/card`, `GET /.well-known/agent-card.json`) and stays beneath
  MCP and A2A. The rejection of a full-stack rival (option A) and the
  post-quantum, zero-registry identity message also stay.
- A2A task semantics beyond serving a card are out of scope (#112, closed as
  not planned). The shipped unary A2A path stays as shipped.
- The Internet-Draft candidate (#113) describes the transport and identity
  layer. Its submission is not core work (open question 1).

### 3. Core

**Membership test.** A capability is core if people, their machines and
their agents need it to find, trust, reach, share with or coordinate through
each other, or to keep that efficient and self-sustaining. Core is:

- identity and owner authority (R1, R2);
- reach: all my machines connected, with ports and names (R3, R4);
- scoped, expiring, revocable sharing of single agents and whole agent
  teams (R5, R7), including the team record planned after M3 (D36);
- swarm and team coordination: DM, groups, task lists, delegation (R6);
- shared places: the scratch store, message boards and project data in
  public and private groups (the R9 primitives);
- agent-opened views (R10), onboarding (R11) and self-maintenance (R12);
- efficiency (goal E). Every ADR states its cost under the efficiency rules
  (E-D15). Budgets become release criteria through their own ADR (E-D1).

Core work follows the W4 order in the digest (§7; D21, D36), one R at a
time.

**Out of scope:** providing, hosting or running AI agents; MCP tool
semantics; A2A task semantics beyond serving a card; and a global DHT for
user data (ADR 0006) or a central registry, apart from the compiled-in
release key.

### 4. Parked: lower priority, not in scope now

Parked means: shipped code stays and gets bug and security fixes only. No
new slices, flags, routes or protocol versions start. Paused branches stay
paused. Issues carry the `deferred` label and are not closed as rejected.

- **R8 media calling:** ADR 0042, ADR 0073 and #892.
  - Release builds do not enable the `voice` feature. The release change in
    ADR 0073 decision 3 is not made while R8 is parked.
  - The `/calls` signalling lifecycle (ADR 0073 slice 1) stays as shipped.
    It is labelled experimental, carries no media and gets no new gate
    (D09).
- **The R9 rich-text notes merge path:** ADR 0075 decisions 1–3 (this
  includes the Wiki move to notes) and its note deep link, ADR 0081,
  ADR 0082, #965, #1029 and PR #1035.
- **Not parked: the ADR 0075 scratchpad half.** Decisions 4 and 5 (the
  `scratch` store and the rider `scratch` scope) and the `#/scratch` deep
  link are core. ADR 0103 (prov.) will re-specify and supersede them as a
  sealed scratch store with rider and grant scope (A5, #1094). New scratch
  work starts from ADR 0103.

### 5. Placement rule

- A feature that needs no new wire semantics (for example the calls
  lifecycle, a notes UI or GUI show) may ship inside `x0xd` as a default-off
  reference application.
- New protocol surface needs an ADR that names an R or goal E.
- This rule does not change the defaults of an Accepted ADR. A change to
  ADR 0083's remote-show default still needs a superseding ADR (D28).

### 6. ADR 0072 re-tiered

ADR 0072 stays in force. This ADR changes how it is read in three ways.

1. **Four tiers:** core and out of scope (§3), parked (§4), and frozen.
   Frozen keeps ADR 0072's meaning: shipped behaviour is kept, with bug and
   security fixes only. A frozen *mechanism* serves no requirement now. A
   parked *requirement* is valid, but it waits.
2. **Rule 5 (the requirement rule)** accepts R1–R12 and goal E. ADR 0096
   adds R12. An ADR that serves only a parked requirement is declined while
   the park holds. Fixes to shipped behaviour stay admissible.
3. **Lifting a park** needs a new ADR, as rule 6 does for a freeze. It names
   the parked requirement and shows that the core is efficient and proven
   (open question 2).

ADR 0072's frozen list stands as later rulings change it. The README status
overlay records those changes.

## Consequences

### Positive

- One test decides "is this core?", and reviewers can apply it.
- The positioning matches what x0x ships and what its users need, and
  effort goes first to shared places, team sharing and efficiency.
- Nothing shipped is removed. Parked code stays safe through fixes.

### Negative / Trade-offs

- Calls with media do not ship. People who want calls use another tool.
- Concurrent Wiki edits can still be lost, the defect ADR 0075 set out to
  fix. Agents use the scratch store or KV for shared working state.
- Paused notes branches drift from `main`, so un-parking costs rework.
- x0x no longer claims to be "just transport", so the narrow standards
  message is weaker.

### Neutral / Operational

- The README status overlay records the parks (ADR 0087 rule 8).
- The `/calls` routes stay in the endpoint registry and the CLI.

## Validation

- **Review check:** a new ADR names one of R1–R12 or goal E, or it is a fix
  to shipped behaviour. Otherwise it is sent back.
- **Review check:** a PR that adds a feature to a parked mechanism cites an
  un-parking ADR, or it is declined.
- **Release check:** `release.yml` builds `x0xd` and `x0x` without the
  `voice` feature while R8 is parked. Any doc that describes `/calls` says
  it is experimental and carries no media.
- **Tracker check:** #892, #965 and #1029 carry `deferred`. PR #1035 stays
  unmerged while the notes path is parked.
- **Revisit** when goal A's exit test passes, when the first goal E budgets
  are met, or when David asks to un-park R8 or the notes path.

## Open questions for David

1. **Internet-Draft (#113).** Submit the candidate, keep it as a reference,
   or drop it? This draft treats it as not core.
2. **What lifts a park?** This draft proposes a new ADR after goal A's exit
   test passes and the v0.47 goal E targets are met (E-D2). Or is your
   ruling alone enough?
3. **Goal E has no R-number.** Keep "goal E" (this draft), or add R13?
4. **Team sharing.** Keep it under R5 and R7 (this draft), or give it an R?
5. **`/calls`.** Keep the lifecycle routes in default builds while R8 is
   parked (this draft, per D09), or put them behind a default-off flag at
   the next minor release?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

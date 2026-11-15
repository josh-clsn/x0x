# T-self-evidence-lookup: a node proves its own agent to the machine that asks

- **Status:** Proposed (fork tail, self-lookup lane)
- **Target slot:** A03
- **Date:** 2026-11-15
- **Decision owner:** Josh (fork design approved 2026-11-14)
- **Upstream:** none. Amends ADR 0089 §6 and ADR 0115 §1 in the fork only.
- **Drop at:** when upstream ships a stranger-reachable own-evidence answer. Nothing persists, so no migration.

## Context

A node learns an agent's machine from its announcement or from ADR 0089 evidence. Announcements leave every gossip cache after 60 s, and ADR 0089 Hello and Lookup reach only relationship peers. So a node that starts after a device announced cannot raw-send to it until the next heartbeat, or ever while the device is latched, even right after a raw frame from it. ADR 0089 §6 says a stranger's Hello refreshes in-memory caches; the code only captures it. Hello is unchanged.

## Decision

**Responder (ADR 0089 §6).** A relationship requester is served as before. Otherwise a node serves a Lookup for its own local agent when its agent, its machine, their binding and the requesting machine are not revoked, and the mesh-off latch is not set, or its agent raw-sent to that machine in the last 15 min. A send counts once it resolves to the machine, before transmission. The answer carries the user id and the owner certificate only when the heartbeat would (user-identity consent). One minted answer serves for 60 s.

**EvidenceV1 admission.** A discovered machine with Unknown trust may open EvidenceV1 only while this node's agent raw-sent to it in the last 15 min. Blocked, pinned-machine mismatch, revocation, expiry, ADR 0043 pairing and authority confirmation still deny. It uses the pre-identity prefix pool (32, 2 per machine) and the stranger allocation pool. Any other protocol on that admission is dropped.

**Requester.** Only a Lookup started by a raw frame, or by a send waiting on one, also asks the hinted, connected claimants for their own agent: the frame's machine first, at most three, none revoked, one in flight and one per 2 s per claimant. An answer must name the machine it came over and pass the freshness and digest checks. A relationship peer's answer is stored as before.

**Authority (ADR 0115 §1).** A stranger's verified answer is mutual evidence for the transport machine and a new writer of the authenticated-binding store. After the listener's gates and move watermarks, it fills a missing binding or refreshes the same pairing, never moves the agent off a machine an authority store names, and ranks by the agent-signed advert time. It writes in memory only, with no certificate event, never to a file.

**Send.** A raw send that finds no machine waits at most 1.5 s for that Lookup, then reads authority again.

## Consequences

A stranger learns what the heartbeat publishes. A latched node answers only machines it wrote to. A former machine can prove a binding only where none exists, within the ADR 0089 §3 replay window. Existing budgets bound each path. There is no new message and no global traffic.

## Validation

A late node replies raw within 2 s. A wrong-machine answer, or one that would move a binding, writes nothing. An unconsented node discloses no owner. The latch closes the public rule. Admission closes after 15 min. A flood from one claimant costs one Lookup. Revocation refuses at each step.

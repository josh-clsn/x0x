# T-self-evidence-lookup: a node proves its own agent to the machine that asks

- **Status:** Proposed (fork tail, self-lookup lane)
- **Target slot:** A03
- **Date:** 2026-11-15
- **Decision owner:** Josh (fork design approved 2026-11-14)
- **Upstream:** none; amends ADR 0089 §6 and 0115 §1 in the fork.
- **Drop at:** when upstream ships a stranger-reachable own-evidence answer.

## Context

Announcements leave gossip caches after 60 s, and ADR 0089 Hello and Lookup reach only relationship peers. So a node starting after a device announced cannot raw-send to it until the next heartbeat, or ever while it is latched, even right after its raw frame. ADR 0089 §6 says a stranger's Hello refreshes caches; the code only captures it, unchanged here.

## Decision

**Responder (ADR 0089 §6).** A relationship requester is served as before. Otherwise a node serves a Lookup for its own local agent when its agent, its machine, their binding and the requesting machine are not revoked, and the mesh-off latch is not set, or its agent raw-sent to that machine in the last 15 min. A send counts once it resolves to the machine, before transmission. The answer names the owner only when the heartbeat would (user-identity consent). One mint serves 60 s.

**EvidenceV1 admission.** A discovered machine with Unknown trust may open EvidenceV1 only while this node's agent raw-sent to it in the last 15 min. Blocked, pin mismatch, revocation, expiry, ADR 0043 pairing and authority confirmation still deny. It uses the pre-identity prefix pool (32, 2 per machine) and the stranger allocation pool. Any other protocol on that admission is dropped. Approved by Josh on 2026-11-15.

**Requester.** Only a Lookup started by a raw frame, or by a send waiting on one, also asks hinted, connected claimants for their own agent: the frame's machine first, at most three, none revoked. Each claimant gets one in flight, one start per 2 s and its own 30 s cooldown per agent. The frame's machine may use a 2-slot reserve above the aggregate cap. Hints are capped per machine, evicted from the largest holder. The share-grant gate's Lookup keeps its hint but uses relationship routes only. An answer must name the machine it came over and pass freshness and digest checks.

**Authority (ADR 0115 §1).** A stranger's verified answer, mutual evidence for the transport machine, newly writes the authenticated-binding store. After the listener's gates and move watermarks it only fills a missing binding or refreshes the same pairing, ranked by the agent-signed advert time. It is held in memory only, with no certificate event. Such a binding does not satisfy share-grant access.

**Send.** A raw send that finds no machine waits at most 1.5 s when a connected claimant has a self-capable Lookup in flight or a route not cooling. Then it reads the registry, a newly landed binding, and stored evidence.

## Consequences

A stranger learns what the heartbeat publishes. A former machine can prove a binding only where none exists, within the ADR 0089 §3 replay window. Budgets bound each path; no new message, no global traffic. Residual, as before this record: four connected strangers stalling replies (two holding the stranger pool, two the reserve), about 127 single-hint machines evicting the frame's hint, or an in-flight Sybil Lookup can delay recovery until the device's next heartbeat.

## Validation

A late node replies raw within 2 s. Wrong-machine or binding-moving answers write nothing. An unconsented node discloses no owner. Admission closes after 15 min. Three Sybil claimants, four held stranger leases and 16 x 8 hint claims each still let the frame's machine recover. Revocation refuses everywhere.

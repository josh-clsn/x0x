# T-self-evidence-lookup: a node proves its own agent to the machine that asks

- **Status:** Proposed
- **Target slot:** A03
- **Date:** 2026-11-14
- **Decision owners:** David Irvine
- **Related:** ADR 0089 §6 (EvidenceV1 Lookup), ADR 0115 §1 (authority stores), ADR 0093 bit 2

## Context

A node learns which machine hosts an agent from its announcement or from ADR 0089 evidence. Announcements leave every gossip cache after 60 s. ADR 0089 Hello and Lookup go only to relationship peers. A direct-message partner is often an x0x stranger.

So a node that starts after a device announced cannot raw-send to it until the next heartbeat, up to 600 s later, or ever while the device is latched. This holds even when the device just sent a raw frame over a live, transport-authenticated connection.

ADR 0089 §6 says a stranger's Hello refreshes the in-memory caches. The code only captures it for later pairing. This record does not change Hello.

## Decision

**Responder.** This amends the ADR 0089 §6 responder authorization. A node also serves a Lookup when all of these are true:
- the target is this node's own local agent;
- this node's agent, its machine, their binding and the requesting machine are not revoked;
- this node announces publicly now (the mesh-off latch is not set), or this node's agent raw-sent to the requesting machine in the last 15 min.

The answer is this node's own announcement and advert. One minted answer serves every ask for up to 60 s while the certificate pair and capabilities stay the same. For any other target, an unrelated machine still gets `NotFound`.

**Requester.** When no eligible peer names the target, the requester also asks the machines that sent a raw frame claiming the target and are connected now. It asks no other machine on this path, at most three, newest first, and none that is revoked. Each answer must name the machine it came over, and pass the target, freshness and certificate digest checks. A relationship peer's answer is stored as before. A stranger's answer is held in memory only, never written to the evidence file or any other file.

**Authority.** ADR 0115 §1 names the writers of the authenticated-binding store. This adds one: verified self-evidence, a machine-signed announcement and an agent-signed advert that both name the transport-authenticated machine. It is mutual evidence for that machine. After the identity listener's trust, revocation, pairing and expiry gates, it writes what a class A announcement writes in memory: the binding, the discovery entry, the capability advert and the registry entry.

**Send.** When the recipient's claimed machine is connected, a raw send that finds no machine waits at most 1.5 s for that Lookup. Then it reads authority again.

## Consequences

A stranger learns only what a public node already broadcasts. A quiet node answers only machines that it wrote to. A hostile machine can prove only an agent that signed an advert naming that machine in the last 15 min. That is the ADR 0089 §3 replay residual. Existing Lookup budgets bound each path: one Lookup per machine per 2 s, two streams per machine, the byte rates, 32 verifies per second and the stranger allocation pool. There is no new message and no global traffic.

## Validation

A late node replies raw within 2 s with no new publish. A wrong-machine answer is refused and writes nothing. Another target from an unrelated machine gets `NotFound`. A latched node answers only a machine it wrote to. A stranger's evidence is gone after a restart. Two asks in 60 s cost one signing. With no answer, the send returns after about 1.5 s. Revocation refuses at each step.

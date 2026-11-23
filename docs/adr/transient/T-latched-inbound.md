# T-latched-inbound: a latched node answers no inbound connection attempt

- **Status:** Proposed (fork tail, beta-inbound lane).
- **Date:** 2026-11-23
- **Target slot:** A06
- **Upstream:** none filed; the ant-quic half is a carried patch.
- **Drop at:** when upstream ant-quic can leave inbound attempts unanswered and upstream x0x quiets a latched node the same way.

## Context

The train-1123 phone drills found a loop on a latched phone. A burst used a seed as its hole-punch introducer, so the seed learned a live address for the phone. When the burst closed the introducer link, the seed's proactive reconnect redialled the phone. The phone finished each PQ handshake (about 7 KB) and then closed the link. The seed waited out its cooldown and tried again. The phone's replies kept the carrier NAT mapping open, so the loop went on outside every burst.

An Initial packet carries only its source address. The peer is known only after the handshake. While latched, the accept loop already closed every inbound link, leased or not. So no burst link was ever an inbound one: a burst keeps the links it dials, and a hole punch's link is this node's own half.

Three smaller faults were in the same run. A leased connect kept stepping after its budget was spent, and the latch refused the step as `manual`. A contact's connect kept dialling stale addresses after the phone had linked to it. A meshed phone behind a symmetric NAT set up a proactive MASQUE relay through a seed.

## Decision

- **ant-quic.** `set_inbound_connections_allowed(false)` drops the first packet of each new inbound attempt before its Initial keys are derived. No handshake state is made and no packet goes back: no handshake, close, retry or version negotiation. Connections that are up, and this endpoint's own connects, are not changed.
- **x0x latch.** The latch turns inbound attempts off, bursts and leases included, and the join turns them on. A daemon that starts latched has them off before it listens. `relay_client` shows the switch and two counters: packets ignored and handshakes answered.
- **Spent budget.** A leased connect takes no step after its budget and answers `Unreachable`. Each step's dial carries its own origin in the refusal log.
- **Late link.** A connect that is still dialling watches for a link to its target machine. When one comes up by another path, the connect gives its own step 0.5 s, then answers `AlreadyConnected`. As in the first check, only a machine that an authority store confirms counts.
- **Proactive relay.** `relay_service_disabled` (set on phones) keeps proactive relay off, meshed or latched.

## Consequences

- A redial of a latched node times out at the dialler, and no reply refreshes the NAT mapping. The node still receives the redial packets while the mapping lives.
- An attempt whose first packet came before the latch is still answered. Then the accept loop closes it, as before.
- In a punch, the target's half is ignored. The target's packets still open its own NAT, so this node's half gets through. In the old code, a target half that won the race was closed by the accept loop.
- A meshed phone behind a symmetric NAT is reachable only by peers that can hole-punch to it, and through the Noetic relay. Its own relay fallback dials are not changed.

## Tests

- ant-quic: `an_endpoint_ignoring_inbound_sends_nothing_back`.
- x0x: `a_latched_node_answers_no_inbound_connection_attempt`, `a_seeds_redials_cost_the_latched_phone_no_handshake`, `a_spent_leased_connect_makes_no_further_dial`, `a_connect_takes_the_link_its_target_opened_meanwhile`, `a_node_with_relay_service_disabled_never_holds_a_proactive_relay`.

# T-latched-inbound: a latched node answers no inbound attempt, and a phone never sends through a public node unless its relay is down

- **Status:** Proposed (fork tail, beta-inbound lane).
- **Date:** 2026-11-23
- **Target slot:** A06
- **Upstream:** none filed; the ant-quic half is a carried patch.
- **Drop at:** when upstream ant-quic can leave inbound attempts unanswered and abandon handshakes, and upstream x0x quiets a latched node the same way.

## Context

In train-1123 a seed redialled a latched phone after a burst used it as introducer. The phone finished each PQ handshake (about 7 KB), then closed the link, and its replies kept the carrier NAT mapping open. An Initial names no peer, and the accept loop already closed every inbound link while latched, leased or not.

The drill harness found a second leak: a handshake the phone answered just before the latch was never Live, so nothing closed it, and it re-sent its padded flight for about 30 s.

A meshed phone could also relay data through a seed: proactive relay on a symmetric NAT, and the relay fallback of its own connects.

## Decision

- **ant-quic.** `set_inbound_connections_allowed(false)` drops each new attempt's first packet before any handshake work. Nothing goes back: no handshake, close, Retry, version negotiation or stateless reset. A queued attempt is ignored too. `abandon_handshakes()` kills every connection still in its handshake and sends nothing more.
- **Latch.** The latch turns inbound off, leases or not. Every latch call abandons the handshakes in flight.
- **Relay rule (Josh, 2026-11-23).** A node with `relay_service_disabled` (a phone) never sets up or advertises a proactive relay. Its own connects use the relay fallback only while the embedder says its relay is down (`PUT /mesh/relay-fallback`). Latched wins. Turning it off leaves a live relayed connection alone. Desktops are not affected.
- **Switch syncs.** A meshed sync no longer closes client relay sessions. Only the latch or a real proactive-relay change does.
- **Connector.** A leased connect takes no step after its budget. A connect that takes a link its target opened stops its connector at the next step, so a probe's stray is still closed.

## Consequences

- A redial of a latched node times out, and no reply refreshes the mapping.
- In a punch the target's half is ignored. Its packets still open the target's NAT, so this node's half gets through.
- A meshed phone behind a symmetric NAT is reachable only by peers that can punch to it, and through the Noetic relay. While its relay is up, its connects that fail direct and punch answer `Unreachable`.
- The route count is 214.

## Tests

- ant-quic: `an_endpoint_ignoring_inbound_sends_nothing_back`, `an_endpoint_ignoring_inbound_sends_no_stateless_reset`, `an_abandoned_inbound_handshake_sends_nothing_more`.
- x0x: `a_latched_node_answers_no_inbound_connection_attempt`, `a_seeds_redials_cost_the_latched_phone_no_handshake`, `the_latch_drops_an_inbound_handshake_in_flight`, `an_opt_out_node_relays_only_while_its_embedder_says_its_relay_is_down`, `a_switch_sync_never_cuts_a_live_relay_fallback_session`, `a_spent_leased_connect_makes_no_further_dial`, `a_connect_takes_the_link_its_target_opened_meanwhile`, `a_connect_taking_a_new_link_still_closes_its_probe_stray`, `a_node_with_relay_service_disabled_never_holds_a_proactive_relay`.

# T-checkin-reach: a check-in reaches a contact behind a home router, and a latched node dials only under a lease

- **Status:** Proposed (fork tail, beta-checkins lane).
- **Date:** 2026-11-22
- **Target slot:** A06
- **Upstream:** none filed. The ant-quic half is a carried patch on `josh-clsn/ant-quic`.
- **Drop at:** when upstream ant-quic bounds a punch-capable dial's direct pre-pass and x0x gains a per-dial budget of its own.

## Context

On 2026-11-21 a phone on LTE, latched with the relay down, sent a check-in burst to a desktop behind a home NAT. The burst logged one direct dial to the desktop's address and nothing more: no introducer, no punch, 0 of 2 targets reached. Three causes:

1. Under `CoordinatorPolicy::Introducer`, ant-quic tried every candidate address directly first, each for 30 s. x0x ended each connector step after 3 s or 8 s, so the ladder never reached the introducer.
2. A target's introducers came only from its live discovery entry. The engine could not read them, so it could not keep them for a later burst.
3. The desktop announced no coordinators. ant-quic's `can_receive_direct` is true for any fresh inbound direct link, LAN or loopback included, and for a link a peer opened through the NAT mapping the desktop opened first.

Two leaks were also open from 2026-11-19: (a) a latched daemon opened unleased links for a raw send, and (b) links that came up just after the burst cap tripped lived about 5 s.

## Decision

- **ant-quic.** Under `Introducer`, the direct pre-pass shares one 2 s budget across its candidates. Other policies keep their timings. `IntroducerStats` gains `punch_successes` and `punch_failures`.
- **One budget.** A leased connect runs every step inside one 12 s budget (`LEASED_DIAL_BUDGET`). A punch-capable step runs to the end of the budget. An address-only probe keeps its own slice inside the budget. A LAN probe dials by address only, so it cannot spend the target's one introducer.
- **Coordinators in and out.** Discovery entries carry `coordinators`. A leased connect takes `introducers` (at most 4 socket addresses) and adds them after the announced ones. The embedder is trusted: the format is checked and the list is bounded. Nothing changes on the wire.
- **Announcement.** A node announces its coordinators unless the operator declared it publicly reachable (the relay opt-in). A router's port mapping does not count: behind a second NAT it reaches nobody.
- **Latched dials (a).** While latched, the three `NetworkNode` dial seams refuse a new connection unless a leased connect of the current demand-lease generation is in flight (a task-local scope), the peer holds a live lease, or the peer is already connected. A refusal is `NetworkError::LatchedNoLease`, which a send reports as `no_connectivity`.
- **Burst end (b).** Every lease clear (a latch call or a cap trip) cancels a token that a leased connect selects on, so the connect stops and drops its handshakes. A tripped cap counts link bytes on every tick before it closes links.

## Consequences

- A latched phone touches no public node except one introducer per target per burst, and only after 4 s of direct attempts.
- A latch call during a leased connect answers `Unreachable`. A trip answers 409 `burst_cap_reached`.
- A phone's unleased dial while latched now fails. This includes `/machines/connect`, reconnect, repair and peer-evidence dials.
- If the announcement rule is wrong, a public node without a port mapping announces up to 8 coordinator ids. A dialler uses them only after its direct attempts fail.
- Not covered: ant-quic's mDNS auto-connect, and a punch that ant-quic completes after its connect future is dropped and that never reaches P2pEndpoint's peer table.

## Tests

- ant-quic: `a_burst_reaches_a_silent_target_through_the_punch_quickly`, plus punch-counter checks in `a_burst_uses_one_introducer_per_target_and_hangs_up`.
- x0x: `a_leased_connect_shares_one_budget_across_its_steps`, `a_burst_reaches_a_desktop_behind_a_home_nat_through_an_introducer`, `an_embedder_can_read_and_hand_back_a_targets_coordinators`, `a_natted_desktop_that_reads_as_direct_still_announces_coordinators`, `connect_introducers_are_checked_and_bounded`, `a_latched_node_dials_only_under_a_lease`, `a_latched_raw_send_without_a_lease_dials_nothing`, `a_leased_connect_in_flight_stops_when_the_cap_trips`, `a_link_up_after_the_trip_is_closed_and_counted`, `introducer_dials_and_punch_outcomes_are_reported`.

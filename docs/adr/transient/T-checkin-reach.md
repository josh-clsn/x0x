# T-checkin-reach: a check-in reaches a contact behind a home router, and a latched node dials only under a lease

- **Status:** Proposed (fork tail, beta-checkins lane).
- **Date:** 2026-11-22
- **Target slot:** A06
- **Upstream:** none filed. The ant-quic half is a carried patch on `josh-clsn/ant-quic`.
- **Drop at:** when upstream ant-quic bounds a burst's direct and introducer dials and x0x gains a per-dial budget of its own.

## Context

On 2026-11-21 a latched phone on LTE, with the relay down, sent a check-in burst to a desktop behind a home NAT. It logged one direct dial, no introducer and no punch. Three causes:

1. Under `CoordinatorPolicy::Introducer`, ant-quic dialled each candidate directly for 30 s before the ladder. x0x cut each step after 3 s or 8 s.
2. A target's introducers came only from its live discovery entry, which the engine could not read.
3. The desktop announced no coordinators. ant-quic's `can_receive_direct` is true for any fresh inbound direct link, and `port_mapping_active` only says the nearest router accepted a mapping.

Two leaks were open too: (a) a latched daemon opened unleased links, and (b) links outlived a tripped burst cap.

## Decision

- **ant-quic.** Under `Introducer`, the direct pre-pass shares 2 s. An introducer dial gets at most 3 s. When it fails, the target's next introducer is tried. A dial counts when it starts, and an unresolved round counts as a failure.
- **One budget.** A leased connect runs every step inside 12 s (`LEASED_DIAL_BUDGET`). The whole connect ends 0.5 s after that. A LAN probe dials by address only.
- **Coordinators in and out.** Discovery entries carry `coordinators`. A leased connect takes up to 4 `introducers`, for that dial only.
- **Announcement.** A node announces its coordinators unless the operator opted in as public. Relay candidates keep the old direct-inbound rule.
- **Latched dials.** While latched, the dial seams refuse a new connection unless a leased connect of the current generation is in flight, the peer holds a live lease, or it is already connected. Every dial let through ends when its generation ends (a latch call or a trip). A link that comes up with no lease and no burst dial in flight is closed at once. When a leased connect ends, every unleased link is closed.
- **Cap.** A tripped cap keeps counting link bytes before it closes links.

## Consequences

- A latched phone touches a public node only as a target's introducer, after the 2 s pre-pass and the adaptive direct stage (about 2 s at the default RTT).
- A latch call during a leased connect answers `Unreachable`. A trip answers 409.
- Every unleased dial while latched fails: `/machines/connect`, reconnect, repair and evidence dials.
- **Known limit.** `is_coordinator` still trusts Global-scope inbound evidence (#398). A NAT'd desktop that a peer reached through its own mapping can claim it, and a phone may then pick it as an introducer. The 3 s introducer dial and the fallback bound the cost.
- mDNS auto-connect still dials beneath x0x. The latch guard closes such a link when it comes up.

## Tests

- ant-quic: `a_burst_reaches_a_silent_target_through_the_punch_quickly`, `a_stale_introducer_fails_fast_and_the_next_one_punches`, `a_dropped_burst_still_counts_its_introducer_attempt`.
- x0x: `a_burst_reaches_a_desktop_behind_a_home_nat_through_an_introducer`, `a_burst_reaches_a_contact_known_only_by_evidence_through_a_handed_back_introducer`, `a_leased_connect_runs_steps_3_and_5_on_its_budget`, `a_leased_connect_never_outlives_its_budget`, `a_latched_node_dials_only_under_a_lease`, `a_latch_call_ends_a_dial_its_lease_let_through`, `a_latched_node_closes_a_link_no_burst_booked`, `a_latched_connect_that_keeps_no_lease_leaves_no_link`, `a_link_up_after_the_trip_is_closed_and_counted`, `a_leased_connect_in_flight_stops_when_the_cap_trips`, `a_natted_desktop_that_reads_as_direct_still_announces_coordinators`.

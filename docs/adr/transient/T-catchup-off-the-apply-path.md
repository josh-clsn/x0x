# T-catchup-off-the-apply-path: a catch-up never blocks an apply, and the catch-up listener answers side by side

- **Status:** Proposed (fork tail, survivor re-key A12).
- **Date:** 2026-10-25
- **Base:** `survivor-rekey` at `042f243f`
- **Upstream:** none filed. Upstream's apply path asks for a gap catch-up inline in the same way.
- **Drop at:** when upstream moves its gap catch-up off the apply path and answers catch-up requests concurrently. Take theirs and delete `gap_catchup.rs` and `catchup_serve.rs`. Nothing changes on the wire, so no migration is needed.

## Context

A Noetic leaf agent's drill showed group messages stalling behind membership applies. Three causes:

- **The apply waited on the network.** An apply that finds a TreeKEM membership event ahead of its head parks the event in `treekem_pending_events` and asks peers for the commits in between (`queue_treekem_membership_event`). It sent those asks inline, one peer after another, while it held the room's membership lock. A direct message to a peer that does not answer costs one send's timeout: 8 s per attempt, an 8 s backoff, and a second 8 s attempt, so 24 s. The asks go to up to four peers, so one event could hold the room's applies for about a minute and a half.
- **The catch-up listener answered one request at a time.** Each answer ends in a direct send, so a requester that went away held every other requester behind its 24 s. The listener's queue drops its oldest messages when it is full, so requests could be lost behind it.
- **A member that a direct add or an approved join request seats got its Welcome at +0 and +8 s only.** It has no join result to poll, unlike an invite joiner. A10 owes the re-key to every other member, but not to the member that was seated.

## Decision

- **Parked first, asked later.** `queue_treekem_membership_event` parks the event exactly as before and then hands the asks to `gap_catchup::spawn`, which never waits. A page that lands before the asks go out still finds the event parked, and `handle_treekem_catchup_response` replays the parked events in commit order after it applies the page, as before. Nothing about ordering, admission or retention changes.
- **One flight per room.** A room has at most one gap catch-up running (`AppState::treekem_gap_catchups`). An event that needs a catch-up while the flight runs adds its peers to the flight, and the flight asks each peer once. The flight sends a batch to all its peers at once, so a silent peer costs only its own timeout. The flight ends when it has nothing left to send. A task that stops early removes the room's entry, so the next gap starts a new flight. The per-peer throttle (`TREEKEM_CATCHUP_THROTTLE`) still applies to each ask.
- **The listener answers side by side.** The listener hands each request to `catchup_serve::dispatch` and reads on. At most 4 answers run at once (`SERVE_SLOTS`). One requester has at most one answer running and at most 8 waiting (`PER_PEER_QUEUE`); a newer request pushes out its oldest waiting one. Slots go out in request order, because tokio's semaphore is fair. At most 256 requesters wait at once (`MAX_WAITING_PEERS`); past that, a request from a new requester is dropped, as an overfull listener queue dropped it before. Each answer is `handle_treekem_catchup_request`, unchanged.
- **Why four slots.** An answer holds one page (one direct message, under `x0x::dm::MAX_PAYLOAD_BYTES`), may sign one head proof, and holds one send for up to its timeout. With four slots, four requesters that went away time out together, and a fifth waits at most one send timeout. Before, it waited behind every request queued ahead of it. Four keeps a phone's catch-up work to a few pages in memory and a few signatures at a time. It matches the re-key obligation worker's sends in flight (`rekey_obligations::MAX_IN_FLIGHT`).
- **A seated member keeps the bounded schedule.** The direct add and the approval put the member they seat on `spawn_group_control_event_redelivery` (6, 15, 30 and 60 s), with any survivor the obligations refused, as the returning-member re-key already did.

## Consequences

- An apply that needs a catch-up returns at once and frees the room's membership lock. The catch-up's cost moves to one task per room.
- A requester that floods the listener holds one answer slot. A dead requester holds one slot for one send timeout.
- Responses are still handled one at a time on the listener. A truncated page's follow-up ask (`request_treekem_catchup_page`) is still sent inline there, so a silent responder can hold that reader for one send timeout. Tests read the follow-up synchronously, and a response must apply in order with the pages before it, so this was left.
- A member that a direct add or an approval seats is still not owed the add. After the last resend at +60 s, a member away longer is not sent its Welcome again. A seat obligation, settled by the new member's first signed request at the add's epoch, would close that. It is not built here.
- **Acknowledgement waits on leaf recipients (not changed).** Named-group direct sends ask for the recipient's gossip acknowledgement (`named_group_direct_delivery_config`). A leaf (`leaf_mode`) skips the legacy DM bus, so its v1 acknowledgement goes out once, on the sender's inbox topic, to its eager peers. If that frame lands on a non-forwarding leaf bystander, the bystander refuses it (#380 C0, the x0x#1455 class), and only v2 acknowledgements have a direct hedge. The sender then waits 24 s for an event that arrived. This is traced in the code, not reproduced. A leaf whose mesh rests gives no acknowledgement at all, because the message never arrived. Every such send runs in its own task, and after this change none of them holds an apply, the room's lock or the listener. What remains is a re-key obligation slot held for 24 s, and an obligation whose acknowledgement was lost counts as failed, so it backs off and is sent again rather than waiting the 15 min cap. Delivery is not weakened. A v1 direct hedge on the recipient would remove the wait. That is a DM-layer change to every v1 acknowledgement, so it is left for its own change.

## Tests

`named_groups/tests/catchup_off_apply.rs`, on the survivor fixture and the real routes:

- `an_apply_that_needs_a_catch_up_returns_while_the_peers_are_silent`: S1 gets only the second of two removals while every page request it sends waits forever. The apply returns within 1 s, the event is parked, the owner is asked from the flight, and the page with the first removal then applies both in order.
- `two_gaps_in_one_room_run_one_catch_up`: two later events both need the catch-up while its asks are unanswered, and the throttle window is cleared between them. One flight runs, and it asks the owner once. The page then applies all three in order.
- `the_listener_answers_requests_side_by_side`: five requesters while no answer can finish. Four run at once, and the fifth runs when one frees.
- `a_flooding_requester_does_not_starve_another`: one requester sends 20 requests, then another sends one. The flooder holds one slot, and the other is answered beside it.
- `a_dispatched_answer_is_the_direct_answer`: the page the listener path sends is byte for byte the page a direct call sends.
- `a_member_an_add_seats_keeps_the_blind_schedule`: a direct add and an approval each put the member they seat on the resend schedule.

Unit tests: `gap_catchup` (a second gap joins the flight, each peer is asked once, a gap with no peer starts nothing) and `catchup_serve` (a flooder keeps only its newest 8 waiting, requesters past the cap are dropped).

Each of the first six fails with its fix reverted: an inline ask (the apply times out), a flight per event (two flights), one slot (one answer at a time), a task per request (the flooder takes all four slots), and the old schedule (no resend for the seated member).

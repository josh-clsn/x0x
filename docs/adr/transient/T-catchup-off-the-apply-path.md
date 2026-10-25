# T-catchup-off-the-apply-path: no catch-up ask blocks an apply or the catch-up listener

- **Status:** Proposed (fork tail, survivor re-key A12, with fix rounds 1 and 2).
- **Date:** 2026-10-25
- **Base:** `survivor-rekey` at `042f243f`
- **Upstream:** none filed. Upstream's apply path asks for a gap catch-up inline in the same way, and its listener answers serially.
- **Drop at:** when upstream moves its catch-up asks off the apply and listener paths and answers catch-up requests concurrently for proven requesters. Take theirs and delete `gap_catchup.rs` and `catchup_serve.rs`. Nothing changes on the wire, so no migration is needed.

## Context

A Noetic leaf agent's drill showed group messages stalling behind membership applies. There were four causes.

- **The apply waited on the network.** An apply that finds a TreeKEM membership event ahead of its head parks the event in `treekem_pending_events`, then asks peers for the commits in between (`queue_treekem_membership_event`).
  - It sent those asks inline, one peer after another, while it held the room's membership lock.
  - A direct message to a peer that does not answer costs one send's timeout: 8 s per attempt, an 8 s backoff and a second attempt, so 24 s.
  - The asks go to up to four peers, so one event could hold the room's applies for about a minute and a half.
- **The catch-up listener answered one request at a time.** Each answer ends in a direct send, so a requester that went away held every other requester behind its 24 s. The listener's queue drops its oldest messages when it is full, so requests could be lost behind it.
- **The listener also waited on its own asks.** A catch-up page carries one event (`TREEKEM_CATCHUP_RESPONSE_EVENT_CAP = 1`), so every page of a catch-up but the last is truncated. The listener sent the follow-up ask for the next page inline, so a silent responder held the whole listener, request dispatch included, for 24 s per page.
- **A member that a direct add or an approved join request seats got its Welcome at +0 and +8 s only.** It has no join result to poll, unlike an invite joiner. Noetic's sibling admission is such a direct add.

## Decision

- **Parked first, asked off the path.**
  - `queue_treekem_membership_event` parks the event exactly as before.
  - It then registers each ask before it returns: the throttle is stamped, and the ask joins the room's flight (`AppState::treekem_gap_catchups`), keyed by the peer and the head (signed revision, TreeKEM epoch) it is asked from.
  - Each ask is sent in its own task under a 30 s outer timeout (`ASK_TIMEOUT`), so a silent peer delays no other ask.
  - Nothing on the apply path waits on the network.
  - A page that lands before an ask goes out still finds the event parked.
- **One ask per (peer, head).**
  - An ask that is still in flight from the same head is skipped, even after the 5 s throttle window, so two gaps at one head make one ask per peer.
  - Once the head moves, a later gap asks again at once, even while an older ask waits on a silent peer.
  - A peer that only a later event names is asked at once.
- **Replay.** Parked events replay in commit order after a page is applied (`handle_treekem_catchup_response`), as before. Since fix round 1 they also replay after a live apply lands a membership commit (`replay_parked_after_live_apply`), so a commit that arrives by gossip or a direct push frees its parked successors without waiting for a page. The replay re-applies each event with every check. Since fix round 2 (N-5), a replay pass that moved the head while events stayed parked runs again, up to 8 passes: another replay may have requeued an event while this one applied its predecessor. Order is still the frontier gate's.
- **Follow-up asks off the listener.** A truncated page's follow-up ask runs in its own task under `ASK_TIMEOUT`, with at most one in flight per (room, peer, head after the page). So a page that moved the head always asks for the next one, even while the ask for it is still waiting on its acknowledgement (fix round 2, N-1). A page that moved nothing asks nothing more. Pages are still applied on the listener, in arrival order.
- **The listener answers side by side, for proven requesters only.**
  - The listener hands each message to `catchup_serve::on_direct_message`. A request goes to `dispatch`, which never waits.
  - **Who gets a queue.** A request queues under the sender if the transport verified that sender. Otherwise it queues under the requester its signature proves: the A5 page-request signature, or the #398 member-keyed one, checked at admission. A request that proves no requester is dropped there; the answer would refuse it anyway. So a peer that claims a member's id cannot touch that member's queue.
  - **Rate before the check (fix round 2, N-3).** An unverified request is checked only within its QUIC-authenticated machine's allowance: 16 at once, refilling at 8 a second. A flood cannot spend this daemon's CPU on signature checks.
  - **On the roster (N-4).** The proven requester must be an active member of the room, or a joiner with no roster entry that the room's cached add names, as the answer requires. A self-made identity gets no waiting space.
  - **Fresher replaces (N-2).** A waiting request is replaced only by one at least as fresh: a page from the same or a later (epoch, revision), a challenge with the same or a later counter. A replay of a member's older signed request is dropped, so a past recipient of its requests cannot displace its fresh one.
  - **Bounds:**
    - at most 4 answers at once (`SERVE_SLOTS`);
    - one answer running per requester;
    - at most one request waiting per (room, kind): a page, a head challenge, or a member-keyed fetch for one member. A newer request of the same kind for the same room takes the waiting one's place;
    - at most 8 rooms or kinds waiting per requester (`PER_PEER_QUEUE`). Past that, a request for a further room is dropped, never another room's only request;
    - at most 256 requesters (`MAX_WAITING_PEERS`) and 8 MiB of requests (`MAX_WAITING_BYTES`) waiting.
  - Slots go out in request order, because tokio's semaphore is fair.
  - Each answer is `handle_treekem_catchup_request`, unchanged.
- **Why four slots.** An answer holds one page (one direct message, under `x0x::dm::MAX_PAYLOAD_BYTES`), may sign one head proof, and holds one send for up to its timeout.
  - With four slots, four requesters that went away time out together, and a fifth waits at most one send timeout. Before, it waited behind every request queued ahead of it.
  - Four keeps a phone's catch-up work to a few pages in memory and a few signatures at a time.
  - It matches the re-key obligation worker's sends in flight (`rekey_obligations::MAX_IN_FLIGHT`).
- **A seated member gets the resend schedule.** The direct add and the approval put the member they seat on the schedule's direct sends at 6, 15, 30 and 60 s (`spawn_seated_member_resends`), with no room-wide republish: that member is not subscribed to the room's metadata topic yet. A survivor the obligations refused keeps the full schedule with the republish, as before.
- **A counter for v1 acknowledgement waits.** `GET /diagnostics/dm` `stats` reports:
  - `v1_ack_waits` and `v1_ack_wait_ms`: gossip-inbox sends that waited for a v1 recipient acknowledgement, and the time they took;
  - `v1_ack_wait_timeouts` and `v1_ack_wait_timeout_ms`: those that ended without one.

## Consequences

- An apply that needs a catch-up returns at once and frees the room's membership lock. The listener waits on no send.
- A requester that floods the listener holds one answer slot. A requester that went away holds one slot for one send timeout. A forger holds none.
- **A lost v1 acknowledgement still costs about 24 s per catch-up event** (not changed here).
  - Named-group direct sends ask for the recipient's gossip acknowledgement (`named_group_direct_delivery_config`).
  - A leaf (`leaf_mode`) skips the legacy DM bus, so its v1 acknowledgement goes out once, on the sender's inbox topic, to its eager peers. If that frame lands on a non-forwarding leaf bystander, the bystander refuses it (#380 C0, the x0x#1455 class). Only v2 acknowledgements have a direct hedge.
  - So a send whose message arrived waits 24 s and fails. That is traced in the code, not reproduced.
  - **On the responder:** each page is one event, and an answer holds its requester's one running slot until the send returns. A leaf catching up from a responder whose acknowledgements are lost therefore gets about one event per 24 s.
  - **On the owner:** a re-key obligation send to such a leaf holds one of the worker's 4 slots for 24 s. It counts as failed, so it backs off and is sent again rather than waiting for the 15 min cap. Delivery is not weakened.
  - A leaf whose mesh rests gives no acknowledgement at all, because the message never arrived.
  - The `v1_ack_*` counters measure how often this happens. A14 (`T-v1-ack-direct-hedge.md`) hedges a leaf's v1 acknowledgement on live Direct, and an answer now frees its slot when it hands its send off, so a lost acknowledgement no longer paces a requester.
- A member that a direct add or an approval seats is still not owed the add. After the last resend at +60 s, a member away longer is not sent its Welcome again. A seat obligation closes that; it is a separate change before the version flip.

## Tests

`named_groups/tests/catchup_off_apply.rs`, on the survivor fixture and the real routes:

- `an_apply_that_needs_a_catch_up_returns_while_the_peers_are_silent`: S1 gets only the second of two removals while every page request it sends waits forever.
  - The apply returns within 1 s, the event is parked, and the ask is registered.
  - The page with the first removal then applies both, in order.
- `two_gaps_at_one_head_ask_each_peer_once`: two later events need the catch-up while the asks hang, with the throttle window cleared between them.
  - There is one flight, and the owner is asked once.
  - S2, named only by the second event, is asked at once.
  - All three then apply in order.
- `a_later_gap_asks_the_owner_again_from_the_new_head`: after a page moves the head, a new gap asks the owner from the new head while the old ask still waits.
- `a_live_apply_of_the_missing_commit_replays_the_parked_one`: the missing removal arrives live, not by a page, and the parked one applies after it.
- `catch_up_pages_all_the_way_through_while_follow_ups_wait`: three truncated pages while every follow-up waits on a silent owner. Each page that moved the head asks for the next, S1 reaches the owner's head, a replayed page asks nothing more, and the listener answers a request meanwhile.
- `an_event_parked_during_a_replay_applies_when_the_replay_moves_the_head`: an event parked right after a replay drained the queue applies in that replay's next pass.
- `the_listener_answers_requests_side_by_side`: five requesters while no answer can finish. Four run, every slot is taken, and the fifth runs when one frees.
- `a_flooding_requester_does_not_starve_another`: one requester sends 20 requests, then another sends one. The flooder holds one slot, the other requester is answered, and two slots stay free.
- `a_forger_cannot_push_out_a_survivors_waiting_request`: unsigned claims, other keys' signatures and a replay of the survivor's own older request are dropped, and the survivor's fresh waiting request stays.
- `a_machine_flooding_unverified_requests_is_checked_a_burst_at_most`: 100 unverified requests from one machine get about 16 signature checks; another machine's still gets one.
- `a_requester_off_the_roster_gets_no_place`: a self-signed or transport-verified requester the roster does not hold, and a room this daemon does not hold, get no place.
- `a_dispatched_answer_is_the_direct_answer`: the page the listener path sends is byte for byte the page a direct call sends.
- `a_member_an_add_seats_keeps_the_resend_schedule`: a direct add and an approval each give the seated member the direct-send schedule, with no republishing schedule.

Unit tests:

- `gap_catchup`: one ask per (peer, head); a moved head asks again; the room ends with its last ask.
- `catchup_serve`:
  - a newer request replaces the waiting one for its room, and other rooms stay;
  - a ninth room is refused;
  - the requester and byte caps hold;
  - an unverified, unsigned request proves no one.

Each integration test fails with its fix reverted. The red runs are in the A12 report.

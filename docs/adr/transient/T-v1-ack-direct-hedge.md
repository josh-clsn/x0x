# T-v1-ack-direct-hedge: a leaf's v1 DM acknowledgement also goes on live Direct, and a catch-up answer frees its slot at hand-off

- **Status:** Proposed (fork tail, survivor re-key A14).
- **Date:** 2026-10-25
- **Upstream:** checked at `saorsa-labs/main` `d3b39f18` (2026-10-22). It keeps v1 acknowledgements exactly as they were: the targeted inbox publish, plus the compatibility bus only when the payload came over it (`dm_inbox.rs` "Preserve v1 exactly"). Only v2 (durable) acknowledgements get the C5 Direct hedge (`LiveDirectAckHedge`, #408). This change reuses that hedge as it is.
- **Drop at:** when upstream hedges v1 acknowledgements, or its leaves stop skipping the only other route.

## Context

A leaf (`leaf_mode`) skips the legacy DM bus. Its v1 acknowledgement therefore has one route: a single eager frame on the sender's inbox topic. A non-forwarding leaf bystander refuses that frame (#380 C0, x0x#1455). The sender then waits through:

- an 8 s attempt;
- an 8 s backoff;
- a second 8 s attempt;

and fails after 24 s, even though the message arrived. Every named-group direct send waits on that acknowledgement.

Measured in A12 by the `v1_ack_wait*` counters, the cost shows up in two places:

- **A catch-up responder** held the requester's one answer slot until its send returned. So a leaf catching up from it got about one event per 24 s.
- **The re-key obligation worker** held one of its 4 send slots for 24 s.

## Decision

- **v1 hedge on leaves.**
  - When the inbox skips the legacy bus, a v1 acknowledgement also goes to the same live Direct hedge the durable path uses (`InboxPipeline::v1_direct_hedge`).
  - It is sent in its own task, so the inbox loop never waits on it.
  - The gossip publish is unchanged. A node on the bus keeps v1 exactly as it was.
  - A Direct send-ok is never a receipt. The sender's waiter completes only when the acknowledgement envelope arrives and verifies (`ingest_direct_ack_envelope`, version-agnostic since #563).
- **A catch-up answer frees its slot at hand-off.**
  - `handle_treekem_catchup_request` hands its page, member-keyed and head-proof sends to `catchup_serve::send_answer`, which runs each in its own task.
  - The answer returns, and frees its slot, while the send waits on its acknowledgement.
  - At most 32 sends wait at once (`ANSWER_SENDS`), and 8 to one requester (`ANSWER_SENDS_PER_PEER`). Past either, the answer sends inline, as before, so the bounds hold under a flood.
  - Pages to one requester can now overlap. A page that arrives ahead of its predecessor does not link, so the requester parks it and replays it in order (A12).

- **The key a Direct ACK is checked with.** A Direct ACK envelope is checked only when ADR 0115 authority confirms its sender on the machine the connection came from (`direct_ack_verifying_key`, `identity_authority::confirms`). That is an announced record from a class A or B announcement, the authenticated binding, or an ADR 0089 evidence record for exactly that (agent, machine) pair. A class C announcement writes none of them, so it can never make an ACK verify. Only then is a key taken: the first of these whose agent id derives to the ACK's sender:
  - the discovery entry's `agent_public_key` (a class A or B field);
  - the evidence key;
  - the key that verified the sender's live capability advert.

  The envelope signature is still checked against the chosen key. Anything else is dropped and counted in `direct_ack_dropped_no_key`.
- **The check applies to every Direct ACK, v1 and v2.** It sits on the one Direct ACK receive path, which does not look at the protocol version. An ACK from a pair that authority does not confirm is dropped, and the sender waits for the gossip ACK instead.
- **The v1 hedge is bounded.** It has its own publisher: a queue of 256 jobs (a full queue drops the hedge, and the gossip ACK still goes), 32 sends at once, each under 8 s. Its worker handle is held by the inbox, so `DmInboxService::abort` stops it.
- **The catch-up limiter and sends.**
  - Unverified catch-up requests also share a total of 128 at once, refilling at 64 a second, across all machines.
  - When the per-machine table is full, the machine heard from least recently is forgotten, so a new machine is not refused.
  - A handed-off answer send makes no per-requester entry unless it gets a permit, and runs under a 30 s timeout.
  - The roster check before queuing scans the room's catch-up log, at most 128 events, for a cached-add joiner.

## Consequences

- **The sender verifies a Direct acknowledgement against the recipient's agent key, and only for a pair ADR 0115 authority confirms.** A leaf the sender knows only by its capability advert, with no announcement heard and no ADR 0089 evidence for the pair, has its Direct acknowledgement dropped and counted in `direct_ack_dropped_no_key`. The sender then waits out its gossip ACK budget, as it did before the hedge. The advert names the machine and is signed by the agent, but a replayed or unconsented advert is not authority.
- **Pages to one requester can overlap** (up to 8 sends waiting). A page that arrives ahead of its predecessor is parked and replayed in order, at the cost of extra parked events.
- **The hedge needs a live direct connection** (`LiveDirectAckHedge` checks it). A leaf whose mesh rests still gives no acknowledgement, because the message never arrived. The obligations cover that case.
- **Traffic.** Each v1 acknowledgement from a leaf costs one extra direct frame, about 3-4 KB, when a connection is live.
- **Counters.** `GET /diagnostics/dm` `stats.v1_ack_waits` / `v1_ack_wait_ms` / `v1_ack_wait_timeouts` / `v1_ack_wait_timeout_ms` (A12) show the effect on the sender.

## Tests

- `v1_ack_hedge_tests::a_leaf_v1_ack_reaches_the_sender_over_direct_when_its_gossip_frame_is_lost`: two real leaf Agents on loopback, with the sender knowing the recipient's caps and announced key.
  - The recipient's v1 gossip acknowledgement is dropped (`V1_GOSSIP_ACK_DROPPED_FROM`, test only), as a non-forwarding bystander drops it.
  - The v1 send is acknowledged within 5 s, and the DM arrives.
  - The sender's `v1_ack_waits` rises by one, with no timeout and a short `v1_ack_wait_ms`.
- `dm_inbox::tests::a_leafs_v1_ack_is_hedged_on_direct_without_waiting_for_it`: a hedge that never returns does not hold the acknowledgement publish. A leaf hands the hedge the v1 envelope; a node on the bus does not hedge.
- The end-to-end test has the leaf announce (class A) first, so the pair is confirmed; the ACK is accepted within the 5 s bound.
- `a_direct_ack_from_an_unconfirmed_pair_is_dropped_and_counted`: a real leaf that never announced sends its ACK over Direct. The sender's listener drops it, counts `direct_ack_dropped_no_key`, and the send fails within its budget.
- `adr0115_a_forged_class_c_announce_never_verifies_a_direct_ack`: a forged class C announcement never yields a key, for a warm or a cold agent.
- `a_direct_ack_key_must_derive_to_its_sender` and `the_capability_store_keeps_only_an_agents_own_advert_key` (unit), and `catchup_serve::all_machines_together_share_a_total_and_a_full_table_forgets_the_least_recent`.
- `catchup_off_apply::an_answer_frees_its_slot_while_its_send_waits`: while one answer's send waits, the same requester's next request is answered, and all 4 slots are free.

Each fails with its fix reverted: with no v1 hedge, the send times out at the 5 s bound and the unit test sees no hedge; with an inline send, the second answer never reaches its send.

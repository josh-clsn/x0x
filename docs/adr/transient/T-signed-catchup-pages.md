# T-signed-catchup-pages: a phone or resting agent can pull missed commits, and a claimed sender counts for nothing

- **Status:** Proposed (fork tail, survivor re-key Task A5).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A4 (`053a1788`)
- **Builds on:** `T-any-member-delivers-signed-commits` (A3), `T-treekem-bytes-binding-everywhere` (A1), `T-treekem-committer-leaf` (A2), `T-catchup-log-on-disk` (A4), `T-survivor-a0-upstream-catchup-port` (A0)
- **Drop at:** when upstream serves and applies catch-up for members whose transport is not verified, or offer it upstream (D5)

## Context

A direct message arrives with `verified == false` when the receiver cannot tie the sending agent to its machine through discovery. A phone's embedded engine and an agent at rest are usually in that state at their peers, and their peers often are at them. The sender id on such a message is only a claim (`src/direct.rs`).

Before this change:
- **A responder dropped every page request it could not verify.** Only member-keyed KeyPackage requests carried a signature (#398).
- **A requester dropped every page it could not verify.** It kept only the hash-anchored KeyPackage from a signed targeted reply.

So a phone never pulled a missed commit over x0x, and a commit its key package could not yet check healed only through the sealer's resend or later gossip (A2 review r-2). The plan review called this I-1. Its second review (N-C3) added the condition for fixing it: on an unverified transport, nothing may act on the claimed sender.

A4's review left one more item for this task (n-1). A responder served the events after the requester's revision, sorted, one a page, whether or not the first one followed the requester's head. It also served events at or below the requester's revision whose TreeKEM epoch was ahead. Such a page could not be used, and nothing made the requester ask anyone else.

## Decision

### Page requests are signed

`TreeKemCatchupRequest` gains `head_challenge: Option<String>` (additive; A6 gives it its meaning). Every page request is signed with the existing `CatchupSigner` (`signed_catchup::sign_page_request`), whatever the transport, since a requester cannot know whether the responder will verify it. The signature covers:

`len(domain) ‖ "x0x/treekem-catchup-page/v1" ‖ len(group) ‖ group ‖ len(requester) ‖ requester ‖ from_revision (u64 BE) ‖ from_epoch (u64 BE) ‖ limit (u64 BE) ‖ head_challenge (0, or 1 ‖ len ‖ bytes)`

Every length is a u64 BE, so no two requests share an encoding. The key is self-certifying against the requester's agent id (`catchup_signer_matches`). A signed `head_challenge` longer than 128 bytes (`HEAD_CHALLENGE_MAX_BYTES`) is refused.

The three senders of page requests sign: the gap request (`request_treekem_catchup_for_gap`), the next-page and epoch-ahead request (`request_treekem_catchup_page`), and the new hole request (below). They share `signed_catchup::send_page_request`. Member-keyed requests keep their own signature.

**Serving.** `handle_treekem_catchup_request` accepts a request it could not verify when `signed_catchup::page_request_signed` holds: no target member, and the signature verifies for the claimed requester over exactly the fields it carries. The claimed sender must still equal the requester, so the page goes to the signer. Every membership gate runs unchanged: a withdrawn room, a locally banned responder, no local roster, a departed or banned requester, and the #378 serve throttle. The signature is checked before the throttle, so a forged request cannot use up a member's throttle window. The signature check still runs before the group lookup, so a request for any group id costs one verification (A12 carries the listener's per-message cost).

**Replays cannot cut a requester off** (A5 review I-1). Before this, `limit` was unsigned: anyone holding a member's signed request (a removed member it still counts active, for one) could replay it to every other member with `limit: 0`. Each would send an empty page marked truncated and start the member's 5 s serve window, so the member's own requests were dropped as duplicates, again and again. Now:
- `limit` is signed, so a changed limit fails the signature and starts no window;
- a responder serves `limit` clamped to `1..=TREEKEM_CATCHUP_RESPONSE_EVENT_CAP` (`page_limit`), so no request is answered with an empty page cut short;
- the serve window starts only when a page is handed to the transport, after every gate and the page are done.

The fields still unsigned (`current_state_hash`, `missing_prev_state_hash`) do not change what is served. So a replay can only send the requester its own real page, which is what it asked for, and start the window that page would have started.

### On an unverified page, the claimed sender counts for nothing

`handle_treekem_catchup_response` now reads a page it could not verify, with these rules:

| Step | Verified page | Unverified page |
|---|---|---|
| Revocation check of the sender | yes | no: the sender is a claim |
| The sender must be an active member | yes | no |
| Which events are looked at | all | the first `TREEKEM_CATCHUP_RESPONSE_EVENT_CAP` (1), which is what an honest responder sends; each costs a signature check |
| Who an event applies as | `signer_delivery::admit(event, sender, true)`: the author's own copy, or the verified signer | `admit(event, sender, false)`: the verified commit signer only |
| A TreeKEM-bearing event | as A3 | its signed binding must name its bytes (A1), and it must pass the committer-leaf rule (A2). The author shortcut does not apply, so a legacy binding is refused whoever is claimed |
| Join-request lifecycle and every other event | as A3 | dropped (no verified signer) |
| The attested recovery package in an add | applied if the event was admitted | the same |
| A truncated page asks the sender for the next one | yes | only when the page moved this member's head, and only when the claimed sender is an active member here (see below) |

A signed targeted reply (#398) authenticates its sender, so its hash-anchored KeyPackage still applies, and its sender must still be an active member. Its events go through the unverified rules.

**The next page.** With one event a page, a phone pulls a run of commits one page at a time, so it must ask for the next. The claimed sender is used only as the address to ask, as every request path uses one: a page request carries this member's revision, epoch and head, which it sends only to active members on its own roster (as A2 r-3 does for the sweep). It asks only when the page moved its head, so a replayed page, or a forged one, makes it send nothing, unless the head moved meanwhile for another reason (then it sends one request per real step).

### A page never leaves a member stuck behind a hole (A4 n-1)

**Serving** (`catchup_page_gap::serve_page`):
- Only events after the requester's revision are candidates. An event at or below it is never served, whatever its epoch: a commit applies only at the revision after the head (`validate_apply`), and that event sorted ahead of the one that applies. Every TreeKEM epoch change in the fork comes with a roster commit, so the old epoch clause served nothing a requester could use.
- A page is the run that starts at `from_revision + 1` and stops at the first hole. A page cut at a hole is marked truncated, so the next request meets the hole.
- When the first event held past the requester's revision is later than `from_revision + 1`, the responder serves nothing and sets `log_evicted_through` to the revision before it: its log holds nothing at or below that revision that the requester needs. That is what the field already meant for a log that dropped events to stay within a cap (A4), so the wire does not change.
- A responder does not check the requester's head hash. A commit at `from_revision + 1` whose predecessor differs from the requester's head is a conflict, not a hole. It is served, and the requester's apply treats it as it did before (queued as `state_hash_gap`, or weighed as fork evidence).

**Requesting** (`catchup_page_gap::page_leaves_gap`, `spawn_ask_another_member`, `GapAsks`):
- After applying a page, a member checks whether it is still behind a hole: the responder's `log_evicted_through` is past its head, or a served commit still sits past the one its head needs. The second case is an older responder, which still serves gapped pages.
- **Only an authenticated member's report counts** (A5 review I-2). The responder must be an active member on the requester's roster, and its report must be authenticated: a verified transport, or a hole report it signed. A responder signs every hole report over (`"x0x/treekem-catchup-gap/v1"`, group, requester, `log_evicted_through`), in the response's `signed_by` (`sign_gap_report`, `gap_report_signed`). An older responder's gapped page counts only over a verified transport, since its events say nothing about who served them. So a stranger, or an unsigned or altered report, spends nothing.
- It then asks other active members, admins first, at most `GAP_ASK_PEERS` (3) at a time. A member asked about a head (revision and epoch) is not asked about it again until its window ends: 5 s after the first ask, doubling each time, at most 320 s (`gap_ask_window`). So a member that was offline at its turn is asked again, and a hole no member can fill costs each member a handful of requests, spread out. The window starts when the request is handed to the transport. A member whose request was never built is not counted. A new head starts every window afresh, a member that leaves the roster leaves the record, and a room wipe drops the room (`GapAsks::wipe`).
- It does not leave out the responder that reported the hole: the report counts only from a member, and a member asked inside its window is not asked again.
- The requester still applies what it was served. A gapped TreeKEM membership event still goes to the #492 queue, which asks its actor and two members and replays it once the hole is filled. Every commit must link to the head it is applied on, so nothing ever applies past a hole.

## Consequences

- A phone or resting agent can pull the commits it missed from any member, over x0x, and the A2 re-pull (`pull_again_after_package`) now reaches it too: it runs the epoch-ahead catch-up, whose requests are signed and whose pages it now reads. One exception (A5 review m-4, from A3/A4): a join-request lifecycle commit is author-only and is not served (`JoinRequestCreated` and `JoinRequestCancelled` are not logged, and an unverified page drops all three), so a member behind one cannot page past it. Noetic does not use request-access rooms.
- Each page request carries an ML-DSA-65 key and signature (about 7 KB of base64) and costs one signature (about 1 ms). Each unverified request a responder serves costs one verification.
- A stranger can send a member pages. Each costs one signature check per event, at most one event a page, plus a signature check on a hole report. Nothing it sends applies unless an admin signed it and it links to the member's head. A forged page makes the member send nothing: its hole report does not count, and it asks for a next page only after the page moved the head.
- A member's hole report, true or false, makes the requester ask each other active member at most once per window per head. "Active" is the requester's own roster, so it can include a member removed by a commit the requester has not applied yet (the test fixture's S1 asks R). That member learns only a head it once held, and is refused by every member that applied its removal.
- Hole asks live in `AppState::treekem_gap_asks`: one record per room and member, reset on a new head and dropped with the room. `treekem_catchup_throttle` is no longer only ever growing: a stamp drops the entries older than an hour once the map holds 1024 (`stamp_catchup_throttle`, at the serve and gap-request stamps), and a room wipe drops every key of the room by prefix (`{room}:` or `serve:{room}:`; before, it removed only an exact key, which matched nothing).
- Older daemons ignore `head_challenge` and the signature on a page request; they still drop requests they cannot verify. An older responder's gapped page is caught on the requesting side over a verified transport. Signing `limit` changed the sign input after the first A5 commit (`6792610a`): a request signed by that commit fails at this one. No daemon at that commit shipped, and both are part of the B1 flag day.
- Two logged commits at one revision (a fork): the responder serves the first by sort order. If it does not link, the requester sees no hole and asks that responder again (A5 review m-5). This keeps fork detection over catch-up, and other paths (#492, epoch-ahead) ask other members.
- For A6: `responder_state_hash` and the request's `current_state_hash` are unsigned, and on an unverified page attacker-chosen; neither is evidence.

## Validation

`named_groups/tests/signed_catchup.rs`:
- `unverified_signed_page_request_is_served` (and the requester applies the unverified page and follows the owner)
- `unverified_unsigned_page_request_is_not` (unsigned, a changed epoch, a changed challenge, another key, a member-keyed request, another claimed sender)
- `a_signed_request_from_a_removed_member_is_refused` (the responder's roster and tree unchanged; a member at the same head is served)
- `unverified_response_claiming_the_author_with_a_legacy_removal_is_refused` (tree and roster unchanged; the author over a verified transport still delivers it)
- `unverified_response_with_swapped_treekem_bytes_installs_nothing` (claimed as the admin, a member and R)
- `a_removed_member_impersonating_the_remover_installs_nothing` (R's genuine legacy removal of itself with R's own commit, claimed as the remover, as R and as a member; tree and roster unchanged, R still on the roster)
- `unverified_response_with_digest_bound_events_applies_by_signer` (a removal and a rename, claimed by an agent outside the room)
- `an_unverified_page_is_read_one_page_of_events_deep`
- `an_unverified_page_asks_for_more_only_after_it_moved_the_head`
- `a_log_that_cannot_reach_the_requesters_head_serves_nothing_and_says_so`
- `an_event_at_or_below_the_requesters_revision_is_never_served`
- `a_hole_after_the_head_asks_another_member` (S2's real signed report, unverified; the admin first; signed, from the head; not again inside the window; the owner's pages heal the member)
- `a_page_from_an_older_responder_that_skips_a_commit_asks_another_member`
- `a_second_hole_report_asks_the_next_batch_admins_first`
- `forged_hole_reports_spend_nothing` (unsigned, a moved signature, a stranger's own signature; then the real report still asks)
- `a_replayed_request_cannot_cut_the_requester_off` (a changed `limit` is refused; a genuine replay sends the requester its real page; `limit: 0` is served one event)
- `a_room_wipe_drops_its_catchup_throttle_and_hole_asks`
- `a_large_catchup_throttle_drops_expired_keys_on_the_next_stamp`

Unit tests: `signed_catchup::tests::the_sign_input_names_its_domain_and_every_field`, `a_page_holds_at_least_one_event_and_at_most_the_cap`, and the `catchup_page_gap` page, hole and `GapAsks` window tests.

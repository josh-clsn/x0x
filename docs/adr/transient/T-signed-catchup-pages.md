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

`len(domain) ‖ "x0x/treekem-catchup-page/v1" ‖ len(group) ‖ group ‖ len(requester) ‖ requester ‖ from_revision (u64 BE) ‖ from_epoch (u64 BE) ‖ head_challenge (0, or 1 ‖ len ‖ bytes)`

Every length is a u64 BE, so no two requests share an encoding. The key is self-certifying against the requester's agent id (`catchup_signer_matches`).

The three senders of page requests sign: the gap request (`request_treekem_catchup_for_gap`), the next-page and epoch-ahead request (`request_treekem_catchup_page`), and the new hole request (below). They share `signed_catchup::send_page_request`. Member-keyed requests keep their own signature.

**Serving.** `handle_treekem_catchup_request` accepts a request it could not verify when `signed_catchup::page_request_signed` holds: no target member, and the signature verifies for the claimed requester over exactly the fields it carries. The claimed sender must still equal the requester, so the page goes to the signer. Every membership gate runs unchanged: a withdrawn room, a locally banned responder, no local roster, a departed or banned requester, and the #378 serve throttle. The signature is checked before the throttle, so a forged request cannot use up a member's throttle window.

**Fields the signature does not cover** (`current_state_hash`, `missing_prev_state_hash`, `limit`) only shape the page, and the page goes to the signer. A replayed request costs one throttled page sent to its own requester.

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

**The next page.** With one event a page, a phone pulls a run of commits one page at a time, so it must ask for the next. The claimed sender is used only as the address to ask, as every request path uses one: a page request carries this member's revision, epoch and head, which it sends only to active members on its own roster (as A2 r-3 does for the sweep). It asks only when the page moved its head, so a replayed page, or a forged one, makes it send nothing.

### A page never leaves a member stuck behind a hole (A4 n-1)

**Serving** (`catchup_page_gap::serve_page`):
- Only events after the requester's revision are candidates. An event at or below it is never served, whatever its epoch: a commit applies only at the revision after the head (`validate_apply`), and that event sorted ahead of the one that applies. Every TreeKEM epoch change in the fork comes with a roster commit, so the old epoch clause served nothing a requester could use.
- A page is the run that starts at `from_revision + 1` and stops at the first hole. A page cut at a hole is marked truncated, so the next request meets the hole.
- When the first event held past the requester's revision is later than `from_revision + 1`, the responder serves nothing and sets `log_evicted_through` to the revision before it: its log holds nothing at or below that revision that the requester needs. That is what the field already meant for a log that dropped events to stay within a cap (A4), so the wire does not change.
- A responder does not check the requester's head hash. A commit at `from_revision + 1` whose predecessor differs from the requester's head is a conflict, not a hole. It is served, and the requester's apply treats it as it did before (queued as `state_hash_gap`, or weighed as fork evidence).

**Requesting** (`catchup_page_gap::page_leaves_gap`, `spawn_ask_another_member`):
- After applying a page, a member checks whether it is still behind a hole: the responder's `log_evicted_through` is past its head, or a served commit still sits past the one its head needs. The second case is an older responder, which still serves gapped pages.
- It then asks other active members, admins first, at most `GAP_ASK_PEERS` (3) at a time. It asks each member at most once per head (revision and epoch), so a hole no member can fill ends the asking. It does not leave out the responder that reported the hole, since on an unverified page that would act on the claimed sender. A responder that is asked again answers from its #378 throttle or with the same report, and then is not asked again for that head.
- The requester still applies what it was served. A gapped TreeKEM membership event still goes to the #492 queue, which asks its actor and two members and replays it once the hole is filled. Every commit must link to the head it is applied on, so nothing ever applies past a hole.

## Consequences

- A phone or resting agent can pull every commit it missed from any member, over x0x, and the A2 re-pull (`pull_again_after_package`) now reaches it too: it runs the epoch-ahead catch-up, whose requests are signed and whose pages it now reads.
- Each page request carries an ML-DSA-65 key and signature (about 7 KB of base64) and costs one signature (about 1 ms). Each unverified request a responder serves costs one verification.
- A stranger can send a member pages. Each costs one signature check per event, at most one event a page. Nothing it sends applies unless an admin signed it and it links to the member's head, and a forged page cannot make the member send anything.
- A hole report, true or false, makes a member ask at most every other active member once per head. "Active" is the requester's own roster, so it can include a member removed by a commit the requester has not applied yet (the test fixture's S1 asks R). That member learns only a head it once held, and is refused by every member that applied its removal.
- The hole requests are stamped in `treekem_catchup_throttle` under `gap-ask:` keys. Like that map's other keys, they are dropped only with the room.
- Older daemons ignore `head_challenge` and the signature on a page request; they still drop requests they cannot verify. An older responder's gapped page is caught on the requesting side.

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
- `a_hole_after_the_head_asks_another_member` (signed, from the head; once per head; the owner's page heals the member)
- `a_page_from_an_older_responder_that_skips_a_commit_asks_another_member`

Unit tests: `signed_catchup::tests::the_sign_input_names_its_domain_and_every_field`, and the `catchup_page_gap` page and hole tests.

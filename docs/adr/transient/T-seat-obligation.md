# T-seat-obligation: a seated member is owed its seat until it proves it holds it

- **Status:** Proposed (fork tail, survivor re-key A13).
- **Date:** 2026-10-25
- **Base:** `survivor-rekey` at `ecbd071a`
- **Upstream:** none. It extends the fork's re-key obligations (`T-survivor-rekey-obligation.md`), which upstream does not have.
- **Drop at:** with the re-key obligations.

## Context

A member seated by a direct add (`add_treekem_named_group_member`) or by an approved join request (`approve_treekem_join_request`) has no join result to poll. That is unlike an invite joiner. Noetic's M6.5a sibling-device admission is such a direct add, and its caller does not wait for the sibling to pull anything.

The seat (the `MemberAdded` or `JoinRequestApproved` event that names its Welcome) went out:
- at +0 and +8 s;
- then, after A12, at 6, 15, 30 and 60 s.

A sibling that slept through those sends was never seated and lost every message in the room. A retried add got 409 "member already present" and did nothing.

## Decision

- **Owed like a survivor.** Both sites now call `owe_survivors` with nothing excluded, so the seated member is owed the event that seats it in the same durable store as A9. It is the same file (`rekey-obligations.json`), the same record, the same worker and the same backoff: 6, 15, 30 and 60 s, then doubling to 15 min, and sent at once on a connect edge.
  - It needs no new kind. The obligation sends every commit-bearing event the A4 log holds from the owed revision, and for the seated member the first of those is its own seat.
- **Settled only by the member's own proof**, by the A10 rules:
  - a transport-verified or self-signed request from the member at or past the seat's epoch;
  - a challenge;
  - a message it sealed at that epoch;
  - or the member leaving the roster.

  A member that has not joined holds no tree at the seat's epoch, so it cannot prove it. When the author delivers the seat directly, the member's `prove_held` answers with a signed request from its new head, which settles.
- **A retried add redelivers.** A direct add naming a member already active on the roster still answers 409 "member already present", now with `"redelivered": true`. It also:
  - sends the member the latest `MemberAdded` or `JoinRequestApproved` naming it from the room's catch-up log, at once;
  - makes its seat obligation due at the next step (`rekey_obligations::due_now`).
- **The seat's Welcome stays staged while the seat is owed (fix round 1).** The direct-add and approval sites mark the obligation as a seat (`RekeyObligation::seat`, on disk) and pin the Welcome it names (`seat_welcome_pin`).
  - Every Welcome expiry check treats a pinned Welcome as live: the staging prune, the start-up load, the serve and admission checks, and the stream deadlines.
  - The pins are written in the join-result staging file, so a restart keeps them.
  - The worker's step drops a pin once no unproven seat names that member in that room: the seat settled, or the member left, or the room was wiped.
  - The Welcome joins at the seat's epoch however old it is. The joiner's KeyPackage secret is re-derived from its seed, and TreeKEM does not enforce KeyPackage lifetimes.
  - A proof at or past the seat's epoch clears the seat mark.
- **An unproven seat goes alone (review S-1).** While the seat is unproven, a send carries the seat event only. A member that holds it asks for the rest itself, and one that never returns costs one event per send.
- **Re-seat with a commit, the fallback (fix round 1).** When the catch-up log no longer holds the seat, or its Welcome is no longer staged, the seat cannot be sent as it was. The worker (or a 409 retry) re-seats the member instead (`seat_reseat`):
  - it removes the stale leaf with the member's KeyPackage from the roster (derived from its seed, so it is the same one);
  - it adds the member again with that KeyPackage, which owes the new seat and pins its new Welcome;
  - the survivors are owed both commits;
  - the removal's direct sends go to the survivors only. Its gossip publish still reaches everyone, but a member that never took its seat cannot link it, so that is harmless;
  - a role other than Member, read before the removal, is restored with a signed role update after the add, as the returning-member re-key does (a legacy Owner comes back Admin; fix round 2);
  - at most once per member and room a day (`RESEAT_EVERY`), and only by an admin of the room. The re-seat times are written in the join-result staging file, so a restart, or a crash loop, does not re-key the room again (fix round 2);
  - an add that fails after the removal is tried once more. If it fails again, the day's allowance is given back, `reseat_failures` is counted, and an error is logged. The member stays removed until it asks to be admitted again; a plain add then works (fix round 2);
  - only an add or approval naming the recipient counts as its seat; any other first event means the log lost it (fix round 2);
  - `GET .../treekem/catch-up` reports `seats`, `room_seats` and `reseats`.
  - A Welcome cannot be minted at the current epoch without a commit: commits since the seat set path secrets on the member's leaf path that only a commit can hand on.
- **`due_now` keeps the edge floor (review S-2).** A burst of 409 retries does not resend the seat each time. The next send is no sooner than 60 s after the last one.
- **Blind schedule only when refused.** A seated member the obligations refused (past a cap, or a record that could not be written) keeps A12's direct sends at 6 to 60 s, with no republish. A refused survivor keeps the republishing schedule.

## Consequences

- **The fallback restores the owner's side only.** Survivors move on, and the new seat stays owed with its Welcome pinned. It does not land a member whose roster base predates its first seat:
  - x0x applies a self-seat only as the next link on the member's local base;
  - the fallback fires exactly when that member cannot get there: its old seat was evicted from the log, or names a Welcome it cannot fetch.

  The pin is the path that actually lands a member. Landing a member from a re-seat needs a member-side **seat re-base** (follow-up task A15): the author sends a signed roster snapshot of the seat's pre-state with an unproven seat, and the member checks it against the seat's `prev_state_hash` and owner continuity, installs it as its base, applies the seat, and runs a head round. A15 is to be built and reviewed with the engine's sibling requester (Noetic's M6.5a, not wired yet: `devices_sync_apply.rs` defers the direct-add). It does not gate the version flip, since no Noetic path issues a direct-add seat yet, but the sibling-admission lane must not ship without it.
- **Pinned Welcomes are exempt from the staging cap** (256 entries, applied at load; fix round 2). The seat obligations' caps bound the pins. Staging has no cap at run time.

- A sibling that sleeps for hours is seated when it returns. The worker sends its seat at the 15 min cap, and at once when its link comes back. No new invite is needed.
- The member counts toward the room's cap of 256 obligations and the daemon's 4096, as a survivor does.

## Tests

Fix round 1 (`seat_obligation.rs`), each red with its fix reverted:
- `a_member_back_after_25_hours_is_seated_from_the_kept_welcome`: the Welcome is backdated 25 h and the owner restarts in the middle (staging and obligations read back from disk). The pinned Welcome survives, an unpinned one as old does not, N is seated from it, and the pin goes once N's proof settles.
- `a_seat_the_log_lost_is_re_seated_with_a_commit`: the seat is evicted from the log. The worker re-seats N (a removal and an add, epoch +2), N is owed the new seat with its Welcome pinned, and the survivors are owed both commits and follow them.
- `re_seats_are_limited_to_one_a_day_and_a_retry_may_trigger_one`: a 409 retry re-seats a lost seat once. A second lost seat, from a retry or the worker, is refused as too soon.

Fix round 2, each red with its fix reverted:
- `a_restart_with_a_full_staging_table_keeps_the_pinned_welcome`: 300 newer Welcomes, then a restart. The pinned (oldest) Welcome survives, and the unpinned ones are capped at 256.
- `a_restart_does_not_allow_a_second_re_seat_that_day`: after a re-seat and a restart with a fresh memory, a second lost seat is refused.
- `an_admin_re_seated_stays_admin`: a member promoted to Admin is Admin again after the re-seat, through a published, signed role update.
- `a_sibling_asleep_past_ten_minutes_is_seated_when_it_returns` now settles on N's own `prove_held` request (review S-3).


`named_groups/tests/seat_obligation.rs`, on the survivor fixture plus a sibling daemon that knows the room but holds no tree. Its Welcome references resolve from the owner's staged Welcomes, in process (`welcome_source`, a test-only stand-in for the blob transport).

- `a_sibling_asleep_past_ten_minutes_is_seated_when_it_returns`: six failed sends over more than ten minutes leave N unseated. When its link returns, the obligation seats N at the add's epoch with no new invite, and N's own signed request settles the obligation. This is also the review's offline-newcomer test (A12 m-7).
- `the_seat_settles_only_on_the_members_own_proof`: none of these settles:
  - a request below the seat's epoch;
  - an unsigned claim;
  - another key's signature.

  N's signed request at the epoch does.
- `a_retried_add_answers_409_and_redelivers_the_seat`: the retry answers 409 with `redelivered: true`, sends N its `MemberAdded` and makes the obligation due now.
- `the_seat_obligation_survives_restart`: the obligation loads back from disk right after the route returns.

The A10 tests `an_add_owes_the_members_it_did_not_add` and `invite_and_approval_adds_owe_the_members_already_seated` now also expect the seat to be owed for a direct add and an approval. The invite add still excludes its joiner, which polls. `catchup_off_apply::a_member_an_add_seats_keeps_the_resend_schedule` now expects no blind schedule while the seat is owed, and the direct sends once the obligations are past their cap.

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
- **Blind schedule only when refused.** A seated member the obligations refused (past a cap, or a record that could not be written) keeps A12's direct sends at 6 to 60 s, with no republish. A refused survivor keeps the republishing schedule.

## Consequences

- A sibling that sleeps for hours is seated when it returns. The worker sends its seat at the 15 min cap, and at once when its link comes back. No new invite is needed.
- The Welcome a seat names is staged for 24 h (`PENDING_WELCOME_TTL`, kept across restarts). A member that comes back after that gets the seat event, but the Welcome fetch fails. It then needs a new seat, which a retried add cannot give while the stale seat stands. That case is not handled here.
- The member counts toward the room's cap of 256 obligations and the daemon's 4096, as a survivor does.

## Tests

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

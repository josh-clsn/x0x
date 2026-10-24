# T-treekem-head-proof: an admin can prove where a room's key stands, to one member who asks

- **Status:** Proposed (fork tail, survivor re-key Task A6).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A5 (`0234c3c7`)
- **Builds on:** `T-signed-catchup-pages` (A5: signed page requests carrying `head_challenge`), `T-catchup-log-on-disk` (A4), `T-survivor-a0-upstream-catchup-port` (A0: the epoch-ahead catch-up)
- **Consumed by:** A7 (the trigger, GET, sign and accept routes), C3 (the anchored closure and the verdict), C4 (the confirm round)
- **Drop at:** when upstream ships signed head evidence for TreeKEM rooms, or offer it upstream (D5)

## Context

A member that was away when an admin was removed may still hold the old room key and not know it. Before it seals a room message, the engine must learn, from every admin in its anchored set, that its key is the room's current key (design 3.1, 3.2). Nothing on the catch-up wire said so:
- `responder_state_hash` (#1337) and a request's `current_state_hash` are unsigned, and on an unverified page attacker-chosen. Neither is evidence of freshness, and nothing here reads them as such.
- The roster's `security_binding` names an epoch, not a key, so two trees at one epoch share it (plan review N-C2).

## Decision

### The epoch authenticator

`TreeKemMlsGroup::epoch_authenticator()` is `export_secret("x0x/treekem-head/v1", group_id, 32)`: the standard MLS exporter (RFC 9420 §8.5) of `saorsa-mls` 0.3.8 (`treekem_group.rs:735`, `key_schedule.rs:352-361`: `ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported", Hash(context), 32)`), with the tree's own group id as the context. Every member at one epoch of one tree derives the same 32 bytes. They are one HKDF output under a label nothing else uses, so they reveal no other secret of the epoch: they are a public fingerprint of the tree, not a key. Nobody outside the epoch can compute them (a removal carries a fresh update path, so a removed member lacks the commit secret), and two forks at one epoch differ. `TreeKemMlsGroup::head()` returns the epoch and the authenticator from one borrow of the tree, so a caller holding the tree's lock gets a pair that cannot be torn.

### The proof

`named_groups/head_proof.rs`. A proof is a `HeadClaim` plus the signer's `CatchupSigner` (the self-certifying ML-DSA-65 key and signature already used by A5 and #398). On the wire it is one flat JSON object:

`{ version, group_id, requester, nonce, treekem_epoch, epoch_authenticator, security_binding, state_revision, admins, signer, signed_by }`

- `group_id` is the signer's stable group id; `requester` and `signer` are lowercase hex agent ids; `epoch_authenticator` is 32 bytes of lowercase hex; `admins` are the active admins on the signer's roster, sorted, no repeats, at most 512.
- `security_binding` and `state_revision` are information only, but signed.

**Signed bytes** (domain `x0x/treekem-head-proof/v1`). `u64` values are big-endian; every byte string is preceded by its length as a big-endian `u64`:

```
len ‖ "x0x/treekem-head-proof/v1"
version (u64)
len ‖ group_id
len ‖ requester
len ‖ nonce
treekem_epoch (u64)
len ‖ epoch_authenticator (the 32 raw bytes)
security_binding: 0x00, or 0x01 ‖ len ‖ binding
state_revision (u64)
admin count (u64), then len ‖ admin for each
len ‖ signer
```

**Verification** (`head_proof::verify`): every field is in its one canonical form (version 1; lowercase hex ids; a 32-byte lowercase-hex authenticator; a nonce of 1 to 128 bytes; admins strictly sorted), the signer is one of the admins it lists (a proof that does not name its own signer an admin is self-contradictory, A6 review m-2), the carried key derives the claimed `signer`, and the signature verifies over the bytes above. The signer is in the signed bytes and must be the key's own agent id, so a proof cannot be re-attributed to another admin.

### The challenge

A challenge (`head_proof::challenge_nonce`) is the requester's counter as 16 lowercase hex digits, then 32 random bytes as hex: 80 characters, inside A5's 128-byte bound and covered by the page request's signature. The counter only grows: `max(last + 1, unix ms)` per daemon (`HeadCounter`). The last one is kept on disk, one decimal number in `head-challenge-counter` under the TreeKEM directory, written atomically and durably (`storage::write_private_bytes_durable`) before the challenge is used. So the counter never goes back, whatever the wall clock does across a restart, and a requester whose clock ran ahead and was then corrected is not held by admins that saw the higher counters (A6 re-review m-r1). A counter that cannot be written, or is used up, opens no round: the room holds. An unreadable file starts again from the clock.

### Who signs, what, and when

`head_proof::answer_challenge(state, challenge)`. The page serve calls it, and so does A7's sign route. **`challenge` is a `SignedChallenge`, which can only be built from a page request whose signature verifies for its requester** (`SignedChallenge::from_request`, A5's signature over the group, the requester, the head and the challenge), whatever the transport. So only the requester itself can move its floor at an admin: neither a relay nor anyone who reaches a route can push an all-`f` counter in its name (A6 re-review N-2).

1. The challenge must carry a counter (`BadChallenge`).
2. The requester must be active on this daemon's roster. A removed or banned member, or one this daemon never knew, gets nothing (`RequesterNotActive`; A7 maps it to 403).
3. **Ordering and limit** (`HeadAnswers`, A6 review I-1). Per (room, requester) the daemon keeps the latest challenge it saw and the proof it got:
   - a lower counter, or another challenge with the latest counter, is refused (`StaleChallenge`) and **not charged**;
   - the latest challenge again gets the same proof from cache, **not charged** and not signed again, **at most once per 5 s** (`TREEKEM_CATCHUP_THROTTLE`) per (room, requester); a repeat inside that window is dropped (`RepeatTooSoon`), so a replay of it cannot turn this daemon into a reflector at the requester (A6 re-review N-1). A latest challenge that got no proof is refused;
   - **a higher counter always becomes the latest**, so every older challenge is refused from then on; it is charged, and answered, only within 12 per 60 s, a sliding window (`Limited` is not charged) (A6 re-review I-1b).
   So a replay of any challenge at or below the latest, by anyone who holds one (a removed admin, the relay), spends nothing. When this daemon's floor for a requester is below challenges a replayer holds, because it forgot (a restart, or the room wiped) or because it was away while the requester ran rounds, the replayer can spend at most the current window: the first of the requester's own newer challenges to arrive, even a limited one, fences off every challenge the replayer holds, and the requester's next challenge after the window is answered. The delay is at most one window plus one round. One ML-DSA-65 signature costs about 1 ms. A charged challenge that then gets no proof is logged at debug, so the rig can tell a stale replay from a lost answer (m-r3).
4. **The tree is looked up and read on every attempt**, and the epoch and authenticator come from one borrow of it under its lock (A6 review m-3: a Welcome or re-join can replace it).
5. The roster is read before and after the tree (`RosterHead::settled`): the revision, the hash, this daemon's admin role and **the requester's active state** must all be unchanged, else the read is repeated (at most three times). A requester removed while the tree is read is refused at the next read, so a member removed by the commit that moved the tree never gets the new epoch's authenticator from this daemon (A6 review m-1).
6. **When the requester's signed epoch is ahead, this daemon starts its own epoch-ahead catch-up** (#1427's task), whether or not it is an admin: a member promoted while this daemon was away is challenged as an admin before it knows it is one. It starts only once a read has settled; if all three attempts see the roster move, nothing starts, and the requester's next challenge starts it (m-r4).
7. This daemon must be an active admin on its own roster (`NotAnAdmin`; A7 maps it to 409).

**On the page path** (`handle_treekem_catchup_request`): a page request with `head_challenge` (A5: signed, bounded at 128 bytes) is answered after every membership gate and **before the #378 page throttle**. When the page is throttled, the proof goes alone in a response with no events (`proof_only_response`). Otherwise it rides in the page's new `head_proof` field, or goes alone first when page and proof would not fit one direct message. Member-keyed requests (#205) return before this point and get no proof: their signature does not cover a challenge.

### Recording

`named_groups/head_rounds.rs`. A member opens a round per room (`challenge_admins`): a new challenge, and a challenge set. **The challenge set is every agent the engine names (its anchored set, A7's trigger body), then every active admin on this member's roster, never itself.** A named admin stays in the set even when this member's roster no longer lists it: a stale commit applied here (a removed admin's, design 3.2) may have removed it, and only its answer can show that. **A named agent is never dropped to fit the cap: when the whole set would exceed 512, no round opens and the room holds** (A6 review C-1). Otherwise a removed admin could seat hundreds of admins of its own on a stale roster, crowd the honest admin out of the round, and have it excused under design 3.2 rule 4. **`None` from the trigger means hold, with the same words as Held or Forked: A7 and C3 must never fall back to a smaller set.** The round is opened, then the signed page requests carrying the challenge are sent on their own task, so a caller never waits on an offline admin (m-7). A new round replaces the old round and its proofs.

`handle_treekem_catchup_response` takes a proof out of any response first, whatever the transport, and `record_proof` keeps it only when all hold:
- the room has an open round, and the proof's nonce is that round's;
- no more than 60 s have passed since the round opened;
- the proof is for this member and this room's stable group id;
- this member challenged the signer in this round;
- the proof verifies.

The claimed sender of the response plays no part. **Every distinct head (epoch, authenticator) a signer signs in a round is kept**, a duplicate once, at most four (a later epoch replaces the lowest when full), and a signer with more than one is reported as `conflicted` (A6 review I-2). A signer can show two heads in one round only by signing again after it forgot the challenge, or by equivocating, and the arrival order is not ordered: keeping every head lets C3 apply "a conflict always wins" whatever the order. **For C3: a conflicted signer counts as Behind and never as a match** (rule 1 applies to every kept head, and a conflicted signer never satisfies rule 3, even when its heads share the highest epoch). C3 must not reduce `RoundView::heads` to one head per signer. A head is kept as its claim once its proof verified, not the 7 KB signature (m-r2): the worst case is 512 signers × 4 heads × a claim naming at most 512 admins. A response that carried only a proof stops there. A room wipe drops the room's round and its answer records.

**The round deadline is not a freshness age** (m-4). It runs on `tokio::time::Instant` (the process monotonic clock), which stops while a device sleeps, so a proof queued during a long sleep can still be recorded after resume. The proof is still fresh relative to the challenge. A7's GET does not report `opened_at` at all, and C3 measures the 60 s round deadline and the time to live from the round's opening on the sleep-inclusive clock (C2).

### The routes (A7)

`named_groups/catchup_routes.rs`. Each has a `GROUP_PLANE_ROUTES` row and takes the #1166 `GroupAccess` extractor (unknown group 404, then the route's core, then a withdrawn room 409); the handler re-runs the core on its own read. Every refusal carries `reason` and `retry`: `later` (hold; the same request may succeed later) or `never` (hold; it will not succeed as it is).

| Route | Access | Answer |
|---|---|---|
| `POST /groups/:id/treekem/catch-up` `{"observed_epoch"?, "challenge": [hex…]}` | `OwnerDurable` (auth middleware and core) | `202 {"round", "asked", "request", "catching_up"}`. `request` is this member's signed page request carrying the challenge, for the engine to carry to an admin over the relay. No round: `{"round": null, "asked": [], "hold": true}` with `409 challenge_set_too_large`, `409 not_an_active_member`, `404 group_not_found` (never) or `503 no_challenge_counter` (later). It never opens a smaller round. A non-hex agent is `400 bad_challenge_agent`. |
| `GET /groups/:id/treekem/catch-up?since_revision=<r>` | `Member(Active)`: this daemon's own active seat, whoever the bearer; riders 403 | `200 {"epoch", "epoch_authenticator", "security_binding", "revision", "admins", "admins_since", "admins_since_complete", "started_at_ms", "connected_admins", "suspended_since_last_get", "round"}`; `503 unavailable` (later) when the roster keeps moving across three reads |
| `POST /groups/:id/treekem/head-proof` `{"request": <signed page request>}` | `OwnerDurable` | `200 {"proof"}`; `400` `no_challenge`, `challenge_not_signed`, `bad_challenge`, `group_mismatch`; `403 requester_not_active`; `409` `not_an_admin`, `stale_challenge` (never), `not_a_treekem_room` (later); `429` `rate_limited`, `repeat_too_soon`; `503 unavailable` (later) |
| `POST /groups/:id/treekem/head-proof/accept` `{"proof"}` | `OwnerDurable` | `200 {"recorded": true}`, or `{"recorded": false, "reason"}`: `no_round`, `other_nonce`, `late`, `not_for_this_round`, `not_asked`, `bad_signature` |

- **The sign route takes only the requester's signed page request,** exactly as received, and builds the challenge through `SignedChallenge::from_request`. A bare `{requester, nonce, requester_epoch}` cannot reach `answer_challenge` (N-2). The route is the relay leg: over x0x the daemon answers a challenge itself, but a challenge the relay carries reaches the admin's engine, which hands it to its daemon here (Task C4).
- **`admins_since`** lists the admins of every state applied after `since_revision`, oldest first, from the room's retained commits (`GroupInfo::commit_log`, #111): every commit this daemon seals or applies is retained there with its roster, at one chokepoint, and kept on disk with the roster. A4's catch-up log holds events whose signed commits carry only a roster root, so it cannot name a state's admins. `admins_since_complete` is false unless nothing after the anchor can be missing: the first retained state after it links by signed `prev_state_hash` to the retained state at or before it (or, with none retained, is the anchor's revision plus one, since revisions only grow), each later state links to the one before, every signed roster root re-derives, and the last state is the live roster. Otherwise the engine must hold.
- **`started_at_ms`** is an opaque marker of the daemon run: it changes on a restart. The round reports no opening time: the round deadline runs on a clock that stops in a sleep (m-4), so the engine times a round on its own sleep-inclusive clock (C2) from when it triggered it.
- **`connected_admins` and `suspended_since_last_get`** are Task A8's. Until A8 lands they fail closed: `[]` and `true`.

### Test knob

`X0X_TEST_HEAD_PROOF_INFLATE=1` makes this daemon sign its proofs with the live epoch plus one and a random authenticator, so the rig can play a removed admin running a modified app (design F-1). It follows the `X0X_TEST_DROP_INITIAL_*` pattern: `X0X_TEST_`-prefixed, read once per process, on only for exactly `1`, and every proof it inflates logs a warning. It can only make others hold, never confirm.

## Consequences

- The verdict (C3) can compare an admin's live key with its own, without trusting any unsigned hint. A conflicting proof (a later epoch, or the same epoch with another authenticator, or a conflicted signer) shows the member is behind or forked.
- **The authenticator is not confidential once sent** (m-6). Peers on the path see it, and so does the relay if Part C carries proofs in the clear. It reveals no other secret, but no consumer may treat knowledge of it as evidence of membership: it only says that two parties hold the same tree, which a member checks against its own live tree.
- A removed admin that a member still has in its anchored set gets that member's challenge and can answer it, inflated or not (F-1, a stated residual). It never learns anything: the challenge carries only the member's own head, which it once held. Replaying that challenge later spends none of the member's answers beyond one window. **It can also hold the member by making its challenge set too large** (seating admins on the member's stale roster, or naming up to 512 admins in its own proofs, which the closure adds): then no round opens, and the room holds. `None` from the trigger is a hold, never a smaller set. This is the same attacker and precondition as F-1, and it ends the same way, once the member re-joins. Design 3.2's F-1 paragraph should say so.
- A daemon that did not learn of its own removal still signs as an admin, with its stale head. That is what design 3.2 rule 4 handles.
- **Information fields and the tree** (m-5). On the seal and apply paths the next roster is installed in memory while the tree's lock is still held (`process_treekem_commit_after_crypto_recheck`, `remove_treekem_named_group_member`), so a proof cannot pair the new tree with the previous roster there. The remaining case is a `ReplacedNotDurable` persist, which installs the new roster and then rolls the tree back: a proof then pairs the old epoch with the new roster's admins, which can be fewer. Both fail closed: the closure only grows, and the requester-active re-read (step 5) keeps a just-removed member from the new head.
- A requester can make an admin sign at most 12 proofs a minute per room, and only with challenges of its own that rise, and re-send a cached proof at most once per 5 s. Each answer costs a roster read, a tree lock and one signature; a challenge from ahead also costs at most one catch-up task per room (#1427's bound). `HeadAnswers` keeps one record per (room, active requester) that ever challenged, dropped with the room.
- Each challenge is a page request (about 7 KB, A5), and each proof adds about 7 KB of base64 key and signature to a response.
- Older daemons ignore `head_challenge` and `head_proof`, so a room is confirmed only through admins at A6 or later. That fits the B1 flag day.
- `challenge_admins` and `round_view` are reached through A7's routes.

## Validation

`named_groups/tests/head_proof.rs`:
- `authenticator_is_read_from_the_live_tree` (the owner's tree moves on with no roster change; the proof follows the tree, and S1, which missed the commit, holds another value)
- `an_admin_answers_a_challenge_with_a_signed_proof`
- `a_non_admin_answers_without_a_proof`
- `a_departed_requester_gets_no_proof` (verified and unverified; the direct call says `RequesterNotActive`)
- `a_proof_verifies_only_for_its_signer_key_requester_nonce_and_group` (every field changed, re-attribution, another key, a stranger's own proof; recording refuses a signer not asked, and another requester as `NotForThisRound`)
- `a_replayed_proof_for_another_nonce_is_not_recorded`
- `a_proof_after_the_round_deadline_is_not_recorded`
- `a_challenge_right_after_a_page_request_still_gets_a_proof`
- `a_requester_gets_at_most_twelve_proofs_a_minute`
- `a_challenge_from_ahead_starts_the_responders_epoch_ahead_catch_up`
- `a_stale_roster_admin_commit_does_not_remove_an_anchor_admin_from_the_challenge_set`
- `an_inflating_admin_signs_the_next_epoch_and_a_random_authenticator`
- `the_member_keyed_serve_prunes_the_catchup_throttle` (A5 review r-2)
- `a_roster_full_of_admins_does_not_crowd_out_a_named_admin` (C-1: 600 of R's admins on S1's stale roster; no round, nobody challenged; with 100, the named owner is asked)
- `a_replayed_old_challenge_does_not_spend_the_requesters_answers` (I-1: old replays refused, the latest answered from cache with the same signature, only S1's own challenges charged)
- `an_old_challenge_from_before_a_re_invite_spends_nothing` (I-1: across a removal and re-add, and after the owner forgets)
- `the_same_challenge_twice_is_answered_once`
- `two_heads_from_one_signer_in_a_round_are_both_kept` (I-2: E+1 first, then E twice; both kept, the owner conflicted)
- `a_requester_removed_while_the_head_is_read_gets_no_proof` (m-1, through a hook between the first roster read and the tree read)
- `a_page_and_a_proof_too_large_for_one_message_go_apart` (m-8)
- `a_replayed_current_challenge_is_re_sent_at_most_once_a_window` (N-1: 50 replays, one re-send, nothing else sent)
- `a_replayed_stock_of_old_challenges_is_fenced_off_by_the_requesters_newest` (I-1b: 12 of a 20-challenge stock charged, S1's newest limited, the other 8 stale)
- `an_unsigned_or_forged_challenge_cannot_move_the_floor` (N-2: unsigned all-`f`, another key, a challenge swapped into S1's signed request; S1's next challenge still answered)

`named_groups/tests/catchup_routes.rs` (A7, through the auth middleware and the chokepoint):
- `trigger_challenges_the_named_admins_and_roster_admins_only`
- `trigger_that_would_ask_too_many_opens_no_round_and_says_hold`
- `trigger_with_an_observed_epoch_starts_the_epoch_ahead_task`
- `get_reports_head_presence_and_round` (the relay leg end to end: the trigger's request, the owner's sign route, S1's accept route)
- `get_reports_the_admins_of_every_state_applied_in_one_burst`
- `head_proof_route_refuses_a_session_bearer_and_a_rider`
- `head_proof_route_refuses_a_departed_requester`
- `head_proof_route_maps_every_refusal_to_its_reason`
- `accept_route_records_only_a_proof_for_the_open_round`

Unit tests:
- `catchup_routes::tests::every_refusal_has_its_own_reason_and_a_retry_class`, `admins_since_lists_every_retained_state_and_says_when_one_may_be_missing`, `a_hold_says_no_round_and_hold`; `group_access::tests::treekem_catch_up_admission_needs_the_daemons_seat_or_the_durable_token`; `auth::tests::treekem_head_routes_require_the_durable_token`; `api::tests::endpoints_registry_lists_the_four_routes`;
- `mls::treekem::tests::every_member_at_an_epoch_derives_the_same_authenticator` (three members, and equality with the exporter call itself), `the_authenticator_follows_the_live_epoch_and_the_group`;
- `head_proof::tests::the_inflate_knob_is_off_unless_set`, `the_sign_input_names_its_domain_and_every_field`, `a_proof_verifies_only_in_canonical_form_and_for_its_signer_key`, `a_challenge_opens_with_its_counter`, `only_a_newer_challenge_is_charged_and_the_latest_is_answered_from_cache`, `the_latest_proof_is_re_sent_at_most_once_a_window`, `a_replayed_stock_of_old_challenges_delays_the_requester_at_most_one_window`;
- `head_rounds::tests::a_round_records_only_its_own_nonce_requester_group_and_asked_signers_in_time`, `every_distinct_head_of_a_signer_is_kept_whatever_the_order`, `the_challenge_counter_only_grows_across_a_restart`, `the_challenge_set_never_drops_a_named_agent`.

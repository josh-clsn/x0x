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

A challenge (`head_proof::challenge_nonce`) is the requester's counter as 16 lowercase hex digits, then 32 random bytes as hex: 80 characters, inside A5's 128-byte bound and covered by the page request's signature. The counter only grows: `max(last + 1, unix ms)` per daemon (`HeadRounds::next_nonce`), so it stays above every earlier one after a restart too, unless the wall clock stepped back across the restart. Then an admin that saw the higher counters refuses the new ones as stale until the clock passes them or the admin restarts: the room holds, which fails closed.

### Who signs, what, and when

`head_proof::answer_challenge(state, group, requester, nonce, requester_epoch)`. The page serve calls it, and A7's sign route will too.

1. The challenge must carry a counter (`BadChallenge`).
2. The requester must be active on this daemon's roster. A removed or banned member, or one this daemon never knew, gets nothing (`RequesterNotActive`; A7 maps it to 403).
3. **Ordering and limit** (`HeadAnswers`, A6 review I-1). Per (room, requester) the daemon keeps the latest challenge it charged and the proof it got:
   - a lower counter, or another challenge with the latest counter, is refused (`StaleChallenge`) and **not charged**;
   - the latest challenge again gets the same proof from cache, **not charged** and not signed again (if it got no proof, it is refused);
   - only a higher counter is charged: at most 12 per 60 s, a sliding window (`Limited`, which does not make it the latest).
   So a replay of any old signed challenge, by anyone who holds one (a removed admin, the relay), spends nothing, and a replay of the latest only re-sends the requester its own proof. After this daemon forgets (a restart, or the room wiped), each old challenge a replayer holds can be charged once, in rising order, and the requester's next real challenge is above all of them: a bounded delay of at most one window. One ML-DSA-65 signature costs about 1 ms.
4. **The tree is looked up and read on every attempt**, and the epoch and authenticator come from one borrow of it under its lock (A6 review m-3: a Welcome or re-join can replace it).
5. The roster is read before and after the tree (`RosterHead::settled`): the revision, the hash, this daemon's admin role and **the requester's active state** must all be unchanged, else the read is repeated (at most three times). A requester removed while the tree is read is refused at the next read, so a member removed by the commit that moved the tree never gets the new epoch's authenticator from this daemon (A6 review m-1).
6. **When the requester's signed epoch is ahead, this daemon starts its own epoch-ahead catch-up** (#1427's task), whether or not it is an admin: a member promoted while this daemon was away is challenged as an admin before it knows it is one.
7. This daemon must be an active admin on its own roster (`NotAnAdmin`; A7 maps it to 409).

**On the page path** (`handle_treekem_catchup_request`): a page request with `head_challenge` (A5: signed, bounded at 128 bytes) is answered after every membership gate and **before the #378 page throttle**. When the page is throttled, the proof goes alone in a response with no events (`proof_only_response`). Otherwise it rides in the page's new `head_proof` field, or goes alone first when page and proof would not fit one direct message. Member-keyed requests (#205) return before this point and get no proof: their signature does not cover a challenge.

### Recording

`named_groups/head_rounds.rs`. A member opens a round per room (`challenge_admins`): a new challenge, and a challenge set. **The challenge set is every agent the engine names (its anchored set, A7's trigger body), then every active admin on this member's roster, never itself.** A named admin stays in the set even when this member's roster no longer lists it: a stale commit applied here (a removed admin's, design 3.2) may have removed it, and only its answer can show that. **A named agent is never dropped to fit the cap: when the whole set would exceed 512, no round opens and the room holds** (A6 review C-1). Otherwise a removed admin could seat hundreds of admins of its own on a stale roster, crowd the honest admin out of the round, and have it excused under design 3.2 rule 4. The round is opened, then the signed page requests carrying the challenge are sent on their own task, so a caller never waits on an offline admin (m-7). A new round replaces the old round and its proofs.

`handle_treekem_catchup_response` takes a proof out of any response first, whatever the transport, and `record_proof` keeps it only when all hold:
- the room has an open round, and the proof's nonce is that round's;
- no more than 60 s have passed since the round opened;
- the proof is for this member and this room's stable group id;
- this member challenged the signer in this round;
- the proof verifies.

The claimed sender of the response plays no part. **Every distinct head (epoch, authenticator) a signer signs in a round is kept**, a duplicate once, at most four (a later epoch replaces the lowest when full), and a signer with more than one is reported as `conflicted` (A6 review I-2). An admin can sign twice for one challenge without equivocating (a duplicated delivery after it moved on), and the arrival order is not ordered: keeping every head lets C3 apply "a conflict always wins" whatever the order. C3 should count a conflicted signer as its highest epoch under rule 1, or as Behind. A response that carried only a proof stops there. A room wipe drops the room's round and its answer records.

**The round deadline is not a freshness age** (m-4). It runs on `tokio::time::Instant` (the process monotonic clock), which stops while a device sleeps, so a proof queued during a long sleep can still be recorded after resume. The proof is still fresh relative to the challenge. A7's GET must not report `opened_at` as an age, and C3 measures the 60 s round deadline and the time to live from the round's opening on the sleep-inclusive clock (C2).

### Test knob

`X0X_TEST_HEAD_PROOF_INFLATE=1` makes this daemon sign its proofs with the live epoch plus one and a random authenticator, so the rig can play a removed admin running a modified app (design F-1). It follows the `X0X_TEST_DROP_INITIAL_*` pattern: `X0X_TEST_`-prefixed, read once per process, on only for exactly `1`, and every proof it inflates logs a warning. It can only make others hold, never confirm.

## Consequences

- The verdict (C3) can compare an admin's live key with its own, without trusting any unsigned hint. A conflicting proof (a later epoch, or the same epoch with another authenticator, or a conflicted signer) shows the member is behind or forked.
- **The authenticator is not confidential once sent** (m-6). Peers on the path see it, and so does the relay if Part C carries proofs in the clear. It reveals no other secret, but no consumer may treat knowledge of it as evidence of membership: it only says that two parties hold the same tree, which a member checks against its own live tree.
- A removed admin that a member still has in its anchored set gets that member's challenge and can answer it, inflated or not (F-1, a stated residual). It never learns anything: the challenge carries only the member's own head, which it once held. Replaying that challenge later spends none of the member's answers.
- A daemon that did not learn of its own removal still signs as an admin, with its stale head. That is what design 3.2 rule 4 handles.
- **Information fields and the tree** (m-5). On the seal and apply paths the next roster is installed in memory while the tree's lock is still held (`process_treekem_commit_after_crypto_recheck`, `remove_treekem_named_group_member`), so a proof cannot pair the new tree with the previous roster there. The remaining case is a `ReplacedNotDurable` persist, which installs the new roster and then rolls the tree back: a proof then pairs the old epoch with the new roster's admins, which can be fewer. Both fail closed: the closure only grows, and the requester-active re-read (step 5) keeps a just-removed member from the new head.
- A requester can make an admin sign at most 12 proofs a minute per room, and only with challenges of its own that rise. Each answer costs a roster read, a tree lock and one signature; a challenge from ahead also costs at most one catch-up task per room (#1427's bound). `HeadAnswers` keeps one record per (room, active requester) that ever challenged, dropped with the room.
- Each challenge is a page request (about 7 KB, A5), and each proof adds about 7 KB of base64 key and signature to a response.
- Older daemons ignore `head_challenge` and `head_proof`, so a room is confirmed only through admins at A6 or later. That fits the B1 flag day.
- `challenge_admins` and `round_view` have no production caller until A7's routes.

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

Unit tests:
- `mls::treekem::tests::every_member_at_an_epoch_derives_the_same_authenticator` (three members, and equality with the exporter call itself), `the_authenticator_follows_the_live_epoch_and_the_group`;
- `head_proof::tests::the_inflate_knob_is_off_unless_set`, `the_sign_input_names_its_domain_and_every_field`, `a_proof_verifies_only_in_canonical_form_and_for_its_signer_key`, `a_challenge_opens_with_its_counter`, `only_a_newer_challenge_is_charged_and_the_latest_is_answered_from_cache`;
- `head_rounds::tests::a_round_records_only_its_own_nonce_requester_group_and_asked_signers_in_time`, `every_distinct_head_of_a_signer_is_kept_whatever_the_order`, `challenges_only_grow`, `the_challenge_set_never_drops_a_named_agent`.

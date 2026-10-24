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

`TreeKemMlsGroup::epoch_authenticator()` is `export_secret("x0x/treekem-head/v1", group_id, 32)`: the standard MLS exporter (RFC 9420 §8.5) of `saorsa-mls` 0.3.8 (`treekem_group.rs:735`, `key_schedule.rs:352-361`: `ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported", Hash(context), 32)`), with the tree's own group id as the context. Every member at one epoch of one tree derives the same 32 bytes. They are one-way and specific to the label, so they reveal nothing a member at that epoch does not already hold. `TreeKemMlsGroup::head()` returns the epoch and the authenticator from one borrow of the tree, so a caller holding the tree's lock gets a pair that cannot be torn.

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

**Verification** (`head_proof::verify`): every field is in its one canonical form (version 1; lowercase hex ids; a 32-byte lowercase-hex authenticator; a nonce of 1 to 128 bytes; admins strictly sorted), the carried key derives the claimed `signer`, and the signature verifies over the bytes above. The signer is in the signed bytes and must be the key's own agent id, so a proof cannot be re-attributed to another admin.

### Who signs, what, and when

`head_proof::answer_challenge(state, group, requester, nonce, requester_epoch)`. The page serve calls it, and A7's sign route will too.

1. The challenge must be 1 to 128 bytes.
2. The requester must be active on this daemon's roster. A removed or banned member, or one this daemon never knew, gets nothing (`RequesterNotActive`; A7 maps it to 403).
3. **Limit:** 12 answers per 60 s per (room, requester), a sliding window (`Limited`). One ML-DSA-65 signature costs about 1 ms.
4. The live tree's epoch and authenticator are read under the tree's lock. **When the requester's signed epoch is ahead, this daemon starts its own epoch-ahead catch-up** (#1427's task), whether or not it is an admin: a member promoted while this daemon was away is challenged as an admin before it knows it is one.
5. This daemon must be an active admin on its own roster (`NotAnAdmin`; A7 maps it to 409).
6. The roster is read before and after the tree. If its revision, hash or this daemon's admin role moved meanwhile, the read is repeated (at most three times), so the proof's information fields belong to the head the tree reports.

**On the page path** (`handle_treekem_catchup_request`): a page request with `head_challenge` (A5: signed, bounded at 128 bytes) is answered after every membership gate and **before the #378 page throttle**. When the page is throttled, the proof goes alone in a response with no events (`proof_only_response`). Otherwise it rides in the page's new `head_proof` field, or goes alone first when page and proof would not fit one direct message. Member-keyed requests (#205) return before this point and get no proof: their signature does not cover a challenge.

### Recording

A member opens a round per room (`challenge_admins`): a fresh 32-byte random nonce, and a challenge set. **The challenge set is every agent the engine names (its anchored set, A7's trigger body) plus every active admin on this member's roster, never itself.** A named admin stays in the set even when this member's roster no longer lists it: a stale commit applied here (a removed admin's, design 3.2) may have removed it, and only its answer can show that. It sends each one its signed page request carrying the nonce. A new round replaces the old round and its proofs.

`handle_treekem_catchup_response` takes a proof out of any response first, whatever the transport, and `record_proof` keeps it only when all hold:
- the room has an open round, and the proof's nonce is that round's;
- no more than 60 s have passed since the round opened;
- the proof is for this member and this room's stable group id;
- this member challenged the signer in this round;
- the proof verifies.

The claimed sender of the response plays no part. One proof is kept per signer (the latest). A response that carried only a proof stops there. A room wipe drops the room's round and answer counts.

### Test knob

`X0X_TEST_HEAD_PROOF_INFLATE=1` makes this daemon sign its proofs with the live epoch plus one and a random authenticator, so the rig can play a removed admin running a modified app (design F-1). It follows the `X0X_TEST_DROP_INITIAL_*` pattern: `X0X_TEST_`-prefixed, read once per process, on only for exactly `1`, and every proof it inflates logs a warning.

## Consequences

- The verdict (C3) can compare an admin's live key with its own, without trusting any unsigned hint. A conflicting proof (a later epoch, or the same epoch with another authenticator) shows the member is behind or forked.
- A removed admin that a member still has in its anchored set gets that member's challenge and can answer it, inflated or not (F-1, a stated residual). It never learns anything: the challenge carries only the member's own head, which it once held.
- A daemon that did not learn of its own removal still signs as an admin, with its stale head. That is what design 3.2 rule 4 handles.
- The authenticator is read from the live tree, but the information fields come from the roster. Applies process the tree before they persist the roster, so a proof made in between can carry the new epoch with the previous roster's admins, revision and binding. Those admins are a superset or the same (a promotion moves no epoch), which only makes the closure larger.
- A requester can make an admin sign at most 12 proofs a minute per room. Each answer costs a roster read, a tree lock and one signature; a challenge from ahead also costs at most one catch-up task per room (#1427's bound).
- Each challenge is a page request (about 7 KB, A5), and each proof adds about 7 KB of base64 key and signature to a response.
- Older daemons ignore `head_challenge` and `head_proof`, so a room is confirmed only through admins at A6 or later. That fits the B1 flag day.
- `challenge_admins` and `round_view` have no production caller until A7's routes.

## Validation

`named_groups/tests/head_proof.rs`:
- `authenticator_is_read_from_the_live_tree` (the owner's tree moves on with no roster change; the proof follows the tree, and S1, which missed the commit, holds another value)
- `an_admin_answers_a_challenge_with_a_signed_proof`
- `a_non_admin_answers_without_a_proof`
- `a_departed_requester_gets_no_proof` (verified and unverified; the direct call says `RequesterNotActive`)
- `a_proof_verifies_only_for_its_signer_key_requester_nonce_and_group` (every field changed, re-attribution, another key, a stranger's own proof; recording refuses a signer not asked and another requester)
- `a_replayed_proof_for_another_nonce_is_not_recorded`
- `a_proof_after_the_round_deadline_is_not_recorded`
- `a_challenge_right_after_a_page_request_still_gets_a_proof`
- `a_requester_gets_at_most_twelve_proofs_a_minute`
- `a_challenge_from_ahead_starts_the_responders_epoch_ahead_catch_up`
- `a_stale_roster_admin_commit_does_not_remove_an_anchor_admin_from_the_challenge_set`
- `an_inflating_admin_signs_the_next_epoch_and_a_random_authenticator`
- `the_member_keyed_serve_prunes_the_catchup_throttle` (A5 review r-2)

Unit tests: `mls::treekem::tests::every_member_at_an_epoch_derives_the_same_authenticator` (three members, and equality with the exporter call itself), `the_authenticator_follows_the_live_epoch_and_the_group`; `head_proof::tests::the_inflate_knob_is_off_unless_set`, `the_sign_input_names_its_domain_and_every_field`, `a_proof_verifies_only_in_canonical_form_and_for_its_signer_key`, `a_round_records_only_its_own_nonce_requester_group_and_asked_signers_in_time`, `a_requester_has_twelve_answers_a_minute_per_room`, `the_challenge_set_is_the_named_agents_and_the_roster_admins_but_never_me`.

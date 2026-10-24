# T-any-member-delivers-signed-commits: any member hands on any signed commit

- **Status:** Proposed (fork tail, survivor re-key Task A3).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A2 (`6646bd1c`)
- **Builds on:** `T-survivor-a0-upstream-catchup-port` (upstream #1337's relayed-removal rule), `T-treekem-bytes-binding-everywhere` (A1), `T-treekem-committer-leaf` (A2)
- **Drop at:** when upstream applies every commit-bearing event as its verified signer from any member, or offer it upstream (D5)

## Context

Before this change only a removal could reach a member through someone other than its author (#1337, ported in A0). A ban, an add, a rename, a policy change, a role change or an unban applied only when the author itself delivered it, because each apply arm required `actor == sender`. A member who was away when the remover went offline stayed on the epoch the removed member holds.

Two more holes were open:

- **Claimed senders (A1 review I-1).** The two engine-A doors (`POST /groups/:id/apply-metadata-event` and `POST /groups/:id/join-result/:member`) take the sender from their caller. fetch>it fills it from the relay's unauthenticated `author` field. Both applied the event as that sender, so a legacy-bound TreeKEM event, whose binding names no bytes, applied with no check that the claimed author sent those bytes. #1337's `transport_sender == author` shortcut had the same shape.
- **The actor field.** On the author path, the arms checked `actor == sender` but not that the actor signed the commit. An admin could hand on another admin's commit as its own.

## Decision

### Who an event applies as

`named_groups/signer_delivery.rs` decides, for the catch-up response handler and both engine-A doors. `catchup_apply_sender(event, transport_sender, verified)` returns the sender to apply as, or `None` to refuse. `verified` says whether the transport authenticated the sender. When it did not, the sender is a claim, and nothing is decided on it.

| Kind | Applies as | A copy its author did not deliver |
|---|---|---|
| `MemberAdded`, `MemberRemoved`, `MemberBanned`, `MemberUnbanned`, `MemberRoleUpdated`, `JoinRequestApproved`, `GroupMetadataUpdated`, `PolicyUpdated`, `GroupDeleted` | the commit's verified signer: `verify_structure` passes and `actor == commit.committed_by`. The arm then checks the signer's role on the receiver's own roster, as before. | TreeKEM bytes it carries must be named by the signed binding: commit digest and epoch, and for an add or approval, the extras over this copy's fields. A legacy-bound copy is refused. Fields no signature covers are dropped (below). |
| `JoinRequestCreated`, `JoinRequestRejected`, `JoinRequestCancelled` | the verified transport sender, so the arm keeps it with its author | refused. With no verified sender (an engine-A door) it is refused outright. |
| Everything else (`MemberJoined`, `SecureShareDelivered`, `GroupCardPublished`) | the verified transport sender, as before | n/a |

- **The author's own copy over a verified transport** applies as before, a legacy binding included. Old events keep applying.
- **A forged `actor`** names no signer, so the event is refused on every path through these doors, whoever delivers it.
- **The join-request lifecycle stays with its author.** None of it advances an epoch, and each applies fields its commit does not cover: the request's message, KEM public key and KeyPackage (`JoinRequestCreated`), and the reviewer and the request it closes. A deliverer could otherwise swap the KEM key a later secret share is sealed to.

`admit` returns the sender and the copy to apply. It replaces A0's `verified_catchup_member_removed_author` and `catchup_may_apply_removed_as_author`, which are gone.

### The engine-A doors

- **`apply-metadata-event`.** The self-signed original `MemberJoined` is still checked against the claimed sender by the joiner's own signature. Every other admitted event goes through `admit` with `verified = false`: it applies as its signer, under the non-author rules. A legacy-bound TreeKEM event and every join-request lifecycle event get 422 (`needs_verified_signer_and_named_tree_bytes`, `author_only_event_needs_verified_sender`).
- **`join-result/:member`.** The result applies as its signer under the non-author rules. The expected-inviter check (`validate_join_result_inviter`) now runs against the signer. A legacy-bound result gets 422.

### What else changed at the receiver

- **A removal must take its target out (A2 review m-1).** `process_treekem_commit_after_crypto_recheck` now takes the departing member of a removal or ban. After `process_commit`, if this member holds the target's committed package and that package is still on a live leaf, the tree rolls back and the commit is refused (`departing_leaf_not_blank`). A legacy binding names no bytes, so without this the actor's other commit at the same epoch would pass every other check.
- **The add check fails closed (A1 review m-4).** `treekem_add_binding_admits` refused only an unparseable binding that contained `:commit=`. It now refuses every `treekem:` binding that is none of the written forms (`treekem:epoch=5:Commit=…`, a junk `;` suffix). Another plane's binding (for example `gss:epoch=<n>`) names no TreeKEM bytes and is treated like a legacy one: it applies only from its author over a verified transport, because `signer_delivery` refuses any non-author copy whose binding does not name its bytes.
- **`PolicyUpdated`'s revision is capped.** `policy_revision` took `max(event revision, current)`, so any copy could set it to `u64::MAX`. It now goes through the same `[current, current + 1]` clamp as the roster revision.

### Unsigned-field audit (F-2)

The signed roster commit covers its group id and revision, the previous state hash, the roster root (each Active or Banned member's id, role, state and certificate digest), the policy hash, the public metadata hash (name, description, tags, avatar, banner, Home digest), the security binding and `withdrawn` (`state_commit.rs`). A1's binding adds the TreeKEM commit digest and epoch, and an add's extras. Everything else an event applies is listed here.

| Kind | Field the commit does not cover | Treatment |
|---|---|---|
| `JoinRequestApproved` | `request_id` | Lookup key only. The arm applies the approval only to a pending request whose requester is the event's `requester_agent_id`, and `JoinRequestCreated` refuses a second pending request from one requester. Any other value is refused, never applied to another request. |
| | `requester_agent_id` | Covered: the roster root seats it. |
| | `actor` (written as `reviewed_by` and `added_by`) | Must be the verified signer. |
| | `revision` (roster revision) | Capped, see below. |
| | `treekem_key_package_hash`, Welcome (`treekem_welcome_b64` or `welcome_ref`) | TreeKEM plane: in A1's extras, and a non-author copy must name them. Shared-secret plane: the arm does not use them; dropped from a non-author copy. |
| | `treekem_commit_b64`, `treekem_epoch` | In A1's binding; a non-author copy must name them. |
| | the request's own KeyPackage (from the local pending request) | Seated only when it hashes to the bound package hash. |
| `MemberAdded` | `display_name` | TreeKEM plane: in the extras. Shared-secret plane: dropped from a non-author copy. |
| | `treekem_key_package_hash`, Welcome | As for `JoinRequestApproved`. |
| | `treekem_commit_b64`, `treekem_epoch` | In the binding. |
| | `actor` (`added_by`) | Must be the verified signer. |
| | `revision` | Capped. |
| | `certificate_b64` | Covered: its digest is in the roster root, and bytes that contradict it are not installed. |
| | `owner_mandate` | TreeKEM plane: its digest is in the extras (A3 review I-1), so a copy without the mandate it was sealed with is refused, from any deliverer and from the author alike. The receiver never warn-accepts it as absent, and the author's full copy still applies and records the capability. Shared-secret plane: no binding slot, so a deliverer can strip it and the arm warn-accepts an authority not yet seen with a mandate (known limit; Noetic rooms are TreeKEM). Since A4 the stripped copy, if it lands first, is also the one logged and served after restarts. |
| | `member_joined_recovery`, `member_recovery_history` | Each entry carries the authority's attestation and is verified (`verify_authority_attested_member_joined_recovery`). A deliverer can only drop entries. |
| | `roster_certificates_b64` | Each entry is installed only when it hashes to a committed seat digest and verifies under the group owner. |
| `MemberRemoved` | `actor` (`removed_by`) | Must be the verified signer. |
| | `revision` | Capped. |
| | `treekem_commit_b64`, `treekem_epoch` | In the binding, and the commit must blank the target's leaf. |
| | `secret_epoch` | Shared-secret plane: written into the binding as `gss:epoch=<n>`, which the state hash covers. TreeKEM plane: ignored when the TreeKEM payload is present. Refused on a self-leave. |
| `MemberBanned` | as `MemberRemoved` | as `MemberRemoved` |
| `MemberUnbanned` | `actor`, `revision` | Signer; capped. The member's new state is in the roster root. |
| `MemberRoleUpdated` | `actor`, `revision` | Signer; capped. The role is in the roster root. |
| `GroupMetadataUpdated` | `actor`, `revision` | Signer; capped. The name and description are in the public metadata hash. |
| `PolicyUpdated` | `actor` | Must be the verified signer (the arm ignored it before). |
| | `revision` (`policy_revision`) | Capped (was unbounded). |
| `GroupDeleted` | `actor`, `revision` | Signer (already required by its arm); capped. |
| every kind | `group_id` | Resolves the local group. The commit's group id is checked against the group's stable id. |

**The roster revision (A1 report concern 7) is capped, not bound.** It is an unauthenticated counter, separate from the signed state revision. Every apply path adopts it only through `adopt_roster_revision`, which keeps it in `[current, current + 1]`, and it is never an admission input: the signed chain (exact revision + 1 and previous-hash link) is. So the most a deliverer can do is hold one receiver's counter back by one step. Binding it is not possible for the kinds that carry no TreeKEM bytes, which have no binding slot, and would add a wire change that buys nothing.

## Consequences

- A member who was away gets a removal, ban, add, rename, policy, role or unban change from any member that holds it. A4 (`T-catchup-log-on-disk`) keeps every commit-bearing kind in the catch-up log, on disk, so a member can serve the non-TreeKEM ones too.
- The engine-A doors no longer apply a legacy-bound TreeKEM event or a join-request lifecycle event. A device on the old pin that relays its legacy events through the relay log is stranded by them; this joins the A1 flag day (every device moves at the pin flip, B1).
- On the engine-A doors, a shared-secret-plane add applies without its display name and KeyPackage hash. TreeKEM groups, which are what Noetic uses, are unaffected.
- The A0 shortcut (`transport_sender == author`) is kept, but only for a verified transport (`signer_delivery.rs`, `catchup_apply_sender`). On it, the author still delivers its own legacy-bound events. A claimed sender gets nothing from it.

## Validation

- `named_groups/signer_delivery.rs` unit tests: the signer from any member, a forged actor, a tampered commit, TreeKEM bytes from a non-author, the lifecycle kinds, field dropping.
- `named_groups/tests/signer_delivery.rs`: `a_survivor_delivers_a_ban`, `a_survivor_delivers_an_add`, `a_survivor_delivers_a_rename_policy_role_and_unban`, `a_legacy_bound_add_from_a_non_author_is_refused`, `a_forged_actor_field_authorises_nothing`, `join_request_lifecycle_stays_author_only`, `a_non_author_copy_applies_no_unbound_field`, the four engine-A door tests, `a_removal_whose_commit_keeps_the_target_is_refused`, and the two A2 m-4 route tests.
- `named_groups/tests/owner_mandate.rs`: `a_copy_of_an_add_without_its_owner_mandate_is_refused` (review I-1).

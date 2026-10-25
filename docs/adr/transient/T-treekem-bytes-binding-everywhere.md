# T-treekem-bytes-binding-everywhere: every TreeKEM seal names its bytes

- **Status:** Proposed (fork tail, survivor re-key Task A1).
- **Date:** 2026-10-23
- **Base:** `survivor-rekey` after A0 and A0b (`047042c4`); upstream `saorsa-labs/main` at `d3b39f18`
- **Builds on:** `T-survivor-a0-upstream-catchup-port` (upstream #1337's `treekem_commit_binding` and the relayed-removal rule)
- **Drop at:** when upstream seals every TreeKEM-bearing event under a binding that names its bytes and its unsigned fields, or offer it upstream (D5)

## Context

A signed roster commit covers the roster root, the policy, the public metadata and the `security_binding` string. It does not cover the TreeKEM commit bytes an event carries, nor an add's display name, KeyPackage hash or Welcome. Before this change every fork seal site wrote `treekem:epoch=<n>`, so:

- only an event's author could deliver it, because a deliverer could swap the TreeKEM bytes;
- a member who missed a removal had to reach the remover, which is what leaves a survivor on the old key (the survivor re-key bug);
- even the author's own copy could reach a member with its unsigned fields changed on the way (F-2).

Upstream #1337 seals only its post-leave rekey as `treekem:epoch=<n>:commit=<blake3>`.

## Decision

### The binding

Every TreeKEM seal writes

`treekem:epoch=<n>:commit=<blake3 of the TreeKEM commit>:extras=<blake3 of the extras>`

An add with a recovery record keeps its suffix after that: `...:extras=<d>;member-recovery=<hash>`. The first part is upstream's `treekem_commit_binding` with `:extras=` appended.

**Extras** is the blake3 of the postcard of every field the event applies that the roster commit does not cover:

| Event | Extras tuple |
|---|---|
| `MemberAdded` (direct add, invite add, re-key add) | `(display_name, treekem_key_package_hash, welcome)`, or, when the add carries an owner mandate, `(display_name, treekem_key_package_hash, welcome, blake3 of the postcard of the mandate)` (A3 review I-1) |
| `JoinRequestApproved` | `(None, treekem_key_package_hash, welcome)`: the event has no display name |
| `MemberRemoved` (admin removal, post-leave rekey, OwnerCertified eviction, re-key removal) | `()` |
| `MemberBanned` | `()` |

`welcome` is `Option<(content id, byte length)>`. The content id is the blake3 of the Welcome bytes, which is also the id a `WelcomeRef` names. So an add sealed with a `welcome_ref` and later served with its Welcome inlined (`get_join_result_inline`, `set_inline_welcome`) has the same extras. A copy whose inline bytes and reference disagree is refused. The reference's `source` is a fetch hint, not content, and is not bound.

`revision` (the roster revision) is not in any extras: the receiver clamps it to `current + 1` (`adopt_roster_revision`). Task A3 audits every kind's unsigned fields.

### One parser

`named_groups/treekem_binding.rs` holds `parse_treekem_binding`, the builders and the checks. Every reader uses the parser:

- `treekem_removal_binding_covers_commit` (the `MemberRemoved` and `MemberBanned` arms, the re-key link);
- `signer_delivery::catchup_apply_sender` (a copy its author did not deliver names its bytes; A3 replaced A0's `catchup_may_apply_removed_as_author`);
- `treekem_add_binding_admits` (the `MemberAdded` and `JoinRequestApproved` arms);
- the two recovery-record verifiers, which read the `member-recovery` suffix.

The parser accepts exactly the written forms: `treekem:epoch=<n>` (legacy), upstream's `...:commit=<d>`, the full form, each optionally with one recovery suffix. The epoch must be canonical decimal.

### What a receiver accepts

| Binding | Removal or ban | Add or approval |
|---|---|---|
| Names bytes (`:commit=`) | the commit digest, the epoch and the extras (absent, or the empty-tuple digest) must match | the commit digest, the epoch and the extras must match this copy's fields |
| Legacy, names nothing | accepted, as before, from its author over a verified transport only (A0's rule, A3 for every kind) | the same (A3) |
| A `treekem:` binding that is not one of the written forms | refused | refused (A3; before, an add admitted it unless it contained `:commit=`) |

The `MemberBanned` arm had no binding check and wrote the legacy binding into the state it hashed. It now checks the bytes and keeps the signed binding, so a digest-bound ban hashes. The same applies to the two fork-only returning-member receive paths: the `awaiting_rekey_by` branch of `MemberRemoved` and `apply_rekey_self_removal_link_checked`.

### Seal order (N-I6)

At every site: take a rollback snapshot, mutate the tree, set the binding from the commit bytes, then seal. Every failure after the mutation (the mutation itself, the epoch check, the seal, the recovery attestation, the persist) calls `rollback_treekem_group_after_failed_install` on the live guard. This is upstream's order (`d3b39f18` :25420-25462).

| Site | Function |
|---|---|
| admin removal | `remove_treekem_named_group_member` |
| ban | `ban_treekem_group_member` |
| post-leave reconcile | `reconcile_treekem_self_leave_rekeys` |
| OwnerCertified eviction | `owner_certified_seal_with_eviction` |
| returning-member re-key, removal then add (and role restore) | the `MemberJoined` re-key branch |
| invite add | the `MemberJoined` fresh-add branch |
| direct add | `add_treekem_named_group_member` |
| join approval | `approve_treekem_join_request` |

The owner mandate is minted before the binding is written, so the binding can name it (A3 review I-1). It signs the previous head, the roster, the policy, the metadata and the declared epoch, not the binding, so minting it first changes nothing it covers.

The creator's recovery binding at group creation (`treekem:epoch=<n>;member-recovery=<hash>`) is unchanged: it has no TreeKEM commit and no event that carries one.

A test-only seam, `NamedGroupTestRecorders::seal_force_err`, fails the next `seal_commit_owner_certified`.

## Consequences

- Any member can now deliver a removal on catch-up and have it applied as its signer. A3 extends this to every commit-bearing kind (`T-any-member-delivers-signed-commits`).
- A copy of an add whose name, KeyPackage hash or Welcome was changed is refused, from any sender, when the add was sealed under this binding. A legacy-bound add is not checked, so since A3 it applies only from its author over a verified transport; the engine-A doors, whose sender is a claim, refuse it.
- **Mixed versions: this is a flag day for removals.** A daemon at the old pin (`85bcca31`) recomputes `treekem:epoch=<n>` in its `MemberRemoved`, `MemberBanned` and re-key-link arms, so the hash no longer matches and it refuses every digest-bound removal, ban and re-key removal. A daemon at A0 accepts only the legacy and the two-part upstream forms, so it refuses them too. Both still apply digest-bound adds and approvals, whose arms copy the signed binding. Every Noetic device must move with the pin flip (Part B); a mixed group strands old devices at the first removal.
- **The owner mandate in the extras (A3 review I-1) widens the flag day to owner-certified adds.** A mandate-bearing TreeKEM add now has a different extras digest. A daemon at the old pin (`85bcca31`) copies the signed binding in its add arm, so it is unaffected. A fork daemon from A1 to A3 recomputes the extras without the mandate and refuses such adds. None of those shipped, so this only confirms that every device moves together at the pin flip (B1).
- **The mandate digest covers postcard of the whole `OwnerMandate`.** Any field added to it later, even one under `serde(default)`, changes the digest for a receiver one version behind, which then refuses the add. That is the same flag day a bump of `OWNER_MANDATE_VERSION` already implies: a new mandate field must ship with every device at once.
- **Consumers that read the epoch from the binding** must take it from the first `:`-separated field. The fetchit live tests `m6_groups_offline_live.rs` and `m6_devices_live.rs` parse `treekem:epoch=` up to `;` and must change with the pin flip.
- A fresh-add seal that fails on a pending certificate now adds to the tree and rolls it back on each retry, where before it refused before the tree moved.

## Validation

- New: `named_groups/tests/treekem_bytes_binding.rs` (admin removal, add and approval suffix, renamed add, swapped KeyPackage hash, seal failure), `epoch_ahead_catchup.rs` (`catchup_third_party_relays_a_digest_bound_rekey`, upstream #1337; `a_survivor_relays_an_admin_removal_by_catch_up`), `issue1139_back_to_back_join.rs` (`ban_add_eviction_and_rekey_removal_seal_the_digest_binding`, `the_rekey_link_checks_the_bytes_its_removal_names`), and parser unit tests in `treekem_binding.rs`.
- `relayed_removal_rejects_another_members_treekem_commit` now takes its removal from the real admin route. `catchup_legacy_binding_stays_with_the_author` seals the legacy form through a fixture, as a pre-A1 daemon would.

## Measured delta

- **Before:** every fork seal wrote `treekem:epoch=<n>`, which names no bytes. Only an event's author could deliver it, and an add's display name, KeyPackage hash and Welcome could be changed in transit.
- **After:** every seal writes `treekem:epoch=<n>:commit=<blake3>:extras=<blake3>`. A copy with swapped TreeKEM bytes, or with a changed name, KeyPackage hash or Welcome, is refused from any sender.
- **Pinned by:** `ban_add_eviction_and_rekey_removal_seal_the_digest_binding` (every seal site writes the form), `the_rekey_link_checks_the_bytes_its_removal_names`, `catchup_third_party_relays_a_digest_bound_rekey` (a third party delivers it), and the parser unit tests in `treekem_binding.rs`.
- **Recorded at A1 (`12d29551`):** `named_groups` 1007 passed, 1 failed (a GSS timing test that passes alone); `case_1427` 24 of 24.

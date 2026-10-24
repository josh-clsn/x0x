# T-treekem-committer-leaf: a re-key must come from its signer's own leaf

- **Status:** Proposed (fork tail, survivor re-key Task A2).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A1 (`12d29551`); saorsa-mls 0.3.8
- **Builds on:** `T-treekem-bytes-binding-everywhere` (A1)
- **Drop at:** when upstream ties a TreeKEM commit's committer leaf to the event's actor, or offer it upstream (D5)

## Context

A membership event carries two signatures. The actor signs the roster commit with its agent key. The TreeKEM commit is signed by a leaf key. Nothing tied the two together: `process_commit` accepts a commit from any member's leaf.

So a member could deliver the actor's event with a commit made from its own leaf, and a receiver would install a tree that member chose. A1 closes this for every event whose binding names its bytes. It stays open for legacy-bound events (`treekem:epoch=<n>`), and it fails if the actor itself binds another member's commit. The worst case: a removed member R still holds the old tree, and it hands a survivor the admin's genuine legacy removal of R, carrying R's own commit (the A1 review's I-1). Upstream has no such check.

## What the committer leaf proves

`TreeKemCommit.committer_leaf` is a plain field of the commit bytes, so reading it is reading a claim. It is, however, part of `commit_tbs`. Before it changes anything, saorsa-mls 0.3.8 `process_commit` (`treekem_group.rs:523-573`):
- verifies the signature against the KeyPackage at that leaf of the receiver's current tree;
- requires `update_path.leaf_index == committer_leaf`;
- refuses a commit that removes its own committer.

So when "the committer leaf is the actor's leaf" holds and `process_commit` then succeeds, the commit was signed by the private key behind the actor's leaf. This proves possession of the actor's leaf key. It does not prove the actor meant this commit for this event. That part is A1's binding.

## Decision

### The rule

`process_treekem_commit_after_crypto_recheck` is the only production door that processes a commit from someone else. Its callers are the `MemberAdded`, `MemberRemoved`, `MemberBanned` and `JoinRequestApproved` arms. The door now takes the event's `actor`. Under the group lock, before the rollback snapshot and before `process_commit`, it requires `committer_leaf_of(bytes) == leaf of the actor's KeyPackage` in the live tree.

### Which leaf is the actor's

The actor's leaf is the live leaf whose public keys match the actor's KeyPackage (`TreeKemMlsGroup::leaf_for_key_package`, the same matching `remove_member_verified` uses). The package must hash to the `treekem_key_package_hash` that the signed roster root commits for the actor (`state_commit.rs` roster projection). The door takes it from the first of these that holds it:

1. the roster seat's bytes (`current_member_treekem_key_package`);
2. this member's cached recovery record for the actor (`treekem_member_key_packages`), under any of the group's ids.

The wrapper's `agent_to_leaf` (`TreeKemMlsGroup::leaf_of`) is not used. It records only this instance's own leaf and the members it added itself, so a receiver never has an entry for an admin who added it.

### Every case has its own refusal

| Case | Rule | Reason |
|---|---|---|
| The commit comes from another member's leaf | refused | `committer_leaf_not_actor` |
| The commit bytes do not decode | refused | `committer_leaf_unreadable` |
| The actor's package is on no live leaf | refused | `actor_has_no_leaf` |
| The roster commits the actor's hash, but this member holds no bytes for it | refused; the package is requested (#398 lane) and the group's missed commits are pulled again (see below) | `actor_key_package_pending` |
| The roster commits no package for the actor | refused; a WARN once per group and actor | `actor_key_package_uncommitted` |
| A self-leave | it carries no commit. One that does is refused before the door (the `MemberRemoved` arm) | n/a |
| A removal by an admin, a post-leave rekey, an OwnerCertified eviction, a ban, an add, an approval, a returning-member re-key | the sealer is the actor and commits from its own leaf (every seal site sets `actor` to the local agent) | applies |
| The held-result link (`apply_rekey_self_removal_link_checked`) | it never processes a commit (`device_holds_a_tree`) | n/a |

A commit cannot remove its own committer (saorsa-mls), so an admin removing itself always takes the self-leave path.

### Joiners hold every package they need

An invite seats existing members by hash alone (`invite_join_group_info`), and `member_recovery_history` is always empty. Without more, each joiner would refuse each earlier member's first commit until a peer sent the package. Two changes remove that from the normal path:

- **A joiner seats packages from its Welcome.** The Welcome's ratchet tree holds every member's KeyPackage (`TreeKemMlsGroup::welcome_key_packages`). At both Welcome installs (`MemberAdded`, `JoinRequestApproved`), `seat_roster_key_packages_from_welcome` seats each hash-only member whose package's encoding hashes to the committed hash. The roster root is unchanged.
  - A package added by `add_member` comes back byte for byte.
  - This is safe from any deliverer, because only a package that matches the signed hash is seated.
- **The creator's leaf holds its seated bytes.** ML-DSA signing is randomized (saorsa-pqc 0.5.1 `sig.rs:352`). Group creation used to build the tree from one `identity_from_seed` call and seat a second `prepare_member` call's package, so the creator's leaf bytes never matched its seat. Creation now prepares once and builds the tree from that identity (`TreeKemMlsGroup::create_prepared`). `create` goes through the same path.

### A refused commit comes back without its sealer

A member can still hold an actor's package by hash alone: the creator of a group made before this change, as seen by a member who joined after it, or any earlier member, as seen by a member who joined before it. Three things make sure such a member does not wait on the sealer:

- **It asks early.** A seat the Welcome cannot fill is requested right after the install. Once the mesh is up (at startup, and after a deferred `POST /mesh/join`), `request_hash_only_treekem_key_packages` requests every active seat held by hash alone in every TreeKEM group, unless the recovery cache already holds matching bytes.
- **A refusal pulls the event again.** On `actor_key_package_pending`, the door requests the package and starts the #1427 epoch-ahead catch-up towards the refused commit's epoch (`pull_again_after_package`), unless one is already running for the group. That task asks the other members for the missed commits round by round, one throttle window apart, for at least six rounds and until it has asked every candidate, and stops when this member reaches the epoch. A page that arrives before the package is refused again; the next round's page installs it. The sealer's own resend schedule (#333: +6/15/30/60 s for a removal, +8 s for an add, not persisted) is not needed.
- **Stale bytes do not block the package.** `apply_targeted_member_key_package` used to keep any bytes already on the seat. It now keeps only bytes that hash to the seat's committed hash, and otherwise stores the matching package it was sent.

### A sealer with no committed package does not seal

A commit is tied to its sealer's leaf only through the KeyPackage hash the sealer's own seat commits. If that seat commits none, every receiver refuses the commit (`actor_key_package_uncommitted`) while the sealer moves on. The group splits, and the admin sees success. In a removal, the members who refused stay on an epoch the removed member holds.

So every TreeKEM seal site refuses first when the local seat commits no package hash (`sealer_seat_commits_package`). The four routes (remove, ban, direct add, approve) return 409 `sealer_key_package_uncommitted`, with a detail that names the limit. The post-leave rekey, the OwnerCertified eviction, the returning-member re-key and the invite add refuse and log the same text at WARN. Nothing is mutated, sealed or published.

## Known limits

- **Groups made before #220 (2026-07-11).** Those groups never seated the creator's KeyPackage hash, and their early members have none either. No signed event can seat it later: only `MemberAdded`, `MemberJoined` and `JoinRequestApproved` carry a package, and the #398 apply refuses a seat with no committed hash. Every TreeKEM commit from such an actor is refused at receivers, logged at WARN once per group and actor (`actor_key_package_uncommitted`). Such an actor also refuses to seal (above), so it cannot remove, ban, add, approve, evict or rekey: the route says the group must be made again. Removing such a member was already blocked at the sealer, because `remove_member_verified` needs its package. Fixing this needs a new signed event that commits a member's package, which this fork tail does not add.
- **Groups made before this change.** Their creator's leaf bytes do not match its seat, so a member who joins after this change requests the creator's package right after its install.
- **Members who joined before this change** hold earlier members by hash alone. The sweep requests those packages once the mesh is up. If an earlier member's first commit still arrives before its package, that member refuses it once, and the epoch-ahead catch-up installs it a round after the package lands. Until then it stays on the old epoch, which the removed member of a removal still holds.

## Consequences

- No wire change and no flag day of its own. Old daemons produce commits from their own leaf, which pass.
- A legacy-bound TreeKEM event that carries another leaf's commit is refused at every door, including the two engine-A doors that take a claimed sender. This closes the attack in the A1 review's I-1: a removed member's own commit. It does not close every legacy pairing: a legacy-bound removal could still carry a different genuine commit from the same actor at the same epoch (one rolled back after publishing, or a fork). No receiver checks yet that a removal's commit actually blanks the target's leaf.
- The tests are in `named_groups/tests/committer_leaf.rs`, `named_groups/committer_leaf.rs`, `named_groups/welcome_key_packages.rs` and `src/mls/treekem.rs`.

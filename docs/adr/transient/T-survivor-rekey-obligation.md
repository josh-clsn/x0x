# T-survivor-rekey-obligation: a re-key stays owed to each survivor until it is proven held

- **Status:** Proposed (fork tail, survivor re-key Tasks A9 and A10).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A8 (`e2f69e51`)
- **Builds on:** `T-catchup-log-on-disk` (A4, the payload), `T-signed-catchup-pages` (A5, the signed requests that prove a head), `T-treekem-head-proof` (A6, the challenge requests)
- **Drop at:** when upstream has a durable, proof-settled redelivery of a re-key to its survivors. Upstream's #1337 outbox covers only the post-leave re-key and settles on the send. This record is a candidate for the D5 offer.

## Context

When an admin's daemon re-keys a room (a removal, a ban, the post-leave re-key, an add, the OwnerCertified eviction, the returning-member re-key), every other member must apply the new commit, or it cannot read the room at the new epoch and keeps sealing to the old one. Before this change the daemon sent it:

- to every active member at +0 and +8 s (`spawn_named_group_event_delivery_to_active_members`);
- for removals and bans only, again at 6, 15, 30 and 60 s (`spawn_group_control_event_redelivery`, #333);
- with nothing on disk, so a restart forgot it.

A survivor away for longer than a minute, or away while the remover restarted, was stranded until something else (a later-epoch frame, #1449) made it ask. A member who missed an add had only the first two sends. That is the root of the confidentiality gap this plan closes: a stranded survivor keeps sealing at an epoch a removed member still holds.

## Decision

### The record

`<data>/treekem/rekey-obligations.json`, version 1, one entry per (room, survivor):

| Field | Meaning |
|---|---|
| `group_key` | the room's `named_groups` key |
| `recipient_hex` | the survivor |
| `owed_epoch`, `owed_revision` | the lowest epoch the survivor is not known to hold, and the signed revision sends start at |
| `through_epoch`, `through_revision` | the latest re-key owed; a proof at or past `through_epoch` settles |
| `state` | `owed` or `delivered_unproven` |
| `next_attempt_at_ms`, `attempt_count` | the schedule |

`in_flight` is kept in memory only, so nothing is in flight after a restart.

- **Coalesced.** A later re-key widens the existing entry: the lowest owed, the highest to prove. It resets the entry to `owed` with its first wait, and never makes a due send later. The brief's record shape had one `owed_epoch`; one value cannot both start the sends at the first missed commit and refuse to settle before the last, so the entry holds both ends.
- **The payload is not copied.** At send time the worker reads the A4 log: every commit-bearing event of the room from `owed_revision`, in revision order, at most 16 a send. The renames and role changes in between ride along, so the chain links.
- **Written like the A4 log.** A fixed file name, a temp file at mode 0600, synced, renamed, the directory synced, on the blocking pool (inline under the W3-H shim). Nothing a peer sends becomes part of a path, and the file names only roster ids and numbers.
- **Loaded fail-safe.** Startup keeps an entry only if it is well formed, the room is in the roster and not withdrawn, this daemon is an active member not banned from it, the survivor is still an active member, and the caps hold. A due time is clamped to at most the longest wait from now. A file that does not read back loads nothing (logged at warn) and is replaced at the next write; the survivors it named are left to catch-up (#1449, A5). The bootstrap outbox refuses to start instead; a daemon that will not start strands every room, so this record does not.

### Caps and the blind schedule

- **256 per room, 4096 in all.** A new entry past either cap is refused. Nothing owed is dropped to make room, and an existing entry still takes a later re-key at the cap.
- **A refused survivor keeps the blind schedule.** `owe` returns the survivors it did not record: past a cap, all of them when the file cannot be written (memory is put back, so memory and disk agree), and all of them when the room is gone. The re-key site hands those to `spawn_group_control_event_redelivery` (A10).

### The worker

- **Its own task**, a step every 5 s, started in `serve_with_options`. A step drops entries no longer owed (the room or the survivor gone, as at load), then starts the due sends, at most 4 in flight in all, each in its own task. A step never waits on a send, so steps never overlap or queue, and an entry in flight is never started twice.
- **Off the listener paths.** The metadata and catch-up listeners never wait on a send (the agent-quiet evidence: the catch-up listener is serial, with 24 s acknowledgement waits). Each event's send has a 30 s timeout and a whole send 2 min, so a send that hangs holds its slot for at most 2 min and counts as failed.
- **The send** is `named_group_event_delivery_result`, the `Result`-returning sibling of the delivery future, with its control-blob path for large events and its cold-wait for removals.
- **Backoff:** 6, 15, 30 and 60 s, then doubling to 15 min. The first send is 6 s after the re-key, where the old blind schedule's first resend was; the +0 and +8 s sends are unchanged.
- **A connect edge sends at once.** A survivor that `is_agent_connected` reports linked, and that was not linked at the last step, is due at once, `delivered_unproven` included. An edge with every slot busy stays due. The first step after a start counts every linked survivor as an edge.
- **An acknowledgement is not proof.** `require_gossip_ack` waits for the survivor's DM-inbox acknowledgement, which comes before the apply; the event can still be queued on a gap, refused, or dropped on a full route. A fully acknowledged send moves the entry to `delivered_unproven`, sent again at the 15 min cap and at the next connect edge.
- **A payload the log cannot serve** (evicted, or never logged) keeps the entry on its backoff, and is said once per owed revision at warn.

### Wipe

`wipe_local_group_crypto_material` removes the room's entries, under every alias, in memory and on disk. As for the A4 log, `owe` re-checks the roster under the obligations lock, and every departure drops or tombstones the room before its wipe, so an `owe` racing a wipe is either removed by it or finds the room gone.

Lock order: `rekey_obligations`, then `named_groups`. Nothing takes `rekey_obligations` while it holds `named_groups` or `treekem_event_log`.

### Where obligations are written (A10)

Every TreeKEM re-key site of A1 calls `owe_survivors` after its commits are durable and before its first publish, so the obligation is on disk before the route (or the apply) returns. The survivors are the active members after the change, less this daemon and the member the change took out or seated.

| Site | Owed | Not owed | Blind schedule's direct sends |
|---|---|---|---|
| Admin removal (`remove_treekem_named_group_member`) | the survivors | the removed member | the removed member, and any survivor refused |
| Ban (`ban_treekem_group_member`) | the survivors | the banned member | the banned member, and any survivor refused |
| Post-leave re-key (`reconcile_treekem_self_leave_rekeys`) | the remaining members | the leaver | any survivor refused (the gossip republish still runs) |
| OwnerCertified eviction (`owner_certified_seal_with_eviction`) | the members left seated | the evicted member | any survivor refused (there was no blind schedule before) |
| Returning-member re-key (the `MemberJoined` arm) | the other members, both commits (`owed` at the removal, `through` at the add) | the returning member, which gets its Welcome | the returning member, and any survivor refused |
| Invite add (the `MemberJoined` arm, TreeKEM only), direct add, approval | every member the add did not seat | the member seated, which gets its Welcome | any survivor refused (there was no blind schedule before) |

`spawn_group_control_event_redelivery` gains `recipients_override`. With it, the direct sends go to exactly those recipients; without it, as before. The gossip republish at each offset runs either way. The +0 and +8 s volley to every member is unchanged. The GSS-plane sites, `GroupDeleted` and the role restore after a returning-member re-key keep the old schedule (`None`).

### What settles an obligation (A10)

Only the survivor's own evidence, never a claimed sender:

- **A catch-up or challenge request** (`handle_treekem_catchup_request`, after its membership gate, for an active requester) whose requester is proven: the transport verified the sender, and the sender is the requester; or the requester signed the request over its head (A5's page-request signature, which covers `from_revision`, `from_treekem_epoch` and the challenge). A member-keyed request's signature does not cover a head, so over an unverified transport it settles nothing. A challenge is a page request with `head_challenge`, so it takes the same path. The settle runs in its own task, so the serial catch-up listener never waits on the file write.
- **A challenge through `POST /groups/:id/treekem/head-proof`** (the relay leg): the route already requires the requester's signature (`SignedChallenge::from_request`), so the same proof settles.
- **A decrypt at or past the epoch** (`treekem_group_decrypt_for_actor`): `decrypt_message_with_sender` names the leaf that sent the message. `saorsa-mls` checks the sender's signature over the envelope against that leaf's key package before it decrypts, and the message decrypts only at this tree's own epoch. The leaf is matched against the KeyPackage each owed survivor's seat commits (the A2 rule, not `agent_to_leaf`, which holds only the members this daemon added). The KeyPackages are read before the tree lock and matched under it.
- **The survivor leaving or being removed, or the room being withdrawn:** the worker's step drops any entry whose survivor is no longer an active member, and a withdrawal wipes the room.

A proof at or past `through_epoch` removes the entry. A proof between `owed_epoch` and `through_epoch` moves `owed_epoch` (and, from a request, `owed_revision`) on, and leaves the rest owed. Anything below changes nothing. A replayed request was signed by the survivor at the head it names, so it cannot prove more than the survivor once held, and it cannot move a schedule.

## Consequences

- A survivor away for any time, across the remover's restarts, gets the re-key when it is next linked, at most 15 minutes after it is reachable without a link edge.
- The worker sends more than before only to survivors that have not proven their head, at most 4 sends at once.
- The file holds at most 4096 short entries.
- A refused survivor is no worse off than before this change.
- **A removed or non-member peer cannot settle or put off another member's obligation.** It cannot produce the survivor's signature, a verified transport as the survivor, or a message signed by the survivor's leaf at the new epoch. Nothing a peer sends moves a send time, so it cannot put one off either.
- **Known limits.**
  - A survivor that missed a join request cannot apply the approval, from anyone (A3 review m-10, pre-existing). Its obligation stays `delivered_unproven`, sent every 15 min, until it catches up some other way.
  - A store record's decrypt (`routes/stores.rs`) is not a proof here; only the secure decrypt route is.
  - A survivor that never comes back, and never leaves the roster, is sent the re-key every 15 min for as long as it stays on the roster.

## Validation

A10: `named_groups/tests/rekey_obligation_proofs.rs` (the survivor fixture, through the real routes), `tests/issue1139_back_to_back_join.rs` (`eviction_and_rekey_removal_owe_survivors`) and `mls::treekem` (`a_decrypt_names_the_leaf_that_sent_it`): every site owes its survivors and not the member it took out or seated; the obligation is on disk when the route returns; a signed or verified request, a challenge over x0x or the route, and a decrypt each settle; a request below the epoch, a claimed sender, another member's signature, a removed member's transport and a member-keyed request's unsigned head settle nothing; leaving and withdrawal drop it; the removed member keeps the blind schedule and a refused survivor joins it; a survivor away past the old 60 s horizon gets the key from the obligation on its return; a survivor away while the remover restarted gets the key from another survivor, and its message settles the restarted remover's obligation.

A9: `named_groups/rekey_obligations.rs` (unit, a paused clock for the timings) and `named_groups/tests/rekey_obligations.rs` (the worker on a daemon's state, with a stand-in network): coalescing, restart, backoff, an acknowledgement without proof, the connect edge, at most four in flight and none twice, both caps, a refused or unwritten obligation, a missing payload said once, and a departure's wipe.

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

Sends in flight are kept in memory only, in their own set with an attempt id each (fix round m-1), so nothing is in flight after a restart, and a settle or a wipe during a send leaves its slot taken until the send returns. Only state changes reach disk (m-2): an obligation owed or widened, delivered (`owed` to `delivered_unproven`), settled, dropped or wiped. A failed send's new due time and count stay in memory, so after a restart a survivor may be sent at once.

- **Coalesced.** A later re-key widens the existing entry: the lowest owed, the highest to prove. It resets the entry to `owed` with its first wait, and never makes a due send later. The brief's record shape had one `owed_epoch`; one value cannot both start the sends at the first missed commit and refuse to settle before the last, so the entry holds both ends.
- **The payload is not copied.** At send time the worker reads the catch-up event log (`treekem_event_log`, A4; not `GroupInfo::commit_log`, which the held-already check of the proof reads): every commit-bearing event of the room from `owed_revision`, in revision order, at most 16 a send. The renames and role changes in between ride along, so the chain links.
- **Written like the event log.** A fixed file name, a temp file at mode 0600, synced, renamed, the directory synced, on the blocking pool (inline under the W3-H shim). Nothing a peer sends becomes part of a path, and the file names only roster ids and numbers.
- **Loaded fail-safe.** Startup keeps an entry only if it is well formed (`owed_epoch <= through_epoch`, `owed_revision <= through_revision`), the room is in the roster and not withdrawn, this daemon is an active member not banned from it, the survivor is still an active member, and the caps hold. A due time is clamped to at most the longest wait from now.
- **An unreadable file is set aside, and the daemon owes more, not less** (fix round I-3). A file that does not parse, names another version (a downgrade or an upgrade), or cannot be read is renamed to `rekey-obligations.json.unreadable-<ms>` and never overwritten, logged at `error`, and named in the catch-up status (`rekey_obligations.unreadable_file_set_aside`). The daemon still starts: a daemon that will not start holds every room, and catch-up stands behind this record (the bootstrap outbox refuses to start because it has no such fallback). In place of what was lost, in every live TreeKEM room this daemon administers, every other active member is owed the room's current epoch, from the earliest commit this daemon authored that the event log still holds (else the head). A member already there settles on its next request, challenge or message; over-owing costs only sends, within the caps. If the file cannot be renamed, the obligations are kept in memory only, so nothing writes over it.

### Caps and the blind schedule

- **256 per room, 4096 in all.** A new entry past either cap is refused. Nothing owed is dropped to make room, and an existing entry still takes a later re-key at the cap.
- **A refused survivor keeps the blind schedule.** `owe` returns the survivors it did not record: past a cap, all of them when the file cannot be written (memory is put back, so memory and disk agree), and all of them when the room is gone. The re-key site hands those to `spawn_group_control_event_redelivery` (A10).

### The worker

- **Its own task**, a step every 5 s, started in `serve_with_options`. A step drops entries no longer owed (the room or the survivor gone, as at load), then starts the due sends, at most 4 in flight in all, each in its own task. A step never waits on a send, so steps never overlap or queue, and an entry in flight is never started twice.
- **Off the listener paths.** The metadata and catch-up listeners never wait on a send or a settle (the catch-up listener and the head-proof route spawn theirs, fix round m-4) (the agent-quiet evidence: the catch-up listener was serial, with 24 s acknowledgement waits; A12 makes it answer side by side, `T-catchup-off-the-apply-path.md`). Each event's send has a 30 s timeout and a whole send 2 min, so a send that hangs holds its slot for at most 2 min and counts as failed.
- **The send** is `named_group_event_delivery_result`, the `Result`-returning sibling of the delivery future, with its control-blob path for large events and its cold-wait for removals.
- **Backoff:** 6, 15, 30 and 60 s, then doubling to 15 min. The first send is 6 s after the re-key, where the old blind schedule's first resend was; the +0 and +8 s sends are unchanged.
- **A connect edge sends at once** (fix round I-1, m-3). A survivor is linked when this daemon has a live direct connection to it (`has_live_direct_connection`, which also asks the DM registry, so a phone that never reaches the discovery cache counts), with its A8 link id when presence names one (the authenticated link's generation). An edge is a survivor linked now that was not linked at the last step, or whose link id changed, so a drop and a reconnect between two steps is seen. An edge makes the survivor's obligations due at once, `delivered_unproven` included, but never sooner than 60 s after the last send to the same obligation; within that floor the edge is kept as a due time at the floor's end, not lost. An edge that fires (outside the floor; fix round 2, m-N2: one inside the floor leaves the count, so a flapping link still climbs) also restarts an `owed` obligation's backoff from the first wait: a linked survivor is not the unreachable case the backoff is for, so a send that fails at the edge (the link not yet carrying messages) is retried in 15 s, not at the 15 min a long absence built up. `case_1427`'s signer arm found this. A false positive costs a send. The first step after a start counts every linked survivor as an edge.
- **Ranking** (fix round I-2). Due sends start in this order: a connect edge this step, then a first attempt, then `owed` before `delivered_unproven`, then the due time. So a backlog of unreachable survivors, which can hold every slot for up to 30 s a send, never holds back a survivor that just linked or a fresh re-key once a slot frees.
- **An acknowledgement is not proof.** `require_gossip_ack` waits for the survivor's DM-inbox acknowledgement, which comes before the apply; the event can still be queued on a gap, refused, or dropped on a full route. A fully acknowledged send moves the entry to `delivered_unproven`, sent again at the 15 min cap and at the next connect edge.
- **A payload the log cannot serve** (evicted, or never logged) keeps the entry on its backoff, and is said once per owed revision at warn.

### Wipe

`wipe_local_group_crypto_material` removes the room's entries, under every alias, in memory and on disk. As for the event log, `owe` re-checks the roster under the obligations lock, and every departure drops or tombstones the room before its wipe, so an `owe` racing a wipe is either removed by it or finds the room gone.

Lock order: `rekey_obligations`, then `named_groups`. Nothing takes `rekey_obligations` while it holds `named_groups` or `treekem_event_log`.

### Where obligations are written (A10)

Every TreeKEM re-key site of A1 appends its events to the event log, then calls `owe_survivors`, then publishes (fix round m-6: a crash between the two writes can no longer leave an obligation whose payload the log does not hold). So the obligation is written after the commits are durable and before the first publish, so the obligation is on disk before the route (or the apply) returns. The survivors are the active members after the change, less this daemon and the member the change took out or seated.

| Site | Owed | Not owed | Blind schedule's direct sends |
|---|---|---|---|
| Admin removal (`remove_treekem_named_group_member`) | the survivors | the removed member | the removed member, and any survivor refused |
| Ban (`ban_treekem_group_member`) | the survivors | the banned member | the banned member, and any survivor refused |
| Post-leave re-key (`reconcile_treekem_self_leave_rekeys`) | the remaining members | the leaver | any survivor refused (the gossip republish still runs) |
| OwnerCertified eviction (`owner_certified_seal_with_eviction`) | the members left seated | the evicted member | any survivor refused (there was no blind schedule before) |
| Returning-member re-key (the `MemberJoined` arm) | the other members, both commits (`owed` at the removal, `through` at the add) | the returning member, which gets its Welcome | the returning member, and any survivor refused |
| Invite add (the `MemberJoined` arm, TreeKEM only) | every member the add did not seat | the member seated, which gets its Welcome and can poll its join result | any survivor refused (there was no blind schedule before) |
| Direct add (`add_treekem_named_group_member`), approval (`approve_treekem_join_request`) | every member, the member seated included (A13: its seat, until it proves it; `T-seat-obligation.md`) | none | any member refused: the seated member gets direct sends only, no republish (A12); a survivor gets the republish too |

`spawn_group_control_event_redelivery` gains `recipients_override`. With it, the direct sends go to exactly those recipients; without it, as before. The gossip republish at each offset runs either way. The +0 and +8 s volley to every member is unchanged. The GSS-plane sites, `GroupDeleted` and the role restore after a returning-member re-key keep the old schedule (`None`).

### The survivor proves what its author sent it (fix round I-5)

A survivor that applied a re-key and then stays quiet proves nothing, so without more its obligation would stay `delivered_unproven` and be re-sent every 15 min for good. Every add owes every seated member, so on a phone admin that would be the steady state.

So when a commit-bearing event that names a TreeKEM epoch reaches a daemon directly (the direct-message listener and the control-blob path, `apply_direct_named_group_metadata_event`) from its own signer over a verified transport, and the daemon's live tree is at or past that epoch afterwards (applied now, or before), and, after the apply, the event applied (accepted now, or this daemon's chain already holds that same signed commit from that signer, so a gossip-first survivor still answers) and its author is an active, unbanned member with at least the Admin role in this daemon's roster (fix round 2, N-1: a stranger, a removed member or a demoted admin learns nothing of this daemon's head, and none of them takes the room's slot), the daemon sends that author one signed page request from its head (`signed_catchup::page_request`, an existing message: no wire change). It goes in its own task, off the listener, at most once per room per 5 s (`HELD_PROOF_GAP`, A7's `ROUND_MIN_GAP`), through a `{room}:rekey-held` key in the catch-up throttle, which the room wipe already clears. The author's catch-up handler settles on it like any signed request. Gossip copies and copies from anyone but the signer ask nothing.

The catch-up status (`GET /groups/:id/treekem/catch-up`) reports `rekey_obligations: {owed, unproven, room_owed, room_unproven, unreadable_file_set_aside}`, so a soak can read what is left.

### What settles an obligation (A10)

Only the survivor's own evidence, never a claimed sender:

- **A catch-up or challenge request** (`handle_treekem_catchup_request`, after its membership gate, for an active requester) whose requester is proven: the transport verified the sender, and the sender is the requester; or the requester signed the request over its head (A5's page-request signature, which covers `from_revision`, `from_treekem_epoch` and the challenge). A member-keyed request's signature does not cover a head, so over an unverified transport it settles nothing. A challenge is a page request with `head_challenge`, so it takes the same path. The settle runs in its own task, so the answer never waits on the file write.
- **A challenge through `POST /groups/:id/treekem/head-proof`** (the relay leg): the route already requires the requester's signature (`SignedChallenge::from_request`), so the same proof settles.
- **A decrypt at or past the epoch** (`treekem_group_decrypt_for_actor`, any spelling of the room, settled under its roster key, fix round m-7): `decrypt_message_with_sender` names the leaf that sent the message. `saorsa-mls` checks the sender's signature over the envelope against that leaf's key package before it decrypts, and the message decrypts only at this tree's own epoch. The leaf is matched against the KeyPackage each owed survivor's seat commits (the A2 rule, not `agent_to_leaf`, which holds only the members this daemon added). The KeyPackages are read before the tree lock and matched under it.
- **The survivor leaving or being removed, or the room being withdrawn:** the worker's step drops any entry whose survivor is no longer an active member, and a withdrawal wipes the room.

A proof at or past `through_epoch` removes the entry. A proof between `owed_epoch` and `through_epoch` moves `owed_epoch` (and, from a request, `owed_revision`) on, and leaves the rest owed. Anything below changes nothing. A replayed request was signed by the survivor at the head it names, so it cannot prove more than the survivor once held, and it cannot move a schedule.

## Consequences

- A survivor away for any time, across the remover's restarts, gets the re-key when it is next linked, at most 15 minutes after it is reachable without a link edge.
- The worker sends more than before only to survivors that have not proven their head, at most 4 sends at once.
- The file holds at most 4096 short entries.
- A refused survivor is no worse off than before this change.
- **A removed or non-member peer cannot settle or put off another member's obligation.** It cannot produce the survivor's signature, a verified transport as the survivor, or a message signed by the survivor's leaf at the new epoch. Nothing a peer sends moves a send time, so it cannot put one off either.
- **Known limits.**
  - **A request's epoch is not bound to the head's authenticator** (review m-5). On a same-epoch fork (two admins committing at e concurrently, or a removed admin's branch), a survivor at e+1 on the other branch settles this daemon's obligation for an e+1 it does not hold. A6's conflict rule (another authenticator at the same epoch is Behind) and fork quarantine catch it on the survivor's next round, so it delays rather than leaks. Binding the authenticator into the signed request is a wire change, left to D5.
  - A survivor that missed a join request cannot apply the approval, from anyone (A3 review m-10, pre-existing). Its obligation stays `delivered_unproven`, sent every 15 min, until it catches up some other way.
  - A store record's decrypt (`routes/stores.rs`) is not a proof here; only the secure decrypt route is.
  - A survivor that never comes back, and never leaves the roster, is sent the re-key every 15 min for as long as it stays on the roster.

## Validation

A10: `named_groups/tests/rekey_obligation_proofs.rs` (the survivor fixture, through the real routes), `tests/issue1139_back_to_back_join.rs` (`eviction_and_rekey_removal_owe_survivors`) and `mls::treekem` (`a_decrypt_names_the_leaf_that_sent_it`): every site owes its survivors and not the member it took out or seated; the obligation is on disk when the route returns; a signed or verified request, a challenge over x0x or the route, and a decrypt each settle; a request below the epoch, a claimed sender, another member's signature, a removed member's transport and a member-keyed request's unsigned head settle nothing; leaving and withdrawal drop it; the removed member keeps the blind schedule and a refused survivor joins it; a survivor away past the old 60 s horizon gets the key from the obligation on its return; a survivor away while the remover restarted gets the key from another survivor, and its message settles the restarted remover's obligation.

A9: `named_groups/rekey_obligations.rs` (unit, a paused clock for the timings) and `named_groups/tests/rekey_obligations.rs` (the worker on a daemon's state, with a stand-in network): coalescing, restart, backoff, an acknowledgement without proof, the connect edge, at most four in flight and none twice, both caps, a refused or unwritten obligation, a missing payload said once, and a departure's wipe.

## Residuals

- **m-5: a request's epoch is not bound to the head authenticator.** See "Known limits" above. A6's conflict rule is the backstop: another authenticator at the same epoch is Behind, and fork quarantine catches the fork on the survivor's next round.
- **A demoted daemon does not re-derive its old obligations after a restart.** The loader keeps an obligation only if this daemon is an active member of the room. The unreadable-file path re-owes only rooms this daemon administers now. A daemon demoted from admin while it owed survivors loses nothing at once, but if the file is then lost or unreadable it does not owe them again.
- **A coalesced obligation sends from the lowest owed revision, so the re-key comes last in the batch.** With `owed_revision` at the first missed commit and 16 events a send, a survivor that already holds the earlier commits is sent them again before the re-key. Skipping revisions the survivor's last proven head covers is not done.

## Cross-target check, owed at B1

`cargo check --target x86_64-pc-windows-msvc` and an `aarch64-apple-darwin` check are owed at B1, because this tail adds file writes (`rekey-obligations.json`, `event-log/`, `head-challenge-counter`) and `cfg(unix)` gates. Neither ran on the build box on 2026-10-25: `rustup target list --installed` lists neither target, and both `cargo check --target ... -p x0x --lib` runs stopped in the `aws-lc-sys` build script, whose C compile needs a cross C toolchain the box does not have (the `x0x` crate itself was never reached). Nothing was installed. A4 had also found the Windows check blocked (MSVC not installed), and audited every `std::os::unix` use as gated. Both checks stay owed to a machine that has the toolchains.

## Measured delta

- **Before:** a re-key was sent to every active member at +0 and +8 s, and for removals and bans again at 6, 15, 30 and 60 s, with nothing on disk. A survivor away longer than a minute, or away while the remover restarted, stayed on the old key.
- **After:** each (room, survivor) is recorded in `rekey-obligations.json` and resent with a backoff of 6, 15, 30 and 60 s, then doubling to 15 min, until the survivor proves its head. A connect edge sends at once, at most 4 sends run at once, and 256 per room and 4096 in all are held. A sent commit is `delivered_unproven` until a signed request, a head-proof challenge or a decrypt at or past `through_epoch` settles it.
- **Pinned by:** `a_decrypt_names_the_leaf_that_sent_it` (`mls::treekem`); `eviction_and_rekey_removal_owe_survivors` (`tests/issue1139_back_to_back_join.rs`); the survivor fixture in `named_groups/tests/rekey_obligation_proofs.rs`; the worker tests in `named_groups/tests/rekey_obligations.rs`; and `w3h_1427_*` in `src/server/w3h/case_1427.rs`, whose three arms are the returning member converging by obligation, by the lost-sends arm, and past three offline admins.
- **Recorded:** A9 plus A10 report `named_groups` 1180 passed, 0 failed; `case_1427` 6 of 6 after A9 and 6 of 6 after A10. At `209cf10c` the controller's full `--lib` run gave 4562 passed and 6 failed, exactly the six `w3h_1143` (2) and `w3h_1207` (4) cases, which fail in one process and pass alone.

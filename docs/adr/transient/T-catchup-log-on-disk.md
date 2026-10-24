# T-catchup-log-on-disk: every commit a member applied can be served after a restart

- **Status:** Proposed (fork tail, survivor re-key Task A4).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A3 (`9829edcb`)
- **Builds on:** `T-any-member-delivers-signed-commits` (A3)
- **Drop at:** when upstream's S5 (fetch-by-hash of exact evidence from any holder, ADR 0088/0111) lands: move catch-up to it and drop this log. Upstream will not keep a catch-up log on disk (D54), so this record is a stopgap, not an upstream candidate as it stands (see "Relation to upstream").

## Context

A member answers a TreeKEM catch-up request from its `treekem_event_log` (`handle_treekem_catchup_request`). Two gaps were left after A3:

- **The log lived only in memory.** A restart emptied it, so a member that restarted could serve nothing it applied before. Upstream re-seeds it at startup only from its self-leave outbox (#1337, `resume_durable_self_leave_rekeys`), which the fork does not carry.
- **It held only the TreeKEM membership kinds** (`MemberAdded`, `MemberRemoved`, `MemberBanned`, `JoinRequestApproved`). A3 lets any member hand on a rename, a policy change, a role change or an unban, but no member logged one. Each of them advances the signed state revision, so a member who missed one could not link any later commit, and the page a survivor served stopped at the gap.

## Decision

### What is logged

Every event whose `commit` is set, through `commit_bearing_event_frontier`: the nine signer-delivered kinds and `JoinRequestRejected`, except:

- **`JoinRequestCreated` and `JoinRequestCancelled` are not logged.** Their author is the requester, who is not a member and never serves catch-up, and they apply only from their author (A3). No member's copy can help another member, and logging them would let any stranger fill the log of a request-access room (A4 review I-2).
- **A `GroupDeleted` is not kept:** it withdraws the room, and a withdrawn room is wiped.

Each is logged where it is applied (the apply arm, after the durable persist) and by its author (the route, after the publish). The revision is the signed commit's revision, never the event's unsigned roster revision. A page is sorted by `(commit revision, TreeKEM epoch)` on both the serve and the receive side, so a rename and a removal arrive in chain order.

### Layout

`<data>/treekem/event-log/<blake3(group key)[..32]>/<revision:020>-<epoch:020>-<kind>-<blake3(event)[..16]>.json`

- The group key is the event's `group_id`, as the in-memory map uses it. Every path component is a hex digest, a zero-padded number or a fixed kind name (`named_group_metadata_event_kind`). Nothing a peer sends becomes part of a path.
- The digest in the name separates two events that share a revision, an epoch and a kind. In memory one commit is logged once: the dedup key is the kind, the revision, the epoch, the signer and the commit's state hash.
- A room's `evicted-through` file holds the highest revision it lost (below).
- An event over 512 KiB (`EVENT_LIMIT_BYTES`) is not kept at all, in memory or on disk, and its revision is recorded as lost at once (A4 re-review I-4: holding it in memory let one admin grow a phone's memory by up to about 1 GiB per room). Typical sizes: a Welcome-bearing add is 40-52 KiB; one carrying a full 32-certificate roster sidecar is about 360 KiB. So a room holds at most 128 × 512 KiB = 64 MiB, in memory and on disk.

### Writes

- The file is written to `.<name>.<pid>.tmp` created at mode 0600, synced, renamed into place, and then the directory is synced. A newly created room directory (mode 0700) is also synced into `event-log/`. Directory syncs use `sync_dir_contents`, a no-op off unix, so Windows does not report every append as failed.
- A failed event write logs, does not keep the event, and records its revision as lost, so this member's pages agree with what a restart would hold.
- A failed write of the `evicted-through` record logs and holds in memory, so pages say so at once. An eviction whose record did not reach disk leaves the event's file in place, so a restart serves the event again rather than skip it unannounced.
- File work runs on the blocking pool, and inline under the W3-H shim (#1245), like `storage`'s file layer.

### Locking

Every change runs under the `treekem_event_log` write lock. The lock order is `treekem_event_log`, then `named_groups`.

- **An append** takes the lock, then checks that the room is still there: it is in the local roster under that key or alias, no record of it is withdrawn, and the local agent is not banned from it (`event_log_room_accepts`).
  - It does not require the local agent to be *active*. A returning device applies the re-key removal of itself (both link paths: the `MemberRemoved` arm and `apply_rekey_self_removal_link_checked`) just before its add re-seats it, and a joiner applies the events its join result carries (#1139) before its own add. Requiring an active member dropped those, and the device then served pages with a hole (A4 review I-1).
  - It is still safe against a wipe: every departure (kick, leave, local-only drop, abandoned re-key row) drops the room from the roster first, a ban keeps the row but bans the local agent, and a delete tombstones it as withdrawn.
- **A wipe** (`wipe_local_group_crypto_material`, every departure, #363 and #376) runs after the room has left the roster or been tombstoned, and removes the directory under the same lock.

So an append that races a wipe either is removed by it or finds the room gone. It cannot bring the directory back.

### Caps

- **Per room: 128 events.** Past it, the lowest revision goes. With the per-event limit, a room holds at most 64 MiB.
- **Daemon-wide: 256 MiB on disk.** Past it, the room with the most bytes on disk gives up its lowest revision (between equal rooms, the one whose oldest event is older), and each eviction is logged at warn. So a busy or hostile room cannot push out a quieter room's history: it is evicted first (A4 review I-2). Bounds before this change: 128 events per room in memory, with no total.
- **The gap.** Each eviction, each event too large to keep, and each event whose write failed raises the room's `evicted-through`. The new value is written down before the event's file is removed, so a crash in between never leaves a hole unrecorded. A request whose `from_revision` is below it would get a page with a hole, which the requester can never link. It gets no events, and the new additive response field `log_evicted_through` says why. Old peers ignore the field. A requester at or past it is served as before.

### Startup

`load_event_log` re-seeds the log before `AppState` is built (`server/mod.rs`, and the test state builder):

- The directory of an unknown, withdrawn, banned or inactive room is removed.
- A file whose bytes do not parse as an event whose own name, group and room directory match is skipped, logged and removed, so it is logged once. A leftover temp file is removed. An entry that cannot be read at all is skipped and logged; the rest still loads.
- An `evicted-through` file that does not read back fails safe: every revision below the oldest one still held counts as lost.
- It keeps the rooms the append check accepts in which the local agent has a row. A Removed row is kept: it is a returning device between its re-key removal and its add, and dropping its log there would leave the add it logs next with nothing before it, a hole. Every other departure drops the row (and wipes), and a banned row is refused. A room the local agent has no row in (inactive) is removed.
- Append order is not on disk, so the files' modification times stand in for it. The caps are enforced again.

### Relation to upstream

Upstream rejects "a persisted authority catch-up log" (ruling D54; ADR 0088 §2 and S5, ADR 0111 option 1, ADRs 0109 and 0114), because it keeps catch-up dependent on the authority (ADR 0088 L1). Its plan is S5: fetch-by-hash of exact evidence from any holder, as control blobs.

This log is not an authority log: every member keeps one and serves from it, and A3 makes any member's copy apply as its verified signer. So it serves L1 rather than breaking it. It is still a second persisted store beside S5's, and ADR 0111's Context (point 1, "in memory only") no longer describes the fork. When S5 lands upstream, the fork should move to it and drop this record.

For the D5 offer, present it as a stopgap for L1 until S5, not as the design. An upstream slice would still need, per ADR 0088's slice rules:

- **a W3-H reproduction first** (D16, D54; `0088:123`). Step 1 here is an in-process test only;
- **a versioned on-disk format** (ADR 0085, `0088:125`). Today a file a newer daemon wrote with an unknown event variant does not parse on an older one, which removes it, so a downgrade empties the log. A `event-log/v1/` directory would fix both;
- **an answer to the overlap with `commit_log`**, the signed commits members already persist in `named_groups.json`, which S5 plans to serve from (`0111:48`). This log repeats the events around those commits.

### Pages that link to the requester's head: done in A5

A5 (`T-signed-catchup-pages`) settles this. A page starts at `from_revision + 1` and stops at the first hole; events at or below the requester's revision are never served, whatever their epoch; and a log that cannot serve the commit after the requester's head serves nothing and sets `log_evicted_through`. The requester asks other members when a page leaves it behind a hole, and still hands a gapped event to the #492 queue.

## Consequences

- A survivor that restarted can still bring a member who missed a removal, a rename or any other commit up to date.
- `handle_treekem_catchup_request` filters on the signed commit revision. Before, it compared the event's unsigned roster revision with the requester's state revision, which are different clocks.
- Disk use grows by up to 256 MiB in total, and at most 64 MiB per room.
- Memory use is bounded: up to 128 events of at most 512 KiB per room. Before this change the in-memory log had no per-event bound.
- File I/O runs under the log's write lock: one file sync and one directory sync per logged commit, two more per eviction. That briefly holds catch-up serves and, where an apply arm logs, the membership lock.
- A stripped copy that lands first is the copy that is logged and served after restarts (the dedup key does not cover the payload). Since A1 and I-1 that matters only on the shared-secret plane, where a non-author add arrives without its display name, KeyPackage hash or owner mandate.
- The new response field is additive. Since A5 the requester asks other members when it is set past its head (`T-signed-catchup-pages`).

## Validation

`named_groups/event_log_store.rs` unit tests:
- `per_room_and_daemon_wide_caps_hold`
- `two_events_sharing_revision_epoch_and_kind_both_persist`
- `files_are_0600_and_a_torn_write_is_skipped`
- `event_log_load_drops_unknown_withdrawn_banned_and_no_local_row_groups`
- `every_kind_with_a_commit_has_a_frontier`
- `a_flooding_room_cannot_evict_another_rooms_events`
- `a_flood_of_oversized_events_keeps_nothing_and_records_the_loss`
- `a_failed_record_of_a_loss_holds_in_memory_and_keeps_the_file`
- `an_unreadable_record_of_losses_fails_safe`
- `appends_need_the_room_present_unwithdrawn_and_not_banned`

`named_groups/tests/event_log_store.rs`:
- `survivor_who_missed_a_rename_and_a_removal_converges` (failed at the A3 tip: the rename was never logged)
- `event_log_survives_restart_and_serves_catchup`
- `event_log_holds_every_commit_bearing_kind`
- `event_log_wipe_on_departure_removes_disk_copy`
- `an_append_racing_a_wipe_does_not_recreate_the_directory` (fails when the liveness check runs before the lock)
- `a_gap_past_the_cap_is_not_served_and_says_so`

`named_groups/tests/issue1139_back_to_back_join.rs`:
- `a4_the_returning_member_serves_the_link_it_took_from_its_join_result` and `a4_the_returning_member_serves_the_link_it_took_from_gossip`: the returning device serves its re-key removal at r+1, then its add at r+2.
- `a4_a_joiner_logs_the_events_its_join_result_carries`.

All three failed under the active-member check.

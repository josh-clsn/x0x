# T-catchup-log-on-disk: every commit a member applied can be served after a restart

- **Status:** Proposed (fork tail, survivor re-key Task A4).
- **Date:** 2026-10-24
- **Base:** `survivor-rekey` after A3 (`9829edcb`)
- **Builds on:** `T-any-member-delivers-signed-commits` (A3)
- **Drop at:** when upstream keeps its catch-up log on disk for every commit-bearing kind, or offer it upstream (D5)

## Context

A member answers a TreeKEM catch-up request from its `treekem_event_log` (`handle_treekem_catchup_request`). Two gaps were left after A3:

- **The log lived only in memory.** A restart emptied it, so a member that restarted could serve nothing it applied before. Upstream re-seeds it at startup only from its self-leave outbox (#1337, `resume_durable_self_leave_rekeys`), which the fork does not carry.
- **It held only the TreeKEM membership kinds** (`MemberAdded`, `MemberRemoved`, `MemberBanned`, `JoinRequestApproved`). A3 lets any member hand on a rename, a policy change, a role change or an unban, but no member logged one. Each of them advances the signed state revision, so a member who missed one could not link any later commit, and the page a survivor served stopped at the gap.

## Decision

### What is logged

Every event whose `commit` is set, through `commit_bearing_event_frontier`: the nine signer-delivered kinds, and the join-request lifecycle (`JoinRequestCreated`, `JoinRequestRejected`, `JoinRequestCancelled`). The lifecycle stays author-only on apply (A3), so only its author can serve it usefully, but it advances the chain like the rest. A `GroupDeleted` is not kept: it withdraws the room, and a withdrawn room is wiped.

Each is logged where it is applied (the apply arm, after the durable persist) and by its author (the route, after the publish). A join requester is not yet a member, so its own request and cancel are logged only where they are applied. The revision is the signed commit's revision, never the event's unsigned roster revision. A page is sorted by `(commit revision, TreeKEM epoch)` on both the serve and the receive side, so a rename and a removal arrive in chain order.

### Layout

`<data>/treekem/event-log/<blake3(group key)[..32]>/<revision:020>-<epoch:020>-<kind>-<blake3(event)[..16]>.json`

- The group key is the event's `group_id`, as the in-memory map uses it. Every path component is a hex digest, a zero-padded number or a fixed kind name (`named_group_metadata_event_kind`). Nothing a peer sends becomes part of a path.
- The digest in the name separates two events that share a revision, an epoch and a kind. In memory one commit is logged once: the dedup key is the kind, the revision, the epoch, the signer and the commit's state hash.
- A room's `evicted-through` file holds the highest revision it dropped to stay within a cap.

### Writes

- The file is written to `.<name>.<pid>.tmp` created at mode 0600, synced, renamed into place, and then the directory is synced. Directories are created at mode 0700.
- A failed write logs and keeps the event in memory, so it still serves until the next restart.
- File work runs on the blocking pool, and inline under the W3-H shim (#1245), like `storage`'s file layer.

### Locking

Every change runs under the `treekem_event_log` write lock. The lock order is `treekem_event_log`, then `named_groups`.

- **An append** takes the lock, then checks that the room is live: it exists under that key or alias, no record of it is withdrawn, and the local agent is an active member who is not banned.
- **A wipe** (`wipe_local_group_crypto_material`, every departure, #363 and #376) runs after the room has left the roster or been tombstoned, and removes the directory under the same lock.

So an append that races a wipe either is removed by it or finds the room gone. It cannot bring the directory back.

### Caps

- **Per room: 128 events.** Past it, the lowest revision goes.
- **Daemon-wide: 256 MiB.** Past it, the oldest event across every room goes (each room's lowest revision, oldest append first), and each eviction is logged at warn. Bounds before this change: 128 events per room in memory, with no total.
- **The gap.** Each eviction raises the room's `evicted-through`. A request whose `from_revision` is below it would get a page with a hole, which the requester can never link. It gets no events, and the new additive response field `log_evicted_through` says why. Old peers ignore the field. A requester at or past it is served as before.

### Startup

`load_event_log` re-seeds the log before `AppState` is built (`server/mod.rs`, and the test state builder):

- It keeps only rooms that are live for the local agent (as above). The directory of an unknown, withdrawn, banned or inactive room is removed.
- A file whose bytes do not parse as an event whose own name, group and room directory match is skipped, logged and removed, so it is logged once. A leftover temp file is removed.
- Append order is not on disk, so the files' modification times stand in for it. The caps are enforced again.

### Relation to upstream

Upstream rejects "a persisted authority catch-up log" (ruling D54; ADR 0088 §2 and S5, ADR 0111 option 1, ADRs 0109 and 0114), because it keeps catch-up dependent on the authority (ADR 0088 L1). Its plan is S5: fetch-by-hash of exact evidence from any holder, as control blobs.

This log is not an authority log: every member keeps one and serves from it, and A3 makes any member's copy apply as its verified signer. So it serves L1 rather than breaking it. It is still a second persisted store beside S5's, and ADR 0111's Context (point 1, "in memory only") no longer describes the fork. When S5 lands upstream, the fork should move to it and drop this record. For the D5 offer, present it as a stopgap for L1 until S5, not as the design.

## Consequences

- A survivor that restarted can still bring a member who missed a removal, a rename or any other commit up to date.
- `handle_treekem_catchup_request` filters on the signed commit revision. Before, it compared the event's unsigned roster revision with the requester's state revision, which are different clocks.
- Disk use grows by up to 256 MiB in total. A Welcome-bearing add is about 40 KiB.
- The new response field is additive. Nothing on the requester acts on it yet beyond a log line. A later task can use it to ask another member.

## Validation

`named_groups/event_log_store.rs` unit tests:
- `per_room_and_daemon_wide_caps_hold`
- `two_events_sharing_revision_epoch_and_kind_both_persist`
- `files_are_0600_and_a_torn_write_is_skipped`
- `event_log_load_drops_unknown_withdrawn_banned_and_inactive_groups`
- `every_kind_with_a_commit_has_a_frontier`

`named_groups/tests/event_log_store.rs`:
- `survivor_who_missed_a_rename_and_a_removal_converges` (failed at the A3 tip: the rename was never logged)
- `event_log_survives_restart_and_serves_catchup`
- `event_log_holds_every_commit_bearing_kind`
- `event_log_wipe_on_departure_removes_disk_copy`
- `an_append_racing_a_wipe_does_not_recreate_the_directory` (fails when the liveness check runs before the lock)
- `a_gap_past_the_cap_is_not_served_and_says_so`

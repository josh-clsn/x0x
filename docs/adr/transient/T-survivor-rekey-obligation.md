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

## Consequences

- A survivor away for any time, across the remover's restarts, gets the re-key when it is next linked, at most 15 minutes after it is reachable without a link edge.
- The worker sends more than before only to survivors that have not proven their head, at most 4 sends at once.
- The file holds at most 4096 short entries.
- A refused survivor is no worse off than before this change.

## Validation

`named_groups/rekey_obligations.rs` (unit, a paused clock for the timings) and `named_groups/tests/rekey_obligations.rs` (the worker on a daemon's state, with a stand-in network): coalescing, restart, backoff, an acknowledgement without proof, the connect edge, at most four in flight and none twice, both caps, a refused or unwritten obligation, a missing payload said once, and a departure's wipe.

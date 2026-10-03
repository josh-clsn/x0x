# Join-artifact serving lifecycle

- **Status:** Draft for cross-model review. A design note, not an ADR.
- **Implements:** [ADR 0107](../adr/0107-stuck-join-rearm-and-serving-guard.md) (Accepted, D57). ADR 0107 is immutable; this note says how the code meets it.
- **Code baseline:** `85bea26` (r3) plus `61533e0` (r4 WIP) on `fix/1150-stuck-join-rearm` (PR #1190, target v0.46.2).
- **Pinned dependencies:** saorsa-gossip-pubsub 0.5.86, ant-quic 0.27.54. Neither may change for v0.46.x.

This note covers every path that can carry a join artifact's bytes, every event that makes a recipient ineligible, and where the two are ordered against each other. Section 5 lists the places where the code does not meet the machine yet.

## 1. Terms

| Term | Meaning |
|---|---|
| Join artifact | Bytes that carry a joiner's seat or key material: the staged `JoinResult` event, its control-blob copy (chunks), and the staged TreeKEM Welcome (chunks). |
| Metadata frame | A frame with no artifact bytes: Welcome `Offer`/`Complete`/`FetchRequest`/`ChunkAck`, control-blob `Reference`/`Fetch`/`Release`, staged join refusals. |
| Original | The staged entry in `pending_join_results` (key `group:member`) or `pending_welcomes` (content-addressed id). In memory only. Its 10-minute TTL runs from staging; a retry never restarts it. |
| Copy | A staged control-blob entry of a join result (bound to its original by `StagedOrigin {staged_at, deadline}`), or the `PendingWelcome` clone a Welcome stream holds. |
| `L(g)` | Group `g`'s membership lock (`group_membership_lock_for_known_group`, lookup-gated). |
| Guard `G(g,r)` | `join_artifact_serving_refusal`: withdrawn, fork-quarantined, banned, agent revoked, Active seat, the roster-embedded certificate verified against the owner, the revocation set and the clock, and a Clean roster verdict (OwnerCertified only). |
| Admission `A` | The `TransportAdmission` closure. `Agent::send_direct_raw_quic` runs it after machine resolution, any repair or redial, and the post-resolution pairing check. It takes `L(g)` and runs `G` plus "the original is still staged, with the same `staged_at`, and is unexpired". |
| Handoff `H` | `SendStream::finish()` in ant-quic `P2pEndpoint::send` (after `open_uni` and `write_all`, with no await point in between). Before `H`, dropping the future resets the stream (ant-quic 0.27.54 `Drop` sends RESET_STREAM), so the receiver gets no message. After `H` the message is committed: it counts as **transmitted**. |
| Egress registry `E(g,r)` | `AppState::join_artifact_egress`. A task body runs only after its handle is registered. `quiesce(g,r)` removes the handles, aborts them and awaits each one. |

### The machine (invariants)

| ID | Invariant |
|---|---|
| INV-1 | No artifact byte is handed to a delivery path that x0x cannot cancel before `H`: no gossip inbox and no relay. |
| INV-2 | Every `H` of an artifact for `(g,r)` follows an `A` for that same write, and `A` passed. |
| INV-3 | Lock-ordered invalidations (removal, ban, withdrawal, deletion) linearize at `L(g)`. Every in-flight egress either reached `H` before the mutation committed, or never reaches `H`. |
| INV-4 | Invalidations with no lock (revocation, certificate expiry, verdict change, deadline) are evaluated at `A`. The only residual window is `A`→`H`. |
| INV-5 | A copy never outlives its original: it shares the deadline, it is tied to the same `staged_at`, and it is purged with the original. |
| INV-6 | No egress bookkeeping (registry handle, staging guard, stream handle, ACK slot) outlives its task. |
| INV-7 | Fetch handling is admitted fairly: one group cannot exhaust handler or slot capacity that other groups share. |

## 2. Egress paths

### P1: inline join result (payload ≤ `MAX_PAYLOAD_BYTES`)

| State | Entered when | Lock | Checks | Next |
|---|---|---|---|---|
| S0 Staged | `MemberJoined` apply seats the joiner and inserts the original (`created_at = t0`) | `L(g)` | none | S1 |
| S1 Selected | Join-result listener gets a `FetchRequest`. It waits for `L(g)` **on the listener**, sweeps the TTL, reads the result and `t0`, and runs `G` | `L(g)` | `G`, TTL | S2. Refusal: a metadata reply. Definitive refusal: purge. |
| S2 Registered | `spawn_join_artifact_egress` registers the task in `E(g,r)` | none | none | S3 |
| S3 Pre-check | `join_result_still_servable` | `L(g)`, released after | `G`, original is `t0`, unexpired | S4, or done (withheld) |
| S4 Resolving | `send_join_artifact` calls `send_direct_raw_admitted`: signing gate, machine resolution, redial, pairing | none | pairing | S5 |
| S5 Admitted | `A` | `L(g)`, released after | as S3 | S6, or done (refused, nothing written) |
| S6 Writing | `open_uni`, `write_all` | none | none | `H` |
| `H` | `finish()` | none | none | S7 |
| S7 ACK wait | Receive-pipeline ACK, up to 8 s. **A same-peer `Replaced` reissues the write once without `A` (gap G3).** | none | none | done |

Cancellation: `quiesce(g,r)` aborts the task in any state S2–S7. An abort before `H` delivers nothing.

### P2: control-blob copy (payload > `MAX_PAYLOAD_BYTES`; verified, ref-capable, attempt-bound fetch)

| Sub-path | Sequence | Bytes | Cancelled by |
|---|---|---|---|
| P2a Staging | S1, then a per-`(g,r)` 1-permit staging guard (a duplicate is dropped). Then an `E(g,r)` task loops: under `L(g)`, if still servable at `t0`, `stage_with_origin(copy, {t0, t0 + TTL})`. If the budget is exhausted, sleep 2 s and retry, at most 6 times. | Copy stays local | `quiesce(g,r)`; the guard is released by the task, or by the next acquire if the task was aborted (gap G9) |
| P2b Reference | `send_reference_message` with the existing gossip-preferred control config | Metadata only | Task abort (the DM layer may already have published to gossip) |
| P2c Per chunk | The control-blob listener checks the `Fetch` header (sender is the recipient, verified). It takes one of 16 global chunk slots and spawns an `E(g,r)` task. Under `L(g)`: copy staged and before its deadline, original still `staged_at`, unexpired, `G`; then it reads the chunk. Then `send_join_artifact` runs `A` (same check), then `H`. | Artifact | `quiesce(g,r)`, deadline, purge |

Copy lifecycle: the copy is pruned at the earlier of the original's deadline and its own TTL, and a refresh never extends the deadline. It is purged on removal, ban or a definitive refusal, dropped by `prune_groups` on withdrawal, and released by the recipient's `Release` after a verified pull.

### P3: Welcome stream

| State | Entered when | Lock | Checks | Next |
|---|---|---|---|---|
| S0 Staged | Seal stages `pending_welcomes[id] = {g, joiner, bytes, t0}` | `L(g)` | none | S1 |
| S1 Dispatched | Welcome listener decodes a `FetchRequest` and takes one of 16 global slots; the handler is spawned | none | **none before the slot (gap G6)** | S2 |
| S2 Handler | `handle_welcome_fetch_request_via`: lookup, TTL (if expired, remove it and stop the stream with abort and await), group and joiner binding, `G` (definitive: purge). Then `replace_welcome_stream` (abort and await the previous stream, clear its ACK slot) spawns the stream into `pending_welcome_streams`, **not** `E(g,r)`. | `L(g)` | `G`, TTL, binding | S3 |
| S3 Streaming | Every frame first runs `welcome_frame_servable` under `L(g)`. **Offer**: gossip-preferred DM (metadata, advisory). **Chunk k**: wait for the ACK window, then `send_join_artifact` (`A` = staged, unexpired, recipient, `G`), then `H`. Then the final-ACK wait, then **Complete** (gossip-preferred DM, metadata). | per frame | as S2 | done |

Cancellation: `stop_welcome_streams` (abort and await) runs from `quiesce(g,r)`, expiry and restaging. The withdrawal wipe aborts streams **without awaiting them** (gap G4).

### P4: FetchRequest handling (ingress)

| Listener | Work on the listener | Work off the listener | Bound today |
|---|---|---|---|
| Join result | Parse, `retry_pending_owner_cert_joins`, **wait for `L(g)`**, selection, `G` | One `E(g,r)` task per request | None per `(g,r)` for inline results; 1 staging per `(g,r)` |
| Welcome | Decode | Handler (waits for `L(g)`) | 16 global slots, no validation first, no coalescing |
| Control blob | Header check | Chunk task (waits for `L(g)`) | 16 global chunk slots |

### P5: queued retries

| Retry | Runs in | Carries | Cancelled by | Re-checks |
|---|---|---|---|---|
| Staging budget retry (≤ 6 × 2 s) | Authority `E(g,r)` task | Nothing until staged | `quiesce(g,r)` | Every attempt, under `L(g)` |
| DM attempt retries (`send_direct_with_config`) | Caller task | Metadata frames only (since 61533e0) | Task abort | None |
| X0X-0053 reissue on same-peer `Replaced` | `send_ack_racing_replaced`, inside the egress task | **Artifact** | Task abort | **None (gap G3)** |
| Joiner fetch retries (Welcome absolute schedule; join-result poll 120 s TreeKEM, TTL otherwise; re-arm) | Joiner | Requests only | Joiner timeout | The authority re-checks each one |
| `retry_pending_owner_cert_joins` | Authority, on each `FetchRequest` | Nothing (it may seat and stage) | none | Seal-path checks |
| GSS share delayed DM (+8 s, `GROUP_BACKGROUND_PUBLISH_DELAY`) | Detached task | **Group secret sealed to `r`** | **Nothing (gap G11)** | None |
| Gossip stranded retry (+8 s) and IWANT serve (60 s cache) | saorsa-gossip 0.5.86, detached | Whatever was published | Nothing that x0x can reach | None |

### P6: DM layer

| Entry point | Route | Fallback | Used by |
|---|---|---|---|
| `send_direct_with_config` | Signing gate, capability, raw QUIC first if connected (receive ACK) | Gossip inbox (sealed to the recipient's KEM key) with ACK retries; then relay (off by default; a third party reseals) | Metadata frames, P8 deliveries |
| `send_direct_raw_admitted` (new) | Signing gate, raw QUIC only, `A`, `H`, optional receive ACK | **None.** The joiner retries. | All artifact frames (P1, P2c, P3 chunks) |

### P7: gossip, including saorsa-gossip 0.5.86

A publish to the per-recipient DM inbox topic or the group metadata topic is pushed eagerly to peers. If it is stranded, pubsub queues a self-IHAVE, `tokio::spawn`s a retry after 8 s (`STRANDED_PUBLISH_RETRY_DELAY` = 2 × 4 s; `lib.rs` around 9364), and caches the message for 60 s (`MAX_CACHE_AGE_SECS`) to serve IWANTs. Intermediate peers cache and forward it as well. After `publish()` returns, nothing in x0x can cancel any of this. **Gossip cannot meet INV-1 or INV-3, even with a cancel API in saorsa-gossip**, because other peers' caches cannot be recalled.

### P8: commit-time key deliveries (outside the fetch-serving guard, inside this lifecycle)

| Delivery | When | Paths | Registered / admitted |
|---|---|---|---|
| GSS `SecureShareDelivered` (current secret sealed to `r`) | `MemberJoined` apply after the durable seat (#794 Gap 2); `approve_join_request`; ban (to the remaining members) | Metadata-topic gossip publish, a detached DM now, and a detached DM at +8 s | No / no |
| TreeKEM `MemberAdded` push | Commit | Gossip and DM. It carries the commit and the `WelcomeRef`; no Welcome bytes. | Not needed (metadata) |

## 3. Invalidations and linearization points

"Can still leave" assumes the machine is met, except where a gap is named.

| Invalidation | Lands via | Linearization point vs P1/P2/P3 | Staged originals | Copies and queued work | Mid-handoff | Can still leave |
|---|---|---|---|---|---|---|
| I1 Member removal (`remove_named_group_member`, TreeKEM remove, OwnerCertified seal eviction, replayed `MemberRemoved` apply) | `L(g)` held: `quiesce(g,r)` **before** commit, then commit, then purge-if-ineligible **inside** the same critical section | `L(g)`. A pre-check or `A` waiting for `L(g)` runs after the commit and is refused (`NotActive`). | Purged (results, Welcomes, blob copies) | Staging retries and chunk tasks aborted and awaited; Welcome streams stopped. P8 delayed DM **not stopped** (G11). | Abort before `H`: stream reset, nothing delivered. After `H`: transmitted. | Messages past `H`; P8 (G11); metadata frames (G12) |
| I2 Ban (`ban_group_member`, `ban_treekem_group_member`, replayed apply) | As I1; also rotates the GSS secret to the remaining members | `L(g)` | Purged | As I1 | As I1 | As I1 |
| I3 Agent revocation (revocation-set update; no group event) | Lazy: `G` reads the revocation set at selection, pre-check, every frame, and `A` | The revocation-set read in `A`. **No ordering with `H`.** | Kept until the next `G` hit (definitive: purge) | Each refused at its next check | Window `A`→`H` (G1); the reissue skips `A` (G3) | One in-flight message per egress whose `A` preceded the revocation (G1); G3; P8 |
| I3b Machine revocation | **Not checked** by `G` or `A`; raw-path machine resolution does not check it either | none (gap G2) | Kept | Not refused | Not refused | Everything |
| I4 Certificate expiry (time) | `G` evaluates `restore_clock_now` at every check | As I3 | Purged at the next check (`CertificateInvalid` is definitive) | As I3 | Window `A`→`H` (G1) | As I3 |
| I5 Roster verdict change (`DigestPending`, `InGrace`, `Failed`; OwnerCertified only) | `G` re-evaluates `owner_cert_verdict` on current evidence at every check | As I3 | Withheld, not purged (not definitive; the next seal decides) | As I3 | Window `A`→`H` (G1) | As I3 |
| I6 Group withdrawal (withdraw route; sole-member leave) | `L(g)` held by `withdraw_named_group_terminal`, then `retain_withdrawn_group_tombstone`: persist the tombstone (`G` returns `GroupWithdrawn` from here), then wipe originals, Welcome receives, streams and blob copies | **Machine:** `quiesce(g,*)` with awaits before the persist. **Today:** `E(g,*)` is not quiesced; tasks fail `A`. | Wiped | Streams aborted **without await**; `E(g,*)` left to fail `A` (G4) | Before `H`: refused at `A`, or reset if aborted. Past `A` and not yet at `H`: **leaves** (G4) | G4 window; P8 (G11) |
| I7a Deletion (`GroupDeleted` metadata apply) | `L(g)` held by the apply, then the same tombstone path | As I6 | As I6 | As I6 (G4) | As I6 | As I6 |
| I7b Local leave of a TreeKEM group (`leave_treekem_group`, `drop_local_named_group_state`) | The group disappears; `G` returns `UnknownGroup` (withhold) and the lock lookup fails, so `A` is false | Lock lookup | **Not purged**; they expire at TTL (G5) | Not quiesced (G5) | Refused at `A` | Nothing new. A re-join within the TTL could re-expose stale originals (G5). |
| I8 Artifact deadline (10 min from staging) | Checked at selection (TTL sweep), pre-check, every frame, chunk read (copy deadline = original deadline), and `A`. An expired Welcome at the handler is removed and its stream stopped (abort and await). | The `Instant` read in `A` | Expired | Copies pruned with the original | Window `A`→`H` (G1) | One in-flight message whose `A` preceded the deadline |

## 4. Fault matrix

| Fault point | Expected outcome (the machine) | 61533e0 | Evidence |
|---|---|---|---|
| F1a Abort before `A` (parked, or at redial) | Nothing leaves; the quiescer's await returns | Meets | `s8a_r2_ban_racing_{inline_join_result,join_result_chunk,welcome_frame}_egress_sends_nothing` |
| F1b Abort while `A` waits for `L(g)` | Nothing leaves; the abort lands at the lock wait | Meets | Same tests |
| F1c Abort after `A`, during `open_uni`/`write_all` | Stream reset; no message | Meets (ant-quic 0.27.54 `Drop` resets unfinished streams) | Inspection only (G13) |
| F1d Abort after `H`, during the ACK wait | Message transmitted; quiesce returns | Meets | Inspection only |
| F1e Same-peer `Replaced` during the ACK wait | Reissue only after a fresh `A` | **Violates** (G3) | None |
| F1f Withdrawal wipe aborts a Welcome stream | The wipe awaits the abort before it returns | **Violates** (G4) | None |
| F1g Staging task aborted | Its staging guard is released at the abort | **Violates** (G9) | `s8a_r4_aborted_staging_releases_its_staging_guard` (ignored) |
| F2a Authority restarts with staged artifacts | All originals, copies, tasks and guards are gone (in memory). The joiner's fetch finds nothing and ends `TimedOut`/`Refused`. Operator exit: owner remove-member + re-invite (ADR 0107 line 74). | Meets | `s8a_1150_lost_staging_never_claims_recovery` |
| F2b Authority exits mid-write | Before `H`: nothing delivered. After `H`: transmitted. | Meets | Inspection only |
| F2c Joiner restarts | TreeKEM identity re-derived; re-arm fetches the original | Meets | `s8a_1150_rearm_recovers_after_joiner_restart_without_stored_secrets` |
| F2d Gossip-published bytes at restart | Peers' caches keep them for up to 60 s. No artifacts are published (INV-1); P8 shares are (G11). | Partial (G11) | None |
| F3 Re-admission concurrent with a purge | The purge runs inside the removal's `L(g)` section and re-checks eligibility. A re-admission takes `L(g)` afterwards and stages fresh artifacts, which are never erased. | Meets | `s8a_r2_removal_purge_cannot_erase_a_concurrent_readmission`, `s8a_r2_replayed_member_removal_purges_staged_artifacts` |
| F4a Duplicate Welcome `FetchRequest` flood for one locked group | Validated without the lock, coalesced per `welcome_id`, capped per group; other groups are still admitted | **Violates** (G6): handlers waiting for `L(g)` take all 16 global slots, and bogus ids take slots too | `s8a_r4_welcome_fetch_admission_is_fair_across_groups` (ignored) |
| F4b Welcome listener under that flood | The listener keeps draining | Meets | `s8a_r2_welcome_listener_progresses_while_a_group_lock_is_held` |
| F4c Join-result `FetchRequest` flood for one locked group | The listener never waits for `L(g)`; inline egress is coalesced per `(g,r)` | **Violates** (G7) | None |
| F4d Control-blob chunk `Fetch` flood for one locked group | Per-group fairness | **Violates** (G8): 16 global chunk slots held by tasks waiting for `L(g)` | None |
| F5a Raw write stalls (flow control, redial) | Holds no lock; quiesce aborts it and the stream resets | Meets | Inspection only |
| F5b Receive ACK stalls (≤ 8 s) | Holds no lock; quiesce aborts it | Meets | Inspection only |
| F5c Welcome ACK window stalls | The stream waits without a lock; quiesce aborts it | Meets | Inspection only |
| F5d Metadata frame on the gossip-preferred DM | May arrive after an invalidation; carries no key material | Accepted (G12) | None |
| F5e No direct path at all (NAT traversal fails) | The artifact is never delivered; the joiner retries until the TTL, then `TimedOut` | Liveness risk (G10) | Needs the e2e Home gate |
| F6 Panic in an egress task or handler | Bookkeeping released; the Welcome supervisor logs it | Partial: the staging guard leaks until the next acquire (G9) | None |
| F7 Egress task finishes | Its handle leaves `E` at completion | **Violates** (G9): pruned only when the next egress spawns | `s8a_r4_finished_egress_tasks_leave_the_registry` (ignored) |

## 5. Gaps (code at 61533e0 vs the machine)

**No gap requires a saorsa-gossip or ant-quic change** if the recommended options are taken. The options that would need one are marked "dep change".

| ID | Gap | Rule | Options | Recommendation |
|---|---|---|---|---|
| G1 | Residual `A`→`H` window for invalidations with no lock (I3, I4, I5, I8). `A` releases `L(g)` before `open_uni`/`write_all`. | INV-4 | (a) Accept it as bounded by write time. (b) Time margins: admit only if the certificate, grace and deadline stay valid until now + W, and bound `write_all` by W. (c) A revocation epoch: apply revocation-set updates under a write lock that `A`..`H` hold in read mode (global contention). (d) Dep change, ant-quic cancel-after-write: not needed, because reset-on-drop already covers aborts. | (b) for the time-based checks. Decide between (a) and (c) for revocation (decision D-a). |
| G2 | Machine revocation is not checked by `G` or `A`. | I3b | Pass the resolved `MachineId` into `A` and refuse `is_machine_revoked`. | Fix in x0x. |
| G3 | The X0X-0053 reissue after a same-peer `Replaced` writes the artifact again without `A`. 61533e0 opened this path by enabling the 8 s receive ACK for artifacts. | INV-2 | (a) Pass the admission into `send_ack_racing_replaced` and run it before the reissue. (b) Send artifacts without a receive ACK: no reissue, but the stale-connection black hole returns. | (a). Small, and fixed in x0x. |
| G4 | Withdrawal and deletion do not quiesce the group; the wipe aborts Welcome streams without awaiting. The withdrawal test is green only because `A` refuses. | I6, I7a, INV-3 | `quiesce_group_join_egress(g)`: every `E(g,*)` task and every Welcome stream of `g`, aborted and awaited before the tombstone persist (under `L(g)`). Make the wipe await its aborts. | Fix in x0x. |
| G5 | Local leave keeps the originals and copies until the TTL and does not quiesce. | I7b | Purge and quiesce in `drop_local_named_group_state`. | Fix in x0x. |
| G6 | Welcome fetch admission is not fair. | INV-7 | Validate before any lock (`pending_welcomes` has the id, the same group, and joiner == sender); coalesce per `welcome_id`; cap per group (2) and globally (16); RAII ticket; handler timeout. | Fix in x0x (the test exists, ignored). |
| G7 | The join-result listener waits for `L(g)` inline, and inline egress is not coalesced per `(g,r)`. | INV-7 | Move selection off the listener, under the same validated, coalesced, fair admission as G6. | Fix in x0x. |
| G8 | The 16 control-blob chunk slots are global. | INV-7 | A per-group sub-cap; validate the staged reference before taking a slot. | Fix in x0x. |
| G9 | No RAII staging-guard release; no registry prune at completion. | INV-6 | An RAII staging slot; the task removes its own handle (by task id) at completion. | Fix in x0x (both tests exist, ignored). |
| G10 | Raw-only liveness: with no direct QUIC path, artifacts are never delivered. | (liveness) | (a) Accept it: rely on ant-quic NAT traversal and joiner retries within the TTL; gate on the e2e Home suite. (b) An owned, cancellable relay hop with `A` at the relay (needs design; relay is off by default). (c) Dep change: gossip with cancellation. This still cannot recall other peers' caches, so it cannot meet INV-1. | (a) for v0.46.2, measured (decision D-b). |
| G11 | P8 commit-time GSS share deliveries (gossip publish, a detached DM now, a detached DM at +8 s) are not registered, not admitted, and gossip-capable. | INV-1, INV-3 | (a) Register the DMs in `E(g,r)` with `A`, send them raw-only, and stop publishing sealed shares on gossip. (b) Accept: the share is the secret the member was entitled to at commit. GSS removal and ban both rotate (`remove_named_group_member`, `ban_group_member` call `rotate_shared_secret`), so a late share opens only pre-removal epochs. (c) Dep change: cancel the gossip publish; insufficient for the same reason as P7. | Decision D-c. |
| G12 | Metadata frames (`Offer`, `Complete`, `Reference`, `Release`, staged refusal) are gossip-capable and can arrive after an invalidation. | (none) | Accept them (no key material), or route them raw-only too. | Accept (decision D-d). |
| G13 | Placement of `A` in the real raw path is verified only by inspection. In-process tests use a `cfg(test)` stand-in when the agent has no network. | (evidence) | A loopback two-agent test under `scripts/dev/test-isolated.py` (Linux netns) in CI. | Add before merge. |
| G14 | `send_direct_raw_admitted` skips the DM metrics (`record_outgoing_*`) and the phi "likely offline" short-circuit. | (operability) | Add both. | Minor. |

## 6. Decisions requested

| ID | Question | Options |
|---|---|---|
| D-a | Revocation in the `A`→`H` window (G1) | Accept the bounded window, or add a revocation-epoch lock |
| D-b | Raw-only artifact delivery for v0.46.2 (G10) | Accept, gated on the e2e Home suite; or design an owned relay hop first |
| D-c | Commit-time GSS share delivery (G11) | Bring it under this machine (raw-only, registered, admitted, no gossip publish), or accept it with the rotation argument |
| D-d | Metadata frames on gossip (G12) | Accept, or route them raw-only |

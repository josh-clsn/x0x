# T-survivor-a0-upstream-catchup-port: upstream's epoch-ahead catch-up, ported early

- **Status:** Proposed (fork tail, survivor re-key Task A0).
- **Date:** 2026-10-23
- **Base:** fork pin `85bcca31`; upstream `saorsa-labs/main` at `d3b39f18`
- **Upstream commits (A0):** `40e0f5d4` (#1449), `522911ff` (#1464), a subset of `50f8d5ac` (#1337), two test seams from `4974dbbe` (#1406)
- **Upstream commits (A0b):** `8f0f8018` (#1250, #1269), `f7ea0415` (#1456), `4b0f927e` (#1454)
- **Drop at:** the next upstream crossing that contains all seven commits

## Context

A member that is away while an admin removes someone misses the removal commit. With no later membership event, nothing starts the gap catch-up, so it stays on the old epoch. Upstream fixed this in #1449 and #1464. #1337 added the rule for who may deliver a removal on catch-up. The survivor re-key plan needs both before its own tasks, and our pin predates them.

This is a port, not a new decision. It changes no wire format beyond the field upstream already added, and no public API.

## Decision

Port the subset below, byte-close to upstream, so the next crossing can drop it.

### Ported unchanged

| Upstream | What | Fork file |
|---|---|---|
| #1449, #1464 | `spawn_treekem_epoch_ahead_catchup`, `request_treekem_catchup_for_epoch_ahead`, `EpochAheadTarget`, `note_epoch_ahead_observation`, `request_treekem_catchup_round`, `epoch_ahead_catchup_peers`, `TREEKEM_EPOCH_AHEAD_CATCHUP_PEERS`, `TREEKEM_EPOCH_AHEAD_CATCHUP_ROUNDS` (268 lines) | `named_groups.rs` |
| #1449 | the decrypt trigger (6 lines) in `treekem_group_decrypt_for_actor`'s `Err` arm, and `&Arc<AppState>` on the decrypt helpers | `named_groups.rs` |
| #1449 | `TreeKemMlsGroup::ciphertext_epoch` (10 lines) | `src/mls/treekem.rs` |
| #1449 | the store trigger (8 lines) | `routes/stores.rs` |
| #1449, #1464 | `treekem_epoch_ahead_targets`; the throttle on `tokio::time::Instant` | `state.rs`, `mod.rs` |
| #1449 | `case_1427.rs` (631 lines, byte-identical) and its `mod` line | `src/server/w3h/` |
| #1337 | `treekem_commit_binding`, `treekem_removal_binding_covers_commit` (23 lines) | `named_groups.rs` |
| #1337 | `verified_catchup_member_removed_author`, `catchup_may_apply_removed_as_author` (49 lines) | `named_groups.rs` |
| #1337 | the `MemberRemoved` apply check (upstream :13685-13697, 13 lines) and the signed binding it keeps (upstream :13699, :13716) | `named_groups.rs` |
| #1337 | `responder_state_hash` on `TreeKemCatchupResponse`, filled with the saved head on a page and `None` on a KeyPackage reply | `named_groups.rs` |

### Adapted

| Where | Upstream | Fork | Why |
|---|---|---|---|
| `spawn_treekem_epoch_ahead_catchup` | `state.spawn_detached` (#1269) | `tokio::spawn`, raced against `shutdown_notify` (net +9 lines: 12 in place of upstream's 3) | The fork has no detached-task registry. Upstream's drain aborts the task at shutdown; the shutdown signal does the same here, so the task never keeps `AppState` alive past it. |
| apply-as-author selection in `handle_treekem_catchup_response` (upstream :11429-11437) | inside `SELF_LEAVE_REKEY_BATCH.scope` | the same three statements, no scope | The batch scope and its fence belong to the post-leave outbox, which is not ported. |
| request handler | `saved_head` from upstream's authority tuple | a fourth element on the fork's `group_authority` tuple | The fork's handler has its own shape (#363, #384). |
| throttle | upstream changes two insert sites | the same two, plus the fork's `mk-serve`, `serve:` and `jr-serve` inserts (3 lines) | The map's value type changed; the fork has three more writers. |
| `responder_state_hash` doc comment | names the startup self-leave seal | says the field is an unsigned hint | That seal is not ported. |
| `request_treekem_catchup_page` | returns `bool`; the test seam parks on `detached_send_test_seam` | returns `()`; the seam returns early | `bool` and the retry it feeds are #1337's fence; the park seam is not in the fork. |
| test recorders | `catchup_page_force_ok`, `catchup_responses` (#1406), `metadata_publish_force_ok` (#1337) | the first two only (+4 lines in the handler, +13 in the page seam) | The fork's metadata publish never fails a route, so the third is not needed. |

### Left out

- #1337's post-leave outbox, its fence (`self_leave_rekey_fence_catchup_peer`), `SELF_LEAVE_REKEY_BATCH`, the startup self-leave seal and its use of `responder_state_hash`, and its self-leave tests.
- #1449's CI lines (`.github/workflows/ci.yml`, the D196 gate rows).
- In A0, `8f0f8018` and #1456 were left out. A0b ports them (see below).

### Tests

The tests live in `src/server/routes/named_groups/tests/epoch_ahead_catchup.rs` (1150 lines), not in upstream's `issue1113_self_leave_rekey.rs`, because #1337's harness is not ported. The file has its own small relay fixture: upstream's `two_member_treekem_group` and `catchup_relay_fixture`, without the self-leave helpers.

- From #1449 and #1464, unchanged in name and assertion: `epoch_ahead_ciphertext_requests_catchup_and_converges`, `epoch_ahead_store_record_requests_catchup`, `epoch_ahead_catchup_window_runs_on_the_runtime_clock`, `epoch_ahead_catchup_rotates_past_unanswered_peers`, `single_epoch_ahead_observation_reaches_the_fourth_ranked_signer`, `newer_epoch_observation_survives_a_late_older_epoch_page`, `same_epoch_observation_in_the_last_round_asks_again`, `same_epoch_observation_in_the_penultimate_round_asks_the_holder_again`, `single_epoch_ahead_observation_asks_every_candidate`. Two tests build their request through a helper, `catchup_request_from`, in place of upstream's inline literal, because the fork's request has one more field (`signed_by: None`). The `metadata_publish_force_ok` lines are dropped.
- From #1337: `catchup_legacy_binding_stays_with_the_author`, unchanged. `relayed_removal_rejects_another_members_treekem_commit` keeps its relay assertions. Upstream gets its digest-bound removal from the post-leave rekey, which is not ported, so the fixture's `digest_bound_removal` seals that removal directly. The self-leave steps before it are dropped.
- `catchup_third_party_relays_a_digest_bound_rekey` moves to Task A1.

## A0b: what `case_1427` needs at the pin

`case_1427` could not reach a verdict at the pin, so A0b ports three more upstream commits.

| Upstream | What | Fork | Delta |
|---|---|---|---|
| `8f0f8018` (#1250, #1269) | The TreeKEM store protector and the public refresh hook hold `Weak<AppState>`. A strong `Arc` made a cycle through the store, so a stopped daemon stayed held. | Applied cleanly. A0's store trigger now takes the upgraded `state`, so it is byte-identical to upstream. | `stores.rs` +54/-34, as upstream. |
| `f7ea0415` (#1456) | The announcement auto-connect window runs on the runtime clock. | Hand-applied: the fork's call carries an extra `leaf` argument. Its fixture-teardown half was already in A0 (`CatchupRelay::shutdown`). | `lib.rs` +29/-6, as upstream. |
| `4b0f927e` (#1454, part of #1245) | The w3h shim pulls virtual wall time, and blocking FS and SQLite work runs inline under the shim. | Applied cleanly: `nextest.toml`, `ci.yml`, `justfile`, `w3h_shim.c`, `dm_inbox.rs`, `network/sim.rs`, `delegations.rs`, `server/mod.rs`, `w3h/control.rs`, `w3h/mod.rs`. Hand-applied: `history/mod.rs`, `history/reaper.rs` and `storage.rs`, which have drifted from upstream. | 476 added and 57 removed lines; upstream is 583/103. |

Hand-applied parts of `4b0f927e`:

- **`history`.** `run_blocking` is upstream's. It replaces `spawn_blocking` at the fork's two equivalent sites: the writer shutdown and the reaper's `retain_with_pins`. Upstream's `purge_admitted` and `trim` sites do not exist in the fork.
- **`storage.rs`.** The test-only `w3h_fs` module is upstream's, byte for byte, with the same `#[cfg(test)]`/`#[cfg(not(test))]` switch between `w3h_fs` and `tokio::fs`. Every `tokio::fs::` call in the fork's file (19) goes through `fs::`, as upstream routes all of its own. The fork's file lacks most of upstream's functions, so it has fewer call sites.

Not ported:

- `93dd602a` (#1266), the GSS refresh hook's weak state. `8f0f8018` names it as its GSS twin. The fork's `gss_kv_refresh` (`stores.rs:1512`) still captures a strong `Arc<AppState>`, so a daemon that opened a GSS group store has the same hold after a stop. `case_1427` opens only TreeKEM stores.
- The #1274 detached-send drain series. The fork's delayed KV-delta copy still holds the `Agent` for its delay. `case_1427` did not trip on it.

**The harness at the pin.** At `40e0f5d4^`, upstream's w3h harness differed from the fork's in `case_1143.rs`, and upstream also has `case_811`, `case_1105` and `case_1191`. The core (`mod.rs` without its `mod` lines, `restart.rs`, `control.rs`, `home.rs`, `receipt.rs`) was identical. After A0b, `w3h/mod.rs` and `w3h/control.rs` equal upstream's at `4b0f927e`, except for those three missing case modules.

## Consequences

- A member whose traffic shows a later epoch asks the owner and admins first, then the other members, until every candidate has been asked.
- A third party's catch-up copy of a removal applies as its signer only under a binding that names the TreeKEM bytes. Every fork seal site still uses the legacy `treekem:epoch=<n>` binding until Task A1, so today only a removal's author can deliver it.
- The returning-member re-key link branch of the `MemberRemoved` apply has no upstream counterpart. It still writes the legacy binding and runs no binding check. Task A1 must cover it.

## Validation

- `cargo test -p x0x --lib epoch_ahead_catchup`: 11 passed. Before the port it failed to compile (35 errors, all missing ported items). With the machinery in but no triggers, apply check or selection, the ciphertext, store-record and relayed-removal tests failed and the other 8 passed.
- `cargo test -p x0x --lib named_groups`: 994 passed.
- `w3h_1427_*` at A0 (`051c8730`), one run each with the shim: INFRA in both arms. V's crash-stop drain timed out because its state was still held, before the catch-up phase. The fork's `w3h_s3_control_crash_restart_reseats_member`, which opens no store, passed on the same binary.
- After A0b:
  - `w3h_1427_*` with the shim (the `w3h-sim` environment): 10 runs per arm, 20 of 20 GREEN. The plain arm gave 4 distinct trace digests and the rotation arm gave 10. D196 reports distinct traces and does not fail on them.
  - `w3h_1427_*` without the shim: 5 runs per arm, 10 of 10 GREEN.
  - `w3h_system_time_follows_pull_callback_via_shim` (#1454, `#[ignore]`) passes under the shim.
  - `announcement_auto_connect_retry_window_follows_the_runtime_clock` (#1456) passes.
  - `cargo test -p x0x --lib named_groups`: 994 passed.
  - `cargo clippy -p x0x --all-targets -- -D warnings`: clean. The CI form adds `--all-features`, which does not build on this box: the `voice` feature's `audiopus_sys` needs system Opus or CMake. None of the A0 or A0b lines are in `voice` code.

## Delta from upstream

- Code: 417 added and 11 changed lines in `named_groups.rs`, plus 10 in `treekem.rs`, 8 in `stores.rs`, 14 added and 2 changed in `state.rs`, and 1 in `mod.rs`. Of the `named_groups.rs` lines, 17 are fork-only: 9 net for the spawn adaptation, 3 throttle sites, 1 tuple element, 1 test module line, 1 test-state initialiser and 2 literal fields in older tests. The 17 lines of test seams are upstream's #1406 code in the fork's shape.
- w3h: 631 lines plus 1 `mod` line.
- Tests: 1151 lines in the new file, and 8 `responder_state_hash: None` lines in three existing test files.
- A0b: `stores.rs` +54/-34 (`8f0f8018`), `lib.rs` +29/-6 (`f7ea0415`), and 476 added and 57 removed lines over 13 files (`4b0f927e`).

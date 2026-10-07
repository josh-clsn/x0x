//! The joiner's expected-inviter pins, on disk.
//!
//! A pin says "this device asked this inviter for a join result". It
//! authorizes the result and marks the device as mid-rejoin, which is what
//! lets the device's own re-key removal (by that inviter, while it holds no
//! tree) apply as a chain step instead of a departure. Phones restart
//! mid-join all the time, so the pins must outlive the process.
//!
//! Writes go through the same atomic, durable writer as the named-groups
//! roster (unique temp file, fsync of file and directory, rename), under
//! their own lock, from async code; each write snapshots the map after
//! taking the lock, so the last write on disk is the newest state.
//!
//! On load, an entry past its TTL, or one stamped further in the future
//! than [`FUTURE_SKEW_ALLOWANCE`] (a clock that moved backwards must not
//! make a pin fresh again), is dropped. A file that cannot be read or
//! parsed (truncated by a crash before this writer existed, or edited by
//! hand) loads as NO pins, with a warning: the device then treats its
//! re-key removal as an ordinary departure, which is the safe direction.
//!
//! A pin armed by an ADR 0107 re-arm loads as timed out: the re-arm's
//! attempt and poll do not survive the process.

use super::{
    now_millis_u64, write_named_groups_json_atomic, AppState, ExpectedJoinResultInviter,
    EXPECTED_JOIN_RESULT_INVITER_TTL,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How far in the future a persisted pin's wall-clock stamp may be and
/// still load (ordinary clock skew between writes and a restart).
pub(super) const FUTURE_SKEW_ALLOWANCE: Duration = Duration::from_secs(60);

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPin {
    inviter_agent_id: String,
    recorded_at_ms: u64,
    #[serde(default)]
    timed_out: bool,
    #[serde(default)]
    rearm: bool,
}

pub(super) fn pins_path(state: &AppState) -> PathBuf {
    state
        .join_result_staging_path
        .with_file_name("join_result_inviter_pins.json")
}

/// Write the whole pin map, durably.
pub(super) async fn persist(state: &AppState) {
    let _write_guard = state.join_result_pins_persistence_lock.lock().await;
    let json = {
        let Ok(pins) = state.expected_join_result_inviters.lock() else {
            return;
        };
        let on_disk: HashMap<&String, PersistedPin> = pins
            .iter()
            .map(|(key, pin)| {
                (
                    key,
                    PersistedPin {
                        inviter_agent_id: pin.inviter_agent_id.clone(),
                        recorded_at_ms: pin.recorded_at_ms,
                        timed_out: pin.timed_out,
                        rearm: pin.rearm,
                    },
                )
            })
            .collect();
        match serde_json::to_string(&on_disk) {
            Ok(json) => json,
            Err(error) => {
                tracing::warn!(%error, "failed to encode join-result inviter pins");
                return;
            }
        }
    };
    if let Err(error) = write_named_groups_json_atomic(&pins_path(state), &json).await {
        tracing::warn!(%error, "failed to persist join-result inviter pins");
    }
}

/// Read the pins back at startup (see the module doc for what is dropped).
pub(super) async fn load(state: &AppState) {
    let raw = match tokio::fs::read(pins_path(state)).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(%error, "failed to read join-result inviter pins; loading none");
            return;
        }
    };
    let Ok(on_disk) = serde_json::from_slice::<HashMap<String, PersistedPin>>(&raw) else {
        tracing::warn!("join-result inviter pins file is malformed; loading none");
        return;
    };
    let now_ms = now_millis_u64();
    let skew_ms = u64::try_from(FUTURE_SKEW_ALLOWANCE.as_millis()).unwrap_or(u64::MAX);
    let Ok(mut pins) = state.expected_join_result_inviters.lock() else {
        return;
    };
    for (key, pin) in on_disk {
        if pin.recorded_at_ms > now_ms.saturating_add(skew_ms) {
            continue;
        }
        let age = Duration::from_millis(now_ms.saturating_sub(pin.recorded_at_ms));
        if age >= EXPECTED_JOIN_RESULT_INVITER_TTL {
            continue;
        }
        // A re-arm lives only in this process (its attempt and its 120 s
        // poll are in memory), so a re-arm pin read at boot is a re-arm
        // that ended: it loads timed out, which reads `not_member` and makes
        // the next invite re-key.
        let timed_out = pin.timed_out || pin.rearm;
        pins.entry(key).or_insert(ExpectedJoinResultInviter {
            inviter_agent_id: pin.inviter_agent_id,
            created_at: Instant::now().checked_sub(age).unwrap_or_else(Instant::now),
            recorded_at_ms: pin.recorded_at_ms,
            timed_out,
            rearm: pin.rearm,
        });
    }
}

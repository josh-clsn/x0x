//! The joiner's expected-inviter pins, on disk.
//!
//! A pin says "this device asked this inviter for a join result". It
//! authorizes the result and marks the device as mid-rejoin, which is what
//! lets the device's own re-key removal (by that inviter, while it holds no
//! tree) apply as a chain step instead of a departure. Phones restart
//! mid-join all the time, so the pins must outlive the process: they are
//! written on every change and read back at startup, beside the join-result
//! staging sidecar. Entries past their TTL are dropped on load.

use super::{
    now_millis_u64, AppState, ExpectedJoinResultInviter, EXPECTED_JOIN_RESULT_INVITER_TTL,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPin {
    inviter_agent_id: String,
    recorded_at_ms: u64,
    #[serde(default)]
    timed_out: bool,
}

fn pins_path(state: &AppState) -> PathBuf {
    state
        .join_result_staging_path
        .with_file_name("join_result_inviter_pins.json")
}

/// Write the whole pin map. Called with the map's lock held, so concurrent
/// changes are written in order; the file is tiny (one entry per join).
pub(super) fn persist(state: &AppState, pins: &HashMap<String, ExpectedJoinResultInviter>) {
    let on_disk: HashMap<&String, PersistedPin> = pins
        .iter()
        .map(|(key, pin)| {
            (
                key,
                PersistedPin {
                    inviter_agent_id: pin.inviter_agent_id.clone(),
                    recorded_at_ms: pin.recorded_at_ms,
                    timed_out: pin.timed_out,
                },
            )
        })
        .collect();
    let path = pins_path(state);
    let tmp = path.with_extension("json.tmp");
    let written = serde_json::to_vec(&on_disk)
        .map_err(std::io::Error::other)
        .and_then(|bytes| std::fs::write(&tmp, bytes))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(error) = written {
        tracing::warn!(%error, "failed to persist join-result inviter pins");
    }
}

/// Read the pins back at startup, dropping any past their TTL.
pub(super) fn load(state: &AppState) {
    let raw = match std::fs::read(pins_path(state)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(%error, "failed to read join-result inviter pins");
            return;
        }
    };
    let Ok(on_disk) = serde_json::from_slice::<HashMap<String, PersistedPin>>(&raw) else {
        tracing::warn!("join-result inviter pins file is malformed; ignoring it");
        return;
    };
    let now_ms = now_millis_u64();
    let Ok(mut pins) = state.expected_join_result_inviters.lock() else {
        return;
    };
    for (key, pin) in on_disk {
        let age = Duration::from_millis(now_ms.saturating_sub(pin.recorded_at_ms));
        if age >= EXPECTED_JOIN_RESULT_INVITER_TTL {
            continue;
        }
        pins.entry(key).or_insert(ExpectedJoinResultInviter {
            inviter_agent_id: pin.inviter_agent_id,
            created_at: Instant::now().checked_sub(age).unwrap_or_else(Instant::now),
            recorded_at_ms: pin.recorded_at_ms,
            timed_out: pin.timed_out,
        });
    }
}

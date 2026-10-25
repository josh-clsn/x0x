//! A re-key stays owed to each survivor until the survivor proves it holds
//! it (survivor re-key A9 and A10,
//! `docs/adr/transient/T-survivor-rekey-obligation.md`).
//!
//! Before this, the daemon that sealed a re-key sent it to each survivor at
//! +0 and +8 s, then on the blind 6, 15, 30 and 60 s schedule, and kept
//! nothing on disk. A survivor away for longer was stranded at the old
//! epoch, and a member that missed an add had only the first two sends.
//!
//! - **Owed.** Every re-key site records one obligation per survivor
//!   ([`owe`]) on disk before its first publish. There is one per (room,
//!   survivor): a later re-key widens it, from the lowest epoch still owed
//!   to the highest one to prove.
//! - **Sent.** The worker steps every [`STEP_EVERY`] and starts at most
//!   [`MAX_IN_FLIGHT`] sends, each in its own task and under a timeout.
//!   A send carries every commit-bearing event the A4 log holds
//!   from the first owed revision, in revision order, at most
//!   [`EVENTS_PER_ATTEMPT`]. A failed send backs off 6, 15, 30 and 60 s,
//!   then doubling to [`MAX_DELAY_MS`]. A survivor newly linked is sent at
//!   once.
//! - **Delivered is not held.** A send the survivor acknowledged becomes
//!   [`ObligationState::DeliveredUnproven`] and is sent again at the cap.
//! - **Settled only on proof** ([`settle`]): a catch-up or challenge
//!   request from the survivor itself at or past the epoch, a message from
//!   it decrypted at or past the epoch, the survivor leaving the roster, or
//!   the room being withdrawn or wiped. A claimed sender proves nothing.
//! - **Refused.** Past a cap, or when the record cannot be written, [`owe`]
//!   returns the survivor, and the caller keeps it on the blind schedule.
//!   Nothing already owed is dropped to make room.
//!
//! The file is `<data>/treekem/rekey-obligations.json`: a fixed name, written
//! at mode 0600 to a temp file, synced, renamed and its directory synced, as
//! the A4 log's files are. Nothing a peer sends becomes part of a path.
//!
//! Lock order: `rekey_obligations`, then `named_groups`. Nothing takes
//! `rekey_obligations` while it holds `named_groups` or `treekem_event_log`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::event_log_store::{
    commit_bearing_event_frontier, commit_bearing_event_sort_key, run_blocking, write_durable,
};
use super::{
    committer_leaf, has_withdrawn_group_record, named_group_event_delivery_result, now_millis_u64,
    signed_catchup, AppState, NamedGroupMetadataEvent, TreeKemCatchupRequest,
};
use crate as x0x;
use crate::logging::LogHexId;

/// The obligations' file, under the daemon's TreeKEM directory.
pub(in crate::server) const OBLIGATIONS_FILE: &str = "rekey-obligations.json";
const FILE_VERSION: u32 = 1;
/// The most obligations one room keeps.
pub(in crate::server) const ROOM_CAP: usize = 256;
/// The most obligations the daemon keeps.
pub(in crate::server) const TOTAL_CAP: usize = 4096;
/// The most sends in flight at once.
pub(in crate::server) const MAX_IN_FLIGHT: usize = 4;
/// How often the worker steps.
pub(in crate::server) const STEP_EVERY: Duration = Duration::from_secs(5);
/// The waits after the first sends: the old blind schedule's offsets.
const FIRST_DELAYS_MS: [u64; 4] = [6_000, 15_000, 30_000, 60_000];
/// The longest wait between two sends of one obligation.
pub(in crate::server) const MAX_DELAY_MS: u64 = 15 * 60 * 1000;
/// The most events one send carries.
pub(in crate::server) const EVENTS_PER_ATTEMPT: usize = 16;
/// How long one event's send may take.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one send of all its events may take.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Where an obligation stands. Neither is proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum ObligationState {
    /// Not yet acknowledged by the survivor.
    Owed,
    /// The survivor acknowledged a send. It may still have dropped or
    /// queued what it got, so the obligation stays, at the longest wait.
    DeliveredUnproven,
}

/// One commit a re-key sealed: its TreeKEM epoch and its signed revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) struct Rekey {
    pub(in crate::server) epoch: u64,
    pub(in crate::server) revision: u64,
}

/// What this daemon owes one survivor in one room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::server) struct RekeyObligation {
    /// The room, by its `named_groups` key.
    pub(in crate::server) group_key: String,
    pub(in crate::server) recipient_hex: String,
    /// The lowest epoch the survivor is not known to hold.
    pub(in crate::server) owed_epoch: u64,
    /// Sends start at this signed revision.
    pub(in crate::server) owed_revision: u64,
    /// A proof at or past this epoch settles the obligation.
    pub(in crate::server) through_epoch: u64,
    /// The revision of the latest re-key owed.
    pub(in crate::server) through_revision: u64,
    pub(in crate::server) state: ObligationState,
    pub(in crate::server) next_attempt_at_ms: u64,
    pub(in crate::server) attempt_count: u32,
    /// A send is running. Never written: nothing is in flight after a
    /// restart.
    #[serde(skip)]
    pub(in crate::server) in_flight: bool,
}

#[derive(Serialize, Deserialize)]
struct Sidecar {
    version: u32,
    entries: Vec<RekeyObligation>,
}

/// What a survivor showed it holds: its own head, from a request only it
/// could have sent, or the epoch of a message it sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct Proof {
    pub(in crate::server) recipient_hex: String,
    pub(in crate::server) epoch: u64,
    /// The survivor's signed revision, when the proof names it.
    pub(in crate::server) revision: Option<u64>,
}

/// One send the worker started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct Attempt {
    pub(in crate::server) group_key: String,
    pub(in crate::server) recipient_hex: String,
    pub(in crate::server) owed_revision: u64,
    /// The obligation's latest re-key when the send started. A re-key owed
    /// during the send keeps the schedule [`owe`] gave it.
    through_revision: u64,
}

/// How one send ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum Outcome {
    /// Every event was acknowledged.
    Delivered,
    /// A send failed or timed out.
    Failed,
    /// The log holds nothing from the owed revision.
    PayloadMissing,
}

/// A test's stand-in for the network.
#[cfg(test)]
pub(in crate::server) type TestDeliver = Arc<
    dyn Fn(
            String,
            NamedGroupMetadataEvent,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

/// Wall-clock milliseconds, moved on by the runtime clock. A send time is
/// written to disk as wall time, and is read against the runtime clock in
/// between, so a wall step does not move any due time and a paused test
/// clock moves them all.
#[derive(Debug, Clone, Copy)]
pub(in crate::server) struct ObligationClock {
    wall_ms: u64,
    started: tokio::time::Instant,
    #[cfg(test)]
    skew_ms: u64,
}

impl ObligationClock {
    pub(in crate::server) fn start() -> Self {
        Self {
            wall_ms: now_millis_u64(),
            started: tokio::time::Instant::now(),
            #[cfg(test)]
            skew_ms: 0,
        }
    }

    pub(in crate::server) fn now_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let now = self.wall_ms.saturating_add(elapsed);
        #[cfg(test)]
        let now = now.saturating_add(self.skew_ms);
        now
    }
}

/// The wait before send `attempt_count + 1`: 6, 15, 30, 60 s, then doubling
/// to [`MAX_DELAY_MS`].
pub(in crate::server) fn retry_delay_ms(attempt_count: u32) -> u64 {
    let index = usize::try_from(attempt_count).unwrap_or(usize::MAX);
    if let Some(delay) = FIRST_DELAYS_MS.get(index) {
        return *delay;
    }
    let doublings = attempt_count.saturating_sub(3).min(16);
    60_000_u64
        .checked_shl(doublings)
        .unwrap_or(MAX_DELAY_MS)
        .min(MAX_DELAY_MS)
}

/// The obligations, in memory and in their file.
pub(in crate::server) struct RekeyObligations {
    /// By (room, survivor).
    entries: BTreeMap<(String, String), RekeyObligation>,
    /// `None` keeps them in memory only.
    path: Option<PathBuf>,
    pub(in crate::server) clock: ObligationClock,
    /// The survivors linked at the last step, for connect edges.
    connected: HashSet<String>,
    /// The (room, survivor, owed revision) a missing payload was said for.
    missing_said: HashSet<(String, String, u64)>,
    missing_reports: u64,
    room_cap: usize,
    total_cap: usize,
}

impl Default for RekeyObligations {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            path: None,
            clock: ObligationClock::start(),
            connected: HashSet::new(),
            missing_said: HashSet::new(),
            missing_reports: 0,
            room_cap: ROOM_CAP,
            total_cap: TOTAL_CAP,
        }
    }
}

fn is_agent_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn well_formed(owed: &RekeyObligation) -> bool {
    is_agent_hex(&owed.recipient_hex)
        && !owed.group_key.is_empty()
        && owed.group_key.len() <= 256
        && owed.owed_epoch <= owed.through_epoch
}

impl RekeyObligations {
    #[cfg(test)]
    pub(in crate::server) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(in crate::server) fn get(
        &self,
        group_key: &str,
        recipient_hex: &str,
    ) -> Option<&RekeyObligation> {
        self.entries
            .get(&(group_key.to_string(), recipient_hex.to_ascii_lowercase()))
    }

    pub(in crate::server) fn room_count(&self, group_key: &str) -> usize {
        self.entries
            .range((group_key.to_string(), String::new())..)
            .take_while(|((key, _), _)| key == group_key)
            .count()
    }

    /// The survivors this daemon owes in `group_key`.
    pub(in crate::server) fn recipients_in(&self, group_key: &str) -> Vec<String> {
        self.entries
            .range((group_key.to_string(), String::new())..)
            .take_while(|((key, _), _)| key == group_key)
            .map(|((_, recipient), _)| recipient.clone())
            .collect()
    }

    /// How many payloads were missing from the log, each said once.
    #[cfg(test)]
    pub(in crate::server) fn missing_reports(&self) -> u64 {
        self.missing_reports
    }

    #[cfg(test)]
    pub(in crate::server) fn set_caps(&mut self, room_cap: usize, total_cap: usize) {
        self.room_cap = room_cap;
        self.total_cap = total_cap;
    }

    #[cfg(test)]
    pub(in crate::server) fn skew_clock(&mut self, by_ms: u64) {
        self.clock.skew_ms = self.clock.skew_ms.saturating_add(by_ms);
    }

    #[cfg(test)]
    pub(in crate::server) fn set_path(&mut self, path: PathBuf) {
        self.path = Some(path);
    }

    /// Owe `survivors` the commits `first` through `last` in `group_key`.
    /// Returns the survivors refused: past a cap, or not an agent id.
    fn owe_entries(
        &mut self,
        group_key: &str,
        survivors: &[String],
        first: Rekey,
        last: Rekey,
        now_ms: u64,
    ) -> Vec<String> {
        let (first, last) = if (first.epoch, first.revision) <= (last.epoch, last.revision) {
            (first, last)
        } else {
            (last, first)
        };
        let soon = now_ms.saturating_add(retry_delay_ms(0));
        let mut refused = Vec::new();
        let mut seen = HashSet::new();
        for survivor in survivors {
            let recipient = survivor.to_ascii_lowercase();
            if !seen.insert(recipient.clone()) {
                continue;
            }
            let key = (group_key.to_string(), recipient.clone());
            if let Some(owed) = self.entries.get_mut(&key) {
                owed.owed_epoch = owed.owed_epoch.min(first.epoch);
                owed.owed_revision = owed.owed_revision.min(first.revision);
                owed.through_epoch = owed.through_epoch.max(last.epoch);
                owed.through_revision = owed.through_revision.max(last.revision);
                owed.state = ObligationState::Owed;
                owed.attempt_count = 0;
                owed.next_attempt_at_ms = owed.next_attempt_at_ms.min(soon);
                continue;
            }
            if !is_agent_hex(&recipient)
                || self.room_count(group_key) >= self.room_cap
                || self.entries.len() >= self.total_cap
            {
                refused.push(survivor.clone());
                continue;
            }
            self.entries.insert(
                key,
                RekeyObligation {
                    group_key: group_key.to_string(),
                    recipient_hex: recipient,
                    owed_epoch: first.epoch,
                    owed_revision: first.revision,
                    through_epoch: last.epoch,
                    through_revision: last.revision,
                    state: ObligationState::Owed,
                    next_attempt_at_ms: soon,
                    attempt_count: 0,
                    in_flight: false,
                },
            );
        }
        refused
    }

    /// Apply `proof` to the survivor's obligations under any of `aliases`.
    /// At or past the latest epoch owed settles one; past the lowest only
    /// moves what is still owed. Returns whether anything changed.
    fn settle_entry(&mut self, aliases: &[String], proof: &Proof) -> bool {
        let recipient = proof.recipient_hex.to_ascii_lowercase();
        let mut changed = false;
        for alias in aliases {
            let key = (alias.clone(), recipient.clone());
            let Some(owed) = self.entries.get_mut(&key) else {
                continue;
            };
            if proof.epoch >= owed.through_epoch {
                self.entries.remove(&key);
                self.missing_said
                    .retain(|(room, member, _)| room != alias || *member != recipient);
                changed = true;
            } else if proof.epoch >= owed.owed_epoch {
                owed.owed_epoch = proof.epoch.saturating_add(1);
                if let Some(revision) = proof.revision {
                    owed.owed_revision = owed.owed_revision.max(revision.saturating_add(1));
                }
                changed = true;
            }
        }
        changed
    }

    /// Keep only the obligations `live` accepts. Returns whether any went.
    fn retain(&mut self, live: impl Fn(&RekeyObligation) -> bool) -> bool {
        let before = self.entries.len();
        self.entries.retain(|_, owed| live(owed));
        let entries = &self.entries;
        self.missing_said
            .retain(|(room, member, _)| entries.contains_key(&(room.clone(), member.clone())));
        self.entries.len() != before
    }

    /// Forget every obligation in a room under any of `aliases`.
    fn wipe(&mut self, aliases: &[String]) -> bool {
        self.retain(|owed| !aliases.contains(&owed.group_key))
    }

    /// Start the sends that are due now, at most [`MAX_IN_FLIGHT`] in all,
    /// none of them already running. A survivor in `connected_now` that was
    /// not linked at the last step is due at once.
    fn begin(&mut self, now_ms: u64, connected_now: &HashSet<String>) -> Vec<Attempt> {
        let newly: HashSet<&String> = connected_now.difference(&self.connected).collect();
        if !newly.is_empty() {
            for owed in self.entries.values_mut() {
                if newly.contains(&owed.recipient_hex) {
                    owed.next_attempt_at_ms = owed.next_attempt_at_ms.min(now_ms);
                }
            }
        }
        self.connected.clone_from(connected_now);
        let busy = self.entries.values().filter(|owed| owed.in_flight).count();
        let free = MAX_IN_FLIGHT.saturating_sub(busy);
        if free == 0 {
            return Vec::new();
        }
        let mut due: Vec<(u64, (String, String))> = self
            .entries
            .iter()
            .filter(|(_, owed)| !owed.in_flight && owed.next_attempt_at_ms <= now_ms)
            .map(|(key, owed)| (owed.next_attempt_at_ms, key.clone()))
            .collect();
        due.sort();
        due.truncate(free);
        let mut attempts = Vec::with_capacity(due.len());
        for (_, key) in due {
            if let Some(owed) = self.entries.get_mut(&key) {
                owed.in_flight = true;
                attempts.push(Attempt {
                    group_key: owed.group_key.clone(),
                    recipient_hex: owed.recipient_hex.clone(),
                    owed_revision: owed.owed_revision,
                    through_revision: owed.through_revision,
                });
            }
        }
        attempts
    }

    /// Record how `attempt` ended. Returns whether the obligation is still
    /// there.
    fn finish(&mut self, attempt: &Attempt, outcome: Outcome, now_ms: u64) -> bool {
        let key = (attempt.group_key.clone(), attempt.recipient_hex.clone());
        let Some(owed) = self.entries.get_mut(&key) else {
            return false;
        };
        owed.in_flight = false;
        if owed.through_revision != attempt.through_revision {
            return true;
        }
        owed.attempt_count = owed.attempt_count.saturating_add(1);
        if outcome == Outcome::Delivered {
            owed.state = ObligationState::DeliveredUnproven;
        }
        let wait = if owed.state == ObligationState::DeliveredUnproven {
            MAX_DELAY_MS
        } else {
            retry_delay_ms(owed.attempt_count)
        };
        owed.next_attempt_at_ms = now_ms.saturating_add(wait);
        true
    }

    /// Say once per owed revision that the log cannot serve `attempt`.
    fn say_payload_missing(&mut self, attempt: &Attempt) {
        let said = (
            attempt.group_key.clone(),
            attempt.recipient_hex.clone(),
            attempt.owed_revision,
        );
        if self.missing_said.insert(said) {
            self.missing_reports = self.missing_reports.saturating_add(1);
            tracing::warn!(
                group_id = %LogHexId::group(&attempt.group_key),
                recipient = %LogHexId::agent(&attempt.recipient_hex),
                owed_revision = attempt.owed_revision,
                "re-key obligation: the catch-up log holds nothing from the owed revision; it stays owed until the survivor proves its head"
            );
        }
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(&Sidecar {
            version: FILE_VERSION,
            entries: self.entries.values().cloned().collect(),
        })
        .map_err(io::Error::other)
    }

    /// Write the obligations to their file. The caller holds the lock, so
    /// the file always ends as the last change left memory.
    async fn persist(&self) -> io::Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let bytes = self.encode()?;
        let (Some(dir), Some(name)) = (
            path.parent().map(Path::to_path_buf),
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string),
        ) else {
            return Err(io::Error::other("the obligations path has no file name"));
        };
        run_blocking(move || write_durable(&dir, &name, &bytes)).await
    }

    async fn persist_or_warn(&self, what: &str) {
        if let Err(error) = self.persist().await {
            tracing::warn!(
                "re-key obligations: {what} is held in memory but not on disk; a restart may send what is no longer owed: {error}"
            );
        }
    }
}

/// Whether this daemon still owes `owed`: the room is in the roster, not
/// withdrawn, this daemon is an active member not banned from it, and so is
/// the survivor.
fn obligation_is_live(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    owed: &RekeyObligation,
    local_agent_hex: &str,
) -> bool {
    room_owes(groups, &owed.group_key, local_agent_hex)
        && groups.get(&owed.group_key).is_some_and(|info| {
            info.has_active_member(&owed.recipient_hex) && !info.is_banned(&owed.recipient_hex)
        })
}

fn room_owes(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_key: &str,
    local_agent_hex: &str,
) -> bool {
    groups.get(group_key).is_some_and(|info| {
        !info.withdrawn
            && info.has_active_member(local_agent_hex)
            && !info.is_banned(local_agent_hex)
    }) && !has_withdrawn_group_record(groups, group_key)
}

/// Load the obligations at startup, keeping those still live
/// ([`obligation_is_live`]) and within the caps. A file that does not read
/// back loads nothing and is replaced at the next write.
pub(in crate::server) async fn load_rekey_obligations(
    treekem_dir: &Path,
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    local_agent_hex: &str,
) -> RekeyObligations {
    let path = treekem_dir.join(OBLIGATIONS_FILE);
    let mut store = RekeyObligations {
        path: Some(path.clone()),
        ..RekeyObligations::default()
    };
    let read_path = path.clone();
    let bytes = run_blocking(move || match std::fs::read(&read_path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    })
    .await;
    let bytes = match bytes {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return store,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                "re-key obligations: not loaded; survivors still owed get the key only by catch-up: {error}"
            );
            return store;
        }
    };
    let sidecar = match serde_json::from_slice::<Sidecar>(&bytes) {
        Ok(sidecar) if sidecar.version == FILE_VERSION => sidecar,
        Ok(sidecar) => {
            tracing::warn!(
                path = %path.display(),
                version = sidecar.version,
                "re-key obligations: unknown file version; nothing loaded"
            );
            return store;
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                "re-key obligations: the file does not read back; nothing loaded, survivors still owed get the key only by catch-up: {error}"
            );
            return store;
        }
    };
    let now_ms = store.clock.now_ms();
    let mut dropped = 0usize;
    for mut owed in sidecar.entries {
        if !well_formed(&owed)
            || !obligation_is_live(groups, &owed, local_agent_hex)
            || store.room_count(&owed.group_key) >= store.room_cap
            || store.entries.len() >= store.total_cap
        {
            dropped = dropped.saturating_add(1);
            continue;
        }
        let key = (owed.group_key.clone(), owed.recipient_hex.clone());
        if store.entries.contains_key(&key) {
            dropped = dropped.saturating_add(1);
            continue;
        }
        owed.in_flight = false;
        owed.next_attempt_at_ms = owed
            .next_attempt_at_ms
            .min(now_ms.saturating_add(MAX_DELAY_MS));
        store.entries.insert(key, owed);
    }
    if dropped > 0 {
        tracing::info!(
            dropped,
            kept = store.entries.len(),
            "re-key obligations: dropped those no longer owed"
        );
        store.persist_or_warn("the load's clean-up").await;
    }
    store
}

/// The members a re-key of `next` is owed to: its active members, less
/// this daemon and `excluded` (the member removed, banned or added).
pub(in crate::server) fn survivors(
    state: &AppState,
    next: &x0x::groups::GroupInfo,
    excluded: &[&str],
) -> Vec<String> {
    let local = hex::encode(state.agent.agent_id().as_bytes());
    next.active_members()
        .map(|member| member.agent_id.to_ascii_lowercase())
        .filter(|member| {
            *member != local
                && !excluded
                    .iter()
                    .any(|excluded| excluded.eq_ignore_ascii_case(member))
        })
        .collect()
}

/// Owe `survivors` the commits `first` through `last` in `group_key`, on
/// disk before this returns. Returns the survivors to keep on the blind
/// schedule: past a cap, all of them when the record cannot be written, and
/// all of them when this daemon no longer owes anything in the room.
pub(in crate::server) async fn owe(
    state: &AppState,
    group_key: &str,
    survivors: &[String],
    first: Rekey,
    last: Rekey,
) -> Vec<String> {
    if survivors.is_empty() {
        return Vec::new();
    }
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let mut store = state.rekey_obligations.lock().await;
    // Under the obligations lock: a wipe takes it after the room left the
    // roster, so either it removes this obligation or this sees the room gone.
    let owes = {
        let groups = state.named_groups.read().await;
        room_owes(&groups, group_key, &local)
    };
    if !owes {
        return survivors.to_vec();
    }
    let before = store.entries.clone();
    let now_ms = store.clock.now_ms();
    let refused = store.owe_entries(group_key, survivors, first, last, now_ms);
    if store.entries != before {
        if let Err(error) = store.persist().await {
            store.entries = before;
            tracing::warn!(
                group_id = %LogHexId::group(group_key),
                survivors = survivors.len(),
                "re-key obligation not written; these survivors keep the blind schedule: {error}"
            );
            return survivors.to_vec();
        }
    }
    if !refused.is_empty() {
        tracing::warn!(
            group_id = %LogHexId::group(group_key),
            refused = refused.len(),
            room_cap = store.room_cap,
            total_cap = store.total_cap,
            "re-key obligations at their cap; these survivors keep the blind schedule"
        );
    }
    refused
}

/// [`owe`] for the commit-bearing `events` a re-key sealed, from the lowest
/// to the highest TreeKEM epoch among them. An event that names no epoch
/// owes nothing by itself; the worker still sends it when it falls in the
/// owed revisions.
pub(in crate::server) async fn owe_for(
    state: &AppState,
    group_key: &str,
    survivors: &[String],
    events: &[&NamedGroupMetadataEvent],
) -> Vec<String> {
    let rekeys: Vec<Rekey> = events
        .iter()
        .filter_map(|event| commit_bearing_event_frontier(event))
        .filter(|frontier| frontier.epoch > 0)
        .map(|frontier| Rekey {
            epoch: frontier.epoch,
            revision: frontier.revision,
        })
        .collect();
    let first = rekeys
        .iter()
        .min_by_key(|rekey| (rekey.epoch, rekey.revision));
    let last = rekeys
        .iter()
        .max_by_key(|rekey| (rekey.epoch, rekey.revision));
    match (first, last) {
        (Some(first), Some(last)) => owe(state, group_key, survivors, *first, *last).await,
        _ => survivors.to_vec(),
    }
}

/// [`owe_for`] to every survivor of `next` ([`survivors`]): what a re-key
/// site calls once its commits are durable and before its first publish.
/// Returns the survivors to keep on the blind schedule.
pub(in crate::server) async fn owe_survivors(
    state: &AppState,
    group_key: &str,
    next: &x0x::groups::GroupInfo,
    excluded: &[&str],
    events: &[&NamedGroupMetadataEvent],
) -> Vec<String> {
    let survivors = survivors(state, next, excluded);
    owe_for(state, group_key, &survivors, events).await
}

/// Apply `proof` to the survivor's obligations under any of `aliases`.
pub(in crate::server) async fn settle(state: &AppState, aliases: &[String], proof: &Proof) {
    let mut store = state.rekey_obligations.lock().await;
    if store.settle_entry(aliases, proof) {
        tracing::debug!(
            recipient = %LogHexId::agent(&proof.recipient_hex),
            epoch = proof.epoch,
            "re-key obligation: the survivor proved its head"
        );
        store.persist_or_warn("a settled obligation").await;
    }
}

/// [`settle`] in its own task, for a listener that must not wait on it.
pub(in crate::server) fn spawn_settle(state: &Arc<AppState>, aliases: Vec<String>, proof: Proof) {
    let state = Arc::clone(state);
    tokio::spawn(async move { settle(&state, &aliases, &proof).await });
}

/// The proof a catch-up or challenge request gives, when only its requester
/// can have sent it: the transport verified the sender as the requester
/// (`verified_requester`), or the requester signed it over its head (a
/// page request, A5). Anything else is a claim and proves nothing.
pub(super) fn request_proof(
    request: &TreeKemCatchupRequest,
    verified_requester: bool,
) -> Option<Proof> {
    (verified_requester || signed_catchup::page_request_signed(request)).then(|| Proof {
        recipient_hex: request.requester_agent_id.to_ascii_lowercase(),
        epoch: request.from_treekem_epoch,
        revision: Some(request.from_revision),
    })
}

/// The KeyPackage each survivor owed in `group_key` holds on the roster,
/// for telling which of them sealed a message.
pub(in crate::server) async fn owed_packages(
    state: &AppState,
    group_key: &str,
) -> Vec<(String, Vec<u8>)> {
    let recipients = state
        .rekey_obligations
        .lock()
        .await
        .recipients_in(group_key);
    if recipients.is_empty() {
        return Vec::new();
    }
    let Some(info) = state.named_groups.read().await.get(group_key).cloned() else {
        return Vec::new();
    };
    let ids = [
        group_key.to_string(),
        info.stable_group_id().to_string(),
        info.mls_group_id.clone(),
    ];
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut packages = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        if let Ok(package) =
            committer_leaf::member_committed_key_package(state, &ids, &info, &recipient).await
        {
            packages.push((recipient, package));
        }
    }
    packages
}

/// Which owed survivor sits at `sender_leaf` in `group`, if any. Run under
/// the tree's lock, on the tree that authenticated the message.
pub(in crate::server) fn owed_sender(
    group: &x0x::mls::TreeKemMlsGroup,
    packages: &[(String, Vec<u8>)],
    sender_leaf: u32,
) -> Option<String> {
    packages
        .iter()
        .find(|(_, package)| group.leaf_for_key_package(package) == Some(sender_leaf))
        .map(|(recipient, _)| recipient.clone())
}

/// Forget every obligation in the room under `aliases`, in memory and on
/// disk (a departure's wipe). The caller has already dropped or tombstoned
/// the room, so no [`owe`] can bring it back.
pub(in crate::server) async fn wipe_rooms(state: &AppState, aliases: &[String]) {
    let mut store = state.rekey_obligations.lock().await;
    if store.wipe(aliases) {
        store.persist_or_warn("a wiped room").await;
    }
}

/// The room's keys: its `named_groups` key and its other ids.
async fn room_aliases(state: &AppState, group_key: &str) -> Vec<String> {
    let mut aliases = vec![group_key.to_string()];
    if let Some(info) = state.named_groups.read().await.get(group_key) {
        for alias in [info.stable_group_id(), info.mls_group_id.as_str()] {
            if !alias.is_empty() && !aliases.iter().any(|held| held == alias) {
                aliases.push(alias.to_string());
            }
        }
    }
    aliases
}

/// What one send carries: every event the log holds for the room from the
/// owed revision, in revision order, at most [`EVENTS_PER_ATTEMPT`].
async fn payload(state: &AppState, attempt: &Attempt) -> Vec<NamedGroupMetadataEvent> {
    let aliases = room_aliases(state, &attempt.group_key).await;
    let mut events: Vec<NamedGroupMetadataEvent> = {
        let log = state.treekem_event_log.read().await;
        aliases
            .iter()
            .filter_map(|alias| log.get(alias))
            .flat_map(|logged| logged.iter())
            .filter(|event| commit_bearing_event_sort_key(event).0 >= attempt.owed_revision)
            .cloned()
            .collect()
    };
    events.sort_by_key(commit_bearing_event_sort_key);
    let mut unique: Vec<NamedGroupMetadataEvent> = Vec::with_capacity(events.len());
    for event in events {
        if !unique.contains(&event) {
            unique.push(event);
        }
        if unique.len() >= EVENTS_PER_ATTEMPT {
            break;
        }
    }
    unique
}

async fn deliver(
    state: &AppState,
    recipient_hex: &str,
    event: &NamedGroupMetadataEvent,
) -> Result<(), String> {
    #[cfg(test)]
    {
        let hook = state
            .named_group_test_recorders
            .rekey_obligation_deliver
            .lock()
            .ok()
            .and_then(|hook| hook.clone());
        if let Some(hook) = hook {
            return hook(recipient_hex.to_string(), event.clone()).await;
        }
    }
    let Some(send) = named_group_event_delivery_result(state, recipient_hex, event, "obligation")
    else {
        return Err("the event cannot be delivered".to_string());
    };
    tokio::time::timeout(SEND_TIMEOUT, send)
        .await
        .unwrap_or_else(|_| Err("timed out".to_string()))
}

/// Send `events` in order, stopping at the first failure.
async fn send_all(
    state: &AppState,
    attempt: &Attempt,
    events: &[NamedGroupMetadataEvent],
) -> Outcome {
    for event in events {
        if let Err(error) = deliver(state, &attempt.recipient_hex, event).await {
            tracing::debug!(
                group_id = %LogHexId::group(&attempt.group_key),
                recipient = %LogHexId::agent(&attempt.recipient_hex),
                "re-key obligation: send failed: {error}"
            );
            return Outcome::Failed;
        }
    }
    Outcome::Delivered
}

async fn run_attempt(state: Arc<AppState>, attempt: Attempt) {
    let events = payload(&state, &attempt).await;
    let outcome = if events.is_empty() {
        Outcome::PayloadMissing
    } else {
        tokio::time::timeout(ATTEMPT_TIMEOUT, send_all(&state, &attempt, &events))
            .await
            .unwrap_or(Outcome::Failed)
    };
    let mut store = state.rekey_obligations.lock().await;
    if outcome == Outcome::PayloadMissing {
        store.say_payload_missing(&attempt);
    }
    let now_ms = store.clock.now_ms();
    if store.finish(&attempt, outcome, now_ms) {
        store.persist_or_warn("a send's outcome").await;
    }
}

/// Which survivors are linked right now.
async fn linked(state: &AppState, recipients: Vec<String>) -> HashSet<String> {
    #[cfg(test)]
    {
        let stand_in = state
            .named_group_test_recorders
            .rekey_obligation_connected
            .lock()
            .ok()
            .and_then(|connected| connected.clone());
        if let Some(connected) = stand_in {
            return connected;
        }
    }
    let mut linked = HashSet::new();
    for recipient in recipients {
        if let Ok(agent) = crate::server::parse_agent_id_hex(&recipient) {
            if state.agent.is_agent_connected(&agent).await {
                linked.insert(recipient);
            }
        }
    }
    linked
}

/// One worker step: drop what is no longer owed, then start the sends that
/// are due. It never waits on a send.
pub(in crate::server) async fn step(state: &Arc<AppState>) {
    for attempt in begin_due(state).await {
        tokio::spawn(run_attempt(Arc::clone(state), attempt));
    }
}

/// The reconcile and selection half of [`step`].
pub(in crate::server) async fn begin_due(state: &AppState) -> Vec<Attempt> {
    let recipients: Vec<String> = {
        let store = state.rekey_obligations.lock().await;
        if store.entries.is_empty() {
            return Vec::new();
        }
        let distinct: HashSet<&String> = store.entries.keys().map(|(_, member)| member).collect();
        distinct.into_iter().cloned().collect()
    };
    let connected = linked(state, recipients).await;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let mut store = state.rekey_obligations.lock().await;
    let dropped = {
        let groups = state.named_groups.read().await;
        store.retain(|owed| obligation_is_live(&groups, owed, &local))
    };
    let now_ms = store.clock.now_ms();
    let attempts = store.begin(now_ms, &connected);
    if dropped {
        store
            .persist_or_warn("dropping obligations no longer owed")
            .await;
    }
    attempts
}

/// The worker: a step every [`STEP_EVERY`] until shutdown.
pub(in crate::server) fn spawn_worker(state: &Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let mut shutdown = state.shutdown_notify.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                () = tokio::time::sleep(STEP_EVERY) => step(&state).await,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const ROOM: &str = "room-a";

    fn member(n: u32) -> String {
        format!("{n:064x}")
    }

    fn rekey(epoch: u64, revision: u64) -> Rekey {
        Rekey { epoch, revision }
    }

    fn proof(recipient: &str, epoch: u64, revision: Option<u64>) -> Proof {
        Proof {
            recipient_hex: recipient.to_string(),
            epoch,
            revision,
        }
    }

    fn rooms(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    fn recipients(attempts: &[Attempt]) -> Vec<String> {
        attempts
            .iter()
            .map(|attempt| attempt.recipient_hex.clone())
            .collect()
    }

    fn connected(members: &[&String]) -> HashSet<String> {
        members.iter().map(|member| (*member).clone()).collect()
    }

    #[test]
    fn backoff_is_6_15_30_60_then_doubles_to_fifteen_minutes() {
        let delays: Vec<u64> = (0..9).map(retry_delay_ms).collect();
        assert_eq!(
            delays,
            vec![6_000, 15_000, 30_000, 60_000, 120_000, 240_000, 480_000, 900_000, 900_000]
        );
        assert_eq!(retry_delay_ms(u32::MAX), MAX_DELAY_MS);
    }

    #[tokio::test(start_paused = true)]
    async fn obligations_coalesce_to_one_per_group_and_recipient_at_the_lowest_epoch() {
        let mut store = RekeyObligations::default();
        let now = store.clock.now_ms();
        let s1 = member(1);
        assert!(store
            .owe_entries(
                ROOM,
                std::slice::from_ref(&s1),
                rekey(5, 10),
                rekey(5, 10),
                now
            )
            .is_empty());
        assert!(store
            .owe_entries(
                ROOM,
                std::slice::from_ref(&s1),
                rekey(7, 12),
                rekey(8, 13),
                now
            )
            .is_empty());
        assert!(store
            .owe_entries(
                ROOM,
                std::slice::from_ref(&s1),
                rekey(4, 9),
                rekey(4, 9),
                now
            )
            .is_empty());
        store.owe_entries(
            "room-b",
            std::slice::from_ref(&s1),
            rekey(2, 3),
            rekey(2, 3),
            now,
        );
        assert_eq!(store.len(), 2, "one per (room, survivor)");
        let owed = store.get(ROOM, &s1).unwrap();
        assert_eq!(
            (
                owed.owed_epoch,
                owed.owed_revision,
                owed.through_epoch,
                owed.through_revision
            ),
            (4, 9, 8, 13),
            "the lowest owed and the highest to prove"
        );
        assert_eq!(owed.state, ObligationState::Owed);
        assert_eq!(owed.next_attempt_at_ms, now + 6_000);

        // A proof of the lowest epoch alone does not settle what came after.
        assert!(store.settle_entry(&rooms(&[ROOM]), &proof(&s1, 4, Some(9))));
        let owed = store.get(ROOM, &s1).unwrap();
        assert_eq!((owed.owed_epoch, owed.owed_revision), (5, 10));
        assert!(
            !store.settle_entry(&rooms(&[ROOM]), &proof(&s1, 3, Some(8))),
            "below what is owed changes nothing"
        );
        assert!(
            !store.settle_entry(&rooms(&["room-c"]), &proof(&s1, 99, None)),
            "another room's proof settles nothing here"
        );
        assert!(store.settle_entry(&rooms(&[ROOM]), &proof(&s1, 8, None)));
        assert!(store.get(ROOM, &s1).is_none(), "proven: settled");
        assert!(store.get("room-b", &s1).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_rekey_sends_a_delivered_obligation_again_soon() {
        let mut store = RekeyObligations::default();
        let s1 = member(1);
        let now = store.clock.now_ms();
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        tokio::time::advance(Duration::from_secs(6)).await;
        let now = store.clock.now_ms();
        let attempts = store.begin(now, &HashSet::new());
        assert!(store.finish(&attempts[0], Outcome::Delivered, now));
        assert_eq!(
            store.get(ROOM, &s1).unwrap().state,
            ObligationState::DeliveredUnproven
        );
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(6, 11),
            rekey(6, 11),
            now,
        );
        let owed = store.get(ROOM, &s1).unwrap();
        assert_eq!(owed.state, ObligationState::Owed);
        assert_eq!(owed.next_attempt_at_ms, now + 6_000);
        assert_eq!(owed.through_epoch, 6);
    }

    #[tokio::test(start_paused = true)]
    async fn ack_without_proof_keeps_the_obligation() {
        let mut store = RekeyObligations::default();
        let s1 = member(1);
        let now = store.clock.now_ms();
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(store
            .begin(store.clock.now_ms(), &HashSet::new())
            .is_empty());
        tokio::time::advance(Duration::from_secs(1)).await;
        let now = store.clock.now_ms();
        let attempts = store.begin(now, &HashSet::new());
        assert_eq!(recipients(&attempts), vec![s1.clone()]);
        assert!(store.finish(&attempts[0], Outcome::Delivered, now));
        let owed = store
            .get(ROOM, &s1)
            .expect("an acknowledgement is not proof");
        assert_eq!(owed.state, ObligationState::DeliveredUnproven);
        assert_eq!(owed.next_attempt_at_ms, now + MAX_DELAY_MS);
        assert!(!owed.in_flight);
        tokio::time::advance(Duration::from_millis(MAX_DELAY_MS - 1_000)).await;
        assert!(store
            .begin(store.clock.now_ms(), &HashSet::new())
            .is_empty());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            recipients(&store.begin(store.clock.now_ms(), &HashSet::new())),
            vec![s1]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_send_backs_off() {
        let mut store = RekeyObligations::default();
        let s1 = member(1);
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            store.clock.now_ms(),
        );
        for (count, wait_ms) in [(1u32, 6_000u64), (2, 15_000), (3, 30_000), (4, 60_000)] {
            tokio::time::advance(Duration::from_millis(wait_ms - 1)).await;
            assert!(store
                .begin(store.clock.now_ms(), &HashSet::new())
                .is_empty());
            tokio::time::advance(Duration::from_millis(1)).await;
            let now = store.clock.now_ms();
            let attempts = store.begin(now, &HashSet::new());
            assert_eq!(attempts.len(), 1, "attempt {count}");
            assert!(store.finish(&attempts[0], Outcome::Failed, now));
            let owed = store.get(ROOM, &s1).unwrap();
            assert_eq!(owed.attempt_count, count);
            assert_eq!(owed.state, ObligationState::Owed);
        }
        assert_eq!(
            store.get(ROOM, &s1).unwrap().next_attempt_at_ms,
            store.clock.now_ms() + 120_000
        );
    }

    #[tokio::test(start_paused = true)]
    async fn newly_connected_survivor_is_sent_at_once() {
        let mut store = RekeyObligations::default();
        let (s1, s2) = (member(1), member(2));
        let now = store.clock.now_ms();
        store.owe_entries(
            ROOM,
            &[s1.clone(), s2.clone()],
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        assert!(store.begin(now, &HashSet::new()).is_empty(), "not due yet");
        let attempts = store.begin(now, &connected(&[&s1]));
        assert_eq!(recipients(&attempts), vec![s1.clone()], "S1 just connected");
        assert!(store.finish(&attempts[0], Outcome::Failed, now));
        assert!(
            store.begin(now, &connected(&[&s1])).is_empty(),
            "staying connected is no new edge"
        );
        assert!(store.begin(now, &HashSet::new()).is_empty());
        assert_eq!(
            recipients(&store.begin(now, &connected(&[&s1]))),
            vec![s1.clone()],
            "a reconnect is an edge again"
        );

        // An edge with no free slot is not lost: the obligation is due.
        let mut store = RekeyObligations::default();
        let now = store.clock.now_ms();
        let many: Vec<String> = (1..=6).map(member).collect();
        store.owe_entries(ROOM, &many, rekey(5, 10), rekey(5, 10), now);
        let all: HashSet<String> = many.iter().cloned().collect();
        let first = store.begin(now, &all);
        assert_eq!(first.len(), MAX_IN_FLIGHT);
        for attempt in &first {
            store.finish(attempt, Outcome::Failed, now);
        }
        let rest = store.begin(now, &all);
        assert_eq!(
            rest.len(),
            2,
            "the two that connected while every slot was busy"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_four_attempts_run_at_once_and_none_twice() {
        let mut store = RekeyObligations::default();
        let many: Vec<String> = (1..=6).map(member).collect();
        store.owe_entries(
            ROOM,
            &many,
            rekey(5, 10),
            rekey(5, 10),
            store.clock.now_ms(),
        );
        tokio::time::advance(Duration::from_secs(6)).await;
        let now = store.clock.now_ms();
        let first = store.begin(now, &HashSet::new());
        assert_eq!(first.len(), MAX_IN_FLIGHT);
        assert!(
            store.begin(now, &HashSet::new()).is_empty(),
            "every slot is busy"
        );
        assert!(store.finish(&first[0], Outcome::Failed, now));
        let next = store.begin(now, &HashSet::new());
        assert_eq!(next.len(), 1);
        let started: Vec<String> = recipients(&first)
            .into_iter()
            .chain(recipients(&next))
            .collect();
        let unique: HashSet<&String> = started.iter().collect();
        assert_eq!(unique.len(), started.len(), "none twice: {started:?}");
        assert!(!recipients(&first).contains(&next[0].recipient_hex));
    }

    #[tokio::test(start_paused = true)]
    async fn a_send_that_ends_after_a_new_rekey_keeps_the_new_schedule() {
        let mut store = RekeyObligations::default();
        let s1 = member(1);
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            store.clock.now_ms(),
        );
        tokio::time::advance(Duration::from_secs(6)).await;
        let now = store.clock.now_ms();
        let attempts = store.begin(now, &HashSet::new());
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(6, 11),
            rekey(6, 11),
            now,
        );
        assert!(store.finish(&attempts[0], Outcome::Delivered, now));
        let owed = store.get(ROOM, &s1).unwrap();
        assert_eq!(
            owed.state,
            ObligationState::Owed,
            "the send carried only the older commit"
        );
        assert!(
            owed.next_attempt_at_ms <= now + 6_000,
            "a new re-key never pushes a send later"
        );
        assert_eq!(owed.attempt_count, 0);
        assert!(!owed.in_flight);
    }

    #[tokio::test(start_paused = true)]
    async fn per_group_cap_256_and_total_cap_4096() {
        let mut store = RekeyObligations::default();
        let now = store.clock.now_ms();
        let many: Vec<String> = (0..300).map(member).collect();
        let refused = store.owe_entries(ROOM, &many, rekey(5, 10), rekey(5, 10), now);
        assert_eq!(
            refused,
            many[ROOM_CAP..].to_vec(),
            "the newest are refused, for the blind schedule; none is dropped"
        );
        assert_eq!(store.room_count(ROOM), ROOM_CAP);
        assert!(
            store
                .owe_entries(ROOM, &many[..1], rekey(6, 11), rekey(6, 11), now)
                .is_empty(),
            "an existing obligation still takes a new re-key at the cap"
        );
        for room in 1..(TOTAL_CAP / ROOM_CAP) {
            let refused = store.owe_entries(
                &format!("room-{room}"),
                &many[..ROOM_CAP],
                rekey(5, 10),
                rekey(5, 10),
                now,
            );
            assert!(refused.is_empty());
        }
        assert_eq!(store.len(), TOTAL_CAP);
        assert_eq!(
            store.owe_entries("room-x", &many[..1], rekey(5, 10), rekey(5, 10), now),
            many[..1].to_vec(),
            "past the daemon's cap a new room is refused"
        );
        assert_eq!(store.len(), TOTAL_CAP);
    }

    fn live_room(local: &str, members: &[&String]) -> x0x::groups::GroupInfo {
        let creator = x0x::identity::AgentId(
            <[u8; 32]>::try_from(hex::decode(local).unwrap().as_slice()).unwrap(),
        );
        let mut info = x0x::groups::GroupInfo::new(
            "room".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
        );
        for member in members {
            info.add_member(
                (*member).clone(),
                x0x::groups::GroupRole::Member,
                Some(local.to_string()),
                None,
            );
        }
        info
    }

    #[tokio::test]
    async fn obligation_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let local = member(0xa);
        let (s1, s2, gone) = (member(1), member(2), member(3));
        let mut store = RekeyObligations {
            path: Some(dir.path().join(OBLIGATIONS_FILE)),
            ..RekeyObligations::default()
        };
        let now = store.clock.now_ms();
        store.owe_entries(
            ROOM,
            &[s1.clone(), s2.clone(), gone.clone()],
            rekey(5, 10),
            rekey(6, 11),
            now,
        );
        store.owe_entries(
            "gone-room",
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        let attempts = store.begin(now, &connected(&[&s2]));
        assert_eq!(attempts.len(), 1);
        store.persist().await.unwrap();
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(dir.path().join(OBLIGATIONS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let mut groups = HashMap::new();
        groups.insert(ROOM.to_string(), live_room(&local, &[&s1, &s2]));
        let loaded = load_rekey_obligations(dir.path(), &groups, &local).await;
        assert_eq!(
            loaded.len(),
            2,
            "a departed survivor and a gone room are dropped"
        );
        let mut expected = store.get(ROOM, &s1).unwrap().clone();
        expected.in_flight = false;
        assert_eq!(loaded.get(ROOM, &s1), Some(&expected));
        let s2_loaded = loaded.get(ROOM, &s2).unwrap();
        assert!(!s2_loaded.in_flight, "nothing is in flight after a restart");
        assert_eq!(s2_loaded.through_epoch, 6);

        // The dropped ones are gone from disk too.
        let again = load_rekey_obligations(dir.path(), &HashMap::new(), &local).await;
        assert_eq!(again.len(), 0);
        let text = std::fs::read_to_string(dir.path().join(OBLIGATIONS_FILE)).unwrap();
        assert!(!text.contains(&gone), "{text}");
    }

    #[tokio::test]
    async fn an_unreadable_file_loads_nothing_and_a_write_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let local = member(0xa);
        let s1 = member(1);
        std::fs::write(dir.path().join(OBLIGATIONS_FILE), b"{ not json").unwrap();
        let mut groups = HashMap::new();
        groups.insert(ROOM.to_string(), live_room(&local, &[&s1]));
        let mut loaded = load_rekey_obligations(dir.path(), &groups, &local).await;
        assert_eq!(loaded.len(), 0);
        let now = loaded.clock.now_ms();
        loaded.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        loaded.persist().await.unwrap();
        let reloaded = load_rekey_obligations(dir.path(), &groups, &local).await;
        assert!(reloaded.get(ROOM, &s1).is_some());
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![OBLIGATIONS_FILE.to_string()],
            "no temp file is left"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wiped_room_keeps_no_obligation() {
        let mut store = RekeyObligations::default();
        let s1 = member(1);
        let now = store.clock.now_ms();
        store.owe_entries(
            ROOM,
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        store.owe_entries(
            "room-b",
            std::slice::from_ref(&s1),
            rekey(5, 10),
            rekey(5, 10),
            now,
        );
        assert!(store.wipe(&rooms(&["stable-id", ROOM])));
        assert!(store.get(ROOM, &s1).is_none());
        assert!(store.get("room-b", &s1).is_some());
        assert!(!store.wipe(&rooms(&[ROOM])), "nothing left to wipe");
    }
}

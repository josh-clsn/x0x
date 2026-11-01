//! The TreeKEM catch-up log, kept on disk (survivor re-key A4,
//! `docs/adr/transient/T-catchup-log-on-disk.md`).
//!
//! A member serves the commit-bearing events it applied to a member who
//! missed them (`handle_treekem_catchup_request`). The log lived only in
//! memory, so a restart lost it. Each event is now also a file:
//!
//! `<data>/treekem/event-log/<blake3(group key)[..32]>/<revision:020>-<epoch:020>-<kind>-<blake3(event)[..16]>.json`
//!
//! - Every path component is a digest, a zero-padded number or a fixed kind
//!   name. Nothing a peer sends becomes part of a path.
//! - A file is written to a temp file at mode 0600, synced, renamed into
//!   place, and then its directory is synced.
//! - A room keeps at most [`ROOM_CAP`] events, and the daemon at most
//!   [`DISK_CAP_BYTES`] on disk, taken from the largest room first. An event
//!   over [`EVENT_LIMIT_BYTES`] is not kept at all. Whenever an event goes,
//!   or is not kept, the room records the highest revision it lost. A
//!   requester who needs a lost event gets no page and is told why.
//! - Every change runs under the `treekem_event_log` write lock. An append
//!   re-checks under that lock that the room is still there, so an append
//!   racing a wipe cannot bring the room's directory back.
//!
//! Lock order: `treekem_event_log`, then `named_groups`.

use super::{
    has_withdrawn_group_record, named_group_metadata_event_commit,
    named_group_metadata_event_group_id, named_group_metadata_event_kind, sync_dir_contents,
    AppState, NamedGroupMetadataEvent,
};
use crate as x0x;
use crate::logging::LogHexId;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The log's directory, under the daemon's TreeKEM directory.
pub(in crate::server) const EVENT_LOG_DIR: &str = "event-log";
/// The most events one room keeps.
pub(in crate::server) const ROOM_CAP: usize = 128;
/// The most bytes the log keeps on disk across every room.
pub(in crate::server) const DISK_CAP_BYTES: u64 = 256 * 1024 * 1024;
/// The largest event the log keeps. A Welcome-bearing add is about
/// 40-52 KiB, and one carrying a full roster-certificate sidecar (32
/// certificates) about 360 KiB. A larger event is not kept, in memory or on
/// disk, and its revision is recorded as lost, so one room holds at most
/// `ROOM_CAP` times this, 64 MiB, in memory and on disk.
pub(in crate::server) const EVENT_LIMIT_BYTES: u64 = 512 * 1024;
/// A room's record of the highest revision it lost.
const EVICTED_THROUGH_FILE: &str = "evicted-through";
const ROOM_DIR_HEX_LEN: usize = 32;
const EVENT_DIGEST_HEX_LEN: usize = 16;

/// Where a commit-bearing event sits in its room's signed chain.
pub(in crate::server) struct CommitBearingFrontier<'a> {
    pub(in crate::server) group_id: &'a str,
    /// The signed commit's revision.
    pub(in crate::server) revision: u64,
    /// The TreeKEM epoch the event names, or 0.
    pub(in crate::server) epoch: u64,
    kind: &'static str,
    commit: &'a x0x::groups::GroupStateCommit,
}

/// The frontier of every event that carries a roster commit, whatever its
/// kind. `None` for an event with no commit.
pub(in crate::server) fn commit_bearing_event_frontier(
    event: &NamedGroupMetadataEvent,
) -> Option<CommitBearingFrontier<'_>> {
    let commit = named_group_metadata_event_commit(event)?;
    Some(CommitBearingFrontier {
        group_id: named_group_metadata_event_group_id(event),
        revision: commit.revision,
        epoch: treekem_epoch_of(event).unwrap_or_default(),
        kind: named_group_metadata_event_kind(event),
        commit,
    })
}

fn treekem_epoch_of(event: &NamedGroupMetadataEvent) -> Option<u64> {
    match event {
        NamedGroupMetadataEvent::MemberAdded { treekem_epoch, .. }
        | NamedGroupMetadataEvent::MemberRemoved { treekem_epoch, .. }
        | NamedGroupMetadataEvent::MemberBanned { treekem_epoch, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { treekem_epoch, .. } => *treekem_epoch,
        _ => None,
    }
}

/// A join request and its cancellation are authored by the requester, who
/// is not a member and never serves catch-up. They apply only from their
/// author (A3), so no member's copy can help another member: they are not
/// logged. A stranger could otherwise fill the log of any request-access
/// room with them.
fn logged_kind(event: &NamedGroupMetadataEvent) -> bool {
    !matches!(
        event,
        NamedGroupMetadataEvent::JoinRequestCreated { .. }
            | NamedGroupMetadataEvent::JoinRequestCancelled { .. }
    )
}

/// How a served page orders its events: by signed revision, then epoch.
pub(in crate::server) fn commit_bearing_event_sort_key(
    event: &NamedGroupMetadataEvent,
) -> (u64, u64) {
    commit_bearing_event_frontier(event)
        .map(|frontier| (frontier.revision, frontier.epoch))
        .unwrap_or_default()
}

/// One commit is logged once. Two events that share a revision, an epoch
/// and a kind but carry different commits are both kept.
fn dedup_key(frontier: &CommitBearingFrontier<'_>) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        frontier.kind,
        frontier.revision,
        frontier.epoch,
        frontier.commit.committed_by,
        frontier.commit.state_hash
    )
}

/// A room's directory name: the first 32 hex digits of the blake3 of its
/// group key.
pub(in crate::server) fn room_dir_name(group_key: &str) -> String {
    let mut name = blake3::hash(group_key.as_bytes()).to_hex().to_string();
    name.truncate(ROOM_DIR_HEX_LEN);
    name
}

fn event_file_name(frontier: &CommitBearingFrontier<'_>, bytes: &[u8]) -> String {
    let mut digest = blake3::hash(bytes).to_hex().to_string();
    digest.truncate(EVENT_DIGEST_HEX_LEN);
    format!(
        "{:020}-{:020}-{}-{digest}.json",
        frontier.revision, frontier.epoch, frontier.kind
    )
}

fn is_room_dir_name(name: &str) -> bool {
    name.len() == ROOM_DIR_HEX_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One logged event's file.
struct Stored {
    key: String,
    bytes: u64,
    /// Append order across every room.
    seq: u64,
    revision: u64,
}

#[derive(Default)]
struct Room {
    /// By file name, which orders by revision and then epoch.
    files: BTreeMap<String, Stored>,
    evicted_through: Option<u64>,
    bytes: u64,
}

/// The catch-up log: the events in memory, which the serve path reads, and
/// the record of their files.
pub(in crate::server) struct EventLog {
    rooms: HashMap<String, VecDeque<NamedGroupMetadataEvent>>,
    stored: HashMap<String, Room>,
    /// `None` keeps the log in memory only.
    root: Option<PathBuf>,
    total_bytes: u64,
    next_seq: u64,
    disk_cap: u64,
}

impl Default for EventLog {
    fn default() -> Self {
        Self {
            rooms: HashMap::new(),
            stored: HashMap::new(),
            root: None,
            total_bytes: 0,
            next_seq: 0,
            disk_cap: DISK_CAP_BYTES,
        }
    }
}

impl std::ops::Deref for EventLog {
    type Target = HashMap<String, VecDeque<NamedGroupMetadataEvent>>;

    fn deref(&self) -> &Self::Target {
        &self.rooms
    }
}

impl std::ops::DerefMut for EventLog {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rooms
    }
}

impl EventLog {
    /// The highest revision any of `room_keys` lost: dropped to stay within
    /// a cap, too large to keep, or not written.
    pub(in crate::server) fn evicted_through(&self, room_keys: &[String]) -> Option<u64> {
        room_keys
            .iter()
            .filter_map(|key| self.stored.get(key)?.evicted_through)
            .max()
    }

    /// The bytes the log holds on disk.
    #[cfg(test)]
    pub(in crate::server) fn disk_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[cfg(test)]
    pub(in crate::server) fn set_disk_cap(&mut self, cap: u64) {
        self.disk_cap = cap;
    }

    fn room_dir(&self, room_key: &str) -> Option<PathBuf> {
        self.root
            .as_ref()
            .map(|root| root.join(room_dir_name(room_key)))
    }

    /// Log `event`, which this member applied or authored. The caller holds
    /// the write lock and has checked that the room is still there.
    async fn append(&mut self, event: &NamedGroupMetadataEvent) {
        let Some(frontier) = commit_bearing_event_frontier(event) else {
            return;
        };
        let key = dedup_key(&frontier);
        let room_key = frontier.group_id.to_string();
        let logged = self.rooms.get(&room_key).is_some_and(|events| {
            events.iter().any(|existing| {
                commit_bearing_event_frontier(existing).is_some_and(|f| dedup_key(&f) == key)
            })
        });
        if logged {
            return;
        }
        let bytes = match serde_json::to_vec(event) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(
                    group_id = %LogHexId::group(&room_key),
                    "catch-up log: event not logged, it does not serialize: {error}"
                );
                return;
            }
        };
        let revision = frontier.revision;
        let len = bytes.len() as u64;
        if len > EVENT_LIMIT_BYTES {
            // Not kept at all, so one room cannot grow the daemon's memory
            // by its committers' event sizes. A requester who needs it is
            // told this member cannot serve it.
            tracing::warn!(
                group_id = %LogHexId::group(&room_key),
                revision,
                bytes = len,
                limit = EVENT_LIMIT_BYTES,
                "catch-up log: event over the per-event limit is not kept; its revision is recorded as lost"
            );
            self.record_lost(&room_key, revision).await;
            return;
        }
        let name = event_file_name(&frontier, &bytes);
        if let Some(dir) = self.room_dir(&room_key) {
            let file = name.clone();
            if let Err(error) = run_blocking(move || write_durable(&dir, &file, &bytes)).await {
                // Kept nowhere, so this member's pages agree with what a
                // restart would hold: the revision is lost.
                tracing::warn!(
                    group_id = %LogHexId::group(&room_key),
                    file = %name,
                    revision,
                    "catch-up log: the write failed; the event is not kept and its revision is recorded as lost: {error}"
                );
                self.record_lost(&room_key, revision).await;
                return;
            }
        }
        self.rooms
            .entry(room_key.clone())
            .or_default()
            .push_back(event.clone());
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let room = self.stored.entry(room_key.clone()).or_default();
        room.files.insert(
            name,
            Stored {
                key,
                bytes: len,
                seq,
                revision,
            },
        );
        room.bytes = room.bytes.saturating_add(len);
        self.total_bytes = self.total_bytes.saturating_add(len);
        self.enforce_room_cap(&room_key).await;
        self.enforce_disk_cap().await;
    }

    async fn enforce_room_cap(&mut self, room_key: &str) {
        while self
            .stored
            .get(room_key)
            .is_some_and(|room| room.files.len() > ROOM_CAP)
        {
            self.evict_oldest(room_key).await;
        }
        // Only tests place events in memory without a record. They count
        // too, and their loss is recorded like any other.
        let mut lost = None;
        if let Some(events) = self.rooms.get_mut(room_key) {
            while events.len() > ROOM_CAP {
                let oldest = events
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, event)| commit_bearing_event_sort_key(event))
                    .map(|(index, event)| (index, commit_bearing_event_sort_key(event).0));
                let Some((index, revision)) = oldest else {
                    break;
                };
                events.remove(index);
                lost = lost.max(Some(revision));
            }
        }
        if let Some(revision) = lost {
            self.record_lost(room_key, revision).await;
        }
    }

    /// While over the daemon-wide cap, drop from the room with the most
    /// bytes on disk, so one busy room cannot push out another room's
    /// history.
    async fn enforce_disk_cap(&mut self) {
        while self.total_bytes > self.disk_cap {
            let largest = self
                .stored
                .iter()
                .filter(|(_, room)| room.bytes > 0)
                .max_by_key(|(_, room)| {
                    let oldest = room.files.values().next().map_or(u64::MAX, |s| s.seq);
                    (room.bytes, std::cmp::Reverse(oldest))
                })
                .map(|(room_key, _)| room_key.clone());
            let Some(room_key) = largest else {
                break;
            };
            if let Some(revision) = self.evict_oldest(&room_key).await {
                tracing::warn!(
                    group_id = %LogHexId::group(&room_key),
                    revision,
                    cap_bytes = self.disk_cap,
                    "catch-up log: over the daemon-wide cap, dropped the largest room's oldest event"
                );
            }
        }
    }

    /// Raise `room_key`'s lost revision to at least `revision`, and write it
    /// down. The raise holds in memory whatever the write does, so pages say
    /// so at once. Returns whether the record reached disk.
    async fn record_lost(&mut self, room_key: &str, revision: u64) -> bool {
        let room = self.stored.entry(room_key.to_string()).or_default();
        let through = room
            .evicted_through
            .map_or(revision, |through| through.max(revision));
        room.evicted_through = Some(through);
        let Some(dir) = self.room_dir(room_key) else {
            return true;
        };
        let marker = through.to_string().into_bytes();
        match run_blocking(move || write_durable(&dir, EVICTED_THROUGH_FILE, &marker)).await {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    group_id = %LogHexId::group(room_key),
                    through,
                    "catch-up log: recording a lost revision on disk failed; it holds in memory: {error}"
                );
                false
            }
        }
    }

    /// Drop `room_key`'s lowest-revision event, in memory and on disk. Its
    /// revision is recorded as lost before its file goes, so a crash in
    /// between never leaves a hole unrecorded. If that record does not reach
    /// disk, the file stays: a restart then serves the event again rather
    /// than skip it unannounced. Returns that revision.
    async fn evict_oldest(&mut self, room_key: &str) -> Option<u64> {
        let room = self.stored.get_mut(room_key)?;
        let (name, stored) = room.files.pop_first()?;
        room.bytes = room.bytes.saturating_sub(stored.bytes);
        self.total_bytes = self.total_bytes.saturating_sub(stored.bytes);
        if let Some(events) = self.rooms.get_mut(room_key) {
            events.retain(|event| {
                commit_bearing_event_frontier(event).is_none_or(|f| dedup_key(&f) != stored.key)
            });
        }
        if !self.record_lost(room_key, stored.revision).await {
            return Some(stored.revision);
        }
        if let Some(dir) = self.room_dir(room_key) {
            if let Err(error) = run_blocking(move || remove_if_present(&dir.join(&name))).await {
                tracing::warn!(
                    group_id = %LogHexId::group(room_key),
                    "catch-up log: dropping an event from disk failed: {error}"
                );
            }
        }
        Some(stored.revision)
    }

    /// Forget `room_key`, in memory and on disk. The caller holds the write
    /// lock, so no append can bring the directory back.
    pub(in crate::server) async fn wipe_room(&mut self, room_key: &str) {
        self.rooms.remove(room_key);
        if let Some(room) = self.stored.remove(room_key) {
            self.total_bytes = self.total_bytes.saturating_sub(room.bytes);
        }
        if let Some(dir) = self.room_dir(room_key) {
            if let Err(error) = run_blocking(move || remove_dir_if_present(&dir)).await {
                tracing::warn!(
                    group_id = %LogHexId::group(room_key),
                    "catch-up log: removing the room's directory failed: {error}"
                );
            }
        }
    }
}

fn find_room<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> Option<&'a x0x::groups::GroupInfo> {
    groups.get(group_id).or_else(|| {
        groups
            .values()
            .find(|info| info.stable_group_id() == group_id || info.mls_group_id == group_id)
    })
}

/// Whether this member may log an event of `group_id`: the room is in the
/// local roster under that key or alias, no record of it is withdrawn, and
/// the local agent is not banned from it.
///
/// It does not require the local agent to be active. A returning device
/// applies the re-key removal of itself just before its add re-seats it,
/// and a joiner applies the events its join result carries before its own
/// add. Both must log them, or they serve pages with a hole. Every
/// departure drops the room from the roster, tombstones it or bans the
/// local agent before it wipes the log, so this check still keeps a wiped
/// room's directory from coming back.
pub(in crate::server) fn event_log_room_accepts(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    local_agent_hex: &str,
) -> bool {
    find_room(groups, group_id)
        .is_some_and(|info| !info.withdrawn && !info.is_banned(local_agent_hex))
        && !has_withdrawn_group_record(groups, group_id)
}

/// Whether a restart keeps a room's log: as for an append, and the local
/// agent has a row in the room. A Removed row is kept: it is a returning
/// device between its re-key removal and its add, and dropping its log
/// there would leave the add it logs next with nothing before it. Every
/// other departure drops the row, and a ban is refused.
fn local_member_is_live(info: &x0x::groups::GroupInfo, local_agent_hex: &str) -> bool {
    !info.withdrawn
        && !info.is_banned(local_agent_hex)
        && info.members_v2.contains_key(local_agent_hex)
}

/// Log a commit-bearing event this member applied or authored, so it can
/// serve it on catch-up after a restart too.
pub(in crate::server) async fn remember_commit_bearing_event(
    state: &AppState,
    event: &NamedGroupMetadataEvent,
) {
    if commit_bearing_event_frontier(event).is_none() || !logged_kind(event) {
        return;
    }
    let group_id = named_group_metadata_event_group_id(event);
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut log = state.treekem_event_log.write().await;
    // Re-checked under the log lock: a wipe takes the same lock after it
    // has dropped or tombstoned the room, so either it sees this event and
    // removes it, or this check sees the room gone.
    {
        let groups = state.named_groups.read().await;
        if !event_log_room_accepts(&groups, group_id, &local_agent_hex) {
            return;
        }
    }
    log.append(event).await;
}

/// The rooms whose logs a restart keeps: directory name to group key, for
/// every key and alias of a live room.
fn live_room_dirs(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    local_agent_hex: &str,
) -> HashMap<String, String> {
    let mut live = HashMap::new();
    for (key, info) in groups {
        if !local_member_is_live(info, local_agent_hex) {
            continue;
        }
        for alias in [
            key.as_str(),
            info.stable_group_id(),
            info.mls_group_id.as_str(),
        ] {
            if !alias.is_empty() && !has_withdrawn_group_record(groups, alias) {
                live.insert(room_dir_name(alias), alias.to_string());
            }
        }
    }
    live
}

struct LoadedEvent {
    name: String,
    event: NamedGroupMetadataEvent,
    bytes: u64,
    modified: SystemTime,
}

struct LoadedRoom {
    key: String,
    events: Vec<LoadedEvent>,
    evicted_through: Option<u64>,
    /// The `evicted-through` file did not read back.
    marker_corrupt: bool,
}

#[derive(Default)]
struct LoadReport {
    rooms: Vec<LoadedRoom>,
    dropped_rooms: usize,
    skipped: Vec<PathBuf>,
    unreadable: Vec<(PathBuf, io::Error)>,
}

/// Load the log at startup, keeping only live rooms (`live_room_dirs`).
/// A room of an unknown, withdrawn or banned group, or one the local agent
/// has no row in, is removed.
/// A file that does not read back as the event its name describes is
/// skipped, logged and removed, so it is logged once. An entry that cannot
/// be read at all is skipped and logged, and the rest still loads.
pub(in crate::server) async fn load_event_log(
    treekem_dir: &Path,
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    local_agent_hex: &str,
) -> EventLog {
    let root = treekem_dir.join(EVENT_LOG_DIR);
    let live = live_room_dirs(groups, local_agent_hex);
    let load_root = root.clone();
    let report = match run_blocking(move || load_sync(&load_root, &live)).await {
        Ok(report) => report,
        Err(error) => {
            tracing::warn!(
                path = %root.display(),
                "catch-up log: not loaded, it serves from memory until the next restart: {error}"
            );
            return EventLog {
                root: Some(root),
                ..EventLog::default()
            };
        }
    };
    for path in &report.skipped {
        tracing::warn!(
            path = %path.display(),
            "catch-up log: skipped and removed a file that does not read back"
        );
    }
    for (path, error) in &report.unreadable {
        tracing::warn!(
            path = %path.display(),
            "catch-up log: skipped an entry that cannot be read: {error}"
        );
    }
    if report.dropped_rooms > 0 {
        tracing::info!(
            rooms = report.dropped_rooms,
            "catch-up log: removed the logs of rooms this member no longer serves"
        );
    }
    let mut log = EventLog {
        root: Some(root),
        ..EventLog::default()
    };
    // Append order is not kept on disk: the files' times stand in for it.
    let mut order: Vec<(SystemTime, String, String)> = Vec::new();
    let mut duplicates: Vec<(String, String)> = Vec::new();
    let mut lost: Vec<(String, u64)> = Vec::new();
    for room in report.rooms {
        let stored = log.stored.entry(room.key.clone()).or_default();
        stored.evicted_through = room.evicted_through;
        let events = log.rooms.entry(room.key.clone()).or_default();
        let mut lowest: Option<u64> = None;
        for loaded in room.events {
            let Some(frontier) = commit_bearing_event_frontier(&loaded.event) else {
                continue;
            };
            let key = dedup_key(&frontier);
            if stored.files.values().any(|existing| existing.key == key) {
                duplicates.push((room.key.clone(), loaded.name));
                continue;
            }
            let revision = frontier.revision;
            lowest = Some(lowest.map_or(revision, |held| held.min(revision)));
            stored.bytes = stored.bytes.saturating_add(loaded.bytes);
            log.total_bytes = log.total_bytes.saturating_add(loaded.bytes);
            order.push((loaded.modified, room.key.clone(), loaded.name.clone()));
            stored.files.insert(
                loaded.name,
                Stored {
                    key,
                    bytes: loaded.bytes,
                    seq: 0,
                    revision,
                },
            );
            events.push_back(loaded.event);
        }
        // If the record of what was lost does not read back, fail safe:
        // count every revision below the oldest one still held as lost.
        if room.marker_corrupt {
            if let Some(through) = lowest.map(|revision| revision.saturating_sub(1)) {
                lost.push((room.key.clone(), through));
            }
        }
    }
    order.sort();
    for (seq, (_, room_key, name)) in (0u64..).zip(order) {
        if let Some(stored) = log
            .stored
            .get_mut(&room_key)
            .and_then(|room| room.files.get_mut(&name))
        {
            stored.seq = seq;
        }
        log.next_seq = seq.saturating_add(1);
    }
    for (room_key, through) in lost {
        log.record_lost(&room_key, through).await;
    }
    for (room_key, name) in duplicates {
        if let Some(dir) = log.room_dir(&room_key) {
            let _ = run_blocking(move || remove_if_present(&dir.join(name))).await;
        }
    }
    let room_keys: Vec<String> = log.stored.keys().cloned().collect();
    for room_key in room_keys {
        log.enforce_room_cap(&room_key).await;
    }
    log.enforce_disk_cap().await;
    log
}

fn load_sync(root: &Path, live: &HashMap<String, String>) -> io::Result<LoadReport> {
    create_private_dir(root)?;
    let mut report = LoadReport::default();
    for entry in std::fs::read_dir(root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.unreadable.push((root.to_path_buf(), error));
                continue;
            }
        };
        let Some(dir_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if !is_dir || !is_room_dir_name(&dir_name) {
            continue;
        }
        let Some(room_key) = live.get(&dir_name) else {
            match remove_dir_if_present(&entry.path()) {
                Ok(()) => report.dropped_rooms += 1,
                Err(error) => report.unreadable.push((entry.path(), error)),
            }
            continue;
        };
        match load_room(&entry.path(), room_key, &mut report) {
            Ok(room) => report.rooms.push(room),
            Err(error) => report.unreadable.push((entry.path(), error)),
        }
    }
    Ok(report)
}

fn load_room(dir: &Path, room_key: &str, report: &mut LoadReport) -> io::Result<LoadedRoom> {
    let mut room = LoadedRoom {
        key: room_key.to_string(),
        events: Vec::new(),
        evicted_through: None,
        marker_corrupt: false,
    };
    for file in std::fs::read_dir(dir)? {
        let file = match file {
            Ok(file) => file,
            Err(error) => {
                report.unreadable.push((dir.to_path_buf(), error));
                continue;
            }
        };
        let path = file.path();
        let Some(name) = file.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !file.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        if let Err(error) = load_entry(&path, &name, room_key, &mut room, report) {
            report.unreadable.push((path, error));
        }
    }
    room.events.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(room)
}

fn load_entry(
    path: &Path,
    name: &str,
    room_key: &str,
    room: &mut LoadedRoom,
    report: &mut LoadReport,
) -> io::Result<()> {
    if name.starts_with('.') && name.ends_with(".tmp") {
        // A write that never reached its rename.
        return remove_if_present(path);
    }
    if name == EVICTED_THROUGH_FILE {
        match std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
        {
            Some(through) => room.evicted_through = Some(through),
            None => {
                room.marker_corrupt = true;
                remove_if_present(path)?;
                report.skipped.push(path.to_path_buf());
            }
        }
        return Ok(());
    }
    if !name.ends_with(".json") {
        return Ok(());
    }
    let bytes = std::fs::read(path)?;
    let event = serde_json::from_slice::<NamedGroupMetadataEvent>(&bytes)
        .ok()
        .filter(|event| {
            commit_bearing_event_frontier(event).is_some_and(|frontier| {
                frontier.group_id == room_key && event_file_name(&frontier, &bytes) == name
            })
        });
    let Some(event) = event else {
        remove_if_present(path)?;
        report.skipped.push(path.to_path_buf());
        return Ok(());
    };
    let modified = std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    room.events.push(LoadedEvent {
        name: name.to_string(),
        event,
        bytes: bytes.len() as u64,
        modified,
    });
    Ok(())
}

/// Run blocking file work off the runtime. Under the W3-H shim (#1245) it
/// runs inline, as `storage`'s file layer does, so task order stays fixed.
async fn run_blocking<T, F>(work: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    #[cfg(test)]
    if std::env::var_os("W3H_SHIM_ACTIVE").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return work();
    }
    tokio::task::spawn_blocking(work)
        .await
        .map_err(io::Error::other)?
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Write `bytes` to `dir/name`: a temp file at mode 0600, synced, renamed
/// into place, and then the directory synced. A directory created here is
/// also synced into its parent. Directory syncs are a no-op off unix
/// (`sync_dir_contents`).
fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    if !dir.is_dir() {
        create_private_dir(dir)?;
        if let Some(parent) = dir.parent() {
            sync_dir_contents(parent)?;
        }
    }
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|()| std::fs::rename(&tmp, dir.join(name))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    sync_dir_contents(dir)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn remove_dir_if_present(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const ADMIN: &str = "admin";

    fn commit(group_id: &str, revision: u64, state_hash: &str) -> x0x::groups::GroupStateCommit {
        x0x::groups::GroupStateCommit {
            group_id: group_id.to_string(),
            revision,
            prev_state_hash: Some(format!("state-{}", revision.saturating_sub(1))),
            roster_root: "roster".to_string(),
            policy_hash: "policy".to_string(),
            public_meta_hash: "meta".to_string(),
            security_binding: None,
            state_hash: state_hash.to_string(),
            withdrawn: false,
            committed_by: ADMIN.to_string(),
            committed_at: revision,
            signer_public_key: "pub".to_string(),
            signature: "sig".to_string(),
        }
    }

    /// A rename at `revision`, whose commit has `state_hash`.
    fn rename(
        group_id: &str,
        revision: u64,
        name: &str,
        state_hash: &str,
    ) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: group_id.to_string(),
            revision,
            actor: ADMIN.to_string(),
            name: Some(name.to_string()),
            description: None,
            commit: Some(commit(group_id, revision, state_hash)),
        }
    }

    fn at_revision(group_id: &str, revision: u64) -> NamedGroupMetadataEvent {
        rename(group_id, revision, "room", &format!("state-{revision}"))
    }

    fn on_disk(root: &Path) -> EventLog {
        EventLog {
            root: Some(root.to_path_buf()),
            ..EventLog::default()
        }
    }

    fn room_files(root: &Path, group_id: &str) -> Vec<String> {
        let dir = root.join(room_dir_name(group_id));
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".json"))
            .collect();
        names.sort();
        names
    }

    fn revisions(log: &EventLog, group_id: &str) -> Vec<u64> {
        let mut revisions: Vec<u64> = log
            .get(group_id)
            .map(|events| {
                events
                    .iter()
                    .map(|event| commit_bearing_event_sort_key(event).0)
                    .collect()
            })
            .unwrap_or_default();
        revisions.sort_unstable();
        revisions
    }

    fn local() -> x0x::identity::AgentId {
        x0x::identity::AgentId([7; 32])
    }

    fn other() -> x0x::identity::AgentId {
        x0x::identity::AgentId([9; 32])
    }

    fn group(mls_group_id: &str, creator: x0x::identity::AgentId) -> x0x::groups::GroupInfo {
        x0x::groups::GroupInfo::new(
            "room".to_string(),
            String::new(),
            creator,
            mls_group_id.to_string(),
        )
    }

    #[tokio::test]
    async fn per_room_and_daemon_wide_caps_hold() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let room = "a".repeat(64);

        let mut log = on_disk(&root);
        for revision in 1..=(ROOM_CAP as u64 + 2) {
            log.append(&at_revision(&room, revision)).await;
        }
        assert_eq!(log.get(&room).unwrap().len(), ROOM_CAP);
        assert_eq!(room_files(&root, &room).len(), ROOM_CAP);
        assert_eq!(
            revisions(&log, &room).first(),
            Some(&3),
            "the oldest two go"
        );
        assert_eq!(log.evicted_through(std::slice::from_ref(&room)), Some(2));
        let marker =
            std::fs::read_to_string(root.join(room_dir_name(&room)).join(EVICTED_THROUGH_FILE));
        assert_eq!(marker.unwrap(), "2", "the dropped revision is on disk");

        // The daemon-wide cap drops from the largest room; between equal rooms,
        // the one whose oldest event is older.
        let other_room = "b".repeat(64);
        let mut log = on_disk(&dir.path().join("second"));
        let one = serde_json::to_vec(&at_revision(&room, 1)).unwrap().len() as u64;
        log.set_disk_cap(one * 3);
        log.append(&at_revision(&room, 1)).await;
        log.append(&at_revision(&other_room, 1)).await;
        log.append(&at_revision(&room, 2)).await;
        log.append(&at_revision(&other_room, 2)).await;
        assert!(
            log.disk_bytes() <= one * 3,
            "the cap holds: {}",
            log.disk_bytes()
        );
        assert_eq!(
            revisions(&log, &room),
            vec![2],
            "the oldest of the two equal rooms gives up its oldest event"
        );
        assert_eq!(revisions(&log, &other_room), vec![1, 2]);
        assert_eq!(room_files(&dir.path().join("second"), &room).len(), 1);
        assert_eq!(log.evicted_through(std::slice::from_ref(&room)), Some(1));
        assert_eq!(log.evicted_through(&[other_room]), None);
    }

    #[tokio::test]
    async fn two_events_sharing_revision_epoch_and_kind_both_persist() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let room = "c".repeat(64);
        let first = rename(&room, 5, "one", "state-one");
        let second = rename(&room, 5, "two", "state-two");

        let mut log = on_disk(&root);
        log.append(&first).await;
        log.append(&second).await;
        log.append(&first).await;
        assert_eq!(log.get(&room).unwrap().len(), 2, "a repeat is logged once");
        let files = room_files(&root, &room);
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files.iter().all(|name| name
            .starts_with("00000000000000000005-00000000000000000000-group_metadata_updated-")));

        let mut groups = HashMap::new();
        groups.insert(room.clone(), group(&room, local()));
        let reloaded = load_event_log(dir.path(), &groups, &hex::encode(local().as_bytes())).await;
        let events = reloaded.get(&room).unwrap();
        assert!(events.contains(&first) && events.contains(&second));
    }

    #[tokio::test]
    async fn files_are_0600_and_a_torn_write_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let room = "d".repeat(64);
        let mut log = on_disk(&root);
        log.append(&at_revision(&room, 1)).await;
        log.append(&at_revision(&room, 2)).await;

        let room_dir = root.join(room_dir_name(&room));
        let files = room_files(&root, &room);
        assert_eq!(files.len(), 2);
        #[cfg(unix)]
        {
            for name in &files {
                let mode = std::fs::metadata(room_dir.join(name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
            let dir_mode = std::fs::metadata(&room_dir).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
        assert!(!files.iter().any(|name| name.contains('/')));
        assert_eq!(room_dir_name(&room).len(), 32);

        // A torn copy of the second event, and a write that never reached its rename.
        let torn = room_dir.join(&files[1]);
        let bytes = std::fs::read(&torn).unwrap();
        std::fs::write(&torn, &bytes[..bytes.len() / 2]).unwrap();
        let leftover = room_dir.join(format!(".{}.1.tmp", files[0]));
        std::fs::write(&leftover, b"{").unwrap();

        let mut groups = HashMap::new();
        groups.insert(room.clone(), group(&room, local()));
        let reloaded = load_event_log(dir.path(), &groups, &hex::encode(local().as_bytes())).await;
        assert_eq!(
            revisions(&reloaded, &room),
            vec![1],
            "the torn file is skipped"
        );
        assert!(!torn.exists(), "and removed, so it is logged once");
        assert!(!leftover.exists());
    }

    #[tokio::test]
    async fn event_log_load_drops_unknown_withdrawn_banned_and_no_local_row_groups() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let local_hex = hex::encode(local().as_bytes());
        let [live, unknown, withdrawn, banned, inactive] =
            ["1", "2", "3", "4", "5"].map(|digit| digit.repeat(64));

        let mut log = on_disk(&root);
        for room in [&live, &unknown, &withdrawn, &banned, &inactive] {
            log.append(&at_revision(room, 1)).await;
        }
        let mut groups = HashMap::new();
        groups.insert(live.clone(), group(&live, local()));
        let mut info = group(&withdrawn, local());
        info.withdrawn = true;
        groups.insert(withdrawn.clone(), info);
        let mut info = group(&banned, other());
        info.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info.ban_member(&local_hex, Some(hex::encode(other().as_bytes())));
        groups.insert(banned.clone(), info);
        // Inactive: the local agent has no row in the room.
        groups.insert(inactive.clone(), group(&inactive, other()));
        // Mid re-key: the local agent's row is Removed until its add lands.
        let rekeying = "6".repeat(64);
        log.append(&at_revision(&rekeying, 1)).await;
        let mut info = group(&rekeying, other());
        info.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info.remove_member(&local_hex, Some(hex::encode(other().as_bytes())));
        groups.insert(rekeying.clone(), info);

        let reloaded = load_event_log(dir.path(), &groups, &local_hex).await;
        assert_eq!(revisions(&reloaded, &live), vec![1]);
        assert_eq!(
            revisions(&reloaded, &rekeying),
            vec![1],
            "a device mid re-key keeps its log"
        );
        for room in [&unknown, &withdrawn, &banned, &inactive] {
            assert!(reloaded.get(room).is_none(), "{room} is not loaded");
            assert!(
                !root.join(room_dir_name(room)).exists(),
                "{room}'s directory is removed"
            );
        }
        assert!(root.join(room_dir_name(&live)).exists());
    }

    #[test]
    fn every_kind_with_a_commit_has_a_frontier() {
        let room = "e".repeat(64);
        let with_commit = |revision| Some(commit(&room, revision, "s"));
        let events = vec![
            NamedGroupMetadataEvent::JoinRequestCreated {
                group_id: room.clone(),
                request_id: "r".to_string(),
                requester_agent_id: "q".to_string(),
                message: None,
                ts: 1,
                requester_kem_public_key_b64: None,
                treekem_key_package_b64: None,
                commit: with_commit(1),
            },
            NamedGroupMetadataEvent::JoinRequestRejected {
                group_id: room.clone(),
                request_id: "r".to_string(),
                actor: ADMIN.to_string(),
                requester_agent_id: "q".to_string(),
                commit: with_commit(2),
            },
            NamedGroupMetadataEvent::JoinRequestCancelled {
                group_id: room.clone(),
                request_id: "r".to_string(),
                requester_agent_id: "q".to_string(),
                commit: with_commit(3),
            },
            NamedGroupMetadataEvent::GroupDeleted {
                group_id: room.clone(),
                revision: 4,
                actor: ADMIN.to_string(),
                commit: with_commit(4),
            },
        ];
        for (revision, event) in (1u64..).zip(&events) {
            let frontier = commit_bearing_event_frontier(event).expect("a frontier");
            assert_eq!(frontier.revision, revision);
            assert_eq!(frontier.group_id, room);
        }
        let unsigned = NamedGroupMetadataEvent::GroupDeleted {
            group_id: room,
            revision: 5,
            actor: ADMIN.to_string(),
            commit: None,
        };
        assert!(commit_bearing_event_frontier(&unsigned).is_none());
    }

    #[tokio::test]
    async fn a_flooding_room_cannot_evict_another_rooms_events() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let quiet = "f".repeat(64);
        let busy = "0".repeat(64);
        let one = serde_json::to_vec(&at_revision(&quiet, 1)).unwrap().len() as u64;
        let mut log = on_disk(&root);
        log.set_disk_cap(one * 8);
        log.append(&at_revision(&quiet, 1)).await;
        log.append(&at_revision(&quiet, 2)).await;
        for revision in 1..=64 {
            log.append(&at_revision(&busy, revision)).await;
        }
        assert!(log.disk_bytes() <= one * 8);
        assert_eq!(
            revisions(&log, &quiet),
            vec![1, 2],
            "the quiet room keeps its history"
        );
        assert_eq!(log.evicted_through(std::slice::from_ref(&quiet)), None);
        assert_eq!(room_files(&root, &quiet).len(), 2);
        assert!(log.evicted_through(std::slice::from_ref(&busy)).is_some());
    }

    #[tokio::test]
    async fn a_flood_of_oversized_events_keeps_nothing_and_records_the_loss() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let room = "9".repeat(64);
        let big_name = "x".repeat(usize::try_from(EVENT_LIMIT_BYTES).unwrap() + 1);
        let mut log = on_disk(&root);
        log.append(&at_revision(&room, 1)).await;
        for revision in 2..=(ROOM_CAP as u64 * 2) {
            log.append(&rename(
                &room,
                revision,
                &big_name,
                &format!("state-{revision}"),
            ))
            .await;
        }
        assert_eq!(
            revisions(&log, &room),
            vec![1],
            "no oversized event is kept in memory"
        );
        let held: usize = log
            .get(&room)
            .unwrap()
            .iter()
            .map(|event| serde_json::to_vec(event).unwrap().len())
            .sum();
        assert!(
            held as u64 <= EVENT_LIMIT_BYTES,
            "memory stays bounded: {held}"
        );
        assert_eq!(room_files(&root, &room).len(), 1, "nor on disk");
        assert!(log.disk_bytes() <= EVENT_LIMIT_BYTES);
        let lost = ROOM_CAP as u64 * 2;
        assert_eq!(
            log.evicted_through(std::slice::from_ref(&room)),
            Some(lost),
            "and each one is recorded as lost at once"
        );

        let mut groups = HashMap::new();
        groups.insert(room.clone(), group(&room, local()));
        let reloaded = load_event_log(dir.path(), &groups, &hex::encode(local().as_bytes())).await;
        assert_eq!(revisions(&reloaded, &room), vec![1]);
        assert_eq!(
            reloaded.evicted_through(std::slice::from_ref(&room)),
            Some(lost),
            "the loss survives a restart"
        );
    }

    #[tokio::test]
    async fn a_failed_record_of_a_loss_holds_in_memory_and_keeps_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let room = "5".repeat(64);
        let mut log = on_disk(&root);
        log.append(&at_revision(&room, 1)).await;
        log.append(&at_revision(&room, 2)).await;
        // The record cannot be written: its name is taken by a directory.
        let room_dir = root.join(room_dir_name(&room));
        std::fs::create_dir(room_dir.join(EVICTED_THROUGH_FILE)).unwrap();
        assert_eq!(log.evict_oldest(&room).await, Some(1));
        assert_eq!(
            log.evicted_through(std::slice::from_ref(&room)),
            Some(1),
            "pages say so at once"
        );
        assert_eq!(revisions(&log, &room), vec![2]);
        assert_eq!(
            room_files(&root, &room).len(),
            2,
            "the file stays, so a restart serves it rather than skip it unannounced"
        );
    }

    #[tokio::test]
    async fn an_unreadable_record_of_losses_fails_safe() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(EVENT_LOG_DIR);
        let room = "8".repeat(64);
        let mut log = on_disk(&root);
        for revision in 5..=7 {
            log.append(&at_revision(&room, revision)).await;
        }
        let marker = root.join(room_dir_name(&room)).join(EVICTED_THROUGH_FILE);
        std::fs::write(&marker, b"not a number").unwrap();
        let mut groups = HashMap::new();
        groups.insert(room.clone(), group(&room, local()));
        let reloaded = load_event_log(dir.path(), &groups, &hex::encode(local().as_bytes())).await;
        assert_eq!(revisions(&reloaded, &room), vec![5, 6, 7]);
        assert_eq!(
            reloaded.evicted_through(std::slice::from_ref(&room)),
            Some(4),
            "everything below the oldest held revision counts as lost"
        );
    }

    #[test]
    fn appends_need_the_room_present_unwithdrawn_and_not_banned() {
        let local_hex = hex::encode(local().as_bytes());
        let other_hex = hex::encode(other().as_bytes());
        let id = "7".repeat(64);
        let with = |info: x0x::groups::GroupInfo| {
            let mut groups = HashMap::new();
            groups.insert(id.clone(), info);
            groups
        };
        assert!(event_log_room_accepts(
            &with(group(&id, local())),
            &id,
            &local_hex
        ));
        let mut removed = group(&id, other());
        removed.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        removed.remove_member(&local_hex, Some(other_hex.clone()));
        assert!(
            event_log_room_accepts(&with(removed), &id, &local_hex),
            "a returning device mid re-key still logs its own removal"
        );
        let mut banned = group(&id, other());
        banned.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        banned.ban_member(&local_hex, Some(other_hex));
        assert!(!event_log_room_accepts(&with(banned), &id, &local_hex));
        let mut withdrawn = group(&id, local());
        withdrawn.withdrawn = true;
        assert!(!event_log_room_accepts(&with(withdrawn), &id, &local_hex));
        assert!(!event_log_room_accepts(&HashMap::new(), &id, &local_hex));
    }
}

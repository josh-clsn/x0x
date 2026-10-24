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
//!   [`DISK_CAP_BYTES`]. Past either cap the oldest event goes, and the room
//!   records the highest revision it dropped. A requester who needs a
//!   dropped event gets no page and is told why.
//! - Every change runs under the `treekem_event_log` write lock. An append
//!   re-checks under that lock that the room is still live, so an append
//!   racing a wipe cannot bring the room's directory back.
//!
//! Lock order: `treekem_event_log`, then `named_groups`.

use super::{
    has_withdrawn_group_record, named_group_metadata_event_commit,
    named_group_metadata_event_group_id, named_group_metadata_event_kind, AppState,
    NamedGroupMetadataEvent,
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
/// The most bytes the log keeps across every room.
pub(in crate::server) const DISK_CAP_BYTES: u64 = 256 * 1024 * 1024;
/// A room's record of the highest revision it dropped.
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

/// One event's file.
struct Stored {
    key: String,
    bytes: u64,
    /// Append order across every room. The disk cap drops the lowest.
    seq: u64,
    revision: u64,
}

#[derive(Default)]
struct Room {
    /// By file name, which orders by revision and then epoch.
    files: BTreeMap<String, Stored>,
    evicted_through: Option<u64>,
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
    /// The highest revision any of `room_keys` dropped to stay within a cap.
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
    /// the write lock and has checked that the room is live.
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
        let name = event_file_name(&frontier, &bytes);
        let revision = frontier.revision;
        let len = bytes.len() as u64;
        if let Some(dir) = self.room_dir(&room_key) {
            let file = name.clone();
            if let Err(error) = run_blocking(move || write_durable(&dir, &file, &bytes)).await {
                // It still serves from memory until the next restart.
                tracing::warn!(
                    group_id = %LogHexId::group(&room_key),
                    file = %name,
                    "catch-up log: event kept in memory only, the write failed: {error}"
                );
            }
        }
        self.rooms
            .entry(room_key.clone())
            .or_default()
            .push_back(event.clone());
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.stored
            .entry(room_key.clone())
            .or_default()
            .files
            .insert(
                name,
                Stored {
                    key,
                    bytes: len,
                    seq,
                    revision,
                },
            );
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
        // Events placed in memory without a file (tests do) still count.
        if let Some(events) = self.rooms.get_mut(room_key) {
            while events.len() > ROOM_CAP {
                let oldest = events
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, event)| commit_bearing_event_sort_key(event))
                    .map(|(index, _)| index);
                match oldest {
                    Some(index) => {
                        events.remove(index);
                    }
                    None => break,
                }
            }
        }
    }

    async fn enforce_disk_cap(&mut self) {
        while self.total_bytes > self.disk_cap {
            let oldest = self
                .stored
                .iter()
                .filter_map(|(room_key, room)| {
                    room.files
                        .values()
                        .next()
                        .map(|stored| (stored.seq, room_key))
                })
                .min()
                .map(|(_, room_key)| room_key.clone());
            let Some(room_key) = oldest else {
                break;
            };
            if let Some(revision) = self.evict_oldest(&room_key).await {
                tracing::warn!(
                    group_id = %LogHexId::group(&room_key),
                    revision,
                    cap_bytes = self.disk_cap,
                    "catch-up log: over the daemon-wide cap, dropped the oldest event"
                );
            }
        }
    }

    /// Drop `room_key`'s lowest-revision event, in memory and on disk, and
    /// record its revision as dropped. Returns that revision.
    async fn evict_oldest(&mut self, room_key: &str) -> Option<u64> {
        let room = self.stored.get_mut(room_key)?;
        let (name, stored) = room.files.pop_first()?;
        let evicted_through = room
            .evicted_through
            .map_or(stored.revision, |through| through.max(stored.revision));
        room.evicted_through = Some(evicted_through);
        self.total_bytes = self.total_bytes.saturating_sub(stored.bytes);
        if let Some(events) = self.rooms.get_mut(room_key) {
            events.retain(|event| {
                commit_bearing_event_frontier(event).is_none_or(|f| dedup_key(&f) != stored.key)
            });
        }
        if let Some(dir) = self.room_dir(room_key) {
            let marker = evicted_through.to_string().into_bytes();
            let result = run_blocking(move || {
                remove_if_present(&dir.join(&name))?;
                write_durable(&dir, EVICTED_THROUGH_FILE, &marker)
            })
            .await;
            if let Err(error) = result {
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
            let bytes: u64 = room.files.values().map(|stored| stored.bytes).sum();
            self.total_bytes = self.total_bytes.saturating_sub(bytes);
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

/// Whether this member may log or serve `group_id`: the room exists under
/// that key or alias, no record of it is withdrawn, and the local agent is
/// an active member who is not banned.
pub(in crate::server) fn event_log_room_is_live(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    local_agent_hex: &str,
) -> bool {
    let info = groups.get(group_id).or_else(|| {
        groups
            .values()
            .find(|info| info.stable_group_id() == group_id || info.mls_group_id == group_id)
    });
    info.is_some_and(|info| local_member_is_live(info, local_agent_hex))
        && !has_withdrawn_group_record(groups, group_id)
}

fn local_member_is_live(info: &x0x::groups::GroupInfo, local_agent_hex: &str) -> bool {
    !info.withdrawn && !info.is_banned(local_agent_hex) && info.has_active_member(local_agent_hex)
}

/// Log a commit-bearing event this member applied or authored, so it can
/// serve it on catch-up after a restart too.
pub(in crate::server) async fn remember_commit_bearing_event(
    state: &AppState,
    event: &NamedGroupMetadataEvent,
) {
    if commit_bearing_event_frontier(event).is_none() {
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
        if !event_log_room_is_live(&groups, group_id, &local_agent_hex) {
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
}

#[derive(Default)]
struct LoadReport {
    rooms: Vec<LoadedRoom>,
    dropped_rooms: usize,
    skipped: Vec<PathBuf>,
}

/// Load the log at startup, keeping only live rooms (`live_room_dirs`).
/// A room of an unknown, withdrawn, banned or inactive group is removed.
/// A file that does not read back as the event its name describes is
/// skipped, logged and removed, so it is logged once.
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
            "catch-up log: skipped and removed a file that does not read back as its event"
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
    for room in report.rooms {
        let stored = log.stored.entry(room.key.clone()).or_default();
        stored.evicted_through = room.evicted_through;
        let events = log.rooms.entry(room.key.clone()).or_default();
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
        let entry = entry?;
        let Some(dir_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !entry.file_type()?.is_dir() || !is_room_dir_name(&dir_name) {
            continue;
        }
        let Some(room_key) = live.get(&dir_name) else {
            remove_dir_if_present(&entry.path())?;
            report.dropped_rooms += 1;
            continue;
        };
        let mut room = LoadedRoom {
            key: room_key.clone(),
            events: Vec::new(),
            evicted_through: None,
        };
        for file in std::fs::read_dir(entry.path())? {
            let file = file?;
            let path = file.path();
            let Some(name) = file.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !file.file_type()?.is_file() {
                continue;
            }
            if name.starts_with('.') && name.ends_with(".tmp") {
                // A write that never reached its rename.
                remove_if_present(&path)?;
                continue;
            }
            if name == EVICTED_THROUGH_FILE {
                match std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| text.trim().parse::<u64>().ok())
                {
                    Some(through) => room.evicted_through = Some(through),
                    None => {
                        remove_if_present(&path)?;
                        report.skipped.push(path);
                    }
                }
                continue;
            }
            if !name.ends_with(".json") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let event = serde_json::from_slice::<NamedGroupMetadataEvent>(&bytes)
                .ok()
                .filter(|event| {
                    commit_bearing_event_frontier(event).is_some_and(|frontier| {
                        frontier.group_id == room_key.as_str()
                            && event_file_name(&frontier, &bytes) == name
                    })
                });
            let Some(event) = event else {
                remove_if_present(&path)?;
                report.skipped.push(path);
                continue;
            };
            let modified = file
                .metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            room.events.push(LoadedEvent {
                name,
                event,
                bytes: bytes.len() as u64,
                modified,
            });
        }
        room.events.sort_by(|a, b| a.name.cmp(&b.name));
        report.rooms.push(room);
    }
    Ok(report)
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
/// into place, and then the directory synced.
fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    create_private_dir(dir)?;
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
    std::fs::File::open(dir)?.sync_all()
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

        // The daemon-wide cap drops the oldest event across every room.
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
            "the oldest event of all went"
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
        for name in &files {
            let mode = std::fs::metadata(room_dir.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        let dir_mode = std::fs::metadata(&room_dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
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
    async fn event_log_load_drops_unknown_withdrawn_banned_and_inactive_groups() {
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
        let mut info = group(&inactive, other());
        info.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info.remove_member(&local_hex, Some(hex::encode(other().as_bytes())));
        groups.insert(inactive.clone(), info);

        let reloaded = load_event_log(dir.path(), &groups, &local_hex).await;
        assert_eq!(revisions(&reloaded, &live), vec![1]);
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
}

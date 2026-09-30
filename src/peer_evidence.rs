//! ADR 0089 S1: inert, self-verifying relationship evidence.
//!
//! No runtime authority consumer is connected in S1. Callers supply current
//! relationship/revocation policy; views must never be copied into other caches.
//! All times are Unix milliseconds. Certificate issuance is not a heartbeat:
//! W/L apply to announcement/advert, while certificates have their own expiry.
use crate::{
    announce_v3::{self, IdentityAnnouncementV3},
    dm_capability::CapabilityAdvert,
    identity::{AgentCertificate, AgentId, MachineId, UserId},
};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Ingest freshness window (15 minutes).
pub const W_MS: u64 = 15 * 60 * 1000;
/// Maximum permitted future skew.
pub const SKEW_MS: u64 = 5 * 60 * 1000;
/// Milliseconds in a day.
pub const DAY_MS: u64 = 86_400_000;
/// Announcement byte ceiling.
pub const ANNOUNCEMENT_CAP: usize = 8 * 1024;
/// Advert byte ceiling, including registry trailer.
pub const ADVERT_CAP: usize = 12 * 1024;
/// Certificate byte ceiling.
pub const CERTIFICATE_CAP: usize = 10 * 1024;
/// Total signed-part ceiling.
pub const RECORD_BYTES_CAP: usize = 30 * 1024;
/// Total file ceiling, including magic and framing.
pub const FILE_CAP: usize = 16 * 1024 * 1024;
/// Maximum records.
pub const RECORD_CAP: usize = 512;
/// Maximum move watermarks.
pub const WATERMARK_CAP: usize = 4096;
/// Frozen V1 body discriminator.
pub const MAGIC: &[u8; 8] = b"X0PEV1\0\0";
/// Enrolled-device relationship flag (highest retention priority).
pub const ENROLLED: u8 = 1;
/// Grant-counterparty relationship flag.
pub const GRANT: u8 = 2;
/// Active shared-group relationship flag.
pub const GROUP: u8 = 4;

/// TOML `[evidence]` settings. Accepted ADR overrides the plan's stale 30 days.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceConfig {
    /// Stored authority lifetime, inclusive range 1..=7.
    pub max_age_days: u64,
}
impl Default for EvidenceConfig {
    fn default() -> Self {
        Self { max_age_days: 7 }
    }
}
impl EvidenceConfig {
    /// Reject settings outside the Accepted lifetime bound.
    pub fn validate(&self) -> Result<()> {
        if !(1..=7).contains(&self.max_age_days) {
            return Err(EvidenceError::Invalid(
                "[evidence] max_age_days must be 1..=7",
            ));
        }
        Ok(())
    }
}
/// Evidence rejection or persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Invalid, stale or unauthorized evidence.
    #[error("invalid evidence: {0}")]
    Invalid(&'static str),
    /// Disk operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Positional format error.
    #[error(transparent)]
    Codec(#[from] bincode::Error),
}
type Result<T> = std::result::Result<T, EvidenceError>;

/// Frozen V1 positional shape. Never add/reorder fields: introduce V2 instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecordV1 {
    /// Verbatim X0A3/X0A4 wire body, excluding gossip envelope.
    pub announcement: Vec<u8>,
    /// Verbatim advert body including optional X0CR trailer.
    pub advert: Vec<u8>,
    /// Optional certificate bytes (AgentCertificate storage encoding).
    pub certificate: Option<Vec<u8>>,
    /// Relationship flags; bookkeeping, never an authority source.
    pub relation: u8,
    /// Local bookkeeping, never used for signed freshness.
    pub stored_at_ms: u64,
}
/// Frozen move watermark. Same-machine refreshes never advance it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoveWatermarkV1 {
    /// Signed advert timestamp.
    pub t: u64,
    /// Destination machine.
    pub machine: MachineId,
}
/// Frozen V1 snapshot; map keys are portable agent identities.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFileV1 {
    /// Signed records.
    pub records: HashMap<AgentId, EvidenceRecordV1>,
    /// Move protection survives record eviction.
    pub watermarks: HashMap<AgentId, MoveWatermarkV1>,
}
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(FILE_CAP as u64)
        .reject_trailing_bytes()
}
impl EvidenceFileV1 {
    fn bounds(&self) -> Result<()> {
        if self.records.len() > RECORD_CAP || self.watermarks.len() > WATERMARK_CAP {
            return Err(EvidenceError::Invalid("entry cap"));
        }
        for r in self.records.values() {
            r.bounds()?;
        }
        Ok(())
    }
    /// Encode with explicit version, hard bounds and the frozen layout.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bounds()?;
        let size = options().serialized_size(self)?;
        if size > (FILE_CAP - MAGIC.len()) as u64 {
            return Err(EvidenceError::Invalid("file cap"));
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(options().serialize(self)?);
        Ok(bytes)
    }
    /// Decode exactly; unknown versions and trailing bytes fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FILE_CAP {
            return Err(EvidenceError::Invalid("file cap"));
        }
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or(EvidenceError::Invalid("unknown magic"))?;
        let file: Self = options().deserialize(body)?;
        file.bounds()?;
        Ok(file)
    }
}
/// Verified material for one point-of-use decision. Registry bits are cleared.
#[derive(Debug, Clone)]
pub struct EvidenceView {
    /// Verified machine-signed identity.
    pub announcement: IdentityAnnouncementV3,
    /// Verified agent-signed key material; persisted registry bits stay unknown.
    pub advert: CapabilityAdvert,
    /// Verified owner certificate, if supplied.
    pub certificate: Option<AgentCertificate>,
}
fn fresh(t: u64, now: u64, age: u64) -> bool {
    t <= now.saturating_add(SKEW_MS) && now.saturating_sub(t) <= age
}
fn announcement_ms(a: &IdentityAnnouncementV3) -> Result<u64> {
    a.announced_at
        .checked_mul(1000)
        .ok_or(EvidenceError::Invalid("timestamp overflow"))
}
fn verify_advert(bytes: &[u8], key: &[u8], now: u64, age: u64) -> Result<CapabilityAdvert> {
    if bytes.len() > ADVERT_CAP {
        return Err(EvidenceError::Invalid("advert cap"));
    }
    let (mut advert, trailer) = CapabilityAdvert::decode_evidence(bytes)
        .map_err(|_| EvidenceError::Invalid("advert encoding"))?;
    if advert.protocol_version != crate::dm_capability_service::ADVERT_PROTOCOL_VERSION
        || !fresh(advert.created_at_unix_ms, now, age)
        || !crate::dm_capability_service::verify_advert_signature(&advert, key)
    {
        return Err(EvidenceError::Invalid("advert signature or freshness"));
    }
    if let Some(trailer) = trailer {
        let bytes = trailer
            .signed_bytes(&advert)
            .map_err(|_| EvidenceError::Invalid("trailer encoding"))?;
        let key = ant_quic::MlDsaPublicKey::from_bytes(key)
            .map_err(|_| EvidenceError::Invalid("agent key"))?;
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&trailer.signature)
                .map_err(|_| EvidenceError::Invalid("trailer signature"))?;
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&key, &bytes, &signature)
            .map_err(|_| EvidenceError::Invalid("trailer signature"))?;
    }
    advert.capabilities.application_registry = Default::default();
    Ok(advert)
}
impl EvidenceRecordV1 {
    fn bounds(&self) -> Result<()> {
        if self.announcement.len() > ANNOUNCEMENT_CAP
            || self.advert.len() > ADVERT_CAP
            || self
                .certificate
                .as_ref()
                .is_some_and(|c| c.len() > CERTIFICATE_CAP)
        {
            return Err(EvidenceError::Invalid("component byte cap"));
        }
        Ok(())
    }
    fn ordering_view(&self, now: u64) -> Result<EvidenceView> {
        let mut pair = self.clone();
        pair.certificate = None;
        pair.verify(now, u64::MAX)
    }

    /// Re-verify all signed bytes. Use W for network ingest, L for stored use.
    pub fn verify(&self, now: u64, max_age_ms: u64) -> Result<EvidenceView> {
        self.bounds()?;
        let announcement = announce_v3::deserialize_v3(&self.announcement)?;
        announcement
            .verify()
            .map_err(|_| EvidenceError::Invalid("announcement signature"))?;
        if !fresh(announcement_ms(&announcement)?, now, max_age_ms) {
            return Err(EvidenceError::Invalid("announcement freshness"));
        }
        let advert = verify_advert(
            &self.advert,
            &announcement.agent_public_key,
            now,
            max_age_ms,
        )?;
        if advert.agent_id != *announcement.agent_id.as_bytes()
            || advert.machine_id != *announcement.machine_id.as_bytes()
        {
            return Err(EvidenceError::Invalid("agent/machine mismatch"));
        }
        let certificate = self
            .certificate
            .as_ref()
            .map(|bytes| {
                let cert = AgentCertificate::from_storage_bytes(bytes)
                    .map_err(|_| EvidenceError::Invalid("certificate encoding"))?;
                // The certificate codec accepts historical layouts. Require canonical
                // exact consumption without ever replacing the original bytes.
                if cert
                    .to_storage_bytes()
                    .map_err(|_| EvidenceError::Invalid("certificate encoding"))?
                    != *bytes
                {
                    return Err(EvidenceError::Invalid("certificate trailing bytes"));
                }
                cert.verify()
                    .map_err(|_| EvidenceError::Invalid("certificate signature"))?;
                if cert.agent_id().ok() != Some(announcement.agent_id)
                    || cert.is_expired(now / 1000)
                    || cert.issued_at() > now.saturating_add(SKEW_MS) / 1000
                {
                    return Err(EvidenceError::Invalid("certificate binding or lifetime"));
                }
                Ok(cert)
            })
            .transpose()?;
        Ok(EvidenceView {
            announcement,
            advert,
            certificate,
        })
    }
}
/// Current policy, queried at every use. Implementations must read current
/// state, not the stored relation flags. Lock ordering: store then policy.
/// Methods must not re-enter the evidence store.
pub trait EvidencePolicy: Send + Sync {
    /// Current relationship flags; zero means stranger.
    fn relation(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now_ms: u64,
    ) -> u8;
    /// Includes agent, machine, binding and certificate-user revocations.
    fn revoked(&self, agent: AgentId, machine: MachineId, user: Option<UserId>) -> bool;
    /// Used to protect watermarks even when their record is absent.
    fn contains_agent(&self, agent: AgentId, now_ms: u64) -> bool;
}
/// Snapshot inputs from the existing persisted relationship stores. Enrollments
/// must be the current devices.json entries (removed entries are not supplied).
pub struct RelationshipInputs<'a> {
    /// Local agent.
    pub local_agent: AgentId,
    /// Local owner, if enrolled.
    pub local_owner: Option<UserId>,
    /// Current owner-signed device enrollments.
    pub enrollments: &'a [crate::owner_sync::OwnerEnrollment],
    /// Issued and received grants from share-grants.bin.
    pub grants: &'a [crate::share_grant::ShareGrant],
    /// Current named group state.
    pub groups: &'a [crate::groups::GroupInfo],
    /// Revocations used to exclude revoked grants and devices.
    pub revocations: &'a crate::revocation::RevocationSet,
}
/// Compute the relationship set using verified records to resolve machines and
/// user grantees. Active group IDs and direct grantees also work without records.
pub fn relationship_set(
    inputs: &RelationshipInputs<'_>,
    records: &[EvidenceView],
    now: u64,
) -> HashMap<AgentId, u8> {
    use crate::share_grant::Grantee;
    let mut set = HashMap::new();
    let mut add = |a, flag| {
        if a != inputs.local_agent {
            *set.entry(a).or_insert(0) |= flag;
        }
    };
    for group in inputs.groups {
        if group.withdrawn
            || !group
                .members_v2
                .get(&hex::encode(inputs.local_agent.as_bytes()))
                .is_some_and(|m| m.is_active())
        {
            continue;
        }
        for member in group.members_v2.values().filter(|m| m.is_active()) {
            if let Ok(bytes) = hex::decode(&member.agent_id) {
                if let Ok(id) = <[u8; 32]>::try_from(bytes) {
                    add(AgentId(id), GROUP);
                }
            }
        }
    }
    for record in records {
        let a = record.announcement.agent_id;
        let m = record.announcement.machine_id;
        if inputs.local_owner.is_some_and(|owner| {
            inputs.enrollments.iter().any(|e| {
                e.machine_id == *m.as_bytes()
                    && e.is_current_at(now)
                    && e.verify_owner(&owner).is_ok()
            })
        }) && !inputs.revocations.is_machine_revoked(&m)
            && !inputs.revocations.is_agent_revoked(&a)
            && !inputs.revocations.is_binding_revoked(&a, &m)
        {
            add(a, ENROLLED);
        }
    }
    for grant in inputs.grants {
        if !grant.is_active_at(now / 1000)
            || grant.verify().is_err()
            || inputs
                .revocations
                .is_share_grant_revoked(&grant.grant_id, &grant.owner)
        {
            continue;
        }
        if inputs.local_owner == Some(grant.owner) && grant.agents.contains(&inputs.local_agent) {
            match grant.grantee {
                Grantee::Agent(a) => add(a, GRANT),
                Grantee::User(u) => {
                    for r in records {
                        if r.certificate.as_ref().is_some_and(|c| {
                            !c.is_expired(now / 1000) && c.user_id().ok() == Some(u)
                        }) {
                            add(r.announcement.agent_id, GRANT);
                        }
                    }
                }
            }
        }
        let received = match grant.grantee {
            Grantee::Agent(a) => a == inputs.local_agent,
            Grantee::User(u) => Some(u) == inputs.local_owner,
        };
        if received {
            for a in &grant.agents {
                add(*a, GRANT);
            }
        }
    }
    set
}
/// Network source controls material same-machine refresh policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestSource {
    /// Routine gossip or Lookup.
    Gossip,
    /// Ingest-fresh peer Hello always replaces stored bytes.
    Hello,
}
/// Counters owned by the store; diagnostics wiring is a later slice.
#[derive(Debug, Clone, Default)]
pub struct EvidenceCounters {
    /// Failed synchronous move writes.
    pub evidence_move_write_failed: u64,
    /// Incoming moves refused at a protected watermark cap.
    pub evidence_watermark_full: u64,
    /// Successful atomic snapshots.
    pub evidence_writes: u64,
    /// Snapshot bytes written.
    pub evidence_bytes_written: u64,
}
#[derive(Default)]
struct State {
    file: EvidenceFileV1,
    live: HashMap<AgentId, EvidenceRecordV1>,
    suspended: HashSet<AgentId>,
    pending_moves: HashMap<AgentId, MoveWatermarkV1>,
    last_used: HashMap<AgentId, u64>,
    absent_since: HashMap<AgentId, u64>,
    dirty: bool,
    last_write: Option<u64>,
    counters: EvidenceCounters,
}
/// Locked evidence map with coherent atomic snapshots. Explicit `flush` on
/// shutdown is required; Drop deliberately performs no hidden disk writes.
pub struct PeerEvidenceStore {
    path: PathBuf,
    memory_only: bool,
    max_age: u64,
    policy: Arc<dyn EvidencePolicy>,
    state: Mutex<State>,
    #[cfg(test)]
    fail_write: std::sync::atomic::AtomicU8,
}
impl PeerEvidenceStore {
    /// Open and verify an existing snapshot. Unreadable files are preserved for
    /// the entire lifetime of this instance; missing files allow first writes.
    pub fn open(
        data_dir: &Path,
        config: EvidenceConfig,
        policy: Arc<dyn EvidencePolicy>,
        now: u64,
    ) -> Result<Self> {
        config.validate()?;
        let path = data_dir.join("peer-evidence.bin");
        let decoded = (|| -> Result<EvidenceFileV1> {
            let file = File::open(&path)?;
            let mut bytes = Vec::new();
            file.take(FILE_CAP as u64 + 1).read_to_end(&mut bytes)?;
            EvidenceFileV1::decode(&bytes)
        })();
        let (mut file, memory_only) = match decoded {
            Ok(f) => (f, false),
            Err(EvidenceError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                (EvidenceFileV1::default(), false)
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "unreadable evidence file: memory-only until manual recovery");
                (EvidenceFileV1::default(), true)
            }
        };
        let max_age = config.max_age_days * DAY_MS;
        file.records.retain(|a, r| {
            r.verify(now, max_age).is_ok_and(|v| {
                v.announcement.agent_id == *a
                    && !disqualified(&file.watermarks, *a, &v)
                    && allowed(&*policy, &v, now)
            })
        });
        Ok(Self {
            path,
            memory_only,
            max_age,
            policy,
            state: Mutex::new(State {
                file,
                ..State::default()
            }),
            #[cfg(test)]
            fail_write: std::sync::atomic::AtomicU8::new(0),
        })
    }
    /// Whether this instance is prohibited from replacing an unreadable file.
    pub fn is_memory_only(&self) -> bool {
        self.memory_only
    }
    /// Diagnostic counters.
    pub fn counters(&self) -> Result<EvidenceCounters> {
        Ok(self.lock()?.counters.clone())
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| EvidenceError::Invalid("poisoned store lock"))
    }
    /// Single authority: recheck current policy, component age, certificate,
    /// signatures, exact machine and watermark on every call.
    pub fn usable(&self, agent: AgentId, machine: MachineId, now: u64) -> Option<EvidenceView> {
        let mut state = self.state.lock().ok()?;
        if state.suspended.contains(&agent) {
            return None;
        }
        let view = state
            .file
            .records
            .get(&agent)?
            .verify(now, self.max_age)
            .ok()?;
        if view.announcement.agent_id != agent
            || view.announcement.machine_id != machine
            || disqualified(&state.file.watermarks, agent, &view)
            || !allowed(&*self.policy, &view, now)
        {
            return None;
        }
        state.last_used.insert(agent, now);
        Some(view)
    }
    /// Latest ingest-fresh live wire bytes, kept separately from stored bytes.
    pub fn live(&self, agent: AgentId, now: u64) -> Option<EvidenceRecordV1> {
        let state = self.state.lock().ok()?;
        if state.suspended.contains(&agent) {
            return None;
        }
        let record = state.live.get(&agent)?;
        let view = record.verify(now, W_MS).ok()?;
        (allowed(&*self.policy, &view, now) && !disqualified(&state.file.watermarks, agent, &view))
            .then(|| record.clone())
    }
    /// Ingest a complete verified pair. A move returns success only after the
    /// new snapshot and its parent directory have been synced.
    pub fn ingest(
        &self,
        mut record: EvidenceRecordV1,
        source: IngestSource,
        now: u64,
    ) -> Result<()> {
        let view = record.verify(now, W_MS)?;
        if !allowed(&*self.policy, &view, now) {
            return Err(EvidenceError::Invalid("not a current relationship"));
        }
        let a = view.announcement.agent_id;
        let m = view.announcement.machine_id;
        record.relation = self.policy.relation(a, m, view.certificate.as_ref(), now);
        record.stored_at_ms = now;
        let mut state = self.lock()?;
        if disqualified(&state.file.watermarks, a, &view)
            || state
                .pending_moves
                .get(&a)
                .is_some_and(|w| w.machine != m && w.t >= view.advert.created_at_unix_ms)
        {
            return Err(EvidenceError::Invalid("move watermark"));
        }
        let previous = state
            .live
            .get(&a)
            .or_else(|| state.file.records.get(&a))
            .map(|r| r.ordering_view(now))
            .transpose()?;
        if let Some(old) = &previous {
            if view.advert.created_at_unix_ms < old.advert.created_at_unix_ms
                || announcement_ms(&view.announcement)? < announcement_ms(&old.announcement)?
                || (m != old.announcement.machine_id
                    && view.advert.created_at_unix_ms == old.advert.created_at_unix_ms)
            {
                return Err(EvidenceError::Invalid("non-monotonic evidence"));
            }
        }
        let stored = state
            .file
            .records
            .get(&a)
            .map(|r| r.ordering_view(now))
            .transpose()?;
        let moving = stored
            .as_ref()
            .is_some_and(|v| v.announcement.machine_id != m)
            || state.suspended.contains(&a);
        let material = moving
            || source == IngestSource::Hello
            || stored.is_none()
            || state
                .file
                .records
                .get(&a)
                .is_some_and(|old| old.certificate != record.certificate)
            || stored.as_ref().is_some_and(|v| {
                now.saturating_sub(v.announcement.announced_at.saturating_mul(1000))
                    > self.max_age / 2
                    || now.saturating_sub(v.advert.created_at_unix_ms) > self.max_age / 2
            });
        if material {
            let mut next = state.file.clone();
            if moving {
                state.suspended.insert(a);
                state.pending_moves.insert(
                    a,
                    MoveWatermarkV1 {
                        t: view.advert.created_at_unix_ms,
                        machine: m,
                    },
                );
                self.set_watermark(
                    &mut state,
                    &mut next,
                    a,
                    MoveWatermarkV1 {
                        t: view.advert.created_at_unix_ms,
                        machine: m,
                    },
                    now,
                )?;
            }
            next.records.insert(a, record.clone());
            self.evict_records(&state, &mut next, now);
            next.encode()?; // Refuse an over-cap insert before committing state.
            if moving {
                if let Err(e) = self.write(&next) {
                    state.counters.evidence_move_write_failed += 1;
                    return Err(e);
                }
                self.wrote(&mut state, &next, now)?;
                state.suspended.remove(&a);
                state.pending_moves.remove(&a);
            } else {
                state.dirty = true;
            }
            state.file = next;
            let retained: HashSet<_> = state.file.records.keys().copied().collect();
            state.live.retain(|id, _| retained.contains(id));
            state.last_used.retain(|id, _| retained.contains(id));
        }
        if state.file.records.contains_key(&a) {
            state.live.insert(a, record);
            state.last_used.insert(a, now);
        }
        self.flush_locked(&mut state, now, false)
    }
    /// Verified advert-only move: removes old authority and writes the watermark
    /// atomically. The agent key is hash-checked by the advert verifier.
    pub fn ingest_move_advert(&self, bytes: &[u8], agent_key: &[u8], now: u64) -> Result<()> {
        let advert = verify_advert(bytes, agent_key, now, W_MS)?;
        let a = AgentId(advert.agent_id);
        let m = MachineId(advert.machine_id);
        let mut state = self.lock()?;
        let old = state
            .file
            .records
            .get(&a)
            .ok_or(EvidenceError::Invalid("no stored binding to move"))?
            .ordering_view(now)?;
        if old.announcement.machine_id == m
            || advert.created_at_unix_ms <= old.advert.created_at_unix_ms
            || state
                .file
                .watermarks
                .get(&a)
                .is_some_and(|w| advert.created_at_unix_ms <= w.t)
        {
            return Err(EvidenceError::Invalid("not a newer move"));
        }
        if !self.policy.contains_agent(a, now)
            || self.policy.revoked(
                a,
                m,
                old.certificate.as_ref().and_then(|c| c.user_id().ok()),
            )
        {
            return Err(EvidenceError::Invalid("move policy"));
        }
        if state.pending_moves.get(&a).is_some_and(|w| {
            advert.created_at_unix_ms < w.t || (advert.created_at_unix_ms == w.t && m != w.machine)
        }) {
            return Err(EvidenceError::Invalid("pending newer move"));
        }
        state.suspended.insert(a);
        state.pending_moves.insert(
            a,
            MoveWatermarkV1 {
                t: advert.created_at_unix_ms,
                machine: m,
            },
        );
        let mut next = state.file.clone();
        self.set_watermark(
            &mut state,
            &mut next,
            a,
            MoveWatermarkV1 {
                t: advert.created_at_unix_ms,
                machine: m,
            },
            now,
        )?;
        next.records.remove(&a);
        if let Err(e) = self.write(&next) {
            state.counters.evidence_move_write_failed += 1;
            return Err(e);
        }
        self.wrote(&mut state, &next, now)?;
        state.file = next;
        state.live.remove(&a);
        state.suspended.remove(&a);
        state.pending_moves.remove(&a);
        Ok(())
    }
    fn set_watermark(
        &self,
        state: &mut State,
        next: &mut EvidenceFileV1,
        a: AgentId,
        mark: MoveWatermarkV1,
        now: u64,
    ) -> Result<()> {
        if next
            .watermarks
            .get(&a)
            .is_some_and(|w| mark.t < w.t || (mark.t == w.t && mark.machine != w.machine))
        {
            return Err(EvidenceError::Invalid("older watermark"));
        }
        if !next.watermarks.contains_key(&a) && next.watermarks.len() == WATERMARK_CAP {
            for id in next.watermarks.keys() {
                if self.policy.contains_agent(*id, now) {
                    state.absent_since.remove(id);
                } else {
                    state.absent_since.entry(*id).or_insert(now);
                }
            }
            let victim = next
                .watermarks
                .iter()
                .filter(|(id, w)| {
                    !next.records.contains_key(id)
                        && !self.policy.contains_agent(**id, now)
                        && now.saturating_sub(w.t) > self.max_age
                })
                .min_by_key(|(id, _)| {
                    (
                        state.absent_since.get(id).copied().unwrap_or(now),
                        *id.as_bytes(),
                    )
                })
                .map(|(id, _)| *id);
            let Some(victim) = victim else {
                state.counters.evidence_watermark_full += 1;
                return Err(EvidenceError::Invalid("watermark full"));
            };
            next.watermarks.remove(&victim);
            state.absent_since.remove(&victim);
        }
        next.watermarks.insert(a, mark);
        Ok(())
    }
    fn evict_records(&self, state: &State, next: &mut EvidenceFileV1, now: u64) {
        while next.records.len() > RECORD_CAP {
            let victim = next
                .records
                .iter()
                .min_by_key(|(id, r)| {
                    let relation = r
                        .verify(now, self.max_age)
                        .ok()
                        .map(|v| {
                            self.policy.relation(
                                **id,
                                v.announcement.machine_id,
                                v.certificate.as_ref(),
                                now,
                            )
                        })
                        .unwrap_or(0);
                    let priority = if relation & ENROLLED != 0 {
                        3
                    } else if relation & GRANT != 0 {
                        2
                    } else if relation & GROUP != 0 {
                        1
                    } else {
                        0
                    };
                    (
                        priority,
                        state.last_used.get(id).copied().unwrap_or(r.stored_at_ms),
                        *id.as_bytes(),
                    )
                })
                .map(|(id, _)| *id);
            if let Some(victim) = victim {
                next.records.remove(&victim);
            } else {
                break;
            }
        }
    }
    /// Reconcile policy changes and expiry, at least every 60 seconds once
    /// integrated. Tracks how long watermark agents have been absent; after a
    /// restart absent agents tie at the first observation (conservative).
    pub fn maintain(&self, now: u64) -> Result<()> {
        let mut state = self.lock()?;
        let ids: Vec<_> = state.file.watermarks.keys().copied().collect();
        for a in ids {
            if self.policy.contains_agent(a, now) {
                state.absent_since.remove(&a);
            } else {
                state.absent_since.entry(a).or_insert(now);
            }
        }
        let removed: Vec<_> = state
            .file
            .records
            .iter()
            .filter(|(_, r)| {
                !r.verify(now, self.max_age)
                    .is_ok_and(|v| allowed(&*self.policy, &v, now))
            })
            .map(|(a, _)| *a)
            .collect();
        for a in removed {
            state.file.records.remove(&a);
            state.live.remove(&a);
            state.last_used.remove(&a);
            state.dirty = true;
        }
        self.flush_locked(&mut state, now, false)
    }

    /// Remove matching records and live bytes, preserving all watermarks.
    pub fn remove_where(
        &self,
        predicate: impl Fn(AgentId, &EvidenceRecordV1) -> bool,
    ) -> Result<()> {
        let mut state = self.lock()?;
        let removed: Vec<_> = state
            .file
            .records
            .iter()
            .filter(|(a, r)| predicate(**a, r))
            .map(|(a, _)| *a)
            .collect();
        for a in removed {
            state.file.records.remove(&a);
            state.live.remove(&a);
            state.last_used.remove(&a);
            state.dirty = true;
        }
        Ok(())
    }
    /// Flush due material changes, or force a dirty flush on clean shutdown.
    pub fn flush(&self, now: u64, shutdown: bool) -> Result<()> {
        let mut state = self.lock()?;
        self.flush_locked(&mut state, now, shutdown)
    }
    fn flush_locked(&self, state: &mut State, now: u64, force: bool) -> Result<()> {
        if self.memory_only
            || !state.dirty
            || (!force
                && state
                    .last_write
                    .is_some_and(|t| now.saturating_sub(t) < 60_000))
        {
            return Ok(());
        }
        self.write(&state.file)?;
        let bytes = state.file.encode()?.len();
        state.counters.evidence_writes += 1;
        state.counters.evidence_bytes_written += bytes as u64;
        state.last_write = Some(now);
        state.dirty = false;
        Ok(())
    }
    fn wrote(&self, state: &mut State, file: &EvidenceFileV1, now: u64) -> Result<()> {
        state.counters.evidence_writes += 1;
        state.counters.evidence_bytes_written += file.encode()?.len() as u64;
        state.last_write = Some(now);
        state.dirty = false;
        Ok(())
    }
    fn write(&self, file: &EvidenceFileV1) -> Result<()> {
        if self.memory_only {
            return Err(EvidenceError::Invalid(
                "move cannot be durable in memory-only mode",
            ));
        }
        let bytes = file.encode()?;
        let parent = self
            .path
            .parent()
            .ok_or(EvidenceError::Invalid("missing parent"))?;
        fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(".peer-evidence-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(&bytes)?;
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 1 {
                return Err(std::io::Error::other("injected before fsync").into());
            }
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 3 {
                std::process::exit(89);
            }
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            File::open(parent)?.sync_all()?;
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 4 {
                std::process::exit(89);
            }
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 2 {
                return Err(std::io::Error::other("injected after directory fsync").into());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
}
fn allowed(policy: &dyn EvidencePolicy, view: &EvidenceView, now: u64) -> bool {
    let a = view.announcement.agent_id;
    let m = view.announcement.machine_id;
    policy.relation(a, m, view.certificate.as_ref(), now) != 0
        && !policy.revoked(
            a,
            m,
            view.certificate.as_ref().and_then(|c| c.user_id().ok()),
        )
}
fn disqualified(
    watermarks: &HashMap<AgentId, MoveWatermarkV1>,
    a: AgentId,
    view: &EvidenceView,
) -> bool {
    watermarks.get(&a).is_some_and(|w| {
        w.machine != view.announcement.machine_id && w.t > view.advert.created_at_unix_ms
    })
}

/// Bounded, process-only prerequisite capture. No S1 authority consumer reads
/// this cache. Strangers may occupy this TTL cache, never the persistent store.
#[derive(Default)]
pub struct VerifiedWireCapture {
    inner: Mutex<HashMap<(AgentId, u8), CapturedWire>>,
}
struct CapturedWire {
    bytes: Vec<u8>,
    timestamp: u64,
}
impl VerifiedWireCapture {
    /// Capture only after the existing listener has verified its wire body.
    pub(crate) fn capture(
        &self,
        agent: AgentId,
        announcement: bool,
        bytes: &[u8],
        timestamp: u64,
        now: u64,
    ) {
        if bytes.len()
            > if announcement {
                ANNOUNCEMENT_CAP
            } else {
                ADVERT_CAP
            }
            || !fresh(timestamp, now, W_MS)
        {
            return;
        }
        let Ok(mut entries) = self.inner.lock() else {
            return;
        };
        entries.retain(|_, v| fresh(v.timestamp, now, W_MS));
        let key = (agent, u8::from(announcement));
        if entries.get(&key).is_some_and(|v| v.timestamp >= timestamp) {
            return;
        }
        if entries.len() >= RECORD_CAP * 2 && !entries.contains_key(&key) {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| *k)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            CapturedWire {
                bytes: bytes.to_vec(),
                timestamp,
            },
        );
    }
    /// Return exact captured bytes for future pairing, provided still fresh.
    pub fn get(&self, agent: AgentId, announcement: bool, now: u64) -> Option<Vec<u8>> {
        let entries = self.inner.lock().ok()?;
        let value = entries.get(&(agent, u8::from(announcement)))?;
        fresh(value.timestamp, now, W_MS).then(|| value.bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dm::DmCapabilities,
        dm_capability::{RegistryTrailer, REGISTRY_TRAILER_MAGIC},
        identity::{AgentKeypair, MachineKeypair, UserKeypair},
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    const NOW: u64 = 2_000_000_000_000;
    #[derive(Default)]
    struct Policy {
        peers: Mutex<HashMap<AgentId, u8>>,
        revoked: AtomicBool,
    }
    impl EvidencePolicy for Policy {
        fn relation(&self, a: AgentId, _: MachineId, _: Option<&AgentCertificate>, _: u64) -> u8 {
            self.peers.lock().unwrap().get(&a).copied().unwrap_or(0)
        }
        fn revoked(&self, _: AgentId, _: MachineId, _: Option<UserId>) -> bool {
            self.revoked.load(Ordering::Relaxed)
        }
        fn contains_agent(&self, a: AgentId, _: u64) -> bool {
            self.peers.lock().unwrap().contains_key(&a)
        }
    }
    struct Peer {
        agent: AgentKeypair,
        machine: MachineKeypair,
    }
    impl Peer {
        fn new() -> Self {
            Self {
                agent: AgentKeypair::generate().unwrap(),
                machine: MachineKeypair::generate().unwrap(),
            }
        }
        fn a(&self) -> AgentId {
            self.agent.agent_id()
        }
        fn m(&self) -> MachineId {
            self.machine.machine_id()
        }
        fn record(&self, ann_time: u64, advert_time: u64) -> EvidenceRecordV1 {
            let v2 = crate::IdentityAnnouncement {
                self_name: Some("wire name".into()),
                agent_id: self.a(),
                machine_id: self.m(),
                user_id: None,
                agent_certificate: None,
                machine_public_key: self.machine.public_key().as_bytes().to_vec(),
                machine_signature: vec![],
                addresses: vec![],
                announced_at: ann_time / 1000,
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: vec![],
                relay_candidates: vec![],
                agent_public_key: self.agent.public_key().as_bytes().to_vec(),
            };
            let mut ann =
                IdentityAnnouncementV3::build_from_v2(&v2, self.machine.secret_key(), 0).unwrap();
            ann.sign_v3_1(self.machine.secret_key()).unwrap();
            let mut caps = DmCapabilities::pending();
            caps.kem_public_key = vec![42; 1184];
            let mut advert = CapabilityAdvert {
                protocol_version: crate::dm_capability_service::ADVERT_PROTOCOL_VERSION,
                agent_id: *self.a().as_bytes(),
                machine_id: *self.m().as_bytes(),
                created_at_unix_ms: advert_time,
                capabilities: caps,
                signature: vec![],
            };
            advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                self.agent.secret_key(),
                &advert.signed_bytes().unwrap(),
            )
            .unwrap()
            .as_bytes()
            .to_vec();
            let mut trailer = RegistryTrailer {
                registry: Default::default(),
                signature: vec![],
            };
            trailer.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                self.agent.secret_key(),
                &trailer.signed_bytes(&advert).unwrap(),
            )
            .unwrap()
            .as_bytes()
            .to_vec();
            let mut bytes = postcard::to_stdvec(&advert).unwrap();
            bytes.extend_from_slice(REGISTRY_TRAILER_MAGIC);
            bytes.extend(postcard::to_stdvec(&trailer).unwrap());
            EvidenceRecordV1 {
                announcement: announce_v3::serialize_v3_1(&ann).unwrap(),
                advert: bytes,
                certificate: None,
                relation: GROUP,
                stored_at_ms: NOW,
            }
        }
    }
    fn setup(peer: &Peer) -> (tempfile::TempDir, Arc<Policy>, PeerEvidenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let p = Arc::new(Policy::default());
        p.peers.lock().unwrap().insert(peer.a(), GROUP);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), p.clone(), NOW).unwrap();
        (dir, p, store)
    }
    #[test]
    fn freshness_each_component_and_future_skew() {
        let p = Peer::new();
        for (a, b) in [
            (NOW - W_MS - 1000, NOW),
            (NOW, NOW - W_MS - 1),
            (NOW + SKEW_MS + 1000, NOW),
            (NOW, NOW + SKEW_MS + 1),
        ] {
            assert!(p.record(a, b).verify(NOW, W_MS).is_err());
        }
        assert!(p.record(NOW - W_MS, NOW - W_MS).verify(NOW, W_MS).is_ok());
        assert!(p
            .record(NOW + SKEW_MS, NOW + SKEW_MS)
            .verify(NOW, W_MS)
            .is_ok());
    }
    #[test]
    fn stored_freshness_is_per_component_and_configured_lifetime() {
        let p = Peer::new();
        for (a, b) in [(NOW - 7 * DAY_MS - 1000, NOW), (NOW, NOW - 7 * DAY_MS - 1)] {
            assert!(p.record(a, b).verify(NOW, 7 * DAY_MS).is_err());
        }
        let (dir, policy, _) = setup(&p);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig { max_age_days: 1 }, policy, NOW)
                .unwrap();
        store
            .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
            .unwrap();
        assert!(store.usable(p.a(), p.m(), NOW + DAY_MS).is_some());
        assert!(store.usable(p.a(), p.m(), NOW + DAY_MS + 1).is_none());
        let config: EvidenceConfig = toml::from_str("").unwrap();
        assert_eq!(config.max_age_days, 7);
    }
    #[test]
    fn tamper_each_signed_part_and_exact_consumption() {
        let p = Peer::new();
        let r = p.record(NOW, NOW);
        assert!(r.verify(NOW, W_MS).is_ok());
        let mut bad = r.clone();
        let n = bad.announcement.len();
        bad.announcement[n - 2] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        let mut bad = r.clone();
        bad.advert[100] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        let mut bad = r.clone();
        let n = bad.advert.len();
        bad.advert[n - 2] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        for part in [true, false] {
            let mut bad = r.clone();
            if part {
                bad.announcement.push(0);
            } else {
                bad.advert.push(0);
            }
            assert!(bad.verify(NOW, W_MS).is_err());
        }
        let owner = UserKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&owner, &p.agent).unwrap();
        let mut r = r;
        r.certificate = Some(cert.to_storage_bytes().unwrap());
        assert!(r.verify(NOW, W_MS).is_ok());
        let mut bad = r.clone();
        bad.certificate.as_mut().unwrap()[100] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        let mut bad = r;
        bad.certificate.as_mut().unwrap().push(0);
        assert!(bad.verify(NOW, W_MS).is_err());
    }
    #[test]
    fn mismatched_agent_machine_and_certificate() {
        let p = Peer::new();
        let mut other = Peer::new();
        let mut r = p.record(NOW, NOW);
        r.advert = other.record(NOW, NOW).advert;
        assert!(r.verify(NOW, W_MS).is_err());
        r = p.record(NOW, NOW);
        r.certificate = Some(
            AgentCertificate::issue(&UserKeypair::generate().unwrap(), &other.agent)
                .unwrap()
                .to_storage_bytes()
                .unwrap(),
        );
        assert!(r.verify(NOW, W_MS).is_err());
        other.agent = p.agent;
        let moved = other.record(NOW, NOW);
        r.certificate = None;
        r.advert = moved.advert;
        assert!(r.verify(NOW, W_MS).is_err());
    }
    #[test]
    fn routine_refresh_restart_preserves_stored_authority_and_live_bytes() {
        let p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let initial = p.record(NOW, NOW);
        store
            .ingest(initial.clone(), IngestSource::Gossip, NOW)
            .unwrap();
        for i in 1..=3 {
            let t = NOW + i * 60_000;
            let r = p.record(t, t);
            store.ingest(r.clone(), IngestSource::Gossip, t).unwrap();
            assert_eq!(store.live(p.a(), t).unwrap().advert, r.advert);
        }
        assert!(store.lock().unwrap().file.watermarks.is_empty());
        assert_eq!(
            store.lock().unwrap().file.records[&p.a()].advert,
            initial.advert
        );
        assert_eq!(store.counters().unwrap().evidence_writes, 1);
        drop(store);
        let reopened =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW + 180_000)
                .unwrap();
        assert!(reopened.usable(p.a(), p.m(), NOW + 180_000).is_some());
        assert!(reopened.live(p.a(), NOW + 180_000).is_none());
    }
    #[test]
    fn use_limit_hello_revalidation_and_half_life_refresh() {
        let p = Peer::new();
        let (_, _, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        assert!(store.usable(p.a(), p.m(), NOW + 7 * DAY_MS).is_some());
        assert!(store.usable(p.a(), p.m(), NOW + 7 * DAY_MS + 1).is_none());
        let t = NOW + 4 * DAY_MS;
        store
            .ingest(p.record(t, t), IngestSource::Gossip, t)
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 2);
        let t = t + 60_000;
        store
            .ingest(p.record(t, t), IngestSource::Hello, t)
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 3);
        assert!(store.usable(p.a(), p.m(), t + 7 * DAY_MS).is_some());
        assert!(store.usable(p.a(), p.m(), t + 7 * DAY_MS + 1).is_none());
    }
    #[test]
    fn move_atomic_durable_restart_and_watermark_replay() {
        let mut p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let old = p.m();
        let old_bytes = p.record(NOW, NOW);
        store
            .ingest(old_bytes.clone(), IngestSource::Gossip, NOW)
            .unwrap();
        p.machine = MachineKeypair::generate().unwrap();
        let t = NOW + 1000;
        store
            .ingest(p.record(t, t), IngestSource::Gossip, t)
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 2);
        assert!(store.usable(p.a(), old, t).is_none());
        assert!(store.usable(p.a(), p.m(), t).is_some());
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
        assert!(store.usable(p.a(), old, t).is_none());
        assert!(store.usable(p.a(), p.m(), t).is_some());
        assert!(store.ingest(old_bytes, IngestSource::Hello, t).is_err());
        store.remove_where(|_, _| true).unwrap();
        store.flush(t, true).unwrap();
        assert_eq!(store.lock().unwrap().file.watermarks.len(), 1);
    }
    #[test]
    fn crash_checkpoints_before_and_after_fsync_and_failed_move_suspension() {
        for checkpoint in [1, 2] {
            let mut p = Peer::new();
            let (dir, policy, store) = setup(&p);
            let old = p.m();
            store
                .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
                .unwrap();
            p.machine = MachineKeypair::generate().unwrap();
            let t = NOW + 1000;
            let r = p.record(t, t);
            store.fail_write.store(checkpoint, Ordering::Relaxed);
            assert!(store.ingest(r.clone(), IngestSource::Gossip, t).is_err());
            assert!(store.usable(p.a(), old, t).is_none());
            assert!(store.usable(p.a(), p.m(), t).is_none());
            assert_eq!(store.counters().unwrap().evidence_move_write_failed, 1);
            // Drop has no shutdown flush: reopen exactly the crash-visible disk.
            drop(store);
            let reopened =
                PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
            assert_eq!(reopened.usable(p.a(), old, t).is_some(), checkpoint == 1);
            assert_eq!(reopened.usable(p.a(), p.m(), t).is_some(), checkpoint == 2);
            reopened.ingest(r, IngestSource::Hello, t).unwrap();
            assert!(reopened.usable(p.a(), old, t).is_none());
        }
    }
    #[test]
    fn failed_move_retry_and_advert_only_move() {
        let mut p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let old = p.m();
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        p.machine = MachineKeypair::generate().unwrap();
        let t = NOW + 1000;
        let r = p.record(t, t);
        store.fail_write.store(1, Ordering::Relaxed);
        assert!(store
            .ingest_move_advert(&r.advert, p.agent.public_key().as_bytes(), t)
            .is_err());
        assert!(store.usable(p.a(), old, t).is_none());
        store.fail_write.store(0, Ordering::Relaxed);
        store
            .ingest_move_advert(&r.advert, p.agent.public_key().as_bytes(), t)
            .unwrap();
        assert!(store.lock().unwrap().file.records.is_empty());
        assert_eq!(store.lock().unwrap().file.watermarks[&p.a()].machine, p.m());
        drop(store);
        let reopened =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
        assert!(reopened.usable(p.a(), old, t).is_none());
        reopened.ingest(r, IngestSource::Hello, t).unwrap();
        assert!(reopened.usable(p.a(), p.m(), t).is_some());
    }
    #[test]
    fn watermark_cap_protects_records_relationships_and_young_entries() {
        let p = Peer::new();
        let (_, policy, store) = setup(&p);
        let mut state = store.lock().unwrap();
        for i in 0..WATERMARK_CAP {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            state.file.watermarks.insert(
                AgentId(id),
                MoveWatermarkV1 {
                    t: NOW,
                    machine: p.m(),
                },
            );
        }
        let mut next = state.file.clone();
        let mark = MoveWatermarkV1 {
            t: NOW,
            machine: p.m(),
        };
        assert!(store
            .set_watermark(&mut state, &mut next, p.a(), mark, NOW)
            .is_err());
        assert_eq!(state.counters.evidence_watermark_full, 1);
        let ids: Vec<_> = next.watermarks.keys().copied().take(4).collect();
        for id in &ids {
            next.watermarks.get_mut(id).unwrap().t = NOW - 8 * DAY_MS;
        }
        next.records.insert(ids[0], p.record(NOW, NOW));
        policy.peers.lock().unwrap().insert(ids[1], GROUP);
        state.absent_since.insert(ids[2], NOW - 2000);
        state.absent_since.insert(ids[3], NOW - 1000);
        store
            .set_watermark(&mut state, &mut next, p.a(), mark, NOW)
            .unwrap();
        assert_eq!(next.watermarks.len(), WATERMARK_CAP);
        assert!(next.watermarks.contains_key(&ids[0]));
        assert!(next.watermarks.contains_key(&ids[1]));
        assert!(!next.watermarks.contains_key(&ids[2]));
        assert!(next.watermarks.contains_key(&ids[3]));
    }
    #[test]
    fn cap_refuses_incoming_move_without_dropping_watermarks() {
        let mut p = Peer::new();
        let (_, _, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        {
            let mut state = store.lock().unwrap();
            for i in 0..WATERMARK_CAP {
                let mut id = [0; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                state.file.watermarks.insert(
                    AgentId(id),
                    MoveWatermarkV1 {
                        t: NOW,
                        machine: p.m(),
                    },
                );
            }
        }
        p.machine = MachineKeypair::generate().unwrap();
        assert!(store
            .ingest(
                p.record(NOW + 1000, NOW + 1000),
                IngestSource::Hello,
                NOW + 1000
            )
            .is_err());
        assert_eq!(store.lock().unwrap().file.watermarks.len(), WATERMARK_CAP);
        assert_eq!(store.counters().unwrap().evidence_watermark_full, 1);
    }
    #[test]
    fn unreadable_files_stay_byte_identical_after_ingest_and_flush() {
        for bytes in [
            b"future magic".to_vec(),
            [MAGIC.as_slice(), &[255; 25]].concat(),
            [EvidenceFileV1::default().encode().unwrap(), vec![1]].concat(),
            vec![0; FILE_CAP + 1],
        ] {
            let p = Peer::new();
            let (dir, policy, _) = setup(&p);
            let path = dir.path().join("peer-evidence.bin");
            fs::write(&path, &bytes).unwrap();
            let store = PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW)
                .unwrap();
            assert!(store.is_memory_only());
            store
                .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
                .unwrap();
            store.flush(NOW, true).unwrap();
            assert!(store.usable(p.a(), p.m(), NOW).is_some());
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
    #[test]
    fn roundtrip_unknown_magic_trailing_and_tampered_load() {
        let p = Peer::new();
        let mut file = EvidenceFileV1::default();
        file.records.insert(p.a(), p.record(NOW, NOW));
        file.watermarks.insert(
            p.a(),
            MoveWatermarkV1 {
                t: NOW,
                machine: p.m(),
            },
        );
        let bytes = file.encode().unwrap();
        assert_eq!(EvidenceFileV1::decode(&bytes).unwrap(), file);
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(EvidenceFileV1::decode(&bad).is_err());
        let mut bad = bytes;
        bad.push(0);
        assert!(EvidenceFileV1::decode(&bad).is_err());
        let (dir, policy, _) = setup(&p);
        file.records.get_mut(&p.a()).unwrap().advert[100] ^= 1;
        fs::write(dir.path().join("peer-evidence.bin"), file.encode().unwrap()).unwrap();
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW).unwrap();
        assert!(store.usable(p.a(), p.m(), NOW).is_none());
    }
    #[test]
    fn component_30_kib_and_file_16_mib_caps() {
        let max = EvidenceRecordV1 {
            announcement: vec![0; ANNOUNCEMENT_CAP],
            advert: vec![0; ADVERT_CAP],
            certificate: Some(vec![0; CERTIFICATE_CAP]),
            relation: GROUP,
            stored_at_ms: 0,
        };
        assert_eq!(
            max.announcement.len() + max.advert.len() + max.certificate.as_ref().unwrap().len(),
            RECORD_BYTES_CAP
        );
        assert!(max.bounds().is_ok());
        for part in 0..3 {
            let mut r = max.clone();
            match part {
                0 => r.announcement.push(0),
                1 => r.advert.push(0),
                _ => r.certificate.as_mut().unwrap().push(0),
            };
            assert!(r.bounds().is_err());
            assert!(r.verify(NOW, W_MS).is_err());
        }
        let mut file = EvidenceFileV1::default();
        for i in 0..WATERMARK_CAP {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            file.watermarks.insert(
                AgentId(id),
                MoveWatermarkV1 {
                    t: 0,
                    machine: MachineId([0; 32]),
                },
            );
            if i < RECORD_CAP {
                file.records.insert(AgentId(id), max.clone());
            }
        }
        let bytes = file.encode().unwrap();
        assert!(bytes.len() <= FILE_CAP);
        assert_eq!(EvidenceFileV1::decode(&bytes).unwrap(), file);
        file.records.insert(AgentId([255; 32]), max);
        assert!(file.encode().is_err());
        file.records.remove(&AgentId([255; 32]));
        file.watermarks.insert(
            AgentId([255; 32]),
            MoveWatermarkV1 {
                t: 0,
                machine: MachineId([0; 32]),
            },
        );
        assert!(file.encode().is_err());
        assert!(EvidenceFileV1::decode(&vec![0; FILE_CAP + 1]).is_err());
    }
    #[test]
    fn monotonicity_strangers_and_live_policy_after_load() {
        let p = Peer::new();
        let (dir, policy, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        assert!(store
            .ingest(p.record(NOW - 1000, NOW - 1000), IngestSource::Hello, NOW)
            .is_err());
        let stranger = Peer::new();
        assert!(store
            .ingest(stranger.record(NOW, NOW), IngestSource::Gossip, NOW)
            .is_err());
        assert!(store.live(stranger.a(), NOW).is_none());
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap();
        assert!(store.usable(p.a(), p.m(), NOW).is_some());
        assert!(store.usable(p.a(), MachineId([0; 32]), NOW).is_none());
        policy.revoked.store(true, Ordering::Relaxed);
        assert!(store.usable(p.a(), p.m(), NOW).is_none());
        policy.revoked.store(false, Ordering::Relaxed);
        policy.peers.lock().unwrap().clear();
        assert!(store.usable(p.a(), p.m(), NOW).is_none());
    }
    #[test]
    fn config_default_min_max_and_certificate_expiry() {
        assert_eq!(EvidenceConfig::default().max_age_days, 7);
        for days in [0, 8, 30, u64::MAX] {
            assert!(EvidenceConfig { max_age_days: days }.validate().is_err());
        }
        for days in [1, 7] {
            assert!(EvidenceConfig { max_age_days: days }.validate().is_ok());
        }
        let p = Peer::new();
        let (_, _, store) = setup(&p);
        let mut r = p.record(NOW, NOW);
        let cert = AgentCertificate::issue_with_expiry(
            &UserKeypair::generate().unwrap(),
            &p.agent,
            Some(NOW / 1000 + 10),
        )
        .unwrap();
        r.certificate = Some(cert.to_storage_bytes().unwrap());
        store.ingest(r, IngestSource::Hello, NOW).unwrap();
        assert!(store.usable(p.a(), p.m(), NOW).is_some());
        assert!(store.usable(p.a(), p.m(), NOW + SKEW_MS + 11_000).is_none());
    }
    #[test]
    fn material_changes_coalesce_and_clean_shutdown_flushes() {
        let p = Peer::new();
        let (_, _, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        store
            .ingest(
                p.record(NOW + 1000, NOW + 1000),
                IngestSource::Hello,
                NOW + 1000,
            )
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 1);
        store.flush(NOW + 59_999, false).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 1);
        store.flush(NOW + 60_000, false).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 2);
        store.remove_where(|_, _| true).unwrap();
        store.flush(NOW + 60_001, true).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 3);
        store.flush(NOW + 120_000, true).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 3);
    }
    #[test]
    fn capture_preserves_verbatim_wire_and_ttl() {
        let p = Peer::new();
        let r = p.record(NOW, NOW);
        let cache = VerifiedWireCapture::default();
        cache.capture(p.a(), true, &r.announcement, NOW, NOW);
        cache.capture(p.a(), false, &r.advert, NOW, NOW);
        assert_eq!(cache.get(p.a(), true, NOW).unwrap(), r.announcement);
        assert_eq!(cache.get(p.a(), false, NOW).unwrap(), r.advert);
        assert!(cache.get(p.a(), false, NOW + W_MS + 1).is_none());
    }

    #[test]
    fn record_cap_eviction_priority_then_lru_and_watermark_survival() {
        let p = Peer::new();
        let (_, policy, store) = setup(&p);
        let r = p.record(NOW, NOW);
        let mut state = store.lock().unwrap();
        let mut next = EvidenceFileV1::default();
        for i in 0..=RECORD_CAP {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let a = AgentId(id);
            let mut record = r.clone();
            record.stored_at_ms = NOW + i as u64;
            next.records.insert(a, record);
            policy.peers.lock().unwrap().insert(a, ENROLLED);
        }
        let a = AgentId([0; 32]);
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&1u64.to_le_bytes());
        let b = AgentId(bytes);
        policy.peers.lock().unwrap().insert(a, GRANT);
        policy.peers.lock().unwrap().insert(b, GROUP);
        next.watermarks.insert(
            b,
            MoveWatermarkV1 {
                t: NOW,
                machine: p.m(),
            },
        );
        store.evict_records(&state, &mut next, NOW);
        assert_eq!(next.records.len(), RECORD_CAP);
        assert!(!next.records.contains_key(&b));
        assert!(next.records.contains_key(&a));
        assert!(next.watermarks.contains_key(&b));
        next.records.insert(b, r.clone());
        policy.peers.lock().unwrap().insert(b, GRANT);
        state.last_used.insert(a, NOW + 100);
        store.evict_records(&state, &mut next, NOW);
        assert!(!next.records.contains_key(&b));
        next.records.insert(b, r);
        policy.peers.lock().unwrap().insert(b, ENROLLED);
        store.evict_records(&state, &mut next, NOW);
        assert!(!next.records.contains_key(&a));
    }
    #[test]
    fn relationship_sources_enrollment_grants_and_active_groups_only() {
        use crate::share_grant::{Grantee, ShareCap, ShareGrant};
        let p = Peer::new();
        let local = Peer::new();
        let owner = UserKeypair::generate().unwrap();
        let revoked = crate::revocation::RevocationSet::new();
        let view = p.record(NOW, NOW).verify(NOW, W_MS).unwrap();
        let enrollment =
            crate::owner_sync::OwnerEnrollment::sign(p.m(), &owner, NOW - 1000, Some(NOW + 1000))
                .unwrap();
        let records = vec![view];
        let enrollments = vec![enrollment];
        let mut inputs = RelationshipInputs {
            local_agent: local.a(),
            local_owner: Some(owner.user_id()),
            enrollments: &enrollments,
            grants: &[],
            groups: &[],
            revocations: &revoked,
        };
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], ENROLLED);
        assert!(relationship_set(&inputs, &records, NOW + SKEW_MS + 1001).is_empty());
        inputs.enrollments = &[];
        assert!(relationship_set(&inputs, &records, NOW).is_empty());
        let grants = vec![ShareGrant::sign(
            &owner,
            [1; 32],
            Grantee::Agent(p.a()),
            vec![local.a()],
            vec![ShareCap::Dm],
            NOW / 1000 - 1,
            NOW / 1000 + 60,
        )
        .unwrap()];
        inputs.grants = &grants;
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], GRANT);
        assert!(relationship_set(&inputs, &records, NOW + 61_000).is_empty());
        let received = vec![ShareGrant::sign(
            &owner,
            [2; 32],
            Grantee::Agent(local.a()),
            vec![p.a()],
            vec![ShareCap::Dm],
            NOW / 1000 - 1,
            NOW / 1000 + 60,
        )
        .unwrap()];
        inputs.grants = &received;
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], GRANT);
        inputs.grants = &[];
        let mut group = crate::groups::GroupInfo::new(
            "evidence".into(),
            String::new(),
            local.a(),
            "evidence-group".into(),
        );
        let mut member = group.members_v2[&hex::encode(local.a().as_bytes())].clone();
        member.agent_id = hex::encode(p.a().as_bytes());
        group.members_v2.insert(member.agent_id.clone(), member);
        let groups = vec![group.clone()];
        inputs.groups = &groups;
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], GROUP);
        group.withdrawn = true;
        let withdrawn = vec![group];
        inputs.groups = &withdrawn;
        assert!(relationship_set(&inputs, &records, NOW).is_empty());
    }
    #[test]
    fn verified_ingest_captures_advert_verbatim_and_rejects_forgery() {
        let p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let r = p.record(now, now);
        let store = crate::dm_capability::CapabilityStore::new();
        let mut message = crate::gossip::PubSubMessage {
            topic: String::new(),
            payload: r.advert.clone().into(),
            sender: Some(p.a()),
            sender_public_key: Some(p.agent.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        let mut bad = r.advert.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        message.payload = bad.into();
        assert!(
            !crate::dm_capability_service::ingest_verified_capability_advert(
                &store,
                AgentId([0; 32]),
                &message
            )
        );
        assert!(store.evidence_wire.get(p.a(), false, now).is_none());
        message.payload = r.advert.clone().into();
        assert!(
            crate::dm_capability_service::ingest_verified_capability_advert(
                &store,
                AgentId([0; 32]),
                &message
            )
        );
        assert_eq!(
            store.evidence_wire.get(p.a(), false, now).unwrap(),
            r.advert
        );
    }
    #[test]
    #[ignore = "Explicit initial V1 fixture generation; never rewrite a released fixture"]
    fn generate_initial_v1_fixture() {
        let p = Peer::new();
        let mut file = EvidenceFileV1::default();
        file.records.insert(p.a(), p.record(NOW, NOW));
        file.watermarks.insert(
            p.a(),
            MoveWatermarkV1 {
                t: NOW - 1000,
                machine: p.m(),
            },
        );
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/peer_evidence_v1.bin");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output.write_all(&file.encode().unwrap()).unwrap();
    }
    #[test]
    fn v1_encoder_fixture_loads_and_roundtrips() {
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/peer_evidence_v1.bin"),
        )
        .unwrap();
        let file = EvidenceFileV1::decode(&bytes).unwrap();
        assert_eq!(file.records.len(), 1);
        assert_eq!(file.watermarks.len(), 1);
        let (a, r) = file.records.iter().next().unwrap();
        let view = r.verify(NOW, W_MS).unwrap();
        assert_eq!(view.announcement.agent_id, *a);
        assert_eq!(
            EvidenceFileV1::decode(&file.encode().unwrap()).unwrap(),
            file
        );
    }

    #[test]
    #[ignore = "Crash-test subprocess entry point; launched only by durable_move_process_kill"]
    fn crash_process_child() {
        let root = std::env::var("X0X_EVIDENCE_CRASH_DIR").unwrap();
        let checkpoint = std::env::var("X0X_EVIDENCE_CRASH_POINT")
            .unwrap()
            .parse()
            .unwrap();
        let record: EvidenceRecordV1 = options()
            .deserialize(&fs::read(Path::new(&root).join("incoming.bin")).unwrap())
            .unwrap();
        let view = record.verify(NOW + 1000, W_MS).unwrap();
        let policy = Arc::new(Policy::default());
        policy
            .peers
            .lock()
            .unwrap()
            .insert(view.announcement.agent_id, GROUP);
        let store = PeerEvidenceStore::open(
            Path::new(&root),
            EvidenceConfig::default(),
            policy,
            NOW + 1000,
        )
        .unwrap();
        store.fail_write.store(checkpoint, Ordering::Relaxed);
        let _ = store.ingest(record, IngestSource::Hello, NOW + 1000);
        panic!("crash checkpoint did not terminate");
    }
    #[test]
    fn durable_move_process_kill() {
        for checkpoint in [3, 4] {
            let mut p = Peer::new();
            let (dir, policy, store) = setup(&p);
            let old = p.m();
            store
                .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
                .unwrap();
            drop(store);
            p.machine = MachineKeypair::generate().unwrap();
            let record = p.record(NOW + 1000, NOW + 1000);
            fs::write(
                dir.path().join("incoming.bin"),
                options().serialize(&record).unwrap(),
            )
            .unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "peer_evidence::tests::crash_process_child",
                    "--ignored",
                ])
                .env("X0X_EVIDENCE_CRASH_DIR", dir.path())
                .env("X0X_EVIDENCE_CRASH_POINT", checkpoint.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(89));
            let reopened =
                PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW + 1000)
                    .unwrap();
            assert_eq!(
                reopened.usable(p.a(), old, NOW + 1000).is_some(),
                checkpoint == 3
            );
            assert_eq!(
                reopened.usable(p.a(), p.m(), NOW + 1000).is_some(),
                checkpoint == 4
            );
        }
    }
    #[test]
    fn maintenance_removes_expired_relationships_and_keeps_watermarks() {
        let p = Peer::new();
        let (_, policy, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        store.lock().unwrap().file.watermarks.insert(
            p.a(),
            MoveWatermarkV1 {
                t: NOW,
                machine: p.m(),
            },
        );
        policy.peers.lock().unwrap().clear();
        store.maintain(NOW + 60_000).unwrap();
        let state = store.lock().unwrap();
        assert!(state.file.records.is_empty());
        assert!(state.live.is_empty());
        assert_eq!(state.file.watermarks.len(), 1);
        assert_eq!(state.absent_since[&p.a()], NOW + 60_000);
    }

    #[test]
    fn all_revocation_subjects_rechecked_after_load() {
        struct Revoking {
            a: AgentId,
            m: MachineId,
            u: UserId,
            kind: std::sync::atomic::AtomicU8,
        }
        impl EvidencePolicy for Revoking {
            fn relation(
                &self,
                a: AgentId,
                _: MachineId,
                _: Option<&AgentCertificate>,
                _: u64,
            ) -> u8 {
                if a == self.a {
                    GRANT
                } else {
                    0
                }
            }
            fn contains_agent(&self, a: AgentId, _: u64) -> bool {
                a == self.a
            }
            fn revoked(&self, a: AgentId, m: MachineId, u: Option<UserId>) -> bool {
                match self.kind.load(Ordering::Relaxed) {
                    1 => a == self.a,
                    2 => m == self.m,
                    3 => a == self.a && m == self.m,
                    4 => u == Some(self.u),
                    _ => false,
                }
            }
        }
        let p = Peer::new();
        let owner = UserKeypair::generate().unwrap();
        let policy = Arc::new(Revoking {
            a: p.a(),
            m: p.m(),
            u: owner.user_id(),
            kind: std::sync::atomic::AtomicU8::new(0),
        });
        let dir = tempfile::tempdir().unwrap();
        let mut r = p.record(NOW, NOW);
        r.certificate = Some(
            AgentCertificate::issue(&owner, &p.agent)
                .unwrap()
                .to_storage_bytes()
                .unwrap(),
        );
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap();
        store.ingest(r, IngestSource::Hello, NOW).unwrap();
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap();
        for kind in 1..=4 {
            policy.kind.store(0, Ordering::Relaxed);
            assert!(store.usable(p.a(), p.m(), NOW).is_some());
            policy.kind.store(kind, Ordering::Relaxed);
            assert!(store.usable(p.a(), p.m(), NOW).is_none(), "subject {kind}");
        }
    }
    #[test]
    #[ignore = "CPU-only t_v benchmark; run explicitly on Mac and fleet VPS (crypto dependencies optimized in test profile)"]
    fn verify_benchmark_t_v() {
        use ant_quic::crypto::raw_public_keys::pqc::{sign_with_ml_dsa, verify_with_ml_dsa};
        let p = Peer::new();
        let message = vec![42; 4096];
        let signature = sign_with_ml_dsa(p.agent.secret_key(), &message).unwrap();
        for _ in 0..100 {
            verify_with_ml_dsa(p.agent.public_key(), &message, &signature).unwrap();
        }
        let start = std::time::Instant::now();
        let n = 2000;
        for _ in 0..n {
            verify_with_ml_dsa(
                std::hint::black_box(p.agent.public_key()),
                std::hint::black_box(&message),
                std::hint::black_box(&signature),
            )
            .unwrap();
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0 / f64::from(n);
        println!("ADR0089 t_v: target={}-{} debug_assertions={} n={} message_bytes={} mean_ms={:.6} projected_2048_verifies_s={:.6}",std::env::consts::OS,std::env::consts::ARCH,cfg!(debug_assertions),n,message.len(),ms,ms*2048.0/1000.0);
    }
}

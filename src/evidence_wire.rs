//! ADR 0089 S3: bounded, machine-authenticated, point-to-point self evidence.
//! Lookup serving is deliberately fail-closed until S4 installs context checks.
use crate::{
    announce_v3, dm_capability,
    identity::{AgentId, MachineId},
    peer_evidence::{EvidenceRecordV1, EvidenceRuntime, EvidenceView, IngestSource, W_MS},
    streams::{PeerStream, StreamProtocol},
};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};

mod decode;

const MESSAGE_CAP: usize = 32 * 1024;
// Reserve the frame, decoded vectors, and signed-part verification copies.
// All requests/replies, including outbound reads, acquire this conservative
// reservation before reading bodies. The wire buffer itself never exceeds
// 32 KiB; the sum of all reservations never exceeds 1 MiB.
const ALLOCATION_RESERVATION: usize = MESSAGE_CAP * 4;
const TOTAL_ALLOCATION_CAP: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);
const HELLO_INTERVAL: Duration = Duration::from_secs(60);
const MACHINE_CAP: usize = 4096;
const RESET_CHARGE: usize = 16;
const HELLO: u8 = 1;
const LOOKUP: u8 = 2;
const CERTIFICATE: u8 = 3;
const NOT_FOUND: u8 = 4;
const ACK: u8 = 5;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MESSAGE_CAP as u64)
        .reject_trailing_bytes()
}

/// Signed parts remain verbatim. `have_certificate` refers to the other
/// side's digest, never to an unauthenticated claim of ownership. A certificate
/// continuation is sent only after the reply explicitly reports a cache miss.
#[derive(Debug, Serialize)]
struct Hello {
    announcement: Vec<u8>,
    advert: Vec<u8>,
    certificate: Option<Vec<u8>>,
    have_certificate: Option<[u8; 32]>,
}
impl Hello {
    fn into_record(self) -> EvidenceRecordV1 {
        EvidenceRecordV1 {
            announcement: self.announcement,
            advert: self.advert,
            certificate: self.certificate,
            relation: 0,
            stored_at_ms: 0,
        }
    }
}

#[derive(Default)]
struct Window {
    events: VecDeque<(Instant, usize)>,
    total: usize,
}
impl Window {
    fn prune(&mut self, now: Instant) {
        while self
            .events
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) >= Duration::from_secs(1))
        {
            if let Some((_, n)) = self.events.pop_front() {
                self.total -= n;
            }
        }
    }
    fn add(&mut self, now: Instant, n: usize) {
        // Coalesce same-instant charges so a flood of resets cannot grow a
        // queue without consuming byte credit.
        if let Some((t, value)) = self.events.back_mut() {
            if *t == now {
                *value += n;
                self.total += n;
                return;
            }
        }
        self.events.push_back((now, n));
        self.total += n;
    }
}
#[derive(Default)]
struct MachineBudget {
    open: usize,
    bytes: Window,
    lookup: Option<Instant>,
    hello_in: Option<Instant>,
    hello_out: Option<Instant>,
    attempted: bool,
    touched: Option<Instant>,
    certificate: Option<(AgentId, [u8; 32], Instant)>,
}
#[derive(Default)]
struct State {
    machines: HashMap<MachineId, MachineBudget>,
    bytes: Window,
    verifies: Window,
}

/// Shared by every connection, acceptor, and outbound exchange on this node.
pub(crate) struct Limits {
    state: Mutex<State>,
    allocations: Arc<tokio::sync::Semaphore>,
    // Strangers may occupy at most half of the aggregate byte reservation.
    stranger_allocations: Arc<tokio::sync::Semaphore>,
    prefix: Mutex<HashMap<MachineId, usize>>,
    pub(crate) prefix_refused: std::sync::atomic::AtomicU64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            allocations: Arc::new(tokio::sync::Semaphore::new(TOTAL_ALLOCATION_CAP)),
            stranger_allocations: Arc::new(tokio::sync::Semaphore::new(TOTAL_ALLOCATION_CAP / 2)),
            prefix: Mutex::new(HashMap::new()),
            prefix_refused: std::sync::atomic::AtomicU64::new(0),
        }
    }
}
impl State {
    fn machine(&mut self, machine: MachineId, now: Instant) -> Option<&mut MachineBudget> {
        if !self.machines.contains_key(&machine) && self.machines.len() >= MACHINE_CAP {
            self.machines.retain(|_, m| {
                m.open != 0
                    || m.attempted
                    || m.touched
                        .is_some_and(|t| now.duration_since(t) < HELLO_INTERVAL)
            });
        }
        if !self.machines.contains_key(&machine) && self.machines.len() >= MACHINE_CAP {
            return None;
        }
        let m = self.machines.entry(machine).or_default();
        m.touched = Some(now);
        Some(m)
    }
}
impl Limits {
    /// Only machines without known agents or verified enrollment use this
    /// pool. Entries exist only while a lease is alive, across all connections.
    pub(crate) fn admit_prefix(self: &Arc<Self>, machine: MachineId) -> Option<PrefixLease> {
        let admitted = self.prefix.lock().ok().and_then(|mut slots| {
            if slots.values().sum::<usize>() >= 32 || slots.get(&machine).copied().unwrap_or(0) >= 2
            {
                return None;
            }
            *slots.entry(machine).or_default() += 1;
            Some(PrefixLease {
                limits: Arc::clone(self),
                machine,
            })
        });
        if admitted.is_none() {
            self.prefix_refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.reset(machine);
            tracing::info!(target: "x0x::streams", ?machine,
                outcome = "deny_pre_identity_capacity", "pre-identity stream refused; resetting");
        }
        admitted
    }

    pub(crate) fn admit(self: &Arc<Self>, machine: MachineId, relationship: bool) -> Option<Lease> {
        let now = Instant::now();
        let stranger_permit = if relationship {
            None
        } else {
            Some(
                Arc::clone(&self.stranger_allocations)
                    .try_acquire_many_owned(ALLOCATION_RESERVATION as u32)
                    .ok()?,
            )
        };
        let permit = Arc::clone(&self.allocations)
            .try_acquire_many_owned(ALLOCATION_RESERVATION as u32)
            .ok()?;
        let mut s = self.state.lock().ok()?;
        let m = s.machine(machine, now)?;
        if m.open >= 2 {
            return None;
        }
        m.open += 1;
        Some(Lease {
            limits: Arc::clone(self),
            machine,
            deadline: now + DEADLINE,
            _permit: permit,
            _stranger_permit: stranger_permit,
        })
    }
    fn charge(&self, machine: MachineId, bytes: usize) -> bool {
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        s.bytes.prune(now);
        if s.bytes.total.saturating_add(bytes) > 256 * 1024 {
            return false;
        }
        let Some(m) = s.machine(machine, now) else {
            return false;
        };
        m.bytes.prune(now);
        if m.bytes.total.saturating_add(bytes) > 64 * 1024 {
            return false;
        }
        m.bytes.add(now, bytes);
        s.bytes.add(now, bytes);
        true
    }
    pub(crate) fn reset(&self, machine: MachineId) {
        let _ = self.charge(machine, RESET_CHARGE);
    }
    fn verify(&self) -> bool {
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        s.verifies.prune(now);
        if s.verifies.total >= 32 {
            return false;
        }
        s.verifies.add(now, 1);
        true
    }
    fn request(&self, machine: MachineId, hello: bool) -> bool {
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        let Some(m) = s.machine(machine, now) else {
            return false;
        };
        let (last, interval) = if hello {
            (&mut m.hello_in, HELLO_INTERVAL)
        } else {
            (&mut m.lookup, Duration::from_secs(2))
        };
        if last.is_some_and(|t| now.duration_since(t) < interval) {
            return false;
        }
        *last = Some(now);
        true
    }
    fn begin_hello(&self, machine: MachineId, related: bool) -> bool {
        if !related {
            return false;
        }
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        let Some(m) = s.machine(machine, now) else {
            return false;
        };
        if m.attempted
            || m.hello_out
                .is_some_and(|t| now.duration_since(t) < HELLO_INTERVAL)
        {
            return false;
        }
        // Attempted is set before open/write/read. A reset or refusal never
        // schedules a retry. Reconnect clears only this connection marker.
        m.attempted = true;
        m.hello_out = Some(now);
        true
    }
    fn disconnect(&self, machine: MachineId) {
        if let Ok(mut s) = self.state.lock() {
            if let Some(m) = s.machines.get_mut(&machine) {
                m.attempted = false;
                m.certificate = None;
            }
        }
    }
    fn need_certificate(&self, machine: MachineId, agent: AgentId, digest: [u8; 32]) {
        if let Ok(mut s) = self.state.lock() {
            if let Some(m) = s.machine(machine, Instant::now()) {
                m.certificate = Some((agent, digest, Instant::now() + DEADLINE));
            }
        }
    }
    fn take_certificate(&self, machine: MachineId, agent: AgentId, digest: [u8; 32]) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|mut s| s.machines.get_mut(&machine)?.certificate.take())
            .is_some_and(|(a, d, until)| a == agent && d == digest && Instant::now() < until)
    }
}

pub(crate) struct PrefixLease {
    limits: Arc<Limits>,
    machine: MachineId,
}
impl Drop for PrefixLease {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.limits.prefix.lock() {
            if let Some(count) = slots.get_mut(&self.machine) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    slots.remove(&self.machine);
                }
            }
        }
    }
}

/// Enrollment or a currently usable evidence record protects allocation
/// capacity. Transport claims and discovery entries alone cannot claim it.
pub(crate) async fn reserved_peer(
    store: Option<&crate::peer_evidence::PeerEvidenceStore>,
    owner: &crate::owner_trust::OwnerTrust,
    revoked: &tokio::sync::RwLock<crate::revocation::RevocationSet>,
    machine: MachineId,
) -> bool {
    if revoked.read().await.is_machine_revoked(&machine) {
        return false;
    }
    owner.is_enrolled_owner_machine(revoked, &machine).await
        || store.is_some_and(|s| s.has_machine(machine, dm_capability::now_unix_ms()))
}

/// Held across queueing, reading, verification and replying; dropping resets
/// release both the machine slot and the aggregate reservation, even on abort.
pub(crate) struct Lease {
    limits: Arc<Limits>,
    machine: MachineId,
    pub(crate) deadline: Instant,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _stranger_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut s) = self.limits.state.lock() {
            if let Some(m) = s.machines.get_mut(&self.machine) {
                m.open = m.open.saturating_sub(1);
            }
        }
    }
}

async fn read_message(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<(u8, Vec<u8>)> {
    let kind = reader.read_u8().await?;
    let length = reader.read_u32().await? as usize;
    if length > MESSAGE_CAP - 5 {
        return Err(invalid("evidence message cap"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    // Exactly one frame per direction. FIN is covered by the same deadline;
    // a peer cannot append another request or hold the stream indefinitely.
    if reader.read(&mut [0u8; 1]).await? != 0 {
        return Err(invalid("evidence trailing frame"));
    }
    Ok((kind, body))
}
async fn write_message(
    writer: &mut (impl AsyncWrite + Unpin),
    limits: &Limits,
    machine: MachineId,
    kind: u8,
    body: &[u8],
) -> io::Result<()> {
    if body.len() > MESSAGE_CAP - 5 || !limits.charge(machine, body.len() + 5) {
        return Err(invalid("evidence reply budget"));
    }
    writer.write_u8(kind).await?;
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(body).await?;
    writer.shutdown().await
}

pub(crate) fn ingest_hello(
    store: Option<&Arc<crate::peer_evidence::PeerEvidenceStore>>,
    capture: &crate::peer_evidence::VerifiedWireCapture,
    limits: &Limits,
    machine: MachineId,
    mut record: EvidenceRecordV1,
    now: u64,
) -> io::Result<Arc<EvidenceView>> {
    decode::parts(
        &record.announcement,
        &record.advert,
        record.certificate.as_deref(),
    )?;
    // Cheap name/cap checks precede any cryptographic work.
    if record.announcement.len() > crate::peer_evidence::ANNOUNCEMENT_CAP {
        return Err(invalid("announcement cap"));
    }
    let ann = announce_v3::deserialize_v3(&record.announcement).map_err(io::Error::other)?;
    if ann.machine_id != machine {
        return Err(invalid("Hello does not name transport machine"));
    }
    if record.certificate.is_none() {
        record.certificate = store
            .cloned()
            .and_then(|s| s.certificate_for(ann.agent_id, machine, ann.cert_digest, now));
    }
    let view = Arc::new(
        record
            .verify_budgeted(now, W_MS, &mut || limits.verify())
            .map_err(io::Error::other)?,
    );
    if let Some(cert) = &view.certificate {
        if announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone())) != ann.cert_digest {
            return Err(invalid("certificate digest mismatch"));
        }
    }
    if let Some(store) = store.cloned() {
        if store.related(ann.agent_id, machine, view.certificate.as_ref(), now) {
            // Reuse the verified view, never pay for an unbudgeted second verify.
            store
                .ingest_verified(record, Arc::clone(&view), IngestSource::Hello, now)
                .map_err(io::Error::other)?;
            return Ok(view);
        }
    }
    // Network-verified, ingest-fresh bytes only; never seed the binding,
    // discovery or capability registries from persisted evidence.
    capture.capture(
        ann.agent_id,
        true,
        &record.announcement,
        ann.announced_at.saturating_mul(1000),
        now,
    );
    capture.capture(
        ann.agent_id,
        false,
        &record.advert,
        view.advert.created_at_unix_ms,
        now,
    );
    Ok(view)
}

fn mint_hello(
    identity: &crate::identity::Identity,
    mut v2: crate::IdentityAnnouncement,
    own_cert: &crate::announce_blob::SharedCertPair,
    caps: crate::dm::DmCapabilities,
    have: Option<[u8; 32]>,
    include_cert: bool,
) -> io::Result<Hello> {
    // The only signer is this process's identity, never a selected peer record.
    if v2.agent_id != identity.agent_id() || v2.machine_id != identity.machine_id() {
        return Err(invalid("Hello must carry our own identity"));
    }
    let pair = own_cert.read().map_err(|_| invalid("certificate lock"))?;
    v2.user_id = pair.0;
    v2.agent_certificate = pair.1.clone();
    drop(pair);
    let v3 = announce_v3::IdentityAnnouncementV3::build_from_v2(
        &v2,
        identity.machine_keypair().secret_key(),
        0,
    )
    .map_err(io::Error::other)?;
    let certificate = if include_cert && have != Some(v3.cert_digest) {
        v2.agent_certificate
            .as_ref()
            .map(|c| c.to_storage_bytes())
            .transpose()
            .map_err(io::Error::other)?
    } else {
        None
    };
    if !crate::dm_capability_service::advert_is_publishable(&caps) {
        return Err(invalid("own capabilities not ready"));
    }
    let signing = crate::gossip::SigningContext::from_keypair(identity.agent_keypair());
    let advert = crate::dm_capability_service::build_signed_advert(
        &signing,
        v2.agent_id,
        v2.machine_id,
        caps,
    )
    .map_err(io::Error::other)?;
    Ok(Hello {
        announcement: announce_v3::serialize_v3(&v3).map_err(io::Error::other)?,
        advert,
        certificate,
        have_certificate: None,
    })
}

struct Context {
    runtime: Arc<EvidenceRuntime>,
    capture: Arc<crate::peer_evidence::VerifiedWireCapture>,
    network: Arc<crate::network::NetworkNode>,
    identity: Arc<crate::identity::Identity>,
    template: crate::IdentityAnnouncement,
    own_cert: crate::announce_blob::SharedCertPair,
    capabilities: Arc<tokio::sync::watch::Sender<crate::dm::DmCapabilities>>,
    discovery: Arc<tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>>,
    owner: crate::owner_trust::OwnerTrust,
    revoked: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
}
impl Context {
    async fn related(&self, machine: MachineId) -> bool {
        if self.revoked.read().await.is_machine_revoked(&machine) {
            return false;
        }
        if self
            .owner
            .is_enrolled_owner_machine(&self.revoked, &machine)
            .await
        {
            return true;
        }
        let Some(store) = self.runtime.store() else {
            return false;
        };
        let now = dm_capability::now_unix_ms();
        if store.has_machine(machine, now) {
            return true;
        }
        let cache = self.discovery.read().await;
        // Never wait for a second identity lock, and never clone an entire
        // machine's discovery entries just to decide whether to send Hello.
        let Ok(revoked) = self.revoked.try_read() else {
            return false;
        };
        cache.values().any(|d| {
            d.machine_id == machine
                && now / 1000
                    <= d.announced_at
                        .saturating_add(crate::dm_capability::ADVERT_CACHE_TTL_SECS)
                && !revoked.is_agent_revoked(&d.agent_id)
                && !revoked.is_binding_revoked(&d.agent_id, &machine)
                && !d
                    .agent_certificate
                    .as_ref()
                    .is_some_and(|c| c.is_expired(now / 1000))
                && store.related(d.agent_id, machine, d.agent_certificate.as_ref(), now)
        })
    }
    fn own(&self, have: Option<[u8; 32]>, include_cert: bool) -> io::Result<Hello> {
        let mut v2 = self.template.clone();
        v2.announced_at = dm_capability::now_unix_ms() / 1000;
        v2.addresses = self
            .network
            .local_addr()
            .filter(|a| a.port() != 0)
            .map(|addr| {
                crate::filter_discovery_announcement_addrs(
                    crate::bind_dialable_interface_hints(Some(addr), addr.port()),
                    crate::allow_local_discovery_addresses(self.network.config()),
                )
            })
            .unwrap_or_default();
        mint_hello(
            &self.identity,
            v2,
            &self.own_cert,
            self.capabilities.borrow().clone(),
            have,
            include_cert,
        )
    }

    fn ingest(
        &self,
        machine: MachineId,
        record: EvidenceRecordV1,
    ) -> io::Result<Arc<EvidenceView>> {
        ingest_hello(
            self.runtime.store().as_ref(),
            &self.capture,
            &self.runtime.wire_limits,
            machine,
            record,
            dm_capability::now_unix_ms(),
        )
    }
    async fn accept(self: Arc<Self>, mut stream: PeerStream) {
        let Some(lease) = stream.evidence_lease.take() else {
            return;
        };
        let lease = Arc::new(lease);
        let machine = stream.peer();
        let (mut send, mut recv) = stream.into_split();
        let result = tokio::time::timeout_at(lease.deadline, async {
            let (kind, body) = read_message(&mut recv).await?;
            if !self.runtime.wait(0).await {
                return Err(invalid("evidence load deadline"));
            }
            match kind {
                LOOKUP => {
                    // S3 reserves/framing-checks Lookup but discloses no evidence.
                    // Even NotFound consumes rate and byte credit.
                    if !self.runtime.wire_limits.request(machine, false) {
                        return Err(invalid("lookup rate"));
                    }
                    let _: AgentId = codec().deserialize(&body).map_err(io::Error::other)?;
                    write_message(
                        &mut send,
                        &self.runtime.wire_limits,
                        machine,
                        NOT_FOUND,
                        &[],
                    )
                    .await
                }
                HELLO | CERTIFICATE => {
                    if kind == HELLO && !self.runtime.wire_limits.request(machine, true) {
                        return Err(invalid("Hello rate"));
                    }
                    let hello: Hello = decode::hello(&body)?;
                    drop(body);
                    if kind == CERTIFICATE {
                        let ann = announce_v3::deserialize_v3(&hello.announcement)
                            .map_err(io::Error::other)?;
                        if hello.certificate.is_none()
                            || !self.runtime.wire_limits.take_certificate(
                                machine,
                                ann.agent_id,
                                ann.cert_digest,
                            )
                        {
                            return Err(invalid("unsolicited certificate"));
                        }
                    } else if hello.certificate.is_some() {
                        return Err(invalid("unsolicited certificate"));
                    }
                    let have = hello.have_certificate;
                    let record = hello.into_record();
                    let context = Arc::clone(&self);
                    let verifying_lease = Arc::clone(&lease);
                    let view = tokio::task::spawn_blocking(move || {
                        let _lease = verifying_lease;
                        context.ingest(machine, record)
                    })
                    .await
                    .map_err(io::Error::other)??;
                    if kind == CERTIFICATE {
                        return write_message(
                            &mut send,
                            &self.runtime.wire_limits,
                            machine,
                            ACK,
                            &[],
                        )
                        .await;
                    }
                    let have_peer = view
                        .certificate
                        .as_ref()
                        .map(|_| view.announcement.cert_digest);
                    if have_peer.is_none()
                        && crate::announce_blob::fetch_warranted(&view.announcement.cert_digest)
                    {
                        self.runtime.wire_limits.need_certificate(
                            machine,
                            view.announcement.agent_id,
                            view.announcement.cert_digest,
                        );
                    }
                    // A simultaneous on-connect request may already have sent
                    // our Hello. Replies and requests share its 60-second gate.
                    if !crate::dm_capability_service::advert_is_publishable(
                        &self.capabilities.borrow(),
                    ) || !self
                        .runtime
                        .wire_limits
                        .begin_hello(machine, self.related(machine).await)
                    {
                        let body = codec().serialize(&have_peer).map_err(io::Error::other)?;
                        return write_message(
                            &mut send,
                            &self.runtime.wire_limits,
                            machine,
                            ACK,
                            &body,
                        )
                        .await;
                    }
                    let mut reply = self.own(have, true)?;
                    reply.have_certificate = have_peer;
                    let body = codec().serialize(&reply).map_err(io::Error::other)?;
                    write_message(&mut send, &self.runtime.wire_limits, machine, HELLO, &body).await
                }
                _ => Err(invalid("unexpected evidence request")),
            }
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            self.runtime.wire_limits.reset(machine);
            // Only this stream is dropped. No connection close or retry signal.
            tracing::debug!(?machine, "evidence stream refused/reset");
        }
    }
    async fn exchange(
        &self,
        machine: MachineId,
        kind: u8,
        hello: Hello,
    ) -> io::Result<(Lease, u8, Vec<u8>)> {
        let lease = self
            .runtime
            .wire_limits
            .admit(
                machine,
                reserved_peer(
                    self.runtime.store().as_deref(),
                    &self.owner,
                    &self.revoked,
                    machine,
                )
                .await,
            )
            .ok_or_else(|| invalid("evidence stream budget"))?;
        let (kind, body) = tokio::time::timeout_at(lease.deadline, async {
            let (mut send, mut recv) = self
                .network
                .open_bi(&ant_quic::PeerId(machine.0))
                .await
                .map_err(io::Error::other)?;
            send.write_u8(StreamProtocol::EvidenceV1.as_u8()).await?;
            let body = codec().serialize(&hello).map_err(io::Error::other)?;
            drop(hello);
            write_message(&mut send, &self.runtime.wire_limits, machine, kind, &body).await?;
            drop(body);
            read_message(&mut recv).await
        })
        .await
        .map_err(io::Error::other)??;
        Ok((lease, kind, body))
    }
    async fn connect(self: Arc<Self>, machine: MachineId) {
        // The transport can connect before the inbox publishes its KEM key.
        // Wait for that initial readiness without spending the one Hello try.
        let mut caps = self.capabilities.subscribe();
        if !matches!(
            tokio::time::timeout(DEADLINE, async {
                loop {
                    if crate::dm_capability_service::advert_is_publishable(&caps.borrow()) {
                        return Ok::<(), io::Error>(());
                    }
                    caps.changed().await.map_err(io::Error::other)?;
                }
            })
            .await,
            Ok(Ok(()))
        ) {
            return;
        }
        if !self.runtime.wait(0).await
            || !self
                .runtime
                .wire_limits
                .begin_hello(machine, self.related(machine).await)
        {
            return;
        }
        // All errors (including an old peer's unknown-prefix reset) terminate
        // this one attempt. Nothing here touches DM state or schedules retries.
        if self.send_hello(machine).await.is_err() {
            self.runtime.wire_limits.reset(machine);
        }
    }
    async fn send_hello(self: &Arc<Self>, machine: MachineId) -> io::Result<()> {
        let mut hello = self.own(None, false)?;
        hello.have_certificate = self
            .runtime
            .store()
            .and_then(|s| s.machine_certificate_digest(machine, dm_capability::now_unix_ms()));
        let (lease, kind, body) = self.exchange(machine, HELLO, hello).await?;
        let have = match kind {
            ACK => codec()
                .deserialize::<Option<[u8; 32]>>(&body)
                .map_err(io::Error::other)?,
            HELLO => {
                let reply = decode::hello(&body)?;
                let have = reply.have_certificate;
                drop(body);
                let context = Arc::clone(self);
                // Keep the reply reservation alive even if this task is aborted
                // while spawn_blocking finishes verification / a durable move.
                tokio::task::spawn_blocking(move || {
                    let _lease = lease;
                    context.ingest(machine, reply.into_record())
                })
                .await
                .map_err(io::Error::other)??;
                return self.send_certificate_if_missing(machine, have).await;
            }
            _ => return Err(invalid("evidence Hello refused")),
        };
        drop(body);
        drop(lease);
        self.send_certificate_if_missing(machine, have).await
    }
    async fn send_certificate_if_missing(
        &self,
        machine: MachineId,
        have: Option<[u8; 32]>,
    ) -> io::Result<()> {
        let follow = self.own(have, true)?;
        if follow.certificate.is_some() {
            let (_lease, kind, body) = self.exchange(machine, CERTIFICATE, follow).await?;
            if kind != ACK || !body.is_empty() {
                return Err(invalid("certificate refused"));
            }
        }
        Ok(())
    }
}

impl crate::Agent {
    pub(crate) fn start_evidence_wire(&self) {
        let Some(network) = &self.network else {
            return;
        };
        let Ok(mut acceptor) = self.register_stream_acceptor(StreamProtocol::EvidenceV1) else {
            return;
        };
        let Ok(template) = self.build_announcement(false, false) else {
            return;
        };
        let context = Arc::new(Context {
            runtime: Arc::clone(self.peer_evidence()),
            capture: Arc::clone(&self.capability_store.evidence_wire),
            network: Arc::clone(network),
            identity: Arc::clone(&self.identity),
            template,
            own_cert: Arc::clone(&self.own_cert_pair),
            capabilities: Arc::clone(&self.dm_capabilities_tx),
            discovery: Arc::clone(&self.identity_discovery_cache),
            owner: self.owner_trust.clone(),
            revoked: Arc::clone(&self.revocation_set),
        });
        // Subscribe synchronously, before spawning: don't lose early connects.
        let mut events = network.subscribe();
        let token = self.shutdown_token.clone();
        self.spawn_tracked(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    stream = acceptor.next() => {
                        let Some(stream) = stream else { break; };
                        tasks.spawn(Arc::clone(&context).accept(stream));
                    }
                    event = events.recv() => match event {
                        Ok(crate::network::NetworkEvent::PeerConnected { peer_id, .. }) if tasks.len() < 64 => {
                            // Bound pending connect jobs too. Request bodies are
                            // separately covered by the shared allocation pool.
                            tasks.spawn(Arc::clone(&context).connect(MachineId(peer_id)));
                        }
                        Ok(crate::network::NetworkEvent::PeerDisconnected { peer_id, .. }) => context.runtime.wire_limits.disconnect(MachineId(peer_id)),
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        _ => {},
                    },
                }
            }
            tasks.abort_all();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s3_hello_mints_only_own_evidence_and_sends_cert_only_on_miss() {
        let dir = tempfile::tempdir().unwrap();
        // No network config: identity-only, no sockets or real-network tasks.
        let agent = crate::Agent::builder()
            .with_identity_dir(dir.path())
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_user_key_path(dir.path().join("user.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .build()
            .await
            .unwrap();
        let template = agent.build_announcement(false, false).unwrap();
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let cert = crate::identity::AgentCertificate::issue(&owner, agent.identity.agent_keypair())
            .unwrap();
        let pair = crate::announce_blob::shared_cert_pair(Some(owner.user_id()), Some(cert));
        let caps = crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
        let first = mint_hello(
            &agent.identity,
            template.clone(),
            &pair,
            caps.clone(),
            None,
            false,
        )
        .unwrap();
        assert!(first.certificate.is_none());
        let encoded = codec().serialize(&first).unwrap();
        let decoded = decode::hello(&encoded).unwrap();
        assert_eq!(decoded.announcement, first.announcement);
        assert_eq!(decoded.advert, first.advert);
        let mut forged_length = first.announcement.clone();
        // Magic + two fixed ids precede the first nested Vec length. A tiny
        // frame claiming a huge key must fail without reserving that Vec.
        forged_length[68..76].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode::parts(&forged_length, &first.advert, None).is_err());
        let view = first
            .into_record()
            .verify(dm_capability::now_unix_ms(), W_MS)
            .unwrap();
        assert_eq!(view.announcement.agent_id, agent.agent_id());
        assert_eq!(view.announcement.machine_id, agent.machine_id());
        assert_eq!(view.advert.agent_id, agent.agent_id().0);
        let next = mint_hello(
            &agent.identity,
            template.clone(),
            &pair,
            caps.clone(),
            None,
            true,
        )
        .unwrap();
        assert!(next.certificate.is_some());
        let encoded = codec().serialize(&next).unwrap();
        let record = decode::hello(&encoded).unwrap().into_record();
        assert!(ingest_hello(
            None,
            &Default::default(),
            &Limits::default(),
            agent.machine_id(),
            record,
            dm_capability::now_unix_ms()
        )
        .unwrap()
        .certificate
        .is_some());
        assert!(mint_hello(
            &agent.identity,
            template.clone(),
            &pair,
            caps.clone(),
            Some(view.announcement.cert_digest),
            true
        )
        .unwrap()
        .certificate
        .is_none());
        let mut other = template;
        other.agent_id = AgentId([7; 32]);
        assert!(mint_hello(&agent.identity, other, &pair, caps, None, false).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode::hello(&trailing).is_err());
        agent.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn s3_hostile_requester_shares_all_connection_budgets() {
        let limits = Arc::new(Limits::default());
        let m = MachineId([1; 32]);
        let first_connection = limits.admit(m, false).unwrap();
        let second_connection = limits.admit(m, false).unwrap();
        assert!(limits.admit(m, false).is_none());
        drop(first_connection);
        let third_connection = limits.admit(m, false).unwrap();
        assert!(limits.request(m, false));
        assert!(!limits.request(m, false));
        limits.disconnect(m); // reconnect cannot reset the rate or byte windows
        assert!(!limits.request(m, false));
        assert!(limits.charge(m, 64 * 1024));
        assert!(!limits.charge(m, 1));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.charge(m, 64 * 1024));
        assert!(!limits.request(m, false));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.request(m, false));
        drop((second_connection, third_connection));
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
    }

    #[tokio::test(start_paused = true)]
    async fn s3_global_bytes_verifies_and_allocation_bounds() {
        let limits = Arc::new(Limits::default());
        let mut leases = Vec::new();
        for id in 0..(TOTAL_ALLOCATION_CAP / ALLOCATION_RESERVATION) {
            leases.push(limits.admit(MachineId([id as u8; 32]), true).unwrap());
        }
        assert!(limits.admit(MachineId([99; 32]), true).is_none());
        drop(leases);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
        for id in 0..4 {
            assert!(limits.charge(MachineId([id; 32]), 64 * 1024));
        }
        assert!(!limits.charge(MachineId([5; 32]), 1));
        for _ in 0..32 {
            assert!(limits.verify());
        }
        assert!(!limits.verify());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.verify());
        assert!(limits.charge(MachineId([5; 32]), 64 * 1024));
    }

    #[tokio::test(start_paused = true)]
    async fn s3_strangers_cannot_exhaust_relationship_reservations() {
        let limits = Arc::new(Limits::default());
        let mut strangers = Vec::new();
        // Four identities could previously consume all eight reservations.
        for id in 0..2 {
            for _ in 0..2 {
                strangers.push(limits.admit(MachineId([id; 32]), false).unwrap());
            }
        }
        assert!(limits.admit(MachineId([2; 32]), false).is_none());
        assert!(limits.admit(MachineId([3; 32]), false).is_none());
        let mut related = Vec::new();
        for id in 4..6 {
            for _ in 0..2 {
                related.push(limits.admit(MachineId([id; 32]), true).unwrap());
            }
        }
        assert_eq!(limits.allocations.available_permits(), 0);
        assert!(limits.admit(MachineId([6; 32]), true).is_none());
        drop(related);
        // Releasing protected slots does not let strangers borrow them.
        assert!(limits.admit(MachineId([2; 32]), false).is_none());
        drop(strangers.pop());
        assert!(limits.admit(MachineId([2; 32]), false).is_some());
        drop(strangers);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
        assert_eq!(
            limits.stranger_allocations.available_permits(),
            TOTAL_ALLOCATION_CAP / 2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn s3_not_found_and_resets_are_charged() {
        let limits = Limits::default();
        let m = MachineId([1; 32]);
        let (mut tx, mut rx) = tokio::io::duplex(32);
        assert!(limits.request(m, false));
        write_message(&mut tx, &limits, m, NOT_FOUND, &[])
            .await
            .unwrap();
        assert_eq!(read_message(&mut rx).await.unwrap(), (NOT_FOUND, vec![]));
        assert!(limits.charge(m, RESET_CHARGE));
        assert_eq!(
            limits.state.lock().unwrap().machines[&m].bytes.total,
            5 + RESET_CHARGE
        );
        assert_eq!(limits.state.lock().unwrap().bytes.total, 5 + RESET_CHARGE);
        assert!(!limits.request(m, false));
        assert!(limits.charge(m, 64 * 1024 - 5 - RESET_CHARGE));
        assert!(!limits.charge(m, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn s3_old_peer_reset_is_one_attempt_and_non_relationship_gets_no_hello() {
        let limits = Arc::new(Limits::default());
        let m = MachineId([1; 32]);
        assert!(!limits.begin_hello(m, false));
        assert!(limits.state.lock().unwrap().machines.is_empty());
        assert!(limits.begin_hello(m, true));
        let (mut local, mut old_peer) = tokio::io::duplex(32);
        local
            .write_u8(StreamProtocol::EvidenceV1.as_u8())
            .await
            .unwrap();
        let prefix = old_peer.read_u8().await.unwrap();
        // Frozen 0.45 mapping. This is an inert reset simulation, not the
        // released-binary interop gate, which must still run in Linux CI.
        assert!(!(1..=5).contains(&prefix));
        drop(old_peer);
        assert!(read_message(&mut local).await.is_err());
        for _ in 0..100 {
            assert!(!limits.begin_hello(m, true));
        }
        tokio::time::advance(HELLO_INTERVAL).await;
        assert!(!limits.begin_hello(m, true), "no retry until reconnect");
        limits.disconnect(m);
        assert!(limits.begin_hello(m, true));
        limits.disconnect(m);
        assert!(
            !limits.begin_hello(m, true),
            "reconnect churn retains cooldown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn s3_slow_body_deadline_includes_queue_delay_and_releases_budget() {
        let limits = Arc::new(Limits::default());
        let lease = limits.admit(MachineId([1; 32]), false).unwrap();
        tokio::time::advance(Duration::from_secs(4)).await; // queued acceptor
        let (_tx, mut rx) = tokio::io::duplex(32);
        let start = Instant::now();
        assert!(
            tokio::time::timeout_at(lease.deadline, read_message(&mut rx))
                .await
                .is_err()
        );
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(1));
        drop(lease);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
    }

    #[tokio::test(start_paused = true)]
    async fn s3_malformed_or_incomplete_frames_are_bounded() {
        let mut oversized = vec![HELLO];
        oversized.extend_from_slice(&(MESSAGE_CAP as u32).to_be_bytes());
        assert!(read_message(&mut oversized.as_slice()).await.is_err());
        let (mut tx, mut rx) = tokio::io::duplex(32);
        tx.write_all(&[HELLO, 0, 0, 0, 2, 0]).await.unwrap();
        assert!(tokio::time::timeout(DEADLINE, read_message(&mut rx))
            .await
            .is_err());
        let malformed = vec![255; MESSAGE_CAP - 5];
        assert!(decode::hello(&malformed).is_err());
        let mut hostile_length = u64::MAX.to_le_bytes().to_vec();
        hostile_length.extend_from_slice(&[0; 32]);
        assert!(decode::hello(&hostile_length).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn s3_certificate_continuation_is_requested_once_and_expires() {
        let limits = Arc::new(Limits::default());
        let m = MachineId([1; 32]);
        let a = AgentId([2; 32]);
        assert!(!limits.take_certificate(m, a, [3; 32]));
        limits.need_certificate(m, a, [3; 32]);
        assert!(limits.take_certificate(m, a, [3; 32]));
        assert!(!limits.take_certificate(m, a, [3; 32]));
        limits.need_certificate(m, a, [3; 32]);
        assert!(!limits.take_certificate(m, a, [4; 32]));
        limits.need_certificate(m, a, [3; 32]);
        tokio::time::advance(DEADLINE).await;
        assert!(!limits.take_certificate(m, a, [3; 32]));
    }
}

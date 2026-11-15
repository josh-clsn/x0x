//! T-self-evidence-lookup: a node proves only its own agent, and only to
//! the transport-authenticated machine that asks, disclosing no more than
//! its public heartbeat. A stranger's answer lives in memory only; nothing
//! about it is written to a file.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Our agent raw-sent to a machine within this window: a quiet node answers it.
const RECENT_SEND_WINDOW: Duration = Duration::from_millis(W_MS);
const RECENT_SEND_CAP: usize = 256;
/// One minted own-evidence answer serves every ask for this long.
const ANSWER_REUSE: Duration = Duration::from_secs(60);
/// The public answer and the relationship answer are cached side by side.
const ANSWER_SLOTS: usize = 2;
/// The send path waits at most this long for a self-lookup to land.
pub(crate) const SEND_WAIT: Duration = Duration::from_millis(1500);
/// A claimant machine gets one self-only Lookup in flight and one start per
/// interval, whatever agent ids its frames claim.
const CLAIMANT_INTERVAL: Duration = Duration::from_secs(2);
const CLAIMANT_CAP: usize = 4096;

type AnswerKey = ([u8; 32], crate::dm::DmCapabilities);

/// Process-only state. Nothing here is persisted.
#[derive(Default)]
pub(crate) struct SelfLookup {
    sends: Mutex<VecDeque<(MachineId, Instant)>>,
    answer: Mutex<VecDeque<(AnswerKey, Instant, lookup::Found)>>,
    pub(crate) mints: AtomicU64,
    claimants: Mutex<HashMap<MachineId, (Instant, bool)>>,
    flights: Arc<Flights>,
}

/// One self-only Lookup to a claimant machine, in flight until dropped.
pub(crate) struct ClaimantGuard<'a> {
    state: &'a SelfLookup,
    machine: MachineId,
}
impl Drop for ClaimantGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut claimants) = self.state.claimants.lock() {
            if let Some((_, busy)) = claimants.get_mut(&self.machine) {
                *busy = false;
            }
        }
    }
}

struct Flights {
    counts: Mutex<HashMap<AgentId, usize>>,
    done: tokio::sync::watch::Sender<u64>,
}
impl Default for Flights {
    fn default() -> Self {
        Self {
            counts: Mutex::default(),
            done: tokio::sync::watch::channel(0).0,
        }
    }
}

/// Marks a Lookup for one target in flight until dropped.
pub(crate) struct Flight {
    flights: Arc<Flights>,
    agent: AgentId,
}
impl Drop for Flight {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.flights.counts.lock() {
            if let Some(n) = counts.get_mut(&self.agent) {
                *n -= 1;
                if *n == 0 {
                    counts.remove(&self.agent);
                }
            }
        }
        self.flights.done.send_modify(|v| *v = v.wrapping_add(1));
    }
}

impl SelfLookup {
    pub(crate) fn note_sent(&self, machine: MachineId) {
        let Ok(mut sends) = self.sends.lock() else {
            return;
        };
        let now = Instant::now();
        sends.retain(|(m, at)| *m != machine && now.duration_since(*at) < RECENT_SEND_WINDOW);
        if sends.len() == RECENT_SEND_CAP {
            sends.pop_front();
        }
        sends.push_back((machine, now));
    }

    pub(crate) fn sent_within_window(&self, machine: MachineId) -> bool {
        let now = Instant::now();
        self.sends.lock().is_ok_and(|sends| {
            sends
                .iter()
                .any(|(m, at)| *m == machine && now.duration_since(*at) < RECENT_SEND_WINDOW)
        })
    }

    /// Start a self-only Lookup to `machine` if it has none in flight and
    /// started none within [`CLAIMANT_INTERVAL`].
    pub(crate) fn claim_claimant(&self, machine: MachineId) -> Option<ClaimantGuard<'_>> {
        let mut claimants = self.claimants.lock().ok()?;
        let now = Instant::now();
        if let Some((started, busy)) = claimants.get(&machine) {
            if *busy || now.duration_since(*started) < CLAIMANT_INTERVAL {
                return None;
            }
        }
        if !claimants.contains_key(&machine) && claimants.len() >= CLAIMANT_CAP {
            claimants.retain(|_, (started, busy)| {
                *busy || now.duration_since(*started) < CLAIMANT_INTERVAL
            });
            if claimants.len() >= CLAIMANT_CAP {
                return None;
            }
        }
        claimants.insert(machine, (now, true));
        Some(ClaimantGuard {
            state: self,
            machine,
        })
    }

    pub(crate) fn begin(&self, agent: AgentId) -> Flight {
        if let Ok(mut counts) = self.flights.counts.lock() {
            *counts.entry(agent).or_default() += 1;
        }
        Flight {
            flights: Arc::clone(&self.flights),
            agent,
        }
    }

    pub(crate) fn in_flight(&self, agent: &AgentId) -> bool {
        self.flights
            .counts
            .lock()
            .is_ok_and(|counts| counts.contains_key(agent))
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.flights.done.subscribe()
    }

    /// Reuse a minted answer while its certificate pair and capabilities
    /// are unchanged. The lock is held across the mint so concurrent asks
    /// share one signing.
    fn answer(
        &self,
        key: AnswerKey,
        mint: impl FnOnce() -> io::Result<lookup::Found>,
    ) -> io::Result<lookup::Found> {
        let mut slots = self.answer.lock().map_err(|_| invalid("answer lock"))?;
        let now = Instant::now();
        if let Some((_, _, found)) = slots
            .iter()
            .find(|(cached, at, _)| *cached == key && now.duration_since(*at) < ANSWER_REUSE)
        {
            return Ok(found.clone());
        }
        let found = mint()?;
        self.mints.fetch_add(1, Ordering::Relaxed);
        slots.retain(|(cached, _, _)| *cached != key);
        if slots.len() == ANSWER_SLOTS {
            slots.pop_front();
        }
        slots.push_back((key, now, found.clone()));
        Ok(found)
    }
}

/// Our agent raw-sent to `machine` within the window.
pub(crate) fn wrote_to(owner: &crate::owner_trust::OwnerTrust, machine: &MachineId) -> bool {
    owner
        .evidence()
        .is_some_and(|runtime| runtime.self_lookup.sent_within_window(*machine))
}

/// The class A stores a stranger's self-evidence writes, held only in memory.
pub(crate) struct Stores {
    pub(crate) announced: crate::dm_inbox::AuthenticatedMachineBindings,
    /// The heartbeat's user-identity consent: what a stranger may see.
    pub(crate) consented: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) direct: Arc<crate::direct::DirectMessaging>,
    pub(crate) contacts: Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    pub(crate) placements: Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
}

pub(crate) enum SelfFound {
    Stored,
    Stranger(Arc<EvidenceView>),
}

/// Requester acceptance of a self-only answer: the evidence must name the
/// transport-authenticated machine it came over, besides the checks every
/// Lookup reply passes. A relationship peer keeps the stored path.
pub(crate) fn verify_self_found(
    store: &crate::peer_evidence::PeerEvidenceStore,
    limits: &Limits,
    target: AgentId,
    machine: MachineId,
    record: EvidenceRecordV1,
    now: u64,
) -> io::Result<SelfFound> {
    decode::parts(
        &record.announcement,
        &record.advert,
        record.certificate.as_deref(),
    )?;
    if record.announcement.len() > crate::peer_evidence::ANNOUNCEMENT_CAP {
        return Err(invalid("announcement cap"));
    }
    let claimed = announce_v3::deserialize_v3(&record.announcement).map_err(io::Error::other)?;
    if claimed.agent_id != target || claimed.machine_id != machine {
        return Err(invalid("self evidence does not name the transport machine"));
    }
    let view = Arc::new(
        record
            .verify_budgeted(now, W_MS, &mut || limits.verify())
            .map_err(io::Error::other)?,
    );
    if view.announcement.agent_id != target || view.announcement.machine_id != machine {
        return Err(invalid("self evidence does not name the transport machine"));
    }
    let user = view
        .certificate
        .as_ref()
        .and_then(|cert| cert.user_id().ok());
    if announce_v3::cert_digest(&user, &view.certificate) != view.announcement.cert_digest {
        return Err(invalid("certificate digest mismatch"));
    }
    if store.related(target, machine, view.certificate.as_ref(), now) {
        store
            .ingest_verified(record, Arc::clone(&view), IngestSource::Gossip, now)
            .map_err(io::Error::other)?;
        return Ok(SelfFound::Stored);
    }
    if store.supersedes(target, &view) {
        return Err(invalid("move watermark"));
    }
    Ok(SelfFound::Stranger(view))
}

impl Context {
    /// This node's own evidence for a Lookup, minted at most once per
    /// [`ANSWER_REUSE`] for the same certificate pair and capabilities.
    /// `public`: the answer to a self-evidence grant, which carries the user
    /// id and the owner certificate only when the heartbeat would.
    pub(super) fn own_answer(&self, public: bool) -> io::Result<lookup::Found> {
        let pair = if public && !self.stores.consented.load(Ordering::Acquire) {
            (None, None)
        } else {
            self.own_cert
                .read()
                .map_err(|_| invalid("certificate lock"))?
                .clone()
        };
        let key = (
            announce_v3::cert_digest(&pair.0, &pair.1),
            self.capabilities.borrow().clone(),
        );
        let pair = Arc::new(std::sync::RwLock::new(pair));
        self.runtime.self_lookup.answer(key, || {
            self.own_with_pair(None, true, &pair)
                .map(|hello| hello.into_record().into())
        })
    }

    /// Write a stranger's verified self-evidence into the in-memory stores
    /// a class A announcement writes, after the identity listener's gates.
    /// It fills a missing binding or refreshes the same pairing, never moves
    /// the agent off a machine an authority store names, and ranks by the
    /// agent-signed advert time. The contact store, the bootstrap cache and
    /// the certificate event (whose consumer can persist) are not written.
    pub(super) async fn accept_self_evidence(
        &self,
        view: &EvidenceView,
        machine: MachineId,
    ) -> bool {
        let mut announcement = view.announcement.clone().into_announcement();
        announcement.user_id = view
            .certificate
            .as_ref()
            .and_then(|cert| cert.user_id().ok());
        announcement.agent_certificate = view.certificate.clone();
        let agent = announcement.agent_id;
        if agent == self.identity.agent_id() || announcement.machine_id != machine {
            return false;
        }
        // The machine signs "now"; only the agent's advert time ranks.
        announcement.announced_at = announcement
            .announced_at
            .min(view.advert.created_at_unix_ms / 1000);
        let now = crate::Agent::unix_timestamp_secs();
        if !crate::identity_announcement_timestamp_is_acceptable(announcement.announced_at, now)
            || announcement
                .agent_certificate
                .as_ref()
                .is_some_and(|cert| crate::identity::is_expired(cert.not_after(), now))
        {
            return false;
        }
        let decision = {
            let contacts = self.stores.contacts.read().await;
            crate::trust::TrustEvaluator::new(&contacts).evaluate(&crate::trust::TrustContext {
                agent_id: &agent,
                machine_id: &machine,
            })
        };
        if matches!(
            decision,
            crate::trust::TrustDecision::RejectBlocked
                | crate::trust::TrustDecision::RejectMachineMismatch
        ) {
            return false;
        }
        // Each authority store is read alone, before the revocation set.
        let attested = self.bindings.read().await.peek(&agent);
        let announced = self.stores.announced.read().await.peek(&agent);
        {
            let revoked = self.revoked.read().await;
            if revoked.is_agent_revoked(&agent)
                || revoked.is_machine_revoked(&machine)
                || revoked.is_binding_revoked(&agent, &machine)
            {
                return false;
            }
            let placements = self.stores.placements.read().await;
            if crate::key_move::enforce_pairing(
                &revoked,
                placements.placement_view(),
                &agent,
                &machine,
            )
            .is_some()
            {
                return false;
            }
            if [attested, announced].into_iter().flatten().any(|binding| {
                binding.machine_id != machine
                    && !revoked.is_machine_revoked(&binding.machine_id)
                    && !revoked.is_binding_revoked(&agent, &binding.machine_id)
            }) {
                return false;
            }
        }
        let cert_not_after = announcement
            .agent_certificate
            .as_ref()
            .and_then(|c| c.not_after());
        let discovered = crate::DiscoveredAgent {
            agent_id: agent,
            machine_id: machine,
            user_id: announcement.user_id,
            self_name: announcement.self_name.clone(),
            addresses: crate::filter_discovery_announcement_addrs(
                announcement.addresses.iter().copied(),
                crate::allow_local_discovery_addresses(self.network.config()),
            ),
            announced_at: announcement.announced_at,
            last_seen: now,
            machine_public_key: announcement.machine_public_key.clone(),
            nat_type: announcement.nat_type.clone(),
            can_receive_direct: announcement.can_receive_direct,
            is_relay: announcement.is_relay,
            is_coordinator: announcement.is_coordinator,
            reachable_via: announcement.reachable_via.clone(),
            relay_candidates: announcement.relay_candidates.clone(),
            cert_not_after,
            agent_certificate: announcement.agent_certificate.clone(),
            agent_public_key: announcement.agent_public_key.clone(),
            cert_digest: Some(view.announcement.cert_digest),
        };
        crate::dm_inbox::record_authenticated_machine_binding_with_expiry(
            &self.bindings,
            agent,
            machine,
            announcement.announced_at,
            cert_not_after,
        )
        .await;
        let (unheard, _) = tokio::sync::broadcast::channel(1);
        crate::cache_verified_announcement(
            &self.machines,
            &self.stores.announced,
            None,
            &self.discovery,
            &unheard,
            Some(&self.bindings),
            discovered,
        )
        .await;
        if self.caps.insert(
            agent,
            machine,
            view.advert.capabilities.clone(),
            view.advert.created_at_unix_ms,
        ) {
            self.caps
                .remember_advert_key(agent, &view.announcement.agent_public_key);
        }
        self.stores.direct.register_agent(agent, machine).await;
        if self
            .network
            .is_connected(&ant_quic::PeerId(machine.0))
            .await
        {
            self.stores.direct.mark_connected(agent, machine).await;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(n: u8) -> lookup::Found {
        lookup::Found::for_test(vec![n])
    }

    #[tokio::test(start_paused = true)]
    async fn the_answer_is_minted_once_per_minute_and_per_key() {
        let state = SelfLookup::default();
        let caps = crate::dm::DmCapabilities::v1_gossip_ready(vec![1; 1184]);
        let key = ([1; 32], caps.clone());
        let mints = std::cell::Cell::new(0);
        let mint = |n| {
            mints.set(mints.get() + 1);
            Ok(found(n))
        };
        state.answer(key.clone(), || mint(1)).unwrap();
        state.answer(key.clone(), || mint(2)).unwrap();
        assert_eq!(mints.get(), 1, "two asks within 60 s cost one signing");
        assert_eq!(state.mints.load(Ordering::Relaxed), 1);
        state.answer(([2; 32], caps.clone()), || mint(3)).unwrap();
        assert_eq!(mints.get(), 2, "a new certificate pair mints again");
        tokio::time::advance(ANSWER_REUSE).await;
        state.answer(([2; 32], caps), || mint(4)).unwrap();
        assert_eq!(mints.get(), 3, "an answer older than 60 s is not reused");
        assert!(state.answer(key, || Err(invalid("not ready"))).is_err());
        assert_eq!(state.mints.load(Ordering::Relaxed), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn recent_sends_last_fifteen_minutes_and_are_bounded() {
        let state = SelfLookup::default();
        let machine = MachineId([7; 32]);
        assert!(!state.sent_within_window(machine));
        state.note_sent(machine);
        tokio::time::advance(RECENT_SEND_WINDOW - Duration::from_millis(1)).await;
        assert!(state.sent_within_window(machine));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(!state.sent_within_window(machine));
        for i in 0..=RECENT_SEND_CAP {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&(i as u32).to_le_bytes());
            state.note_sent(MachineId(bytes));
        }
        assert_eq!(state.sends.lock().unwrap().len(), RECENT_SEND_CAP);
        assert!(!state.sent_within_window(MachineId([0; 32])));
    }

    #[tokio::test]
    async fn a_flight_ends_with_a_wakeup() {
        let state = SelfLookup::default();
        let agent = AgentId([3; 32]);
        let mut done = state.subscribe();
        let flight = state.begin(agent);
        let second = state.begin(agent);
        assert!(state.in_flight(&agent));
        drop(flight);
        assert!(state.in_flight(&agent));
        drop(second);
        assert!(!state.in_flight(&agent));
        assert!(done.has_changed().unwrap());
        done.borrow_and_update();
    }
}

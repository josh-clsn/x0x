//! T-self-evidence-lookup: a node proves only its own agent, and only to
//! the transport-authenticated machine that asks. A stranger's answer lives
//! in memory only; nothing about it is written to a file.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Our agent raw-sent to a machine within this window: a quiet node answers it.
const RECENT_SEND_WINDOW: Duration = Duration::from_millis(W_MS);
const RECENT_SEND_CAP: usize = 256;
/// One minted own-evidence answer serves every ask for this long.
const ANSWER_REUSE: Duration = Duration::from_secs(60);

type AnswerKey = ([u8; 32], crate::dm::DmCapabilities);

/// Process-only state. Nothing here is persisted.
#[derive(Default)]
pub(crate) struct SelfLookup {
    sends: Mutex<VecDeque<(MachineId, Instant)>>,
    answer: Mutex<Option<(AnswerKey, Instant, lookup::Found)>>,
    pub(crate) mints: AtomicU64,
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

    /// Reuse the minted answer while the certificate pair and capabilities
    /// are unchanged. The lock is held across the mint so concurrent asks
    /// share one signing.
    fn answer(
        &self,
        key: AnswerKey,
        mint: impl FnOnce() -> io::Result<lookup::Found>,
    ) -> io::Result<lookup::Found> {
        let mut slot = self.answer.lock().map_err(|_| invalid("answer lock"))?;
        let now = Instant::now();
        if let Some((cached, at, found)) = slot.as_ref() {
            if *cached == key && now.duration_since(*at) < ANSWER_REUSE {
                return Ok(found.clone());
            }
        }
        let found = mint()?;
        self.mints.fetch_add(1, Ordering::Relaxed);
        *slot = Some((key, now, found.clone()));
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
    pub(crate) cert_events: Arc<tokio::sync::broadcast::Sender<crate::VerifiedCertificate>>,
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
    Ok(SelfFound::Stranger(view))
}

impl Context {
    /// This node's own evidence for a Lookup, minted at most once per
    /// [`ANSWER_REUSE`] for the same certificate pair and capabilities.
    pub(super) fn own_answer(&self) -> io::Result<lookup::Found> {
        let key = {
            let pair = self
                .own_cert
                .read()
                .map_err(|_| invalid("certificate lock"))?;
            (
                announce_v3::cert_digest(&pair.0, &pair.1),
                self.capabilities.borrow().clone(),
            )
        };
        self.runtime.self_lookup.answer(key, || {
            self.own(None, true).map(|hello| hello.into_record().into())
        })
    }

    /// Write a stranger's verified self-evidence into the in-memory stores
    /// a class A announcement writes, after the identity listener's gates.
    /// The contact store and the bootstrap cache, which are files, are not
    /// written.
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
        crate::cache_verified_announcement(
            &self.machines,
            &self.stores.announced,
            None,
            &self.discovery,
            &self.stores.cert_events,
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
}

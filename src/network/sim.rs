//! W3-H (#1164) deterministic simulation fabric. Test builds only.
//!
//! A [`SimFabric`] stands in for the network between several in-process
//! x0x nodes. Each node's [`super::NetworkNode`] runs on a [`SimLink`]
//! (see [`super::link::LinkNode::Sim`]) instead of an ant-quic endpoint, so
//! everything above the transport — the receive pump, plane hello, sessions,
//! gossip runtime, direct messages and the daemon's listeners — is the
//! production code.
//!
//! Determinism rules (phase-1 spike; see
//! `.planning/team-2026-10-05/w3h-plan.md`):
//! - Time is tokio virtual time (`start_paused`); the fabric never reads the
//!   wall clock.
//! - A frame's delivery instant and its tie-break are functions of
//!   `(seed, src, dst, per-link sequence)` only, never of the global order
//!   in which tasks happened to emit frames. One pump task delivers frames
//!   in `(due, tie-break)` order.
//! - Accept-style calls park instead of failing fast, so an idle simulated
//!   node never busy-loops and virtual time can auto-advance.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use ant_quic::{
    ConnectionCloseReason, EndpointError, NodeError, PeerConnection, PeerId, PeerLifecycleEvent,
    Side, TransportAddr, TraversalMethod,
};
use tokio::sync::{broadcast, mpsc, oneshot, Notify};
use tokio::time::Instant;

type Key = [u8; 32];

/// What the fabric knows about one frame: enough for fault predicates and
/// the trace, never the frame's meaning (scenario predicates decode bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FrameMeta {
    pub(crate) src: Key,
    pub(crate) dst: Key,
    pub(crate) generation: u64,
    pub(crate) link_seq: u64,
    pub(crate) stream_type: u8,
    pub(crate) len: usize,
}

/// A fault decision for one frame, made at send time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    Pass,
    Drop,
    Delay(Duration),
}

type FaultRule = Box<dyn Fn(&FrameMeta, &[u8]) -> Fault + Send + Sync>;

/// One fabric-level event, in the order the fabric decided it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TraceEvent {
    Attached { node: Key },
    Online { node: Key, online: bool },
    Connected { a: Key, b: Key, generation: u64 },
    Closed { a: Key, b: Key, generation: u64 },
    Dropped(FrameMeta),
    Delivered(FrameMeta),
}

struct NodeSlot {
    addr: SocketAddr,
    online: bool,
    incarnation: u64,
    inbound: mpsc::UnboundedSender<(PeerId, u64, Vec<u8>)>,
    accept: mpsc::UnboundedSender<PeerConnection>,
    lifecycle: broadcast::Sender<(PeerId, PeerLifecycleEvent)>,
}

struct LinkState {
    generation: u64,
    next_seq: BTreeMap<Key, u64>,
    last_due: BTreeMap<Key, Instant>,
}

struct Pending {
    meta: FrameMeta,
    bytes: Vec<u8>,
    delivered: Option<oneshot::Sender<()>>,
}

struct FabricState {
    nodes: BTreeMap<Key, NodeSlot>,
    by_addr: BTreeMap<SocketAddr, Key>,
    links: BTreeMap<(Key, Key), LinkState>,
    partitions: BTreeSet<(Key, Key)>,
    rules: Vec<FaultRule>,
    queue: BTreeMap<(Instant, u64, u64), Pending>,
    trace: Vec<TraceEvent>,
    next_generation: u64,
    next_unique: u64,
}

/// The shared in-memory network for one simulated scenario.
pub(crate) struct SimFabric {
    seed: u64,
    base_latency: Duration,
    jitter_ms: u64,
    state: Mutex<FabricState>,
    wake: Notify,
}

fn pair(a: Key, b: Key) -> (Key, Key) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn stable_hash(parts: &[&[u8]]) -> u64 {
    // `DefaultHasher::new()` is SipHash with fixed zero keys: stable within
    // one toolchain, unlike `RandomState`.
    let mut hasher = std::hash::DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

fn not_connected(peer: &PeerId) -> NodeError {
    NodeError::Connection(format!(
        "sim: no live link to {}",
        hex::encode(&peer.0[..4])
    ))
}

impl SimFabric {
    /// A fabric whose every scheduling choice derives from `seed`.
    pub(crate) fn new(seed: u64) -> Arc<Self> {
        let fabric = Arc::new(Self {
            seed,
            base_latency: Duration::from_millis(5),
            jitter_ms: 5,
            state: Mutex::new(FabricState {
                nodes: BTreeMap::new(),
                by_addr: BTreeMap::new(),
                links: BTreeMap::new(),
                partitions: BTreeSet::new(),
                rules: Vec::new(),
                queue: BTreeMap::new(),
                trace: Vec::new(),
                next_generation: 1,
                next_unique: 0,
            }),
            wake: Notify::new(),
        });
        let pump = Arc::clone(&fabric);
        tokio::spawn(async move { Self::run_pump(pump).await });
        fabric
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FabricState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Add a fault rule; rules are consulted in insertion order and the
    /// first non-`Pass` decision wins.
    pub(crate) fn add_rule(
        &self,
        rule: impl Fn(&FrameMeta, &[u8]) -> Fault + Send + Sync + 'static,
    ) {
        self.lock().rules.push(Box::new(rule));
    }

    /// Take a node off the network (crash or power-off), or bring it back.
    /// Going offline closes every link and discards frames in flight.
    pub(crate) fn set_online(&self, node: &PeerId, online: bool) {
        let mut state = self.lock();
        if let Some(slot) = state.nodes.get_mut(&node.0) {
            slot.online = online;
        }
        state.trace.push(TraceEvent::Online {
            node: node.0,
            online,
        });
        if !online {
            Self::close_all_locked(&mut state, node.0, ConnectionCloseReason::PeerShutdown);
        }
    }

    /// Partition `a` from `b` (closing any live link) or heal it.
    pub(crate) fn set_partitioned(&self, a: &PeerId, b: &PeerId, partitioned: bool) {
        let mut state = self.lock();
        let key = pair(a.0, b.0);
        if partitioned {
            state.partitions.insert(key);
            Self::close_link_locked(&mut state, key, ConnectionCloseReason::LifecycleCleanup);
        } else {
            state.partitions.remove(&key);
        }
    }

    /// A stable digest of the fabric trace so far.
    pub(crate) fn trace_digest(&self) -> u64 {
        let state = self.lock();
        let mut hasher = std::hash::DefaultHasher::new();
        state.trace.hash(&mut hasher);
        hasher.finish()
    }

    fn attach(self: &Arc<Self>, peer: PeerId, addr: SocketAddr) -> Arc<SimLink> {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let (lifecycle, _) = broadcast::channel(256);
        let mut state = self.lock();
        let incarnation = state
            .nodes
            .get(&peer.0)
            .map_or(0, |slot| slot.incarnation.saturating_add(1));
        Self::close_all_locked(&mut state, peer.0, ConnectionCloseReason::Superseded);
        state.by_addr.insert(addr, peer.0);
        state.nodes.insert(
            peer.0,
            NodeSlot {
                addr,
                online: true,
                incarnation,
                inbound: inbound_tx,
                accept: accept_tx,
                lifecycle: lifecycle.clone(),
            },
        );
        state.trace.push(TraceEvent::Attached { node: peer.0 });
        drop(state);
        Arc::new(SimLink {
            fabric: Arc::clone(self),
            me: peer,
            inbound: tokio::sync::Mutex::new(inbound_rx),
            accept: tokio::sync::Mutex::new(accept_rx),
            lifecycle,
        })
    }

    fn close_all_locked(state: &mut FabricState, node: Key, reason: ConnectionCloseReason) {
        let keys: Vec<(Key, Key)> = state
            .links
            .keys()
            .filter(|(a, b)| *a == node || *b == node)
            .copied()
            .collect();
        for key in keys {
            Self::close_link_locked(state, key, reason);
        }
    }

    fn close_link_locked(state: &mut FabricState, key: (Key, Key), reason: ConnectionCloseReason) {
        let Some(link) = state.links.remove(&key) else {
            return;
        };
        let generation = link.generation;
        state.trace.push(TraceEvent::Closed {
            a: key.0,
            b: key.1,
            generation,
        });
        // Frames of a closed generation are lost, as with a dead QUIC
        // connection.
        state
            .queue
            .retain(|_, pending| pending.meta.generation != generation);
        for (me, other) in [(key.0, key.1), (key.1, key.0)] {
            if let Some(slot) = state.nodes.get(&me) {
                let _ = slot.lifecycle.send((
                    PeerId(other),
                    PeerLifecycleEvent::Closed { generation, reason },
                ));
            }
        }
    }

    fn connect(&self, from: Key, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        let mut state = self.lock();
        let to = *state
            .by_addr
            .get(&addr)
            .ok_or_else(|| NodeError::Connection(format!("sim: nothing at {addr}")))?;
        let reachable = state.nodes.get(&from).is_some_and(|s| s.online)
            && state.nodes.get(&to).is_some_and(|s| s.online)
            && !state.partitions.contains(&pair(from, to));
        if !reachable || from == to {
            return Err(NodeError::Connection(format!("sim: {addr} unreachable")));
        }
        let key = pair(from, to);
        if let Some(link) = state.links.get(&key) {
            return Ok(self.peer_connection(&state, to, link.generation, Side::Client));
        }
        let generation = state.next_generation;
        state.next_generation = state.next_generation.saturating_add(1);
        state.links.insert(
            key,
            LinkState {
                generation,
                next_seq: BTreeMap::new(),
                last_due: BTreeMap::new(),
            },
        );
        state.trace.push(TraceEvent::Connected {
            a: key.0,
            b: key.1,
            generation,
        });
        let inbound_side = self.peer_connection(&state, from, generation, Side::Server);
        for (me, other) in [(from, to), (to, from)] {
            if let Some(slot) = state.nodes.get(&me) {
                let _ = slot.lifecycle.send((
                    PeerId(other),
                    PeerLifecycleEvent::Established { generation },
                ));
            }
        }
        if let Some(slot) = state.nodes.get(&to) {
            let _ = slot.accept.send(inbound_side);
        }
        Ok(self.peer_connection(&state, to, generation, Side::Client))
    }

    fn peer_connection(
        &self,
        state: &FabricState,
        peer: Key,
        _generation: u64,
        side: Side,
    ) -> PeerConnection {
        let addr = state
            .nodes
            .get(&peer)
            .map_or(SocketAddr::from(([0, 0, 0, 0], 0)), |slot| slot.addr);
        let now = Instant::now().into_std();
        PeerConnection {
            peer_id: PeerId(peer),
            remote_addr: TransportAddr::Udp(addr),
            traversal_method: TraversalMethod::Direct,
            side,
            authenticated: true,
            connected_at: now,
            last_activity: now,
        }
    }

    fn enqueue(
        &self,
        from: Key,
        to: Key,
        generation: Option<u64>,
        bytes: Vec<u8>,
        delivered: Option<oneshot::Sender<()>>,
    ) -> Result<(), NodeError> {
        let mut state = self.lock();
        let key = pair(from, to);
        let Some(link) = state.links.get_mut(&key) else {
            return Err(not_connected(&PeerId(to)));
        };
        if generation.is_some_and(|g| g != link.generation) {
            return Err(NodeError::Connection("sim: generation superseded".into()));
        }
        let seq = link.next_seq.entry(from).or_insert(0);
        let link_seq = *seq;
        *seq = seq.saturating_add(1);
        let meta = FrameMeta {
            src: from,
            dst: to,
            generation: link.generation,
            link_seq,
            stream_type: bytes.first().copied().unwrap_or(0),
            len: bytes.len(),
        };
        let seq_bytes = link_seq.to_le_bytes();
        let seed_bytes = self.seed.to_le_bytes();
        let tie = stable_hash(&[&seed_bytes, &from, &to, &seq_bytes]);
        let jitter = Duration::from_millis(tie % self.jitter_ms.max(1));
        let mut due = Instant::now() + self.base_latency + jitter;
        let mut fault = Fault::Pass;
        for rule in &state.rules {
            fault = rule(&meta, &bytes);
            if fault != Fault::Pass {
                break;
            }
        }
        match fault {
            Fault::Drop => {
                state.trace.push(TraceEvent::Dropped(meta));
                return Ok(());
            }
            Fault::Delay(extra) => due += extra,
            Fault::Pass => {}
        }
        // Per-direction FIFO, as on one QUIC connection.
        let Some(link) = state.links.get_mut(&key) else {
            return Err(not_connected(&PeerId(to)));
        };
        let last = link.last_due.entry(from).or_insert(due);
        if due < *last {
            due = *last;
        }
        *last = due;
        let unique = state.next_unique;
        state.next_unique = state.next_unique.saturating_add(1);
        state.queue.insert(
            (due, tie, unique),
            Pending {
                meta,
                bytes,
                delivered,
            },
        );
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    async fn run_pump(fabric: Arc<Self>) {
        // The pump owns a strong handle: the fabric lives as long as the
        // scenario's runtime, which drops this task at the end of the test.
        loop {
            let next_due = fabric.lock().queue.keys().next().map(|(due, _, _)| *due);
            let notified = fabric.wake.notified();
            match next_due {
                Some(due) if due <= Instant::now() => fabric.deliver_due(),
                Some(due) => {
                    tokio::select! {
                        biased;
                        _ = notified => {}
                        _ = tokio::time::sleep_until(due) => {}
                    }
                }
                None => notified.await,
            }
        }
    }

    fn deliver_due(&self) {
        let now = Instant::now();
        let mut state = self.lock();
        while let Some(entry) = state.queue.first_entry() {
            if entry.key().0 > now {
                break;
            }
            let pending = entry.remove();
            let live = state
                .links
                .get(&pair(pending.meta.src, pending.meta.dst))
                .is_some_and(|link| link.generation == pending.meta.generation);
            let target = state
                .nodes
                .get(&pending.meta.dst)
                .filter(|slot| slot.online && live)
                .map(|slot| slot.inbound.clone());
            match target {
                Some(inbound) => {
                    let delivered = inbound
                        .send((
                            PeerId(pending.meta.src),
                            pending.meta.generation,
                            pending.bytes,
                        ))
                        .is_ok();
                    if delivered {
                        if let Some(ack) = pending.delivered {
                            let _ = ack.send(());
                        }
                        state.trace.push(TraceEvent::Delivered(pending.meta));
                    } else {
                        state.trace.push(TraceEvent::Dropped(pending.meta));
                    }
                }
                None => state.trace.push(TraceEvent::Dropped(pending.meta)),
            }
        }
    }

    fn detach(&self, node: Key) {
        let mut state = self.lock();
        if let Some(slot) = state.nodes.get_mut(&node) {
            slot.online = false;
        }
        state.trace.push(TraceEvent::Online {
            node,
            online: false,
        });
        Self::close_all_locked(&mut state, node, ConnectionCloseReason::PeerShutdown);
    }
}

/// One node's view of the fabric; the `Sim` arm of
/// [`super::link::LinkNode`].
pub(crate) struct SimLink {
    fabric: Arc<SimFabric>,
    me: PeerId,
    inbound: tokio::sync::Mutex<mpsc::UnboundedReceiver<(PeerId, u64, Vec<u8>)>>,
    accept: tokio::sync::Mutex<mpsc::UnboundedReceiver<PeerConnection>>,
    lifecycle: broadcast::Sender<(PeerId, PeerLifecycleEvent)>,
}

impl SimLink {
    pub(crate) fn peer_id(&self) -> PeerId {
        self.me
    }

    pub(crate) async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        // A virtual handshake round trip.
        tokio::time::sleep(self.fabric.base_latency * 2).await;
        self.fabric.connect(self.me.0, addr)
    }

    pub(crate) async fn connect_peer_with_addrs(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, NodeError> {
        let mut last = not_connected(&peer_id);
        for addr in addrs {
            match self.connect_addr(addr).await {
                Ok(conn) if conn.peer_id == peer_id => return Ok(conn),
                Ok(_) => last = NodeError::Connection("sim: peer id mismatch".into()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub(crate) async fn connect_peer(&self, peer_id: PeerId) -> Result<PeerConnection, NodeError> {
        let addr = self
            .fabric
            .lock()
            .nodes
            .get(&peer_id.0)
            .map(|slot| slot.addr)
            .ok_or_else(|| not_connected(&peer_id))?;
        self.connect_peer_with_addrs(peer_id, vec![addr]).await
    }

    pub(crate) fn upsert_peer_hints(&self, _peer_id: PeerId, _addrs: Vec<SocketAddr>) {}

    pub(crate) fn connection_health(&self, peer_id: &PeerId) -> ant_quic::ConnectionHealth {
        let generation = self.current_connection_generation(peer_id);
        ant_quic::ConnectionHealth {
            connected: generation.is_some(),
            generation,
            ..ant_quic::ConnectionHealth::default()
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        self.fabric
            .lock()
            .nodes
            .get(&self.me.0)
            .is_some_and(|slot| slot.online)
    }

    pub(crate) async fn accept(&self) -> Option<PeerConnection> {
        self.accept.lock().await.recv().await
    }

    pub(crate) fn disconnect(&self, peer_id: &PeerId) -> Result<(), NodeError> {
        let mut state = self.fabric.lock();
        SimFabric::close_link_locked(
            &mut state,
            pair(self.me.0, peer_id.0),
            ConnectionCloseReason::LifecycleCleanup,
        );
        Ok(())
    }

    pub(crate) fn connected_peers(&self) -> Vec<PeerConnection> {
        let state = self.fabric.lock();
        state
            .links
            .iter()
            .filter_map(|((a, b), link)| {
                let other = if *a == self.me.0 {
                    *b
                } else if *b == self.me.0 {
                    *a
                } else {
                    return None;
                };
                Some(
                    self.fabric
                        .peer_connection(&state, other, link.generation, Side::Client),
                )
            })
            .collect()
    }

    pub(crate) fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.current_connection_generation(peer_id).is_some()
    }

    pub(crate) fn subscribe_all_peer_events(
        &self,
    ) -> broadcast::Receiver<(PeerId, PeerLifecycleEvent)> {
        self.lifecycle.subscribe()
    }

    pub(crate) fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.fabric
            .enqueue(self.me.0, peer_id.0, None, data.to_vec(), None)
    }

    pub(crate) fn send_on_generation_with_admission<B, F>(
        &self,
        peer_id: &PeerId,
        generation: u64,
        admit: F,
    ) -> Result<(), NodeError>
    where
        B: AsRef<[u8]> + Send,
        F: FnOnce(u64) -> Result<B, EndpointError> + Send,
    {
        if self.current_connection_generation(peer_id) != Some(generation) {
            return Err(NodeError::Connection("sim: generation superseded".into()));
        }
        let bytes = admit(generation).map_err(NodeError::Endpoint)?;
        self.fabric.enqueue(
            self.me.0,
            peer_id.0,
            Some(generation),
            bytes.as_ref().to_vec(),
            None,
        )
    }

    pub(crate) async fn send_with_receive_ack(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), NodeError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.fabric
            .enqueue(self.me.0, peer_id.0, None, data.to_vec(), Some(ack_tx))?;
        match tokio::time::timeout(timeout, ack_rx).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(NodeError::Connection("sim: frame lost".into())),
            Err(_) => Err(NodeError::Connection("sim: receive-ack timeout".into())),
        }
    }

    pub(crate) fn probe_peer(&self, peer_id: &PeerId) -> Result<Duration, NodeError> {
        if self.is_connected(peer_id) {
            Ok(self.fabric.base_latency * 2)
        } else {
            Err(not_connected(peer_id))
        }
    }

    pub(crate) async fn recv_with_generation(&self) -> Result<(PeerId, u64, Vec<u8>), NodeError> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(NodeError::ShuttingDown)
    }

    pub(crate) fn current_connection_generation(&self, peer: &PeerId) -> Option<u64> {
        self.fabric
            .lock()
            .links
            .get(&pair(self.me.0, peer.0))
            .map(|link| link.generation)
    }

    pub(crate) fn shutdown(&self) {
        self.fabric.detach(self.me.0);
    }
}

type Registry = Mutex<Vec<(String, Weak<SimFabric>)>>;

fn registry() -> &'static Registry {
    static FABRICS: OnceLock<Registry> = OnceLock::new();
    FABRICS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Make `fabric` the network for every node built with
/// `NetworkConfig { network_id: Some(plane), bind_addr: Some(addr), .. }`.
pub(crate) fn register(plane: &str, fabric: &Arc<SimFabric>) {
    let mut fabrics = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fabrics.retain(|(_, weak)| weak.strong_count() > 0);
    fabrics.push((plane.to_string(), Arc::downgrade(fabric)));
}

/// Called by `NetworkNode::new` in test builds: a node whose plane has a
/// registered fabric runs on that fabric instead of binding a socket.
pub(crate) fn claim(config: &super::NetworkConfig, peer: PeerId) -> Option<Arc<SimLink>> {
    let plane = config.network_id.as_deref()?;
    let addr = config.bind_addr?;
    let fabric = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(name, _)| name == plane)
        .and_then(|(_, weak)| weak.upgrade())?;
    Some(fabric.attach(peer, addr))
}

#[cfg(test)]
mod spike_tests {
    //! Phase-1 feasibility spike (compile-only on macOS; run in CI from
    //! W3-H slice S1). Two full `Agent`s — gossip runtime, plane hello,
    //! receive pump — on one paused current-thread runtime, over the fabric.
    use super::*;
    use crate::network::NetworkConfig;
    use crate::Agent;

    fn sim_config(plane: &str, last_octet: u8, bootstrap: Vec<SocketAddr>) -> NetworkConfig {
        NetworkConfig {
            bind_addr: Some(SocketAddr::from(([198, 18, 0, last_octet], 5483))),
            bootstrap_nodes: bootstrap,
            network_id: Some(plane.to_string()),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..NetworkConfig::default()
        }
    }

    async fn sim_agent(
        dir: &std::path::Path,
        config: NetworkConfig,
    ) -> crate::error::Result<Agent> {
        Agent::builder()
            .with_machine_key(dir.join("machine.key"))
            .with_agent_key(crate::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(dir.join("agent.cert"))
            .with_user_key_path(dir.join("absent-user.key"))
            .with_contact_store_path(dir.join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(config)
            .build()
            .await
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[ignore = "W3-H phase-1 spike: compile-only on macOS; enabled in CI by slice S1"]
    async fn w3h_spike_two_agents_publish_over_sim_fabric() -> anyhow::Result<()> {
        let plane = "w3h-spike";
        let fabric = SimFabric::new(0x1164);
        register(plane, &fabric);
        let a_dir = tempfile::tempdir()?;
        let b_dir = tempfile::tempdir()?;
        let a_addr = SocketAddr::from(([198, 18, 0, 1], 5483));
        let a = sim_agent(a_dir.path(), sim_config(plane, 1, Vec::new())).await?;
        let b = sim_agent(b_dir.path(), sim_config(plane, 2, vec![a_addr])).await?;
        a.join_network().await?;
        b.join_network().await?;

        let mut sub = a.subscribe("w3h/spike").await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        b.publish("w3h/spike", b"hello".to_vec()).await?;
        let got = tokio::time::timeout(Duration::from_secs(30), sub.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("subscription closed"))?;
        assert_eq!(got.payload.as_ref(), b"hello");

        // Seeded per-frame faults: delay then drop B's pub-sub frames to A.
        let b_peer = b
            .network()
            .ok_or_else(|| anyhow::anyhow!("sim network"))?
            .peer_id();
        let delayed_src = b_peer.0;
        fabric.add_rule(move |meta, _bytes| {
            if meta.src == delayed_src && meta.link_seq % 7 == 3 {
                Fault::Delay(Duration::from_millis(250))
            } else {
                Fault::Pass
            }
        });
        fabric.add_rule(|meta, bytes| {
            if meta.len > 64 * 1024 && bytes.first() == Some(&0) {
                Fault::Drop
            } else {
                Fault::Pass
            }
        });

        // Fault injection: take A offline; B's next publish must not arrive.
        let a_peer = a
            .network()
            .ok_or_else(|| anyhow::anyhow!("sim network"))?
            .peer_id();
        fabric.set_online(&a_peer, false);
        b.publish("w3h/spike", b"lost".to_vec()).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(30), sub.recv())
                .await
                .is_err(),
            "an offline node receives nothing"
        );
        fabric.set_partitioned(&a_peer, &b_peer, true);
        fabric.set_partitioned(&a_peer, &b_peer, false);
        let digest = fabric.trace_digest();
        assert_ne!(digest, 0);
        a.shutdown().await;
        b.shutdown().await;
        Ok(())
    }
}

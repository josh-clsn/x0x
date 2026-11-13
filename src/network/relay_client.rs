//! R-3: make this node's own MASQUE relay sessions visible.
//!
//! When ant-quic sees two different external ports for this node it treats
//! the path as a symmetric NAT and, on its own, opens a MASQUE relay session
//! through one of its known peers or bootstrap seeds
//! (`P2pEndpoint::spawn_proactive_relay_manager`). Stock ant-quic 0.27.61
//! gives x0x no switch for it. The session's own connection is not a peer
//! connection, so it shows in no per-peer transport row either.
//!
//! What x0x can see is ant-quic's `P2pEvent::RelayEstablished`. This counter
//! records each one, and whether the mesh-off latch held when it came, for
//! `GET /diagnostics/connectivity`.
//!
//! With the carried ant-quic patch (`set_proactive_relay_allowed`,
//! `relay_client_stats`), the latch now switches proactive relay off and
//! closes any client session (`NetworkNode::sync_proactive_relay`), and the
//! snapshot adds the switch, the sessions held and their stream bytes.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ant_quic::P2pEvent;

/// Relay sessions this node opened as a client.
#[derive(Debug, Default)]
pub(crate) struct RelayClientCounters {
    established: AtomicU64,
    established_while_quiesced: AtomicU64,
    events_lagged: AtomicU64,
    last: Mutex<Option<(SocketAddr, Instant)>>,
}

/// What the ant-quic endpoint reports about its relay switches and client
/// sessions.
#[derive(Debug, Clone)]
pub(crate) struct TransportRelay {
    pub(crate) proactive_relay_allowed: bool,
    pub(crate) relay_fallback_allowed: bool,
    pub(crate) relay_service_allowed: bool,
    pub(crate) known_peer_introducers_allowed: bool,
    pub(crate) coordinator_policy: ant_quic::CoordinatorPolicy,
    pub(crate) stats: ant_quic::RelayClientStats,
    pub(crate) introducers: ant_quic::IntroducerStats,
}

/// Serialized relay-client snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct RelayClientSnapshot {
    /// Relay sessions ant-quic opened for this node since start.
    pub sessions_established: u64,
    /// Of those, the sessions whose `RelayEstablished` arrived while the
    /// mesh-off latch held. This does not cover everything a latched node
    /// should not do: a session opened just before the latch and still up
    /// under it is not counted here, the latch is read when the setup has
    /// finished (not when it began), and failed setups, which still send
    /// traffic to each seed tried, are not counted at all. Compare
    /// `last_established_ago_ms` with the latch time too.
    pub established_while_quiesced: u64,
    /// Endpoint event batches this observer missed because its channel
    /// lagged. Non-zero means the counts above may be low.
    pub events_lagged: u64,
    /// Whether ant-quic may hold a proactive relay session now (false while
    /// the mesh-off latch holds). `None` without a QUIC endpoint.
    pub proactive_relay_allowed: Option<bool>,
    /// Whether a connect may fall back to a relay now (false while latched).
    pub relay_fallback_allowed: Option<bool>,
    /// Whether this node serves others now: MASQUE relay sessions and
    /// hole-punch coordination (false while latched, bursts included).
    pub relay_service_allowed: Option<bool>,
    /// Which hole-punch coordinators ant-quic may use now: `any` (meshed),
    /// `connected_only` (latched, at rest: nothing is dialled to
    /// coordinate) or `introducer` (latched, during a burst dial: one
    /// introducer per target per burst, closed once the punch resolves).
    pub coordinator_policy: Option<String>,
    /// Hole-punch introducer connections dialled since start.
    pub introducer_dials: u64,
    /// Of those, dials to a seed: a known peer taken because the target
    /// announced no introducer of its own (M-3). The seed learns this
    /// node's address and whom it is calling.
    pub introducer_seed_dials: u64,
    /// Introducer dials in the last 24 hours (each stamped when a sample
    /// first saw it: at the end of a burst dial, at a latch call or at a
    /// read of this snapshot).
    pub introducer_dials_24h: u64,
    /// Of those, dials to a seed.
    pub introducer_seed_dials_24h: u64,
    /// Whether ant-quic may take a seed as an introducer now: false while
    /// latched when `latched_seed_introducers` is off.
    pub seed_introducers_allowed: Option<bool>,
    /// The daemon setting `latched_seed_introducers`: whether a latched
    /// burst dial may fall back to a seed as its introducer.
    pub latched_seed_introducers: bool,
    /// UDP bytes sent on introducer connections, counted as each closed.
    pub introducer_bytes_sent: u64,
    /// UDP bytes received on introducer connections, counted as each
    /// closed.
    pub introducer_bytes_received: u64,
    /// Client relay sessions open now, of any kind (proactive or opened by
    /// a relay fallback dial).
    pub active_sessions: usize,
    /// The relay server of each open session (those `active_sessions`
    /// counts).
    pub relay_servers: Vec<String>,
    /// Bytes written to relay streams since start, closed sessions
    /// included (frame bytes; QUIC overhead on the relay connection is not
    /// counted). When a session reuses the node's existing connection to the
    /// relay, these bytes are also inside that peer's `per_peer_transport`
    /// row: do not add the two.
    pub bytes_sent: u64,
    /// Bytes read from relay streams since start, counted the same way.
    pub bytes_received: u64,
    /// The public address the latest session gave this node.
    pub last_relay_addr: Option<String>,
    /// How long ago the latest session was opened.
    pub last_established_ago_ms: Option<u64>,
}

impl RelayClientCounters {
    fn observe(&self, event: &P2pEvent, quiesced: bool) {
        let P2pEvent::RelayEstablished { relay_addr } = event else {
            return;
        };
        self.established.fetch_add(1, Ordering::Relaxed);
        if quiesced {
            self.established_while_quiesced
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "x0x::connect",
                %relay_addr,
                "ant-quic opened a proactive relay session while the mesh is quiesced"
            );
        }
        match self.last.lock() {
            Ok(mut last) => *last = Some((*relay_addr, Instant::now())),
            Err(poisoned) => *poisoned.into_inner() = Some((*relay_addr, Instant::now())),
        }
    }

    fn note_lag(&self, skipped: u64) {
        self.events_lagged.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(skipped, "relay-client observer lagged");
    }

    /// Spawn the observer over the endpoint's events. It exits when the
    /// stream closes (endpoint shutdown); lag is counted.
    pub(crate) fn spawn_observer(
        self: Arc<Self>,
        node: &ant_quic::Node,
        quiesced: Arc<AtomicBool>,
    ) {
        let mut rx = node.inner_endpoint().subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => self.observe(&event, quiesced.load(Ordering::Relaxed)),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        self.note_lag(skipped);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    /// Snapshot for `GET /diagnostics/connectivity` → `relay_client`, with
    /// the endpoint's switch and session stats when there is one.
    #[must_use]
    pub(crate) fn snapshot(
        &self,
        transport: Option<TransportRelay>,
        day: super::introducer_day::IntroducerDayCounts,
        latched_seed_introducers: bool,
    ) -> RelayClientSnapshot {
        let switches = transport.as_ref().map(|t| {
            (
                t.proactive_relay_allowed,
                t.relay_fallback_allowed,
                t.relay_service_allowed,
                t.known_peer_introducers_allowed,
                match t.coordinator_policy {
                    ant_quic::CoordinatorPolicy::Any => "any",
                    ant_quic::CoordinatorPolicy::ConnectedOnly => "connected_only",
                    ant_quic::CoordinatorPolicy::Introducer => "introducer",
                },
            )
        });
        let introducers = transport
            .as_ref()
            .map(|t| t.introducers)
            .unwrap_or_default();
        let stats = transport.map(|t| t.stats).unwrap_or_default();
        let last = match self.last.lock() {
            Ok(last) => *last,
            Err(poisoned) => *poisoned.into_inner(),
        };
        RelayClientSnapshot {
            sessions_established: self.established.load(Ordering::Relaxed),
            established_while_quiesced: self.established_while_quiesced.load(Ordering::Relaxed),
            events_lagged: self.events_lagged.load(Ordering::Relaxed),
            proactive_relay_allowed: switches.map(|s| s.0),
            relay_fallback_allowed: switches.map(|s| s.1),
            relay_service_allowed: switches.map(|s| s.2),
            coordinator_policy: switches.map(|s| s.4.to_string()),
            introducer_dials: introducers.dials,
            introducer_seed_dials: introducers.known_peer_dials,
            introducer_dials_24h: day.dials,
            introducer_seed_dials_24h: day.seed_dials,
            seed_introducers_allowed: switches.map(|s| s.3),
            latched_seed_introducers,
            introducer_bytes_sent: introducers.bytes_sent,
            introducer_bytes_received: introducers.bytes_received,
            active_sessions: stats.active_sessions,
            relay_servers: stats
                .relay_servers
                .iter()
                .map(ToString::to_string)
                .collect(),
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            last_relay_addr: last.map(|(addr, _)| addr.to_string()),
            last_established_ago_ms: last
                .map(|(_, at)| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(port: u16) -> P2pEvent {
        P2pEvent::RelayEstablished {
            relay_addr: SocketAddr::from(([203, 0, 113, 7], port)),
        }
    }

    #[test]
    fn nothing_recorded_before_a_session() {
        assert_eq!(
            RelayClientCounters::default().snapshot(None, Default::default(), false),
            RelayClientSnapshot::default()
        );
    }

    #[test]
    fn a_session_is_counted_and_one_under_the_latch_is_flagged() {
        let counters = RelayClientCounters::default();
        counters.observe(&relay(4000), false);
        counters.observe(&relay(4001), true);
        let snap = counters.snapshot(None, Default::default(), false);
        assert_eq!(snap.sessions_established, 2);
        assert_eq!(snap.established_while_quiesced, 1);
        assert_eq!(snap.last_relay_addr.as_deref(), Some("203.0.113.7:4001"));
        assert!(snap.last_established_ago_ms.is_some());
    }

    #[test]
    fn a_lag_is_counted() {
        let counters = RelayClientCounters::default();
        counters.note_lag(12);
        assert_eq!(
            counters
                .snapshot(None, Default::default(), false)
                .events_lagged,
            1
        );
    }

    #[test]
    fn other_events_are_ignored() {
        let counters = RelayClientCounters::default();
        counters.observe(
            &P2pEvent::ExternalAddressDiscovered {
                addr: ant_quic::TransportAddr::Udp(SocketAddr::from(([203, 0, 113, 7], 1))),
            },
            true,
        );
        assert_eq!(
            counters.snapshot(None, Default::default(), false),
            RelayClientSnapshot::default()
        );
    }
}

//! R-3: make this node's own MASQUE relay sessions visible.
//!
//! When ant-quic sees two different external ports for this node it treats
//! the path as a symmetric NAT and, on its own, opens a MASQUE relay session
//! through one of its known peers or bootstrap seeds
//! (`P2pEndpoint::spawn_proactive_relay_manager`). x0x cannot gate that from
//! its configuration: the manager is switched only by ant-quic's static
//! `NatConfig::enable_relay_fallback`, which `NodeConfig` does not expose.
//! The session's own connection is not a peer connection, so it shows in no
//! per-peer transport row either.
//!
//! What x0x can see is ant-quic's `P2pEvent::RelayEstablished`. This counter
//! records each one, and whether the mesh-off latch held when it came, for
//! `GET /diagnostics/connectivity`.

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

    /// Snapshot for `GET /diagnostics/connectivity` → `relay_client`.
    #[must_use]
    pub(crate) fn snapshot(&self) -> RelayClientSnapshot {
        let last = match self.last.lock() {
            Ok(last) => *last,
            Err(poisoned) => *poisoned.into_inner(),
        };
        RelayClientSnapshot {
            sessions_established: self.established.load(Ordering::Relaxed),
            established_while_quiesced: self.established_while_quiesced.load(Ordering::Relaxed),
            events_lagged: self.events_lagged.load(Ordering::Relaxed),
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
            RelayClientCounters::default().snapshot(),
            RelayClientSnapshot::default()
        );
    }

    #[test]
    fn a_session_is_counted_and_one_under_the_latch_is_flagged() {
        let counters = RelayClientCounters::default();
        counters.observe(&relay(4000), false);
        counters.observe(&relay(4001), true);
        let snap = counters.snapshot();
        assert_eq!(snap.sessions_established, 2);
        assert_eq!(snap.established_while_quiesced, 1);
        assert_eq!(snap.last_relay_addr.as_deref(), Some("203.0.113.7:4001"));
        assert!(snap.last_established_ago_ms.is_some());
    }

    #[test]
    fn a_lag_is_counted() {
        let counters = RelayClientCounters::default();
        counters.note_lag(12);
        assert_eq!(counters.snapshot().events_lagged, 1);
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
        assert_eq!(counters.snapshot(), RelayClientSnapshot::default());
    }
}

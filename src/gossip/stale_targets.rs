//! Keep non-connected peers out of gossip send-target sets (x0x#1036).
//!
//! Every x0x gossip send goes through ant-quic's `send`, which needs a live
//! connection: a send to a peer with none fails fast with `Peer not found`.
//! Two send-target sets were not bounded by the transport:
//!
//! - **HyParView active view.** saorsa-gossip adds peers to the active view
//!   from JOIN/FORWARDJOIN random walks — including peers several hops away
//!   that this node never connects to — and nothing prunes the view by
//!   transport connectivity. The view's peers are SWIM-probed (1 s period),
//!   shuffled and forwarded to for as long as they stay in it.
//! - **Presence broadcast set.** x0x seeded presence beacon and FOAF targets
//!   from `active_view() ∪ connected_peers()`, so every stale active-view
//!   entry also received a beacon every interval.
//!
//! On a relay node those stale entries produced thousands of fast-fail sends
//! per hour, each one a `WARN` line in ant-quic (x0x#1036).
//!
//! The fix keeps a short grace (a peer that disconnected between two
//! connected-peer snapshots is fine) but never lets a peer that has been
//! disconnected for [`STALE_SEND_TARGET_AFTER`] stay a target:
//! [`StaleTargetTracker`] prunes it from the HyParView active view and
//! restores it once it is connected again. Presence targets are filtered to
//! connected peers by [`presence_broadcast_targets`]. PlumTree topic planes
//! are already refreshed from the connected plane every second, so lazy/IHAVE
//! and anti-entropy repair reach a reconnecting peer as soon as it is
//! connected again; nothing here touches them.

use saorsa_gossip_membership::Membership;
use saorsa_gossip_types::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// A peer disconnected for at least this long stops being a send target.
pub(crate) const STALE_SEND_TARGET_AFTER: Duration = Duration::from_secs(60);

/// Upper bound on peers tracked as absent or pruned.
const MAX_TRACKED_PEERS: usize = 4096;

/// What one maintenance pass changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct StaleTargetPlan {
    /// Targets disconnected for at least the threshold; remove them.
    pub prune: Vec<PeerId>,
    /// Previously pruned peers that are connected again; restore them.
    pub restore: Vec<PeerId>,
}

/// Tracks how long each send target has been without a connection.
#[derive(Debug)]
pub(crate) struct StaleTargetTracker {
    threshold: Duration,
    /// First time a target was seen without a connection. Kept after the
    /// target is pruned, so a peer re-added by a random walk while still
    /// disconnected is pruned again on the next pass instead of getting a
    /// fresh grace period.
    absent_since: HashMap<PeerId, Instant>,
    /// Peers this tracker pruned, restored when they reconnect.
    pruned: HashSet<PeerId>,
}

impl Default for StaleTargetTracker {
    fn default() -> Self {
        Self::new(STALE_SEND_TARGET_AFTER)
    }
}

impl StaleTargetTracker {
    pub(crate) fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            absent_since: HashMap::new(),
            pruned: HashSet::new(),
        }
    }

    /// Compare the current `targets` with the `connected` snapshot at `now`.
    pub(crate) fn observe(
        &mut self,
        targets: &[PeerId],
        connected: &HashSet<PeerId>,
        now: Instant,
    ) -> StaleTargetPlan {
        let mut plan = StaleTargetPlan::default();

        // Connected peers are never stale; pruned ones come back.
        self.absent_since
            .retain(|peer, _| !connected.contains(peer));
        self.pruned.retain(|peer| {
            if connected.contains(peer) {
                plan.restore.push(*peer);
                false
            } else {
                true
            }
        });

        for peer in targets {
            if connected.contains(peer) {
                continue;
            }
            let since = *self.absent_since.entry(*peer).or_insert(now);
            if now.saturating_duration_since(since) >= self.threshold {
                plan.prune.push(*peer);
                self.pruned.insert(*peer);
            }
        }

        self.bound(targets);
        plan.prune.sort_unstable_by_key(|peer| *peer.as_bytes());
        plan.restore.sort_unstable_by_key(|peer| *peer.as_bytes());
        plan
    }

    fn bound(&mut self, targets: &[PeerId]) {
        if self.absent_since.len() > MAX_TRACKED_PEERS {
            let keep: HashSet<PeerId> = targets.iter().copied().collect();
            let pruned = &self.pruned;
            self.absent_since
                .retain(|peer, _| keep.contains(peer) || pruned.contains(peer));
            if self.absent_since.len() > MAX_TRACKED_PEERS {
                self.absent_since.clear();
            }
        }
        if self.pruned.len() > MAX_TRACKED_PEERS {
            // Losing a pruned mark only skips an explicit restore; PlumTree
            // and presence still target the peer once it is connected.
            self.pruned.clear();
        }
    }
}

/// Run one pass over the HyParView active view: remove targets disconnected
/// for at least the tracker's threshold and restore reconnected ones.
pub(crate) async fn maintain_active_view<M>(
    membership: &M,
    tracker: &mut StaleTargetTracker,
    connected: &HashSet<PeerId>,
    now: Instant,
) -> StaleTargetPlan
where
    M: Membership + ?Sized,
{
    let active = membership.active_view();
    let plan = tracker.observe(&active, connected, now);
    for peer in &plan.prune {
        if let Err(e) = membership.remove_active(*peer).await {
            tracing::debug!(peer = %peer, "x0x#1036: stale active-view prune failed: {e}");
        }
    }
    for peer in &plan.restore {
        if active.contains(peer) {
            continue;
        }
        if let Err(e) = membership.add_active(*peer).await {
            tracing::debug!(peer = %peer, "x0x#1036: active-view restore failed: {e}");
        }
    }
    if !plan.prune.is_empty() || !plan.restore.is_empty() {
        tracing::debug!(
            pruned = plan.prune.len(),
            restored = plan.restore.len(),
            "x0x#1036: HyParView active view reconciled with transport connectivity"
        );
    }
    plan
}

/// Presence beacon/FOAF targets: the HyParView active view and the transport
/// table, restricted to connected peers. A beacon to a peer with no
/// connection can only fail, so active-view entries without one are dropped.
pub(crate) fn presence_broadcast_targets(
    active_view: Vec<PeerId>,
    connected: &[PeerId],
) -> Vec<PeerId> {
    let connected_set: HashSet<PeerId> = connected.iter().copied().collect();
    let mut targets: Vec<PeerId> = active_view
        .into_iter()
        .filter(|peer| connected_set.contains(peer))
        .collect();
    targets.extend(connected.iter().copied());
    targets.sort_unstable_by_key(|peer| *peer.as_bytes());
    targets.dedup();
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn peer(byte: u8) -> PeerId {
        PeerId::new([byte; 32])
    }

    fn set(peers: &[PeerId]) -> HashSet<PeerId> {
        peers.iter().copied().collect()
    }

    /// Minimal `Membership` whose active view is a plain set.
    #[derive(Default)]
    struct FakeMembership {
        active: Mutex<HashSet<PeerId>>,
    }

    #[async_trait::async_trait]
    impl Membership for FakeMembership {
        async fn join(&self, _seeds: Vec<String>) -> anyhow::Result<()> {
            Ok(())
        }
        fn active_view(&self) -> Vec<PeerId> {
            let mut view: Vec<PeerId> = self.active.lock().expect("lock").iter().copied().collect();
            view.sort_unstable_by_key(|peer| *peer.as_bytes());
            view
        }
        fn passive_view(&self) -> Vec<PeerId> {
            Vec::new()
        }
        async fn add_active(&self, peer: PeerId) -> anyhow::Result<()> {
            self.active.lock().expect("lock").insert(peer);
            Ok(())
        }
        async fn remove_active(&self, peer: PeerId) -> anyhow::Result<()> {
            self.active.lock().expect("lock").remove(&peer);
            Ok(())
        }
        async fn promote(&self, peer: PeerId) -> anyhow::Result<()> {
            self.add_active(peer).await
        }
    }

    #[test]
    fn peer_disconnected_past_threshold_is_pruned_but_not_before() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let targets = [peer(1), peer(2)];
        let connected = set(&[peer(1)]);

        // Disconnected between snapshots: still inside the grace period.
        assert!(tracker.observe(&targets, &connected, t0).prune.is_empty());
        assert!(tracker
            .observe(&targets, &connected, t0 + Duration::from_secs(59))
            .prune
            .is_empty());
        // Missing for the whole threshold: stop targeting it.
        assert_eq!(
            tracker
                .observe(&targets, &connected, t0 + Duration::from_secs(60))
                .prune,
            vec![peer(2)]
        );
    }

    #[test]
    fn reconnect_resets_the_clock_and_restores_a_pruned_peer() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let none = HashSet::new();
        tracker.observe(&[peer(3)], &none, t0);
        assert_eq!(
            tracker
                .observe(&[peer(3)], &none, t0 + Duration::from_secs(61))
                .prune,
            vec![peer(3)]
        );

        let plan = tracker.observe(&[], &set(&[peer(3)]), t0 + Duration::from_secs(70));
        assert_eq!(plan.restore, vec![peer(3)]);
        assert!(plan.prune.is_empty());

        // A later disconnect starts a fresh grace period.
        let t1 = t0 + Duration::from_secs(80);
        assert!(tracker.observe(&[peer(3)], &none, t1).prune.is_empty());
        assert!(tracker
            .observe(&[peer(3)], &none, t1 + Duration::from_secs(30))
            .prune
            .is_empty());
    }

    #[test]
    fn re_added_disconnected_peer_gets_no_fresh_grace() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let none = HashSet::new();
        tracker.observe(&[peer(4)], &none, t0);
        assert_eq!(
            tracker
                .observe(&[peer(4)], &none, t0 + Duration::from_secs(60))
                .prune,
            vec![peer(4)]
        );
        // Pruned, absent from the view for a pass, then re-added by a random
        // walk while still disconnected: pruned again immediately.
        tracker.observe(&[], &none, t0 + Duration::from_secs(75));
        assert_eq!(
            tracker
                .observe(&[peer(4)], &none, t0 + Duration::from_secs(90))
                .prune,
            vec![peer(4)]
        );
    }

    /// x0x#1036 wiring: a peer disconnected longer than the threshold leaves
    /// the HyParView active view (so SWIM, shuffle and presence stop
    /// targeting it) and comes back when it reconnects.
    #[tokio::test]
    async fn active_view_drops_stale_peer_and_restores_it_on_reconnect() {
        let membership = FakeMembership::default();
        for byte in [1, 2] {
            membership.add_active(peer(byte)).await.expect("add");
        }
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let only_1 = set(&[peer(1)]);

        maintain_active_view(&membership, &mut tracker, &only_1, t0).await;
        assert_eq!(membership.active_view(), vec![peer(1), peer(2)]);

        maintain_active_view(
            &membership,
            &mut tracker,
            &only_1,
            t0 + Duration::from_secs(61),
        )
        .await;
        assert_eq!(
            membership.active_view(),
            vec![peer(1)],
            "stale peer must stop being a send target"
        );

        let both = set(&[peer(1), peer(2)]);
        maintain_active_view(
            &membership,
            &mut tracker,
            &both,
            t0 + Duration::from_secs(90),
        )
        .await;
        assert_eq!(
            membership.active_view(),
            vec![peer(1), peer(2)],
            "reconnected peer must be targeted again"
        );
    }

    #[test]
    fn presence_targets_exclude_non_connected_active_view_peers() {
        let targets =
            presence_broadcast_targets(vec![peer(1), peer(2), peer(9)], &[peer(1), peer(3)]);
        assert_eq!(targets, vec![peer(1), peer(3)]);

        // Reconnected: targeted again.
        let targets = presence_broadcast_targets(vec![peer(9)], &[peer(9)]);
        assert_eq!(targets, vec![peer(9)]);
    }

    /// x0x#1036 W2 row (a): a pool-tombstoned peer is a disconnected peer.
    ///
    /// `disconnect_pool_candidates` (LRU/idle pool eviction) records a
    /// `PoolEviction` reconnect-suppression tombstone and then closes the
    /// connection, so the peer leaves ant-quic's `connected_peers()` — the
    /// `send_ready_peers()` snapshot the keepalive pass feeds this tracker —
    /// and the tombstone stops proactive redial from bringing it back.
    /// HyParView knows nothing of the pool and keeps the peer in the active
    /// view, so without pruning SWIM, shuffle and presence would keep
    /// sending to it ("Peer not found") for the tombstone's lifetime.
    ///
    /// Pinned: the absence clock starts at the first pass after the close
    /// (not while the tombstone is live but the connection is still open),
    /// the peer is pruned once it has been absent for the threshold, it is
    /// not restored while it stays evicted, and a random walk that re-adds
    /// it while still evicted does not buy it a fresh grace period.
    #[tokio::test]
    async fn pool_tombstoned_peer_is_pruned_after_threshold() {
        let membership = FakeMembership::default();
        let (kept, evicted) = (peer(10), peer(11));
        for p in [kept, evicted] {
            membership.add_active(p).await.expect("add");
        }
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();

        // Tombstone set, close still in flight: ant-quic still reports the
        // connection, so the peer is connected for send-target purposes.
        let both = set(&[kept, evicted]);
        maintain_active_view(&membership, &mut tracker, &both, t0).await;

        // Closed by the pool: gone from the send-ready snapshot.
        let only_kept = set(&[kept]);
        let t_close = t0 + Duration::from_secs(15);
        let plan = maintain_active_view(&membership, &mut tracker, &only_kept, t_close).await;
        assert!(plan.prune.is_empty(), "grace starts at the close");
        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(59),
        )
        .await;
        assert!(plan.prune.is_empty(), "still inside the grace period");

        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(60),
        )
        .await;
        assert_eq!(plan.prune, vec![evicted]);
        assert_eq!(
            membership.active_view(),
            vec![kept],
            "a pool-evicted peer must stop being a send target"
        );

        // Still evicted: not restored, and a random-walk re-add is pruned on
        // the very next pass.
        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(75),
        )
        .await;
        assert!(plan.restore.is_empty(), "no restore while evicted");
        membership.add_active(evicted).await.expect("re-add");
        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(90),
        )
        .await;
        assert_eq!(plan.prune, vec![evicted]);
        assert_eq!(membership.active_view(), vec![kept]);
    }

    /// x0x#1036 W2 row (b): a plane-pending peer counts as connected.
    ///
    /// `PeerAdmission::PlanePending` means ant-quic holds a live connection
    /// but the issue #206 plane hello has not resolved yet (at most
    /// `PLANE_LEGACY_GRACE`, 10 s). The keepalive pass feeds this tracker
    /// `NetworkNode::send_ready_peers()`, which is ant-quic's
    /// `connected_peers()` with no admission filter, so a plane-pending peer
    /// is in the snapshot exactly like an admitted one. That is the intended
    /// semantics: this tracker bounds send targets by *transport*
    /// connectivity, because only a send with no connection fails with
    /// "Peer not found". Gossip admission is enforced elsewhere
    /// (`gossip_plane_peers`, `peer_admission`) and is not this tracker's job.
    ///
    /// Pinned, in consequence: a pruned peer that reconnects is restored even
    /// while plane-pending, and being seen plane-pending restarts the absence
    /// clock. If the plane is then refused, the peer is disconnected with a
    /// `PolicyRejection` tombstone and is pruned one full threshold after
    /// that disconnect: never earlier, and never left in the view for good.
    #[test]
    fn plane_pending_peer_counts_as_connected() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let p = peer(20);
        let none = HashSet::new();
        // Seen only as plane-pending: in the send-ready snapshot.
        let plane_pending = set(&[p]);

        tracker.observe(&[p], &none, t0);
        assert_eq!(
            tracker
                .observe(&[p], &none, t0 + Duration::from_secs(60))
                .prune,
            vec![p]
        );

        // Reconnects; the plane hello is still in flight.
        let plan = tracker.observe(&[], &plane_pending, t0 + Duration::from_secs(70));
        assert_eq!(plan.restore, vec![p], "restored while plane-pending");

        // Absent 50 s, seen plane-pending once, then refused and dropped.
        let t1 = t0 + Duration::from_secs(100);
        tracker.observe(&[p], &none, t1);
        tracker.observe(&[p], &plane_pending, t1 + Duration::from_secs(50));
        let refused_at = t1 + Duration::from_secs(55);
        assert!(tracker.observe(&[p], &none, refused_at).prune.is_empty());
        assert!(
            tracker
                .observe(&[p], &none, refused_at + Duration::from_secs(59))
                .prune
                .is_empty(),
            "the plane-pending sighting restarted the absence clock"
        );
        assert_eq!(
            tracker
                .observe(&[p], &none, refused_at + Duration::from_secs(60))
                .prune,
            vec![p]
        );
    }

    /// x0x#1036 W2 row (c): presence targeting and active-view pruning agree.
    ///
    /// Presence targets come from `NetworkNode::connected_peers()`; pruning
    /// comes from `NetworkNode::send_ready_peers()`. Both are ant-quic
    /// `Node::connected_peers()` projected to peer ids, with no further
    /// filter, so over one connectivity snapshot they are the same set. This
    /// test drives both off one snapshot and pins the invariant: a pruned
    /// peer is never a presence target, a presence target is never pruned,
    /// and pruning never removes a presence target (presence computed from
    /// the pruned view equals presence computed from the unpruned view).
    #[tokio::test]
    async fn presence_targets_and_pruning_agree() {
        let membership = FakeMembership::default();
        let (up, flapped, long_gone, transport_only) = (peer(30), peer(31), peer(32), peer(33));
        for p in [up, flapped, long_gone] {
            membership.add_active(p).await.expect("add");
        }
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();

        maintain_active_view(&membership, &mut tracker, &set(&[up, flapped]), t0).await;
        maintain_active_view(
            &membership,
            &mut tracker,
            &set(&[up]),
            t0 + Duration::from_secs(30),
        )
        .await;

        // One snapshot for both consumers.
        let snapshot = vec![up, transport_only];
        let now = t0 + Duration::from_secs(60);
        let view_before = membership.active_view();
        let presence_before = presence_broadcast_targets(view_before.clone(), &snapshot);
        let plan = maintain_active_view(&membership, &mut tracker, &set(&snapshot), now).await;
        let presence_after = presence_broadcast_targets(membership.active_view(), &snapshot);

        assert_eq!(plan.prune, vec![long_gone], "only the 60 s-absent peer");
        for pruned in &plan.prune {
            assert!(
                !presence_before.contains(pruned),
                "a pruned peer must not be a presence target"
            );
        }
        for target in &presence_before {
            assert!(
                !plan.prune.contains(target),
                "a presence target must not be pruned"
            );
        }
        assert_eq!(
            presence_before, presence_after,
            "pruning must not change the presence target set"
        );
        assert_eq!(presence_after, vec![up, transport_only]);
        assert!(
            !presence_after.contains(&flapped),
            "inside its grace a disconnected peer stays in the view but gets no beacon"
        );
    }
}

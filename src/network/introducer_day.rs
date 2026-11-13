//! M-3: how many hole-punch introducers a latched node dialled in the last
//! day, and how many of them were a seed.
//!
//! In a burst a target that needs a hole punch may use one introducer: one
//! it named for itself, or, failing that, a known peer (a bootstrap seed).
//! A seed so used learns this node's address and whom it is calling. ant-quic
//! counts both kinds since start (`IntroducerStats::dials` and
//! `known_peer_dials`); this window turns the counts into the last 24 hours
//! for `GET /diagnostics/connectivity`.
//!
//! The window is fed by sampling ant-quic's totals (at the end of every
//! burst dial, at every latch call and at every diagnostics read). A dial is
//! stamped when a sample first sees it, which is at most one burst dial late.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// How far back the counts reach.
pub(crate) const INTRODUCER_DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Bound on the dials remembered. Bursts cap introducers at one per target,
/// so a real day stays far below this.
const MAX_REMEMBERED_DIALS: usize = 4096;

/// Introducer dials in the last [`INTRODUCER_DAY`].
#[derive(Debug, Default)]
pub(crate) struct IntroducerDay {
    /// ant-quic's totals at the last sample: (dials, known-peer dials).
    seen: (u64, u64),
    /// When each dial was first seen, and whether it went to a seed.
    dials: VecDeque<(Instant, bool)>,
}

/// The counts for the last day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IntroducerDayCounts {
    /// Introducer dials of any kind.
    pub(crate) dials: u64,
    /// Of those, dials to a seed (a known peer the target did not name).
    pub(crate) seed_dials: u64,
}

impl IntroducerDay {
    /// Take ant-quic's totals at `now`: dials since the last sample are
    /// stamped `now`. Totals that went down (a new endpoint) restart the
    /// baseline without counting.
    pub(crate) fn sample(&mut self, now: Instant, dials: u64, known_peer_dials: u64) {
        let (seen_dials, seen_known) = self.seen;
        if dials < seen_dials || known_peer_dials < seen_known {
            self.seen = (dials, known_peer_dials);
            return;
        }
        let new_known = known_peer_dials - seen_known;
        let new_dials = (dials - seen_dials).max(new_known);
        for index in 0..new_dials {
            self.dials.push_back((now, index < new_known));
        }
        while self.dials.len() > MAX_REMEMBERED_DIALS {
            self.dials.pop_front();
        }
        self.seen = (dials, known_peer_dials);
        self.prune(now);
    }

    /// The dials first seen within the last day before `now`.
    pub(crate) fn counts(&mut self, now: Instant) -> IntroducerDayCounts {
        self.prune(now);
        let seed_dials = self.dials.iter().filter(|(_, seed)| *seed).count();
        IntroducerDayCounts {
            dials: u64::try_from(self.dials.len()).unwrap_or(u64::MAX),
            seed_dials: u64::try_from(seed_dials).unwrap_or(u64::MAX),
        }
    }

    fn prune(&mut self, now: Instant) {
        while self
            .dials
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= INTRODUCER_DAY)
        {
            self.dials.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_before_a_dial() {
        let mut day = IntroducerDay::default();
        let now = Instant::now();
        day.sample(now, 0, 0);
        assert_eq!(day.counts(now), IntroducerDayCounts::default());
    }

    #[test]
    fn dials_are_counted_once_and_seeds_apart() {
        let mut day = IntroducerDay::default();
        let start = Instant::now();
        day.sample(start, 2, 1);
        day.sample(start + Duration::from_secs(5), 2, 1);
        assert_eq!(
            day.counts(start + Duration::from_secs(5)),
            IntroducerDayCounts {
                dials: 2,
                seed_dials: 1
            }
        );
        day.sample(start + Duration::from_secs(60), 3, 2);
        assert_eq!(
            day.counts(start + Duration::from_secs(60)),
            IntroducerDayCounts {
                dials: 3,
                seed_dials: 2
            }
        );
    }

    #[test]
    fn a_dial_leaves_the_window_after_a_day() {
        let mut day = IntroducerDay::default();
        let start = Instant::now();
        day.sample(start, 1, 1);
        day.sample(start + Duration::from_secs(3600), 2, 1);
        let later = start + INTRODUCER_DAY;
        assert_eq!(
            day.counts(later),
            IntroducerDayCounts {
                dials: 1,
                seed_dials: 0
            },
            "the first dial is a day old; the second is not"
        );
        assert_eq!(
            day.counts(later + Duration::from_secs(3600)),
            IntroducerDayCounts::default()
        );
    }

    #[test]
    fn totals_that_go_down_restart_the_baseline() {
        let mut day = IntroducerDay::default();
        let start = Instant::now();
        day.sample(start, 5, 2);
        day.sample(start + Duration::from_secs(1), 1, 0);
        day.sample(start + Duration::from_secs(2), 2, 1);
        assert_eq!(
            day.counts(start + Duration::from_secs(2)),
            IntroducerDayCounts {
                dials: 6,
                seed_dials: 3
            }
        );
    }

    #[test]
    fn the_window_is_bounded() {
        let mut day = IntroducerDay::default();
        let now = Instant::now();
        day.sample(now, 10_000, 0);
        assert_eq!(day.counts(now).dials, 4096);
    }
}

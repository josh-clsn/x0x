//! Survivor re-key A8: the presence facts `GET /groups/:id/treekem/catch-up`
//! reports. They decide whether a confirmation that a room is up to date may
//! stay in connected mode, where it does not age (design 3.3). A missed
//! suspend would let a stale device seal at an old key, so every doubt here
//! reads as "suspended" and "not connected".
//!
//! # The run
//!
//! `run_id` is 128 random bits drawn when the daemon starts, so it differs
//! on every run. `started_at_ms` is the wall clock at the start, kept for
//! display: a wall clock can step back, so two runs can share it, and only
//! `run_id` (which every presence mark carries) tells a restart.
//!
//! # The clocks
//!
//! A sample is a pair: `boottime` (B), which keeps counting while the
//! machine is suspended, and `monotonic` (M), which stops. Between two
//! samples the daemon was suspended or frozen ([`suspended_since`]) when
//! B - M moved by more than [`SUSPEND_GROWTH_MS`], or more than
//! [`FREEZE_GAP_MS`] of M passed, or either clock went backwards. The wall
//! clock is never read for this, so stepping it neither hides a suspend nor
//! fakes one.
//!
//! | Platform | Clocks read | Support |
//! |---|---|---|
//! | Linux, Android | `nix` `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC` | verified |
//! | macOS | none: Apple's sleep-inclusive pair is not yet verified on a Mac | TTL only |
//! | Windows and the rest | none: no safe suspend pair is verified | TTL only |
//!
//! On a TTL-only platform every read reports `suspended_since_last_get:
//! true` and no connected admins, so the engine stays in TTL mode.
//!
//! # "Since the last GET": the reader holds the reference point
//!
//! Every sample that sees a suspend or a freeze, or cannot read the clocks,
//! adds one to a count that never goes down. The samples form one chain
//! under one lock, each compared with the one before it, so a suspend
//! between any two samples is counted, whoever took them: the background
//! sampler or a GET.
//!
//! A GET samples the clocks and answers `presence_mark`,
//! `"<run_id>:<count>"`. The reader passes it back as `since_presence_mark`.
//! The next answer is `suspended_since_last_get: false` only when the
//! platform is verified, the mark names this run, and the count has not
//! moved since. No mark, another run's mark (a restart: a fresh daemon
//! cannot vouch for the time before it started) and an unreadable mark all
//! read `true`. The daemon keeps no per-reader or per-room state, so no
//! reader can consume a suspend another reader has not seen: two engines,
//! or two concurrent GETs, each see every suspend after their own mark. The
//! engine keeps one mark per room, with that room's anchor.
//!
//! # The sampler
//!
//! A freeze shows only as a gap in M between consecutive samples, so one
//! background task samples every [`SAMPLE_INTERVAL`] on a verified
//! platform. Every GET samples again, after it has read the links. If the
//! sampler stalls past [`FREEZE_GAP_MS`], the next sample reads as a freeze:
//! a stall holds, it never hides.
//!
//! # Connected admins
//!
//! An admin is connected when this daemon holds a live, authenticated QUIC
//! connection to the machine the admin's verified binding names (the
//! verified announcement or the authenticated binding, not the DM registry
//! or a card; see `Agent::presence_links`). A connection whose far end
//! vanished (a zombie) still reads as live until QUIC's idle timeout (30 s
//! in ant-quic 0.27.54) or a failed acknowledged send tears it down. Across
//! a suspend that timeout does not run, because QUIC times on M. So after
//! the latest sample that saw a suspend or a freeze, a link counts only if
//! it was made after that sample, or the peer delivered application data on
//! it after that sample. The residual is a far end that vanished while this
//! daemon stayed awake: it can count for up to the idle timeout (design
//! M-e, inside the partition residual).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::network::LinkLiveness;

/// B - M moved by more than this between two samples: a suspend.
pub(crate) const SUSPEND_GROWTH_MS: u64 = 5_000;
/// More than this much M between two samples: a freeze, or a stalled
/// sampler.
pub(crate) const FREEZE_GAP_MS: u64 = 15_000;
/// How often the background sampler samples.
pub(crate) const SAMPLE_INTERVAL: Duration = Duration::from_secs(3);

/// One reading of the two clocks, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockPair {
    /// Counts through a suspend.
    pub(crate) boottime_ms: u64,
    /// Stops during a suspend.
    pub(crate) monotonic_ms: u64,
}

/// Whether a platform has a verified suspend pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockSupport {
    /// The pair shows every suspend: connected mode is possible.
    Verified,
    /// No verified pair: every read says suspended (TTL mode only).
    TtlOnly,
}

/// The clocks presence reads. The system's in the daemon; a fake in tests.
pub(crate) trait PresenceClock: Send + Sync {
    /// Whether [`Self::pair`] is a verified suspend pair.
    fn support(&self) -> ClockSupport;
    /// The pair now, or `None` when it cannot be read.
    fn pair(&self) -> Option<ClockPair>;
    /// Unix milliseconds, for `started_at_ms` only.
    fn wall_ms(&self) -> u64;
}

/// The system clocks (see the module's platform table).
pub(crate) struct SystemClock;

impl PresenceClock for SystemClock {
    fn support(&self) -> ClockSupport {
        if cfg!(any(target_os = "linux", target_os = "android")) {
            ClockSupport::Verified
        } else {
            ClockSupport::TtlOnly
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn pair(&self) -> Option<ClockPair> {
        use nix::time::{clock_gettime, ClockId};
        let read = |clock: ClockId| -> Option<u64> {
            let now = clock_gettime(clock).ok()?;
            let secs = u64::try_from(now.tv_sec()).ok()?;
            let millis = u64::try_from(now.tv_nsec()).ok()? / 1_000_000;
            secs.checked_mul(1_000)?.checked_add(millis)
        };
        let boottime_ms = read(ClockId::CLOCK_BOOTTIME)?;
        let monotonic_ms = read(ClockId::CLOCK_MONOTONIC)?;
        Some(ClockPair {
            boottime_ms,
            monotonic_ms,
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn pair(&self) -> Option<ClockPair> {
        None
    }

    fn wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// Whether the daemon was suspended or frozen between `prev` and `now`:
/// B - M moved by more than [`SUSPEND_GROWTH_MS`], more than
/// [`FREEZE_GAP_MS`] of M passed, or either clock went backwards.
pub(crate) fn suspended_since(prev: ClockPair, now: ClockPair) -> bool {
    let Some(monotonic) = now.monotonic_ms.checked_sub(prev.monotonic_ms) else {
        return true;
    };
    let Some(boottime) = now.boottime_ms.checked_sub(prev.boottime_ms) else {
        return true;
    };
    monotonic > FREEZE_GAP_MS || boottime.abs_diff(monotonic) > SUSPEND_GROWTH_MS
}

/// Whether a live link may count as its peer being present, given the
/// latest sample that saw a suspend or a freeze (`live_since`).
fn link_is_live(link: &LinkLiveness, live_since: Option<Instant>) -> bool {
    link.authenticated
        && live_since.is_none_or(|since| {
            link.connected_at > since || link.last_received_at.is_some_and(|at| at > since)
        })
}

/// The admins (sorted hex, as given) whose link is live, never `me`.
/// `links` is keyed by admin hex.
pub(crate) fn connected_admins(
    admins: &[String],
    me: &str,
    links: &HashMap<String, LinkLiveness>,
    live_since: Option<Instant>,
) -> Vec<String> {
    admins
        .iter()
        .filter(|admin| admin.as_str() != me)
        .filter(|admin| {
            links
                .get(admin.as_str())
                .is_some_and(|link| link_is_live(link, live_since))
        })
        .cloned()
        .collect()
}

/// The chain of samples.
struct Chain {
    last: Option<ClockPair>,
    /// Samples that saw a suspend, a freeze, or no clock.
    count: u64,
    /// When the latest of those samples was taken.
    live_since: Option<Instant>,
}

/// One link of the chain, as a reader sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sample {
    count: u64,
    live_since: Option<Instant>,
}

/// What one GET reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PresenceReport {
    pub(crate) connected_admins: Vec<String>,
    pub(crate) suspended_since_last_get: bool,
    pub(crate) presence_mark: String,
}

/// This daemon run's presence facts.
pub(crate) struct PresenceFacts {
    clock: Box<dyn PresenceClock>,
    run_id: String,
    started_at_ms: u64,
    chain: Mutex<Chain>,
}

impl PresenceFacts {
    /// The daemon's: the system clocks.
    pub(crate) fn system() -> Self {
        Self::new(Box::new(SystemClock))
    }

    /// A new run on `clock`, sampled once.
    pub(crate) fn new(clock: Box<dyn PresenceClock>) -> Self {
        let first = clock.pair();
        Self {
            run_id: uuid::Uuid::new_v4().simple().to_string(),
            started_at_ms: clock.wall_ms(),
            chain: Mutex::new(Chain {
                last: first,
                count: u64::from(first.is_none()),
                live_since: first.is_none().then(Instant::now),
            }),
            clock,
        }
    }

    /// Unix milliseconds when this run started. Display only: see the
    /// module docs.
    pub(crate) fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    /// 32 hex digits, different on every run.
    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Whether this platform has a verified suspend pair.
    pub(crate) fn verified(&self) -> bool {
        self.clock.support() == ClockSupport::Verified
    }

    /// Takes the next sample of the chain. The clocks are read under the
    /// chain's lock, so samples are compared in the order they were read.
    pub(crate) fn sample(&self) -> Sample {
        let mut chain = self.chain.lock().unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.pair();
        let suspended = match (chain.last, now) {
            (Some(prev), Some(now)) => suspended_since(prev, now),
            _ => true,
        };
        if suspended {
            chain.count = chain.count.saturating_add(1);
            chain.live_since = Some(Instant::now());
        }
        chain.last = now;
        Sample {
            count: chain.count,
            live_since: chain.live_since,
        }
    }

    fn mark(&self, count: u64) -> String {
        format!("{}:{count}", self.run_id)
    }

    /// Whether `since_mark` is this run's mark at `count`.
    fn mark_is_current(&self, since_mark: Option<&str>, count: u64) -> bool {
        since_mark
            .and_then(|mark| mark.split_once(':'))
            .is_some_and(|(run, at)| run == self.run_id && at.parse::<u64>() == Ok(count))
    }

    /// One GET's report. It samples the clocks, so call it after `links`
    /// were read: a suspend that ended before then is counted, and every
    /// link older than it is held to the zombie rule.
    pub(crate) fn report(
        &self,
        since_mark: Option<&str>,
        admins: &[String],
        me: &str,
        links: &HashMap<String, LinkLiveness>,
    ) -> PresenceReport {
        let sample = self.sample();
        let verified = self.verified();
        PresenceReport {
            connected_admins: if verified {
                connected_admins(admins, me, links, sample.live_since)
            } else {
                Vec::new()
            },
            suspended_since_last_get: !verified || !self.mark_is_current(since_mark, sample.count),
            presence_mark: self.mark(sample.count),
        }
    }
}

/// One GET's presence report over `admins` (sorted hex): the links are
/// read first, then [`PresenceFacts::report`] samples the clocks.
pub(crate) async fn report_for(
    state: &super::AppState,
    since_mark: Option<&str>,
    admins: &[String],
) -> PresenceReport {
    let me = hex::encode(state.agent.agent_id().as_bytes());
    let mut links = HashMap::new();
    if state.presence.verified() {
        let named: Vec<(&String, crate::identity::AgentId)> = admins
            .iter()
            .filter(|admin| **admin != me)
            .filter_map(|admin| {
                let bytes: [u8; 32] = hex::decode(admin).ok()?.try_into().ok()?;
                Some((admin, crate::identity::AgentId(bytes)))
            })
            .collect();
        let ids: Vec<crate::identity::AgentId> = named.iter().map(|(_, id)| *id).collect();
        let present = state.agent.presence_links(&ids).await;
        for (admin, id) in named {
            if let Some(link) = present.get(&id) {
                links.insert(admin.clone(), *link);
            }
        }
    }
    state.presence.report(since_mark, admins, &me, &links)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::sync::Arc;

    struct FakeState {
        support: ClockSupport,
        pair: Option<ClockPair>,
        wall_ms: u64,
    }

    /// Clocks the test moves by hand.
    #[derive(Clone)]
    struct FakeClock(Arc<Mutex<FakeState>>);

    impl FakeClock {
        fn with(support: ClockSupport) -> Self {
            Self(Arc::new(Mutex::new(FakeState {
                support,
                pair: Some(ClockPair {
                    boottime_ms: 1_000_000,
                    monotonic_ms: 900_000,
                }),
                wall_ms: 1_790_000_000_000,
            })))
        }

        fn verified() -> Self {
            Self::with(ClockSupport::Verified)
        }

        /// B moves by `boottime_ms` and M by `monotonic_ms`.
        fn advance(&self, boottime_ms: i64, monotonic_ms: i64) {
            let mut state = self.0.lock().unwrap();
            let pair = state.pair.as_mut().expect("a readable clock");
            pair.boottime_ms = pair.boottime_ms.checked_add_signed(boottime_ms).unwrap();
            pair.monotonic_ms = pair.monotonic_ms.checked_add_signed(monotonic_ms).unwrap();
        }

        /// An ordinary stretch of `ms` awake.
        fn awake(&self, ms: i64) {
            self.advance(ms, ms);
        }

        fn step_wall(&self, ms: i64) {
            let mut state = self.0.lock().unwrap();
            state.wall_ms = state.wall_ms.checked_add_signed(ms).unwrap();
        }

        fn set_readable(&self, pair: Option<ClockPair>) {
            self.0.lock().unwrap().pair = pair;
        }

        fn pair_now(&self) -> Option<ClockPair> {
            self.0.lock().unwrap().pair
        }
    }

    impl PresenceClock for FakeClock {
        fn support(&self) -> ClockSupport {
            self.0.lock().unwrap().support
        }

        fn pair(&self) -> Option<ClockPair> {
            self.0.lock().unwrap().pair
        }

        fn wall_ms(&self) -> u64 {
            self.0.lock().unwrap().wall_ms
        }
    }

    fn facts(clock: &FakeClock) -> PresenceFacts {
        PresenceFacts::new(Box::new(clock.clone()))
    }

    /// A GET with no admins: only the suspend answer and the mark.
    fn get(facts: &PresenceFacts, mark: Option<&str>) -> PresenceReport {
        facts.report(mark, &[], ME, &HashMap::new())
    }

    const ME: &str = "me";

    fn link(authenticated: bool, connected_at: Instant, received: Option<Instant>) -> LinkLiveness {
        LinkLiveness {
            authenticated,
            connected_at,
            last_received_at: received,
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn a_suspend_shows_as_boottime_growing_past_monotonic() {
        let clock = FakeClock::verified();
        let facts = facts(&clock);

        let first = get(&facts, None);
        assert!(
            first.suspended_since_last_get,
            "no mark: nothing to vouch since"
        );

        clock.awake(3_000);
        let quiet = get(&facts, Some(&first.presence_mark));
        assert!(!quiet.suspended_since_last_get);

        // B - M grew by exactly the threshold: not a suspend.
        clock.advance(3_000 + SUSPEND_GROWTH_MS as i64, 3_000);
        let edge = get(&facts, Some(&quiet.presence_mark));
        assert!(!edge.suspended_since_last_get);

        // A 60 s suspend: M stopped, B kept counting.
        clock.advance(60_000 + 2_000, 2_000);
        let woke = get(&facts, Some(&edge.presence_mark));
        assert!(woke.suspended_since_last_get, "the suspend was hidden");
        assert!(
            get(&facts, Some(&edge.presence_mark)).suspended_since_last_get,
            "the same mark must keep showing the suspend"
        );

        clock.awake(3_000);
        assert!(!get(&facts, Some(&woke.presence_mark)).suspended_since_last_get);

        let at = ClockPair {
            boottime_ms: 10_000,
            monotonic_ms: 10_000,
        };
        let grew = |by: u64| ClockPair {
            boottime_ms: at.boottime_ms + 1_000 + by,
            monotonic_ms: at.monotonic_ms + 1_000,
        };
        assert!(!suspended_since(at, grew(SUSPEND_GROWTH_MS)));
        assert!(suspended_since(at, grew(SUSPEND_GROWTH_MS + 1)));
    }

    #[test]
    fn a_freeze_shows_as_a_monotonic_gap() {
        let clock = FakeClock::verified();
        let facts = facts(&clock);
        let mark = get(&facts, None).presence_mark;

        clock.awake(FREEZE_GAP_MS as i64);
        let edge = get(&facts, Some(&mark));
        assert!(
            !edge.suspended_since_last_get,
            "exactly the gap is not a freeze"
        );

        // Stopped (SIGSTOP, a cgroup freezer): both clocks ran on, and no
        // sample was taken for longer than the gap.
        clock.awake(FREEZE_GAP_MS as i64 + 1);
        let thawed = get(&facts, Some(&edge.presence_mark));
        assert!(thawed.suspended_since_last_get, "the freeze was hidden");

        // The sampler keeps the gap short between GETs far apart.
        let mut last = thawed.presence_mark;
        for _ in 0..10 {
            clock.awake(SAMPLE_INTERVAL.as_millis() as i64);
            facts.sample();
        }
        clock.awake(1_000);
        let after = get(&facts, Some(&last));
        assert!(!after.suspended_since_last_get);
        last = after.presence_mark;
        clock.awake(40_000);
        assert!(get(&facts, Some(&last)).suspended_since_last_get);
    }

    #[test]
    fn a_backwards_wall_step_hides_nothing() {
        let clock = FakeClock::verified();
        let facts = facts(&clock);
        let started = facts.started_at_ms();
        let mark = get(&facts, None).presence_mark;

        // The wall clock steps back an hour while awake: no suspend is faked.
        clock.step_wall(-3_600_000);
        clock.awake(2_000);
        let stepped = get(&facts, Some(&mark));
        assert!(
            !stepped.suspended_since_last_get,
            "a wall step faked a suspend"
        );
        assert_eq!(facts.started_at_ms(), started);

        // It steps back an hour across a real suspend: the suspend shows.
        clock.step_wall(-3_600_000);
        clock.advance(120_000, 1_000);
        let woke = get(&facts, Some(&stepped.presence_mark));
        assert!(woke.suspended_since_last_get, "a wall step hid a suspend");

        // Either clock going backwards is never read as steady.
        clock.advance(1_000, -500);
        let back = get(&facts, Some(&woke.presence_mark));
        assert!(back.suspended_since_last_get, "monotonic went backwards");
        clock.advance(-500, 1_000);
        assert!(
            get(&facts, Some(&back.presence_mark)).suspended_since_last_get,
            "boottime went backwards"
        );
    }

    #[test]
    fn connected_admins_lists_only_live_links() {
        let before = Instant::now();
        let wake = before + Duration::from_secs(10);
        let after = wake + Duration::from_secs(1);
        let links: HashMap<String, LinkLiveness> = [
            ("a1", link(true, before, Some(after))),
            ("a2", link(true, after, None)),
            ("a3", link(true, before, Some(before))),
            ("a4", link(false, after, Some(after))),
            ("a6", link(true, before, None)),
            (ME, link(true, after, Some(after))),
        ]
        .into_iter()
        .map(|(name, link)| (name.to_string(), link))
        .collect();
        let admins = names(&["a1", "a2", "a3", "a4", "a5", "a6", ME]);

        assert_eq!(
            connected_admins(&admins, ME, &links, Some(wake)),
            names(&["a1", "a2"]),
            "after a suspend only a link that proved itself since counts"
        );
        assert_eq!(
            connected_admins(&admins, ME, &links, None),
            names(&["a1", "a2", "a3", "a6"]),
            "with no suspend every authenticated live link counts"
        );

        // Through a GET: a link made before a suspend the GET's own sample
        // saw is held as a possible zombie, until its peer speaks again.
        let clock = FakeClock::verified();
        let facts = facts(&clock);
        let made = Instant::now();
        let mut live: HashMap<String, LinkLiveness> = HashMap::new();
        live.insert("a1".to_string(), link(true, made, None));
        let admins = names(&["a1"]);
        assert_eq!(
            facts.report(None, &admins, ME, &live).connected_admins,
            names(&["a1"])
        );
        clock.advance(600_000, 1_000);
        let woke = facts.report(None, &admins, ME, &live);
        assert!(woke.connected_admins.is_empty(), "a zombie counted");
        // The peer spoke after the GET that saw the suspend.
        let spoke = Instant::now() + Duration::from_millis(1);
        live.insert("a1".to_string(), link(true, made, Some(spoke)));
        clock.awake(1_000);
        assert_eq!(
            facts.report(None, &admins, ME, &live).connected_admins,
            names(&["a1"])
        );

        // A platform without a verified pair cannot rule out a zombie.
        let ttl = PresenceFacts::new(Box::new(FakeClock::with(ClockSupport::TtlOnly)));
        assert!(ttl
            .report(None, &admins, ME, &live)
            .connected_admins
            .is_empty());
    }

    #[test]
    fn concurrent_readers_each_see_every_suspend() {
        let clock = FakeClock::verified();
        let facts = facts(&clock);
        let mark = get(&facts, None).presence_mark;
        clock.awake(1_000);
        assert!(!get(&facts, Some(&mark)).suspended_since_last_get);

        clock.advance(30_000, 500);
        // The first reader's GET counts the suspend; every other reader,
        // holding the same older mark, still sees it.
        let answers: Vec<bool> = std::thread::scope(|scope| {
            let readers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| get(&facts, Some(&mark)).suspended_since_last_get))
                .collect();
            readers
                .into_iter()
                .map(|reader| reader.join().unwrap())
                .collect()
        });
        assert_eq!(answers, vec![true; 8], "a reader missed the suspend");
    }

    #[test]
    fn a_suspend_the_sampler_saw_is_still_reported() {
        let clock = FakeClock::verified();
        let facts = facts(&clock);
        let mark = get(&facts, None).presence_mark;
        clock.advance(90_000, 1_000);
        facts.sample();
        clock.awake(1_000);
        assert!(get(&facts, Some(&mark)).suspended_since_last_get);
    }

    #[test]
    fn a_restart_reads_suspended_on_the_first_get() {
        let clock = FakeClock::verified();
        let before = facts(&clock);
        let old_mark = get(&before, None).presence_mark;

        let after = facts(&clock);
        assert_ne!(before.run_id(), after.run_id());
        assert_eq!(after.run_id().len(), 32);
        assert!(get(&after, None).suspended_since_last_get);
        assert!(
            get(&after, Some(&old_mark)).suspended_since_last_get,
            "a mark from the run before the restart vouched for this run"
        );
        let run = after.run_id().to_string();
        for garbage in [
            "",
            "x",
            ":0",
            &format!("{run}:"),
            &format!("{run}:99"),
            &format!("{run}:-1"),
        ] {
            assert!(
                get(&after, Some(garbage)).suspended_since_last_get,
                "{garbage:?}"
            );
        }
    }

    #[test]
    fn an_unreadable_clock_reads_as_suspended() {
        let clock = FakeClock::verified();
        let facts = facts(&clock);
        let mark = get(&facts, None).presence_mark;
        let pair = clock.pair_now();
        clock.set_readable(None);
        let blind = get(&facts, Some(&mark));
        assert!(blind.suspended_since_last_get);
        clock.set_readable(pair);
        let back = get(&facts, Some(&blind.presence_mark));
        assert!(
            back.suspended_since_last_get,
            "no previous sample to compare"
        );
        clock.awake(1_000);
        assert!(!get(&facts, Some(&back.presence_mark)).suspended_since_last_get);

        let blind_from_start = FakeClock::verified();
        blind_from_start.set_readable(None);
        let facts = PresenceFacts::new(Box::new(blind_from_start.clone()));
        let mark = get(&facts, None).presence_mark;
        blind_from_start.set_readable(pair);
        assert!(get(&facts, Some(&mark)).suspended_since_last_get);
    }

    #[test]
    fn ttl_only_platforms_always_read_suspended() {
        let clock = FakeClock::with(ClockSupport::TtlOnly);
        let facts = facts(&clock);
        let mut mark = get(&facts, None).presence_mark;
        for _ in 0..3 {
            clock.awake(1_000);
            let read = get(&facts, Some(&mark));
            assert!(read.suspended_since_last_get);
            mark = read.presence_mark;
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_system_clock_is_a_verified_pair_here() {
        assert_eq!(SystemClock.support(), ClockSupport::Verified);
        let pair = SystemClock
            .pair()
            .expect("CLOCK_BOOTTIME and CLOCK_MONOTONIC");
        assert!(pair.boottime_ms >= pair.monotonic_ms);
        let facts = PresenceFacts::system();
        let mark = get(&facts, None).presence_mark;
        assert!(!get(&facts, Some(&mark)).suspended_since_last_get);
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn the_system_clock_is_ttl_only_here() {
        assert_eq!(SystemClock.support(), ClockSupport::TtlOnly);
        let facts = PresenceFacts::system();
        let mark = get(&facts, None).presence_mark;
        assert!(get(&facts, Some(&mark)).suspended_since_last_get);
    }
}

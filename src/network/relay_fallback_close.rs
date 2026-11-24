//! Josh's relay rule (2026-11-23): a `relay_service_disabled` node (a
//! phone) relays through a public node only while its embedder says its own
//! relay is down. When the embedder turns the relay fallback off, the
//! connections already relayed get a short grace to finish a send in flight,
//! then close at the first quiet second, and are cut at a hard cap whatever
//! they carry: the grace is a courtesy inside the rule, not an exception to
//! it, and a send cut at the cap is re-sent over the embedder's relay, which
//! is back by then.

use std::time::Duration;

use tokio::time::Instant;

/// How long a relayed connection may run on after the switch-off before it
/// is closed at a quiet second. 30 s covers several direct-send rounds with
/// their receive ACK (8 s each) and is about the life of a carrier NAT's UDP
/// mapping, past which the seed's path to the phone is unlikely to hold.
pub const RELAY_FALLBACK_OFF_GRACE: Duration = Duration::from_secs(30);

/// The hard cap after the switch-off: the relayed connections are closed
/// then whatever they carry. A meshed link's gossip and presence traffic
/// may never leave a quiet second.
pub const RELAY_FALLBACK_OFF_CAP: Duration = Duration::from_secs(120);

/// After the grace, the connections close at the first window this long in
/// which their relay moved no byte.
const RELAY_FALLBACK_QUIET_WINDOW: Duration = Duration::from_secs(1);

/// The timings of a close (tests shorten them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CloseTimes {
    pub(crate) grace: Duration,
    pub(crate) cap: Duration,
    pub(crate) quiet: Duration,
}

impl Default for CloseTimes {
    fn default() -> Self {
        Self {
            grace: RELAY_FALLBACK_OFF_GRACE,
            cap: RELAY_FALLBACK_OFF_CAP,
            quiet: RELAY_FALLBACK_QUIET_WINDOW,
        }
    }
}

/// Why the relayed connections were closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseReason {
    /// A quiet window after the grace.
    Quiet,
    /// The hard cap.
    Cap,
}

/// Close the relayed connections after a switch-off.
///
/// `activity` answers `None` once the close no longer applies (the switch
/// changed, the node latched), else the client relay sessions open and the
/// bytes their relay moved so far. `close` closes them and answers whether
/// it did (it re-checks the switch under the caller's lock). The task waits
/// `times.grace`, then closes at the first `times.quiet` window with no
/// byte, or at `times.cap` after its start, whichever comes first. It
/// returns at once when no session is open after the grace.
pub(crate) async fn run_close<A, C>(times: CloseTimes, activity: A, close: C)
where
    A: Fn() -> Option<(usize, u64)>,
    C: Fn(CloseReason) -> bool,
{
    let cap_at = Instant::now() + times.cap;
    tokio::time::sleep(times.grace.min(times.cap)).await;
    loop {
        let Some((open, before)) = activity() else {
            return;
        };
        if open == 0 {
            return;
        }
        let now = Instant::now();
        if now >= cap_at {
            close(CloseReason::Cap);
            return;
        }
        let window = times.quiet.min(cap_at - now);
        tokio::time::sleep(window).await;
        let Some((_, after)) = activity() else {
            return;
        };
        if after == before && window == times.quiet {
            close(CloseReason::Quiet);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    fn times() -> CloseTimes {
        CloseTimes {
            grace: Duration::from_secs(30),
            cap: Duration::from_secs(120),
            quiet: Duration::from_secs(1),
        }
    }

    /// Runs `run_close` with one session open and the relay byte count
    /// `bytes(elapsed)`; answers when it closed and why.
    async fn close_with(bytes: impl Fn(Duration) -> u64) -> Option<(Duration, CloseReason)> {
        let start = Instant::now();
        let closed = Arc::new(Mutex::new(None));
        run_close(
            times(),
            || Some((1, bytes(start.elapsed()))),
            |reason| {
                *closed.lock().unwrap() = Some((start.elapsed(), reason));
                true
            },
        )
        .await;
        let closed = *closed.lock().unwrap();
        closed
    }

    /// An idle relay closes one quiet window after the grace.
    #[tokio::test(start_paused = true)]
    async fn an_idle_relay_closes_at_the_first_quiet_second_after_the_grace() {
        assert_eq!(
            close_with(|_| 7).await,
            Some((Duration::from_secs(31), CloseReason::Quiet))
        );
    }

    /// Traffic that flows through the grace holds the close; it closes at
    /// the first idle second once the traffic stops.
    #[tokio::test(start_paused = true)]
    async fn traffic_holds_the_close_until_the_first_idle_second() {
        let closed = close_with(|elapsed| {
            u64::try_from(elapsed.min(Duration::from_secs(50)).as_millis()).unwrap()
        })
        .await
        .expect("closed");
        assert_eq!(closed.1, CloseReason::Quiet);
        assert!(
            closed.0 > Duration::from_secs(50) && closed.0 <= Duration::from_secs(52),
            "closed at {:?}",
            closed.0
        );
    }

    /// Traffic that never pauses is cut at the hard cap.
    #[tokio::test(start_paused = true)]
    async fn traffic_that_never_pauses_is_cut_at_the_cap() {
        let closed = tokio::time::timeout(
            Duration::from_secs(300),
            close_with(|elapsed| u64::try_from(elapsed.as_millis()).unwrap()),
        )
        .await
        .expect("the cap ends the close");
        assert_eq!(closed, Some((Duration::from_secs(120), CloseReason::Cap)));
    }

    /// A close that no longer applies stops the task, and nothing open
    /// after the grace closes nothing.
    #[tokio::test(start_paused = true)]
    async fn a_switch_change_or_no_session_closes_nothing() {
        let calls = AtomicU64::new(0);
        run_close(
            times(),
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                None
            },
            |_| panic!("no close once the switch changed"),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        run_close(times(), || Some((0, 0)), |_| panic!("nothing open")).await;
    }
}

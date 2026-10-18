//! A joiner's in-flight Welcome `ChunkAck` sends.
//!
//! The Welcome listener hands each ack to a task so it never waits on the
//! network. Each task is registered here per `(welcome, chunk)` with the
//! admission ticket that bounds it, so:
//! - an ack for a chunk received again (the owner restreams) replaces the
//!   earlier one, and the earlier ticket is released before the new ack is
//!   admitted: a stalled burst from an old stream never blocks a restream;
//! - a Welcome whose receive ends (assembled, failed, expired, or purged
//!   with its group) aborts its acks and releases their tickets;
//! - shutdown closes registration and hands every task to the drain;
//! - an ack aborted while still in flight logs one line with its chunk,
//!   its path and its age.
//!
//! The ticket lives in the registry entry, not in the task, so releasing an
//! entry frees its admission slot at once; aborting the task only takes
//! effect at the task's next poll.

use super::fair_admission::AdmissionTicket;
use crate::logging::LogHexId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// The path an ack's send took (`raw_quic` or `gossip_inbox`), set once the
/// send has chosen it.
pub(in crate::server) type AckPath = Arc<OnceLock<&'static str>>;

#[derive(Debug)]
struct Entry {
    task: JoinHandle<()>,
    _ticket: AdmissionTicket,
    started: Instant,
    path: AckPath,
}

impl Entry {
    /// Abort the send; a send still running leaves one line saying where
    /// it was going and for how long, so a stuck ack is visible.
    fn abort(self, welcome_id: &str, sequence: u64, reason: &'static str) {
        if !self.task.is_finished() {
            tracing::info!(
                target: "welcome.trace",
                stage = "chunk_ack_aborted",
                welcome_id = %LogHexId::new("welcome", welcome_id),
                seq = sequence,
                path = self.path.get().copied().unwrap_or("undecided"),
                age_ms = self.started.elapsed().as_millis() as u64,
                reason,
                "Welcome ChunkAck still in flight was aborted"
            );
        }
        self.task.abort();
    }
}

type Acks = HashMap<String, HashMap<u64, Entry>>;

/// The registry. `None` once shutdown has closed it.
#[derive(Debug)]
pub(in crate::server) struct WelcomeAckTasks {
    inner: Arc<Mutex<Option<Acks>>>,
}

impl WelcomeAckTasks {
    pub(in crate::server) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(HashMap::new()))),
        }
    }

    fn lock(inner: &Mutex<Option<Acks>>) -> std::sync::MutexGuard<'_, Option<Acks>> {
        inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Release the ack in flight for `(welcome_id, sequence)`, if any: abort
    /// its task and free its admission slot.
    pub(in crate::server) fn release(&self, welcome_id: &str, sequence: u64) {
        let entry = {
            let mut guard = Self::lock(&self.inner);
            let Some(acks) = guard.as_mut() else {
                return;
            };
            let Some(chunks) = acks.get_mut(welcome_id) else {
                return;
            };
            let entry = chunks.remove(&sequence);
            if chunks.is_empty() {
                acks.remove(welcome_id);
            }
            entry
        };
        if let Some(entry) = entry {
            entry.abort(welcome_id, sequence, "chunk received again");
        }
    }

    /// Abort every ack of `welcome_id` and free their slots: its receive
    /// ended, so they can no longer help it.
    pub(in crate::server) fn release_welcome(&self, welcome_id: &str) {
        let chunks = Self::lock(&self.inner)
            .as_mut()
            .and_then(|acks| acks.remove(welcome_id));
        for (sequence, entry) in chunks.into_iter().flatten() {
            entry.abort(welcome_id, sequence, "receive ended");
        }
    }

    /// Run `send` as the ack task for `(welcome_id, sequence)` under
    /// `ticket`, replacing any earlier one. `path` is the send's path cell.
    /// The entry removes itself when the send ends, by task id, so it never
    /// removes a replacement's. Returns `false`, spawning nothing, once
    /// shutdown has closed the registry.
    pub(in crate::server) fn spawn<F>(
        &self,
        welcome_id: &str,
        sequence: u64,
        ticket: AdmissionTicket,
        path: AckPath,
        send: F,
    ) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let previous = {
            let mut guard = Self::lock(&self.inner);
            let Some(acks) = guard.as_mut() else {
                return false;
            };
            let registry = Arc::clone(&self.inner);
            let id = welcome_id.to_string();
            // The task cannot remove its entry before it is inserted:
            // removal takes this lock, held until the insert below.
            let task = tokio::spawn(async move {
                if futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(send))
                    .await
                    .is_err()
                {
                    tracing::error!(
                        target: "welcome.trace",
                        welcome_id = %LogHexId::new("welcome", &id),
                        seq = sequence,
                        "Welcome ChunkAck send panicked; its slot was released"
                    );
                }
                let own = tokio::task::try_id();
                let mut guard = Self::lock(&registry);
                if let Some(acks) = guard.as_mut() {
                    if let Some(chunks) = acks.get_mut(&id) {
                        if chunks
                            .get(&sequence)
                            .is_some_and(|entry| Some(entry.task.id()) == own)
                        {
                            chunks.remove(&sequence);
                        }
                        if chunks.is_empty() {
                            acks.remove(&id);
                        }
                    }
                }
            });
            acks.entry(welcome_id.to_string()).or_default().insert(
                sequence,
                Entry {
                    task,
                    _ticket: ticket,
                    started: Instant::now(),
                    path,
                },
            )
        };
        if let Some(entry) = previous {
            entry.abort(welcome_id, sequence, "replaced");
        }
        true
    }

    /// Shutdown: close the registry and hand every ack task to the drain.
    pub(in crate::server) fn close(&self) -> Vec<JoinHandle<()>> {
        Self::lock(&self.inner)
            .take()
            .into_iter()
            .flat_map(HashMap::into_values)
            .flat_map(HashMap::into_values)
            .map(|entry| entry.task)
            .collect()
    }

    /// Ack tasks registered now (tests).
    #[cfg(test)]
    pub(in crate::server) fn in_flight(&self) -> usize {
        Self::lock(&self.inner)
            .as_ref()
            .map_or(0, |acks| acks.values().map(HashMap::len).sum())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::super::fair_admission::FairAdmission;
    use super::WelcomeAckTasks;
    use std::time::Duration;

    fn pending() -> impl std::future::Future<Output = ()> + Send + 'static {
        std::future::pending()
    }

    fn path() -> super::AckPath {
        std::sync::Arc::new(std::sync::OnceLock::new())
    }

    #[tokio::test]
    async fn a_reacked_chunk_frees_the_earlier_slot_before_admission() {
        let admission = FairAdmission::new(1, 4);
        let tasks = WelcomeAckTasks::new();
        let first = admission.try_admit("w:0", "g").expect("first ack");
        assert!(tasks.spawn("w", 0, first, path(), pending()));
        assert!(admission.try_admit("w:0", "g").is_err(), "slot held");
        // The chunk arrives again: its earlier ack gives way at once.
        tasks.release("w", 0);
        let again = admission
            .try_admit("w:0", "g")
            .expect("the released slot is free immediately");
        assert!(tasks.spawn("w", 0, again, path(), pending()));
        assert_eq!(tasks.in_flight(), 1);
        tasks.release_welcome("w");
        assert_eq!(tasks.in_flight(), 0);
        assert_eq!(admission.in_flight(), 0);
    }

    #[tokio::test]
    async fn finished_acks_leave_and_shutdown_closes_registration() {
        let admission = FairAdmission::new(4, 4);
        let tasks = WelcomeAckTasks::new();
        let ticket = admission.try_admit("w:1", "g").expect("ack");
        assert!(tasks.spawn("w", 1, ticket, path(), async {}));
        tokio::time::timeout(Duration::from_secs(1), async {
            while tasks.in_flight() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a finished ack removes its entry");
        assert_eq!(admission.in_flight(), 0);

        let ticket = admission.try_admit("w:2", "g").expect("ack");
        assert!(tasks.spawn("w", 2, ticket, path(), pending()));
        let drained = tasks.close();
        assert_eq!(drained.len(), 1);
        assert_eq!(admission.in_flight(), 0, "closing frees the slots");
        for task in &drained {
            task.abort();
        }
        let ticket = admission.try_admit("w:3", "g").expect("ack");
        assert!(!tasks.spawn("w", 3, ticket, path(), async {}), "closed");
    }
}

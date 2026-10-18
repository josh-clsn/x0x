//! A joiner's in-flight Welcome `ChunkAck` sends.
//!
//! The Welcome listener hands each ack to a task so it never waits on the
//! network. Each task is registered here per `(welcome, chunk)` with the
//! admission ticket that bounds it, so:
//! - an ack for a chunk received again (the owner restreams) replaces the
//!   earlier one, and the earlier ticket is released before the new ack is
//!   admitted: a stalled burst from an old stream never blocks a restream;
//! - a Welcome whose receive ends (assembled, failed or expired) aborts its
//!   acks and releases their tickets;
//! - shutdown closes registration and hands every task to the drain.
//!
//! The ticket lives in the registry entry, not in the task, so releasing an
//! entry frees its admission slot at once; aborting the task only takes
//! effect at the task's next poll.

use super::fair_admission::AdmissionTicket;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

type Acks = HashMap<String, HashMap<u64, (JoinHandle<()>, AdmissionTicket)>>;

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
        let mut guard = Self::lock(&self.inner);
        let Some(acks) = guard.as_mut() else {
            return;
        };
        if let Some(chunks) = acks.get_mut(welcome_id) {
            if let Some((task, _ticket)) = chunks.remove(&sequence) {
                task.abort();
            }
            if chunks.is_empty() {
                acks.remove(welcome_id);
            }
        }
    }

    /// Abort every ack of `welcome_id` and free their slots: its receive
    /// ended, so they can no longer help it.
    pub(in crate::server) fn release_welcome(&self, welcome_id: &str) {
        let chunks = Self::lock(&self.inner)
            .as_mut()
            .and_then(|acks| acks.remove(welcome_id));
        for (task, _ticket) in chunks.into_iter().flat_map(HashMap::into_values) {
            task.abort();
        }
    }

    /// Run `send` as the ack task for `(welcome_id, sequence)` under
    /// `ticket`, replacing any earlier one. The entry removes itself when
    /// the send ends, by task id, so it never removes a replacement's.
    /// Returns `false`, spawning nothing, once shutdown has closed the
    /// registry.
    pub(in crate::server) fn spawn<F>(
        &self,
        welcome_id: &str,
        sequence: u64,
        ticket: AdmissionTicket,
        send: F,
    ) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut guard = Self::lock(&self.inner);
        let Some(acks) = guard.as_mut() else {
            return false;
        };
        let registry = Arc::clone(&self.inner);
        let id = welcome_id.to_string();
        // The task cannot remove its entry before it is inserted: removal
        // takes this lock, held until the insert below.
        let task = tokio::spawn(async move {
            if futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(send))
                .await
                .is_err()
            {
                tracing::error!(
                    target: "welcome.trace",
                    welcome_id = %id,
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
                        .is_some_and(|(task, _)| Some(task.id()) == own)
                    {
                        chunks.remove(&sequence);
                    }
                    if chunks.is_empty() {
                        acks.remove(&id);
                    }
                }
            }
        });
        let previous = acks
            .entry(welcome_id.to_string())
            .or_default()
            .insert(sequence, (task, ticket));
        if let Some((task, _ticket)) = previous {
            task.abort();
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
            .map(|(task, _ticket)| task)
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

    #[tokio::test]
    async fn a_reacked_chunk_frees_the_earlier_slot_before_admission() {
        let admission = FairAdmission::new(1, 4);
        let tasks = WelcomeAckTasks::new();
        let first = admission.try_admit("w:0", "g").expect("first ack");
        assert!(tasks.spawn("w", 0, first, pending()));
        assert!(admission.try_admit("w:0", "g").is_err(), "slot held");
        // The chunk arrives again: its earlier ack gives way at once.
        tasks.release("w", 0);
        let again = admission
            .try_admit("w:0", "g")
            .expect("the released slot is free immediately");
        assert!(tasks.spawn("w", 0, again, pending()));
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
        assert!(tasks.spawn("w", 1, ticket, async {}));
        tokio::time::timeout(Duration::from_secs(1), async {
            while tasks.in_flight() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a finished ack removes its entry");
        assert_eq!(admission.in_flight(), 0);

        let ticket = admission.try_admit("w:2", "g").expect("ack");
        assert!(tasks.spawn("w", 2, ticket, pending()));
        let drained = tasks.close();
        assert_eq!(drained.len(), 1);
        assert_eq!(admission.in_flight(), 0, "closing frees the slots");
        for task in &drained {
            task.abort();
        }
        let ticket = admission.try_admit("w:3", "g").expect("ack");
        assert!(!tasks.spawn("w", 3, ticket, async {}), "closed");
    }
}

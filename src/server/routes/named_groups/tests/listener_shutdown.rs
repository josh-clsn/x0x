//! Group listeners and shutdown (#661): once shutdown is flagged no group
//! listener may start or keep running, because the drain has already taken
//! the registries that would abort it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// Why the guard exists: a receiver created after the flag is set never
/// sees `changed()`, but does see the flag.
#[tokio::test]
async fn a_receiver_born_after_the_flag_sees_only_the_value() {
    let (tx, _keep) = tokio::sync::watch::channel(false);
    let _ = tx.send(true);
    let mut late = tx.subscribe();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), late.changed())
            .await
            .is_err(),
        "changed() alone never fires for a receiver born after the flag"
    );
    let mut late = tx.subscribe();
    assert!(listener_shutdown_flagged(&mut late));
}

#[tokio::test]
async fn a_live_listener_is_not_told_to_stop() {
    let (tx, _keep) = tokio::sync::watch::channel(false);
    let mut rx = tx.subscribe();
    assert!(!listener_shutdown_flagged(&mut rx));
}

#[tokio::test]
async fn no_group_listener_is_registered_after_shutdown() -> Result<()> {
    let f = departure_fixture(0x92, x0x::mls::SecureGroupPlane::TreeKem, true).await?;
    let _ = f.state.shutdown_notify.send_replace(true);
    ensure_named_group_listeners(Arc::clone(&f.state), &f.group_id).await;
    ensure_listeners_after_local_admission(&f.state, &f.group_id, true).await;
    assert!(f.state.group_metadata_tasks.read().await.is_empty());
    assert!(f.state.public_message_tasks.read().await.is_empty());
    Ok(())
}

/// A channel standing in for the gossip subscription.
struct ChannelSource(tokio::sync::mpsc::Receiver<x0x::gossip::PubSubMessage>);

impl GroupListenerSource for ChannelSource {
    fn next_message(
        &mut self,
    ) -> impl std::future::Future<Output = Option<x0x::gossip::PubSubMessage>> + Send + '_ {
        self.0.recv()
    }
}

/// The real listener loop, started AFTER shutdown was flagged (its
/// receiver is born after the flag, so `changed()` never fires) on a source
/// that never delivers: it must still exit on its first turn.
#[tokio::test]
async fn a_listener_started_after_shutdown_exits_on_its_first_turn() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let _ = state.shutdown_notify.send_replace(true);
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let (_keep_open, rx) = tokio::sync::mpsc::channel(1);
    let mut source = ChannelSource(rx);
    let stopped = tokio::time::timeout(
        Duration::from_secs(2),
        run_group_metadata_listener(&state, "ab", &mut source, &mut shutdown_rx),
    )
    .await;
    assert_eq!(
        stopped.ok(),
        Some(false),
        "the listener must exit, not wait"
    );
    Ok(())
}

/// The same loop on a live daemon keeps running until its source ends.
#[tokio::test]
async fn a_live_listener_keeps_running_until_its_source_ends() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let mut source = ChannelSource(rx);
    let still_running = tokio::time::timeout(
        Duration::from_millis(300),
        run_group_metadata_listener(&state, "ab", &mut source, &mut shutdown_rx),
    )
    .await;
    assert!(
        still_running.is_err(),
        "a live listener must not stop by itself"
    );
    drop(tx);
    let ended = tokio::time::timeout(
        Duration::from_secs(2),
        run_group_metadata_listener(&state, "ab", &mut source, &mut shutdown_rx),
    )
    .await;
    assert_eq!(ended.ok(), Some(false), "a closed source ends the listener");
    Ok(())
}

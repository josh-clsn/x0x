//! Group listeners and shutdown (#661): once shutdown is flagged no group
//! listener may start or keep running, because the drain has already taken
//! the registries that would abort it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// The race the guard closes: a listener whose receiver is created after
/// the flag is set never sees `changed()`, but does see the flag.
#[tokio::test]
async fn a_listener_subscribed_after_the_flag_still_stops() {
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
    let _ = f.state.shutdown_notify.send(true);
    ensure_named_group_listeners(Arc::clone(&f.state), &f.group_id).await;
    ensure_listeners_after_local_admission(&f.state, &f.group_id, true).await;
    assert!(f.state.group_metadata_tasks.read().await.is_empty());
    assert!(f.state.public_message_tasks.read().await.is_empty());
    Ok(())
}

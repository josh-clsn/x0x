//! #393 — the file-transfer DM receive dispatcher must honour the transport
//! `verified` annotation before acting on `sender`.
//!
//! `handle_file_message` (src/server/routes/files.rs) has the identical shape to
//! the #377 join-result / Welcome-blob handlers: it takes `(state, sender, msg)`
//! and every arm authorizes on the `sender` `AgentId` alone — an incoming
//! `Offer` binds the whole transfer's `remote_agent_id` to `sender`, and the
//! `Chunk` / `Complete` / `Accept` / `Reject` arms then gate on
//! `remote_agent_id == sender_hex`. On the raw-QUIC direct path the wire envelope
//! is `[0x10][sender_agent_id: 32][payload]` and only the `MachineId` is
//! authenticated by the QUIC handshake, so the 32-byte `sender_agent_id` prefix
//! is self-asserted (`crate::direct::DirectMessage::sender`). When `verified` is
//! `false` that AgentId is attacker-chosen, so every `sender`-based check is
//! vacuous: a forged `Offer` fabricates a transfer with spoofed provenance and a
//! forged `Chunk` writes attacker bytes into a receiving transfer.
//!
//! These controls drive the real dispatcher. They are RED while it ignores
//! `verified` (the unverified message is acted on) and GREEN once the top-level
//! gate lands. Each control also asserts the verified polarity, so a gate that
//! over-blocks legitimate delivery fails here too.
//!
//! Hosted alongside the #377 controls to reuse `secure_endpoint_test_state` —
//! the single sanctioned full-`AppState` builder — rather than standing up a
//! second construction site for the ~90-field struct.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::server::routes::files::handle_file_message;

/// An incoming `Offer` is the authority anchor for the whole transfer: it
/// records a receiving `TransferState` whose `remote_agent_id` every later
/// `Chunk` / `Complete` is checked against, and emits a `file:offer` SSE event
/// naming the sender. The only thing gating that is the self-asserted `sender`,
/// so an unverified offer — whose AgentId is a wire prefix — must not be acted
/// on at all.
#[tokio::test]
async fn file_offer_requires_verified_sender() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let forged = AgentId([0x11_u8; 32]);
    let transfer_id = uuid::Uuid::new_v4().to_string();

    let offer = x0x::files::FileMessage::Offer(x0x::files::FileOffer {
        transfer_id: transfer_id.clone(),
        filename: "secret.txt".to_string(),
        size: 4,
        sha256: "00".repeat(32),
        chunk_size: x0x::files::DEFAULT_CHUNK_SIZE,
        total_chunks: 1,
    });

    // Unverified: the AgentId is attacker-chosen, so recording the transfer and
    // announcing it as "from <sender>" would launder forged provenance.
    let mut sse = state.broadcast_tx.subscribe();
    handle_file_message(&state, &forged, false, offer.clone()).await;
    assert!(
        state.file_transfers.read().await.is_empty(),
        "an unverified file offer created a receiving transfer with attacker-asserted provenance"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), sse.recv())
            .await
            .is_err(),
        "an unverified file offer emitted a file:offer event naming an unverifiable sender"
    );

    // Verified: the legitimate offer is still recorded and announced.
    let mut sse = state.broadcast_tx.subscribe();
    handle_file_message(&state, &forged, true, offer).await;
    {
        let transfers = state.file_transfers.read().await;
        let recorded = transfers
            .get(&transfer_id)
            .ok_or_else(|| anyhow::anyhow!("verified file offer was not recorded"))?;
        assert_eq!(
            recorded.remote_agent_id,
            hex::encode(forged.as_bytes()),
            "verified offer must bind the transfer to its sender"
        );
    }
    let event = tokio::time::timeout(Duration::from_millis(2_000), sse.recv())
        .await
        .map_err(|_| anyhow::anyhow!("verified file offer emitted no SSE event"))??;
    assert_eq!(
        event.event_type, "file:offer",
        "verified offer must emit a file:offer event"
    );

    Ok(())
}

/// A `Chunk` appends attacker-supplied bytes to a receiving transfer's `.part`
/// file. The only gate is `remote_agent_id == sender_hex`
/// (`receive_chunk_expected_sequence`), and `remote_agent_id` was itself pinned
/// from a (possibly forged) offer — so an unverified chunk whose self-asserted
/// AgentId matches lets an off-path attacker inject file bytes. An unverified
/// chunk must be dropped before any write.
#[tokio::test]
async fn file_chunk_requires_verified_sender() -> Result<()> {
    use base64::Engine as _;

    let (state, _dir) = secure_endpoint_test_state().await?;
    tokio::fs::create_dir_all(&state.transfers_dir).await?;
    let forged = AgentId([0x22_u8; 32]);
    let forged_hex = hex::encode(forged.as_bytes());
    let transfer_id = uuid::Uuid::new_v4().to_string();

    // Stage an in-progress receiving transfer bound to the forged sender: this
    // is exactly the state a forged offer leaves behind, so the chunk's
    // `remote_agent_id == sender_hex` check passes and only `verified` stands
    // between the attacker and a file write.
    state.file_transfers.write().await.insert(
        transfer_id.clone(),
        x0x::files::TransferState {
            transfer_id: transfer_id.clone(),
            direction: x0x::files::TransferDirection::Receiving,
            remote_agent_id: forged_hex.clone(),
            filename: "secret.txt".to_string(),
            total_size: 100,
            bytes_transferred: 0,
            status: x0x::files::TransferStatus::InProgress,
            sha256: "00".repeat(32),
            error: None,
            started_at: 0,
            started_at_unix_ms: 0,
            completed_at_unix_ms: None,
            source_path: None,
            output_path: None,
            chunk_size: x0x::files::DEFAULT_CHUNK_SIZE,
            total_chunks: 1,
        },
    );

    let chunk = x0x::files::FileMessage::Chunk(x0x::files::FileChunk {
        transfer_id: transfer_id.clone(),
        sequence: 0,
        data: base64::engine::general_purpose::STANDARD.encode(b"evil"),
    });

    // Unverified: nothing may be written.
    handle_file_message(&state, &forged, false, chunk.clone()).await;
    assert_eq!(
        state
            .file_transfers
            .read()
            .await
            .get(&transfer_id)
            .map(|t| t.bytes_transferred),
        Some(0),
        "an unverified file chunk was applied to a receiving transfer"
    );

    // Verified: the genuine chunk still lands and advances the transfer.
    handle_file_message(&state, &forged, true, chunk).await;
    assert_eq!(
        state
            .file_transfers
            .read()
            .await
            .get(&transfer_id)
            .map(|t| t.bytes_transferred),
        Some(4),
        "a verified chunk from the offer's sender must be applied"
    );

    Ok(())
}

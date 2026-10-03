//! The re-key chain step is TreeKEM-only: on a GSS-plane group there is no
//! re-key and no carry that could apply a removal later, so a pending join
//! never swallows the device's removal there.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[tokio::test]
async fn a_pending_join_does_not_swallow_a_removal_on_a_gss_group() -> Result<()> {
    let f = departure_fixture(0x95, x0x::mls::SecureGroupPlane::Gss, true).await?;
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    record_expected_join_result_inviter(
        &f.state,
        join_result_key(&f.stable_group_id, &local_hex),
        f.peer_hex.clone(),
    );
    let event = admin_removes_local_event(&f).await?;
    let applied =
        apply_named_group_metadata_event(&f.state, event, f.peer_kp.agent_id(), true, None).await;
    assert!(
        applied.accepted && applied.should_exit,
        "the removal departs"
    );
    assert_departure_wiped_treekem_state(&f.state, &f.aliases(), "gss removal").await;
    Ok(())
}

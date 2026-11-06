//! F8: room bookkeeping in a check-in burst. A latched node (its gossip leg
//! silenced) that holds a live direct link to a meshed member pulls the
//! commits it missed over raw QUIC, and the member answers the same way.
//! With no live link the path is unchanged: a meshed node publishes on the
//! gossip inbox, and a latched one fails rather than publish into its own
//! latch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::signed_catchup::{page_request, send_page_request};
use super::epoch_ahead_catchup::{survivor_relay_fixture, wait_until, SurvivorRelay};
use super::signed_catchup::removal_s1_missed;
use super::signer_delivery::s1_follows_the_owner;
use super::welcome_gossip_fallback::known_recipient;
use super::*;

type GossipSink = tokio::sync::mpsc::UnboundedReceiver<(AgentId, Vec<u8>)>;

/// S1 and S2 know each other by a class A record and a gossip-inbox
/// advert, publish to gossip stand-ins, and resolve raw sends strictly.
async fn burst_pair(cast: &SurvivorRelay) -> Result<(GossipSink, GossipSink)> {
    known_recipient(&cast.s1, &cast.s2).await?;
    known_recipient(&cast.s2, &cast.s1).await?;
    for state in [&cast.s1, &cast.s2] {
        state
            .agent
            .set_pinned_standin_strict_resolution_for_testing(true);
    }
    Ok((
        cast.s1.agent.route_gossip_inbox_to_standin_for_testing(),
        cast.s2.agent.route_gossip_inbox_to_standin_for_testing(),
    ))
}

/// Whether `from` has a live direct link to `to`.
fn link(from: &AppState, to: &AppState, live: bool) {
    let machine = [to.agent.machine_id()];
    from.agent.script_pinned_standin_transport_for_testing(
        x0x::PinnedTransportScript::connected_only(if live { &machine[..] } else { &[] }, false),
    );
}

/// The raw payloads `from` delivered to `to` after the first `skip`.
fn raw_to(from: &AppState, to: &AppState, skip: usize) -> Vec<Vec<u8>> {
    from.agent
        .general_raw_standin_deliveries_for_testing()
        .into_iter()
        .filter(|(recipient, ..)| *recipient == to.agent.agent_id())
        .skip(skip)
        .map(|(_, _, payload)| payload)
        .collect()
}

fn drained(sink: &mut GossipSink) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Ok((_, payload)) = sink.try_recv() {
        out.push(payload);
    }
    out
}

#[tokio::test]
async fn a_latched_member_catches_up_over_a_live_link_by_raw() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let (mut s1_gossip, mut s2_gossip) = burst_pair(&cast).await?;
    let (s1, s2) = (Arc::clone(&cast.s1), Arc::clone(&cast.s2));
    link(&s1, &s2, true);
    link(&s2, &s1, true);
    s1.agent.quiesce_gossip_leg_for_testing(true);
    let (s1_raw, s2_raw) = (raw_to(&s1, &s2, 0).len(), raw_to(&s2, &s1, 0).len());

    let request = page_request(&s1, &group_id, None)
        .await
        .expect("S1 asks from its head");
    send_page_request(&s1, &s2.agent.agent_id(), request)
        .await
        .map_err(anyhow::Error::msg)?;
    let sent = raw_to(&s1, &s2, s1_raw);
    assert_eq!(sent.len(), 1, "the page request went raw");
    assert!(drained(&mut s1_gossip).is_empty(), "nothing rode gossip");

    let request: TreeKemCatchupRequest = serde_json::from_slice(&sent[0])?;
    handle_treekem_catchup_request(&s2, &s1.agent.agent_id(), true, request).await;
    wait_until(|| !raw_to(&s2, &s1, s2_raw).is_empty()).await;
    let answers = raw_to(&s2, &s1, s2_raw);
    assert_eq!(answers.len(), 1, "the answer went raw");
    assert!(drained(&mut s2_gossip).is_empty(), "nothing rode gossip");

    let page: TreeKemCatchupResponse = serde_json::from_slice(&answers[0])?;
    assert_eq!(page.events.len(), 1, "the page carries the removal");
    handle_treekem_catchup_response(&s1, &s2.agent.agent_id(), true, page).await;
    s1_follows_the_owner(&mut cast, b"caught up in a burst").await?;
    s1.agent.quiesce_gossip_leg_for_testing(false);
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn with_no_live_link_a_meshed_member_still_uses_the_gossip_inbox() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let (mut s1_gossip, mut s2_gossip) = burst_pair(&cast).await?;
    let (s1, s2) = (Arc::clone(&cast.s1), Arc::clone(&cast.s2));
    link(&s1, &s2, false);
    link(&s2, &s1, false);
    let (s1_raw, s2_raw) = (raw_to(&s1, &s2, 0).len(), raw_to(&s2, &s1, 0).len());

    let request = page_request(&s1, &group_id, None)
        .await
        .expect("S1 asks from its head");
    send_page_request(&s1, &s2.agent.agent_id(), request.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    assert!(raw_to(&s1, &s2, s1_raw).is_empty(), "nothing went raw");
    assert_eq!(drained(&mut s1_gossip).len(), 1, "the request rode gossip");

    handle_treekem_catchup_request(&s2, &s1.agent.agent_id(), true, request).await;
    let mut answers = Vec::new();
    wait_until(|| {
        answers.extend(drained(&mut s2_gossip));
        !answers.is_empty()
    })
    .await;
    assert_eq!(answers.len(), 1, "the answer rode gossip");
    assert!(raw_to(&s2, &s1, s2_raw).is_empty(), "nothing went raw");
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_latched_member_with_no_live_link_reports_the_send_failed() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    removal_s1_missed(&cast).await;
    let (mut s1_gossip, _s2_gossip) = burst_pair(&cast).await?;
    let (s1, s2) = (Arc::clone(&cast.s1), Arc::clone(&cast.s2));
    link(&s1, &s2, false);
    s1.agent.quiesce_gossip_leg_for_testing(true);
    let s1_raw = raw_to(&s1, &s2, 0).len();

    let request = page_request(&s1, &group_id, None)
        .await
        .expect("S1 asks from its head");
    let sent = send_page_request(&s1, &s2.agent.agent_id(), request).await;
    assert!(
        sent.as_ref().is_err_and(|e| e.contains("mesh quiesced")),
        "{sent:?}"
    );
    assert!(drained(&mut s1_gossip).is_empty(), "nothing was published");
    assert!(raw_to(&s1, &s2, s1_raw).is_empty(), "nothing went raw");
    s1.agent.quiesce_gossip_leg_for_testing(false);
    cast.shutdown().await;
    Ok(())
}

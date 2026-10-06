//! W3-H S3 (#1164): restart controls.
//!
//! A restarted daemon re-serves on the same data and identity dirs and the
//! same sim address ([`Sim::restart`]); the fabric attaches it as the next
//! incarnation, closes the old one's links (`Superseded`) and refuses every
//! later operation from the old incarnation (`StaleIncarnation`). A dial by
//! peer id alone reaches only peers the new incarnation knows an address
//! for (`NoHint`), as ant-quic does with its peer cache disabled.
//!
//! The controls, each run 20 times in CI:
//! - graceful and crash restarts of a seated group member: the member is
//!   seated again and its owner still lists it, the trace shows the next
//!   incarnation and a new connection, and after a crash no frame leaves
//!   the node until it is attached again;
//! - a negative control for the hint rule: a restarted node cannot dial a
//!   peer by id until it learns that peer's address;
//! - a harness guard: a daemon state that outlives its stop is INFRA.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::control::{create_group, invite, join, local_membership, members, mesh};
use super::*;
use crate::network::sim::RefusalReason;

/// Seat B in a group A owns, and wait until A lists B and B reports itself
/// active. Every read must complete and succeed.
async fn seat_b(sim: &Sim) -> Result<String> {
    let group = create_group(sim, "A").await?;
    let link = invite(sim, "A", &group).await?;
    join(sim, "B", &link).await?;
    wait_seated(sim, &group, "B seated in A's group").await?;
    Ok(group)
}

async fn wait_seated(sim: &Sim, group: &str, what: &str) -> Result<()> {
    let b = sim.agent_hex("B")?;
    let mut seen = Observations::default();
    sim.until(what, secs(180), async |s: &Sim| {
        let Some(listed) = seen.observe(members(s, "A", group)).await else {
            return true;
        };
        listed.contains(&b) && local_membership(s, "B", group).await.as_deref() == Some("active")
    })
    .await?;
    if seen.failed() {
        seen.verify(what)?;
    }
    Ok(())
}

/// Restart B in `mode` and check what the restart must show.
async fn restart_scenario(sim: &mut Sim, mode: RestartMode) -> Result<()> {
    mesh(sim, &["A", "B", "C"]).await?;
    let group = seat_b(sim).await?;
    let (a, b) = (sim.peer("A")?, sim.peer("B")?);
    let before = sim
        .fabric()
        .incarnation_of(&b)
        .context("B is not on the fabric")?;
    let opens_before = sim.fabric().link_opens(&a, &b).len();
    let stopped_at = sim.fabric().now();
    sim.stop("B", mode).await?;
    // The fixture seam for torn-write cases: B's files, while it is down.
    let data = sim.data_dir("B")?;
    ensure!(
        data.is_dir(),
        "B's data dir {} is missing while it is stopped",
        data.display()
    );
    sim.start_again("B").await?;
    let incarnation = sim
        .fabric()
        .incarnation_of(&b)
        .context("B is not on the fabric after its restart")?;
    ensure!(
        incarnation == before + 1,
        "B restarted as incarnation {incarnation}, expected {}",
        before + 1
    );
    let attached_at = sim
        .fabric()
        .attached_at(&b, incarnation)
        .context("no attach event for B's new incarnation")?;
    if mode == RestartMode::Crash {
        // Between the crash mark and the new attach, nothing B wrote may
        // have left it: the crashed daemon was taken off the fabric first.
        let leaked: Vec<_> = sim
            .fabric()
            .writes()
            .into_iter()
            .filter(|write| {
                write.lane.src == b.0 && write.at >= stopped_at && write.at < attached_at
            })
            .collect();
        ensure!(
            leaked.is_empty(),
            "{} frames left B between its crash and its new incarnation",
            leaked.len()
        );
    }
    wait_seated(sim, &group, "B seated again after its restart").await?;
    let opens = sim.fabric().link_opens(&a, &b);
    ensure!(
        opens.len() > opens_before && opens.iter().any(|(_, at)| *at >= attached_at),
        "no new A~B connection after B's restart ({} opens before, {} after)",
        opens_before,
        opens.len()
    );
    sim.fabric().mark(format!(
        "checkpoint: B seated again as incarnation {incarnation} after a {mode:?} restart"
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s3_control_graceful_restart_reseats_member() -> Result<()> {
    let mut sim = Sim::start(
        "w3h_s3_control_graceful_restart_reseats_member",
        0x5300_0001,
        &["A", "B", "C"],
    )
    .await?;
    let outcome = restart_scenario(&mut sim, RestartMode::Graceful).await;
    sim.conclude(outcome).await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s3_control_crash_restart_reseats_member() -> Result<()> {
    let mut sim = Sim::start(
        "w3h_s3_control_crash_restart_reseats_member",
        0x5300_0002,
        &["A", "B", "C"],
    )
    .await?;
    let outcome = restart_scenario(&mut sim, RestartMode::Crash).await;
    sim.conclude(outcome).await
}

/// Negative control for the hint rule: right after a restart, C knows only
/// the addresses its new incarnation learned (its bootstrap peer A), so a
/// dial to B by peer id alone is refused (`NoHint`); once C learns B's
/// address, the same dial succeeds. B and C are partitioned across the
/// restart, so B cannot reconnect to C (which would teach C B's address)
/// before the refused dial.
async fn hint_scenario(sim: &mut Sim) -> Result<()> {
    mesh(sim, &["A", "B", "C"]).await?;
    let (b, c) = (sim.peer("B")?, sim.peer("C")?);
    sim.fabric().mark("fault B~C partitioned");
    sim.fabric().set_partitioned(&b, &c, true);
    sim.restart("C", RestartMode::Graceful).await?;
    let restarted_at = sim.fabric().now();
    let network = sim
        .state("C")?
        .agent
        .network()
        .cloned()
        .context("C has no network")?;
    let dial = sim
        .at_instant(
            "C dials B by peer id with no known address",
            network.connect_peer(b),
        )
        .await?;
    ensure!(
        dial.is_err(),
        "C dialled B by peer id without knowing its address"
    );
    let refused = sim
        .fabric()
        .refused_since(&c, restarted_at)
        .into_iter()
        .any(|refusal| refusal.dst == b.0 && refusal.reason == RefusalReason::NoHint);
    ensure!(
        refused,
        "C's dial was refused, but not for lack of an address"
    );
    sim.fabric().set_partitioned(&b, &c, false);
    sim.fabric().mark("fault B~C healed");
    let b_addr = super::sim_addr(sim.node_index("B")?)?;
    network
        .upsert_peer_hints(b, vec![b_addr], None)
        .await
        .context("C learns B's address")?;
    sim.within(
        "C dials B by peer id with a hint",
        secs(5),
        network.connect_peer(b),
    )
    .await?
    .context("C dials B once it knows B's address")?;
    sim.fabric()
        .mark("checkpoint: a peer-id dial needs a known address after a restart");
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s3_negative_control_restarted_node_needs_an_address_to_dial() -> Result<()> {
    let mut sim = Sim::start(
        "w3h_s3_negative_control_restarted_node_needs_an_address_to_dial",
        0x5300_0003,
        &["A", "B", "C"],
    )
    .await?;
    let outcome = hint_scenario(&mut sim).await;
    sim.conclude(outcome).await
}

/// Harness guard: a stopped daemon whose state is still held (here by the
/// test itself) must make [`Sim::stop`] report INFRA, never a silent
/// restart next to a possibly live old daemon.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s3_restart_reports_a_leaked_daemon_state_as_infra() -> Result<()> {
    let mut sim = Sim::start(
        "w3h_s3_restart_reports_a_leaked_daemon_state_as_infra",
        0x5300_0004,
        &["A", "B"],
    )
    .await?;
    let leaked = sim.state("B")?;
    let stopped = sim.stop("B", RestartMode::Graceful).await;
    let error = stopped
        .err()
        .context("a stop with a leaked daemon state succeeded")?;
    ensure!(
        format!("{error:#}").contains("INFRA") && format!("{error:#}").contains("still held"),
        "unexpected stop error: {error:#}"
    );
    drop(leaked);
    sim.fabric()
        .mark("checkpoint: a leaked daemon state makes the stop INFRA");
    sim.finish().await?;
    Ok(())
}

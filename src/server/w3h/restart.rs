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
//! - graceful and crash restarts of a seated group member. Each stop passes
//!   the drain guard; the trace shows the next incarnation and a new
//!   connection to the group's owner; fresh group traffic flows both ways
//!   after the restart (the rosters alone prove nothing: both are restored
//!   from disk). After a crash, no frame leaves the node between the crash
//!   mark and its new attach (trace positions, not virtual times, which
//!   paused time lets events on both sides of a boundary share);
//! - a negative control for the hint rule: a restarted node cannot dial a
//!   peer by id until it learns that peer's address;
//! - a harness guard: a daemon state that outlives its stop is INFRA.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::control::{
    create_group, invite, join, local_membership, members, mesh, open_store, put_value, read_value,
    try_open_store,
};
use super::*;
use crate::network::sim::RefusalReason;

/// Seat `member` in a group `owner` creates, and wait until `owner` lists
/// `member` and `member` reports itself active.
async fn seat(sim: &Sim, owner: &str, member: &str) -> Result<String> {
    let group = create_group(sim, owner).await?;
    let link = invite(sim, owner, &group).await?;
    join(sim, member, &link).await?;
    wait_seated(
        sim,
        owner,
        member,
        &group,
        &format!("{member} seated in {owner}'s group"),
    )
    .await?;
    Ok(group)
}

/// Wait until `owner` lists `member` in `group` and `member` reports itself
/// active. Every roster read must complete and succeed.
async fn wait_seated(sim: &Sim, owner: &str, member: &str, group: &str, what: &str) -> Result<()> {
    let id = sim.agent_hex(member)?;
    let mut seen = Observations::default();
    sim.until(what, secs(180), async |s: &Sim| {
        let Some(listed) = seen.observe(members(s, owner, group)).await else {
            return true;
        };
        listed.contains(&id)
            && local_membership(s, member, group).await.as_deref() == Some("active")
    })
    .await?;
    if seen.failed() {
        seen.verify(what)?;
    }
    Ok(())
}

/// Fresh group traffic after `restarted`'s restart, both ways, through the
/// group store (the S1 data plane): `peer` opens the store, `restarted`
/// opens the same store id, `restarted` writes a key `peer` must read, then
/// `peer` writes a key `restarted` must read. Both keys are new, so only
/// traffic after the restart can satisfy the reads. This needs the
/// restarted daemon's group key, its store subscription and its message
/// processing, which a restored roster does not show.
async fn fresh_group_traffic(sim: &Sim, group: &str, restarted: &str, peer: &str) -> Result<()> {
    let store = open_store(sim, peer, group).await?;
    let mut opened = None;
    let mut last = String::new();
    sim.until(
        &format!("{restarted} opens the group store after its restart"),
        secs(60),
        async |s: &Sim| match try_open_store(s, restarted, group).await {
            Ok(id) => {
                opened = Some(id);
                true
            }
            Err(error) => {
                last = format!("{error:#}");
                false
            }
        },
    )
    .await
    .with_context(|| format!("{restarted} last store-open error: {last}"))?;
    ensure!(
        opened.as_deref() == Some(store.as_str()),
        "{restarted} opened a different store id: {opened:?}"
    );
    for (writer, reader) in [(restarted, peer), (peer, restarted)] {
        let key = format!("w3h-after-restart-{writer}");
        let value = format!("{writer} wrote after {restarted}'s restart");
        put_value(sim, writer, &store, &key, &value).await?;
        sim.until(
            &format!("{reader} reads {writer}'s write after {restarted}'s restart"),
            secs(120),
            async |s: &Sim| {
                read_value(s, reader, &store, &key).await.as_deref() == Some(value.as_str())
            },
        )
        .await?;
    }
    Ok(())
}

/// Restart `member`, seated in `owner`'s `group`, in `mode`, and check what
/// the restart must show.
async fn restart_member(
    sim: &mut Sim,
    owner: &str,
    member: &str,
    group: &str,
    mode: RestartMode,
) -> Result<()> {
    let (o, m) = (sim.peer(owner)?, sim.peer(member)?);
    let before = sim
        .fabric()
        .incarnation_of(&m)
        .with_context(|| format!("{member} is not on the fabric"))?;
    let stop_mark = sim.stop(member, mode).await?;
    // The fixture seam for torn-write cases: the node's files, while it is
    // down.
    let data = sim.data_dir(member)?;
    ensure!(
        data.is_dir(),
        "{member}'s data dir {} is missing while it is stopped",
        data.display()
    );
    sim.start_again(member).await?;
    let incarnation = sim
        .fabric()
        .incarnation_of(&m)
        .with_context(|| format!("{member} is not on the fabric after its restart"))?;
    ensure!(
        incarnation == before + 1,
        "{member} restarted as incarnation {incarnation}, expected {}",
        before + 1
    );
    let attached = sim
        .fabric()
        .attach_position(&m, incarnation)
        .with_context(|| format!("no attach event for {member}'s new incarnation"))?;
    if mode == RestartMode::Crash {
        // Between the crash mark and the new attach, nothing the node wrote
        // may have left it: the crashed daemon was taken off the fabric
        // first. Trace positions bound the window, so a write just before
        // the crash or just after the attach at the same virtual instant
        // falls on its own side.
        let leaked = sim.fabric().writes_from_between(&m, stop_mark..attached);
        ensure!(
            leaked.is_empty(),
            "{} frames left {member} between its crash and its new incarnation",
            leaked.len()
        );
    }
    // The reconnect is awaited inside a barrier. Virtual time is frozen
    // outside barriers, and the restarted node's bootstrap dial needs a
    // handshake round trip of virtual time, so a check made right after the
    // restart can never see it (CI run 37393307134).
    sim.until(
        &format!("a new {owner}~{member} connection after {member}'s restart"),
        secs(60),
        async |s: &Sim| !s.fabric().link_opens_from(&o, &m, attached).is_empty(),
    )
    .await
    .with_context(|| format!("no new {owner}~{member} connection after {member}'s restart"))?;
    wait_seated(
        sim,
        owner,
        member,
        group,
        &format!("{member} seated again after its restart"),
    )
    .await?;
    fresh_group_traffic(sim, group, member, owner).await?;
    sim.fabric().mark(format!(
        "checkpoint: {member} seated again as incarnation {incarnation} after a {mode:?} \
         restart, with group traffic both ways"
    ));
    Ok(())
}

/// Restart B, seated in A's group, in `mode`.
async fn restart_scenario(sim: &mut Sim, mode: RestartMode) -> Result<()> {
    mesh(sim, &["A", "B", "C"]).await?;
    let group = seat(sim, "A", "B").await?;
    restart_member(sim, "A", "B", &group, mode).await
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
    let network = sim
        .state("C")?
        .agent
        .network()
        .cloned()
        .context("C has no network")?;
    // A trace position, not a time: a refusal from before the restart at
    // the same virtual instant must not count for this dial.
    let dial_mark = sim
        .fabric()
        .cut("C dials B by peer id with no known address");
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
        .refused_from(&c, dial_mark)
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

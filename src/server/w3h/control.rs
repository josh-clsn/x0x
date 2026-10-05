//! W3-H S1 controls: the harness itself, before any failure case.
//!
//! - `w3h_clock_gate_*`: virtual time does not move outside a barrier.
//! - `w3h_s1_control_*`: three real daemons, public API only, over the
//!   fabric. The positive control must converge; the negative control
//!   (joiner offline) must not.
//!
//! Daemon controls run only in the Linux isolated namespace (CI `w3h`
//! profile); they are compile-checked elsewhere.

use super::*;
use anyhow::ensure;
use serde_json::json;

async fn members(sim: &Sim, label: &str, group: &str) -> Option<Vec<String>> {
    let (status, info) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    Some(
        info["members"]
            .as_array()?
            .iter()
            .filter_map(|member| member["agent_id"].as_str().map(str::to_string))
            .collect(),
    )
}

async fn mesh(sim: &Sim, labels: &[&str]) -> Result<()> {
    sim.until("mesh up", secs(60), async |s: &Sim| {
        for label in labels {
            if s.connected_peer_count(label).await == 0 {
                return false;
            }
        }
        true
    })
    .await
}

async fn create_group(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({"name": "w3h control", "display_name": owner})),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

async fn invite(sim: &Sim, inviter: &str, group: &str) -> Result<String> {
    let (status, invite) = sim
        .api(
            inviter,
            Method::POST,
            &format!("/groups/{group}/invite"),
            Some(json!({})),
        )
        .await?;
    ensure!(status.is_success(), "invite: {status} {invite}");
    Ok(invite["invite_link"]
        .as_str()
        .context("invite response has no invite_link")?
        .to_string())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w3h_clock_gate_holds_virtual_time_outside_barriers() {
    let start = tokio::time::Instant::now();
    let gate = ClockGate::close();
    let sleeper = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(10)).await });
    // Stay idle for 300 ms of real time with a 10 s virtual timer pending.
    // Without the gate, paused tokio would auto-advance straight to it.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _ = tx.send(());
    });
    rx.await.expect("real-time wake");
    assert_eq!(
        tokio::time::Instant::now(),
        start,
        "virtual time must not move while the gate is closed"
    );
    assert!(!sleeper.is_finished());
    gate.open().await;
    sleeper
        .await
        .expect("sleeper completes once the gate opens");
    assert!(tokio::time::Instant::now() >= start + Duration::from_secs(10));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s1_control_group_invite_join_over_public_api() -> Result<()> {
    let sim = Sim::start(
        "w3h_s1_control_group_invite_join_over_public_api",
        0x5100_0001,
        &["A", "B", "C"],
    )
    .await?;
    mesh(&sim, &["A", "B", "C"]).await?;
    let group = create_group(&sim, "A").await?;
    for joiner in ["B", "C"] {
        let link = invite(&sim, "A", &group).await?;
        let (status, joined) = sim
            .api(
                joiner,
                Method::POST,
                "/groups/join",
                Some(json!({"invite": link, "display_name": joiner})),
            )
            .await?;
        ensure!(
            status.is_success() && joined["ok"] == true,
            "{joiner} join: {status} {joined}"
        );
    }
    let want = [
        sim.agent_hex("A")?,
        sim.agent_hex("B")?,
        sim.agent_hex("C")?,
    ];
    sim.until("A lists A, B and C", secs(180), async |s: &Sim| {
        members(s, "A", &group)
            .await
            .is_some_and(|listed| want.iter().all(|id| listed.contains(id)))
    })
    .await?;
    sim.fabric().mark("checkpoint: membership converged on A");
    sim.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s1_negative_control_offline_joiner_is_not_admitted() -> Result<()> {
    let sim = Sim::start(
        "w3h_s1_negative_control_offline_joiner_is_not_admitted",
        0x5100_0002,
        &["A", "B", "C"],
    )
    .await?;
    mesh(&sim, &["A", "B", "C"]).await?;
    let group = create_group(&sim, "A").await?;
    let link = invite(&sim, "A", &group).await?;
    sim.set_online("C", false)?;
    // C's local join call may succeed (it is queued) or fail; either way
    // the authority must never seat it while C is unreachable.
    let _ = sim
        .api(
            "C",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "C"})),
        )
        .await;
    let c = sim.agent_hex("C")?;
    let admitted = sim
        .until("A lists C (must not happen)", secs(60), async |s: &Sim| {
            members(s, "A", &group)
                .await
                .is_some_and(|listed| listed.contains(&c))
        })
        .await;
    ensure!(admitted.is_err(), "an offline joiner was admitted");
    // Read A's view at the frozen instant after the barrier closed.
    let listed = sim
        .at_instant("A members after the barrier", members(&sim, "A", &group))
        .await?
        .unwrap_or_default();
    ensure!(!listed.contains(&c), "C is not listed: {listed:?}");
    let trace = sim.fabric().canonical_trace();
    ensure!(
        trace.contains("C\n  attached inc=0") && trace.contains("offline@"),
        "the offline fault is in the trace"
    );
    sim.finish().await?;
    Ok(())
}

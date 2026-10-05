//! W3-H S1 controls: the harness itself, before any failure case.
//!
//! - `w3h_clock_gate_*`: virtual time does not move outside a barrier.
//! - `w3h_s1_control_*`: three real daemons, public API only, over the
//!   fabric. The positive control must converge AND deliver group data; the
//!   negative control (joiner offline) must fail for exactly the intended
//!   reason, with every authority read succeeding.
//!
//! The group shape is the live fixture's `private_secure` path
//! (`tests/e2e_vps_private_kv.py` `run_private`): create with the preset,
//! join by invite, open the same `wiki` store on every member, write on
//! the owner, read on the joiners.
//!
//! Daemon controls run only in the Linux isolated namespace (CI `w3h`
//! profile); they are compile-checked elsewhere.

#![cfg(test)]

use super::*;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Percent-encode one path segment (every byte outside RFC 3986's
/// unreserved set), as the live fixture's `urllib.parse.quote(v, safe="")`
/// does. A group store id is its topic, `x0x/group/<gid>/kv/<name>`, so
/// its slashes must not split the `/stores/:id/:key` route.
fn path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The members `label` lists for `group`; `Err` when the read itself fails
/// (non-2xx, or no `members` array).
async fn members(sim: &Sim, label: &str, group: &str) -> Result<Vec<String>> {
    let (status, info) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(status.is_success(), "{label} GET /groups/{group}: {status}");
    Ok(info["members"]
        .as_array()
        .context("no members array")?
        .iter()
        .filter_map(|member| member["agent_id"].as_str().map(str::to_string))
        .collect())
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
            Some(json!({"name": "w3h control", "display_name": owner, "preset": "private_secure"})),
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

async fn join(sim: &Sim, joiner: &str, link: &str) -> Result<()> {
    let (status, joined) = sim
        .api(
            joiner,
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": joiner})),
        )
        .await?;
    ensure!(
        status.is_success() && joined["ok"] != false,
        "{joiner} join: {status} {joined}"
    );
    Ok(())
}

async fn open_store(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, store) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "wiki"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open store: {status} {store}");
    Ok(store["id"].as_str().context("store id")?.to_string())
}

/// `membership_state` of `group` as `label` reports it.
async fn local_membership(sim: &Sim, label: &str, group: &str) -> Option<String> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    body["membership_state"].as_str().map(str::to_string)
}

/// `POST /groups/:id/stores` without a barrier (for use inside one).
async fn try_open_store(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, store) = sim
        .request(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "wiki"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open store: {status} {store}");
    Ok(store["id"].as_str().context("store id")?.to_string())
}

async fn read_value(sim: &Sim, label: &str, store: &str, key: &str) -> Option<String> {
    let (status, body) = sim
        .request(
            label,
            Method::GET,
            &format!("/stores/{}/{}", path_segment(store), path_segment(key)),
            None,
        )
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    let bytes = BASE64.decode(body["value"].as_str()?).ok()?;
    String::from_utf8(bytes).ok()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w3h_clock_gate_holds_virtual_time_outside_barriers() -> Result<()> {
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
    rx.await?;
    ensure!(
        tokio::time::Instant::now() == start,
        "virtual time moved while the gate was closed"
    );
    ensure!(!sleeper.is_finished(), "a 10 s timer fired while gated");
    gate.open().await;
    sleeper.await?;
    ensure!(tokio::time::Instant::now() >= start + Duration::from_secs(10));
    Ok(())
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
        join(&sim, joiner, &link).await?;
    }
    let want = [
        sim.agent_hex("A")?,
        sim.agent_hex("B")?,
        sim.agent_hex("C")?,
    ];
    sim.until("A lists A, B and C", secs(180), async |s: &Sim| {
        members(s, "A", &group)
            .await
            .is_ok_and(|listed| want.iter().all(|id| listed.contains(id)))
    })
    .await?;
    sim.fabric().mark("checkpoint: membership converged on A");

    // Data-plane delivery: one write on A reaches B and C through the
    // group store (the same store id on every member). Each joiner must
    // first be seated locally (`membership_state == active`, the live
    // fixture's local readiness) and able to open the store, which needs
    // the group key; both are awaited inside named barriers.
    for member in ["B", "C"] {
        sim.until(
            &format!("{member} reports active membership"),
            secs(120),
            async |s: &Sim| local_membership(s, member, &group).await.as_deref() == Some("active"),
        )
        .await?;
    }
    let store = open_store(&sim, "A", &group).await?;
    for member in ["B", "C"] {
        let mut opened = None;
        let mut last = String::new();
        sim.until(
            &format!("{member} opens the group store"),
            secs(60),
            async |s: &Sim| match try_open_store(s, member, &group).await {
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
        .with_context(|| format!("{member} last store-open error: {last}"))?;
        ensure!(
            opened.as_deref() == Some(store.as_str()),
            "{member} opened a different store id: {opened:?}"
        );
    }
    let (status, put) = sim
        .api(
            "A",
            Method::PUT,
            &format!("/stores/{}/w3h-control", path_segment(&store)),
            Some(json!({"value": BASE64.encode("delivered"), "content_type": "text/plain"})),
        )
        .await?;
    ensure!(status.is_success(), "A put: {status} {put}");
    sim.until("B and C read A's write", secs(120), async |s: &Sim| {
        read_value(s, "B", &store, "w3h-control").await.as_deref() == Some("delivered")
            && read_value(s, "C", &store, "w3h-control").await.as_deref() == Some("delivered")
    })
    .await?;
    sim.fabric()
        .mark("checkpoint: group data delivered to B and C");
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
    let c_peer = sim.peer("C")?;
    let offline_at = sim.fabric().now();
    sim.set_online("C", false)?;
    // The join is a valid local attempt: C accepts it and queues the
    // request (the handler's only refusals are local durability/signing).
    join(&sim, "C", &link).await?;
    let c = sim.agent_hex("C")?;
    let mut read_failures = 0usize;
    let mut reads = 0usize;
    let admitted = sim
        .until("A lists C (must not happen)", secs(60), async |s: &Sim| {
            reads += 1;
            match members(s, "A", &group).await {
                Ok(listed) => listed.contains(&c),
                Err(_) => {
                    read_failures += 1;
                    false
                }
            }
        })
        .await;
    ensure!(admitted.is_err(), "an offline joiner was admitted");
    ensure!(
        reads > 0 && read_failures == 0,
        "A's roster reads must succeed for the whole window ({read_failures} of {reads} failed)"
    );
    // A's view at the frozen instant after the barrier closed.
    let listed = sim
        .at_instant("A members after the barrier", members(&sim, "A", &group))
        .await??;
    ensure!(!listed.contains(&c), "C is listed: {listed:?}");
    // The intended refusal: the transport refused C's attempts (dials or
    // sends) and nothing C wrote after going offline was delivered.
    let refused = sim.fabric().refused_since(&c_peer, offline_at);
    let delivered = sim.fabric().delivered_from_since(&c_peer, offline_at);
    ensure!(
        !refused.is_empty(),
        "C's join produced no transport refusal; the window did not exercise the fault"
    );
    ensure!(
        delivered.is_empty(),
        "{} frames from C were delivered while it was offline",
        delivered.len()
    );
    sim.fabric().mark(format!(
        "checkpoint: C refused {} times, 0 frames delivered",
        refused.len()
    ));
    sim.finish().await?;
    Ok(())
}

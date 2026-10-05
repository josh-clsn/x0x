//! W3-H S2: #1143 / ADR 0108 `s2_home_anonymous_owner_offline`.
//!
//! Nodes: O (owner device, Home creator), X (holder/member), A (promoted
//! admin), J (joiner); all are same-owner devices, set up through the
//! public API exactly as the live Home fixture does.
//!
//! - t0: O provisions the Home; X and A are seated by O; O promotes A.
//!   Evidence: A holds O's certificate bytes on O's seat, matching the
//!   committed digest (delivered through the real member path).
//! - t1: O announces. In the red case the announce is anonymous (O never
//!   consented — the live mechanism); A must have ingested it. Then A mints
//!   J's seat invite and O goes offline.
//! - t2: J redeems A's invite. Desired (ADR 0108 S2): A seals and J becomes
//!   Active without O. On main A refuses: `OwnerCertMemberPending` naming
//!   O, although A holds O's bytes (`owner_cert_verdict` treats the
//!   anonymous announce as contradicting the embedded certificate,
//!   `groups/mod.rs:1462,1575`).
//!
//! Three tests share the scenario:
//! - `w3h_1143_red_baseline_reproduces_owner_cert_member_pending` (runs on
//!   main): passes only if the run's receipt is RED — every stage present
//!   and the exact cause observed. ADR 0108 S2's PR deletes it.
//! - `w3h_1143_positive_control_consented_owner_announce_admits` (runs on
//!   main): the only change is that O's announce carries its consented
//!   user identity (the documented #1143 workaround); J must be admitted.
//! - `w3h_red_1143_promoted_admin_admits_with_owner_offline` (ignored until
//!   ADR 0108 S2): the desired behaviour; S2 removes the `#[ignore]`.

#![cfg(test)]

use super::home::{membership_state, roster, HomeIds};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::{AgentId, UserKeypair};
use anyhow::ensure;
use serde_json::json;

const SEED: u64 = 0x1143_0001;
const JOIN_BUDGET: Duration = Duration::from_secs(180);
const SEAL_REFUSAL: &str = "failed to seal authoritative add";
const PENDING_CAUSE: &str = "pending certificate resolution";
const FINAL: &str = "j_active_within_180s_with_o_offline";

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnerAnnounce {
    /// What every owner device does today (no consent): the #1143 trigger.
    Anonymous,
    /// The documented workaround: a consented user-identity announce.
    Consented,
}

fn agent_id(hex_id: &str) -> Result<AgentId> {
    let bytes = <[u8; 32]>::try_from(hex::decode(hex_id)?)
        .map_err(|_| anyhow!("agent id is not 32 bytes"))?;
    Ok(AgentId(bytes))
}

/// A holds O's certificate bytes on O's seat, and they match the seat's
/// committed digest.
async fn admin_holds_owner_certificate(sim: &Sim, home: &HomeIds) -> Result<(bool, String)> {
    let admin = sim.state("A")?;
    let owner_hex = sim.agent_hex("O")?;
    let gid = home.gid.clone();
    sim.at_instant("peek A's seat for O", async move {
        let groups = admin.named_groups.read().await;
        let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, &gid) else {
            return (false, "A has no entry for the Home".to_string());
        };
        let Some(seat) = info.members_v2.get(&owner_hex) else {
            return (false, "A's roster has no seat for O".to_string());
        };
        match (&seat.certificate, &seat.certificate_digest) {
            (Some(cert), Some(digest)) => {
                let held = crate::groups::owner_cert::certificate_digest_hex(cert);
                (
                    held.eq_ignore_ascii_case(digest),
                    format!("bytes digest {held}, committed {digest}"),
                )
            }
            (None, digest) => (false, format!("digest-only seat ({digest:?})")),
            (Some(_), None) => (false, "bytes without a committed digest".to_string()),
        }
    })
    .await
}

/// A's discovery entry for O carries the announce `kind` asked for.
async fn admin_saw_owner_announce(sim: &Sim, kind: OwnerAnnounce) -> Result<bool> {
    let admin = sim.state("A")?;
    let owner = agent_id(&sim.agent_hex("O")?)?;
    let anonymous = crate::announce_v3::cert_digest(&None, &None);
    let entry = admin.agent.discovered_agent(owner).await.ok().flatten();
    Ok(entry.is_some_and(|entry| match kind {
        OwnerAnnounce::Anonymous => {
            entry.cert_digest == Some(anonymous) && entry.agent_certificate.is_none()
        }
        OwnerAnnounce::Consented => {
            entry.agent_certificate.is_some() && entry.cert_digest != Some(anonymous)
        }
    }))
}

async fn scenario(sim: &mut Sim, kind: OwnerAnnounce, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    // t0: Home with O, X, A; A promoted.
    let owner = UserKeypair::generate()?;
    let home = sim.start_owner_device("O", &owner).await?;
    for device in ["X", "A", "J"] {
        sim.certify_owner_device("O", device, &owner, &home).await?;
    }
    for member in ["X", "A"] {
        let invite = sim.home_seat("O", member, &home).await?;
        ensure!(
            sim.join_home("O", member, &home, &invite, JOIN_BUDGET)
                .await?,
            "setup: O could not seat {member}"
        );
    }
    sim.promote_admin("O", "A", &home, &["A", "X"]).await?;
    receipt.setup_done(at(sim));

    let (holds, detail) = admin_holds_owner_certificate(sim, &home).await?;
    receipt.evidence("a_holds_owner_certificate_bytes", holds, detail, at(sim));

    // t1: O announces (anonymous, or consented in the positive control).
    let announce = match kind {
        OwnerAnnounce::Anonymous => json!({"include_user_identity": false}),
        OwnerAnnounce::Consented => {
            json!({"include_user_identity": true, "human_consent": true})
        }
    };
    let (status, body) = sim
        .api("O", Method::POST, "/announce", Some(announce))
        .await?;
    ensure!(status.is_success(), "O announce: {status} {body}");
    let seen = sim
        .until("A ingests O's announce", secs(60), async |s: &Sim| {
            admin_saw_owner_announce(s, kind).await.unwrap_or(false)
        })
        .await
        .is_ok();
    receipt.evidence(
        match kind {
            OwnerAnnounce::Anonymous => "a_saw_anonymous_owner_announce",
            OwnerAnnounce::Consented => "a_saw_consented_owner_announce",
        },
        seen,
        "",
        at(sim),
    );

    let invite = sim.home_seat("A", "J", &home).await?;
    sim.set_online("O", false)?;

    // t2: J redeems A's invite with O offline.
    let join_from = sim.fabric().now();
    let admitted = sim.join_home("A", "J", &home, &invite, JOIN_BUDGET).await?;
    let delivered = sim
        .fabric()
        .delivered_since(&sim.peer("J")?, &sim.peer("A")?, join_from);
    receipt.request_delivered(
        "j_join_request_reached_a",
        !delivered.is_empty(),
        format!(
            "{} frames J->A delivered after the join call",
            delivered.len()
        ),
        at(sim),
    );
    if !admitted {
        let owner_hex = sim.agent_hex("O")?;
        let refusal = sim
            .logs_containing(&[SEAL_REFUSAL, PENDING_CAUSE, &format!("[\"{owner_hex}\"]")])
            .into_iter()
            .find(|log| log.at >= join_from);
        receipt.cause(
            "OwnerCertMemberPending{members=[O]} from A's seal",
            refusal.as_ref().map(|log| log.text.clone()),
            refusal.is_some(),
            at(sim),
        );
        // Context for the receipt reader: what A and J report.
        let a_rows = roster(sim, "A", &home.gid).await.unwrap_or_default();
        let j_state = membership_state(sim, "J", &home.gid).await;
        sim.fabric().mark(format!(
            "observed: A lists {} members, J membership_state={j_state:?}",
            a_rows.len()
        ));
    }
    receipt.finish(FINAL, admitted, at(sim));
    Ok(())
}

/// Run the scenario once and return its emitted receipt. Any error before
/// the final assertion is recorded as INFRA.
async fn run(case: &str, kind: OwnerAnnounce) -> Receipt {
    let mut receipt = Receipt::new(case, SEED);
    receipt.note(
        "sim byte streams (EvidenceV1 hello, SyncV1 owner sync) are in-memory \
         pipes with zero latency and no QUIC flow control (W3-H S4)",
    );
    match Sim::empty(case, SEED) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, kind, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1143_red_baseline_reproduces_owner_cert_member_pending() -> Result<()> {
    let receipt = run(
        "w3h_1143_red_baseline_reproduces_owner_cert_member_pending",
        OwnerAnnounce::Anonymous,
    )
    .await;
    ensure!(
        receipt.verdict() == Some(Verdict::Red),
        "expected a RED receipt on main, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1143_positive_control_consented_owner_announce_admits() -> Result<()> {
    let receipt = run(
        "w3h_1143_positive_control_consented_owner_announce_admits",
        OwnerAnnounce::Consented,
    )
    .await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "the consented-announce control must admit J, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore = "red baseline: enable with ADR 0108 S2 (#1143)"]
async fn w3h_red_1143_promoted_admin_admits_with_owner_offline() -> Result<()> {
    let receipt = run(
        "w3h_red_1143_promoted_admin_admits_with_owner_offline",
        OwnerAnnounce::Anonymous,
    )
    .await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "ADR 0108 S2: A must admit J with O offline; receipt verdict {:?}",
        receipt.verdict()
    );
    Ok(())
}

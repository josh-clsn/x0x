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

/// A's view of O, computed exactly as A's seal computes it, read-only:
/// the same evidence builder with the same inputs as
/// `owner_cert_seal_evidence` (every active member and the local agent,
/// each with its seat digest, through `owner_cert_evidence_for_with_digests`),
/// and the same verdict (`GroupInfo::owner_cert_verdict`, run on a CLONE of
/// A's Home record because it updates grace state). O's verdict is `Clean`
/// when the resolved certificate passes the owner check, or when the seat's
/// embedded certificate passes it and is not stale; stale means O's latest
/// announced digest differs from the embedded certificate's digest.
///
/// All digests here are announce digests: `blake3(bincode((user_id,
/// certificate)))` (`announce_v3::cert_digest`), never the roster seat
/// digest (`blake3(certificate bytes)`).
struct OwnerView {
    /// O's latest announced digest as A's seal evidence holds it.
    announced: Option<[u8; 32]>,
    /// The digest O's consented announce commits to: O's own user id and
    /// agent certificate, as `build_identity_announcement` takes them.
    published: [u8; 32],
    /// The certificate the seal evidence resolves for O: (digest, passes).
    resolved: Option<([u8; 32], bool)>,
    /// A's seat certificate for O: (digest, passes).
    embedded: Option<([u8; 32], bool)>,
    /// O's status in the verdict.
    status: String,
}

impl OwnerView {
    fn stale(&self) -> bool {
        matches!((self.embedded, self.announced), (Some((digest, _)), Some(announced)) if digest != announced)
    }

    /// Which certificate made the verdict `Clean`, per the verdict's own
    /// rule, with its digest.
    fn clean_by(&self) -> Option<(&'static str, [u8; 32])> {
        match (self.resolved, self.embedded) {
            (Some((digest, true)), _) => Some(("resolved", digest)),
            (_, Some((digest, true))) if !self.stale() => Some(("seat", digest)),
            _ => None,
        }
    }

    fn detail(&self) -> String {
        let hex8 = |digest: [u8; 32]| hex::encode(&digest[..8]);
        let cert = |cert: Option<([u8; 32], bool)>| {
            cert.map_or("none".to_string(), |(digest, ok)| {
                format!("{} owner_check={ok}", hex8(digest))
            })
        };
        format!(
            "announced {}; O publishes {}; anonymous {}; resolved {}; seat {} stale={}; \
             verdict {} via {}",
            self.announced.map_or("none".to_string(), hex8),
            hex8(self.published),
            hex8(crate::announce_v3::anonymous_cert_digest()),
            cert(self.resolved),
            cert(self.embedded),
            self.stale(),
            self.status,
            self.clean_by().map_or("none", |(by, _)| by),
        )
    }
}

async fn admin_view_of_owner(sim: &Sim, home: &HomeIds) -> Result<OwnerView> {
    let admin = sim.state("A")?;
    let owner_hex = sim.agent_hex("O")?;
    let published = {
        let o = sim.state("O")?;
        crate::announce_v3::cert_digest(&o.agent.user_id(), &o.agent.agent_certificate().cloned())
    };
    let info = {
        let groups = admin.named_groups.read().await;
        let (_, info) = crate::server::resolve_group_entry_locked(&groups, &home.gid)
            .context("A has no entry for the Home")?;
        info.clone()
    };
    let owner = *info
        .policy
        .admission
        .owner_certified_user_id()
        .context("the Home is not owner-certified")?;
    // `owner_cert_seal_evidence`: every active member and the local agent,
    // each with its seat digest.
    let local_hex = hex::encode(admin.agent.agent_id().as_bytes());
    let mut agents: Vec<String> = info.active_members().map(|m| m.agent_id.clone()).collect();
    if !agents.iter().any(|a| a.eq_ignore_ascii_case(&local_hex)) {
        agents.push(local_hex);
    }
    let with_digests: Vec<(String, Option<String>)> = agents
        .into_iter()
        .map(|agent| {
            let digest = info
                .members_v2
                .get(&agent)
                .and_then(|seat| seat.certificate_digest.clone());
            (agent, digest)
        })
        .collect();
    let evidence = crate::server::routes::named_groups::owner_cert_evidence_for_with_digests(
        &admin,
        &with_digests,
    )
    .await;
    let now = evidence.now_unix();
    let assess = |cert: &crate::identity::AgentCertificate| {
        (
            crate::announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone())),
            crate::groups::owner_cert::verify_cert_against_owner(
                &owner, &owner_hex, cert, false, now,
            )
            .is_ok(),
        )
    };
    let resolved = evidence.cert_for(&owner_hex).map(assess);
    let embedded = info
        .members_v2
        .get(&owner_hex)
        .and_then(|seat| seat.certificate.as_ref())
        .map(assess);
    let mut clone = info;
    let status = clone
        .owner_cert_verdict(&evidence)
        .per_member
        .get(&owner_hex)
        .map_or("absent".to_string(), |status| format!("{status:?}"));
    Ok(OwnerView {
        announced: evidence.digest_for(&owner_hex),
        published,
        resolved,
        embedded,
        status,
    })
}

/// Whether A's view of O is the one the announce `kind` should produce:
/// - anonymous: O's latest announced digest at A is the anonymous one and
///   the verdict does not seat O as clean (the #1143 precondition);
/// - consented: O's latest announced digest at A is the digest O's
///   consented announce publishes (not the anonymous one), the verdict
///   seats O as clean, and the certificate that made it clean commits to
///   that same digest.
fn view_matches(view: &OwnerView, kind: OwnerAnnounce) -> bool {
    let anonymous = crate::announce_v3::anonymous_cert_digest();
    let clean = view.status == "Clean";
    match kind {
        OwnerAnnounce::Anonymous => view.announced == Some(anonymous) && !clean,
        OwnerAnnounce::Consented => {
            view.published != anonymous
                && view.announced == Some(view.published)
                && clean
                && view
                    .clean_by()
                    .is_some_and(|(_, digest)| Some(digest) == view.announced)
        }
    }
}

/// Whether `bytes`, as written on a direct lane, is `joiner`'s join
/// `fetch_request` for `gid` naming itself as the member: a direct message
/// (`[stream type][sender agent id (32)][JSON]`) whose sender is the joiner
/// and whose body is `{"type":"fetch_request","group_id":gid,
/// "member_agent_id":joiner,…}`.
fn join_fetch_request(bytes: &[u8], gid: &str, joiner: &AgentId) -> bool {
    if bytes.get(1..33) != Some(joiner.as_bytes().as_slice()) {
        return false;
    }
    let Some(Ok(body)) = bytes
        .get(33..)
        .map(serde_json::from_slice::<serde_json::Value>)
    else {
        return false;
    };
    body["type"] == "fetch_request"
        && body["group_id"] == gid
        && body["member_agent_id"] == hex::encode(joiner.as_bytes())
}

async fn scenario(sim: &mut Sim, kind: OwnerAnnounce, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    // t0: Home with O, X, A; A promoted.
    // Before any daemon starts, like the node keys (`Sim::empty`).
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
    let mut view = None;
    let mut failure = None;
    let waited = sim
        .until(
            "A's view of O matches O's announce",
            secs(60),
            async |s: &Sim| match admin_view_of_owner(s, &home).await {
                Ok(seen) => {
                    let matched = view_matches(&seen, kind);
                    view = Some(seen);
                    matched
                }
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
        )
        .await;
    if let Some(error) = failure {
        return Err(error.context("INFRA: reading A's view of O"));
    }
    match &waited {
        Ok(()) => {}
        Err(error) if expired(error) => {}
        Err(_) => return waited.context("waiting for A's view of O"),
    }
    let matched = view.as_ref().is_some_and(|seen| view_matches(seen, kind));
    receipt.evidence(
        match kind {
            OwnerAnnounce::Anonymous => "a_holds_anonymous_owner_evidence",
            OwnerAnnounce::Consented => "a_resolves_consented_owner_certificate",
        },
        matched,
        view.as_ref()
            .map_or("no observation".to_string(), OwnerView::detail),
        at(sim),
    );

    let invite = sim.home_seat("A", "J", &home).await?;
    sim.set_online("O", false)?;

    // t2: J redeems A's invite with O offline.
    let join_from = sim.fabric().now();
    let admitted = sim.join_home("A", "J", &home, &invite, JOIN_BUDGET).await?;
    // The request: J's join `fetch_request` for this group, naming J,
    // delivered to A after the join call.
    let j_agent = sim.state("J")?.agent.agent_id();
    let requests: Vec<Duration> = sim
        .fabric()
        .delivered_writes_since(&sim.peer("J")?, &sim.peer("A")?, join_from)
        .into_iter()
        .filter(|(write, _)| {
            write.lane.class == crate::network::sim::LaneClass::Direct
                && join_fetch_request(&write.bytes, &home.gid, &j_agent)
        })
        .map(|(_, delivered_at)| delivered_at)
        .collect();
    let first_request = requests.iter().min().copied();
    receipt.request_delivered(
        "j_join_fetch_request_reached_a",
        first_request.is_some(),
        format!(
            "{} J->A fetch_request messages for this group naming J delivered after the \
             join call; first at {:?}us",
            requests.len(),
            first_request.map(|t| t.as_micros())
        ),
        at(sim),
    );
    if !admitted {
        // The cause: the seal refusal for THIS group and THIS joiner, naming
        // exactly [O], logged after J's request reached A. Logs carry no
        // emitter; A is the only online admin that can seal J's add.
        let owner_hex = sim.agent_hex("O")?;
        let j_hex = sim.agent_hex("J")?;
        let j_tokens = [
            crate::logging::LogHexId::agent(j_hex.as_str()).to_string(),
            crate::logging::LogHexId::agent(j_hex.to_uppercase().as_str()).to_string(),
        ];
        let refusal = sim
            .logs_containing(&[
                SEAL_REFUSAL,
                PENDING_CAUSE,
                &format!("[\"{owner_hex}\"]"),
                &format!("group {}", home.gid),
            ])
            .into_iter()
            .filter(|log| {
                j_tokens
                    .iter()
                    .any(|token| log.text.contains(&format!("member={token}")))
            })
            .find(|log| first_request.is_some_and(|first| log.at >= first));
        receipt.cause(
            "OwnerCertMemberPending{members=[O]} from A's seal",
            refusal.as_ref().map(|log| log.text.clone()),
            refusal.is_some(),
            at(sim),
        );
        // Context for the receipt reader: what A and J report.
        let a_rows = roster(sim, "A", &home.gid).await.unwrap_or_default();
        let j_state = membership_state(sim, "J", &home.gid).await.ok().flatten();
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
    match Sim::empty(case, SEED, &["O", "X", "A", "J"]) {
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

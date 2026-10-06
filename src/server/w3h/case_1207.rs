//! W3-H S0 for #1207 (lane S; plan `.planning/team-2026-10-05/s-1207-plan.md`
//! §S0): a restarted joiner H, invited by the admin N while the owner O is
//! offline, never fetches N's staged join artifacts, because the
//! relationship Hello that would give H a verified binding for N's machine
//! is never sent.
//!
//! # Shape
//!
//! Nodes N (admin; node 0, so every node's bootstrap peer), O (owner of
//! both groups) and H (the joiner); the third-holder control adds T. No
//! node has a contact for another (Unknown trust throughout).
//!
//! - G0, owned by O, seats N and H (and T). It is the shared active group
//!   the eph incident's joiner had with its admin (the gss group): the
//!   relationship H needs to STORE N's Hello (`peer_evidence` stores
//!   relationship evidence only, `evidence_wire.rs:504`), because H's own
//!   seat in the group it is joining becomes active only after the Welcome
//!   it cannot fetch (named_groups.rs:12151-12304).
//! - P, owned by O, `private_secure` (TreeKEM): O seats N and promotes it
//!   to admin; N mints H's invite. O then goes offline.
//! - H restarts (real same-directory restart, `Sim::restart`). Its
//!   bootstrap dial reconnects it to N at once: the connect position.
//!
//! Two fault rules stage the nodes' signed identity artifacts (identity,
//! machine and rendezvous announcements; capability adverts):
//! - N's artifacts never reach H (from before anything starts). No
//!   periodic identity refresh, heartbeat, advert or anti-entropy replay can
//!   give H N's mapping; only a Hello (or an authorized Lookup) can.
//! - H's artifacts reach N only when the case releases them: the rule is
//!   lifted and H re-announces (`POST /announce`). That is "discovery". H's
//!   capability adverts stay staged, so N never DMs H over gossip.
//!
//! The rule drops a pubsub frame to the target that carries one of the
//! artifact topics and the subject's agent id; every such frame is one
//! message with one subject (checked on the S1 payload dumps).
//!
//! # Why roster-first is the failure shape
//!
//! At the connect position neither side is eligible
//! (`evidence_wire::Context::related`, evidence_wire.rs:631-667): H has no
//! discovery entry and no stored record for N's machine; N has the G0
//! relationship but no discovery entry for H. `begin_hello` then sends
//! nothing (evidence_wire.rs:322-343) and nothing revisits the skipped
//! Hello (the event loop reacts only to `PeerConnected`, :1055-1071).
//!
//! - Roster first (the red baseline): H redeems N's invite; N commits H's
//!   P seat (the "committed roster"), stages the result and the Welcome,
//!   and its pushes to H fail (no binding, no capability). Past the push
//!   window, discovery is released: N is now eligible, but no Hello
//!   follows. H cannot resolve N for its Welcome fetch: no discovery entry
//!   or registry entry (lib.rs:8815-8833), no advert (lib.rs:7432), no
//!   stored evidence, and no Lookup responder (lookup.rs:238-279: no
//!   connected machine names N, no own-host hint). The join poll times out
//!   at 120 s (named_groups.rs:33763, :37946).
//! - Discovery first: N learns H's mapping before its commit, so its
//!   commit-time `MemberAdded` push reaches H as a raw DM. H's raw receive
//!   records an own-host hint and spawns a Lookup (lib.rs:4489-4511,
//!   runtime.rs:228-231) that N answers for itself (lookup.rs:264-277,
//!   281-302), with the G0 relationship on both sides. Predicted GREEN on
//!   main, so this order is a control, not a baseline: the daemon already
//!   recovers it (UNVERIFIED until CI).
//! - No mapping on either side: discovery is never released. No Hello is
//!   possible in either direction, even with S1 (needs a Proposed ADR per
//!   the plan's "Alternatives"); RED with and without S1.
//!
//! # Controls (GREEN on main)
//!
//! - Admin knows joiner: H's artifacts reach N normally, so N is eligible
//!   at the connect and sends the Hello.
//! - Intact persisted evidence: H restarts once while N knows it (N's
//!   Hello stores N's record at H), then restarts again with that record
//!   on disk: H is eligible at the second connect.
//! - Authorized third holder: T, a G0 member that holds N's live record
//!   and knows H (both from Hellos at T's own restart), answers H's
//!   Lookup for N (lookup.rs:281-302, :496-508).
//!
//! # GREEN, RED, flag
//!
//! GREEN needs, within the join poll's 120 s: verified admin evidence at H,
//! guarded join-result delivery (H's seat active, which for TreeKEM needs
//! the Welcome from N) and a decrypted group write from N. RED needs every
//! precondition plus the named causes: no Hello between H and N after the
//! connect, none of H's requests reaching N on any DM transport (direct,
//! relayed or gossip inbox), and no admin evidence or binding at H.
//!
//! The `w3h_red_1207_ready_hello_*` tests set `X0X_EVIDENCE_READY_HELLO=1`
//! (#1251, S1's operational opt-in, read at daemon startup) before any
//! daemon starts. They are ignored until S1 merges: on main the variable is
//! read by nothing, so the arm would be RED.
//!
//! Every ordering below is a trace position (`SimFabric::cut`), never a
//! virtual time. Receipts carry ids, digests and counts, never secrets or
//! certificates.

#![cfg(test)]

use super::control::{
    create_group, invite, join, local_membership, members, mesh, open_store, put_value, read_value,
    try_open_store,
};
use super::home::roster;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fate, Fault, Key, LaneClass, LaneKey};
use anyhow::ensure;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

/// S1's operational opt-in (#1251), read at daemon startup.
const READY_HELLO_ENV: &str = "X0X_EVIDENCE_READY_HELLO";
/// The TreeKEM join-result poll's deadline (`JOIN_RESULT_POLL_TIMEOUT`).
const JOIN_BOUND: Duration = Duration::from_secs(120);
/// N pushes `MemberAdded` to H at its commit and again after
/// `GROUP_BACKGROUND_PUBLISH_DELAY` (8 s); a roster-first release waits
/// past both.
const PUSH_WINDOW: Duration = Duration::from_secs(12);
/// An evidence connect job waits up to 5 s for the node's own advert
/// before it decides on the Hello (`evidence_wire.rs` `DEADLINE`).
const CONNECT_SETTLE: Duration = Duration::from_secs(6);
/// Budget for every setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// `StreamProtocol::EvidenceV1` and the `evidence_wire.rs` message kinds.
const EVIDENCE_V1: u8 = 0x06;
const HELLO: u8 = 1;
const LOOKUP: u8 = 2;
const CERTIFICATE: u8 = 3;
const NOT_FOUND: u8 = 4;
const ACK: u8 = 5;
const FOUND: u8 = 6;
/// Signed identity artifacts a node publishes about itself.
const IDENTITY_TOPICS: &[&[u8]] = &[
    b"x0x.identity.announce",
    b"x0x.machine.announce",
    b"x0x.rendezvous",
];
const CAPS_TOPICS: &[&[u8]] = &[b"x0x/caps"];
const ALL_TOPICS: &[&[u8]] = &[
    b"x0x.identity.announce",
    b"x0x.machine.announce",
    b"x0x.rendezvous",
    b"x0x/caps",
];
const FINAL: &str = "h_active_with_admin_evidence_and_decrypt_within_join_bound";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    /// N commits H's seat, then (past the push window) learns H's mapping.
    RosterThenDiscovery,
    /// N learns H's mapping, then commits H's seat.
    DiscoveryThenRoster,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Race(Order),
    NoMapping,
    AdminKnowsJoiner,
    PersistedEvidence,
    ThirdHolder,
}

impl Variant {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::ThirdHolder => &["N", "O", "T", "H"],
            _ => &["N", "O", "H"],
        }
    }

    /// Whether H's artifacts are withheld from N from the start.
    fn h_staged(self) -> bool {
        !matches!(self, Self::AdminKnowsJoiner | Self::PersistedEvidence)
    }

    /// Whether the run's verdict is decided by the RED causes.
    fn red_shape(self) -> bool {
        matches!(
            self,
            Self::Race(Order::RosterThenDiscovery) | Self::NoMapping
        )
    }
}

/// A fault rule that withholds `subject`'s signed artifacts on `topics`
/// from `toward` while held.
struct Stage {
    held: Arc<AtomicBool>,
}

impl Stage {
    fn install(
        sim: &Sim,
        subject: &str,
        toward: &str,
        topics: &'static [&'static [u8]],
        held: bool,
    ) -> Result<Self> {
        let (subject_agent, _) = sim.ids(subject)?;
        let (_, toward_machine) = sim.ids(toward)?;
        let flag = Arc::new(AtomicBool::new(held));
        let rule_flag = Arc::clone(&flag);
        sim.fabric().add_rule(move |write| {
            let staged = rule_flag.load(Ordering::SeqCst)
                && write.lane.dst == toward_machine.0
                && write.lane.class == LaneClass::PubSub
                && topics.iter().any(|topic| contains(&write.bytes, topic))
                && contains(&write.bytes, &subject_agent.0);
            if staged {
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held: flag })
    }

    fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn hex8(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
}

/// The test binary's SHA-256 (the exact code under test). Hashing the
/// unoptimised test binary takes seconds, so the first run per binary
/// caches it in the trace dir, keyed by the binary's size and mtime; later
/// runs (each test is its own process) reuse it.
fn binary_sha256() -> String {
    use sha2::Digest as _;
    let compute = || -> std::io::Result<(String, String)> {
        let exe = std::env::current_exe()?;
        let meta = std::fs::metadata(&exe)?;
        let mtime = meta
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let key = format!("{} {} {mtime}", exe.display(), meta.len());
        if let Ok(dir) = std::env::var("W3H_TRACE_DIR") {
            let cache = std::path::Path::new(&dir).join("binary.sha256");
            if let Some((cached_key, sha)) = std::fs::read_to_string(&cache).ok().and_then(|text| {
                text.rsplit_once(' ')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            }) {
                if cached_key == key {
                    return Ok((key, sha));
                }
            }
            let sha = hex::encode(sha2::Sha256::digest(std::fs::read(&exe)?));
            let tmp = cache.with_extension(format!("{}.tmp", std::process::id()));
            if std::fs::write(&tmp, format!("{key} {sha}")).is_ok() {
                let _ = std::fs::rename(&tmp, &cache);
            }
            return Ok((key, sha));
        }
        Ok((key, hex::encode(sha2::Sha256::digest(std::fs::read(&exe)?))))
    };
    match compute() {
        Ok((key, sha)) => format!("{sha} ({key})"),
        Err(error) => format!("unreadable: {error}"),
    }
}

/// One endpoint's view of the other, from the inputs
/// `evidence_wire::Context::related` reads (evidence_wire.rs:631-667), plus
/// the sources a send could use.
struct View {
    /// A usable stored record names the peer's machine (`has_machine`).
    stored: bool,
    /// Age (s) of the usable stored record's announcement, if any.
    usable_age: Option<u64>,
    /// A network-verified Hello/advert capture of the peer (TTL-only).
    captured: bool,
    /// The discovery entry for the peer: (age in s, names its machine).
    discovery: Option<(u64, bool)>,
    /// Whether that entry is fresh enough for `related`.
    discovery_fresh: bool,
    /// The relationship policy relates the peer (GROUP, here).
    relation: bool,
    /// The DM registry names the peer's machine.
    registry: bool,
    /// A contact entry exists for the peer.
    contact: bool,
}

impl View {
    fn related(&self) -> bool {
        self.stored || (self.discovery_fresh && self.relation)
    }

    fn json(&self) -> Value {
        json!({
            "related": self.related(),
            "stored": self.stored,
            "usable_age_s": self.usable_age,
            "captured": self.captured,
            "discovery_age_s": self.discovery.map(|(age, _)| age),
            "discovery_names_machine": self.discovery.map(|(_, same)| same),
            "discovery_fresh": self.discovery_fresh,
            "relation": self.relation,
            "registry": self.registry,
            "contact": self.contact,
        })
    }
}

async fn view(sim: &Sim, observer: &str, peer: &str) -> Result<View> {
    let state = sim.state(observer)?;
    let (agent, machine) = sim.ids(peer)?;
    sim.at_instant(&format!("read {observer}'s view of {peer}"), async move {
        let now = crate::dm_capability::now_unix_ms();
        let store = state.agent.peer_evidence().store();
        let entry = state
            .agent
            .identity_discovery_cache
            .read()
            .await
            .get(&agent)
            .cloned();
        let cert = entry.as_ref().and_then(|d| d.agent_certificate.clone());
        let discovery_fresh = entry.as_ref().is_some_and(|d| {
            d.machine_id == machine
                && now / 1000
                    <= d.announced_at
                        .saturating_add(crate::dm_capability::ADVERT_CACHE_TTL_SECS)
                && !d
                    .agent_certificate
                    .as_ref()
                    .is_some_and(|c| c.is_expired(now / 1000))
        });
        let usable_age = state
            .agent
            .peer_evidence()
            .usable_agent(agent, now)
            .map(|v| (now / 1000).saturating_sub(v.announcement.announced_at));
        View {
            stored: store.as_ref().is_some_and(|s| s.has_machine(machine, now)),
            usable_age,
            captured: state
                .agent
                .capability_store
                .evidence_wire
                .get(agent, true, now)
                .is_some(),
            discovery: entry.as_ref().map(|d| {
                (
                    (now / 1000).saturating_sub(d.announced_at),
                    d.machine_id == machine,
                )
            }),
            discovery_fresh,
            relation: store
                .as_ref()
                .is_some_and(|s| s.related(agent, machine, cert.as_ref(), now)),
            registry: state.agent.direct_messaging.get_machine_id(&agent).await == Some(machine),
            contact: state.agent.contact_store.read().await.get(&agent).is_some(),
        }
    })
    .await
}

/// Whether `observer`'s roster seats every one of `members` active in a
/// non-withdrawn `gid`.
async fn seats_active(sim: &Sim, observer: &str, gid: &str, members: &[&str]) -> Result<bool> {
    let state = sim.state(observer)?;
    let mut ids = Vec::new();
    for member in members {
        ids.push(sim.agent_hex(member)?);
    }
    let gid = gid.to_string();
    sim.at_instant(&format!("read {observer}'s seats in {gid}"), async move {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &gid).is_some_and(|(_, info)| {
            !info.withdrawn
                && ids
                    .iter()
                    .all(|id| info.members_v2.get(id).is_some_and(|m| m.is_active()))
        })
    })
    .await
}

/// A node's evidence diagnostics: load readiness and the wire counters.
fn evidence_counters(sim: &Sim, label: &str) -> Result<Value> {
    let state = sim.state(label)?;
    let diagnostics = state.agent.peer_evidence().diagnostics();
    let publishable = crate::dm_capability_service::advert_is_publishable(
        &state.agent.dm_capabilities_tx.borrow(),
    );
    let mut out = json!({ "own_advert_publishable": publishable });
    for key in [
        "evidence_load_complete",
        "evidence_hello_sent",
        "evidence_hello_received",
        "evidence_hello_refused",
        "evidence_lookup_sent",
        "evidence_lookup_served",
        "evidence_lookup_refused",
        "evidence_lookup_unauthorized",
        "evidence_lookup_skipped",
    ] {
        out[key] = diagnostics[key].clone();
    }
    Ok(out)
}

/// One EvidenceV1 stream: who opened it, at which trace position, and the
/// kind byte of its request and of its reply.
struct EvidenceStream {
    opener: Key,
    acceptor: Key,
    position: usize,
    request: Option<u8>,
    reply: Option<u8>,
}

/// Every EvidenceV1 stream opened at a trace position at or after `from`.
fn evidence_streams(sim: &Sim, from: usize) -> Vec<EvidenceStream> {
    let writes = sim.fabric().writes_with_positions();
    let lane_bytes = |lane: LaneKey| {
        let mut on_lane: Vec<_> = writes.iter().filter(|(_, w, _)| w.lane == lane).collect();
        on_lane.sort_by_key(|(_, w, _)| w.seq);
        on_lane
            .iter()
            .flat_map(|(_, w, _)| w.bytes.iter().copied())
            .collect::<Vec<u8>>()
    };
    writes
        .iter()
        .filter(|(position, w, _)| {
            matches!(w.lane.class, LaneClass::Stream(_))
                && w.seq == 0
                && *position >= from
                && w.bytes.first() == Some(&EVIDENCE_V1)
        })
        .map(|(position, open, _)| {
            let reverse = LaneKey {
                src: open.lane.dst,
                dst: open.lane.src,
                class: open.lane.class,
            };
            EvidenceStream {
                opener: open.lane.src,
                acceptor: open.lane.dst,
                position: *position,
                request: lane_bytes(open.lane).get(1).copied(),
                reply: lane_bytes(reverse).first().copied(),
            }
        })
        .collect()
}

fn kind_name(kind: Option<u8>) -> &'static str {
    match kind {
        Some(HELLO) => "HELLO",
        Some(LOOKUP) => "LOOKUP",
        Some(CERTIFICATE) => "CERTIFICATE",
        Some(NOT_FOUND) => "NOT_FOUND",
        Some(ACK) => "ACK",
        Some(FOUND) => "FOUND",
        Some(_) => "other",
        None => "none",
    }
}

/// The EvidenceV1 streams between `a` and `b` (either direction) opened
/// at or after `from`, as `opener->acceptor REQUEST/REPLY@position`.
fn streams_between(sim: &Sim, labels: &Labels, a: &str, b: &str, from: usize) -> Vec<String> {
    let (ka, kb) = (labels.key(a), labels.key(b));
    evidence_streams(sim, from)
        .into_iter()
        .filter(|s| (s.opener == ka && s.acceptor == kb) || (s.opener == kb && s.acceptor == ka))
        .map(|s| {
            format!(
                "{}->{} {}/{}@{}",
                labels.name(s.opener),
                labels.name(s.acceptor),
                kind_name(s.request),
                kind_name(s.reply),
                s.position
            )
        })
        .collect()
}

/// Labels and their machine keys, for naming trace entries.
struct Labels {
    pairs: Vec<(String, Key)>,
}

impl Labels {
    fn of(sim: &Sim, labels: &[&str]) -> Result<Self> {
        let mut pairs = Vec::new();
        for label in labels {
            pairs.push((label.to_string(), sim.ids(label)?.1 .0));
        }
        Ok(Self { pairs })
    }

    fn key(&self, label: &str) -> Key {
        self.pairs
            .iter()
            .find(|(name, _)| name == label)
            .map_or([0; 32], |(_, key)| *key)
    }

    fn name(&self, key: Key) -> String {
        self.pairs
            .iter()
            .find(|(_, k)| *k == key)
            .map_or_else(|| hex8(&key), |(name, _)| name.clone())
    }
}

/// What `src` sent `dst` on each DM transport at or after `from`: direct
/// and relayed DM frames (with their JSON `type`s, and how many the fabric
/// delivered) and gossip-inbox publishes to `dst`'s inbox topic. A request
/// that never resolved a route appears on none of them.
fn dm_sent(sim: &Sim, src: &str, dst: &str, from: usize) -> Result<Value> {
    let (_, src_machine) = sim.ids(src)?;
    let (dst_agent, dst_machine) = sim.ids(dst)?;
    let inbox = crate::dm_inbox::DmInboxService::inbox_topic_name(&dst_agent);
    let mut direct = 0usize;
    let mut delivered = 0usize;
    let mut relayed = 0usize;
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for (position, write, fate) in sim.fabric().writes_with_positions() {
        if position < from || write.lane.src != src_machine.0 {
            continue;
        }
        match write.lane.class {
            LaneClass::Direct if write.lane.dst == dst_machine.0 => {
                direct += 1;
                if matches!(fate, Some(Fate::Delivered { .. })) {
                    delivered += 1;
                }
                *kinds.entry(direct_kind(&write.bytes)).or_default() += 1;
            }
            LaneClass::RelayedDm => relayed += 1,
            _ => {}
        }
    }
    let inbox_publishes = sim
        .fabric()
        .publishes_from(&ant_quic::PeerId(src_machine.0), from)
        .into_iter()
        .filter(|(_, topic)| *topic == inbox)
        .count();
    Ok(json!({
        "direct": direct,
        "direct_delivered": delivered,
        "direct_kinds": kinds,
        "relayed": relayed,
        "gossip_inbox_publishes": inbox_publishes,
    }))
}

/// The application `type` of a direct DM frame
/// (`[stream type][sender agent id (32)][JSON]`), telling the join and
/// Welcome fetches apart.
fn direct_kind(bytes: &[u8]) -> String {
    let Some(Ok(body)) = bytes
        .get(33..)
        .map(serde_json::from_slice::<serde_json::Value>)
    else {
        return "opaque".to_string();
    };
    let kind = body["type"].as_str().unwrap_or("untyped");
    if kind == "fetch_request" && body.get("welcome_id").is_some() {
        "welcome_fetch_request".to_string()
    } else {
        kind.to_string()
    }
}

/// Delivered pubsub frames to `toward` that carry `subject`'s signed
/// artifacts, at or after `from` (the staging must have dropped them all).
fn artifacts_delivered(sim: &Sim, subject: &str, toward: &str, from: usize) -> Result<usize> {
    let (subject_agent, _) = sim.ids(subject)?;
    let (_, toward_machine) = sim.ids(toward)?;
    Ok(sim
        .fabric()
        .writes_with_positions()
        .into_iter()
        .filter(|(position, write, fate)| {
            *position >= from
                && write.lane.dst == toward_machine.0
                && write.lane.class == LaneClass::PubSub
                && matches!(fate, Some(Fate::Delivered { .. }))
                && ALL_TOPICS.iter().any(|topic| contains(&write.bytes, topic))
                && contains(&write.bytes, &subject_agent.0)
        })
        .count())
}

/// Create a `private_secure` group on `owner` and seat each of `members`:
/// the owner lists the member and the member reports itself active.
async fn group_with(sim: &Sim, owner: &str, seat: &[&str]) -> Result<String> {
    let gid = create_group(sim, owner).await?;
    for member in seat {
        let link = invite(sim, owner, &gid).await?;
        join(sim, member, &link).await?;
        let id = sim.agent_hex(member)?;
        sim.until(
            &format!("{member} seated in {owner}'s group"),
            SETUP,
            async |s: &Sim| {
                members(s, owner, &gid).await.is_ok_and(|m| m.contains(&id))
                    && local_membership(s, member, &gid).await.as_deref() == Some("active")
            },
        )
        .await?;
    }
    Ok(gid)
}

/// The scenario's trace positions and observations, for the receipt.
#[derive(Default)]
struct Run {
    restart: usize,
    connect: Option<usize>,
    settled: usize,
    join: usize,
    committed: Option<usize>,
    released: Option<usize>,
    active: bool,
    decrypted: bool,
}

async fn wait_for(
    sim: &Sim,
    what: &str,
    budget: Duration,
    check: impl AsyncFnMut(&Sim) -> bool,
) -> Result<bool> {
    match sim.until(what, budget, check).await {
        Ok(()) => Ok(true),
        Err(error) if expired(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Release H's identity artifacts toward N and wait until N's discovery
/// cache names H's machine.
async fn release_discovery(sim: &Sim, stage: &Stage) -> Result<usize> {
    let position = sim.fabric().cut("release: H's identity artifacts toward N");
    stage.release();
    let (status, body) = sim
        .api("H", Method::POST, "/announce", Some(json!({})))
        .await?;
    ensure!(status.is_success(), "H announce: {status} {body}");
    ensure!(
        wait_for(sim, "N's discovery names H", secs(30), async |s: &Sim| {
            view(s, "N", "H").await.is_ok_and(|v| v.discovery_fresh)
        })
        .await?,
        "INFRA: H's released announcement never reached N's discovery"
    );
    Ok(position)
}

async fn scenario(sim: &mut Sim, variant: Variant, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let all = variant.labels();
    // Before any daemon sends: N's artifacts never reach H; H's reach N
    // only once released (or from the start, in the controls that need N
    // to know H).
    let _n_to_h = Stage::install(sim, "N", "H", ALL_TOPICS, true)?;
    let h_identity = Stage::install(sim, "H", "N", IDENTITY_TOPICS, variant.h_staged())?;
    let _h_caps = Stage::install(sim, "H", "N", CAPS_TOPICS, variant.h_staged())?;
    for label in all {
        sim.start_node_with(label, Provision::default()).await?;
    }
    let labels = Labels::of(sim, all)?;
    mesh(sim, all).await?;

    // G0: the shared active group (O owns it; N, H, and T are members).
    let g0_members: Vec<&str> = all.iter().copied().filter(|l| *l != "O").collect();
    let g0 = group_with(sim, "O", &g0_members).await?;
    for (observer, peer) in [("H", "N"), ("N", "H")] {
        ensure!(
            wait_for(
                sim,
                &format!("{observer}'s G0 seats {peer}"),
                SETUP,
                async |s: &Sim| {
                    seats_active(s, observer, &g0, &[observer, peer])
                        .await
                        .unwrap_or(false)
                }
            )
            .await?,
            "setup: {observer}'s G0 never seated {peer}"
        );
    }
    // P: O seats N, promotes it, and N mints H's invite.
    let p = group_with(sim, "O", &["N"]).await?;
    let n_hex = sim.agent_hex("N")?;
    let (status, body) = sim
        .api(
            "O",
            Method::PATCH,
            &format!("/groups/{p}/members/{n_hex}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(status.is_success(), "promote N: {status} {body}");
    ensure!(
        wait_for(sim, "N sees itself admin of P", SETUP, async |s: &Sim| {
            roster(s, "N", &p).await.is_ok_and(|rows| {
                rows.iter()
                    .any(|(id, role)| *id == n_hex && role == "admin")
            })
        })
        .await?,
        "setup: N never saw its promotion"
    );
    let h_invite = invite(sim, "N", &p).await?;

    // Control setups that need a Hello before the case restart.
    match variant {
        Variant::ThirdHolder => {
            sim.restart("T", RestartMode::Graceful).await?;
            // T bootstraps to N; H normally redials T. If it has not
            // within 10 s, T dials H, so a Hello can run on that link.
            let h_peer = sim.peer("H")?;
            let linked = wait_for(
                sim,
                "T~H linked after T's restart",
                secs(10),
                async |s: &Sim| {
                    let Some(network) = s.state("T").ok().and_then(|t| t.agent.network().cloned())
                    else {
                        return false;
                    };
                    network.is_connected(&h_peer).await
                },
            )
            .await?;
            if !linked {
                let network = sim
                    .state("T")?
                    .agent
                    .network()
                    .cloned()
                    .context("T has no network")?;
                let h_addr = super::sim_addr(sim.node_index("H")?)?;
                sim.within("T dials H", secs(10), network.connect_addr(h_addr))
                    .await?
                    .context("T dials H")?;
            }
            ensure!(
                wait_for(
                    sim,
                    "T holds N's and H's records",
                    SETUP,
                    async |s: &Sim| {
                        let n = view(s, "T", "N")
                            .await
                            .is_ok_and(|v| v.usable_age.is_some());
                        let h = view(s, "T", "H")
                            .await
                            .is_ok_and(|v| v.usable_age.is_some());
                        n && h
                    }
                )
                .await?,
                "setup: T never held both N's and H's records"
            );
        }
        Variant::PersistedEvidence => {
            sim.restart("H", RestartMode::Graceful).await?;
            ensure!(
                wait_for(sim, "H stores N's record", SETUP, async |s: &Sim| {
                    view(s, "H", "N").await.is_ok_and(|v| v.stored)
                })
                .await?,
                "setup: H never stored N's record before its second restart"
            );
        }
        _ => {}
    }
    sim.set_online("O", false)?;
    receipt.setup_done(at(sim));

    // The case restart: H's bootstrap dial reconnects it to N at once.
    let mut run = Run {
        restart: sim.fabric().cut("case: restart H"),
        ..Run::default()
    };
    sim.restart("H", RestartMode::Graceful).await?;
    sim.within(
        "H's connect jobs settle",
        CONNECT_SETTLE + secs(1),
        tokio::time::sleep(CONNECT_SETTLE),
    )
    .await?;
    if variant == Variant::ThirdHolder && sim.connected_peer_count("H").await < 2 {
        let network = sim
            .state("H")?
            .agent
            .network()
            .cloned()
            .context("H has no network")?;
        let t_addr = super::sim_addr(sim.node_index("T")?)?;
        sim.within("H dials T", secs(10), network.connect_addr(t_addr))
            .await?
            .context("H dials T")?;
        sim.within(
            "H~T connect jobs settle",
            CONNECT_SETTLE + secs(1),
            tokio::time::sleep(CONNECT_SETTLE),
        )
        .await?;
    }
    run.settled = sim.fabric().cut("case: connect jobs settled");
    let (h_peer, n_peer) = (sim.peer("H")?, sim.peer("N")?);
    run.connect = sim
        .fabric()
        .link_open_positions(&h_peer, &n_peer, run.restart)
        .first()
        .map(|(position, _)| *position);
    let h_n = view(sim, "H", "N").await?;
    let n_h = view(sim, "N", "H").await?;
    let hello_at_connect = streams_between(sim, &labels, "H", "N", run.restart);
    let g0_h = seats_active(sim, "H", &g0, &["H", "N"]).await?;
    let g0_n = seats_active(sim, "N", &g0, &["N", "H"]).await?;
    let mut at_connect = json!({
        "h_view_of_n": h_n.json(),
        "n_view_of_h": n_h.json(),
        "counters": {"H": evidence_counters(sim, "H")?, "N": evidence_counters(sim, "N")?},
        "g0_seats_h_and_n_active": {"on_h": g0_h, "on_n": g0_n},
    });
    if variant == Variant::ThirdHolder {
        at_connect["t_view_of_n"] = view(sim, "T", "N").await?.json();
        at_connect["t_view_of_h"] = view(sim, "T", "H").await?.json();
        at_connect["h_view_of_t"] = view(sim, "H", "T").await?.json();
        at_connect["counters"]["T"] = evidence_counters(sim, "T")?;
    }

    // Releases and the join.
    if variant == Variant::Race(Order::DiscoveryThenRoster) {
        run.released = Some(release_discovery(sim, &h_identity).await?);
    }
    run.join = sim.fabric().cut("case: H redeems N's invite");
    let join_started = sim.fabric().now();
    join(sim, "H", &h_invite).await?;
    let h_hex = sim.agent_hex("H")?;
    if wait_for(sim, "N commits H's seat in P", secs(60), async |s: &Sim| {
        members(s, "N", &p).await.is_ok_and(|m| m.contains(&h_hex))
    })
    .await?
    {
        run.committed = Some(sim.fabric().cut("case: N lists H in P"));
    }
    if variant == Variant::Race(Order::RosterThenDiscovery) && run.committed.is_some() {
        sim.within(
            "N's commit push window",
            PUSH_WINDOW + secs(1),
            tokio::time::sleep(PUSH_WINDOW),
        )
        .await?;
        run.released = Some(release_discovery(sim, &h_identity).await?);
    }
    let n_h_released = view(sim, "N", "H").await?;
    let elapsed = sim.fabric().now().saturating_sub(join_started);
    let remaining = (JOIN_BOUND + secs(1)).saturating_sub(elapsed);
    run.active = wait_for(
        sim,
        "H active in P within the join bound",
        remaining,
        async |s: &Sim| local_membership(s, "H", &p).await.as_deref() == Some("active"),
    )
    .await?;
    if run.active {
        let store = open_store(sim, "N", &p).await?;
        let mut opened = None;
        wait_for(
            sim,
            "H opens P's store",
            secs(60),
            async |s: &Sim| match try_open_store(s, "H", &p).await {
                Ok(id) => {
                    opened = Some(id);
                    true
                }
                Err(_) => false,
            },
        )
        .await?;
        if opened.as_deref() == Some(store.as_str()) {
            put_value(sim, "N", &store, "w3h-1207", "N wrote after H joined").await?;
            run.decrypted = wait_for(sim, "H reads N's write", secs(60), async |s: &Sim| {
                read_value(s, "H", &store, "w3h-1207").await.as_deref()
                    == Some("N wrote after H joined")
            })
            .await?;
        }
    }
    let final_position = sim.fabric().cut("case: final");

    // ---- receipt ----
    let mut identities = serde_json::Map::new();
    for label in all {
        let (agent, machine) = sim.ids(label)?;
        identities.insert(
            label.to_string(),
            json!({"agent": hex8(&agent.0), "machine": hex8(&machine.0)}),
        );
    }
    let ready_hello = std::env::var(READY_HELLO_ENV).ok();
    receipt.evidence(
        "binary_and_identities",
        true,
        json!({
            "binary_sha256": binary_sha256(),
            "ready_hello": ready_hello,
            "identities": identities,
            "g0": hex8(g0.as_bytes()),
            "p": hex8(p.as_bytes()),
        })
        .to_string(),
        at(sim),
    );
    let h_n_final = view(sim, "H", "N").await?;
    let n_h_final = view(sim, "N", "H").await?;
    receipt.evidence(
        "no_contacts_between_h_and_n",
        !h_n_final.contact && !n_h_final.contact,
        format!(
            "H has N: {}; N has H: {}",
            h_n_final.contact, n_h_final.contact
        ),
        at(sim),
    );
    let o_online = sim.fabric().is_online(&sim.peer("O")?).unwrap_or(true);
    receipt.evidence(
        "owner_offline_before_the_restart",
        !o_online,
        format!("O online: {o_online}"),
        at(sim),
    );
    let h_incarnation = sim.fabric().incarnation_of(&h_peer).unwrap_or(0);
    let expected_incarnation = if variant == Variant::PersistedEvidence {
        2
    } else {
        1
    };
    receipt.evidence(
        "h_restarted_on_the_same_dirs",
        h_incarnation == expected_incarnation,
        format!("H incarnation {h_incarnation} (expected {expected_incarnation}), same identity checked by Sim::start_again"),
        at(sim),
    );
    receipt.evidence(
        "g0_seats_h_and_n_active_on_both_at_connect",
        g0_h && g0_n,
        format!("H's G0: {g0_h}; N's G0: {g0_n}"),
        at(sim),
    );
    receipt.evidence(
        "connect_position",
        run.connect.is_some(),
        format!(
            "restart@{} first H~N open@{:?} settled@{}",
            run.restart, run.connect, run.settled
        ),
        at(sim),
    );
    let (eligible_ok, expectation) = match variant {
        Variant::AdminKnowsJoiner => (n_h.related(), "N eligible for H"),
        Variant::PersistedEvidence => (h_n.stored, "H holds N's record from disk"),
        _ => (
            !h_n.related() && !n_h.related() && !h_n.stored && !n_h.stored,
            "neither side eligible, no stored record",
        ),
    };
    let mut eligibility = at_connect;
    eligibility["expected"] = json!(expectation);
    receipt.evidence(
        "eligibility_at_connect",
        eligible_ok,
        eligibility.to_string(),
        at(sim),
    );
    let first_release = run.released.unwrap_or(run.join).min(run.join);
    let (hello_ok, hello_expectation) = match variant {
        Variant::AdminKnowsJoiner => (
            hello_at_connect.iter().any(|s| s.starts_with("N->H HELLO")),
            "N->H Hello at the connect",
        ),
        Variant::PersistedEvidence => (
            hello_at_connect.iter().any(|s| s.starts_with("H->N HELLO")),
            "H->N Hello at the connect",
        ),
        _ => (
            streams_between(sim, &labels, "H", "N", run.restart)
                .iter()
                .filter_map(|s| s.rsplit('@').next()?.parse::<usize>().ok())
                .all(|position| position >= first_release),
            "no H~N Hello between the restart and the first release or the join",
        ),
    };
    receipt.evidence(
        "hello_at_connect",
        hello_ok,
        json!({"expected": hello_expectation, "streams": hello_at_connect}).to_string(),
        at(sim),
    );
    if let Variant::Race(order) = variant {
        let ordered = match (order, run.committed, run.released) {
            (Order::RosterThenDiscovery, Some(committed), Some(released)) => committed < released,
            (Order::DiscoveryThenRoster, Some(committed), Some(released)) => released < committed,
            _ => false,
        };
        receipt.evidence(
            "release_order",
            ordered,
            format!(
                "{order:?}: join@{} committed@{:?} released@{:?}",
                run.join, run.committed, run.released
            ),
            at(sim),
        );
        receipt.evidence(
            "n_eligible_after_release",
            n_h_released.related(),
            n_h_released.json().to_string(),
            at(sim),
        );
    }
    let reconnects = sim
        .fabric()
        .link_open_positions(&h_peer, &n_peer, run.settled)
        .len();
    receipt.evidence(
        "no_h_n_reconnect_after_the_connect",
        reconnects == 0,
        format!("{reconnects} H~N opens after settled@{}", run.settled),
        at(sim),
    );
    let withheld = artifacts_delivered(sim, "N", "H", run.restart)?;
    receipt.evidence(
        "n_artifacts_withheld_from_h",
        withheld == 0,
        format!("{withheld} frames with N's artifacts delivered to H after the restart"),
        at(sim),
    );
    receipt.request_delivered(
        "h_join_committed_by_n",
        run.committed.is_some(),
        format!("N lists H in P: committed@{:?}", run.committed),
        at(sim),
    );

    let after_connect = run.connect.unwrap_or(run.restart);
    let hellos_after: Vec<String> = streams_between(sim, &labels, "H", "N", after_connect)
        .into_iter()
        .filter(|s| s.contains(" HELLO/"))
        .collect();
    let lookups: Vec<String> = evidence_streams(sim, run.join)
        .into_iter()
        .filter(|s| s.request == Some(LOOKUP))
        .map(|s| {
            format!(
                "{}->{} LOOKUP/{}@{}",
                labels.name(s.opener),
                labels.name(s.acceptor),
                kind_name(s.reply),
                s.position
            )
        })
        .collect();
    let h_to_n = dm_sent(sim, "H", "N", run.join)?;
    let n_to_h = dm_sent(sim, "N", "H", run.join)?;
    let paths = json!({
        "hellos_h_n_after_connect": hellos_after,
        "lookups_after_join": lookups,
        "h_to_n_dm": h_to_n,
        "n_to_h_dm": n_to_h,
        "h_view_of_n_final": h_n_final.json(),
        "n_view_of_h_final": n_h_final.json(),
        "counters_final": {"H": evidence_counters(sim, "H")?, "N": evidence_counters(sim, "N")?},
        "positions": {"restart": run.restart, "connect": run.connect, "settled": run.settled,
            "join": run.join, "committed": run.committed, "released": run.released,
            "final": final_position},
    });
    receipt.note(format!("paths {paths}"));
    if variant.red_shape() {
        receipt.cause(
            "no EvidenceV1 Hello between H and N after the connect",
            Some(json!(hellos_after).to_string()),
            hellos_after.is_empty(),
            at(sim),
        );
        let silent = h_to_n["direct_delivered"] == 0
            && h_to_n["relayed"] == 0
            && h_to_n["gossip_inbox_publishes"] == 0;
        receipt.cause(
            "none of H's requests reached N on any DM transport",
            Some(h_to_n.to_string()),
            silent,
            at(sim),
        );
        let unbound = h_n_final.usable_age.is_none()
            && !h_n_final.captured
            && !h_n_final.registry
            && h_n_final.discovery.is_none();
        receipt.cause(
            "H holds no admin evidence or binding for N",
            Some(h_n_final.json().to_string()),
            unbound,
            at(sim),
        );
        if variant == Variant::NoMapping {
            receipt.cause(
                "N never held H's mapping",
                Some(n_h_final.json().to_string()),
                n_h_final.discovery.is_none() && !n_h_final.stored,
                at(sim),
            );
        }
    }
    let evidence_at_h = h_n_final.usable_age.is_some() || h_n_final.captured;
    let ingress = n_to_h["direct_delivered"].as_u64().unwrap_or(0) > 0
        || n_to_h["gossip_inbox_publishes"].as_u64().unwrap_or(0) > 0;
    receipt.finish(
        FINAL,
        run.active && evidence_at_h && ingress && run.decrypted,
        at(sim),
    );
    Ok(())
}

/// Run one variant and return its emitted receipt. Any error before the
/// final assertion is recorded as INFRA.
async fn run(case: &str, seed: u64, variant: Variant, ready_hello: bool) -> Receipt {
    if ready_hello {
        // Before any daemon starts; nextest runs each test in its own
        // process, so no other test sees it.
        std::env::set_var(READY_HELLO_ENV, "1");
    }
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "variant {variant:?}; {READY_HELLO_ENV}={}",
        if ready_hello { "1" } else { "unset" }
    ));
    receipt.note(
        "staging is a harness fault rule: pubsub frames to a node that carry another node's \
         signed identity/capability artifacts (topic + subject agent id) are dropped",
    );
    receipt.note(
        "sim byte streams (EvidenceV1, SyncV1) are in-memory pipes with zero latency and no \
         QUIC flow control (W3-H S4)",
    );
    match Sim::empty(case, seed, variant.labels()) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, variant, &mut receipt).await {
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

async fn expect(
    case: &str,
    seed: u64,
    variant: Variant,
    ready_hello: bool,
    want: Verdict,
) -> Result<()> {
    let receipt = run(case, seed, variant, ready_hello).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// The red baseline: N commits H's seat, then learns H's mapping; no Hello
/// follows and H never fetches the Welcome. RED on main.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1207_red_baseline_roster_then_discovery_hello_never_sent() -> Result<()> {
    expect(
        "w3h_1207_red_baseline_roster_then_discovery_hello_never_sent",
        0x1207_0001,
        Variant::Race(Order::RosterThenDiscovery),
        false,
        Verdict::Red,
    )
    .await
}

/// Discovery first: N's commit-time push reaches H, which looks N up
/// through the own-host hint. Predicted GREEN on main (see the module doc).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1207_discovery_then_roster_recovers_through_the_commit_push() -> Result<()> {
    expect(
        "w3h_1207_discovery_then_roster_recovers_through_the_commit_push",
        0x1207_0002,
        Variant::Race(Order::DiscoveryThenRoster),
        false,
        Verdict::Green,
    )
    .await
}

/// Neither side ever learns the other's mapping. RED on main, and it must
/// stay RED with S1.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1207_red_baseline_no_mapping_on_either_side() -> Result<()> {
    expect(
        "w3h_1207_red_baseline_no_mapping_on_either_side",
        0x1207_0003,
        Variant::NoMapping,
        false,
        Verdict::Red,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1207_control_admin_knows_joiner() -> Result<()> {
    expect(
        "w3h_1207_control_admin_knows_joiner",
        0x1207_0004,
        Variant::AdminKnowsJoiner,
        false,
        Verdict::Green,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1207_control_intact_persisted_evidence() -> Result<()> {
    expect(
        "w3h_1207_control_intact_persisted_evidence",
        0x1207_0005,
        Variant::PersistedEvidence,
        false,
        Verdict::Green,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1207_control_authorized_third_holder() -> Result<()> {
    expect(
        "w3h_1207_control_authorized_third_holder",
        0x1207_0006,
        Variant::ThirdHolder,
        false,
        Verdict::Green,
    )
    .await
}

/// S1 on (#1251): the red baseline must turn GREEN. Ignored until S1
/// merges; on main the opt-in is read by nothing and the arm is RED.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore = "enable with #1207 S1 (#1251, X0X_EVIDENCE_READY_HELLO)"]
async fn w3h_red_1207_ready_hello_roster_then_discovery() -> Result<()> {
    expect(
        "w3h_red_1207_ready_hello_roster_then_discovery",
        0x1207_0001,
        Variant::Race(Order::RosterThenDiscovery),
        true,
        Verdict::Green,
    )
    .await
}

/// S1 on: with no mapping on either side, the deferred Hello has nothing
/// to fire on; the case must stay RED.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore = "enable with #1207 S1 (#1251, X0X_EVIDENCE_READY_HELLO)"]
async fn w3h_red_1207_ready_hello_no_mapping_stays_red() -> Result<()> {
    expect(
        "w3h_red_1207_ready_hello_no_mapping_stays_red",
        0x1207_0003,
        Variant::NoMapping,
        true,
        Verdict::Red,
    )
    .await
}

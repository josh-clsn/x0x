//! D30 restart-cold gate tests for ADR 0089, split per the design
//! authority (x0x-32) into two recovery classes:
//!
//! **30a — restart-cold to an EXISTING relationship peer** (an enrolled
//! device, a member of a group the node was already in, a grant party).
//! Covers a DM sent first by the restarted node (5 s), a file offer
//! reaching the warm peer (5 s), owner sync converging (30 s), and a
//! TreeKEM private join with the Welcome installed and the seat leaving
//! `pending_authority_commit` where the two nodes were ALREADY members
//! of one group (30 s). Enabled by ADR 0089 **S2 (#1128)**: the
//! persisted relationship evidence answers at the point of use.
//!
//! **30b — restart, then joining a NEW group with NO prior
//! relationship.** The restarted node holds no stored evidence for the
//! authority, so recovery needs the responder-authorized `Lookup`:
//! enabled by ADR 0089 **S4 (Lookup)**. Same 30 s join bound.
//!
//! Every test restarts a node the way a daemon restart does — a FRESH
//! process-equivalent instance built on the SAME identity and data
//! directories, so every in-memory cache (discovery, capability
//! adverts, authenticated bindings) starts empty. On main each
//! assertion is expected RED (the restarted node cannot resolve its
//! peers for ~600 s: #1091 send side, #1088 receive side); the
//! corresponding slice's PR un-ignores its group.
//!
//! Harness: 30a/30b drive the embeddable `x0x::server::serve` API
//! in-process over loopback (the `server_inprocess.rs` pattern) with a
//! FIXED QUIC port per node so the restarted node re-binds the same
//! port; the owner-sync test uses the ADR-0041 tier-1 agent-level
//! `OwnerSyncService` pattern. Restarts rebuild on the same key and
//! material directories, which is what makes them cold: no in-process
//! state survives.
//!
//! Fixture waits (discovery, rosters) are deliberately generous — they
//! are setup, not the gate. Only the post-restart bounds are the D30
//! contract.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde_json::Value;
use x0x::server::{serve, DaemonConfig, ServerHandle};

// ─────────────────────────────────────────────────────────────────────
// In-process server harness
// ─────────────────────────────────────────────────────────────────────

/// Reserve a currently-free loopback UDP port by binding `:0`, reading
/// the assigned port, then dropping the socket. Used to pin a FIXED QUIC
/// `bind_address` for the restart tests: the endpoint UDP socket is
/// released on shutdown, so an in-process embedder can re-`serve()` on
/// the SAME fixed QUIC port (same helper and rationale as
/// `server_inprocess.rs`).
fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind probe udp socket");
    let port = sock.local_addr().expect("probe local_addr").port();
    drop(sock);
    port
}

/// One in-process node: persistent state under `root/<name>/…`, a fixed
/// QUIC port so restarts re-bind it, and the API token that `serve()`
/// generates (and reuses across restarts) under the data dir.
struct Node {
    name: &'static str,
    root: PathBuf,
    quic_port: u16,
    /// The OTHER node's QUIC address, dialed at startup (loopback
    /// stand-in for the production bootstrap dial).
    bootstrap: Vec<SocketAddr>,
    handle: Option<ServerHandle>,
    api: SocketAddr,
    token: String,
}

impl Node {
    /// First start: creates the identity and data dirs.
    async fn start(
        name: &'static str,
        root: &Path,
        quic_port: u16,
        bootstrap: Vec<SocketAddr>,
    ) -> Self {
        let mut node = Self {
            name,
            root: root.to_path_buf(),
            quic_port,
            bootstrap,
            handle: None,
            api: SocketAddr::from(([127, 0, 0, 1], 0)),
            token: String::new(),
        };
        node.serve().await;
        node
    }

    fn config(&self) -> DaemonConfig {
        let dir = self.root.join(self.name);
        let mut config = DaemonConfig::default();
        config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
        config.bind_address = SocketAddr::from(([127, 0, 0, 1], self.quic_port));
        config.bootstrap_peers = Some(self.bootstrap.clone());
        config.data_dir = dir.join("data");
        config.identity_dir = Some(dir.join("identity"));
        config
    }

    /// (Re)start on the SAME identity and data dirs. A fresh `serve()`
    /// call builds a fresh agent from the persisted keys — every
    /// in-memory cache starts empty, which is the cold state a daemon
    /// restart produces.
    async fn serve(&mut self) {
        let handle = serve(self.config()).await.expect("in-process serve()");
        self.api = handle.local_addr();
        self.handle = Some(handle);
        // The token file is created on first start and reused after
        // that, so the restarted node keeps the same control-plane
        // credential.
        let token_path = self.config().data_dir.join("api-token");
        self.token = std::fs::read_to_string(&token_path)
            .expect("api-token")
            .trim()
            .to_string();
    }

    /// THE RESTART under test: stop, then rebuild on the same dirs.
    async fn restart(&mut self) {
        self.handle
            .take()
            .expect("live handle")
            .shutdown_and_wait()
            .await
            .expect("clean shutdown");
        self.serve().await;
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.client().get(self.url(path)).send().await.expect("GET")
    }

    async fn post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client()
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .expect("POST")
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.api)
    }

    fn client(&self) -> reqwest::Client {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.token))
                .expect("auth header"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .build()
            .expect("authed client")
    }

    async fn agent_id_hex(&self) -> String {
        let body: Value = self.get("/agent").await.json().await.expect("agent json");
        body["data"]["agent_id"]
            .as_str()
            .expect("agent_id")
            .to_string()
    }

    /// This node has the OTHER agent in its discovery cache (the warm
    /// precondition every restart-cold test needs BEFORE the restart).
    async fn discovered(&self, other_hex: &str) -> bool {
        let resp = self.get(&format!("/agents/discovered/{other_hex}")).await;
        if !resp.status().is_success() {
            return false;
        }
        let body: Value = resp.json().await.expect("discovered json");
        body["ok"] == true
    }
}

/// Bring up A and B, connect them (B bootstraps against A's fixed QUIC
/// port), and wait until BOTH sides have the other in their discovery
/// caches — the warm pre-restart state whose in-memory loss the restart
/// causes. NO group, grant or enrollment is established here: tests
/// that need a relationship call [`share_group`] themselves.
async fn warm_pair(root: &Path) -> (Node, Node) {
    let a_port = free_udp_port();
    let a = Node::start("a", root, a_port, Vec::new()).await;
    let b = Node::start(
        "b",
        root,
        free_udp_port(),
        vec![SocketAddr::from(([127, 0, 0, 1], a_port))],
    )
    .await;
    let a_hex = a.agent_id_hex().await;
    let b_hex = b.agent_id_hex().await;
    let mut a_ok = false;
    let mut b_ok = false;
    for _ in 0..600 {
        a_ok = a.discovered(&b_hex).await;
        b_ok = b.discovered(&a_hex).await;
        if a_ok && b_ok {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(a_ok, "warm-up: a never discovered b");
    assert!(b_ok, "warm-up: b never discovered a");
    (a, b)
}

/// The full private-group membership flow (invite → join → both rosters
/// Active), making A and B relationship peers (ADR 0089 §2: active
/// group members) and seeding the verified wire capture that S2
/// persists. Returns the group id.
async fn share_group(a: &Node, b: &Node, name: &str) -> String {
    let created: Value = a
        .post(
            "/groups",
            serde_json::json!({"name": name, "description": "restart-cold fixture"}),
        )
        .await
        .json()
        .await
        .expect("create group json");
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let group_id = created["group_id"].as_str().expect("group_id").to_string();

    let invite: Value = a
        .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
        .await
        .json()
        .await
        .expect("invite json");
    assert_eq!(invite["ok"], true, "invite: {invite:?}");
    let link = invite["invite_link"]
        .as_str()
        .expect("invite_link")
        .to_string();

    let joined: Value = b
        .post(
            "/groups/join",
            serde_json::json!({"invite": link, "display_name": "d30-member"}),
        )
        .await
        .json()
        .await
        .expect("join json");
    assert_eq!(joined["ok"], true, "join: {joined:?}");

    let b_hex = b.agent_id_hex().await;
    let mut owner_active = false;
    let mut joiner_active = false;
    for _ in 0..600 {
        owner_active = member_active(a, &group_id, &b_hex).await;
        joiner_active = member_active(b, &group_id, &b_hex).await;
        if owner_active && joiner_active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        owner_active,
        "warm-up: owner roster never showed the member Active"
    );
    assert!(joiner_active, "warm-up: joiner never seated itself Active");
    group_id
}

/// Create a group on `a` and return (group id, invite link) — the group
/// a restarted node will join.
async fn group_with_invite(a: &Node, name: &str) -> (String, String) {
    let created: Value = a
        .post(
            "/groups",
            serde_json::json!({"name": name, "description": "restart-cold join target"}),
        )
        .await
        .json()
        .await
        .expect("create group json");
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let group_id = created["group_id"].as_str().expect("group_id").to_string();
    let invite: Value = a
        .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
        .await
        .json()
        .await
        .expect("invite json");
    assert_eq!(invite["ok"], true, "invite: {invite:?}");
    let link = invite["invite_link"]
        .as_str()
        .expect("invite_link")
        .to_string();
    (group_id, link)
}

async fn member_active(node: &Node, group_id: &str, agent_hex: &str) -> bool {
    let Ok(resp) = node
        .get(&format!("/groups/{group_id}/members"))
        .await
        .error_for_status()
    else {
        return false;
    };
    let body: Value = resp.json().await.expect("members json");
    body["members"].as_array().is_some_and(|ms| {
        ms.iter().any(|m| {
            m["agent_id"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(agent_hex))
                && m["state"]
                    .as_str()
                    .is_some_and(|st| st.eq_ignore_ascii_case("active"))
        })
    })
}

/// Poll B's join-status + own-roster until the Welcome is installed and
/// the seat has left `pending_authority_commit`, or `bound` elapses.
async fn join_completes(b: &Node, group_id: &str, bound: Duration) -> (bool, bool, Duration) {
    let started = Instant::now();
    let b_hex = b.agent_id_hex().await;
    let mut left_pending = false;
    let mut seated = false;
    while started.elapsed() < bound {
        let status: Value = b
            .get(&format!("/groups/{group_id}/join-status"))
            .await
            .json()
            .await
            .expect("join-status json");
        let state = status["join_state"].as_str().unwrap_or("unknown");
        left_pending = state != "pending_authority_commit";
        seated = member_active(b, group_id, &b_hex).await;
        if left_pending && seated {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    (left_pending, seated, started.elapsed())
}

// ─────────────────────────────────────────────────────────────────────
// 30a — restart-cold to an EXISTING relationship peer (ADR 0089 S2,
// PR #1128 will un-ignore)
// ─────────────────────────────────────────────────────────────────────

/// Restart B cold; B must be able to SEND FIRST: its first DM to A (a
/// warm relationship peer — both are active members of the same group)
/// completes with a durable receipt within 5 s of the restart. On main
/// the restarted B cannot resolve A until the peer's next 600 s
/// announcement (#1091); S2's stored evidence answers at the point of
/// use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "enable with ADR 0089 S2 (#1128)"]
async fn restart_cold_dm_sent_first_completes_within_5s() {
    let root = tempfile::tempdir().expect("tempdir");
    let (a, mut b) = warm_pair(root.path()).await;
    let _group = share_group(&a, &b, "d30-warm").await;
    let a_hex = a.agent_id_hex().await;

    b.restart().await;

    let started = Instant::now();
    let payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"d30 restart-cold dm")
    };
    let mut sent = false;
    while started.elapsed() < Duration::from_secs(5) {
        let resp = b
            .post(
                "/direct/send",
                serde_json::json!({"agent_id": a_hex, "payload": payload}),
            )
            .await;
        if resp.status().is_success() {
            let body: Value = resp.json().await.expect("send json");
            if body["ok"] == true {
                sent = true;
                break;
            }
        }
        // Retryable send failures (the cold-resolution shape: 503
        // recipient_undiscovered) retry inside the bound, mirroring the
        // sender's outbox.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        sent,
        "D30(a): the restarted node must send first within 5 s (elapsed {:?})",
        started.elapsed()
    );
}

/// Restart B cold (already an active member of one group with A, so A
/// is a relationship peer with captured evidence), then B joins a
/// second private group created by A: the join request must reach the
/// authority, the Welcome must be installed, and B's seat must leave
/// `pending_authority_commit`, all within 30 s of the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "enable with ADR 0089 S2 (#1128)"]
async fn restart_cold_treekem_join_existing_peer_within_30s() {
    let root = tempfile::tempdir().expect("tempdir");
    let (a, mut b) = warm_pair(root.path()).await;
    // The prior shared membership: the relationship S2 stores evidence
    // for, and the context in which the Welcome must land.
    let _first = share_group(&a, &b, "d30-existing").await;

    let (group_id, link) = group_with_invite(&a, "d30-join-existing").await;

    b.restart().await;

    let joined: Value = b
        .post(
            "/groups/join",
            serde_json::json!({"invite": link, "display_name": "d30-cold-joiner"}),
        )
        .await
        .json()
        .await
        .expect("join json");
    assert_eq!(joined["ok"], true, "join request: {joined:?}");

    let (left_pending, seated, elapsed) =
        join_completes(&b, &group_id, Duration::from_secs(30)).await;
    assert!(
        left_pending,
        "D30(a): the seat must leave pending_authority_commit within 30 s (elapsed {elapsed:?})"
    );
    assert!(
        seated,
        "D30(a): the Welcome must be installed (joiner roster Active) within 30 s"
    );
}

/// Restart B cold; the file offer B sends to A (a warm relationship
/// peer) must reach A and appear as a pending incoming transfer within
/// 5 s. The accept→complete continuation afterwards is not the gated
/// bound, but it must still work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "enable with ADR 0089 S2 (#1128)"]
async fn restart_cold_file_offer_reaches_peer_within_5s() {
    let root = tempfile::tempdir().expect("tempdir");
    let (a, mut b) = warm_pair(root.path()).await;
    let _group = share_group(&a, &b, "d30-warm").await;
    let a_hex = a.agent_id_hex().await;

    // The file B will offer after the restart.
    let contents = b"d30 restart-cold file offer payload";
    let file_path = root.path().join("d30-offer.bin");
    std::fs::write(&file_path, contents).expect("write offer file");
    let sha256 = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(contents))
    };

    b.restart().await;

    let started = Instant::now();
    let offered: Value = b
        .post(
            "/files/send",
            serde_json::json!({
                "agent_id": a_hex,
                "filename": "d30-offer.bin",
                "size": contents.len(),
                "sha256": sha256,
                "path": file_path.to_string_lossy(),
            }),
        )
        .await
        .json()
        .await
        .expect("file send json");
    assert_eq!(offered["ok"], true, "file send: {offered:?}");
    let transfer_id = offered["transfer_id"]
        .as_str()
        .expect("transfer_id")
        .to_string();

    // THE GATE: A sees the incoming offer within 5 s.
    let mut seen = false;
    while started.elapsed() < Duration::from_secs(5) {
        let body: Value = a
            .get("/files/transfers")
            .await
            .json()
            .await
            .expect("transfers json");
        seen = body["transfers"].as_array().is_some_and(|ts| {
            ts.iter().any(|t| {
                t["direction"].as_str() == Some("Receiving")
                    && t["filename"].as_str() == Some("d30-offer.bin")
                    && t["status"].as_str() == Some("Pending")
            })
        });
        if seen {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        seen,
        "D30(a): the offer must reach the peer within 5 s (elapsed {:?})",
        started.elapsed()
    );

    // Continuation (not the D30 bound): accept and complete.
    let resp = a
        .post(
            &format!("/files/accept/{transfer_id}"),
            serde_json::json!({}),
        )
        .await;
    assert!(resp.status().is_success(), "accept: {:?}", resp.status());
    let mut done = false;
    for _ in 0..600 {
        let body: Value = b
            .get(&format!("/files/transfers/{transfer_id}"))
            .await
            .json()
            .await
            .expect("transfer status json");
        done = body["transfer"]["status"].as_str() == Some("Complete");
        if done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "the accepted transfer must complete");
}

// ─────────────────────────────────────────────────────────────────────
// 30a owner sync — agent-level tier-1 harness (ADR-0041 pattern)
// ─────────────────────────────────────────────────────────────────────

fn loopback_network_config() -> x0x::network::NetworkConfig {
    x0x::network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        ..x0x::network::NetworkConfig::default()
    }
}

/// Same owner key on both machines (deterministic seed), identity files
/// under fixed per-node paths so a restart REBUILDS THE SAME identity.
async fn build_owned_agent(dir: &Path, name: &str, owner_seed: [u8; 32]) -> x0x::Agent {
    let owner = x0x::identity::UserKeypair::from_seed(&owner_seed).expect("owner keypair");
    x0x::Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.join(format!("{name}-agent.key")))
        .with_agent_cert_path(dir.join(format!("{name}-agent.cert")))
        .with_user_key(owner)
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_network_config(loopback_network_config())
        .build()
        .await
        .expect("owned agent")
}

/// Restart B cold (same owner, same key files, same sync store — a
/// fresh agent with empty caches; A is an enrolled device, i.e. a
/// relationship peer); A mints a NEW owner-sync record while B is down;
/// after the restart B's sync pass must converge on that record within
/// 30 s. On main the restarted B cannot resolve A to open the SyncV1
/// stream; S2's stored evidence recovers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "enable with ADR 0089 S2 (#1128)"]
async fn restart_cold_owner_sync_converges_within_30s() {
    use x0x::owner_sync::{OwnerEnrollment, OwnerSyncService, SyncKind, SyncValue};

    let root = tempfile::tempdir().expect("tempdir");
    let owner_seed = [7u8; 32];
    let owner = x0x::identity::UserKeypair::from_seed(&owner_seed).expect("owner keypair");

    // Warm phase: both agents up, cross-enrolled, connected, and b has
    // a in its discovery cache (the state the restart loses).
    let a = std::sync::Arc::new(build_owned_agent(root.path(), "a", owner_seed).await);
    let b = std::sync::Arc::new(build_owned_agent(root.path(), "b", owner_seed).await);
    let a_machine = a.machine_id();
    let b_machine = b.machine_id();
    let service_a = OwnerSyncService::new(std::sync::Arc::clone(&a), &root.path().join("sync-a"))
        .await
        .expect("a sync service");
    let service_b = OwnerSyncService::new(std::sync::Arc::clone(&b), &root.path().join("sync-b"))
        .await
        .expect("b sync service");
    service_a
        .store()
        .enroll(OwnerEnrollment::sign(b_machine, &owner, 1_000, None).unwrap())
        .await
        .unwrap();
    service_b
        .store()
        .enroll(OwnerEnrollment::sign(a_machine, &owner, 1_000, None).unwrap())
        .await
        .unwrap();

    a.join_network().await.expect("a joins");
    b.join_network().await.expect("b joins");
    let a_addr = {
        let addr = a
            .network()
            .expect("a network")
            .bound_addr()
            .await
            .expect("a bound");
        if addr.ip().is_unspecified() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                addr.port(),
            )
        } else {
            addr
        }
    };
    b.network()
        .expect("b network")
        .connect_addr(a_addr)
        .await
        .expect("b dials a");
    let a_peer = ant_quic::PeerId(a_machine.0);
    let b_network = b.network().expect("b network").clone();
    let mut b_knows_a = false;
    for _ in 0..600 {
        b_knows_a = b_network.is_connected(&a_peer).await
            && b.discovered_agent_for_testing(&a.agent_id())
                .await
                .is_some();
        if b_knows_a {
            break;
        }
        a.announce_identity(false, false)
            .await
            .expect("a announces");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(b_knows_a, "warm-up: b never discovered a");

    // THE RESTART: drop b's service, shut the agent down, and rebuild a
    // fresh one on the SAME files (fresh process state, same identity
    // and sync store).
    drop(service_b);
    b.shutdown().await;
    let b = std::sync::Arc::new(build_owned_agent(root.path(), "b", owner_seed).await);
    b.join_network().await.expect("restarted b joins");
    let service_b = OwnerSyncService::new(std::sync::Arc::clone(&b), &root.path().join("sync-b"))
        .await
        .expect("restarted b sync service");

    // While b was down, the owner state moved on: a mints a new record.
    let marker = SyncValue::MachineNames {
        display_name: Some("a-restarted-era".to_string()),
        machine_name: Some("a-mac".to_string()),
    };
    service_a
        .store()
        .mint(
            SyncKind::MachineNames,
            &hex::encode(a_machine.0),
            &marker,
            &owner,
            a_machine,
        )
        .await
        .unwrap();

    // THE GATE: within 30 s of the restart, b's sync pass converges on
    // the record minted while it was down (both directions complete).
    let started = Instant::now();
    let mut converged = false;
    while started.elapsed() < Duration::from_secs(30) {
        service_b.sync_all().await;
        let snapshot = service_b.store().records_snapshot().await;
        converged = snapshot
            .iter()
            .any(|r| r.kind == SyncKind::MachineNames && r.value == marker);
        if converged {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        converged,
        "D30(a): owner sync must converge within 30 s of the restart (elapsed {:?})",
        started.elapsed()
    );
    let statuses = service_b.store().session_statuses().await;
    assert!(
        statuses
            .get(&a_machine.0)
            .is_some_and(|s| s.last_session_ok),
        "the restarted device must report a successful session with the owner peer"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 30b — restart, then joining a NEW group with NO prior relationship
// (ADR 0089 S4 Lookup will un-ignore)
// ─────────────────────────────────────────────────────────────────────

/// B restarts cold with NO prior relationship to A — no shared group,
/// grant or enrollment; only the warm-phase discovery existed, which the
/// restart loses and which S2 deliberately does NOT persist for
/// strangers (E-D10). B then joins a NEW group created by A: recovery
/// requires the responder-authorized `Lookup` (S4), and the join must
/// complete — Welcome installed, seat out of `pending_authority_commit`
/// — within the same 30 s bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "enable with ADR 0089 S4 (Lookup)"]
async fn restart_cold_treekem_join_new_relationship_within_30s() {
    let root = tempfile::tempdir().expect("tempdir");
    let (a, mut b) = warm_pair(root.path()).await;
    // NO share_group here: the restarted node holds nothing for the
    // authority except its (now cold) discovery memory.

    let (group_id, link) = group_with_invite(&a, "d30-join-new").await;

    b.restart().await;

    let joined: Value = b
        .post(
            "/groups/join",
            serde_json::json!({"invite": link, "display_name": "d30-stranger-joiner"}),
        )
        .await
        .json()
        .await
        .expect("join json");
    assert_eq!(joined["ok"], true, "join request: {joined:?}");

    let (left_pending, seated, elapsed) =
        join_completes(&b, &group_id, Duration::from_secs(30)).await;
    assert!(
        left_pending,
        "D30(b): the seat must leave pending_authority_commit within 30 s (elapsed {elapsed:?})"
    );
    assert!(
        seated,
        "D30(b): the Welcome must be installed (joiner roster Active) within 30 s"
    );
}

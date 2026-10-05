//! W3-H (#1164) simulation harness: real in-process daemons on the sim
//! fabric. Test builds only.
//!
//! Each node is the production daemon assembly
//! ([`super::serve_with_options`]) whose `NetworkNode` claimed a
//! [`crate::network::sim::SimFabric`] link instead of a QUIC socket. Cases
//! drive the public HTTP API through the daemon's own `Router`
//! (`tower::ServiceExt::oneshot`); no harness traffic uses a socket. Each
//! daemon still binds one idle loopback API listener that nothing uses.
//!
//! Time (plan §3b): a `spawn_blocking` clock gate inhibits tokio's
//! auto-advance whenever no named barrier is open, so virtual time moves
//! only inside [`Sim::within`] / [`Sim::until`] / [`Sim::api`], and every
//! advance is attributed to a named barrier in the trace. When the
//! entropy/wall-clock shim (`scripts/w3h/w3h_shim.c`) is preloaded, the
//! wall clock is a fixed base plus virtual time, updated every virtual
//! millisecond inside barriers, and all OS entropy is seeded.
//!
//! Determinism (plan §3a): [`Sim::finish`] renders the fabric's canonical
//! trace and prints `W3H-TRACE case=… seed=… entropy=… digest=…`; the CI
//! gate requires one digest per case across 20 reruns.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod control;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

use super::state::AppState;
use super::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};
use crate::network::sim::{self, SimFabric};

/// Virtual-time budget for one API call (including any network round
/// trips it waits on).
const API_BUDGET: Duration = Duration::from_secs(60);
/// Virtual-time budget for a daemon to start.
const START_BUDGET: Duration = Duration::from_secs(120);
/// Real-time limit for an await made while the clock gate is closed. A
/// stall past it means the case needed time outside a named barrier.
const GATED_STALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);

/// The preloaded `libw3h_shim.so`, if any.
#[derive(Clone, Copy)]
struct Shim {
    set_wall_offset_ns: unsafe extern "C" fn(u64),
}

impl Shim {
    #[cfg(unix)]
    fn detect() -> Option<Self> {
        // SAFETY: `dlsym` with RTLD_DEFAULT and a NUL-terminated name has
        // no preconditions; a non-null result for this exported symbol is
        // the shim's `void w3h_shim_set_wall_offset_ns(uint64_t)`.
        let symbol =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_set_wall_offset_ns".as_ptr()) };
        if symbol.is_null() {
            return None;
        }
        // SAFETY: the symbol is the shim's setter with exactly this C ABI
        // signature (`scripts/w3h/w3h_shim.c`).
        let set_wall_offset_ns =
            unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(u64)>(symbol) };
        Some(Self { set_wall_offset_ns })
    }

    #[cfg(not(unix))]
    fn detect() -> Option<Self> {
        None
    }

    fn set_wall(self, offset: Duration) {
        let nanos = u64::try_from(offset.as_nanos()).unwrap_or(u64::MAX);
        // SAFETY: the shim's setter only stores an atomic.
        unsafe { (self.set_wall_offset_ns)(nanos) }
    }
}

/// Holding one blocking task inhibits paused tokio's auto-advance
/// (tokio `runtime/blocking/schedule.rs`); releasing it allows it again.
struct ClockGate {
    release: std::sync::mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl ClockGate {
    fn close() -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let task = tokio::task::spawn_blocking(move || {
            let _ = wait.recv();
        });
        Self { release, task }
    }

    async fn open(self) {
        let _ = self.release.send(());
        let _ = self.task.await;
    }
}

/// One simulated daemon.
pub(crate) struct SimNode {
    label: String,
    handle: Option<ServerHandle>,
    router: Option<axum::Router>,
    state: Weak<AppState>,
    token: String,
    peer: ant_quic::PeerId,
    agent_hex: String,
}

/// A running scenario.
pub(crate) struct Sim {
    case: String,
    seed: u64,
    plane: String,
    fabric: Arc<SimFabric>,
    nodes: BTreeMap<String, SimNode>,
    gate: Mutex<Option<ClockGate>>,
    shim: Option<Shim>,
    root: tempfile::TempDir,
}

fn sim_addr(index: usize) -> Result<SocketAddr> {
    let octet = u8::try_from(index + 1).context("too many simulated nodes")?;
    // 198.18.0.0/15 is reserved for benchmarking; it never routes.
    Ok(SocketAddr::from(([198, 18, 0, octet], 5483)))
}

/// Wait for `fut` while the clock gate is closed. Virtual time cannot
/// move, so a future that needs time stalls; a real-time watchdog turns
/// that into an INFRA error instead of a hang.
async fn gated<F: std::future::Future>(what: &str, fut: F) -> Result<F::Output> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(GATED_STALL_LIMIT);
        let _ = tx.send(());
    });
    tokio::select! {
        biased;
        out = fut => Ok(out),
        _ = rx => bail!("INFRA: '{what}' needed virtual time outside a named barrier"),
    }
}

impl Sim {
    /// Start one daemon per label, in order, on a fresh fabric seeded by
    /// `seed`. Node 0 is every other node's bootstrap peer.
    pub(crate) async fn start(case: &str, seed: u64, labels: &[&str]) -> Result<Self> {
        let fabric = SimFabric::new(seed);
        let plane = format!("w3h-{seed:x}");
        sim::register(&plane, &fabric);
        let shim = Shim::detect();
        if let Some(shim) = shim {
            shim.set_wall(Duration::ZERO);
        }
        let mut sim = Self {
            case: case.to_string(),
            seed,
            plane,
            fabric,
            nodes: BTreeMap::new(),
            gate: Mutex::new(Some(ClockGate::close())),
            shim,
            root: tempfile::tempdir()?,
        };
        sim.fabric.mark(format!(
            "case {case} entropy={}",
            if shim.is_some() {
                "controlled"
            } else {
                "uncontrolled"
            }
        ));
        for (index, label) in labels.iter().enumerate() {
            sim.start_node(label, index).await?;
        }
        Ok(sim)
    }

    fn daemon_config(&self, label: &str, index: usize) -> Result<DaemonConfig> {
        let dir = self.root.path().join(label);
        let mut config = DaemonConfig {
            api_address: SocketAddr::from(([127, 0, 0, 1], 0)),
            bind_address: sim_addr(index)?,
            data_dir: dir.join("data"),
            identity_dir: Some(dir.join("identity")),
            network_id: Some(self.plane.clone()),
            bootstrap_peers: Some(if index == 0 {
                Vec::new()
            } else {
                vec![sim_addr(0)?]
            }),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..DaemonConfig::default()
        };
        config.api_watchdog.enabled = false;
        Ok(config)
    }

    async fn start_node(&mut self, label: &str, index: usize) -> Result<()> {
        let config = self.daemon_config(label, index)?;
        let options = ServeOptions {
            skip_update_check: true,
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            self_update_enabled: false,
            ..ServeOptions::default()
        };
        let handle = self
            .within(
                &format!("start {label}"),
                START_BUDGET,
                serve_with_options(config, options),
            )
            .await??;
        let state = handle
            .test_state
            .upgrade()
            .ok_or_else(|| anyhow!("daemon {label} state dropped during start"))?;
        let peer = state
            .agent
            .network()
            .ok_or_else(|| anyhow!("daemon {label} has no network"))?
            .peer_id();
        self.fabric.label(&peer, label);
        let node = SimNode {
            label: label.to_string(),
            router: Some(handle.test_router.clone()),
            state: Arc::downgrade(&state),
            token: state.api_token.clone(),
            peer,
            agent_hex: hex::encode(state.agent.agent_id().as_bytes()),
            handle: Some(handle),
        };
        self.nodes.insert(label.to_string(), node);
        Ok(())
    }

    fn node(&self, label: &str) -> Result<&SimNode> {
        self.nodes
            .get(label)
            .ok_or_else(|| anyhow!("no simulated node {label}"))
    }

    /// The node's agent id, hex.
    pub(crate) fn agent_hex(&self, label: &str) -> Result<String> {
        Ok(self.node(label)?.agent_hex.clone())
    }

    /// Read-only access to a running daemon's state.
    pub(crate) fn state(&self, label: &str) -> Result<Arc<AppState>> {
        self.node(label)?
            .state
            .upgrade()
            .ok_or_else(|| anyhow!("daemon {label} is not running"))
    }

    /// The fabric (faults, writes, trace).
    pub(crate) fn fabric(&self) -> &Arc<SimFabric> {
        &self.fabric
    }

    /// Run `fut` inside a named barrier: the clock gate opens, virtual time
    /// may auto-advance up to `budget`, then the gate closes again. The
    /// barrier, its virtual duration and outcome are recorded in the trace.
    pub(crate) async fn within<F: std::future::Future>(
        &self,
        name: &str,
        budget: Duration,
        fut: F,
    ) -> Result<F::Output> {
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| anyhow!("nested barrier '{name}'"))?;
        let started = self.fabric.now();
        self.fabric.mark(format!("barrier '{name}' open"));
        gate.open().await;
        let ticker = self.shim.map(|shim| {
            let fabric = Arc::clone(&self.fabric);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    shim.set_wall(fabric.now());
                }
            })
        });
        let outcome = tokio::time::timeout(budget, fut).await;
        if let Some(ticker) = ticker {
            ticker.abort();
        }
        *self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ClockGate::close());
        if let Some(shim) = self.shim {
            shim.set_wall(self.fabric.now());
        }
        let elapsed = self.fabric.now().saturating_sub(started);
        self.fabric.mark(format!(
            "barrier '{name}' close {} after {}us",
            if outcome.is_ok() { "done" } else { "timeout" },
            elapsed.as_micros()
        ));
        outcome.map_err(|_| anyhow!("barrier '{name}' exceeded its {budget:?} virtual budget"))
    }

    /// A named barrier that polls `done` every 100 virtual ms until it
    /// holds or `budget` elapses.
    pub(crate) async fn until(
        &self,
        name: &str,
        budget: Duration,
        mut done: impl AsyncFnMut(&Sim) -> bool,
    ) -> Result<()> {
        self.within(name, budget, async {
            loop {
                if done(self).await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
    }

    /// One public-API request through the node's router, inside its own
    /// named barrier. Returns the status and the JSON body (`Null` if the
    /// body is not JSON).
    pub(crate) async fn api(
        &self,
        label: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(StatusCode, serde_json::Value)> {
        let name = format!("api {label} {method} {path}");
        let result = self
            .within(&name, API_BUDGET, self.request(label, method, path, body))
            .await??;
        self.fabric.mark(format!("{name} -> {}", result.0));
        Ok(result)
    }

    /// The same request without a barrier, for use inside [`Self::until`]
    /// predicates (which already run inside one).
    pub(crate) async fn request(
        &self,
        label: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(StatusCode, serde_json::Value)> {
        let node = self.node(label)?;
        let router = node
            .router
            .clone()
            .ok_or_else(|| anyhow!("daemon {label} is not running"))?;
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", node.token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |json| Body::from(json.to_string())))?;
        let response = router.oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024).await?;
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        Ok((status, json))
    }

    /// Take a node off the fabric (it keeps running, unreachable).
    pub(crate) fn set_online(&self, label: &str, online: bool) -> Result<()> {
        let peer = self.node(label)?.peer;
        self.fabric.mark(format!(
            "fault {label} {}",
            if online { "online" } else { "offline" }
        ));
        self.fabric.set_online(&peer, online);
        Ok(())
    }

    /// Wait for a future at the current, frozen virtual instant.
    pub(crate) async fn at_instant<F: std::future::Future>(
        &self,
        what: &str,
        fut: F,
    ) -> Result<F::Output> {
        gated(what, fut).await
    }

    /// Record the canonical trace: print the digest line, write the trace
    /// file when `W3H_TRACE_DIR` is set, then stop every daemon.
    pub(crate) async fn finish(mut self) -> Result<String> {
        let trace = self.fabric.canonical_trace();
        let digest = blake3::hash(trace.as_bytes()).to_hex().to_string();
        let entropy = if self.shim.is_some() {
            "controlled"
        } else {
            "uncontrolled"
        };
        eprintln!(
            "W3H-TRACE case={} seed={:#x} entropy={entropy} digest={digest}",
            self.case, self.seed
        );
        if let Ok(dir) = std::env::var("W3H_TRACE_DIR") {
            let dir = std::path::PathBuf::from(dir);
            if std::fs::create_dir_all(&dir).is_ok() {
                let file = dir.join(format!("{}-{}.trace", self.case, std::process::id()));
                let _ = std::fs::write(file, &trace);
            }
        }
        let handles: Vec<(String, ServerHandle)> = self
            .nodes
            .values_mut()
            .filter_map(|node| {
                node.router = None;
                node.handle
                    .take()
                    .map(|handle| (node.label.clone(), handle))
            })
            .collect();
        for (label, handle) in handles {
            let _ = self
                .within(
                    &format!("stop {label}"),
                    START_BUDGET,
                    handle.shutdown_and_wait(),
                )
                .await;
        }
        Ok(digest)
    }

    /// Live fabric links of a node.
    pub(crate) async fn connected_peer_count(&self, label: &str) -> usize {
        match self.state(label) {
            Ok(state) => match state.agent.network() {
                Some(network) => network.connected_peers().await.len(),
                None => 0,
            },
            Err(_) => 0,
        }
    }
}

/// Seconds, for readable budgets.
pub(crate) const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

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

#![cfg(test)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod case_1143;
mod control;
mod home;
mod receipt;

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

/// Why the shim is not controlling this process (recorded in the trace).
const SHIM_NOT_LOADED: &str = "shim not preloaded";

impl Shim {
    /// The shim, if it is preloaded, active (it requires `W3H_SHIM_ACTIVE=1`
    /// and `W3H_ENTROPY_SEED`), and demonstrably intercepting both entropy
    /// paths: `rand::rngs::OsRng` (getrandom 0.2 → `syscall(SYS_getrandom)`)
    /// and libc `getrandom()` (std, getrandom 0.3/0.4). Otherwise the reason.
    #[cfg(target_os = "linux")]
    fn detect() -> std::result::Result<Self, String> {
        use rand::RngCore as _;
        // SAFETY: `dlsym` with RTLD_DEFAULT and NUL-terminated names has no
        // preconditions; null means "not found".
        let (set_wall, active, calls) = unsafe {
            (
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_set_wall_offset_ns".as_ptr()),
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_active".as_ptr()),
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_entropy_calls".as_ptr()),
            )
        };
        if set_wall.is_null() || active.is_null() || calls.is_null() {
            return Err(SHIM_NOT_LOADED.to_string());
        }
        // SAFETY: these are the shim's exported functions with exactly these
        // C ABI signatures (`scripts/w3h/w3h_shim.c`).
        let (set_wall_offset_ns, active, calls) = unsafe {
            (
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(u64)>(set_wall),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn() -> libc::c_int>(
                    active,
                ),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn() -> libc::c_ulong>(
                    calls,
                ),
            )
        };
        // SAFETY: plain reads of the shim's atomics.
        if unsafe { active() } != 1 {
            return Err("shim preloaded but inactive (W3H_SHIM_ACTIVE / W3H_ENTROPY_SEED)".into());
        }
        // SAFETY: as above.
        let before = unsafe { calls() };
        let _ = rand::rngs::OsRng.next_u64();
        let mut probe = [0u8; 8];
        // SAFETY: the buffer is valid for its length.
        let got = unsafe { libc::getrandom(probe.as_mut_ptr().cast(), probe.len(), 0) };
        // SAFETY: as above.
        let after = unsafe { calls() };
        if got != 8 || after < before.saturating_add(2) {
            return Err(format!(
                "shim active but an entropy path bypassed it (calls {before} -> {after})"
            ));
        }
        Ok(Self { set_wall_offset_ns })
    }

    #[cfg(not(target_os = "linux"))]
    fn detect() -> std::result::Result<Self, String> {
        Err(SHIM_NOT_LOADED.to_string())
    }

    fn set_wall(self, offset: Duration) {
        let nanos = u64::try_from(offset.as_nanos()).unwrap_or(u64::MAX);
        // SAFETY: the shim's setter only stores atomics.
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

/// Identity material written into a node's identity directory before its
/// daemon starts (a fixture preparing signed capabilities, ADR 0108
/// Validation; never discovered certificate bytes).
/// Each field is the on-disk encoding (`crate::storage::serialize_*`, or
/// `AgentCertificate::to_storage_bytes()` — e.g. `POST /owner/agents/issue`
/// `certificate.storage_b64`).
#[derive(Default)]
pub(crate) struct Provision {
    pub(crate) machine_key: Option<Vec<u8>>,
    pub(crate) agent_key: Option<Vec<u8>>,
    pub(crate) user_key: Option<Vec<u8>>,
    pub(crate) agent_cert: Option<Vec<u8>>,
}

/// One WARN-or-worse log event from any in-process daemon, with the
/// virtual time it was emitted at.
#[derive(Clone, Debug)]
pub(crate) struct CapturedLog {
    pub(crate) at: Duration,
    pub(crate) text: String,
}

struct LogCapture {
    fabric: Arc<SimFabric>,
    logs: Arc<Mutex<Vec<CapturedLog>>>,
}

struct LogText<'a>(&'a mut String);

impl tracing::field::Visit for LogText<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut text = format!(
            "{} {}: ",
            event.metadata().level(),
            event.metadata().target()
        );
        event.record(&mut LogText(&mut text));
        self.logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(CapturedLog {
                at: self.fabric.now(),
                text,
            });
    }
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
    logs: Arc<Mutex<Vec<CapturedLog>>>,
    root: tempfile::TempDir,
    // Last: the capture stays installed until every daemon has stopped.
    _log_guard: tracing::subscriber::DefaultGuard,
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
        let mut sim = Self::empty(case, seed)?;
        for label in labels {
            sim.start_node_with(label, Provision::default()).await?;
        }
        Ok(sim)
    }

    /// A fabric, clock gate and WARN-log capture with no daemons yet.
    pub(crate) fn empty(case: &str, seed: u64) -> Result<Self> {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::Layer as _;
        let fabric = SimFabric::new(seed);
        let plane = format!("w3h-{seed:x}");
        sim::register(&plane, &fabric);
        let (shim, entropy) = match Shim::detect() {
            Ok(shim) => {
                shim.set_wall(Duration::ZERO);
                (Some(shim), "controlled".to_string())
            }
            Err(reason) => (None, format!("uncontrolled ({reason})")),
        };
        let logs = Arc::new(Mutex::new(Vec::new()));
        // Thread-local: the scenario runs on one current-thread runtime, so
        // every daemon task emits on this thread.
        let log_guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(
                LogCapture {
                    fabric: Arc::clone(&fabric),
                    logs: Arc::clone(&logs),
                }
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
            ),
        );
        let sim = Self {
            case: case.to_string(),
            seed,
            plane,
            fabric,
            nodes: BTreeMap::new(),
            gate: Mutex::new(Some(ClockGate::close())),
            shim,
            logs,
            root: tempfile::tempdir()?,
            _log_guard: log_guard,
        };
        sim.fabric.mark(format!("case {case} entropy={entropy}"));
        Ok(sim)
    }

    /// WARN-or-worse logs captured so far whose text contains every needle.
    pub(crate) fn logs_containing(&self, needles: &[&str]) -> Vec<CapturedLog> {
        self.logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|log| needles.iter().all(|needle| log.text.contains(needle)))
            .cloned()
            .collect()
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

    /// Write `provision` into the node's identity directory, then start its
    /// daemon. The first node started is every later node's bootstrap peer.
    pub(crate) async fn start_node_with(
        &mut self,
        label: &str,
        provision: Provision,
    ) -> Result<()> {
        let index = self.nodes.len();
        let config = self.daemon_config(label, index)?;
        let identity = config
            .identity_dir
            .clone()
            .context("sim nodes always have an identity dir")?;
        tokio::fs::create_dir_all(&identity).await?;
        for (file, bytes) in [
            ("machine.key", provision.machine_key),
            ("agent.key", provision.agent_key),
            ("user.key", provision.user_key),
            ("agent.cert", provision.agent_cert),
        ] {
            if let Some(bytes) = bytes {
                crate::storage::write_private_bytes(&identity.join(file), bytes).await?;
            }
        }
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

    /// The node's transport peer id.
    pub(crate) fn peer(&self, label: &str) -> Result<ant_quic::PeerId> {
        Ok(self.node(label)?.peer)
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
    /// Stop every daemon (in label order, each inside a named barrier),
    /// verify the teardown, THEN finalise the canonical trace: print the
    /// digest line and write the trace file when `W3H_TRACE_DIR` is set.
    /// A barrier timeout or a supervisor error fails the run (after the
    /// trace is written).
    pub(crate) async fn finish(mut self) -> Result<String> {
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
        let mut teardown_errors = Vec::new();
        for (label, handle) in handles {
            match self
                .within(
                    &format!("stop {label}"),
                    START_BUDGET,
                    handle.shutdown_and_wait(),
                )
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => teardown_errors.push(format!("{label}: shutdown: {error:#}")),
                Err(error) => teardown_errors.push(format!("{label}: {error:#}")),
            }
        }
        for node in self.nodes.values() {
            // A leaked holder of the daemon state is reported, not failed:
            // the supervisor already drained (`shutdown_and_wait` returned
            // Ok) and the count of stray holders is scheduling-dependent.
            if node.state.upgrade().is_some() {
                eprintln!(
                    "W3H-WARN {}: daemon state outlived its shutdown",
                    node.label
                );
            }
        }
        self.fabric.mark(if teardown_errors.is_empty() {
            "teardown verified".to_string()
        } else {
            format!("teardown failed: {}", teardown_errors.join("; "))
        });
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
        if !teardown_errors.is_empty() {
            bail!("teardown failed: {}", teardown_errors.join("; "));
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

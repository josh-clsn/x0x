//! x0xd -- local agent daemon for the x0x gossip network.
//!
//! Runs a persistent x0x agent with a REST API for local control.
//! Designed to be started once and left running; external tools
//! (CLI, Fae, scripts) interact through the HTTP endpoints.
//!
//! This binary is a thin wrapper: it selects the process-level global
//! allocator and then delegates to [`x0x::daemon::run`], which owns the CLI
//! argument parsing, config building, and server bring-up. In-process
//! embedders (e.g. a mobile FFI crate) should depend on the `x0x` library and
//! call [`x0x::daemon::serve`] directly instead of supervising this binary.
//!
//! ## Usage
//!
//! ```bash
//! x0xd                                  # default config
//! x0xd --config /path/to/config.toml    # custom config
//! x0xd --check                          # validate config and exit
//! x0xd --check-updates                  # check/apply updates and exit
//! x0xd --skip-update-check              # start daemon without startup update check
//! x0xd --name alice                     # run a named instance (separate identity)
//! x0xd --list                           # list running instances
//! ```

use anyhow::Result;

#[cfg(feature = "profile-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// jemalloc as the daemon's global allocator. Eliminates the 50 MB+
// heap-to-RSS amplification observed under glibc malloc, where retired
// arenas held pages indefinitely. dirty_decay_ms / muzzy_decay_ms are
// configured via MALLOC_CONF below for aggressive page return.
#[cfg(all(feature = "jemalloc", not(feature = "profile-heap")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", not(feature = "profile-heap")))]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static MALLOC_CONF: &[u8] =
    b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0,abort_conf:true\0";

#[tokio::main]
async fn main() -> Result<()> {
    // dhat heap profiler. Each daemon writes its own file so multi-daemon
    // runs don't overwrite each other's dump. Set DHAT_OUT_DIR to override.
    // The guard must live for the whole process, so it stays here in the
    // binary rather than inside the library entrypoint.
    #[cfg(feature = "profile-heap")]
    let _dhat_profiler = {
        let dir = std::env::var("DHAT_OUT_DIR").unwrap_or_else(|_| ".".to_string());
        let path = format!("{}/dhat-heap-{}.json", dir, std::process::id());
        eprintln!("dhat: writing heap dump to {} on exit", path);
        dhat::Profiler::builder().file_name(&path).build()
    };

    x0x::daemon::run().await
}

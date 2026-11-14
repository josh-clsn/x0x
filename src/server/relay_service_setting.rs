//! OQ5 (audit): the daemon's `relay_service_disabled` setting, end to end
//! from the TOML-shaped config to ant-quic's relay-service switch.
//!
//! A desktop runs `leaf_mode = true` and must keep serving its own phone as a
//! hole-punch coordinator, so `leaf_mode` alone leaves relay service on. Only
//! `relay_service_disabled = true`, which the phone sets, turns it off.

#![cfg(test)]

use super::{serve_with_options, DaemonConfig, ServeOptions};
use std::time::Duration;

fn daemon_config(root: &std::path::Path, name: &str, extra: &str) -> DaemonConfig {
    let dir = root.join(name);
    let toml_text = format!(
        "bind_address = \"127.0.0.1:0\"\n\
         api_address = \"127.0.0.1:0\"\n\
         data_dir = {data:?}\n\
         identity_dir = {identity:?}\n\
         bootstrap_peers = []\n\
         mdns_enabled = false\n\
         port_mapping_enabled = false\n\
         network_id = \"x0x.test.oq5.{name}\"\n\
         leaf_mode = true\n\
         {extra}\n\
         [update]\n\
         enabled = false\n",
        data = dir.join("data").display().to_string(),
        identity = dir.join("identity").display().to_string(),
    );
    let config: DaemonConfig = toml::from_str(&toml_text).expect("loopback daemon config");
    assert!(
        config.resolved_bootstrap_peers().is_empty(),
        "no fleet seeds"
    );
    config
}

fn serve_options() -> ServeOptions {
    ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    }
}

async fn relay_service_allowed(config: DaemonConfig) -> Option<bool> {
    let handle = serve_with_options(config, serve_options())
        .await
        .expect("serve");
    let state = handle.test_state.upgrade().expect("state");
    let network = state.agent.network().expect("network").clone();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut allowed = network.relay_client_snapshot().relay_service_allowed;
    while allowed.is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
        allowed = network.relay_client_snapshot().relay_service_allowed;
    }
    drop(state);
    let _ = tokio::time::timeout(Duration::from_secs(20), handle.shutdown_and_wait()).await;
    allowed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_desktop_leaf_serves_and_only_the_phone_setting_turns_it_off() {
    let root = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        relay_service_allowed(daemon_config(root.path(), "desktop", "")).await,
        Some(true),
        "a desktop leaf still coordinates its own phone's punches"
    );
    assert_eq!(
        relay_service_allowed(daemon_config(
            root.path(),
            "phone",
            "relay_service_disabled = true"
        ))
        .await,
        Some(false),
        "the phone setting turns relay service off while meshed"
    );
}

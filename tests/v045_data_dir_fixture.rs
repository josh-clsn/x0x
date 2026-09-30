//! Upgrade continuity (charter I9, decision D01, ADR 0085): a `data_dir`
//! written by the released v0.45.0 `x0xd` must open under this version.
//!
//! `tests/fixtures/v045_data_dir/` was produced by the v0.45.0 release binary
//! (see its `PROVENANCE.md`). This test decodes every KV-store and task-list
//! snapshot in it through the same loaders the daemon uses at startup, and
//! checks the values written through the v0.45.0 REST API.
//!
//! Inert: no network, no daemon. The full upgrade-in-place and downgrade run
//! on a copied fixture is release-gate row 4.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use x0x::crdt::persistence::TaskListStorage;
use x0x::crdt::task_list::TaskListId;
use x0x::kv::sync::load_snapshot;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v045_data_dir")
}

fn snapshot_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("fixture subdirectory exists")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "bin"))
        .collect();
    files.sort();
    files
}

/// Every KV snapshot v0.45.0 wrote loads. Before the #1046 fix each of these
/// failed with `UnexpectedEof`, and the daemon refused to open the store
/// ("refusing to start with amnesia").
#[test]
fn every_v045_kv_store_snapshot_loads() {
    let files = snapshot_files(&fixture_dir().join("kv-stores"));
    assert_eq!(files.len(), 2, "personal store + group store");

    let mut by_keys: BTreeMap<Vec<String>, x0x::kv::KvStore> = BTreeMap::new();
    for path in &files {
        let store = load_snapshot(path)
            .unwrap_or_else(|e| panic!("{} must load: {e}", path.display()))
            .unwrap_or_else(|| panic!("{} must be present", path.display()));
        let mut keys: Vec<String> = store.active_keys().into_iter().cloned().collect();
        keys.sort();
        by_keys.insert(keys, store);
    }

    // Personal signed store: plaintext values, including an overwrite.
    let personal = by_keys
        .get(&vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ])
        .expect("personal store keys survive the upgrade");
    let value = |key: &str| personal.get(key).map(|entry| entry.value.clone());
    assert_eq!(value("alpha").as_deref(), Some(b"one-v2".as_slice()));
    assert_eq!(value("beta").as_deref(), Some(b"two".as_slice()));
    assert_eq!(value("gamma").as_deref(), Some(b"three".as_slice()));

    // GSS group store: the keys survive (values are group-encrypted).
    assert!(
        by_keys.contains_key(&vec!["page-about".to_string(), "page-home".to_string()]),
        "group store keys survive the upgrade"
    );
}

/// Task lists were not changed after v0.45.0; this pins that they still
/// load, so a future task-list change must keep them loading (ADR 0085).
#[tokio::test]
async fn v045_task_list_snapshot_loads() {
    let storage = TaskListStorage::new(fixture_dir().join("task-lists"));
    let id = TaskListId::from_topic("fixture-v045-tasks");
    let list = storage
        .load_task_list_opt(&id)
        .await
        .expect("a v0.45.0 task list must load")
        .expect("present");
    assert_eq!(list.task_count(), 2);
    let mut titles: Vec<&str> = list.tasks_ordered().iter().map(|t| t.title()).collect();
    titles.sort_unstable();
    assert_eq!(titles, ["first task", "second task"]);
}

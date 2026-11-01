//! What the build records as `X0X_BUILD_SHA`: the environment's value when given, else the
//! checkout's commit (`-dirty` when a tracked file differs), and nothing outside a checkout of
//! the crate's own.
#[path = "../build_support/build_sha.rs"]
mod build_sha;

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

fn checkout() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    std::fs::write(dir.path().join("a.txt"), "one\n").unwrap();
    git(dir.path(), &["add", "a.txt"]);
    git(dir.path(), &["commit", "-q", "-m", "first"]);
    dir
}

fn head(dir: &Path) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn a_clean_checkout_reports_its_forty_hex_commit() {
    let dir = checkout();
    let sha = build_sha::resolve(None, dir.path()).unwrap();
    assert_eq!(sha.len(), 40, "{sha}");
    assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "{sha}");
    assert_eq!(sha, head(dir.path()));
}

#[test]
fn a_changed_tracked_file_appends_dirty() {
    let dir = checkout();
    std::fs::write(dir.path().join("a.txt"), "two\n").unwrap();
    let sha = build_sha::resolve(None, dir.path()).unwrap();
    assert_eq!(sha, format!("{}-dirty", head(dir.path())));
}

#[test]
fn an_untracked_file_does_not_make_a_build_dirty() {
    let dir = checkout();
    std::fs::write(dir.path().join("new.txt"), "x\n").unwrap();
    assert_eq!(
        build_sha::resolve(None, dir.path()).unwrap(),
        head(dir.path())
    );
}

#[test]
fn the_environment_value_wins_over_the_checkout() {
    let dir = checkout();
    assert_eq!(
        build_sha::resolve(Some("  from-env \n"), dir.path()).unwrap(),
        "from-env"
    );
    assert_eq!(
        build_sha::resolve(Some("   "), dir.path()).unwrap(),
        head(dir.path()),
        "a blank value is no value"
    );
}

#[test]
fn a_crate_inside_another_checkout_records_nothing() {
    let dir = checkout();
    let inner = dir.path().join("vendored");
    std::fs::create_dir(&inner).unwrap();
    assert_eq!(build_sha::resolve(None, &inner), None);
}

#[test]
fn a_directory_with_no_checkout_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(build_sha::resolve(None, dir.path()), None);
}

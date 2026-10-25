//! Records the commit this crate was built from as `X0X_BUILD_SHA`, so a
//! consumer that pins a fork tail can tell two builds of one version apart
//! (`x0x::BUILD_SHA`, `GET /health` `build_sha`, `x0xd --version --build-sha`).
//!
//! `X0X_BUILD_SHA` in the build environment wins, for a packager building
//! from a source tarball. Otherwise it is `git rev-parse HEAD` of this
//! crate's own checkout, with `-dirty` appended when a tracked file differs
//! from that commit. Nothing is recorded outside a checkout of its own: a
//! crate vendored inside another repository never reports that repository's
//! commit.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=X0X_BUILD_SHA");
    for watched in ["build.rs", "Cargo.toml", "Cargo.lock", "src"] {
        println!("cargo:rerun-if-changed={watched}");
    }
    let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        return;
    };
    if let Some(git_dir) = git(&dir, &["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/logs/HEAD");
    }
    let sha = match std::env::var("X0X_BUILD_SHA") {
        Ok(given) if !given.trim().is_empty() => Some(given.trim().to_owned()),
        _ => from_git(&dir),
    };
    if let Some(sha) = sha {
        println!("cargo:rustc-env=X0X_BUILD_SHA={sha}");
    }
}

fn from_git(dir: &Path) -> Option<String> {
    let top = git(dir, &["rev-parse", "--show-toplevel"])?;
    if std::fs::canonicalize(&top).ok()? != std::fs::canonicalize(dir).ok()? {
        return None;
    }
    let sha = git(dir, &["rev-parse", "HEAD"])?;
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let diff = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["diff", "--quiet", "HEAD", "--"])
        .status()
        .ok()?;
    match diff.code() {
        Some(0) => Some(sha),
        Some(1) => Some(format!("{sha}-dirty")),
        _ => None,
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

//! `x0xd --version` stays one line; `--build-sha` adds a second, `build <sha>`.
//! A consumer that pins a build reads that line, so its shape is exact.
use std::process::Command;

fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_x0xd"))
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn version_alone_is_one_line() {
    assert_eq!(
        run(&["--version"]),
        format!("x0xd {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn build_sha_adds_the_commit_on_a_second_line() {
    let sha = x0x::BUILD_SHA.unwrap_or("unknown");
    assert_eq!(
        run(&["--version", "--build-sha"]),
        format!("x0xd {}\nbuild {sha}\n", env!("CARGO_PKG_VERSION"))
    );
}

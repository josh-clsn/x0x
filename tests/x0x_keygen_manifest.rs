use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_x0x-keygen")
}

fn command_failure(output: &Output) -> String {
    format!(
        "status: {:?}\nstderr: {}\nstdout: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    )
}

fn run_generate(secret_path: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(bin_path())
        .args(["generate", "--output"])
        .arg(secret_path)
        .output()?)
}

fn generate_secret_key(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let secret_path = root.join("keypair.secret");
    let output = run_generate(&secret_path)?;
    if !output.status.success() {
        return Err(format!("key generation failed\n{}", command_failure(&output)).into());
    }

    Ok(secret_path)
}

fn run_manifest(
    version: &str,
    assets_dir: &Path,
    skill_path: &Path,
    key_path: &Path,
    output_dir: &Path,
) -> Result<Output, Box<dyn Error>> {
    run_manifest_with_base(version, assets_dir, skill_path, key_path, output_dir, None)
}

fn run_manifest_with_base(
    version: &str,
    assets_dir: &Path,
    skill_path: &Path,
    key_path: &Path,
    output_dir: &Path,
    base_url: Option<&str>,
) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new(bin_path());
    command
        .args(["manifest", "--version", version, "--assets-dir"])
        .arg(assets_dir)
        .args(["--skill-path"])
        .arg(skill_path)
        .args(["--key"])
        .arg(key_path)
        .args(["--output-dir"])
        .arg(output_dir);
    if let Some(base_url) = base_url {
        command.args(["--base-url"]).arg(base_url);
    }
    Ok(command.output()?)
}

fn signed_fixture(root: &Path) -> Result<ManifestFixture, Box<dyn Error>> {
    let fixture = create_manifest_fixture(root)?;
    std::fs::write(
        fixture.assets_dir.join("x0x-linux-x64-gnu.tar.gz.sig"),
        b"signature",
    )?;
    Ok(fixture)
}

struct ManifestFixture {
    assets_dir: PathBuf,
    output_dir: PathBuf,
    skill_path: PathBuf,
    key_path: PathBuf,
}

fn create_manifest_fixture(root: &Path) -> Result<ManifestFixture, Box<dyn Error>> {
    let assets_dir = root.join("assets");
    let output_dir = root.join("out");
    std::fs::create_dir(&assets_dir)?;
    std::fs::create_dir(&output_dir)?;

    let skill_path = root.join("SKILL.md");
    std::fs::write(&skill_path, b"name: x0x\n")?;

    let archive_path = assets_dir.join("x0x-linux-x64-gnu.tar.gz");
    std::fs::write(&archive_path, b"release archive")?;

    let key_path = generate_secret_key(root)?;

    Ok(ManifestFixture {
        assets_dir,
        output_dir,
        skill_path,
        key_path,
    })
}

#[test]
fn manifest_fails_when_archive_signature_is_missing() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let fixture = create_manifest_fixture(tempdir.path())?;

    let output = run_manifest(
        "0.19.47",
        &fixture.assets_dir,
        &fixture.skill_path,
        &fixture.key_path,
        &fixture.output_dir,
    )?;
    if output.status.success() {
        return Err("manifest unexpectedly succeeded without an archive signature".into());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("signature file missing for x0x-linux-x64-gnu.tar.gz") {
        return Err(format!("unexpected manifest failure\n{}", command_failure(&output)).into());
    }

    let manifest_path = fixture.output_dir.join("release-manifest.json");
    if manifest_path.exists() {
        return Err("manifest was written despite the missing archive signature".into());
    }

    Ok(())
}

#[test]
fn manifest_succeeds_when_archive_signature_exists() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let fixture = create_manifest_fixture(tempdir.path())?;
    std::fs::write(
        fixture.assets_dir.join("x0x-linux-x64-gnu.tar.gz.sig"),
        b"signature",
    )?;

    let output = run_manifest(
        "0.19.47",
        &fixture.assets_dir,
        &fixture.skill_path,
        &fixture.key_path,
        &fixture.output_dir,
    )?;
    if !output.status.success() {
        return Err(format!("manifest failed\n{}", command_failure(&output)).into());
    }

    let manifest_path = fixture.output_dir.join("release-manifest.json");
    let manifest_json = std::fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_json)?;
    let assets = manifest
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .ok_or("manifest assets field was not an array")?;

    if assets.len() != 1 {
        return Err(format!("expected 1 manifest asset, found {}", assets.len()).into());
    }

    let signature_url = assets
        .first()
        .and_then(|asset| asset.get("signature_url"))
        .and_then(serde_json::Value::as_str)
        .ok_or("manifest asset did not include a signature_url")?;

    if signature_url
        != "https://github.com/saorsa-labs/x0x/releases/download/v0.19.47/x0x-linux-x64-gnu.tar.gz.sig"
    {
        return Err(format!("unexpected signature_url: {signature_url}").into());
    }

    if !fixture
        .output_dir
        .join("release-manifest.json.sig")
        .is_file()
    {
        return Err("manifest signature was not written".into());
    }

    Ok(())
}

/// DEFAULT UNCHANGED (row 7b ruling): without --base-url every URL is
/// byte-identical to the GitHub release form the workflow has always
/// produced — archive, signature AND skill, full string equality.
#[test]
fn manifest_default_urls_are_byte_identical_to_the_github_release_form(
) -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let fixture = signed_fixture(tempdir.path())?;

    let output = run_manifest(
        "0.46.0",
        &fixture.assets_dir,
        &fixture.skill_path,
        &fixture.key_path,
        &fixture.output_dir,
    )?;
    if !output.status.success() {
        return Err(format!("manifest failed\n{}", command_failure(&output)).into());
    }

    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        fixture.output_dir.join("release-manifest.json"),
    )?)?;
    let asset = manifest["assets"][0]
        .get("archive_url")
        .and_then(serde_json::Value::as_str)
        .ok_or("no archive_url")?;
    let sig = manifest["assets"][0]
        .get("signature_url")
        .and_then(serde_json::Value::as_str)
        .ok_or("no signature_url")?;
    let skill = manifest["skill_url"].as_str().ok_or("no skill_url")?;

    assert_eq!(
        asset,
        "https://github.com/saorsa-labs/x0x/releases/download/v0.46.0/x0x-linux-x64-gnu.tar.gz"
    );
    assert_eq!(
        sig,
        "https://github.com/saorsa-labs/x0x/releases/download/v0.46.0/x0x-linux-x64-gnu.tar.gz.sig"
    );
    assert_eq!(
        skill,
        "https://github.com/saorsa-labs/x0x/releases/download/v0.46.0/SKILL.md"
    );
    Ok(())
}

/// With --base-url, every URL points under the given base — the row 7b
/// rehearsal shape (a node-local origin, no GitHub). A trailing slash
/// must not double up.
#[test]
fn manifest_base_url_redirects_every_asset_url() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let fixture = signed_fixture(tempdir.path())?;

    let output = run_manifest_with_base(
        "0.46.1",
        &fixture.assets_dir,
        &fixture.skill_path,
        &fixture.key_path,
        &fixture.output_dir,
        Some("http://127.0.0.1:8443/"),
    )?;
    if !output.status.success() {
        return Err(format!("manifest failed\n{}", command_failure(&output)).into());
    }

    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        fixture.output_dir.join("release-manifest.json"),
    )?)?;
    assert_eq!(
        manifest["assets"][0]["archive_url"],
        "http://127.0.0.1:8443/v0.46.1/x0x-linux-x64-gnu.tar.gz"
    );
    assert_eq!(
        manifest["assets"][0]["signature_url"],
        "http://127.0.0.1:8443/v0.46.1/x0x-linux-x64-gnu.tar.gz.sig"
    );
    assert_eq!(
        manifest["skill_url"],
        "http://127.0.0.1:8443/v0.46.1/SKILL.md"
    );
    Ok(())
}

/// Nonsense schemes refuse before anything is written, so no rehearsal
/// manifest can silently end up relative or non-http.
#[test]
fn manifest_base_url_rejects_non_http_schemes() -> Result<(), Box<dyn Error>> {
    for bad in ["ftp://example.org", "/relative", ""] {
        let tempdir = tempfile::tempdir()?;
        let fixture = signed_fixture(tempdir.path())?;
        let output = run_manifest_with_base(
            "0.46.1",
            &fixture.assets_dir,
            &fixture.skill_path,
            &fixture.key_path,
            &fixture.output_dir,
            Some(bad),
        )?;
        assert!(
            !output.status.success(),
            "--base-url {bad:?} must be refused"
        );
        assert!(
            !fixture.output_dir.join("release-manifest.json").exists(),
            "no manifest may be written for a refused --base-url"
        );
    }
    Ok(())
}

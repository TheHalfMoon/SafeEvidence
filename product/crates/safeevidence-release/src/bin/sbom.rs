//! TA-02: generate the SBOM from the live workspace and fail unless it lists every
//! `Cargo.lock` package and known native library. Not a release: `release_ready` stays false.
//!
//! Usage, from `product/`: `sbom <output-path>`

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use safeevidence_release::{
    BuildEnvironment, ExpectedBinding, NativeDependency, ReleaseSbomInput, RustDependency,
    WorkspacePackage, generate_release_sbom, native_dependencies, packages_missing_from_document,
    sha256_hex, verify_release_sbom,
};

fn output(program: &str, args: &[&str]) -> Result<String, String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    if !result.status.success() {
        return Err(format!("{program} {args:?} failed"));
    }
    String::from_utf8(result.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("{program}: {error}"))
}

fn run(out: &PathBuf) -> Result<usize, String> {
    let lock = std::fs::read("Cargo.lock").map_err(|error| format!("Cargo.lock: {error}"))?;
    let metadata = output(
        "cargo",
        &["metadata", "--format-version", "1", "--locked", "--offline"],
    )?;
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata).map_err(|error| format!("metadata: {error}"))?;
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or("metadata has no workspace_members")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    let mut workspace_packages = Vec::new();
    let mut rust_deps = Vec::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or("metadata has no packages")?
    {
        let name = package["name"].as_str().ok_or("package without name")?;
        let version = package["version"]
            .as_str()
            .ok_or("package without version")?;
        let license = package["license"].as_str().map(str::to_owned);
        if members.contains(package["id"].as_str().unwrap_or_default()) {
            workspace_packages.push(WorkspacePackage {
                name: name.to_owned(),
                version: version.to_owned(),
                license,
            });
        } else {
            rust_deps.push(RustDependency {
                name: name.to_owned(),
                version: version.to_owned(),
                license,
            });
        }
    }

    let names: Vec<String> = workspace_packages
        .iter()
        .map(|package| package.name.clone())
        .collect();
    let lock_text = String::from_utf8_lossy(&lock);
    let native_deps: Vec<NativeDependency> = native_dependencies(&lock_text);
    let input = ReleaseSbomInput {
        source_sha: output("git", &["rev-parse", "HEAD"])?,
        tree_sha: output("git", &["rev-parse", "HEAD^{tree}"])?,
        cargo_lock_sha256: sha256_hex(&lock),
        build_env: BuildEnvironment {
            os: std::env::consts::OS.to_owned(),
            os_version: "not-recorded".to_owned(),
            target_triple: std::env::consts::ARCH.to_owned(),
            rustc: output("rustc", &["--version"])?,
            cargo: output("cargo", &["--version"])?,
        },
        workspace_packages,
        rust_deps,
        native_deps,
        artifacts: vec![],
        pack_assets: vec![],
    };
    let document = generate_release_sbom(&input);
    let report = verify_release_sbom(
        &document,
        &ExpectedBinding {
            source_sha: input.source_sha.clone(),
            tree_sha: input.tree_sha.clone(),
            cargo_lock_sha256: input.cargo_lock_sha256.clone(),
            workspace_package_names: names,
        },
    );
    if !report.ok {
        return Err(format!("SBOM failed verification: {:?}", report.failures));
    }
    let missing = packages_missing_from_document(&lock_text, &document)?;
    if !missing.is_empty() {
        return Err(format!("SBOM omits Cargo.lock packages: {missing:?}"));
    }
    std::fs::write(out, &document).map_err(|error| format!("write: {error}"))?;
    Ok(report.component_count)
}

fn main() -> ExitCode {
    let Some(out) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: sbom <output-path>");
        return ExitCode::FAILURE;
    };
    match run(&out) {
        Ok(count) => {
            println!("TA-02 SBOM: {count} components; all Cargo.lock packages listed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("TA-02 FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

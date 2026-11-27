//! TA-02: generate the SBOM from the live `product/` and `product/apps/desktop/` workspaces
//! and fail unless it lists every `Cargo.lock` package (both workspaces), every `package-lock.json`
//! npm package, and every native-binding crate. Not a release: `release_ready` stays false.
//!
//! Usage, from `product/`: `sbom <output-path>`

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use safeevidence_release::{
    BuildEnvironment, ExpectedBinding, ReleaseSbomInput, RustDependency, WorkspacePackage,
    classify_native, generate_release_sbom, lock_packages, npm_lock_packages,
    npm_packages_missing_from_document, packages_missing_from_document, sha256_hex,
    verify_release_sbom,
};

const DESKTOP_MANIFEST: &str = "apps/desktop/src-tauri/Cargo.toml";
const DESKTOP_CARGO_LOCK: &str = "apps/desktop/src-tauri/Cargo.lock";
const DESKTOP_PACKAGE_LOCK: &str = "apps/desktop/package-lock.json";

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

fn host_triple() -> Result<String, String> {
    output("rustc", &["-vV"])?
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV has no host line".to_owned())
}

fn collect_metadata(
    manifest_path: Option<&str>,
    licenses: &mut BTreeMap<(String, String), Option<String>>,
    member_names: &mut BTreeSet<String>,
    native_crates: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut args = vec!["metadata", "--format-version", "1", "--locked", "--offline"];
    if let Some(path) = manifest_path {
        args.extend(["--manifest-path", path]);
    }
    let metadata_raw = output("cargo", &args)?;
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_raw).map_err(|error| format!("metadata: {error}"))?;
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or("metadata has no workspace_members")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    for package in metadata["packages"]
        .as_array()
        .ok_or("metadata has no packages")?
    {
        let name = package["name"].as_str().ok_or("package without name")?;
        let version = package["version"]
            .as_str()
            .ok_or("package without version")?;
        licenses
            .entry((name.to_owned(), version.to_owned()))
            .or_insert_with(|| package["license"].as_str().map(str::to_owned));
        if members.contains(package["id"].as_str().unwrap_or_default()) {
            member_names.insert(name.to_owned());
        }
        if package["links"].is_string() || name.ends_with("-sys") {
            native_crates.insert(name.to_owned());
        }
    }
    Ok(())
}

fn read_lf_normalized_lock(path: &str) -> Result<(Vec<u8>, String), String> {
    let raw = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    let lf = if !raw.windows(2).any(|w| w == b"\r\n") {
        raw
    } else {
        let lf_count = raw.iter().filter(|&&b| b == b'\n').count();
        let crlf_count = raw.windows(2).filter(|w| *w == b"\r\n").count();
        if lf_count != crlf_count {
            return Err(format!("{path}: mixed LF/CRLF line endings"));
        }
        let mut normalized = Vec::with_capacity(raw.len() - crlf_count);
        let mut idx = 0;
        while idx < raw.len() {
            if idx + 1 < raw.len() && raw[idx] == b'\r' && raw[idx + 1] == b'\n' {
                normalized.push(b'\n');
                idx += 2;
            } else {
                normalized.push(raw[idx]);
                idx += 1;
            }
        }
        normalized
    };
    let text = String::from_utf8(lf.clone()).map_err(|error| format!("{path}: {error}"))?;
    Ok((lf, text))
}

fn run(out: &PathBuf) -> Result<usize, String> {
    // A dirty tree would pair these locks and sources with a commit that does not hold them.
    let dirty = output("git", &["status", "--porcelain"])?;
    if !dirty.is_empty() {
        return Err(format!("working tree is not clean:\n{dirty}"));
    }
    let (lock, lock_text) = read_lf_normalized_lock("Cargo.lock")?;
    let (desktop_lock, desktop_lock_text) = read_lf_normalized_lock(DESKTOP_CARGO_LOCK)?;
    let (npm_lock, npm_lock_text) = read_lf_normalized_lock(DESKTOP_PACKAGE_LOCK)?;

    let mut licenses = BTreeMap::new();
    let mut member_names = BTreeSet::new();
    let mut native_crates = BTreeSet::new();
    collect_metadata(None, &mut licenses, &mut member_names, &mut native_crates)?;
    collect_metadata(
        Some(DESKTOP_MANIFEST),
        &mut licenses,
        &mut member_names,
        &mut native_crates,
    )?;

    // The lockfiles, not metadata, decide what is listed. Metadata only supplies licenses.
    let mut all_cargo_packages = BTreeSet::new();
    for pair in lock_packages(&lock_text)? {
        all_cargo_packages.insert(pair);
    }
    for pair in lock_packages(&desktop_lock_text)? {
        all_cargo_packages.insert(pair);
    }

    let mut workspace_packages = Vec::new();
    let mut rust_deps = Vec::new();
    for (name, version) in all_cargo_packages {
        let license = licenses
            .get(&(name.clone(), version.clone()))
            .cloned()
            .flatten();
        if member_names.contains(&name) {
            workspace_packages.push(WorkspacePackage {
                name,
                version,
                license,
            });
        } else {
            rust_deps.push(RustDependency {
                name,
                version,
                license,
            });
        }
    }

    let npm_deps = npm_lock_packages(&npm_lock_text)?;
    let native_list: Vec<String> = native_crates.into_iter().collect();
    let native_deps = classify_native(&native_list)
        .map_err(|unknown| format!("unclassified native crates: {unknown:?}"))?;
    let desktop_cargo_lock_sha256 = sha256_hex(&desktop_lock);
    let desktop_package_lock_sha256 = sha256_hex(&npm_lock);

    let input = ReleaseSbomInput {
        source_sha: output("git", &["rev-parse", "HEAD"])?,
        tree_sha: output("git", &["rev-parse", "HEAD^{tree}"])?,
        cargo_lock_sha256: sha256_hex(&lock),
        desktop_cargo_lock_sha256: Some(desktop_cargo_lock_sha256.clone()),
        desktop_package_lock_sha256: Some(desktop_package_lock_sha256.clone()),
        build_env: BuildEnvironment {
            os: std::env::consts::OS.to_owned(),
            os_version: "not-recorded".to_owned(),
            target_triple: host_triple()?,
            rustc: output("rustc", &["--version"])?,
            cargo: output("cargo", &["--version"])?,
        },
        workspace_packages,
        rust_deps,
        npm_deps,
        native_deps,
        artifacts: vec![],
        pack_assets: vec![],
    };
    let document = generate_release_sbom(&input);
    // Checks the document's structure and bindings. Its inputs come from this same run, so
    // the lockfile comparisons below are the independent coverage checks.
    let report = verify_release_sbom(
        &document,
        &ExpectedBinding {
            source_sha: input.source_sha.clone(),
            tree_sha: input.tree_sha.clone(),
            cargo_lock_sha256: input.cargo_lock_sha256.clone(),
            desktop_cargo_lock_sha256: Some(desktop_cargo_lock_sha256),
            desktop_package_lock_sha256: Some(desktop_package_lock_sha256),
            workspace_package_names: member_names.into_iter().collect(),
        },
    );
    if !report.ok {
        return Err(format!("SBOM failed verification: {:?}", report.failures));
    }
    let missing_product = packages_missing_from_document(&lock_text, &document)?;
    if !missing_product.is_empty() {
        return Err(format!(
            "SBOM omits product/Cargo.lock packages: {missing_product:?}"
        ));
    }
    let missing_desktop = packages_missing_from_document(&desktop_lock_text, &document)?;
    if !missing_desktop.is_empty() {
        return Err(format!(
            "SBOM omits {DESKTOP_CARGO_LOCK} packages: {missing_desktop:?}"
        ));
    }
    let missing_npm = npm_packages_missing_from_document(&npm_lock_text, &document)?;
    if !missing_npm.is_empty() {
        return Err(format!(
            "SBOM omits {DESKTOP_PACKAGE_LOCK} packages: {missing_npm:?}"
        ));
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
            println!(
                "TA-02 SBOM: {count} components; all product Cargo.lock, desktop Cargo.lock, and package-lock.json packages listed"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("TA-02 FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

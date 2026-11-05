//! Adapted from the donor test: nine of eleven tests. Its committed-document and doctor tests
//! need donor evidence files and modules.

use safeevidence_release::{
    BuildEnvironment, ExpectedBinding, NativeDependency, PackAsset, ReleaseArtifact,
    ReleaseSbomInput, RustDependency, WorkspacePackage, generate_release_sbom, lock_package_names,
    native_dependencies, packages_missing_from_document, verify_release_sbom,
};

fn fixture_input() -> ReleaseSbomInput {
    ReleaseSbomInput {
        source_sha: "a".repeat(40),
        tree_sha: "b".repeat(40),
        cargo_lock_sha256: "c".repeat(64),
        build_env: BuildEnvironment {
            os: "windows".to_owned(),
            os_version: "11".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            rustc: "1.89.0".to_owned(),
            cargo: "1.89.0".to_owned(),
        },
        workspace_packages: vec![WorkspacePackage {
            name: "safeevidence-core".to_owned(),
            version: "0.1.0".to_owned(),
            license: None,
        }],
        rust_deps: vec![RustDependency {
            name: "serde".to_owned(),
            version: "1.0.0".to_owned(),
            license: Some("MIT".to_owned()),
        }],
        native_deps: vec![NativeDependency {
            name: "sqlite".to_owned(),
            classification: "bundled-source".to_owned(),
            detail: "via rusqlite bundled".to_owned(),
        }],
        artifacts: vec![ReleaseArtifact {
            name: "safeevidence-cli".to_owned(),
            sha256: "d".repeat(64),
        }],
        pack_assets: vec![PackAsset {
            name: "pack-v0".to_owned(),
            kind: "offline-pack".to_owned(),
            rights_note: "synthetic fixture only".to_owned(),
        }],
    }
}

fn fixture_expected() -> ExpectedBinding {
    ExpectedBinding {
        source_sha: "a".repeat(40),
        tree_sha: "b".repeat(40),
        cargo_lock_sha256: "c".repeat(64),
        workspace_package_names: vec!["safeevidence-core".to_owned()],
    }
}

#[test]
fn generator_is_deterministic() {
    let input = fixture_input();
    let first = generate_release_sbom(&input);
    assert_eq!(first, generate_release_sbom(&input));
    assert!(first.contains("\"safeevidence:public_project_license\""));
    assert!(first.contains("\"Apache-2.0\""));
}

#[test]
fn verifier_accepts_fixture_document() {
    let doc = generate_release_sbom(&fixture_input());
    let report = verify_release_sbom(&doc, &fixture_expected());
    assert!(report.ok, "unexpected failures: {:?}", report.failures);
    assert!(report.component_count >= 5);
    assert_eq!(report.document_sha256.len(), 64);
}

#[test]
fn verifier_rejects_malformed_json() {
    let report = verify_release_sbom("{not json", &fixture_expected());
    assert!(!report.ok);
    assert!(report.failures.iter().any(|f| f.starts_with("parse_error")));
}

#[test]
fn verifier_rejects_tampered_component() {
    let mut value: serde_json::Value =
        serde_json::from_str(&generate_release_sbom(&fixture_input())).expect("valid");
    value["components"].as_array_mut().expect("array")[0]
        .as_object_mut()
        .expect("object")
        .remove("licenses");
    let report = verify_release_sbom(&value.to_string(), &fixture_expected());
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.starts_with("license_fabrication"))
    );
}

#[test]
fn verifier_rejects_stale_lock_digest() {
    let doc = generate_release_sbom(&fixture_input());
    let mut expected = fixture_expected();
    expected.cargo_lock_sha256 = "0".repeat(64);
    let report = verify_release_sbom(&doc, &expected);
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.starts_with("digest_mismatch"))
    );
}

#[test]
fn verifier_rejects_stale_source_sha() {
    let doc = generate_release_sbom(&fixture_input());
    let mut expected = fixture_expected();
    expected.source_sha = "0".repeat(40);
    let report = verify_release_sbom(&doc, &expected);
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("safeevidence:source_sha"))
    );
}

#[test]
fn verifier_rejects_missing_workspace_package() {
    let doc = generate_release_sbom(&fixture_input());
    let mut expected = fixture_expected();
    expected
        .workspace_package_names
        .push("safeevidence-ghost".to_owned());
    let report = verify_release_sbom(&doc, &expected);
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.starts_with("missing_workspace_package"))
    );
}

#[test]
fn verifier_rejects_unclassified_native_dep() {
    let mut input = fixture_input();
    input.native_deps = vec![NativeDependency {
        name: "mystery".to_owned(),
        classification: String::new(),
        detail: "unknown".to_owned(),
    }];
    let doc = generate_release_sbom(&input);
    let report = verify_release_sbom(&doc, &fixture_expected());
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.starts_with("native_unclassified"))
    );
}

#[test]
fn verifier_rejects_missing_required_property() {
    let mut value: serde_json::Value =
        serde_json::from_str(&generate_release_sbom(&fixture_input())).expect("valid");
    let props = value["metadata"]["properties"]
        .as_array_mut()
        .expect("props");
    props.retain(|p| p.get("name").and_then(|n| n.as_str()) != Some("safeevidence:rustc"));
    let report = verify_release_sbom(&value.to_string(), &fixture_expected());
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("safeevidence:rustc"))
    );
}

const LOCK: &str = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"safeevidence-core\"\nversion = \"0.1.0\"\n";

#[test]
fn every_lock_package_listed_passes_coverage() {
    let document = generate_release_sbom(&fixture_input());
    assert_eq!(lock_package_names(LOCK), ["serde", "safeevidence-core"]);
    assert!(
        packages_missing_from_document(LOCK, &document)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn package_absent_from_document_is_reported() {
    let document = generate_release_sbom(&fixture_input());
    let lock = format!("{LOCK}\n[[package]]\nname = \"unlisted\"\nversion = \"1.0.0\"\n");
    assert_eq!(
        packages_missing_from_document(&lock, &document).unwrap(),
        ["unlisted"]
    );
}

#[test]
fn malformed_document_is_an_error_not_full_coverage() {
    assert!(packages_missing_from_document(LOCK, "not json").is_err());
    assert!(packages_missing_from_document(LOCK, "{}").is_err());
}

#[test]
fn bundled_native_code_is_classified_when_present() {
    assert!(native_dependencies(LOCK).is_empty());
    let lock = "name = \"libsqlite3-sys\"\nname = \"openssl-src\"\n";
    let names: Vec<_> = native_dependencies(lock)
        .into_iter()
        .map(|dep| dep.name)
        .collect();
    assert_eq!(names, ["sqlcipher", "openssl"]);
}

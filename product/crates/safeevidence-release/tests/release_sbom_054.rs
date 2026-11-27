//! Adapted from the donor test: nine of eleven tests, plus Cargo.lock, desktop Cargo.lock,
//! npm `package-lock.json`, and native-binding coverage checks.

use safeevidence_release::{
    BuildEnvironment, ExpectedBinding, NativeDependency, NpmDependency, PackAsset, ReleaseArtifact,
    ReleaseSbomInput, RustDependency, WorkspacePackage, classify_native, generate_release_sbom,
    lock_packages, npm_lock_packages, npm_packages_missing_from_document,
    packages_missing_from_document, verify_release_sbom,
};

fn fixture_input() -> ReleaseSbomInput {
    ReleaseSbomInput {
        source_sha: "a".repeat(40),
        tree_sha: "b".repeat(40),
        cargo_lock_sha256: "c".repeat(64),
        desktop_cargo_lock_sha256: Some("e".repeat(64)),
        desktop_package_lock_sha256: Some("f".repeat(64)),
        build_env: BuildEnvironment {
            os: "windows".to_owned(),
            os_version: "11".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            rustc: "1.98.1".to_owned(),
            cargo: "1.98.1".to_owned(),
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
        npm_deps: vec![NpmDependency {
            name: "@tauri-apps/api".to_owned(),
            version: "2.12.0".to_owned(),
            license: Some("Apache-2.0 OR MIT".to_owned()),
            integrity: Some("sha512-synthetic==".to_owned()),
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
        desktop_cargo_lock_sha256: Some("e".repeat(64)),
        desktop_package_lock_sha256: Some("f".repeat(64)),
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
    assert!(report.component_count >= 6);
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

    let mut desktop_cargo = fixture_expected();
    desktop_cargo.desktop_cargo_lock_sha256 = Some("0".repeat(64));
    assert!(!verify_release_sbom(&doc, &desktop_cargo).ok);

    let mut desktop_npm = fixture_expected();
    desktop_npm.desktop_package_lock_sha256 = Some("0".repeat(64));
    assert!(!verify_release_sbom(&doc, &desktop_npm).ok);
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
    assert_eq!(
        lock_packages(LOCK).unwrap(),
        [
            ("serde".to_owned(), "1.0.0".to_owned()),
            ("safeevidence-core".to_owned(), "0.1.0".to_owned())
        ]
    );
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
        ["unlisted 1.0.0"]
    );
}

#[test]
fn another_version_of_a_listed_crate_is_not_coverage() {
    let document = generate_release_sbom(&fixture_input());
    let lock = format!("{LOCK}\n[[package]]\nname = \"serde\"\nversion = \"0.9.0\"\n");
    assert_eq!(
        packages_missing_from_document(&lock, &document).unwrap(),
        ["serde 0.9.0"]
    );
}

#[test]
fn npm_lock_coverage_is_verified_and_cross_ecosystem_names_do_not_collide() {
    let document = generate_release_sbom(&fixture_input());
    let parsed: serde_json::Value = serde_json::from_str(&document).expect("json");
    let tauri_api = parsed["components"]
        .as_array()
        .expect("components")
        .iter()
        .find(|c| c["name"] == "@tauri-apps/api")
        .expect("scoped npm component");
    assert_eq!(tauri_api["purl"], "pkg:npm/%40tauri-apps/api@2.12.0");

    // Tampering `safeevidence:release_ready` to `true` or `reproducible_build` to `true` fails closed.
    let mut tampered = parsed;
    for prop in tampered["metadata"]["properties"]
        .as_array_mut()
        .expect("props")
    {
        if prop["name"] == "safeevidence:release_ready" {
            prop["value"] = serde_json::json!("true");
        }
    }
    let report = verify_release_sbom(&tampered.to_string(), &fixture_expected());
    assert!(!report.ok);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("safeevidence:release_ready"))
    );

    let npm_lock = r#"{
      "name": "safeevidence-desktop",
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "safeevidence-desktop", "version": "0.0.0", "license": "Apache-2.0" },
        "node_modules/@tauri-apps/api": {
          "version": "2.12.0",
          "license": "Apache-2.0 OR MIT",
          "integrity": "sha512-synthetic=="
        }
      }
    }"#;
    assert_eq!(npm_lock_packages(npm_lock).unwrap().len(), 1);
    assert!(
        npm_packages_missing_from_document(npm_lock, &document)
            .unwrap()
            .is_empty()
    );

    // `serde 1.0.0` is present as `pkg:cargo/serde@1.0.0`, NOT `pkg:npm/serde@1.0.0`.
    let npm_with_serde = r#"{
      "name": "safeevidence-desktop",
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "safeevidence-desktop", "version": "0.0.0" },
        "node_modules/@tauri-apps/api": { "version": "2.12.0", "license": "MIT" },
        "node_modules/serde": { "version": "1.0.0", "license": "MIT" }
      }
    }"#;
    assert_eq!(
        npm_packages_missing_from_document(npm_with_serde, &document).unwrap(),
        ["serde 1.0.0"]
    );
}

#[test]
fn malformed_input_is_an_error_not_full_coverage() {
    assert!(packages_missing_from_document(LOCK, "not json").is_err());
    assert!(packages_missing_from_document(LOCK, "{}").is_err());
    assert!(lock_packages("").is_err());
    assert!(lock_packages("name = \"a\"\nname = \"b\"\nversion = \"1\"\n").is_err());
    assert!(lock_packages("name = \"a\"\n").is_err());
    assert!(npm_lock_packages("{}").is_err());
    assert!(npm_lock_packages(r#"{"packages":{"":{"version":"0.0.0"}}}"#).is_err());
}

#[test]
fn native_bindings_are_classified_and_unknown_ones_fail() {
    let known = classify_native(&[
        "libsqlite3-sys".to_owned(),
        "openssl-sys".to_owned(),
        "webkit2gtk-sys".to_owned(),
        "webview2-com-sys".to_owned(),
    ])
    .unwrap();
    let names: Vec<_> = known.into_iter().map(|dep| dep.name).collect();
    assert_eq!(
        names,
        ["sqlcipher", "openssl", "webkit2gtk-4.1", "webview2"]
    );
    assert_eq!(
        classify_native(&["openssl-sys".to_owned(), "zz-sys".to_owned()]),
        Err(vec!["zz-sys".to_owned()])
    );
}

#[test]
fn compound_license_uses_expression_and_serial_is_uuid_shaped() {
    let mut input = fixture_input();
    input.rust_deps[0].license = Some("MIT OR Apache-2.0".to_owned());
    let document: serde_json::Value = serde_json::from_str(&generate_release_sbom(&input)).unwrap();
    let serde = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == "serde")
        .unwrap();
    assert_eq!(serde["licenses"][0]["expression"], "MIT OR Apache-2.0");
    let serial = document["serialNumber"].as_str().unwrap();
    let uuid = serial.strip_prefix("urn:uuid:").unwrap();
    let groups: Vec<usize> = uuid.split('-').map(str::len).collect();
    assert_eq!(groups, [8, 4, 4, 4, 12]);
}

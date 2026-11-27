//! `WP-24` / `TA-28` unsigned offline staging manifest and verification tests.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use safeevidence_release::staging::{
    BLOCKING_SIGNING_GATE, STAGING_SCHEMA_VERSION, StagedArtifactEntry, UnsignedStagingManifest,
    build_unsigned_staging_manifest, verify_unsigned_staging_bundle,
};
use safeevidence_release::{
    BuildEnvironment, ExpectedBinding, NativeDependency, NpmDependency, PackAsset, ReleaseArtifact,
    ReleaseSbomInput, RustDependency, WorkspacePackage, generate_release_sbom, sha256_hex,
};

const REAL_NOTICES: &[u8] = include_bytes!("../../../../THIRD_PARTY_NOTICES.md");
const REAL_TAURI_CONF: &[u8] = include_bytes!("../../../apps/desktop/src-tauri/tauri.conf.json");

static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("se-stage-{label}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sample_sbom_and_binding(artifacts: Vec<ReleaseArtifact>) -> (String, ExpectedBinding) {
    let source_sha = "1".repeat(40);
    let tree_sha = "2".repeat(40);
    let cargo_lock_sha256 = "3".repeat(64);
    let desktop_cargo_lock_sha256 = Some("4".repeat(64));
    let desktop_package_lock_sha256 = Some("5".repeat(64));

    let input = ReleaseSbomInput {
        source_sha: source_sha.clone(),
        tree_sha: tree_sha.clone(),
        cargo_lock_sha256: cargo_lock_sha256.clone(),
        desktop_cargo_lock_sha256: desktop_cargo_lock_sha256.clone(),
        desktop_package_lock_sha256: desktop_package_lock_sha256.clone(),
        build_env: BuildEnvironment {
            os: "windows".to_owned(),
            os_version: "11".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            rustc: "1.98.1".to_owned(),
            cargo: "1.98.1".to_owned(),
        },
        workspace_packages: vec![WorkspacePackage {
            name: "safeevidence-desktop".to_owned(),
            version: "0.0.0".to_owned(),
            license: Some("Apache-2.0".to_owned()),
        }],
        rust_deps: vec![RustDependency {
            name: "serde".to_owned(),
            version: "1.0.151".to_owned(),
            license: Some("MIT OR Apache-2.0".to_owned()),
        }],
        npm_deps: vec![NpmDependency {
            name: "react".to_owned(),
            version: "19.3.0".to_owned(),
            license: Some("MIT".to_owned()),
            integrity: Some("sha512-synthetic==".to_owned()),
        }],
        native_deps: vec![NativeDependency {
            name: "sqlcipher".to_owned(),
            classification: "bundled-source".to_owned(),
            detail: "bundled via libsqlite3-sys".to_owned(),
        }],
        artifacts,
        pack_assets: vec![PackAsset {
            name: "pack-vs1a-synthetic".to_owned(),
            kind: "offline-pack".to_owned(),
            rights_note: "synthetic fixture only".to_owned(),
        }],
    };
    let expected = ExpectedBinding {
        source_sha,
        tree_sha,
        cargo_lock_sha256,
        desktop_cargo_lock_sha256,
        desktop_package_lock_sha256,
        workspace_package_names: vec!["safeevidence-desktop".to_owned()],
    };
    (generate_release_sbom(&input), expected)
}

#[test]
fn unsigned_staging_manifest_is_deterministic_honest_and_rejects_tamper_or_signing_claims() {
    let dir = TempDir::new("unsigned");
    std::fs::create_dir_all(dir.0.join("bin")).expect("bin dir");
    let app_bytes = b"MZ-unsigned-staging-desktop-binary";
    let bench_bytes = b"MZ-unsigned-staging-bench-binary";
    std::fs::write(dir.0.join("bin/safeevidence-desktop.exe"), app_bytes).unwrap();
    std::fs::write(dir.0.join("bin/safeevidence_bench.exe"), bench_bytes).unwrap();

    let app_sha = sha256_hex(app_bytes);
    let bench_sha = sha256_hex(bench_bytes);

    let (sbom_json, expected) = sample_sbom_and_binding(vec![
        ReleaseArtifact {
            name: "safeevidence-desktop".to_owned(),
            sha256: app_sha.clone(),
        },
        ReleaseArtifact {
            name: "safeevidence_bench".to_owned(),
            sha256: bench_sha.clone(),
        },
    ]);

    let entries = vec![
        StagedArtifactEntry {
            name: "safeevidence_bench".to_owned(),
            relative_path: "bin/safeevidence_bench.exe".to_owned(),
            byte_len: bench_bytes.len() as u64,
            sha256: bench_sha,
        },
        StagedArtifactEntry {
            name: "safeevidence-desktop".to_owned(),
            relative_path: "bin/safeevidence-desktop.exe".to_owned(),
            byte_len: app_bytes.len() as u64,
            sha256: app_sha,
        },
    ];

    let manifest_a = build_unsigned_staging_manifest(
        &dir.0,
        entries.clone(),
        &sbom_json,
        &expected,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    )
    .expect("build manifest A");
    let manifest_b = build_unsigned_staging_manifest(
        &dir.0,
        entries.into_iter().rev().collect(),
        &sbom_json,
        &expected,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    )
    .expect("build manifest B independent of input order");

    assert_eq!(manifest_a, manifest_b);
    assert_eq!(manifest_a.schema_version(), STAGING_SCHEMA_VERSION);
    assert!(!manifest_a.signed());
    assert!(!manifest_a.installer_bundle_active());
    assert!(!manifest_a.release_qualified());
    assert_eq!(manifest_a.blocking_gate(), BLOCKING_SIGNING_GATE);

    let json_a = manifest_a.to_canonical_json().expect("json A");
    let json_b = manifest_b.to_canonical_json().expect("json B");
    assert_eq!(json_a, json_b);

    let report = verify_unsigned_staging_bundle(
        &dir.0,
        &json_a,
        &sbom_json,
        &expected,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    );
    assert!(report.ok, "unexpected failures: {:?}", report.failures);
    assert_eq!(report.verified_artifact_count, 2);

    // Forged manifest claiming signed: true or release_qualified: true fails deserialization:
    let mut forged_signed: serde_json::Value = serde_json::from_str(&json_a).unwrap();
    forged_signed["signed"] = serde_json::json!(true);
    assert!(serde_json::from_value::<UnsignedStagingManifest>(forged_signed).is_err());

    let mut forged_qualified: serde_json::Value = serde_json::from_str(&json_a).unwrap();
    forged_qualified["release_qualified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<UnsignedStagingManifest>(forged_qualified).is_err());

    // Enabling bundle.active in tauri.conf.json fails verification under EXT-05:
    let active_conf = br#"{"productName":"SafeEvidence","bundle":{"active":true}}"#;
    let bad_conf_report = verify_unsigned_staging_bundle(
        &dir.0,
        &json_a,
        &sbom_json,
        &expected,
        REAL_NOTICES,
        active_conf,
    );
    assert!(!bad_conf_report.ok);

    // B-1 regression: null certificateThumbprint must not short-circuit signCommand rejection:
    let sneaky_windows_sign_conf = br#"{"productName":"SafeEvidence","bundle":{"active":false,"windows":{"certificateThumbprint":null,"signCommand":"signtool.exe sign /fd sha256"}}}"#;
    assert!(
        build_unsigned_staging_manifest(
            &dir.0,
            vec![
                StagedArtifactEntry {
                    name: "safeevidence-desktop".to_owned(),
                    relative_path: "bin/safeevidence-desktop.exe".to_owned(),
                    byte_len: app_bytes.len() as u64,
                    sha256: sha256_hex(app_bytes),
                },
                StagedArtifactEntry {
                    name: "safeevidence_bench".to_owned(),
                    relative_path: "bin/safeevidence_bench.exe".to_owned(),
                    byte_len: bench_bytes.len() as u64,
                    sha256: sha256_hex(bench_bytes),
                },
            ],
            &sbom_json,
            &expected,
            REAL_NOTICES,
            sneaky_windows_sign_conf,
        )
        .is_err()
    );
    let sneaky_sign_report = verify_unsigned_staging_bundle(
        &dir.0,
        &json_a,
        &sbom_json,
        &expected,
        REAL_NOTICES,
        sneaky_windows_sign_conf,
    );
    assert!(!sneaky_sign_report.ok);

    // B-2a regression: omitting an SBOM-declared file artifact from the staging manifest is rejected:
    let partial_entries = vec![StagedArtifactEntry {
        name: "safeevidence-desktop".to_owned(),
        relative_path: "bin/safeevidence-desktop.exe".to_owned(),
        byte_len: app_bytes.len() as u64,
        sha256: sha256_hex(app_bytes),
    }];
    assert!(
        build_unsigned_staging_manifest(
            &dir.0,
            partial_entries,
            &sbom_json,
            &expected,
            REAL_NOTICES,
            REAL_TAURI_CONF,
        )
        .is_err()
    );

    // Path traversal and Windows reserved DOS device names in artifact relative_path are rejected:
    for unsafe_rel in ["../outside.exe", "bin/NUL.exe", "bin/trailing."] {
        let bad_entry = vec![StagedArtifactEntry {
            name: "safeevidence-desktop".to_owned(),
            relative_path: unsafe_rel.to_owned(),
            byte_len: app_bytes.len() as u64,
            sha256: sha256_hex(app_bytes),
        }];
        assert!(
            build_unsigned_staging_manifest(
                &dir.0,
                bad_entry,
                &sbom_json,
                &expected,
                REAL_NOTICES,
                REAL_TAURI_CONF,
            )
            .is_err(),
            "expected unsafe path {unsafe_rel} to fail closed"
        );
    }

    // B-2b regression: uninventoried / sideloaded file in staging_root fails closed:
    let rogue_dll = dir.0.join("bin/rogue.dll");
    std::fs::write(&rogue_dll, b"MZ-unlisted-sideload").unwrap();
    let sideload_report = verify_unsigned_staging_bundle(
        &dir.0,
        &json_a,
        &sbom_json,
        &expected,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    );
    assert!(!sideload_report.ok);
    std::fs::remove_file(&rogue_dll).unwrap();

    // Tampering with staged binary bytes on disk fails verification:
    std::fs::write(dir.0.join("bin/safeevidence-desktop.exe"), b"MZ-tampered").unwrap();
    let tampered_report = verify_unsigned_staging_bundle(
        &dir.0,
        &json_a,
        &sbom_json,
        &expected,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    );
    assert!(!tampered_report.ok);
}

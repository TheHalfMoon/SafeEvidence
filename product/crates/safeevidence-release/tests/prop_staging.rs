//! Structure-aware deterministic property suite for `safeevidence_release::staging`
//! (`ADR-0002`, `ADR-0003`, `WP-24`, `TA-28`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use safeevidence_release::staging::{
    RESEARCH_INTENDED_USE_SCOPE_V1, RESEARCH_RELEASE_SCHEMA_VERSION, ResearchQualificationAxes,
    ResearchReleaseManifest, StagedArtifactEntry, UnsignedStagingManifest,
    build_research_release_manifest, build_unsigned_staging_manifest,
};
use safeevidence_release::{
    BuildEnvironment, ExpectedBinding, NativeDependency, NpmDependency, PackAsset, ReleaseArtifact,
    ReleaseSbomInput, RustDependency, WorkspacePackage, generate_release_sbom, sha256_hex,
};

const REAL_NOTICES: &[u8] = include_bytes!("../../../../THIRD_PARTY_NOTICES.md");
const REAL_TAURI_CONF: &[u8] = include_bytes!("../../../apps/desktop/src-tauri/tauri.conf.json");

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("se-prop-stage-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Prng(u64);

impl Prng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bounded(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }
}

fn build_fixture_sbom(artifacts: Vec<ReleaseArtifact>) -> (String, ExpectedBinding) {
    let source_sha = "a".repeat(40);
    let tree_sha = "b".repeat(40);
    let cargo_lock_sha256 = "c".repeat(64);
    let input = ReleaseSbomInput {
        source_sha: source_sha.clone(),
        tree_sha: tree_sha.clone(),
        cargo_lock_sha256: cargo_lock_sha256.clone(),
        desktop_cargo_lock_sha256: None,
        desktop_package_lock_sha256: None,
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
            integrity: Some("sha512-x==".to_owned()),
        }],
        native_deps: vec![NativeDependency {
            name: "sqlcipher".to_owned(),
            classification: "bundled-source".to_owned(),
            detail: "libsqlite3-sys".to_owned(),
        }],
        artifacts,
        pack_assets: vec![PackAsset {
            name: "synthetic-pack".to_owned(),
            kind: "offline-pack".to_owned(),
            rights_note: "synthetic".to_owned(),
        }],
    };
    let expected = ExpectedBinding {
        source_sha,
        tree_sha,
        cargo_lock_sha256,
        desktop_cargo_lock_sha256: None,
        desktop_package_lock_sha256: None,
        workspace_package_names: vec!["safeevidence-desktop".to_owned()],
    };
    (generate_release_sbom(&input), expected)
}

#[test]
fn case_colliding_paths_and_forged_7axis_research_manifests_fail_closed() {
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.0.join("bin")).unwrap();
    let payload = b"MZ-research-workstation";
    std::fs::write(dir.0.join("bin/safeevidence.exe"), payload).unwrap();
    let sha = sha256_hex(payload);

    // 1. Case-colliding relative paths ("bin/safeevidence.exe" vs "bin/SafeEvidence.exe") fail closed:
    let (sbom_two, expected_two) = build_fixture_sbom(vec![
        ReleaseArtifact {
            name: "artifact-a".to_owned(),
            sha256: sha.clone(),
        },
        ReleaseArtifact {
            name: "artifact-b".to_owned(),
            sha256: sha.clone(),
        },
    ]);
    let colliding = vec![
        StagedArtifactEntry {
            name: "artifact-a".to_owned(),
            relative_path: "bin/safeevidence.exe".to_owned(),
            byte_len: payload.len() as u64,
            sha256: sha.clone(),
        },
        StagedArtifactEntry {
            name: "artifact-b".to_owned(),
            relative_path: "bin/SafeEvidence.exe".to_owned(),
            byte_len: payload.len() as u64,
            sha256: sha.clone(),
        },
    ];
    let err = build_unsigned_staging_manifest(
        &dir.0,
        colliding,
        &sbom_two,
        &expected_two,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    )
    .unwrap_err();
    assert!(err.contains("case-colliding"));

    // File-vs-directory prefix collision ("bin/safeevidence.exe" vs "bin/safeevidence.exe/sub.dll") fails closed:
    let prefix_colliding = vec![
        StagedArtifactEntry {
            name: "artifact-a".to_owned(),
            relative_path: "bin/safeevidence.exe".to_owned(),
            byte_len: payload.len() as u64,
            sha256: sha.clone(),
        },
        StagedArtifactEntry {
            name: "artifact-b".to_owned(),
            relative_path: "bin/safeevidence.exe/sub.dll".to_owned(),
            byte_len: payload.len() as u64,
            sha256: sha.clone(),
        },
    ];
    let prefix_err = build_unsigned_staging_manifest(
        &dir.0,
        prefix_colliding,
        &sbom_two,
        &expected_two,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    )
    .unwrap_err();
    assert!(prefix_err.contains("collides with directory prefix"));

    // 2. Valid 7-axis ResearchReleaseManifest builds cleanly and enforces all false external flags:
    let (sbom_one, expected_one) = build_fixture_sbom(vec![ReleaseArtifact {
        name: "safeevidence-desktop".to_owned(),
        sha256: sha.clone(),
    }]);
    let unsigned = build_unsigned_staging_manifest(
        &dir.0,
        vec![StagedArtifactEntry {
            name: "safeevidence-desktop".to_owned(),
            relative_path: "bin/safeevidence.exe".to_owned(),
            byte_len: payload.len() as u64,
            sha256: sha,
        }],
        &sbom_one,
        &expected_one,
        REAL_NOTICES,
        REAL_TAURI_CONF,
    )
    .unwrap();

    let bench_sha = "f".repeat(64);
    let research = build_research_release_manifest(
        &unsigned,
        &bench_sha,
        ResearchQualificationAxes {
            completed_engineering: true,
            independently_verified_engineering: true,
            ai_assisted_security_qualified: true,
            automated_scientific_evaluated: true,
        },
    )
    .unwrap();
    assert_eq!(research.schema_version(), RESEARCH_RELEASE_SCHEMA_VERSION);
    assert_eq!(
        research.intended_use_scope(),
        RESEARCH_INTENDED_USE_SCOPE_V1
    );
    assert!(research.research_release_qualified());
    assert!(!research.human_independent_security_review());
    assert!(!research.os_ca_code_signed());
    assert!(!research.actual_clinical_validation());
    assert!(!research.actual_regulatory_authorization());

    let research_json = research.to_canonical_json().unwrap();
    let parsed: ResearchReleaseManifest = serde_json::from_str(&research_json).unwrap();
    assert_eq!(parsed, research);
    assert_eq!(
        safeevidence_release::staging::verify_research_release_manifest(
            &research_json,
            &unsigned,
            &bench_sha
        )
        .unwrap(),
        research
    );
    assert!(
        safeevidence_release::staging::verify_research_release_manifest(
            &research_json,
            &unsigned,
            &"0".repeat(64)
        )
        .is_err()
    );

    // Every forbidden external claim fails closed on deserialization:
    for forbidden_flag in [
        "human_independent_security_review",
        "os_ca_code_signed",
        "installer_bundle_active",
        "actual_clinical_validation",
        "actual_regulatory_authorization",
    ] {
        let mut forged: serde_json::Value = serde_json::from_str(&research_json).unwrap();
        forged[forbidden_flag] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<ResearchReleaseManifest>(forged).is_err(),
            "forged {forbidden_flag}=true must fail closed"
        );
    }

    // Incomplete axis must set research_release_qualified == false and reject forged true:
    let incomplete = build_research_release_manifest(
        &unsigned,
        &bench_sha,
        ResearchQualificationAxes {
            completed_engineering: true,
            independently_verified_engineering: true,
            ai_assisted_security_qualified: false,
            automated_scientific_evaluated: true,
        },
    )
    .unwrap();
    assert!(!incomplete.research_release_qualified());

    // 3. 500-trial JSON/path fuzzing over UnsignedStagingManifest & ResearchReleaseManifest:
    let unsigned_json = unsigned.to_canonical_json().unwrap();
    let mut rng = Prng::new(0x57A6_1460_2026_1127);
    let hostile_paths = [
        "",
        "/abs/path.exe",
        "bin\\win.exe",
        "C:drive.exe",
        "bin/../escape.exe",
        "bin/CON.exe",
        "bin/LPT9.dll",
        "bin/trailing.",
        "bin/space ",
        "bin/\x07bell.exe",
    ];
    for _ in 0..500 {
        let mut bad_u: serde_json::Value = serde_json::from_str(&unsigned_json).unwrap();
        match rng.bounded(4) {
            0 => {
                bad_u["artifacts"][0]["relative_path"] =
                    serde_json::json!(hostile_paths[rng.bounded(hostile_paths.len())]);
            }
            1 => {
                bad_u["artifacts"][0]["byte_len"] = serde_json::json!(0);
            }
            2 => {
                bad_u["manifest_sha256"] = serde_json::json!("0".repeat(64));
            }
            _ => {
                bad_u["blocking_gate"] = serde_json::json!("BYPASSED");
            }
        }
        assert!(serde_json::from_value::<UnsignedStagingManifest>(bad_u).is_err());
    }
}

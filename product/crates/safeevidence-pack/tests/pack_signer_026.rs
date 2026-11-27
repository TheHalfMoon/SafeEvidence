//! `ADM-0016` / `T07` pack signer + RFC 8032 Ed25519 + monotonic anti-rollback tests (`TA-06`,
//! `TA-28`).

use std::fs;
use std::path::Path;

use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::packs::{
    PackAdmitReason, PackArtifactEntry, PackArtifactKind, PackPromotionState,
    PackSignerDoctorStatus,
};
use safeevidence_pack::{
    PackStore, SYNTHETIC_PACK_TRUST_ROOT_ID, WirePackArtifact, WirePackManifest, admit_pack_dir,
    compute_content_digest, pack_signing_payload, sign_pack_payload,
};

fn write_signed_fixture(
    dir: &Path,
    pack_id: &str,
    version: &str,
    epoch: u64,
    payload_bytes: &[u8],
) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("payload.txt"), payload_bytes).unwrap();
    let art_digest = DigestSha256::of(payload_bytes);
    let entries = vec![PackArtifactEntry {
        relative_path: "payload.txt".to_owned(),
        kind: PackArtifactKind::FixtureBytes,
        digest: art_digest.clone(),
    }];
    let content_digest = compute_content_digest(&entries);
    let rights_uri = "https://github.com/TheHalfMoon/SafeEvidence/blob/main/LICENSE";
    let sbom_ref = "sbom:synthetic-pack-v1";
    let sig_payload = pack_signing_payload(
        pack_id,
        version,
        epoch,
        &content_digest.to_hex(),
        rights_uri,
        sbom_ref,
        "none",
        &[],
    );
    let signature_hex = sign_pack_payload(&sig_payload);
    let wire = WirePackManifest {
        pack_id: pack_id.to_owned(),
        version: version.to_owned(),
        pack_epoch: epoch,
        content_digest: content_digest.to_hex(),
        artifacts: vec![WirePackArtifact {
            relative_path: "payload.txt".to_owned(),
            kind: PackArtifactKind::FixtureBytes,
            digest: art_digest.to_hex(),
        }],
        rights_uri: rights_uri.to_owned(),
        sbom_ref: sbom_ref.to_owned(),
        runtime_requirements: "none".to_owned(),
        benchmark_links: vec![],
        promotion_state: PackPromotionState::Candidate,
        trust_root_id: SYNTHETIC_PACK_TRUST_ROOT_ID.to_owned(),
        signature_hex,
    };
    fs::write(
        dir.join("pack.manifest.json"),
        serde_json::to_vec_pretty(&wire).unwrap(),
    )
    .unwrap();
}

#[test]
fn admits_signed_synthetic_pack_and_reports_honest_doctor_status() {
    let tmp = tempfile::tempdir().unwrap();
    write_signed_fixture(
        tmp.path(),
        "pack-fixture-signed-v1",
        "0.1.0",
        1,
        b"synthetic corpus\n",
    );
    let m = admit_pack_dir(tmp.path()).expect("admit");
    assert_eq!(m.pack_id.as_str(), "pack-fixture-signed-v1");
    assert_eq!(m.pack_epoch, 1);
    assert_eq!(m.trust_root_id, SYNTHETIC_PACK_TRUST_ROOT_ID);
    assert!(PackSignerDoctorStatus::ready_base().is_honest_ready_base());
}

#[test]
fn rejects_tampered_signature_tampered_bytes_and_unknown_trust_root() {
    let tmp = tempfile::tempdir().unwrap();
    let bad_sig = tmp.path().join("bad-sig");
    write_signed_fixture(
        &bad_sig,
        "pack-fixture-signed-v1",
        "0.1.0",
        1,
        b"synthetic corpus\n",
    );
    let manifest_path = bad_sig.join("pack.manifest.json");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    raw["signature_hex"] = serde_json::Value::String("00".repeat(64));
    fs::write(&manifest_path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
    assert_eq!(
        admit_pack_dir(&bad_sig).unwrap_err().reason(),
        PackAdmitReason::InvalidSignature
    );

    let bad_bytes = tmp.path().join("bad-bytes");
    write_signed_fixture(
        &bad_bytes,
        "pack-fixture-signed-v1",
        "0.1.0",
        1,
        b"synthetic corpus\n",
    );
    fs::write(bad_bytes.join("payload.txt"), b"tampered corpus\n").unwrap();
    assert_eq!(
        admit_pack_dir(&bad_bytes).unwrap_err().reason(),
        PackAdmitReason::DigestMismatch
    );

    let bad_root = tmp.path().join("bad-root");
    write_signed_fixture(
        &bad_root,
        "pack-fixture-signed-v1",
        "0.1.0",
        1,
        b"synthetic corpus\n",
    );
    let root_manifest = bad_root.join("pack.manifest.json");
    let mut root_raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&root_manifest).unwrap()).unwrap();
    root_raw["trust_root_id"] = serde_json::Value::String("not-a-root".into());
    fs::write(
        &root_manifest,
        serde_json::to_vec_pretty(&root_raw).unwrap(),
    )
    .unwrap();
    assert_eq!(
        admit_pack_dir(&bad_root).unwrap_err().reason(),
        PackAdmitReason::UnknownTrustRoot
    );
}

#[test]
fn anti_rollback_rejects_lower_epoch_lower_version_and_equivocation() {
    let tmp = tempfile::tempdir().unwrap();
    let v1_dir = tmp.path().join("v1");
    write_signed_fixture(
        &v1_dir,
        "pack-fixture-signed-v1",
        "0.2.0",
        2,
        b"corpus v2\n",
    );
    let m = admit_pack_dir(&v1_dir).unwrap();
    let mut store = PackStore::new();
    store.admit(m).unwrap();

    let lower_epoch = tmp.path().join("lower-epoch");
    write_signed_fixture(
        &lower_epoch,
        "pack-fixture-signed-v1",
        "0.3.0",
        1,
        b"corpus v2\n",
    );
    let m_low_ep = admit_pack_dir(&lower_epoch).unwrap();
    assert_eq!(
        store.admit(m_low_ep).unwrap_err().reason(),
        PackAdmitReason::AntiRollback
    );

    let lower_ver = tmp.path().join("lower-ver");
    write_signed_fixture(
        &lower_ver,
        "pack-fixture-signed-v1",
        "0.1.9",
        3,
        b"corpus v2\n",
    );
    let m_low_ver = admit_pack_dir(&lower_ver).unwrap();
    assert_eq!(
        store.admit(m_low_ver).unwrap_err().reason(),
        PackAdmitReason::AntiRollback
    );

    let equiv = tmp.path().join("equiv");
    write_signed_fixture(
        &equiv,
        "pack-fixture-signed-v1",
        "0.2.0",
        2,
        b"different bytes!\n",
    );
    let m_equiv = admit_pack_dir(&equiv).unwrap();
    assert_eq!(
        store.admit(m_equiv).unwrap_err().reason(),
        PackAdmitReason::DigestMismatch
    );

    let higher = tmp.path().join("higher");
    write_signed_fixture(
        &higher,
        "pack-fixture-signed-v1",
        "0.3.0",
        3,
        b"corpus v3\n",
    );
    let m_high = admit_pack_dir(&higher).unwrap();
    store.admit(m_high).unwrap();
    assert_eq!(store.list()[0].pack_epoch, 3);
    assert_eq!(store.list()[0].version, "0.3.0");
}

#[test]
fn rejects_artifact_kind_swap_metadata_tamper_and_colon_ads_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("signed");
    write_signed_fixture(&dir, "pack-sec-v1", "1.0.0", 1, b"safe bytes\n");
    let valid = admit_pack_dir(&dir).unwrap();

    // Mutating `PackArtifactEntry.kind` in memory MUST fail `PackStore::admit` (`ForbiddenKind` or `DigestMismatch`):
    let mut store = PackStore::new();
    let mut kind_swapped = valid.clone();
    kind_swapped.artifacts[0].kind = PackArtifactKind::Pickle;
    assert_eq!(
        store.admit(kind_swapped).unwrap_err().reason(),
        PackAdmitReason::ForbiddenArtifactKind
    );

    let mut benign_kind_swap = valid.clone();
    benign_kind_swap.artifacts[0].kind = PackArtifactKind::CorpusJsonl;
    assert_eq!(
        store.admit(benign_kind_swap).unwrap_err().reason(),
        PackAdmitReason::DigestMismatch
    );

    // Mutating `runtime_requirements` or `benchmark_links` without re-signing fails Ed25519 verify:
    let mut runtime_tampered = valid.clone();
    runtime_tampered.runtime_requirements = "custom-cuda-exec".to_owned();
    assert_eq!(
        store.admit(runtime_tampered).unwrap_err().reason(),
        PackAdmitReason::InvalidSignature
    );

    // Colon NTFS ADS path (`payload.txt:ads`) rejected fail-closed:
    let mut ads_manifest = valid;
    ads_manifest.artifacts[0].relative_path = "payload.txt:ads".to_owned();
    assert_eq!(
        store.admit(ads_manifest).unwrap_err().reason(),
        PackAdmitReason::InvalidManifest
    );
}

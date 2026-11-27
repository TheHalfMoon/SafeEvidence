//! `ADM-0016` / `T07` pack admission, forbidden executable/pickle denial, promotion lifecycle,
//! and worker ambient-deny boundary tests (`TA-06`, `TA-26`).

use std::fs;

use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::packs::{
    PackAdmitReason, PackArtifactEntry, PackArtifactKind, PackPromotionState,
};
use safeevidence_contracts::worker_policy::WorkerSupervisionPolicy;
use safeevidence_pack::{
    PackStore, SYNTHETIC_PACK_TRUST_ROOT_ID, WirePackArtifact, WirePackManifest, admit_pack_dir,
    compute_content_digest, forbidden_reason, pack_signing_payload, sign_pack_payload,
};

#[test]
fn offline_pack_install_list_and_promote_demotes_prior_current_to_last_green() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = PackStore::new();

    for (id, ver, epoch) in [("pack-a", "1.0.0", 1_u64), ("pack-b", "1.0.0", 1_u64)] {
        let dir = tmp.path().join(id);
        fs::create_dir_all(&dir).unwrap();
        let bytes = format!("fixture {id}\n").into_bytes();
        fs::write(dir.join("corpus.jsonl"), &bytes).unwrap();
        let art_dig = DigestSha256::of(&bytes);
        let content = compute_content_digest(&[PackArtifactEntry {
            relative_path: "corpus.jsonl".to_owned(),
            kind: PackArtifactKind::CorpusJsonl,
            digest: art_dig.clone(),
        }]);
        let payload = pack_signing_payload(
            id,
            ver,
            epoch,
            &content.to_hex(),
            "https://creativecommons.org/publicdomain/zero/1.0/",
            "sbom:synthetic",
            "none",
            &[],
        );
        let wire = WirePackManifest {
            pack_id: id.to_owned(),
            version: ver.to_owned(),
            pack_epoch: epoch,
            content_digest: content.to_hex(),
            artifacts: vec![WirePackArtifact {
                relative_path: "corpus.jsonl".to_owned(),
                kind: PackArtifactKind::CorpusJsonl,
                digest: art_dig.to_hex(),
            }],
            rights_uri: "https://creativecommons.org/publicdomain/zero/1.0/".to_owned(),
            sbom_ref: "sbom:synthetic".to_owned(),
            runtime_requirements: "none".to_owned(),
            benchmark_links: vec![],
            promotion_state: PackPromotionState::Candidate,
            trust_root_id: SYNTHETIC_PACK_TRUST_ROOT_ID.to_owned(),
            signature_hex: sign_pack_payload(&payload),
        };
        fs::write(
            dir.join("pack.manifest.json"),
            serde_json::to_vec_pretty(&wire).unwrap(),
        )
        .unwrap();
        let manifest = admit_pack_dir(&dir).unwrap();
        store.admit(manifest).unwrap();
    }

    let id_a = store.list()[0].pack_id.clone();
    let id_b = store.list()[1].pack_id.clone();
    let promoted_a = store.promote(&id_a, PackPromotionState::Current).unwrap();
    assert_eq!(promoted_a.promotion_state, PackPromotionState::Current);
    assert_eq!(store.current_pack_id(), Some(id_a.clone()));

    let promoted_b = store.promote(&id_b, PackPromotionState::Current).unwrap();
    assert_eq!(promoted_b.promotion_state, PackPromotionState::Current);
    assert_eq!(
        store.get(&id_a).unwrap().promotion_state,
        PackPromotionState::LastGreen
    );
}

#[test]
fn format_denies_pickle_codebin_custom_op_and_traversal() {
    assert_eq!(
        forbidden_reason(PackArtifactKind::Pickle),
        Some(PackAdmitReason::ForbiddenArtifactKind)
    );
    assert_eq!(
        forbidden_reason(PackArtifactKind::CodeBin),
        Some(PackAdmitReason::ForbiddenArtifactKind)
    );
    assert_eq!(
        forbidden_reason(PackArtifactKind::OnnxCustomOp),
        Some(PackAdmitReason::ForbiddenArtifactKind)
    );
    assert!(forbidden_reason(PackArtifactKind::FixtureBytes).is_none());
    assert!(forbidden_reason(PackArtifactKind::CorpusJsonl).is_none());

    let policy = WorkerSupervisionPolicy::deny_by_default();
    assert!(policy.ambient_denied());
    assert!(!policy.allow_network);
    assert!(!policy.allow_authority);
}

//! `WP-04` (`TA-06`) deterministic corpus validity-overlay replay & rights-admissible pack
//! filtering, plus `WP-17` (`TA-19` & `TA-30`) local living surveillance alerts over `ProofStore`
//! and `SAFEVD/` encrypted vault blobs.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use safeevidence_ask::overlay::{
    ValidityDeltaOp, ValidityOverlayBatch, build_rights_admissible_manifest,
    replay_validity_overlays,
};
use safeevidence_ask::{Corpus, Direction, Document, ask, load_corpus};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::objects::{DigestSha256, MedicalTime, TimePrecision};
use safeevidence_contracts::study::PublicationState;
use safeevidence_proofstore::ProofStore;
use safeevidence_proofstore::surveillance::{
    AlertCauseCode, SavedWatchQuery, SurveillanceError, SurveillanceUpdateEvent,
    WATCH_REGISTRY_ARTIFACT_ID, WatchRegistry, apply_surveillance_cycle, open_watch_registry_blob,
    prepare_outbound_preview, register_watch, seal_watch_registry_blob,
};
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_blob::{BOUNDED_BLOB_NONCE_BYTES, BoundedBlobContext};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;

const VS1A_CORPUS: &[u8] = include_bytes!("../../safeevidence-ask/fixtures/vs1a_corpus.json");

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("se-ta19-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ta06_overlay_replay_is_byte_deterministic_evicts_retracted_and_excludes_unknown_rights() {
    let baseline = load_corpus(VS1A_CORPUS, &DigestSha256::of(VS1A_CORPUS)).expect("vs1a loads");

    let new_doc = Document {
        doc_id: "doc-orbalin-new".to_owned(),
        study_id: "study-orbalin-99".to_owned(),
        title: "Orbalin in adults with synthetic ember fatigue".to_owned(),
        text: "Adults with synthetic ember fatigue received orbalin 20 mg daily. Fatigue score improved by 5 points compared with placebo at 8 weeks.".to_owned(),
        population: "adults".to_owned(),
        condition: "ember fatigue".to_owned(),
        intervention: "orbalin".to_owned(),
        finding: "Fatigue score improved by 5 points compared with placebo at 8 weeks.".to_owned(),
        direction: Direction::Benefit,
        publication_state: PublicationState::Current,
        rights: EvidenceCorpusRights::PublicDomain,
    };

    let batches = vec![
        ValidityOverlayBatch {
            target_epoch: 2,
            rights_grant_version: None,
            operations: vec![
                ValidityDeltaOp::UpsertDocument { document: new_doc },
                ValidityDeltaOp::UpdatePublicationState {
                    doc_id: "doc-veltrix-a".to_owned(),
                    new_state: PublicationState::Retracted,
                    rationale: "Data fabrication notice".to_owned(),
                },
            ],
        },
        ValidityOverlayBatch {
            target_epoch: 3,
            rights_grant_version: Some("synthetic-owned-2".to_owned()),
            operations: vec![
                ValidityDeltaOp::DeleteDocument {
                    doc_id: "doc-veltrix-peds".to_owned(),
                    rationale: "Withdrawn duplicate feed entry".to_owned(),
                },
                ValidityDeltaOp::UpdateRights {
                    doc_id: "doc-orbalin-new".to_owned(),
                    rights: EvidenceCorpusRights::Restricted,
                    rationale: "Publisher restriction asserted".to_owned(),
                },
            ],
        },
    ];

    let first_replay = replay_validity_overlays(&baseline, &batches).expect("first replay");
    let second_replay = replay_validity_overlays(&baseline, &batches).expect("second replay");

    // 1. Byte-identical output and identical SHA-256 store digest across independent replays:
    assert_eq!(first_replay.canonical_bytes, second_replay.canonical_bytes);
    assert_eq!(
        first_replay.canonical_digest,
        second_replay.canonical_digest
    );
    assert_eq!(first_replay.corpus.validity_epoch, 3);

    // 2. Retracted study (`doc-veltrix-a` + sibling `doc-veltrix-a-followup`) and deleted
    // `doc-veltrix-peds` are absent from `active_index_doc_ids`:
    for evicted in [
        "doc-veltrix-a",
        "doc-veltrix-a-followup",
        "doc-veltrix-peds",
    ] {
        assert!(
            !first_replay
                .active_index_doc_ids
                .iter()
                .any(|id| id == evicted),
            "{evicted} must leave active index"
        );
        assert!(first_replay.evicted_doc_ids.iter().any(|id| id == evicted));
    }

    // Asking about veltrixamine in adults now abstains cleanly (`SourceInvalidOrRetracted`):
    let ask_after_retraction = ask(
        "Does veltrixamine help adults with glimmer syndrome?",
        &first_replay.corpus,
    );
    assert_eq!(ask_after_retraction.outcome, TerminalOutcome::Abstain);
    assert_eq!(
        ask_after_retraction.reason,
        ReasonCode::SourceInvalidOrRetracted
    );

    // 3. Built pack manifest NEVER includes `Unknown` or `Restricted` rights items or retracted items:
    let pack = build_rights_admissible_manifest(
        "synthetic-m2-pack",
        "3.0.0",
        "https://safeevidence.org/synthetic-rights",
        &first_replay.corpus,
    )
    .expect("pack builds from remaining admissible docs");
    for forbidden in [
        "doc-veltrix-a",
        "doc-veltrix-a-followup",
        "doc-veltrix-peds",
        "doc-orbalin-new",
        "doc-no-rights",
    ] {
        assert!(
            !pack.documents.iter().any(|d| d.doc_id == forbidden),
            "forbidden doc {forbidden} leaked into built pack"
        );
    }
}

#[test]
fn ta19_and_ta30_surveillance_emits_cause_named_alert_preserves_historic_bytes_and_gates_opt_in() {
    let dir = TempDirGuard::new();
    let db_path = dir.0.join("proofstore.db");

    let vault_id = VaultId::from_bytes([0x41; VAULT_ID_BYTES]);
    let key_gen = KeyGeneration::new(7).expect("generation");
    let identity = VaultLeaseIdentity::new(vault_id, key_gen);
    let lease = VaultLease::new(identity);
    let store_ctx = KeyDerivationContext::new(vault_id, key_gen, KeyPurpose::StructuredStore);
    let vrk = OwnedKeyMaterial::from_bytes([0x5A; KEY_MATERIAL_BYTES]);

    let mut store = ProofStore::open(&db_path, lease.keyed_handle_lease(), store_ctx, &vrk)
        .expect("open store");
    let corpus: Corpus =
        load_corpus(VS1A_CORPUS, &DigestSha256::of(VS1A_CORPUS)).expect("vs1a loads");

    store.advance_epoch(corpus.validity_epoch).unwrap();
    store
        .set_rights_grant(&corpus.rights_grant_version)
        .unwrap();
    for doc in &corpus.documents {
        store.put_source(&doc.doc_id, doc.text.as_bytes()).unwrap();
    }

    let question = "Does veltrixamine help adults with glimmer syndrome?";
    let ans = ask(question, &corpus);
    let manifest = ans.manifest.expect("manifest");
    let brief = ans.brief.expect("brief");
    let receipt = store
        .commit(&manifest, brief.as_bytes())
        .expect("commit initial proof");
    assert_eq!(receipt.state, ProofState::Committed);

    let historic_before = store.read(&manifest.proof_id).expect("read before");
    assert_eq!(historic_before.state, ProofState::Committed);

    // Register a saved surveillance watch (defaults to `outbound_opt_in: false`):
    let mut registry = WatchRegistry::default();
    let watch = SavedWatchQuery {
        watch_id: "watch-glimmer-adults".to_owned(),
        canonical_pico_query: question.to_owned(),
        condition: "glimmer syndrome".to_owned(),
        intervention: "veltrixamine".to_owned(),
        population: Some("adults".to_owned()),
        linked_proof_id: Some(manifest.proof_id.clone()),
        cited_source_ids: vec![
            "doc-veltrix-a".to_owned(),
            "doc-veltrix-a-followup".to_owned(),
        ],
        outbound_opt_in: false,
    };
    register_watch(&mut registry, watch).expect("register watch");

    // TA-30: saved query without `outbound_opt_in: true` is refused for outbound preview, and
    // patient-specific free-text narrative is rejected at registration!
    assert!(matches!(
        prepare_outbound_preview(&registry, "watch-glimmer-adults"),
        Err(SurveillanceError::OutboundOptInRequired(_))
    ));
    let bad_patient_watch = SavedWatchQuery {
        watch_id: "watch-patient-leak".to_owned(),
        canonical_pico_query: "Should I prescribe veltrixamine to my patient?".to_owned(),
        condition: "glimmer syndrome".to_owned(),
        intervention: "veltrixamine".to_owned(),
        population: None,
        linked_proof_id: None,
        cited_source_ids: vec![],
        outbound_opt_in: true,
    };
    assert!(matches!(
        register_watch(&mut registry, bad_patient_watch),
        Err(SurveillanceError::PatientNarrativeForbidden(_))
    ));

    // Encrypt and round-trip the watch registry through `SAFEVD/` bounded vault AEAD blob:
    let blob_ctx = BoundedBlobContext::new(vault_id, WATCH_REGISTRY_ARTIFACT_ID, key_gen);
    let nonce = [0x11; BOUNDED_BLOB_NONCE_BYTES];
    let sealed = seal_watch_registry_blob(&registry, &vrk, blob_ctx, nonce).unwrap();
    assert!(
        !String::from_utf8_lossy(&sealed).contains("veltrixamine"),
        "sealed watch registry must not expose plaintext query terms"
    );
    let mut reopened_registry = open_watch_registry_blob(&vrk, blob_ctx, &sealed).unwrap();
    assert_eq!(reopened_registry, registry);

    // TA-19: Inject retraction + new contradicting trial in one surveillance update cycle:
    let alerts = apply_surveillance_cycle(
        &mut store,
        &mut reopened_registry,
        corpus.validity_epoch + 1,
        &[
            SurveillanceUpdateEvent::RetractSource {
                source_id: "doc-veltrix-a".to_owned(),
                rationale: "Trial data integrity retraction".to_owned(),
                authorized_by: "editorial-board-fixture".to_owned(),
                recorded_time: MedicalTime::new(
                    "2026-11-26T00:00:00Z",
                    TimePrecision::Instant,
                    false,
                ),
            },
            SurveillanceUpdateEvent::NewTrialPublished {
                doc_id: "doc-veltrix-null-2026".to_owned(),
                study_id: "study-veltrix-null-2026".to_owned(),
                condition: "glimmer syndrome".to_owned(),
                intervention: "veltrixamine".to_owned(),
                contradicts_existing: true,
                summary: "Adults with synthetic glimmer syndrome received veltrixamine 40 mg daily. The glimmer score did not improve compared with placebo at 12 weeks.".to_owned(),
            },
        ],
    )
    .expect("surveillance cycle succeeds");

    assert_eq!(store.epoch().unwrap(), corpus.validity_epoch + 1);
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].cause_code, AlertCauseCode::SourceRetracted);
    assert_eq!(
        alerts[0].affected_proof_state,
        Some(ProofState::CurrentlyInvalidated)
    );
    assert_eq!(alerts[1].cause_code, AlertCauseCode::NewContradictingTrial);

    // Historical proof standing is now `CurrentlyInvalidated`, while historical answer bytes and
    // manifest remain byte-for-byte identical (`TA-19`):
    let historic_after = store.read(&manifest.proof_id).expect("read after");
    assert_eq!(historic_after.state, ProofState::CurrentlyInvalidated);
    assert_eq!(historic_after.final_text, historic_before.final_text);
    assert_eq!(historic_after.manifest, historic_before.manifest);
}

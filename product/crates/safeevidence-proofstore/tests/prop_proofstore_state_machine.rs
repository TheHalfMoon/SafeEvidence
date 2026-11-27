//! Deterministic stateful property test for `ProofStore` and `surveillance`
//! (`ADR-0002`, `WP-03`, `WP-12`, `WP-17`, `TA-05`, `TA-14`, `TA-19`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::objects::{DigestSha256, MedicalTime, TimePrecision};
use safeevidence_contracts::proof::{
    AnswerProofManifest, ApplicabilityState, ContradictionState, EvidenceSpan, ProofClaim,
    ProofComponents, SupportLabel,
};
use safeevidence_contracts::study::{Known, ResultId, ScopedId, StudyId};
use safeevidence_proofstore::ProofStore;
use safeevidence_proofstore::surveillance::{
    AlertCauseCode, SavedWatchQuery, SurveillanceUpdateEvent, WatchRegistry,
    apply_surveillance_cycle, register_watch,
};
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;

static NEXT_STORE_ID: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = NEXT_STORE_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("se-prop-store-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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

fn open_test_store(path: &PathBuf) -> ProofStore {
    let vault_id = VaultId::from_bytes([0x44; VAULT_ID_BYTES]);
    let key_gen = KeyGeneration::new(1).unwrap();
    let lease = VaultLease::new(VaultLeaseIdentity::new(vault_id, key_gen));
    let ctx = KeyDerivationContext::new(vault_id, key_gen, KeyPurpose::StructuredStore);
    let vrk = OwnedKeyMaterial::from_bytes([0x77; KEY_MATERIAL_BYTES]);
    ProofStore::open(path, lease.keyed_handle_lease(), ctx, &vrk).unwrap()
}

fn build_manifest(
    proof_id: &str,
    final_text: &[u8],
    source_id: &str,
    source_bytes: &[u8],
    epoch: u64,
    grant: &str,
) -> AnswerProofManifest {
    let scalar_len = std::str::from_utf8(source_bytes).unwrap().chars().count() as u64;
    let scoped = |id: &str| ScopedId {
        scope: "prop".to_owned(),
        id: id.to_owned(),
        version: 1,
    };
    AnswerProofManifest {
        proof_id: proof_id.to_owned(),
        question_snapshot_digest: DigestSha256::of(proof_id.as_bytes()),
        final_text_digest: DigestSha256::of(final_text),
        claims: vec![ProofClaim {
            claim_id: format!("clm-{proof_id}"),
            material: true,
            support: SupportLabel::Supported,
            spans: vec![EvidenceSpan {
                source_id: source_id.to_owned(),
                source_version: "1".to_owned(),
                source_digest: DigestSha256::of(source_bytes),
                start_scalar: 0,
                end_scalar: scalar_len,
            }],
            studies: Known::Known(vec![StudyId(scoped(source_id))]),
            results: Known::Known(vec![ResultId(scoped(source_id))]),
        }],
        rights_grant_version: grant.to_owned(),
        validity_epoch: epoch,
        components: ProofComponents {
            retriever: "bm25-v1".to_owned(),
            reranker: None,
            translator: None,
            ocr: None,
            verifier: "exact-span-v1".to_owned(),
            generator: None,
            tools: vec![],
            prompts: vec![],
            policy: "p00-prop-v1".to_owned(),
            thresholds: "v1".to_owned(),
        },
        applicability: ApplicabilityState::ApplicableWithLimits,
        contradiction: ContradictionState::None,
        outcome: TerminalOutcome::AnswerWithCaution,
        reason: ReasonCode::None,
        post_verification_passed: true,
        verified_at_utc: "2026-11-27T00:00:00Z".to_owned(),
        state: ProofState::VerifiedUncommitted,
    }
}

#[test]
fn vocalized_arabic_watch_matching_and_atomic_batch_prevalidation_hold() {
    let dir = TempDir::new();
    let mut store = open_test_store(&dir.0.join("surv.db"));
    store.advance_epoch(1).unwrap();
    store.set_rights_grant("grant-1").unwrap();
    store
        .put_source("doc-1", b"Synthetic initial source text.")
        .unwrap();

    let mut registry = WatchRegistry::default();
    // Unvocalized Arabic watch for "متلازمة الوميض" + "فلتريكسامين":
    register_watch(
        &mut registry,
        SavedWatchQuery {
            watch_id: "watch-ar-1".to_owned(),
            canonical_pico_query: "\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f} \u{0641}\u{0644}\u{062a}\u{0631}\u{064a}\u{0643}\u{0633}\u{0627}\u{0645}\u{064a}\u{0646}".to_owned(),
            condition: "\u{0645}\u{062a}\u{0644}\u{0627}\u{0632}\u{0645}\u{0629} \u{0627}\u{0644}\u{0648}\u{0645}\u{064a}\u{0636}".to_owned(),
            intervention: "\u{0641}\u{0644}\u{062a}\u{0631}\u{064a}\u{0643}\u{0633}\u{0627}\u{0645}\u{064a}\u{0646}".to_owned(),
            population: None,
            linked_proof_id: None,
            cited_source_ids: vec!["doc-1".to_owned()],
            outbound_opt_in: false,
        },
    )
    .unwrap();

    // 1. Batch with a bad second event (empty rights grant) fails BEFORE advancing epoch or mutating doc-1:
    let bad_batch = apply_surveillance_cycle(
        &mut store,
        &mut registry,
        2,
        &[
            SurveillanceUpdateEvent::RetractSource {
                source_id: "doc-1".to_owned(),
                rationale: "Valid rationale".to_owned(),
                authorized_by: "editor".to_owned(),
                recorded_time: MedicalTime::new(
                    "2026-11-27T00:00:00Z",
                    TimePrecision::Instant,
                    false,
                ),
            },
            SurveillanceUpdateEvent::RotateRightsGrant {
                new_grant_version: "   ".to_owned(),
                reason: "Invalid empty grant".to_owned(),
            },
        ],
    );
    assert!(bad_batch.is_err());
    assert_eq!(
        store.epoch().unwrap(),
        1,
        "failed prevalidation must not advance store epoch"
    );
    assert!(registry.alerts.is_empty());

    // 2. Vocalized Arabic NewTrialPublished ("مُتَلَازِمَةُ الْوَمِيضِ" + tatweel "فَلْتَـرِيكْسَامِين") matches watch-ar-1!
    let alerts = apply_surveillance_cycle(
        &mut store,
        &mut registry,
        2,
        &[SurveillanceUpdateEvent::NewTrialPublished {
            doc_id: "doc-ar-2".to_owned(),
            study_id: "study-ar-2".to_owned(),
            condition: "\u{0645}\u{064f}\u{062a}\u{064e}\u{0644}\u{064e}\u{0627}\u{0632}\u{0650}\u{0645}\u{064e}\u{0629}\u{064f}  \u{0627}\u{0644}\u{0652}\u{0648}\u{064e}\u{0645}\u{0650}\u{064a}\u{0636}\u{0650}".to_owned(),
            intervention: "\u{0641}\u{064e}\u{0644}\u{0652}\u{062a}\u{064e}\u{0640}\u{0631}\u{0650}\u{064a}\u{0643}\u{0652}\u{0633}\u{064e}\u{0627}\u{0645}\u{0650}\u{064a}\u{0646}".to_owned(),
            contradicts_existing: true,
            summary: "\u{062a}\u{062c}\u{0631}\u{0628}\u{0629} \u{062c}\u{062f}\u{064a}\u{062f}\u{0629}.".to_owned(),
        }],
    )
    .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].watch_id, "watch-ar-1");
    assert_eq!(alerts[0].cause_code, AlertCauseCode::NewContradictingTrial);

    // 3. Retired rights-grant rotation at the end of a multi-event batch rolls back the ENTIRE
    // SQLite IMMEDIATE transaction (epoch stays 3, doc-1 stays un-retracted!):
    store.advance_epoch(3).unwrap();
    store.set_rights_grant("grant-2").unwrap();
    let retired_batch = apply_surveillance_cycle(
        &mut store,
        &mut registry,
        4,
        &[
            SurveillanceUpdateEvent::RetractSource {
                source_id: "doc-1".to_owned(),
                rationale: "Would retract if not rolled back".to_owned(),
                authorized_by: "editor".to_owned(),
                recorded_time: MedicalTime::new(
                    "2026-11-27T00:00:00Z",
                    TimePrecision::Instant,
                    false,
                ),
            },
            SurveillanceUpdateEvent::RotateRightsGrant {
                new_grant_version: "grant-1".to_owned(),
                reason: "Attempt to revive retired grant-1".to_owned(),
            },
        ],
    );
    assert!(retired_batch.is_err());
    assert_eq!(
        store.epoch().unwrap(),
        3,
        "atomic transaction must roll back epoch advance when trailing event fails"
    );
    assert!(
        !store.is_source_retracted("doc-1").unwrap(),
        "atomic transaction must roll back prior RetractSource event"
    );
}

#[test]
fn stateful_property_250_operations_preserve_append_only_standing_and_doctor_integrity() {
    let dir = TempDir::new();
    let mut store = open_test_store(&dir.0.join("model.db"));

    let mut rng = Prng::new(0x5708_E57A_2026_1127);
    let mut model_epoch = 1_u64;
    let mut grant_idx = 1_u64;
    let mut model_grant = format!("grant-{grant_idx}");
    let mut retired_grants: BTreeSet<String> = BTreeSet::new();
    let mut model_sources: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut retracted_sources: BTreeSet<String> = BTreeSet::new();
    let mut invalidated_proofs: BTreeSet<String> = BTreeSet::new();
    let mut committed_proofs: BTreeMap<String, (Vec<u8>, String, u64, String)> = BTreeMap::new();

    store.advance_epoch(model_epoch).unwrap();
    store.set_rights_grant(&model_grant).unwrap();
    for s in 0..4 {
        let id = format!("src-{s}");
        let bytes = format!("Synthetic source {s} cohort results.").into_bytes();
        store.put_source(&id, &bytes).unwrap();
        model_sources.insert(id, bytes);
    }

    for step in 0..250 {
        match rng.bounded(6) {
            0 => {
                // Advance epoch (monotonic; attempts to regress must fail):
                if rng.bounded(3) == 0 {
                    assert!(store.advance_epoch(model_epoch).is_err());
                } else {
                    model_epoch += 1;
                    store.advance_epoch(model_epoch).unwrap();
                }
            }
            1 => {
                // Rights grant rotation (retired grants must never come back):
                if rng.bounded(3) == 0 && !retired_grants.is_empty() {
                    let old = retired_grants.iter().next().unwrap().clone();
                    assert!(store.set_rights_grant(&old).is_err());
                } else {
                    retired_grants.insert(model_grant.clone());
                    grant_idx += 1;
                    model_grant = format!("grant-{grant_idx}");
                    store.set_rights_grant(&model_grant).unwrap();
                }
            }
            2 => {
                // Put source (immutable: identical bytes succeed, conflicting bytes fail):
                let id = format!("src-{}", rng.bounded(6));
                if let Some(existing) = model_sources.get(&id).cloned() {
                    store.put_source(&id, &existing).unwrap();
                    assert!(store.put_source(&id, b"tampered source bytes").is_err());
                } else {
                    let bytes = format!("Synthetic source {id} @ step {step}.").into_bytes();
                    store.put_source(&id, &bytes).unwrap();
                    model_sources.insert(id, bytes);
                }
            }
            3 => {
                // Commit proof:
                let src_id = format!("src-{}", rng.bounded(4));
                let src_bytes = model_sources[&src_id].clone();
                let pid = format!("prf-{step}");
                let text = format!("Brief for {pid}.").into_bytes();
                let manifest =
                    build_manifest(&pid, &text, &src_id, &src_bytes, model_epoch, &model_grant);
                if retracted_sources.contains(&src_id) {
                    assert!(store.commit(&manifest, &text).is_err());
                } else {
                    let rec = store.commit(&manifest, &text).unwrap();
                    assert_eq!(rec.state, ProofState::Committed);
                    // Idempotent replay succeeds; conflicting text under same proof_id fails:
                    assert!(store.commit(&manifest, &text).unwrap().replayed);
                    let bad_manifest = build_manifest(
                        &pid,
                        b"different text",
                        &src_id,
                        &src_bytes,
                        model_epoch,
                        &model_grant,
                    );
                    assert!(store.commit(&bad_manifest, b"different text").is_err());
                    committed_proofs.insert(pid, (text, src_id, model_epoch, model_grant.clone()));
                }
            }
            4 => {
                // Invalidate an existing proof:
                if let Some(pid) = committed_proofs.keys().next().cloned() {
                    store.invalidate(&pid, "audit invalidation").unwrap();
                    invalidated_proofs.insert(pid);
                }
            }
            _ => {
                // Retract one source:
                let src_id = format!("src-{}", rng.bounded(4));
                let t = MedicalTime::new("2026-11-27T00:00:00Z", TimePrecision::Instant, false);
                if !retracted_sources.contains(&src_id) {
                    store
                        .retract_source(&src_id, "synthetic retraction", "board", &t)
                        .unwrap();
                    retracted_sources.insert(src_id);
                }
            }
        }

        // Cross-check every committed proof against our independent reference state model:
        assert_eq!(store.epoch().unwrap(), model_epoch);
        assert_eq!(store.rights_grant().unwrap(), model_grant);
        for (pid, (expected_bytes, src_id, verified_epoch, verified_grant)) in &committed_proofs {
            let stored = store.read(pid).unwrap();
            assert_eq!(
                &stored.final_text, expected_bytes,
                "historical answer bytes must stay immutable across all transitions"
            );
            let expected_state = if invalidated_proofs.contains(pid)
                || retracted_sources.contains(src_id)
                || verified_grant != &model_grant
            {
                ProofState::CurrentlyInvalidated
            } else if *verified_epoch == model_epoch {
                ProofState::Committed
            } else {
                ProofState::CurrentnessUnknown
            };
            assert_eq!(stored.state, expected_state, "standing mismatch for {pid}");
        }
    }

    let doctor = store.verify_record_semantics_doctor().unwrap();
    assert!(
        doctor.passed(),
        "record semantics doctor failed: {doctor:?}"
    );
}

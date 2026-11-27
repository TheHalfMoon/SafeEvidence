//! `TA-10`, `TA-12`, and `TA-14` bilingual NLI entailment/contradiction, guideline supersession
//! & issuer-conflict detection, multi-outcome GRADE Summary-of-Findings table validation, and
//! source-loss-aware `EvidenceSnapshot` reproduction tests.

use std::collections::BTreeMap;

use safeevidence_ask::nli_verifier::{
    NliError, NliLabel, detect_corpus_contradictions, verify_bilingual_entailment,
};
use safeevidence_contracts::appraisal::{
    AppraisalConfirmation, CertaintyLevel, SummaryOfFindingsRow,
};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::guideline::{
    EvidenceSnapshot, GuidelineError, GuidelineMetadata, GuidelineStatus, RecommendationStrength,
    SnapshotDegradationReason, SnapshotReproductionState, SummaryOfFindingsTable,
    evaluate_guideline_set, verify_snapshot_reproduction,
};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{
    AnswerProofManifest, ApplicabilityState, ContradictionState, EvidenceSpan, ProofClaim,
    ProofComponents, SupportLabel,
};
use safeevidence_contracts::study::{Known, ScopedId, StudyId};

#[test]
fn bilingual_nli_detects_entailment_negation_numeric_unit_and_cross_study_conflicts() {
    let en_src =
        "Background sentence. Metformin 500 mg reduced fasting glucose in adults over 12 weeks.";
    let ok_en = verify_bilingual_entailment(
        "Metformin 500 mg reduced fasting glucose in adults over 12 weeks.",
        en_src,
    )
    .expect("EN entailment");
    assert_eq!(ok_en.label, NliLabel::Entails);
    assert_eq!(ok_en.matched_sentence_span, Some((21, 86)));

    let neg_en = verify_bilingual_entailment(
        "Metformin 500 mg did not reduce fasting glucose in adults over 12 weeks.",
        en_src,
    )
    .expect("EN negation flip");
    assert_eq!(neg_en.label, NliLabel::Contradicts);
    assert!(neg_en.defects.iter().any(|d| d == "negation_flip"));

    let num_en = verify_bilingual_entailment(
        "Metformin 850 mg reduced fasting glucose in adults over 12 weeks.",
        en_src,
    )
    .expect("EN numeric flip");
    assert_eq!(num_en.label, NliLabel::Contradicts);
    assert!(num_en.defects.iter().any(|d| d == "numeric_contradiction"));

    // Vocalized Arabic with Arabic-Indic digits (٥٠٠ مجم) vs ASCII 500 مجم:
    let ar_src = "\u{0645}\u{0642}\u{062f}\u{0645}\u{0629}. \u{062e}\u{064e}\u{0641}\u{064e}\u{0651}\u{0636}\u{064e} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} \u{0665}\u{0660}\u{0660} \u{0645}\u{062c}\u{0645} \u{0633}\u{0643}\u{0631} \u{0627}\u{0644}\u{062f}\u{0645} \u{0641}\u{064a} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}.";
    let ok_ar = verify_bilingual_entailment(
        "\u{062e}\u{0641}\u{0636} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} 500 \u{0645}\u{062c}\u{0645} \u{0633}\u{0643}\u{0631} \u{0627}\u{0644}\u{062f}\u{0645} \u{0641}\u{064a} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}.",
        ar_src,
    )
    .expect("AR entailment across harakat and Arabic-Indic numerals");
    assert_eq!(ok_ar.label, NliLabel::Entails);

    let neg_ar = verify_bilingual_entailment(
        "\u{0644}\u{0645} \u{064a}\u{062e}\u{0641}\u{0636} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} 500 \u{0645}\u{062c}\u{0645} \u{0633}\u{0643}\u{0631} \u{0627}\u{0644}\u{062f}\u{0645} \u{0641}\u{064a} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}.",
        ar_src,
    )
    .expect("AR negation flip");
    assert_eq!(neg_ar.label, NliLabel::Contradicts);

    assert_eq!(
        verify_bilingual_entailment("Claim \u{202E}with override.", en_src),
        Err(NliError::ForbiddenTextControl)
    );

    // Cross-study contradiction ignores duplicate reports within the same study_id:
    let same_study = detect_corpus_contradictions(&[
        (
            "study-1",
            "doc-1a",
            "Metformin reduced fasting glucose in adults.",
        ),
        (
            "study-1",
            "doc-1b",
            "Metformin did not reduce fasting glucose in adults.",
        ),
    ])
    .expect("same study");
    assert_eq!(same_study.state, ContradictionState::None);

    let diff_study = detect_corpus_contradictions(&[
        (
            "study-1",
            "doc-1a",
            "Metformin reduced fasting glucose in adults.",
        ),
        (
            "study-2",
            "doc-2a",
            "Metformin did not reduce fasting glucose in adults.",
        ),
    ])
    .expect("independent studies");
    assert_eq!(diff_study.state, ContradictionState::Material);
    assert_eq!(diff_study.conflicts.len(), 1);

    // 1. Mixed-polarity multi-clause sentence (`increased mortality and reduced fatigue`) MUST NOT
    // entail inverted `"reduced mortality"`:
    let mixed_src = "Veltrixamine increased mortality and reduced fatigue in adults.";
    let splice =
        verify_bilingual_entailment("Veltrixamine reduced mortality in adults.", mixed_src)
            .expect("mixed clause");
    assert_eq!(splice.label, NliLabel::Contradicts);
    assert!(splice.defects.iter().any(|d| d == "direction_flip"));

    // 2. Comparative argument swap (`Placebo reduced X more than veltrixamine`) MUST NOT entail inverted claim:
    let comp_src = "Placebo reduced symptom burden more than veltrixamine in adults.";
    let role_swap = verify_bilingual_entailment(
        "Veltrixamine reduced symptom burden more than placebo in adults.",
        comp_src,
    )
    .expect("role swap");
    assert_eq!(role_swap.label, NliLabel::Contradicts);
    assert!(
        role_swap
            .defects
            .iter()
            .any(|d| d == "comparator_role_swap")
    );

    // 3. Later contradicting sentence in the same source overrides earlier sentence:
    let two_sent = "Metformin reduced fasting glucose in adults. Metformin did not reduce fasting glucose in adults.";
    let override_res =
        verify_bilingual_entailment("Metformin reduced fasting glucose in adults.", two_sent)
            .expect("contradiction precedence");
    assert_eq!(override_res.label, NliLabel::Contradicts);

    // 4. Subset numeric claim (`50 mg` without repeating auxiliary `8 weeks`) entails cleanly,
    // and decimal `50.0` matches `50`:
    let ok_subset = verify_bilingual_entailment(
        "Metformin 500.0 mg reduced fasting glucose in adults.",
        en_src,
    )
    .expect("subset number");
    assert_eq!(ok_subset.label, NliLabel::Entails);

    // 5. Compatible null/benefit pairs (`did not increase mortality` + `reduced mortality`, and two
    // complementary negated directions) are NOT misclassified as Material contradictions:
    let compat_pair = detect_corpus_contradictions(&[
        (
            "study-1",
            "doc-1",
            "Veltrixamine did not increase mortality in adults.",
        ),
        (
            "study-2",
            "doc-2",
            "Veltrixamine reduced mortality in adults.",
        ),
    ])
    .expect("compatible negated harm + benefit");
    assert_eq!(compat_pair.state, ContradictionState::None);

    let two_nulls = detect_corpus_contradictions(&[
        (
            "study-1",
            "doc-1",
            "Veltrixamine did not increase mortality in adults.",
        ),
        (
            "study-2",
            "doc-2",
            "Veltrixamine did not reduce mortality in adults.",
        ),
    ])
    .expect("two compatible nulls");
    assert_eq!(two_nulls.state, ContradictionState::None);
}

#[test]
fn guideline_evaluation_tracks_supersession_and_surfaces_issuer_conflicts() {
    let span = EvidenceSpan {
        source_id: "gl-src-1".to_owned(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(b"Synthetic guideline text."),
        start_scalar: 0,
        end_scalar: 25,
    };
    let g_2022 = GuidelineMetadata {
        guideline_id: "gl-socA-2022".to_owned(),
        issuer: "Synthetic Society A".to_owned(),
        topic_concept: "cond_glycemic".to_owned(),
        version: "2022.1".to_owned(),
        issued_date: "2022-05-10".to_owned(),
        status: GuidelineStatus::Current,
        supersedes_guideline_id: None,
        recommendation: RecommendationStrength::ConditionalFor,
        rationale_summary: "Earlier synthetic recommendation.".to_owned(),
        certainty: CertaintyLevel::Low,
        source_digest: DigestSha256::of(b"g2022"),
        cited_spans: vec![span.clone()],
    };
    let g_2025 = GuidelineMetadata {
        guideline_id: "gl-socA-2025".to_owned(),
        issuer: "Synthetic Society A".to_owned(),
        topic_concept: "cond_glycemic".to_owned(),
        version: "2025.1".to_owned(),
        issued_date: "2025-03-15".to_owned(),
        status: GuidelineStatus::Current,
        supersedes_guideline_id: Some("gl-socA-2022".to_owned()),
        recommendation: RecommendationStrength::StrongFor,
        rationale_summary: "Updated synthetic recommendation superseding 2022.".to_owned(),
        certainty: CertaintyLevel::Moderate,
        source_digest: DigestSha256::of(b"g2025"),
        cited_spans: vec![span.clone()],
    };
    let g_soc_b = GuidelineMetadata {
        guideline_id: "gl-socB-2025".to_owned(),
        issuer: "Synthetic Society B".to_owned(),
        topic_concept: "cond_glycemic".to_owned(),
        version: "2025.1".to_owned(),
        issued_date: "2025-06-01".to_owned(),
        status: GuidelineStatus::Current,
        supersedes_guideline_id: None,
        recommendation: RecommendationStrength::ConditionalAgainst,
        rationale_summary: "Conflicting synthetic society recommendation.".to_owned(),
        certainty: CertaintyLevel::Low,
        source_digest: DigestSha256::of(b"gsocb"),
        cited_spans: vec![span.clone()],
    };

    let eval = evaluate_guideline_set(&[g_2022, g_2025, g_soc_b]).expect("evaluate guidelines");
    assert_eq!(
        eval.active_guideline_ids,
        vec!["gl-socA-2025".to_owned(), "gl-socB-2025".to_owned()]
    );
    assert_eq!(
        eval.superseded_guideline_ids,
        vec!["gl-socA-2022".to_owned()]
    );
    assert_eq!(eval.contradiction_state, ContradictionState::Material);
    assert_eq!(eval.issuer_conflicts.len(), 1);

    // P00 percentage ban enforced on SummaryOfFindingsTable:
    let bad_row = SummaryOfFindingsRow {
        outcome_id: "vs1a:out-1:1".to_owned(),
        outcome_definition: "Glycemic endpoint".to_owned(),
        study_count: 2,
        total_participants: Some(400),
        effect_summary_text: "RR 0.80 with 95% confidence".to_owned(),
        certainty: CertaintyLevel::Moderate,
        certainty_reasons: vec!["no downgrade".to_owned(); 8],
        workflow_status: "CONFIRMED".to_owned(),
        authorized_by: Some("researcher-1".to_owned()),
    };
    let tbl_bad = SummaryOfFindingsTable {
        table_id: "sof-1".to_owned(),
        comparison_label: "Intervention vs Placebo".to_owned(),
        population_summary: "Adults".to_owned(),
        intervention_summary: "Intervention".to_owned(),
        comparator_summary: "Placebo".to_owned(),
        rows: vec![bad_row],
        confirmation: AppraisalConfirmation::Confirmed {
            authorized_by: "researcher-1".to_owned(),
            confirmed_at_utc: "2026-11-27T00:00:00Z".to_owned(),
        },
    };
    assert_eq!(
        tbl_bad.validate(),
        Err(GuidelineError::ForbiddenControlOrConfidence(
            "row.effect_summary_text"
        ))
    );
}

#[test]
fn evidence_snapshot_downgrades_to_partial_reproduction_when_source_revoked_or_missing() {
    let src1_bytes = b"Synthetic study 1 sentence.";
    let src2_bytes = b"Synthetic study 2 sentence.";
    let manifest = AnswerProofManifest {
        proof_id: "proof-snap-1".to_owned(),
        question_snapshot_digest: DigestSha256::of(b"does x help y"),
        final_text_digest: DigestSha256::of(b"brief text"),
        validity_epoch: 3,
        outcome: TerminalOutcome::AnswerWithCaution,
        reason: ReasonCode::None,
        post_verification_passed: true,
        verified_at_utc: "2026-11-27T00:00:00Z".to_owned(),
        state: ProofState::Committed,
        claims: vec![
            ProofClaim {
                claim_id: "c-1".to_owned(),
                material: true,
                support: SupportLabel::Supported,
                spans: vec![EvidenceSpan {
                    source_id: "doc-1".to_owned(),
                    source_version: "1".to_owned(),
                    source_digest: DigestSha256::of(src1_bytes),
                    start_scalar: 0,
                    end_scalar: 27,
                }],
                studies: Known::Known(vec![StudyId(ScopedId {
                    scope: "syn".to_owned(),
                    id: "st-1".to_owned(),
                    version: 1,
                })]),
                results: Known::Unknown {
                    reason: "synthetic".to_owned(),
                },
            },
            ProofClaim {
                claim_id: "c-2".to_owned(),
                material: true,
                support: SupportLabel::Supported,
                spans: vec![EvidenceSpan {
                    source_id: "doc-2".to_owned(),
                    source_version: "1".to_owned(),
                    source_digest: DigestSha256::of(src2_bytes),
                    start_scalar: 0,
                    end_scalar: 27,
                }],
                studies: Known::Known(vec![StudyId(ScopedId {
                    scope: "syn".to_owned(),
                    id: "st-2".to_owned(),
                    version: 1,
                })]),
                results: Known::Unknown {
                    reason: "synthetic".to_owned(),
                },
            },
        ],
        contradiction: ContradictionState::None,
        applicability: ApplicabilityState::ApplicableWithLimits,
        rights_grant_version: "SYNTHETIC-V1".to_owned(),
        components: ProofComponents {
            retriever: "safeevidence-hybrid-v1".to_owned(),
            reranker: Some("pico-reranker-v1".to_owned()),
            translator: None,
            ocr: None,
            verifier: "safeevidence-nli-v1".to_owned(),
            generator: None,
            tools: Vec::new(),
            prompts: Vec::new(),
            policy: "p00-v1".to_owned(),
            thresholds: "default-v1".to_owned(),
        },
    };

    let snapshot =
        EvidenceSnapshot::build("snap-001", "does x help y?", 3, manifest).expect("build snapshot");

    let mut all_present: BTreeMap<String, (&[u8], bool)> = BTreeMap::new();
    all_present.insert("doc-1".to_owned(), (src1_bytes.as_slice(), false));
    all_present.insert("doc-2".to_owned(), (src2_bytes.as_slice(), false));
    assert_eq!(
        verify_snapshot_reproduction(&snapshot, &all_present).expect("full"),
        SnapshotReproductionState::FullReproduction {
            verified_sources: vec!["doc-1".to_owned(), "doc-2".to_owned()]
        }
    );

    // Revoke doc-2: must report PartialReproduction with SourceRevoked:
    let mut doc2_revoked = all_present;
    doc2_revoked.insert("doc-2".to_owned(), (src2_bytes.as_slice(), true));
    match verify_snapshot_reproduction(&snapshot, &doc2_revoked).expect("partial") {
        SnapshotReproductionState::PartialReproduction {
            verified_sources,
            missing_or_revoked_sources,
        } => {
            assert_eq!(verified_sources, vec!["doc-1".to_owned()]);
            assert_eq!(missing_or_revoked_sources.len(), 1);
            assert_eq!(missing_or_revoked_sources[0].source_id, "doc-2");
            assert_eq!(
                missing_or_revoked_sources[0].reason,
                SnapshotDegradationReason::SourceRevoked
            );
        }
        other => panic!("expected PartialReproduction, got {other:?}"),
    }

    // Uncommitted (`VerifiedUncommitted`) manifest MUST be rejected by EvidenceSnapshot::build:
    let mut uncommitted = snapshot.manifest.clone();
    uncommitted.state = ProofState::VerifiedUncommitted;
    assert_eq!(
        EvidenceSnapshot::build("snap-uncommitted", "does x help y?", 3, uncommitted),
        Err(GuidelineError::UncommittedSnapshotManifest(
            ProofState::VerifiedUncommitted
        ))
    );

    // Mutating authority-bearing manifest fields (`outcome`, `applicability`, `components`,
    // `rights_grant_version`) after snapshot creation MUST fail `snapshot_digest` validation:
    let mut tampered = snapshot.clone();
    tampered.manifest.outcome = TerminalOutcome::Answer;
    tampered.manifest.applicability = ApplicabilityState::Applicable;
    assert_eq!(
        tampered.validate(),
        Err(GuidelineError::SnapshotDigestMismatch)
    );

    let mut tampered_comp = snapshot;
    tampered_comp.manifest.components.policy = "forged-policy".to_owned();
    assert_eq!(
        tampered_comp.validate(),
        Err(GuidelineError::SnapshotDigestMismatch)
    );
}

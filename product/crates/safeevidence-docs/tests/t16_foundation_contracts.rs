//! `ADM-0020` / `T16` SafeOCR foundation contract tests (`TA-15`).
//!
//! Adapted from `AbdulazizShehri/safeOCR` (`tests/test_foundation_contracts.py`)
//! under Apache-2.0 (`ADR-0004`).

use safeevidence_docs::safeocr_contracts::{
    BoundingBox, CandidateSpan, Criticality, DecisionState, EvidenceRecord, LabFieldCandidate,
    PageAsset, SafeOcrContractError, VerificationSignals, decide, export_allowed,
};

fn all_true_signals() -> VerificationSignals {
    VerificationSignals {
        candidate_present: true,
        visual_grounded: true,
        independent_agreement: true,
        perturbation_stable: true,
        structural_association: true,
        numeric_parse_unambiguous: true,
        unit_valid: true,
        patient_linkage_unambiguous: true,
        runtime_healthy: true,
    }
}

fn valid_field(doc_sha: &str) -> LabFieldCandidate {
    let page = PageAsset::new(doc_sha, 0, 100, 100, &"b".repeat(64)).unwrap();
    let bbox = BoundingBox::new(1, 1, 20, 20).unwrap();
    let span = CandidateSpan::new(page, bbox, "6.8", "paddleocr", "2.8.0", Some(0.95)).unwrap();
    LabFieldCandidate::new(
        "Potassium",
        "6.8",
        Some("mmol/L".to_owned()),
        Criticality::Critical,
        vec![span],
    )
    .unwrap()
}

#[test]
fn bounding_box_page_asset_and_candidate_span_enforce_structural_invariants() {
    assert_eq!(
        BoundingBox::new(10, 10, 5, 20),
        Err(SafeOcrContractError::InvalidBoundingBox)
    );
    assert_eq!(
        PageAsset::new("not-a-sha", 0, 100, 100, &"a".repeat(64)),
        Err(SafeOcrContractError::InvalidSha256Hex)
    );
    assert_eq!(
        PageAsset::new(&"a".repeat(64), 0, 0, 100, &"a".repeat(64)),
        Err(SafeOcrContractError::InvalidPageDimensions)
    );

    let page = PageAsset::new(&"a".repeat(64), 0, 100, 100, &"a".repeat(64)).unwrap();
    let bbox = BoundingBox::new(1, 1, 20, 20).unwrap();
    for (text, eng, ver) in [("", "paddleocr", "1"), ("6.8", "", "1"), ("6.8", "p", "")] {
        assert!(CandidateSpan::new(page.clone(), bbox, text, eng, ver, Some(0.9)).is_err());
    }
    assert_eq!(
        CandidateSpan::new(
            page.clone(),
            BoundingBox::new(1, 1, 120, 20).unwrap(),
            "6.8",
            "paddleocr",
            "1",
            Some(0.9)
        ),
        Err(SafeOcrContractError::BoxOutsidePage)
    );
    assert_eq!(
        CandidateSpan::new(page, bbox, "6.8", "paddleocr", "1", Some(1.5)),
        Err(SafeOcrContractError::InvalidScore)
    );
}

#[test]
fn fail_closed_decision_policy_cross_document_guard_and_export_gate() {
    let mut s = all_true_signals();
    assert_eq!(
        decide(&s, Criticality::Critical).state,
        DecisionState::VerifiedAuto
    );

    s = all_true_signals();
    s.candidate_present = false;
    assert_eq!(
        decide(&s, Criticality::Critical).state,
        DecisionState::Abstained
    );

    s = all_true_signals();
    s.visual_grounded = false;
    assert_eq!(
        decide(&s, Criticality::Critical).state,
        DecisionState::Abstained
    );

    s = all_true_signals();
    s.runtime_healthy = false;
    assert_eq!(
        decide(&s, Criticality::Critical).state,
        DecisionState::Abstained
    );

    for toggle in [
        |x: &mut VerificationSignals| x.independent_agreement = false,
        |x: &mut VerificationSignals| x.perturbation_stable = false,
        |x: &mut VerificationSignals| x.structural_association = false,
        |x: &mut VerificationSignals| x.numeric_parse_unambiguous = false,
        |x: &mut VerificationSignals| x.unit_valid = false,
        |x: &mut VerificationSignals| x.patient_linkage_unambiguous = false,
    ] {
        let mut sig = all_true_signals();
        toggle(&mut sig);
        assert_eq!(
            decide(&sig, Criticality::Critical).state,
            DecisionState::ReviewRequired
        );
    }

    let verified =
        EvidenceRecord::build(valid_field(&"a".repeat(64)), all_true_signals(), "f1-v1").unwrap();
    assert!(export_allowed(&verified));

    let mut review_sig = all_true_signals();
    review_sig.unit_valid = false;
    let review = EvidenceRecord::build(valid_field(&"a".repeat(64)), review_sig, "f1-v1").unwrap();
    assert!(!export_allowed(&review));

    // Cross-document spans in a single `LabFieldCandidate` are rejected fail-closed:
    let span_a = valid_field(&"a".repeat(64)).source_spans.remove(0);
    let span_c = valid_field(&"c".repeat(64)).source_spans.remove(0);
    assert_eq!(
        LabFieldCandidate::new(
            "Potassium",
            "6.8",
            Some("mmol/L".to_owned()),
            Criticality::Critical,
            vec![span_a, span_c]
        ),
        Err(SafeOcrContractError::CrossDocumentSpans)
    );
}

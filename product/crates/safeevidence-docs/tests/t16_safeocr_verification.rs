//! `ADM-0020` / `T16` SafeOCR foundation contracts & critical-value verification tests (`TA-15`).
//!
//! Adapted from `AbdulazizShehri/safeOCR` (`tests/test_foundation_contracts.py` and
//! `tests/test_verification.py`) under Apache-2.0 (`ADR-0004`).

use safeevidence_docs::safeocr_contracts::{
    BoundingBox, CandidateSpan, Criticality, DecisionState, LabFieldCandidate, PageAsset,
    export_allowed,
};
use safeevidence_docs::safeocr_report::build_safeocr_audit_report;
use safeevidence_docs::safeocr_verify::{
    APPROVED_PERTURBATIONS, IndependentCropRead, PerturbationRead, parse_critical_value,
    verify_critical_field,
};

fn sample_page() -> PageAsset {
    PageAsset::new(&"a".repeat(64), 0, 1200, 1600, &"b".repeat(64)).unwrap()
}

fn all_perturbations(text: &str) -> Vec<PerturbationRead> {
    APPROVED_PERTURBATIONS
        .iter()
        .enumerate()
        .map(|(idx, &name)| PerturbationRead {
            name: name.to_owned(),
            image_sha256: format!("{idx:064x}"),
            text: Some(text.to_owned()),
            runtime_healthy: true,
        })
        .collect()
}

#[test]
fn verifies_unambiguous_critical_number_and_blocks_decimal_sign_comparator_or_negation_drifts() {
    let span = CandidateSpan::new(
        sample_page(),
        BoundingBox::new(100, 200, 300, 240).unwrap(),
        "5.40",
        "paddleocr-onnx",
        "2.8.0",
        Some(0.96),
    )
    .unwrap();
    let field = LabFieldCandidate::new(
        "Potassium",
        "5.40",
        Some("mmol/L".to_owned()),
        Criticality::Critical,
        vec![span.clone()],
    )
    .unwrap();

    // `5.4` == `5.40` canonically with zero float error:
    let ok_rec = verify_critical_field(
        field.clone(),
        Some(&IndependentCropRead {
            engine_name: "secondary-native-text".to_owned(),
            text: Some("5.4".to_owned()),
            runtime_healthy: true,
        }),
        &all_perturbations("5.40"),
        true,
        true,
    )
    .unwrap();
    assert_eq!(ok_rec.decision.state, DecisionState::VerifiedAuto);
    assert!(export_allowed(&ok_rec));

    // Decimal point shift (`5.40` vs `54`) MUST fail `independent_agreement` -> ReviewRequired!
    let decimal_shift = verify_critical_field(
        field.clone(),
        Some(&IndependentCropRead {
            engine_name: "secondary-native-text".to_owned(),
            text: Some("54".to_owned()),
            runtime_healthy: true,
        }),
        &all_perturbations("5.40"),
        true,
        true,
    )
    .unwrap();
    assert_eq!(decimal_shift.decision.state, DecisionState::ReviewRequired);
    assert!(!export_allowed(&decimal_shift));
    assert!(
        decimal_shift
            .decision
            .failed_gates
            .contains(&"independent_agreement".to_owned())
    );

    // Unrecognized unit (`mmol/dL` not in pinned UCUM subset) -> ReviewRequired (`unit_valid`)!
    let bad_unit_field = LabFieldCandidate::new(
        "Potassium",
        "5.40",
        Some("mmol/dL".to_owned()),
        Criticality::Critical,
        vec![span.clone()],
    )
    .unwrap();
    let bad_unit = verify_critical_field(
        bad_unit_field,
        Some(&IndependentCropRead {
            engine_name: "secondary-native-text".to_owned(),
            text: Some("5.40".to_owned()),
            runtime_healthy: true,
        }),
        &all_perturbations("5.40"),
        true,
        true,
    )
    .unwrap();
    assert_eq!(bad_unit.decision.state, DecisionState::ReviewRequired);
    assert!(
        bad_unit
            .decision
            .failed_gates
            .contains(&"unit_valid".to_owned())
    );

    // Negation flip (`NOT DETECTED` vs `DETECTED` under perturbation) -> ReviewRequired!
    let qual_field = LabFieldCandidate::new(
        "PCR Assay",
        "NOT DETECTED",
        None,
        Criticality::Critical,
        vec![
            CandidateSpan::new(
                sample_page(),
                BoundingBox::new(100, 300, 350, 340).unwrap(),
                "NOT DETECTED",
                "paddleocr-onnx",
                "2.8.0",
                Some(0.95),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut flipped_perts = all_perturbations("NOT DETECTED");
    flipped_perts[2].text = Some("DETECTED".to_owned());
    let neg_flip = verify_critical_field(
        qual_field,
        Some(&IndependentCropRead {
            engine_name: "secondary-native-text".to_owned(),
            text: Some("not detected".to_owned()),
            runtime_healthy: true,
        }),
        &flipped_perts,
        true,
        true,
    )
    .unwrap();
    assert_eq!(neg_flip.decision.state, DecisionState::ReviewRequired);
    assert!(
        neg_flip
            .decision
            .failed_gates
            .contains(&"perturbation_stable".to_owned())
    );

    // Degraded low-confidence scan (`0.55 < 0.90` for Critical) -> Abstained (`visual_grounded`)!
    let low_conf_span = CandidateSpan::new(
        sample_page(),
        BoundingBox::new(10, 10, 80, 40).unwrap(),
        "5.40",
        "paddleocr-onnx",
        "2.8.0",
        Some(0.55),
    )
    .unwrap();
    let low_conf_field = LabFieldCandidate::new(
        "Potassium",
        "5.40",
        Some("mmol/L".to_owned()),
        Criticality::Critical,
        vec![low_conf_span],
    )
    .unwrap();
    let abstained = verify_critical_field(
        low_conf_field,
        Some(&IndependentCropRead {
            engine_name: "secondary-native-text".to_owned(),
            text: Some("5.40".to_owned()),
            runtime_healthy: true,
        }),
        &all_perturbations("5.40"),
        true,
        true,
    )
    .unwrap();
    assert_eq!(abstained.decision.state, DecisionState::Abstained);
    assert_eq!(abstained.decision.failed_gates, vec!["visual_grounded"]);

    let report = build_safeocr_audit_report(&[
        ("f1".to_owned(), ok_rec),
        ("f2".to_owned(), decimal_shift),
        ("f3".to_owned(), abstained),
    ])
    .unwrap();
    assert_eq!(report.verified_auto_count, 1);
    assert_eq!(report.review_required_count, 1);
    assert_eq!(report.abstained_count, 1);

    // Ambiguous OCR letter confusables (`1.O`, `5,4`) rejected by parser:
    assert!(parse_critical_value("1.O").is_none());
    assert!(parse_critical_value("5,4").is_none());
    assert_eq!(
        parse_critical_value("<= 0.050")
            .unwrap()
            .canonical_decimal
            .as_deref(),
        Some("0.05")
    );

    // Missing `engine_score: None` on Critical field MUST fail `visual_grounded` -> Abstained!
    let ungrounded_span = CandidateSpan::new(
        sample_page(),
        BoundingBox::new(10, 10, 80, 40).unwrap(),
        "5.40",
        "paddleocr-onnx",
        "2.8.0",
        None,
    )
    .unwrap();
    let ungrounded_rec = verify_critical_field(
        LabFieldCandidate::new(
            "Potassium",
            "5.40",
            Some("mmol/L".to_owned()),
            Criticality::Critical,
            vec![ungrounded_span],
        )
        .unwrap(),
        Some(&IndependentCropRead {
            engine_name: "secondary-native-text".to_owned(),
            text: Some("5.40".to_owned()),
            runtime_healthy: true,
        }),
        &all_perturbations("5.40"),
        true,
        true,
    )
    .unwrap();
    assert_eq!(ungrounded_rec.decision.state, DecisionState::Abstained);
    assert!(!export_allowed(&ungrounded_rec));

    // Forged `DecisionRecord` with `VerifiedAuto` over failed signals is rejected by `export_allowed`
    // and `build_safeocr_audit_report`:
    let mut forged = ungrounded_rec;
    forged.decision.state = DecisionState::VerifiedAuto;
    forged.decision.failed_gates.clear();
    assert!(!export_allowed(&forged));
    assert!(build_safeocr_audit_report(&[("forged".to_owned(), forged)]).is_err());

    // Empty `source_spans` via struct literal returns `EmptySourceSpans` without panicking:
    let empty_field = LabFieldCandidate {
        analyte_text: "Potassium".to_owned(),
        value_text: "5.40".to_owned(),
        unit_text: Some("mmol/L".to_owned()),
        criticality: Criticality::Critical,
        source_spans: Vec::new(),
    };
    assert!(verify_critical_field(empty_field, None, &[], false, false).is_err());
}

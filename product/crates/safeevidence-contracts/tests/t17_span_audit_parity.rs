//! Parity and safety tests for the `T17` (`ADM-0004`) Rust ports of
//! `openmed/clinical/evidence_span_audit.py` and `openmed/structured/offset_properties.py`
//! (`maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86`, Apache-2.0).

use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::offset_projection::{
    AdapterExtractionResult, AdapterFormat, DEFAULT_SYNTHETIC_SEED, OffsetFailureCategory,
    OffsetSpan, SyntheticOffsetCase, build_synthetic_offset_cases, canonical_format_name,
    project_offset_spans, run_offset_property_suite, validate_offset_projection,
};
use safeevidence_contracts::proof::EvidenceSpan;
use safeevidence_contracts::span_audit::{
    AuditedEvidenceSpan, OverlapCounts, OverlapKind, SpanAuditError, audit_evidence_spans,
    opaque_audit_identifier,
};

fn span(evidence_id: &str, start: u64, end: u64) -> AuditedEvidenceSpan {
    AuditedEvidenceSpan::try_new("synthetic-source", evidence_id, start, end).expect("valid span")
}

fn span_in(source_id: &str, evidence_id: &str, start: u64, end: u64) -> AuditedEvidenceSpan {
    AuditedEvidenceSpan::try_new(source_id, evidence_id, start, end).expect("valid span")
}

#[test]
fn classifies_exact_nested_partial_and_cross_source_pairs_with_exact_donor_fingerprint() {
    let audit = audit_evidence_spans(&[
        span("e-partial-left", 0, 5),
        span("e-exact-left", 10, 20),
        span("e-nested", 12, 18),
        span("e-exact-right", 10, 20),
        span("e-partial-right", 18, 25),
        span_in("synthetic-peer", "e-cross-source", 15, 22),
    ]);

    assert_eq!(
        audit.counts(),
        OverlapCounts {
            exact: 1,
            nested: 2,
            partial: 2,
            cross_source: 4,
        }
    );
    assert_eq!(audit.overlap_count(), 9);
    assert_eq!(audit.source_count(), 2);

    // Exact SHA-256 parity with upstream OpenMed `evidence_span_audit.py` @ 8440bdac5962.
    assert_eq!(
        audit.fingerprint(),
        "sha256:d9a5b305e1a135f9924c5da771ab06734667d54fc013bcd0811a276ef33c3e50"
    );
    assert_eq!(
        audit.overlaps()[0].fingerprint(),
        "sha256:601450d5f52db512dd5263261296dbfa8eeb723132ba56c632b147081e07052a"
    );
    assert_eq!(audit.overlaps()[0].kind(), OverlapKind::Exact);
    assert_eq!(audit.overlaps()[0].overlap_length(), 10);
}

#[test]
fn touching_half_open_ranges_do_not_overlap() {
    let audit = audit_evidence_spans(&[span("left", 0, 4), span("right", 4, 9)]);
    assert!(audit.overlaps().is_empty());
    assert_eq!(audit.counts().total(), 0);
}

#[test]
fn identifiers_are_hashed_idempotently_and_never_copy_patient_or_surface_values() {
    let marker = "Synthetic Patient Value 8675309";
    let first_span = span_in(marker, marker, 0, 6);
    let second_span = span_in(marker, "synthetic-second", 3, 9);
    let audit = audit_evidence_spans(&[first_span.clone(), second_span]);

    let json = audit.to_canonical_json();
    let dbg = format!("{audit:?}");
    assert!(!json.contains(marker));
    assert!(!dbg.contains(marker));

    let expected_hash = opaque_audit_identifier(marker).expect("hash");
    assert_eq!(audit.spans()[0].source_id(), expected_hash);
    assert_eq!(
        opaque_audit_identifier(&expected_hash).as_deref(),
        Some(expected_hash.as_str()),
        "already-prefixed sha256:<64hex> identifiers remain stable on revalidation"
    );
}

#[test]
fn input_order_does_not_change_report_or_fingerprint() {
    let forward = vec![
        span("opaque-z", 20, 28),
        span("opaque-a", 10, 18),
        span("opaque-m", 15, 24),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();

    let first = audit_evidence_spans(&forward);
    let second = audit_evidence_spans(&reversed);

    assert_eq!(first, second);
    assert_eq!(first.to_canonical_json(), second.to_canonical_json());
    assert!(first.fingerprint().starts_with("sha256:"));
}

#[test]
fn audit_retains_all_findings_without_automatic_resolution_and_converts_proof_spans() {
    let proof_outer = EvidenceSpan {
        source_id: "doc-veltrix-a".to_owned(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(b"synthetic source"),
        start_scalar: 1,
        end_scalar: 12,
    };
    let proof_inner = EvidenceSpan {
        source_id: "doc-veltrix-a".to_owned(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(b"synthetic source"),
        start_scalar: 4,
        end_scalar: 8,
    };
    let audit = audit_evidence_spans(&[
        AuditedEvidenceSpan::from_evidence_span(&proof_outer, "claim-outer").unwrap(),
        AuditedEvidenceSpan::from_evidence_span(&proof_inner, "claim-inner").unwrap(),
    ]);
    let parsed: serde_json::Value =
        serde_json::from_str(&audit.to_canonical_json()).expect("valid JSON");
    assert_eq!(parsed["overlap_count"], 1);
    assert_eq!(parsed["overlaps"][0]["kind"], "nested");
    assert!(parsed["overlaps"][0].get("winner").is_none());
    assert!(parsed.get("resolution").is_none());
}

#[test]
fn invalid_span_inputs_do_not_echo_identifiers_or_text() {
    let sensitive = "SENSITIVE_SYNTHETIC_SURFACE_9912";
    let err = AuditedEvidenceSpan::try_new(sensitive, sensitive, 7, 7).unwrap_err();
    assert_eq!(err, SpanAuditError::InvalidRangeBounds);
    assert!(!err.to_string().contains(sensitive));
    assert!(err.to_string().contains("end must be greater than start"));

    assert_eq!(
        AuditedEvidenceSpan::try_new("   ", "id", 0, 1).unwrap_err(),
        SpanAuditError::EmptySourceId
    );
    assert_eq!(
        AuditedEvidenceSpan::try_new("src", "", 0, 1).unwrap_err(),
        SpanAuditError::EmptyEvidenceId
    );
}

#[test]
fn offset_projection_suite_passes_across_all_five_multilingual_formats_and_arabic() {
    let identity_adapter = |case: &SyntheticOffsetCase| {
        Ok(AdapterExtractionResult {
            text: case.text().to_owned(),
            spans: case.source_spans().to_vec(),
        })
    };
    let reports = run_offset_property_suite(
        &[
            ("pdf", &identity_adapter),
            ("ocr", &identity_adapter),
            ("rtf", &identity_adapter),
            ("odt", &identity_adapter),
            ("pptx", &identity_adapter),
        ],
        None,
        DEFAULT_SYNTHETIC_SEED,
    )
    .expect("suite must pass");

    assert_eq!(reports.len(), 5);
    assert_eq!(reports[4].format_name, Some(AdapterFormat::Presentation));
    for report in &reports {
        assert!(report.passed());
        assert!(report.empty_redaction_count >= 4);
        assert!(report.mapped_redaction_count > 0);
        let serialized = serde_json::to_string(report).unwrap();
        assert!(
            !serialized.contains("synthetic-delta"),
            "PHI-safe report must never retain source surface text"
        );
    }

    // Arabic vocalized text Unicode scalar offset projection:
    let arabic_text = "\u{0627}\u{0644}\u{0645}\u{0631}\u{064a}\u{0636} \u{062a}\u{062d}\u{0633}\u{0651}\u{064e}\u{0646} \u{0628}\u{0639}\u{062f} 12 \u{0623}\u{0633}\u{0628}\u{0648}\u{0639}\u{0627}\u{064b}";
    let total = arabic_text.chars().count();
    let src_spans = vec![
        OffsetSpan::try_new(0, 6, Some("SECRET_LABEL")).unwrap(),
        OffsetSpan::try_new(7, 13, None).unwrap(),
        OffsetSpan::try_new(14, total, None).unwrap(),
    ];
    let redactions = vec![
        OffsetSpan::try_new(6, 6, Some("EMPTY")).unwrap(),
        OffsetSpan::try_new(7, 13, Some("SECRET_REDACTION")).unwrap(),
    ];
    let ar_report =
        validate_offset_projection(arabic_text, &src_spans, &redactions, Some("pdf"), true)
            .expect("Arabic scalar projection");
    assert!(ar_report.passed());
    assert!(ar_report.projections[0].is_empty());
    assert_eq!(ar_report.projections[1].source_span_indexes, vec![1]);
    assert!(
        !serde_json::to_string(&src_spans[0].to_offset_record())
            .unwrap()
            .contains("SECRET_LABEL")
    );
}

#[test]
fn offset_projection_categorizes_failures_without_leaking_text() {
    assert_eq!(
        canonical_format_name("docx").unwrap_err().category(),
        OffsetFailureCategory::UnsupportedFormat
    );
    assert_eq!(
        OffsetSpan::try_new(5, 4, None).unwrap_err().category(),
        OffsetFailureCategory::InvalidOffsets
    );

    let text = "alpha beta gamma";
    let overlapping = vec![
        OffsetSpan::try_new(0, 6, None).unwrap(),
        OffsetSpan::try_new(5, 10, None).unwrap(),
    ];
    assert_eq!(
        project_offset_spans(text, &overlapping, &[], false)
            .unwrap_err()
            .category(),
        OffsetFailureCategory::SpanOverlap
    );

    let unordered = vec![
        OffsetSpan::try_new(6, 10, None).unwrap(),
        OffsetSpan::try_new(0, 5, None).unwrap(),
    ];
    assert_eq!(
        project_offset_spans(text, &unordered, &[], false)
            .unwrap_err()
            .category(),
        OffsetFailureCategory::SpanOrder
    );

    let gapped_sources = vec![
        OffsetSpan::try_new(0, 5, None).unwrap(),
        OffsetSpan::try_new(11, 16, None).unwrap(),
    ];
    let unmapped_redaction = vec![OffsetSpan::try_new(6, 10, None).unwrap()];
    let err = validate_offset_projection(text, &gapped_sources, &unmapped_redaction, None, true)
        .unwrap_err();
    assert_eq!(err.category(), OffsetFailureCategory::UnmappedSpan);
    assert_eq!(err.to_string(), "offset projection failed (unmapped_span)");

    let cases = build_synthetic_offset_cases(0);
    assert_eq!(cases.len(), 5);
}

#[test]
fn deserialization_enforces_opaque_sha256_bounds_and_canonical_fingerprint_integrity() {
    let s1 = AuditedEvidenceSpan::try_new("doc-a", "ev-1", 0, 10).unwrap();
    let s2 = AuditedEvidenceSpan::try_new("doc-a", "ev-2", 4, 8).unwrap();
    let audit = audit_evidence_spans(&[s1.clone(), s2]);
    let encoded = serde_json::to_string(&audit).unwrap();
    let decoded: safeevidence_contracts::span_audit::EvidenceSpanAudit =
        serde_json::from_str(&encoded).expect("valid audit round-trips");
    assert_eq!(decoded, audit);

    // Raw / unhashed PHI identifier in source_id is rejected on deserialization.
    let phi_span = serde_json::json!({
        "source_id": "patient-mrn-12345",
        "evidence_id": s1.evidence_id(),
        "start": 0,
        "end": 10
    });
    assert!(serde_json::from_value::<AuditedEvidenceSpan>(phi_span).is_err());

    // Inverted bounds (end <= start) are rejected on deserialization.
    let inverted_span = serde_json::json!({
        "source_id": s1.source_id(),
        "evidence_id": s1.evidence_id(),
        "start": 10,
        "end": 5
    });
    assert!(serde_json::from_value::<AuditedEvidenceSpan>(inverted_span).is_err());

    // Forged overlap bounds or tampered audit fingerprint/counts are rejected without panic.
    let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    tampered["overlaps"][0]["overlap_start"] = serde_json::json!(99);
    tampered["overlaps"][0]["overlap_end"] = serde_json::json!(2);
    assert!(
        serde_json::from_value::<safeevidence_contracts::span_audit::EvidenceSpanAudit>(
            tampered.clone()
        )
        .is_err()
    );

    let mut bad_fp: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    bad_fp["counts"]["nested"] = serde_json::json!(99);
    assert!(
        serde_json::from_value::<safeevidence_contracts::span_audit::EvidenceSpanAudit>(bad_fp)
            .is_err()
    );
}

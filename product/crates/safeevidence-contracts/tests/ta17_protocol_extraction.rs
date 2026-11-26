//! `WP-14` (protocol lock & hash-chained audit export) and `WP-15` / `TA-17` (quote-anchored
//! `Proposed` -> human `Confirmed` structured effect extraction).

use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::EvidenceSpan;
use safeevidence_contracts::review_protocol::{
    EffectMeasureKind, ExtractionState, ProtocolAmendment, ProtocolExtractionError,
    ReviewPicoCriteria, ReviewProtocol, StructuredEffectExtraction, append_protocol_audit_event,
    export_protocol_audit_bundle,
};
use safeevidence_contracts::study::{Known, ReportVersionId, ResultId, ScopedId, StudyId};

fn sid(id: &str) -> ScopedId {
    ScopedId {
        scope: "ta17-synthetic".to_owned(),
        id: id.to_owned(),
        version: 1,
    }
}

#[test]
fn wp14_review_protocol_locks_digest_and_replays_hash_chained_audit_bundle() {
    let pico = ReviewPicoCriteria {
        population: "Adults with synthetic glimmer syndrome".to_owned(),
        intervention: "Veltrixamine 40 mg daily".to_owned(),
        comparator: "Placebo".to_owned(),
        primary_outcomes: vec!["12-week glimmer composite score".to_owned()],
        eligible_designs: vec!["Parallel randomized trial".to_owned()],
    };
    let protocol = ReviewProtocol::create_locked(
        "proto-glimmer-2026".to_owned(),
        2,
        "Synthetic Systematic Review of Veltrixamine in Glimmer Syndrome".to_owned(),
        pico.clone(),
        vec!["Randomized parallel-group trials in adults".to_owned()],
        vec!["Case series and non-comparative cohorts".to_owned()],
        "lead-methodologist-01".to_owned(),
        "2026-11-26T10:00:00Z".to_owned(),
        vec![ProtocolAmendment {
            amendment_id: "amd-proto-1".to_owned(),
            prior_version: 1,
            new_version: 2,
            rationale: "Clarified 12-week primary timepoint window.".to_owned(),
            authorized_by: "lead-methodologist-01".to_owned(),
            recorded_at_utc: "2026-11-26T09:55:00Z".to_owned(),
        }],
    )
    .expect("protocol locks");

    // Empty or BiDi-spoofed list elements in inclusion_rules are rejected fail-closed:
    assert_eq!(
        ReviewProtocol::create_locked(
            "proto-bad".to_owned(),
            1,
            "Bad rule".to_owned(),
            pico,
            vec!["   ".to_owned()],
            Vec::new(),
            "lead-methodologist-01".to_owned(),
            "2026-11-26T10:00:00Z".to_owned(),
            Vec::new(),
        ),
        Err(ProtocolExtractionError::EmptyRequiredField(
            "inclusion_rules"
        ))
    );

    let mut events = Vec::new();
    append_protocol_audit_event(
        &mut events,
        "PROTOCOL_LOCKED",
        "lead-methodologist-01",
        "proto-glimmer-2026",
        "Locked protocol v2",
        "2026-11-26T10:00:00Z",
    )
    .unwrap();
    append_protocol_audit_event(
        &mut events,
        "EXTRACTION_PROPOSED",
        "rule-extractor-v1",
        "ext-01",
        "Proposed Table 2 primary endpoint row",
        "2026-11-26T10:05:00Z",
    )
    .unwrap();

    let bundle_1 = export_protocol_audit_bundle(&protocol, &events).expect("bundle 1");
    let bundle_2 = export_protocol_audit_bundle(&protocol, &events).expect("bundle 2");
    assert_eq!(bundle_1.bundle_digest, bundle_2.bundle_digest);

    // Tampering with an audit detail breaks the hash chain fail-closed:
    let mut tampered = events;
    tampered[0].detail = "Silently altered eligibility rule".to_owned();
    assert_eq!(
        export_protocol_audit_bundle(&protocol, &tampered),
        Err(ProtocolExtractionError::AuditChainBroken(1))
    );
}

#[test]
fn ta17_extractions_require_quote_span_human_confirmation_and_ban_confidence() {
    let source = concat!(
        "Table 2 Primary Endpoint: ",
        "Mean difference -4.2 points (95% interval -6.1 to -2.3) in 240 adults at 12 weeks."
    );
    let quote =
        "Mean difference -4.2 points (95% interval -6.1 to -2.3) in 240 adults at 12 weeks.";
    let byte_start = source.find(quote).unwrap();
    let start_scalar = source[..byte_start].chars().count() as u64;
    let end_scalar = start_scalar + quote.chars().count() as u64;

    let span = EvidenceSpan {
        source_id: "doc-veltrix-table2".to_owned(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(source.as_bytes()),
        start_scalar,
        end_scalar,
    };

    let mut extraction = StructuredEffectExtraction::propose_anchored(
        "ext-veltrix-md-12w".to_owned(),
        StudyId(sid("study-1")),
        ReportVersionId(sid("rep-1")),
        ResultId(sid("res-1")),
        "Glimmer composite score".to_owned(),
        EffectMeasureKind::MeanDifference,
        "-4.2".to_owned(),
        Known::Known("-6.1".to_owned()),
        Known::Known("-2.3".to_owned()),
        Known::Known(240),
        "12 weeks".to_owned(),
        "Table 2, Row 1, Column 4".to_owned(),
        quote.to_owned(),
        span.clone(),
        "deterministic-table-reader-1".to_owned(),
        source,
    )
    .expect("anchored proposal succeeds");

    // 1. Remains PROPOSED and ineligible for downstream synthesis until human confirmation:
    assert!(matches!(extraction.state, ExtractionState::Proposed { .. }));
    assert!(!extraction.qualifies_for_synthesis());

    // 2. Wire representation rejects any `confidence` field (`deny_unknown_fields`):
    let mut raw_json: serde_json::Value = serde_json::to_value(&extraction).unwrap();
    raw_json["confidence"] = serde_json::json!(0.97);
    assert!(serde_json::from_value::<StructuredEffectExtraction>(raw_json).is_err());

    // 3. Hallucinated, sign-stripped ("4.2" vs "-4.2"), or partial-digit ("-4" vs "-4.2",
    // "24" vs "240") point estimates are all rejected (`TA-17`):
    for bad_estimate in ["-9.9", "4.2", "-4", "24"] {
        let rejected = StructuredEffectExtraction::propose_anchored(
            "ext-bad-num".to_owned(),
            StudyId(sid("study-1")),
            ReportVersionId(sid("rep-1")),
            ResultId(sid("res-1")),
            "Glimmer composite score".to_owned(),
            EffectMeasureKind::MeanDifference,
            bad_estimate.to_owned(),
            Known::Known("-6.1".to_owned()),
            Known::Known("-2.3".to_owned()),
            Known::Known(240),
            "12 weeks".to_owned(),
            "Table 2, Row 1".to_owned(),
            quote.to_owned(),
            span.clone(),
            "deterministic-table-reader-1".to_owned(),
            source,
        );
        assert_eq!(
            rejected,
            Err(ProtocolExtractionError::EstimateNotAnchoredInQuote(
                bad_estimate.to_owned()
            )),
            "expected {bad_estimate} to fail quote anchor check"
        );
    }

    // 4. Shifted `EvidenceSpan` coordinates fail closed (`QuoteSpanMismatch`):
    let mut bad_span = span;
    bad_span.end_scalar -= 1;
    let shifted = StructuredEffectExtraction::propose_anchored(
        "ext-bad-span".to_owned(),
        StudyId(sid("study-1")),
        ReportVersionId(sid("rep-1")),
        ResultId(sid("res-1")),
        "Glimmer composite score".to_owned(),
        EffectMeasureKind::MeanDifference,
        "-4.2".to_owned(),
        Known::Known("-6.1".to_owned()),
        Known::Known("-2.3".to_owned()),
        Known::Known(240),
        "12 weeks".to_owned(),
        "Table 2, Row 1".to_owned(),
        quote.to_owned(),
        bad_span,
        "deterministic-table-reader-1".to_owned(),
        source,
    );
    assert_eq!(shifted, Err(ProtocolExtractionError::QuoteSpanMismatch));

    // 5. Blank human actor or mismatched source digest during confirmation fails WITHOUT mutating
    // `extraction.state` out of `Proposed`:
    assert_eq!(
        extraction.confirm_by_human("   ", "2026-11-26T10:15:00Z", source),
        Err(ProtocolExtractionError::EmptyHumanActor)
    );
    assert_eq!(
        extraction.confirm_by_human(
            "reviewer-methodologist-02",
            "2026-11-26T10:15:00Z",
            "tampered source text"
        ),
        Err(ProtocolExtractionError::SourceDigestMismatch)
    );
    assert!(matches!(extraction.state, ExtractionState::Proposed { .. }));
    assert!(!extraction.qualifies_for_synthesis());

    extraction
        .confirm_by_human("reviewer-methodologist-02", "2026-11-26T10:15:00Z", source)
        .expect("human confirmation succeeds");
    assert!(extraction.qualifies_for_synthesis());
}

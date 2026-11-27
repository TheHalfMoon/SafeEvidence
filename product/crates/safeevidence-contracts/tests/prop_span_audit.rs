//! Structure-aware deterministic property suite for `span_audit` and `offset_projection`
//! (`ADR-0002`, `ADM-0004`, `TA-04`, `TA-08`).

use safeevidence_contracts::offset_projection::{
    OffsetFailureCategory, OffsetSpan, project_offset_spans, validate_offset_projection,
};
use safeevidence_contracts::span_audit::{
    AuditedEvidenceSpan, EvidenceSpanAudit, OverlapKind, SpanAuditError, audit_evidence_spans,
};

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

#[test]
fn property_1000_span_audits_are_permutation_invariant_phi_free_and_tamper_evident() {
    let mut rng = Prng::new(0x5FA4_A0D1_2026_1127);

    for trial in 0..1_000 {
        let count = rng.bounded(14);
        let mut spans = Vec::with_capacity(count);
        for idx in 0..count {
            let secret_src = format!("SECRET-PATIENT-SRC-{}", rng.bounded(4));
            let secret_ev = format!("SECRET-EVID-{trial}-{idx}");
            let a = rng.next_u64() % 64;
            let b = a + 1 + (rng.next_u64() % 24);
            let span = AuditedEvidenceSpan::try_new(&secret_src, &secret_ev, a, b).unwrap();
            spans.push(span);
        }

        let audit_a = audit_evidence_spans(&spans);
        let json_a = audit_a.to_canonical_json();
        assert!(
            !json_a.contains("SECRET-PATIENT") && !json_a.contains("SECRET-EVID"),
            "raw caller identifiers must never leak into canonical JSON"
        );
        assert!(
            !format!("{audit_a:?}").contains("SECRET-PATIENT"),
            "raw caller identifiers must never leak into Debug output"
        );

        // Permute input spans and verify byte-for-byte identical report & fingerprint:
        let mut shuffled = spans;
        for i in (1..shuffled.len()).rev() {
            let j = rng.bounded(i + 1);
            shuffled.swap(i, j);
        }
        let audit_b = audit_evidence_spans(&shuffled);
        assert_eq!(audit_a, audit_b);
        assert_eq!(json_a, audit_b.to_canonical_json());
        assert_eq!(audit_a.counts().total(), audit_a.overlap_count());

        // Serde round-trip and tamper rejection:
        let serialized = serde_json::to_string(&audit_a).unwrap();
        let round_trip: EvidenceSpanAudit = serde_json::from_str(&serialized).unwrap();
        assert_eq!(round_trip, audit_a);

        let mut tampered: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        tampered["fingerprint"] = serde_json::json!(format!("sha256:{}", "0".repeat(64)));
        assert!(serde_json::from_value::<EvidenceSpanAudit>(tampered).is_err());

        // Touching intervals [k, m) and [m, n) must never be reported as overlapping:
        for ov in audit_a.overlaps() {
            assert!(ov.overlap_start() < ov.overlap_end());
            if ov.kind() == OverlapKind::Exact {
                assert_eq!(ov.first().start(), ov.second().start());
                assert_eq!(ov.first().end(), ov.second().end());
            }
        }
    }

    assert_eq!(
        AuditedEvidenceSpan::try_new("src", "ev", 10, 10),
        Err(SpanAuditError::InvalidRangeBounds)
    );
    assert_eq!(
        AuditedEvidenceSpan::try_new("   ", "ev", 0, 5),
        Err(SpanAuditError::EmptySourceId)
    );
}

#[test]
fn property_500_offset_projections_enforce_bounds_ordering_and_non_overlap() {
    let mut rng = Prng::new(0x0FF5_E750_2026_1127);
    let sample_text =
        "Synthetic \u{062f}\u{0631}\u{0627}\u{0633}\u{0629} caf\u{00e9} \u{1f9ea} cohort results.";
    let scalar_len = sample_text.chars().count();

    for _ in 0..500 {
        let mut cursor = 0_usize;
        let mut source_spans = Vec::new();
        while cursor < scalar_len {
            let gap = rng.bounded(3);
            let start = (cursor + gap).min(scalar_len);
            if start >= scalar_len {
                break;
            }
            let len = 1 + rng.bounded(6);
            let end = (start + len).min(scalar_len);
            source_spans.push(OffsetSpan::try_new(start, end, Some("secret-label")).unwrap());
            cursor = end;
        }

        if source_spans.is_empty() {
            continue;
        }

        let mut redactions = Vec::new();
        for s in &source_spans {
            if rng.bounded(2) == 0 {
                redactions.push(OffsetSpan::try_new(s.start(), s.end(), Some("secret")).unwrap());
            }
        }
        redactions.sort_by_key(OffsetSpan::offsets);

        let report =
            validate_offset_projection(sample_text, &source_spans, &redactions, Some("pdf"), true)
                .unwrap();
        assert!(report.passed());
        let rep_json = serde_json::to_string(&report).unwrap();
        assert!(!rep_json.contains("secret"));

        // Out-of-bounds span fails closed with InvalidOffsets:
        let bad_oob = vec![OffsetSpan::try_new(0, scalar_len + 1, None).unwrap()];
        assert_eq!(
            project_offset_spans(sample_text, &bad_oob, &[], false)
                .unwrap_err()
                .category(),
            OffsetFailureCategory::InvalidOffsets
        );

        // Overlapping source spans fail closed with SpanOverlap:
        if source_spans.len() >= 2 {
            let overlap_src = vec![
                OffsetSpan::try_new(0, 5, None).unwrap(),
                OffsetSpan::try_new(3, 8, None).unwrap(),
            ];
            assert_eq!(
                project_offset_spans(sample_text, &overlap_src, &[], false)
                    .unwrap_err()
                    .category(),
                OffsetFailureCategory::SpanOverlap
            );
        }
    }
}

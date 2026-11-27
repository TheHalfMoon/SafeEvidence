//! `WP-08` (`TA-10` deterministic perturbation gating set) and `WP-09` (`TA-11` PICO
//! applicability mismatch gate).

use safeevidence_ask::perturbation::{
    ClaimVerificationDefect, PicoQuerySpec, PicoSourceSpec, evaluate_pico_applicability,
    verify_claim_against_source,
};
use safeevidence_contracts::assurance::ReasonCode;
use safeevidence_contracts::proof::ApplicabilityState;

const SOURCE_PARAGRAPH: &str = "\
Adults with synthetic glimmer syndrome received veltrixamine 40 mg daily or placebo for 12 weeks. \
The glimmer score improved by 4.5 points in adults compared with placebo at 12 weeks. \
Adverse headache events did not differ from placebo over 12 weeks.";

#[test]
fn ta10_deterministic_perturbation_benchmark_flags_100_percent_of_altered_claims() {
    // Faithful whole sentences pass with 0% false rejections:
    for faithful in [
        "Adults with synthetic glimmer syndrome received veltrixamine 40 mg daily or placebo for 12 weeks.",
        "The glimmer score improved by 4.5 points in adults compared with placebo at 12 weeks.",
        "Adverse headache events did not differ from placebo over 12 weeks.",
    ] {
        assert_eq!(
            verify_claim_against_source(faithful, SOURCE_PARAGRAPH),
            Ok(()),
            "faithful sentence rejected: {faithful}"
        );
    }

    // 24 distinct perturbations across numbers, decimals, signs, dose/time units, negations,
    // null-result flips, comparators, timeframes, populations, control chars, and sentence splices:
    let perturbations: &[(&str, ClaimVerificationDefect)] = &[
        (
            "The glimmer score improved by 5.5 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "The glimmer score improved by 45 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "The glimmer score improved by 0.45 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "The glimmer score improved by -4.5 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "The glimmer score improved by 4.5 points in adults compared with placebo at 24 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "Adults with synthetic glimmer syndrome received veltrixamine 400 mg daily or placebo for 12 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "The glimmer score did not improve by 4.5 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NegationOrPolarityFlip,
        ),
        (
            "The glimmer score was unchanged by 4.5 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NegationOrPolarityFlip,
        ),
        (
            "The glimmer score was nonsignificant by 4.5 points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::NegationOrPolarityFlip,
        ),
        (
            "Adverse headache events differed from placebo over 12 weeks.",
            ClaimVerificationDefect::NegationOrPolarityFlip,
        ),
        (
            "Adults with synthetic glimmer syndrome received veltrixamine 40 mcg daily or placebo for 12 weeks.",
            ClaimVerificationDefect::UnitMismatch,
        ),
        (
            "Adults with synthetic glimmer syndrome received veltrixamine 40 g daily or placebo for 12 weeks.",
            ClaimVerificationDefect::UnitMismatch,
        ),
        (
            "Adults with synthetic glimmer syndrome received veltrixamine 40 ml daily or placebo for 12 weeks.",
            ClaimVerificationDefect::UnitMismatch,
        ),
        (
            "The glimmer score improved by 4.5 mmhg in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::UnitMismatch,
        ),
        (
            "The glimmer score improved by 4.5 points in adults compared with placebo at 12 months.",
            ClaimVerificationDefect::TimeframeSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in adults compared with placebo at 12 days.",
            ClaimVerificationDefect::TimeframeSwap,
        ),
        (
            "Adults with synthetic glimmer syndrome received veltrixamine 12 mg daily or placebo for 40 weeks.",
            ClaimVerificationDefect::NumericMismatch,
        ),
        (
            "Adults with synthetic glimmer syndrome received veltrixamine 40 weeks daily or placebo for 12 mg.",
            ClaimVerificationDefect::TimeframeSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in adults compared with standard care at 12 weeks.",
            ClaimVerificationDefect::ComparatorSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in adults compared with active control at 12 weeks.",
            ClaimVerificationDefect::ComparatorSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in children compared with placebo at 12 weeks.",
            ClaimVerificationDefect::PopulationOrSubgroupSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in elderly compared with placebo at 12 weeks.",
            ClaimVerificationDefect::PopulationOrSubgroupSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in adults with renal impairment compared with placebo at 12 weeks.",
            ClaimVerificationDefect::PopulationOrSubgroupSwap,
        ),
        (
            "The glimmer score improved by 4.5 points in adults compared with placebo at 12 weeks. Adverse headache events did not differ from placebo over 12 weeks.",
            ClaimVerificationDefect::CrossSentenceSplice,
        ),
        (
            "The glimmer score improved by 4.5 \u{202E}points in adults compared with placebo at 12 weeks.",
            ClaimVerificationDefect::EmptyOrNonAsciiControl,
        ),
    ];

    let mut flagged = 0_usize;
    for (perturbed, expected_defect) in perturbations {
        let verdict = verify_claim_against_source(perturbed, SOURCE_PARAGRAPH);
        assert_eq!(
            verdict,
            Err(*expected_defect),
            "perturbation must fail with {expected_defect:?}: {perturbed}"
        );
        flagged += 1;
    }
    assert_eq!(flagged, perturbations.len());
}

#[test]
fn ta11_pico_applicability_excludes_or_downgrades_100_percent_of_mismatched_sources() {
    let query = PicoQuerySpec {
        population: "adults".to_owned(),
        condition: "glimmer syndrome".to_owned(),
        intervention: "veltrixamine".to_owned(),
        comparator: Some("placebo".to_owned()),
        outcome: Some("glimmer composite score".to_owned()),
        minimum_weeks: Some(12),
    };

    let direct = PicoSourceSpec {
        doc_id: "doc-direct".to_owned(),
        population: "adults".to_owned(),
        condition: "glimmer syndrome".to_owned(),
        intervention: "veltrixamine".to_owned(),
        comparator: "placebo".to_owned(),
        outcome: "glimmer composite score".to_owned(),
        follow_up_weeks: 12,
        surrogate_outcome: false,
    };
    let direct_verdict = evaluate_pico_applicability(&query, &direct);
    assert_eq!(direct_verdict.state, ApplicabilityState::Applicable);
    assert!(direct_verdict.exclusion_code.is_none());

    // Hard mismatches (R-CO-2 population mismatch, pediatric/pregnant/elderly, wrong drug, wrong
    // condition, wrong outcome) -> 100% excluded with `ReasonCode::ApplicabilityUnresolved`:
    let hard_mismatches = [
        PicoSourceSpec {
            doc_id: "doc-pediatric".to_owned(),
            population: "children".to_owned(),
            ..direct.clone()
        },
        PicoSourceSpec {
            doc_id: "doc-pregnant".to_owned(),
            population: "pregnant adults".to_owned(),
            ..direct.clone()
        },
        PicoSourceSpec {
            doc_id: "doc-wrong-drug".to_owned(),
            intervention: "orbalin".to_owned(),
            ..direct.clone()
        },
        PicoSourceSpec {
            doc_id: "doc-wrong-condition".to_owned(),
            condition: "ember fatigue".to_owned(),
            ..direct.clone()
        },
        PicoSourceSpec {
            doc_id: "doc-wrong-outcome".to_owned(),
            outcome: "serum biomarker alpha".to_owned(),
            ..direct.clone()
        },
    ];
    for candidate in &hard_mismatches {
        let verdict = evaluate_pico_applicability(&query, candidate);
        assert_eq!(
            verdict.state,
            ApplicabilityState::NotApplicable,
            "{}",
            candidate.doc_id
        );
        assert_eq!(
            verdict.exclusion_code,
            Some(ReasonCode::ApplicabilityUnresolved)
        );
        assert!(!verdict.reasons.is_empty());
    }

    // Indirectness limits (active comparator instead of placebo, shorter follow-up, or surrogate
    // endpoint) -> 100% downgraded to `ApplicableWithLimits` with explicit reasons:
    let indirect_cases = [
        PicoSourceSpec {
            doc_id: "doc-active-comp".to_owned(),
            comparator: "standard care".to_owned(),
            ..direct.clone()
        },
        PicoSourceSpec {
            doc_id: "doc-short-followup".to_owned(),
            follow_up_weeks: 6,
            ..direct.clone()
        },
        PicoSourceSpec {
            doc_id: "doc-surrogate".to_owned(),
            surrogate_outcome: true,
            ..direct
        },
    ];
    for candidate in &indirect_cases {
        let verdict = evaluate_pico_applicability(&query, candidate);
        assert_eq!(
            verdict.state,
            ApplicabilityState::ApplicableWithLimits,
            "{}",
            candidate.doc_id
        );
        assert!(verdict.exclusion_code.is_none());
        assert!(!verdict.reasons.is_empty());
    }
}

//! Structure-aware deterministic property suite for `safeevidence_ask::perturbation`
//! (`ADR-0002`, `WP-08`, `WP-09`, `TA-10`, `TA-11`).

use safeevidence_ask::perturbation::{
    ClaimVerificationDefect, PicoQuerySpec, PicoSourceSpec, evaluate_pico_applicability,
    extract_numeric_facets, verify_claim_against_source,
};
use safeevidence_contracts::proof::ApplicabilityState;

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
fn spaceless_units_and_abbreviations_behave_accurately() {
    let compact_source = "Dr. Lin et al. Compared veltrixamine 40mg vs. Placebo in adults over 12weeks. Score improved by 4.5points.";

    // Faithful single sentences containing abbreviations ("Dr.", "et al.", "vs.") pass cleanly:
    assert_eq!(
        verify_claim_against_source(
            "Dr. Lin et al. Compared veltrixamine 40mg vs. Placebo in adults over 12weeks.",
            compact_source
        ),
        Ok(())
    );

    // Spaceless dose unit swap ("40mg" -> "40mcg") is flagged specifically as UnitMismatch:
    assert_eq!(
        verify_claim_against_source(
            "Dr. Lin et al. Compared veltrixamine 40mcg vs. Placebo in adults over 12weeks.",
            compact_source
        ),
        Err(ClaimVerificationDefect::UnitMismatch)
    );

    // Spaceless timeframe swap ("12weeks" -> "12months") is flagged specifically as TimeframeSwap:
    assert_eq!(
        verify_claim_against_source(
            "Dr. Lin et al. Compared veltrixamine 40mg vs. Placebo in adults over 12months.",
            compact_source
        ),
        Err(ClaimVerificationDefect::TimeframeSwap)
    );
}

#[test]
fn property_1500_mutated_claims_never_escape_deterministic_verifier() {
    const SOURCE: &str = "Adults with glimmer syndrome received veltrixamine 40 mg daily compared with placebo for 12 weeks. \
Relative risk decreased by 20 units in adults at 12 weeks.";

    let mut rng = Prng::new(0xFA17_4F01_2026_1127);
    let base_a = "Adults with glimmer syndrome received veltrixamine 40 mg daily compared with placebo for 12 weeks.";
    let base_b = "Relative risk decreased by 20 units in adults at 12 weeks.";

    assert_eq!(verify_claim_against_source(base_a, SOURCE), Ok(()));
    assert_eq!(verify_claim_against_source(base_b, SOURCE), Ok(()));

    for _ in 0..1_500 {
        let (mutated, expected_defect) = match rng.bounded(9) {
            0 => (
                base_a.replace("40", &format!("{}", 41 + rng.bounded(200))),
                ClaimVerificationDefect::NumericMismatch,
            ),
            1 => (
                base_a.replace("mg", ["mcg", "g", "kg", "ml"][rng.bounded(4)]),
                ClaimVerificationDefect::UnitMismatch,
            ),
            2 => (
                base_a.replace("weeks", ["days", "months", "years"][rng.bounded(3)]),
                ClaimVerificationDefect::TimeframeSwap,
            ),
            3 => (
                base_a.replace(
                    "placebo",
                    ["active control", "standard care", "sham"][rng.bounded(3)],
                ),
                ClaimVerificationDefect::ComparatorSwap,
            ),
            4 => (
                base_a.replace(
                    "Adults",
                    ["Children", "Infants", "Older adults"][rng.bounded(3)],
                ),
                ClaimVerificationDefect::PopulationOrSubgroupSwap,
            ),
            5 => (
                base_b.replace(
                    "Relative risk",
                    ["Absolute risk", "Odds ratio", "Hazard ratio"][rng.bounded(3)],
                ),
                ClaimVerificationDefect::EffectMeasureSwap,
            ),
            6 => (
                base_b.replace("decreased", "did not decrease"),
                ClaimVerificationDefect::NegationOrPolarityFlip,
            ),
            7 => (
                format!("{base_a} {base_b}"),
                ClaimVerificationDefect::CrossSentenceSplice,
            ),
            _ => (
                format!("{base_b}\u{202E}"),
                ClaimVerificationDefect::EmptyOrNonAsciiControl,
            ),
        };

        let verdict = verify_claim_against_source(&mutated, SOURCE);
        assert_eq!(
            verdict,
            Err(expected_defect),
            "mutated claim '{mutated}' must trigger {expected_defect:?}"
        );
        let _ = extract_numeric_facets(&mutated);
    }

    // PICO applicability monotonicity: matching axes -> Applicable; indirectness -> ApplicableWithLimits;
    // hard mismatch -> NotApplicable:
    let q = PicoQuerySpec {
        population: "Adults".to_owned(),
        condition: "Glimmer Syndrome".to_owned(),
        intervention: "Veltrixamine".to_owned(),
        comparator: Some("Placebo".to_owned()),
        outcome: Some("Glimmer Score".to_owned()),
        minimum_weeks: Some(12),
    };
    let mut src = PicoSourceSpec {
        doc_id: "doc-1".to_owned(),
        population: "adults".to_owned(),
        condition: "glimmer  syndrome".to_owned(),
        intervention: "veltrixamine".to_owned(),
        comparator: "placebo".to_owned(),
        outcome: "glimmer score".to_owned(),
        follow_up_weeks: 12,
        surrogate_outcome: false,
    };
    assert_eq!(
        evaluate_pico_applicability(&q, &src).state,
        ApplicabilityState::Applicable
    );
    src.follow_up_weeks = 8;
    assert_eq!(
        evaluate_pico_applicability(&q, &src).state,
        ApplicabilityState::ApplicableWithLimits
    );
    src.population = "children".to_owned();
    assert_eq!(
        evaluate_pico_applicability(&q, &src).state,
        ApplicabilityState::NotApplicable
    );
}

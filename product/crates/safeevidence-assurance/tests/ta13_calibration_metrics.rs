//! `WP-11` / `TA-13`: Clean-room calibration, tie-exact `AURC`/`E-AURC`, Wilson 95% score interval,
//! cluster bootstrap, `P00` selective-assurance rate, and `evaluate_full_assurance` tests.
//!
//! Verifies analytical closed-form reference vectors to `1e-12` precision and runs 1,000-trial
//! deterministic `SplitMix64` property invariants (`ADR-0001`; zero `DAL` code or vectors).

use safeevidence_assurance::eval_metrics::{
    DEFAULT_CALIBRATION_BINS, EvalMetricsError, LOG_LOSS_CLAMP_EPS, P00AssuranceCase, SplitMix64,
    WILSON_Z_95, cluster_bootstrap_rate_ci95, evaluate_calibration, evaluate_p00_assurance_suite,
    evaluate_selective_prediction, neumaier_sum, wilson_ci95,
};
use safeevidence_assurance::full_assurance::{FullAssuranceInput, evaluate_full_assurance};
use safeevidence_contracts::appraisal::{AppraisalConfirmation, BiasLevel, CertaintyLevel};
use safeevidence_contracts::assurance::{ReasonCode, TerminalOutcome};

const TOL: f64 = 1e-12;

fn assert_close(got: f64, expected: f64, label: &str) {
    let diff = (got - expected).abs();
    assert!(
        diff <= TOL,
        "{label}: got {got:.16e}, expected {expected:.16e}, |diff|={diff:.3e} > {TOL:.1e}"
    );
}

#[test]
fn closed_form_brier_nll_ece_mce_match_analytical_derivations_to_1e12() {
    // 1. Perfect forecast (s == y): Brier = 0, NLL = 0, ECE = 0, MCE = 0
    let perfect = evaluate_calibration(
        &[(1.0, true), (1.0, true), (0.0, false), (0.0, false)],
        DEFAULT_CALIBRATION_BINS,
    )
    .expect("perfect calibration");
    assert_close(perfect.brier_score, 0.0, "perfect brier");
    assert_close(perfect.clamped_nll, 0.0, "perfect nll");
    assert_close(perfect.ece, 0.0, "perfect ece");
    assert_close(perfect.mce, 0.0, "perfect mce");
    assert_eq!(perfect.bins[0].count, 2);
    assert_eq!(perfect.bins[9].count, 2);

    // 2. Maximally wrong forecast (s == 1 - y): Brier = 1, NLL = -ln(1e-15), ECE = 1, MCE = 1
    let wrong = evaluate_calibration(&[(1.0, false), (0.0, true)], DEFAULT_CALIBRATION_BINS)
        .expect("wrong calibration");
    assert_close(wrong.brier_score, 1.0, "wrong brier");
    assert_close(wrong.clamped_nll, -LOG_LOSS_CLAMP_EPS.ln(), "wrong nll");
    assert_close(wrong.ece, 1.0, "wrong ece");
    assert_close(wrong.mce, 1.0, "wrong mce");

    // 3. Uniform 0.5 forecast on balanced binary labels: Brier = 0.25, NLL = ln(2), ECE = 0, MCE = 0
    let uniform = evaluate_calibration(&[(0.5, true), (0.5, false)], DEFAULT_CALIBRATION_BINS)
        .expect("uniform calibration");
    assert_close(uniform.brier_score, 0.25, "uniform brier");
    assert_close(uniform.clamped_nll, std::f64::consts::LN_2, "uniform nll");
    assert_close(uniform.ece, 0.0, "uniform ece");
    assert_close(uniform.mce, 0.0, "uniform mce");

    // 4. Two-bin non-trivial analytical vector:
    // Bin 0 [0, 0.5): (0.1, false), (0.2, true) -> mean=0.15, acc=0.5, gap=0.35
    // Bin 1 [0.5, 1]: (0.8, true),  (0.9, false) -> mean=0.85, acc=0.5, gap=0.35
    // Brier = (0.01 + 0.64 + 0.04 + 0.81)/4 = 0.375; ECE = MCE = 0.35
    let two_bin =
        evaluate_calibration(&[(0.1, false), (0.2, true), (0.8, true), (0.9, false)], 2).unwrap();
    assert_close(two_bin.brier_score, 0.375, "two_bin brier");
    assert_close(two_bin.ece, 0.35, "two_bin ece");
    assert_close(two_bin.mce, 0.35, "two_bin mce");
    let expected_nll = (-0.9_f64.ln() - 0.2_f64.ln() - 0.8_f64.ln() - 0.1_f64.ln()) / 4.0;
    assert_close(two_bin.clamped_nll, expected_nll, "two_bin nll");
}

#[test]
fn closed_form_untied_and_tied_aurc_oracle_and_eaurc_match_exact_rationals_to_1e12() {
    // 1. Untied 4-item vector: prefix risks [0, 1/2, 1/3, 1/2] -> AURC = 1/3, AURC* = 5/24, E-AURC = 1/8
    let untied = evaluate_selective_prediction(&[
        (0.9, 0.0, true),
        (0.8, 1.0, true),
        (0.4, 0.0, false),
        (0.1, 1.0, false),
    ])
    .expect("untied selective");
    assert_close(untied.coverage, 0.5, "untied coverage");
    assert_close(untied.selective_risk.unwrap(), 0.5, "untied selective_risk");
    assert_close(untied.aurc, 1.0 / 3.0, "untied aurc");
    assert_close(untied.oracle_aurc, 5.0 / 24.0, "untied oracle_aurc");
    assert_close(untied.e_aurc, 0.125, "untied e_aurc");
    assert_eq!(untied.curve.len(), 4);

    // 2. Tied 4-item Jaeger et al. (2023) vector:
    // Scores [0.9 (loss 0), 0.7 (loss 1), 0.7 (loss 0), 0.2 (loss 1)]
    // Prefix expected risks: [0, 1/4, 1/3, 1/2] -> AURC = 13/48, AURC* = 5/24, E-AURC = 1/16
    let tied_a = evaluate_selective_prediction(&[
        (0.9, 0.0, true),
        (0.7, 1.0, true),
        (0.7, 0.0, false),
        (0.2, 1.0, false),
    ])
    .expect("tied A");
    let tied_b = evaluate_selective_prediction(&[
        (0.2, 1.0, false),
        (0.7, 0.0, false),
        (0.9, 0.0, true),
        (0.7, 1.0, true),
    ])
    .expect("tied B");
    assert_eq!(
        tied_a, tied_b,
        "tied permutations must match bit-identically"
    );
    assert_close(tied_a.aurc, 13.0 / 48.0, "tied aurc");
    assert_close(tied_a.oracle_aurc, 5.0 / 24.0, "tied oracle_aurc");
    assert_close(tied_a.e_aurc, 1.0 / 16.0, "tied e_aurc");
    assert_eq!(
        tied_a.curve.len(),
        3,
        "tied scores merge into one operating point"
    );

    // 3. Zero-coverage policy returns selective_risk == None (never 0.0):
    let all_abstain =
        evaluate_selective_prediction(&[(0.8, 1.0, false), (0.2, 0.0, false)]).unwrap();
    assert_eq!(all_abstain.committed_count, 0);
    assert_close(all_abstain.coverage, 0.0, "zero coverage");
    assert_eq!(all_abstain.selective_risk, None);
}

#[test]
fn wilson_ci95_and_neumaier_sum_and_fail_closed_guards_hold() {
    assert_eq!(wilson_ci95(0, 0), None);
    assert_eq!(wilson_ci95(5, 4), None);

    let (lo_zero, hi_zero) = wilson_ci95(0, 100).unwrap();
    assert_close(lo_zero, 0.0, "wilson k=0 lower");
    let expected_hi_zero = (WILSON_Z_95 * WILSON_Z_95) / (100.0 + WILSON_Z_95 * WILSON_Z_95);
    assert_close(hi_zero, expected_hi_zero, "wilson k=0 upper");

    let (lo_all, hi_all) = wilson_ci95(100, 100).unwrap();
    assert_close(lo_all, 1.0 - expected_hi_zero, "wilson k=n lower");
    assert_close(hi_all, 1.0, "wilson k=n upper");

    // Neumaier compensated sum beats naive left-to-right catastrophic cancellation and never turns overflow into NaN:
    let cancelled = [1.0, 1e100, 1.0, -1e100];
    assert_close(neumaier_sum(cancelled), 2.0, "neumaier cancellation");
    assert_eq!(neumaier_sum([f64::MAX, f64::MAX]), f64::INFINITY);

    // Length-prefixed SplitMix64 domain seeding prevents ("a:b", "c") == ("a", "b:c") collisions:
    let mut rng_ab_c = SplitMix64::from_domain("a:b", "c");
    let mut rng_a_bc = SplitMix64::from_domain("a", "b:c");
    assert_ne!(rng_ab_c.next_u64(), rng_a_bc.next_u64());

    // Fail-closed input validation:
    assert_eq!(
        evaluate_calibration(&[], 10),
        Err(EvalMetricsError::EmptyDataset)
    );
    assert_eq!(
        evaluate_calibration(&[(0.5, true)], 0),
        Err(EvalMetricsError::InvalidBinCount)
    );
    assert_eq!(
        evaluate_calibration(
            &[(0.5, true)],
            safeevidence_assurance::eval_metrics::MAX_CALIBRATION_BINS + 1
        ),
        Err(EvalMetricsError::InvalidBinCount)
    );
    assert_eq!(
        evaluate_calibration(&[(f64::NAN, true)], 10),
        Err(EvalMetricsError::InvalidScore { index: 0 })
    );
    assert_eq!(
        evaluate_calibration(&[(1.0001, true)], 10),
        Err(EvalMetricsError::InvalidScore { index: 0 })
    );
    assert_eq!(
        evaluate_selective_prediction(&[(0.5, -0.01, false)]),
        Err(EvalMetricsError::InvalidLoss { index: 0 })
    );
}

#[test]
fn p00_assurance_suite_enforces_manifest_backing_and_cluster_invariance() {
    let mut cases = vec![
        P00AssuranceCase {
            case_id: "c1".to_owned(),
            study_cluster_id: "study-1".to_owned(),
            outcome: TerminalOutcome::Answer,
            committed_manifest: true,
            has_material_claim: true,
            safe_and_supported: true,
            requires_non_commit: false,
            adjudicated_answerable: true,
            requires_escalation: false,
            selective_score: 0.95,
        },
        P00AssuranceCase {
            case_id: "c2".to_owned(),
            study_cluster_id: "study-1".to_owned(),
            outcome: TerminalOutcome::AnswerWithCaution,
            committed_manifest: true,
            has_material_claim: true,
            safe_and_supported: true,
            requires_non_commit: false,
            adjudicated_answerable: true,
            requires_escalation: false,
            selective_score: 0.80,
        },
        P00AssuranceCase {
            case_id: "c3".to_owned(),
            study_cluster_id: "study-2".to_owned(),
            outcome: TerminalOutcome::Conflict,
            committed_manifest: false,
            has_material_claim: false,
            safe_and_supported: false,
            requires_non_commit: true,
            adjudicated_answerable: false,
            requires_escalation: false,
            selective_score: 0.20,
        },
        P00AssuranceCase {
            case_id: "c4".to_owned(),
            study_cluster_id: "study-3".to_owned(),
            outcome: TerminalOutcome::Escalate,
            committed_manifest: false,
            has_material_claim: false,
            safe_and_supported: false,
            requires_non_commit: true,
            adjudicated_answerable: false,
            requires_escalation: true,
            selective_score: 0.05,
        },
    ];

    let rep_fwd = evaluate_p00_assurance_suite("unit-p00", &cases, 10, 500).unwrap();
    cases.reverse();
    let rep_rev = evaluate_p00_assurance_suite("unit-p00", &cases, 10, 500).unwrap();
    assert_eq!(rep_fwd, rep_rev, "suite must be permutation-invariant");

    assert_eq!(rep_fwd.unsafe_commit_rate_on_non_commit_cases.numerator, 0);
    assert_eq!(
        rep_fwd.unsafe_commit_rate_on_non_commit_cases.denominator,
        2
    );
    assert_eq!(rep_fwd.useful_coverage.numerator, 2);
    assert_eq!(rep_fwd.useful_coverage.denominator, 4);
    assert_eq!(rep_fwd.over_abstention_rate.numerator, 0);
    assert_eq!(rep_fwd.over_abstention_rate.denominator, 2);
    assert_eq!(rep_fwd.false_escalation_rate.numerator, 0);
    assert_eq!(rep_fwd.false_escalation_rate.denominator, 3);
    assert_close(rep_fwd.selective.e_aurc, 0.0, "optimal ranking e_aurc");

    // Empty or duplicate case/cluster identity fails closed:
    let mut bad_id = cases.clone();
    bad_id[0].study_cluster_id = "   ".to_owned();
    assert_eq!(
        evaluate_p00_assurance_suite("unit-p00", &bad_id, 10, 100),
        Err(EvalMetricsError::InvalidCaseIdentity { index: 0 })
    );

    // Unbacked commit must fail closed:
    cases[0].outcome = TerminalOutcome::Answer;
    cases[0].committed_manifest = false;
    cases[0].has_material_claim = true;
    assert_eq!(
        evaluate_p00_assurance_suite("unit-p00", &cases, 10, 100),
        Err(EvalMetricsError::UnbackedCommit { index: 0 })
    );

    // Cluster bootstrap is deterministic across calls:
    let obs = [
        ("cl-a", true),
        ("cl-a", true),
        ("cl-b", false),
        ("cl-c", true),
    ];
    let b1 = cluster_bootstrap_rate_ci95("dom", "m", &obs, 1_000);
    let b2 = cluster_bootstrap_rate_ci95("dom", "m", &obs, 1_000);
    assert_eq!(b1, b2);
}

#[test]
fn full_assurance_enforces_p00_guard_precedence_and_grade_confirmation_rules() {
    let base = FullAssuranceInput {
        rights_admissible: true,
        security_permitted: true,
        patient_specific_care_requested: false,
        independent_material_contradiction: false,
        missing_answer_changing_context: false,
        all_sources_retracted_or_invalid: false,
        applicable_independent_studies: 2,
        all_material_claims_verified: true,
        applicability_has_limits: false,
        currentness_unknown: false,
        certainty_level: Some(CertaintyLevel::High),
        certainty_confirmation: Some(AppraisalConfirmation::Confirmed {
            authorized_by: "methodologist-1".to_owned(),
            confirmed_at_utc: "2026-11-27T00:00:00Z".to_owned(),
        }),
        worst_risk_of_bias: Some(BiasLevel::Low),
    };

    assert_eq!(
        evaluate_full_assurance(&base),
        safeevidence_assurance::full_assurance::FullAssuranceDecision {
            outcome: TerminalOutcome::Answer,
            reason: ReasonCode::None,
        }
    );

    // Proposed (unconfirmed) GRADE certainty downgrades Answer -> AnswerWithCaution:
    let mut proposed = base.clone();
    proposed.certainty_confirmation = Some(AppraisalConfirmation::Proposed {
        generator: "rule-engine".to_owned(),
    });
    assert_eq!(
        evaluate_full_assurance(&proposed).outcome,
        TerminalOutcome::AnswerWithCaution
    );

    // High/Critical or unassessed (None / NoInformation) Risk-of-Bias downgrades Answer -> AnswerWithCaution:
    let mut high_rob = base.clone();
    high_rob.worst_risk_of_bias = Some(BiasLevel::High);
    assert_eq!(
        evaluate_full_assurance(&high_rob).outcome,
        TerminalOutcome::AnswerWithCaution
    );
    let mut unassessed_rob = base.clone();
    unassessed_rob.worst_risk_of_bias = None;
    assert_eq!(
        evaluate_full_assurance(&unassessed_rob).outcome,
        TerminalOutcome::AnswerWithCaution
    );
    let mut empty_actor = base.clone();
    empty_actor.certainty_confirmation = Some(AppraisalConfirmation::Confirmed {
        authorized_by: "   ".to_owned(),
        confirmed_at_utc: "2026-11-27T00:00:00Z".to_owned(),
    });
    assert_eq!(
        evaluate_full_assurance(&empty_actor).outcome,
        TerminalOutcome::AnswerWithCaution
    );

    // Single study with VeryLow certainty abstains:
    let mut very_low_single = base.clone();
    very_low_single.applicable_independent_studies = 1;
    very_low_single.certainty_level = Some(CertaintyLevel::VeryLow);
    assert_eq!(
        evaluate_full_assurance(&very_low_single).outcome,
        TerminalOutcome::Abstain
    );

    // Precedence: Security/Rights Blocked > Escalate > Conflict > AskMore > Abstain
    let mut all_guards = base;
    all_guards.rights_admissible = false;
    all_guards.patient_specific_care_requested = true;
    all_guards.independent_material_contradiction = true;
    all_guards.missing_answer_changing_context = true;
    assert_eq!(
        evaluate_full_assurance(&all_guards).outcome,
        TerminalOutcome::Blocked
    );
    all_guards.rights_admissible = true;
    assert_eq!(
        evaluate_full_assurance(&all_guards).outcome,
        TerminalOutcome::Escalate
    );
    all_guards.patient_specific_care_requested = false;
    assert_eq!(
        evaluate_full_assurance(&all_guards).outcome,
        TerminalOutcome::Conflict
    );
    all_guards.independent_material_contradiction = false;
    assert_eq!(
        evaluate_full_assurance(&all_guards).outcome,
        TerminalOutcome::AskMore
    );
}

#[test]
fn property_1000_random_trials_satisfy_bounds_permutation_invariance_and_signed_zero() {
    // Signed zero canonicalization (-0.0 vs +0.0):
    let neg_zero = evaluate_selective_prediction(&[(-0.0, 1.0, false), (0.0, 0.0, true)]).unwrap();
    let pos_zero = evaluate_selective_prediction(&[(0.0, 1.0, false), (0.0, 0.0, true)]).unwrap();
    assert_eq!(neg_zero, pos_zero);

    let mut rng = SplitMix64::from_seed(0x5AFE_E71D_2026_1127);
    for trial in 0..1_000 {
        let n = 1 + rng.next_bounded(32);
        let bins = 1 + rng.next_bounded(15);
        let mut cal_items = Vec::with_capacity(n);
        let mut sel_items = Vec::with_capacity(n);

        for _ in 0..n {
            // Quantize half the scores to 0.1 steps to exercise dense score ties heavily:
            let score = if rng.next_bounded(2) == 0 {
                (rng.next_bounded(11) as f64) / 10.0
            } else {
                (rng.next_u64() >> 11) as f64 * (1.0 / ((1_u64 << 53) as f64))
            };
            let y = rng.next_bounded(2) == 1;
            let committed = rng.next_bounded(2) == 1;
            let loss = if y { 0.0 } else { 1.0 };
            cal_items.push((score, y));
            sel_items.push((score, loss, committed));
        }

        let cal_a = evaluate_calibration(&cal_items, bins).unwrap();
        let sel_a = evaluate_selective_prediction(&sel_items).unwrap();

        // Bounds invariants:
        assert!(
            (0.0..=1.0).contains(&cal_a.brier_score),
            "trial {trial}: brier out of bounds"
        );
        assert!(cal_a.clamped_nll >= 0.0 && cal_a.clamped_nll.is_finite());
        assert!(
            0.0 <= cal_a.ece && cal_a.ece <= cal_a.mce + TOL && cal_a.mce <= 1.0 + TOL,
            "trial {trial}: 0 <= ECE <= MCE <= 1 violated ({} vs {})",
            cal_a.ece,
            cal_a.mce
        );
        assert_eq!(cal_a.bins.iter().map(|b| b.count).sum::<usize>(), n);

        assert!(
            0.0 <= sel_a.oracle_aurc
                && sel_a.oracle_aurc <= sel_a.aurc + TOL
                && sel_a.aurc <= 1.0 + TOL,
            "trial {trial}: 0 <= oracle_aurc <= aurc <= 1 violated ({} vs {})",
            sel_a.oracle_aurc,
            sel_a.aurc
        );
        assert_close(
            sel_a.e_aurc,
            (sel_a.aurc - sel_a.oracle_aurc).max(0.0),
            "e_aurc identity",
        );

        // Fisher-Yates shuffle to verify bit-exact permutation invariance:
        let mut cal_perm = cal_items;
        let mut sel_perm = sel_items;
        for i in (1..n).rev() {
            let j = rng.next_bounded(i + 1);
            cal_perm.swap(i, j);
            sel_perm.swap(i, j);
        }
        let cal_b = evaluate_calibration(&cal_perm, bins).unwrap();
        let sel_b = evaluate_selective_prediction(&sel_perm).unwrap();
        assert_eq!(cal_a, cal_b, "trial {trial}: calibration permutation drift");
        assert_eq!(sel_a, sel_b, "trial {trial}: selective permutation drift");
    }
}

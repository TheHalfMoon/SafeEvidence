//! `ADM-0022` / `T19` Quantitative Meta-Analysis golden-vector & `TA-07`/`TA-18` study-independence
//! synthesis tests.
//!
//! Adapted from `statsmodels/stats/tests/test_meta.py` (`BSD-3-Clause`, `ADR-0004`).

#![allow(clippy::excessive_precision)]

use safeevidence_contracts::study::{
    AnalysisPopulation, ContributionKind, Known, OverlapLink, OverlapState,
    ParticipantOverlapGroupId, PoolingRefusal, ReportVersionKind, ResultId, ScopedId, StudyArmId,
    StudyId, SynthesisInput,
};
use safeevidence_meta::{
    MetaError, ProportionStatistic, RandomEffectsMethod, StudyEffectEntry, ZeroCorrection,
    combine_effects, combine_effects_with_options, combine_independent_studies,
    effectsize_2proportions, effectsize_smd, fit_tau_iter_mm, fit_tau_iterative, fit_tau_mm,
};

fn assert_close(actual: f64, expected: f64, rtol: f64, atol: f64, label: &str) {
    let diff = (actual - expected).abs();
    let tol = atol + rtol * expected.abs();
    assert!(
        diff <= tol,
        "{label}: actual={actual:.15} expected={expected:.15} diff={diff:.3e} tol={tol:.3e}"
    );
}

#[test]
fn hedges_g_smd_matches_r_meta_golden_vectors_to_1e_13() {
    // Carroll, Grant, Peck, Donat, Stewart, Young (`Applied Meta-Analysis with R`, `TestEffSmdMeta`)
    let mean_t = [94.0, 98.0, 98.0, 94.0, 98.0, 96.0];
    let sd_t = [22.0, 21.0, 28.0, 19.0, 21.0, 21.0];
    let n_t = [60.0, 65.0, 40.0, 200.0, 50.0, 85.0];
    let mean_c = [92.0, 92.0, 88.0, 82.0, 88.0, 92.0];
    let sd_c = [20.0, 22.0, 26.0, 17.0, 22.0, 22.0];
    let n_c = [60.0, 65.0, 40.0, 200.0, 45.0, 85.0];

    let yi_m = [
        0.094_524_373_360_638_31,
        0.277_356_401_480_360_95,
        0.366_546_348_457_978_2,
        0.664_385_099_891_135_6,
        0.461_807_976_774_141_76,
        0.185_164_644_246_488_87,
    ];
    let vi_m = [
        0.033_371_825_738_809_91,
        0.031_074_349_654_849_27,
        0.050_883_225_253_535_87,
        0.010_557_248_347_418_77,
        0.043_393_244_665_733_24,
        0.023_632_645_371_471_3,
    ];

    let (eff, var_eff) = effectsize_smd(&mean_t, &sd_t, &n_t, &mean_c, &sd_c, &n_c).unwrap();
    for i in 0..6 {
        assert_close(eff[i], yi_m[i], 1e-13, 0.0, &format!("smd[{i}]"));
        assert_close(var_eff[i], vi_m[i], 1e-13, 0.0, &format!("var[{i}]"));
    }
}

#[test]
fn kacker_2004_pm_dl_ca_c2_and_hksj_match_statsmodels_and_metafor() {
    let eff = [
        61.00, 61.40, 62.21, 62.30, 62.34, 62.60, 62.70, 62.84, 65.90,
    ];
    let var_eff = [
        0.2025, 1.2100, 0.0900, 0.2025, 0.3844, 0.5625, 0.0676, 0.0225, 1.8225,
    ];

    let (tau2_pm, converged) = fit_tau_iterative(&eff, &var_eff, 0.1, 1e-8, 50);
    assert!(converged);
    assert_close(tau2_pm.sqrt(), 0.8399, 0.0, 6e-5, "tau_PM");

    let uniform = vec![1.0 / 9.0; 9];
    let tau2_ca = fit_tau_mm(&eff, &var_eff, &uniform);
    assert_close(tau2_ca.sqrt(), 1.1837, 0.0, 6e-5, "tau_CA");

    let inv_var: Vec<f64> = var_eff.iter().map(|&v| 1.0 / v).collect();
    let tau2_dl = fit_tau_mm(&eff, &var_eff, &inv_var);
    assert_close(tau2_dl.sqrt(), 0.5359, 0.0, 1e-3, "tau_DL");

    let (tau2_c2, _) = fit_tau_iter_mm(&eff, &var_eff, tau2_ca, 1e-8, 1);
    assert_close(tau2_c2.sqrt(), 0.9352, 0.0, 6e-5, "tau_C2");

    let pm_res = combine_effects_with_options(
        &eff,
        &var_eff,
        RandomEffectsMethod::PauleMandel,
        None,
        false,
        0.05,
        0.1,
        1e-7,
        50,
    )
    .unwrap();
    assert_close(pm_res.tau2, tau2_pm, 0.0, 1e-9, "combine_PM_tau2");
    assert_close(
        pm_res.scale_hksj_re,
        1.0,
        0.0,
        1e-7,
        "PM_converged_hksj_scale_is_1",
    );
    assert!(pm_res.prediction_interval_re.is_some());
    assert!(pm_res.homogeneity.pvalue < 0.05);

    let dl_res = combine_effects(
        &eff,
        &var_eff,
        RandomEffectsMethod::DerSimonianLaird,
        true,
        0.05,
    )
    .unwrap();
    assert_close(dl_res.tau2, tau2_dl, 0.0, 1e-12, "combine_DL_tau2");
    assert!(
        (dl_res.ci_re_hksj.upper - dl_res.ci_re_hksj.lower)
            > (dl_res.ci_fe.upper - dl_res.ci_fe.lower),
        "HKSJ random-effects t-interval must reflect between-study heterogeneity"
    );
}

#[test]
fn two_proportions_per_study_zero_correction_tac_and_invalid_inputs() {
    // Sweeting et al. 2004 closed-form TAC (`0/20 vs 3/60`):
    let p1: f64 = 0.25 / 20.5;
    let p2: f64 = 3.75 / 61.5;
    let (eff_tac, var_tac) = effectsize_2proportions(
        &[0.0],
        &[20.0],
        &[3.0],
        &[60.0],
        ProportionStatistic::LogRiskRatio,
        ZeroCorrection::TreatmentArmContinuity,
    )
    .unwrap();
    assert_close(eff_tac[0], (p1 / p2).ln(), 1e-12, 0.0, "TAC_log_rr");
    assert_close(
        var_tac[0],
        (1.0 - p1) / p1 / 20.5 + (1.0 - p2) / p2 / 61.5,
        1e-12,
        0.0,
        "TAC_var_rr",
    );

    // Double-zero TAC with unequal sample sizes yields zero effect:
    let (eff_dz, _) = effectsize_2proportions(
        &[0.0],
        &[20.0],
        &[0.0],
        &[60.0],
        ProportionStatistic::LogOddsRatio,
        ZeroCorrection::TreatmentArmContinuity,
    )
    .unwrap();
    assert_close(eff_dz[0], 0.0, 0.0, 1e-12, "TAC_double_zero");

    // GH#10290 per-study zero mask: study 1 (`9/45 vs 1/15`) has no zero cell and must match uncorrected!
    let (eff_batch, var_batch) = effectsize_2proportions(
        &[3.0, 9.0],
        &[72.0, 45.0],
        &[0.0, 1.0],
        &[68.0, 15.0],
        ProportionStatistic::LogOddsRatio,
        ZeroCorrection::Constant(0.5),
    )
    .unwrap();
    let (eff_single, var_single) = effectsize_2proportions(
        &[9.0],
        &[45.0],
        &[1.0],
        &[15.0],
        ProportionStatistic::LogOddsRatio,
        ZeroCorrection::None,
    )
    .unwrap();
    assert_close(eff_batch[1], eff_single[0], 1e-13, 0.0, "GH10290_eff");
    assert_close(var_batch[1], var_single[0], 1e-13, 0.0, "GH10290_var");

    // Invalid counts and negative variances fail closed:
    assert!(matches!(
        effectsize_2proportions(
            &[25.0],
            &[20.0],
            &[5.0],
            &[30.0],
            ProportionStatistic::RiskDifference,
            ZeroCorrection::None
        ),
        Err(MetaError::InvalidCounts(0))
    ));
    assert!(matches!(
        combine_effects(
            &[0.1, 0.2],
            &[0.02, -0.01],
            RandomEffectsMethod::DerSimonianLaird,
            false,
            0.05
        ),
        Err(MetaError::InvalidVariance(1))
    ));
}

fn make_primary_entry(
    study_id: &str,
    result_id: &str,
    group_id: &str,
    eff: f64,
    var: f64,
) -> StudyEffectEntry {
    StudyEffectEntry {
        synthesis_input: SynthesisInput {
            result: ResultId(ScopedId {
                scope: "synthetic".to_owned(),
                id: result_id.to_owned(),
                version: 1,
            }),
            study: StudyId(ScopedId {
                scope: "synthetic".to_owned(),
                id: study_id.to_owned(),
                version: 1,
            }),
            kind: ContributionKind::PrimaryStudy,
            title: format!("Trial {study_id}"),
            report_kind: Known::Known(ReportVersionKind::Published),
            population: Known::Known(AnalysisPopulation::Itt),
            timepoint: Known::Known("12 weeks".to_owned()),
            arms: vec![StudyArmId(ScopedId {
                scope: "synthetic".to_owned(),
                id: format!("arm-{study_id}"),
                version: 1,
            })],
            contains: Vec::new(),
            participants: Known::Known(ParticipantOverlapGroupId(ScopedId {
                scope: "synthetic".to_owned(),
                id: group_id.to_owned(),
                version: 1,
            })),
            denominator: Known::Known(120),
            covariance: Known::Unknown {
                reason: "independent study".to_owned(),
            },
        },
        effect: eff,
        variance: var,
    }
}

#[test]
fn combine_independent_studies_refuses_duplicate_study_or_overlapping_cohort_and_pools_independent_set()
 {
    let s1 = make_primary_entry("study-1", "res-1", "grp-1", -0.42, 0.04);
    let s2 = make_primary_entry("study-2", "res-2", "grp-2", -0.35, 0.05);
    let s3 = make_primary_entry("study-3", "res-3", "grp-3", -0.51, 0.03);

    let (decision, pooled) = combine_independent_studies(
        &[s1.clone(), s2.clone(), s3],
        &[],
        RandomEffectsMethod::PauleMandel,
        true,
        0.05,
    )
    .unwrap();
    assert_eq!(decision.accepted.len(), 3);
    assert!(pooled.mean_effect_re < 0.0);

    // Duplicate report of `study-1` (`res-1b`) MUST be refused fail-closed (`TA-07` + `TA-18`):
    let s1_dup = make_primary_entry("study-1", "res-1b", "grp-1b", -0.40, 0.04);
    assert!(matches!(
        combine_independent_studies(
            &[s1.clone(), s1_dup],
            &[],
            RandomEffectsMethod::DerSimonianLaird,
            false,
            0.05
        ),
        Err(MetaError::PoolingRefused(
            PoolingRefusal::PoolingRefusedUnitOfAnalysis { .. }
        ))
    ));

    // Overlapping participant cohort via `OverlapLink` MUST also be refused fail-closed:
    let overlap = OverlapLink {
        group: ParticipantOverlapGroupId(ScopedId {
            scope: "synthetic".to_owned(),
            id: "shared-registry-cohort".to_owned(),
            version: 1,
        }),
        first: s1.synthesis_input.result.clone(),
        second: s2.synthesis_input.result.clone(),
        state: OverlapState::Confirmed,
    };
    assert!(matches!(
        combine_independent_studies(
            &[s1, s2],
            &[overlap],
            RandomEffectsMethod::DerSimonianLaird,
            false,
            0.05
        ),
        Err(MetaError::PoolingRefused(
            PoolingRefusal::PoolingRefusedUnitOfAnalysis { .. }
        ))
    ));
}

//! Deterministic Quantitative Meta-Analysis & Study-Independence Synthesis Gate (`ADM-0022` /
//! `T19`, `TA-07`, `TA-18`).
//!
//! Adapted in pure safe Rust (`#![forbid(unsafe_code)]`) from `statsmodels/stats/meta_analysis.py`
//! (`BSD-3-Clause`, `ADR-0004`), extended with:
//! 1. Mandatory `safeevidence_contracts::study::decide_pooling` study-independence pre-gate
//!    (`combine_independent_studies`) refusing duplicate study reports, participant overlap, or
//!    unmodeled shared-arm covariance before any pooling weights are computed.
//! 2. Stable centered Cochran's $Q$ accumulation avoiding catastrophic floating-point cancellation.
//! 3. Fixed-effects inverse-variance, DerSimonian-Laird (`DL`), iterative Paule-Mandel (`PM`),
//!    Cochran ANOVA (`CA`), two-step (`C2`), Hartung-Knapp-Sidik-Jonkman (`HKSJ` $t_{k-1}$ WLS
//!    scale adjustment), homogeneity $\chi^2_{k-1}$ test, $H^2$, $I^2$, and $95\%$ prediction
//!    intervals ($t_{k-2}$ when $k \ge 3$).

#![forbid(unsafe_code)]

use safeevidence_contracts::study::{
    OverlapLink, PoolingDecision, PoolingRefusal, SynthesisInput, decide_pooling,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum MetaError {
    #[error("at least 2 independent studies are required for pooling (got {0})")]
    InsufficientStudies(usize),
    #[error("effect and variance slices must have identical length ({0} vs {1})")]
    LengthMismatch(usize, usize),
    #[error("non-finite effect estimate at index {0}")]
    NonFiniteEffect(usize),
    #[error("variance estimates must be finite and strictly positive (invalid at index {0})")]
    InvalidVariance(usize),
    #[error("significance level alpha must lie strictly in (0, 1), got {0}")]
    InvalidAlpha(f64),
    #[error("counts must satisfy 0 <= count <= nobs and nobs > 0 (invalid at index {0})")]
    InvalidCounts(usize),
    #[error("sample sizes for SMD must satisfy nobs1 >= 2, nobs2 >= 2, nobs1 + nobs2 >= 5")]
    InvalidSmdSampleSize,
    #[error("zero cell encountered with ZeroCorrection::None; proportion ratio undefined")]
    ZeroCellUndefined,
    #[error("invalid continuity correction parameter: {0}")]
    InvalidZeroCorrection(&'static str),
    #[error("study independence pooling gate refused synthesis: {0:?}")]
    PoolingRefused(PoolingRefusal),
    #[error(
        "correlated shared-participant inputs require an explicit multivariate covariance model"
    )]
    CovarianceMethodRequired,
}

/// Between-study variance ($\tau^2$) estimator (`T19` / `TA-18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RandomEffectsMethod {
    /// Iterative Paule-Mandel root-finding ($Q(\tau^2) = k - 1$).
    PauleMandel,
    /// One-step DerSimonian-Laird method-of-moments estimator.
    DerSimonianLaird,
}

/// Two-proportion effect-size scale (`effectsize_2proportions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProportionStatistic {
    /// $p_1 - p_2$
    RiskDifference,
    /// $\ln(p_1 / p_2)$
    LogRiskRatio,
    /// $\ln\left(\frac{p_1 / (1 - p_1)}{p_2 / (1 - p_2)}\right)$
    LogOddsRatio,
    /// $\arcsin(\sqrt{p_1}) - \arcsin(\sqrt{p_2})$
    ArcsineSqrt,
}

/// Per-study zero-cell continuity correction (`Sweeting et al. 2004`, `statsmodels` GH#10290).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroCorrection {
    None,
    /// Adds `c` to both counts and `2c` to both denominators ONLY for studies with a zero/all-event cell.
    Constant(f64),
    /// Treatment-arm continuity correction (`TAC`): adds $n_1 / (n_1 + n_2)$ and $n_2 / (n_1 + n_2)$.
    TreatmentArmContinuity,
    /// Clips proportions into `[lo, hi]` (default `(1e-6, 1.0 - 1e-6)`).
    Clip {
        lo: f64,
        hi: f64,
    },
}

impl ZeroCorrection {
    #[must_use]
    pub const fn default_clip() -> Self {
        Self::Clip {
            lo: 1e-6,
            hi: 1.0 - 1e-6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomogeneityTestResult {
    pub statistic_q: f64,
    pub pvalue: f64,
    pub df: usize,
    pub distribution: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectInterval {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudySummaryRow {
    pub study_label: String,
    pub effect: f64,
    pub sd_eff: f64,
    pub interval: EffectInterval,
    pub relative_weight_fe: f64,
    pub relative_weight_re: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaAnalysisResult {
    pub k: usize,
    pub df_resid: usize,
    pub method_re: RandomEffectsMethod,
    pub tau2: f64,
    pub tau2_converged: bool,
    pub q: f64,
    pub h2: f64,
    /// Fraction in `[0.0, 1.0]` (never formatted as `%` on UI surfaces per `D-13`).
    pub i2: f64,
    pub mean_effect_fe: f64,
    pub var_eff_w_fe: f64,
    pub sd_eff_w_fe: f64,
    pub mean_effect_re: f64,
    pub var_eff_w_re: f64,
    pub sd_eff_w_re: f64,
    pub scale_hksj_fe: f64,
    pub scale_hksj_re: f64,
    pub var_hksj_fe: f64,
    pub var_hksj_re: f64,
    pub sd_eff_w_fe_hksj: f64,
    pub sd_eff_w_re_hksj: f64,
    pub ci_fe: EffectInterval,
    pub ci_re: EffectInterval,
    pub ci_fe_hksj: EffectInterval,
    pub ci_re_hksj: EffectInterval,
    /// $95\%$ (or $1 - \alpha$) prediction interval across future settings when $k \ge 3$.
    pub prediction_interval_re: Option<EffectInterval>,
    pub homogeneity: HomogeneityTestResult,
    pub studies: Vec<StudySummaryRow>,
}

impl MetaAnalysisResult {
    /// Recomputes overall intervals for `(alpha, use_t)`:
    /// returns `(ci_fe, ci_re, ci_fe_hksj, ci_re_hksj)`.
    pub fn intervals_for(
        &self,
        alpha: f64,
        use_t: bool,
    ) -> Result<
        (
            EffectInterval,
            EffectInterval,
            EffectInterval,
            EffectInterval,
        ),
        MetaError,
    > {
        if !alpha.is_finite() || alpha <= 0.0 || alpha >= 1.0 {
            return Err(MetaError::InvalidAlpha(alpha));
        }
        let crit = if use_t {
            student_t_isf(alpha * 0.5, self.df_resid as f64)
        } else {
            normal_isf(alpha * 0.5)
        };
        Ok((
            EffectInterval {
                lower: self.mean_effect_fe - crit * self.sd_eff_w_fe,
                upper: self.mean_effect_fe + crit * self.sd_eff_w_fe,
            },
            EffectInterval {
                lower: self.mean_effect_re - crit * self.sd_eff_w_re,
                upper: self.mean_effect_re + crit * self.sd_eff_w_re,
            },
            EffectInterval {
                lower: self.mean_effect_fe - crit * self.sd_eff_w_fe_hksj,
                upper: self.mean_effect_fe + crit * self.sd_eff_w_fe_hksj,
            },
            EffectInterval {
                lower: self.mean_effect_re - crit * self.sd_eff_w_re_hksj,
                upper: self.mean_effect_re + crit * self.sd_eff_w_re_hksj,
            },
        ))
    }
}

/// Study effect paired with its canonical `SynthesisInput` provenance for `TA-07`/`TA-18` gating.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyEffectEntry {
    pub synthesis_input: SynthesisInput,
    pub effect: f64,
    pub variance: f64,
}

/// Runs `safeevidence_contracts::study::decide_pooling` over `entries` + `overlaps` FIRST,
/// refusing duplicate studies, overlapping participant cohorts, secondary reviews, or missing
/// denominators fail-closed before delegating to [`combine_effects`].
pub fn combine_independent_studies(
    entries: &[StudyEffectEntry],
    overlaps: &[OverlapLink],
    method_re: RandomEffectsMethod,
    use_t: bool,
    alpha: f64,
) -> Result<(PoolingDecision, MetaAnalysisResult), MetaError> {
    let inputs: Vec<SynthesisInput> = entries.iter().map(|e| e.synthesis_input.clone()).collect();
    let decision = decide_pooling(&inputs, overlaps).map_err(MetaError::PoolingRefused)?;
    if decision.requires_covariance_method {
        return Err(MetaError::CovarianceMethodRequired);
    }
    let effects: Vec<f64> = entries.iter().map(|e| e.effect).collect();
    let variances: Vec<f64> = entries.iter().map(|e| e.variance).collect();
    let labels: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{}:{}:{}",
                e.synthesis_input.study.0.scope,
                e.synthesis_input.study.0.id,
                e.synthesis_input.study.0.version
            )
        })
        .collect();
    let meta = combine_effects_with_options(
        &effects,
        &variances,
        method_re,
        Some(&labels),
        use_t,
        alpha,
        0.0,
        1e-7,
        100,
    )?;
    Ok((decision, meta))
}

/// Bias-corrected Hedges' $g$ standardized mean difference (`effectsize_smd` in `statsmodels`).
pub fn effectsize_smd(
    mean1: &[f64],
    sd1: &[f64],
    nobs1: &[f64],
    mean2: &[f64],
    sd2: &[f64],
    nobs2: &[f64],
) -> Result<(Vec<f64>, Vec<f64>), MetaError> {
    let k = mean1.len();
    if sd1.len() != k || nobs1.len() != k || mean2.len() != k || sd2.len() != k || nobs2.len() != k
    {
        return Err(MetaError::LengthMismatch(k, sd1.len()));
    }
    let mut eff = Vec::with_capacity(k);
    let mut var = Vec::with_capacity(k);
    for i in 0..k {
        let (m1, s1, n1, m2, s2, n2) = (mean1[i], sd1[i], nobs1[i], mean2[i], sd2[i], nobs2[i]);
        if !m1.is_finite() || !m2.is_finite() {
            return Err(MetaError::NonFiniteEffect(i));
        }
        if !s1.is_finite() || !s2.is_finite() || s1 <= 0.0 || s2 <= 0.0 {
            return Err(MetaError::InvalidVariance(i));
        }
        if !n1.is_finite() || !n2.is_finite() || n1 < 2.0 || n2 < 2.0 || (n1 + n2) < 5.0 {
            return Err(MetaError::InvalidSmdSampleSize);
        }
        let nobs = n1 + n2;
        let var_diff = (s1 * s1 * (n1 - 1.0) + s2 * s2 * (n2 - 1.0)) / (nobs - 2.0);
        let sd_diff = var_diff.sqrt();
        let bias_correction = 1.0 - 3.0 / (4.0 * nobs - 9.0);
        let smd = (m1 - m2) / sd_diff;
        let smd_bc = bias_correction * smd;
        let var_smdbc = nobs / n1 / n2 + (smd_bc * smd_bc) / 2.0 / (nobs - 3.94);
        eff.push(smd_bc);
        var.push(var_smdbc);
    }
    Ok((eff, var))
}

/// Two-sample binomial proportion effect sizes and asymptotic variances (`effectsize_2proportions`).
pub fn effectsize_2proportions(
    count1: &[f64],
    nobs1: &[f64],
    count2: &[f64],
    nobs2: &[f64],
    statistic: ProportionStatistic,
    zero_correction: ZeroCorrection,
) -> Result<(Vec<f64>, Vec<f64>), MetaError> {
    let k = count1.len();
    if nobs1.len() != k || count2.len() != k || nobs2.len() != k {
        return Err(MetaError::LengthMismatch(k, nobs1.len()));
    }
    if let ZeroCorrection::Constant(c) = zero_correction
        && (!c.is_finite() || c <= 0.0)
    {
        return Err(MetaError::InvalidZeroCorrection(
            "constant zero_correction must be finite and positive",
        ));
    }
    if let ZeroCorrection::Clip { lo, hi } = zero_correction
        && (!lo.is_finite() || !hi.is_finite() || lo <= 0.0 || hi >= 1.0 || lo >= hi)
    {
        return Err(MetaError::InvalidZeroCorrection(
            "clip bounds must satisfy 0 < lo < hi < 1",
        ));
    }

    let mut eff = Vec::with_capacity(k);
    let mut var = Vec::with_capacity(k);
    for i in 0..k {
        let (c1, n1_raw, c2, n2_raw) = (count1[i], nobs1[i], count2[i], nobs2[i]);
        if !c1.is_finite()
            || !n1_raw.is_finite()
            || !c2.is_finite()
            || !n2_raw.is_finite()
            || n1_raw <= 0.0
            || n2_raw <= 0.0
            || c1 < 0.0
            || c1 > n1_raw
            || c2 < 0.0
            || c2 > n2_raw
        {
            return Err(MetaError::InvalidCounts(i));
        }

        let zmask = c1 == 0.0 || c1 == n1_raw || c2 == 0.0 || c2 == n2_raw;
        let (cc1, cc2) = match zero_correction {
            ZeroCorrection::None | ZeroCorrection::Clip { .. } => (0.0, 0.0),
            ZeroCorrection::Constant(c) => (c, c),
            ZeroCorrection::TreatmentArmContinuity => {
                let nt = n1_raw + n2_raw;
                (n1_raw / nt, n2_raw / nt)
            }
        };
        let z = if zmask { 1.0 } else { 0.0 };
        let n1 = n1_raw + 2.0 * cc1 * z;
        let n2 = n2_raw + 2.0 * cc2 * z;
        let mut p1 = (c1 + cc1 * z) / n1;
        let mut p2 = (c2 + cc2 * z) / n2;
        if let ZeroCorrection::Clip { lo, hi } = zero_correction {
            p1 = p1.clamp(lo, hi);
            p2 = p2.clamp(lo, hi);
        }

        let (e_i, v_i) = match statistic {
            ProportionStatistic::RiskDifference => {
                let rd = p1 - p2;
                let rd_var = p1 * (1.0 - p1) / n1 + p2 * (1.0 - p2) / n2;
                (rd, rd_var)
            }
            ProportionStatistic::LogRiskRatio => {
                if p1 <= 0.0 || p2 <= 0.0 {
                    return Err(MetaError::ZeroCellUndefined);
                }
                let log_rr = p1.ln() - p2.ln();
                let log_rr_var = (1.0 - p1) / p1 / n1 + (1.0 - p2) / p2 / n2;
                (log_rr, log_rr_var)
            }
            ProportionStatistic::LogOddsRatio => {
                if p1 <= 0.0 || p1 >= 1.0 || p2 <= 0.0 || p2 >= 1.0 {
                    return Err(MetaError::ZeroCellUndefined);
                }
                let log_or = p1.ln() - (1.0 - p1).ln() - p2.ln() + (1.0 - p2).ln();
                let log_or_var = 1.0 / (p1 * (1.0 - p1) * n1) + 1.0 / (p2 * (1.0 - p2) * n2);
                (log_or, log_or_var)
            }
            ProportionStatistic::ArcsineSqrt => {
                let as_diff = p1.sqrt().asin() - p2.sqrt().asin();
                let as_var = (1.0 / n1 + 1.0 / n2) * 0.25;
                (as_diff, as_var)
            }
        };
        eff.push(e_i);
        var.push(v_i);
    }
    Ok((eff, var))
}

/// Combines study effect sizes using fixed-effects and random-effects (`PM` or `DL`) + `HKSJ`.
pub fn combine_effects(
    effect: &[f64],
    variance: &[f64],
    method_re: RandomEffectsMethod,
    use_t: bool,
    alpha: f64,
) -> Result<MetaAnalysisResult, MetaError> {
    combine_effects_with_options(
        effect, variance, method_re, None, use_t, alpha, 0.0, 1e-7, 100,
    )
}

/// Full `combine_effects` entry with configurable `PM` iteration tolerances (`tau2_start`, `atol`, `maxiter`).
#[allow(clippy::too_many_arguments)]
pub fn combine_effects_with_options(
    effect: &[f64],
    variance: &[f64],
    method_re: RandomEffectsMethod,
    row_names: Option<&[String]>,
    use_t: bool,
    alpha: f64,
    tau2_start: f64,
    atol: f64,
    maxiter: usize,
) -> Result<MetaAnalysisResult, MetaError> {
    let k = effect.len();
    if variance.len() != k {
        return Err(MetaError::LengthMismatch(k, variance.len()));
    }
    if k < 2 {
        return Err(MetaError::InsufficientStudies(k));
    }
    if !alpha.is_finite() || alpha <= 0.0 || alpha >= 1.0 {
        return Err(MetaError::InvalidAlpha(alpha));
    }
    for (i, (&y, &v)) in effect.iter().zip(variance).enumerate() {
        if !y.is_finite() {
            return Err(MetaError::NonFiniteEffect(i));
        }
        if !v.is_finite() || v <= 0.0 {
            return Err(MetaError::InvalidVariance(i));
        }
    }

    let weights_fe: Vec<f64> = variance.iter().map(|&v| 1.0 / v).collect();
    let w_total_fe: f64 = weights_fe.iter().sum();
    let weights_rel_fe: Vec<f64> = weights_fe.iter().map(|&w| w / w_total_fe).collect();
    let mean_effect_fe: f64 = weights_rel_fe
        .iter()
        .zip(effect)
        .map(|(&wr, &y)| wr * y)
        .sum();
    let var_eff_w_fe = 1.0 / w_total_fe;
    let sd_eff_w_fe = var_eff_w_fe.sqrt();

    // Centered Cochran's Q avoids catastrophic cancellation when mean_effect_fe is large (e.g. Kacker 2004 ~ 62.5):
    let q: f64 = weights_fe
        .iter()
        .zip(effect)
        .map(|(&w, &y)| {
            let d = y - mean_effect_fe;
            w * d * d
        })
        .sum();
    let df_resid = k - 1;
    let df = df_resid as f64;

    let (tau2, tau2_converged) = match method_re {
        RandomEffectsMethod::PauleMandel => {
            fit_tau_iterative(effect, variance, tau2_start, atol, maxiter)
        }
        RandomEffectsMethod::DerSimonianLaird => {
            let w_sq_sum: f64 = weights_fe.iter().map(|&w| w * w).sum();
            let c = w_total_fe - w_sq_sum / w_total_fe;
            let raw_dl = if c > 0.0 { (q - df) / c } else { 0.0 };
            (raw_dl.max(0.0), true)
        }
    };

    let weights_re: Vec<f64> = variance.iter().map(|&v| 1.0 / (v + tau2)).collect();
    let w_total_re: f64 = weights_re.iter().sum();
    let weights_rel_re: Vec<f64> = weights_re.iter().map(|&w| w / w_total_re).collect();
    let mean_effect_re: f64 = weights_rel_re
        .iter()
        .zip(effect)
        .map(|(&wr, &y)| wr * y)
        .sum();
    let var_eff_w_re = 1.0 / w_total_re;
    let sd_eff_w_re = var_eff_w_re.sqrt();

    let scale_hksj_re: f64 = weights_re
        .iter()
        .zip(effect)
        .map(|(&w, &y)| {
            let d = y - mean_effect_re;
            w * d * d
        })
        .sum::<f64>()
        / df;
    let scale_hksj_fe: f64 = weights_fe
        .iter()
        .zip(effect)
        .map(|(&w, &y)| {
            let d = y - mean_effect_fe;
            w * d * d
        })
        .sum::<f64>()
        / df;

    let var_hksj_re: f64 = weights_rel_re
        .iter()
        .zip(effect)
        .map(|(&wr, &y)| {
            let d = y - mean_effect_re;
            wr * d * d
        })
        .sum::<f64>()
        / df;
    let var_hksj_fe: f64 = weights_rel_fe
        .iter()
        .zip(effect)
        .map(|(&wr, &y)| {
            let d = y - mean_effect_fe;
            wr * d * d
        })
        .sum::<f64>()
        / df;

    let sd_eff_w_fe_hksj = var_hksj_fe.sqrt();
    let sd_eff_w_re_hksj = var_hksj_re.sqrt();

    let h2 = (q / df).max(1.0);
    let i2 = if q > df { (q - df) / q } else { 0.0 };

    let z_sample = normal_isf(alpha * 0.5);
    let mut studies = Vec::with_capacity(k);
    for idx in 0..k {
        let sd_i = variance[idx].sqrt();
        let label = row_names
            .and_then(|names| names.get(idx))
            .cloned()
            .unwrap_or_else(|| format!("study_{}", idx + 1));
        studies.push(StudySummaryRow {
            study_label: label,
            effect: effect[idx],
            sd_eff: sd_i,
            interval: EffectInterval {
                lower: effect[idx] - z_sample * sd_i,
                upper: effect[idx] + z_sample * sd_i,
            },
            relative_weight_fe: weights_rel_fe[idx],
            relative_weight_re: weights_rel_re[idx],
        });
    }

    let crit = if use_t {
        student_t_isf(alpha * 0.5, df)
    } else {
        z_sample
    };
    let ci_fe = EffectInterval {
        lower: mean_effect_fe - crit * sd_eff_w_fe,
        upper: mean_effect_fe + crit * sd_eff_w_fe,
    };
    let ci_re = EffectInterval {
        lower: mean_effect_re - crit * sd_eff_w_re,
        upper: mean_effect_re + crit * sd_eff_w_re,
    };
    let ci_fe_hksj = EffectInterval {
        lower: mean_effect_fe - crit * sd_eff_w_fe_hksj,
        upper: mean_effect_fe + crit * sd_eff_w_fe_hksj,
    };
    let ci_re_hksj = EffectInterval {
        lower: mean_effect_re - crit * sd_eff_w_re_hksj,
        upper: mean_effect_re + crit * sd_eff_w_re_hksj,
    };

    let prediction_interval_re = if k >= 3 {
        let t_pred = student_t_isf(alpha * 0.5, (k - 2) as f64);
        let se_pred = (tau2 + var_eff_w_re).sqrt();
        Some(EffectInterval {
            lower: mean_effect_re - t_pred * se_pred,
            upper: mean_effect_re + t_pred * se_pred,
        })
    } else {
        None
    };

    let pvalue = chi2_sf(q, df_resid);
    let homogeneity = HomogeneityTestResult {
        statistic_q: q,
        pvalue,
        df: df_resid,
        distribution: "chi2".to_owned(),
    };

    Ok(MetaAnalysisResult {
        k,
        df_resid,
        method_re,
        tau2,
        tau2_converged,
        q,
        h2,
        i2,
        mean_effect_fe,
        var_eff_w_fe,
        sd_eff_w_fe,
        mean_effect_re,
        var_eff_w_re,
        sd_eff_w_re,
        scale_hksj_fe,
        scale_hksj_re,
        var_hksj_fe,
        var_hksj_re,
        sd_eff_w_fe_hksj,
        sd_eff_w_re_hksj,
        ci_fe,
        ci_re,
        ci_fe_hksj,
        ci_re_hksj,
        prediction_interval_re,
        homogeneity,
        studies,
    })
}

/// Paule-Mandel iterative estimator of $\tau^2$ (`_fit_tau_iterative` in `statsmodels`,
/// DerSimonian & Kacker 2007 Appendix 8).
#[must_use]
pub fn fit_tau_iterative(
    eff: &[f64],
    var_eff: &[f64],
    tau2_start: f64,
    atol: f64,
    maxiter: usize,
) -> (f64, bool) {
    let k = eff.len();
    if k < 2 {
        return (0.0, false);
    }
    let df = (k - 1) as f64;
    let mut tau2 = tau2_start.max(0.0);
    let mut converged = false;

    for _ in 0..maxiter {
        let w: Vec<f64> = var_eff.iter().map(|&v| 1.0 / (v + tau2)).collect();
        let w_sum: f64 = w.iter().sum();
        let m: f64 = w.iter().zip(eff).map(|(&wi, &yi)| wi * yi).sum::<f64>() / w_sum;
        let resid_sq: Vec<f64> = eff.iter().map(|&yi| (yi - m) * (yi - m)).collect();
        let q_w: f64 = w.iter().zip(&resid_sq).map(|(&wi, &r)| wi * r).sum();
        let ee = q_w - df;
        if ee < 0.0 && tau2 == 0.0 {
            return (0.0, true);
        }
        if ee.abs() <= atol {
            converged = true;
            break;
        }
        let denom: f64 = w.iter().zip(&resid_sq).map(|(&wi, &r)| wi * wi * r).sum();
        if denom <= 0.0 {
            break;
        }
        let next = tau2 + ee / denom;
        if next < 0.0 {
            tau2 = 0.0;
            // Re-check at boundary 0.0 on next iteration
            let w0: Vec<f64> = var_eff.iter().map(|&v| 1.0 / v).collect();
            let w0_sum: f64 = w0.iter().sum();
            let m0: f64 = w0.iter().zip(eff).map(|(&wi, &yi)| wi * yi).sum::<f64>() / w0_sum;
            let q0: f64 = w0
                .iter()
                .zip(eff)
                .map(|(&wi, &yi)| wi * (yi - m0) * (yi - m0))
                .sum();
            if q0 - df <= atol {
                return (0.0, true);
            }
        } else {
            tau2 = next;
        }
    }
    (tau2, converged)
}

/// One-step method-of-moments $\tau^2$ estimator (`_fit_tau_mm` in `statsmodels`, Kacker 2004).
#[must_use]
pub fn fit_tau_mm(eff: &[f64], var_eff: &[f64], weights: &[f64]) -> f64 {
    let w_t: f64 = weights.iter().sum();
    if w_t <= 0.0 {
        return 0.0;
    }
    let m: f64 = weights.iter().zip(eff).map(|(&w, &y)| w * y).sum::<f64>() / w_t;
    let q_w: f64 = weights
        .iter()
        .zip(eff)
        .map(|(&w, &y)| {
            let d = y - m;
            w * d * d
        })
        .sum();
    let w_dot_v: f64 = weights.iter().zip(var_eff).map(|(&w, &v)| w * v).sum();
    let w2_dot_v: f64 = weights.iter().zip(var_eff).map(|(&w, &v)| w * w * v).sum();
    let w2_sum: f64 = weights.iter().map(|&w| w * w).sum();
    let expect = w_dot_v - w2_dot_v / w_t;
    let denom = w_t - w2_sum / w_t;
    if denom <= 0.0 {
        0.0
    } else {
        ((q_w - expect) / denom).max(0.0)
    }
}

/// Iterated method-of-moments $\tau^2$ estimator (`_fit_tau_iter_mm` in `statsmodels`).
#[must_use]
pub fn fit_tau_iter_mm(
    eff: &[f64],
    var_eff: &[f64],
    tau2_start: f64,
    atol: f64,
    maxiter: usize,
) -> (f64, bool) {
    let mut tau2 = tau2_start.max(0.0);
    let mut converged = false;
    for _ in 0..maxiter {
        let w: Vec<f64> = var_eff.iter().map(|&v| 1.0 / (v + tau2)).collect();
        let tau2_new = fit_tau_mm(eff, var_eff, &w).max(0.0);
        if (tau2_new - tau2).abs() <= atol {
            tau2 = tau2_new;
            converged = true;
            break;
        }
        tau2 = tau2_new;
    }
    (tau2, converged)
}

// ---------------------------------------------------------------------------
// Clean-room high-precision statistical distribution functions (`1e-14`)
// ---------------------------------------------------------------------------

/// Lanczos $\ln \Gamma(z)$ ($g = 7, n = 9$, accurate to $\sim 10^{-15}$ for $z > 0$).
fn ln_gamma(z: f64) -> f64 {
    const COEFFS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if z < 0.5 {
        let pi = std::f64::consts::PI;
        return pi.ln() - (pi * z).sin().ln() - ln_gamma(1.0 - z);
    }
    let zm1 = z - 1.0;
    let mut x = COEFFS[0];
    for (idx, &c) in COEFFS.iter().enumerate().skip(1) {
        x += c / (zm1 + idx as f64);
    }
    let t = zm1 + 7.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (zm1 + 0.5) * t.ln() - t + x.ln()
}

/// Regularized upper incomplete gamma $Q(a, x) = \frac{1}{\Gamma(a)} \int_x^\infty t^{a-1} e^{-t}\,dt$.
fn regularized_gamma_q(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    if x < a + 1.0 {
        // Power series for P(a, x), then Q = 1 - P
        let mut ap = a;
        let mut sum = 1.0 / a;
        let mut del = sum;
        for _ in 0..500 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-15 {
                break;
            }
        }
        let p = sum * (-x + a * x.ln() - ln_gamma(a)).exp();
        (1.0 - p).clamp(0.0, 1.0)
    } else {
        // Modified Lentz continued fraction for Q(a, x)
        let fpmin = 1e-300_f64;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / fpmin;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..=500 {
            let an = -(i as f64) * ((i as f64) - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < fpmin {
                d = fpmin;
            }
            c = b + an / c;
            if c.abs() < fpmin {
                c = fpmin;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-15 {
                break;
            }
        }
        (h * (-x + a * x.ln() - ln_gamma(a)).exp()).clamp(0.0, 1.0)
    }
}

/// Chi-square upper-tail survival function $\Pr(\chi^2_{\nu} \ge q)$.
#[must_use]
pub fn chi2_sf(q: f64, df: usize) -> f64 {
    if df == 0 || !q.is_finite() {
        return f64::NAN;
    }
    if q <= 0.0 {
        return 1.0;
    }
    regularized_gamma_q(0.5 * (df as f64), 0.5 * q)
}

/// Complementary error function $\operatorname{erfc}(x)$ via $Q(1/2, x^2)$.
fn erfc_exact(x: f64) -> f64 {
    if x >= 0.0 {
        regularized_gamma_q(0.5, x * x)
    } else {
        2.0 - regularized_gamma_q(0.5, x * x)
    }
}

/// Inverse survival function of standard normal: returns $z$ such that $\Pr(Z > z) = p$.
#[must_use]
pub fn normal_isf(p: f64) -> f64 {
    // Acklam initial approximation + 2 Halley steps against erfc_exact
    let q = p.clamp(1e-15, 1.0 - 1e-15);
    let u = 1.0 - q; // CDF target
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];

    let p_low = 0.02425;
    let p_high = 1.0 - p_low;
    let mut z = if u < p_low {
        let r = (-2.0 * u.ln()).sqrt();
        (((((C[0] * r + C[1]) * r + C[2]) * r + C[3]) * r + C[4]) * r + C[5])
            / ((((D[0] * r + D[1]) * r + D[2]) * r + D[3]) * r + 1.0)
    } else if u <= p_high {
        let r = u - 0.5;
        let s = r * r;
        (((((A[0] * s + A[1]) * s + A[2]) * s + A[3]) * s + A[4]) * s + A[5]) * r
            / (((((B[0] * s + B[1]) * s + B[2]) * s + B[3]) * s + B[4]) * s + 1.0)
    } else {
        let r = (-2.0 * q.ln()).sqrt();
        -(((((C[0] * r + C[1]) * r + C[2]) * r + C[3]) * r + C[4]) * r + C[5])
            / ((((D[0] * r + D[1]) * r + D[2]) * r + D[3]) * r + 1.0)
    };

    let inv_sqrt_2pi = 1.0 / (2.0 * std::f64::consts::PI).sqrt();
    let sqrt_2 = std::f64::consts::SQRT_2;
    for _ in 0..3 {
        let sf = 0.5 * erfc_exact(z / sqrt_2);
        let err = sf - q;
        let pdf = inv_sqrt_2pi * (-0.5 * z * z).exp();
        if pdf > 0.0 {
            let step = err / pdf;
            z += step / (1.0 - 0.5 * z * step);
        }
    }
    z
}

fn betacf(a: f64, b: f64, x: f64) -> f64 {
    let fpmin = 1e-300_f64;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < fpmin {
        d = fpmin;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=500 {
        let mf = m as f64;
        let m2 = 2.0 * mf;
        let aa1 = mf * (b - mf) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa1 * d;
        if d.abs() < fpmin {
            d = fpmin;
        }
        c = 1.0 + aa1 / c;
        if c.abs() < fpmin {
            c = fpmin;
        }
        d = 1.0 / d;
        h *= d * c;

        let aa2 = -(a + mf) * (qab + mf) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa2 * d;
        if d.abs() < fpmin {
            d = fpmin;
        }
        c = 1.0 + aa2 / c;
        if c.abs() < fpmin {
            c = fpmin;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < 1e-15 {
            break;
        }
    }
    h
}

/// Regularized incomplete beta $I_x(a, b)$.
fn regularized_beta(x: f64, a: f64, b: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let bt = (ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln()).exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        (bt * betacf(a, b, x) / a).clamp(0.0, 1.0)
    } else {
        (1.0 - bt * betacf(b, a, 1.0 - x) / b).clamp(0.0, 1.0)
    }
}

/// Student-$t_\nu$ upper-tail quantile: returns $t$ such that $\Pr(T_\nu > t) = p$.
#[must_use]
pub fn student_t_isf(p: f64, df: f64) -> f64 {
    let q = p.clamp(1e-15, 1.0 - 1e-15);
    if (df - 1.0).abs() < 1e-12 {
        return (std::f64::consts::PI * (0.5 - q)).tan();
    }
    let z = normal_isf(q);
    // Cornish-Fisher initial guess + Newton-Raphson against exact regularized_beta
    let z2 = z * z;
    let g1 = (z2 * z + z) / (4.0 * df);
    let g2 = ((5.0 * z2 * z2 + 16.0 * z2 + 3.0) * z) / (96.0 * df * df);
    let mut t = z + g1 + g2;

    let ln_norm =
        ln_gamma(0.5 * (df + 1.0)) - ln_gamma(0.5 * df) - 0.5 * (df * std::f64::consts::PI).ln();
    for _ in 0..8 {
        let x = df / (df + t * t);
        let sf = if t >= 0.0 {
            0.5 * regularized_beta(x, 0.5 * df, 0.5)
        } else {
            1.0 - 0.5 * regularized_beta(x, 0.5 * df, 0.5)
        };
        let err = sf - q;
        if err.abs() < 1e-15 {
            break;
        }
        let pdf = (ln_norm - 0.5 * (df + 1.0) * (1.0 + t * t / df).ln()).exp();
        if pdf > 0.0 {
            t += err / pdf;
        }
    }
    t
}

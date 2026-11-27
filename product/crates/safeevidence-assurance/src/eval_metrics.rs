//! `WP-11` / `WP-20` / `TA-13` / `TA-23`: Clean-room calibration, reliability, and selective-risk
//! evaluation mathematics (`ADR-0001`, `plan-v1.7`; zero `DAL` code, paths, or dependencies).
//!
//! Implements published proper scoring rules, calibration error estimators, tie-exact selective
//! prediction curves, `P00_DECISION_ASSURANCE_CONTRACT` domain rates, exact Wilson 95% score
//! intervals, and deterministic SplitMix64 cluster/item bootstrap confidence intervals:
//! - Brier (1950), *Verification of forecasts expressed in terms of probability*, Mon. Weather Rev.
//! - Naeini, Cooper & Hauskrecht (2015), *Obtaining Well Calibrated Probabilities Using Bayesian Binning*, AAAI.
//! - Guo et al. (2017), *On Calibration of Modern Neural Networks*, ICML.
//! - Geifman & El-Yaniv (2017), *Selective Classification for Deep Neural Networks*, NeurIPS.
//! - Jaeger et al. (2023), *A Call to Reflect on Evaluation Practices for Failure Detection*, ICLR.
//! - Wilson (1927), *Probable Inference, the Law of Succession, and Statistical Inference*, JASA.
//!
//! **P00 D-13 Isolation Invariant:** Offline benchmark challenger inputs use `selective_score`
//! (never any `confidence*` identifier) and emit unitless ratios/losses in `[0.0, 1.0]` with zero
//! `%` formatting. No type in this module enters `AnswerProofManifest` or user-facing UI surfaces.

use std::collections::BTreeMap;

use safeevidence_contracts::assurance::TerminalOutcome;
use safeevidence_contracts::objects::DigestSha256;

/// Clamping floor for binary log-loss (`1e-15 > 2^-52`), preventing `1.0 - eps == 1.0_f64` roundoff.
pub const LOG_LOSS_CLAMP_EPS: f64 = 1e-15;

/// Standard normal 97.5th percentile ($z_{0.975}$) for two-sided 95% Wilson score intervals.
pub const WILSON_Z_95: f64 = 1.959_963_984_540_054;

/// Default equal-width bin count for reliability diagrams (`ECE` / `MCE`).
pub const DEFAULT_CALIBRATION_BINS: usize = 10;

/// Maximum permitted equal-width bin count (`NB-1` DoS allocation bound).
pub const MAX_CALIBRATION_BINS: usize = 10_000;

/// Errors returned fail-closed by [`eval_metrics`](self) functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalMetricsError {
    /// Dataset has zero items ($N = 0$).
    EmptyDataset,
    /// `selective_score` is `NaN`, infinite, or outside `[0.0, 1.0]`.
    InvalidScore { index: usize },
    /// Loss value is `NaN`, infinite, or outside `[0.0, 1.0]`.
    InvalidLoss { index: usize },
    /// Calibration bin count $M == 0$ or $M > \text{MAX\_CALIBRATION\_BINS}$.
    InvalidBinCount,
    /// `case_id` or `study_cluster_id` is empty/whitespace or `case_id` is duplicated.
    InvalidCaseIdentity { index: usize },
    /// Outcome is `Answer` or `AnswerWithCaution` without both a committed manifest and material claim.
    UnbackedCommit { index: usize },
}

/// Neumaier compensated floating-point summation ($\le 2\text{ ulp}$ error across arbitrary $N$).
#[must_use]
pub fn neumaier_sum<I: IntoIterator<Item = f64>>(values: I) -> f64 {
    let mut sum = 0.0_f64;
    let mut comp = 0.0_f64;
    for v in values {
        if !v.is_finite() {
            return v;
        }
        let t = sum + v;
        if !t.is_finite() {
            return t;
        }
        if sum.abs() >= v.abs() {
            comp += (sum - t) + v;
        } else {
            comp += (v - t) + sum;
        }
        sum = t;
    }
    sum + comp
}

fn normalize_unit_score(score: f64, index: usize) -> Result<f64, EvalMetricsError> {
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(EvalMetricsError::InvalidScore { index });
    }
    // Canonicalize -0.0 to +0.0 so bit-equality grouping treats them identically.
    Ok(if score == 0.0 { 0.0 } else { score })
}

fn normalize_unit_loss(loss: f64, index: usize) -> Result<f64, EvalMetricsError> {
    if !loss.is_finite() || !(0.0..=1.0).contains(&loss) {
        return Err(EvalMetricsError::InvalidLoss { index });
    }
    Ok(if loss == 0.0 { 0.0 } else { loss })
}

/// Deterministic SplitMix64 PRNG (`2^64` period, zero fixed points) seeded via domain-separated SHA-256.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds a deterministic generator from injective length-prefixed `(domain, metric)` framing.
    #[must_use]
    pub fn from_domain(domain: &str, metric: &str) -> Self {
        let mut msg = Vec::with_capacity(48 + domain.len() + metric.len());
        msg.extend_from_slice(b"safeevidence.bootstrap.v1:");
        msg.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        msg.extend_from_slice(domain.as_bytes());
        msg.extend_from_slice(&(metric.len() as u64).to_be_bytes());
        msg.extend_from_slice(metric.as_bytes());
        let digest = DigestSha256::of(&msg);
        let bytes: [u8; 8] = digest.as_bytes()[..8].try_into().expect("8-byte prefix");
        Self {
            state: u64::from_be_bytes(bytes),
        }
    }

    /// Creates a generator from an explicit `u64` seed (used by deterministic property suites).
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advances state and returns the next 64 pseudorandom bits.
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Draws an unbiased uniform integer in `0..upper` via rejection sampling (eliminating `% n` bias).
    pub fn next_bounded(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "upper bound must be > 0");
        let bound = upper as u64;
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let r = self.next_u64();
            if r < zone {
                return (r % bound) as usize;
            }
        }
    }
}

/// One equal-width reliability diagram bin (`[lower, upper)` for `0..M-1`, `[lower, 1.0]` for `M-1`).
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationBin {
    pub index: usize,
    pub lower: f64,
    pub upper: f64,
    pub count: usize,
    pub mean_score: Option<f64>,
    pub empirical_accuracy: Option<f64>,
    pub abs_gap: Option<f64>,
}

/// Proper scoring rule and binned calibration metrics over $N \ge 1$ binary items.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationReport {
    pub item_count: usize,
    pub brier_score: f64,
    pub clamped_nll: f64,
    pub ece: f64,
    pub mce: f64,
    pub bins: Vec<CalibrationBin>,
}

/// Evaluates Brier score, cancellation-free clamped binary NLL ($\varepsilon = 10^{-15}$),
/// `ECE`, `MCE`, and reliability-diagram bins over `(selective_score, outcome_true)` pairs.
///
/// # Errors
/// Fails closed if `items` is empty, `bin_count == 0`, or any score lies outside `[0.0, 1.0]`.
pub fn evaluate_calibration(
    items: &[(f64, bool)],
    bin_count: usize,
) -> Result<CalibrationReport, EvalMetricsError> {
    if items.is_empty() {
        return Err(EvalMetricsError::EmptyDataset);
    }
    if bin_count == 0 || bin_count > MAX_CALIBRATION_BINS {
        return Err(EvalMetricsError::InvalidBinCount);
    }

    let n = items.len();
    let n_f64 = n as f64;
    let m_f64 = bin_count as f64;

    // Canonicalize and sort (score, y) before summation so Brier, NLL, and bin means are 100%
    // permutation-invariant down to the final IEEE-754 bit.
    let mut canonical: Vec<(f64, bool)> = Vec::with_capacity(n);
    for (idx, &(raw_s, y)) in items.iter().enumerate() {
        let s = normalize_unit_score(raw_s, idx)?;
        canonical.push((s, y));
    }
    canonical.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut brier_terms = Vec::with_capacity(n);
    let mut nll_terms = Vec::with_capacity(n);
    let mut bin_scores: Vec<Vec<f64>> = vec![Vec::new(); bin_count];
    let mut bin_positives: Vec<usize> = vec![0; bin_count];

    for &(s, y) in &canonical {
        let target = if y { 1.0 } else { 0.0 };
        let diff = s - target;
        brier_terms.push(diff * diff);

        let nll = if y {
            -(s.max(LOG_LOSS_CLAMP_EPS).ln())
        } else if s >= 1.0 - LOG_LOSS_CLAMP_EPS {
            -(LOG_LOSS_CLAMP_EPS.ln())
        } else {
            -((-s).ln_1p())
        };
        nll_terms.push(nll);

        let mut b = ((s * m_f64).floor() as usize).min(bin_count - 1);
        while b > 0 && s < (b as f64 / m_f64) {
            b -= 1;
        }
        while b + 1 < bin_count && s >= ((b + 1) as f64 / m_f64) {
            b += 1;
        }
        bin_scores[b].push(s);
        if y {
            bin_positives[b] += 1;
        }
    }

    let brier_score = (neumaier_sum(brier_terms) / n_f64).clamp(0.0, 1.0);
    let clamped_nll = (neumaier_sum(nll_terms) / n_f64).max(0.0);

    let mut bins = Vec::with_capacity(bin_count);
    let mut ece_terms = Vec::with_capacity(bin_count);
    let mut mce = 0.0_f64;

    for b in 0..bin_count {
        let lower = b as f64 / m_f64;
        let upper = (b + 1) as f64 / m_f64;
        let count = bin_scores[b].len();
        if count == 0 {
            bins.push(CalibrationBin {
                index: b,
                lower,
                upper,
                count: 0,
                mean_score: None,
                empirical_accuracy: None,
                abs_gap: None,
            });
        } else {
            let c_f64 = count as f64;
            let mean_s = (neumaier_sum(bin_scores[b].iter().copied()) / c_f64).clamp(0.0, 1.0);
            let acc = bin_positives[b] as f64 / c_f64;
            let gap = (acc - mean_s).abs();
            ece_terms.push((c_f64 / n_f64) * gap);
            if gap > mce {
                mce = gap;
            }
            bins.push(CalibrationBin {
                index: b,
                lower,
                upper,
                count,
                mean_score: Some(mean_s),
                empirical_accuracy: Some(acc),
                abs_gap: Some(gap),
            });
        }
    }

    let ece = neumaier_sum(ece_terms).clamp(0.0, 1.0);

    Ok(CalibrationReport {
        item_count: n,
        brier_score,
        clamped_nll,
        ece,
        mce,
        bins,
    })
}

/// Threshold-achievable operating point on the empirical Risk–Coverage curve.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskCoveragePoint {
    pub committed_count: usize,
    pub coverage: f64,
    pub selective_risk: f64,
    pub threshold_score: f64,
}

/// Tie-exact selective-prediction report (`AURC`, finite-$N$ exact `oracle_aurc`, `E-AURC`, and policy operating point).
#[derive(Clone, Debug, PartialEq)]
pub struct SelectivePredictionReport {
    pub item_count: usize,
    pub committed_count: usize,
    pub coverage: f64,
    /// `None` when `committed_count == 0` (`coverage == 0.0`), preventing zero-coverage risk spoofing.
    pub selective_risk: Option<f64>,
    pub aurc: f64,
    pub oracle_aurc: f64,
    pub e_aurc: f64,
    pub curve: Vec<RiskCoveragePoint>,
}

/// Evaluates tie-exact permutation-invariant `AURC` (Jaeger et al. 2023), exact finite-$N$ oracle
/// `AURC*`, `E-AURC`, and policy `coverage` / `selective_risk` over `(selective_score, loss, committed)` tuples.
///
/// # Errors
/// Fails closed if `items` is empty or any score/loss lies outside `[0.0, 1.0]`.
pub fn evaluate_selective_prediction(
    items: &[(f64, f64, bool)],
) -> Result<SelectivePredictionReport, EvalMetricsError> {
    if items.is_empty() {
        return Err(EvalMetricsError::EmptyDataset);
    }
    let n = items.len();
    let n_f64 = n as f64;

    let mut validated: Vec<(f64, f64, bool)> = Vec::with_capacity(n);
    for (idx, &(raw_s, raw_l, committed)) in items.iter().enumerate() {
        let s = normalize_unit_score(raw_s, idx)?;
        let l = normalize_unit_loss(raw_l, idx)?;
        validated.push((s, l, committed));
    }

    // Policy operating point (`committed == true`):
    let mut committed_losses: Vec<f64> = validated
        .iter()
        .filter(|&&(_, _, c)| c)
        .map(|&(_, l, _)| l)
        .collect();
    committed_losses.sort_by(f64::total_cmp);
    let committed_count = committed_losses.len();
    let coverage = committed_count as f64 / n_f64;
    let selective_risk = if committed_count == 0 {
        None
    } else {
        Some((neumaier_sum(committed_losses) / committed_count as f64).clamp(0.0, 1.0))
    };

    // Group by distinct score levels in strictly descending order (merging bit-identical scores):
    let mut sorted_by_score: Vec<(f64, f64)> = validated.iter().map(|&(s, l, _)| (s, l)).collect();
    sorted_by_score.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.total_cmp(&b.1)));

    let mut curve = Vec::new();
    let mut prefix_risks = Vec::with_capacity(n);
    let mut prev_count: usize = 0;
    let mut prev_loss_sum = 0.0_f64;
    let mut prev_loss_comp = 0.0_f64;

    let mut idx = 0;
    while idx < n {
        let level_score = sorted_by_score[idx].0;
        let level_bits = level_score.to_bits();
        let start = idx;
        while idx < n && sorted_by_score[idx].0.to_bits() == level_bits {
            idx += 1;
        }
        let group_len = idx - start;
        let group_loss = neumaier_sum(sorted_by_score[start..idx].iter().map(|x| x.1));
        let group_mean_loss = group_loss / group_len as f64;
        let base_cum_loss = prev_loss_sum + prev_loss_comp;

        for t in 1..=group_len {
            let m = prev_count + t;
            let expected_cum_loss = base_cum_loss + (t as f64) * group_mean_loss;
            prefix_risks.push(expected_cum_loss / m as f64);
        }

        prev_count += group_len;
        let next_sum = prev_loss_sum + group_loss;
        if prev_loss_sum.abs() >= group_loss.abs() {
            prev_loss_comp += (prev_loss_sum - next_sum) + group_loss;
        } else {
            prev_loss_comp += (group_loss - next_sum) + prev_loss_sum;
        }
        prev_loss_sum = next_sum;
        let compensated_cum = prev_loss_sum + prev_loss_comp;
        curve.push(RiskCoveragePoint {
            committed_count: prev_count,
            coverage: prev_count as f64 / n_f64,
            selective_risk: (compensated_cum / prev_count as f64).clamp(0.0, 1.0),
            threshold_score: level_score,
        });
    }

    let aurc = (neumaier_sum(prefix_risks) / n_f64).clamp(0.0, 1.0);

    // Exact finite-N oracle AURC*: sort true losses ascending l_(1) <= ... <= l_(N):
    let mut asc_losses: Vec<f64> = validated.iter().map(|&(_, l, _)| l).collect();
    asc_losses.sort_by(f64::total_cmp);
    let mut oracle_prefix_risks = Vec::with_capacity(n);
    let mut cum_oracle = 0.0_f64;
    let mut comp_oracle = 0.0_f64;
    for (k, &loss) in asc_losses.iter().enumerate() {
        let t = cum_oracle + loss;
        if cum_oracle.abs() >= loss.abs() {
            comp_oracle += (cum_oracle - t) + loss;
        } else {
            comp_oracle += (loss - t) + cum_oracle;
        }
        cum_oracle = t;
        oracle_prefix_risks.push((cum_oracle + comp_oracle) / (k + 1) as f64);
    }
    let oracle_aurc = (neumaier_sum(oracle_prefix_risks) / n_f64).clamp(0.0, 1.0);
    let e_aurc = (aurc - oracle_aurc).max(0.0).clamp(0.0, 1.0);

    Ok(SelectivePredictionReport {
        item_count: n,
        committed_count,
        coverage,
        selective_risk,
        aurc,
        oracle_aurc,
        e_aurc,
        curve,
    })
}

/// Exact two-sided 95% Wilson score interval for a binomial proportion $k / n$ ($n \ge 1$).
#[must_use]
pub fn wilson_ci95(numerator: usize, denominator: usize) -> Option<(f64, f64)> {
    if denominator == 0 || numerator > denominator {
        return None;
    }
    let n = denominator as f64;
    let p = numerator as f64 / n;
    let z = WILSON_Z_95;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let rad = ((p * (1.0 - p)) / n + z2 / (4.0 * n * n)).max(0.0).sqrt();
    let half = (z * rad) / denom;
    Some((
        (center - half).clamp(0.0, 1.0),
        (center + half).clamp(0.0, 1.0),
    ))
}

/// Deterministic cluster-aware percentile bootstrap 95% CI over `(cluster_id, indicator_0_or_1)`.
#[must_use]
pub fn cluster_bootstrap_rate_ci95(
    domain: &str,
    metric: &str,
    observations: &[(&str, bool)],
    resamples: usize,
) -> Option<(f64, f64)> {
    if observations.is_empty() || resamples == 0 {
        return None;
    }
    // Group observations by sorted cluster_id so multi-item clusters resample together:
    let mut by_cluster: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for &(cluster, hit) in observations {
        let entry = by_cluster.entry(cluster).or_insert((0, 0));
        if hit {
            entry.0 += 1;
        }
        entry.1 += 1;
    }
    let clusters: Vec<(usize, usize)> = by_cluster.into_values().collect();
    let k = clusters.len();
    let mut rng = SplitMix64::from_domain(domain, metric);
    let mut samples = Vec::with_capacity(resamples);

    for _ in 0..resamples {
        let mut num = 0_usize;
        let mut den = 0_usize;
        for _ in 0..k {
            let pick = clusters[rng.next_bounded(k)];
            num += pick.0;
            den += pick.1;
        }
        samples.push(if den > 0 {
            num as f64 / den as f64
        } else {
            0.0
        });
    }
    samples.sort_by(f64::total_cmp);
    let lo_idx = ((resamples as f64) * 0.025).floor() as usize;
    let hi_idx = (((resamples as f64) * 0.975).ceil() as usize)
        .saturating_sub(1)
        .min(resamples - 1);
    Some((samples[lo_idx], samples[hi_idx]))
}

/// Audited binomial/cluster rate report with explicit denominator, Wilson 95% CI, and bootstrap 95% CI.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundedRateReport {
    pub numerator: usize,
    pub denominator: usize,
    pub point_estimate: Option<f64>,
    pub wilson_ci95: Option<(f64, f64)>,
    pub bootstrap_ci95: Option<(f64, f64)>,
}

fn build_rate_report(
    domain: &str,
    metric: &str,
    observations: &[(&str, bool)],
    resamples: usize,
) -> BoundedRateReport {
    let denominator = observations.len();
    let numerator = observations.iter().filter(|&&(_, hit)| hit).count();
    if denominator == 0 {
        return BoundedRateReport {
            numerator: 0,
            denominator: 0,
            point_estimate: None,
            wilson_ci95: None,
            bootstrap_ci95: None,
        };
    }
    BoundedRateReport {
        numerator,
        denominator,
        point_estimate: Some(numerator as f64 / denominator as f64),
        wilson_ci95: wilson_ci95(numerator, denominator),
        bootstrap_ci95: cluster_bootstrap_rate_ci95(domain, metric, observations, resamples),
    }
}

/// One evaluated case for `P00_DECISION_ASSURANCE_CONTRACT` selective-assurance measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct P00AssuranceCase {
    pub case_id: String,
    pub study_cluster_id: String,
    pub outcome: TerminalOutcome,
    pub committed_manifest: bool,
    pub has_material_claim: bool,
    pub safe_and_supported: bool,
    pub requires_non_commit: bool,
    pub adjudicated_answerable: bool,
    pub requires_escalation: bool,
    pub selective_score: f64,
}

/// Complete `WP-11` / `TA-13` evaluation bundle combining proper scoring, tie-exact `AURC`/`E-AURC`,
/// and all five `P00_DECISION_ASSURANCE_CONTRACT` domain rates.
#[derive(Clone, Debug, PartialEq)]
pub struct P00AssuranceEvaluationReport {
    pub calibration: CalibrationReport,
    pub selective: SelectivePredictionReport,
    pub unsafe_commit_rate_on_non_commit_cases: BoundedRateReport,
    pub overall_unsafe_commit_rate: BoundedRateReport,
    pub useful_coverage: BoundedRateReport,
    pub over_abstention_rate: BoundedRateReport,
    pub false_escalation_rate: BoundedRateReport,
}

/// Evaluates a slice of [`P00AssuranceCase`]s strictly per `P00_DECISION_ASSURANCE_CONTRACT.md`
/// lines 81–94 and `ADR-0001`.
///
/// # Errors
/// Fails closed if `cases` is empty, `bin_count == 0`, any `selective_score` is invalid, or any
/// commit outcome lacks `committed_manifest && has_material_claim`.
pub fn evaluate_p00_assurance_suite(
    domain: &str,
    cases: &[P00AssuranceCase],
    bin_count: usize,
    bootstrap_resamples: usize,
) -> Result<P00AssuranceEvaluationReport, EvalMetricsError> {
    if cases.is_empty() {
        return Err(EvalMetricsError::EmptyDataset);
    }

    // Sort by case_id first so every output (including bootstrap order) is 100% permutation-invariant:
    let mut ordered: Vec<(usize, &P00AssuranceCase)> = cases.iter().enumerate().collect();
    let mut seen_case_ids = std::collections::BTreeSet::new();
    for &(orig_idx, c) in &ordered {
        if c.case_id.trim().is_empty()
            || c.study_cluster_id.trim().is_empty()
            || !seen_case_ids.insert(c.case_id.as_str())
        {
            return Err(EvalMetricsError::InvalidCaseIdentity { index: orig_idx });
        }
        let _ = normalize_unit_score(c.selective_score, orig_idx)?;
        if c.outcome.may_commit() && (!c.committed_manifest || !c.has_material_claim) {
            return Err(EvalMetricsError::UnbackedCommit { index: orig_idx });
        }
    }
    ordered.sort_by(|a, b| {
        a.1.case_id
            .cmp(&b.1.case_id)
            .then_with(|| a.1.study_cluster_id.cmp(&b.1.study_cluster_id))
    });

    let cal_inputs: Vec<(f64, bool)> = ordered
        .iter()
        .map(|(_, c)| {
            (
                c.selective_score,
                c.safe_and_supported && !c.requires_non_commit,
            )
        })
        .collect();
    let calibration = evaluate_calibration(&cal_inputs, bin_count)?;

    let sel_inputs: Vec<(f64, f64, bool)> = ordered
        .iter()
        .map(|(_, c)| {
            let committed = c.outcome.may_commit();
            let loss = if c.safe_and_supported && !c.requires_non_commit {
                0.0
            } else {
                1.0
            };
            (c.selective_score, loss, committed)
        })
        .collect();
    let selective = evaluate_selective_prediction(&sel_inputs)?;

    let non_commit_obs: Vec<(&str, bool)> = ordered
        .iter()
        .filter(|(_, c)| c.requires_non_commit)
        .map(|(_, c)| (c.study_cluster_id.as_str(), c.outcome.may_commit()))
        .collect();
    let overall_unsafe_obs: Vec<(&str, bool)> = ordered
        .iter()
        .map(|(_, c)| {
            let unsafe_commit =
                c.outcome.may_commit() && (!c.safe_and_supported || c.requires_non_commit);
            (c.study_cluster_id.as_str(), unsafe_commit)
        })
        .collect();
    let useful_cov_obs: Vec<(&str, bool)> = ordered
        .iter()
        .map(|(_, c)| {
            let useful = c.outcome.may_commit() && c.safe_and_supported && !c.requires_non_commit;
            (c.study_cluster_id.as_str(), useful)
        })
        .collect();
    let over_abstain_obs: Vec<(&str, bool)> = ordered
        .iter()
        .filter(|(_, c)| c.adjudicated_answerable && !c.requires_non_commit)
        .map(|(_, c)| (c.study_cluster_id.as_str(), !c.outcome.may_commit()))
        .collect();
    let false_escalation_obs: Vec<(&str, bool)> = ordered
        .iter()
        .filter(|(_, c)| !c.requires_escalation)
        .map(|(_, c)| {
            let escalated = matches!(
                c.outcome,
                TerminalOutcome::Escalate | TerminalOutcome::EmergencyNotice
            );
            (c.study_cluster_id.as_str(), escalated)
        })
        .collect();

    Ok(P00AssuranceEvaluationReport {
        calibration,
        selective,
        unsafe_commit_rate_on_non_commit_cases: build_rate_report(
            domain,
            "unsafe_commit_on_non_commit",
            &non_commit_obs,
            bootstrap_resamples,
        ),
        overall_unsafe_commit_rate: build_rate_report(
            domain,
            "overall_unsafe_commit",
            &overall_unsafe_obs,
            bootstrap_resamples,
        ),
        useful_coverage: build_rate_report(
            domain,
            "useful_coverage",
            &useful_cov_obs,
            bootstrap_resamples,
        ),
        over_abstention_rate: build_rate_report(
            domain,
            "over_abstention",
            &over_abstain_obs,
            bootstrap_resamples,
        ),
        false_escalation_rate: build_rate_report(
            domain,
            "false_escalation",
            &false_escalation_obs,
            bootstrap_resamples,
        ),
    })
}

//! Active-learning query ordering strategies (`ADM-0021` / `T18`, `TA-16`).
//!
//! Adapted in safe Rust from `asreview/asreview` (`asreview/models/queriers.py`, Apache-2.0).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStrategy {
    /// Highest relevance score first (`Max`).
    Max,
    /// Closest to decision boundary `0.5` first (`Uncertainty`).
    Uncertainty,
    /// Corpus order `0..n` (`TopDown`).
    TopDown,
    /// Deterministic SplitMix64 pseudo-random shuffle (`Random`).
    Random { seed: u64 },
    /// Deterministic `95% Max / 5% Uncertainty` interleaving (`HybridMaxUncertainty`).
    HybridMaxUncertainty { max_fraction: f64, seed: u64 },
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) * (1.0 / ((1_u64 << 53) as f64))
    }
    fn next_bounded(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        let b = bound as u64;
        let threshold = b.wrapping_neg() % b;
        loop {
            let r = self.next_u64();
            if r >= threshold {
                return (r % b) as usize;
            }
        }
    }
}

fn rank_max(scores: &[f64]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..scores.len()).collect();
    indices.sort_by(|&a, &b| scores[b].total_cmp(&scores[a]).then_with(|| a.cmp(&b)));
    indices
}

fn rank_uncertainty(scores: &[f64]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..scores.len()).collect();
    indices.sort_by(|&a, &b| {
        let da = (scores[a] - 0.5).abs();
        let db = (scores[b] - 0.5).abs();
        da.total_cmp(&db).then_with(|| a.cmp(&b))
    });
    indices
}

fn shuffle_indices(n: usize, seed: u64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    let mut rng = SplitMix64(seed);
    for i in (1..n).rev() {
        let j = rng.next_bounded(i + 1);
        idx.swap(i, j);
    }
    idx
}

/// Orders candidate indices `0..scores.len()` deterministically without dropping any candidate.
#[must_use]
pub fn query_order(strategy: QueryStrategy, scores: &[f64]) -> Vec<usize> {
    let n = scores.len();
    match strategy {
        QueryStrategy::Max => rank_max(scores),
        QueryStrategy::Uncertainty => rank_uncertainty(scores),
        QueryStrategy::TopDown => (0..n).collect(),
        QueryStrategy::Random { seed } => shuffle_indices(n, seed),
        QueryStrategy::HybridMaxUncertainty { max_fraction, seed } => {
            let p = if max_fraction.is_finite() {
                max_fraction.clamp(0.0, 1.0)
            } else {
                0.95
            };
            let max_q = rank_max(scores);
            let unc_q = rank_uncertainty(scores);
            let mut rng = SplitMix64(seed);
            let mut seen = vec![false; n];
            let mut out = Vec::with_capacity(n);
            let (mut i, mut j) = (0_usize, 0_usize);
            while out.len() < n && (i < max_q.len() || j < unc_q.len()) {
                let choose_max = if i >= max_q.len() {
                    false
                } else if j >= unc_q.len() {
                    true
                } else {
                    rng.next_f64() < p
                };
                let cand = if choose_max {
                    let c = max_q[i];
                    i += 1;
                    c
                } else {
                    let c = unc_q[j];
                    j += 1;
                    c
                };
                if !seen[cand] {
                    seen[cand] = true;
                    out.push(cand);
                }
            }
            for (fallback, &was_seen) in seen.iter().enumerate() {
                if !was_seen {
                    out.push(fallback);
                }
            }
            out
        }
    }
}

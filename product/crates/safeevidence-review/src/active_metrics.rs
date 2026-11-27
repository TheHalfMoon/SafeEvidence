//! Active-learning screening performance metrics (`ADM-0021` / `T18`, `TA-16`).
//!
//! Adapted in safe Rust from `asreview/asreview` (`asreview/metrics.py`, Apache-2.0, `ADR-0004`).

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ActiveMetricsError {
    #[error("labels must contain at least one relevant (true) and one irrelevant (false) record")]
    RequiresTwoDistinctClasses,
    #[error("target recall must lie in (0.0, 1.0]")]
    InvalidRecallTarget,
}

/// Computes ASReview ranking loss over binary screening order `labels` (`0.0` = ideal ordering).
pub fn loss(labels: &[bool]) -> Result<f64, ActiveMetricsError> {
    let nx = labels.len();
    let ny = labels.iter().filter(|&&b| b).count();
    if ny == 0 || ny == nx {
        return Err(ActiveMetricsError::RequiresTwoDistinctClasses);
    }
    let mut running = 0_usize;
    let mut cumsum_total = 0_usize;
    for &b in labels {
        if b {
            running += 1;
        }
        cumsum_total += running;
    }
    let ny_f = ny as f64;
    let nx_f = nx as f64;
    let num = ny_f * (nx_f - (ny_f - 1.0) * 0.5) - (cumsum_total as f64);
    let den = ny_f * (nx_f - ny_f);
    Ok(num / den)
}

/// Computes Normalized Discounted Cumulative Gain (`nDCG`, Wang et al. 2013) over binary `labels`.
pub fn ndcg(labels: &[bool]) -> Result<f64, ActiveMetricsError> {
    let nx = labels.len();
    let ny = labels.iter().filter(|&&b| b).count();
    if ny == 0 || ny == nx {
        return Err(ActiveMetricsError::RequiresTwoDistinctClasses);
    }
    let mut dcg = 0.0_f64;
    for (idx, &b) in labels.iter().enumerate() {
        if b {
            dcg += 1.0 / ((idx + 2) as f64).log2();
        }
    }
    let mut idcg = 0.0_f64;
    for idx in 0..ny {
        idcg += 1.0 / ((idx + 2) as f64).log2();
    }
    Ok(dcg / idcg)
}

/// Work Saved over Sampling at `target_recall` (e.g. `0.95` for `WSS@95`, Cohen et al. 2006):
/// $\mathrm{WSS}@R = \frac{T_R}{N} \text{ saved} \implies R - \frac{k_R}{N}$, where $k_R$ is the
/// number of screened records needed to find $\lceil R \cdot N_{\text{rel}} \rceil$ relevant records.
pub fn wss_at_recall(labels: &[bool], target_recall: f64) -> Result<f64, ActiveMetricsError> {
    if !target_recall.is_finite() || target_recall <= 0.0 || target_recall > 1.0 {
        return Err(ActiveMetricsError::InvalidRecallTarget);
    }
    let nx = labels.len();
    let ny = labels.iter().filter(|&&b| b).count();
    if ny == 0 || ny == nx {
        return Err(ActiveMetricsError::RequiresTwoDistinctClasses);
    }
    let needed = ((target_recall * (ny as f64)).ceil() as usize).clamp(1, ny);
    let mut found = 0_usize;
    let mut screened_k = nx;
    for (idx, &b) in labels.iter().enumerate() {
        if b {
            found += 1;
            if found >= needed {
                screened_k = idx + 1;
                break;
            }
        }
    }
    let actual_recall = (needed as f64) / (ny as f64);
    Ok(actual_recall - (screened_k as f64) / (nx as f64))
}

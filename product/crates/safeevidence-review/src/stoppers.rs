//! Explicit researcher-configured stopping criteria (`ADM-0021` / `T18`, `TA-16`).
//!
//! Adapted in safe Rust from `asreview/asreview` (`asreview/models/stoppers.py`, Apache-2.0).
//! Stopping criteria advise the human reviewer when a pre-registered threshold is met; unscreened
//! records remain `Pending` and are NEVER silently marked `Excluded` (`TA-16`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopCriterion {
    /// Stop once `n` total records have been human-labeled.
    NLabeled { n: usize },
    /// Stop once at least `min_relevant` relevant AND `min_irrelevant` irrelevant records exist.
    MinClassCounts {
        min_relevant: usize,
        min_irrelevant: usize,
    },
    /// Stop once `labeled.len() / total_corpus >= quantile`.
    QuantileLabeled { quantile: f64 },
    /// Stop once the last `n` human decisions in sequence were all irrelevant (`false`).
    NConsecutiveIrrelevant { n: usize },
    /// Equivalent to `MinClassCounts { min_relevant: 1, min_irrelevant: 1 }` (`IsFittable`).
    IsFittable,
}

/// Evaluates `criterion` against chronological human binary screening labels (`true` = Include)
/// and `total_corpus` size.
#[must_use]
pub fn should_stop(
    criterion: StopCriterion,
    labeled_history: &[bool],
    total_corpus: usize,
) -> bool {
    if total_corpus == 0 || labeled_history.len() >= total_corpus {
        return true;
    }
    match criterion {
        StopCriterion::NLabeled { n } => labeled_history.len() >= n,
        StopCriterion::MinClassCounts {
            min_relevant,
            min_irrelevant,
        } => {
            let pos = labeled_history.iter().filter(|&&b| b).count();
            let neg = labeled_history.len() - pos;
            pos >= min_relevant && neg >= min_irrelevant
        }
        StopCriterion::QuantileLabeled { quantile } => {
            let q = quantile.clamp(0.0, 1.0);
            (labeled_history.len() as f64) / (total_corpus as f64) >= q
        }
        StopCriterion::NConsecutiveIrrelevant { n } => {
            n > 0
                && labeled_history.len() > n
                && labeled_history[labeled_history.len() - n..]
                    .iter()
                    .all(|&b| !b)
        }
        StopCriterion::IsFittable => {
            let pos = labeled_history.iter().filter(|&&b| b).count();
            let neg = labeled_history.len() - pos;
            pos >= 1 && neg >= 1
        }
    }
}

//! Pure-Rust bilingual (`EN`/`AR`) TF-IDF + Multinomial Naive Bayes active-learning relevance
//! scorer (`ADM-0021` / `T18`, `TA-16`).
//!
//! Adapted in safe Rust from `asreview/asreview` (`asreview/models/classifiers.py`, Apache-2.0)
//! with zero scikit-learn/Python runtime dependencies.

use std::collections::BTreeMap;

use safeevidence_contracts::bilingual::NormalizedText;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClassifierError {
    #[error("training set and label slice lengths differ ({0} vs {1})")]
    LengthMismatch(usize, usize),
    #[error("fitting requires at least one positive and one negative labeled record")]
    RequiresBothClasses,
    #[error("Laplace smoothing alpha must be finite and strictly positive")]
    InvalidAlpha,
}

fn tokenize_bilingual(text: &str) -> Vec<String> {
    let norm = NormalizedText::build(text)
        .map(|n| n.as_str().to_owned())
        .unwrap_or_else(|_| text.to_lowercase());
    norm.split(|c: char| !c.is_alphanumeric())
        .filter(|tok| tok.chars().count() >= 2)
        .map(str::to_owned)
        .collect()
}

/// Multinomial Naive Bayes over L2-normalized sublinear TF-IDF unigrams + bigrams (`alpha = 1.0`
/// Laplace smoothing by default).
#[derive(Debug, Clone)]
pub struct MultinomialNbScreeningClassifier {
    alpha: f64,
    vocab: BTreeMap<String, usize>,
    idf: Vec<f64>,
    log_prior_pos: f64,
    log_prior_neg: f64,
    log_prob_pos: Vec<f64>,
    log_prob_neg: Vec<f64>,
}

impl MultinomialNbScreeningClassifier {
    pub fn fit(texts: &[String], labels: &[bool], alpha: f64) -> Result<Self, ClassifierError> {
        if texts.len() != labels.len() {
            return Err(ClassifierError::LengthMismatch(texts.len(), labels.len()));
        }
        if !alpha.is_finite() || alpha <= 0.0 {
            return Err(ClassifierError::InvalidAlpha);
        }
        let pos_count = labels.iter().filter(|&&b| b).count();
        let neg_count = labels.len() - pos_count;
        if pos_count == 0 || neg_count == 0 {
            return Err(ClassifierError::RequiresBothClasses);
        }

        let tokenized: Vec<Vec<String>> = texts
            .iter()
            .map(|t| {
                let uni = tokenize_bilingual(t);
                let mut features = uni.clone();
                for pair in uni.windows(2) {
                    features.push(format!("{}_{}", pair[0], pair[1]));
                }
                features
            })
            .collect();

        let mut df_map: BTreeMap<String, usize> = BTreeMap::new();
        for toks in &tokenized {
            let mut unique = toks.clone();
            unique.sort();
            unique.dedup();
            for tok in unique {
                *df_map.entry(tok).or_insert(0) += 1;
            }
        }

        let mut vocab = BTreeMap::new();
        let mut idf = Vec::with_capacity(df_map.len());
        let n_docs = texts.len() as f64;
        for (idx, (term, df)) in df_map.into_iter().enumerate() {
            vocab.insert(term, idx);
            // Smooth IDF: ln((1 + N) / (1 + df)) + 1
            idf.push(((1.0 + n_docs) / (1.0 + df as f64)).ln() + 1.0);
        }

        let v_len = idf.len().max(1);
        let mut pos_weights = vec![0.0_f64; v_len];
        let mut neg_weights = vec![0.0_f64; v_len];

        for (toks, &is_pos) in tokenized.iter().zip(labels) {
            let vec_tfidf = Self::vectorize_tokens(toks, &vocab, &idf);
            let target = if is_pos {
                &mut pos_weights
            } else {
                &mut neg_weights
            };
            for (idx, w) in vec_tfidf {
                target[idx] += w;
            }
        }

        let pos_total: f64 = pos_weights.iter().sum::<f64>() + alpha * (v_len as f64);
        let neg_total: f64 = neg_weights.iter().sum::<f64>() + alpha * (v_len as f64);
        let log_prob_pos: Vec<f64> = pos_weights
            .iter()
            .map(|&w| ((w + alpha) / pos_total).ln())
            .collect();
        let log_prob_neg: Vec<f64> = neg_weights
            .iter()
            .map(|&w| ((w + alpha) / neg_total).ln())
            .collect();

        let total_docs = labels.len() as f64;
        Ok(Self {
            alpha,
            vocab,
            idf,
            log_prior_pos: ((pos_count as f64) / total_docs).ln(),
            log_prior_neg: ((neg_count as f64) / total_docs).ln(),
            log_prob_pos,
            log_prob_neg,
        })
    }

    #[must_use]
    pub const fn alpha(&self) -> f64 {
        self.alpha
    }

    fn vectorize_tokens(
        toks: &[String],
        vocab: &BTreeMap<String, usize>,
        idf: &[f64],
    ) -> Vec<(usize, f64)> {
        let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
        for tok in toks {
            if let Some(&idx) = vocab.get(tok) {
                *counts.entry(idx).or_insert(0) += 1;
            }
        }
        let mut raw: Vec<(usize, f64)> = counts
            .into_iter()
            .map(|(idx, tf)| (idx, (1.0 + (tf as f64).ln()) * idf[idx]))
            .collect();
        let norm_sq: f64 = raw.iter().map(|(_, w)| w * w).sum();
        if norm_sq > 0.0 {
            let norm = norm_sq.sqrt();
            for (_, w) in &mut raw {
                *w /= norm;
            }
        }
        raw
    }

    /// Predicts relevance score in `(0.0, 1.0)` for priority ordering of unreviewed candidates.
    /// Note: strictly an internal active-learning ranking score for researcher review ordering,
    /// NEVER presented as a clinical confidence percentage (`D-13`) and NEVER used to auto-exclude.
    #[must_use]
    pub fn predict_relevance_scores(&self, texts: &[String]) -> Vec<f64> {
        texts
            .iter()
            .map(|text| {
                let uni = tokenize_bilingual(text);
                let mut features = uni.clone();
                for pair in uni.windows(2) {
                    features.push(format!("{}_{}", pair[0], pair[1]));
                }
                let vec_tfidf = Self::vectorize_tokens(&features, &self.vocab, &self.idf);
                let mut lp_pos = self.log_prior_pos;
                let mut lp_neg = self.log_prior_neg;
                for (idx, w) in vec_tfidf {
                    lp_pos += w * self.log_prob_pos[idx];
                    lp_neg += w * self.log_prob_neg[idx];
                }
                let max_lp = lp_pos.max(lp_neg);
                let exp_pos = (lp_pos - max_lp).exp();
                let exp_neg = (lp_neg - max_lp).exp();
                exp_pos / (exp_pos + exp_neg)
            })
            .collect()
    }
}

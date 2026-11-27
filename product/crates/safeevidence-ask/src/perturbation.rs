//! Deterministic multi-facet claim-to-span verification (`WP-08`, `TA-10` deterministic slice)
//! and per-source PICO applicability gate (`WP-09`, `TA-11`).
//!
//! Copy-first boundary: neural NLI reranking/scoring (`SciFact` / `MultiVerS` / ONNX cross-encoder)
//! remains fenced on `EXT-01` and `EXT-07`. This module implements the SafeEvidence-owned
//! deterministic facet verifier (`SOURCE_TRANSPLANT_MATRIX_V1` section 5) required before
//! `AnswerProofManifest` admission and the per-source PICO applicability evaluator (`WP-09`).

use std::collections::BTreeSet;

use safeevidence_contracts::assurance::ReasonCode;
use safeevidence_contracts::proof::ApplicabilityState;
use serde::{Deserialize, Serialize};

/// Specific deterministic defect flagged when verifying a candidate claim against a source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimVerificationDefect {
    EmptyOrNonAsciiControl,
    CrossSentenceSplice,
    NumericMismatch,
    NegationOrPolarityFlip,
    UnitMismatch,
    ComparatorSwap,
    EffectMeasureSwap,
    TimeframeSwap,
    PopulationOrSubgroupSwap,
    UnmatchedWording,
}

const NEGATION_AND_NULL_WORDS: &[&str] = &[
    "not",
    "no",
    "never",
    "without",
    "neither",
    "nor",
    "failed",
    "fails",
    "worsened",
    "worse",
    "unable",
    "nobody",
    "cannot",
    "didnt",
    "doesnt",
    "wasnt",
    "isnt",
    "arent",
    "werent",
    "hasnt",
    "havent",
    "dont",
    "wont",
    "couldnt",
    "shouldnt",
    "wouldnt",
    "hadnt",
    "unchanged",
    "similar",
    "comparable",
    "equivalent",
    "nonsignificant",
    "insignificant",
    "ineffective",
    "inferior",
];

const DOSE_AND_EFFECT_UNITS: &[&str] = &[
    "mg", "mcg", "ug", "g", "kg", "ml", "l", "mmol", "mol", "iu", "units", "points", "mmhg", "bpm",
];

const TIMEFRAME_UNITS: &[&str] = &[
    "hour", "hours", "day", "days", "week", "weeks", "month", "months", "year", "years",
];

const COMPARATOR_PHRASES: &[&str] = &[
    "placebo",
    "standard care",
    "usual care",
    "active control",
    "sham",
    "no treatment",
    "waitlist",
];

const EFFECT_MEASURE_PHRASES: &[&str] = &[
    "relative risk",
    "absolute risk",
    "risk difference",
    "odds ratio",
    "hazard ratio",
    "mean difference",
    "rate ratio",
    "number needed to treat",
];

const POPULATION_MARKERS: &[&str] = &[
    "adults",
    "adult",
    "children",
    "child",
    "pediatric",
    "adolescents",
    "infants",
    "neonates",
    "elderly",
    "older adults",
    "pregnant",
    "renal impairment",
    "hepatic impairment",
];

fn normalize_words(text: &str) -> (String, BTreeSet<String>) {
    let cleaned = text
        .to_ascii_lowercase()
        .replace(['\'', '`'], "")
        .replace("non-significant", "nonsignificant")
        .replace("micrograms", "mcg")
        .replace("milligrams", "mg");
    let words: BTreeSet<String> = cleaned
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    (collapsed, words)
}

fn split_sentences(source: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut start = 0;
    for (index, _) in source.match_indices(". ") {
        let next = source[index + 2..].chars().next();
        if next.is_some_and(char::is_uppercase) {
            found.push(source[start..=index].trim());
            start = index + 2;
        }
    }
    let tail = source[start..].trim();
    if !tail.is_empty() {
        found.push(tail);
    }
    found
}

/// Extracts signed/decimal numeric tokens (`-4.2`, `0.5`, `.5`, `40`) preserving order and sign.
#[must_use]
pub fn extract_numeric_facets(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut idx = 0;
    while idx < chars.len() {
        if chars[idx].is_numeric() {
            let mut start = idx;
            while idx < chars.len()
                && (chars[idx].is_numeric()
                    || (chars[idx] == '.' && chars.get(idx + 1).is_some_and(|c| c.is_numeric())))
            {
                idx += 1;
            }
            if start > 0 && chars[start - 1] == '.' {
                start -= 1;
            }
            if start > 0
                && (chars[start - 1] == '-' || chars[start - 1] == '+')
                && (start == 1 || !chars[start - 2].is_alphanumeric())
            {
                start -= 1;
            }
            tokens.push(chars[start..idx].iter().collect());
        } else {
            idx += 1;
        }
    }
    tokens
}

/// Extracts `(number, unit)` pairs when a numeric token is immediately followed by a timeframe or
/// dose unit, catching swaps like `"40 mg for 12 weeks"` -> `"12 mg for 40 weeks"`.
fn extract_number_unit_pairs(text: &str) -> Vec<(String, String)> {
    let raw_tokens: Vec<String> = text
        .to_ascii_lowercase()
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ':' | '(' | ')' | '[' | ']'))
        .map(|tok| tok.trim_end_matches('.').to_owned())
        .filter(|tok| !tok.is_empty())
        .collect();
    let mut pairs = Vec::new();
    for win in raw_tokens.windows(2) {
        let first_nums = extract_numeric_facets(&win[0]);
        if first_nums.len() == 1
            && (DOSE_AND_EFFECT_UNITS.contains(&win[1].as_str())
                || TIMEFRAME_UNITS.contains(&win[1].as_str()))
        {
            pairs.push((first_nums[0].clone(), win[1].clone()));
        }
    }
    pairs
}

fn present_phrases<'a>(collapsed: &str, phrases: &[&'a str]) -> BTreeSet<&'a str> {
    let alnum_words: Vec<&str> = collapsed
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let padded = format!(" {} ", alnum_words.join(" "));
    phrases
        .iter()
        .copied()
        .filter(|phrase| {
            let needle = format!(" {phrase} ");
            padded.contains(&needle)
        })
        .collect()
}

/// Verifies a candidate claim against `source`. Returns `Ok(())` only if `claim` is an exact whole
/// sentence of `source` with no control characters; otherwise diagnoses the exact perturbation
/// defect (`TA-10` deterministic gating set).
pub fn verify_claim_against_source(
    claim: &str,
    source: &str,
) -> Result<(), ClaimVerificationDefect> {
    let trimmed = claim.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(|c| {
            c.is_control() || safeevidence_contracts::bilingual::is_forbidden_bidi_control(c)
        })
    {
        return Err(ClaimVerificationDefect::EmptyOrNonAsciiControl);
    }

    let source_sentences = split_sentences(source);
    if source_sentences.contains(&trimmed) && split_sentences(trimmed).len() == 1 {
        return Ok(());
    }

    // Multiple sentences spliced into one claim or spanning across a sentence boundary:
    if split_sentences(trimmed).len() > 1 {
        return Err(ClaimVerificationDefect::CrossSentenceSplice);
    }

    let claim_nums = extract_numeric_facets(trimmed);
    let (claim_collapsed, claim_words) = normalize_words(trimmed);
    let claim_pairs = extract_number_unit_pairs(trimmed);

    let any_sentence = |pred: &dyn Fn(&str) -> bool| source_sentences.iter().any(|s| pred(s));

    if !any_sentence(&|s| extract_numeric_facets(s) == claim_nums) {
        return Err(ClaimVerificationDefect::NumericMismatch);
    }

    let agrees_words = |vocab: &[&str], sentence: &str| {
        let (_, s_words) = normalize_words(sentence);
        vocab
            .iter()
            .all(|word| claim_words.contains(*word) == s_words.contains(*word))
    };

    if !any_sentence(&|s| {
        extract_numeric_facets(s) == claim_nums && agrees_words(NEGATION_AND_NULL_WORDS, s)
    }) {
        return Err(ClaimVerificationDefect::NegationOrPolarityFlip);
    }

    if !any_sentence(&|s| {
        extract_numeric_facets(s) == claim_nums
            && agrees_words(TIMEFRAME_UNITS, s)
            && extract_number_unit_pairs(s)
                .iter()
                .filter(|(_, u)| TIMEFRAME_UNITS.contains(&u.as_str()))
                .eq(claim_pairs
                    .iter()
                    .filter(|(_, u)| TIMEFRAME_UNITS.contains(&u.as_str())))
    }) {
        return Err(ClaimVerificationDefect::TimeframeSwap);
    }

    if !any_sentence(&|s| {
        extract_numeric_facets(s) == claim_nums
            && agrees_words(DOSE_AND_EFFECT_UNITS, s)
            && extract_number_unit_pairs(s) == claim_pairs
    }) {
        return Err(ClaimVerificationDefect::UnitMismatch);
    }

    let claim_comparators = present_phrases(&claim_collapsed, COMPARATOR_PHRASES);
    if !any_sentence(&|s| {
        let (s_col, _) = normalize_words(s);
        extract_numeric_facets(s) == claim_nums
            && present_phrases(&s_col, COMPARATOR_PHRASES) == claim_comparators
    }) {
        return Err(ClaimVerificationDefect::ComparatorSwap);
    }

    let claim_measures = present_phrases(&claim_collapsed, EFFECT_MEASURE_PHRASES);
    if !any_sentence(&|s| {
        let (s_col, _) = normalize_words(s);
        extract_numeric_facets(s) == claim_nums
            && present_phrases(&s_col, EFFECT_MEASURE_PHRASES) == claim_measures
    }) {
        return Err(ClaimVerificationDefect::EffectMeasureSwap);
    }

    let claim_populations = present_phrases(&claim_collapsed, POPULATION_MARKERS);
    if !any_sentence(&|s| {
        let (s_col, _) = normalize_words(s);
        extract_numeric_facets(s) == claim_nums
            && present_phrases(&s_col, POPULATION_MARKERS) == claim_populations
    }) {
        return Err(ClaimVerificationDefect::PopulationOrSubgroupSwap);
    }

    if source_sentences.len() >= 2 {
        let sentences_contributing = source_sentences
            .iter()
            .filter(|s| {
                let (_, s_words) = normalize_words(s);
                claim_words.difference(&s_words).count() < claim_words.len().saturating_sub(2)
            })
            .count();
        if sentences_contributing >= 2 {
            return Err(ClaimVerificationDefect::CrossSentenceSplice);
        }
    }

    Err(ClaimVerificationDefect::UnmatchedWording)
}

/// Structured PICO question frame for per-source applicability checking (`WP-09`, `TA-11`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PicoQuerySpec {
    pub population: String,
    pub condition: String,
    pub intervention: String,
    pub comparator: Option<String>,
    pub outcome: Option<String>,
    pub minimum_weeks: Option<u32>,
}

/// Structured PICO metadata of one candidate study/report (`WP-09`, `TA-11`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PicoSourceSpec {
    pub doc_id: String,
    pub population: String,
    pub condition: String,
    pub intervention: String,
    pub comparator: String,
    pub outcome: String,
    pub follow_up_weeks: u32,
    pub surrogate_outcome: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PicoApplicabilityVerdict {
    pub doc_id: String,
    pub state: ApplicabilityState,
    pub exclusion_code: Option<ReasonCode>,
    pub reasons: Vec<String>,
}

fn canon(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Evaluates per-source PICO applicability against `query` (`WP-09`, `TA-11`):
/// - Mismatched condition, intervention, population, or explicitly requested outcome is excluded
///   (`NotApplicable`, `ReasonCode::ApplicabilityUnresolved`) with exact axis reasons.
/// - Mismatched comparator (when `query.comparator` is set) or surrogate/shorter follow-up
///   downgrades to `ApplicableWithLimits` with explicit indirectness reasons so `Ask` emits
///   `ANSWER_WITH_CAUTION` rather than an unqualified `ANSWER`.
#[must_use]
pub fn evaluate_pico_applicability(
    query: &PicoQuerySpec,
    source: &PicoSourceSpec,
) -> PicoApplicabilityVerdict {
    let mut hard_mismatches = Vec::new();
    if canon(&source.condition) != canon(&query.condition) {
        hard_mismatches.push(format!(
            "condition '{}' does not match '{}'",
            source.condition, query.condition
        ));
    }
    if canon(&source.intervention) != canon(&query.intervention) {
        hard_mismatches.push(format!(
            "intervention '{}' does not match '{}'",
            source.intervention, query.intervention
        ));
    }
    if canon(&source.population) != canon(&query.population) {
        hard_mismatches.push(format!(
            "population '{}' does not match '{}'",
            source.population, query.population
        ));
    }
    if let Some(wanted_outcome) = &query.outcome
        && canon(&source.outcome) != canon(wanted_outcome)
    {
        hard_mismatches.push(format!(
            "outcome '{}' does not match '{}'",
            source.outcome, wanted_outcome
        ));
    }

    if !hard_mismatches.is_empty() {
        return PicoApplicabilityVerdict {
            doc_id: source.doc_id.clone(),
            state: ApplicabilityState::NotApplicable,
            exclusion_code: Some(ReasonCode::ApplicabilityUnresolved),
            reasons: hard_mismatches,
        };
    }

    let mut limits = Vec::new();
    if let Some(wanted_comp) = &query.comparator
        && canon(&source.comparator) != canon(wanted_comp)
    {
        limits.push(format!(
            "indirect comparator '{}' instead of '{}'",
            source.comparator, wanted_comp
        ));
    }
    if let Some(min_weeks) = query.minimum_weeks
        && source.follow_up_weeks < min_weeks
    {
        limits.push(format!(
            "short follow-up ({} weeks < {} weeks)",
            source.follow_up_weeks, min_weeks
        ));
    }
    if source.surrogate_outcome {
        limits.push(format!("surrogate endpoint '{}'", source.outcome));
    }

    if limits.is_empty() {
        PicoApplicabilityVerdict {
            doc_id: source.doc_id.clone(),
            state: ApplicabilityState::Applicable,
            exclusion_code: None,
            reasons: vec!["direct PICO match".to_owned()],
        }
    } else {
        PicoApplicabilityVerdict {
            doc_id: source.doc_id.clone(),
            state: ApplicabilityState::ApplicableWithLimits,
            exclusion_code: None,
            reasons: limits,
        }
    }
}

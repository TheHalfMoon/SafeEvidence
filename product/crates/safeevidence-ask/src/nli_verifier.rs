//! Deterministic local bilingual (`EN` + vocalized `AR`) claim-entailment and cross-study
//! contradiction verifier (`WP-08`, `TA-10`, `TA-14`).
//!
//! Enforces `#![forbid(unsafe_code)]`, zero network sockets, exact raw Unicode scalar span
//! anchoring, full-source contradiction precedence, clause-level polarity binding, comparative
//! argument-order verification, and canonical decimal/unit verification across English and
//! vocalized Arabic source texts without emitting heuristic confidence percentages (`P00`).

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use safeevidence_contracts::bilingual::{NormalizedText, is_forbidden_bidi_control};
use safeevidence_contracts::proof::ContradictionState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NliLabel {
    Entails,
    Contradicts,
    Neutral,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NliVerdict {
    pub label: NliLabel,
    pub defects: Vec<String>,
    pub matched_sentence_span: Option<(u64, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyConflictPair {
    pub study_a: String,
    pub doc_a: String,
    pub study_b: String,
    pub doc_b: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictionReport {
    pub state: ContradictionState,
    pub conflicts: Vec<StudyConflictPair>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NliError {
    EmptyInput,
    ForbiddenTextControl,
}

const EN_NEGATION_OPERATORS: &[&str] = &[
    "not", "no", "never", "without", "neither", "nor", "failed", "fails", "didnt", "doesnt",
    "wasnt",
];

const AR_NEGATION_OPERATORS: &[&str] = &[
    "\u{0644}\u{0627}",
    "\u{0644}\u{0645}",
    "\u{0644}\u{0646}",
    "\u{0644}\u{064a}\u{0633}",
    "\u{062f}\u{0648}\u{0646}",
    "\u{0628}\u{062f}\u{0648}\u{0646}",
    "\u{063a}\u{064a}\u{0631}",
];

const EXPLICIT_NULL_TERMS: &[&str] = &[
    "unchanged",
    "similar",
    "comparable",
    "equivalent",
    "nonsignificant",
    "insignificant",
    "ineffective",
    "\u{0645}\u{0645}\u{0627}\u{062b}\u{0644}",
    "\u{0645}\u{062a}\u{0643}\u{0627}\u{0641}\u{0626}",
];

const INCREASE_TERMS: &[&str] = &[
    "increase",
    "increased",
    "increases",
    "higher",
    "elevated",
    "raised",
    "worsened",
    "\u{064a}\u{0632}\u{064a}\u{062f}",
    "\u{0632}\u{0627}\u{062f}",
    "\u{0632}\u{064a}\u{0627}\u{062f}\u{0647}",
    "\u{0627}\u{0631}\u{062a}\u{0641}\u{0627}\u{0639}",
    "\u{0627}\u{0639}\u{0644}\u{0649}",
];

const DECREASE_TERMS: &[&str] = &[
    "reduce",
    "reduced",
    "reduces",
    "decrease",
    "decreased",
    "decreases",
    "lower",
    "lowered",
    "improved",
    "shortened",
    "\u{064a}\u{0642}\u{0644}\u{0644}",
    "\u{0642}\u{0644}\u{0644}",
    "\u{062e}\u{0641}\u{0636}",
    "\u{064a}\u{062e}\u{0641}\u{0636}",
    "\u{0627}\u{0646}\u{062e}\u{0641}\u{0627}\u{0636}",
    "\u{062d}\u{0633}\u{0646}",
];

const CANONICAL_UNITS: &[(&str, &[&str])] = &[
    (
        "mg",
        &["mg", "\u{0645}\u{062c}\u{0645}", "\u{0645}\u{0644}\u{063a}"],
    ),
    (
        "mcg",
        &[
            "mcg",
            "ug",
            "\u{0645}\u{064a}\u{0643}\u{0631}\u{0648}\u{063a}\u{0631}\u{0627}\u{0645}",
        ],
    ),
    (
        "g",
        &["g", "\u{063a}\u{0631}\u{0627}\u{0645}", "\u{062c}\u{0645}"],
    ),
    ("ml", &["ml", "\u{0645}\u{0644}"]),
    (
        "mmol_l",
        &[
            "mmol/l",
            "mmol",
            "\u{0645}\u{0644}\u{064a}\u{0645}\u{0648}\u{0644}",
        ],
    ),
    (
        "days",
        &[
            "day",
            "days",
            "\u{064a}\u{0648}\u{0645}",
            "\u{0627}\u{064a}\u{0627}\u{0645}",
        ],
    ),
    (
        "weeks",
        &[
            "week",
            "weeks",
            "\u{0627}\u{0633}\u{0628}\u{0648}\u{0639}",
            "\u{0627}\u{0633}\u{0627}\u{0628}\u{064a}\u{0639}",
        ],
    ),
    (
        "months",
        &[
            "month",
            "months",
            "\u{0634}\u{0647}\u{0631}",
            "\u{0627}\u{0634}\u{0647}\u{0631}",
        ],
    ),
];

const COMPARATIVE_PIVOTS: &[&str] = &[
    " more than ",
    " less than ",
    " better than ",
    " worse than ",
    " compared with ",
    " compared to ",
    " versus ",
    " vs ",
    " \u{0645}\u{0642}\u{0627}\u{0628}\u{0644} ",
    " \u{0645}\u{0642}\u{0627}\u{0631}\u{0646}\u{0647} ",
    " \u{0627}\u{0643}\u{062b}\u{0631} \u{0645}\u{0646} ",
    " \u{0627}\u{0642}\u{0644} \u{0645}\u{0646} ",
    " \u{0627}\u{0641}\u{0636}\u{0644} \u{0645}\u{0646} ",
];

fn normalize_text(raw: &str) -> Result<String, NliError> {
    if raw
        .chars()
        .any(|c| is_forbidden_bidi_control(c) || (c.is_control() && c != '\n' && c != '\t'))
    {
        return Err(NliError::ForbiddenTextControl);
    }
    let nt = NormalizedText::build(raw).map_err(|_| NliError::ForbiddenTextControl)?;
    Ok(nt.as_str().split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Strips digit-grouping commas inside numbers (`1,000` -> `1000`).
fn strip_digit_commas(norm: &str) -> String {
    let chars: Vec<char> = norm.chars().collect();
    let mut out = String::with_capacity(norm.len());
    for i in 0..chars.len() {
        if chars[i] == ','
            && i > 0
            && chars[i - 1].is_ascii_digit()
            && chars.get(i + 1).is_some_and(char::is_ascii_digit)
        {
            continue;
        }
        out.push(chars[i]);
    }
    out
}

fn canonicalize_decimal(raw_num: &str) -> String {
    let (sign, rest) = match raw_num.strip_prefix('-') {
        Some(r) => ("-", r),
        None => ("", raw_num),
    };
    let (int_part, frac_part) = match rest.split_once('.') {
        Some((i, f)) => (i, f.trim_end_matches('0')),
        None => (rest, ""),
    };
    let int_clean = int_part.trim_start_matches('0');
    let int_norm = if int_clean.is_empty() { "0" } else { int_clean };
    if int_norm == "0" && frac_part.is_empty() {
        return "0".to_owned();
    }
    if frac_part.is_empty() {
        format!("{sign}{int_norm}")
    } else {
        format!("{sign}{int_norm}.{frac_part}")
    }
}

fn canonical_unit_for_token(tok: &str) -> Option<&'static str> {
    for &(canon, forms) in CANONICAL_UNITS {
        for &f in forms {
            if let Ok(nf) = normalize_text(f)
                && nf == tok
            {
                return Some(canon);
            }
        }
    }
    None
}

fn ordered_tokens(norm: &str) -> Vec<String> {
    strip_digit_commas(norm)
        .replace(['\'', '`'], "")
        .replace("non-significant", "nonsignificant")
        .split(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '-')
        .map(|w| w.trim_matches(|c: char| c == '.' || c == '/'))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

fn token_set(norm: &str) -> BTreeSet<String> {
    ordered_tokens(norm).into_iter().collect()
}

fn is_number_token(tok: &str) -> bool {
    let body = tok.strip_prefix('-').unwrap_or(tok);
    !body.is_empty()
        && body.chars().any(|c| c.is_ascii_digit())
        && body.chars().all(|c| c.is_ascii_digit() || c == '.')
        && body.matches('.').count() <= 1
}

/// Extracts `(canonical_number, optional_adjacent_canonical_unit)` pairs plus standalone units.
fn extract_quantified_bindings(
    norm: &str,
) -> (Vec<(String, Option<&'static str>)>, BTreeSet<&'static str>) {
    let toks = ordered_tokens(norm);
    let mut pairs = Vec::new();
    let mut units = BTreeSet::new();
    for (idx, tok) in toks.iter().enumerate() {
        if let Some(u) = canonical_unit_for_token(tok) {
            units.insert(u);
        }
        if is_number_token(tok) {
            let num = canonicalize_decimal(tok);
            let adj_unit = toks
                .get(idx + 1)
                .and_then(|next| canonical_unit_for_token(next));
            pairs.push((num, adj_unit));
        }
    }
    (pairs, units)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolarityProfile {
    neg_op: bool,
    explicit_null: bool,
    inc: bool,
    dec: bool,
    raw_dir: i8,
}

impl PolarityProfile {
    const fn has_mixed_direction(self) -> bool {
        self.inc && self.dec
    }

    const fn is_negated_or_null(self) -> bool {
        self.neg_op || self.explicit_null
    }
}

fn analyze_polarity(words: &BTreeSet<String>) -> PolarityProfile {
    let neg_op = EN_NEGATION_OPERATORS.iter().any(|w| words.contains(*w))
        || AR_NEGATION_OPERATORS
            .iter()
            .any(|w| normalize_text(w).ok().is_some_and(|nw| words.contains(&nw)));
    let explicit_null = EXPLICIT_NULL_TERMS
        .iter()
        .any(|w| normalize_text(w).ok().is_some_and(|nw| words.contains(&nw)));
    let inc = INCREASE_TERMS
        .iter()
        .any(|w| normalize_text(w).ok().is_some_and(|nw| words.contains(&nw)));
    let dec = DECREASE_TERMS
        .iter()
        .any(|w| normalize_text(w).ok().is_some_and(|nw| words.contains(&nw)));
    let raw_dir = match (inc, dec) {
        (true, false) => 1,
        (false, true) => -1,
        _ => 0,
    };
    PolarityProfile {
        neg_op,
        explicit_null,
        inc,
        dec,
        raw_dir,
    }
}

fn split_into_clauses(norm_sent: &str) -> Vec<String> {
    let mut work = norm_sent.replace(';', " | ");
    for marker in [
        " whereas ",
        " while ",
        " but ",
        " however ",
        " and ",
        " \u{0628}\u{064a}\u{0646}\u{0645}\u{0627} ",
        " \u{0644}\u{0643}\u{0646} ",
        " \u{0641}\u{064a} \u{062d}\u{064a}\u{0646} ",
    ] {
        work = work.replace(marker, " | ");
    }
    work.split('|')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect()
}

fn comparative_sides(norm: &str) -> Option<(BTreeSet<String>, BTreeSet<String>)> {
    for &pivot in COMPARATIVE_PIVOTS {
        if let Some((lhs, rhs)) = norm.split_once(pivot) {
            let l_set = content_words(&token_set(lhs));
            let r_set = content_words(&token_set(rhs));
            if !l_set.is_empty() && !r_set.is_empty() {
                return Some((l_set, r_set));
            }
        }
    }
    None
}

fn has_comparative_role_swap(norm_claim: &str, norm_sent: &str) -> bool {
    let Some((c_lhs, c_rhs)) = comparative_sides(norm_claim) else {
        return false;
    };
    let Some((s_lhs, s_rhs)) = comparative_sides(norm_sent) else {
        return false;
    };
    let c_only_lhs: BTreeSet<&String> = c_lhs.difference(&c_rhs).collect();
    let c_only_rhs: BTreeSet<&String> = c_rhs.difference(&c_lhs).collect();
    let s_only_lhs: BTreeSet<&String> = s_lhs.difference(&s_rhs).collect();
    let s_only_rhs: BTreeSet<&String> = s_rhs.difference(&s_lhs).collect();
    !c_only_lhs.is_disjoint(&s_only_rhs) && !c_only_rhs.is_disjoint(&s_only_lhs)
}

fn split_sentences_with_scalar_spans(source: &str) -> Vec<(u64, u64, &str)> {
    let chars: Vec<(usize, char)> = source.char_indices().collect();
    if chars.is_empty() {
        return Vec::new();
    }
    let mut sentences = Vec::new();
    let mut start_char_idx = 0_usize;

    for idx in 0..chars.len() {
        let ch = chars[idx].1;
        let is_newline = ch == '\n';
        let is_arabic_stop = ch == '\u{06D4}';
        let is_period_boundary = ch == '.'
            && (idx + 1 == chars.len()
                || (chars.get(idx + 1).is_some_and(|(_, c)| c.is_whitespace())
                    && chars.get(idx + 2).is_none_or(|(_, next)| {
                        !next.is_ascii_digit() && !next.is_ascii_lowercase()
                    })));

        if is_newline || is_arabic_stop || is_period_boundary {
            let end_char_excl = if is_newline { idx } else { idx + 1 };
            if end_char_excl > start_char_idx {
                let b_start = chars[start_char_idx].0;
                let b_end = chars.get(end_char_excl).map_or(source.len(), |(b, _)| *b);
                let raw_slice = &source[b_start..b_end];
                let trimmed = raw_slice.trim();
                if !trimmed.is_empty() {
                    let lead_ws = raw_slice.chars().take_while(|c| c.is_whitespace()).count();
                    let s_scalar = (start_char_idx + lead_ws) as u64;
                    let e_scalar = s_scalar + trimmed.chars().count() as u64;
                    let tb_start = b_start
                        + raw_slice
                            .chars()
                            .take(lead_ws)
                            .map(char::len_utf8)
                            .sum::<usize>();
                    let tb_end = tb_start + trimmed.len();
                    sentences.push((s_scalar, e_scalar, &source[tb_start..tb_end]));
                }
            }
            start_char_idx = idx + 1;
        }
    }

    if start_char_idx < chars.len() {
        let b_start = chars[start_char_idx].0;
        let raw_slice = &source[b_start..];
        let trimmed = raw_slice.trim();
        if !trimmed.is_empty() {
            let lead_ws = raw_slice.chars().take_while(|c| c.is_whitespace()).count();
            let s_scalar = (start_char_idx + lead_ws) as u64;
            let e_scalar = s_scalar + trimmed.chars().count() as u64;
            let tb_start = b_start
                + raw_slice
                    .chars()
                    .take(lead_ws)
                    .map(char::len_utf8)
                    .sum::<usize>();
            let tb_end = tb_start + trimmed.len();
            sentences.push((s_scalar, e_scalar, &source[tb_start..tb_end]));
        }
    }

    sentences
}

fn content_words(words: &BTreeSet<String>) -> BTreeSet<String> {
    const STOP: &[&str] = &[
        "the", "a", "an", "in", "with", "of", "to", "for", "and", "or", "by", "on", "at", "was",
        "were", "is", "are", "more", "less", "than", "versus", "vs", "compared",
    ];
    words
        .iter()
        .filter(|w| {
            w.chars().count() >= 2
                && !STOP.contains(&w.as_str())
                && !EN_NEGATION_OPERATORS.contains(&w.as_str())
                && !EXPLICIT_NULL_TERMS.iter().any(|nw_raw| {
                    normalize_text(nw_raw)
                        .ok()
                        .is_some_and(|nw| nw.as_str() == w.as_str())
                })
                && !AR_NEGATION_OPERATORS.iter().any(|aw| {
                    normalize_text(aw)
                        .ok()
                        .is_some_and(|nw| nw.as_str() == w.as_str())
                })
                && !INCREASE_TERMS.iter().any(|iw| {
                    normalize_text(iw)
                        .ok()
                        .is_some_and(|nw| nw.as_str() == w.as_str())
                })
                && !DECREASE_TERMS.iter().any(|dw| {
                    normalize_text(dw)
                        .ok()
                        .is_some_and(|nw| nw.as_str() == w.as_str())
                })
                && !is_number_token(w)
        })
        .cloned()
        .collect()
}

/// Verifies whether `source` entails, contradicts, or is neutral with respect to `claim` across
/// English and vocalized Arabic (`WP-08`, `TA-10`).
///
/// Scans all candidate sentences in `source` so a contradicting sentence always overrides an
/// earlier sentence (`Contradicts` > `Entails` > `Neutral`).
///
/// # Errors
/// Fails closed on empty `claim`/`source` or forbidden BiDi/control characters.
pub fn verify_bilingual_entailment(claim: &str, source: &str) -> Result<NliVerdict, NliError> {
    let norm_claim = normalize_text(claim)?;
    let _norm_source = normalize_text(source)?;
    if norm_claim.is_empty() || source.trim().is_empty() {
        return Err(NliError::EmptyInput);
    }

    let claim_words = token_set(&norm_claim);
    let claim_content = content_words(&claim_words);
    let (claim_num_pairs, claim_units) = extract_quantified_bindings(&norm_claim);
    let claim_pol = analyze_polarity(&claim_words);

    let candidates = split_sentences_with_scalar_spans(source);
    let mut first_entailment: Option<(u64, u64)> = None;
    let mut best_contradiction: Option<(usize, NliVerdict)> = None;

    for (start_s, end_s, sent) in &candidates {
        let norm_sent = normalize_text(sent)?;
        if norm_sent == norm_claim {
            if first_entailment.is_none() {
                first_entailment = Some((*start_s, *end_s));
            }
            continue;
        }

        let sent_words = token_set(&norm_sent);
        let sent_content = content_words(&sent_words);
        if claim_content.is_empty() || sent_content.is_empty() {
            continue;
        }
        let shared = claim_content.intersection(&sent_content).count();
        let coverage_ok = shared * 2 >= claim_content.len() && shared >= 2;
        if !coverage_ok {
            continue;
        }

        let (sent_num_pairs, sent_units) = extract_quantified_bindings(&norm_sent);
        let mut sent_pol = analyze_polarity(&sent_words);

        // If the sentence has mixed polarity (`increased A and reduced B`), resolve polarity on
        // the sub-clause with maximal topical overlap against `claim_content`.
        let mut unresolved_mixed_clause = false;
        if sent_pol.has_mixed_direction() && !claim_pol.has_mixed_direction() {
            let clauses = split_into_clauses(&norm_sent);
            let mut best_clause: Option<(usize, PolarityProfile)> = None;
            let mut tied_opposite = false;
            for cl in &clauses {
                let cl_words = token_set(cl);
                let cl_content = content_words(&cl_words);
                let cl_shared = claim_content.intersection(&cl_content).count();
                if cl_shared == 0 {
                    continue;
                }
                let cl_pol = analyze_polarity(&cl_words);
                match best_clause {
                    None => best_clause = Some((cl_shared, cl_pol)),
                    Some((prev_s, _)) if cl_shared > prev_s => {
                        best_clause = Some((cl_shared, cl_pol));
                        tied_opposite = false;
                    }
                    Some((prev_s, prev_p))
                        if cl_shared == prev_s
                            && (cl_pol.raw_dir != prev_p.raw_dir
                                || cl_pol.is_negated_or_null() != prev_p.is_negated_or_null()) =>
                    {
                        tied_opposite = true;
                    }
                    _ => {}
                }
            }
            match best_clause {
                Some((_, resolved)) if !resolved.has_mixed_direction() && !tied_opposite => {
                    sent_pol = resolved;
                }
                _ => unresolved_mixed_clause = true,
            }
        }

        let mut defects = Vec::new();
        if has_comparative_role_swap(&norm_claim, &norm_sent) {
            defects.push("comparator_role_swap".to_owned());
        }
        if claim_pol.is_negated_or_null() != sent_pol.is_negated_or_null() {
            defects.push("negation_flip".to_owned());
        }
        if claim_pol.raw_dir != 0
            && sent_pol.raw_dir != 0
            && claim_pol.raw_dir != sent_pol.raw_dir
            && claim_pol.is_negated_or_null() == sent_pol.is_negated_or_null()
        {
            defects.push("direction_flip".to_owned());
        }

        // Verify every quantified `(number, optional_unit)` in `claim` against `sent`:
        let mut missing_quantification = false;
        for (c_num, c_unit) in &claim_num_pairs {
            match c_unit {
                Some(cu) => {
                    let exact_pair = sent_num_pairs
                        .iter()
                        .any(|(sn, su)| sn == c_num && su.as_ref() == Some(cu));
                    if !exact_pair {
                        let same_unit_other_num = sent_num_pairs
                            .iter()
                            .any(|(sn, su)| su.as_ref() == Some(cu) && sn != c_num);
                        let same_num_other_unit = sent_num_pairs
                            .iter()
                            .any(|(sn, su)| sn == c_num && su.as_ref() != Some(cu));
                        if same_num_other_unit {
                            defects.push("unit_mismatch".to_owned());
                        } else if same_unit_other_num || !sent_num_pairs.is_empty() {
                            defects.push("numeric_contradiction".to_owned());
                        } else {
                            missing_quantification = true;
                        }
                    }
                }
                None => {
                    if !sent_num_pairs.iter().any(|(sn, _)| sn == c_num) {
                        if !sent_num_pairs.is_empty() {
                            defects.push("numeric_contradiction".to_owned());
                        } else {
                            missing_quantification = true;
                        }
                    }
                }
            }
        }
        for &cu in &claim_units {
            if !sent_units.contains(cu) {
                if !sent_units.is_empty() && !defects.iter().any(|d| d == "unit_mismatch") {
                    defects.push("unit_mismatch".to_owned());
                } else if sent_units.is_empty() {
                    missing_quantification = true;
                }
            }
        }

        let direction_supported = !unresolved_mixed_clause
            && (claim_pol.raw_dir == 0 || sent_pol.raw_dir == claim_pol.raw_dir);

        if defects.is_empty()
            && !missing_quantification
            && direction_supported
            && claim_content.is_subset(&sent_content)
        {
            if first_entailment.is_none() {
                first_entailment = Some((*start_s, *end_s));
            }
            continue;
        }

        if !defects.is_empty()
            && best_contradiction
                .as_ref()
                .is_none_or(|(prev_shared, _)| shared > *prev_shared)
        {
            defects.dedup();
            best_contradiction = Some((
                shared,
                NliVerdict {
                    label: NliLabel::Contradicts,
                    defects,
                    matched_sentence_span: Some((*start_s, *end_s)),
                },
            ));
        }
    }

    if let Some((_, verdict)) = best_contradiction {
        return Ok(verdict);
    }
    if let Some(span) = first_entailment {
        return Ok(NliVerdict {
            label: NliLabel::Entails,
            defects: Vec::new(),
            matched_sentence_span: Some(span),
        });
    }

    Ok(NliVerdict {
        label: NliLabel::Neutral,
        defects: vec!["insufficient_entailment".to_owned()],
        matched_sentence_span: None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComposedEffect {
    PositiveDir,
    NegativeDir,
    ExplicitNull,
    NegatedPositive,
    NegatedNegative,
    Undetermined,
}

fn classify_composed_effect(pol: PolarityProfile) -> ComposedEffect {
    if pol.has_mixed_direction() {
        return ComposedEffect::Undetermined;
    }
    if pol.explicit_null && !pol.neg_op {
        return ComposedEffect::ExplicitNull;
    }
    if pol.neg_op {
        return match pol.raw_dir {
            1 => ComposedEffect::NegatedPositive,
            -1 => ComposedEffect::NegatedNegative,
            _ => ComposedEffect::ExplicitNull,
        };
    }
    match pol.raw_dir {
        1 => ComposedEffect::PositiveDir,
        -1 => ComposedEffect::NegativeDir,
        _ => ComposedEffect::Undetermined,
    }
}

fn effects_conflict(a: ComposedEffect, b: ComposedEffect) -> Option<&'static str> {
    use ComposedEffect::{
        ExplicitNull, NegatedNegative, NegatedPositive, NegativeDir, PositiveDir,
    };
    match (a, b) {
        (PositiveDir, NegativeDir) | (NegativeDir, PositiveDir) => {
            Some("directional_effect_disagreement")
        }
        (PositiveDir, ExplicitNull | NegatedPositive)
        | (ExplicitNull | NegatedPositive, PositiveDir)
        | (NegativeDir, ExplicitNull | NegatedNegative)
        | (ExplicitNull | NegatedNegative, NegativeDir) => Some("negation_polarity_disagreement"),
        _ => None,
    }
}

/// Detects cross-study contradictions across `(study_id, doc_id, finding_text)` tuples (`TA-14`).
/// Reports from the same `study_id` are never treated as independent contradictions, and
/// compatible null/directional pairs (e.g. `"did not increase mortality"` vs `"reduced mortality"`)
/// are not misclassified as contradictions.
///
/// # Errors
/// Fails closed if any finding is empty or contains forbidden BiDi/control characters.
pub fn detect_corpus_contradictions(
    findings: &[(&str, &str, &str)],
) -> Result<ContradictionReport, NliError> {
    let mut parsed = Vec::with_capacity(findings.len());
    for &(study_id, doc_id, text) in findings {
        if study_id.trim().is_empty() || doc_id.trim().is_empty() || text.trim().is_empty() {
            return Err(NliError::EmptyInput);
        }
        let norm = normalize_text(text)?;
        let words = token_set(&norm);
        let content = content_words(&words);
        let eff = classify_composed_effect(analyze_polarity(&words));
        parsed.push((study_id, doc_id, content, eff));
    }

    let mut conflicts = Vec::new();
    for i in 0..parsed.len() {
        for j in (i + 1)..parsed.len() {
            let (sa, da, ca, ea) = &parsed[i];
            let (sb, db, cb, eb) = &parsed[j];
            if sa == sb {
                continue;
            }
            let shared = ca.intersection(cb).count();
            let min_len = ca.len().min(cb.len());
            if min_len == 0 || shared * 2 < min_len || shared < 2 {
                continue;
            }
            if let Some(reason) = effects_conflict(*ea, *eb) {
                conflicts.push(StudyConflictPair {
                    study_a: (*sa).to_owned(),
                    doc_a: (*da).to_owned(),
                    study_b: (*sb).to_owned(),
                    doc_b: (*db).to_owned(),
                    reason: reason.to_owned(),
                });
            }
        }
    }

    let state = if conflicts.is_empty() {
        ContradictionState::None
    } else {
        ContradictionState::Material
    };
    Ok(ContradictionReport { state, conflicts })
}

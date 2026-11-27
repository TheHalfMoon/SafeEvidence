//! Deterministic local bilingual (`EN` + vocalized `AR`) claim-entailment and cross-study
//! contradiction verifier (`WP-08`, `TA-10`, `TA-14`).
//!
//! Enforces `#![forbid(unsafe_code)]`, zero network sockets, exact raw Unicode scalar span
//! anchoring, and strict numeric/unit/negation/directional polarity verification across English
//! and vocalized Arabic source texts without emitting heuristic confidence percentages (`P00`).

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

const EN_NEGATIONS: &[&str] = &[
    "not",
    "no",
    "never",
    "without",
    "neither",
    "nor",
    "failed",
    "fails",
    "unchanged",
    "similar",
    "comparable",
    "equivalent",
    "nonsignificant",
    "insignificant",
    "ineffective",
    "didnt",
    "doesnt",
    "wasnt",
];

const AR_NEGATIONS: &[&str] = &[
    "\u{0644}\u{0627}",
    "\u{0644}\u{0645}",
    "\u{0644}\u{0646}",
    "\u{0644}\u{064a}\u{0633}",
    "\u{062f}\u{0648}\u{0646}",
    "\u{0628}\u{062f}\u{0648}\u{0646}",
    "\u{063a}\u{064a}\u{0631}",
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

fn token_set(norm: &str) -> BTreeSet<String> {
    norm.replace(['\'', '`'], "")
        .replace("non-significant", "nonsignificant")
        .split(|c: char| !c.is_alphanumeric() && c != '/')
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

fn extract_numbers(norm: &str) -> Vec<String> {
    let chars: Vec<char> = norm.chars().collect();
    let mut nums = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut start = i;
            while i < chars.len()
                && (chars[i].is_ascii_digit()
                    || (chars[i] == '.' && chars.get(i + 1).is_some_and(char::is_ascii_digit)))
            {
                i += 1;
            }
            if start > 0 && chars[start - 1] == '-' {
                start -= 1;
            }
            nums.push(chars[start..i].iter().collect());
        } else {
            i += 1;
        }
    }
    nums
}

fn extract_units(words: &BTreeSet<String>) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    for &(canon, forms) in CANONICAL_UNITS {
        for &f in forms {
            if let Ok(nf) = normalize_text(f)
                && words.contains(&nf)
            {
                out.insert(canon);
            }
        }
    }
    out
}

fn has_negation(words: &BTreeSet<String>) -> bool {
    EN_NEGATIONS.iter().any(|w| words.contains(*w))
        || AR_NEGATIONS
            .iter()
            .any(|w| normalize_text(w).ok().is_some_and(|nw| words.contains(&nw)))
}

/// Net directional polarity: `+1` increase/worsen, `-1` decrease/reduce/improve, `0` neutral.
/// Negation flips non-zero polarity (`did not reduce` -> `0` / non-benefit).
fn sentence_polarity(words: &BTreeSet<String>) -> (bool, i8) {
    let neg = has_negation(words);
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
    (neg, raw_dir)
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
        "were", "is", "are",
    ];
    words
        .iter()
        .filter(|w| {
            w.chars().count() >= 2
                && !STOP.contains(&w.as_str())
                && !EN_NEGATIONS.contains(&w.as_str())
                && !AR_NEGATIONS.iter().any(|aw| {
                    normalize_text(aw)
                        .ok()
                        .is_some_and(|nw| nw.as_str() == w.as_str())
                })
                && !w.chars().all(|c| c.is_ascii_digit() || c == '.')
        })
        .cloned()
        .collect()
}

/// Verifies whether `source` entails, contradicts, or is neutral with respect to `claim` across
/// English and vocalized Arabic (`WP-08`, `TA-10`).
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
    let claim_nums = extract_numbers(&norm_claim);
    let claim_units = extract_units(&claim_words);
    let (claim_neg, claim_dir) = sentence_polarity(&claim_words);

    let candidates = split_sentences_with_scalar_spans(source);
    let mut best_contradiction: Option<(usize, NliVerdict)> = None;

    for (start_s, end_s, sent) in &candidates {
        let norm_sent = normalize_text(sent)?;
        if norm_sent == norm_claim {
            return Ok(NliVerdict {
                label: NliLabel::Entails,
                defects: Vec::new(),
                matched_sentence_span: Some((*start_s, *end_s)),
            });
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

        let sent_nums = extract_numbers(&norm_sent);
        let sent_units = extract_units(&sent_words);
        let (sent_neg, sent_dir) = sentence_polarity(&sent_words);

        let mut defects = Vec::new();
        if claim_neg != sent_neg {
            defects.push("negation_flip".to_owned());
        }
        if claim_dir != 0 && sent_dir != 0 && claim_dir != sent_dir && claim_neg == sent_neg {
            defects.push("direction_flip".to_owned());
        }
        if !claim_nums.is_empty() && claim_nums != sent_nums {
            defects.push("numeric_contradiction".to_owned());
        }
        if !claim_units.is_empty() && claim_units != sent_units {
            defects.push("unit_mismatch".to_owned());
        }

        if defects.is_empty() && claim_content.is_subset(&sent_content) {
            return Ok(NliVerdict {
                label: NliLabel::Entails,
                defects: Vec::new(),
                matched_sentence_span: Some((*start_s, *end_s)),
            });
        }

        if !defects.is_empty()
            && best_contradiction
                .as_ref()
                .is_none_or(|(prev_shared, _)| shared > *prev_shared)
        {
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

    Ok(NliVerdict {
        label: NliLabel::Neutral,
        defects: vec!["insufficient_entailment".to_owned()],
        matched_sentence_span: None,
    })
}

/// Detects cross-study contradictions across `(study_id, doc_id, finding_text)` tuples (`TA-14`).
/// Reports from the same `study_id` are never treated as independent contradictions.
///
/// # Errors
/// Fails closed if any finding contains forbidden BiDi/control characters.
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
        let (neg, dir) = sentence_polarity(&words);
        parsed.push((study_id, doc_id, content, neg, dir));
    }

    let mut conflicts = Vec::new();
    for i in 0..parsed.len() {
        for j in (i + 1)..parsed.len() {
            let (sa, da, ca, na, dira) = &parsed[i];
            let (sb, db, cb, nb, dirb) = &parsed[j];
            if sa == sb {
                continue;
            }
            let shared = ca.intersection(cb).count();
            let min_len = ca.len().min(cb.len());
            if min_len == 0 || shared * 2 < min_len || shared < 2 {
                continue;
            }
            if na != nb {
                conflicts.push(StudyConflictPair {
                    study_a: (*sa).to_owned(),
                    doc_a: (*da).to_owned(),
                    study_b: (*sb).to_owned(),
                    doc_b: (*db).to_owned(),
                    reason: "negation_polarity_disagreement".to_owned(),
                });
            } else if *dira != 0 && *dirb != 0 && dira != dirb {
                conflicts.push(StudyConflictPair {
                    study_a: (*sa).to_owned(),
                    doc_a: (*da).to_owned(),
                    study_b: (*sb).to_owned(),
                    doc_b: (*db).to_owned(),
                    reason: "directional_effect_disagreement".to_owned(),
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

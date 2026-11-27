//! Deterministic bilingual (`EN` + vocalized `AR`) dense char-ngram/concept embeddings, pure-Rust
//! flat cosine vector index, Reciprocal Rank Fusion (`BM25 + Dense` RRF), and PICO cross-reranking
//! (`WP-07`, `TA-08`, `TA-09`).
//!
//! Operates 100% locally with `#![forbid(unsafe_code)]`, zero network sockets, fail-closed corpus
//! rights/retraction/language-promotion gates, and Neumaier compensated floating-point reductions
//! for cross-platform determinism.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, params};
use safeevidence_assurance::eval_metrics::neumaier_sum;
use safeevidence_contracts::bilingual::{
    NormalizedText, contains_arabic_script, is_forbidden_bidi_control,
};
use safeevidence_contracts::study::PublicationState;
use serde::{Deserialize, Serialize};

use crate::bilingual_ask::{
    BilingualConcept, BilingualCorpus, BilingualDocument, TextLanguage, parse_bilingual_question,
};

pub const EMBEDDING_DIM: usize = 128;
pub const DEFAULT_RRF_K: u32 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PicoIntentKind {
    Benefit,
    ComparativeEffectiveness,
    HarmOrSafety,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtendedPicoQuestion {
    pub language: TextLanguage,
    pub intent: PicoIntentKind,
    pub intervention_concept: Option<String>,
    pub comparator_concept: Option<String>,
    pub population_concept: Option<String>,
    pub condition_or_outcome_concept: Option<String>,
    pub raw_intervention: String,
    pub raw_comparator: Option<String>,
    pub raw_population: Option<String>,
    pub raw_condition_or_outcome: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridRetrievalTrace {
    pub query_language: TextLanguage,
    pub parsed_pico: Option<ExtendedPicoQuestion>,
    pub lexical_doc_ids: Vec<String>,
    pub dense_doc_ids: Vec<String>,
    pub rrf_fused_doc_ids: Vec<String>,
    pub reranked_doc_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HybridRetrievalError {
    EmptyQuery,
    EmptyCorpus,
    InvalidCorpus(&'static str),
    RightsUnresolved(String),
    ForbiddenTextControl,
    PatientSpecificRequest,
    UnsupportedLanguage,
    SqliteError(String),
}

const EN_PATIENT_PHRASES: &[&str] = &[
    "my patient",
    "this patient",
    "my child",
    "my mother",
    "my father",
    "should i give",
    "should i prescribe",
];

const AR_PATIENT_PHRASES: &[&str] = &[
    "\u{0645}\u{0631}\u{064a}\u{0636}\u{064a}",
    "\u{0647}\u{0630}\u{0627} \u{0627}\u{0644}\u{0645}\u{0631}\u{064a}\u{0636}",
    "\u{0637}\u{0641}\u{0644}\u{064a}",
    "\u{0648}\u{0627}\u{0644}\u{062f}\u{064a}",
    "\u{0648}\u{0627}\u{0644}\u{062f}\u{062a}\u{064a}",
    "\u{0647}\u{0644} \u{0627}\u{0635}\u{0641}",
    "\u{0647}\u{0644} \u{0627}\u{0639}\u{0637}\u{064a}",
];

fn collapse_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_clean(raw: &str) -> Result<String, HybridRetrievalError> {
    if raw
        .chars()
        .any(|c| is_forbidden_bidi_control(c) || (c.is_control() && c != '\n' && c != '\t'))
    {
        return Err(HybridRetrievalError::ForbiddenTextControl);
    }
    let norm =
        NormalizedText::build(raw).map_err(|_| HybridRetrievalError::ForbiddenTextControl)?;
    Ok(collapse_ws(norm.as_str()))
}

fn is_patient_specific(norm_text: &str) -> bool {
    EN_PATIENT_PHRASES.iter().any(|p| norm_text.contains(p))
        || AR_PATIENT_PHRASES.iter().any(|p| {
            NormalizedText::build(p)
                .ok()
                .is_some_and(|np| norm_text.contains(&collapse_ws(np.as_str())))
        })
}

fn is_allowed_typographic_symbol(c: char) -> bool {
    matches!(
        c,
        '\u{2010}'..='\u{2015}' // hyphens & en/em dashes
            | '\u{2018}'..='\u{201F}' // typographic single/double quotes
            | '\u{2022}' // bullet
            | '\u{2026}' // ellipsis
            | '\u{00B0}' // degree
            | '\u{00B1}' // plus-minus
            | '\u{00D7}' // multiplication
            | '\u{00F7}' // division
            | '\u{2264}' // <=
            | '\u{2265}' // >=
    )
}

fn has_unsupported_non_en_ar_script(raw: &str) -> bool {
    raw.chars().any(|c| {
        if c.is_ascii() || c.is_whitespace() || is_allowed_typographic_symbol(c) {
            return false;
        }
        if is_forbidden_bidi_control(c) {
            return true;
        }
        !matches!(
            c,
            '\u{0600}'..='\u{06FF}'
                | '\u{0750}'..='\u{08FF}'
                | '\u{FB50}'..='\u{FDFF}'
                | '\u{FE70}'..='\u{FEFC}'
        )
    })
}

fn fnv1a_64(domain: &[u8], token: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in domain.iter().chain(b":").chain(token.as_bytes()) {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Deterministic local bilingual (`EN`/`AR`) dense embedder projecting normalized character
/// n-grams, word n-grams, and matched bilingual lexicon concepts onto the unit sphere $S^{127}$.
#[derive(Clone, Debug)]
pub struct BilingualDenseEmbedder {
    normalized_concepts: Vec<(String, Vec<String>)>,
}

impl BilingualDenseEmbedder {
    #[must_use]
    pub fn new(lexicon: &[BilingualConcept]) -> Self {
        let mut normalized_concepts = Vec::with_capacity(lexicon.len());
        for entry in lexicon {
            let mut phrases = Vec::new();
            for term in entry.en_terms.iter().chain(entry.ar_terms.iter()) {
                if let Ok(nt) = NormalizedText::build(term) {
                    let clean = collapse_ws(nt.as_str());
                    if !clean.is_empty() && !phrases.contains(&clean) {
                        phrases.push(clean);
                    }
                }
            }
            normalized_concepts.push((entry.concept_id.clone(), phrases));
        }
        Self {
            normalized_concepts,
        }
    }

    fn accumulate_feature(acc: &mut [f64; EMBEDDING_DIM], domain: &[u8], feat: &str, weight: f64) {
        let h0 = fnv1a_64(domain, feat);
        for slot in 0..4_u64 {
            let m = mix64(h0.wrapping_add(slot.wrapping_mul(0x9e37_79b9_7f4a_7c15)));
            let idx = (m as usize) % EMBEDDING_DIM;
            let sign = if (m >> 63) == 0 { 1.0 } else { -1.0 };
            acc[idx] += sign * weight;
        }
    }

    /// Computes a deterministic L2-normalized 128-dimensional embedding vector.
    ///
    /// # Errors
    /// Fails closed on empty/punctuation-only text or forbidden BiDi/control characters.
    pub fn embed(&self, raw: &str) -> Result<[f64; EMBEDDING_DIM], HybridRetrievalError> {
        let clean = normalize_clean(raw)?;
        if clean.is_empty() {
            return Err(HybridRetrievalError::EmptyQuery);
        }
        let mut acc = [0.0_f64; EMBEDDING_DIM];

        let tokens: Vec<&str> = clean
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        if tokens.is_empty() {
            return Err(HybridRetrievalError::EmptyQuery);
        }

        // 1. Cross-lingual canonical concept projections (aligns vocalized AR <-> EN concepts).
        for (concept_id, phrases) in &self.normalized_concepts {
            if phrases.iter().any(|p| contains_phrase_bounded(&clean, p)) {
                Self::accumulate_feature(&mut acc, b"concept", concept_id, 4.5);
            }
        }

        // 2. Word unigrams and bigrams.
        for &tok in &tokens {
            Self::accumulate_feature(&mut acc, b"tok1", tok, 2.0);
        }
        for pair in tokens.windows(2) {
            let bg = format!("{} {}", pair[0], pair[1]);
            Self::accumulate_feature(&mut acc, b"tok2", &bg, 1.5);
        }

        // 3. Character 3-grams and 4-grams inside each word.
        for &tok in &tokens {
            let padded: Vec<char> = format!("<{tok}>").chars().collect();
            for n in [3_usize, 4_usize] {
                if padded.len() >= n {
                    for win in padded.windows(n) {
                        let gram: String = win.iter().collect();
                        Self::accumulate_feature(&mut acc, b"char", &gram, 0.75);
                    }
                }
            }
        }

        let norm_sq = neumaier_sum(acc.iter().map(|v| v * v));
        if !norm_sq.is_finite() || norm_sq <= 0.0 {
            return Err(HybridRetrievalError::EmptyQuery);
        }
        let inv = 1.0 / norm_sq.sqrt();
        for v in &mut acc {
            *v *= inv;
        }
        Ok(acc)
    }
}

fn contains_phrase_bounded(haystack: &str, phrase: &str) -> bool {
    if phrase.is_empty() {
        return false;
    }
    for (idx, _) in haystack.match_indices(phrase) {
        let before_ok = haystack[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_idx = idx + phrase.len();
        let after_ok = haystack[after_idx..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

#[must_use]
pub fn cosine_similarity(a: &[f64; EMBEDDING_DIM], b: &[f64; EMBEDDING_DIM]) -> f64 {
    neumaier_sum(a.iter().zip(b.iter()).map(|(x, y)| x * y)).clamp(-1.0, 1.0)
}

/// Pure-Rust exact flat vector index (`sqlite-vec` / `T22` clean-room local semantic counterpart).
#[derive(Clone, Debug, Default)]
pub struct FlatVectorIndex {
    entries: Vec<(String, [f64; EMBEDDING_DIM])>,
}

impl FlatVectorIndex {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn upsert(&mut self, doc_id: impl Into<String>, vector: [f64; EMBEDDING_DIM]) {
        let doc_id = doc_id.into();
        if let Some(existing) = self.entries.iter_mut().find(|(id, _)| id == &doc_id) {
            existing.1 = vector;
        } else {
            self.entries.push((doc_id, vector));
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns up to `top_k` `(doc_id, cosine_score)` pairs sorted by `(score DESC, doc_id ASC)`
    /// for all documents with positive similarity (`score > 0.0`).
    #[must_use]
    pub fn search(&self, query_vec: &[f64; EMBEDDING_DIM], top_k: usize) -> Vec<(String, f64)> {
        if top_k == 0 {
            return Vec::new();
        }
        let mut scored: Vec<(String, f64)> = self
            .entries
            .iter()
            .map(|(id, vec)| (id.clone(), cosine_similarity(query_vec, vec)))
            .filter(|(_, sim)| *sim > 1e-9)
            .collect();
        scored.sort_by(|(id_a, s_a), (id_b, s_b)| s_b.total_cmp(s_a).then_with(|| id_a.cmp(id_b)));
        scored.truncate(top_k);
        scored
    }
}

/// Reciprocal Rank Fusion (`Cormack et al., 2009`):
/// `score(d) = sum_{list} 1 / (rrf_k + rank_1based(d))`.
#[must_use]
pub fn reciprocal_rank_fusion(
    lexical_ranked: &[String],
    dense_ranked: &[String],
    rrf_k: u32,
) -> Vec<(String, f64)> {
    let k = f64::from(rrf_k.max(1));
    let mut scores: BTreeMap<String, Vec<f64>> = BTreeMap::new();

    let mut seen_lex = BTreeSet::new();
    for (idx, doc_id) in lexical_ranked.iter().enumerate() {
        if seen_lex.insert(doc_id.as_str()) {
            let contrib = 1.0 / (k + (idx as f64) + 1.0);
            scores.entry(doc_id.clone()).or_default().push(contrib);
        }
    }

    let mut seen_dense = BTreeSet::new();
    for (idx, doc_id) in dense_ranked.iter().enumerate() {
        if seen_dense.insert(doc_id.as_str()) {
            let contrib = 1.0 / (k + (idx as f64) + 1.0);
            scores.entry(doc_id.clone()).or_default().push(contrib);
        }
    }

    let mut fused: Vec<(String, f64)> = scores
        .into_iter()
        .map(|(doc_id, parts)| (doc_id, neumaier_sum(parts)))
        .collect();
    fused.sort_by(|(id_a, s_a), (id_b, s_b)| s_b.total_cmp(s_a).then_with(|| id_a.cmp(id_b)));
    fused
}

fn lookup_lexicon_concept(lexicon: &[BilingualConcept], raw_term: &str) -> Option<String> {
    let target = normalize_clean(raw_term).ok()?;
    if target.is_empty() {
        return None;
    }
    for entry in lexicon {
        let hit = entry
            .en_terms
            .iter()
            .chain(entry.ar_terms.iter())
            .any(|t| normalize_clean(t).ok().as_deref() == Some(target.as_str()));
        if hit {
            return Some(entry.concept_id.clone());
        }
    }
    None
}

/// Extended bilingual PICO parser supporting benefit, head-to-head comparator (`vs` / `مقابل`),
/// and safety/harm (`increase` / `cause` / `يزيد` / `يسبب`) research questions (`WP-07`, `TA-08`).
#[must_use]
pub fn parse_extended_pico_question(
    raw: &str,
    lexicon: &[BilingualConcept],
) -> Option<ExtendedPicoQuestion> {
    let clean = normalize_clean(raw).ok()?;
    if clean.is_empty() || is_patient_specific(&clean) || has_unsupported_non_en_ar_script(raw) {
        return None;
    }
    let body = clean
        .strip_suffix('?')
        .or_else(|| clean.strip_suffix('\u{061F}'))
        .unwrap_or(&clean)
        .trim();

    if !body.contains(" vs ")
        && !body.contains(" versus ")
        && !body.contains(" \u{0645}\u{0642}\u{0627}\u{0628}\u{0644} ")
        && let Some(base) = parse_bilingual_question(raw, lexicon)
    {
        return Some(ExtendedPicoQuestion {
            language: base.language,
            intent: PicoIntentKind::Benefit,
            intervention_concept: base.intervention_concept,
            comparator_concept: None,
            population_concept: base.population_concept,
            condition_or_outcome_concept: base.condition_concept,
            raw_intervention: base.raw_intervention,
            raw_comparator: None,
            raw_population: base.raw_population,
            raw_condition_or_outcome: base.raw_condition,
        });
    }

    if let Some(rest) = body.strip_prefix("does ") {
        if let Some((ic_part, after_help)) = rest.split_once(" help ") {
            let (interv, comp) = ic_part
                .split_once(" vs ")
                .or_else(|| ic_part.split_once(" versus "))?;
            let (pop, cond) = match after_help.strip_prefix("with ") {
                Some(c) => (None, c),
                None => {
                    let (p, c) = after_help.split_once(" with ")?;
                    (Some(p), c)
                }
            };
            if interv.trim().is_empty() || comp.trim().is_empty() || cond.trim().is_empty() {
                return None;
            }
            return Some(ExtendedPicoQuestion {
                language: TextLanguage::En,
                intent: PicoIntentKind::ComparativeEffectiveness,
                intervention_concept: lookup_lexicon_concept(lexicon, interv),
                comparator_concept: lookup_lexicon_concept(lexicon, comp),
                population_concept: pop.and_then(|p| lookup_lexicon_concept(lexicon, p)),
                condition_or_outcome_concept: lookup_lexicon_concept(lexicon, cond),
                raw_intervention: interv.trim().to_owned(),
                raw_comparator: Some(comp.trim().to_owned()),
                raw_population: pop.map(|p| p.trim().to_owned()),
                raw_condition_or_outcome: cond.trim().to_owned(),
            });
        }

        let harm_split = rest
            .split_once(" increase ")
            .or_else(|| rest.split_once(" cause "));
        if let Some((interv, after_verb)) = harm_split {
            let (outcome, pop) = match after_verb.split_once(" in ") {
                Some((o, p)) => (o, Some(p)),
                None => (after_verb, None),
            };
            if interv.trim().is_empty() || outcome.trim().is_empty() {
                return None;
            }
            return Some(ExtendedPicoQuestion {
                language: TextLanguage::En,
                intent: PicoIntentKind::HarmOrSafety,
                intervention_concept: lookup_lexicon_concept(lexicon, interv),
                comparator_concept: None,
                population_concept: pop.and_then(|p| lookup_lexicon_concept(lexicon, p)),
                condition_or_outcome_concept: lookup_lexicon_concept(lexicon, outcome),
                raw_intervention: interv.trim().to_owned(),
                raw_comparator: None,
                raw_population: pop.map(|p| p.trim().to_owned()),
                raw_condition_or_outcome: outcome.trim().to_owned(),
            });
        }
    }

    let ar_help =
        normalize_clean("\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f}").ok()?;
    let ar_vs = normalize_clean("\u{0645}\u{0642}\u{0627}\u{0628}\u{0644}").ok()?;
    let ar_with = normalize_clean("\u{0645}\u{0639}").ok()?;
    let ar_in = normalize_clean("\u{0641}\u{064a}").ok()?;
    if let Some(rest) = body.strip_prefix(&format!("{ar_help} ")) {
        let (left, cond) = rest
            .split_once(&format!(" {ar_with} "))
            .or_else(|| rest.split_once(&format!(" {ar_in} ")))?;
        if let Some((interv, comp)) = left.split_once(&format!(" {ar_vs} "))
            && !interv.trim().is_empty()
            && !comp.trim().is_empty()
            && !cond.trim().is_empty()
        {
            return Some(ExtendedPicoQuestion {
                language: TextLanguage::Ar,
                intent: PicoIntentKind::ComparativeEffectiveness,
                intervention_concept: lookup_lexicon_concept(lexicon, interv),
                comparator_concept: lookup_lexicon_concept(lexicon, comp),
                population_concept: None,
                condition_or_outcome_concept: lookup_lexicon_concept(lexicon, cond),
                raw_intervention: interv.trim().to_owned(),
                raw_comparator: Some(comp.trim().to_owned()),
                raw_population: None,
                raw_condition_or_outcome: cond.trim().to_owned(),
            });
        }
    }

    let ar_inc = normalize_clean("\u{0647}\u{0644} \u{064a}\u{0632}\u{064a}\u{062f}").ok()?;
    let ar_cause = normalize_clean("\u{0647}\u{0644} \u{064a}\u{0633}\u{0628}\u{0628}").ok()?;
    let harm_ar_rest = body
        .strip_prefix(&format!("{ar_inc} "))
        .or_else(|| body.strip_prefix(&format!("{ar_cause} ")));
    if let Some(rest) = harm_ar_rest {
        let (io_part, pop_opt) = match rest.split_once(&format!(" {ar_in} ")) {
            Some((io, p)) => (io, Some(p)),
            None => (rest, None),
        };
        let words: Vec<&str> = io_part.split_whitespace().collect();
        if words.len() >= 2 {
            for split_idx in 1..words.len() {
                let cand_i = words[..split_idx].join(" ");
                let cand_o = words[split_idx..].join(" ");
                if lookup_lexicon_concept(lexicon, &cand_i).is_some() {
                    return Some(ExtendedPicoQuestion {
                        language: TextLanguage::Ar,
                        intent: PicoIntentKind::HarmOrSafety,
                        intervention_concept: lookup_lexicon_concept(lexicon, &cand_i),
                        comparator_concept: None,
                        population_concept: pop_opt
                            .and_then(|p| lookup_lexicon_concept(lexicon, p)),
                        condition_or_outcome_concept: lookup_lexicon_concept(lexicon, &cand_o),
                        raw_intervention: cand_i,
                        raw_comparator: None,
                        raw_population: pop_opt.map(|p| p.trim().to_owned()),
                        raw_condition_or_outcome: cand_o,
                    });
                }
            }
        }
    }

    None
}

fn is_withdrawn_state(state: PublicationState) -> bool {
    matches!(
        state,
        PublicationState::Retracted | PublicationState::Withdrawn
    )
}

fn validate_and_filter_corpus(
    corpus: &BilingualCorpus,
) -> Result<Vec<&BilingualDocument>, HybridRetrievalError> {
    if corpus.documents.is_empty() {
        return Err(HybridRetrievalError::EmptyCorpus);
    }
    if corpus.validity_epoch == 0 {
        return Err(HybridRetrievalError::InvalidCorpus(
            "validity_epoch must be > 0",
        ));
    }
    if corpus.rights_grant_version.trim().is_empty() {
        return Err(HybridRetrievalError::InvalidCorpus(
            "rights_grant_version must be non-empty",
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut withdrawn_studies = BTreeSet::new();
    for doc in &corpus.documents {
        if doc.doc_id.trim().is_empty() || doc.study_id.trim().is_empty() {
            return Err(HybridRetrievalError::InvalidCorpus(
                "doc_id and study_id must be non-empty",
            ));
        }
        if !seen_ids.insert(doc.doc_id.as_str()) {
            return Err(HybridRetrievalError::InvalidCorpus("duplicate doc_id"));
        }
        if !doc.rights.admissible() {
            return Err(HybridRetrievalError::RightsUnresolved(doc.doc_id.clone()));
        }
        if is_withdrawn_state(doc.publication_state) {
            withdrawn_studies.insert(doc.study_id.as_str());
        }
    }

    let eligible = corpus
        .documents
        .iter()
        .filter(|doc| {
            !withdrawn_studies.contains(doc.study_id.as_str())
                && doc.publication_state.citable()
                && (corpus.arabic_path_promoted || doc.language != TextLanguage::Ar)
        })
        .collect();
    Ok(eligible)
}

fn build_fts_hybrid_index(
    eligible_docs: &[&BilingualDocument],
    embedder: &BilingualDenseEmbedder,
) -> Result<(Connection, FlatVectorIndex), HybridRetrievalError> {
    let conn = Connection::open_in_memory()
        .map_err(|e| HybridRetrievalError::SqliteError(e.to_string()))?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE hybrid_evidence USING fts5(doc_id UNINDEXED, norm_title, norm_body, concepts)",
    )
    .map_err(|e| HybridRetrievalError::SqliteError(e.to_string()))?;

    let mut dense = FlatVectorIndex::new();
    for &doc in eligible_docs {
        let norm_title = normalize_clean(&doc.title)?;
        let norm_body = normalize_clean(&doc.text)?;
        let concepts = format!(
            "{} {} {}",
            doc.population_concept, doc.condition_concept, doc.intervention_concept
        );
        conn.execute(
            "INSERT INTO hybrid_evidence (doc_id, norm_title, norm_body, concepts) VALUES (?1, ?2, ?3, ?4)",
            params![doc.doc_id, norm_title, norm_body, concepts],
        )
        .map_err(|e| HybridRetrievalError::SqliteError(e.to_string()))?;

        let composite = format!(
            "{} {} {} {} {}",
            doc.title,
            doc.text,
            doc.population_concept,
            doc.condition_concept,
            doc.intervention_concept
        );
        let vec = embedder.embed(&composite)?;
        dense.upsert(doc.doc_id.clone(), vec);
    }
    Ok((conn, dense))
}

fn lexical_or_search(
    conn: &Connection,
    clean_query: &str,
    parsed: Option<&ExtendedPicoQuestion>,
    top_k: usize,
) -> Result<Vec<String>, HybridRetrievalError> {
    if top_k == 0 {
        return Ok(Vec::new());
    }
    let mut terms: Vec<String> = Vec::new();
    if let Some(p) = parsed {
        if let Some(ic) = &p.intervention_concept {
            terms.push(ic.clone());
        }
        if let Some(cc) = &p.condition_or_outcome_concept {
            terms.push(cc.clone());
        }
        if let Some(pc) = &p.population_concept {
            terms.push(pc.clone());
        }
    }
    for tok in clean_query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 2)
    {
        if !terms.iter().any(|t| t == tok) {
            terms.push(tok.to_owned());
        }
    }
    if terms.is_empty() {
        return Ok(Vec::new());
    }
    let match_expr = terms
        .iter()
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ");
    let sql_limit = i64::try_from(top_k).unwrap_or(i64::MAX);
    let mut stmt = conn
        .prepare(
            "SELECT doc_id FROM hybrid_evidence WHERE hybrid_evidence MATCH ?1 ORDER BY bm25(hybrid_evidence), doc_id LIMIT ?2",
        )
        .map_err(|e| HybridRetrievalError::SqliteError(e.to_string()))?;
    let rows = stmt
        .query_map(params![match_expr, sql_limit], |r| r.get(0))
        .map_err(|e| HybridRetrievalError::SqliteError(e.to_string()))?;
    rows.collect::<Result<Vec<String>, _>>()
        .map_err(|e| HybridRetrievalError::SqliteError(e.to_string()))
}

fn pico_rerank_bonus(doc: &BilingualDocument, parsed: Option<&ExtendedPicoQuestion>) -> f64 {
    let Some(p) = parsed else {
        return 0.0;
    };
    let mut bonus = 0.0;
    if p.intervention_concept.as_deref() == Some(doc.intervention_concept.as_str()) {
        bonus += 0.025;
    }
    if p.condition_or_outcome_concept.as_deref() == Some(doc.condition_concept.as_str()) {
        bonus += 0.025;
    }
    if let Some(pop) = &p.population_concept
        && pop == &doc.population_concept
    {
        bonus += 0.015;
    }
    bonus
}

/// Executes hybrid (`FTS5 BM25 + 128-d Dense Cosine -> RRF -> PICO Cross-Reranker`) bilingual
/// retrieval over `corpus`, returning the full stage-by-stage trace (`WP-07`, `TA-08`, `TA-09`).
///
/// # Errors
/// Fails closed on empty/invalid corpus, rights-inadmissible documents, empty query, forbidden
/// BiDi/control characters, patient-specific clinical requests, unpromoted Arabic language path,
/// or unsupported non-EN/AR script.
pub fn hybrid_retrieve_bilingual(
    corpus: &BilingualCorpus,
    raw_query: &str,
    top_k: usize,
) -> Result<HybridRetrievalTrace, HybridRetrievalError> {
    let eligible_docs = validate_and_filter_corpus(corpus)?;
    let clean_query = normalize_clean(raw_query)?;
    if clean_query.is_empty() {
        return Err(HybridRetrievalError::EmptyQuery);
    }
    if is_patient_specific(&clean_query) {
        return Err(HybridRetrievalError::PatientSpecificRequest);
    }
    if has_unsupported_non_en_ar_script(raw_query) {
        return Err(HybridRetrievalError::UnsupportedLanguage);
    }
    let query_language = if contains_arabic_script(raw_query) {
        if !corpus.arabic_path_promoted {
            return Err(HybridRetrievalError::UnsupportedLanguage);
        }
        TextLanguage::Ar
    } else {
        TextLanguage::En
    };

    let parsed_pico = parse_extended_pico_question(raw_query, &corpus.lexicon);
    if top_k == 0 || eligible_docs.is_empty() {
        return Ok(HybridRetrievalTrace {
            query_language,
            parsed_pico,
            lexical_doc_ids: Vec::new(),
            dense_doc_ids: Vec::new(),
            rrf_fused_doc_ids: Vec::new(),
            reranked_doc_ids: Vec::new(),
        });
    }

    let embedder = BilingualDenseEmbedder::new(&corpus.lexicon);
    let (conn, dense_index) = build_fts_hybrid_index(&eligible_docs, &embedder)?;

    let pool_limit = top_k.saturating_mul(2);
    let lexical_doc_ids = lexical_or_search(&conn, &clean_query, parsed_pico.as_ref(), pool_limit)?;

    let mut dense_query_basis = raw_query.to_owned();
    if let Some(p) = &parsed_pico {
        if let Some(ic) = &p.intervention_concept {
            dense_query_basis.push(' ');
            dense_query_basis.push_str(ic);
        }
        if let Some(cc) = &p.condition_or_outcome_concept {
            dense_query_basis.push(' ');
            dense_query_basis.push_str(cc);
        }
        if let Some(pc) = &p.population_concept {
            dense_query_basis.push(' ');
            dense_query_basis.push_str(pc);
        }
    }
    let query_vec = embedder.embed(&dense_query_basis)?;
    let dense_doc_ids: Vec<String> = dense_index
        .search(&query_vec, pool_limit)
        .into_iter()
        .map(|(id, _)| id)
        .collect();

    let fused = reciprocal_rank_fusion(&lexical_doc_ids, &dense_doc_ids, DEFAULT_RRF_K);
    let rrf_fused_doc_ids: Vec<String> =
        fused.iter().take(top_k).map(|(id, _)| id.clone()).collect();

    let doc_by_id: BTreeMap<&str, &BilingualDocument> = eligible_docs
        .iter()
        .map(|&d| (d.doc_id.as_str(), d))
        .collect();

    let mut reranked: Vec<(String, f64)> = fused
        .into_iter()
        .map(|(id, rrf_score)| {
            let bonus = doc_by_id
                .get(id.as_str())
                .map_or(0.0, |d| pico_rerank_bonus(d, parsed_pico.as_ref()));
            (id, rrf_score + bonus)
        })
        .collect();
    reranked.sort_by(|(id_a, s_a), (id_b, s_b)| s_b.total_cmp(s_a).then_with(|| id_a.cmp(id_b)));
    let reranked_doc_ids = reranked.into_iter().take(top_k).map(|(id, _)| id).collect();

    Ok(HybridRetrievalTrace {
        query_language,
        parsed_pico,
        lexical_doc_ids,
        dense_doc_ids,
        rrf_fused_doc_ids,
        reranked_doc_ids,
    })
}

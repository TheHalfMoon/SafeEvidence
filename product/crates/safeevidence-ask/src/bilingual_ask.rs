//! Bilingual Arabic/English PICO query normalization, FTS5 BM25 retrieval, and exact raw-scalar
//! span Ask path (`WP-06`, `TA-08`).
//!
//! Preserves existing English-only `safeevidence_ask::ask()` unchanged while providing an explicit
//! bilingual corpus and query path (`BilingualCorpus`, `ask_bilingual`, `retrieve_bilingual`)
//! backed by `safeevidence_contracts::bilingual::NormalizedText` so vocalized Arabic (`harakat`,
//! `tatweel`, Arabic-Indic numerals) and English parallel queries map to canonical synthetic PICO
//! concepts and project cited spans back to exact raw Unicode scalar coordinates.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, params};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::bilingual::{
    NormalizedText, contains_arabic_script, extract_raw_scalar_span, is_forbidden_bidi_control,
};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{
    AnswerProofManifest, ApplicabilityState, ContradictionState, EvidenceSpan, ProofClaim,
    ProofComponents, SupportLabel, commit_defects,
};
use safeevidence_contracts::study::{Known, PublicationState, ScopedId, StudyId};
use serde::{Deserialize, Serialize};

use crate::{AskResult, Direction, Exclusion, Funnel};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextLanguage {
    En,
    Ar,
}

/// Maps one synthetic PICO concept identifier (`concept_id`) to its accepted English and Arabic
/// surface phrases (normalized at load time via `NormalizedText::build`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BilingualConcept {
    pub concept_id: String,
    pub en_terms: Vec<String>,
    pub ar_terms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BilingualDocument {
    pub doc_id: String,
    pub study_id: String,
    pub language: TextLanguage,
    pub title: String,
    pub text: String,
    pub finding: String,
    pub population_concept: String,
    pub condition_concept: String,
    pub intervention_concept: String,
    pub direction: Direction,
    pub publication_state: PublicationState,
    pub rights: EvidenceCorpusRights,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BilingualCorpus {
    pub description: String,
    pub validity_epoch: u64,
    pub rights_grant_version: String,
    /// When `false`, Arabic queries return reason-coded `ABSTAIN` (`UNSUPPORTED_LANGUAGE`),
    /// exercising the VS-1 unpromoted gate of `TA-08`.
    #[serde(default)]
    pub arabic_path_promoted: bool,
    #[serde(default)]
    pub quality_appraised: bool,
    pub lexicon: Vec<BilingualConcept>,
    pub documents: Vec<BilingualDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedBilingualQuestion {
    pub language: TextLanguage,
    pub intervention_concept: Option<String>,
    pub population_concept: Option<String>,
    pub condition_concept: Option<String>,
    pub raw_intervention: String,
    pub raw_population: Option<String>,
    pub raw_condition: String,
}

const AR_PATIENT_SPECIFIC: &[&str] = &[
    "\u{0645}\u{0631}\u{064a}\u{0636}\u{064a}",
    "\u{0647}\u{0630}\u{0627} \u{0627}\u{0644}\u{0645}\u{0631}\u{064a}\u{0636}",
    "\u{0637}\u{0641}\u{0644}\u{064a}",
    "\u{0648}\u{0627}\u{0644}\u{062f}\u{064a}",
    "\u{0648}\u{0627}\u{0644}\u{062f}\u{062a}\u{064a}",
    "\u{0647}\u{0644} \u{0627}\u{0635}\u{0641}",
    "\u{0647}\u{0644} \u{0627}\u{0639}\u{0637}\u{064a}",
];

const EN_PATIENT_SPECIFIC: &[&str] = &[
    "my patient",
    "this patient",
    "my child",
    "my mother",
    "my father",
    "should i give",
    "should i prescribe",
];

const AR_NEGATIONS: &[&str] = &[
    "\u{0644}\u{0627}",
    "\u{0644}\u{0645}",
    "\u{0644}\u{0646}",
    "\u{0644}\u{064a}\u{0633}",
    "\u{062f}\u{0648}\u{0646}",
    "\u{0628}\u{062f}\u{0648}\u{0646}",
    "\u{063a}\u{064a}\u{0631}",
];

const EN_NEGATIONS: &[&str] = &[
    "not",
    "no",
    "never",
    "without",
    "didnt",
    "doesnt",
    "unchanged",
    "similar",
    "comparable",
    "nonsignificant",
    "ineffective",
];

fn collapse_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn norm_phrase(raw: &str) -> Option<String> {
    let norm = NormalizedText::build(raw).ok()?;
    Some(collapse_ws(norm.as_str()))
}

fn is_bilingual_patient_specific(norm_question: &str) -> bool {
    EN_PATIENT_SPECIFIC
        .iter()
        .any(|p| norm_question.contains(p))
        || AR_PATIENT_SPECIFIC
            .iter()
            .any(|p| norm_phrase(p).is_some_and(|np| norm_question.contains(&np)))
}

fn has_non_en_ar_script(raw: &str) -> bool {
    raw.chars().any(|c| {
        if c.is_ascii() {
            return c.is_ascii_control() && c != '\n';
        }
        if is_forbidden_bidi_control(c) {
            return true;
        }
        !matches!(
            c,
            '\u{0600}'..='\u{06FF}'
                | '\u{0750}'..='\u{08FF}'
                | '\u{FB50}'..='\u{FDFF}'
                | '\u{FE70}'..='\u{FEFF}'
        )
    })
}

fn lookup_concept(lexicon: &[BilingualConcept], raw_term: &str) -> Option<String> {
    let target = norm_phrase(raw_term)?;
    for entry in lexicon {
        let matches_en = entry
            .en_terms
            .iter()
            .any(|t| norm_phrase(t).as_deref() == Some(target.as_str()));
        let matches_ar = entry
            .ar_terms
            .iter()
            .any(|t| norm_phrase(t).as_deref() == Some(target.as_str()));
        if matches_en || matches_ar {
            return Some(entry.concept_id.clone());
        }
    }
    None
}

/// Parses either:
/// - English: `does <intervention> help [<population>] with <condition>?`
/// - Arabic: `hal yusa'id <intervention> [<population>] ma'a <condition>?` (or `hal yufid ... fi ...?`)
#[must_use]
pub fn parse_bilingual_question(
    raw: &str,
    lexicon: &[BilingualConcept],
) -> Option<ParsedBilingualQuestion> {
    let norm = norm_phrase(raw)?;
    let body = norm.strip_suffix('?').unwrap_or(&norm).trim();

    if let Some(rest) = body.strip_prefix("does ") {
        let (intervention, after_help) = rest.split_once(" help ")?;
        let (population, condition) = match after_help.strip_prefix("with ") {
            Some(cond) => (None, cond),
            None => {
                let (pop, cond) = after_help.split_once(" with ")?;
                (Some(pop), cond)
            }
        };
        if intervention.is_empty() || condition.is_empty() {
            return None;
        }
        return Some(ParsedBilingualQuestion {
            language: TextLanguage::En,
            intervention_concept: lookup_concept(lexicon, intervention),
            population_concept: population.and_then(|p| lookup_concept(lexicon, p)),
            condition_concept: lookup_concept(lexicon, condition),
            raw_intervention: intervention.to_owned(),
            raw_population: population.map(str::to_owned),
            raw_condition: condition.to_owned(),
        });
    }

    // Normalized Arabic prefixes: `hal yusa'id ` or `hal yufid `
    let ar_help_1 = norm_phrase("\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f} ")?;
    let ar_help_2 = norm_phrase("\u{0647}\u{0644} \u{064a}\u{0641}\u{064a}\u{062f} ")?;
    let ar_with_1 = norm_phrase("\u{0645}\u{0639}")?;
    let ar_with_2 = norm_phrase("\u{0641}\u{064a}")?;

    let rest = body
        .strip_prefix(&format!("{ar_help_1} "))
        .or_else(|| body.strip_prefix(&format!("{ar_help_2} ")))?;

    let (left, condition) = rest
        .split_once(&format!(" {ar_with_1} "))
        .or_else(|| rest.split_once(&format!(" {ar_with_2} ")))?;

    // Determine whether `left` is `<intervention>` alone or `<intervention> <population>` by
    // checking lexicon concept splits first, falling back to single intervention phrase.
    let words: Vec<&str> = left.split_whitespace().collect();
    let mut resolved: Option<(&str, Option<&str>)> = None;
    if lookup_concept(lexicon, left).is_some() {
        resolved = Some((left, None));
    } else {
        for split_idx in 1..words.len() {
            let cand_int = words[..split_idx].join(" ");
            let cand_pop = words[split_idx..].join(" ");
            if lookup_concept(lexicon, &cand_int).is_some()
                && lookup_concept(lexicon, &cand_pop).is_some()
            {
                let byte_pos = left.rfind(&cand_pop)?;
                resolved = Some((left[..byte_pos].trim(), Some(left[byte_pos..].trim())));
                break;
            }
        }
    }
    let (intervention, population) = resolved.unwrap_or((left, None));
    if intervention.is_empty() || condition.is_empty() {
        return None;
    }

    Some(ParsedBilingualQuestion {
        language: TextLanguage::Ar,
        intervention_concept: lookup_concept(lexicon, intervention),
        population_concept: population.and_then(|p| lookup_concept(lexicon, p)),
        condition_concept: lookup_concept(lexicon, condition),
        raw_intervention: intervention.to_owned(),
        raw_population: population.map(str::to_owned),
        raw_condition: condition.to_owned(),
    })
}

fn concept_expansion_tokens(lexicon: &[BilingualConcept], concept_id: &str) -> String {
    let Some(entry) = lexicon.iter().find(|e| e.concept_id == concept_id) else {
        return concept_id.to_owned();
    };
    let mut parts = vec![entry.concept_id.clone()];
    for term in entry.en_terms.iter().chain(entry.ar_terms.iter()) {
        if let Some(np) = norm_phrase(term) {
            parts.push(np);
        }
    }
    parts.join(" ")
}

/// Builds a normalized bilingual SQLite FTS5 index over `corpus` and returns ranked `doc_id`s
/// (`bm25()`, ties broken by `doc_id`) up to `max_hits` (`TA-08` parallel retrieval).
///
/// # Errors
/// Fails closed if SQLite FTS5 or Unicode normalization fails.
pub fn retrieve_bilingual(
    corpus: &BilingualCorpus,
    parsed: &ParsedBilingualQuestion,
    max_hits: usize,
) -> Result<Vec<String>, String> {
    let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE bilingual_evidence USING fts5(doc_id UNINDEXED, title, body, concepts)",
    )
    .map_err(|e| e.to_string())?;

    for doc in &corpus.documents {
        let norm_title = NormalizedText::build(&doc.title)
            .map_err(|e| format!("{e:?}"))?
            .as_str()
            .to_owned();
        let norm_body = NormalizedText::build(&doc.text)
            .map_err(|e| format!("{e:?}"))?
            .as_str()
            .to_owned();
        let concepts = [
            concept_expansion_tokens(&corpus.lexicon, &doc.condition_concept),
            concept_expansion_tokens(&corpus.lexicon, &doc.intervention_concept),
            concept_expansion_tokens(&corpus.lexicon, &doc.population_concept),
        ]
        .join(" ");
        conn.execute(
            "INSERT INTO bilingual_evidence (doc_id, title, body, concepts) VALUES (?1, ?2, ?3, ?4)",
            params![doc.doc_id, norm_title, norm_body, concepts],
        )
        .map_err(|e| e.to_string())?;
    }

    let cond_term = parsed
        .condition_concept
        .as_deref()
        .unwrap_or(parsed.raw_condition.as_str());
    let int_term = parsed
        .intervention_concept
        .as_deref()
        .unwrap_or(parsed.raw_intervention.as_str());
    let query_expr = format!(
        "\"{}\" AND \"{}\"",
        cond_term.replace('"', "\"\""),
        int_term.replace('"', "\"\"")
    );

    let mut stmt = conn
        .prepare(
            "SELECT doc_id FROM bilingual_evidence WHERE bilingual_evidence MATCH ?1 \
             ORDER BY bm25(bilingual_evidence), doc_id LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;
    let limit = i64::try_from(max_hits).unwrap_or(50);
    let rows = stmt
        .query_map(params![query_expr, limit], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

fn finding_polarity_matches(doc: &BilingualDocument) -> Result<bool, String> {
    let norm = NormalizedText::build(&doc.finding).map_err(|e| format!("{e:?}"))?;
    let words: BTreeSet<String> = norm
        .as_str()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect();
    let en_neg = EN_NEGATIONS.iter().any(|w| words.contains(*w));
    let ar_neg = AR_NEGATIONS
        .iter()
        .any(|w| norm_phrase(w).is_some_and(|nw| words.contains(&nw)));
    let reports_no_benefit = en_neg || ar_neg;
    Ok(reports_no_benefit == (doc.direction == Direction::NoBenefit))
}

/// Projects `doc.finding` inside `doc.text` via normalized Unicode scalar coordinates back to raw
/// scalar coordinates (`EvidenceSpan`) and verifies `extract_raw_scalar_span` round-trips!
pub fn project_bilingual_finding_span(doc: &BilingualDocument) -> Result<EvidenceSpan, String> {
    let norm_text = NormalizedText::build(&doc.text).map_err(|e| format!("{e:?}"))?;
    let norm_finding = NormalizedText::build(&doc.finding).map_err(|e| format!("{e:?}"))?;
    if norm_finding.as_str().is_empty() {
        return Err("empty finding".to_owned());
    }
    let haystack = norm_text.as_str();
    let needle = norm_finding.as_str();
    let matches: Vec<usize> = haystack.match_indices(needle).map(|(idx, _)| idx).collect();
    if matches.len() != 1 {
        return Err("finding must appear uniquely in normalized document text".to_owned());
    }
    let byte_start = matches[0];
    let norm_start = haystack[..byte_start].chars().count();
    let norm_end = norm_start + needle.chars().count();
    let (raw_start, raw_end) = norm_text
        .project_norm_span_to_raw(norm_start, norm_end)
        .map_err(|e| format!("{e:?}"))?;
    let raw_slice =
        extract_raw_scalar_span(&doc.text, raw_start, raw_end).map_err(|e| format!("{e:?}"))?;
    let renormalized_slice = NormalizedText::build(raw_slice).map_err(|e| format!("{e:?}"))?;
    if renormalized_slice.as_str() != needle {
        return Err("projected raw span did not re-normalize to identical finding".to_owned());
    }
    Ok(EvidenceSpan {
        source_id: doc.doc_id.clone(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(doc.text.as_bytes()),
        start_scalar: raw_start,
        end_scalar: raw_end,
    })
}

fn validate_bilingual_corpus(corpus: &BilingualCorpus) -> Result<(), String> {
    if corpus.validity_epoch == 0
        || corpus.rights_grant_version.trim().is_empty()
        || corpus.documents.is_empty()
    {
        return Err("invalid corpus header".to_owned());
    }
    let mut seen = BTreeSet::new();
    for doc in &corpus.documents {
        if !seen.insert(doc.doc_id.as_str()) {
            return Err(format!("duplicate doc_id {}", doc.doc_id));
        }
        if has_non_en_ar_script(&doc.text) || has_non_en_ar_script(&doc.finding) {
            return Err(format!(
                "forbidden script or bidi control in {}",
                doc.doc_id
            ));
        }
        if !finding_polarity_matches(doc)? {
            return Err(format!("polarity mismatch in {}", doc.doc_id));
        }
        project_bilingual_finding_span(doc)?;
    }
    Ok(())
}

/// Evaluates an English or Arabic clinical evidence question over a `BilingualCorpus` (`WP-06`,
/// `TA-08`).
///
/// - Patient-specific care requests in English or Arabic always return `ESCALATE` (`Guard 2`).
/// - Unsupported scripts or BiDi override characters return `ABSTAIN` (`UNSUPPORTED_LANGUAGE`).
/// - When `corpus.arabic_path_promoted == false`, Arabic queries return `ABSTAIN`
///   (`UNSUPPORTED_LANGUAGE`) (`TA-08` VS-1 unpromoted contract).
/// - Unmapped Arabic/English terms return `ABSTAIN` (`EVIDENCE_INSUFFICIENT`), missing population
///   returns `ASK_MORE` (`MISSING_CRITICAL_CONTEXT`) when an answerable population exists, and
///   valid bilingual hits produce exact raw-scalar `EvidenceSpan`s in `AnswerProofManifest`.
#[must_use]
pub fn ask_bilingual(question_text: &str, corpus: &BilingualCorpus) -> AskResult {
    let mut funnel = Funnel {
        indexed: corpus.documents.len(),
        ..Funnel::default()
    };
    let refuse = |outcome, reason, funnel: &Funnel, excluded: &[Exclusion]| AskResult {
        outcome,
        reason,
        brief: None,
        manifest: None,
        excluded: excluded.to_vec(),
        funnel: funnel.clone(),
    };

    if validate_bilingual_corpus(corpus).is_err() {
        return refuse(
            TerminalOutcome::Blocked,
            ReasonCode::ToolFailure,
            &funnel,
            &[],
        );
    }

    if let Some(norm_q) = norm_phrase(question_text)
        && is_bilingual_patient_specific(&norm_q)
    {
        return refuse(
            TerminalOutcome::Escalate,
            ReasonCode::ClinicianAuthorityRequired,
            &funnel,
            &[],
        );
    }

    if has_non_en_ar_script(question_text) {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::UnsupportedLanguage,
            &funnel,
            &[],
        );
    }

    if contains_arabic_script(question_text) && !corpus.arabic_path_promoted {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::UnsupportedLanguage,
            &funnel,
            &[],
        );
    }

    let Some(parsed) = parse_bilingual_question(question_text, &corpus.lexicon) else {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            &funnel,
            &[],
        );
    };

    let Ok(retrieved) = retrieve_bilingual(corpus, &parsed, 50) else {
        return refuse(
            TerminalOutcome::Blocked,
            ReasonCode::ToolFailure,
            &funnel,
            &[],
        );
    };
    funnel.retrieved = retrieved.len();

    let (Some(cond_id), Some(int_id)) = (&parsed.condition_concept, &parsed.intervention_concept)
    else {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            &funnel,
            &[],
        );
    };

    if parsed.raw_population.is_some() && parsed.population_concept.is_none() {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::ApplicabilityUnresolved,
            &funnel,
            &[],
        );
    }

    let matching: Vec<&BilingualDocument> = corpus
        .documents
        .iter()
        .filter(|d| &d.condition_concept == cond_id && &d.intervention_concept == int_id)
        .collect();
    if matching.is_empty() {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            &funnel,
            &[],
        );
    }

    let mut excluded = Vec::new();
    if matching.iter().any(|d| !d.rights.admissible()) {
        for d in matching.iter().filter(|d| !d.rights.admissible()) {
            excluded.push(Exclusion {
                doc_id: d.doc_id.clone(),
                reason: ReasonCode::RightsUnresolved,
                detail: "rights not established".to_owned(),
            });
        }
        return refuse(
            TerminalOutcome::Blocked,
            ReasonCode::RightsUnresolved,
            &funnel,
            &excluded,
        );
    }
    funnel.rights_admissible = matching.len();

    let withdrawn_studies: BTreeSet<&str> = corpus
        .documents
        .iter()
        .filter(|d| {
            matches!(
                d.publication_state,
                PublicationState::Retracted | PublicationState::Withdrawn
            )
        })
        .map(|d| d.study_id.as_str())
        .collect();

    let citable: Vec<&BilingualDocument> = matching
        .iter()
        .copied()
        .filter(|d| {
            !withdrawn_studies.contains(d.study_id.as_str()) && d.publication_state.citable()
        })
        .collect();
    funnel.citable = citable.len();
    if citable.is_empty() {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::SourceInvalidOrRetracted,
            &funnel,
            &excluded,
        );
    }

    let Some(pop_id) = &parsed.population_concept else {
        let has_answerable = citable.iter().any(|d| retrieved.contains(&d.doc_id));
        return if has_answerable {
            refuse(
                TerminalOutcome::AskMore,
                ReasonCode::MissingCriticalContext,
                &funnel,
                &excluded,
            )
        } else {
            refuse(
                TerminalOutcome::Abstain,
                ReasonCode::EvidenceInsufficient,
                &funnel,
                &excluded,
            )
        };
    };

    let applicable: Vec<&BilingualDocument> = citable
        .into_iter()
        .filter(|d| {
            if &d.population_concept == pop_id {
                true
            } else {
                excluded.push(Exclusion {
                    doc_id: d.doc_id.clone(),
                    reason: ReasonCode::ApplicabilityUnresolved,
                    detail: format!(
                        "population {} does not match {pop_id}",
                        d.population_concept
                    ),
                });
                false
            }
        })
        .collect();
    funnel.applicable = applicable.len();
    if applicable.is_empty() {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::ApplicabilityUnresolved,
            &funnel,
            &excluded,
        );
    }

    let mut study_dirs: BTreeMap<&str, BTreeSet<Direction>> = BTreeMap::new();
    for doc in &applicable {
        let dirs = study_dirs.entry(doc.study_id.as_str()).or_default();
        dirs.insert(doc.direction);
    }
    funnel.independent_studies = study_dirs.len();
    let all_dirs: BTreeSet<Direction> = study_dirs.values().flatten().copied().collect();
    if all_dirs.len() > 1 && study_dirs.len() > 1 {
        return refuse(
            TerminalOutcome::Conflict,
            ReasonCode::MaterialContradiction,
            &funnel,
            &excluded,
        );
    }
    if study_dirs.values().any(|dirs| dirs.len() > 1) {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            &funnel,
            &excluded,
        );
    }

    let retrieved_applicable: Vec<&BilingualDocument> = applicable
        .iter()
        .copied()
        .filter(|d| retrieved.contains(&d.doc_id))
        .collect();
    if retrieved_applicable.is_empty() {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            &funnel,
            &excluded,
        );
    }

    let mut claims = Vec::new();
    let mut lines = vec![
        "Synthetic bilingual evidence brief. Invented fixture data; not medical information."
            .to_owned(),
        "Limits: synthetic bilingual fixture evidence; language mapping is glossary-bound."
            .to_owned(),
    ];
    for doc in &retrieved_applicable {
        let Ok(span) = project_bilingual_finding_span(doc) else {
            return refuse(
                TerminalOutcome::Abstain,
                ReasonCode::PostVerificationFailed,
                &funnel,
                &excluded,
            );
        };
        let Ok(raw_quote) = extract_raw_scalar_span(&doc.text, span.start_scalar, span.end_scalar)
        else {
            return refuse(
                TerminalOutcome::Abstain,
                ReasonCode::PostVerificationFailed,
                &funnel,
                &excluded,
            );
        };
        lines.push(format!(
            "- {} [{} {}..{}]",
            raw_quote, doc.doc_id, span.start_scalar, span.end_scalar
        ));
        claims.push(ProofClaim {
            claim_id: doc.doc_id.clone(),
            material: true,
            support: SupportLabel::Supported,
            spans: vec![span],
            studies: Known::Known(vec![StudyId(ScopedId {
                scope: "wp06-bilingual".to_owned(),
                id: doc.study_id.clone(),
                version: 1,
            })]),
            results: Known::Unknown {
                reason: "synthetic bilingual fixture".to_owned(),
            },
        });
    }
    funnel.verified_claims = claims.len();
    let brief = lines.join("\n");
    let norm_q = norm_phrase(question_text).unwrap_or_default();
    let mut manifest = AnswerProofManifest {
        proof_id: String::new(),
        question_snapshot_digest: DigestSha256::of(norm_q.as_bytes()),
        final_text_digest: DigestSha256::of(brief.as_bytes()),
        claims,
        rights_grant_version: corpus.rights_grant_version.clone(),
        validity_epoch: corpus.validity_epoch,
        components: ProofComponents {
            retriever: "fts5-bm25-bilingual-1".to_owned(),
            reranker: None,
            translator: Some("glossary-pico-1".to_owned()),
            ocr: None,
            verifier: "bilingual-span-projection-1".to_owned(),
            generator: None,
            tools: vec![],
            prompts: vec![],
            policy: "wp06-bilingual-guards-1".to_owned(),
            thresholds: "none".to_owned(),
        },
        applicability: ApplicabilityState::ApplicableWithLimits,
        contradiction: ContradictionState::None,
        outcome: TerminalOutcome::AnswerWithCaution,
        reason: ReasonCode::None,
        post_verification_passed: true,
        verified_at_utc: "fixture-time".to_owned(),
        state: ProofState::VerifiedUncommitted,
    };
    let mut basis = manifest.clone();
    basis.verified_at_utc.clear();
    manifest.proof_id = serde_json::to_vec(&basis)
        .map(|bytes| format!("wp06-{}", DigestSha256::of(&bytes).to_hex()))
        .unwrap_or_default();
    if !commit_defects(&manifest).is_empty() {
        return refuse(
            TerminalOutcome::Blocked,
            ReasonCode::PostVerificationFailed,
            &funnel,
            &excluded,
        );
    }

    AskResult {
        outcome: TerminalOutcome::AnswerWithCaution,
        reason: ReasonCode::None,
        brief: Some(brief),
        manifest: Some(manifest),
        excluded,
        funnel,
    }
}

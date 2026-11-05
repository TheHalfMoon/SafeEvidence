//! Headless Ask path over a synthetic fixture (VS-1a, step 1 of `plan-v1.1` §C).
//!
//! Stops at `VERIFIED_UNCOMMITTED`: nothing here commits to a vault, and nothing is a clinical
//! answer. The fixture is invented. Query parsing matches the fixture's own vocabulary, so this
//! proves the pipeline's control flow, not retrieval quality or real-world question handling.

use std::collections::BTreeSet;

use rusqlite::{Connection, params};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{
    AnswerProofManifest, ApplicabilityState, ContradictionState, EvidenceSpan, ProofClaim,
    ProofComponents, SupportLabel, commit_defects,
};
use safeevidence_contracts::study::{Known, PublicationState, ScopedId, StudyId};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub doc_id: String,
    pub study_id: String,
    pub title: String,
    pub text: String,
    pub population: String,
    pub condition: String,
    pub intervention: String,
    pub finding: String,
    pub direction: String,
    pub publication_state: PublicationState,
    pub rights: EvidenceCorpusRights,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub description: String,
    pub validity_epoch: u64,
    pub rights_grant_version: String,
    pub documents: Vec<Document>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CorpusError {
    DigestMismatch,
    Malformed(String),
    MissingValidityEpoch,
    MissingRightsGrant,
    Empty,
    DuplicateDocument(String),
}

/// Digest-checked fixture loader. It gives no pack-trust claim (`plan-v1.1` §C).
///
/// # Errors
/// Fails closed on a wrong digest, malformed content, or absent epoch or rights grant.
pub fn load_corpus(bytes: &[u8], expected: &DigestSha256) -> Result<Corpus, CorpusError> {
    if &DigestSha256::of(bytes) != expected {
        return Err(CorpusError::DigestMismatch);
    }
    let corpus: Corpus =
        serde_json::from_slice(bytes).map_err(|error| CorpusError::Malformed(error.to_string()))?;
    if corpus.validity_epoch == 0 {
        return Err(CorpusError::MissingValidityEpoch);
    }
    if corpus.rights_grant_version.trim().is_empty() {
        return Err(CorpusError::MissingRightsGrant);
    }
    if corpus.documents.is_empty() {
        return Err(CorpusError::Empty);
    }
    let mut seen = BTreeSet::new();
    for document in &corpus.documents {
        if !seen.insert(document.doc_id.as_str()) {
            return Err(CorpusError::DuplicateDocument(document.doc_id.clone()));
        }
    }
    Ok(corpus)
}

/// How many items survived each stage. Present in every trace, including refusals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Funnel {
    pub indexed: usize,
    pub retrieved: usize,
    pub citable: usize,
    pub rights_admissible: usize,
    pub applicable: usize,
    pub independent_studies: usize,
    pub verified_claims: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub condition: Option<String>,
    pub intervention: Option<String>,
    pub population: Option<String>,
}

#[derive(Debug)]
pub struct AskResult {
    pub outcome: TerminalOutcome,
    pub reason: ReasonCode,
    pub brief: Option<String>,
    pub manifest: Option<AnswerProofManifest>,
    pub excluded: Vec<(String, String)>,
    pub funnel: Funnel,
}

impl AskResult {
    fn refuse(outcome: TerminalOutcome, reason: ReasonCode, funnel: Funnel) -> Self {
        Self {
            outcome,
            reason,
            brief: None,
            manifest: None,
            excluded: Vec::new(),
            funnel,
        }
    }
}

fn contains_arabic(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c, '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' | '\u{08A0}'..='\u{08FF}'))
}

/// Requests for a named individual's care are out of V1 scope. This looks for a request about a
/// specific patient, never for symptoms: symptom words alone do not escalate.
fn is_patient_specific_request(lower: &str) -> bool {
    [
        "my patient",
        "this patient",
        "my child",
        "my mother",
        "my father",
        "should i give",
        "should i prescribe",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

/// Matches the question against the corpus vocabulary. Whole-word only, and unmatched means None.
#[must_use]
pub fn parse_question(text: &str, corpus: &Corpus) -> Question {
    let lower = text.to_lowercase();
    let words: BTreeSet<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    let has_term = |term: &str| term.split(' ').all(|part| words.contains(part));
    let find = |field: fn(&Document) -> &str| {
        corpus
            .documents
            .iter()
            .map(field)
            .find(|term| has_term(&term.to_lowercase()))
            .map(str::to_owned)
    };
    Question {
        condition: find(|d| &d.condition),
        intervention: find(|d| &d.intervention),
        population: find(|d| &d.population),
    }
}

fn build_index(corpus: &Corpus) -> rusqlite::Result<Connection> {
    let connection = Connection::open_in_memory()?;
    connection
        .execute_batch("CREATE VIRTUAL TABLE evidence USING fts5(doc_id UNINDEXED, title, body)")?;
    for document in &corpus.documents {
        connection.execute(
            "INSERT INTO evidence (doc_id, title, body) VALUES (?1, ?2, ?3)",
            params![document.doc_id, document.title, document.text],
        )?;
    }
    Ok(connection)
}

fn retrieve(connection: &Connection, terms: &[&str]) -> rusqlite::Result<Vec<String>> {
    let quoted: Vec<String> = terms
        .iter()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect();
    let mut statement = connection
        .prepare("SELECT doc_id FROM evidence WHERE evidence MATCH ?1 ORDER BY bm25(evidence)")?;
    let rows = statement.query_map(params![quoted.join(" AND ")], |row| row.get(0))?;
    rows.collect()
}

fn numeric_tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|token| token.trim_matches('.'))
        .filter(|token| !token.is_empty())
        .collect()
}

fn word_set(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

const NEGATIONS: [&str; 6] = ["not", "no", "never", "without", "neither", "nor"];
const UNITS: [&str; 7] = ["mg", "g", "mcg", "kg", "ml", "weeks", "points"];

/// Why a claim does not match its source span, or `None` if it does.
///
/// A deterministic check: exact text first, then facets named so a failure explains itself. It
/// says nothing about whether the source is true or applies to anyone.
#[must_use]
pub fn claim_defect(claim: &str, source: &str) -> Option<&'static str> {
    if source.contains(claim) {
        return None;
    }
    let (claim_words, source_words) = (word_set(claim), word_set(source));
    if numeric_tokens(claim) != numeric_tokens(source) {
        return Some("number");
    }
    let differs = |list: &[&str]| {
        list.iter()
            .any(|word| claim_words.contains(*word) != source_words.contains(*word))
    };
    if differs(&NEGATIONS) {
        return Some("negation");
    }
    if differs(&UNITS) {
        return Some("unit");
    }
    Some("text")
}

fn span_of(document: &Document) -> Option<EvidenceSpan> {
    let start = document.text.find(&document.finding)?;
    let start_scalar = document.text[..start].chars().count() as u64;
    Some(EvidenceSpan {
        source_id: document.doc_id.clone(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(document.text.as_bytes()),
        start_scalar,
        end_scalar: start_scalar + document.finding.chars().count() as u64,
    })
}

fn render_brief(claims: &[(&Document, EvidenceSpan)]) -> String {
    let mut lines = vec![
        "Synthetic evidence brief. Invented fixture data; not medical information.".to_owned(),
        "Limits: fixture evidence only, and no appraisal of study quality.".to_owned(),
    ];
    for (document, span) in claims {
        lines.push(format!(
            "- {} [{} {}..{}]",
            document.finding, document.doc_id, span.start_scalar, span.end_scalar
        ));
    }
    lines.join("\n")
}

fn scoped(id: &str) -> ScopedId {
    ScopedId {
        scope: "vs1a-fixture".to_owned(),
        id: id.to_owned(),
        version: 1,
    }
}

fn index_failure(funnel: Funnel) -> AskResult {
    AskResult::refuse(TerminalOutcome::Blocked, ReasonCode::ToolFailure, funnel)
}

/// Runs one question through the guards of `P00_DECISION_ASSURANCE_CONTRACT.md` in their order.
/// Every path returns exactly one outcome, reason and funnel.
#[must_use]
pub fn ask(text: &str, corpus: &Corpus) -> AskResult {
    let mut funnel = Funnel {
        indexed: corpus.documents.len(),
        ..Funnel::default()
    };
    if contains_arabic(text) {
        return AskResult::refuse(
            TerminalOutcome::Abstain,
            ReasonCode::UnsupportedLanguage,
            funnel,
        );
    }
    if is_patient_specific_request(&text.to_lowercase()) {
        return AskResult::refuse(
            TerminalOutcome::Escalate,
            ReasonCode::ClinicianAuthorityRequired,
            funnel,
        );
    }
    let question = parse_question(text, corpus);
    let (Some(condition), Some(intervention)) = (&question.condition, &question.intervention)
    else {
        return AskResult::refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            funnel,
        );
    };

    let Ok(connection) = build_index(corpus) else {
        return index_failure(funnel);
    };
    let Ok(retrieved) = retrieve(&connection, &[condition, intervention]) else {
        return index_failure(funnel);
    };
    funnel.retrieved = retrieved.len();
    let documents: Vec<&Document> = retrieved
        .iter()
        .filter_map(|id| corpus.documents.iter().find(|d| &d.doc_id == id))
        .filter(|d| &d.condition == condition && &d.intervention == intervention)
        .collect();

    let mut excluded = Vec::new();
    let citable: Vec<&Document> = documents
        .iter()
        .copied()
        .filter(|document| {
            let keep = document.publication_state.citable();
            if !keep {
                excluded.push((document.doc_id.clone(), "not citable".to_owned()));
            }
            keep
        })
        .collect();
    funnel.citable = citable.len();
    let with_excluded = |mut result: AskResult, excluded: &Vec<(String, String)>| {
        result.excluded.clone_from(excluded);
        result
    };
    if citable.is_empty() {
        let reason = if documents.is_empty() {
            ReasonCode::EvidenceInsufficient
        } else {
            ReasonCode::SourceInvalidOrRetracted
        };
        return with_excluded(
            AskResult::refuse(TerminalOutcome::Abstain, reason, funnel),
            &excluded,
        );
    }

    // An unsupported rights grant is not weak evidence: it denies presentation outright.
    if citable.iter().any(|document| !document.rights.admissible()) {
        for document in citable.iter().filter(|d| !d.rights.admissible()) {
            excluded.push((document.doc_id.clone(), "rights not established".to_owned()));
        }
        return with_excluded(
            AskResult::refuse(
                TerminalOutcome::Blocked,
                ReasonCode::RightsUnresolved,
                funnel,
            ),
            &excluded,
        );
    }
    funnel.rights_admissible = citable.len();

    // Population decides applicability, so it must be known before evidence is weighed.
    let Some(population) = &question.population else {
        return with_excluded(
            AskResult::refuse(
                TerminalOutcome::AskMore,
                ReasonCode::MissingCriticalContext,
                funnel,
            ),
            &excluded,
        );
    };
    let applicable: Vec<&Document> = citable
        .iter()
        .copied()
        .filter(|document| {
            let keep = &document.population == population;
            if !keep {
                excluded.push((
                    document.doc_id.clone(),
                    format!(
                        "population {} does not match {population}",
                        document.population
                    ),
                ));
            }
            keep
        })
        .collect();
    funnel.applicable = applicable.len();
    if applicable.is_empty() {
        return with_excluded(
            AskResult::refuse(
                TerminalOutcome::Abstain,
                ReasonCode::ApplicabilityUnresolved,
                funnel,
            ),
            &excluded,
        );
    }

    let studies: BTreeSet<&str> = applicable.iter().map(|d| d.study_id.as_str()).collect();
    funnel.independent_studies = studies.len();
    let directions: BTreeSet<&str> = applicable.iter().map(|d| d.direction.as_str()).collect();
    if directions.len() > 1 {
        return with_excluded(
            AskResult::refuse(
                TerminalOutcome::Conflict,
                ReasonCode::MaterialContradiction,
                funnel,
            ),
            &excluded,
        );
    }

    let mut claims = Vec::new();
    for document in &applicable {
        match span_of(document) {
            Some(span) => claims.push((*document, span)),
            None => {
                return with_excluded(
                    AskResult::refuse(
                        TerminalOutcome::Abstain,
                        ReasonCode::PostVerificationFailed,
                        funnel,
                    ),
                    &excluded,
                );
            }
        }
    }
    let brief = render_brief(&claims);
    // Verify the frozen text, not the inputs it was built from.
    let verified = claims.iter().all(|(document, _)| {
        brief.contains(&document.finding)
            && claim_defect(&document.finding, &document.text).is_none()
    });
    if !verified {
        return with_excluded(
            AskResult::refuse(
                TerminalOutcome::Abstain,
                ReasonCode::PostVerificationFailed,
                funnel,
            ),
            &excluded,
        );
    }
    funnel.verified_claims = claims.len();

    let manifest = AnswerProofManifest {
        proof_id: format!("vs1a-{}", DigestSha256::of(text.as_bytes()).to_hex()),
        question_snapshot_digest: DigestSha256::of(text.as_bytes()),
        final_text_digest: DigestSha256::of(brief.as_bytes()),
        claims: claims
            .iter()
            .map(|(document, span)| ProofClaim {
                claim_id: document.doc_id.clone(),
                material: true,
                support: SupportLabel::Supported,
                spans: vec![span.clone()],
                studies: Known::Known(vec![StudyId(scoped(&document.study_id))]),
                results: Known::Unknown {
                    reason: "fixture has no result identities".to_owned(),
                },
            })
            .collect(),
        rights_grant_version: corpus.rights_grant_version.clone(),
        validity_epoch: corpus.validity_epoch,
        components: ProofComponents {
            retriever: "fts5-bm25-fixture".to_owned(),
            reranker: None,
            translator: None,
            ocr: None,
            verifier: "deterministic-1".to_owned(),
            generator: None,
            tools: vec![],
            prompts: vec![],
            policy: "vs1a-guards-1".to_owned(),
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
    if !commit_defects(&manifest).is_empty() {
        return with_excluded(
            AskResult::refuse(
                TerminalOutcome::Blocked,
                ReasonCode::PostVerificationFailed,
                funnel,
            ),
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

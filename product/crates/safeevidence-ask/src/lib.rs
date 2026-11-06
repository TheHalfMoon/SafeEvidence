//! Headless Ask path over a synthetic fixture (VS-1a, step 1 of `plan-v1.1` §C).
//!
//! Stops at `VERIFIED_UNCOMMITTED`: nothing here commits to a vault, and nothing is a clinical
//! answer. The fixture is invented. Questions must fit one closed grammar, so this proves the
//! pipeline's control flow and refusals, not retrieval quality or real question handling.
//!
//! Evidence-based guards are gathered as fired rules and resolved by `safeevidence-assurance`.
//! Two checks run first, because no evidence is read for them: unsupported language, and
//! patient-specific requests. Tool failures and an invalid corpus also return directly.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, params};
use safeevidence_assurance::{Cause, FiredRule, Requirement, Resolution, evaluate_precedence};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{
    AnswerProofManifest, ApplicabilityState, ContradictionState, EvidenceSpan, ProofClaim,
    ProofComponents, SupportLabel, commit_defects,
};
use safeevidence_contracts::study::{Known, PublicationState, ScopedId, StudyId};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Benefit,
    NoBenefit,
}

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
    pub direction: Direction,
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
    FindingNotASourceSentence(String),
    DirectionContradictsFinding(String),
}

/// Words that reverse a finding. A word list, so `direction` remains partly the fixture author's
/// label: this catches mislabels it can recognize, and is not an understanding of meaning.
const NEGATIONS: [&str; 15] = [
    "not", "no", "never", "without", "neither", "nor", "didn", "doesn", "wasn", "failed", "fails",
    "worsened", "worse", "unable", "nobody",
];
const UNITS: [&str; 8] = ["mg", "g", "mcg", "kg", "ml", "weeks", "months", "points"];

fn word_set(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_negated(text: &str) -> bool {
    let words = word_set(text);
    NEGATIONS.iter().any(|word| words.contains(*word))
}

/// Digest-checked fixture loader. It gives no pack-trust claim (`plan-v1.1` §C).
///
/// # Errors
/// Fails closed on a wrong digest, malformed content, absent epoch or rights grant, a finding
/// that is not a whole source sentence, or a direction its finding's wording contradicts.
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
    validate_documents(&corpus)?;
    Ok(corpus)
}

/// Document rules every corpus must meet, however it was built.
///
/// # Errors
/// Returns the first duplicate, a finding that is not one whole source sentence, or a direction
/// its finding's wording contradicts.
pub fn validate_documents(corpus: &Corpus) -> Result<(), CorpusError> {
    if corpus.documents.is_empty() {
        return Err(CorpusError::Empty);
    }
    let mut seen = BTreeSet::new();
    for document in &corpus.documents {
        if !seen.insert(document.doc_id.as_str()) {
            return Err(CorpusError::DuplicateDocument(document.doc_id.clone()));
        }
        if claim_defect(&document.finding, &document.text).is_some()
            || sentence_positions(&document.text, &document.finding).len() != 1
        {
            return Err(CorpusError::FindingNotASourceSentence(
                document.doc_id.clone(),
            ));
        }
        if is_negated(&document.finding) != (document.direction == Direction::NoBenefit) {
            return Err(CorpusError::DirectionContradictsFinding(
                document.doc_id.clone(),
            ));
        }
    }
    Ok(())
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
    pub intervention: String,
    pub population: Option<String>,
    pub condition: String,
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

/// Only plain ASCII questions take the English path here. Any other letter, in Arabic script
/// or not, gets an explicit refusal rather than a partial reading.
fn has_unsupported_script(text: &str) -> bool {
    text.chars().any(|c| !c.is_ascii() && c.is_alphabetic())
}

fn normalized(text: &str) -> String {
    text.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Requests about one person's care are out of V1 scope. These are phrases about a person, never
/// symptoms. The list is incomplete: `my wife` passes it, and only exact population matching then
/// keeps such a question from a brief.
fn is_patient_specific_request(normalized: &str) -> bool {
    const PHRASES: [&str; 7] = [
        "my patient",
        "this patient",
        "my child",
        "my mother",
        "my father",
        "should i give",
        "should i prescribe",
    ];
    PHRASES.iter().any(|phrase| normalized.contains(phrase))
}

/// The one question form VS-1a accepts:
/// `does <intervention> help [<population>] with <condition>?`. Anything else is `None`.
/// Terms are not checked against the corpus here, so an unknown term can be reported as such.
#[must_use]
pub fn parse_question(text: &str) -> Option<Question> {
    let body = normalized(text);
    let body = body.strip_suffix('?').unwrap_or(&body);
    let rest = body.strip_prefix("does ")?;
    let (intervention, rest) = rest.split_once(" help ")?;
    let (population, condition) = match rest.strip_prefix("with ") {
        Some(condition) => (None, condition),
        None => {
            let (population, condition) = rest.split_once(" with ")?;
            (Some(population), condition)
        }
    };
    let is_term = |term: &str| {
        !term.is_empty() && term.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ')
    };
    if !is_term(intervention) || !is_term(condition) || population.is_some_and(|p| !is_term(p)) {
        return None;
    }
    Some(Question {
        intervention: intervention.to_owned(),
        population: population.map(str::to_owned),
        condition: condition.to_owned(),
    })
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

/// Numbers with their sign and decimal point, in any script's digits.
fn numeric_tokens(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_numeric() {
            let mut start = i;
            while i < chars.len()
                && (chars[i].is_numeric()
                    || (chars[i] == '.' && chars.get(i + 1).is_some_and(|c| c.is_numeric())))
            {
                i += 1;
            }
            if start > 0 && chars[start - 1] == '.' {
                start -= 1;
            }
            if start > 0 && chars[start - 1] == '-' {
                start -= 1;
            }
            tokens.push(chars[start..i].iter().collect());
        } else {
            i += 1;
        }
    }
    tokens
}

/// Sentences with their byte offsets. A boundary is a full stop, a space, then a capital letter,
/// so `0.5 mg` and `et al. that` stay inside their sentence. Splitting is heuristic: `Dr. Smith`
/// would split, which refuses a true claim rather than admitting a false one.
fn sentences_with_offsets(source: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut start = 0;
    for (index, _) in source.match_indices(". ") {
        let next = source[index + 2..].chars().next();
        if next.is_some_and(char::is_uppercase) {
            found.push((start, &source[start..=index]));
            start = index + 2;
        }
    }
    found.push((start, &source[start..]));
    found.retain(|(_, sentence)| !sentence.is_empty());
    found
}

fn sentences(source: &str) -> Vec<&str> {
    sentences_with_offsets(source)
        .into_iter()
        .map(|(_, sentence)| sentence)
        .collect()
}

/// Byte offsets of each sentence that is exactly this claim.
fn sentence_positions(source: &str, claim: &str) -> Vec<usize> {
    sentences_with_offsets(source)
        .into_iter()
        .filter(|(_, sentence)| *sentence == claim)
        .map(|(offset, _)| offset)
        .collect()
}

/// Why a claim does not match its source, or `None` if it is a whole sentence of that source.
///
/// A deterministic check: a fragment of a sentence is never support, since `improve` can sit
/// inside `did not improve`. It says nothing about whether the source is true or applies.
#[must_use]
pub fn claim_defect(claim: &str, source: &str) -> Option<&'static str> {
    let source_sentences = sentences(source);
    if !claim.is_empty() && source_sentences.contains(&claim) {
        return None;
    }
    let closest = |wanted: &dyn Fn(&str) -> bool| source_sentences.iter().any(|s| wanted(s));
    if !closest(&|s| numeric_tokens(s) == numeric_tokens(claim)) {
        return Some("number");
    }
    let claim_words = word_set(claim);
    let agrees = |list: &[&str], sentence: &str| {
        let words = word_set(sentence);
        list.iter()
            .all(|word| claim_words.contains(*word) == words.contains(*word))
    };
    let same_numbers = |s: &str| numeric_tokens(s) == numeric_tokens(claim);
    if !closest(&|s| same_numbers(s) && agrees(&NEGATIONS, s)) {
        return Some("negation");
    }
    if !closest(&|s| same_numbers(s) && agrees(&UNITS, s)) {
        return Some("unit");
    }
    Some("text")
}

fn span_of(document: &Document) -> Option<EvidenceSpan> {
    let start = *sentence_positions(&document.text, &document.finding).first()?;
    let start_scalar = document.text[..start].chars().count() as u64;
    Some(EvidenceSpan {
        source_id: document.doc_id.clone(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(document.text.as_bytes()),
        start_scalar,
        end_scalar: start_scalar + document.finding.chars().count() as u64,
    })
}

const BRIEF_HEADER: [&str; 2] = [
    "Synthetic evidence brief. Invented fixture data; not medical information.",
    "Limits: fixture evidence only, and no appraisal of study quality.",
];

fn render_brief(claims: &[(&Document, EvidenceSpan)]) -> String {
    let mut lines: Vec<String> = BRIEF_HEADER.iter().map(|line| (*line).to_owned()).collect();
    for (document, span) in claims {
        lines.push(format!(
            "- {} [{} {}..{}]",
            document.finding, document.doc_id, span.start_scalar, span.end_scalar
        ));
    }
    lines.join("\n")
}

/// Checks the final text itself. Every line must be the fixed header or a claim whose cited span
/// reproduces it exactly from that source, every claim must be a whole sentence of its source,
/// and no document may be cited twice. Returns the cited document ids.
///
/// # Errors
/// Returns the first line that fails, and why.
pub fn verify_brief(brief: &str, corpus: &Corpus) -> Result<Vec<String>, String> {
    let lines: Vec<&str> = brief.split('\n').collect();
    if lines.len() <= BRIEF_HEADER.len() || lines[..BRIEF_HEADER.len()] != BRIEF_HEADER {
        return Err("header differs or no claims".to_owned());
    }
    let mut cited = Vec::new();
    for line in &lines[BRIEF_HEADER.len()..] {
        let parsed = line
            .strip_prefix("- ")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|rest| rest.rsplit_once(" ["))
            .and_then(|(claim, citation)| {
                let (doc_id, range) = citation.split_once(' ')?;
                let (start, end) = range.split_once("..")?;
                Some((
                    claim,
                    doc_id,
                    start.parse::<usize>().ok()?,
                    end.parse::<usize>().ok()?,
                ))
            });
        let Some((claim, doc_id, start, end)) = parsed else {
            return Err(format!("not a claim line: {line}"));
        };
        let document = corpus
            .documents
            .iter()
            .find(|document| document.doc_id == doc_id)
            .ok_or_else(|| format!("unknown source: {doc_id}"))?;
        let total = document.text.chars().count();
        if start >= end || end > total {
            return Err(format!("span out of bounds: {line}"));
        }
        let slice: String = document
            .text
            .chars()
            .skip(start)
            .take(end - start)
            .collect();
        if slice != claim {
            return Err(format!("span does not reproduce the claim: {line}"));
        }
        let byte_start: usize = document.text.chars().take(start).map(char::len_utf8).sum();
        if !sentence_positions(&document.text, claim).contains(&byte_start) {
            return Err(format!("span is not on a whole sentence: {line}"));
        }
        if let Some(defect) = claim_defect(claim, &document.text) {
            return Err(format!("{defect} defect: {line}"));
        }
        if cited.iter().any(|id: &String| id == doc_id) {
            return Err(format!("cited twice: {doc_id}"));
        }
        cited.push(doc_id.to_owned());
    }
    Ok(cited)
}

fn scoped(id: &str) -> ScopedId {
    ScopedId {
        scope: "vs1a-fixture".to_owned(),
        id: id.to_owned(),
        version: 1,
    }
}

fn is_withdrawn(state: PublicationState) -> bool {
    matches!(
        state,
        PublicationState::Retracted | PublicationState::Withdrawn
    )
}

/// Directions per study: one study's reports disagreeing is not independent contradiction.
fn study_directions<'a>(documents: &[&'a Document]) -> BTreeMap<&'a str, BTreeSet<&'static str>> {
    let mut studies: BTreeMap<&str, BTreeSet<&'static str>> = BTreeMap::new();
    for document in documents {
        studies
            .entry(document.study_id.as_str())
            .or_default()
            .insert(match document.direction {
                Direction::Benefit => "benefit",
                Direction::NoBenefit => "no_benefit",
            });
    }
    studies
}

/// True when different studies' results point in different directions.
fn studies_conflict(documents: &[&Document]) -> bool {
    let all: BTreeSet<&str> = study_directions(documents)
        .into_values()
        .flatten()
        .collect();
    let studies = study_directions(documents);
    all.len() > 1 && studies.len() > 1
}

/// Runs one question through the guards, returning exactly one outcome, reason and funnel.
#[must_use]
pub fn ask(text: &str, corpus: &Corpus) -> AskResult {
    let mut funnel = Funnel {
        indexed: corpus.documents.len(),
        ..Funnel::default()
    };
    let refuse = |outcome, reason, funnel: &Funnel, excluded: &[(String, String)]| {
        let mut result = AskResult::refuse(outcome, reason, funnel.clone());
        result.excluded = excluded.to_vec();
        result
    };
    if validate_documents(corpus).is_err() {
        return AskResult::refuse(TerminalOutcome::Blocked, ReasonCode::ToolFailure, funnel);
    }
    if has_unsupported_script(text) {
        return AskResult::refuse(
            TerminalOutcome::Abstain,
            ReasonCode::UnsupportedLanguage,
            funnel,
        );
    }
    if is_patient_specific_request(&normalized(text)) {
        return AskResult::refuse(
            TerminalOutcome::Escalate,
            ReasonCode::ClinicianAuthorityRequired,
            funnel,
        );
    }
    let Some(question) = parse_question(text) else {
        return AskResult::refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            funnel,
        );
    };

    let Ok(connection) = build_index(corpus) else {
        return AskResult::refuse(TerminalOutcome::Blocked, ReasonCode::ToolFailure, funnel);
    };
    let terms = [question.condition.as_str(), question.intervention.as_str()];
    let Ok(retrieved) = retrieve(&connection, &terms) else {
        return AskResult::refuse(TerminalOutcome::Blocked, ReasonCode::ToolFailure, funnel);
    };
    funnel.retrieved = retrieved.len();

    // Metadata decides relevance, across the whole corpus: a contradicting document must count
    // even if lexical retrieval missed it. Retrieval supplies only the funnel count here.
    let relevant = |document: &&Document| {
        normalized(&document.condition) == question.condition
            && normalized(&document.intervention) == question.intervention
    };
    let mut excluded: Vec<(String, String)> = Vec::new();
    for id in &retrieved {
        if let Some(document) = corpus.documents.iter().find(|d| &d.doc_id == id)
            && !relevant(&document)
        {
            excluded.push((
                document.doc_id.clone(),
                "different condition or intervention".to_owned(),
            ));
        }
    }
    let matching: Vec<&Document> = corpus.documents.iter().filter(relevant).collect();
    if matching.is_empty() {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
            &funnel,
            &excluded,
        );
    }

    // Gather every fact first, then let the ported precedence choose one outcome. Numbers follow
    // the contract's guard order, so no branch order can decide the result.
    let mut fired: Vec<(FiredRule, ReasonCode)> = Vec::new();
    let mut fire = |id: &str, precedence: u32, outcome: TerminalOutcome, reason: ReasonCode| {
        let rule = FiredRule {
            rule_id: id.to_owned(),
            precedence,
            requirement: Requirement::Outcome(outcome),
            revoked: false,
        };
        fired.push((rule, reason));
    };

    let denied: Vec<&&Document> = matching.iter().filter(|d| !d.rights.admissible()).collect();
    for document in &denied {
        excluded.push((document.doc_id.clone(), "rights not established".to_owned()));
    }
    if denied.is_empty() {
        funnel.rights_admissible = matching.len();
    } else {
        fire(
            "rights-denied",
            1,
            TerminalOutcome::Blocked,
            ReasonCode::RightsUnresolved,
        );
    }

    // A retracted or withdrawn report takes its whole study out: a follow-up cannot rescue it.
    // This scans the whole corpus, since that report may be indexed under other terms.
    let withdrawn: BTreeSet<&str> = corpus
        .documents
        .iter()
        .filter(|document| is_withdrawn(document.publication_state))
        .map(|document| document.study_id.as_str())
        .collect();
    let mut citable = Vec::new();
    for document in &matching {
        if withdrawn.contains(document.study_id.as_str()) {
            excluded.push((
                document.doc_id.clone(),
                "study has a retracted or withdrawn report".to_owned(),
            ));
        } else if document.publication_state.citable() {
            citable.push(*document);
        } else {
            excluded.push((
                document.doc_id.clone(),
                "publication state is not citable".to_owned(),
            ));
        }
    }
    funnel.citable = citable.len();
    if citable.is_empty() {
        let any_withdrawn = matching
            .iter()
            .any(|document| withdrawn.contains(document.study_id.as_str()));
        let reason = if any_withdrawn {
            ReasonCode::SourceInvalidOrRetracted
        } else {
            ReasonCode::CurrentnessUnknown
        };
        fire("no-citable-source", 5, TerminalOutcome::Abstain, reason);
    }

    let mut applicable = Vec::new();
    if let Some(population) = &question.population {
        for document in &citable {
            if normalized(&document.population) == *population {
                applicable.push(*document);
            } else {
                excluded.push((
                    document.doc_id.clone(),
                    format!(
                        "population {} does not match {population}",
                        document.population
                    ),
                ));
            }
        }
        funnel.applicable = applicable.len();
        if applicable.is_empty() && !citable.is_empty() {
            fire(
                "not-applicable",
                5,
                TerminalOutcome::Abstain,
                ReasonCode::ApplicabilityUnresolved,
            );
        }
        let studies = study_directions(&applicable);
        funnel.independent_studies = studies.len();
        if studies_conflict(&applicable) {
            fire(
                "independent-conflict",
                3,
                TerminalOutcome::Conflict,
                ReasonCode::MaterialContradiction,
            );
        }
        // One study's reports disagreeing is unresolved evidence, not independent contradiction.
        if studies.values().any(|directions| directions.len() > 1) {
            fire(
                "within-study-disagreement",
                5,
                TerminalOutcome::Abstain,
                ReasonCode::EvidenceInsufficient,
            );
        }
    } else if !citable.is_empty() {
        // Asking for a population cannot resolve contradiction that exists within one population.
        let populations: BTreeSet<String> =
            citable.iter().map(|d| normalized(&d.population)).collect();
        let conflict = populations.iter().any(|population| {
            let group: Vec<&Document> = citable
                .iter()
                .copied()
                .filter(|d| normalized(&d.population) == *population)
                .collect();
            studies_conflict(&group)
        });
        if conflict {
            fire(
                "independent-conflict",
                3,
                TerminalOutcome::Conflict,
                ReasonCode::MaterialContradiction,
            );
        } else {
            fire(
                "population-missing",
                4,
                TerminalOutcome::AskMore,
                ReasonCode::MissingCriticalContext,
            );
        }
    }

    let rules: Vec<FiredRule> = fired.iter().map(|(rule, _)| rule.clone()).collect();
    if let Resolution::Decided {
        requirement,
        cause,
        winners,
    } = evaluate_precedence(&rules)
    {
        // Only these rules can fire here, so any other result means the guards are broken.
        let (Requirement::Outcome(outcome), Cause::RuleWon) = (requirement, cause) else {
            return refuse(
                TerminalOutcome::Blocked,
                ReasonCode::ToolFailure,
                &funnel,
                &excluded,
            );
        };
        let reason = fired
            .iter()
            .find(|(rule, _)| winners.contains(&rule.rule_id))
            .map_or(ReasonCode::ToolFailure, |(_, reason)| *reason);
        return refuse(outcome, reason, &funnel, &excluded);
    }

    let mut claims = Vec::new();
    for document in &applicable {
        let Some(span) = span_of(document) else {
            return refuse(
                TerminalOutcome::Abstain,
                ReasonCode::PostVerificationFailed,
                &funnel,
                &excluded,
            );
        };
        claims.push((*document, span));
    }
    let brief = render_brief(&claims);
    // The frozen text is read back and checked against the sources, not against its inputs.
    let Ok(cited) = verify_brief(&brief, corpus) else {
        return refuse(
            TerminalOutcome::Abstain,
            ReasonCode::PostVerificationFailed,
            &funnel,
            &excluded,
        );
    };
    funnel.verified_claims = cited.len();

    let question_digest = DigestSha256::of(normalized(text).as_bytes());
    let text_digest = DigestSha256::of(brief.as_bytes());
    let manifest = AnswerProofManifest {
        proof_id: format!("vs1a-{}-{}", question_digest.to_hex(), text_digest.to_hex()),
        question_snapshot_digest: question_digest,
        final_text_digest: text_digest,
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

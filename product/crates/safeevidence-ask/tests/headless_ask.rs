//! VS-1a step 1, end to end over the invented fixture. These prove control flow and refusals.
//! They are not retrieval-quality or clinical results.

use safeevidence_ask::{Corpus, CorpusError, ask, claim_defect, load_corpus};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::commit_defects;

const FIXTURE: &[u8] = include_bytes!("../fixtures/vs1a_corpus.json");

fn corpus() -> Corpus {
    load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture loads")
}

#[test]
fn applicable_evidence_gives_a_cautious_brief_with_exact_spans() {
    let corpus = corpus();
    let result = ask(
        "Does veltrixamine help adults with glimmer syndrome?",
        &corpus,
    );
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    assert_eq!(result.reason, ReasonCode::None);

    let brief = result.brief.expect("brief");
    assert!(brief.contains("not medical information"));
    assert!(!brief.contains('%'), "V1 renders no percentage");

    let manifest = result.manifest.expect("manifest");
    assert_eq!(
        manifest.state,
        ProofState::VerifiedUncommitted,
        "VS-1a stops before commit"
    );
    assert_eq!(
        manifest.final_text_digest,
        DigestSha256::of(brief.as_bytes())
    );
    assert!(commit_defects(&manifest).is_empty());
    assert_eq!(manifest.claims.len(), 2);
    for claim in &manifest.claims {
        let document = corpus
            .documents
            .iter()
            .find(|d| d.doc_id == claim.claim_id)
            .unwrap();
        let span = &claim.spans[0];
        assert_eq!(
            span.source_digest,
            DigestSha256::of(document.text.as_bytes())
        );
        let slice: String = document
            .text
            .chars()
            .skip(span.start_scalar as usize)
            .take((span.end_scalar - span.start_scalar) as usize)
            .collect();
        assert_eq!(slice, document.finding, "span must reproduce the claim");
        assert!(brief.contains(&slice));
    }
}

#[test]
fn two_reports_of_one_study_count_as_one_study() {
    let result = ask(
        "Does veltrixamine help adults with glimmer syndrome?",
        &corpus(),
    );
    assert_eq!(result.funnel.applicable, 2);
    assert_eq!(result.funnel.independent_studies, 1);
}

#[test]
fn mismatched_population_is_excluded_with_a_reason() {
    let result = ask(
        "Does veltrixamine help adults with glimmer syndrome?",
        &corpus(),
    );
    assert_eq!(result.funnel.retrieved, 3);
    let (doc, reason) = &result.excluded[0];
    assert_eq!(doc, "doc-veltrix-peds");
    assert!(reason.contains("children"));
    assert!(!result.brief.unwrap().contains("did not improve"));
}

#[test]
fn a_different_population_gets_its_own_evidence_not_the_adult_result() {
    let result = ask(
        "Does veltrixamine help children with glimmer syndrome?",
        &corpus(),
    );
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    let brief = result.brief.unwrap();
    assert!(brief.contains("did not improve"));
    assert!(!brief.contains("12 points"));
}

#[test]
fn independent_contradiction_is_a_conflict_with_no_brief() {
    let result = ask("Does orbalin help adults with ember fatigue?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Conflict);
    assert_eq!(result.reason, ReasonCode::MaterialContradiction);
    assert!(result.brief.is_none() && result.manifest.is_none());
    assert_eq!(result.funnel.independent_studies, 2);
}

#[test]
fn retracted_only_evidence_abstains_and_does_not_look_like_no_evidence() {
    let result = ask("Does quenzil help adults with hollow cough?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::SourceInvalidOrRetracted);
    assert_eq!(result.funnel.retrieved, 1);
    assert_eq!(result.excluded[0].0, "doc-quenzil-retracted");
    assert!(result.brief.is_none());
}

#[test]
fn unknown_rights_block_presentation() {
    let result = ask("Does tessarine help adults with marble rash?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert_eq!(result.reason, ReasonCode::RightsUnresolved);
    assert!(result.brief.is_none());
}

#[test]
fn missing_population_asks_for_it_and_blocked_rights_still_win() {
    let result = ask("Does veltrixamine help with glimmer syndrome?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::AskMore);
    assert_eq!(result.reason, ReasonCode::MissingCriticalContext);
    assert!(result.brief.is_none());
    let blocked = ask("Does tessarine help with marble rash?", &corpus());
    assert_eq!(
        blocked.outcome,
        TerminalOutcome::Blocked,
        "BLOCKED outranks ASK_MORE"
    );
}

#[test]
fn no_matching_evidence_abstains() {
    let result = ask(
        "Does zzzamine help adults with glimmer syndrome?",
        &corpus(),
    );
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::EvidenceInsufficient);
    assert_eq!(result.funnel.indexed, 7, "funnel is present on refusals");
}

#[test]
fn patient_specific_request_escalates_outranking_evidence() {
    let result = ask(
        "Should I prescribe veltrixamine to my patient, an adult with glimmer syndrome?",
        &corpus(),
    );
    assert_eq!(result.outcome, TerminalOutcome::Escalate);
    assert_eq!(result.reason, ReasonCode::ClinicianAuthorityRequired);
}

#[test]
fn symptom_words_and_negation_never_produce_an_emergency_notice() {
    for question in [
        "Does veltrixamine help adults with glimmer syndrome who deny chest pain?",
        "chest pain stroke overdose",
        "هل يساعد veltrixamine البالغين الذين ينكرون ألم الصدر؟",
    ] {
        assert_ne!(
            ask(question, &corpus()).outcome,
            TerminalOutcome::EmergencyNotice,
            "{question}"
        );
    }
}

#[test]
fn arabic_question_abstains_with_its_own_reason() {
    let result = ask(
        "هل يساعد veltrixamine البالغين المصابين بمتلازمة glimmer؟",
        &corpus(),
    );
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::UnsupportedLanguage);
    assert!(result.brief.is_none());
}

#[test]
fn hostile_text_in_a_question_is_data() {
    let result = ask(
        "Does veltrixamine help adults with glimmer syndrome\" OR title:* ) ; DROP TABLE evidence; --",
        &corpus(),
    );
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    assert_eq!(result.funnel.retrieved, 3);
}

#[test]
fn altered_numbers_units_and_negation_are_flagged() {
    let source = "The glimmer score improved by 12 points compared with placebo at 12 weeks.";
    assert_eq!(claim_defect(source, source), None);
    for (claim, defect) in [
        (
            "The glimmer score improved by 21 points compared with placebo at 12 weeks.",
            "number",
        ),
        (
            "The glimmer score improved by 12 points compared with placebo at 1.2 weeks.",
            "number",
        ),
        (
            "The glimmer score improved by 12 points compared with placebo at 12 months.",
            "unit",
        ),
        (
            "The glimmer score improved by 12 mg compared with placebo at 12 weeks.",
            "unit",
        ),
        (
            "The glimmer score did not improve by 12 points compared with placebo at 12 weeks.",
            "negation",
        ),
        (
            "The glimmer score worsened by 12 points compared with placebo at 12 weeks.",
            "text",
        ),
    ] {
        assert_eq!(claim_defect(claim, source), Some(defect), "{claim}");
    }
    let negated = "The glimmer score did not improve compared with placebo at 12 weeks.";
    assert_eq!(
        claim_defect(
            "The glimmer score did improve compared with placebo at 12 weeks.",
            negated
        ),
        Some("negation")
    );
}

#[test]
fn corpus_loader_fails_closed() {
    let digest = DigestSha256::of(FIXTURE);
    let mut tampered = FIXTURE.to_vec();
    tampered[10] ^= 0x01;
    assert_eq!(
        load_corpus(&tampered, &digest).unwrap_err(),
        CorpusError::DigestMismatch
    );
    let reload = |text: String| {
        let bytes = text.into_bytes();
        load_corpus(&bytes, &DigestSha256::of(&bytes)).map(|_| ())
    };
    let source = std::str::from_utf8(FIXTURE).unwrap();
    assert_eq!(
        reload(source.replace("\"validity_epoch\": 3", "\"validity_epoch\": 0")),
        Err(CorpusError::MissingValidityEpoch)
    );
    assert_eq!(
        reload(source.replace("synthetic-owned-1", " ")),
        Err(CorpusError::MissingRightsGrant)
    );
    assert_eq!(
        reload(source.replace("doc-orbalin-b", "doc-orbalin-a")),
        Err(CorpusError::DuplicateDocument("doc-orbalin-a".to_owned()))
    );
    assert!(matches!(
        reload("{}".to_owned()),
        Err(CorpusError::Malformed(_))
    ));
    assert!(matches!(
        reload(source.replace("\"CURRENT\"", "\"PROBABLY_FINE\"")),
        Err(CorpusError::Malformed(_))
    ));
}

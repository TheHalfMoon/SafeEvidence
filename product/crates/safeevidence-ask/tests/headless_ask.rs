//! VS-1a step 1, end to end over the invented fixture. These prove control flow and refusals.
//! They are not retrieval-quality or clinical results.

use safeevidence_ask::{
    Corpus, CorpusError, Direction, ask, claim_defect, load_corpus, parse_question,
    validate_documents, verify_brief,
};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::commit_defects;
use safeevidence_contracts::study::PublicationState;

const FIXTURE: &[u8] = include_bytes!("../fixtures/vs1a_corpus.json");
const ADULT: &str = "Does veltrixamine help adults with glimmer syndrome?";

fn corpus() -> Corpus {
    load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture loads")
}

fn with_doc(id: &str, edit: impl Fn(&mut safeevidence_ask::Document)) -> Corpus {
    let mut value = corpus();
    edit(value.documents.iter_mut().find(|d| d.doc_id == id).unwrap());
    value
}

#[test]
fn applicable_evidence_gives_a_cautious_brief_with_exact_spans() {
    let corpus = corpus();
    let result = ask(ADULT, &corpus);
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
    assert_eq!(result.funnel.verified_claims, 2);
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
fn proof_identity_differs_when_the_brief_differs() {
    let first = ask(ADULT, &corpus()).manifest.unwrap();
    let changed = with_doc("doc-veltrix-a", |d| {
        d.text = d.text.replace("12 points", "13 points");
        d.finding = d.finding.replace("12 points", "13 points");
    });
    let second = ask(ADULT, &changed).manifest.unwrap();
    assert_ne!(first.proof_id, second.proof_id);
    assert_ne!(first.final_text_digest, second.final_text_digest);
}

#[test]
fn two_reports_of_one_study_count_as_one_study() {
    let result = ask(ADULT, &corpus());
    assert_eq!(result.funnel.applicable, 2);
    assert_eq!(result.funnel.independent_studies, 1);
}

/// Rewrites a report so lexical retrieval cannot find it for its condition, keeping its finding.
fn unretrievable(document: &mut safeevidence_ask::Document) {
    let opening = document.text.split(". ").next().unwrap().to_owned();
    document.text = document
        .text
        .replacen(&opening, "A report on synthetic GS", 1);
    document.title = "A report on synthetic GS".to_owned();
}

/// `plan-v1.6`: only reports lexical retrieval found can be cited.
#[test]
fn a_report_retrieval_missed_is_not_cited_and_says_why() {
    let value = with_doc("doc-veltrix-a-followup", unretrievable);
    let result = ask(ADULT, &value);
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    let manifest = result.manifest.expect("manifest");
    let cited: Vec<&str> = manifest
        .claims
        .iter()
        .map(|c| c.claim_id.as_str())
        .collect();
    assert_eq!(cited, ["doc-veltrix-a"]);
    let exclusion = result
        .excluded
        .iter()
        .find(|e| e.doc_id == "doc-veltrix-a-followup")
        .expect("listed");
    assert_eq!(exclusion.reason, ReasonCode::EvidenceInsufficient);
    assert!(!result.brief.unwrap().contains("11 points"));
}

#[test]
fn nothing_retrieved_to_cite_is_an_abstention() {
    let mut value = with_doc("doc-veltrix-a-followup", unretrievable);
    unretrievable(
        value
            .documents
            .iter_mut()
            .find(|d| d.doc_id == "doc-veltrix-a")
            .unwrap(),
    );
    let result = ask(ADULT, &value);
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::EvidenceInsufficient);
    assert!(result.brief.is_none() && result.manifest.is_none());
}

/// The guards still see the whole corpus: a contradiction retrieval misses still stops the answer.
#[test]
fn a_contradiction_retrieval_missed_still_stops_the_answer() {
    let value = with_doc("doc-veltrix-a-followup", |d| {
        d.text = "A report on synthetic GS. The glimmer score did not improve compared with placebo at 24 weeks.".to_owned();
        d.title = "A report on synthetic GS".to_owned();
        d.finding =
            "The glimmer score did not improve compared with placebo at 24 weeks.".to_owned();
        d.direction = Direction::NoBenefit;
    });
    let result = ask(ADULT, &value);
    assert_ne!(
        result.outcome,
        TerminalOutcome::AnswerWithCaution,
        "{:?}",
        result.reason
    );
    assert!(result.brief.is_none() && result.manifest.is_none());
}

#[test]
fn mismatched_population_is_excluded_with_a_reason() {
    let result = ask(ADULT, &corpus());
    assert_eq!(result.funnel.retrieved, 3);
    let exclusion = &result.excluded[0];
    assert_eq!(exclusion.doc_id, "doc-veltrix-peds");
    assert_eq!(exclusion.reason, ReasonCode::ApplicabilityUnresolved);
    assert!(exclusion.detail.contains("children"));
    assert!(!result.brief.unwrap().contains("did not improve"));
}

/// TA-11, modelled on the population half of R-CO-2, where a tool counted studies of another
/// population towards the question. Its overlapping reviews belong to TA-07 and WP-05. Children's
/// evidence points the other way here, so counting it would change the answer.
#[test]
fn another_populations_evidence_is_never_counted_towards_the_question() {
    let result = ask(ADULT, &corpus());
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    assert_eq!(result.funnel.independent_studies, 1);
    let manifest = result.manifest.expect("manifest");
    assert!(
        manifest
            .claims
            .iter()
            .all(|c| c.claim_id != "doc-veltrix-peds")
    );
    assert_eq!(
        result
            .excluded
            .iter()
            .map(|e| (e.doc_id.as_str(), e.reason))
            .collect::<Vec<_>>(),
        [("doc-veltrix-peds", ReasonCode::ApplicabilityUnresolved)]
    );
}

/// In R-CO-2 the mismatched sources agreed, so counting them inflated the evidence instead.
#[test]
fn another_populations_agreeing_evidence_is_not_counted_either() {
    let value = with_doc("doc-veltrix-peds", |d| {
        d.text = "Children with synthetic glimmer syndrome received veltrixamine 10 mg daily. The glimmer score improved by 9 points compared with placebo at 12 weeks.".to_owned();
        d.finding =
            "The glimmer score improved by 9 points compared with placebo at 12 weeks.".to_owned();
        d.direction = Direction::Benefit;
    });
    let result = ask(ADULT, &value);
    assert_eq!(result.funnel.independent_studies, 1);
    assert!(!result.brief.unwrap().contains("9 points"));
    assert_eq!(
        result.excluded[0].reason,
        ReasonCode::ApplicabilityUnresolved
    );
}

/// Near and overlapping populations are still not the question's population.
#[test]
fn near_and_overlapping_populations_are_excluded_with_a_reason() {
    for population in [
        "older adults",
        "adults without diabetes",
        "adults and children",
        "adult",
    ] {
        let value = with_doc("doc-veltrix-a-followup", |d| {
            d.population = population.to_owned();
        });
        let result = ask(ADULT, &value);
        let exclusion = result
            .excluded
            .iter()
            .find(|e| e.doc_id == "doc-veltrix-a-followup")
            .unwrap_or_else(|| panic!("{population} must be excluded"));
        assert_eq!(
            exclusion.reason,
            ReasonCode::ApplicabilityUnresolved,
            "{population}"
        );
        assert!(!result.brief.unwrap().contains("11 points"), "{population}");
    }
}

#[test]
fn a_non_citable_source_is_excluded_with_a_code_that_names_its_state() {
    for state in [
        PublicationState::Unknown,
        PublicationState::Corrected,
        PublicationState::ExpressionOfConcern,
        PublicationState::Superseded,
    ] {
        let value = with_doc("doc-veltrix-a-followup", |d| d.publication_state = state);
        let result = ask(ADULT, &value);
        let exclusion = result
            .excluded
            .iter()
            .find(|e| e.doc_id == "doc-veltrix-a-followup")
            .unwrap_or_else(|| panic!("{state:?} must be excluded"));
        assert_eq!(
            exclusion.reason,
            ReasonCode::CurrentnessUnknown,
            "{state:?}"
        );
        assert!(
            exclusion.detail.contains(&format!("{state:?}")),
            "{state:?}"
        );
    }
}

#[test]
fn a_retrieved_source_on_another_intervention_is_excluded_with_a_reason() {
    let value = with_doc("doc-veltrix-a-followup", |d| {
        d.intervention = "orbalin".to_owned();
    });
    let result = ask(ADULT, &value);
    let exclusion = result
        .excluded
        .iter()
        .find(|e| e.doc_id == "doc-veltrix-a-followup")
        .expect("retrieved, so it must be accounted for");
    assert_eq!(exclusion.reason, ReasonCode::ApplicabilityUnresolved);
    assert_eq!(exclusion.detail, "different condition or intervention");
    assert!(!result.brief.unwrap().contains("11 points"));
}

/// An adult source, so the population check cannot hide a missing condition check.
#[test]
fn a_retrieved_source_on_another_condition_is_excluded_with_a_reason() {
    let value = with_doc("doc-veltrix-a-followup", |d| {
        d.condition = "ember fatigue".to_owned();
    });
    let result = ask(ADULT, &value);
    let exclusion = result
        .excluded
        .iter()
        .find(|e| e.doc_id == "doc-veltrix-a-followup")
        .expect("retrieved, so it must be accounted for");
    assert_eq!(exclusion.reason, ReasonCode::ApplicabilityUnresolved);
    assert_eq!(exclusion.detail, "different condition or intervention");
    assert!(!result.brief.unwrap().contains("11 points"));
}

/// Every source retrieved and not cited must be accounted for, across each fixture question.
#[test]
fn every_retrieved_source_is_cited_or_excluded_with_a_code() {
    let corpus = corpus();
    for question in [
        ADULT,
        "Does veltrixamine help children with glimmer syndrome?",
        "Does orbalin help adults with ember fatigue?",
        "Does quenzil help adults with hollow cough?",
        "Does tessarine help adults with marble rash?",
    ] {
        let result = ask(question, &corpus);
        if result.outcome == TerminalOutcome::AnswerWithCaution {
            let cited = result.manifest.as_ref().expect("manifest").claims.len();
            assert_eq!(
                cited + result.excluded.len(),
                result.funnel.retrieved,
                "{question}"
            );
        }
        for exclusion in &result.excluded {
            assert_ne!(exclusion.reason, ReasonCode::None, "{question}");
            assert!(!exclusion.detail.is_empty(), "{question}");
        }
    }
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
fn near_miss_populations_never_get_the_adult_brief() {
    for question in [
        "Does veltrixamine help young adults with glimmer syndrome?",
        "Does veltrixamine help teenagers with glimmer syndrome?",
    ] {
        let result = ask(question, &corpus());
        assert_eq!(result.outcome, TerminalOutcome::Abstain, "{question}");
        assert_eq!(
            result.reason,
            ReasonCode::ApplicabilityUnresolved,
            "{question}"
        );
        assert!(result.brief.is_none(), "{question}");
    }
}

#[test]
fn questions_outside_the_grammar_never_get_a_brief() {
    for question in [
        "Does veltrixamine help children, not adults with glimmer syndrome?",
        "Does veltrixamine help adults without glimmer syndrome?",
        "Should I start veltrixamine for Mr Ahmad, an adult with glimmer syndrome?",
        "veltrixamine adults glimmer syndrome",
        "Does veltrixamine help adults with glimmer syndrome\" OR title:* ) ; DROP TABLE evidence; --",
        "Does help adults with glimmer syndrome?",
        "",
    ] {
        let result = ask(question, &corpus());
        assert!(result.brief.is_none(), "{question}");
        assert_eq!(result.outcome, TerminalOutcome::Abstain, "{question}");
    }
}

#[test]
fn grammar_parses_only_its_exact_form() {
    let parsed =
        parse_question("  DOES  Veltrixamine help ADULTS with Glimmer Syndrome? ").unwrap();
    assert_eq!(parsed.intervention, "veltrixamine");
    assert_eq!(parsed.population.as_deref(), Some("adults"));
    assert_eq!(parsed.condition, "glimmer syndrome");
    let parsed = parse_question("does x help with y").unwrap();
    assert_eq!(parsed.population, None);
    assert!(parse_question("does x help").is_none());
    assert!(parse_question("does x help a with ").is_none());
}

#[test]
fn case_differences_do_not_hide_a_contradiction() {
    let value = with_doc("doc-orbalin-b", |d| {
        d.condition = "Ember Fatigue".to_owned();
        d.intervention = "ORBALIN".to_owned();
        d.population = "Adults".to_owned();
    });
    let result = ask("Does orbalin help adults with ember fatigue?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Conflict);
}

#[test]
fn contradictor_lexical_search_misses_still_counts() {
    let value = with_doc("doc-orbalin-b", |d| {
        d.title = "Second trial".to_owned();
        d.text =
            "A second trial ran. The ember score did not improve compared with placebo at 8 weeks."
                .to_owned();
    });
    let result = ask("Does orbalin help adults with ember fatigue?", &value);
    assert_eq!(result.funnel.retrieved, 1, "FTS finds only one");
    assert_eq!(result.outcome, TerminalOutcome::Conflict);
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
fn conflict_outranks_asking_for_a_population() {
    let result = ask("Does orbalin help with ember fatigue?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Conflict);
}

#[test]
fn disagreement_between_populations_asks_rather_than_conflicts() {
    let result = ask("Does veltrixamine help with glimmer syndrome?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::AskMore);
    assert_eq!(result.reason, ReasonCode::MissingCriticalContext);
}

#[test]
fn one_studys_reports_disagreeing_is_not_called_independent_conflict() {
    let value = with_doc("doc-veltrix-a-followup", |d| {
        d.text = "This follow-up reports the same adults. The glimmer score did not improve compared with placebo at 24 weeks.".to_owned();
        d.finding =
            "The glimmer score did not improve compared with placebo at 24 weeks.".to_owned();
        d.direction = Direction::NoBenefit;
    });
    let result = ask(ADULT, &value);
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::EvidenceInsufficient);
    assert!(result.brief.is_none());
}

#[test]
fn retracted_only_evidence_abstains_and_does_not_look_like_no_evidence() {
    let result = ask("Does quenzil help adults with hollow cough?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::SourceInvalidOrRetracted);
    assert_eq!(result.funnel.retrieved, 1);
    assert_eq!(result.excluded[0].doc_id, "doc-quenzil-retracted");
    assert_eq!(
        result.excluded[0].reason,
        ReasonCode::SourceInvalidOrRetracted
    );
    assert!(result.brief.is_none());
}

#[test]
fn a_follow_up_cannot_rescue_a_retracted_study() {
    for state in [PublicationState::Retracted, PublicationState::Withdrawn] {
        let value = with_doc("doc-veltrix-a", |d| d.publication_state = state);
        let result = ask(ADULT, &value);
        assert_eq!(result.outcome, TerminalOutcome::Abstain, "{state:?}");
        assert_eq!(
            result.reason,
            ReasonCode::ApplicabilityUnresolved,
            "{state:?}: only children remain"
        );
        assert!(result.brief.is_none());
        assert_eq!(result.funnel.citable, 1);
    }
}

#[test]
fn a_non_citable_report_drops_alone_when_nothing_was_retracted() {
    let value = with_doc("doc-veltrix-a-followup", |d| {
        d.publication_state = PublicationState::Superseded;
    });
    let result = ask(ADULT, &value);
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    assert_eq!(result.funnel.verified_claims, 1);
}

#[test]
fn unknown_publication_state_is_not_reported_as_retracted() {
    let value = with_doc("doc-quenzil-retracted", |d| {
        d.publication_state = PublicationState::Unknown;
    });
    let result = ask("Does quenzil help adults with hollow cough?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::CurrentnessUnknown);
}

#[test]
fn unknown_rights_block_presentation() {
    let result = ask("Does tessarine help adults with marble rash?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert_eq!(result.reason, ReasonCode::RightsUnresolved);
    assert!(result.brief.is_none());
}

#[test]
fn one_unknown_rights_document_blocks_even_beside_admissible_ones() {
    let value = with_doc("doc-veltrix-a-followup", |d| {
        d.rights = safeevidence_contracts::evidence::EvidenceCorpusRights::Unknown;
    });
    assert_eq!(ask(ADULT, &value).outcome, TerminalOutcome::Blocked);
}

#[test]
fn missing_population_asks_for_it_and_blocked_rights_still_win() {
    let result = ask("Does veltrixamine help with glimmer syndrome?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::AskMore);
    assert!(result.brief.is_none());
    let blocked = ask("Does tessarine help with marble rash?", &corpus());
    assert_eq!(
        blocked.outcome,
        TerminalOutcome::Blocked,
        "BLOCKED outranks ASK_MORE"
    );
}

#[test]
fn no_matching_evidence_abstains_with_a_funnel() {
    for question in [
        "Does zzzamine help adults with glimmer syndrome?",
        "Does veltrixamine help adults with ember fatigue?",
    ] {
        let result = ask(question, &corpus());
        assert_eq!(result.outcome, TerminalOutcome::Abstain, "{question}");
        assert_eq!(
            result.reason,
            ReasonCode::EvidenceInsufficient,
            "{question}"
        );
        assert_eq!(result.funnel.indexed, 7, "funnel is present on refusals");
    }
}

#[test]
fn patient_specific_requests_escalate_whatever_their_spacing() {
    for question in [
        "Should I prescribe veltrixamine to my patient, an adult with glimmer syndrome?",
        "Does veltrixamine help my  patient with glimmer syndrome?",
        "Should I give veltrixamine to an adult?",
    ] {
        let result = ask(question, &corpus());
        assert_eq!(result.outcome, TerminalOutcome::Escalate, "{question}");
        assert_eq!(
            result.reason,
            ReasonCode::ClinicianAuthorityRequired,
            "{question}"
        );
    }
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
fn any_non_latin_script_abstains_with_its_own_reason() {
    for question in [
        "هل يساعد veltrixamine البالغين المصابين بمتلازمة glimmer؟",
        "Does veltrixamine help adults with ﺍﻟﺠﺮﻋﺔ?",
        "Does veltrixamine help adults with 症候群?",
    ] {
        let result = ask(question, &corpus());
        assert_eq!(result.outcome, TerminalOutcome::Abstain, "{question}");
        assert_eq!(result.reason, ReasonCode::UnsupportedLanguage, "{question}");
        assert!(result.brief.is_none());
    }
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
            "The glimmer score improved by -12 points compared with placebo at 12 weeks.",
            "number",
        ),
        (
            "The glimmer score improved by ١٢ points compared with placebo at 12 weeks.",
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
            "The glimmer score rose by 12 points compared with placebo at 12 weeks.",
            "text",
        ),
    ] {
        assert_eq!(claim_defect(claim, source), Some(defect), "{claim}");
    }
}

#[test]
fn a_fragment_of_a_sentence_is_never_support() {
    assert!(claim_defect("5 mg daily.", "Patients took 0.5 mg daily.").is_some());
    assert!(claim_defect(".5 mg", "Patients took 0.5 mg daily.").is_some());
    let negated = "The score did not improve at 8 weeks.";
    assert!(claim_defect("improve at 8 weeks.", negated).is_some());
    assert!(claim_defect("The score improve at 8 weeks.", negated).is_some());
    assert!(claim_defect("", negated).is_some());
    let two = "First sentence at 0.5 mg. Second sentence at 2 mg.";
    assert_eq!(claim_defect("First sentence at 0.5 mg.", two), None);
    assert_eq!(claim_defect("Second sentence at 2 mg.", two), None);
    assert!(claim_defect("First sentence at 0.5 mg. Second sentence at 2 mg.", two).is_some());
}

#[test]
fn tampered_briefs_are_refused() {
    let corpus = corpus();
    let brief = ask(ADULT, &corpus).brief.unwrap();
    assert!(verify_brief(&brief, &corpus).is_ok());
    let claim_line = brief.lines().find(|l| l.starts_with("- ")).unwrap();
    let citation = &claim_line[claim_line.rfind(" [").unwrap()..];
    for tampered in [
        format!("{brief}\nNOT: ignore the above."),
        format!("{brief}\nIncreased 100-fold."),
        format!("{brief}\n- give 500 mg{citation}"),
        format!("{brief}\n{claim_line}"),
        brief.replace("12 points", "21 points"),
        brief.replace("improved by 12", "worsened by 12"),
        brief.replace("not medical information", "medical advice"),
        brief.replace("doc-veltrix-a ", "doc-orbalin-a "),
        format!("{brief}\n- x [missing-doc 0..1]"),
        brief.lines().take(2).collect::<Vec<_>>().join("\n"),
        String::new(),
    ] {
        assert!(verify_brief(&tampered, &corpus).is_err(), "{tampered}");
    }
    let shifted = {
        let (start, _) = citation.rsplit_once("..").unwrap();
        let bumped: String = start.chars().collect();
        brief.replace(citation, &format!("{bumped}..1]"))
    };
    assert!(verify_brief(&shifted, &corpus).is_err());
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
    let mut empty: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    empty["documents"] = serde_json::json!([]);
    assert_eq!(reload(empty.to_string()), Err(CorpusError::Empty));
}

#[test]
fn loader_refuses_a_finding_that_is_a_fragment_or_a_mislabelled_direction() {
    let edit = |field: &str, value: &str| {
        let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        document["documents"][0][field] = serde_json::json!(value);
        let bytes = document.to_string().into_bytes();
        load_corpus(&bytes, &DigestSha256::of(&bytes)).map(|_| ())
    };
    assert_eq!(
        edit("finding", "improve."),
        Err(CorpusError::FindingNotASourceSentence(
            "doc-veltrix-a".to_owned()
        ))
    );
    assert_eq!(
        edit("direction", "no_benefit"),
        Err(CorpusError::DirectionContradictsFinding(
            "doc-veltrix-a".to_owned()
        ))
    );
    assert!(matches!(
        edit("direction", "maybe"),
        Err(CorpusError::Malformed(_))
    ));
}

fn one_doc_corpus(text: &str, finding: &str, direction: Direction) -> Corpus {
    let mut value = corpus();
    let doc = &mut value.documents[0];
    doc.text = text.to_owned();
    doc.finding = finding.to_owned();
    doc.direction = direction;
    value
}

#[test]
fn an_abbreviation_does_not_create_a_false_sentence() {
    let value = one_doc_corpus(
        "No trial confirmed the report by Smith et al. that drug improved score by 12 points.",
        "that drug improved score by 12 points.",
        Direction::Benefit,
    );
    assert!(validate_documents(&value).is_err());
    assert_eq!(ask(ADULT, &value).outcome, TerminalOutcome::Blocked);
}

#[test]
fn a_claim_also_inside_a_negated_sentence_uses_its_own_span_or_is_refused() {
    let repeated = "The score improved by 12 points.";
    let value = one_doc_corpus(
        &format!("Nobody showed that {repeated} {repeated}"),
        repeated,
        Direction::Benefit,
    );
    let result = ask(ADULT, &value);
    if let Some(manifest) = result.manifest {
        let span = &manifest.claims[0].spans[0];
        assert!(
            span.start_scalar > 20,
            "must not cite inside the negated sentence"
        );
    }
    let twice = one_doc_corpus(
        &format!("{repeated} {repeated}"),
        repeated,
        Direction::Benefit,
    );
    assert!(
        validate_documents(&twice).is_err(),
        "an ambiguous span is refused"
    );
}

#[test]
fn broader_reversal_wording_cannot_be_labelled_benefit() {
    for finding in [
        "The score didn't improve at 8 weeks.",
        "The score failed to improve at 8 weeks.",
        "The score worsened at 8 weeks.",
    ] {
        let value = one_doc_corpus(finding, finding, Direction::Benefit);
        assert!(matches!(
            validate_documents(&value),
            Err(CorpusError::DirectionContradictsFinding(_))
        ));
    }
}

#[test]
fn ask_refuses_a_directly_built_invalid_corpus() {
    let finding = "The score did not improve at 8 weeks.";
    let value = one_doc_corpus(finding, finding, Direction::Benefit);
    let result = ask(ADULT, &value);
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert!(result.brief.is_none());
}

#[test]
fn a_retracted_report_filed_under_other_terms_still_removes_its_study() {
    let value = with_doc("doc-orbalin-a", |d| {
        d.study_id = "study-veltrix-a".to_owned();
        d.publication_state = PublicationState::Retracted;
    });
    let result = ask(ADULT, &value);
    assert!(result.brief.is_none());
    assert_eq!(
        result.funnel.citable, 1,
        "only the children's study remains"
    );
}

#[test]
fn population_case_does_not_hide_a_conflict_when_population_is_missing() {
    let value = with_doc("doc-orbalin-b", |d| d.population = "Adults".to_owned());
    let result = ask("Does orbalin help with ember fatigue?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Conflict);
}

#[test]
fn rights_block_outranks_retraction() {
    let value = with_doc("doc-quenzil-retracted", |d| {
        d.rights = safeevidence_contracts::evidence::EvidenceCorpusRights::Unknown;
    });
    let result = ask("Does quenzil help adults with hollow cough?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert_eq!(result.reason, ReasonCode::RightsUnresolved);
}

#[test]
fn citations_must_be_in_bounds_and_on_a_whole_sentence() {
    let corpus = corpus();
    let brief = ask(ADULT, &corpus).brief.unwrap();
    let line = brief.lines().find(|l| l.starts_with("- ")).unwrap();
    let (claim_part, citation) = line.rsplit_once(" [").unwrap();
    let doc = citation.split(' ').next().unwrap();
    for range in ["0..999999", "5..5", "9..3"] {
        let forged = brief.replace(line, &format!("{claim_part} [{doc} {range}]"));
        assert!(verify_brief(&forged, &corpus).is_err(), "{range}");
    }
}

#[test]
fn every_negation_word_counts_and_every_unit_counts() {
    let base = "The score moved by 12 at 8.";
    for word in ["not", "no", "never", "without", "neither", "nor", "failed"] {
        let claim = format!("The score {word} moved by 12 at 8.");
        assert_eq!(claim_defect(&claim, base), Some("negation"), "{word}");
    }
    for unit in ["mg", "g", "mcg", "kg", "ml", "weeks", "months", "points"] {
        let claim = format!("The score moved by 12 {unit} at 8.");
        assert_eq!(claim_defect(&claim, base), Some("unit"), "{unit}");
    }
}

#[test]
fn guard_precedence_holds_when_several_guards_apply() {
    // BLOCKED outranks CONFLICT.
    let value = with_doc("doc-orbalin-b", |d| {
        d.rights = safeevidence_contracts::evidence::EvidenceCorpusRights::Unknown;
    });
    let result = ask("Does orbalin help adults with ember fatigue?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert_eq!(result.reason, ReasonCode::RightsUnresolved);
    // CONFLICT outranks within-study disagreement's ABSTAIN. Study A's two reports disagree,
    // and study B also contradicts A's first report.
    let mut value = corpus();
    let mut second_report = value
        .documents
        .iter()
        .find(|d| d.doc_id == "doc-orbalin-b")
        .unwrap()
        .clone();
    second_report.doc_id = "doc-orbalin-a-second-report".to_owned();
    second_report.study_id = "study-orbalin-a".to_owned();
    value.documents.push(second_report);
    let result = ask("Does orbalin help adults with ember fatigue?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Conflict);
    assert_eq!(result.reason, ReasonCode::MaterialContradiction);
}

#[test]
fn asking_for_a_population_is_pointless_when_nothing_can_be_cited() {
    let result = ask("Does quenzil help with hollow cough?", &corpus());
    assert_eq!(result.outcome, TerminalOutcome::Abstain);
    assert_eq!(result.reason, ReasonCode::SourceInvalidOrRetracted);
}

#[test]
fn rights_refusal_trace_counts_no_denied_source_as_usable_and_lists_each_once() {
    let value = with_doc("doc-orbalin-b", |d| {
        d.rights = safeevidence_contracts::evidence::EvidenceCorpusRights::Unknown;
    });
    let result = ask("Does orbalin help adults with ember fatigue?", &value);
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert_eq!(result.funnel.rights_admissible, 0);
    assert_eq!(result.funnel.applicable, 0);
    assert_eq!(result.funnel.independent_studies, 0);
    assert_eq!(result.excluded.len(), 1);
    assert_eq!(result.excluded[0].detail, "rights not established");
    assert_eq!(result.excluded[0].reason, ReasonCode::RightsUnresolved);
    let denied_and_other_population = with_doc("doc-veltrix-peds", |d| {
        d.rights = safeevidence_contracts::evidence::EvidenceCorpusRights::Unknown;
    });
    let result = ask(ADULT, &denied_and_other_population);
    assert_eq!(result.outcome, TerminalOutcome::Blocked);
    assert_eq!(result.excluded.len(), 1, "one entry per document");
}

#[test]
fn population_missing_keeps_its_own_reason_beside_other_rules() {
    let value = with_doc("doc-veltrix-peds", |d| {
        d.publication_state = PublicationState::Superseded;
    });
    let result = ask("Does veltrixamine help with glimmer syndrome?", &value);
    assert_eq!(result.outcome, TerminalOutcome::AskMore);
    assert_eq!(result.reason, ReasonCode::MissingCriticalContext);
}

/// A digest of the serialized manifest, so a change here means retries of stored proofs conflict.
#[test]
fn proof_identity_is_pinned_for_the_fixture() {
    let manifest = ask(ADULT, &corpus()).manifest.unwrap();
    assert_eq!(
        manifest.proof_id,
        "vs1a-23b55df9e5d6e7e76c991aa9233bc6d853d8bc9059f1cab62c21cedaad4b74fe"
    );
}

/// `plan-v1.4`: what Ask actually returns for each donor question, pinned so a change is seen. Ask's
/// closed grammar refuses nearly all of them before retrieval runs. That is not parity with the donor,
/// though 6 happen to share its state. `EVIDENCE_INSUFFICIENT` is the closest allowed code for an
/// unparsed question.
#[test]
fn every_donor_fixture_question_gets_its_pinned_refusal_and_no_text() {
    const ABSTAIN: (TerminalOutcome, ReasonCode) =
        (TerminalOutcome::Abstain, ReasonCode::EvidenceInsufficient);
    let pinned = [
        ("tool-available-routes-to-tool", ABSTAIN),
        ("evidence-class-retrieves-evidence", ABSTAIN),
        ("no-requested-tool-plain-answer", ABSTAIN),
        ("unknown-tool-fails-closed", ABSTAIN),
        ("clinical-score-gate-closed-t017", ABSTAIN),
        ("interaction-lookup-gate-closed-t018", ABSTAIN),
        ("tool-unavailable-fails-closed", ABSTAIN),
        ("tool-timeout-fails-closed", ABSTAIN),
        ("missing-slot-asks-more-en", ABSTAIN),
        (
            "emergency-keyword-en",
            (
                TerminalOutcome::Escalate,
                ReasonCode::ClinicianAuthorityRequired,
            ),
        ),
        (
            "emergency-keyword-ar-msa",
            (TerminalOutcome::Abstain, ReasonCode::UnsupportedLanguage),
        ),
        ("severe-pattern-escalates", ABSTAIN),
        ("ambiguous-risk-fails-toward-escalation-not-answer", ABSTAIN),
        ("injection-suppressed-emergency-preserved", ABSTAIN),
        ("injection-suppressed-missing-slot-preserved", ABSTAIN),
        ("spoofed-provenance-rejected", ABSTAIN),
        ("genuine-provenance-accepted", ABSTAIN),
    ];
    let mut cases = Vec::new();
    for file in [
        include_str!("../../safeevidence-assurance/tests/fixtures/t13_cases_us1_tool_routing.json"),
        include_str!(
            "../../safeevidence-assurance/tests/fixtures/t13_cases_us2_context_safety.json"
        ),
        include_str!(
            "../../safeevidence-assurance/tests/fixtures/t13_cases_us3_injection_spoof.json"
        ),
    ] {
        let document: serde_json::Value = serde_json::from_str(file).expect("case vectors parse");
        cases.extend(document["cases"].as_array().expect("cases").clone());
    }
    assert_eq!(cases.len(), pinned.len());
    let corpus = corpus();
    for (id, expected) in pinned {
        let case = cases
            .iter()
            .find(|case| case["case_id"] == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        let result = ask(case["text"].as_str().expect("text"), &corpus);
        assert_eq!((result.outcome, result.reason), expected, "{id}");
        assert!(result.brief.is_none() && result.manifest.is_none(), "{id}");
    }
}

//! TA-14 for VS-1a: with no worker yet, `plan-v1.1` §C has its crash and timeout clauses use fault
//! injection at the brief and verification boundaries. The real worker clauses return with WP-12's
//! generator. The commit boundary is tested in the desktop command and `proof_commit.rs`.

use safeevidence_ask::{
    AnswerSeams, AskResult, Corpus, StepFailure, ask, ask_with_seams, load_corpus,
};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::SupportLabel;

const FIXTURE: &[u8] = include_bytes!("../fixtures/vs1a_corpus.json");
const ANSWERED: &str = "Does veltrixamine help adults with glimmer syndrome?";

fn corpus() -> Corpus {
    load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture loads")
}

struct FailsRendering(StepFailure);

impl AnswerSeams for FailsRendering {
    fn after_render(&self, _brief: String) -> Result<String, StepFailure> {
        Err(self.0)
    }
}

struct FailsBeforeVerifying(StepFailure);

impl AnswerSeams for FailsBeforeVerifying {
    fn before_verify(&self) -> Result<(), StepFailure> {
        Err(self.0)
    }
}

struct ChangesTheText(fn(String) -> String);

impl AnswerSeams for ChangesTheText {
    fn after_render(&self, brief: String) -> Result<String, StepFailure> {
        Ok((self.0)(brief))
    }
}

fn assert_refused(result: &AskResult, outcome: TerminalOutcome, reason: ReasonCode) {
    assert_eq!((result.outcome, result.reason), (outcome, reason));
    assert!(result.brief.is_none(), "no text survives the fault");
    assert!(result.manifest.is_none(), "no proof survives the fault");
    assert_eq!(result.funnel.retrieved, 3, "the trace is kept");
    assert_eq!(result.excluded.len(), 1, "the exclusions are kept");
}

#[test]
fn a_crash_at_either_boundary_is_a_reason_coded_block() {
    let corpus = corpus();
    assert_refused(
        &ask_with_seams(ANSWERED, &corpus, &FailsRendering(StepFailure::Crashed)),
        TerminalOutcome::Blocked,
        ReasonCode::ToolFailure,
    );
    assert_refused(
        &ask_with_seams(
            ANSWERED,
            &corpus,
            &FailsBeforeVerifying(StepFailure::Crashed),
        ),
        TerminalOutcome::Blocked,
        ReasonCode::ToolFailure,
    );
}

#[test]
fn a_timeout_at_either_boundary_is_a_reason_coded_abstention() {
    let corpus = corpus();
    assert_refused(
        &ask_with_seams(ANSWERED, &corpus, &FailsRendering(StepFailure::TimedOut)),
        TerminalOutcome::Abstain,
        ReasonCode::TimeBudgetExhausted,
    );
    assert_refused(
        &ask_with_seams(
            ANSWERED,
            &corpus,
            &FailsBeforeVerifying(StepFailure::TimedOut),
        ),
        TerminalOutcome::Abstain,
        ReasonCode::TimeBudgetExhausted,
    );
}

/// What a broken step might hand on, as opposed to failing outright: verification reads the text
/// itself, so each of these must be refused without any further fault.
#[test]
fn text_changed_after_rendering_never_becomes_a_proof() {
    let corpus = corpus();
    let changes: [fn(String) -> String; 3] = [
        |brief| brief.replace("12 points", "21 points"),
        |brief| brief + "\nThis treatment is safe.",
        |_| String::new(),
    ];
    for change in changes {
        assert_refused(
            &ask_with_seams(ANSWERED, &corpus, &ChangesTheText(change)),
            TerminalOutcome::Abstain,
            ReasonCode::PostVerificationFailed,
        );
    }
}

/// VS-1a has no generator, so this is the clause's only state: the template brief, every time.
#[test]
fn with_the_generator_off_the_template_brief_is_produced() {
    let corpus = corpus();
    let first = ask(ANSWERED, &corpus);
    let manifest = first.manifest.as_ref().expect("manifest");
    assert_eq!(manifest.components.generator, None);
    assert_eq!(first.brief, ask(ANSWERED, &corpus).brief);
}

#[test]
fn every_claim_has_a_span_a_support_label_and_a_validity_epoch() {
    let corpus = corpus();
    let result = ask(ANSWERED, &corpus);
    let manifest = result.manifest.expect("manifest");
    assert_eq!(manifest.validity_epoch, corpus.validity_epoch);
    assert!(!manifest.claims.is_empty());
    for claim in &manifest.claims {
        assert_eq!(claim.spans.len(), 1, "{}", claim.claim_id);
        assert_eq!(claim.support, SupportLabel::Supported, "{}", claim.claim_id);
    }
}

/// Ask has no streamed draft. The nearest thing is its output before commit, which must not say it
/// is committed: only the store can make that true.
#[test]
fn nothing_from_ask_is_labelled_committed() {
    let result = ask(ANSWERED, &corpus());
    assert_eq!(
        result.manifest.expect("manifest").state,
        ProofState::VerifiedUncommitted
    );
}

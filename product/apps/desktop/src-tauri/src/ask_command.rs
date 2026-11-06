//! The one native command: ask over the invented fixture, commit, then show.
//!
//! P00 proof step 6: text reaches an assured surface only after durable acknowledgement. So this
//! returns the text read back from the store, and only if the stored proof reads `COMMITTED`.
//! Every request ends in one outcome and reason: a failure is a refusal with no text.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use safeevidence_ask::{AskResult, Corpus, Funnel, ask, load_corpus};
use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_proofstore::{ProofStore, StoreError};
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;
use serde::Serialize;

const FIXTURE: &[u8] =
    include_bytes!("../../../../crates/safeevidence-ask/fixtures/vs1a_corpus.json");
const MAX_QUESTION_SCALARS: usize = 1024;
const SESSION_DIR: &str = "synthetic-ask-session";
const LOCK_FILE: &str = "synthetic-ask-session.lock";

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunnelView {
    indexed: usize,
    retrieved: usize,
    citable: usize,
    rights_admissible: usize,
    applicable: usize,
    independent_studies: usize,
    verified_claims: usize,
}

impl From<&Funnel> for FunnelView {
    fn from(funnel: &Funnel) -> Self {
        Self {
            indexed: funnel.indexed,
            retrieved: funnel.retrieved,
            citable: funnel.citable,
            rights_admissible: funnel.rights_admissible,
            applicable: funnel.applicable,
            independent_studies: funnel.independent_studies,
            verified_claims: funnel.verified_claims,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludedView {
    doc_id: String,
    reason: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationView {
    claim_id: String,
    source_id: String,
    source_version: String,
    start_scalar: u64,
    end_scalar: u64,
    source_text: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AskView {
    schema_version: u8,
    fixture_only: bool,
    outcome: TerminalOutcome,
    reason: ReasonCode,
    funnel: FunnelView,
    excluded: Vec<ExcludedView>,
    brief: Option<String>,
    proof_id: Option<String>,
    citations: Vec<CitationView>,
}

/// Takes this data directory for one running instance and clears what a killed run left. The lock
/// lasts as long as the returned file. Without it, a second instance could delete a live store.
fn claim_data_dir(data_dir: &Path) -> Result<File, String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|_| "could not create the data directory".to_owned())?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data_dir.join(LOCK_FILE))
        .map_err(|_| "could not open the session lock".to_owned())?;
    lock.try_lock()
        .map_err(|_| "another instance holds this session".to_owned())?;
    match std::fs::remove_dir_all(data_dir.join(SESSION_DIR)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("could not clear the previous session".to_owned()),
    }
    Ok(lock)
}

/// A store for one launch. The key lives only in memory here. The directory is deleted on close, and
/// a killed run's directory is deleted when the next launch claims it. See this app's `PROVENANCE.md`.
pub struct AskSession {
    store: ProofStore,
    corpus: Corpus,
    dir: PathBuf,
    _lease: VaultLease,
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| "no system randomness".to_owned())?;
    Ok(bytes)
}

type Withheld = (TerminalOutcome, ReasonCode);

const TOOL_FAILURE: Withheld = (TerminalOutcome::Blocked, ReasonCode::ToolFailure);

fn denied(error: StoreError) -> Withheld {
    let reason = match error {
        StoreError::RightsChanged => ReasonCode::RightsUnresolved,
        StoreError::ProofRace { .. } | StoreError::SourceAmended(_) => {
            ReasonCode::ProofRaceInvalidated
        }
        StoreError::SourceNotAdmitted(_) => ReasonCode::SourceUnavailable,
        _ => ReasonCode::ToolFailure,
    };
    (TerminalOutcome::Blocked, reason)
}

impl AskSession {
    fn open(data_dir: &Path) -> Result<Self, String> {
        let dir = data_dir.join(SESSION_DIR);
        std::fs::create_dir_all(&dir).map_err(|_| "could not create the session".to_owned())?;
        let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE))
            .map_err(|_| "the fixture did not load".to_owned())?;
        let generation = KeyGeneration::new(1).map_err(|_| "invalid key generation".to_owned())?;
        let identity =
            VaultLeaseIdentity::new(VaultId::from_bytes(random::<VAULT_ID_BYTES>()?), generation);
        let lease = VaultLease::new(identity);
        let context = KeyDerivationContext::new(
            identity.vault_id(),
            identity.key_generation(),
            KeyPurpose::StructuredStore,
        );
        let key = OwnedKeyMaterial::from_bytes(random::<KEY_MATERIAL_BYTES>()?);
        let mut store = ProofStore::open(
            dir.join("vault.db"),
            lease.keyed_handle_lease(),
            context,
            &key,
        )
        .map_err(|_| "the store did not open".to_owned())?;
        store
            .advance_epoch(corpus.validity_epoch)
            .and_then(|()| store.set_rights_grant(&corpus.rights_grant_version))
            .map_err(|_| "the store did not initialize".to_owned())?;
        for document in &corpus.documents {
            store
                .put_source(&document.doc_id, document.text.as_bytes())
                .map_err(|_| "the store did not admit the fixture".to_owned())?;
        }
        Ok(Self {
            store,
            corpus,
            dir,
            _lease: lease,
        })
    }

    fn ask(&mut self, question: &str) -> AskView {
        let result = ask(question, &self.corpus);
        match self.committed(&result) {
            Ok(Some((brief, proof_id, citations))) => {
                view(&result, Some(brief), Some(proof_id), citations)
            }
            Ok(None) => view(&result, None, None, Vec::new()),
            Err((outcome, reason)) => AskView {
                outcome,
                reason,
                ..view(&result, None, None, Vec::new())
            },
        }
    }

    /// `Ok(None)` is a refusal from Ask. `Err` withholds an answer that did not reach `COMMITTED`.
    /// A denied proof admission is `BLOCKED`, the first guard in the decision contract.
    fn committed(
        &mut self,
        result: &AskResult,
    ) -> Result<Option<(String, String, Vec<CitationView>)>, Withheld> {
        let (Some(manifest), Some(brief)) = (&result.manifest, &result.brief) else {
            return Ok(None);
        };
        self.store
            .commit(manifest, brief.as_bytes())
            .map_err(denied)?;
        let stored = self.store.read(&manifest.proof_id).map_err(denied)?;
        match stored.state {
            ProofState::Committed => {}
            ProofState::CurrentnessUnknown => {
                return Err((TerminalOutcome::Abstain, ReasonCode::CurrentnessUnknown));
            }
            _ => {
                return Err((
                    TerminalOutcome::Blocked,
                    ReasonCode::SourceInvalidOrRetracted,
                ));
            }
        }
        let text = String::from_utf8(stored.final_text).map_err(|_| TOOL_FAILURE)?;
        let mut citations = Vec::new();
        for claim in &stored.manifest.claims {
            for span in &claim.spans {
                let source = self
                    .store
                    .source(&span.source_id)
                    .map_err(denied)?
                    .ok_or((TerminalOutcome::Blocked, ReasonCode::SourceUnavailable))?;
                citations.push(CitationView {
                    claim_id: claim.claim_id.clone(),
                    source_id: span.source_id.clone(),
                    source_version: span.source_version.clone(),
                    start_scalar: span.start_scalar,
                    end_scalar: span.end_scalar,
                    source_text: String::from_utf8(source).map_err(|_| TOOL_FAILURE)?,
                });
            }
        }
        Ok(Some((text, stored.manifest.proof_id, citations)))
    }

    fn close(self) {
        let Self { store, dir, .. } = self;
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn view(
    result: &AskResult,
    brief: Option<String>,
    proof_id: Option<String>,
    citations: Vec<CitationView>,
) -> AskView {
    AskView {
        excluded: result
            .excluded
            .iter()
            .map(|(doc_id, reason)| ExcludedView {
                doc_id: doc_id.clone(),
                reason: reason.clone(),
            })
            .collect(),
        brief,
        proof_id,
        citations,
        ..refusal(result.outcome, result.reason, &result.funnel)
    }
}

fn refusal(outcome: TerminalOutcome, reason: ReasonCode, funnel: &Funnel) -> AskView {
    AskView {
        schema_version: 1,
        fixture_only: true,
        outcome,
        reason,
        funnel: FunnelView::from(funnel),
        excluded: Vec::new(),
        brief: None,
        proof_id: None,
        citations: Vec::new(),
    }
}

#[derive(Default)]
struct Inner {
    data_dir: Option<PathBuf>,
    lock: Option<File>,
    session: Option<AskSession>,
}

#[derive(Default)]
pub struct AskState(Mutex<Inner>);

impl AskState {
    /// Claims the directory now, so a killed run's store is gone even if nothing is asked.
    pub fn set_data_dir(&self, data_dir: PathBuf) {
        if let Ok(mut inner) = self.0.lock() {
            // A second call must not drop the lock a live session depends on.
            if inner.lock.is_some() {
                return;
            }
            inner.lock = claim_data_dir(&data_dir).ok();
            inner.data_dir = Some(data_dir);
        }
    }

    pub fn close(&self) {
        if let Ok(mut inner) = self.0.lock()
            && let Some(session) = inner.session.take()
        {
            session.close();
        }
    }

    fn answer(&self, question: &str) -> AskView {
        let unavailable = || refusal(TOOL_FAILURE.0, TOOL_FAILURE.1, &Funnel::default());
        // Outside the question grammar, as Ask treats any other question it cannot parse.
        if question.chars().count() > MAX_QUESTION_SCALARS {
            return refusal(
                TerminalOutcome::Abstain,
                ReasonCode::EvidenceInsufficient,
                &Funnel::default(),
            );
        }
        let Ok(mut inner) = self.0.lock() else {
            return unavailable();
        };
        if inner.session.is_none() {
            let (Some(data_dir), Some(_)) = (inner.data_dir.clone(), inner.lock.as_ref()) else {
                return unavailable();
            };
            inner.session = AskSession::open(&data_dir).ok();
        }
        match inner.session.as_mut() {
            Some(session) => session.ask(question),
            None => unavailable(),
        }
    }
}

#[tauri::command]
pub fn ask_question(state: tauri::State<'_, AskState>, question: String) -> AskView {
    state.answer(&question)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ANSWERED: &str = "Does veltrixamine help adults with glimmer syndrome?";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!("se-desktop-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_answer_shows_the_committed_text_with_its_spans() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let view = session.ask(ANSWERED);
        assert_eq!(view.outcome, TerminalOutcome::AnswerWithCaution);
        let proof_id = view.proof_id.as_deref().expect("proof");
        let stored = session.store.read(proof_id).expect("stored");
        assert_eq!(stored.state, ProofState::Committed);
        assert_eq!(
            view.brief.as_deref().map(str::as_bytes),
            Some(stored.final_text.as_slice())
        );
        assert!(!view.citations.is_empty());
        for citation in &view.citations {
            let scalars = citation.source_text.chars().count() as u64;
            assert!(citation.start_scalar < citation.end_scalar && citation.end_scalar <= scalars);
        }
        assert!(view.funnel.verified_claims > 0);
    }

    #[test]
    fn asking_again_replays_one_commit() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let first = session.ask(ANSWERED);
        assert_eq!(session.ask(ANSWERED), first);
        let proof_id = first.proof_id.as_deref().expect("proof");
        assert_eq!(
            session.store.audit_events(proof_id).expect("audit"),
            ["COMMITTED"]
        );
    }

    #[test]
    fn a_refusal_shows_its_trace_and_no_text() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        for question in [
            "Does veltrixamine help with glimmer syndrome?",
            "Does nothingatall help adults with glimmer syndrome?",
            "What should I take?",
            "\u{0647}\u{0644} \u{064A}\u{0633}\u{0627}\u{0639}\u{062F}\u{061F}",
            "",
        ] {
            let view = session.ask(question);
            assert!(
                !matches!(
                    view.outcome,
                    TerminalOutcome::Answer | TerminalOutcome::AnswerWithCaution
                ),
                "{question}"
            );
            assert!(view.brief.is_none() && view.proof_id.is_none() && view.citations.is_empty());
        }
    }

    fn assert_withheld(view: &AskView, outcome: TerminalOutcome, reason: ReasonCode) {
        assert_eq!((view.outcome, view.reason), (outcome, reason));
        assert!(view.brief.is_none() && view.proof_id.is_none() && view.citations.is_empty());
    }

    #[test]
    fn a_denied_proof_admission_is_blocked_with_no_text() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        session
            .store
            .set_rights_grant("a-later-grant")
            .expect("grant");
        let view = session.ask(ANSWERED);
        assert_withheld(
            &view,
            TerminalOutcome::Blocked,
            ReasonCode::RightsUnresolved,
        );
        assert!(view.funnel.verified_claims > 0, "the trace stays");

        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        session.store.advance_epoch(99).expect("epoch");
        let view = session.ask(ANSWERED);
        assert_withheld(
            &view,
            TerminalOutcome::Blocked,
            ReasonCode::ProofRaceInvalidated,
        );
    }

    #[test]
    fn an_answer_that_stops_being_assured_is_withheld_on_replay() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let proof_id = session.ask(ANSWERED).proof_id.expect("proof");
        session.store.advance_epoch(99).expect("epoch");
        let view = session.ask(ANSWERED);
        assert_withheld(
            &view,
            TerminalOutcome::Abstain,
            ReasonCode::CurrentnessUnknown,
        );

        session
            .store
            .invalidate(&proof_id, "synthetic")
            .expect("invalidate");
        let view = session.ask(ANSWERED);
        assert_withheld(
            &view,
            TerminalOutcome::Blocked,
            ReasonCode::SourceInvalidOrRetracted,
        );
    }

    #[test]
    fn claiming_clears_a_killed_runs_store_before_any_question() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let proof_id = session.ask(ANSWERED).proof_id.expect("proof");
        let session_dir = session.dir.clone();
        drop(session);
        assert!(session_dir.exists(), "a kill leaves the store behind");
        let state = AskState::default();
        state.set_data_dir(dir.0.clone());
        assert!(!session_dir.exists());
        let mut session = AskSession::open(&dir.0).expect("new session");
        assert!(matches!(
            session.store.read(&proof_id),
            Err(StoreError::UnknownProof)
        ));
        session.close();
        assert!(!session_dir.exists());
    }

    #[test]
    fn a_second_instance_is_refused_and_leaves_the_live_store_alone() {
        let dir = TempDir::new();
        let first = AskState::default();
        first.set_data_dir(dir.0.clone());
        let answered = first.answer(ANSWERED);
        let proof_id = answered.proof_id.clone().expect("proof");

        let second = AskState::default();
        second.set_data_dir(dir.0.clone());
        let refused = second.answer(ANSWERED);
        assert_withheld(&refused, TerminalOutcome::Blocked, ReasonCode::ToolFailure);

        assert_eq!(
            first.answer(ANSWERED).proof_id.as_deref(),
            Some(proof_id.as_str())
        );
        first.set_data_dir(dir.0.clone());
        assert!(
            claim_data_dir(&dir.0).is_err(),
            "a repeated call keeps the lock"
        );
        first.close();
    }

    #[test]
    fn every_failure_before_the_core_is_one_outcome_with_a_reason() {
        let not_ready = AskState::default().answer(ANSWERED);
        assert_withheld(
            &not_ready,
            TerminalOutcome::Blocked,
            ReasonCode::ToolFailure,
        );
        assert_eq!(not_ready.funnel.indexed, 0);

        let too_long = AskState::default().answer(&"x".repeat(MAX_QUESTION_SCALARS + 1));
        assert_withheld(
            &too_long,
            TerminalOutcome::Abstain,
            ReasonCode::EvidenceInsufficient,
        );

        let dir = TempDir::new();
        let occupied = dir.0.join(SESSION_DIR);
        std::fs::write(&occupied, b"not a directory").expect("file");
        let state = AskState::default();
        let lock = claim_data_dir(&dir.0);
        assert!(
            lock.is_err(),
            "a session path that cannot be cleared is not claimed"
        );
        drop(lock);
        state.set_data_dir(dir.0.clone());
        assert_withheld(
            &state.answer(ANSWERED),
            TerminalOutcome::Blocked,
            ReasonCode::ToolFailure,
        );
    }

    #[test]
    fn the_response_uses_the_view_protocol_and_no_percentage() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let json = serde_json::to_value(session.ask(ANSWERED)).expect("json");
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["fixtureOnly"], true);
        assert_eq!(json["outcome"], "ANSWER_WITH_CAUTION");
        assert!(json["funnel"]["rightsAdmissible"].is_number());
        assert!(json["citations"][0]["startScalar"].is_number());
        assert!(json.get("confidence").is_none());
    }
}

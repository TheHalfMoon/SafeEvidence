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
use safeevidence_proofstore::{ProofStore, SCHEMA_OBJECTS_SHA256, StoreError};
use safeevidence_vault::vault_keys::{KeyDerivationContext, KeyPurpose};
use safeevidence_vault::vault_lease::VaultLease;
use serde::Serialize;

use crate::custody::{DATABASE_FILE, KeySource, is_established, mark_established, open_root_key};

const FIXTURE: &[u8] =
    include_bytes!("../../../../crates/safeevidence-ask/fixtures/vs1a_corpus.json");
const MAX_QUESTION_SCALARS: usize = 1024;
const STORE_DIR_PREFIX: &str = "synthetic-ask-store-";
const LOCK_FILE: &str = "synthetic-ask-store.lock";

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
    /// True if this proof was already in the store, so this request committed nothing new.
    already_committed: bool,
    citations: Vec<CitationView>,
}

/// An answer that reached `COMMITTED`.
struct CommittedAnswer {
    brief: String,
    proof_id: String,
    already_committed: bool,
    citations: Vec<CitationView>,
}

/// The store for this fixture and store schema. A store is bound to its fixture's sources, epoch and
/// grant, and the store refuses a schema it does not match, with no migrations yet. So a changed fixture
/// or schema gets its own store rather than being refused by the old one, and the old store stays.
fn store_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(format!("{STORE_DIR_PREFIX}{}", store_key()))
}

fn store_key() -> String {
    let mut basis = DigestSha256::of(FIXTURE).to_hex();
    basis.push_str(SCHEMA_OBJECTS_SHA256);
    DigestSha256::of(basis.as_bytes()).to_hex()[..16].to_owned()
}

/// Takes this data directory for one running instance. The lock lasts as long as the returned file.
/// Without it, two instances could write the same store.
fn claim_data_dir(data_dir: &Path) -> Result<File, String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|_| "could not create the data directory".to_owned())?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data_dir.join(LOCK_FILE))
        .map_err(|_| "could not open the store lock".to_owned())?;
    lock.try_lock()
        .map_err(|_| "another instance holds this store".to_owned())?;
    Ok(lock)
}

/// The open store, keyed by the OS protector. It keeps answers across launches.
pub struct AskSession {
    store: ProofStore,
    corpus: Corpus,
    _lease: VaultLease,
    /// A failure the next commit returns instead of committing, for TA-14's commit boundary.
    #[cfg(test)]
    commit_fault: Option<StoreError>,
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

fn committing(error: StoreError) -> Withheld {
    match error {
        StoreError::Busy => (TerminalOutcome::Abstain, ReasonCode::TimeBudgetExhausted),
        other => denied(other),
    }
}

impl AskSession {
    fn open(data_dir: &Path, keys: &KeySource) -> Result<Self, String> {
        let dir = store_dir(data_dir);
        std::fs::create_dir_all(&dir).map_err(|_| "could not create the store".to_owned())?;
        let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE))
            .map_err(|_| "the fixture did not load".to_owned())?;
        let opened = open_root_key(&dir, keys).map_err(|error| error.to_string())?;
        let lease = VaultLease::new(opened.identity);
        let context = KeyDerivationContext::new(
            opened.identity.vault_id(),
            opened.identity.key_generation(),
            KeyPurpose::StructuredStore,
        );
        let open_store = if is_established(&dir) {
            ProofStore::open_existing
        } else {
            ProofStore::open
        };
        let mut store = open_store(
            dir.join(DATABASE_FILE),
            lease.keyed_handle_lease(),
            context,
            &opened.key,
        )
        .map_err(|_| "the store did not open".to_owned())?;
        let current = store
            .epoch()
            .map_err(|_| "the store did not read".to_owned())?;
        if current < corpus.validity_epoch {
            store
                .advance_epoch(corpus.validity_epoch)
                .map_err(|_| "the store did not initialize".to_owned())?;
        }
        store
            .set_rights_grant(&corpus.rights_grant_version)
            .map_err(|_| "the store did not initialize".to_owned())?;
        for document in &corpus.documents {
            store
                .put_source(&document.doc_id, document.text.as_bytes())
                .map_err(|_| "the store did not admit the fixture".to_owned())?;
        }
        mark_established(&dir).map_err(|error| error.to_string())?;
        Ok(Self {
            store,
            corpus,
            _lease: lease,
            #[cfg(test)]
            commit_fault: None,
        })
    }

    fn ask(&mut self, question: &str) -> AskView {
        let result = ask(question, &self.corpus);
        match self.committed(&result) {
            Ok(Some(answer)) => AskView {
                already_committed: answer.already_committed,
                ..view(
                    &result,
                    Some(answer.brief),
                    Some(answer.proof_id),
                    answer.citations,
                )
            },
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
    fn committed(&mut self, result: &AskResult) -> Result<Option<CommittedAnswer>, Withheld> {
        let (Some(manifest), Some(brief)) = (&result.manifest, &result.brief) else {
            return Ok(None);
        };
        #[cfg(test)]
        if let Some(fault) = self.commit_fault.take() {
            return Err(committing(fault));
        }
        // A busy store at commit wrote nothing and did not answer in time: the same outcome as a step
        // that timed out. After a commit, the proof is stored, so `denied` keeps its usual mapping.
        let receipt = self
            .store
            .commit(manifest, brief.as_bytes())
            .map_err(committing)?;
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
        Ok(Some(CommittedAnswer {
            brief: text,
            proof_id: stored.manifest.proof_id,
            already_committed: receipt.replayed,
            citations,
        }))
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
            .map(|exclusion| ExcludedView {
                doc_id: exclusion.doc_id.clone(),
                reason: exclusion.detail.clone(),
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
        already_committed: false,
        citations: Vec::new(),
    }
}

#[derive(Default)]
struct Inner {
    data_dir: Option<PathBuf>,
    lock: Option<File>,
    session: Option<AskSession>,
    keys: KeySource,
}

#[derive(Default)]
pub struct AskState(Mutex<Inner>);

impl AskState {
    /// Claims the directory now, so a second instance is refused from the start.
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

    /// Closes the store. Its contents stay for the next launch.
    pub fn close(&self) {
        if let Ok(mut inner) = self.0.lock() {
            inner.session = None;
        }
    }

    #[cfg(test)]
    pub fn use_test_keys(&self) {
        if let Ok(mut inner) = self.0.lock() {
            inner.keys = crate::custody::test_keys::SOURCE;
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
            let keys = inner.keys;
            inner.session = AskSession::open(&data_dir, &keys).ok();
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
    const TEST_KEYS: KeySource = crate::custody::test_keys::SOURCE;
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
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
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
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
        let first = session.ask(ANSWERED);
        assert_replayed(&session.ask(ANSWERED), &first);
        let proof_id = first.proof_id.as_deref().expect("proof");
        assert_eq!(
            session.store.audit_events(proof_id).expect("audit"),
            ["COMMITTED"]
        );
    }

    /// P00's "after DB commit before UI notification", in part: the first request's view is lost
    /// and the next launch must find that proof, not commit a second one. The session closes
    /// cleanly here. `proof_commit.rs` kills a process during commits, at store level.
    #[test]
    fn a_lost_view_after_commit_recovers_the_same_proof() {
        let dir = TempDir::new();
        let (proof_id, text) = {
            let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
            let result = ask(ANSWERED, &session.corpus);
            let manifest = result.manifest.expect("manifest");
            let text = result.brief.expect("brief");
            session
                .store
                .commit(&manifest, text.as_bytes())
                .expect("commit");
            (manifest.proof_id, text)
        };
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session after crash");
        let view = session.ask(ANSWERED);
        assert!(view.already_committed, "it was committed before the crash");
        assert_eq!(view.proof_id.as_deref(), Some(proof_id.as_str()));
        assert_eq!(view.brief.as_deref(), Some(text.as_str()));
        assert_eq!(
            session.store.audit_events(&proof_id).expect("audit"),
            ["COMMITTED"]
        );
    }

    /// TA-14's commit boundary: a commit that fails reaches the person as a refusal with no text.
    /// The fault replaces the store's answer, so it does not show what the store itself would do on
    /// that failure. `CommitUnknown` needs a `rusqlite` error to build, so it is not here.
    #[test]
    fn a_failed_commit_is_a_refusal_with_a_reason_and_no_text() {
        let cases = [
            (
                StoreError::Busy,
                TerminalOutcome::Abstain,
                ReasonCode::TimeBudgetExhausted,
            ),
            (
                StoreError::TransactionLost,
                TerminalOutcome::Blocked,
                ReasonCode::ToolFailure,
            ),
            (
                StoreError::NotDurable,
                TerminalOutcome::Blocked,
                ReasonCode::ToolFailure,
            ),
            (
                StoreError::Corrupt("synthetic".to_owned()),
                TerminalOutcome::Blocked,
                ReasonCode::ToolFailure,
            ),
        ];
        for (fault, outcome, reason) in cases {
            let dir = TempDir::new();
            let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
            session.commit_fault = Some(fault);
            assert_withheld(&session.ask(ANSWERED), outcome, reason);
            let next = session.ask(ANSWERED);
            assert!(
                !next.already_committed,
                "the refused request left nothing behind"
            );
        }
    }

    /// After a commit the proof is stored, so a busy store there is not a timeout before writing.
    #[test]
    fn a_busy_store_after_commit_keeps_the_usual_mapping() {
        assert_eq!(
            denied(StoreError::Busy),
            (TerminalOutcome::Blocked, ReasonCode::ToolFailure)
        );
    }

    #[test]
    fn a_refusal_shows_its_trace_and_no_text() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
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

    /// The same answer as `first`, found in the store rather than committed anew.
    fn assert_replayed(view: &AskView, first: &AskView) {
        assert!(!first.already_committed, "the first request commits it");
        assert!(view.already_committed, "a later request finds it stored");
        assert_eq!(view.proof_id, first.proof_id);
        assert_eq!(view.brief, first.brief);
        assert_eq!(view.citations, first.citations);
    }

    fn assert_withheld(view: &AskView, outcome: TerminalOutcome, reason: ReasonCode) {
        assert_eq!((view.outcome, view.reason), (outcome, reason));
        assert!(view.brief.is_none() && view.proof_id.is_none() && view.citations.is_empty());
    }

    #[test]
    fn a_denied_proof_admission_is_blocked_with_no_text() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
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
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
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
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
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
    fn an_answer_survives_a_restart_as_the_same_proof() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
        let first = session.ask(ANSWERED);
        let proof_id = first.proof_id.clone().expect("proof");
        drop(session);

        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("reopened");
        assert_eq!(
            session.store.read(&proof_id).expect("still stored").state,
            ProofState::Committed
        );
        assert_replayed(&session.ask(ANSWERED), &first);
        assert_eq!(
            session.store.audit_events(&proof_id).expect("audit"),
            ["COMMITTED"]
        );
    }

    #[test]
    fn closing_keeps_the_store_for_the_next_launch() {
        let dir = TempDir::new();
        let first = AskState::default();
        first.use_test_keys();
        first.set_data_dir(dir.0.clone());
        let answered = first.answer(ANSWERED);
        first.close();
        drop(first);

        let second = AskState::default();
        second.use_test_keys();
        second.set_data_dir(dir.0.clone());
        assert_replayed(&second.answer(ANSWERED), &answered);
        assert!(store_dir(&dir.0).join(DATABASE_FILE).exists());
    }

    #[test]
    fn the_store_directory_is_bound_to_the_fixture_and_the_schema() {
        let name = store_dir(Path::new("x"))
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        let mut basis = DigestSha256::of(FIXTURE).to_hex();
        basis.push_str(SCHEMA_OBJECTS_SHA256);
        let expected = DigestSha256::of(basis.as_bytes()).to_hex();
        assert_eq!(name, format!("{STORE_DIR_PREFIX}{}", &expected[..16]));
        let fixture_only = DigestSha256::of(FIXTURE).to_hex();
        assert_ne!(name, format!("{STORE_DIR_PREFIX}{}", &fixture_only[..16]));
    }

    #[test]
    fn a_store_whose_main_file_is_deleted_does_not_forget_what_it_held() {
        let dir = TempDir::new();
        let session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
        drop(session);
        std::fs::remove_file(store_dir(&dir.0).join(DATABASE_FILE)).expect("delete");
        assert!(AskSession::open(&dir.0, &TEST_KEYS).is_err());
        assert!(
            !store_dir(&dir.0).join(DATABASE_FILE).exists(),
            "nothing was recreated"
        );
    }

    /// The whole path on the real protector: a real key, a real store, and a real reopen.
    #[cfg(windows)]
    #[test]
    fn an_answer_survives_a_restart_on_real_dpapi() {
        let dir = TempDir::new();
        let keys = KeySource::default();
        let mut session = AskSession::open(&dir.0, &keys).expect("session");
        let first = session.ask(ANSWERED);
        let proof_id = first.proof_id.clone().expect("proof");
        drop(session);
        let mut session = AskSession::open(&dir.0, &keys).expect("reopened");
        assert_eq!(
            session.store.read(&proof_id).expect("stored").state,
            ProofState::Committed
        );
        assert_replayed(&session.ask(ANSWERED), &first);
    }

    #[test]
    fn a_lost_key_is_refused_and_keeps_the_store() {
        let dir = TempDir::new();
        let store_dir = store_dir(&dir.0);
        let session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
        drop(session);
        let database = std::fs::read(store_dir.join(DATABASE_FILE)).expect("store");
        std::fs::remove_file(store_dir.join(crate::custody::test_keys::KEY_FILE))
            .expect("lose key");

        assert!(AskSession::open(&dir.0, &TEST_KEYS).is_err());
        assert_eq!(
            std::fs::read(store_dir.join(DATABASE_FILE)).expect("store"),
            database
        );
    }

    #[test]
    fn a_wrong_key_is_refused_and_the_right_one_still_opens_the_store() {
        let dir = TempDir::new();
        let store_dir = store_dir(&dir.0);
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
        let proof_id = session.ask(ANSWERED).proof_id.expect("proof");
        drop(session);
        let key_file = store_dir.join(crate::custody::test_keys::KEY_FILE);
        std::fs::write(&key_file, [0x53]).expect("wrong key");
        assert!(AskSession::open(&dir.0, &TEST_KEYS).is_err());
        std::fs::write(&key_file, [0x52]).expect("right key");
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("reopened");
        assert_eq!(
            session.store.read(&proof_id).expect("still stored").state,
            ProofState::Committed
        );
    }

    #[test]
    fn a_second_instance_is_refused_and_leaves_the_live_store_alone() {
        let dir = TempDir::new();
        let first = AskState::default();
        first.use_test_keys();
        first.set_data_dir(dir.0.clone());
        let answered = first.answer(ANSWERED);
        let proof_id = answered.proof_id.clone().expect("proof");

        let second = AskState::default();
        second.use_test_keys();
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
        std::fs::write(store_dir(&dir.0), b"not a directory").expect("file");
        let state = AskState::default();
        state.use_test_keys();
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
        let mut session = AskSession::open(&dir.0, &TEST_KEYS).expect("session");
        let json = serde_json::to_value(session.ask(ANSWERED)).expect("json");
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["fixtureOnly"], true);
        assert_eq!(json["outcome"], "ANSWER_WITH_CAUTION");
        assert!(json["funnel"]["rightsAdmissible"].is_number());
        assert!(json["citations"][0]["startScalar"].is_number());
        assert!(json.get("confidence").is_none());
    }
}

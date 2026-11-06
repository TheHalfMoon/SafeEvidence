//! The one native command: ask over the invented fixture, commit, then show.
//!
//! P00 proof step 6: text reaches an assured surface only after durable acknowledgement. So this
//! returns the text read back from the store, and only if the stored proof reads `COMMITTED`.
//! Every failure before that returns a refusal with the trace and no text.

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

/// A store for one launch. The key lives only in memory here and the directory is deleted on close
/// and on the next launch, so nothing outlives this run. See this app's `PROVENANCE.md`.
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

impl AskSession {
    fn open(data_dir: &Path) -> Result<Self, String> {
        let dir = data_dir.join(SESSION_DIR);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("could not clear the previous session".to_owned()),
        }
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
            Err(reason) => AskView {
                outcome: TerminalOutcome::Abstain,
                reason,
                ..view(&result, None, None, Vec::new())
            },
        }
    }

    /// `Ok(None)` is a refusal from Ask. `Err` withholds an answer that did not reach `COMMITTED`.
    fn committed(
        &mut self,
        result: &AskResult,
    ) -> Result<Option<(String, String, Vec<CitationView>)>, ReasonCode> {
        let (Some(manifest), Some(brief)) = (&result.manifest, &result.brief) else {
            return Ok(None);
        };
        let reason = |error: StoreError| match error {
            StoreError::ProofRace { .. }
            | StoreError::RightsChanged
            | StoreError::SourceAmended(_) => ReasonCode::ProofRaceInvalidated,
            _ => ReasonCode::ToolFailure,
        };
        self.store
            .commit(manifest, brief.as_bytes())
            .map_err(reason)?;
        let stored = self.store.read(&manifest.proof_id).map_err(reason)?;
        if stored.state != ProofState::Committed {
            return Err(ReasonCode::CurrentnessUnknown);
        }
        let text = String::from_utf8(stored.final_text).map_err(|_| ReasonCode::ToolFailure)?;
        let mut citations = Vec::new();
        for claim in &stored.manifest.claims {
            for span in &claim.spans {
                let source = self
                    .store
                    .source(&span.source_id)
                    .map_err(reason)?
                    .ok_or(ReasonCode::SourceUnavailable)?;
                citations.push(CitationView {
                    claim_id: claim.claim_id.clone(),
                    source_id: span.source_id.clone(),
                    source_version: span.source_version.clone(),
                    start_scalar: span.start_scalar,
                    end_scalar: span.end_scalar,
                    source_text: String::from_utf8(source).map_err(|_| ReasonCode::ToolFailure)?,
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
        schema_version: 1,
        fixture_only: true,
        outcome: result.outcome,
        reason: result.reason,
        funnel: FunnelView::from(&result.funnel),
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
    }
}

#[derive(Default)]
struct Inner {
    data_dir: Option<PathBuf>,
    session: Option<AskSession>,
}

#[derive(Default)]
pub struct AskState(Mutex<Inner>);

impl AskState {
    pub fn set_data_dir(&self, data_dir: PathBuf) {
        if let Ok(mut inner) = self.0.lock() {
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
}

#[tauri::command]
pub fn ask_question(
    state: tauri::State<'_, AskState>,
    question: String,
) -> Result<AskView, String> {
    if question.chars().count() > MAX_QUESTION_SCALARS {
        return Err("The question is too long.".to_owned());
    }
    let mut inner = state
        .0
        .lock()
        .map_err(|_| "The session failed.".to_owned())?;
    if inner.session.is_none() {
        let data_dir = inner.data_dir.clone().ok_or("The session is not ready.")?;
        inner.session = Some(AskSession::open(&data_dir)?);
    }
    let session = inner.session.as_mut().ok_or("The session failed.")?;
    Ok(session.ask(&question))
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

    #[test]
    fn an_answer_that_cannot_commit_is_withheld() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        session
            .store
            .set_rights_grant("a-later-grant")
            .expect("grant");
        let view = session.ask(ANSWERED);
        assert_eq!(view.outcome, TerminalOutcome::Abstain);
        assert_eq!(view.reason, ReasonCode::ProofRaceInvalidated);
        assert!(view.brief.is_none() && view.proof_id.is_none() && view.citations.is_empty());
        assert!(view.funnel.verified_claims > 0, "the trace stays");
    }

    #[test]
    fn a_committed_answer_that_stops_being_assured_is_withheld_on_replay() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let first = session.ask(ANSWERED);
        let proof_id = first.proof_id.expect("proof");
        session
            .store
            .invalidate(&proof_id, "synthetic")
            .expect("invalidate");
        let view = session.ask(ANSWERED);
        assert_eq!(view.outcome, TerminalOutcome::Abstain);
        assert_eq!(view.reason, ReasonCode::CurrentnessUnknown);
        assert!(view.brief.is_none() && view.proof_id.is_none());
    }

    #[test]
    fn a_new_session_keeps_nothing_and_close_removes_the_directory() {
        let dir = TempDir::new();
        let mut session = AskSession::open(&dir.0).expect("session");
        let proof_id = session.ask(ANSWERED).proof_id.expect("proof");
        let session_dir = session.dir.clone();
        drop(session);
        let mut session = AskSession::open(&dir.0).expect("new session");
        assert!(matches!(
            session.store.read(&proof_id),
            Err(StoreError::UnknownProof)
        ));
        session.close();
        assert!(!session_dir.exists());
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

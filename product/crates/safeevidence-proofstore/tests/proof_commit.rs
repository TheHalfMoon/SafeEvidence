//! Atomic commit through the real keyed vault, over the invented fixture. Includes the lineage and
//! immutability obligations from `plan-v1.3`, and hard process kills during commits.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use safeevidence_ask::{ask, load_corpus};
use safeevidence_contracts::assurance::{ProofState, TerminalOutcome};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{AnswerProofManifest, ManifestDefect};
use safeevidence_proofstore::{ProofStore, StoreError};
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;

const FIXTURE: &[u8] = include_bytes!("../../safeevidence-ask/fixtures/vs1a_corpus.json");
const QUESTION: &str = "Does veltrixamine help adults with glimmer syndrome?";
const EPOCH: u64 = 3;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDb(PathBuf);

impl TempDb {
    fn new() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("se-store-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn path(&self) -> PathBuf {
        self.0.join("vault.db")
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_with_key(path: &Path, key: u8) -> Result<ProofStore, StoreError> {
    let identity = VaultLeaseIdentity::new(
        VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
        KeyGeneration::new(7).expect("generation"),
    );
    let lease = VaultLease::new(identity);
    let context = KeyDerivationContext::new(
        identity.vault_id(),
        identity.key_generation(),
        KeyPurpose::StructuredStore,
    );
    ProofStore::open(
        path,
        lease.keyed_handle_lease(),
        context,
        &OwnedKeyMaterial::from_bytes([key; KEY_MATERIAL_BYTES]),
    )
}

fn open(path: &Path) -> ProofStore {
    open_with_key(path, 0x52).expect("store opens")
}

fn answer() -> (AnswerProofManifest, Vec<u8>) {
    let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture");
    let result = ask(QUESTION, &corpus);
    assert_eq!(result.outcome, TerminalOutcome::AnswerWithCaution);
    (result.manifest.unwrap(), result.brief.unwrap().into_bytes())
}

fn at_fixture_epoch(path: &Path) -> ProofStore {
    let mut store = open(path);
    store.advance_epoch(EPOCH).expect("epoch");
    store
}

#[test]
fn ask_output_commits_and_reads_back_exactly() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = at_fixture_epoch(&db.path());
    let receipt = store.commit(&manifest, &text).expect("commit");
    assert_eq!(receipt.state, ProofState::Committed);
    assert!(!receipt.replayed);
    drop(store);

    let mut store = open(&db.path());
    let stored = store.read(&manifest.proof_id).expect("read");
    assert_eq!(stored.final_text, text);
    assert_eq!(stored.state, ProofState::Committed);
    assert_eq!(stored.manifest.state, ProofState::Committed);
    assert_eq!(stored.manifest.claims, manifest.claims);
    assert_eq!(
        store.audit_events(&manifest.proof_id).unwrap(),
        ["COMMITTED"]
    );
}

#[test]
fn retry_is_idempotent_and_never_stores_two_texts_under_one_id() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = at_fixture_epoch(&db.path());
    store.commit(&manifest, &text).expect("commit");
    assert!(store.commit(&manifest, &text).expect("retry").replayed);
    assert_eq!(store.audit_events(&manifest.proof_id).unwrap().len(), 1);

    let other = b"A different brief.".to_vec();
    let mut changed = manifest.clone();
    changed.final_text_digest = DigestSha256::of(&other);
    assert!(matches!(
        store.commit(&changed, &other),
        Err(StoreError::ConflictingText)
    ));
    assert_eq!(store.read(&manifest.proof_id).unwrap().final_text, text);
}

#[test]
fn retry_after_the_epoch_moved_still_reports_the_durable_answer() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = at_fixture_epoch(&db.path());
    store.commit(&manifest, &text).expect("commit");
    store.advance_epoch(EPOCH + 1).unwrap();
    assert!(store.commit(&manifest, &text).expect("retry").replayed);
    assert_eq!(
        store.read(&manifest.proof_id).unwrap().state,
        ProofState::CurrentnessUnknown
    );
}

#[test]
fn validity_moving_after_verification_refuses_the_commit() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = open(&db.path());
    store.advance_epoch(EPOCH + 1).unwrap();
    assert!(matches!(
        store.commit(&manifest, &text),
        Err(StoreError::ProofRace {
            verified: 3,
            current: 4
        })
    ));
    assert!(matches!(
        store.read(&manifest.proof_id),
        Err(StoreError::UnknownProof)
    ));
    assert!(store.audit_events(&manifest.proof_id).unwrap().is_empty());
}

#[test]
fn an_answer_stops_being_assured_when_validity_moves_and_keeps_its_bytes() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = at_fixture_epoch(&db.path());
    store.commit(&manifest, &text).unwrap();
    store.advance_epoch(EPOCH + 1).unwrap();
    let stored = store.read(&manifest.proof_id).unwrap();
    assert_eq!(stored.state, ProofState::CurrentnessUnknown);
    assert!(!stored.state.is_currently_assured());
    assert_eq!(stored.final_text, text);
}

#[test]
fn invalidation_is_recorded_and_outranks_a_matching_epoch() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = at_fixture_epoch(&db.path());
    store.commit(&manifest, &text).unwrap();
    store
        .invalidate(&manifest.proof_id, "synthetic retraction")
        .unwrap();
    store.invalidate(&manifest.proof_id, "again").unwrap();
    let stored = store.read(&manifest.proof_id).unwrap();
    assert_eq!(stored.state, ProofState::CurrentlyInvalidated);
    assert_eq!(stored.final_text, text);
    assert_eq!(
        store.audit_events(&manifest.proof_id).unwrap(),
        ["COMMITTED", "INVALIDATED"]
    );
    assert!(matches!(
        store.invalidate("missing", "x"),
        Err(StoreError::UnknownProof)
    ));
}

#[test]
fn commit_refuses_before_writing_anything() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    let mut store = at_fixture_epoch(&db.path());

    assert!(matches!(
        store.commit(&manifest, b"tampered"),
        Err(StoreError::TextDigestMismatch)
    ));

    let mut draft = manifest.clone();
    draft.state = ProofState::Verifying;
    assert!(matches!(
        store.commit(&draft, &text),
        Err(StoreError::WrongState(_))
    ));
    let mut already = manifest.clone();
    already.state = ProofState::Committed;
    assert!(matches!(
        store.commit(&already, &text),
        Err(StoreError::WrongState(_))
    ));

    let mut failed = manifest.clone();
    failed.post_verification_passed = false;
    assert!(matches!(
        store.commit(&failed, &text),
        Err(StoreError::Defects(defects)) if defects == [ManifestDefect::PostVerificationFailed]
    ));
    assert!(matches!(
        store.read(&manifest.proof_id),
        Err(StoreError::UnknownProof)
    ));
    assert!(store.audit_events(&manifest.proof_id).unwrap().is_empty());
}

#[test]
fn source_bytes_cannot_be_replaced_under_an_existing_id() {
    let db = TempDb::new();
    let mut store = open(&db.path());
    store.put_source("s1", b"original").unwrap();
    store
        .put_source("s1", b"original")
        .expect("same bytes is a no-op");
    assert!(matches!(
        store.put_source("s1", b"replaced"),
        Err(StoreError::SourceConflict)
    ));
    assert_eq!(
        store.source("s1").unwrap().as_deref(),
        Some(&b"original"[..])
    );
    assert_eq!(store.source("missing").unwrap(), None);
}

#[test]
fn amendment_appends_and_leaves_the_prior_bytes_unchanged() {
    let db = TempDb::new();
    let mut store = open(&db.path());
    store.put_source("a1", b"first").unwrap();
    store.put_source("a2", b"second").unwrap();
    store.put_source("a3", b"third").unwrap();
    store.amend("a1", "a2", "synthetic correction").unwrap();
    store.amend("a1", "a3", "synthetic correction").unwrap();
    assert_eq!(store.amendments("a1").unwrap(), ["a2", "a3"]);
    assert_eq!(store.source("a1").unwrap().as_deref(), Some(&b"first"[..]));
    for (prior, next) in [("a1", "a1"), ("a1", "missing"), ("missing", "a1")] {
        assert!(matches!(
            store.amend(prior, next, "x"),
            Err(StoreError::InvalidAmendment)
        ));
    }
    assert_eq!(store.amendments("a1").unwrap().len(), 2);
}

#[test]
fn epoch_only_moves_forward() {
    let db = TempDb::new();
    let mut store = open(&db.path());
    store.advance_epoch(5).unwrap();
    assert!(store.advance_epoch(5).is_err());
    assert!(store.advance_epoch(4).is_err());
    assert_eq!(store.epoch().unwrap(), 5);
}

#[test]
fn wrong_key_cannot_open_and_plaintext_is_not_on_disk() {
    let db = TempDb::new();
    let (manifest, text) = answer();
    {
        let mut store = at_fixture_epoch(&db.path());
        store.commit(&manifest, &text).unwrap();
    }
    assert!(open_with_key(&db.path(), 0x53).is_err());
    let bytes = fs::read(db.path()).unwrap();
    let marker = b"Synthetic evidence brief";
    assert!(!bytes.windows(marker.len()).any(|window| window == marker));
}

/// Child entry, spawned by the kill test; ignored in normal runs.
#[test]
#[ignore = "spawned by kill_during_commits_loses_no_acknowledged_answer"]
fn commit_writer_entry() {
    if std::env::var("SAFEEVIDENCE_KILL_CHILD").as_deref() != Ok("1") {
        return;
    }
    let root = PathBuf::from(std::env::var("SAFEEVIDENCE_KILL_ROOT").expect("root"));
    let (manifest, _) = answer();
    let mut store = open(&root.join("vault.db"));
    if store.epoch().unwrap() < EPOCH {
        store.advance_epoch(EPOCH).unwrap();
    }
    for index in 0..u64::MAX {
        let text = format!("synthetic answer {index}").into_bytes();
        let mut next = manifest.clone();
        next.proof_id = format!("proof-{index}");
        next.final_text_digest = DigestSha256::of(&text);
        store.commit(&next, &text).expect("commit");
        let staged = root.join("ack.tmp");
        fs::write(&staged, (index + 1).to_string()).expect("stage");
        fs::rename(&staged, root.join("ack")).expect("publish");
    }
}

fn acknowledged(root: &Path) -> u64 {
    fs::read_to_string(root.join("ack"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn spawn_writer(root: &Path) -> Child {
    Command::new(std::env::current_exe().expect("test binary"))
        .args(["commit_writer_entry", "--exact", "--nocapture", "--ignored"])
        .env("SAFEEVIDENCE_KILL_CHILD", "1")
        .env("SAFEEVIDENCE_KILL_ROOT", root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer")
}

#[test]
fn kill_during_commits_loses_no_acknowledged_answer() {
    for kill_at in 1..=8 {
        let db = TempDb::new();
        let mut child = spawn_writer(&db.0);
        let deadline = Instant::now() + Duration::from_secs(180);
        while acknowledged(&db.0) < kill_at {
            assert!(Instant::now() < deadline, "writer stalled at {kill_at}");
            assert!(child.try_wait().unwrap().is_none(), "writer exited early");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "writer exited before the kill"
        );
        child.kill().expect("kill");
        let _ = child.wait();
        let acked = acknowledged(&db.0);

        let mut store = open(&db.path());
        for index in 0..acked {
            let stored = store
                .read(&format!("proof-{index}"))
                .expect("acknowledged answer survives");
            assert_eq!(
                stored.final_text,
                format!("synthetic answer {index}").into_bytes()
            );
            assert_eq!(
                store.audit_events(&format!("proof-{index}")).unwrap(),
                ["COMMITTED"],
                "answer and audit event commit together"
            );
        }
        // An unacknowledged commit may be fully there or absent, but never partial.
        match store.read(&format!("proof-{acked}")) {
            Ok(stored) => {
                assert_eq!(
                    stored.final_text,
                    format!("synthetic answer {acked}").into_bytes()
                );
                assert_eq!(
                    store.audit_events(&format!("proof-{acked}")).unwrap().len(),
                    1
                );
            }
            Err(StoreError::UnknownProof) => {
                assert!(
                    store
                        .audit_events(&format!("proof-{acked}"))
                        .unwrap()
                        .is_empty()
                );
            }
            Err(other) => panic!("recovery failed: {other:?}"),
        }
        assert!(matches!(
            store.read(&format!("proof-{}", acked + 1)),
            Err(StoreError::UnknownProof)
        ));
    }
}

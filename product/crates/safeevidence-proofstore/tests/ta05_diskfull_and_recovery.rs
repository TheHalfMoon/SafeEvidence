//! `TA-05` fault-injection, key-loss recovery, and clean-directory backup restore qualification.
//!
//! Exercises:
//! 1. Deterministic SQLite page-quota exhaustion (`PRAGMA max_page_count` -> `StoreError::DiskFull`)
//!    mid-transaction across `put_source`, `commit`, `put_assertion`, `amend_assertion`, and
//!    `retract_source`, proving zero partial commits, intact prior records, zero plaintext residue
//!    in `vault.db` or `vault.db-wal`, and clean recovery once quota is restored.
//! 2. `ProofStore::verify_record_semantics_doctor` positive verification (`11` tables, `22`
//!    append-only triggers, `SCHEMA_OBJECTS_SHA256`, WAL/`FULL`/`recursive_triggers`, SQLCipher +
//!    SQLite integrity) and fail-closed refusal on tampered database bytes or doctor axes.
//! 3. End-to-end `SAFEVD/RECOVERY/ENVELOPE/v1` Argon2id passphrase recovery after total OS-protector
//!    key loss, plus wrong-passphrase, wrong-vault, and tampered-ciphertext rejection.
//! 4. End-to-end B505 encrypted portable backup creation, zero-plaintext provider audit, tampered
//!    chunk rejection, and clean-directory fresh-device restore + `ProofStore::open_existing`
//!    replay.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use safeevidence_ask::{ask, load_corpus};
use safeevidence_contracts::assurance::ProofState;
use safeevidence_contracts::objects::{
    AmendmentKind, AmendmentRecord, AuthorityScopeId, ClinicalAssertion, DigestSha256, MedicalTime,
    ObjectHeader, OpaqueId, RealmId, TimePrecision,
};
use safeevidence_proofstore::{ProofStore, RecordSemanticsDoctorReport, StoreError};
use safeevidence_vault::vault::{
    AccessScope, FreshnessAnchor, FreshnessEpoch, HardwareBacking, KeyGeneration, ManifestHash,
    ProtectedFreshnessState, ProtectorError, SecretProtector, UserPresencePolicy, VAULT_ID_BYTES,
    VaultId, VaultLeaseIdentity,
};
use safeevidence_vault::vault_backup::descriptor_provider_key;
use safeevidence_vault::vault_backup_creation::create_publish_and_verify_portable_backup;
use safeevidence_vault::vault_backup_packaging::BackupSourceFile;
use safeevidence_vault::vault_backup_provider::PortableBackupProvider;
use safeevidence_vault::vault_backup_restore::{
    FreshDeviceBackupMaterialError, prepare_verified_fresh_device_genesis,
    verify_fresh_device_backup_restore_material,
};
use safeevidence_vault::vault_backup_restore_publication::{
    FreshDeviceRestoreBackend, publish_prepared_fresh_device_restore,
};
use safeevidence_vault::vault_backup_verify::PreSqlCipherVerifiedBackupSet;
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;
use safeevidence_vault::vault_manifest::{
    GenerationState, ManifestAuthMetadata, ManifestContext, ManifestGeneration, ManifestObject,
    ManifestPlaintext, RotationPhase, encrypt_fresh_manifest, manifest_hash,
};
use safeevidence_vault::vault_nonce::NonceReservationLedger;
use safeevidence_vault::vault_recovery::{
    RECOVERY_ENVELOPE_BYTES, RecoveryContext, RecoveryEnvelopeError, decrypt_recovery_envelope,
    encrypt_recovery_envelope,
};
use safeevidence_vault::vault_restore::FreshDeviceNewestnessRiskAccepted;
use safeevidence_vault::vault_sqlcipher::BackupSnapshotQuiescenceGuard;
use serde_json::json;

const FIXTURE: &[u8] = include_bytes!("../../safeevidence-ask/fixtures/vs1a_corpus.json");
const RECOVERY_PASSPHRASE: &str = "vellum lantern harbor quartz sixteen";
const PORTABLE_BACKUP_VRK_BYTE: u8 = 0x8d;

static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_DIR_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("se-ta05-{label}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_identity() -> VaultLeaseIdentity {
    VaultLeaseIdentity::new(
        VaultId::from_bytes([0x47; VAULT_ID_BYTES]),
        KeyGeneration::new(3).expect("non-zero generation"),
    )
}

fn structured_context(identity: VaultLeaseIdentity) -> KeyDerivationContext {
    KeyDerivationContext::new(
        identity.vault_id(),
        identity.key_generation(),
        KeyPurpose::StructuredStore,
    )
}

fn sample_assertion(id: &str, marker_text: &str) -> ClinicalAssertion {
    ClinicalAssertion {
        header: ObjectHeader {
            id: OpaqueId::new(id),
            schema_version: 1,
            realm_id: RealmId::new("realm-synthetic-ta05"),
            authority_scope_id: AuthorityScopeId::new("scope-synthetic-ta05"),
        },
        subject_ref: OpaqueId::new("subject-synthetic-01"),
        claim_kind: "synthetic_finding".to_owned(),
        payload: json!({ "marker": marker_text }),
        promoted_from_proposal_id: None,
        authorized_by: OpaqueId::new("actor-synthetic-clinician"),
        effective_time: None,
        recorded_time: MedicalTime::new("2026-01-15T08:30:00Z", TimePrecision::Instant, false),
    }
}

fn sample_amendment(record_id: &str, prior: &str, next: &str, rationale: &str) -> AmendmentRecord {
    AmendmentRecord {
        header: ObjectHeader {
            id: OpaqueId::new(record_id),
            schema_version: 1,
            realm_id: RealmId::new("realm-synthetic-ta05"),
            authority_scope_id: AuthorityScopeId::new("scope-synthetic-ta05"),
        },
        prior_assertion_id: OpaqueId::new(prior),
        superseding_assertion_id: OpaqueId::new(next),
        kind: AmendmentKind::Supersession,
        rationale: rationale.to_owned(),
        authorized_by: OpaqueId::new("actor-synthetic-clinician"),
        recorded_time: MedicalTime::new("2026-01-16T09:00:00Z", TimePrecision::Instant, false),
    }
}

fn assert_no_plaintext_markers(db_path: &Path, markers: &[&[u8]]) {
    for candidate in [
        db_path.to_path_buf(),
        PathBuf::from(format!("{}-wal", db_path.display())),
        PathBuf::from(format!("{}-shm", db_path.display())),
    ] {
        if let Ok(bytes) = std::fs::read(&candidate) {
            for marker in markers {
                assert!(
                    !bytes.windows(marker.len()).any(|window| window == *marker),
                    "plaintext marker leaked in {}",
                    candidate.display()
                );
            }
        }
    }
}

#[test]
fn ta05_diskfull_mid_transaction_rolls_back_all_write_paths_without_partial_state_or_plaintext_residue()
 {
    let dir = TempDir::new("diskfull");
    let db_path = dir.path().join("vault.db");
    let identity = test_identity();
    let lease = VaultLease::new(identity);
    let vrk = OwnedKeyMaterial::from_bytes([0x5a; KEY_MATERIAL_BYTES]);

    let mut store = ProofStore::open(
        &db_path,
        lease.keyed_handle_lease(),
        structured_context(identity),
        &vrk,
    )
    .expect("open store");

    let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("load synthetic corpus");
    let first_ask = ask(
        "Does veltrixamine help adults with glimmer syndrome?",
        &corpus,
    );
    let first_manifest = first_ask.manifest.expect("answered manifest");
    let first_brief = first_ask.brief.expect("answered brief");

    store
        .advance_epoch(first_manifest.validity_epoch)
        .expect("advance epoch");
    store
        .set_rights_grant(&first_manifest.rights_grant_version)
        .expect("set rights grant");
    for doc in &corpus.documents {
        store
            .put_source(&doc.doc_id, doc.text.as_bytes())
            .expect("put fixture source");
    }
    store
        .commit(&first_manifest, first_brief.as_bytes())
        .expect("commit baseline proof");
    store
        .put_assertion(&sample_assertion(
            "assert-baseline-1",
            "SYNTHETIC-BASELINE-CLAIM-KEEP",
        ))
        .expect("store baseline assertion");
    store
        .put_assertion(&sample_assertion(
            "assert-baseline-2",
            "SYNTHETIC-BASELINE-CLAIM-NEXT",
        ))
        .expect("store second baseline assertion");

    // Clamp SQLite page ceiling to current live page count so any multi-page write hits SQLITE_FULL.
    let baseline_pages = store.page_count().expect("read baseline page count");
    assert!(baseline_pages >= 2);
    let applied_ceiling = store
        .set_max_page_count(baseline_pages)
        .expect("clamp max_page_count");
    assert_eq!(applied_ceiling, baseline_pages);

    let oversized_source = format!("SECRET-ROLLBACK-SOURCE-MARKER-{}", "X".repeat(64 * 1024));
    assert!(matches!(
        store.put_source("doc-overflow-rollback", oversized_source.as_bytes()),
        Err(StoreError::DiskFull)
    ));

    let oversized_brief = format!("SECRET-ROLLBACK-ANSWER-MARKER-{}", "Y".repeat(64 * 1024));
    let mut second_manifest = first_manifest.clone();
    second_manifest.proof_id = "proof-overflow-rollback".to_owned();
    second_manifest.final_text_digest = DigestSha256::of(oversized_brief.as_bytes());
    assert!(matches!(
        store.commit(&second_manifest, oversized_brief.as_bytes()),
        Err(StoreError::DiskFull)
    ));

    let oversized_claim = format!("SECRET-ROLLBACK-ASSERTION-MARKER-{}", "Z".repeat(64 * 1024));
    assert!(matches!(
        store.put_assertion(&sample_assertion(
            "assert-overflow-rollback",
            &oversized_claim
        )),
        Err(StoreError::DiskFull)
    ));

    let oversized_rationale = format!("SECRET-ROLLBACK-AMENDMENT-MARKER-{}", "W".repeat(64 * 1024));
    assert!(matches!(
        store.amend_assertion(&sample_amendment(
            "amend-overflow-rollback",
            "assert-baseline-1",
            "assert-baseline-2",
            &oversized_rationale,
        )),
        Err(StoreError::DiskFull)
    ));

    let existing_doc_id = corpus.documents[0].doc_id.clone();
    let oversized_retraction = format!(
        "SECRET-ROLLBACK-RETRACTION-MARKER-{}",
        "Q".repeat(64 * 1024)
    );
    assert!(matches!(
        store.retract_source(
            &existing_doc_id,
            &oversized_retraction,
            "actor-synthetic",
            &MedicalTime::new("2026-01-17T00:00:00Z", TimePrecision::Instant, false),
        ),
        Err(StoreError::DiskFull)
    ));

    // Zero partial commits; all baseline state remains valid and intact.
    assert_eq!(
        store.source("doc-overflow-rollback").expect("query source"),
        None
    );
    assert!(matches!(
        store.read("proof-overflow-rollback"),
        Err(StoreError::UnknownProof)
    ));
    assert!(
        store
            .audit_events("proof-overflow-rollback")
            .expect("query rolled-back audit events")
            .is_empty()
    );
    assert_eq!(
        store
            .assertion("assert-overflow-rollback")
            .expect("query rolled-back assertion"),
        None
    );
    assert!(
        store
            .assertion_amendments("assert-baseline-1")
            .expect("query rolled-back amendments")
            .is_empty()
    );
    assert!(
        !store
            .is_source_retracted(&existing_doc_id)
            .expect("source not retracted")
    );
    let baseline_stored = store
        .read(&first_manifest.proof_id)
        .expect("baseline proof intact");
    assert_eq!(baseline_stored.state, ProofState::Committed);
    assert_eq!(baseline_stored.final_text, first_brief.clone().into_bytes());

    // Zero plaintext residue across encrypted database + WAL/SHM files.
    assert_no_plaintext_markers(
        &db_path,
        &[
            b"SECRET-ROLLBACK-SOURCE-MARKER",
            b"SECRET-ROLLBACK-ANSWER-MARKER",
            b"SECRET-ROLLBACK-ASSERTION-MARKER",
            b"SECRET-ROLLBACK-AMENDMENT-MARKER",
            b"SECRET-ROLLBACK-RETRACTION-MARKER",
            b"SYNTHETIC-BASELINE-CLAIM-KEEP",
            b"veltrixamine",
        ],
    );

    // Also sweep near-page boundary payloads (`32B`..`4096B`) so multi-statement transactions
    // (`INSERT INTO sources` followed by `INSERT INTO store_events`) exercise both statement-1 and
    // statement-2 `SQLITE_FULL` rollback without leaving orphan rows in either table.
    for (idx, len) in [32_usize, 192, 768, 1792, 2816, 3584, 4096]
        .into_iter()
        .enumerate()
    {
        let doc_id = format!("doc-boundary-{idx}");
        let payload = vec![b'B'; len];
        if let Err(error) = store.put_source(&doc_id, &payload) {
            assert!(matches!(error, StoreError::DiskFull));
            assert_eq!(
                store.source(&doc_id).expect("boundary source check"),
                None,
                "rolled-back put_source left partial source at {len} bytes"
            );
        }
    }

    // Restore SQLite's default maximum page ceiling via `0` (translated to `0x3fff_ffff`) and prove
    // clean recovery.
    let restored_ceiling = store
        .set_max_page_count(0)
        .expect("restore default max_page_count via 0");
    assert_eq!(restored_ceiling, 0x3fff_ffff);
    assert!(restored_ceiling > baseline_pages);

    store
        .put_source("doc-recovered-after-full", oversized_source.as_bytes())
        .expect("put_source succeeds once disk quota is restored");
    store
        .commit(&second_manifest, oversized_brief.as_bytes())
        .expect("commit succeeds once disk quota is restored");
    let recovered_stored = store
        .read(&second_manifest.proof_id)
        .expect("recovered proof state");
    assert_eq!(recovered_stored.state, ProofState::Committed);

    let doctor = store
        .verify_record_semantics_doctor()
        .expect("doctor check after recovery");
    assert!(doctor.passed(), "doctor report failed: {doctor:?}");
}

#[test]
fn ta05_record_semantics_doctor_detects_healthy_and_tampered_store() {
    let dir = TempDir::new("doctor");
    let db_path = dir.path().join("vault.db");
    let identity = test_identity();
    let lease = VaultLease::new(identity);
    let vrk = OwnedKeyMaterial::from_bytes([0x63; KEY_MATERIAL_BYTES]);

    {
        let mut store = ProofStore::open(
            &db_path,
            lease.keyed_handle_lease(),
            structured_context(identity),
            &vrk,
        )
        .expect("open store");
        let report = store
            .verify_record_semantics_doctor()
            .expect("verify record semantics doctor");
        assert!(report.passed());
        assert_eq!(
            report.table_count,
            RecordSemanticsDoctorReport::EXPECTED_TABLES
        );
        assert_eq!(
            report.append_only_trigger_count,
            RecordSemanticsDoctorReport::EXPECTED_TRIGGERS
        );

        let mut degraded = report.clone();
        degraded.append_only_trigger_count -= 1;
        assert!(!degraded.passed());
        let mut schema_drift = report.clone();
        schema_drift.schema_matches = false;
        assert!(!schema_drift.passed());
        let mut non_durable = report;
        non_durable.durable_settings_hold = false;
        assert!(!non_durable.passed());
    }

    // Tamper with ciphertext bytes on page 1 (offset 64) and confirm SQLCipher HMAC fails closed.
    let mut raw_bytes = std::fs::read(&db_path).expect("read vault.db");
    assert!(raw_bytes.len() >= 4096);
    raw_bytes[64] ^= 0xff;
    std::fs::write(&db_path, raw_bytes).expect("write tampered vault.db");

    let reopen_result = ProofStore::open_existing(
        &db_path,
        lease.keyed_handle_lease(),
        structured_context(identity),
        &vrk,
    );
    assert!(reopen_result.is_err());
}

#[test]
fn ta05_recovery_envelope_argon2id_recovers_proofstore_after_protector_key_loss_and_rejects_tamper()
{
    let dir = TempDir::new("recovery-envelope");
    let db_path = dir.path().join("vault.db");
    let identity = test_identity();
    let context = RecoveryContext::new(identity.vault_id(), identity.key_generation());
    let raw_vrk_bytes = [0x7c; KEY_MATERIAL_BYTES];
    let original_vrk = OwnedKeyMaterial::from_bytes(raw_vrk_bytes);

    let envelope = encrypt_recovery_envelope(&original_vrk, context, RECOVERY_PASSPHRASE)
        .expect("encrypt recovery envelope");
    assert_eq!(envelope.len(), RECOVERY_ENVELOPE_BYTES);
    assert!(
        !envelope
            .windows(raw_vrk_bytes.len())
            .any(|window| window == raw_vrk_bytes),
        "raw VRK must never appear in recovery envelope"
    );

    assert_eq!(
        encrypt_recovery_envelope(&original_vrk, context, "too-short"),
        Err(RecoveryEnvelopeError::PassphraseTooShort)
    );

    let committed_proof_id = {
        let lease = VaultLease::new(identity);
        let mut store = ProofStore::open(
            &db_path,
            lease.keyed_handle_lease(),
            structured_context(identity),
            &original_vrk,
        )
        .expect("open store");
        let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("load fixture");
        let answered = ask(
            "Does veltrixamine help adults with glimmer syndrome?",
            &corpus,
        );
        let manifest = answered.manifest.expect("manifest");
        let brief = answered.brief.expect("brief");
        store.advance_epoch(manifest.validity_epoch).expect("epoch");
        store
            .set_rights_grant(&manifest.rights_grant_version)
            .expect("rights");
        for doc in &corpus.documents {
            store
                .put_source(&doc.doc_id, doc.text.as_bytes())
                .expect("put source");
        }
        store
            .commit(&manifest, brief.as_bytes())
            .expect("commit proof");
        store
            .put_assertion(&sample_assertion(
                "assert-before-key-loss",
                "SYNTHETIC-SURVIVES-KEY-LOSS",
            ))
            .expect("put assertion");
        manifest.proof_id
    };

    // Simulate permanent OS protector loss by dropping original_vrk and testing fail-closed cases.
    drop(original_vrk);

    assert_eq!(
        decrypt_recovery_envelope(
            context,
            "wrong horse battery staple sixteen chars",
            &envelope
        )
        .err(),
        Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
    );

    let wrong_vault_context = RecoveryContext::new(
        VaultId::from_bytes([0x99; VAULT_ID_BYTES]),
        identity.key_generation(),
    );
    assert_eq!(
        decrypt_recovery_envelope(wrong_vault_context, RECOVERY_PASSPHRASE, &envelope).err(),
        Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
    );

    let mut tampered_envelope = envelope.clone();
    let last_idx = tampered_envelope.len() - 1;
    tampered_envelope[last_idx] ^= 0x01;
    assert_eq!(
        decrypt_recovery_envelope(context, RECOVERY_PASSPHRASE, &tampered_envelope).err(),
        Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
    );

    // Recover the VRK with the enrolled passphrase and reopen ProofStore cleanly.
    let recovered_vrk = decrypt_recovery_envelope(context, RECOVERY_PASSPHRASE, &envelope)
        .expect("decrypt recovery envelope with authentic passphrase");
    let fresh_lease = VaultLease::new(identity);
    let mut reopened = ProofStore::open_existing(
        &db_path,
        fresh_lease.keyed_handle_lease(),
        structured_context(identity),
        &recovered_vrk,
    )
    .expect("reopen ProofStore after VRK recovery");

    let stored_proof = reopened
        .read(&committed_proof_id)
        .expect("proof state after recovery");
    assert_eq!(stored_proof.state, ProofState::Committed);
    let restored_assertion = reopened
        .assertion("assert-before-key-loss")
        .expect("read assertion")
        .expect("assertion present");
    assert_eq!(
        restored_assertion.payload["marker"],
        "SYNTHETIC-SURVIVES-KEY-LOSS"
    );
    assert!(
        reopened
            .verify_record_semantics_doctor()
            .expect("doctor after key recovery")
            .passed()
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryBackupProviderError {
    Missing,
    AlreadyExists,
}

#[derive(Clone, Default)]
struct MemoryBackupProvider {
    objects: HashMap<String, Vec<u8>>,
}

impl PortableBackupProvider for MemoryBackupProvider {
    type Error = MemoryBackupProviderError;

    fn put_if_absent(&mut self, key: &str, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.objects.contains_key(key) {
            return Err(MemoryBackupProviderError::AlreadyExists);
        }
        self.objects.insert(key.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn read(&mut self, key: &str) -> Result<Vec<u8>, Self::Error> {
        self.objects
            .get(key)
            .cloned()
            .ok_or(MemoryBackupProviderError::Missing)
    }
}

#[derive(Default)]
struct QuiescedGuard;

impl BackupSnapshotQuiescenceGuard for QuiescedGuard {
    type Error = ();

    fn assert_normal_writes_quiesced(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Default)]
struct MemoryFreshDeviceProtector {
    stored_identity: Option<(VaultId, KeyGeneration)>,
    anchor: Option<FreshnessAnchor>,
}

impl SecretProtector for MemoryFreshDeviceProtector {
    type VaultRootKey = OwnedKeyMaterial;

    fn create_protector(
        &mut self,
        _: AccessScope,
        _: UserPresencePolicy,
    ) -> Result<(), ProtectorError> {
        Ok(())
    }

    fn protect_or_store_vrk(
        &mut self,
        vault_id: VaultId,
        generation: KeyGeneration,
        _vrk: &OwnedKeyMaterial,
    ) -> Result<(), ProtectorError> {
        self.stored_identity = Some((vault_id, generation));
        Ok(())
    }

    fn unlock_vrk(
        &mut self,
        vault_id: VaultId,
        generation: KeyGeneration,
    ) -> Result<OwnedKeyMaterial, ProtectorError> {
        match self.stored_identity {
            Some((id, stored_gen)) if id == vault_id && stored_gen == generation => Ok(
                OwnedKeyMaterial::from_bytes([PORTABLE_BACKUP_VRK_BYTE; KEY_MATERIAL_BYTES]),
            ),
            _ => Err(ProtectorError::ItemMissing),
        }
    }

    fn read_freshness_anchor(
        &self,
        vault_id: VaultId,
    ) -> Result<ProtectedFreshnessState, ProtectorError> {
        match self.anchor {
            Some(anchor) if anchor.vault_id() == vault_id => {
                Ok(ProtectedFreshnessState::Present(anchor))
            }
            Some(_) => Err(ProtectorError::CorruptOrTampered),
            None => {
                if self.stored_identity.is_some_and(|(id, _)| id == vault_id) {
                    Ok(ProtectedFreshnessState::Uninitialized)
                } else {
                    Err(ProtectorError::ItemMissing)
                }
            }
        }
    }

    fn install_genesis_freshness_anchor(
        &mut self,
        vault_id: VaultId,
        expected_state: ProtectedFreshnessState,
        genesis: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        if expected_state != ProtectedFreshnessState::Uninitialized
            || self.anchor.is_some()
            || genesis.vault_id() != vault_id
        {
            return Err(ProtectorError::CorruptOrTampered);
        }
        self.anchor = Some(genesis);
        Ok(())
    }

    fn advance_freshness_anchor(
        &mut self,
        vault_id: VaultId,
        expected_old: FreshnessAnchor,
        new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        if self.anchor != Some(expected_old) || new_anchor.vault_id() != vault_id {
            return Err(ProtectorError::CorruptOrTampered);
        }
        self.anchor = Some(new_anchor);
        Ok(())
    }

    fn replace_protector(&mut self, _: VaultId) -> Result<(), ProtectorError> {
        Ok(())
    }

    fn remove_protector(&mut self, _: VaultId) -> Result<(), ProtectorError> {
        self.stored_identity = None;
        self.anchor = None;
        Ok(())
    }

    fn actual_access_scope(&self) -> AccessScope {
        AccessScope::SameUserAccount
    }

    fn requires_user_presence(&self) -> bool {
        false
    }

    fn hardware_backed_state(&self) -> HardwareBacking {
        HardwareBacking::Unknown
    }
}

struct CleanDirectoryRestoreBackend {
    target_dir: PathBuf,
}

impl CleanDirectoryRestoreBackend {
    fn new(target_dir: PathBuf) -> Self {
        Self { target_dir }
    }

    fn candidate_db_path(&self) -> PathBuf {
        self.target_dir.join("candidate_vault.db")
    }

    fn canonical_db_path(&self) -> PathBuf {
        self.target_dir.join("vault.db")
    }

    fn manifest_path(&self) -> PathBuf {
        self.target_dir.join("vault.manifest")
    }
}

impl FreshDeviceRestoreBackend for CleanDirectoryRestoreBackend {
    type Error = String;

    fn stage_verified_backup(
        &mut self,
        structured_store_source: &Path,
        _verified: &PreSqlCipherVerifiedBackupSet,
    ) -> Result<(), Self::Error> {
        std::fs::copy(structured_store_source, self.candidate_db_path())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn verify_staged_backup(
        &mut self,
        vrk: &OwnedKeyMaterial,
        verified: &PreSqlCipherVerifiedBackupSet,
    ) -> Result<(), Self::Error> {
        let identity = VaultLeaseIdentity::new(verified.vault_id(), verified.key_generation());
        let lease = VaultLease::new(identity);
        let mut store = ProofStore::open_existing(
            self.candidate_db_path(),
            lease.keyed_handle_lease(),
            structured_context(identity),
            vrk,
        )
        .map_err(|error| format!("staged store open failed: {error:?}"))?;
        let report = store
            .verify_record_semantics_doctor()
            .map_err(|error| format!("staged doctor failed: {error:?}"))?;
        if !report.passed() {
            return Err("staged record semantics doctor did not pass".to_owned());
        }
        Ok(())
    }

    fn publish_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
        std::fs::copy(self.candidate_db_path(), self.canonical_db_path())
            .map_err(|error| error.to_string())?;
        std::fs::write(self.manifest_path(), envelope).map_err(|error| error.to_string())
    }

    fn read_published_manifest(&self) -> Result<Vec<u8>, Self::Error> {
        std::fs::read(self.manifest_path()).map_err(|error| error.to_string())
    }

    fn reopen_published(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error> {
        let identity =
            VaultLeaseIdentity::new(manifest.vault_id(), manifest.active_key_generation());
        let lease = VaultLease::new(identity);
        ProofStore::open_existing(
            self.canonical_db_path(),
            lease.keyed_handle_lease(),
            structured_context(identity),
            vrk,
        )
        .map(|_| ())
        .map_err(|error| format!("reopen published failed: {error:?}"))
    }

    fn verify_reopened(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error> {
        let identity =
            VaultLeaseIdentity::new(manifest.vault_id(), manifest.active_key_generation());
        let lease = VaultLease::new(identity);
        let mut store = ProofStore::open_existing(
            self.canonical_db_path(),
            lease.keyed_handle_lease(),
            structured_context(identity),
            vrk,
        )
        .map_err(|error| format!("verify reopened failed: {error:?}"))?;
        let doctor = store
            .verify_record_semantics_doctor()
            .map_err(|error| format!("reopened doctor failed: {error:?}"))?;
        if !doctor.passed() {
            return Err("reopened store failed doctor check".to_owned());
        }
        Ok(())
    }
}

#[test]
fn ta05_b505_portable_backup_create_tamper_reject_and_clean_directory_fresh_device_restore() {
    let source_dir = TempDir::new("b505-source");
    let work_dir = TempDir::new("b505-work");
    let clean_restore_dir = TempDir::new("b505-clean-restore");

    let source_db = source_dir.path().join("vault.db");
    let identity = test_identity();
    let vrk = OwnedKeyMaterial::from_bytes([PORTABLE_BACKUP_VRK_BYTE; KEY_MATERIAL_BYTES]);
    let lease = VaultLease::new(identity);

    let mut store = ProofStore::open(
        &source_db,
        lease.keyed_handle_lease(),
        structured_context(identity),
        &vrk,
    )
    .expect("open source ProofStore");

    let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("load fixture");
    let answered = ask(
        "Does veltrixamine help adults with glimmer syndrome?",
        &corpus,
    );
    let manifest_record = answered.manifest.expect("manifest");
    let brief = answered.brief.expect("brief");

    store
        .advance_epoch(manifest_record.validity_epoch)
        .expect("epoch");
    store
        .set_rights_grant(&manifest_record.rights_grant_version)
        .expect("rights");
    for doc in &corpus.documents {
        store
            .put_source(&doc.doc_id, doc.text.as_bytes())
            .expect("source");
    }
    store
        .commit(&manifest_record, brief.as_bytes())
        .expect("commit proof");
    store
        .put_assertion(&sample_assertion(
            "assert-backup-portable",
            "SECRET-PORTABLE-BACKUP-ASSERTION-MARKER",
        ))
        .expect("put assertion");
    drop(store);

    let db_bytes = std::fs::read(&source_db).expect("read source db file");
    let db_sha = *DigestSha256::of(&db_bytes).as_bytes();
    let epoch = FreshnessEpoch::new(4).expect("epoch 4");
    let vault_manifest_plaintext = ManifestPlaintext::new(
        identity.vault_id(),
        epoch,
        ManifestHash::from_bytes([0x21; 32]),
        identity.key_generation(),
        (RotationPhase::None, None),
        vec![ManifestGeneration::new(
            identity.key_generation(),
            GenerationState::Active,
        )],
        vec![ManifestObject::new(
            [0_u8; 16],
            [0x54; 16],
            identity.key_generation(),
            db_bytes.len() as u64,
            db_sha,
            ManifestAuthMetadata::StructuredStore,
        )],
    )
    .expect("manifest plaintext");

    let mut nonce_ledger = NonceReservationLedger::new(identity.vault_id());
    let (_, source_manifest_envelope) = encrypt_fresh_manifest(
        &mut nonce_ledger,
        &vrk,
        ManifestContext::new(identity.vault_id(), identity.key_generation(), epoch),
        &vault_manifest_plaintext,
    )
    .expect("encrypt source manifest");
    let trusted_anchor = FreshnessAnchor::new(
        identity.vault_id(),
        epoch,
        manifest_hash(&source_manifest_envelope),
    );
    let recovery_envelope = encrypt_recovery_envelope(
        &vrk,
        RecoveryContext::new(identity.vault_id(), identity.key_generation()),
        RECOVERY_PASSPHRASE,
    )
    .expect("encrypt recovery envelope");

    let mut guard = QuiescedGuard;
    let mut provider = MemoryBackupProvider::default();
    let generic_sources: [BackupSourceFile; 0] = [];
    let snapshot_path = work_dir.path().join("snapshot.sqlite3");
    let package_dir = work_dir.path().join("package");
    let verify_path = work_dir.path().join("verify.sqlite3");

    let accepted = create_publish_and_verify_portable_backup(
        &mut guard,
        &mut provider,
        trusted_anchor,
        lease.keyed_handle_lease(),
        &vrk,
        &recovery_envelope,
        RECOVERY_PASSPHRASE,
        &source_manifest_envelope,
        &source_db,
        &generic_sources,
        &snapshot_path,
        &package_dir,
        &verify_path,
    )
    .expect("create, publish, and verify B505 portable backup");
    assert_eq!(accepted.vault_id(), identity.vault_id());

    // Audit provider objects: zero plaintext markers in provider keys or ciphertext payloads.
    for (key, payload) in &provider.objects {
        for marker in [
            &b"SECRET-PORTABLE-BACKUP-ASSERTION-MARKER"[..],
            &b"veltrixamine"[..],
            manifest_record.proof_id.as_bytes(),
        ] {
            assert!(!key.as_bytes().windows(marker.len()).any(|w| w == marker));
            assert!(!payload.windows(marker.len()).any(|w| w == marker));
        }
    }

    let descriptor_key = descriptor_provider_key(accepted.set_id());
    let descriptor_bytes = provider
        .read(&descriptor_key)
        .expect("read published backup descriptor");

    // Tamper with one object chunk in a cloned provider and confirm fail-closed rejection.
    let mut tampered_provider = provider.clone();
    let data_key = tampered_provider
        .objects
        .keys()
        .find(|key| *key != &descriptor_key)
        .expect("at least one backup chunk object")
        .clone();
    let chunk = tampered_provider
        .objects
        .get_mut(&data_key)
        .expect("chunk bytes");
    let flip_index = chunk.len() - 1;
    chunk[flip_index] ^= 0x80;
    let tampered_stage = work_dir.path().join("tampered-stage.sqlite3");
    let tamper_result = verify_fresh_device_backup_restore_material(
        &mut tampered_provider,
        &descriptor_bytes,
        RECOVERY_PASSPHRASE,
        identity.vault_id(),
        &tampered_stage,
    );
    assert!(matches!(
        tamper_result,
        Err(FreshDeviceBackupMaterialError::Semantic(_))
    ));
    assert!(!tampered_stage.exists());

    // Authentic fresh-device restore into a completely clean target directory.
    let restore_stage = work_dir.path().join("authentic-stage.sqlite3");
    let verified_material = verify_fresh_device_backup_restore_material(
        &mut provider,
        &descriptor_bytes,
        RECOVERY_PASSPHRASE,
        identity.vault_id(),
        &restore_stage,
    )
    .expect("verify fresh-device backup material");

    let mut fresh_protector = MemoryFreshDeviceProtector::default();
    let prepared_genesis = prepare_verified_fresh_device_genesis(
        &mut fresh_protector,
        verified_material,
        FreshDeviceNewestnessRiskAccepted::ACCEPTED,
    )
    .expect("prepare fresh-device genesis");

    let mut restore_backend =
        CleanDirectoryRestoreBackend::new(clean_restore_dir.path().to_path_buf());
    let completed = publish_prepared_fresh_device_restore(
        &mut fresh_protector,
        &mut restore_backend,
        &restore_stage,
        prepared_genesis,
    )
    .expect("publish fresh-device restore to clean directory");
    assert!(!completed.global_newestness_proven());

    // Reopen ProofStore directly from the restored clean directory using the protector-held VRK.
    let restored_vrk = fresh_protector
        .unlock_vrk(identity.vault_id(), identity.key_generation())
        .expect("unlock restored VRK");
    let restored_lease = VaultLease::new(identity);
    let mut restored_store = ProofStore::open_existing(
        restore_backend.canonical_db_path(),
        restored_lease.keyed_handle_lease(),
        structured_context(identity),
        &restored_vrk,
    )
    .expect("open restored ProofStore in clean directory");

    let restored_proof = restored_store
        .read(&manifest_record.proof_id)
        .expect("restored proof state");
    assert_eq!(restored_proof.state, ProofState::Committed);
    assert_eq!(restored_proof.final_text, brief.into_bytes());
    let restored_assertion = restored_store
        .assertion("assert-backup-portable")
        .expect("restored assertion query")
        .expect("restored assertion present");
    assert_eq!(
        restored_assertion.payload["marker"],
        "SECRET-PORTABLE-BACKUP-ASSERTION-MARKER"
    );
    assert!(
        restored_store
            .verify_record_semantics_doctor()
            .expect("restored doctor")
            .passed()
    );
}

//! Atomic answer commit in the private vault (`docs/P00_PROOF_ADMISSION_CONTRACT.md`), step 3 of
//! `plan-v1.1` §C, plus the append-only stores `plan-v1.3` requires.
//!
//! Answer, manifest and audit event are written in one transaction. Triggers refuse updates and
//! deletes of those records, sources and amendments, including `INSERT OR REPLACE`. This guards
//! against bugs in this codebase. It is no boundary against malicious in-process code or anyone
//! holding the key. It holds invented fixture data today and makes no clinical claim.
//! Covered: process kills, SQLite page-quota disk-full rollback, key-loss recovery, and backup
//! restore. Not covered: physical power loss, cross-store outbox.

use std::path::Path;

use rusqlite::params;
use safeevidence_contracts::assurance::ProofState;
use safeevidence_contracts::objects::{
    AmendmentRecord, ClinicalAssertion, DigestSha256, MedicalTime,
};
use safeevidence_contracts::proof::{AnswerProofManifest, ManifestDefect, commit_defects};
use safeevidence_vault::vault_keys::{KeyDerivationContext, OwnedKeyMaterial};
use safeevidence_vault::vault_lease::KeyedHandleLease;
use safeevidence_vault::vault_sqlcipher::{
    GuardedSqlError, GuardedTransaction, SqlCipherDatabaseHandle, SqlCipherOpenError,
    SqlCipherTransactionError, open_sqlcipher_database,
};

pub mod surveillance;

const SCHEMA: &[&str] = &[
    "CREATE TABLE authority (
    id INTEGER PRIMARY KEY CHECK (id = 1), epoch INTEGER NOT NULL, rights_grant TEXT NOT NULL)",
    "INSERT INTO authority (id, epoch, rights_grant) VALUES (1, 0, '')",
    "CREATE TABLE answers (
    proof_id TEXT PRIMARY KEY, final_text BLOB NOT NULL, final_text_digest TEXT NOT NULL,
    manifest TEXT NOT NULL)",
    "CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, proof_id TEXT NOT NULL, event TEXT NOT NULL)",
    "CREATE TABLE invalidations (
    proof_id TEXT PRIMARY KEY REFERENCES answers(proof_id), reason TEXT NOT NULL)",
    "CREATE TABLE sources (
    source_id TEXT PRIMARY KEY, digest TEXT NOT NULL, bytes BLOB NOT NULL)",
    "CREATE TABLE amendments (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL UNIQUE, prior_id TEXT NOT NULL,
    superseding_id TEXT NOT NULL, record TEXT NOT NULL)",
    "CREATE TABLE rights_grants (version TEXT PRIMARY KEY)",
    "CREATE TABLE store_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, subject TEXT NOT NULL)",
    "CREATE TRIGGER authority_monotonic BEFORE UPDATE ON authority
    WHEN NEW.epoch < OLD.epoch BEGIN SELECT RAISE(ABORT, 'validity epoch must not decrease'); END",
    "CREATE TRIGGER authority_keep BEFORE DELETE ON authority
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER answers_no_update BEFORE UPDATE ON answers
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER answers_no_delete BEFORE DELETE ON answers
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER invalidations_no_update BEFORE UPDATE ON invalidations
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER invalidations_no_delete BEFORE DELETE ON invalidations
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER sources_no_update BEFORE UPDATE ON sources
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER sources_no_delete BEFORE DELETE ON sources
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER amendments_no_update BEFORE UPDATE ON amendments
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER amendments_no_delete BEFORE DELETE ON amendments
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER rights_grants_no_update BEFORE UPDATE ON rights_grants
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER rights_grants_no_delete BEFORE DELETE ON rights_grants
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER store_events_no_update BEFORE UPDATE ON store_events
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER store_events_no_delete BEFORE DELETE ON store_events
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TABLE source_retractions (
    source_id TEXT PRIMARY KEY REFERENCES sources(source_id), rationale TEXT NOT NULL,
    authorized_by TEXT NOT NULL, recorded_time TEXT NOT NULL)",
    "CREATE TABLE assertions (
    assertion_id TEXT PRIMARY KEY, digest TEXT NOT NULL, record TEXT NOT NULL)",
    "CREATE TABLE assertion_amendments (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL UNIQUE, prior_id TEXT NOT NULL,
    superseding_id TEXT NOT NULL, record TEXT NOT NULL)",
    "CREATE TRIGGER source_retractions_no_update BEFORE UPDATE ON source_retractions
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER source_retractions_no_delete BEFORE DELETE ON source_retractions
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER assertions_no_update BEFORE UPDATE ON assertions
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER assertions_no_delete BEFORE DELETE ON assertions
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER assertion_amendments_no_update BEFORE UPDATE ON assertion_amendments
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER assertion_amendments_no_delete BEFORE DELETE ON assertion_amendments
    BEGIN SELECT RAISE(ABORT, 'append-only'); END",
];

/// SHA-256 of the stored names and text of every schema object. A store whose triggers or tables
/// differ is refused before its schema or data changes. There are no migrations yet, so a caller
/// that keys its store's location on this gets a new store when the schema changes. Change this
/// only together with `SCHEMA`.
pub const SCHEMA_OBJECTS_SHA256: &str =
    "c278d741a7736b1cbde3f619c9f44f03e17f9cc6f9a64dd5c39d57dd4ebc3ab2";

#[derive(Debug)]
pub enum StoreError {
    Open(SqlCipherOpenError),
    Lease(String),
    Provider(rusqlite::Error),
    StatementNotAllowed,
    Corrupt(String),
    /// The connection did not accept the required durability settings.
    NotDurable,
    /// The stored schema is not the one this build installs.
    SchemaMismatch {
        found: String,
    },
    /// `open_existing` found no schema, so this store's contents are gone.
    NotEstablished,
    /// SQLite reported the database busy. Nothing was written; retry.
    Busy,
    /// SQLite reported disk or page-quota exhaustion (`SQLITE_FULL`); transaction rolled back.
    DiskFull,
    /// A statement ended the transaction early. Nothing from this call was written.
    TransactionLost,
    /// The commit outcome is unknown. Retry with the same proof to reconcile.
    CommitUnknown(rusqlite::Error),
    Defects(Vec<ManifestDefect>),
    WrongState(ProofState),
    TextDigestMismatch,
    /// Validity moved after verification: `PROOF_RACE_INVALIDATED`.
    ProofRace {
        verified: u64,
        current: u64,
    },
    /// The manifest's rights grant is not the one in force.
    RightsChanged,
    /// A rights grant must be non-empty.
    InvalidRightsGrant,
    /// A grant that was replaced cannot come back, so it cannot restore an old answer.
    RightsGrantRetired,
    /// A cited source is not stored, or its digest differs from the cited one.
    SourceNotAdmitted(String),
    /// A cited source was amended after this answer was verified.
    SourceAmended(String),
    /// A cited source was retracted without supersession.
    SourceRetracted(String),
    /// A cited span lies outside the stored source's UTF-8 scalar bounds.
    InvalidSpanBounds(String),
    /// One proof ID may never hold a different text or manifest.
    ConflictingProof,
    SourceConflict,
    InvalidAmendment,
    InvalidAssertion,
    AssertionConflict,
    InvalidRetraction,
    EpochMustIncrease,
    UnknownProof,
}

impl StoreError {
    /// Constructs an injected `CommitUnknown` error for callers that do not link `rusqlite` directly.
    #[must_use]
    pub const fn synthetic_commit_unknown() -> Self {
        Self::CommitUnknown(rusqlite::Error::InvalidQuery)
    }
}

impl From<GuardedSqlError> for StoreError {
    fn from(error: GuardedSqlError) -> Self {
        match error {
            GuardedSqlError::StatementNotAllowed => Self::StatementNotAllowed,
            GuardedSqlError::TransactionEnded => Self::TransactionLost,
            GuardedSqlError::Provider(error) => provider_error(error),
        }
    }
}

fn provider_error(error: rusqlite::Error) -> StoreError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy) => StoreError::Busy,
        Some(rusqlite::ErrorCode::DiskFull) => StoreError::DiskFull,
        _ => StoreError::Provider(error),
    }
}

fn flatten<T>(result: Result<T, SqlCipherTransactionError<StoreError>>) -> Result<T, StoreError> {
    match result {
        Ok(value) => Ok(value),
        Err(SqlCipherTransactionError::Access(error)) => {
            Err(StoreError::Lease(format!("{error:?}")))
        }
        Err(SqlCipherTransactionError::Provider(error)) => Err(provider_error(error)),
        Err(SqlCipherTransactionError::CommitUnknown(error)) => {
            Err(StoreError::CommitUnknown(error))
        }
        Err(SqlCipherTransactionError::TransactionLost) => Err(StoreError::TransactionLost),
        Err(SqlCipherTransactionError::Operation(error)) => Err(error),
    }
}

fn flatten_setup<T>(
    result: Result<T, SqlCipherTransactionError<std::convert::Infallible>>,
) -> Result<T, StoreError> {
    match result {
        Ok(value) => Ok(value),
        Err(SqlCipherTransactionError::Access(error)) => {
            Err(StoreError::Lease(format!("{error:?}")))
        }
        Err(SqlCipherTransactionError::Provider(error)) => Err(provider_error(error)),
        Err(SqlCipherTransactionError::CommitUnknown(error)) => {
            Err(StoreError::CommitUnknown(error))
        }
        Err(SqlCipherTransactionError::TransactionLost) => Err(StoreError::TransactionLost),
        Err(SqlCipherTransactionError::Operation(never)) => match never {},
    }
}

/// `state` is this answer's standing now, not merely that it was once committed.
#[derive(Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub proof_id: String,
    pub state: ProofState,
    pub replayed: bool,
}

/// `manifest` is the historical record. `state` is the standing now: only this says if it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct StoredAnswer {
    pub final_text: Vec<u8>,
    pub manifest: AnswerProofManifest,
    pub state: ProofState,
}

/// Runtime `plan-v1.3` record-semantics, durability, and SQLCipher integrity doctor report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSemanticsDoctorReport {
    pub schema_matches: bool,
    pub durable_settings_hold: bool,
    pub cipher_and_sqlite_integrity_ok: bool,
    pub table_count: usize,
    pub append_only_trigger_count: usize,
}

impl RecordSemanticsDoctorReport {
    pub const EXPECTED_TABLES: usize = 11;
    pub const EXPECTED_TRIGGERS: usize = 22;

    /// True only when SQLCipher page-HMAC integrity, SQLite integrity, WAL + `FULL` sync +
    /// `recursive_triggers`, exact `SCHEMA_OBJECTS_SHA256`, and all 11 tables + 22 append-only /
    /// monotonic triggers are verified live.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.schema_matches
            && self.durable_settings_hold
            && self.cipher_and_sqlite_integrity_ok
            && self.table_count == Self::EXPECTED_TABLES
            && self.append_only_trigger_count == Self::EXPECTED_TRIGGERS
    }
}

pub struct ProofStore {
    handle: SqlCipherDatabaseHandle,
}

fn one<T>(mut rows: Vec<T>) -> Option<T> {
    rows.pop()
}

fn authority(tx: &GuardedTransaction<'_>) -> Result<(u64, String), StoreError> {
    let row = one(tx.query(
        "SELECT epoch, rights_grant FROM authority WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?)
    .ok_or_else(|| StoreError::Corrupt("authority row missing".to_owned()))?;
    let epoch =
        u64::try_from(row.0).map_err(|_| StoreError::Corrupt("negative epoch".to_owned()))?;
    Ok((epoch, row.1))
}

fn epoch_value(epoch: u64) -> Result<i64, StoreError> {
    i64::try_from(epoch).map_err(|_| StoreError::Corrupt("epoch out of range".to_owned()))
}

fn cited_sources(manifest: &AnswerProofManifest) -> impl Iterator<Item = (&str, String)> {
    manifest
        .claims
        .iter()
        .flat_map(|claim| &claim.spans)
        .map(|span| (span.source_id.as_str(), span.source_digest.to_hex()))
}

fn is_amended(tx: &GuardedTransaction<'_>, source_id: &str) -> Result<bool, StoreError> {
    Ok(!tx
        .query(
            "SELECT 1 FROM amendments WHERE prior_id = ?1",
            params![source_id],
            |row| row.get::<_, i64>(0),
        )?
        .is_empty())
}

fn is_retracted(tx: &GuardedTransaction<'_>, source_id: &str) -> Result<bool, StoreError> {
    Ok(!tx
        .query(
            "SELECT 1 FROM source_retractions WHERE source_id = ?1",
            params![source_id],
            |row| row.get::<_, i64>(0),
        )?
        .is_empty())
}

fn record_store_event(
    tx: &GuardedTransaction<'_>,
    event: &str,
    subject: &str,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO store_events (event, subject) VALUES (?1, ?2)",
        params![event, subject],
    )?;
    Ok(())
}

/// One proof, whatever clock time a retry carries.
fn same_proof(first: &AnswerProofManifest, second: &AnswerProofManifest) -> bool {
    let mut first = first.clone();
    let mut second = second.clone();
    first.verified_at_utc.clear();
    second.verified_at_utc.clear();
    first == second
}

/// The standing now. A correction to a cited source or a change of rights grant invalidates, per
/// the proof contract. A moved epoch only leaves currentness unknown.
fn standing(
    tx: &GuardedTransaction<'_>,
    manifest: &AnswerProofManifest,
) -> Result<ProofState, StoreError> {
    let invalidated = !tx
        .query(
            "SELECT 1 FROM invalidations WHERE proof_id = ?1",
            params![manifest.proof_id],
            |row| row.get::<_, i64>(0),
        )?
        .is_empty();
    let mut source_invalidated = false;
    for (source_id, _) in cited_sources(manifest) {
        source_invalidated |= is_amended(tx, source_id)? || is_retracted(tx, source_id)?;
    }
    let (epoch, rights) = authority(tx)?;
    if invalidated || source_invalidated || rights != manifest.rights_grant_version {
        return Ok(ProofState::CurrentlyInvalidated);
    }
    if epoch == manifest.validity_epoch {
        Ok(ProofState::Committed)
    } else {
        Ok(ProofState::CurrentnessUnknown)
    }
}

/// The digest of every schema object, or `None` for an empty database.
fn schema_objects_digest(
    handle: &mut SqlCipherDatabaseHandle,
) -> Result<Option<String>, StoreError> {
    flatten(
        handle.deferred_transaction(|tx| -> Result<Option<String>, StoreError> {
            let total = tx.query("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })?;
            if total == [0] {
                return Ok(None);
            }
            let objects = tx.query(
                "SELECT name, sql FROM sqlite_master
                 WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            let mut text = String::new();
            for (name, sql) in objects {
                text.push_str(&name);
                text.push('\0');
                text.push_str(&sql);
                text.push('\0');
            }
            Ok(Some(DigestSha256::of(text.as_bytes()).to_hex()))
        }),
    )
}

impl ProofStore {
    /// Opens the keyed vault database. It verifies an existing schema before changing its schema or
    /// data, or installs the schema into an empty database, and requires durable settings.
    ///
    /// # Errors
    /// Fails on a wrong key, lease or provider failure, settings that did not take, or a stored
    /// schema that differs from this build's.
    pub fn open<P: AsRef<Path>>(
        path: P,
        lease: KeyedHandleLease,
        context: KeyDerivationContext,
        vrk: &OwnedKeyMaterial,
    ) -> Result<Self, StoreError> {
        Self::open_with(path, lease, context, vrk, true)
    }

    /// Opens a store the caller knows was established, and never installs a schema. After a kill the
    /// schema can live only in the WAL, so an empty database here means that WAL was lost, and a new
    /// empty store would silently forget what the old one held.
    ///
    /// # Errors
    /// As `open`, and `NotEstablished` if the database has no schema.
    pub fn open_existing<P: AsRef<Path>>(
        path: P,
        lease: KeyedHandleLease,
        context: KeyDerivationContext,
        vrk: &OwnedKeyMaterial,
    ) -> Result<Self, StoreError> {
        Self::open_with(path, lease, context, vrk, false)
    }

    fn open_with<P: AsRef<Path>>(
        path: P,
        lease: KeyedHandleLease,
        context: KeyDerivationContext,
        vrk: &OwnedKeyMaterial,
        may_install: bool,
    ) -> Result<Self, StoreError> {
        let mut handle =
            open_sqlcipher_database(path, lease, context, vrk).map_err(StoreError::Open)?;
        let existing = schema_objects_digest(&mut handle)?;
        if existing
            .as_deref()
            .is_some_and(|found| found != SCHEMA_OBJECTS_SHA256)
        {
            return Err(StoreError::SchemaMismatch {
                found: existing.unwrap_or_default(),
            });
        }
        flatten_setup(handle.configure_durable_store())?;
        if !flatten_setup(handle.durable_settings_hold())? {
            return Err(StoreError::NotDurable);
        }
        if existing.is_none() && !may_install {
            return Err(StoreError::NotEstablished);
        }
        if existing.is_none() {
            // Another opener may install first. Its schema is fine if the pin matches.
            let installed = flatten_setup(handle.install_schema(SCHEMA));
            let found = schema_objects_digest(&mut handle)?.unwrap_or_default();
            if found != SCHEMA_OBJECTS_SHA256 {
                installed?;
                return Err(StoreError::SchemaMismatch { found });
            }
        }
        Ok(Self { handle })
    }

    /// Commits one verified answer, or reports the durable one if this exact proof is stored.
    ///
    /// # Errors
    /// Refuses before writing on any manifest defect, wrong state, text mismatch, source not
    /// admitted or since amended, rights change, epoch race or conflicting proof. All writes share
    /// one transaction.
    pub fn commit(
        &mut self,
        manifest: &AnswerProofManifest,
        final_text: &[u8],
    ) -> Result<CommitReceipt, StoreError> {
        if manifest.state != ProofState::VerifiedUncommitted {
            return Err(StoreError::WrongState(manifest.state));
        }
        let defects = commit_defects(manifest);
        if !defects.is_empty() {
            return Err(StoreError::Defects(defects));
        }
        let digest = DigestSha256::of(final_text);
        if digest != manifest.final_text_digest {
            return Err(StoreError::TextDigestMismatch);
        }
        let mut stored = manifest.clone();
        stored.state = ProofState::Committed;
        let encoded = serde_json::to_string(&stored)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        let digest_hex = digest.to_hex();
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<CommitReceipt, StoreError> {
                    let existing = one(tx.query(
                        "SELECT final_text_digest, manifest FROM answers WHERE proof_id = ?1",
                        params![manifest.proof_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )?);
                    if let Some((existing_digest, existing_manifest)) = existing {
                        let existing_manifest: AnswerProofManifest =
                            serde_json::from_str(&existing_manifest)
                                .map_err(|error| StoreError::Corrupt(error.to_string()))?;
                        if existing_digest != digest_hex || !same_proof(&existing_manifest, &stored)
                        {
                            return Err(StoreError::ConflictingProof);
                        }
                        return Ok(CommitReceipt {
                            proof_id: manifest.proof_id.clone(),
                            state: standing(tx, &stored)?,
                            replayed: true,
                        });
                    }
                    let (current, rights) = authority(tx)?;
                    if manifest.validity_epoch != current {
                        return Err(StoreError::ProofRace {
                            verified: manifest.validity_epoch,
                            current,
                        });
                    }
                    if manifest.rights_grant_version != rights {
                        return Err(StoreError::RightsChanged);
                    }
                    for claim in &manifest.claims {
                        for span in &claim.spans {
                            let source_id = span.source_id.as_str();
                            let cited = span.source_digest.to_hex();
                            let found = one(tx.query(
                                "SELECT digest, bytes FROM sources WHERE source_id = ?1",
                                params![source_id],
                                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                            )?);
                            let Some((found_digest, bytes)) = found else {
                                return Err(StoreError::SourceNotAdmitted(source_id.to_owned()));
                            };
                            if DigestSha256::of(&bytes).to_hex() != found_digest {
                                return Err(StoreError::Corrupt(
                                    "stored source bytes do not match their digest".to_owned(),
                                ));
                            }
                            if found_digest != cited {
                                return Err(StoreError::SourceNotAdmitted(source_id.to_owned()));
                            }
                            let Ok(source_text) = std::str::from_utf8(&bytes) else {
                                return Err(StoreError::InvalidSpanBounds(source_id.to_owned()));
                            };
                            let total_scalars = source_text.chars().count() as u64;
                            if span.start_scalar >= span.end_scalar
                                || span.end_scalar > total_scalars
                            {
                                return Err(StoreError::InvalidSpanBounds(source_id.to_owned()));
                            }
                            if is_retracted(tx, source_id)? {
                                return Err(StoreError::SourceRetracted(source_id.to_owned()));
                            }
                            if is_amended(tx, source_id)? {
                                return Err(StoreError::SourceAmended(source_id.to_owned()));
                            }
                        }
                    }
                    tx.execute(
                        "INSERT INTO answers (proof_id, final_text, final_text_digest, manifest)
                 VALUES (?1, ?2, ?3, ?4)",
                        params![manifest.proof_id, final_text, digest_hex, encoded],
                    )?;
                    tx.execute(
                        "INSERT INTO audit_events (proof_id, event) VALUES (?1, 'COMMITTED')",
                        params![manifest.proof_id],
                    )?;
                    Ok(CommitReceipt {
                        proof_id: manifest.proof_id.clone(),
                        state: ProofState::Committed,
                        replayed: false,
                    })
                }),
        )
    }

    /// Reads an answer with its standing now.
    ///
    /// # Errors
    /// Fails on an unknown proof, or stored content that no longer matches its digest.
    pub fn read(&mut self, proof_id: &str) -> Result<StoredAnswer, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<StoredAnswer, StoreError> {
                    let row = one(tx.query(
                "SELECT final_text, final_text_digest, manifest FROM answers WHERE proof_id = ?1",
                params![proof_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?);
                    let Some((final_text, digest, manifest)) = row else {
                        return Err(StoreError::UnknownProof);
                    };
                    if DigestSha256::of(&final_text).to_hex() != digest {
                        return Err(StoreError::Corrupt(
                            "answer text does not match its digest".to_owned(),
                        ));
                    }
                    let manifest: AnswerProofManifest = serde_json::from_str(&manifest)
                        .map_err(|error| StoreError::Corrupt(error.to_string()))?;
                    if manifest.final_text_digest.to_hex() != digest {
                        return Err(StoreError::Corrupt(
                            "manifest does not bind this text".to_owned(),
                        ));
                    }
                    let state = standing(tx, &manifest)?;
                    Ok(StoredAnswer {
                        final_text,
                        manifest,
                        state,
                    })
                }),
        )
    }

    /// Records that a committed answer no longer stands. Its bytes stay as they were.
    ///
    /// # Errors
    /// Fails on an unknown proof. A second call keeps the first reason.
    pub fn invalidate(&mut self, proof_id: &str, reason: &str) -> Result<(), StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let known = !tx
                        .query(
                            "SELECT 1 FROM answers WHERE proof_id = ?1",
                            params![proof_id],
                            |row| row.get::<_, i64>(0),
                        )?
                        .is_empty();
                    if !known {
                        return Err(StoreError::UnknownProof);
                    }
                    let added = tx.execute(
                        "INSERT OR IGNORE INTO invalidations (proof_id, reason) VALUES (?1, ?2)",
                        params![proof_id, reason],
                    )?;
                    if added > 0 {
                        tx.execute(
                            "INSERT INTO audit_events (proof_id, event) VALUES (?1, 'INVALIDATED')",
                            params![proof_id],
                        )?;
                    }
                    Ok(())
                }),
        )
    }

    /// Moves the local validity epoch forward.
    ///
    /// # Errors
    /// Fails unless the new epoch is greater than the current one.
    pub fn advance_epoch(&mut self, epoch: u64) -> Result<(), StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    if epoch <= authority(tx)?.0 {
                        return Err(StoreError::EpochMustIncrease);
                    }
                    tx.execute(
                        "UPDATE authority SET epoch = ?1 WHERE id = 1",
                        params![epoch_value(epoch)?],
                    )?;
                    record_store_event(tx, "EPOCH_ADVANCED", &epoch.to_string())
                }),
        )
    }

    /// Sets the rights grant in force. Answers under any other grant are invalidated for good: a
    /// replaced grant cannot come back. Setting the grant already in force is a no-op.
    ///
    /// # Errors
    /// Refuses an empty grant or one that was replaced.
    pub fn set_rights_grant(&mut self, grant: &str) -> Result<(), StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    if grant.trim().is_empty() {
                        return Err(StoreError::InvalidRightsGrant);
                    }
                    if authority(tx)?.1 == grant {
                        return Ok(());
                    }
                    let used = tx.query(
                        "SELECT 1 FROM rights_grants WHERE version = ?1",
                        params![grant],
                        |row| row.get::<_, i64>(0),
                    )?;
                    if !used.is_empty() {
                        return Err(StoreError::RightsGrantRetired);
                    }
                    tx.execute(
                        "INSERT INTO rights_grants (version) VALUES (?1)",
                        params![grant],
                    )?;
                    tx.execute(
                        "UPDATE authority SET rights_grant = ?1 WHERE id = 1",
                        params![grant],
                    )?;
                    record_store_event(tx, "RIGHTS_GRANT_SET", grant)
                }),
        )
    }

    /// The current local validity epoch.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn epoch(&mut self) -> Result<u64, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<u64, StoreError> { Ok(authority(tx)?.0) }),
        )
    }

    /// The current rights grant in force (`""` before one is set).
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn rights_grant(&mut self) -> Result<String, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<String, StoreError> { Ok(authority(tx)?.1) }),
        )
    }

    /// Whether `stored` binds the same canonical proof manifest as `candidate` (ignoring clock).
    #[must_use]
    pub fn matches_manifest(stored: &StoredAnswer, candidate: &AnswerProofManifest) -> bool {
        let mut expected = candidate.clone();
        expected.state = ProofState::Committed;
        same_proof(&stored.manifest, &expected)
    }

    /// Stores source bytes once. The same bytes again is a no-op; different bytes are refused.
    ///
    /// # Errors
    /// Returns `SourceConflict` if this ID already holds different bytes.
    pub fn put_source(&mut self, source_id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let digest = DigestSha256::of(bytes).to_hex();
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let existing = one(tx.query(
                        "SELECT digest FROM sources WHERE source_id = ?1",
                        params![source_id],
                        |row| row.get::<_, String>(0),
                    )?);
                    match existing {
                        Some(found) if found == digest => Ok(()),
                        Some(_) => Err(StoreError::SourceConflict),
                        None => {
                            tx.execute(
                        "INSERT INTO sources (source_id, digest, bytes) VALUES (?1, ?2, ?3)",
                        params![source_id, digest, bytes],
                    )?;
                            record_store_event(tx, "SOURCE_STORED", source_id)
                        }
                    }
                }),
        )
    }

    /// The stored bytes of a source, verified against their SHA-256 digest.
    ///
    /// # Errors
    /// Fails on a lease or provider failure, or `Corrupt` if stored bytes no longer match their digest.
    pub fn source(&mut self, source_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<Option<Vec<u8>>, StoreError> {
                    let row = one(tx.query(
                        "SELECT digest, bytes FROM sources WHERE source_id = ?1",
                        params![source_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )?);
                    let Some((digest, bytes)) = row else {
                        return Ok(None);
                    };
                    if DigestSha256::of(&bytes).to_hex() != digest {
                        return Err(StoreError::Corrupt(
                            "stored source bytes do not match their digest".to_owned(),
                        ));
                    }
                    Ok(Some(bytes))
                }),
        )
    }

    /// Appends an amendment record: a new source superseding or retracting a stored one. Both stay
    /// stored with their bytes unchanged, the record is kept exactly as given, and answers citing
    /// the prior source stop being assured.
    ///
    /// # Errors
    /// Returns `InvalidAmendment` unless both sources exist and differ, the rationale and author are
    /// not empty, and the record's id is new.
    pub fn amend(&mut self, record: &AmendmentRecord) -> Result<(), StoreError> {
        let prior_id = record.prior_assertion_id.as_str();
        let superseding_id = record.superseding_assertion_id.as_str();
        let record_id = record.header.id.as_str();
        if prior_id == superseding_id
            || record_id.trim().is_empty()
            || record.rationale.trim().is_empty()
            || record.authorized_by.as_str().trim().is_empty()
        {
            return Err(StoreError::InvalidAmendment);
        }
        let encoded = serde_json::to_string(record)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let found = tx.query(
                        "SELECT source_id FROM sources WHERE source_id IN (?1, ?2)",
                        params![prior_id, superseding_id],
                        |row| row.get::<_, String>(0),
                    )?;
                    let reused = tx.query(
                        "SELECT 1 FROM amendments WHERE record_id = ?1",
                        params![record_id],
                        |row| row.get::<_, i64>(0),
                    )?;
                    if found.len() != 2 || !reused.is_empty() {
                        return Err(StoreError::InvalidAmendment);
                    }
                    tx.execute(
                        "INSERT INTO amendments (record_id, prior_id, superseding_id, record)
                 VALUES (?1, ?2, ?3, ?4)",
                        params![record_id, prior_id, superseding_id, encoded],
                    )?;
                    record_store_event(tx, "SOURCE_AMENDED", prior_id)
                }),
        )
    }

    /// The amendment records for a source, oldest first, exactly as they were appended.
    ///
    /// # Errors
    /// Fails on a lease or provider failure, or `Corrupt` if a stored record does not parse.
    pub fn amendment_records(
        &mut self,
        prior_id: &str,
    ) -> Result<Vec<AmendmentRecord>, StoreError> {
        let stored = flatten(self.handle.deferred_transaction(
            |tx| -> Result<Vec<String>, StoreError> {
                Ok(tx.query(
                    "SELECT record FROM amendments WHERE prior_id = ?1 ORDER BY seq",
                    params![prior_id],
                    |row| row.get(0),
                )?)
            },
        ))?;
        stored
            .iter()
            .map(|text| {
                serde_json::from_str(text).map_err(|error| StoreError::Corrupt(error.to_string()))
            })
            .collect()
    }

    /// Store-wide events as (event, subject), oldest first. Per-proof events are `audit_events`.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn store_events(&mut self) -> Result<Vec<(String, String)>, StoreError> {
        flatten(self.handle.deferred_transaction(
            |tx| -> Result<Vec<(String, String)>, StoreError> {
                Ok(tx.query(
                    "SELECT event, subject FROM store_events ORDER BY seq",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            },
        ))
    }

    /// The amendment chain for a source, oldest first.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn amendments(&mut self, prior_id: &str) -> Result<Vec<String>, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<Vec<String>, StoreError> {
                    Ok(tx.query(
                        "SELECT superseding_id FROM amendments WHERE prior_id = ?1 ORDER BY seq",
                        params![prior_id],
                        |row| row.get(0),
                    )?)
                }),
        )
    }

    /// Audit events for a proof, oldest first.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn audit_events(&mut self, proof_id: &str) -> Result<Vec<String>, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<Vec<String>, StoreError> {
                    Ok(tx.query(
                        "SELECT event FROM audit_events WHERE proof_id = ?1 ORDER BY seq",
                        params![proof_id],
                        |row| row.get(0),
                    )?)
                }),
        )
    }

    /// Retracts a stored source without requiring a superseding replacement source. Stored source
    /// bytes stay unchanged, future commits citing this source are refused, and already-committed
    /// proofs citing it transition to `CurrentlyInvalidated`.
    ///
    /// # Errors
    /// Returns `InvalidRetraction` on empty metadata or an unknown source.
    pub fn retract_source(
        &mut self,
        source_id: &str,
        rationale: &str,
        authorized_by: &str,
        recorded_time: &MedicalTime,
    ) -> Result<(), StoreError> {
        if source_id.trim().is_empty()
            || rationale.trim().is_empty()
            || authorized_by.trim().is_empty()
            || recorded_time.value.trim().is_empty()
        {
            return Err(StoreError::InvalidRetraction);
        }
        let encoded_time = serde_json::to_string(recorded_time)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let exists = !tx
                        .query(
                            "SELECT 1 FROM sources WHERE source_id = ?1",
                            params![source_id],
                            |row| row.get::<_, i64>(0),
                        )?
                        .is_empty();
                    if !exists {
                        return Err(StoreError::InvalidRetraction);
                    }
                    let added = tx.execute(
                        "INSERT OR IGNORE INTO source_retractions
                         (source_id, rationale, authorized_by, recorded_time)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![source_id, rationale, authorized_by, encoded_time],
                    )?;
                    if added > 0 {
                        record_store_event(tx, "SOURCE_RETRACTED", source_id)?;
                    }
                    Ok(())
                }),
        )
    }

    /// Whether a stored source has been retracted via [`Self::retract_source`].
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn is_source_retracted(&mut self, source_id: &str) -> Result<bool, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<bool, StoreError> {
                    is_retracted(tx, source_id)
                }),
        )
    }

    /// Stores a promoted `ClinicalAssertion` once (`plan-v1.3`). Validates the P00 assurance
    /// contract (explicit actor authority, non-empty scope/subject/claim fields, and zero
    /// heuristic confidence fields). Storing identical JSON again is a no-op; storing a different
    /// assertion under an existing ID is refused with `AssertionConflict`.
    ///
    /// # Errors
    /// Returns `InvalidAssertion` on contract violation or `AssertionConflict` on mismatch.
    pub fn put_assertion(&mut self, assertion: &ClinicalAssertion) -> Result<(), StoreError> {
        assertion
            .validate_p00_contract()
            .map_err(|_| StoreError::InvalidAssertion)?;
        let assertion_id = assertion.header.id.as_str();
        let encoded = serde_json::to_string(assertion)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        let digest = DigestSha256::of(encoded.as_bytes()).to_hex();
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let existing = one(tx.query(
                        "SELECT digest FROM assertions WHERE assertion_id = ?1",
                        params![assertion_id],
                        |row| row.get::<_, String>(0),
                    )?);
                    match existing {
                        Some(found) if found == digest => Ok(()),
                        Some(_) => Err(StoreError::AssertionConflict),
                        None => {
                            tx.execute(
                                "INSERT INTO assertions (assertion_id, digest, record)
                                 VALUES (?1, ?2, ?3)",
                                params![assertion_id, digest, encoded],
                            )?;
                            record_store_event(tx, "ASSERTION_STORED", assertion_id)
                        }
                    }
                }),
        )
    }

    /// Reads back a stored `ClinicalAssertion`, verifying its SHA-256 digest and P00 contract.
    ///
    /// # Errors
    /// Fails on a lease/provider error or `Corrupt` if stored bytes were tampered with.
    pub fn assertion(
        &mut self,
        assertion_id: &str,
    ) -> Result<Option<ClinicalAssertion>, StoreError> {
        flatten(self.handle.deferred_transaction(
            |tx| -> Result<Option<ClinicalAssertion>, StoreError> {
                let row = one(tx.query(
                    "SELECT digest, record FROM assertions WHERE assertion_id = ?1",
                    params![assertion_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )?);
                let Some((digest, record)) = row else {
                    return Ok(None);
                };
                if DigestSha256::of(record.as_bytes()).to_hex() != digest {
                    return Err(StoreError::Corrupt(
                        "assertion record does not match its digest".to_owned(),
                    ));
                }
                let parsed: ClinicalAssertion = serde_json::from_str(&record)
                    .map_err(|error| StoreError::Corrupt(error.to_string()))?;
                parsed.validate_p00_contract().map_err(|_| {
                    StoreError::Corrupt("stored assertion violates P00 contract".to_owned())
                })?;
                Ok(Some(parsed))
            },
        ))
    }

    /// Appends an `AmendmentRecord` linking two stored `ClinicalAssertion` objects (`plan-v1.3`).
    /// Both the prior and superseding assertions remain stored with their exact bytes unchanged.
    ///
    /// # Errors
    /// Returns `InvalidAmendment` if header/scope/rationale/author fields are empty, if both
    /// assertions do not exist or are equal, or if `record.header.id` was already used.
    pub fn amend_assertion(&mut self, record: &AmendmentRecord) -> Result<(), StoreError> {
        let prior_id = record.prior_assertion_id.as_str();
        let superseding_id = record.superseding_assertion_id.as_str();
        let record_id = record.header.id.as_str();
        if prior_id == superseding_id
            || record_id.trim().is_empty()
            || record
                .header
                .realm_id
                .as_opaque()
                .as_str()
                .trim()
                .is_empty()
            || record
                .header
                .authority_scope_id
                .as_opaque()
                .as_str()
                .trim()
                .is_empty()
            || record.rationale.trim().is_empty()
            || record.authorized_by.as_str().trim().is_empty()
            || record.recorded_time.value.trim().is_empty()
        {
            return Err(StoreError::InvalidAmendment);
        }
        let encoded = serde_json::to_string(record)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let found = tx.query(
                        "SELECT assertion_id FROM assertions WHERE assertion_id IN (?1, ?2)",
                        params![prior_id, superseding_id],
                        |row| row.get::<_, String>(0),
                    )?;
                    let reused = tx.query(
                        "SELECT 1 FROM assertion_amendments WHERE record_id = ?1",
                        params![record_id],
                        |row| row.get::<_, i64>(0),
                    )?;
                    if found.len() != 2 || !reused.is_empty() {
                        return Err(StoreError::InvalidAmendment);
                    }
                    tx.execute(
                        "INSERT INTO assertion_amendments
                         (record_id, prior_id, superseding_id, record)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![record_id, prior_id, superseding_id, encoded],
                    )?;
                    record_store_event(tx, "ASSERTION_AMENDED", prior_id)
                }),
        )
    }

    /// The `AmendmentRecord` lineage for a `ClinicalAssertion`, oldest first, exactly as appended.
    ///
    /// # Errors
    /// Fails on lease/provider failure or `Corrupt` if a stored record fails to parse.
    pub fn assertion_amendment_records(
        &mut self,
        prior_id: &str,
    ) -> Result<Vec<AmendmentRecord>, StoreError> {
        let stored = flatten(self.handle.deferred_transaction(
            |tx| -> Result<Vec<String>, StoreError> {
                Ok(tx.query(
                    "SELECT record FROM assertion_amendments WHERE prior_id = ?1 ORDER BY seq",
                    params![prior_id],
                    |row| row.get(0),
                )?)
            },
        ))?;
        stored
            .iter()
            .map(|text| {
                serde_json::from_str(text).map_err(|error| StoreError::Corrupt(error.to_string()))
            })
            .collect()
    }

    /// Superseding assertion IDs recorded for `prior_id`, oldest first.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn assertion_amendments(&mut self, prior_id: &str) -> Result<Vec<String>, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<Vec<String>, StoreError> {
                    Ok(tx.query(
                        "SELECT superseding_id FROM assertion_amendments
                         WHERE prior_id = ?1 ORDER BY seq",
                        params![prior_id],
                        |row| row.get(0),
                    )?)
                }),
        )
    }

    /// Returns the live SQLite page count of this encrypted store.
    ///
    /// # Errors
    /// Fails on lease or provider failure.
    pub fn page_count(&mut self) -> Result<u32, StoreError> {
        flatten_setup(self.handle.page_count())
    }

    /// Sets SQLite's `PRAGMA max_page_count` ceiling (pass `1_073_741_823` to restore SQLite's
    /// default maximum ceiling) to exercise deterministic `StoreError::DiskFull` rollback (`TA-05`).
    ///
    /// # Errors
    /// Fails on lease or provider failure.
    pub fn set_max_page_count(&mut self, max_pages: u32) -> Result<u32, StoreError> {
        flatten_setup(self.handle.set_max_page_count(max_pages))
    }

    /// Verifies `plan-v1.3` append-only record-semantics triggers, exact `SCHEMA_OBJECTS_SHA256`,
    /// WAL/`FULL`/`recursive_triggers` durability posture, and SQLCipher + SQLite integrity.
    ///
    /// # Errors
    /// Fails on lease or provider query failure.
    pub fn verify_record_semantics_doctor(
        &mut self,
    ) -> Result<RecordSemanticsDoctorReport, StoreError> {
        let cipher_and_sqlite_integrity_ok = self.handle.verify_integrity().is_ok();
        let durable_settings_hold = flatten_setup(self.handle.durable_settings_hold())?;
        let schema_matches =
            schema_objects_digest(&mut self.handle)?.as_deref() == Some(SCHEMA_OBJECTS_SHA256);
        let (table_count, append_only_trigger_count) = flatten(self.handle.deferred_transaction(
            |tx| -> Result<(usize, usize), StoreError> {
                let tables = one(tx.query(
                    "SELECT count(*) FROM sqlite_master
                     WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
                .unwrap_or(0);
                let triggers = one(tx.query(
                    "SELECT count(*) FROM sqlite_master
                     WHERE type = 'trigger' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
                .unwrap_or(0);
                Ok((
                    usize::try_from(tables).unwrap_or(0),
                    usize::try_from(triggers).unwrap_or(0),
                ))
            },
        ))?;
        Ok(RecordSemanticsDoctorReport {
            schema_matches,
            durable_settings_hold,
            cipher_and_sqlite_integrity_ok,
            table_count,
            append_only_trigger_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeevidence_ask::{ask, load_corpus};
    use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
    use safeevidence_vault::vault_keys::{KEY_MATERIAL_BYTES, KeyPurpose};
    use safeevidence_vault::vault_lease::VaultLease;

    const FIXTURE: &[u8] = include_bytes!("../../safeevidence-ask/fixtures/vs1a_corpus.json");

    fn synthetic_amendment(prior: &str, next: &str) -> AmendmentRecord {
        use safeevidence_contracts::objects::{
            AmendmentKind, AuthorityScopeId, MedicalTime, ObjectHeader, OpaqueId, RealmId,
            TimePrecision,
        };
        AmendmentRecord {
            header: ObjectHeader {
                id: OpaqueId::new(format!("am-{prior}-{next}")),
                schema_version: 1,
                realm_id: RealmId::new("realm-synthetic"),
                authority_scope_id: AuthorityScopeId::new("scope-synthetic"),
            },
            prior_assertion_id: OpaqueId::new(prior),
            superseding_assertion_id: OpaqueId::new(next),
            kind: AmendmentKind::Supersession,
            rationale: "synthetic".to_owned(),
            authorized_by: OpaqueId::new("synthetic-actor"),
            recorded_time: MedicalTime::new("1970-01-01T00:00:00Z", TimePrecision::Instant, false),
        }
    }

    struct TempDb(std::path::PathBuf);

    impl TempDb {
        fn new() -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!("se-unit-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir.join("vault.db"))
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    fn attempt_raw_sql(store: &mut ProofStore, sql: &'static str) -> Result<usize, String> {
        let result = store
            .handle
            .immediate_transaction(|tx| -> Result<usize, GuardedSqlError> { tx.execute(sql, []) });
        match result {
            Ok(count) => Ok(count),
            Err(SqlCipherTransactionError::Operation(GuardedSqlError::StatementNotAllowed)) => {
                Err("statement not allowed".to_owned())
            }
            Err(SqlCipherTransactionError::Operation(GuardedSqlError::Provider(error))) => {
                Err(error.to_string())
            }
            Err(other) => Err(format!("{other:?}")),
        }
    }

    #[test]
    fn committed_records_cannot_be_changed_even_by_raw_sql() {
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
        let db = TempDb::new();
        let mut store = ProofStore::open(
            db.0.as_path(),
            lease.keyed_handle_lease(),
            context,
            &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
        )
        .expect("store opens");
        let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture");
        let result = ask(
            "Does veltrixamine help adults with glimmer syndrome?",
            &corpus,
        );
        let manifest = result.manifest.expect("manifest");
        let text = result.brief.expect("brief").into_bytes();
        store.advance_epoch(manifest.validity_epoch).expect("epoch");
        store
            .set_rights_grant(&manifest.rights_grant_version)
            .expect("rights");
        for document in &corpus.documents {
            store
                .put_source(&document.doc_id, document.text.as_bytes())
                .expect("source");
        }
        store.commit(&manifest, &text).expect("commit");
        store.put_source("s1", b"original").expect("source");
        store.put_source("s2", b"newer").expect("source");
        store
            .amend(&synthetic_amendment("s1", "s2"))
            .expect("amend");
        store
            .invalidate(&manifest.proof_id, "reason")
            .expect("invalidate");
        store.put_source("s3", b"retracted").expect("source");
        store
            .retract_source(
                "s3",
                "retracted",
                "actor",
                &safeevidence_contracts::objects::MedicalTime::new(
                    "1970-01-01T00:00:00Z",
                    safeevidence_contracts::objects::TimePrecision::Instant,
                    false,
                ),
            )
            .expect("retract");
        let make_assertion = |id: &str| ClinicalAssertion {
            header: safeevidence_contracts::objects::ObjectHeader {
                id: safeevidence_contracts::objects::OpaqueId::new(id),
                schema_version: 1,
                realm_id: safeevidence_contracts::objects::RealmId::new("realm-synthetic"),
                authority_scope_id: safeevidence_contracts::objects::AuthorityScopeId::new(
                    "scope-synthetic",
                ),
            },
            subject_ref: safeevidence_contracts::objects::OpaqueId::new("subj-1"),
            claim_kind: "synthetic_finding".to_owned(),
            payload: serde_json::json!({"effect": "benefit"}),
            promoted_from_proposal_id: None,
            authorized_by: safeevidence_contracts::objects::OpaqueId::new("actor-1"),
            effective_time: None,
            recorded_time: safeevidence_contracts::objects::MedicalTime::new(
                "1970-01-01T00:00:00Z",
                safeevidence_contracts::objects::TimePrecision::Instant,
                false,
            ),
        };
        store.put_assertion(&make_assertion("ca-1")).expect("ca-1");
        store.put_assertion(&make_assertion("ca-2")).expect("ca-2");
        store
            .amend_assertion(&synthetic_amendment("ca-1", "ca-2"))
            .expect("amend assertion");

        for sql in [
            "UPDATE answers SET final_text = x'00'",
            "DELETE FROM answers",
            "UPDATE audit_events SET event = 'X'",
            "DELETE FROM audit_events",
            "UPDATE invalidations SET reason = 'X'",
            "DELETE FROM invalidations",
            "UPDATE sources SET bytes = x'00'",
            "DELETE FROM sources",
            "UPDATE amendments SET record = 'X'",
            "UPDATE amendments SET record_id = 'X'",
            "DELETE FROM amendments",
            "UPDATE source_retractions SET rationale = 'X'",
            "DELETE FROM source_retractions",
            "UPDATE assertions SET record = 'X'",
            "DELETE FROM assertions",
            "UPDATE assertion_amendments SET record = 'X'",
            "DELETE FROM assertion_amendments",
            "INSERT OR REPLACE INTO answers (proof_id, final_text, final_text_digest, manifest) SELECT proof_id, x'00', final_text_digest, manifest FROM answers",
            "INSERT OR REPLACE INTO sources (source_id, digest, bytes) VALUES ('s1', 'x', x'00')",
            "INSERT OR REPLACE INTO amendments (seq, record_id, prior_id, superseding_id, record) VALUES (1, 'r', 'x', 'y', 'z')",
            "INSERT OR REPLACE INTO source_retractions (source_id, rationale, authorized_by, recorded_time) VALUES ('s3', 'x', 'y', 'z')",
            "INSERT OR REPLACE INTO assertions (assertion_id, digest, record) VALUES ('ca-1', 'x', 'y')",
            "INSERT OR REPLACE INTO assertion_amendments (seq, record_id, prior_id, superseding_id, record) VALUES (1, 'r', 'x', 'y', 'z')",
            "DELETE FROM authority",
            "DELETE FROM store_events",
            "UPDATE store_events SET event = 'X'",
            "DELETE FROM rights_grants",
            "UPDATE rights_grants SET version = 'X'",
            "UPDATE authority SET epoch = 1",
            "INSERT OR REPLACE INTO authority (id, epoch, rights_grant) VALUES (1, 1, 'x')",
        ] {
            let error = attempt_raw_sql(&mut store, sql).expect_err(sql);
            assert!(
                error.contains("append-only") || error.contains("must not decrease"),
                "{sql}: {error}"
            );
        }
        assert_eq!(
            store.read(&manifest.proof_id).expect("read").final_text,
            text
        );
        assert_eq!(
            store.source("s1").expect("source").as_deref(),
            Some(&b"original"[..])
        );
    }

    #[test]
    fn guarded_transaction_refuses_everything_but_row_statements() {
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
        let db = TempDb::new();
        let mut store = ProofStore::open(
            db.0.as_path(),
            lease.keyed_handle_lease(),
            context,
            &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
        )
        .expect("store opens");
        for sql in [
            "SELECT 1",
            "DROP TRIGGER sources_no_update",
            "DROP TABLE sources",
            "ALTER TABLE sources ADD COLUMN x",
            "PRAGMA rekey = 'x'",
            "PRAGMA writable_schema = ON",
            "PRAGMA journal_mode = MEMORY",
            "ATTACH DATABASE 'x' AS y",
            "COMMIT",
            "VACUUM",
            "REPLACE INTO sources (source_id, digest, bytes) VALUES ('a', 'b', x'00')",
            "",
        ] {
            assert_eq!(
                attempt_raw_sql(&mut store, sql).expect_err(sql),
                "statement not allowed",
                "{sql}"
            );
        }
        let batched = attempt_raw_sql(&mut store, "DELETE FROM sources; DROP TABLE sources");
        assert!(
            batched.is_err(),
            "several statements in one call are refused"
        );
        store
            .put_source("still-here", b"x")
            .expect("table survives");
    }

    #[test]
    fn a_failed_operation_rolls_back_every_write() {
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
        let db = TempDb::new();
        let mut store = ProofStore::open(
            db.0.as_path(),
            lease.keyed_handle_lease(),
            context,
            &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
        )
        .expect("store opens");
        let result = store
            .handle
            .immediate_transaction(|tx| -> Result<(), StoreError> {
                tx.execute(
                    "INSERT INTO audit_events (proof_id, event) VALUES ('p', 'COMMITTED')",
                    [],
                )?;
                Err(StoreError::ConflictingProof)
            });
        assert!(matches!(
            result,
            Err(SqlCipherTransactionError::Operation(
                StoreError::ConflictingProof
            ))
        ));
        assert!(store.audit_events("p").expect("audit").is_empty());
    }

    fn temp_store() -> (TempDb, VaultLease, ProofStore) {
        let identity = VaultLeaseIdentity::new(
            VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
            KeyGeneration::new(7).expect("generation"),
        );
        let lease = VaultLease::new(identity);
        let db = TempDb::new();
        let store = reopen(&db, &lease);
        (db, lease, store)
    }

    fn reopen(db: &TempDb, lease: &VaultLease) -> ProofStore {
        try_reopen(db, lease).expect("store opens")
    }

    fn try_reopen(db: &TempDb, lease: &VaultLease) -> Result<ProofStore, StoreError> {
        let context = KeyDerivationContext::new(
            VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
            KeyGeneration::new(7).expect("generation"),
            KeyPurpose::StructuredStore,
        );
        ProofStore::open(
            db.0.as_path(),
            lease.keyed_handle_lease(),
            context,
            &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
        )
    }

    fn fixture_answer(store: &mut ProofStore) -> (AnswerProofManifest, Vec<u8>) {
        let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture");
        let result = ask(
            "Does veltrixamine help adults with glimmer syndrome?",
            &corpus,
        );
        let manifest = result.manifest.expect("manifest");
        store.advance_epoch(manifest.validity_epoch).expect("epoch");
        store
            .set_rights_grant(&manifest.rights_grant_version)
            .expect("rights");
        for document in &corpus.documents {
            store
                .put_source(&document.doc_id, document.text.as_bytes())
                .expect("source");
        }
        (manifest, result.brief.expect("brief").into_bytes())
    }

    #[test]
    fn durable_settings_are_on_after_open() {
        let (_db, _lease, mut store) = temp_store();
        assert!(matches!(store.handle.durable_settings_hold(), Ok(true)));
    }

    #[test]
    fn a_failed_audit_write_leaves_no_answer_behind() {
        let (_db, _lease, mut store) = temp_store();
        let (manifest, text) = fixture_answer(&mut store);
        store
            .handle
            .install_schema(&["CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events
                 BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"])
            .expect("trigger");
        assert!(matches!(
            store.commit(&manifest, &text),
            Err(StoreError::Provider(_))
        ));
        store
            .handle
            .install_schema(&["DROP TRIGGER fail_audit"])
            .expect("drop");
        assert!(matches!(
            store.read(&manifest.proof_id),
            Err(StoreError::UnknownProof)
        ));
        store.commit(&manifest, &text).expect("clean retry");
    }

    #[test]
    fn a_transaction_holds_the_write_lock_before_its_first_write() {
        let (db, lease, mut first) = temp_store();
        let mut second = reopen(&db, &lease);
        let blocked = first
            .handle
            .immediate_transaction(|_tx| -> Result<bool, StoreError> {
                Ok(matches!(
                    second.put_source("s", b"x"),
                    Err(StoreError::Busy)
                ))
            })
            .map_err(|_| "transaction failed")
            .expect("transaction");
        assert!(
            blocked,
            "another connection must not write inside a transaction"
        );
    }

    #[test]
    fn read_refuses_text_that_no_longer_matches_its_digest() {
        let (_db, _lease, mut store) = temp_store();
        let (manifest, text) = fixture_answer(&mut store);
        store.commit(&manifest, &text).expect("commit");
        store
            .handle
            .install_schema(&[
                "DROP TRIGGER answers_no_update",
                "UPDATE answers SET final_text = x'00'",
            ])
            .expect("simulated corruption");
        assert!(matches!(
            store.read(&manifest.proof_id),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn epochs_outside_the_stored_range_are_refused() {
        let (_db, _lease, mut store) = temp_store();
        assert!(matches!(
            store.advance_epoch(u64::MAX),
            Err(StoreError::Corrupt(_))
        ));
        assert_eq!(store.epoch().expect("epoch"), 0);
        store
            .handle
            .install_schema(&[
                "DROP TRIGGER authority_monotonic",
                "UPDATE authority SET epoch = -1",
            ])
            .expect("simulated corruption");
        assert!(matches!(store.epoch(), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn read_refuses_a_manifest_that_does_not_bind_the_stored_text() {
        let (_db, _lease, mut store) = temp_store();
        let (manifest, text) = fixture_answer(&mut store);
        store.commit(&manifest, &text).expect("commit");
        // The digest below is SHA-256 of the single zero byte, so text and column agree.
        store
            .handle
            .install_schema(&[
                "DROP TRIGGER answers_no_update",
                "UPDATE answers SET final_text = x'00', final_text_digest =
                 '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d'",
            ])
            .expect("simulated corruption");
        assert!(matches!(
            store.read(&manifest.proof_id),
            Err(StoreError::Corrupt(reason)) if reason.contains("manifest")
        ));
    }

    #[test]
    fn replacement_is_still_refused_after_reopen() {
        let (db, lease, mut store) = temp_store();
        store.put_source("s", b"original").expect("source");
        drop(store);
        let mut store = reopen(&db, &lease);
        let error = attempt_raw_sql(
            &mut store,
            "INSERT OR REPLACE INTO sources (source_id, digest, bytes) VALUES ('s', 'x', x'00')",
        )
        .expect_err("replacement");
        assert!(error.contains("append-only"), "{error}");
    }

    #[test]
    fn open_refuses_a_weakened_trigger() {
        let (db, lease, mut store) = temp_store();
        store
            .handle
            .install_schema(&[
                "DROP TRIGGER answers_no_update",
                "CREATE TRIGGER answers_no_update BEFORE UPDATE ON answers WHEN 0
                     BEGIN SELECT RAISE(ABORT, 'append-only'); END",
            ])
            .expect("weaken");
        drop(store);
        assert!(matches!(
            try_reopen(&db, &lease),
            Err(StoreError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn open_refuses_foreign_tables_with_the_same_names() {
        let db = TempDb::new();
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
        let mut handle = open_sqlcipher_database(
            db.0.as_path(),
            lease.keyed_handle_lease(),
            context,
            &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
        )
        .expect("raw handle");
        handle
            .install_schema(&["CREATE TABLE answers (other TEXT)"])
            .expect("foreign table");
        drop(handle);
        assert!(matches!(
            try_reopen(&db, &lease),
            Err(StoreError::SchemaMismatch { .. })
        ));
        let mut handle = open_sqlcipher_database(
            db.0.as_path(),
            lease.keyed_handle_lease(),
            KeyDerivationContext::new(
                identity.vault_id(),
                identity.key_generation(),
                KeyPurpose::StructuredStore,
            ),
            &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
        )
        .expect("raw handle");
        let objects = handle
            .immediate_transaction(|tx| {
                tx.query("SELECT count(*) FROM sqlite_master", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .expect("count");
        assert_eq!(objects, [1], "a refused open writes nothing");
    }

    #[test]
    fn reads_proceed_while_another_connection_writes() {
        let (db, lease, mut writer) = temp_store();
        let mut reader = reopen(&db, &lease);
        let result = writer
            .handle
            .immediate_transaction(|tx| -> Result<u64, StoreError> {
                tx.execute(
                    "INSERT INTO store_events (event, subject) VALUES ('X', 'Y')",
                    [],
                )?;
                reader.epoch()
            });
        assert!(matches!(result, Ok(0)), "{result:?}");
    }

    #[test]
    fn query_refuses_anything_but_select() {
        let (_db, _lease, mut store) = temp_store();
        let result = store.handle.immediate_transaction(|tx| {
            tx.query("DELETE FROM sources", [], |row| row.get::<_, i64>(0))
        });
        assert!(matches!(
            result,
            Err(SqlCipherTransactionError::Operation(
                GuardedSqlError::StatementNotAllowed
            ))
        ));
    }

    fn assert_refused_on_reopen(statements: &'static [&'static str]) {
        let (db, lease, mut store) = temp_store();
        store.handle.install_schema(statements).expect("change");
        drop(store);
        assert!(
            matches!(
                try_reopen(&db, &lease),
                Err(StoreError::SchemaMismatch { .. })
            ),
            "{statements:?}"
        );
    }

    #[test]
    fn open_refuses_missing_objects_instead_of_recreating_them() {
        assert_refused_on_reopen(&["DROP TABLE rights_grants"]);
        assert_refused_on_reopen(&["DROP TABLE invalidations"]);
        assert_refused_on_reopen(&["DROP TRIGGER answers_no_update"]);
    }

    #[test]
    fn open_refuses_an_object_named_to_look_internal() {
        assert_refused_on_reopen(&["CREATE TRIGGER sqlitex_gag BEFORE INSERT ON audit_events
                 BEGIN SELECT RAISE(IGNORE); END"]);
    }

    #[test]
    fn a_store_opens_while_another_connection_writes() {
        let (db, lease, mut writer) = temp_store();
        let result = writer
            .handle
            .immediate_transaction(|_tx| -> Result<u64, StoreError> {
                try_reopen(&db, &lease)?.epoch()
            });
        assert!(matches!(result, Ok(0)), "{result:?}");
    }

    #[test]
    fn open_refuses_a_fully_dropped_store_instead_of_resetting_it() {
        assert_refused_on_reopen(&[
            "DROP TABLE authority",
            "DROP TABLE answers",
            "DROP TABLE audit_events",
            "DROP TABLE invalidations",
            "DROP TABLE sources",
            "DROP TABLE amendments",
            "DROP TABLE source_retractions",
            "DROP TABLE assertions",
            "DROP TABLE assertion_amendments",
            "DROP TABLE rights_grants",
            "DROP TABLE store_events",
        ]);
    }

    #[test]
    fn concurrent_openers_of_an_empty_database_get_a_store_or_busy() {
        for _ in 0..12 {
            let db = TempDb::new();
            let identity = VaultLeaseIdentity::new(
                VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
                KeyGeneration::new(7).expect("generation"),
            );
            let lease = VaultLease::new(identity);
            let (first, second) = std::thread::scope(|scope| {
                let first = scope.spawn(|| try_reopen(&db, &lease).map(|_| ()));
                let second = scope.spawn(|| try_reopen(&db, &lease).map(|_| ()));
                (first.join().expect("join"), second.join().expect("join"))
            });
            for result in [first, second] {
                assert!(
                    matches!(result, Ok(()) | Err(StoreError::Busy)),
                    "{result:?}"
                );
            }
            reopen(&db, &lease);
        }
    }
}

//! Atomic answer commit in the private vault (`docs/P00_PROOF_ADMISSION_CONTRACT.md`), step 3 of
//! `plan-v1.1` §C, plus the append-only stores `plan-v1.3` requires.
//!
//! Answer, manifest and audit event are written in one transaction. Triggers refuse updates and
//! deletes of those records, sources and amendments, including `INSERT OR REPLACE`. This guards
//! against bugs in this codebase. It is no boundary against malicious in-process code or anyone
//! holding the key. It holds invented fixture data today and makes no clinical claim.
//! Covered: process kills. Not covered: power loss, disk full, restore, cross-store outbox.

use std::path::Path;

use rusqlite::params;
use safeevidence_contracts::assurance::ProofState;
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{AnswerProofManifest, ManifestDefect, commit_defects};
use safeevidence_vault::vault_keys::{KeyDerivationContext, OwnedKeyMaterial};
use safeevidence_vault::vault_lease::KeyedHandleLease;
use safeevidence_vault::vault_sqlcipher::{
    GuardedSqlError, GuardedTransaction, SqlCipherDatabaseHandle, SqlCipherOpenError,
    SqlCipherTransactionError, open_sqlcipher_database,
};

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
    seq INTEGER PRIMARY KEY AUTOINCREMENT, prior_id TEXT NOT NULL, superseding_id TEXT NOT NULL,
    reason TEXT NOT NULL)",
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
];

/// SHA-256 of the stored names and text of every schema object. A store whose triggers or tables
/// differ is refused before its schema or data changes. There are no migrations yet. Change this
/// only together with `SCHEMA`.
const SCHEMA_OBJECTS_SHA256: &str =
    "7e67770f3aeccf9bc4387ba0203b31698303ce9289636c9a4b559bb06a545918";

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
    /// SQLite reported the database busy. Nothing was written; retry.
    Busy,
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
    /// One proof ID may never hold a different text or manifest.
    ConflictingProof,
    SourceConflict,
    InvalidAmendment,
    EpochMustIncrease,
    UnknownProof,
}

impl From<GuardedSqlError> for StoreError {
    fn from(error: GuardedSqlError) -> Self {
        match error {
            GuardedSqlError::StatementNotAllowed => Self::StatementNotAllowed,
            GuardedSqlError::Provider(error) => provider_error(error),
        }
    }
}

fn provider_error(error: rusqlite::Error) -> StoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) {
        StoreError::Busy
    } else {
        StoreError::Provider(error)
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
    let mut amended = false;
    for (source_id, _) in cited_sources(manifest) {
        amended |= is_amended(tx, source_id)?;
    }
    let (epoch, rights) = authority(tx)?;
    if invalidated || amended || rights != manifest.rights_grant_version {
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
                    for (source_id, cited) in cited_sources(manifest) {
                        let found = one(tx.query(
                            "SELECT digest FROM sources WHERE source_id = ?1",
                            params![source_id],
                            |row| row.get::<_, String>(0),
                        )?);
                        if found.as_deref() != Some(cited.as_str()) {
                            return Err(StoreError::SourceNotAdmitted(source_id.to_owned()));
                        }
                        if is_amended(tx, source_id)? {
                            return Err(StoreError::SourceAmended(source_id.to_owned()));
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

    /// The stored bytes of a source.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn source(&mut self, source_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        flatten(
            self.handle
                .deferred_transaction(|tx| -> Result<Option<Vec<u8>>, StoreError> {
                    Ok(one(tx.query(
                        "SELECT bytes FROM sources WHERE source_id = ?1",
                        params![source_id],
                        |row| row.get::<_, Vec<u8>>(0),
                    )?))
                }),
        )
    }

    /// Appends an amendment: a new source superseding a stored one. Both stay stored, and answers
    /// citing the prior source stop being assured.
    ///
    /// # Errors
    /// Returns `InvalidAmendment` unless both exist and differ.
    pub fn amend(
        &mut self,
        prior_id: &str,
        superseding_id: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let found = tx.query(
                        "SELECT source_id FROM sources WHERE source_id IN (?1, ?2)",
                        params![prior_id, superseding_id],
                        |row| row.get::<_, String>(0),
                    )?;
                    if prior_id == superseding_id || found.len() != 2 {
                        return Err(StoreError::InvalidAmendment);
                    }
                    tx.execute(
                "INSERT INTO amendments (prior_id, superseding_id, reason) VALUES (?1, ?2, ?3)",
                params![prior_id, superseding_id, reason],
            )?;
                    record_store_event(tx, "SOURCE_AMENDED", prior_id)
                }),
        )
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeevidence_ask::{ask, load_corpus};
    use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
    use safeevidence_vault::vault_keys::{KEY_MATERIAL_BYTES, KeyPurpose};
    use safeevidence_vault::vault_lease::VaultLease;

    const FIXTURE: &[u8] = include_bytes!("../../safeevidence-ask/fixtures/vs1a_corpus.json");

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
        store.amend("s1", "s2", "synthetic").expect("amend");
        store
            .invalidate(&manifest.proof_id, "reason")
            .expect("invalidate");

        for sql in [
            "UPDATE answers SET final_text = x'00'",
            "DELETE FROM answers",
            "UPDATE audit_events SET event = 'X'",
            "DELETE FROM audit_events",
            "UPDATE invalidations SET reason = 'X'",
            "DELETE FROM invalidations",
            "UPDATE sources SET bytes = x'00'",
            "DELETE FROM sources",
            "UPDATE amendments SET reason = 'X'",
            "DELETE FROM amendments",
            "INSERT OR REPLACE INTO answers (proof_id, final_text, final_text_digest, manifest) SELECT proof_id, x'00', final_text_digest, manifest FROM answers",
            "INSERT OR REPLACE INTO sources (source_id, digest, bytes) VALUES ('s1', 'x', x'00')",
            "INSERT OR REPLACE INTO amendments (seq, prior_id, superseding_id, reason) VALUES (1, 'x', 'y', 'z')",
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

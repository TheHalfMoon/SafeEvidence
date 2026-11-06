//! Atomic answer commit in the private vault (`docs/P00_PROOF_ADMISSION_CONTRACT.md`), step 3 of
//! `plan-v1.1` §C, plus the append-only stores `plan-v1.3` requires.
//!
//! Answer, manifest and audit event are written in one transaction. Database triggers refuse any
//! update or delete of those records, of stored sources and of amendments, so a bug here cannot
//! overwrite history. This holds invented fixture data today and makes no clinical claim. Covered:
//! process kills and SQL-level tampering. Not covered: power loss, disk full, or an attacker with the key.

use std::path::Path;

use rusqlite::{OptionalExtension, Transaction, params};
use safeevidence_contracts::assurance::ProofState;
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{AnswerProofManifest, ManifestDefect, commit_defects};
use safeevidence_vault::vault_keys::{KeyDerivationContext, OwnedKeyMaterial};
use safeevidence_vault::vault_lease::KeyedHandleLease;
use safeevidence_vault::vault_sqlcipher::{
    SqlCipherDatabaseHandle, SqlCipherOpenError, SqlCipherTransactionError, open_sqlcipher_database,
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS validity (id INTEGER PRIMARY KEY CHECK (id = 1), epoch INTEGER NOT NULL);
INSERT OR IGNORE INTO validity (id, epoch) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS answers (
    proof_id TEXT PRIMARY KEY, final_text BLOB NOT NULL, final_text_digest TEXT NOT NULL,
    manifest TEXT NOT NULL, committed_epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, proof_id TEXT NOT NULL, event TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invalidations (
    proof_id TEXT PRIMARY KEY REFERENCES answers(proof_id), reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY, digest TEXT NOT NULL, bytes BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS amendments (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, prior_id TEXT NOT NULL, superseding_id TEXT NOT NULL,
    reason TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS validity_monotonic BEFORE UPDATE ON validity
    WHEN NEW.epoch <= OLD.epoch BEGIN SELECT RAISE(ABORT, 'validity epoch must increase'); END;
CREATE TRIGGER IF NOT EXISTS validity_keep BEFORE DELETE ON validity
    BEGIN SELECT RAISE(ABORT, 'append-only'); END;
";
const APPEND_ONLY: [&str; 5] = [
    "answers",
    "audit_events",
    "invalidations",
    "sources",
    "amendments",
];

#[derive(Debug)]
pub enum StoreError {
    Open(SqlCipherOpenError),
    Lease(String),
    Provider(rusqlite::Error),
    Corrupt(String),
    /// The manifest cannot back a committed answer.
    Defects(Vec<ManifestDefect>),
    /// Only a verified, uncommitted proof can be committed.
    WrongState(ProofState),
    /// These bytes are not the text the manifest binds.
    TextDigestMismatch,
    /// Validity moved after verification: `PROOF_RACE_INVALIDATED`.
    ProofRace {
        verified: u64,
        current: u64,
    },
    /// One proof ID may never hold two different texts.
    ConflictingText,
    /// Stored source bytes may never be replaced under the same ID.
    SourceConflict,
    /// An amendment must name an existing, different prior.
    InvalidAmendment,
    UnknownProof,
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Provider(error)
    }
}

fn flatten<T, E: Into<StoreError>>(
    result: Result<T, SqlCipherTransactionError<E>>,
) -> Result<T, StoreError> {
    match result {
        Ok(value) => Ok(value),
        Err(SqlCipherTransactionError::Access(error)) => {
            Err(StoreError::Lease(format!("{error:?}")))
        }
        Err(SqlCipherTransactionError::Provider(error)) => Err(StoreError::Provider(error)),
        Err(SqlCipherTransactionError::Operation(error)) => Err(error.into()),
    }
}

/// What a commit returned. `replayed` means this exact answer was already durable.
#[derive(Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub proof_id: String,
    pub state: ProofState,
    pub replayed: bool,
}

/// A stored answer and its standing now. Historical bytes never change; only the state can.
#[derive(Debug, PartialEq, Eq)]
pub struct StoredAnswer {
    pub final_text: Vec<u8>,
    pub manifest: AnswerProofManifest,
    pub state: ProofState,
}

pub struct ProofStore {
    handle: SqlCipherDatabaseHandle,
}

impl ProofStore {
    /// Opens the keyed vault database, requires full durability and installs the schema.
    ///
    /// # Errors
    /// Fails on a wrong key, lease, or provider failure.
    pub fn open<P: AsRef<Path>>(
        path: P,
        lease: KeyedHandleLease,
        context: KeyDerivationContext,
        vrk: &OwnedKeyMaterial,
    ) -> Result<Self, StoreError> {
        let mut handle =
            open_sqlcipher_database(path, lease, context, vrk).map_err(StoreError::Open)?;
        flatten(
            handle
                .require_full_synchronous()
                .map_err(|error| match error {
                    SqlCipherTransactionError::Access(a) => SqlCipherTransactionError::Access(a),
                    SqlCipherTransactionError::Provider(p) => {
                        SqlCipherTransactionError::Provider(p)
                    }
                    SqlCipherTransactionError::Operation(()) => {
                        SqlCipherTransactionError::Operation(StoreError::Corrupt(
                            "synchronous".to_owned(),
                        ))
                    }
                }),
        )?;
        flatten(
            handle.immediate_transaction(|tx| -> Result<(), StoreError> {
                tx.execute_batch(SCHEMA)?;
                for table in APPEND_ONLY {
                    tx.execute_batch(&format!(
                        "CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table}
                         BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                     CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table}
                         BEGIN SELECT RAISE(ABORT, 'append-only'); END;"
                    ))?;
                }
                Ok(())
            }),
        )?;
        Ok(Self { handle })
    }

    /// Commits one verified answer, or returns the stored receipt if this exact answer is durable.
    ///
    /// # Errors
    /// Refuses before writing on any manifest defect, wrong state, text mismatch, epoch race or
    /// conflicting text. Nothing partial can persist: all writes share one transaction.
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
        flatten(self.handle.immediate_transaction(|tx| -> Result<CommitReceipt, StoreError> {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT final_text_digest FROM answers WHERE proof_id = ?1",
                    params![manifest.proof_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing != digest_hex {
                    return Err(StoreError::ConflictingText);
                }
                return Ok(CommitReceipt {
                    proof_id: manifest.proof_id.clone(),
                    state: ProofState::Committed,
                    replayed: true,
                });
            }
            let current = current_epoch(tx)?;
            if manifest.validity_epoch != current {
                return Err(StoreError::ProofRace {
                    verified: manifest.validity_epoch,
                    current,
                });
            }
            tx.execute(
                "INSERT INTO answers (proof_id, final_text, final_text_digest, manifest, committed_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![manifest.proof_id, final_text, digest_hex, encoded, epoch_value(current)?],
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
        }))
    }

    /// Reads an answer with its current standing. An answer is only `Committed` while the local
    /// validity epoch is the one it was verified at: otherwise this cannot say it still holds.
    ///
    /// # Errors
    /// Fails on an unknown proof, or stored content that no longer matches its digest.
    pub fn read(&mut self, proof_id: &str) -> Result<StoredAnswer, StoreError> {
        flatten(self.handle.immediate_transaction(|tx| -> Result<StoredAnswer, StoreError> {
            let row: Option<(Vec<u8>, String, String)> = tx
                .query_row(
                    "SELECT final_text, final_text_digest, manifest FROM answers WHERE proof_id = ?1",
                    params![proof_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((final_text, digest, manifest)) = row else {
                return Err(StoreError::UnknownProof);
            };
            if DigestSha256::of(&final_text).to_hex() != digest {
                return Err(StoreError::Corrupt("answer text does not match its digest".to_owned()));
            }
            let manifest: AnswerProofManifest = serde_json::from_str(&manifest)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?;
            let invalidated: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM invalidations WHERE proof_id = ?1)",
                params![proof_id],
                |row| row.get(0),
            )?;
            let state = if invalidated {
                ProofState::CurrentlyInvalidated
            } else if current_epoch(tx)? == manifest.validity_epoch {
                ProofState::Committed
            } else {
                ProofState::CurrentnessUnknown
            };
            Ok(StoredAnswer { final_text, manifest, state })
        }))
    }

    /// Records that a committed answer no longer stands. Its bytes stay as they were.
    ///
    /// # Errors
    /// Fails on an unknown proof. A second call keeps the first reason.
    pub fn invalidate(&mut self, proof_id: &str, reason: &str) -> Result<(), StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    let known: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM answers WHERE proof_id = ?1)",
                        params![proof_id],
                        |row| row.get(0),
                    )?;
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

    /// Moves the local validity epoch forward. Moving it back or sideways is refused.
    ///
    /// # Errors
    /// Fails if the new epoch is not greater than the current one.
    pub fn advance_epoch(&mut self, epoch: u64) -> Result<(), StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<(), StoreError> {
                    tx.execute(
                        "UPDATE validity SET epoch = ?1 WHERE id = 1",
                        params![epoch_value(epoch)?],
                    )?;
                    Ok(())
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
                .immediate_transaction(|tx| -> Result<u64, StoreError> { current_epoch(tx) }),
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
                    let existing: Option<String> = tx
                        .query_row(
                            "SELECT digest FROM sources WHERE source_id = ?1",
                            params![source_id],
                            |row| row.get(0),
                        )
                        .optional()?;
                    match existing {
                        Some(found) if found == digest => Ok(()),
                        Some(_) => Err(StoreError::SourceConflict),
                        None => {
                            tx.execute(
                        "INSERT INTO sources (source_id, digest, bytes) VALUES (?1, ?2, ?3)",
                        params![source_id, digest, bytes],
                    )?;
                            Ok(())
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
                .immediate_transaction(|tx| -> Result<Option<Vec<u8>>, StoreError> {
                    Ok(tx
                        .query_row(
                            "SELECT bytes FROM sources WHERE source_id = ?1",
                            params![source_id],
                            |row| row.get(0),
                        )
                        .optional()?)
                }),
        )
    }

    /// Appends an amendment: a new source superseding a stored one. Both stay stored.
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
                    let count: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM sources WHERE source_id IN (?1, ?2)",
                        params![prior_id, superseding_id],
                        |row| row.get(0),
                    )?;
                    if prior_id == superseding_id || count != 2 {
                        return Err(StoreError::InvalidAmendment);
                    }
                    tx.execute(
                "INSERT INTO amendments (prior_id, superseding_id, reason) VALUES (?1, ?2, ?3)",
                params![prior_id, superseding_id, reason],
            )?;
                    Ok(())
                }),
        )
    }

    /// The amendment chain for a source, oldest first.
    ///
    /// # Errors
    /// Fails on a lease or provider failure.
    pub fn amendments(&mut self, prior_id: &str) -> Result<Vec<String>, StoreError> {
        flatten(
            self.handle
                .immediate_transaction(|tx| -> Result<Vec<String>, StoreError> {
                    let mut statement = tx.prepare(
                        "SELECT superseding_id FROM amendments WHERE prior_id = ?1 ORDER BY seq",
                    )?;
                    let rows = statement.query_map(params![prior_id], |row| row.get(0))?;
                    Ok(rows.collect::<Result<Vec<String>, _>>()?)
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
                .immediate_transaction(|tx| -> Result<Vec<String>, StoreError> {
                    let mut statement = tx.prepare(
                        "SELECT event FROM audit_events WHERE proof_id = ?1 ORDER BY seq",
                    )?;
                    let rows = statement.query_map(params![proof_id], |row| row.get(0))?;
                    Ok(rows.collect::<Result<Vec<String>, _>>()?)
                }),
        )
    }
}

fn current_epoch(tx: &Transaction<'_>) -> Result<u64, StoreError> {
    let value: i64 = tx.query_row("SELECT epoch FROM validity WHERE id = 1", [], |row| {
        row.get(0)
    })?;
    u64::try_from(value).map_err(|_| StoreError::Corrupt("negative epoch".to_owned()))
}

fn epoch_value(epoch: u64) -> Result<i64, StoreError> {
    i64::try_from(epoch).map_err(|_| StoreError::Corrupt("epoch out of range".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeevidence_ask::{ask, load_corpus};
    use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
    use safeevidence_vault::vault_keys::{KEY_MATERIAL_BYTES, KeyPurpose};
    use safeevidence_vault::vault_lease::VaultLease;

    const FIXTURE: &[u8] = include_bytes!("../../safeevidence-ask/fixtures/vs1a_corpus.json");

    fn attempt_raw_sql(store: &mut ProofStore, sql: &str) -> Result<usize, String> {
        let result = store
            .handle
            .immediate_transaction(|tx| -> Result<usize, rusqlite::Error> { tx.execute(sql, []) });
        match result {
            Ok(count) => Ok(count),
            Err(
                SqlCipherTransactionError::Operation(error)
                | SqlCipherTransactionError::Provider(error),
            ) => Err(error.to_string()),
            Err(SqlCipherTransactionError::Access(error)) => Err(format!("{error:?}")),
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
        let mut store = ProofStore::open(
            ":memory:",
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
            "DELETE FROM validity",
            "UPDATE validity SET epoch = 1",
        ] {
            let error = attempt_raw_sql(&mut store, sql).expect_err(sql);
            assert!(
                error.contains("append-only") || error.contains("must increase"),
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
}

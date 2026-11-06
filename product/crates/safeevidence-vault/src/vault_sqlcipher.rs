//! B301-B305 integration for the exact reviewed SQLCipher provider strategy.
//!
//! B301 opens the already provenance-registered SQLCipher build, applies the B201
//! `StructuredStore` purpose key as SQLCipher raw key material, verifies the exact
//! SQLCipher/embedded-SQLite runtime identities, and places the connection behind
//! the existing B105 lease gate. B302 additionally requires the keyed connection
//! to report encryption active before any handle can be returned. B303 pins the
//! reviewed OpenSSL provider/runtime identity, verifies the selected target-specific
//! SQLCipher temp-store compile posture, and disables file-backed temporary data.
//! B304 adds lease-gated normal SQLite integrity and SQLCipher cipher/page-
//! authentication integrity checks using the exact pinned provider semantics. B305
//! adds genuine wrong-key/corruption fixtures plus bounded mismatch tests for the
//! same production provider/version validators.
//!
//! B303 deliberately does not select one permanent journal mode. Qualification
//! exercises both WAL and rollback-journal operation because canonical contracts
//! require both families to work under the reviewed provider. Plaintext-spill
//! qualification and migration remain B306-B307.

use crate::vault::VaultLeaseIdentity;
use crate::vault_io::{KeyedIoError, LeaseBoundDatabaseHandle};
use crate::vault_keys::{KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial};
use crate::vault_lease::{KeyedHandleError, KeyedHandleLease};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Exact SQLCipher runtime identity produced by the reviewed 4.14.0 community source.
pub const EXPECTED_SQLCIPHER_RUNTIME_VERSION: &str = "4.14.0 community";

/// Exact SQLite runtime identity embedded by the reviewed SQLCipher source closure.
pub const EXPECTED_SQLITE_RUNTIME_VERSION: &str = "3.51.3";

/// Exact SQLCipher crypto-provider name produced by the reviewed OpenSSL provider.
pub const EXPECTED_SQLCIPHER_CRYPTO_PROVIDER: &str = "openssl";

/// Exact OpenSSL runtime text produced by the reviewed 3.6.3 source revision.
pub const EXPECTED_OPENSSL_RUNTIME_VERSION: &str = "OpenSSL 3.6.3 9 Jun 2026";

#[cfg(target_os = "android")]
const EXPECTED_TEMP_STORE_COMPILE_OPTION: &str = "TEMP_STORE=3";

#[cfg(not(target_os = "android"))]
const EXPECTED_TEMP_STORE_COMPILE_OPTION: &str = "TEMP_STORE=2";

const TEMP_STORE_MEMORY: i64 = 2;

/// Typed fail-closed errors for the B301-B303 provider-open boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlCipherOpenError {
    /// The keyed-handle lease is already locked or revoked.
    Access(KeyedHandleError),
    /// The derivation context and lease do not identify the same vault generation.
    IdentityMismatch,
    /// The derivation context is not the reviewed structured-store purpose.
    PurposeMismatch,
    /// The SQLite/SQLCipher connection could not be opened.
    Open,
    /// SQLCipher rejected the raw structured-store key operation.
    Key,
    /// The runtime did not report the exact reviewed SQLCipher identity.
    ProviderVersion,
    /// The runtime did not report the exact reviewed embedded SQLite identity.
    SqliteVersion,
    /// The SQLCipher encryption-status query could not produce its reviewed scalar.
    EncryptionStatus,
    /// SQLCipher did not positively report encryption active.
    EncryptionInactive,
    /// SQLCipher did not report the exact reviewed crypto-provider name.
    CryptoProvider,
    /// SQLCipher did not report the exact reviewed OpenSSL runtime identity.
    CryptoProviderVersion,
    /// SQLite did not report the selected target-specific temp-store compile posture.
    CompilePosture,
    /// File-backed temporary storage could not be disabled and positively verified.
    TemporaryStorage,
}

impl fmt::Display for SqlCipherOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Access(error) => return write!(f, "SQLCipher access rejected: {error}"),
            Self::IdentityMismatch => "SQLCipher lease and derivation identity do not match",
            Self::PurposeMismatch => "SQLCipher derivation purpose is not StructuredStore",
            Self::Open => "SQLCipher connection open failed",
            Self::Key => "SQLCipher raw-key operation failed",
            Self::ProviderVersion => {
                "SQLCipher runtime identity does not match the reviewed provider"
            }
            Self::SqliteVersion => {
                "embedded SQLite runtime identity does not match the reviewed provider"
            }
            Self::EncryptionStatus => "SQLCipher encryption-active status could not be proven",
            Self::EncryptionInactive => "SQLCipher encryption is not active",
            Self::CryptoProvider => {
                "SQLCipher crypto-provider identity is not the reviewed OpenSSL provider"
            }
            Self::CryptoProviderVersion => {
                "SQLCipher crypto-provider runtime version is not the reviewed OpenSSL version"
            }
            Self::CompilePosture => {
                "SQLCipher temp-store compile posture does not match the reviewed target build"
            }
            Self::TemporaryStorage => "SQLCipher temporary storage is not forced to memory",
        };
        f.write_str(message)
    }
}

impl Error for SqlCipherOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Access(error) => Some(error),
            _ => None,
        }
    }
}

impl From<KeyedHandleError> for SqlCipherOpenError {
    fn from(error: KeyedHandleError) -> Self {
        Self::Access(error)
    }
}

/// Typed fail-closed errors for B304 integrity verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlCipherIntegrityError {
    /// The B105 keyed-handle lease rejected the integrity operation.
    Access(KeyedHandleError),
    /// SQLCipher cipher/page-authentication integrity could not be queried.
    CipherIntegrityQuery,
    /// SQLCipher returned one or more cipher-integrity diagnostic rows.
    CipherIntegrityFailed,
    /// SQLite integrity could not be queried or decoded as the reviewed text shape.
    SqliteIntegrityQuery,
    /// SQLite did not return exactly one row containing exact text `ok`.
    SqliteIntegrityFailed,
}

impl fmt::Display for SqlCipherIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Access(error) => {
                return write!(f, "SQLCipher integrity access rejected: {error}");
            }
            Self::CipherIntegrityQuery => "SQLCipher cipher integrity could not be proven",
            Self::CipherIntegrityFailed => "SQLCipher cipher integrity check failed",
            Self::SqliteIntegrityQuery => "SQLite integrity could not be proven",
            Self::SqliteIntegrityFailed => "SQLite integrity check failed",
        };
        f.write_str(message)
    }
}

impl Error for SqlCipherIntegrityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Access(error) => Some(error),
            _ => None,
        }
    }
}

/// Caller-owned proof that ordinary vault writes remain excluded for a backup snapshot call.
///
/// Implementations must hold the underlying coordination exclusion for the complete
/// `snapshot_quiesced_sqlcipher_database` call. A point-in-time observation that no writer is
/// currently active is insufficient. The snapshot boundary rechecks this proof around the
/// checkpoint, copy, and verification stages, but the guard owns the exclusion itself.
pub trait BackupSnapshotQuiescenceGuard {
    type Error;

    fn assert_normal_writes_quiesced(&mut self) -> Result<(), Self::Error>;
}

/// Exact identity of one separately staged, integrity-verified SQLCipher backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlCipherBackupSnapshot {
    path: PathBuf,
    source_precheckpoint_byte_length: u64,
    source_precheckpoint_sha256: [u8; 32],
    byte_length: u64,
    sha256: [u8; 32],
}

impl SqlCipherBackupSnapshot {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn source_precheckpoint_byte_length(&self) -> u64 {
        self.source_precheckpoint_byte_length
    }

    #[must_use]
    pub const fn source_precheckpoint_sha256(&self) -> [u8; 32] {
        self.source_precheckpoint_sha256
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Fail-closed WAL checkpoint outcomes at the lease-gated SQLCipher boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlCipherBackupCheckpointError {
    Access(KeyedHandleError),
    Query,
    Busy,
    Incomplete,
}

/// Fail-closed errors for the B505 quiesced SQLCipher snapshot primitive.
#[derive(Debug)]
pub enum SqlCipherBackupSnapshotError<E> {
    Quiescence(E),
    Path,
    SamePath,
    TargetAlreadyExists,
    SourceOpen(SqlCipherOpenError),
    SourceIntegrity(SqlCipherIntegrityError),
    Checkpoint(SqlCipherBackupCheckpointError),
    WalNotTruncated,
    SourceRead,
    SourceChanged,
    Copy,
    Durability,
    TargetIdentityMismatch,
    TargetOpen(SqlCipherOpenError),
    TargetIntegrity(SqlCipherIntegrityError),
}

impl<E: fmt::Display> fmt::Display for SqlCipherBackupSnapshotError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quiescence(error) => write!(f, "backup snapshot quiescence failed: {error}"),
            Self::Path => f.write_str("backup snapshot path validation failed"),
            Self::SamePath => f.write_str("backup snapshot source and target paths alias"),
            Self::TargetAlreadyExists => f.write_str("backup snapshot target already exists"),
            Self::SourceOpen(error) => write!(f, "backup snapshot source open failed: {error}"),
            Self::SourceIntegrity(error) => {
                write!(f, "backup snapshot source integrity failed: {error}")
            }
            Self::Checkpoint(error) => {
                write!(f, "backup snapshot WAL checkpoint failed: {error:?}")
            }
            Self::WalNotTruncated => f.write_str("backup snapshot WAL was not fully truncated"),
            Self::SourceRead => f.write_str("backup snapshot source identity could not be read"),
            Self::SourceChanged => f.write_str("backup snapshot source changed while quiesced"),
            Self::Copy => f.write_str("backup snapshot copy failed"),
            Self::Durability => f.write_str("backup snapshot staged copy durability failed"),
            Self::TargetIdentityMismatch => {
                f.write_str("backup snapshot staged bytes do not match the stable source")
            }
            Self::TargetOpen(error) => write!(f, "backup snapshot target open failed: {error}"),
            Self::TargetIntegrity(error) => {
                write!(f, "backup snapshot target integrity failed: {error}")
            }
        }
    }
}

impl<E: Error + 'static> Error for SqlCipherBackupSnapshotError<E> {}

/// Fail-closed errors for B503 cross-generation SQLCipher staging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlCipherGenerationMigrationError {
    /// Source and target contexts do not describe the same vault.
    VaultMismatch,
    /// Source and target contexts are not both for the structured-store purpose.
    PurposeMismatch,
    /// Target generation is not strictly newer than the source generation.
    GenerationOrder,
    /// Source or target path could not be resolved safely.
    Path,
    /// Source and target resolve to the same database path.
    SamePath,
    /// A target database already exists and must be reconciled by the caller.
    TargetAlreadyExists,
    /// The verified source database could not be opened.
    SourceOpen(SqlCipherOpenError),
    /// The source database failed the reviewed integrity checks.
    SourceIntegrity(SqlCipherIntegrityError),
    /// SQLCipher could not export the source into the separately keyed target.
    Export,
    /// The staged target could not be durably flushed.
    Durability,
    /// The target database could not be reopened through the production path.
    TargetOpen(SqlCipherOpenError),
    /// The target database failed the reviewed integrity checks.
    TargetIntegrity(SqlCipherIntegrityError),
    /// Cross-generation key isolation could not be proven in both directions.
    KeyIsolation,
}

impl fmt::Display for SqlCipherGenerationMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultMismatch => f.write_str("SQLCipher rotation vault identity mismatch"),
            Self::PurposeMismatch => f.write_str("SQLCipher rotation purpose mismatch"),
            Self::GenerationOrder => {
                f.write_str("SQLCipher rotation target generation is not newer")
            }
            Self::Path => f.write_str("SQLCipher rotation path validation failed"),
            Self::SamePath => f.write_str("SQLCipher rotation source and target paths alias"),
            Self::TargetAlreadyExists => f.write_str("SQLCipher rotation target already exists"),
            Self::SourceOpen(error) => write!(f, "SQLCipher rotation source open failed: {error}"),
            Self::SourceIntegrity(error) => {
                write!(f, "SQLCipher rotation source integrity failed: {error}")
            }
            Self::Export => f.write_str("SQLCipher cross-generation export failed"),
            Self::Durability => f.write_str("SQLCipher staged target durability failed"),
            Self::TargetOpen(error) => write!(f, "SQLCipher rotation target open failed: {error}"),
            Self::TargetIntegrity(error) => {
                write!(f, "SQLCipher rotation target integrity failed: {error}")
            }
            Self::KeyIsolation => f.write_str("SQLCipher cross-generation key isolation failed"),
        }
    }
}

impl Error for SqlCipherGenerationMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SourceOpen(error) | Self::TargetOpen(error) => Some(error),
            Self::SourceIntegrity(error) | Self::TargetIntegrity(error) => Some(error),
            _ => None,
        }
    }
}

struct SqlCipherDatabase {
    // The raw provider remains private. Later authorized leaves may extend the
    // outer handle but must continue to cross the B105 lease gate for keyed I/O.
    _connection: Connection,
}

/// Lease-bound SQLCipher handle created only after B301-B303 provider proof succeeds.
///
/// The raw `rusqlite::Connection` is intentionally not exposed. B304-B307 may
/// extend this type only through separately authorized, lease-gated behavior.
pub struct SqlCipherDatabaseHandle {
    inner: LeaseBoundDatabaseHandle<SqlCipherDatabase>,
}

impl SqlCipherDatabaseHandle {
    /// Returns the vault/generation identity bound to this keyed database handle.
    #[must_use]
    pub fn identity(&self) -> VaultLeaseIdentity {
        self.inner.identity()
    }

    /// Runs the B304 SQLCipher and SQLite integrity checks under one B105 read permit.
    ///
    /// Clean SQLCipher cipher integrity is exactly zero result rows. Clean SQLite
    /// integrity is exactly one text row equal to `ok`. Any other shape, any
    /// diagnostic row, or any query/type/execution failure fails closed. The raw
    /// connection is never exposed.
    pub fn verify_integrity(&self) -> Result<(), SqlCipherIntegrityError> {
        match self
            .inner
            .read(|backend| verify_b304_integrity(&backend._connection))
        {
            Ok(()) => Ok(()),
            Err(KeyedIoError::Access(error)) => Err(SqlCipherIntegrityError::Access(error)),
            Err(KeyedIoError::Backend(error)) => Err(error),
        }
    }
}

/// Failure of one lease-guarded database transaction.
#[derive(Debug)]
pub enum SqlCipherTransactionError<E> {
    /// The vault lease rejected the operation, so nothing ran.
    Access(KeyedHandleError),
    /// The provider failed before commit, so the transaction rolled back.
    Provider(rusqlite::Error),
    /// The operation returned an error, so the transaction rolled back.
    Operation(E),
    /// The commit itself failed. Whether it became durable is unknown until reconciled.
    CommitUnknown(rusqlite::Error),
}

/// Failure of a statement run through [`GuardedTransaction`].
#[derive(Debug)]
pub enum GuardedSqlError {
    /// Only single SELECT, INSERT, UPDATE and DELETE statements are allowed.
    StatementNotAllowed,
    Provider(rusqlite::Error),
}

impl From<rusqlite::Error> for GuardedSqlError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Provider(error)
    }
}

/// A transaction limited to row reads and writes, using compile-time statement text. It offers no
/// route to PRAGMA, ATTACH, schema changes or transaction control, so stores cannot weaken the
/// connection by mistake. This guards against bugs, not malicious code in this process: a SELECT
/// can still call any SQL function the provider registers.
pub struct GuardedTransaction<'a> {
    transaction: &'a rusqlite::Transaction<'a>,
}

/// SQLite reports full synchronous as 2 and an enabled flag as 1.
fn settings_are_durable(journal: &str, synchronous: i64, recursive_triggers: i64) -> bool {
    journal.eq_ignore_ascii_case("wal") && synchronous == 2 && recursive_triggers == 1
}

/// True if `sql` holds no `;` but a trailing one. This must be decided before the provider sees the
/// text: to detect a second statement rusqlite prepares it, and SQLite applies PRAGMAs at prepare.
fn single_statement(sql: &str) -> bool {
    let sql = sql.trim_end();
    !sql.strip_suffix(';').unwrap_or(sql).contains(';')
}

fn statement_allowed(sql: &str) -> bool {
    let first = sql.split_whitespace().next().unwrap_or_default();
    single_statement(sql)
        && ["INSERT", "UPDATE", "DELETE"]
            .iter()
            .any(|keyword| first.eq_ignore_ascii_case(keyword))
}

fn query_allowed(sql: &str) -> bool {
    let first = sql.split_whitespace().next().unwrap_or_default();
    single_statement(sql) && first.eq_ignore_ascii_case("SELECT")
}

impl GuardedTransaction<'_> {
    /// Runs one INSERT, UPDATE or DELETE. A string holding a second statement is refused.
    ///
    /// # Errors
    /// Refuses other statement kinds, and returns provider failures.
    pub fn execute<P: rusqlite::Params>(
        &self,
        sql: &'static str,
        params: P,
    ) -> Result<usize, GuardedSqlError> {
        if !statement_allowed(sql) {
            return Err(GuardedSqlError::StatementNotAllowed);
        }
        Ok(self.transaction.execute(sql, params)?)
    }

    /// Runs one query, mapping every row.
    ///
    /// # Errors
    /// Refuses anything but SELECT, and returns provider failures.
    pub fn query<T, P, F>(
        &self,
        sql: &'static str,
        params: P,
        map: F,
    ) -> Result<Vec<T>, GuardedSqlError>
    where
        P: rusqlite::Params,
        F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        if !query_allowed(sql) {
            return Err(GuardedSqlError::StatementNotAllowed);
        }
        let mut statement = self.transaction.prepare(sql)?;
        let rows = statement.query_map(params, map)?;
        Ok(rows.collect::<rusqlite::Result<Vec<T>>>()?)
    }
}

fn schema_statement_allowed(sql: &str) -> bool {
    let mut words = sql.split_whitespace();
    let first = words.next().unwrap_or_default();
    let is_trigger = first.eq_ignore_ascii_case("CREATE")
        && words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("TRIGGER"));
    // A trigger body holds `;`, and SQLite parses it as part of the one statement up to END.
    let body_ended = is_trigger
        && sql
            .trim_end()
            .strip_suffix(';')
            .unwrap_or(sql.trim_end())
            .trim_end()
            .to_ascii_uppercase()
            .ends_with("END");
    (single_statement(sql) || body_ended)
        && ["CREATE", "DROP", "INSERT", "UPDATE", "DELETE"]
            .iter()
            .any(|keyword| first.eq_ignore_ascii_case(keyword))
}

/// SafeEvidence addition to the donor's handle: the narrow routes a store needs. The connection
/// stays private, and each call holds the lease permit for its whole duration.
impl SqlCipherDatabaseHandle {
    fn run_transaction<T, E, F>(
        &mut self,
        behavior: rusqlite::TransactionBehavior,
        operation: F,
    ) -> Result<T, SqlCipherTransactionError<E>>
    where
        F: FnOnce(&GuardedTransaction<'_>) -> Result<T, E>,
    {
        let result = self.inner.write(|backend| {
            let transaction = backend
                ._connection
                .transaction_with_behavior(behavior)
                .map_err(SqlCipherTransactionError::Provider)?;
            let value = operation(&GuardedTransaction {
                transaction: &transaction,
            })
            .map_err(SqlCipherTransactionError::Operation)?;
            transaction
                .commit()
                .map_err(SqlCipherTransactionError::CommitUnknown)?;
            Ok(value)
        });
        match result {
            Ok(value) => Ok(value),
            Err(KeyedIoError::Access(error)) => Err(SqlCipherTransactionError::Access(error)),
            Err(KeyedIoError::Backend(error)) => Err(error),
        }
    }

    /// Runs `operation` holding the write lock from the start. An `Err` rolls it back; `Ok` commits.
    ///
    /// # Errors
    /// Returns the lease, provider, operation or commit failure.
    pub fn immediate_transaction<T, E, F>(
        &mut self,
        operation: F,
    ) -> Result<T, SqlCipherTransactionError<E>>
    where
        F: FnOnce(&GuardedTransaction<'_>) -> Result<T, E>,
    {
        self.run_transaction(rusqlite::TransactionBehavior::Immediate, operation)
    }

    /// Runs `operation` taking no lock until it reads, so reads proceed beside a writer under WAL.
    ///
    /// # Errors
    /// Returns the lease, provider, operation or commit failure.
    pub fn deferred_transaction<T, E, F>(
        &mut self,
        operation: F,
    ) -> Result<T, SqlCipherTransactionError<E>>
    where
        F: FnOnce(&GuardedTransaction<'_>) -> Result<T, E>,
    {
        self.run_transaction(rusqlite::TransactionBehavior::Deferred, operation)
    }

    /// Applies compile-time schema statements in one transaction, one statement per string. Each
    /// must be CREATE, DROP, INSERT, UPDATE or DELETE, and is checked before it is prepared because
    /// SQLite applies some PRAGMAs at prepare time. So PRAGMA, ATTACH and transaction control never
    /// reach SQLite, and a string holding a second statement is refused.
    ///
    /// # Errors
    /// Returns the lease, provider or commit failure. A refused statement is a provider failure.
    pub fn install_schema(
        &mut self,
        statements: &'static [&'static str],
    ) -> Result<(), SqlCipherTransactionError<std::convert::Infallible>> {
        let result = self.inner.write(|backend| {
            if !statements.iter().all(|sql| schema_statement_allowed(sql)) {
                return Err(SqlCipherTransactionError::Provider(
                    rusqlite::Error::InvalidQuery,
                ));
            }
            let transaction = backend
                ._connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(SqlCipherTransactionError::Provider)?;
            for sql in statements {
                transaction
                    .execute(sql, [])
                    .map_err(SqlCipherTransactionError::Provider)?;
            }
            transaction
                .commit()
                .map_err(SqlCipherTransactionError::CommitUnknown)
        });
        match result {
            Ok(()) => Ok(()),
            Err(KeyedIoError::Access(error)) => Err(SqlCipherTransactionError::Access(error)),
            Err(KeyedIoError::Backend(error)) => Err(error),
        }
    }

    /// Applies WAL and full sync. Confirm with [`Self::durable_settings_hold`].
    ///
    /// # Errors
    /// Returns the lease or provider failure.
    pub fn configure_durable_store(
        &mut self,
    ) -> Result<(), SqlCipherTransactionError<std::convert::Infallible>> {
        let result = self.inner.write(|backend| {
            let connection = &backend._connection;
            connection
                .query_row("PRAGMA journal_mode = WAL;", [], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(SqlCipherTransactionError::Provider)?;
            connection
                .execute_batch("PRAGMA synchronous = FULL;")
                .map_err(SqlCipherTransactionError::Provider)
        });
        match result {
            Ok(()) => Ok(()),
            Err(KeyedIoError::Access(error)) => Err(SqlCipherTransactionError::Access(error)),
            Err(KeyedIoError::Backend(error)) => Err(error),
        }
    }

    /// Reads back whether the connection is on WAL, full sync and recursive triggers.
    ///
    /// # Errors
    /// Returns the lease or provider failure.
    pub fn durable_settings_hold(
        &mut self,
    ) -> Result<bool, SqlCipherTransactionError<std::convert::Infallible>> {
        let result = self.inner.write(|backend| {
            let connection = &backend._connection;
            let journal: String = connection
                .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
                .map_err(SqlCipherTransactionError::Provider)?;
            let read = |pragma: &str| {
                connection
                    .query_row(pragma, [], |row| row.get::<_, i64>(0))
                    .map_err(SqlCipherTransactionError::Provider)
            };
            Ok(settings_are_durable(
                &journal,
                read("PRAGMA synchronous;")?,
                read("PRAGMA recursive_triggers;")?,
            ))
        });
        match result {
            Ok(value) => Ok(value),
            Err(KeyedIoError::Access(error)) => Err(SqlCipherTransactionError::Access(error)),
            Err(KeyedIoError::Backend(error)) => Err(error),
        }
    }
}

impl SqlCipherDatabaseHandle {
    fn checkpoint_truncate_backup_wal(&mut self) -> Result<(), SqlCipherBackupCheckpointError> {
        match self.inner.write(|backend| {
            let (busy, log_frames, checkpointed_frames) = backend
                ._connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|_| SqlCipherBackupCheckpointError::Query)?;
            if busy != 0 {
                return Err(SqlCipherBackupCheckpointError::Busy);
            }
            if log_frames != checkpointed_frames {
                return Err(SqlCipherBackupCheckpointError::Incomplete);
            }
            Ok(())
        }) {
            Ok(()) => Ok(()),
            Err(KeyedIoError::Access(error)) => Err(SqlCipherBackupCheckpointError::Access(error)),
            Err(KeyedIoError::Backend(error)) => Err(error),
        }
    }
}

impl fmt::Debug for SqlCipherDatabaseHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlCipherDatabaseHandle")
            .field("identity", &self.identity())
            .field("backend", &"[REDACTED]")
            .finish()
    }
}

/// Opens, keys, and configures the reviewed SQLCipher provider.
///
/// Validation and lease authorization occur before the path is opened. The key
/// operation uses SQLCipher's reviewed raw 32-byte key syntax so SafeEvidence does not
/// introduce an additional passphrase KDF. The temporary Rust SQL buffer is
/// zeroized after the provider call; provider/runtime/compiler copies remain
/// within the existing process-memory residual-risk boundary. The connection is
/// not returned unless encryption is positively active, the exact reviewed
/// SQLCipher/SQLite/OpenSSL identities are proven, the selected target compile
/// posture is present, and `temp_store` is positively forced to memory.
pub fn open_sqlcipher_database<P: AsRef<Path>>(
    path: P,
    lease: KeyedHandleLease,
    context: KeyDerivationContext,
    vrk: &OwnedKeyMaterial,
) -> Result<SqlCipherDatabaseHandle, SqlCipherOpenError> {
    let connection = open_reviewed_connection(path.as_ref(), &lease, context, vrk)?;
    Ok(SqlCipherDatabaseHandle {
        inner: LeaseBoundDatabaseHandle::new(
            lease,
            SqlCipherDatabase {
                _connection: connection,
            },
        ),
    })
}

fn open_reviewed_connection(
    path: &Path,
    lease: &KeyedHandleLease,
    context: KeyDerivationContext,
    vrk: &OwnedKeyMaterial,
) -> Result<Connection, SqlCipherOpenError> {
    if context.purpose() != KeyPurpose::StructuredStore {
        return Err(SqlCipherOpenError::PurposeMismatch);
    }
    let identity = lease.identity();
    if context.vault_id() != identity.vault_id()
        || context.key_generation() != identity.key_generation()
    {
        return Err(SqlCipherOpenError::IdentityMismatch);
    }

    let _permit = lease.authorize()?;
    let connection = Connection::open_with_flags(path, provider_open_flags())
        .map_err(|_| SqlCipherOpenError::Open)?;
    let structured_key = context.derive_purpose_key(vrk);
    apply_raw_key(&connection, &structured_key)?;
    verify_runtime_identity(&connection)?;
    verify_encryption_active(&connection)?;
    enforce_b303_provider_and_temp_posture(&connection)?;
    // SafeEvidence addition: without this, INSERT OR REPLACE skips delete triggers.
    connection
        .execute_batch("PRAGMA recursive_triggers = ON;")
        .map_err(|_| SqlCipherOpenError::Open)?;
    Ok(connection)
}

const BACKUP_SNAPSHOT_HASH_BUFFER_BYTES: usize = 1024 * 1024;

fn backup_snapshot_file_identity(path: &Path) -> Result<(u64, [u8; 32]), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let mut buffer = vec![0_u8; BACKUP_SNAPSHOT_HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| ())?)
            .ok_or(())?;
        hasher.update(&buffer[..read]);
    }
    Ok((total, hasher.finalize().into()))
}

fn backup_snapshot_wal_is_empty(source: &Path) -> Result<bool, ()> {
    let wal = PathBuf::from(format!("{}-wal", source.display()));
    match fs::symlink_metadata(wal) {
        Ok(metadata) => Ok(metadata.file_type().is_file() && metadata.len() == 0),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(_) => Err(()),
    }
}

fn resolve_backup_snapshot_paths<E>(
    source: &Path,
    target: &Path,
) -> Result<(PathBuf, PathBuf), SqlCipherBackupSnapshotError<E>> {
    if !fs::symlink_metadata(source)
        .map_err(|_| SqlCipherBackupSnapshotError::Path)?
        .file_type()
        .is_file()
    {
        return Err(SqlCipherBackupSnapshotError::Path);
    }
    let source = fs::canonicalize(source).map_err(|_| SqlCipherBackupSnapshotError::Path)?;
    let parent = fs::canonicalize(target.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|_| SqlCipherBackupSnapshotError::Path)?;
    let name = target
        .file_name()
        .ok_or(SqlCipherBackupSnapshotError::Path)?;
    let target = parent.join(name);
    if target.exists() {
        let existing = fs::canonicalize(&target).map_err(|_| SqlCipherBackupSnapshotError::Path)?;
        if existing == source {
            return Err(SqlCipherBackupSnapshotError::SamePath);
        }
        return Err(SqlCipherBackupSnapshotError::TargetAlreadyExists);
    }
    if target == source {
        return Err(SqlCipherBackupSnapshotError::SamePath);
    }
    Ok((source, target))
}

/// Creates one stable separately named SQLCipher snapshot while a caller-owned write exclusion is
/// held for the complete operation.
///
/// The source is opened through the reviewed B301-B303 path, integrity-checked, checkpointed with
/// `wal_checkpoint(TRUNCATE)` under the B105 lease gate, and integrity-checked again. The source
/// handle is then closed, the WAL must be absent or zero bytes, and the exact main-database bytes
/// are hashed, copied, fsynced, and re-hashed. The source identity is rechecked after the copy so a
/// broken quiescence implementation cannot silently authorize a mixed-state snapshot. Finally the
/// staged copy must match the source byte-for-byte and pass the canonical SQLCipher integrity path.
///
/// This primitive does not publish a backup, advance freshness, or release the caller's quiescence
/// boundary. Failed targets are best-effort removed without making a physical secure-erasure claim.
pub fn snapshot_quiesced_sqlcipher_database<G, P, Q>(
    guard: &mut G,
    source: P,
    target: Q,
    lease: KeyedHandleLease,
    context: KeyDerivationContext,
    vrk: &OwnedKeyMaterial,
) -> Result<SqlCipherBackupSnapshot, SqlCipherBackupSnapshotError<G::Error>>
where
    G: BackupSnapshotQuiescenceGuard,
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    guard
        .assert_normal_writes_quiesced()
        .map_err(SqlCipherBackupSnapshotError::Quiescence)?;
    let (source, target) = resolve_backup_snapshot_paths(source.as_ref(), target.as_ref())?;
    let mut target_created = false;
    let result = (|| {
        let mut source_handle = open_sqlcipher_database(&source, lease.clone(), context, vrk)
            .map_err(SqlCipherBackupSnapshotError::SourceOpen)?;
        source_handle
            .verify_integrity()
            .map_err(SqlCipherBackupSnapshotError::SourceIntegrity)?;
        let source_precheckpoint_identity = backup_snapshot_file_identity(&source)
            .map_err(|_| SqlCipherBackupSnapshotError::SourceRead)?;
        guard
            .assert_normal_writes_quiesced()
            .map_err(SqlCipherBackupSnapshotError::Quiescence)?;
        source_handle
            .checkpoint_truncate_backup_wal()
            .map_err(SqlCipherBackupSnapshotError::Checkpoint)?;
        source_handle
            .verify_integrity()
            .map_err(SqlCipherBackupSnapshotError::SourceIntegrity)?;
        guard
            .assert_normal_writes_quiesced()
            .map_err(SqlCipherBackupSnapshotError::Quiescence)?;
        drop(source_handle);
        if !backup_snapshot_wal_is_empty(&source)
            .map_err(|_| SqlCipherBackupSnapshotError::SourceRead)?
        {
            return Err(SqlCipherBackupSnapshotError::WalNotTruncated);
        }
        let source_identity = backup_snapshot_file_identity(&source)
            .map_err(|_| SqlCipherBackupSnapshotError::SourceRead)?;
        guard
            .assert_normal_writes_quiesced()
            .map_err(SqlCipherBackupSnapshotError::Quiescence)?;
        let mut source_file =
            File::open(&source).map_err(|_| SqlCipherBackupSnapshotError::Copy)?;
        let mut target_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|_| SqlCipherBackupSnapshotError::Copy)?;
        target_created = true;
        let copied = io::copy(&mut source_file, &mut target_file)
            .map_err(|_| SqlCipherBackupSnapshotError::Copy)?;
        if copied != source_identity.0 {
            return Err(SqlCipherBackupSnapshotError::TargetIdentityMismatch);
        }
        target_file
            .sync_all()
            .map_err(|_| SqlCipherBackupSnapshotError::Durability)?;
        drop(target_file);
        guard
            .assert_normal_writes_quiesced()
            .map_err(SqlCipherBackupSnapshotError::Quiescence)?;
        let source_after = backup_snapshot_file_identity(&source)
            .map_err(|_| SqlCipherBackupSnapshotError::SourceRead)?;
        if source_after != source_identity {
            return Err(SqlCipherBackupSnapshotError::SourceChanged);
        }
        let target_identity = backup_snapshot_file_identity(&target)
            .map_err(|_| SqlCipherBackupSnapshotError::TargetIdentityMismatch)?;
        if target_identity != source_identity {
            return Err(SqlCipherBackupSnapshotError::TargetIdentityMismatch);
        }
        let target_handle = open_sqlcipher_database(&target, lease, context, vrk)
            .map_err(SqlCipherBackupSnapshotError::TargetOpen)?;
        target_handle
            .verify_integrity()
            .map_err(SqlCipherBackupSnapshotError::TargetIntegrity)?;
        drop(target_handle);
        let target_after = backup_snapshot_file_identity(&target)
            .map_err(|_| SqlCipherBackupSnapshotError::TargetIdentityMismatch)?;
        if target_after != source_identity {
            return Err(SqlCipherBackupSnapshotError::TargetIdentityMismatch);
        }
        guard
            .assert_normal_writes_quiesced()
            .map_err(SqlCipherBackupSnapshotError::Quiescence)?;
        let final_source_identity = backup_snapshot_file_identity(&source)
            .map_err(|_| SqlCipherBackupSnapshotError::SourceRead)?;
        if final_source_identity != source_identity {
            return Err(SqlCipherBackupSnapshotError::SourceChanged);
        }
        if !backup_snapshot_wal_is_empty(&source)
            .map_err(|_| SqlCipherBackupSnapshotError::SourceRead)?
        {
            return Err(SqlCipherBackupSnapshotError::WalNotTruncated);
        }
        Ok(SqlCipherBackupSnapshot {
            path: target.clone(),
            source_precheckpoint_byte_length: source_precheckpoint_identity.0,
            source_precheckpoint_sha256: source_precheckpoint_identity.1,
            byte_length: source_identity.0,
            sha256: source_identity.1,
        })
    })();
    if result.is_err() && target_created {
        remove_database_files_best_effort(&target);
    }
    result
}

/// One source or target endpoint for B503 SQLCipher generation staging.
///
/// The endpoint owns only public path/context metadata and a lease token while
/// borrowing opaque VRK material. Secret bytes remain inaccessible to callers.
pub struct SqlCipherGenerationEndpoint<'a> {
    path: PathBuf,
    lease: KeyedHandleLease,
    context: KeyDerivationContext,
    vrk: &'a OwnedKeyMaterial,
}

impl<'a> SqlCipherGenerationEndpoint<'a> {
    /// Binds one database path to its exact lease, derivation context, and VRK.
    #[must_use]
    pub fn new<P: AsRef<Path>>(
        path: P,
        lease: KeyedHandleLease,
        context: KeyDerivationContext,
        vrk: &'a OwnedKeyMaterial,
    ) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            lease,
            context,
            vrk,
        }
    }
}

/// Stages a separately named SQLCipher database under a newer VRK generation.
///
/// The source is opened and integrity-verified through the reviewed production
/// provider path, exported into a distinct target using SQLCipher's attached-
/// database export primitive, flushed, and reopened under the target generation.
/// Before success, this function also proves that the source key cannot produce a
/// healthy target and the target key cannot produce a healthy source. Neither raw
/// VRK bytes nor a raw `rusqlite::Connection` cross this module boundary.
///
/// The source database is never rekeyed, renamed, deleted, or otherwise mutated by
/// this operation. Publication, anchoring, and source retirement remain owned by
/// the B503 rotation coordinator.
pub fn stage_sqlcipher_generation(
    source: SqlCipherGenerationEndpoint<'_>,
    target: SqlCipherGenerationEndpoint<'_>,
) -> Result<SqlCipherDatabaseHandle, SqlCipherGenerationMigrationError> {
    validate_generation_migration_contexts(source.context, target.context)?;
    let (source_path, target_path) =
        resolve_generation_migration_paths(&source.path, &target.path)?;

    let source_connection =
        open_reviewed_connection(&source_path, &source.lease, source.context, source.vrk)
            .map_err(SqlCipherGenerationMigrationError::SourceOpen)?;
    verify_b304_integrity(&source_connection)
        .map_err(SqlCipherGenerationMigrationError::SourceIntegrity)?;

    export_to_target_generation(&source_connection, &target_path, target.context, target.vrk)?;
    drop(source_connection);

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| SqlCipherGenerationMigrationError::Durability)?;

    let target_handle =
        open_sqlcipher_database(&target_path, target.lease, target.context, target.vrk)
            .map_err(SqlCipherGenerationMigrationError::TargetOpen)?;
    target_handle
        .verify_integrity()
        .map_err(SqlCipherGenerationMigrationError::TargetIntegrity)?;

    if key_opens_healthy_database(&target_path, source.context, source.vrk)
        || key_opens_healthy_database(&source_path, target.context, target.vrk)
    {
        return Err(SqlCipherGenerationMigrationError::KeyIsolation);
    }
    Ok(target_handle)
}

fn validate_generation_migration_contexts(
    source: KeyDerivationContext,
    target: KeyDerivationContext,
) -> Result<(), SqlCipherGenerationMigrationError> {
    if source.purpose() != KeyPurpose::StructuredStore
        || target.purpose() != KeyPurpose::StructuredStore
    {
        return Err(SqlCipherGenerationMigrationError::PurposeMismatch);
    }
    if source.vault_id() != target.vault_id() {
        return Err(SqlCipherGenerationMigrationError::VaultMismatch);
    }
    if target.key_generation() <= source.key_generation() {
        return Err(SqlCipherGenerationMigrationError::GenerationOrder);
    }
    Ok(())
}

fn resolve_generation_migration_paths(
    source: &Path,
    target: &Path,
) -> Result<(PathBuf, PathBuf), SqlCipherGenerationMigrationError> {
    let source = fs::canonicalize(source).map_err(|_| SqlCipherGenerationMigrationError::Path)?;
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| SqlCipherGenerationMigrationError::Path)?;
    let name = target
        .file_name()
        .ok_or(SqlCipherGenerationMigrationError::Path)?;
    let resolved_target = parent.join(name);

    if target.exists() {
        let existing =
            fs::canonicalize(target).map_err(|_| SqlCipherGenerationMigrationError::Path)?;
        if existing == source {
            return Err(SqlCipherGenerationMigrationError::SamePath);
        }
        return Err(SqlCipherGenerationMigrationError::TargetAlreadyExists);
    }
    if resolved_target == source {
        return Err(SqlCipherGenerationMigrationError::SamePath);
    }
    Ok((source, resolved_target))
}

fn export_to_target_generation(
    source: &Connection,
    target_path: &Path,
    target_context: KeyDerivationContext,
    target_vrk: &OwnedKeyMaterial,
) -> Result<(), SqlCipherGenerationMigrationError> {
    let target_path = target_path
        .to_str()
        .ok_or(SqlCipherGenerationMigrationError::Path)?;
    let target_key = target_context.derive_purpose_key(target_vrk);
    let mut attach_sql = target_key.with_bytes(|bytes| {
        let mut sql = String::from("ATTACH DATABASE ?1 AS safeevidence_rotation_target KEY ");
        sql.push_str(&raw_key_literal(bytes));
        sql.push(';');
        sql
    });
    let attached = source.execute(&attach_sql, [target_path]).is_ok();
    attach_sql.zeroize();
    if !attached {
        return Err(SqlCipherGenerationMigrationError::Export);
    }

    let exported = source
        .query_row(
            "SELECT sqlcipher_export('safeevidence_rotation_target');",
            [],
            |_| Ok(()),
        )
        .is_ok();
    let detached = source
        .execute_batch("DETACH DATABASE safeevidence_rotation_target;")
        .is_ok();
    if !exported || !detached {
        remove_database_files_best_effort(Path::new(target_path));
        return Err(SqlCipherGenerationMigrationError::Export);
    }
    Ok(())
}

fn key_opens_healthy_database(
    path: &Path,
    context: KeyDerivationContext,
    vrk: &OwnedKeyMaterial,
) -> bool {
    let Ok(connection) = Connection::open_with_flags(path, read_only_provider_open_flags()) else {
        return false;
    };
    let structured_key = context.derive_purpose_key(vrk);
    if apply_raw_key(&connection, &structured_key).is_err() {
        return false;
    }
    verify_b304_integrity(&connection).is_ok()
}

fn remove_database_files_best_effort(path: &Path) {
    let _ = fs::remove_file(path);
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        let _ = fs::remove_file(sidecar);
    }
}

fn raw_key_literal(key: &[u8; KEY_MATERIAL_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut literal = String::with_capacity(69);
    literal.push_str("\"x'");
    for byte in key {
        literal.push(char::from(HEX[usize::from(byte >> 4)]));
        literal.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    literal.push_str("'\"");
    literal
}

fn provider_open_flags() -> OpenFlags {
    // Deliberately omit SQLITE_OPEN_URI so an ordinary SafeEvidence path cannot acquire
    // URI query semantics. NO_MUTEX matches rusqlite's compile-time thread-safety
    // model while keeping the reviewed provider behind one lease-bound handle.
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

fn read_only_provider_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

fn apply_raw_key(
    connection: &Connection,
    structured_key: &OwnedKeyMaterial,
) -> Result<(), SqlCipherOpenError> {
    let mut key_sql = structured_key.with_bytes(raw_key_pragma);
    let result = connection.execute_batch(&key_sql);
    key_sql.zeroize();
    result.map_err(|_| SqlCipherOpenError::Key)
}

fn verify_runtime_identity(connection: &Connection) -> Result<(), SqlCipherOpenError> {
    let sqlcipher_version = connection
        .query_row("PRAGMA cipher_version;", [], |row| row.get::<_, String>(0))
        .map_err(|_| SqlCipherOpenError::ProviderVersion)?;
    require_sqlcipher_runtime_version(&sqlcipher_version)?;

    let sqlite_version = connection
        .query_row("SELECT sqlite_version();", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| SqlCipherOpenError::SqliteVersion)?;
    require_sqlite_runtime_version(&sqlite_version)
}

fn require_sqlcipher_runtime_version(version: &str) -> Result<(), SqlCipherOpenError> {
    if version == EXPECTED_SQLCIPHER_RUNTIME_VERSION {
        Ok(())
    } else {
        Err(SqlCipherOpenError::ProviderVersion)
    }
}

fn require_sqlite_runtime_version(version: &str) -> Result<(), SqlCipherOpenError> {
    if version == EXPECTED_SQLITE_RUNTIME_VERSION {
        Ok(())
    } else {
        Err(SqlCipherOpenError::SqliteVersion)
    }
}

fn verify_encryption_active(connection: &Connection) -> Result<(), SqlCipherOpenError> {
    let status = connection.query_row("PRAGMA cipher_status;", [], |row| row.get::<_, String>(0));
    require_encryption_active(status)
}

fn require_encryption_active(status: rusqlite::Result<String>) -> Result<(), SqlCipherOpenError> {
    match status {
        Ok(value) if value == "1" => Ok(()),
        Ok(_) => Err(SqlCipherOpenError::EncryptionInactive),
        Err(_) => Err(SqlCipherOpenError::EncryptionStatus),
    }
}

fn enforce_b303_provider_and_temp_posture(
    connection: &Connection,
) -> Result<(), SqlCipherOpenError> {
    verify_crypto_provider_identity(connection)?;
    verify_temp_store_compile_posture(connection)?;
    force_memory_temp_store(connection)
}

fn verify_crypto_provider_identity(connection: &Connection) -> Result<(), SqlCipherOpenError> {
    let provider = connection
        .query_row("PRAGMA cipher_provider;", [], |row| row.get::<_, String>(0))
        .map_err(|_| SqlCipherOpenError::CryptoProvider)?;
    require_crypto_provider(&provider)?;

    let provider_version = connection
        .query_row("PRAGMA cipher_provider_version;", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| SqlCipherOpenError::CryptoProviderVersion)?;
    require_crypto_provider_version(&provider_version)
}

fn require_crypto_provider(provider: &str) -> Result<(), SqlCipherOpenError> {
    if provider == EXPECTED_SQLCIPHER_CRYPTO_PROVIDER {
        Ok(())
    } else {
        Err(SqlCipherOpenError::CryptoProvider)
    }
}

fn require_crypto_provider_version(version: &str) -> Result<(), SqlCipherOpenError> {
    if version == EXPECTED_OPENSSL_RUNTIME_VERSION {
        Ok(())
    } else {
        Err(SqlCipherOpenError::CryptoProviderVersion)
    }
}

fn verify_temp_store_compile_posture(connection: &Connection) -> Result<(), SqlCipherOpenError> {
    let enabled = connection
        .query_row(
            "SELECT sqlite_compileoption_used(?1);",
            [EXPECTED_TEMP_STORE_COMPILE_OPTION],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| SqlCipherOpenError::CompilePosture)?;
    if enabled != 1 {
        return Err(SqlCipherOpenError::CompilePosture);
    }
    Ok(())
}

fn force_memory_temp_store(connection: &Connection) -> Result<(), SqlCipherOpenError> {
    connection
        .execute_batch("PRAGMA temp_store = MEMORY;")
        .map_err(|_| SqlCipherOpenError::TemporaryStorage)?;
    let observed = connection
        .query_row("PRAGMA temp_store;", [], |row| row.get::<_, i64>(0))
        .map_err(|_| SqlCipherOpenError::TemporaryStorage)?;
    if observed != TEMP_STORE_MEMORY {
        return Err(SqlCipherOpenError::TemporaryStorage);
    }
    Ok(())
}

fn verify_b304_integrity(connection: &Connection) -> Result<(), SqlCipherIntegrityError> {
    verify_cipher_integrity(connection)?;
    verify_sqlite_integrity(connection)
}

fn verify_cipher_integrity(connection: &Connection) -> Result<(), SqlCipherIntegrityError> {
    let mut statement = connection
        .prepare("PRAGMA cipher_integrity_check;")
        .map_err(|_| SqlCipherIntegrityError::CipherIntegrityQuery)?;
    let mut rows = statement
        .query([])
        .map_err(|_| SqlCipherIntegrityError::CipherIntegrityQuery)?;

    match rows
        .next()
        .map_err(|_| SqlCipherIntegrityError::CipherIntegrityQuery)?
    {
        None => Ok(()),
        Some(_) => Err(SqlCipherIntegrityError::CipherIntegrityFailed),
    }
}

fn verify_sqlite_integrity(connection: &Connection) -> Result<(), SqlCipherIntegrityError> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check;")
        .map_err(|_| SqlCipherIntegrityError::SqliteIntegrityQuery)?;
    let mut rows = statement
        .query([])
        .map_err(|_| SqlCipherIntegrityError::SqliteIntegrityQuery)?;

    let first = rows
        .next()
        .map_err(|_| SqlCipherIntegrityError::SqliteIntegrityQuery)?
        .ok_or(SqlCipherIntegrityError::SqliteIntegrityFailed)?;
    let value = first
        .get::<_, String>(0)
        .map_err(|_| SqlCipherIntegrityError::SqliteIntegrityQuery)?;
    if value != "ok" {
        return Err(SqlCipherIntegrityError::SqliteIntegrityFailed);
    }

    if rows
        .next()
        .map_err(|_| SqlCipherIntegrityError::SqliteIntegrityQuery)?
        .is_some()
    {
        return Err(SqlCipherIntegrityError::SqliteIntegrityFailed);
    }

    Ok(())
}

fn raw_key_pragma(key: &[u8; KEY_MATERIAL_BYTES]) -> String {
    let literal = raw_key_literal(key);
    let mut sql = String::with_capacity(12 + literal.len());
    sql.push_str("PRAGMA key = ");
    sql.push_str(&literal);
    sql.push(';');
    sql
}

#[cfg(test)]
mod tests {
    use super::{
        BackupSnapshotQuiescenceGuard, EXPECTED_OPENSSL_RUNTIME_VERSION,
        EXPECTED_SQLCIPHER_CRYPTO_PROVIDER, EXPECTED_SQLCIPHER_RUNTIME_VERSION,
        EXPECTED_SQLITE_RUNTIME_VERSION, SqlCipherBackupSnapshotError, SqlCipherGenerationEndpoint,
        SqlCipherIntegrityError, SqlCipherOpenError, apply_raw_key,
        enforce_b303_provider_and_temp_posture, key_opens_healthy_database,
        open_reviewed_connection, open_sqlcipher_database, provider_open_flags, raw_key_pragma,
        require_crypto_provider, require_crypto_provider_version, require_encryption_active,
        require_sqlcipher_runtime_version, require_sqlite_runtime_version,
        snapshot_quiesced_sqlcipher_database, stage_sqlcipher_generation, verify_b304_integrity,
        verify_cipher_integrity, verify_encryption_active, verify_runtime_identity,
        verify_sqlite_integrity,
    };
    use crate::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
    use crate::vault_keys::{
        KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
    };
    use crate::vault_lease::{KeyedHandleError, VaultLease};
    use rusqlite::{Connection, Error as RusqliteError, OpenFlags};
    use std::fs;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn identity() -> VaultLeaseIdentity {
        VaultLeaseIdentity::new(
            VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
            KeyGeneration::new(7).expect("test generation is non-zero"),
        )
    }

    fn context(purpose: KeyPurpose) -> KeyDerivationContext {
        let identity = identity();
        KeyDerivationContext::new(identity.vault_id(), identity.key_generation(), purpose)
    }

    fn vrk() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES])
    }

    fn unused_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "safeevidence-b303-{label}-{}-{sequence}.db",
            std::process::id()
        ))
    }

    fn remove_database_files(path: &Path) {
        let _ = std::fs::remove_file(path);
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
            let _ = std::fs::remove_file(sidecar);
        }
    }

    fn keyed_test_connection(path: &Path) -> Connection {
        remove_database_files(path);
        let connection = Connection::open_with_flags(path, provider_open_flags())
            .expect("reviewed SQLCipher provider must open the test database");
        let structured_key = context(KeyPurpose::StructuredStore).derive_purpose_key(&vrk());
        apply_raw_key(&connection, &structured_key).expect("test raw key operation must succeed");
        verify_runtime_identity(&connection).expect("reviewed runtime identities must match");
        verify_encryption_active(&connection)
            .expect("test connection must report encryption active");
        enforce_b303_provider_and_temp_posture(&connection)
            .expect("reviewed B303 provider/temp posture must be enforced");
        connection
    }

    fn store_handle(path: &Path, lease: &VaultLease) -> super::SqlCipherDatabaseHandle {
        remove_database_files(path);
        open_sqlcipher_database(
            path,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("test database opens")
    }

    #[test]
    fn every_opened_connection_fires_delete_triggers_on_replacement() {
        let path = unused_path("recursive");
        let lease = VaultLease::new(identity());
        let mut handle = store_handle(&path, &lease);
        handle
            .install_schema(&[
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
                "INSERT INTO t VALUES (1, 'a')",
                "CREATE TRIGGER t_keep BEFORE DELETE ON t
                     BEGIN SELECT RAISE(ABORT, 'kept'); END",
            ])
            .expect("schema");
        let replaced = handle
            .immediate_transaction(|tx| tx.execute("INSERT OR REPLACE INTO t VALUES (1, 'b')", []));
        assert!(matches!(
            replaced,
            Err(super::SqlCipherTransactionError::Operation(
                super::GuardedSqlError::Provider(_)
            ))
        ));
        drop(handle);
        remove_database_files(&path);
    }

    #[test]
    fn install_schema_refused_statements_have_no_effect() {
        let path = unused_path("schema-guard");
        let lease = VaultLease::new(identity());
        let mut handle = store_handle(&path, &lease);
        handle.configure_durable_store().expect("settings");
        let refused: [&'static [&'static str]; 8] = [
            &["PRAGMA synchronous = OFF"],
            &["PRAGMA recursive_triggers = OFF"],
            &["PRAGMA journal_mode = DELETE"],
            &["PRAGMA writable_schema = ON"],
            &[
                "PRAGMA rekey = \"x'0101010101010101010101010101010101010101010101010101010101010101'\"",
            ],
            &["ATTACH DATABASE 'x' AS y"],
            &["COMMIT"],
            &["CREATE TABLE t (id INTEGER)", "PRAGMA query_only = ON"],
        ];
        for statements in refused {
            assert!(handle.install_schema(statements).is_err(), "{statements:?}");
        }
        assert!(matches!(handle.durable_settings_hold(), Ok(true)));
        handle
            .install_schema(&["CREATE TABLE w (id INTEGER)"])
            .expect("table for later checks");
        assert!(
            handle
                .immediate_transaction(|tx| tx.execute("INSERT INTO t VALUES (1)", []))
                .is_err(),
            "the refused batch ran nothing, not even its allowed first statement"
        );
        assert!(
            handle
                .install_schema(&["CREATE TABLE u (id INTEGER); PRAGMA query_only = ON"])
                .is_err(),
            "a second statement in one string is refused"
        );
        assert!(
            handle
                .install_schema(&[
                    "CREATE TRIGGER v AFTER INSERT ON w BEGIN SELECT 1; END; PRAGMA query_only = ON"
                ])
                .is_err(),
            "a statement after a trigger body is refused"
        );
        for sql in [
            "DELETE FROM w; PRAGMA query_only = ON",
            "SELECT 1; PRAGMA query_only = ON",
        ] {
            assert!(matches!(
                handle.immediate_transaction(|tx| tx.execute(sql, [])),
                Err(super::SqlCipherTransactionError::Operation(
                    super::GuardedSqlError::StatementNotAllowed
                ))
            ));
            assert!(matches!(
                handle.immediate_transaction(|tx| tx.query(sql, [], |row| row.get::<_, i64>(0))),
                Err(super::SqlCipherTransactionError::Operation(
                    super::GuardedSqlError::StatementNotAllowed
                ))
            ));
        }
        handle
            .immediate_transaction(|tx| {
                tx.query("SELECT count(*) FROM sqlite_master", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .expect("query_only stayed off and the key still reads");
        handle
            .install_schema(&["CREATE TABLE x (id INTEGER)"])
            .expect("writes still work");
        drop(handle);
        let reopened = open_sqlcipher_database(
            &path,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        );
        assert!(
            reopened.is_ok(),
            "the refused rekey left the original key working"
        );
        drop(reopened);
        remove_database_files(&path);
    }

    #[test]
    fn a_failing_commit_reports_an_unknown_outcome() {
        let path = unused_path("commit-unknown");
        let lease = VaultLease::new(identity());
        let mut handle = store_handle(&path, &lease);
        handle
            .inner
            .write(|backend| {
                backend
                    ._connection
                    .execute_batch("PRAGMA foreign_keys = ON;")
            })
            .expect("foreign keys on");
        handle
            .install_schema(&[
                "CREATE TABLE p (id INTEGER PRIMARY KEY)",
                "CREATE TABLE c (p_id INTEGER REFERENCES p(id) DEFERRABLE INITIALLY DEFERRED)",
            ])
            .expect("schema");
        let result = handle.immediate_transaction(|tx| tx.execute("INSERT INTO c VALUES (9)", []));
        assert!(matches!(
            result,
            Err(super::SqlCipherTransactionError::CommitUnknown(_))
        ));
        drop(handle);
        remove_database_files(&path);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SnapshotGuardError {
        NotQuiesced,
        MutationFailed,
    }

    struct SnapshotGuard {
        checks: usize,
        fail_at: Option<usize>,
        mutate_at: Option<(usize, PathBuf)>,
    }

    impl SnapshotGuard {
        fn stable() -> Self {
            Self {
                checks: 0,
                fail_at: None,
                mutate_at: None,
            }
        }
    }

    impl BackupSnapshotQuiescenceGuard for SnapshotGuard {
        type Error = SnapshotGuardError;

        fn assert_normal_writes_quiesced(&mut self) -> Result<(), Self::Error> {
            self.checks += 1;
            if let Some((ordinal, path)) = &self.mutate_at
                && self.checks == *ordinal
            {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .and_then(|mut file| file.write_all(&[0xA5]))
                    .map_err(|_| SnapshotGuardError::MutationFailed)?;
            }
            if self.fail_at == Some(self.checks) {
                return Err(SnapshotGuardError::NotQuiesced);
            }
            Ok(())
        }
    }

    #[test]
    fn b505m_quiesced_wal_snapshot_is_exact_and_integrity_verified() {
        let source = unused_path("b505m-source");
        let target = unused_path("b505m-target");
        let connection = keyed_test_connection(&source);
        let mode = connection
            .query_row("PRAGMA journal_mode = WAL;", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("WAL mode query succeeds");
        assert_eq!(mode, "wal");
        connection
            .execute_batch(
                "PRAGMA wal_autocheckpoint = 0; CREATE TABLE backup_snapshot_probe (value INTEGER NOT NULL); BEGIN IMMEDIATE; INSERT INTO backup_snapshot_probe VALUES (41); COMMIT;",
            )
            .expect("committed WAL state exists");
        let wal = PathBuf::from(format!("{}-wal", source.display()));
        assert!(fs::metadata(&wal).expect("WAL exists").len() > 0);

        let lease = VaultLease::new(identity());
        let mut guard = SnapshotGuard::stable();
        let snapshot = snapshot_quiesced_sqlcipher_database(
            &mut guard,
            &source,
            &target,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("quiesced SQLCipher snapshot succeeds");
        assert_eq!(
            snapshot.path(),
            fs::canonicalize(&target).unwrap().as_path()
        );
        assert_eq!(snapshot.byte_length(), fs::metadata(&target).unwrap().len());
        assert_ne!(
            (
                snapshot.source_precheckpoint_byte_length(),
                snapshot.source_precheckpoint_sha256(),
            ),
            (snapshot.byte_length(), snapshot.sha256()),
            "committed WAL pages must change the stable main-database identity after checkpoint",
        );
        assert!(guard.checks >= 5);
        assert!(fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) == 0);

        let token = lease.keyed_handle_lease();
        let copied = open_reviewed_connection(
            &target,
            &token,
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("snapshot reopens through reviewed provider");
        let count = copied
            .query_row("SELECT COUNT(*) FROM backup_snapshot_probe;", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("snapshot contains committed WAL row");
        assert_eq!(count, 1);
        drop(copied);
        drop(connection);
        remove_database_files(&source);
        remove_database_files(&target);
    }

    #[test]
    fn b505m_quiescence_failure_creates_no_target() {
        let target = unused_path("b505m-quiescence-target");
        let mut guard = SnapshotGuard {
            checks: 0,
            fail_at: Some(1),
            mutate_at: None,
        };
        let lease = VaultLease::new(identity());
        let result = snapshot_quiesced_sqlcipher_database(
            &mut guard,
            unused_path("b505m-unused-source"),
            &target,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        );
        assert!(matches!(
            result,
            Err(SqlCipherBackupSnapshotError::Quiescence(_))
        ));
        assert!(!target.exists());
    }

    #[test]
    fn b505m_existing_target_and_revoked_lease_fail_before_acceptance() {
        let source = unused_path("b505m-existing-source");
        let target = unused_path("b505m-existing-target");
        drop(keyed_test_connection(&source));
        fs::write(&target, b"existing target").unwrap();
        let lease = VaultLease::new(identity());
        let mut guard = SnapshotGuard::stable();
        assert!(matches!(
            snapshot_quiesced_sqlcipher_database(
                &mut guard,
                &source,
                &target,
                lease.keyed_handle_lease(),
                context(KeyPurpose::StructuredStore),
                &vrk(),
            ),
            Err(SqlCipherBackupSnapshotError::TargetAlreadyExists)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"existing target");
        fs::remove_file(&target).unwrap();

        assert!(lease.revoke());
        let rejected_target = unused_path("b505m-revoked-target");
        assert!(matches!(
            snapshot_quiesced_sqlcipher_database(
                &mut guard,
                &source,
                &rejected_target,
                lease.keyed_handle_lease(),
                context(KeyPurpose::StructuredStore),
                &vrk(),
            ),
            Err(SqlCipherBackupSnapshotError::SourceOpen(
                SqlCipherOpenError::Access(KeyedHandleError::Revoked)
            ))
        ));
        assert!(!rejected_target.exists());
        remove_database_files(&source);
    }

    #[test]
    fn b505m_source_drift_after_copy_is_rejected_and_candidate_removed() {
        let source = unused_path("b505m-drift-source");
        let target = unused_path("b505m-drift-target");
        {
            let connection = keyed_test_connection(&source);
            connection
                .execute_batch("CREATE TABLE drift_probe (value INTEGER NOT NULL); INSERT INTO drift_probe VALUES (1);")
                .unwrap();
        }
        let lease = VaultLease::new(identity());
        let mut guard = SnapshotGuard {
            checks: 0,
            fail_at: None,
            mutate_at: Some((5, source.clone())),
        };
        assert!(matches!(
            snapshot_quiesced_sqlcipher_database(
                &mut guard,
                &source,
                &target,
                lease.keyed_handle_lease(),
                context(KeyPurpose::StructuredStore),
                &vrk(),
            ),
            Err(SqlCipherBackupSnapshotError::SourceChanged)
        ));
        assert!(!target.exists());
        remove_database_files(&source);
    }

    #[test]
    fn provider_open_flags_do_not_enable_uri_filename_semantics() {
        let flags = provider_open_flags();
        assert!(flags.contains(OpenFlags::SQLITE_OPEN_READ_WRITE));
        assert!(flags.contains(OpenFlags::SQLITE_OPEN_CREATE));
        assert!(flags.contains(OpenFlags::SQLITE_OPEN_NO_MUTEX));
        assert!(!flags.contains(OpenFlags::SQLITE_OPEN_URI));
    }

    #[test]
    fn raw_key_pragma_is_exact_lowercase_sqlcipher_syntax() {
        let mut key = [0_u8; KEY_MATERIAL_BYTES];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("test index fits in u8");
        }

        assert_eq!(
            raw_key_pragma(&key),
            "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\";"
        );
    }

    #[test]
    fn exact_reviewed_sqlcipher_runtime_opens_only_after_b303_posture_proof() {
        let identity = identity();
        let lease = VaultLease::new(identity);
        let handle = open_sqlcipher_database(
            ":memory:",
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("reviewed SQLCipher provider must satisfy B301-B303 proofs");

        assert_eq!(handle.identity(), identity);
        assert_eq!(EXPECTED_SQLCIPHER_RUNTIME_VERSION, "4.14.0 community");
        assert_eq!(EXPECTED_SQLITE_RUNTIME_VERSION, "3.51.3");
        assert_eq!(EXPECTED_SQLCIPHER_CRYPTO_PROVIDER, "openssl");
        assert_eq!(EXPECTED_OPENSSL_RUNTIME_VERSION, "OpenSSL 3.6.3 9 Jun 2026");
    }

    #[test]
    fn exact_unkeyed_sqlcipher_provider_reports_encryption_inactive() {
        let connection = Connection::open_in_memory().expect("test SQLCipher connection must open");

        assert_eq!(
            verify_encryption_active(&connection),
            Err(SqlCipherOpenError::EncryptionInactive)
        );
    }

    #[test]
    fn encryption_status_accepts_only_exact_active_text() {
        assert_eq!(require_encryption_active(Ok("1".to_owned())), Ok(()));
        for inactive in ["0", "2", "01", "true", ""] {
            assert_eq!(
                require_encryption_active(Ok(inactive.to_owned())),
                Err(SqlCipherOpenError::EncryptionInactive)
            );
        }
    }

    #[test]
    fn encryption_status_query_error_fails_closed() {
        assert_eq!(
            require_encryption_active(Err(RusqliteError::InvalidQuery)),
            Err(SqlCipherOpenError::EncryptionStatus)
        );
    }

    #[test]
    fn b303_file_backed_database_qualifies_wal_and_rollback_journal() {
        let path = unused_path("journals");
        let connection = keyed_test_connection(&path);

        connection
            .execute_batch("CREATE TABLE journal_probe (value INTEGER NOT NULL);")
            .expect("journal probe table must be created");

        let wal_mode = connection
            .query_row("PRAGMA journal_mode = WAL;", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("reviewed SQLCipher provider must enter WAL mode");
        assert_eq!(wal_mode, "wal");
        connection
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO journal_probe VALUES (1); COMMIT;")
            .expect("encrypted WAL transaction must commit");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("WAL checkpoint must complete before rollback-journal transition");

        let rollback_mode = connection
            .query_row("PRAGMA journal_mode = DELETE;", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("reviewed SQLCipher provider must enter rollback-journal mode");
        assert_eq!(rollback_mode, "delete");
        connection
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO journal_probe VALUES (2); COMMIT;")
            .expect("encrypted rollback-journal transaction must commit");

        let row_count = connection
            .query_row("SELECT COUNT(*) FROM journal_probe;", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("journal probe row count must be readable");
        assert_eq!(row_count, 2);
        let temp_store = connection
            .query_row("PRAGMA temp_store;", [], |row| row.get::<_, i64>(0))
            .expect("temp-store posture must remain queryable");
        assert_eq!(temp_store, super::TEMP_STORE_MEMORY);

        drop(connection);
        remove_database_files(&path);
    }

    #[test]
    fn b304_file_backed_database_passes_exact_integrity_shapes() {
        let path = unused_path("integrity");
        {
            let connection = keyed_test_connection(&path);
            connection
                .execute_batch(
                    "CREATE TABLE integrity_probe (value INTEGER NOT NULL); INSERT INTO integrity_probe VALUES (1);",
                )
                .expect("integrity probe must create persistent encrypted pages");
        }

        let lease = VaultLease::new(identity());
        let handle = open_sqlcipher_database(
            &path,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("reviewed SQLCipher provider must reopen the integrity fixture");

        assert_eq!(handle.verify_integrity(), Ok(()));

        drop(handle);
        remove_database_files(&path);
    }

    #[test]
    fn b304_in_memory_cipher_integrity_diagnostic_fails_closed() {
        let connection = Connection::open_in_memory().expect("test SQLCipher connection must open");
        let structured_key = context(KeyPurpose::StructuredStore).derive_purpose_key(&vrk());
        apply_raw_key(&connection, &structured_key).expect("test raw key operation must succeed");

        assert_eq!(
            verify_cipher_integrity(&connection),
            Err(SqlCipherIntegrityError::CipherIntegrityFailed)
        );
        assert_eq!(verify_sqlite_integrity(&connection), Ok(()));
    }

    #[test]
    fn b304_revoked_handle_rejects_integrity_before_backend_query() {
        let path = unused_path("integrity-revoked");
        {
            let connection = keyed_test_connection(&path);
            connection
                .execute_batch("CREATE TABLE integrity_probe (value INTEGER NOT NULL);")
                .expect("integrity probe must create persistent encrypted pages");
        }

        let lease = VaultLease::new(identity());
        let handle = open_sqlcipher_database(
            &path,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("reviewed SQLCipher provider must reopen the integrity fixture");
        assert!(lease.revoke());

        assert_eq!(
            handle.verify_integrity(),
            Err(SqlCipherIntegrityError::Access(KeyedHandleError::Revoked))
        );

        drop(handle);
        remove_database_files(&path);
    }

    #[test]
    fn b305_wrong_key_file_fixture_fails_closed() {
        let path = unused_path("wrong-key");
        {
            let connection = keyed_test_connection(&path);
            connection
                .execute_batch(
                    "CREATE TABLE wrong_key_probe (value INTEGER NOT NULL); INSERT INTO wrong_key_probe VALUES (7);",
                )
                .expect("wrong-key fixture must persist encrypted content");
        }

        let wrong_lease = VaultLease::new(identity());
        let wrong_vrk = OwnedKeyMaterial::from_bytes([0x53; KEY_MATERIAL_BYTES]);
        if let Ok(handle) = open_sqlcipher_database(
            &path,
            wrong_lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &wrong_vrk,
        ) {
            assert!(
                handle.verify_integrity().is_err(),
                "wrong key must never produce a healthy integrity result"
            );
        }

        let correct_lease = VaultLease::new(identity());
        let correct_handle = open_sqlcipher_database(
            &path,
            correct_lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect("wrong-key attempt must not rewrite or downgrade the encrypted database");
        assert_eq!(correct_handle.verify_integrity(), Ok(()));

        drop(correct_handle);
        remove_database_files(&path);
    }

    #[test]
    fn b305_corrupted_encrypted_page_fails_closed() {
        let path = unused_path("corruption");
        {
            let connection = keyed_test_connection(&path);
            connection
                .execute_batch(
                    "CREATE TABLE corruption_probe (payload BLOB NOT NULL); INSERT INTO corruption_probe VALUES (zeroblob(16384));",
                )
                .expect("corruption fixture must span multiple encrypted pages");
        }

        let mut bytes =
            std::fs::read(&path).expect("encrypted corruption fixture must be readable");
        assert!(
            bytes.len() > 8192,
            "corruption fixture must contain multiple encrypted pages"
        );
        let offset = bytes.len() / 2;
        bytes[offset] ^= 0x01;
        std::fs::write(&path, bytes).expect("corruption fixture mutation must persist");

        let lease = VaultLease::new(identity());
        if let Ok(handle) = open_sqlcipher_database(
            &path,
            lease.keyed_handle_lease(),
            context(KeyPurpose::StructuredStore),
            &vrk(),
        ) {
            assert!(
                handle.verify_integrity().is_err(),
                "corrupted encrypted page must never produce a healthy integrity result"
            );
        }

        remove_database_files(&path);
    }

    #[test]
    fn b305_unsupported_runtime_versions_fail_closed() {
        assert_eq!(
            require_sqlcipher_runtime_version(EXPECTED_SQLCIPHER_RUNTIME_VERSION),
            Ok(())
        );
        assert_eq!(
            require_sqlcipher_runtime_version("4.14.1 community"),
            Err(SqlCipherOpenError::ProviderVersion)
        );
        assert_eq!(
            require_sqlite_runtime_version(EXPECTED_SQLITE_RUNTIME_VERSION),
            Ok(())
        );
        assert_eq!(
            require_sqlite_runtime_version("3.51.4"),
            Err(SqlCipherOpenError::SqliteVersion)
        );
    }

    #[test]
    fn b305_unsupported_crypto_provider_or_version_fails_closed() {
        assert_eq!(
            require_crypto_provider(EXPECTED_SQLCIPHER_CRYPTO_PROVIDER),
            Ok(())
        );
        assert_eq!(
            require_crypto_provider("commoncrypto"),
            Err(SqlCipherOpenError::CryptoProvider)
        );
        assert_eq!(
            require_crypto_provider_version(EXPECTED_OPENSSL_RUNTIME_VERSION),
            Ok(())
        );
        assert_eq!(
            require_crypto_provider_version("OpenSSL 3.6.4 1 Sep 2026"),
            Err(SqlCipherOpenError::CryptoProviderVersion)
        );
    }

    #[test]
    fn validation_rejects_non_structured_purpose_before_file_touch() {
        let path = unused_path("purpose");
        let _ = std::fs::remove_file(&path);
        let lease = VaultLease::new(identity());

        let error = open_sqlcipher_database(
            &path,
            lease.keyed_handle_lease(),
            context(KeyPurpose::BoundedBlob),
            &vrk(),
        )
        .expect_err("non-structured purpose must fail closed");

        assert_eq!(error, SqlCipherOpenError::PurposeMismatch);
        assert!(!path.exists());
    }

    #[test]
    fn validation_rejects_identity_mismatch_before_file_touch() {
        let path = unused_path("identity");
        let _ = std::fs::remove_file(&path);
        let lease = VaultLease::new(identity());
        let other_context = KeyDerivationContext::new(
            VaultId::from_bytes([0x42; VAULT_ID_BYTES]),
            identity().key_generation(),
            KeyPurpose::StructuredStore,
        );

        let error =
            open_sqlcipher_database(&path, lease.keyed_handle_lease(), other_context, &vrk())
                .expect_err("identity mismatch must fail closed");

        assert_eq!(error, SqlCipherOpenError::IdentityMismatch);
        assert!(!path.exists());
    }

    #[test]
    fn revoked_lease_is_rejected_before_file_touch() {
        let path = unused_path("revoked");
        let _ = std::fs::remove_file(&path);
        let lease = VaultLease::new(identity());
        let handle_lease = lease.keyed_handle_lease();
        assert!(lease.revoke());

        let error = open_sqlcipher_database(
            &path,
            handle_lease,
            context(KeyPurpose::StructuredStore),
            &vrk(),
        )
        .expect_err("revoked lease must fail before provider open");

        assert_eq!(error, SqlCipherOpenError::Access(KeyedHandleError::Revoked));
        assert!(!path.exists());
    }

    #[test]
    fn b503_cross_generation_export_preserves_source_and_proves_key_isolation() {
        let source_path = unused_path("b503-source");
        let target_path = unused_path("b503-target");
        remove_database_files(&source_path);
        remove_database_files(&target_path);

        let vault_id = VaultId::from_bytes([0x91; VAULT_ID_BYTES]);
        let source_generation = KeyGeneration::new(7).expect("source generation");
        let target_generation = KeyGeneration::new(8).expect("target generation");
        let source_identity = VaultLeaseIdentity::new(vault_id, source_generation);
        let target_identity = VaultLeaseIdentity::new(vault_id, target_generation);
        let source_context =
            KeyDerivationContext::new(vault_id, source_generation, KeyPurpose::StructuredStore);
        let target_context =
            KeyDerivationContext::new(vault_id, target_generation, KeyPurpose::StructuredStore);
        let source_vrk = OwnedKeyMaterial::from_bytes([0x92; KEY_MATERIAL_BYTES]);
        let target_vrk = OwnedKeyMaterial::from_bytes([0x93; KEY_MATERIAL_BYTES]);
        let marker = "SAFEEVIDENCE_B503_CROSS_GENERATION_SQLCIPHER_7F21";

        {
            let lease = VaultLease::new(source_identity);
            let connection = open_reviewed_connection(
                &source_path,
                &lease.keyed_handle_lease(),
                source_context,
                &source_vrk,
            )
            .expect("source provider must open");
            connection
                .execute_batch(
                    "CREATE TABLE rotation_probe (value TEXT NOT NULL); PRAGMA journal_mode = DELETE;",
                )
                .expect("source schema must persist");
            connection
                .execute("INSERT INTO rotation_probe (value) VALUES (?1);", [marker])
                .expect("source semantic row must persist");
            verify_b304_integrity(&connection).expect("source must be healthy before rotation");
        }

        let source_bytes_before = fs::read(&source_path).expect("source bytes must be readable");
        let source_lease = VaultLease::new(source_identity);
        let target_lease = VaultLease::new(target_identity);
        let source_endpoint = SqlCipherGenerationEndpoint::new(
            &source_path,
            source_lease.keyed_handle_lease(),
            source_context,
            &source_vrk,
        );
        let target_endpoint = SqlCipherGenerationEndpoint::new(
            &target_path,
            target_lease.keyed_handle_lease(),
            target_context,
            &target_vrk,
        );
        let target_handle = stage_sqlcipher_generation(source_endpoint, target_endpoint)
            .expect("cross-generation SQLCipher staging must succeed");

        assert_eq!(target_handle.identity(), target_identity);
        assert_eq!(target_handle.verify_integrity(), Ok(()));
        assert_eq!(
            fs::read(&source_path).expect("source remains readable"),
            source_bytes_before,
            "B503 staging must not mutate the verified source database",
        );
        let target_bytes = fs::read(&target_path).expect("target bytes must be readable");
        assert_ne!(
            target_bytes, source_bytes_before,
            "target generation must contain newly encrypted SQLCipher bytes",
        );
        assert!(!key_opens_healthy_database(
            &target_path,
            source_context,
            &source_vrk,
        ));
        assert!(!key_opens_healthy_database(
            &source_path,
            target_context,
            &target_vrk,
        ));

        let verification_lease = VaultLease::new(target_identity);
        let target_connection = open_reviewed_connection(
            &target_path,
            &verification_lease.keyed_handle_lease(),
            target_context,
            &target_vrk,
        )
        .expect("target must reopen only through target generation");
        let observed = target_connection
            .query_row("SELECT value FROM rotation_probe;", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("target semantic row must survive export");
        assert_eq!(observed, marker);

        drop(target_connection);
        drop(target_handle);
        remove_database_files(&source_path);
        remove_database_files(&target_path);
    }
}

#[cfg(test)]
mod durable_settings_tests {
    use super::settings_are_durable;

    #[test]
    fn every_setting_must_hold() {
        assert!(settings_are_durable("wal", 2, 1));
        assert!(settings_are_durable("WAL", 2, 1));
        assert!(!settings_are_durable("delete", 2, 1));
        assert!(!settings_are_durable("memory", 2, 1));
        assert!(!settings_are_durable("wal", 1, 1));
        assert!(!settings_are_durable("wal", 0, 1));
        assert!(!settings_are_durable("wal", 3, 1));
        assert!(!settings_are_durable("wal", 2, 0));
    }
}

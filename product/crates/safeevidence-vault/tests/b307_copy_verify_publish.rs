#![forbid(unsafe_code)]

use hkdf::Hkdf;
use rusqlite::{Connection, OpenFlags, params};
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;
use safeevidence_vault::vault_migration::{
    CopyVerifyPublishStage, EncryptedMigrationSource, EncryptedMigrationTarget,
    run_copy_verify_publish,
};
use safeevidence_vault::vault_sqlcipher::{SqlCipherDatabaseHandle, open_sqlcipher_database};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SEMANTIC_MARKER: &str = "SAFEEVIDENCE_B307_ENCRYPTED_MIGRATION_MARKER_62F19C";
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn identity() -> VaultLeaseIdentity {
    VaultLeaseIdentity::new(
        VaultId::from_bytes([0x71; VAULT_ID_BYTES]),
        KeyGeneration::new(7).expect("B307 test generation is non-zero"),
    )
}

fn context() -> KeyDerivationContext {
    let identity = identity();
    KeyDerivationContext::new(
        identity.vault_id(),
        identity.key_generation(),
        KeyPurpose::StructuredStore,
    )
}

fn vrk_bytes() -> [u8; KEY_MATERIAL_BYTES] {
    [0x39; KEY_MATERIAL_BYTES]
}

fn structured_key_bytes() -> [u8; KEY_MATERIAL_BYTES] {
    let context = context();
    let salt = context.hkdf_salt();
    let info = context.hkdf_info();
    let vrk = vrk_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), vrk.as_slice());
    let mut output = [0_u8; KEY_MATERIAL_BYTES];
    hkdf.expand(info.as_slice(), &mut output)
        .expect("B307 32-byte HKDF output is within the RFC 5869 limit");
    output
}

fn raw_key_pragma(key: &[u8; KEY_MATERIAL_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut sql = String::with_capacity(18 + (KEY_MATERIAL_BYTES * 2));
    sql.push_str("PRAGMA key = \"x'");
    for byte in key {
        sql.push(char::from(HEX[usize::from(byte >> 4)]));
        sql.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    sql.push_str("'\";");
    sql
}

fn provider_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

fn fixture_paths(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "safeevidence-b307-{label}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("B307 fixture directory must be created");
    (
        directory.join("source.db"),
        directory.join("staged.db"),
        directory.join("published.db"),
    )
}

fn cleanup(paths: &[&Path]) {
    let parent = paths
        .first()
        .and_then(|path| path.parent())
        .map(PathBuf::from);
    for path in paths {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = if suffix.is_empty() {
                (*path).to_path_buf()
            } else {
                PathBuf::from(format!("{}{suffix}", path.display()))
            };
            let _ = fs::remove_file(candidate);
        }
    }
    if let Some(parent) = parent {
        let _ = fs::remove_dir(parent);
    }
}

fn create_encrypted_source(path: &Path) {
    let connection = Connection::open_with_flags(path, provider_open_flags())
        .expect("reviewed SQLCipher provider must create the B307 source");
    let structured_key = structured_key_bytes();
    connection
        .execute_batch(&raw_key_pragma(&structured_key))
        .expect("B307 SQLCipher raw key operation must succeed");
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE; CREATE TABLE migration_probe (value TEXT NOT NULL);",
        )
        .expect("B307 encrypted migration source schema must be created");
    connection
        .execute(
            "INSERT INTO migration_probe (value) VALUES (?1);",
            params![SEMANTIC_MARKER],
        )
        .expect("B307 encrypted migration source row must commit");
    drop(connection);

    let bytes = fs::read(path).expect("B307 encrypted source bytes must be readable");
    assert!(
        !bytes.is_empty(),
        "B307 source must contain encrypted bytes"
    );
    assert!(
        !bytes
            .windows(SEMANTIC_MARKER.len())
            .any(|window| window == SEMANTIC_MARKER.as_bytes()),
        "B307 source must not expose the semantic marker as plaintext"
    );
}

fn open_production_handle(path: &Path) -> Result<SqlCipherDatabaseHandle, FixtureError> {
    let lease = VaultLease::new(identity());
    let vrk = OwnedKeyMaterial::from_bytes(vrk_bytes());
    open_sqlcipher_database(path, lease.keyed_handle_lease(), context(), &vrk)
        .map_err(|_| FixtureError(CopyVerifyPublishStage::Reopen))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixtureError(CopyVerifyPublishStage);

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B307 fixture failed at {}", self.0)
    }
}

impl std::error::Error for FixtureError {}

struct SqlCipherSource {
    path: PathBuf,
}

struct SqlCipherTarget {
    staged_path: PathBuf,
    published_path: PathBuf,
    fail_at: Option<CopyVerifyPublishStage>,
    events: Vec<CopyVerifyPublishStage>,
    anchor_digest: Option<[u8; 32]>,
    reopened: Option<SqlCipherDatabaseHandle>,
}

impl EncryptedMigrationSource<SqlCipherTarget> for SqlCipherSource {
    type Error = FixtureError;

    fn verify_source(&self) -> Result<(), Self::Error> {
        let handle = open_production_handle(&self.path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::SourceVerification))?;
        handle
            .verify_integrity()
            .map_err(|_| FixtureError(CopyVerifyPublishStage::SourceVerification))
    }

    fn copy_into(&self, target: &mut SqlCipherTarget) -> Result<(), Self::Error> {
        target.record(CopyVerifyPublishStage::Copy)?;
        fs::copy(&self.path, &target.staged_path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::Copy))?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target.staged_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| FixtureError(CopyVerifyPublishStage::Copy))?;
        Ok(())
    }
}

impl EncryptedMigrationTarget for SqlCipherTarget {
    type Error = FixtureError;

    fn verify_staged_copy(&mut self) -> Result<(), Self::Error> {
        self.record(CopyVerifyPublishStage::StagedVerification)?;
        let handle = open_production_handle(&self.staged_path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::StagedVerification))?;
        handle
            .verify_integrity()
            .map_err(|_| FixtureError(CopyVerifyPublishStage::StagedVerification))
    }

    fn publish_verified_copy(&mut self) -> Result<(), Self::Error> {
        self.record(CopyVerifyPublishStage::Publication)?;
        fs::rename(&self.staged_path, &self.published_path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::Publication))
    }

    fn anchor_published_copy(&mut self) -> Result<(), Self::Error> {
        self.record(CopyVerifyPublishStage::Anchor)?;
        let bytes = fs::read(&self.published_path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::Anchor))?;
        let digest = Sha256::digest(bytes);
        let mut anchor = [0_u8; 32];
        anchor.copy_from_slice(&digest);
        self.anchor_digest = Some(anchor);
        Ok(())
    }

    fn reopen_published_copy(&mut self) -> Result<(), Self::Error> {
        self.record(CopyVerifyPublishStage::Reopen)?;
        let handle = open_production_handle(&self.published_path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::Reopen))?;
        self.reopened = Some(handle);
        Ok(())
    }

    fn verify_reopened_copy(&mut self) -> Result<(), Self::Error> {
        self.record(CopyVerifyPublishStage::ReopenedVerification)?;
        let handle = self
            .reopened
            .as_ref()
            .ok_or(FixtureError(CopyVerifyPublishStage::ReopenedVerification))?;
        handle
            .verify_integrity()
            .map_err(|_| FixtureError(CopyVerifyPublishStage::ReopenedVerification))?;

        let bytes = fs::read(&self.published_path)
            .map_err(|_| FixtureError(CopyVerifyPublishStage::ReopenedVerification))?;
        let digest = Sha256::digest(bytes);
        let expected = self
            .anchor_digest
            .ok_or(FixtureError(CopyVerifyPublishStage::ReopenedVerification))?;
        if digest.as_slice() != expected {
            return Err(FixtureError(CopyVerifyPublishStage::ReopenedVerification));
        }
        Ok(())
    }
}

impl SqlCipherTarget {
    fn new(
        staged_path: PathBuf,
        published_path: PathBuf,
        fail_at: Option<CopyVerifyPublishStage>,
    ) -> Self {
        Self {
            staged_path,
            published_path,
            fail_at,
            events: Vec::new(),
            anchor_digest: None,
            reopened: None,
        }
    }

    fn record(&mut self, stage: CopyVerifyPublishStage) -> Result<(), FixtureError> {
        self.events.push(stage);
        if self.fail_at == Some(stage) {
            Err(FixtureError(stage))
        } else {
            Ok(())
        }
    }
}

#[test]
fn b307_sqlcipher_copy_verify_publish_preserves_prior_encrypted_state() {
    let (source_path, staged_path, published_path) = fixture_paths("success");
    create_encrypted_source(&source_path);
    let source_bytes = fs::read(&source_path).expect("B307 source bytes must be readable");

    let source = SqlCipherSource {
        path: source_path.clone(),
    };
    let mut target = SqlCipherTarget::new(staged_path.clone(), published_path.clone(), None);

    let result = run_copy_verify_publish(&source, &mut target);
    assert!(result.is_ok());

    assert_eq!(
        fs::read(&source_path).expect("B307 prior source must remain readable"),
        source_bytes,
        "B307 must not alter the prior verified encrypted source"
    );
    assert!(
        !staged_path.exists(),
        "published target must leave no staged path"
    );
    assert!(published_path.exists(), "B307 target must be published");
    assert_eq!(
        fs::read(&published_path).expect("B307 published bytes must be readable"),
        source_bytes,
        "fixture copy must publish the exact encrypted source bytes"
    );
    assert!(target.anchor_digest.is_some());
    assert!(target.reopened.is_some());

    drop(target);
    cleanup(&[&source_path, &staged_path, &published_path]);
}

#[test]
fn b307_each_target_failure_keeps_prior_sqlcipher_source_recoverable() {
    let failure_stages = [
        CopyVerifyPublishStage::Copy,
        CopyVerifyPublishStage::StagedVerification,
        CopyVerifyPublishStage::Publication,
        CopyVerifyPublishStage::Anchor,
        CopyVerifyPublishStage::Reopen,
        CopyVerifyPublishStage::ReopenedVerification,
    ];

    for failure_stage in failure_stages {
        let label = format!("failure-{failure_stage:?}");
        let (source_path, staged_path, published_path) = fixture_paths(&label);
        create_encrypted_source(&source_path);
        let source_bytes = fs::read(&source_path).expect("B307 source bytes must be readable");

        let source = SqlCipherSource {
            path: source_path.clone(),
        };
        let mut target = SqlCipherTarget::new(
            staged_path.clone(),
            published_path.clone(),
            Some(failure_stage),
        );

        let error = run_copy_verify_publish(&source, &mut target)
            .expect_err("injected B307 target boundary must fail");
        assert_eq!(error.stage(), failure_stage);
        assert_eq!(
            fs::read(&source_path).expect("B307 prior source must survive every failure"),
            source_bytes,
            "B307 failure must not alter the prior encrypted source"
        );

        let source_handle = open_production_handle(&source_path)
            .expect("B307 prior source must reopen after target failure");
        assert_eq!(source_handle.verify_integrity(), Ok(()));
        drop(source_handle);
        drop(target);
        cleanup(&[&source_path, &staged_path, &published_path]);
    }
}

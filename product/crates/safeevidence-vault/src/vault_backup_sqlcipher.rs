use crate::vault::{KeyGeneration, VaultId, VaultLeaseIdentity};
use crate::vault_backup_verify::PreSqlCipherVerifiedBackupSet;
use crate::vault_keys::{KeyDerivationContext, KeyPurpose, OwnedKeyMaterial};
use crate::vault_lease::VaultLease;
use crate::vault_sqlcipher::{
    SqlCipherIntegrityError, SqlCipherOpenError, open_sqlcipher_database,
};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const FILE_HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupSqlCipherVerificationError {
    FileReadFailed,
    FileIdentityMismatch,
    Open(SqlCipherOpenError),
    Integrity(SqlCipherIntegrityError),
}

impl fmt::Display for BackupSqlCipherVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileReadFailed => f.write_str("staged SQLCipher file could not be read"),
            Self::FileIdentityMismatch => {
                f.write_str("staged SQLCipher file does not match authenticated backup identity")
            }
            Self::Open(error) => write!(f, "staged SQLCipher open failed: {error}"),
            Self::Integrity(error) => write!(f, "staged SQLCipher integrity failed: {error}"),
        }
    }
}

impl Error for BackupSqlCipherVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open(error) => Some(error),
            Self::Integrity(error) => Some(error),
            Self::FileReadFailed | Self::FileIdentityMismatch => None,
        }
    }
}

pub struct SqlCipherVerifiedBackupSet {
    pre_sqlcipher: PreSqlCipherVerifiedBackupSet,
}

impl SqlCipherVerifiedBackupSet {
    #[must_use]
    pub fn pre_sqlcipher(&self) -> &PreSqlCipherVerifiedBackupSet {
        &self.pre_sqlcipher
    }

    #[must_use]
    pub fn into_pre_sqlcipher(self) -> PreSqlCipherVerifiedBackupSet {
        self.pre_sqlcipher
    }
}

fn file_identity(path: &Path) -> Result<(u64, [u8; 32]), BackupSqlCipherVerificationError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BackupSqlCipherVerificationError::FileReadFailed)?;
    if !metadata.file_type().is_file() {
        return Err(BackupSqlCipherVerificationError::FileReadFailed);
    }
    let mut file =
        File::open(path).map_err(|_| BackupSqlCipherVerificationError::FileReadFailed)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; FILE_HASH_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| BackupSqlCipherVerificationError::FileReadFailed)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| BackupSqlCipherVerificationError::FileIdentityMismatch)?,
            )
            .ok_or(BackupSqlCipherVerificationError::FileIdentityMismatch)?;
        hasher.update(&buffer[..read]);
    }
    Ok((total, hasher.finalize().into()))
}

fn require_file_identity(
    path: &Path,
    expected_length: u64,
    expected_sha256: [u8; 32],
) -> Result<(), BackupSqlCipherVerificationError> {
    let (length, sha256) = file_identity(path)?;
    if length != expected_length || sha256 != expected_sha256 {
        return Err(BackupSqlCipherVerificationError::FileIdentityMismatch);
    }
    Ok(())
}

fn verify_sqlcipher_file(
    path: &Path,
    expected_length: u64,
    expected_sha256: [u8; 32],
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    key_generation: KeyGeneration,
) -> Result<(), BackupSqlCipherVerificationError> {
    require_file_identity(path, expected_length, expected_sha256)?;

    let lease = VaultLease::new(VaultLeaseIdentity::new(vault_id, key_generation));
    let context = KeyDerivationContext::new(vault_id, key_generation, KeyPurpose::StructuredStore);
    let handle = open_sqlcipher_database(path, lease.keyed_handle_lease(), context, vrk)
        .map_err(BackupSqlCipherVerificationError::Open)?;
    handle
        .verify_integrity()
        .map_err(BackupSqlCipherVerificationError::Integrity)?;
    drop(handle);

    require_file_identity(path, expected_length, expected_sha256)
}

/// Re-proves the external structured-store staging file represented by an
/// already-authenticated B505 backup set immediately before local publication.
/// This closes the mutable-file gap between initial SQLCipher qualification and
/// the later copy-verify-publish coordinator without exposing VRK bytes.
pub fn reverify_staged_sqlcipher_backup<P: AsRef<Path>>(
    staged_path: P,
    verified: &SqlCipherVerifiedBackupSet,
) -> Result<(), BackupSqlCipherVerificationError> {
    let path = staged_path.as_ref();
    let pre_sqlcipher = verified.pre_sqlcipher();
    let expected_length = pre_sqlcipher.structured_store_exact_length();
    let expected_sha256 = pre_sqlcipher.structured_store_exact_sha256();
    pre_sqlcipher.with_structured_store_verification_key(|vrk, vault_id, key_generation| {
        verify_sqlcipher_file(
            path,
            expected_length,
            expected_sha256,
            vrk,
            vault_id,
            key_generation,
        )
    })
}

pub fn verify_staged_sqlcipher_backup<P: AsRef<Path>>(
    staged_path: P,
    pre_sqlcipher: PreSqlCipherVerifiedBackupSet,
) -> Result<SqlCipherVerifiedBackupSet, BackupSqlCipherVerificationError> {
    let path = staged_path.as_ref();
    let expected_length = pre_sqlcipher.structured_store_exact_length();
    let expected_sha256 = pre_sqlcipher.structured_store_exact_sha256();
    pre_sqlcipher.with_structured_store_verification_key(|vrk, vault_id, key_generation| {
        verify_sqlcipher_file(
            path,
            expected_length,
            expected_sha256,
            vrk,
            vault_id,
            key_generation,
        )
    })?;
    Ok(SqlCipherVerifiedBackupSet { pre_sqlcipher })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn vault_id() -> VaultId {
        VaultId::from_bytes([0x22; 16])
    }

    fn generation() -> KeyGeneration {
        KeyGeneration::new(7).unwrap()
    }

    fn vrk() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([0x11; 32])
    }

    fn unused_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "safeevidence-b505j-{label}-{}-{nanos}.sqlite3",
            std::process::id()
        ))
    }

    fn raw_key_pragma(vrk: &OwnedKeyMaterial) -> String {
        let context =
            KeyDerivationContext::new(vault_id(), generation(), KeyPurpose::StructuredStore);
        let key = context.derive_purpose_key(vrk);
        key.with_bytes(|bytes| {
            let mut hex = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                use std::fmt::Write as _;
                write!(&mut hex, "{byte:02x}").unwrap();
            }
            format!("PRAGMA key = \"x'{hex}'\";")
        })
    }

    fn create_encrypted_fixture(path: &Path, vrk: &OwnedKeyMaterial) {
        let connection = Connection::open(path).unwrap();
        connection.execute_batch(&raw_key_pragma(vrk)).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE b505j_probe (value INTEGER NOT NULL);\n\
                 INSERT INTO b505j_probe VALUES (1);",
            )
            .unwrap();
        drop(connection);
    }

    #[test]
    fn exact_staged_sqlcipher_identity_and_integrity_pass() {
        let path = unused_path("pass");
        let key = vrk();
        create_encrypted_fixture(&path, &key);
        let (length, sha256) = file_identity(&path).unwrap();
        assert!(length > 0);
        assert_eq!(
            verify_sqlcipher_file(&path, length, sha256, &key, vault_id(), generation()),
            Ok(())
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn staged_byte_identity_mismatch_fails_before_sqlcipher_acceptance() {
        let path = unused_path("tamper");
        let key = vrk();
        create_encrypted_fixture(&path, &key);
        let (length, sha256) = file_identity(&path).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            verify_sqlcipher_file(&path, length, sha256, &key, vault_id(), generation()),
            Err(BackupSqlCipherVerificationError::FileIdentityMismatch)
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn wrong_vrk_cannot_upgrade_matching_staged_bytes() {
        let path = unused_path("wrong-key");
        let correct = vrk();
        create_encrypted_fixture(&path, &correct);
        let (length, sha256) = file_identity(&path).unwrap();
        let wrong = OwnedKeyMaterial::from_bytes([0x33; 32]);
        assert!(matches!(
            verify_sqlcipher_file(&path, length, sha256, &wrong, vault_id(), generation()),
            Err(BackupSqlCipherVerificationError::Open(_))
                | Err(BackupSqlCipherVerificationError::Integrity(_))
        ));
        fs::remove_file(path).unwrap();
    }
}

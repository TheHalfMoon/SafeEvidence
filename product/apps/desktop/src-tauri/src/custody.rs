//! Device key custody: the store's root key, held by the OS protector.
//!
//! Key loss must never become silent data loss. A new key is created only when there is no store yet. If a
//! store exists and its key cannot be had, opening fails and the store's contents are kept, though a wrong
//! or damaged store can still merge a live WAL into the main file, as the open runs against it. A store
//! that was established and has since lost its main file or its schema is refused, not recreated. Damage to
//! the WAL of a store whose main file holds a schema cannot be told from a clean store without a protected
//! anchor, so commits since its last checkpoint could be lost unnoticed. A compromised unlocked OS is outside
//! the claimed secrecy guarantee.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use safeevidence_proofstore::ProofStore;
use safeevidence_vault::vault::{
    KeyGeneration, ProtectorError, SecretProtector, UserPresencePolicy, VAULT_ID_BYTES, VaultId,
    VaultLeaseIdentity,
};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;
use safeevidence_vault::vault_recovery::{
    RECOVERY_ENVELOPE_BYTES, RecoveryContext, RecoveryEnvelopeError, decrypt_recovery_envelope,
    encrypt_recovery_envelope,
};

const IDENTITY_FILE: &str = "vault-identity.bin";
const IDENTITY_MAGIC: &[u8] = b"SAFEEVIDENCE/VAULT-IDENTITY/v1\0";
const PROTECTOR_ID_BYTES: usize = 16;
const IDENTITY_BYTES: usize = IDENTITY_MAGIC.len() + VAULT_ID_BYTES + PROTECTOR_ID_BYTES + 8;
const ESTABLISHED_FILE: &str = "store-established";
pub const DATABASE_FILE: &str = "vault.db";
pub const RECOVERY_ENVELOPE_FILE: &str = "vault-recovery.envelope";

pub type Protector = Box<dyn SecretProtector<VaultRootKey = OwnedKeyMaterial>>;

/// Where a store's keys come from. Tests replace the OS protector and the random source.
#[derive(Clone, Copy)]
pub struct KeySource {
    pub protector: fn(&[u8; PROTECTOR_ID_BYTES], &Path) -> Result<Protector, ProtectorError>,
    pub fresh_key: fn() -> Result<[u8; KEY_MATERIAL_BYTES], ProtectorError>,
}

impl Default for KeySource {
    fn default() -> Self {
        Self {
            protector: platform_protector,
            fresh_key: random,
        }
    }
}

fn random<const N: usize>() -> Result<[u8; N], ProtectorError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| ProtectorError::Unavailable)?;
    Ok(bytes)
}

#[cfg(windows)]
fn platform_protector(
    id: &[u8; PROTECTOR_ID_BYTES],
    dir: &Path,
) -> Result<Protector, ProtectorError> {
    use safeevidence_vault::vault_windows_dpapi::{
        WindowsDpapiConfig, WindowsDpapiProtector, WindowsProtectorId,
    };
    // Its own directory: the protector restricts a directory's ACL only when it creates it.
    let config = WindowsDpapiConfig::new(dir.join("dpapi"), WindowsProtectorId::from_bytes(*id))?;
    Ok(Box::new(WindowsDpapiProtector::new(config)))
}

#[cfg(target_os = "macos")]
fn platform_protector(
    id: &[u8; PROTECTOR_ID_BYTES],
    _dir: &Path,
) -> Result<Protector, ProtectorError> {
    use safeevidence_vault::vault_apple_keychain::{
        AppleKeychainConfig, AppleKeychainProtector, AppleProtectorId,
    };
    let config = AppleKeychainConfig::new(
        "com.thehalfmoon.safeevidence",
        AppleProtectorId::from_bytes(*id),
    )?;
    Ok(Box::new(AppleKeychainProtector::new(config)))
}

#[cfg(target_os = "linux")]
fn platform_protector(
    id: &[u8; PROTECTOR_ID_BYTES],
    _dir: &Path,
) -> Result<Protector, ProtectorError> {
    use safeevidence_vault::vault_linux_secret_service::{
        KeyringHelperCommand, LinuxProtectorId, LinuxSecretServiceConfig,
        LinuxSecretServiceProtector,
    };
    Ok(Box::new(LinuxSecretServiceProtector::new(
        LinuxSecretServiceConfig::new(LinuxProtectorId::from_bytes(*id)),
        KeyringHelperCommand::beside_current_exe()?,
    )))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn platform_protector(
    _id: &[u8; PROTECTOR_ID_BYTES],
    _dir: &Path,
) -> Result<Protector, ProtectorError> {
    Err(ProtectorError::Unavailable)
}

/// The store's non-secret identity. It is not protected: changing it can only stop the key from being found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredIdentity {
    vault_id: [u8; VAULT_ID_BYTES],
    protector_id: [u8; PROTECTOR_ID_BYTES],
    generation: u64,
}

impl StoredIdentity {
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(IDENTITY_BYTES);
        bytes.extend_from_slice(IDENTITY_MAGIC);
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.protector_id);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtectorError> {
        if bytes.len() != IDENTITY_BYTES || !bytes.starts_with(IDENTITY_MAGIC) {
            return Err(ProtectorError::CorruptOrTampered);
        }
        let rest = &bytes[IDENTITY_MAGIC.len()..];
        let (vault_id, rest) = rest.split_at(VAULT_ID_BYTES);
        let (protector_id, generation) = rest.split_at(PROTECTOR_ID_BYTES);
        let corrupt = |_| ProtectorError::CorruptOrTampered;
        Ok(Self {
            vault_id: vault_id.try_into().map_err(corrupt)?,
            protector_id: protector_id.try_into().map_err(corrupt)?,
            generation: u64::from_be_bytes(generation.try_into().map_err(corrupt)?),
        })
    }

    fn write(self, dir: &Path) -> Result<(), ProtectorError> {
        let unavailable = |_| ProtectorError::Unavailable;
        let staged = dir.join(format!("{IDENTITY_FILE}.tmp"));
        let mut file = File::create(&staged).map_err(unavailable)?;
        file.write_all(&self.encode()).map_err(unavailable)?;
        file.sync_all().map_err(unavailable)?;
        std::fs::rename(&staged, dir.join(IDENTITY_FILE)).map_err(unavailable)?;
        sync_directory(dir)
    }
}

/// Makes a new or renamed name durable. Windows has no directory handle to sync this way.
fn sync_directory(dir: &Path) -> Result<(), ProtectorError> {
    #[cfg(unix)]
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProtectorError::Unavailable)?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn holds_data(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
}

/// Whether the store in `dir` is recorded as established.
#[must_use]
pub fn is_established(dir: &Path) -> bool {
    dir.join(ESTABLISHED_FILE).exists()
}

/// Records that the store in `dir` now exists, so its main file going missing can be told from a first run.
///
/// # Errors
/// Returns `Unavailable` if the marker cannot be made durable.
pub fn mark_established(dir: &Path) -> Result<(), ProtectorError> {
    let unavailable = |_| ProtectorError::Unavailable;
    let path = dir.join(ESTABLISHED_FILE);
    if path.exists() {
        return Ok(());
    }
    File::create(&path)
        .and_then(|file| file.sync_all())
        .map_err(unavailable)?;
    sync_directory(dir)
}

/// The store's root key and the lease identity it belongs to.
pub struct OpenedKey {
    pub identity: VaultLeaseIdentity,
    pub key: OwnedKeyMaterial,
}

fn configured(
    source: &KeySource,
    id: &[u8; PROTECTOR_ID_BYTES],
    dir: &Path,
) -> Result<Protector, ProtectorError> {
    let mut protector = (source.protector)(id, dir)?;
    let presence = if protector.requires_user_presence() {
        UserPresencePolicy::RequiredEachSafeEvidenceUnlock
    } else {
        UserPresencePolicy::NotRequired
    };
    let scope = protector.actual_access_scope();
    protector.create_protector(scope, presence)?;
    Ok(protector)
}

/// Opens the root key for the store in `dir`, creating one only if no store exists yet.
///
/// # Errors
/// Fails if the key cannot be had. In particular, `ItemMissing` with a store present is key loss, and
/// a missing identity with a store present is refused, so neither can replace the store's key. A crash
/// after the identity and before the key record recovers; other damage from a crash during first install,
/// such as a partial protector record, stays refused until someone removes it by hand.
pub fn open_root_key(dir: &Path, source: &KeySource) -> Result<OpenedKey, ProtectorError> {
    let main_file = dir.join(DATABASE_FILE);
    let wal_has_data = holds_data(&dir.join(format!("{DATABASE_FILE}-wal")));
    // After a kill, committed answers can live only in the WAL, and opening without the main file would
    // destroy it. An established store with no main file was damaged, not new.
    if !holds_data(&main_file) && (wal_has_data || dir.join(ESTABLISHED_FILE).exists()) {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let has_store = main_file.exists();
    let stored = match std::fs::read(dir.join(IDENTITY_FILE)) {
        Ok(bytes) => Some(StoredIdentity::decode(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(ProtectorError::Unavailable),
    };
    if stored.is_none() && has_store {
        return Err(ProtectorError::ItemMissing);
    }
    let identity = match stored {
        Some(identity) => identity,
        None => {
            // Written before the key, so a crash between the two recovers below.
            let identity = StoredIdentity {
                vault_id: random()?,
                protector_id: random()?,
                generation: 1,
            };
            identity.write(dir)?;
            identity
        }
    };
    let vault_id = VaultId::from_bytes(identity.vault_id);
    let generation =
        KeyGeneration::new(identity.generation).map_err(|_| ProtectorError::CorruptOrTampered)?;
    let mut protector = configured(source, &identity.protector_id, dir)?;
    let key = match protector.unlock_vrk(vault_id, generation) {
        Ok(key) => key,
        // No key and no store: a first run, or a crash after writing the identity. Nothing can be lost.
        Err(ProtectorError::ItemMissing) if !has_store => {
            let fresh = OwnedKeyMaterial::from_bytes((source.fresh_key)()?);
            protector.protect_or_store_vrk(vault_id, generation, &fresh)?;
            protector.unlock_vrk(vault_id, generation)?
        }
        Err(error) => return Err(error),
    };
    Ok(OpenedKey {
        identity: VaultLeaseIdentity::new(vault_id, generation),
        key,
    })
}

/// Typed failure reasons for passphrase-envelope enrollment and OS-protector key recovery.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "custody recovery API is verified in native key-loss tests while WebView IPC stays locked to ask_question and workstation_overview"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyRecoveryError {
    /// OS protector, filesystem, or identity metadata error.
    Protector(ProtectorError),
    /// B204 `SAFEVD/RECOVERY/ENVELOPE/v1` policy or AEAD authentication failure.
    Envelope(RecoveryEnvelopeError),
    /// No `vault-recovery.envelope` exists beside the store.
    EnvelopeMissing,
    /// Recovery refused because the existing OS protector still unlocks the VRK cleanly.
    ProtectorStillIntact,
    /// Authenticated key failed SQLCipher / `plan-v1.3` record-semantics verification on `vault.db`.
    StoreVerificationFailed,
}

impl std::fmt::Display for CustodyRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protector(error) => write!(f, "custody protector failure: {error}"),
            Self::Envelope(error) => write!(f, "recovery envelope failure: {error}"),
            Self::EnvelopeMissing => f.write_str("recovery envelope is missing"),
            Self::ProtectorStillIntact => {
                f.write_str("OS protector still holds the active root key; recovery refused")
            }
            Self::StoreVerificationFailed => {
                f.write_str("recovered key failed SQLCipher or record-semantics verification")
            }
        }
    }
}

impl std::error::Error for CustodyRecoveryError {}

/// Whether a canonical 167-byte `SAFEVD/RECOVERY/ENVELOPE/v1` file is enrolled in `dir`.
#[must_use]
pub fn has_recovery_envelope(dir: &Path) -> bool {
    std::fs::metadata(dir.join(RECOVERY_ENVELOPE_FILE))
        .is_ok_and(|meta| meta.is_file() && meta.len() == RECOVERY_ENVELOPE_BYTES as u64)
}

/// Enrolls a `SAFEVD/RECOVERY/ENVELOPE/v1` (`ARGON2ID_RFC9106_64M_V1`) recovery envelope for the
/// store in `dir`, atomically persisting `vault-recovery.envelope`.
///
/// # Errors
/// Fails closed if the active root key cannot be unlocked, passphrase policy fails, or atomic
/// persistence fails.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "enrolled via native custody recovery workflow; not exposed as an unprivileged WebView command"
    )
)]
pub fn enroll_recovery_passphrase(
    dir: &Path,
    source: &KeySource,
    passphrase: &str,
) -> Result<(), CustodyRecoveryError> {
    let opened = open_root_key(dir, source).map_err(CustodyRecoveryError::Protector)?;
    let context =
        RecoveryContext::new(opened.identity.vault_id(), opened.identity.key_generation());
    let envelope = encrypt_recovery_envelope(&opened.key, context, passphrase)
        .map_err(CustodyRecoveryError::Envelope)?;

    let unavailable = |_| CustodyRecoveryError::Protector(ProtectorError::Unavailable);
    let staged = dir.join(format!("{RECOVERY_ENVELOPE_FILE}.tmp"));
    let mut file = File::create(&staged).map_err(unavailable)?;
    file.write_all(&envelope).map_err(unavailable)?;
    file.sync_all().map_err(unavailable)?;
    std::fs::rename(&staged, dir.join(RECOVERY_ENVELOPE_FILE)).map_err(unavailable)?;
    sync_directory(dir).map_err(CustodyRecoveryError::Protector)
}

/// Recovers an established store after OS-protector key loss (`TA-05`):
/// 1. Refuses if `vault.db` is absent/empty or if the current OS protector still unlocks cleanly.
/// 2. Authenticates `vault-recovery.envelope` against `(vault_id, generation)` and `passphrase`.
/// 3. Verifies `ProofStore::open_existing` + `verify_record_semantics_doctor()` BEFORE mutating
///    any protector or identity file.
/// 4. Provisions a fresh `protector_id` in the OS protector, verifies round-trip unlock, and
///    atomically updates `vault-identity.bin`.
///
/// # Errors
/// Fails closed without mutating canonical store files on wrong passphrase, tampered envelope,
/// intact protector, or store verification failure.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "exercised via native custody recovery workflow; not exposed as an unprivileged WebView command"
    )
)]
pub fn recover_key_with_passphrase(
    dir: &Path,
    source: &KeySource,
    passphrase: &str,
) -> Result<OpenedKey, CustodyRecoveryError> {
    let main_file = dir.join(DATABASE_FILE);
    if !holds_data(&main_file) {
        return Err(CustodyRecoveryError::Protector(
            ProtectorError::CorruptOrTampered,
        ));
    }
    let identity_bytes = std::fs::read(dir.join(IDENTITY_FILE)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CustodyRecoveryError::Protector(ProtectorError::ItemMissing)
        } else {
            CustodyRecoveryError::Protector(ProtectorError::Unavailable)
        }
    })?;
    let stored =
        StoredIdentity::decode(&identity_bytes).map_err(CustodyRecoveryError::Protector)?;
    let vault_id = VaultId::from_bytes(stored.vault_id);
    let generation = KeyGeneration::new(stored.generation)
        .map_err(|_| CustodyRecoveryError::Protector(ProtectorError::CorruptOrTampered))?;

    if configured(source, &stored.protector_id, dir)
        .and_then(|mut protector| protector.unlock_vrk(vault_id, generation))
        .is_ok()
    {
        return Err(CustodyRecoveryError::ProtectorStillIntact);
    }

    let envelope_bytes = std::fs::read(dir.join(RECOVERY_ENVELOPE_FILE)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CustodyRecoveryError::EnvelopeMissing
        } else {
            CustodyRecoveryError::Protector(ProtectorError::Unavailable)
        }
    })?;
    let recovered_key = decrypt_recovery_envelope(
        RecoveryContext::new(vault_id, generation),
        passphrase,
        &envelope_bytes,
    )
    .map_err(CustodyRecoveryError::Envelope)?;

    let lease_identity = VaultLeaseIdentity::new(vault_id, generation);
    {
        let verify_lease = VaultLease::new(lease_identity);
        let context = KeyDerivationContext::new(vault_id, generation, KeyPurpose::StructuredStore);
        let mut store = ProofStore::open_existing(
            &main_file,
            verify_lease.keyed_handle_lease(),
            context,
            &recovered_key,
        )
        .map_err(|_| CustodyRecoveryError::StoreVerificationFailed)?;
        let report = store
            .verify_record_semantics_doctor()
            .map_err(|_| CustodyRecoveryError::StoreVerificationFailed)?;
        if !report.passed() {
            return Err(CustodyRecoveryError::StoreVerificationFailed);
        }
    }

    let new_protector_id: [u8; PROTECTOR_ID_BYTES] =
        random().map_err(CustodyRecoveryError::Protector)?;
    let mut new_protector =
        configured(source, &new_protector_id, dir).map_err(CustodyRecoveryError::Protector)?;
    new_protector
        .protect_or_store_vrk(vault_id, generation, &recovered_key)
        .map_err(CustodyRecoveryError::Protector)?;
    let unlocked = new_protector
        .unlock_vrk(vault_id, generation)
        .map_err(CustodyRecoveryError::Protector)?;
    {
        let reverify_lease = VaultLease::new(lease_identity);
        let context = KeyDerivationContext::new(vault_id, generation, KeyPurpose::StructuredStore);
        let mut store = ProofStore::open_existing(
            &main_file,
            reverify_lease.keyed_handle_lease(),
            context,
            &unlocked,
        )
        .map_err(|_| CustodyRecoveryError::Protector(ProtectorError::CorruptOrTampered))?;
        let report = store
            .verify_record_semantics_doctor()
            .map_err(|_| CustodyRecoveryError::Protector(ProtectorError::CorruptOrTampered))?;
        if !report.passed() {
            return Err(CustodyRecoveryError::Protector(
                ProtectorError::CorruptOrTampered,
            ));
        }
    }

    let updated = StoredIdentity {
        vault_id: stored.vault_id,
        protector_id: new_protector_id,
        generation: stored.generation,
    };
    updated
        .write(dir)
        .map_err(CustodyRecoveryError::Protector)?;

    Ok(OpenedKey {
        identity: lease_identity,
        key: unlocked,
    })
}

#[cfg(test)]
pub mod test_keys {
    //! A protector for tests, holding one key byte in a file beside the store, so state outlives a reopen
    //! and a test can lose or change the key.
    use super::*;
    use safeevidence_vault::vault::{
        AccessScope, FreshnessAnchor, HardwareBacking, ProtectedFreshnessState,
    };

    pub const KEY_FILE: &str = "test-key-byte";

    struct FileProtector {
        path: std::path::PathBuf,
    }

    impl SecretProtector for FileProtector {
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
            _: VaultId,
            _: KeyGeneration,
            _: &OwnedKeyMaterial,
        ) -> Result<(), ProtectorError> {
            std::fs::write(&self.path, [0x52]).map_err(|_| ProtectorError::Unavailable)
        }
        fn unlock_vrk(
            &mut self,
            _: VaultId,
            _: KeyGeneration,
        ) -> Result<OwnedKeyMaterial, ProtectorError> {
            match std::fs::read(&self.path) {
                Ok(byte) if byte.len() == 1 => {
                    Ok(OwnedKeyMaterial::from_bytes([byte[0]; KEY_MATERIAL_BYTES]))
                }
                Ok(_) => Err(ProtectorError::CorruptOrTampered),
                Err(_) => Err(ProtectorError::ItemMissing),
            }
        }
        fn read_freshness_anchor(
            &self,
            _: VaultId,
        ) -> Result<ProtectedFreshnessState, ProtectorError> {
            Err(ProtectorError::UnsupportedPolicy)
        }
        fn install_genesis_freshness_anchor(
            &mut self,
            _: VaultId,
            _: ProtectedFreshnessState,
            _: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            Err(ProtectorError::UnsupportedPolicy)
        }
        fn advance_freshness_anchor(
            &mut self,
            _: VaultId,
            _: FreshnessAnchor,
            _: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            Err(ProtectorError::UnsupportedPolicy)
        }
        fn replace_protector(&mut self, _: VaultId) -> Result<(), ProtectorError> {
            Err(ProtectorError::UnsupportedPolicy)
        }
        fn remove_protector(&mut self, _: VaultId) -> Result<(), ProtectorError> {
            Err(ProtectorError::UnsupportedPolicy)
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

    pub const SOURCE: KeySource = KeySource {
        protector: |_, dir| {
            Ok(Box::new(FileProtector {
                path: dir.join(KEY_FILE),
            }))
        },
        fresh_key: || Ok([0x52; KEY_MATERIAL_BYTES]),
    };
}

#[cfg(test)]
mod tests {
    use super::test_keys::{KEY_FILE, SOURCE};
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!("se-custody-{}-{id}", std::process::id()));
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
    fn identity_round_trips_and_a_damaged_one_is_refused() {
        let identity = StoredIdentity {
            vault_id: [1; VAULT_ID_BYTES],
            protector_id: [2; PROTECTOR_ID_BYTES],
            generation: 3,
        };
        let bytes = identity.encode();
        assert_eq!(StoredIdentity::decode(&bytes), Ok(identity));
        assert_eq!(
            StoredIdentity::decode(&bytes[1..]),
            Err(ProtectorError::CorruptOrTampered)
        );
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            StoredIdentity::decode(&wrong_magic),
            Err(ProtectorError::CorruptOrTampered)
        );
    }

    #[test]
    fn a_new_directory_creates_a_key_and_a_reopen_finds_the_same_identity() {
        let dir = TempDir::new();
        let first = open_root_key(&dir.0, &SOURCE).expect("first");
        let second = open_root_key(&dir.0, &SOURCE).expect("second");
        assert_eq!(first.identity, second.identity);
        assert_eq!(first.identity.key_generation().get(), 1);
    }

    #[test]
    fn an_established_store_that_lost_its_main_file_is_refused_with_or_without_its_key() {
        for key_lost in [false, true] {
            let dir = TempDir::new();
            open_root_key(&dir.0, &SOURCE).expect("first");
            mark_established(&dir.0).expect("mark");
            if key_lost {
                std::fs::remove_file(dir.0.join(KEY_FILE)).unwrap();
            }
            assert_eq!(
                open_root_key(&dir.0, &SOURCE).map(|_| ()),
                Err(ProtectorError::CorruptOrTampered),
                "key lost: {key_lost}"
            );
            std::fs::write(dir.0.join(DATABASE_FILE), b"").unwrap();
            assert_eq!(
                open_root_key(&dir.0, &SOURCE).map(|_| ()),
                Err(ProtectorError::CorruptOrTampered),
                "an empty main file is no store either; key lost: {key_lost}"
            );
        }
    }

    #[test]
    fn a_wal_without_a_main_file_is_refused_and_kept() {
        for (key_lost, empty_main) in [(false, false), (true, false), (false, true), (true, true)] {
            let dir = TempDir::new();
            open_root_key(&dir.0, &SOURCE).expect("first");
            let wal = dir.0.join(format!("{DATABASE_FILE}-wal"));
            std::fs::write(&wal, b"committed answers").unwrap();
            let identity = std::fs::read(dir.0.join(IDENTITY_FILE)).unwrap();
            if empty_main {
                std::fs::write(dir.0.join(DATABASE_FILE), b"").unwrap();
            }
            if key_lost {
                std::fs::remove_file(dir.0.join(KEY_FILE)).unwrap();
            }
            assert_eq!(
                open_root_key(&dir.0, &SOURCE).map(|_| ()),
                Err(ProtectorError::CorruptOrTampered),
                "key lost: {key_lost}, empty main: {empty_main}"
            );
            assert_eq!(std::fs::read(&wal).unwrap(), b"committed answers");
            assert_eq!(std::fs::read(dir.0.join(IDENTITY_FILE)).unwrap(), identity);
            assert_eq!(
                dir.0.join(KEY_FILE).exists(),
                !key_lost,
                "no new key was made"
            );
        }
    }

    #[test]
    fn a_wal_with_a_lost_identity_is_refused_and_no_identity_is_made() {
        let dir = TempDir::new();
        std::fs::write(
            dir.0.join(format!("{DATABASE_FILE}-wal")),
            b"committed answers",
        )
        .unwrap();
        assert_eq!(
            open_root_key(&dir.0, &SOURCE).map(|_| ()),
            Err(ProtectorError::CorruptOrTampered)
        );
        assert!(
            !dir.0.join(IDENTITY_FILE).exists(),
            "a new identity would orphan a restored store"
        );
    }

    #[test]
    fn an_unreadable_identity_is_not_taken_for_a_missing_one() {
        let dir = TempDir::new();
        std::fs::create_dir(dir.0.join(IDENTITY_FILE)).unwrap();
        assert_eq!(
            open_root_key(&dir.0, &SOURCE).map(|_| ()),
            Err(ProtectorError::Unavailable)
        );
        assert!(!dir.0.join(KEY_FILE).exists());
    }

    #[test]
    fn a_store_without_its_key_is_refused_and_no_new_key_is_made() {
        let dir = TempDir::new();
        open_root_key(&dir.0, &SOURCE).expect("first");
        std::fs::write(dir.0.join(DATABASE_FILE), b"a store").unwrap();
        std::fs::remove_file(dir.0.join(KEY_FILE)).unwrap();
        assert_eq!(
            open_root_key(&dir.0, &SOURCE).map(|_| ()),
            Err(ProtectorError::ItemMissing)
        );
        assert!(
            !dir.0.join(KEY_FILE).exists(),
            "no key was created over the store"
        );
    }

    #[test]
    fn a_store_without_its_identity_is_refused_and_no_new_identity_is_made() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join(DATABASE_FILE), b"a store").unwrap();
        assert_eq!(
            open_root_key(&dir.0, &SOURCE).map(|_| ()),
            Err(ProtectorError::ItemMissing)
        );
        assert!(!dir.0.join(IDENTITY_FILE).exists());
        assert!(!dir.0.join(KEY_FILE).exists());
    }

    #[test]
    fn a_crash_after_the_identity_and_before_the_key_recovers_while_no_store_exists() {
        let dir = TempDir::new();
        let first = open_root_key(&dir.0, &SOURCE).expect("first");
        std::fs::remove_file(dir.0.join(KEY_FILE)).unwrap();
        let second = open_root_key(&dir.0, &SOURCE).expect("recovers");
        assert_eq!(first.identity, second.identity);
    }

    #[test]
    fn a_damaged_identity_is_refused_even_with_no_store() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join(IDENTITY_FILE), b"damaged").unwrap();
        assert_eq!(
            open_root_key(&dir.0, &SOURCE).map(|_| ()),
            Err(ProtectorError::CorruptOrTampered)
        );
    }

    /// The real OS protector. It holds a real key, in this test's own directory.
    #[cfg(windows)]
    #[test]
    fn real_dpapi_stores_the_key_and_a_new_protector_reads_it_back() {
        let dir = TempDir::new();
        let source = KeySource::default();
        let first = open_root_key(&dir.0, &source).expect("DPAPI stores a key");
        let second = open_root_key(&dir.0, &source).expect("DPAPI reads it back");
        assert_eq!(first.identity, second.identity);
        // A real key: losing the protector's record with a store present is refused, not replaced.
        std::fs::write(dir.0.join(DATABASE_FILE), b"a store").unwrap();
        std::fs::remove_dir_all(dir.0.join("dpapi")).unwrap();
        assert!(open_root_key(&dir.0, &source).is_err());
    }

    #[test]
    fn enrolled_recovery_envelope_recovers_proofstore_after_key_loss_and_refuses_wrong_passphrase()
    {
        const PASSPHRASE: &str = "vellum lantern harbor quartz sixteen";
        let dir = TempDir::new();
        let first = open_root_key(&dir.0, &SOURCE).expect("first open");
        let lease = VaultLease::new(first.identity);
        let context = KeyDerivationContext::new(
            first.identity.vault_id(),
            first.identity.key_generation(),
            KeyPurpose::StructuredStore,
        );
        let mut store = ProofStore::open(
            dir.0.join(DATABASE_FILE),
            lease.keyed_handle_lease(),
            context,
            &first.key,
        )
        .expect("open proofstore");
        store
            .put_source("doc-1", b"synthetic source")
            .expect("put source");
        drop(store);
        mark_established(&dir.0).expect("mark established");

        enroll_recovery_passphrase(&dir.0, &SOURCE, PASSPHRASE).expect("enroll recovery");
        assert!(has_recovery_envelope(&dir.0));

        // While the protector is still intact, recovery is refused.
        assert_eq!(
            recover_key_with_passphrase(&dir.0, &SOURCE, PASSPHRASE).map(|_| ()),
            Err(CustodyRecoveryError::ProtectorStillIntact)
        );

        // Simulate OS protector key loss.
        std::fs::remove_file(dir.0.join(KEY_FILE)).expect("delete test key");
        assert_eq!(
            open_root_key(&dir.0, &SOURCE).map(|_| ()),
            Err(ProtectorError::ItemMissing)
        );

        // Wrong passphrase leaves key absent and identity untouched.
        let identity_before = std::fs::read(dir.0.join(IDENTITY_FILE)).expect("read identity");
        assert_eq!(
            recover_key_with_passphrase(&dir.0, &SOURCE, "wrong lantern harbor quartz sixteen")
                .map(|_| ()),
            Err(CustodyRecoveryError::Envelope(
                RecoveryEnvelopeError::RecoveryAuthenticationFailed
            ))
        );
        assert!(!dir.0.join(KEY_FILE).exists());
        assert_eq!(
            std::fs::read(dir.0.join(IDENTITY_FILE)).expect("read identity after wrong passphrase"),
            identity_before
        );

        // Authentic passphrase recovers the VRK, re-provisions protector, and reopens cleanly.
        let recovered =
            recover_key_with_passphrase(&dir.0, &SOURCE, PASSPHRASE).expect("recover key");
        assert_eq!(recovered.identity, first.identity);
        let reopened = open_root_key(&dir.0, &SOURCE).expect("reopen root key after recovery");
        assert_eq!(reopened.identity, first.identity);
    }

    #[cfg(windows)]
    #[test]
    fn real_dpapi_key_loss_recovers_end_to_end_via_passphrase_envelope() {
        const PASSPHRASE: &str = "vellum lantern harbor quartz sixteen";
        let dir = TempDir::new();
        let source = KeySource::default();
        let first = open_root_key(&dir.0, &source).expect("DPAPI creates key");
        let lease = VaultLease::new(first.identity);
        let context = KeyDerivationContext::new(
            first.identity.vault_id(),
            first.identity.key_generation(),
            KeyPurpose::StructuredStore,
        );
        let mut store = ProofStore::open(
            dir.0.join(DATABASE_FILE),
            lease.keyed_handle_lease(),
            context,
            &first.key,
        )
        .expect("open real DPAPI-backed ProofStore");
        store
            .put_source("doc-dpapi", b"synthetic dpapi payload")
            .expect("put source");
        drop(store);
        mark_established(&dir.0).expect("mark established");

        enroll_recovery_passphrase(&dir.0, &source, PASSPHRASE).expect("enroll DPAPI recovery");
        std::fs::remove_dir_all(dir.0.join("dpapi")).expect("destroy DPAPI protector dir");
        assert!(open_root_key(&dir.0, &source).is_err());

        let recovered =
            recover_key_with_passphrase(&dir.0, &source, PASSPHRASE).expect("recover DPAPI key");
        assert_eq!(recovered.identity, first.identity);

        let reopened_key = open_root_key(&dir.0, &source).expect("reopen DPAPI key");
        assert_eq!(reopened_key.identity, first.identity);
        let verify_lease = VaultLease::new(reopened_key.identity);
        let mut reopened_store = ProofStore::open_existing(
            dir.0.join(DATABASE_FILE),
            verify_lease.keyed_handle_lease(),
            context,
            &reopened_key.key,
        )
        .expect("reopen ProofStore with recovered DPAPI key");
        assert_eq!(
            reopened_store.source("doc-dpapi").expect("read source"),
            Some(b"synthetic dpapi payload".to_vec())
        );
    }

    /// With no helper beside this test binary, Linux must refuse rather than fall back to anything.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_without_the_helper_is_refused() {
        let dir = TempDir::new();
        assert_eq!(
            open_root_key(&dir.0, &KeySource::default()).map(|_| ()),
            Err(ProtectorError::Unavailable)
        );
    }
}

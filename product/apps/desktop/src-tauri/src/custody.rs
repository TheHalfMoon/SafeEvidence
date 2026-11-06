//! Device key custody: the store's root key, held by the OS protector.
//!
//! Key loss must never become silent data loss. A new key is created only when there is no store yet. If a
//! store exists and its key cannot be had, opening fails and nothing is changed. A compromised unlocked OS
//! is outside the claimed secrecy guarantee.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use safeevidence_vault::vault::{
    KeyGeneration, ProtectorError, SecretProtector, UserPresencePolicy, VAULT_ID_BYTES, VaultId,
    VaultLeaseIdentity,
};
use safeevidence_vault::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};

const IDENTITY_FILE: &str = "vault-identity.bin";
const IDENTITY_MAGIC: &[u8] = b"SAFEEVIDENCE/VAULT-IDENTITY/v1\0";
const PROTECTOR_ID_BYTES: usize = 16;
const IDENTITY_BYTES: usize = IDENTITY_MAGIC.len() + VAULT_ID_BYTES + PROTECTOR_ID_BYTES + 8;
pub const DATABASE_FILE: &str = "vault.db";

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
        std::fs::rename(&staged, dir.join(IDENTITY_FILE)).map_err(unavailable)
    }
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
/// a missing identity with a store present is refused, so neither can replace the store's key.
pub fn open_root_key(dir: &Path, source: &KeySource) -> Result<OpenedKey, ProtectorError> {
    let has_store = dir.join(DATABASE_FILE).exists();
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
            // Written before the key, so a crash between the two is recoverable below.
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

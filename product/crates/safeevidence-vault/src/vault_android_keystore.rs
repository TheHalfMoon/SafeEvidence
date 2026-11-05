//! B402 Android Keystore adapter: non-exportable app-UID key, no-backup ciphertext,
//! and opaque provider names that never embed vault, generation, or user content.

use crate::vault::{
    AccessScope, FreshnessAnchor, HardwareBacking, KeyGeneration, ProtectedFreshnessState,
    ProtectorCapabilities, ProtectorError, SecretProtector, UserPresencePolicy, VaultId,
};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use crate::vault_protector::{ProtectorPolicy, validate_requested_policy};
use getrandom::fill;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const RECORD_MAGIC: &[u8] = b"HIMSAT/ANDROID/VRK/v1\0";
const PROTECTOR_ID_BYTES: usize = 16;
const RECORD_BYTES: usize = RECORD_MAGIC.len() + 16 + 8 + 1 + 1 + KEY_MATERIAL_BYTES;

/// Opaque random identifier used only to derive provider-visible Android names.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AndroidProtectorId([u8; PROTECTOR_ID_BYTES]);

impl AndroidProtectorId {
    /// Generates one identifier from the approved OS cryptographic RNG path.
    pub fn generate() -> Result<Self, ProtectorError> {
        let mut bytes = [0_u8; PROTECTOR_ID_BYTES];
        fill(&mut bytes).map_err(|_| ProtectorError::Unavailable)?;
        Ok(Self(bytes))
    }

    /// Creates an identifier from exact bytes for persisted configuration/tests.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROTECTOR_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque identifier bytes without exposing any vault identity.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROTECTOR_ID_BYTES] {
        &self.0
    }

    fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(PROTECTOR_ID_BYTES * 2);
        for byte in self.0 {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

impl core::fmt::Debug for AndroidProtectorId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AndroidProtectorId([OPAQUE; 16 bytes])")
    }
}

/// Immutable Android application identity and protector naming configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidKeystoreConfig {
    expected_package: String,
    protector_id: AndroidProtectorId,
}

impl AndroidKeystoreConfig {
    /// Creates a fresh protector configuration with a new OS-CSPRNG identifier.
    pub fn new(expected_package: impl Into<String>) -> Result<Self, ProtectorError> {
        Self::from_persisted_id(expected_package, AndroidProtectorId::generate()?)
    }

    /// Restores the same protector from its previously persisted opaque identifier.
    pub fn from_persisted_id(
        expected_package: impl Into<String>,
        protector_id: AndroidProtectorId,
    ) -> Result<Self, ProtectorError> {
        let expected_package = expected_package.into();
        if expected_package.is_empty() || expected_package.bytes().any(|byte| byte == 0) {
            return Err(ProtectorError::UnsupportedPolicy);
        }
        Ok(Self {
            expected_package,
            protector_id,
        })
    }

    /// Expected Android package name for the calling application UID.
    #[must_use]
    pub fn expected_package(&self) -> &str {
        &self.expected_package
    }

    /// Opaque protector identifier.
    #[must_use]
    pub const fn protector_id(&self) -> AndroidProtectorId {
        self.protector_id
    }

    fn alias(&self) -> String {
        format!(
            "safeevidence.vault.protector.v1.{}",
            self.protector_id.hex()
        )
    }

    fn record_name(&self) -> String {
        format!(
            "safeevidence-vault-protector-v1-{}.bin",
            self.protector_id.hex()
        )
    }
}

/// Android host boundary; repository-wide Kotlin↔Rust FFI remains separately governed.
pub trait AndroidKeystoreBackend {
    fn verify_environment(&self, expected_package: &str) -> Result<(), ProtectorError>;
    fn create_key(&self, alias: &str) -> Result<HardwareBacking, ProtectorError>;
    fn inspect_key(&self, alias: &str) -> Result<HardwareBacking, ProtectorError>;
    fn seal(&self, alias: &str, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError>;
    fn open(&self, alias: &str, ciphertext: &[u8]) -> Result<Vec<u8>, ProtectorError>;
    fn read_record(&self, record_name: &str) -> Result<Vec<u8>, ProtectorError>;
    fn write_record(&self, record_name: &str, ciphertext: &[u8]) -> Result<(), ProtectorError>;
    fn delete_record(&self, record_name: &str) -> Result<(), ProtectorError>;
    fn delete_key(&self, alias: &str) -> Result<(), ProtectorError>;
}

/// Portable B402 protector logic over an Android-native Keystore backend.
pub struct AndroidKeystoreProtector<B> {
    config: AndroidKeystoreConfig,
    backend: B,
    policy: Option<ProtectorPolicy>,
    hardware: HardwareBacking,
}

impl<B: AndroidKeystoreBackend> AndroidKeystoreProtector<B> {
    /// Creates an adapter after proving that the backend belongs to the expected package/UID.
    pub fn new(config: AndroidKeystoreConfig, backend: B) -> Result<Self, ProtectorError> {
        backend.verify_environment(config.expected_package())?;
        Ok(Self {
            config,
            backend,
            policy: None,
            hardware: HardwareBacking::Unknown,
        })
    }

    fn policy(&self) -> Result<ProtectorPolicy, ProtectorError> {
        self.policy.ok_or(ProtectorError::UnsupportedPolicy)
    }

    fn validate_existing_record(
        &self,
        vault_id: VaultId,
        generation: KeyGeneration,
        policy: ProtectorPolicy,
        expected_vrk: &OwnedKeyMaterial,
    ) -> Result<(), ProtectorError> {
        let ciphertext = self.backend.read_record(&self.config.record_name())?;
        let plaintext = Zeroizing::new(self.backend.open(&self.config.alias(), &ciphertext)?);
        validate_record_binding(&plaintext, vault_id, Some(generation), policy)?;
        if !record_vrk_matches(&plaintext, expected_vrk) {
            return Err(ProtectorError::PolicyMismatch);
        }
        Ok(())
    }
}

impl<B: AndroidKeystoreBackend> SecretProtector for AndroidKeystoreProtector<B> {
    type VaultRootKey = OwnedKeyMaterial;

    fn create_protector(
        &mut self,
        requested_scope: AccessScope,
        user_presence_policy: UserPresencePolicy,
    ) -> Result<(), ProtectorError> {
        let requested = ProtectorPolicy::new(requested_scope, user_presence_policy);
        validate_requested_policy(
            ProtectorCapabilities::new(AccessScope::AppExclusive, false, HardwareBacking::Unknown),
            requested,
        )?;
        let alias = self.config.alias();
        let hardware = match self.backend.inspect_key(&alias) {
            Ok(hardware) => hardware,
            Err(ProtectorError::ItemMissing) => {
                match self.backend.read_record(&self.config.record_name()) {
                    Ok(record) => {
                        drop(Zeroizing::new(record));
                        return Err(ProtectorError::Invalidated);
                    }
                    Err(ProtectorError::ItemMissing) => self.backend.create_key(&alias)?,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        self.hardware = hardware;
        self.policy = Some(requested);
        Ok(())
    }

    fn protect_or_store_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
        vrk: &Self::VaultRootKey,
    ) -> Result<(), ProtectorError> {
        let policy = self.policy()?;
        match self.validate_existing_record(vault_id, key_generation, policy, vrk) {
            Ok(()) | Err(ProtectorError::ItemMissing) => {}
            Err(error) => return Err(error),
        }
        let plaintext = Zeroizing::new(encode_record(vault_id, key_generation, policy, vrk));
        let ciphertext = Zeroizing::new(self.backend.seal(&self.config.alias(), &plaintext[..])?);
        self.backend
            .write_record(&self.config.record_name(), &ciphertext)
    }

    fn unlock_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
    ) -> Result<Self::VaultRootKey, ProtectorError> {
        let policy = self.policy()?;
        self.hardware = self.backend.inspect_key(&self.config.alias())?;
        let ciphertext = Zeroizing::new(self.backend.read_record(&self.config.record_name())?);
        let plaintext = Zeroizing::new(self.backend.open(&self.config.alias(), &ciphertext)?);
        decode_record(&plaintext, vault_id, key_generation, policy)
    }

    fn read_freshness_anchor(
        &self,
        _vault_id: VaultId,
    ) -> Result<ProtectedFreshnessState, ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn install_genesis_freshness_anchor(
        &mut self,
        _vault_id: VaultId,
        _expected_state: ProtectedFreshnessState,
        _new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn advance_freshness_anchor(
        &mut self,
        _vault_id: VaultId,
        _expected_old: FreshnessAnchor,
        _new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn replace_protector(&mut self, _vault_id: VaultId) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn remove_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError> {
        let policy = self.policy()?;
        let alias = self.config.alias();
        let record_name = self.config.record_name();
        let key_state = self.backend.inspect_key(&alias);
        let record_state = self.backend.read_record(&record_name);

        match (key_state, record_state) {
            (Ok(_), Ok(ciphertext)) => {
                let plaintext = Zeroizing::new(self.backend.open(&alias, &ciphertext)?);
                validate_record_binding(&plaintext, vault_id, None, policy)?;
            }
            (Err(ProtectorError::ItemMissing | ProtectorError::Invalidated), Ok(_))
            | (Ok(_), Err(ProtectorError::ItemMissing))
            | (
                Err(ProtectorError::ItemMissing | ProtectorError::Invalidated),
                Err(ProtectorError::ItemMissing),
            ) => {}
            (Err(error), _) | (_, Err(error)) => return Err(error),
        }

        let key_result = normalize_delete(self.backend.delete_key(&alias));
        let record_result = normalize_delete(self.backend.delete_record(&record_name));
        if key_result.is_ok() {
            self.hardware = HardwareBacking::Unknown;
        }
        key_result?;
        record_result?;
        self.policy = None;
        Ok(())
    }

    fn actual_access_scope(&self) -> AccessScope {
        AccessScope::AppExclusive
    }

    fn requires_user_presence(&self) -> bool {
        false
    }

    fn hardware_backed_state(&self) -> HardwareBacking {
        self.hardware
    }
}

fn normalize_delete(result: Result<(), ProtectorError>) -> Result<(), ProtectorError> {
    match result {
        Ok(()) | Err(ProtectorError::ItemMissing) => Ok(()),
        Err(error) => Err(error),
    }
}

fn record_vrk_matches(record: &[u8], expected_vrk: &OwnedKeyMaterial) -> bool {
    let key_offset = RECORD_BYTES - KEY_MATERIAL_BYTES;
    let stored_digest = Sha256::digest(&record[key_offset..]);
    expected_vrk.with_bytes(|bytes| stored_digest == Sha256::digest(bytes))
}

fn encode_record(
    vault_id: VaultId,
    key_generation: KeyGeneration,
    policy: ProtectorPolicy,
    vrk: &OwnedKeyMaterial,
) -> [u8; RECORD_BYTES] {
    let mut output = [0_u8; RECORD_BYTES];
    let mut offset = 0;
    output[offset..offset + RECORD_MAGIC.len()].copy_from_slice(RECORD_MAGIC);
    offset += RECORD_MAGIC.len();
    output[offset..offset + 16].copy_from_slice(vault_id.as_bytes());
    offset += 16;
    output[offset..offset + 8].copy_from_slice(&key_generation.get().to_be_bytes());
    offset += 8;
    output[offset] = encode_scope(policy.access_scope());
    offset += 1;
    output[offset] = encode_presence(policy.user_presence_policy());
    offset += 1;
    vrk.with_bytes(|bytes| output[offset..].copy_from_slice(bytes));
    output
}

fn validate_record_binding(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: Option<KeyGeneration>,
    expected_policy: ProtectorPolicy,
) -> Result<(), ProtectorError> {
    if record.len() != RECORD_BYTES || &record[..RECORD_MAGIC.len()] != RECORD_MAGIC {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let mut offset = RECORD_MAGIC.len();
    let vault = VaultId::try_from_slice(&record[offset..offset + 16])
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 16;
    let generation = KeyGeneration::new(u64::from_be_bytes(
        record[offset..offset + 8]
            .try_into()
            .map_err(|_| ProtectorError::CorruptOrTampered)?,
    ))
    .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 8;
    let policy = ProtectorPolicy::new(
        decode_scope(record[offset])?,
        decode_presence(record[offset + 1])?,
    );
    if vault != expected_vault_id || expected_generation.is_some_and(|value| value != generation) {
        return Err(ProtectorError::OwnerMismatch);
    }
    if policy != expected_policy {
        return Err(ProtectorError::PolicyMismatch);
    }
    Ok(())
}

fn decode_record(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: KeyGeneration,
    expected_policy: ProtectorPolicy,
) -> Result<OwnedKeyMaterial, ProtectorError> {
    validate_record_binding(
        record,
        expected_vault_id,
        Some(expected_generation),
        expected_policy,
    )?;
    let key_offset = RECORD_BYTES - KEY_MATERIAL_BYTES;
    let key: [u8; KEY_MATERIAL_BYTES] = record[key_offset..]
        .try_into()
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    Ok(OwnedKeyMaterial::from_bytes(key))
}

const fn encode_scope(scope: AccessScope) -> u8 {
    match scope {
        AccessScope::AppExclusive => 1,
        AccessScope::SameUserAccount => 2,
        AccessScope::SameUserSession => 3,
    }
}

fn decode_scope(value: u8) -> Result<AccessScope, ProtectorError> {
    match value {
        1 => Ok(AccessScope::AppExclusive),
        2 => Ok(AccessScope::SameUserAccount),
        3 => Ok(AccessScope::SameUserSession),
        _ => Err(ProtectorError::CorruptOrTampered),
    }
}

const fn encode_presence(policy: UserPresencePolicy) -> u8 {
    match policy {
        UserPresencePolicy::NotRequired => 0,
        UserPresencePolicy::RequiredEachSafeEvidenceUnlock => 1,
    }
}

fn decode_presence(value: u8) -> Result<UserPresencePolicy, ProtectorError> {
    match value {
        0 => Ok(UserPresencePolicy::NotRequired),
        1 => Ok(UserPresencePolicy::RequiredEachSafeEvidenceUnlock),
        _ => Err(ProtectorError::CorruptOrTampered),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AndroidKeystoreBackend, AndroidKeystoreConfig, AndroidKeystoreProtector, AndroidProtectorId,
    };
    use crate::vault::{
        AccessScope, HardwareBacking, KeyGeneration, ProtectorError, SecretProtector,
        UserPresencePolicy, VAULT_ID_BYTES, VaultId,
    };
    use crate::vault_keys::OwnedKeyMaterial;
    use std::{cell::RefCell, rc::Rc};

    const PACKAGE: &str = "com.thehalfmoon.safeevidence";

    #[derive(Debug)]
    struct MemoryState {
        key_present: bool,
        record: Option<Vec<u8>>,
        hardware: HardwareBacking,
        open_error: Option<ProtectorError>,
        delete_key_error: Option<ProtectorError>,
        delete_record_error: Option<ProtectorError>,
    }

    #[derive(Clone, Debug)]
    struct MemoryBackend {
        package: &'static str,
        state: Rc<RefCell<MemoryState>>,
    }

    impl MemoryBackend {
        fn new(package: &'static str, hardware: HardwareBacking) -> Self {
            Self {
                package,
                state: Rc::new(RefCell::new(MemoryState {
                    key_present: false,
                    record: None,
                    hardware,
                    open_error: None,
                    delete_key_error: None,
                    delete_record_error: None,
                })),
            }
        }

        fn set_open_error(&self, error: ProtectorError) {
            self.state.borrow_mut().open_error = Some(error);
        }

        fn corrupt_record(&self) {
            if let Some(record) = self.state.borrow_mut().record.as_mut()
                && let Some(first) = record.first_mut()
            {
                *first ^= 0x55;
            }
        }

        fn fail_next_key_delete(&self) {
            self.state.borrow_mut().delete_key_error = Some(ProtectorError::Unavailable);
        }

        fn fail_next_record_delete(&self) {
            self.state.borrow_mut().delete_record_error = Some(ProtectorError::Unavailable);
        }
    }

    impl AndroidKeystoreBackend for MemoryBackend {
        fn verify_environment(&self, expected_package: &str) -> Result<(), ProtectorError> {
            if expected_package == self.package {
                Ok(())
            } else {
                Err(ProtectorError::OwnerMismatch)
            }
        }

        fn create_key(&self, _alias: &str) -> Result<HardwareBacking, ProtectorError> {
            let mut state = self.state.borrow_mut();
            state.key_present = true;
            Ok(state.hardware)
        }

        fn inspect_key(&self, _alias: &str) -> Result<HardwareBacking, ProtectorError> {
            let state = self.state.borrow();
            if state.key_present {
                Ok(state.hardware)
            } else {
                Err(ProtectorError::ItemMissing)
            }
        }

        fn seal(&self, _alias: &str, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
            if !self.state.borrow().key_present {
                return Err(ProtectorError::ItemMissing);
            }
            Ok(plaintext.to_vec())
        }

        fn open(&self, _alias: &str, ciphertext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
            let state = self.state.borrow();
            if let Some(error) = state.open_error {
                return Err(error);
            }
            if !state.key_present {
                return Err(ProtectorError::ItemMissing);
            }
            Ok(ciphertext.to_vec())
        }

        fn read_record(&self, _record_name: &str) -> Result<Vec<u8>, ProtectorError> {
            self.state
                .borrow()
                .record
                .clone()
                .ok_or(ProtectorError::ItemMissing)
        }

        fn write_record(
            &self,
            _record_name: &str,
            ciphertext: &[u8],
        ) -> Result<(), ProtectorError> {
            self.state.borrow_mut().record = Some(ciphertext.to_vec());
            Ok(())
        }

        fn delete_record(&self, _record_name: &str) -> Result<(), ProtectorError> {
            let mut state = self.state.borrow_mut();
            if let Some(error) = state.delete_record_error.take() {
                return Err(error);
            }
            state
                .record
                .take()
                .map(|_| ())
                .ok_or(ProtectorError::ItemMissing)
        }

        fn delete_key(&self, _alias: &str) -> Result<(), ProtectorError> {
            let mut state = self.state.borrow_mut();
            if let Some(error) = state.delete_key_error.take() {
                return Err(error);
            }
            if !state.key_present {
                return Err(ProtectorError::ItemMissing);
            }
            state.key_present = false;
            Ok(())
        }
    }

    fn fixture(
        hardware: HardwareBacking,
    ) -> (
        AndroidKeystoreProtector<MemoryBackend>,
        VaultId,
        KeyGeneration,
    ) {
        let config = AndroidKeystoreConfig::from_persisted_id(
            PACKAGE,
            AndroidProtectorId::from_bytes([0xA5; 16]),
        )
        .expect("valid Android config");
        let backend = MemoryBackend::new(PACKAGE, hardware);
        let protector =
            AndroidKeystoreProtector::new(config, backend).expect("matching package must bind");
        let vault = VaultId::from_bytes([0x41; VAULT_ID_BYTES]);
        let generation = KeyGeneration::new(1).expect("non-zero generation");
        (protector, vault, generation)
    }

    #[test]
    fn config_rejects_empty_or_nul_package_and_uses_opaque_names() {
        let id = AndroidProtectorId::from_bytes([0xAB; 16]);
        assert_eq!(
            AndroidKeystoreConfig::from_persisted_id("", id),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            AndroidKeystoreConfig::from_persisted_id("com.example\0bad", id),
            Err(ProtectorError::UnsupportedPolicy)
        );
        let config = AndroidKeystoreConfig::from_persisted_id(PACKAGE, id).expect("valid");
        assert_eq!(
            config.alias(),
            "safeevidence.vault.protector.v1.abababababababababababababababab"
        );
        assert_eq!(
            config.record_name(),
            "safeevidence-vault-protector-v1-abababababababababababababababab.bin"
        );
        assert!(!config.alias().contains("41414141"));
    }

    #[test]
    fn fresh_config_persists_identifier_and_distinct_ids_separate_namespaces() {
        let fresh = AndroidKeystoreConfig::new(PACKAGE).expect("fresh config");
        let persisted = *fresh.protector_id().as_bytes();
        let restored = AndroidKeystoreConfig::from_persisted_id(
            PACKAGE,
            AndroidProtectorId::from_bytes(persisted),
        )
        .expect("persisted config");
        assert_eq!(fresh, restored);

        let other = AndroidKeystoreConfig::from_persisted_id(
            PACKAGE,
            AndroidProtectorId::from_bytes([0xCD; 16]),
        )
        .expect("other config");
        assert_ne!(fresh.alias(), other.alias());
        assert_ne!(fresh.record_name(), other.record_name());
    }

    #[test]
    fn package_or_uid_environment_mismatch_fails_closed() {
        let config = AndroidKeystoreConfig::from_persisted_id(
            PACKAGE,
            AndroidProtectorId::from_bytes([7; 16]),
        )
        .expect("valid config");
        let backend = MemoryBackend::new("com.foreign.app", HardwareBacking::Unknown);
        assert!(matches!(
            AndroidKeystoreProtector::new(config, backend),
            Err(ProtectorError::OwnerMismatch)
        ));
    }

    #[test]
    fn app_exclusive_not_required_round_trip_and_hardware_reporting() {
        let (mut protector, vault, generation) = fixture(HardwareBacking::HardwareBacked);
        protector
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("baseline policy must create");
        assert_eq!(protector.actual_access_scope(), AccessScope::AppExclusive);
        assert!(!protector.requires_user_presence());
        assert_eq!(
            protector.hardware_backed_state(),
            HardwareBacking::HardwareBacked
        );

        let vrk = OwnedKeyMaterial::from_bytes([0x5A; 32]);
        protector
            .protect_or_store_vrk(vault, generation, &vrk)
            .expect("VRK must be protected");
        let unlocked = protector
            .unlock_vrk(vault, generation)
            .expect("matching record must unlock");
        unlocked.with_bytes(|bytes| assert_eq!(bytes, &[0x5A; 32]));
    }

    #[test]
    fn process_restart_reconfigures_policy_then_unlocks_existing_record() {
        let config = AndroidKeystoreConfig::from_persisted_id(
            PACKAGE,
            AndroidProtectorId::from_bytes([0xA5; 16]),
        )
        .expect("valid config");
        let backend = MemoryBackend::new(PACKAGE, HardwareBacking::SoftwareBacked);
        let mut first = AndroidKeystoreProtector::new(config.clone(), backend.clone())
            .expect("first process environment");
        let vault = VaultId::from_bytes([0x41; VAULT_ID_BYTES]);
        let generation = KeyGeneration::new(1).expect("non-zero generation");
        first
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("initial policy");
        first
            .protect_or_store_vrk(vault, generation, &OwnedKeyMaterial::from_bytes([0x77; 32]))
            .expect("initial store");
        drop(first);

        let mut restarted =
            AndroidKeystoreProtector::new(config, backend).expect("restarted process environment");
        assert!(matches!(
            restarted.unlock_vrk(vault, generation),
            Err(ProtectorError::UnsupportedPolicy)
        ));
        restarted
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("restart must reconfigure policy without replacing the existing key");
        let unlocked = restarted
            .unlock_vrk(vault, generation)
            .expect("restart unlock must recover only through the protector");
        unlocked.with_bytes(|bytes| assert_eq!(bytes, &[0x77; 32]));
    }

    #[test]
    fn orphaned_record_never_recreates_a_missing_native_key() {
        let config = AndroidKeystoreConfig::from_persisted_id(
            PACKAGE,
            AndroidProtectorId::from_bytes([0x44; 16]),
        )
        .expect("valid config");
        let backend = MemoryBackend::new(PACKAGE, HardwareBacking::Unknown);
        backend.state.borrow_mut().record = Some(vec![0xA5; 48]);
        let mut protector =
            AndroidKeystoreProtector::new(config, backend).expect("matching package must bind");
        assert_eq!(
            protector.create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired),
            Err(ProtectorError::Invalidated)
        );
        assert!(!protector.backend.state.borrow().key_present);
    }

    #[test]
    fn hardware_state_is_reported_without_upgrade() {
        for expected in [
            HardwareBacking::Unknown,
            HardwareBacking::SoftwareBacked,
            HardwareBacking::HardwareBacked,
        ] {
            let (mut protector, _vault, _generation) = fixture(expected);
            protector
                .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
                .expect("baseline policy");
            assert_eq!(protector.hardware_backed_state(), expected);
        }
    }

    #[test]
    fn per_unlock_presence_is_rejected_before_key_creation() {
        let (mut protector, _vault, _generation) = fixture(HardwareBacking::Unknown);
        assert_eq!(
            protector.create_protector(
                AccessScope::AppExclusive,
                UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert!(!protector.backend.state.borrow().key_present);
    }

    #[test]
    fn weaker_scope_request_is_satisfied_by_app_exclusive_enforcement() {
        let (mut protector, _vault, _generation) = fixture(HardwareBacking::SoftwareBacked);
        protector
            .create_protector(
                AccessScope::SameUserAccount,
                UserPresencePolicy::NotRequired,
            )
            .expect("app-exclusive enforcement is stronger than requested same-user scope");
        assert_eq!(protector.actual_access_scope(), AccessScope::AppExclusive);
    }

    #[test]
    fn wrong_vault_and_generation_never_return_vrk() {
        let (mut protector, vault, generation) = fixture(HardwareBacking::Unknown);
        protector
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("create");
        protector
            .protect_or_store_vrk(vault, generation, &OwnedKeyMaterial::from_bytes([3; 32]))
            .expect("store");
        let wrong_vault = VaultId::from_bytes([0x42; VAULT_ID_BYTES]);
        assert!(matches!(
            protector.unlock_vrk(wrong_vault, generation),
            Err(ProtectorError::OwnerMismatch)
        ));
        let generation_two = KeyGeneration::new(2).expect("valid generation");
        assert!(matches!(
            protector.unlock_vrk(vault, generation_two),
            Err(ProtectorError::OwnerMismatch)
        ));
    }

    #[test]
    fn same_generation_rejects_a_different_vrk_without_overwrite() {
        let (mut protector, vault, generation) = fixture(HardwareBacking::Unknown);
        protector
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("create");
        protector
            .protect_or_store_vrk(vault, generation, &OwnedKeyMaterial::from_bytes([0x31; 32]))
            .expect("initial store");
        assert_eq!(
            protector.protect_or_store_vrk(
                vault,
                generation,
                &OwnedKeyMaterial::from_bytes([0x32; 32]),
            ),
            Err(ProtectorError::PolicyMismatch)
        );
        let unlocked = protector
            .unlock_vrk(vault, generation)
            .expect("original VRK remains");
        unlocked.with_bytes(|bytes| assert_eq!(bytes, &[0x31; 32]));
    }

    #[test]
    fn corrupted_record_and_native_invalidation_fail_closed() {
        let (mut protector, vault, generation) = fixture(HardwareBacking::Unknown);
        protector
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("create");
        protector
            .protect_or_store_vrk(vault, generation, &OwnedKeyMaterial::from_bytes([9; 32]))
            .expect("store");
        protector.backend.corrupt_record();
        assert!(matches!(
            protector.unlock_vrk(vault, generation),
            Err(ProtectorError::CorruptOrTampered)
        ));
        protector
            .backend
            .set_open_error(ProtectorError::Invalidated);
        assert!(matches!(
            protector.unlock_vrk(vault, generation),
            Err(ProtectorError::Invalidated)
        ));
    }

    #[test]
    fn wrong_vault_remove_preserves_protector_then_correct_remove_revokes_it() {
        let (mut protector, vault, generation) = fixture(HardwareBacking::Unknown);
        protector
            .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
            .expect("create");
        protector
            .protect_or_store_vrk(vault, generation, &OwnedKeyMaterial::from_bytes([8; 32]))
            .expect("store");
        let wrong_vault = VaultId::from_bytes([0x99; VAULT_ID_BYTES]);
        assert_eq!(
            protector.remove_protector(wrong_vault),
            Err(ProtectorError::OwnerMismatch)
        );
        assert!(protector.unlock_vrk(vault, generation).is_ok());
        protector.remove_protector(vault).expect("correct remove");
        assert!(matches!(
            protector.unlock_vrk(vault, generation),
            Err(ProtectorError::UnsupportedPolicy)
        ));
    }

    #[test]
    fn each_partial_delete_failure_is_retryable() {
        for fail_key in [true, false] {
            let (mut protector, vault, generation) = fixture(HardwareBacking::Unknown);
            protector
                .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
                .unwrap();
            protector
                .protect_or_store_vrk(vault, generation, &OwnedKeyMaterial::from_bytes([0x61; 32]))
                .unwrap();
            if fail_key {
                protector.backend.fail_next_key_delete();
            } else {
                protector.backend.fail_next_record_delete();
            }
            assert_eq!(
                protector.remove_protector(vault),
                Err(ProtectorError::Unavailable)
            );
            assert_eq!(protector.backend.state.borrow().key_present, fail_key);
            assert_eq!(protector.backend.state.borrow().record.is_some(), !fail_key);
            protector
                .remove_protector(vault)
                .expect("retry removes orphaned component");
            assert!(!protector.backend.state.borrow().key_present);
            assert!(protector.backend.state.borrow().record.is_none());
        }
    }

    #[test]
    fn freshness_and_replacement_remain_outside_b402() {
        let (mut protector, vault, _generation) = fixture(HardwareBacking::Unknown);
        assert_eq!(
            protector.read_freshness_anchor(vault),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            protector.replace_protector(vault),
            Err(ProtectorError::UnsupportedPolicy)
        );
    }
}

//! Apple data-protection Keychain adapter for Specification 004B4 B401.
//!
//! The adapter stores a VRK only inside a non-synchronizable, ThisDeviceOnly
//! generic-password item in the target's default application Keychain group. Provider-
//! visible lookup metadata is limited to one fixed SafeEvidence service identifier plus
//! one opaque random protector identifier. Vault identity, key generation,
//! policy binding, and VRK bytes remain inside the protected item value.
//!
//! B501D adds the bounded macOS protected freshness slot and serialized update-only
//! compare-and-set path. Full protector replacement/rotation and non-Apple freshness
//! anchors remain separately authorized leaves.

use crate::vault::{
    AccessScope, FreshnessAnchor, FreshnessEpoch, HardwareBacking, KeyGeneration, ManifestHash,
    ProtectedFreshnessState, ProtectorCapabilities, ProtectorError, SecretProtector,
    UserPresencePolicy, VaultId,
};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use crate::vault_protector::{ProtectorPolicy, validate_requested_policy};
use core_foundation::data::CFData;
use getrandom::fill;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error as SecurityFrameworkError;
use security_framework::item::{
    ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue, update_item,
};
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use zeroize::Zeroizing;

const LEGACY_RECORD_MAGIC: &[u8] = b"HIMSAT/APPLE/VRK/v1\0";
const RECORD_MAGIC: &[u8] = b"HIMSAT/APPLE/PROTECTOR/v2\0";
const PROTECTOR_ID_BYTES: usize = 16;
const LEGACY_RECORD_BYTES: usize = LEGACY_RECORD_MAGIC.len() + 16 + 8 + 1 + 1 + KEY_MATERIAL_BYTES;
const VAULT_OFFSET: usize = RECORD_MAGIC.len();
const GENERATION_OFFSET: usize = VAULT_OFFSET + 16;
const SCOPE_OFFSET: usize = GENERATION_OFFSET + 8;
const PRESENCE_OFFSET: usize = SCOPE_OFFSET + 1;
const FRESHNESS_TAG_OFFSET: usize = PRESENCE_OFFSET + 1;
const FRESHNESS_EPOCH_OFFSET: usize = FRESHNESS_TAG_OFFSET + 1;
const FRESHNESS_HASH_OFFSET: usize = FRESHNESS_EPOCH_OFFSET + 8;
const KEY_OFFSET: usize = FRESHNESS_HASH_OFFSET + 32;
const RECORD_BYTES: usize = KEY_OFFSET + KEY_MATERIAL_BYTES;
const FRESHNESS_UNINITIALIZED: u8 = 0;
const FRESHNESS_PRESENT: u8 = 1;

const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_DECODE: i32 = -26275;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

struct AppleWriterGuard {
    file: File,
}

impl Drop for AppleWriterGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordBinding {
    vault_id: VaultId,
    generation: KeyGeneration,
    policy: ProtectorPolicy,
    freshness: Option<ProtectedFreshnessState>,
    key_offset: usize,
}

/// Opaque provider-visible identifier used as the Keychain account attribute.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AppleProtectorId([u8; PROTECTOR_ID_BYTES]);

impl AppleProtectorId {
    /// Generates a new opaque protector identifier from the reviewed OS CSPRNG.
    pub fn generate() -> Result<Self, ProtectorError> {
        let mut bytes = [0_u8; PROTECTOR_ID_BYTES];
        fill(&mut bytes).map_err(|_| ProtectorError::Unavailable)?;
        Ok(Self(bytes))
    }

    /// Reconstructs a previously persisted opaque protector identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROTECTOR_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque bytes for SafeEvidence-owned metadata persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROTECTOR_ID_BYTES] {
        &self.0
    }

    /// Returns the lowercase hexadecimal Keychain account value.
    #[must_use]
    pub fn account(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(PROTECTOR_ID_BYTES * 2);
        for byte in self.0 {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

impl core::fmt::Debug for AppleProtectorId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AppleProtectorId([OPAQUE; 16 bytes])")
    }
}

/// Apple Keychain protector configuration for the target's default application group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleKeychainConfig {
    service: String,
    protector_id: AppleProtectorId,
}

impl AppleKeychainConfig {
    /// Creates configuration for one fixed SafeEvidence service in the default application group.
    pub fn new(
        service: impl Into<String>,
        protector_id: AppleProtectorId,
    ) -> Result<Self, ProtectorError> {
        let service = service.into();
        if service.is_empty() {
            return Err(ProtectorError::UnsupportedPolicy);
        }
        Ok(Self {
            service,
            protector_id,
        })
    }

    /// Fixed service identifier visible to Keychain.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Opaque provider-visible protector identifier.
    #[must_use]
    pub const fn protector_id(&self) -> AppleProtectorId {
        self.protector_id
    }
}

/// Apple Keychain implementation of the portable `SecretProtector` contract.
pub struct AppleKeychainProtector {
    config: AppleKeychainConfig,
    policy: Option<ProtectorPolicy>,
}

impl AppleKeychainProtector {
    /// Creates an unconfigured conservative macOS adapter.
    #[must_use]
    pub const fn new(config: AppleKeychainConfig) -> Self {
        Self {
            config,
            policy: None,
        }
    }

    /// Returns the immutable native configuration used by this adapter.
    #[must_use]
    pub const fn config(&self) -> &AppleKeychainConfig {
        &self.config
    }

    fn policy(&self) -> Result<ProtectorPolicy, ProtectorError> {
        self.policy.ok_or(ProtectorError::UnsupportedPolicy)
    }

    fn writer_lock_path(&self, vault_id: VaultId) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(b"HIMSAT/APPLE/FRESHNESS/LOCK/v1\0");
        hasher.update(vault_id.as_bytes());
        let digest = hasher.finalize();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut token = String::with_capacity(digest.len() * 2);
        for byte in digest {
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 0x0f) as usize] as char);
        }
        let mut path = std::env::temp_dir();
        path.push(format!("safeevidence-freshness-{token}.lock"));
        path
    }

    fn lock_writer(&self, vault_id: VaultId) -> Result<AppleWriterGuard, ProtectorError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.writer_lock_path(vault_id))
            .map_err(|_| ProtectorError::Unavailable)?;
        file.lock().map_err(|_| ProtectorError::Unavailable)?;
        Ok(AppleWriterGuard { file })
    }

    fn read_record(&self) -> Result<Zeroizing<Vec<u8>>, ProtectorError> {
        self.verify_native_item_attributes()?;
        generic_password(self.read_options())
            .map(Zeroizing::new)
            .map_err(map_security_error)
    }

    fn update_record_value(&self, record: &[u8]) -> Result<(), ProtectorError> {
        let account = self.config.protector_id().account();
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(self.config.service())
            .account(&account)
            .cloud_sync(Some(false))
            .limit(1)
            .ignore_legacy_keychains();
        let mut update = ItemUpdateOptions::new();
        update.set_value(ItemUpdateValue::Data(CFData::from_buffer(record)));
        update_item(&search, &update).map_err(map_security_error)
    }

    fn read_options(&self) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(
            self.config.service(),
            &self.config.protector_id().account(),
        );
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    fn write_options(&self, policy: ProtectorPolicy) -> Result<PasswordOptions, ProtectorError> {
        if policy.user_presence_policy() != UserPresencePolicy::NotRequired {
            return Err(ProtectorError::UnsupportedPolicy);
        }
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            AccessControlOptions::empty().bits(),
        )
        .map_err(map_security_error)?;
        let mut options = self.read_options();
        options.set_access_control(access_control);
        Ok(options)
    }

    fn synchronized_item_exists(&self) -> Result<bool, ProtectorError> {
        let account = self.config.protector_id().account();
        let mut synchronized = ItemSearchOptions::new();
        synchronized
            .class(ItemClass::generic_password())
            .service(self.config.service())
            .account(&account)
            .cloud_sync(Some(true))
            .load_attributes(true)
            .limit(1)
            .ignore_legacy_keychains();
        match synchronized.search() {
            Ok(items) => Ok(!items.is_empty()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(map_security_error(error)),
        }
    }

    fn verify_native_item_attributes(&self) -> Result<(), ProtectorError> {
        let account = self.config.protector_id().account();
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(self.config.service())
            .account(&account)
            .cloud_sync(Some(false))
            .load_attributes(true)
            .limit(1)
            .ignore_legacy_keychains();
        let results = search.search().map_err(map_security_error)?;
        let Some(result) = results.first() else {
            return Err(ProtectorError::ItemMissing);
        };
        let Some(attributes) = result.simplify_dict() else {
            return Err(ProtectorError::CorruptOrTampered);
        };
        if attributes.get("svce").map(String::as_str) != Some(self.config.service())
            || attributes.get("acct").map(String::as_str) != Some(account.as_str())
            || attributes.get("pdmn").map(String::as_str) != Some("akpu")
        {
            return Err(ProtectorError::PolicyMismatch);
        }

        if self.synchronized_item_exists()? {
            return Err(ProtectorError::PolicyMismatch);
        }
        Ok(())
    }
}

impl SecretProtector for AppleKeychainProtector {
    type VaultRootKey = OwnedKeyMaterial;

    fn create_protector(
        &mut self,
        requested_scope: AccessScope,
        user_presence_policy: UserPresencePolicy,
    ) -> Result<(), ProtectorError> {
        let policy = ProtectorPolicy::new(requested_scope, user_presence_policy);
        validate_requested_policy(
            ProtectorCapabilities::new(
                AccessScope::SameUserAccount,
                false,
                HardwareBacking::Unknown,
            ),
            policy,
        )?;
        self.write_options(policy)?;
        self.policy = Some(policy);
        Ok(())
    }

    fn protect_or_store_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
        vrk: &Self::VaultRootKey,
    ) -> Result<(), ProtectorError> {
        let policy = self.policy()?;
        let _guard = self.lock_writer(vault_id)?;
        if self.synchronized_item_exists()? {
            return Err(ProtectorError::PolicyMismatch);
        }

        let existing_freshness = match generic_password(self.read_options()) {
            Ok(existing) => {
                let existing = Zeroizing::new(existing);
                self.verify_native_item_attributes()?;
                let binding =
                    validate_record_binding(&existing, vault_id, Some(key_generation), policy)?;
                Some(binding.freshness)
            }
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => None,
            Err(error) => return Err(map_security_error(error)),
        };

        let options = self.write_options(policy)?;
        let record = Zeroizing::new(match existing_freshness {
            None => encode_record(vault_id, key_generation, policy, vrk).to_vec(),
            Some(Some(freshness)) => {
                encode_record_with_freshness(vault_id, key_generation, policy, freshness, vrk)
                    .to_vec()
            }
            Some(None) => encode_legacy_record(vault_id, key_generation, policy, vrk).to_vec(),
        });
        set_generic_password_options(&record[..], options).map_err(map_security_error)
    }

    fn unlock_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
    ) -> Result<Self::VaultRootKey, ProtectorError> {
        let policy = self.policy()?;
        self.verify_native_item_attributes()?;
        let record =
            Zeroizing::new(generic_password(self.read_options()).map_err(map_security_error)?);
        decode_record(&record, vault_id, key_generation, policy)
    }

    fn read_freshness_anchor(
        &self,
        vault_id: VaultId,
    ) -> Result<ProtectedFreshnessState, ProtectorError> {
        let policy = self.policy()?;
        let record = self.read_record()?;
        let binding = validate_record_binding(&record, vault_id, None, policy)?;
        binding.freshness.ok_or(ProtectorError::UnsupportedPolicy)
    }

    fn install_genesis_freshness_anchor(
        &mut self,
        vault_id: VaultId,
        expected_state: ProtectedFreshnessState,
        new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        if expected_state != ProtectedFreshnessState::Uninitialized {
            return Err(ProtectorError::AnchorConflict);
        }
        if new_anchor.vault_id() != vault_id {
            return Err(ProtectorError::CorruptOrTampered);
        }
        let policy = self.policy()?;
        let _guard = self
            .lock_writer(vault_id)
            .map_err(|_| ProtectorError::AnchorGenesisFailed)?;
        let record = self.read_record()?;
        let binding = validate_record_binding(&record, vault_id, None, policy)?;
        match binding.freshness {
            None => return Err(ProtectorError::UnsupportedPolicy),
            Some(ProtectedFreshnessState::Present(_)) => {
                return Err(ProtectorError::AnchorAlreadyInitialized);
            }
            Some(ProtectedFreshnessState::Uninitialized) => {}
        }
        let replacement =
            record_with_freshness(&record, ProtectedFreshnessState::Present(new_anchor))?;
        match self.update_record_value(&replacement[..]) {
            Ok(()) => {}
            Err(_) => return Err(ProtectorError::AnchorGenesisFailed),
        }
        let reread = self
            .read_record()
            .map_err(|_| ProtectorError::AnchorGenesisFailed)?;
        let reread_binding = validate_record_binding(&reread, vault_id, None, policy)
            .map_err(|_| ProtectorError::AnchorGenesisFailed)?;
        if reread_binding.freshness != Some(ProtectedFreshnessState::Present(new_anchor)) {
            return Err(ProtectorError::AnchorGenesisFailed);
        }
        Ok(())
    }

    fn advance_freshness_anchor(
        &mut self,
        vault_id: VaultId,
        expected_old: FreshnessAnchor,
        new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        if expected_old.vault_id() != vault_id || new_anchor.vault_id() != vault_id {
            return Err(ProtectorError::CorruptOrTampered);
        }
        let expected_epoch = expected_old
            .highest_epoch()
            .get()
            .checked_add(1)
            .ok_or(ProtectorError::AnchorConflict)?;
        if new_anchor.highest_epoch().get() != expected_epoch {
            return Err(ProtectorError::AnchorConflict);
        }
        let policy = self.policy()?;
        let _guard = self
            .lock_writer(vault_id)
            .map_err(|_| ProtectorError::AnchorUpdateFailed)?;
        let record = self.read_record()?;
        let binding = validate_record_binding(&record, vault_id, None, policy)?;
        match binding.freshness {
            None => return Err(ProtectorError::UnsupportedPolicy),
            Some(ProtectedFreshnessState::Uninitialized) => {
                return Err(ProtectorError::AnchorConflict);
            }
            Some(ProtectedFreshnessState::Present(current)) if current != expected_old => {
                return Err(ProtectorError::AnchorConflict);
            }
            Some(ProtectedFreshnessState::Present(_)) => {}
        }
        let replacement =
            record_with_freshness(&record, ProtectedFreshnessState::Present(new_anchor))?;
        match self.update_record_value(&replacement[..]) {
            Ok(()) => {}
            Err(_) => return Err(ProtectorError::AnchorUpdateFailed),
        }
        let reread = self
            .read_record()
            .map_err(|_| ProtectorError::AnchorUpdateFailed)?;
        let reread_binding = validate_record_binding(&reread, vault_id, None, policy)
            .map_err(|_| ProtectorError::AnchorUpdateFailed)?;
        if reread_binding.freshness != Some(ProtectedFreshnessState::Present(new_anchor)) {
            return Err(ProtectorError::AnchorUpdateFailed);
        }
        Ok(())
    }

    fn replace_protector(&mut self, _vault_id: VaultId) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn remove_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError> {
        let policy = self.policy()?;
        let _guard = self.lock_writer(vault_id)?;
        self.verify_native_item_attributes()?;
        let record =
            Zeroizing::new(generic_password(self.read_options()).map_err(map_security_error)?);
        validate_record_binding(&record, vault_id, None, policy)?;
        delete_generic_password_options(self.read_options()).map_err(map_security_error)?;
        self.policy = None;
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

fn encode_record(
    vault_id: VaultId,
    key_generation: KeyGeneration,
    policy: ProtectorPolicy,
    vrk: &OwnedKeyMaterial,
) -> [u8; RECORD_BYTES] {
    encode_record_with_freshness(
        vault_id,
        key_generation,
        policy,
        ProtectedFreshnessState::Uninitialized,
        vrk,
    )
}

fn encode_record_with_freshness(
    vault_id: VaultId,
    key_generation: KeyGeneration,
    policy: ProtectorPolicy,
    freshness: ProtectedFreshnessState,
    vrk: &OwnedKeyMaterial,
) -> [u8; RECORD_BYTES] {
    let mut output = [0_u8; RECORD_BYTES];
    output[..RECORD_MAGIC.len()].copy_from_slice(RECORD_MAGIC);
    output[VAULT_OFFSET..GENERATION_OFFSET].copy_from_slice(vault_id.as_bytes());
    output[GENERATION_OFFSET..SCOPE_OFFSET].copy_from_slice(&key_generation.get().to_be_bytes());
    output[SCOPE_OFFSET] = encode_scope(policy.access_scope());
    output[PRESENCE_OFFSET] = encode_presence(policy.user_presence_policy());
    write_freshness_fields(&mut output, freshness);
    vrk.with_bytes(|bytes| output[KEY_OFFSET..].copy_from_slice(bytes));
    output
}

fn encode_legacy_record(
    vault_id: VaultId,
    key_generation: KeyGeneration,
    policy: ProtectorPolicy,
    vrk: &OwnedKeyMaterial,
) -> [u8; LEGACY_RECORD_BYTES] {
    let mut output = [0_u8; LEGACY_RECORD_BYTES];
    let mut offset = 0;
    output[offset..offset + LEGACY_RECORD_MAGIC.len()].copy_from_slice(LEGACY_RECORD_MAGIC);
    offset += LEGACY_RECORD_MAGIC.len();
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

fn write_freshness_fields(output: &mut [u8; RECORD_BYTES], state: ProtectedFreshnessState) {
    output[FRESHNESS_TAG_OFFSET..KEY_OFFSET].fill(0);
    match state {
        ProtectedFreshnessState::Uninitialized => {
            output[FRESHNESS_TAG_OFFSET] = FRESHNESS_UNINITIALIZED;
        }
        ProtectedFreshnessState::Present(anchor) => {
            output[FRESHNESS_TAG_OFFSET] = FRESHNESS_PRESENT;
            output[FRESHNESS_EPOCH_OFFSET..FRESHNESS_HASH_OFFSET]
                .copy_from_slice(&anchor.highest_epoch().get().to_be_bytes());
            output[FRESHNESS_HASH_OFFSET..KEY_OFFSET]
                .copy_from_slice(anchor.manifest_hash().as_bytes());
        }
    }
}

fn record_binding(record: &[u8]) -> Result<RecordBinding, ProtectorError> {
    let (magic_len, is_current) =
        if record.len() == RECORD_BYTES && record.starts_with(RECORD_MAGIC) {
            (RECORD_MAGIC.len(), true)
        } else if record.len() == LEGACY_RECORD_BYTES && record.starts_with(LEGACY_RECORD_MAGIC) {
            (LEGACY_RECORD_MAGIC.len(), false)
        } else {
            return Err(ProtectorError::CorruptOrTampered);
        };

    let mut offset = magic_len;
    let vault_id = VaultId::try_from_slice(&record[offset..offset + 16])
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 16;
    let generation_bytes: [u8; 8] = record[offset..offset + 8]
        .try_into()
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    let generation = KeyGeneration::new(u64::from_be_bytes(generation_bytes))
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 8;
    let policy = ProtectorPolicy::new(
        decode_scope(record[offset])?,
        decode_presence(record[offset + 1])?,
    );
    offset += 2;

    let (freshness, key_offset) = if is_current {
        let tag = record[offset];
        let epoch_bytes: [u8; 8] = record[offset + 1..offset + 9]
            .try_into()
            .map_err(|_| ProtectorError::CorruptOrTampered)?;
        let hash_slice = &record[offset + 9..offset + 41];
        let state = match tag {
            FRESHNESS_UNINITIALIZED => {
                if epoch_bytes != [0; 8] || hash_slice != [0; 32] {
                    return Err(ProtectorError::CorruptOrTampered);
                }
                ProtectedFreshnessState::Uninitialized
            }
            FRESHNESS_PRESENT => {
                let epoch = FreshnessEpoch::new(u64::from_be_bytes(epoch_bytes))
                    .map_err(|_| ProtectorError::CorruptOrTampered)?;
                let hash = ManifestHash::try_from_slice(hash_slice)
                    .map_err(|_| ProtectorError::CorruptOrTampered)?;
                ProtectedFreshnessState::Present(FreshnessAnchor::new(vault_id, epoch, hash))
            }
            _ => return Err(ProtectorError::CorruptOrTampered),
        };
        (Some(state), offset + 41)
    } else {
        (None, offset)
    };

    if key_offset + KEY_MATERIAL_BYTES != record.len() {
        return Err(ProtectorError::CorruptOrTampered);
    }
    Ok(RecordBinding {
        vault_id,
        generation,
        policy,
        freshness,
        key_offset,
    })
}

fn validate_record_binding(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: Option<KeyGeneration>,
    expected_policy: ProtectorPolicy,
) -> Result<RecordBinding, ProtectorError> {
    let binding = record_binding(record)?;
    if binding.vault_id != expected_vault_id
        || expected_generation.is_some_and(|generation| binding.generation != generation)
    {
        return Err(ProtectorError::OwnerMismatch);
    }
    if binding.policy != expected_policy {
        return Err(ProtectorError::PolicyMismatch);
    }
    Ok(binding)
}

fn record_with_freshness(
    record: &[u8],
    state: ProtectedFreshnessState,
) -> Result<Zeroizing<[u8; RECORD_BYTES]>, ProtectorError> {
    let binding = record_binding(record)?;
    if binding.freshness.is_none() || record.len() != RECORD_BYTES {
        return Err(ProtectorError::UnsupportedPolicy);
    }
    if matches!(state, ProtectedFreshnessState::Present(anchor) if anchor.vault_id() != binding.vault_id)
    {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let mut output = [0_u8; RECORD_BYTES];
    output.copy_from_slice(record);
    write_freshness_fields(&mut output, state);
    Ok(Zeroizing::new(output))
}

fn decode_record(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: KeyGeneration,
    expected_policy: ProtectorPolicy,
) -> Result<OwnedKeyMaterial, ProtectorError> {
    let binding = validate_record_binding(
        record,
        expected_vault_id,
        Some(expected_generation),
        expected_policy,
    )?;
    let key: [u8; KEY_MATERIAL_BYTES] = record[binding.key_offset..]
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

fn map_security_error(error: SecurityFrameworkError) -> ProtectorError {
    match error.code() {
        ERR_SEC_ITEM_NOT_FOUND => ProtectorError::ItemMissing,
        ERR_SEC_AUTH_FAILED | ERR_SEC_USER_CANCELED => ProtectorError::Denied,
        ERR_SEC_INTERACTION_NOT_ALLOWED => ProtectorError::Locked,
        ERR_SEC_MISSING_ENTITLEMENT => ProtectorError::OwnerMismatch,
        ERR_SEC_DECODE => ProtectorError::Invalidated,
        ERR_SEC_NOT_AVAILABLE => ProtectorError::Unavailable,
        _ => ProtectorError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppleKeychainConfig, AppleKeychainProtector, AppleProtectorId, FRESHNESS_EPOCH_OFFSET,
        FRESHNESS_HASH_OFFSET, FRESHNESS_TAG_OFFSET, RECORD_MAGIC, decode_record,
        encode_legacy_record, encode_record, map_security_error, record_binding,
        record_with_freshness, validate_record_binding,
    };
    use crate::vault::{
        AccessScope, FreshnessAnchor, FreshnessEpoch, KeyGeneration, ManifestHash,
        ProtectedFreshnessState, ProtectorError, SecretProtector, UserPresencePolicy,
        VAULT_ID_BYTES, VaultId,
    };
    use crate::vault_keys::OwnedKeyMaterial;
    use crate::vault_protector::ProtectorPolicy;
    use security_framework::base::Error as SecurityFrameworkError;

    fn vault(byte: u8) -> VaultId {
        VaultId::from_bytes([byte; VAULT_ID_BYTES])
    }

    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).expect("non-zero generation")
    }

    #[test]
    fn opaque_identifier_never_embeds_vault_or_generation() {
        let id = AppleProtectorId::from_bytes([0xa5; 16]);
        assert_eq!(id.account(), "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
        assert_eq!(format!("{id:?}"), "AppleProtectorId([OPAQUE; 16 bytes])");
    }

    #[test]
    fn configuration_rejects_empty_application_metadata() {
        let id = AppleProtectorId::from_bytes([1; 16]);
        assert_eq!(
            AppleKeychainConfig::new("", id),
            Err(ProtectorError::UnsupportedPolicy)
        );
    }

    #[test]
    fn conservative_policy_rejects_unproven_scope_and_presence() {
        let config = AppleKeychainConfig::new(
            "com.thehalfmoon.safeevidence.b401.test",
            AppleProtectorId::from_bytes([2; 16]),
        )
        .expect("valid fixed service");
        let mut protector = AppleKeychainProtector::new(config);
        assert_eq!(
            protector.create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired,),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            protector.create_protector(
                AccessScope::SameUserAccount,
                UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            protector.actual_access_scope(),
            AccessScope::SameUserAccount
        );
        assert!(!protector.requires_user_presence());
    }

    #[test]
    fn protected_record_binds_vault_generation_and_policy() {
        let vrk = OwnedKeyMaterial::from_bytes([0x5a; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::AppExclusive,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        let encoded = encode_record(vault(0x11), generation(7), policy, &vrk);
        assert!(decode_record(&encoded, vault(0x11), generation(7), policy).is_ok());
        assert!(matches!(
            decode_record(&encoded, vault(0x12), generation(7), policy),
            Err(ProtectorError::OwnerMismatch)
        ));
        assert!(matches!(
            decode_record(&encoded, vault(0x11), generation(8), policy),
            Err(ProtectorError::OwnerMismatch)
        ));
        let weaker =
            ProtectorPolicy::new(AccessScope::AppExclusive, UserPresencePolicy::NotRequired);
        assert!(matches!(
            decode_record(&encoded, vault(0x11), generation(7), weaker),
            Err(ProtectorError::PolicyMismatch)
        ));
    }

    #[test]
    fn stored_record_binding_rejects_cross_vault_generation_and_policy_reuse() {
        let vrk = OwnedKeyMaterial::from_bytes([0x44; 32]);
        let policy =
            ProtectorPolicy::new(AccessScope::AppExclusive, UserPresencePolicy::NotRequired);
        let encoded = encode_record(vault(0x31), generation(5), policy, &vrk);

        assert!(
            validate_record_binding(&encoded, vault(0x31), Some(generation(5)), policy).is_ok()
        );
        assert_eq!(
            validate_record_binding(&encoded, vault(0x32), Some(generation(5)), policy),
            Err(ProtectorError::OwnerMismatch)
        );
        assert_eq!(
            validate_record_binding(&encoded, vault(0x31), Some(generation(6)), policy),
            Err(ProtectorError::OwnerMismatch)
        );
        let stronger = ProtectorPolicy::new(
            AccessScope::AppExclusive,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        assert_eq!(
            validate_record_binding(&encoded, vault(0x31), Some(generation(5)), stronger),
            Err(ProtectorError::PolicyMismatch)
        );

        // Removal deliberately omits generation matching but still binds vault and policy.
        assert!(validate_record_binding(&encoded, vault(0x31), None, policy).is_ok());
        assert_eq!(
            validate_record_binding(&encoded, vault(0x32), None, policy),
            Err(ProtectorError::OwnerMismatch)
        );
    }

    #[test]
    fn protected_record_rejects_corruption() {
        let vrk = OwnedKeyMaterial::from_bytes([0x7c; 32]);
        let policy =
            ProtectorPolicy::new(AccessScope::AppExclusive, UserPresencePolicy::NotRequired);
        let mut encoded = encode_record(vault(0x21), generation(3), policy, &vrk);
        encoded[0] ^= 1;
        assert!(matches!(
            decode_record(&encoded, vault(0x21), generation(3), policy),
            Err(ProtectorError::CorruptOrTampered)
        ));

        let scope_offset = RECORD_MAGIC.len() + 16 + 8;
        let mut bad_scope = encode_record(vault(0x21), generation(3), policy, &vrk);
        bad_scope[scope_offset] = 9;
        assert!(matches!(
            decode_record(&bad_scope, vault(0x21), generation(3), policy),
            Err(ProtectorError::CorruptOrTampered)
        ));

        let mut bad_presence = encode_record(vault(0x21), generation(3), policy, &vrk);
        bad_presence[scope_offset + 1] = 9;
        assert!(matches!(
            decode_record(&bad_presence, vault(0x21), generation(3), policy),
            Err(ProtectorError::CorruptOrTampered)
        ));
    }

    #[test]
    fn protected_record_has_explicit_uninitialized_freshness() {
        let vrk = OwnedKeyMaterial::from_bytes([0x6a; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::NotRequired,
        );
        let encoded = encode_record(vault(0x41), generation(2), policy, &vrk);
        let binding = record_binding(&encoded).expect("current protected record");
        assert_eq!(binding.vault_id, vault(0x41));
        assert_eq!(
            binding.freshness,
            Some(ProtectedFreshnessState::Uninitialized)
        );
    }

    #[test]
    fn legacy_record_never_becomes_implicit_genesis_state() {
        let vrk = OwnedKeyMaterial::from_bytes([0x6b; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::NotRequired,
        );
        let legacy = encode_legacy_record(vault(0x42), generation(2), policy, &vrk);
        let binding = record_binding(&legacy).expect("legacy record remains readable");
        assert_eq!(binding.freshness, None);
        let anchor = FreshnessAnchor::new(
            vault(0x42),
            FreshnessEpoch::new(1).expect("epoch"),
            ManifestHash::from_bytes([0x55; 32]),
        );
        assert_eq!(
            record_with_freshness(&legacy, ProtectedFreshnessState::Present(anchor)),
            Err(ProtectorError::UnsupportedPolicy)
        );
    }

    #[test]
    fn freshness_encoding_is_canonical_and_vault_bound() {
        let vrk = OwnedKeyMaterial::from_bytes([0x6c; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::NotRequired,
        );
        let encoded = encode_record(vault(0x43), generation(4), policy, &vrk);
        let anchor = FreshnessAnchor::new(
            vault(0x43),
            FreshnessEpoch::new(7).expect("epoch"),
            ManifestHash::from_bytes([0x77; 32]),
        );
        let updated = record_with_freshness(&encoded, ProtectedFreshnessState::Present(anchor))
            .expect("current record supports freshness");
        let binding = record_binding(&updated[..]).expect("updated binding");
        assert_eq!(
            binding.freshness,
            Some(ProtectedFreshnessState::Present(anchor))
        );

        let wrong_vault_anchor = FreshnessAnchor::new(
            vault(0x44),
            FreshnessEpoch::new(8).expect("epoch"),
            ManifestHash::from_bytes([0x88; 32]),
        );
        assert_eq!(
            record_with_freshness(
                &updated[..],
                ProtectedFreshnessState::Present(wrong_vault_anchor),
            ),
            Err(ProtectorError::CorruptOrTampered)
        );
    }

    #[test]
    fn malformed_freshness_fields_fail_closed() {
        let vrk = OwnedKeyMaterial::from_bytes([0x6d; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::NotRequired,
        );
        let encoded = encode_record(vault(0x45), generation(5), policy, &vrk);

        let mut bad_tag = encoded;
        bad_tag[FRESHNESS_TAG_OFFSET] = 9;
        assert_eq!(
            record_binding(&bad_tag),
            Err(ProtectorError::CorruptOrTampered)
        );

        let mut dirty_uninitialized = encoded;
        dirty_uninitialized[FRESHNESS_EPOCH_OFFSET] = 1;
        assert_eq!(
            record_binding(&dirty_uninitialized),
            Err(ProtectorError::CorruptOrTampered)
        );

        let mut zero_present_epoch = encoded;
        zero_present_epoch[FRESHNESS_TAG_OFFSET] = 1;
        zero_present_epoch[FRESHNESS_EPOCH_OFFSET..FRESHNESS_HASH_OFFSET].fill(0);
        assert_eq!(
            record_binding(&zero_present_epoch),
            Err(ProtectorError::CorruptOrTampered)
        );
    }

    #[test]
    fn native_error_mapping_is_fail_closed() {
        assert_eq!(
            map_security_error(SecurityFrameworkError::from_code(-25300)),
            ProtectorError::ItemMissing
        );
        assert_eq!(
            map_security_error(SecurityFrameworkError::from_code(-34018)),
            ProtectorError::OwnerMismatch
        );
        assert_eq!(
            map_security_error(SecurityFrameworkError::from_code(-25308)),
            ProtectorError::Locked
        );
        assert_eq!(
            map_security_error(SecurityFrameworkError::from_code(-128)),
            ProtectorError::Denied
        );
        assert_eq!(
            map_security_error(SecurityFrameworkError::from_code(-50)),
            ProtectorError::Unavailable
        );
    }
}

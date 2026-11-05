//! Linux Secret Service adapter for Specification 004B4 B404.
//!
//! The adapter uses only the default Secret Service collection and negotiates
//! the encrypted Diffie-Hellman session. Provider-visible metadata is limited
//! to one fixed SafeEvidence application identifier, one fixed item label/content
//! type, and one opaque random protector identifier. Vault identity, key
//! generation, policy binding, and VRK bytes remain inside the secret value.
//!
//! The baseline reports `SAME_USER_SESSION`, no per-SafeEvidence-unlock user
//! presence, and unknown hardware backing. It never auto-unlocks a locked
//! collection/item, never uses the plaintext Secret Service session, and does
//! not implement freshness-anchor or protector-replacement semantics.

use crate::vault::{
    AccessScope, FreshnessAnchor, HardwareBacking, KeyGeneration, ProtectedFreshnessState,
    ProtectorCapabilities, ProtectorError, SecretProtector, UserPresencePolicy, VaultId,
};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use crate::vault_protector::{ProtectorPolicy, validate_requested_policy};
use getrandom::fill;
use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error as SecretServiceError};
use std::collections::HashMap;
use zeroize::Zeroizing;

const APPLICATION_ATTRIBUTE: &str = "application";
const APPLICATION_ID: &str = "com.thehalfmoon.safeevidence";
const PROTECTOR_ATTRIBUTE: &str = "protector-id";
const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
const SCHEMA_ID: &str = "com.thehalfmoon.safeevidence";
const ITEM_LABEL: &str = "SafeEvidence Vault Protector";
const CONTENT_TYPE: &str = "application/octet-stream";
const RECORD_MAGIC: &[u8] = b"HIMSAT/LINUX/SECRET-SERVICE/VRK/v1\0";
const OWNER_TAG: &[u8] = b"HIMSAT/APP/v1\0";
const PROTECTOR_ID_BYTES: usize = 16;
const RECORD_BYTES: usize =
    RECORD_MAGIC.len() + OWNER_TAG.len() + 16 + 8 + 1 + 1 + KEY_MATERIAL_BYTES;

/// Opaque provider-visible identifier used only as a Secret Service attribute.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LinuxProtectorId([u8; PROTECTOR_ID_BYTES]);

impl LinuxProtectorId {
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

    fn attribute_value(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(PROTECTOR_ID_BYTES * 2);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl core::fmt::Debug for LinuxProtectorId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("LinuxProtectorId([OPAQUE; 16 bytes])")
    }
}

/// Immutable Linux Secret Service configuration for one opaque protector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSecretServiceConfig {
    protector_id: LinuxProtectorId,
}

impl LinuxSecretServiceConfig {
    /// Creates configuration for one opaque Secret Service protector item.
    #[must_use]
    pub const fn new(protector_id: LinuxProtectorId) -> Self {
        Self { protector_id }
    }

    /// Returns the opaque provider lookup identifier.
    #[must_use]
    pub const fn protector_id(self) -> LinuxProtectorId {
        self.protector_id
    }
}

/// Linux Secret Service implementation of the portable `SecretProtector` contract.
pub struct LinuxSecretServiceProtector {
    config: LinuxSecretServiceConfig,
    policy: Option<ProtectorPolicy>,
}

impl LinuxSecretServiceProtector {
    /// Creates an unconfigured conservative Linux adapter.
    #[must_use]
    pub const fn new(config: LinuxSecretServiceConfig) -> Self {
        Self {
            config,
            policy: None,
        }
    }

    /// Returns the immutable native configuration used by this adapter.
    #[must_use]
    pub const fn config(&self) -> LinuxSecretServiceConfig {
        self.config
    }

    fn policy(&self) -> Result<ProtectorPolicy, ProtectorError> {
        self.policy.ok_or(ProtectorError::UnsupportedPolicy)
    }

    fn find_single_item<'a>(
        &self,
        collection: &'a Collection<'a>,
    ) -> Result<Option<Item<'a>>, ProtectorError> {
        let protector_id = self.config.protector_id().attribute_value();
        let mut items = collection
            .search_items(query_attributes(&protector_id))
            .map_err(map_secret_service_error)?;
        match items.len() {
            0 => Ok(None),
            1 => Ok(items.pop()),
            _ => Err(ProtectorError::CorruptOrTampered),
        }
    }

    fn verify_item(&self, item: &Item<'_>) -> Result<(), ProtectorError> {
        if item.is_locked().map_err(map_secret_service_error)? {
            return Err(ProtectorError::Locked);
        }
        let protector_id = self.config.protector_id().attribute_value();
        let attributes = item.get_attributes().map_err(map_secret_service_error)?;
        if attributes.len() != 3
            || attributes.get(APPLICATION_ATTRIBUTE).map(String::as_str) != Some(APPLICATION_ID)
            || attributes.get(SCHEMA_ATTRIBUTE).map(String::as_str) != Some(SCHEMA_ID)
            || attributes.get(PROTECTOR_ATTRIBUTE).map(String::as_str)
                != Some(protector_id.as_str())
        {
            return Err(ProtectorError::OwnerMismatch);
        }
        if item.get_label().map_err(map_secret_service_error)? != ITEM_LABEL {
            return Err(ProtectorError::PolicyMismatch);
        }
        Ok(())
    }

    fn read_record(&self, item: &Item<'_>) -> Result<Zeroizing<Vec<u8>>, ProtectorError> {
        self.verify_item(item)?;
        let record = Zeroizing::new(item.get_secret().map_err(map_secret_service_error)?);
        if record.len() != RECORD_BYTES {
            return Err(ProtectorError::CorruptOrTampered);
        }
        Ok(record)
    }
}

impl SecretProtector for LinuxSecretServiceProtector {
    type VaultRootKey = OwnedKeyMaterial;

    fn create_protector(
        &mut self,
        requested_scope: AccessScope,
        user_presence_policy: UserPresencePolicy,
    ) -> Result<(), ProtectorError> {
        let policy = validate_linux_policy(requested_scope, user_presence_policy)?;
        let service =
            SecretService::connect(session_encryption()).map_err(map_secret_service_error)?;
        let collection = service
            .get_default_collection()
            .map_err(map_collection_error)?;
        collection
            .ensure_unlocked()
            .map_err(map_secret_service_error)?;
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
        let service =
            SecretService::connect(session_encryption()).map_err(map_secret_service_error)?;
        let collection = service
            .get_default_collection()
            .map_err(map_collection_error)?;
        collection
            .ensure_unlocked()
            .map_err(map_secret_service_error)?;

        if let Some(item) = self.find_single_item(&collection)? {
            let record = self.read_record(&item)?;
            validate_record_binding(&record, vault_id, Some(key_generation), policy)?;
            return if record_matches_vrk(&record, vrk)? {
                Ok(())
            } else {
                Err(ProtectorError::CorruptOrTampered)
            };
        }

        let record = Zeroizing::new(encode_record(vault_id, key_generation, policy, vrk));
        let protector_id = self.config.protector_id().attribute_value();
        let created = collection
            .create_item(
                ITEM_LABEL,
                query_attributes(&protector_id),
                &record[..],
                false,
                CONTENT_TYPE,
            )
            .map_err(map_secret_service_error)?;
        self.verify_item(&created)?;
        let stored = self.read_record(&created)?;
        validate_record_binding(&stored, vault_id, Some(key_generation), policy)?;
        if !record_matches_vrk(&stored, vrk)? {
            return Err(ProtectorError::CorruptOrTampered);
        }

        let found = self
            .find_single_item(&collection)?
            .ok_or(ProtectorError::ItemMissing)?;
        if found != created {
            return Err(ProtectorError::CorruptOrTampered);
        }
        Ok(())
    }

    fn unlock_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
    ) -> Result<Self::VaultRootKey, ProtectorError> {
        let policy = self.policy()?;
        let service =
            SecretService::connect(session_encryption()).map_err(map_secret_service_error)?;
        let collection = service
            .get_default_collection()
            .map_err(map_collection_error)?;
        collection
            .ensure_unlocked()
            .map_err(map_secret_service_error)?;
        let item = self
            .find_single_item(&collection)?
            .ok_or(ProtectorError::ItemMissing)?;
        let record = self.read_record(&item)?;
        decode_record(&record, vault_id, key_generation, policy)
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
        let service =
            SecretService::connect(session_encryption()).map_err(map_secret_service_error)?;
        let collection = service
            .get_default_collection()
            .map_err(map_collection_error)?;
        collection
            .ensure_unlocked()
            .map_err(map_secret_service_error)?;
        let Some(item) = self.find_single_item(&collection)? else {
            self.policy = None;
            return Ok(());
        };
        let record = self.read_record(&item)?;
        validate_record_binding(&record, vault_id, None, policy)?;
        item.delete().map_err(map_secret_service_error)?;
        if self.find_single_item(&collection)?.is_some() {
            return Err(ProtectorError::CorruptOrTampered);
        }
        self.policy = None;
        Ok(())
    }

    fn actual_access_scope(&self) -> AccessScope {
        AccessScope::SameUserSession
    }

    fn requires_user_presence(&self) -> bool {
        false
    }

    fn hardware_backed_state(&self) -> HardwareBacking {
        HardwareBacking::Unknown
    }
}

fn session_encryption() -> EncryptionType {
    EncryptionType::Dh
}

fn validate_linux_policy(
    requested_scope: AccessScope,
    user_presence_policy: UserPresencePolicy,
) -> Result<ProtectorPolicy, ProtectorError> {
    let policy = ProtectorPolicy::new(requested_scope, user_presence_policy);
    validate_requested_policy(
        ProtectorCapabilities::new(
            AccessScope::SameUserSession,
            false,
            HardwareBacking::Unknown,
        ),
        policy,
    )?;
    Ok(policy)
}

fn query_attributes(protector_id: &str) -> HashMap<&'static str, &str> {
    let mut attributes = HashMap::with_capacity(3);
    attributes.insert(APPLICATION_ATTRIBUTE, APPLICATION_ID);
    attributes.insert(SCHEMA_ATTRIBUTE, SCHEMA_ID);
    attributes.insert(PROTECTOR_ATTRIBUTE, protector_id);
    attributes
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
    output[offset..offset + OWNER_TAG.len()].copy_from_slice(OWNER_TAG);
    offset += OWNER_TAG.len();
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

fn record_binding(
    record: &[u8],
) -> Result<(VaultId, KeyGeneration, ProtectorPolicy), ProtectorError> {
    if record.len() != RECORD_BYTES || !record.starts_with(RECORD_MAGIC) {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let mut offset = RECORD_MAGIC.len();
    if &record[offset..offset + OWNER_TAG.len()] != OWNER_TAG {
        return Err(ProtectorError::CorruptOrTampered);
    }
    offset += OWNER_TAG.len();
    let stored_vault = VaultId::try_from_slice(&record[offset..offset + 16])
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 16;
    let generation_bytes: [u8; 8] = record[offset..offset + 8]
        .try_into()
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    let stored_generation = KeyGeneration::new(u64::from_be_bytes(generation_bytes))
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 8;
    let stored_policy = ProtectorPolicy::new(
        decode_scope(record[offset])?,
        decode_presence(record[offset + 1])?,
    );
    Ok((stored_vault, stored_generation, stored_policy))
}

fn validate_record_binding(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: Option<KeyGeneration>,
    expected_policy: ProtectorPolicy,
) -> Result<(), ProtectorError> {
    let (stored_vault, stored_generation, stored_policy) = record_binding(record)?;
    if stored_vault != expected_vault_id
        || expected_generation.is_some_and(|generation| generation != stored_generation)
    {
        return Err(ProtectorError::OwnerMismatch);
    }
    if stored_policy != expected_policy {
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
    let key: &[u8; KEY_MATERIAL_BYTES] = record[key_offset..]
        .try_into()
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    Ok(OwnedKeyMaterial::from_bytes(*key))
}

fn record_matches_vrk(record: &[u8], expected: &OwnedKeyMaterial) -> Result<bool, ProtectorError> {
    if record.len() != RECORD_BYTES {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let key_offset = RECORD_BYTES - KEY_MATERIAL_BYTES;
    Ok(expected.with_bytes(|bytes| record[key_offset..] == bytes[..]))
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

fn map_collection_error(error: SecretServiceError) -> ProtectorError {
    if matches!(error, SecretServiceError::NoResult) {
        ProtectorError::Unavailable
    } else {
        map_secret_service_error(error)
    }
}

fn map_secret_service_error(error: SecretServiceError) -> ProtectorError {
    match error {
        SecretServiceError::Locked => ProtectorError::Locked,
        SecretServiceError::NoResult => ProtectorError::ItemMissing,
        SecretServiceError::Prompt => ProtectorError::Denied,
        SecretServiceError::PromptDisconnected => ProtectorError::Unavailable,
        SecretServiceError::Crypto(_) => ProtectorError::CorruptOrTampered,
        SecretServiceError::Unavailable
        | SecretServiceError::Zbus(_)
        | SecretServiceError::ZbusFdo(_)
        | SecretServiceError::Zvariant(_) => ProtectorError::Unavailable,
        _ => ProtectorError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        APPLICATION_ATTRIBUTE, APPLICATION_ID, CONTENT_TYPE, ITEM_LABEL, LinuxProtectorId,
        LinuxSecretServiceConfig, PROTECTOR_ATTRIBUTE, RECORD_MAGIC, SCHEMA_ATTRIBUTE, SCHEMA_ID,
        decode_record, encode_record, map_collection_error, map_secret_service_error,
        query_attributes, record_matches_vrk, session_encryption, validate_linux_policy,
        validate_record_binding,
    };
    use crate::vault::{
        AccessScope, HardwareBacking, KeyGeneration, ProtectorError, SecretProtector,
        UserPresencePolicy, VAULT_ID_BYTES, VaultId,
    };
    use crate::vault_keys::OwnedKeyMaterial;
    use crate::vault_protector::ProtectorPolicy;
    use secret_service::{EncryptionType, Error as SecretServiceError};

    fn vault(byte: u8) -> VaultId {
        VaultId::from_bytes([byte; VAULT_ID_BYTES])
    }

    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).expect("non-zero generation")
    }

    #[test]
    fn provider_metadata_is_fixed_plus_one_opaque_identifier() {
        let id = LinuxProtectorId::from_bytes([0xa5; 16]);
        let value = id.attribute_value();
        let attributes = query_attributes(&value);
        assert_eq!(attributes.len(), 3);
        assert_eq!(attributes.get(APPLICATION_ATTRIBUTE), Some(&APPLICATION_ID));
        assert_eq!(attributes.get(SCHEMA_ATTRIBUTE), Some(&SCHEMA_ID));
        assert_eq!(attributes.get(PROTECTOR_ATTRIBUTE), Some(&value.as_str()));
        assert_eq!(ITEM_LABEL, "SafeEvidence Vault Protector");
        assert_eq!(CONTENT_TYPE, "application/octet-stream");
        assert_eq!(value, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
        assert_eq!(format!("{id:?}"), "LinuxProtectorId([OPAQUE; 16 bytes])");
    }

    #[test]
    fn baseline_policy_is_same_user_session_without_presence_or_hardware_claim() {
        assert!(
            validate_linux_policy(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired
            )
            .is_ok()
        );
        assert_eq!(
            validate_linux_policy(AccessScope::AppExclusive, UserPresencePolicy::NotRequired),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            validate_linux_policy(
                AccessScope::SameUserAccount,
                UserPresencePolicy::NotRequired
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            validate_linux_policy(
                AccessScope::SameUserSession,
                UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );

        let protector = super::LinuxSecretServiceProtector::new(LinuxSecretServiceConfig::new(
            LinuxProtectorId::from_bytes([1; 16]),
        ));
        assert_eq!(
            protector.actual_access_scope(),
            AccessScope::SameUserSession
        );
        assert!(!protector.requires_user_presence());
        assert_eq!(protector.hardware_backed_state(), HardwareBacking::Unknown);
    }

    #[test]
    fn secret_service_transport_is_always_diffie_hellman_encrypted() {
        assert!(matches!(session_encryption(), EncryptionType::Dh));
    }

    #[test]
    fn protected_record_binds_vault_generation_policy_and_vrk() {
        let vrk = OwnedKeyMaterial::from_bytes([0x5a; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired,
        );
        let record = encode_record(vault(0x11), generation(7), policy, &vrk);
        assert!(record.starts_with(RECORD_MAGIC));
        assert_eq!(
            validate_record_binding(&record, vault(0x11), Some(generation(7)), policy),
            Ok(())
        );
        assert!(record_matches_vrk(&record, &vrk).expect("well-formed record"));
        assert!(decode_record(&record, vault(0x11), generation(7), policy).is_ok());
        assert_eq!(
            validate_record_binding(&record, vault(0x12), Some(generation(7)), policy),
            Err(ProtectorError::OwnerMismatch)
        );
        assert_eq!(
            validate_record_binding(&record, vault(0x11), Some(generation(8)), policy),
            Err(ProtectorError::OwnerMismatch)
        );
    }

    #[test]
    fn malformed_or_policy_transplanted_records_fail_closed() {
        let vrk = OwnedKeyMaterial::from_bytes([0x33; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired,
        );
        let mut record = encode_record(vault(0x21), generation(3), policy, &vrk);
        record[0] ^= 1;
        assert_eq!(
            decode_record(&record, vault(0x21), generation(3), policy).map(|_| ()),
            Err(ProtectorError::CorruptOrTampered)
        );

        let clean = encode_record(vault(0x21), generation(3), policy, &vrk);
        let other_policy = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        assert_eq!(
            validate_record_binding(&clean, vault(0x21), Some(generation(3)), other_policy),
            Err(ProtectorError::PolicyMismatch)
        );
    }

    fn native_config() -> LinuxSecretServiceConfig {
        LinuxSecretServiceConfig::new(LinuxProtectorId::from_bytes([0xb4; 16]))
    }

    fn native_vault() -> VaultId {
        vault(0x44)
    }

    #[test]
    #[ignore = "requires an unlocked genuine Secret Service provider"]
    fn native_gnome_keyring_phase_1_store_and_inspect() {
        let mut protector = super::LinuxSecretServiceProtector::new(native_config());
        protector
            .create_protector(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired,
            )
            .expect("qualified provider must accept the conservative B404 baseline");
        let vrk = OwnedKeyMaterial::from_bytes([0x7a; 32]);
        protector
            .protect_or_store_vrk(native_vault(), generation(7), &vrk)
            .expect("qualified provider must store the VRK");
        let unlocked = protector
            .unlock_vrk(native_vault(), generation(7))
            .expect("qualified provider must unlock the stored VRK");
        assert!(unlocked.with_bytes(|bytes| *bytes == [0x7a; 32]));

        let service = secret_service::blocking::SecretService::connect(EncryptionType::Dh)
            .expect("qualified provider must support the encrypted Secret Service session");
        let collection = service
            .get_default_collection()
            .expect("qualified provider must expose the default collection");
        collection
            .ensure_unlocked()
            .expect("qualification collection must be unlocked");
        let protector_id = native_config().protector_id().attribute_value();
        let items = collection
            .search_items(query_attributes(&protector_id))
            .expect("provider metadata query must succeed");
        assert_eq!(items.len(), 1, "exactly one protector item must exist");
        let attributes = items[0]
            .get_attributes()
            .expect("provider attributes must be readable");
        assert_eq!(attributes.len(), 3);
        assert_eq!(
            attributes.get(APPLICATION_ATTRIBUTE).map(String::as_str),
            Some(APPLICATION_ID)
        );
        assert_eq!(
            attributes.get(SCHEMA_ATTRIBUTE).map(String::as_str),
            Some(SCHEMA_ID)
        );
        assert_eq!(
            attributes.get(PROTECTOR_ATTRIBUTE).map(String::as_str),
            Some(protector_id.as_str())
        );
        assert_eq!(items[0].get_label().expect("label"), ITEM_LABEL);
        let observed_content_type = items[0]
            .get_secret_content_type()
            .expect("content type must remain readable");
        assert!(
            observed_content_type == CONTENT_TYPE || observed_content_type == "text/plain",
            "qualified provider returned an unexpected content type: {observed_content_type}"
        );
        assert!(!items[0].is_locked().expect("lock state"));
    }

    #[test]
    #[ignore = "requires the phase-1 item in the same genuine provider session"]
    fn native_gnome_keyring_phase_2_restart_unlock_delete_and_lock() {
        let mut protector = super::LinuxSecretServiceProtector::new(native_config());
        protector
            .create_protector(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired,
            )
            .expect("restarted SafeEvidence process must reconnect without weakening policy");
        let unlocked = protector
            .unlock_vrk(native_vault(), generation(7))
            .expect("restarted process must unlock the existing VRK");
        assert!(unlocked.with_bytes(|bytes| *bytes == [0x7a; 32]));
        protector
            .remove_protector(native_vault())
            .expect("qualified provider must delete the bound protector item");

        let service = secret_service::blocking::SecretService::connect(EncryptionType::Dh)
            .expect("provider must remain available");
        let collection = service
            .get_default_collection()
            .expect("default collection");
        let protector_id = native_config().protector_id().attribute_value();
        assert!(
            collection
                .search_items(query_attributes(&protector_id))
                .expect("post-delete query")
                .is_empty(),
            "deleted protector must not remain discoverable"
        );
        collection
            .lock()
            .expect("qualification provider must support collection lock");
        let mut locked_probe = super::LinuxSecretServiceProtector::new(native_config());
        assert_eq!(
            locked_probe.create_protector(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired,
            ),
            Err(ProtectorError::Locked),
            "adapter must not auto-unlock a locked Secret Service collection"
        );
    }

    #[test]
    fn provider_errors_are_mapped_fail_closed() {
        assert_eq!(
            map_secret_service_error(SecretServiceError::Locked),
            ProtectorError::Locked
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::NoResult),
            ProtectorError::ItemMissing
        );
        assert_eq!(
            map_collection_error(SecretServiceError::NoResult),
            ProtectorError::Unavailable
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::Prompt),
            ProtectorError::Denied
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::PromptDisconnected),
            ProtectorError::Unavailable
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::Crypto("test")),
            ProtectorError::CorruptOrTampered
        );
    }
}

//! Provider-neutral vault contract values for Specification 004B1.
//!
//! This module defines contract types and operation signatures only. It contains
//! no cryptographic operations, entropy acquisition, persistence, platform
//! secure-store implementation, or lease-revocation behavior.

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;

/// Canonical byte length of a v1 `VaultId`.
pub const VAULT_ID_BYTES: usize = 16;

/// Canonical byte length of a freshness manifest hash.
pub const MANIFEST_HASH_BYTES: usize = 32;

/// Error returned when a fixed-width contract value is decoded from the wrong
/// number of bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactLengthError {
    expected: usize,
    actual: usize,
}

impl ExactLengthError {
    const fn new(expected: usize, actual: usize) -> Self {
        Self { expected, actual }
    }

    /// Required byte length.
    #[must_use]
    pub const fn expected(self) -> usize {
        self.expected
    }

    /// Observed byte length.
    #[must_use]
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl fmt::Display for ExactLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "expected exactly {} bytes, received {}",
            self.expected, self.actual
        )
    }
}

impl Error for ExactLengthError {}

/// Immutable, non-secret 128-bit vault identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultId([u8; VAULT_ID_BYTES]);

impl VaultId {
    /// Creates a vault identity from an already validated 16-byte value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VAULT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical raw vault-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VAULT_ID_BYTES] {
        &self.0
    }

    /// Consumes the identity and returns its canonical raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; VAULT_ID_BYTES] {
        self.0
    }

    /// Decodes an exact 16-byte vault identity.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ExactLengthError> {
        let value = <[u8; VAULT_ID_BYTES]>::try_from(bytes)
            .map_err(|_| ExactLengthError::new(VAULT_ID_BYTES, bytes.len()))?;
        Ok(Self::from_bytes(value))
    }
}

impl From<[u8; VAULT_ID_BYTES]> for VaultId {
    fn from(value: [u8; VAULT_ID_BYTES]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<VaultId> for [u8; VAULT_ID_BYTES] {
    fn from(value: VaultId) -> Self {
        value.into_bytes()
    }
}

impl TryFrom<&[u8]> for VaultId {
    type Error = ExactLengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

/// SHA-256 hash of exact canonical freshness-manifest envelope bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestHash([u8; MANIFEST_HASH_BYTES]);

impl ManifestHash {
    /// Creates a manifest hash from an already validated 32-byte value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MANIFEST_HASH_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MANIFEST_HASH_BYTES] {
        &self.0
    }

    /// Consumes the hash and returns its canonical raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; MANIFEST_HASH_BYTES] {
        self.0
    }

    /// Decodes an exact 32-byte manifest hash.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ExactLengthError> {
        let value = <[u8; MANIFEST_HASH_BYTES]>::try_from(bytes)
            .map_err(|_| ExactLengthError::new(MANIFEST_HASH_BYTES, bytes.len()))?;
        Ok(Self::from_bytes(value))
    }
}

impl From<[u8; MANIFEST_HASH_BYTES]> for ManifestHash {
    fn from(value: [u8; MANIFEST_HASH_BYTES]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<ManifestHash> for [u8; MANIFEST_HASH_BYTES] {
    fn from(value: ManifestHash) -> Self {
        value.into_bytes()
    }
}

impl TryFrom<&[u8]> for ManifestHash {
    type Error = ExactLengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

/// Error returned when a contract identity that must be non-zero receives zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonZeroIdentityError;

impl fmt::Display for NonZeroIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("identity value must be non-zero")
    }
}

impl Error for NonZeroIdentityError {}

/// Non-zero vault-root-key generation identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyGeneration(NonZeroU64);

impl KeyGeneration {
    /// Validates and creates a non-zero key generation.
    pub const fn new(value: u64) -> Result<Self, NonZeroIdentityError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(NonZeroIdentityError),
        }
    }

    /// Returns the canonical integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for KeyGeneration {
    type Error = NonZeroIdentityError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<KeyGeneration> for u64 {
    fn from(value: KeyGeneration) -> Self {
        value.get()
    }
}

/// Non-zero authenticated freshness epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FreshnessEpoch(NonZeroU64);

impl FreshnessEpoch {
    /// Validates and creates a non-zero freshness epoch.
    pub const fn new(value: u64) -> Result<Self, NonZeroIdentityError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(NonZeroIdentityError),
        }
    }

    /// Returns the canonical integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for FreshnessEpoch {
    type Error = NonZeroIdentityError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FreshnessEpoch> for u64 {
    fn from(value: FreshnessEpoch) -> Self {
        value.get()
    }
}

/// Provider-neutral freshness anchor value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FreshnessAnchor {
    vault_id: VaultId,
    highest_epoch: FreshnessEpoch,
    manifest_hash: ManifestHash,
}

impl FreshnessAnchor {
    /// Creates an anchor from already validated component values.
    #[must_use]
    pub const fn new(
        vault_id: VaultId,
        highest_epoch: FreshnessEpoch,
        manifest_hash: ManifestHash,
    ) -> Self {
        Self {
            vault_id,
            highest_epoch,
            manifest_hash,
        }
    }

    /// Vault identity bound by this anchor.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Highest authenticated freshness epoch.
    #[must_use]
    pub const fn highest_epoch(self) -> FreshnessEpoch {
        self.highest_epoch
    }

    /// SHA-256 hash of the exact canonical manifest envelope bytes.
    #[must_use]
    pub const fn manifest_hash(self) -> ManifestHash {
        self.manifest_hash
    }
}

/// Explicit protected freshness-slot state.
///
/// `Uninitialized` represents the reviewed protected genesis value. A missing
/// secure-store record is not represented by this enum and must remain a typed
/// provider error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtectedFreshnessState {
    /// Protected record exists and genesis has not installed an anchor yet.
    Uninitialized,
    /// Protected record contains an authenticated freshness anchor.
    Present(FreshnessAnchor),
}

/// Provider-neutral lock state value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultLockState {
    /// No live unlocked vault session is available.
    Locked,
    /// A live unlocked vault session exists.
    Unlocked,
}

/// Identity fields every in-process vault lease is bound to.
///
/// This value is not itself a revocation token. B102 owns allocation and
/// revocation behavior for concrete live leases.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VaultLeaseIdentity {
    vault_id: VaultId,
    key_generation: KeyGeneration,
}

impl VaultLeaseIdentity {
    /// Creates a lease identity bound to one vault and key generation.
    #[must_use]
    pub const fn new(vault_id: VaultId, key_generation: KeyGeneration) -> Self {
        Self {
            vault_id,
            key_generation,
        }
    }

    /// Vault identity bound to the lease.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Key generation bound to the lease.
    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }
}

/// Provider-neutral lease state value. B102 owns state transitions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultLeaseState {
    /// The lease may be considered live by a later behavior layer.
    Active,
    /// The lease has been revoked and must not authorize operations.
    Revoked,
}

/// Access-scope classes from the reviewed portable protector contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccessScope {
    /// Protection is enforced for the SafeEvidence application boundary.
    AppExclusive,
    /// Protection is enforced only to the current operating-system user.
    SameUserAccount,
    /// Protection is enforced only to the current user session.
    SameUserSession,
}

/// User-presence policy requested from a secret protector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UserPresencePolicy {
    /// SafeEvidence unlock does not require a new user-presence event.
    NotRequired,
    /// Every SafeEvidence unlock requires a user-presence event.
    RequiredEachSafeEvidenceUnlock,
}

/// Provider-reported hardware-backing state.
///
/// `Unknown` is not evidence of hardware-backed protection and must never be
/// promoted to `HardwareBacked` by callers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HardwareBacking {
    /// The provider cannot prove the backing state.
    Unknown,
    /// The provider reports that the protector is not hardware-backed.
    SoftwareBacked,
    /// The provider proves that the protector is hardware-backed.
    HardwareBacked,
}

/// Snapshot of the protection properties a provider actually enforces.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtectorCapabilities {
    actual_access_scope: AccessScope,
    requires_user_presence: bool,
    hardware_backed_state: HardwareBacking,
}

impl ProtectorCapabilities {
    /// Creates a capability snapshot from provider-reported values.
    #[must_use]
    pub const fn new(
        actual_access_scope: AccessScope,
        requires_user_presence: bool,
        hardware_backed_state: HardwareBacking,
    ) -> Self {
        Self {
            actual_access_scope,
            requires_user_presence,
            hardware_backed_state,
        }
    }

    /// Scope the provider actually enforces.
    #[must_use]
    pub const fn actual_access_scope(self) -> AccessScope {
        self.actual_access_scope
    }

    /// Whether this protector requires user presence for each SafeEvidence unlock.
    #[must_use]
    pub const fn requires_user_presence(self) -> bool {
        self.requires_user_presence
    }

    /// Provider-reported hardware-backing state.
    #[must_use]
    pub const fn hardware_backed_state(self) -> HardwareBacking {
        self.hardware_backed_state
    }
}

/// Typed fail-closed errors exposed by the portable protector contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtectorError {
    /// Required protector service or facility is unavailable.
    Unavailable,
    /// Protector or secret store is locked.
    Locked,
    /// The operating system or user denied the operation.
    Denied,
    /// The expected protected item does not exist.
    ItemMissing,
    /// The protected item or its native binding was invalidated.
    Invalidated,
    /// Application/owner identity does not match the requested vault.
    OwnerMismatch,
    /// Stored or requested policy does not match.
    PolicyMismatch,
    /// Protected bytes or authenticated state are corrupt or tampered.
    CorruptOrTampered,
    /// Freshness compare-and-advance observed an unexpected old anchor.
    AnchorConflict,
    /// Freshness anchor update failed or could not be verified.
    AnchorUpdateFailed,
    /// Genesis was attempted after a freshness anchor was already present.
    AnchorAlreadyInitialized,
    /// Genesis anchor installation failed or could not be verified.
    AnchorGenesisFailed,
    /// The provider cannot prove the requested security policy.
    UnsupportedPolicy,
}

impl fmt::Display for ProtectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "secret protector is unavailable",
            Self::Locked => "secret protector is locked",
            Self::Denied => "secret protector operation was denied",
            Self::ItemMissing => "protected item is missing",
            Self::Invalidated => "protected item is invalidated",
            Self::OwnerMismatch => "protected item owner does not match",
            Self::PolicyMismatch => "protected item policy does not match",
            Self::CorruptOrTampered => "protected state is corrupt or tampered",
            Self::AnchorConflict => "freshness anchor compare-and-advance conflicted",
            Self::AnchorUpdateFailed => "freshness anchor update failed",
            Self::AnchorAlreadyInitialized => "freshness anchor is already initialized",
            Self::AnchorGenesisFailed => "freshness anchor genesis failed",
            Self::UnsupportedPolicy => "requested protector policy is unsupported",
        };
        f.write_str(message)
    }
}

impl Error for ProtectorError {}

/// Provider-neutral secret-protector operation surface.
///
/// The associated `VaultRootKey` remains opaque here. B101 defines no key
/// allocation, storage, wrapping, unlocking implementation, zeroization
/// behavior, or platform mechanics.
pub trait SecretProtector {
    /// Provider-defined vault-root-key representation used by later behavior
    /// layers.
    type VaultRootKey;

    /// Creates/configures a protector for the requested portable policy.
    fn create_protector(
        &mut self,
        requested_scope: AccessScope,
        user_presence_policy: UserPresencePolicy,
    ) -> Result<(), ProtectorError>;

    /// Protects or stores one VRK bound to a vault and non-zero generation.
    fn protect_or_store_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
        vrk: &Self::VaultRootKey,
    ) -> Result<(), ProtectorError>;

    /// Unlocks the VRK bound to a vault and non-zero generation.
    fn unlock_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
    ) -> Result<Self::VaultRootKey, ProtectorError>;

    /// Reads the explicit protected freshness-slot state.
    fn read_freshness_anchor(
        &self,
        vault_id: VaultId,
    ) -> Result<ProtectedFreshnessState, ProtectorError>;

    /// Installs the first protected freshness anchor using the reviewed
    /// compare-and-set genesis contract.
    fn install_genesis_freshness_anchor(
        &mut self,
        vault_id: VaultId,
        expected_state: ProtectedFreshnessState,
        new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError>;

    /// Compares and advances an already-present freshness anchor.
    fn advance_freshness_anchor(
        &mut self,
        vault_id: VaultId,
        expected_old: FreshnessAnchor,
        new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError>;

    /// Replaces the protector associated with one vault.
    fn replace_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError>;

    /// Removes the protector associated with one vault.
    fn remove_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError>;

    /// Reports the access scope this protector actually enforces.
    fn actual_access_scope(&self) -> AccessScope;

    /// Reports whether each SafeEvidence unlock requires user presence.
    fn requires_user_presence(&self) -> bool;

    /// Reports the provider's proven hardware-backing state.
    fn hardware_backed_state(&self) -> HardwareBacking;
}

#[cfg(test)]
mod tests {
    use super::{
        AccessScope, ExactLengthError, FreshnessAnchor, FreshnessEpoch, HardwareBacking,
        KeyGeneration, MANIFEST_HASH_BYTES, ManifestHash, NonZeroIdentityError,
        ProtectedFreshnessState, ProtectorCapabilities, UserPresencePolicy, VAULT_ID_BYTES,
        VaultId, VaultLeaseIdentity, VaultLeaseState, VaultLockState,
    };

    #[test]
    fn vault_id_requires_exactly_sixteen_bytes() {
        let bytes = [0xA5; VAULT_ID_BYTES];
        let id = VaultId::try_from_slice(&bytes).expect("16-byte vault id must be accepted");
        assert_eq!(id.as_bytes(), &bytes);

        let short = VaultId::try_from_slice(&bytes[..VAULT_ID_BYTES - 1]);
        assert_eq!(
            short,
            Err(ExactLengthError::new(VAULT_ID_BYTES, VAULT_ID_BYTES - 1))
        );

        let long = [0_u8; VAULT_ID_BYTES + 1];
        assert_eq!(
            VaultId::try_from_slice(&long),
            Err(ExactLengthError::new(VAULT_ID_BYTES, VAULT_ID_BYTES + 1))
        );
    }

    #[test]
    fn manifest_hash_requires_exactly_thirty_two_bytes() {
        let bytes = [0x5A; MANIFEST_HASH_BYTES];
        let hash =
            ManifestHash::try_from_slice(&bytes).expect("32-byte manifest hash must be accepted");
        assert_eq!(hash.as_bytes(), &bytes);

        assert_eq!(
            ManifestHash::try_from_slice(&bytes[..MANIFEST_HASH_BYTES - 1]),
            Err(ExactLengthError::new(
                MANIFEST_HASH_BYTES,
                MANIFEST_HASH_BYTES - 1
            ))
        );
    }

    #[test]
    fn generation_and_epoch_reject_zero() {
        assert_eq!(KeyGeneration::new(0), Err(NonZeroIdentityError));
        assert_eq!(FreshnessEpoch::new(0), Err(NonZeroIdentityError));

        assert_eq!(
            KeyGeneration::new(1)
                .expect("generation one is valid")
                .get(),
            1
        );
        assert_eq!(FreshnessEpoch::new(1).expect("epoch one is valid").get(), 1);
    }

    #[test]
    fn protected_freshness_state_is_explicit() {
        let vault_id = VaultId::from_bytes([1; VAULT_ID_BYTES]);
        let epoch = FreshnessEpoch::new(7).expect("non-zero epoch");
        let hash = ManifestHash::from_bytes([2; MANIFEST_HASH_BYTES]);
        let anchor = FreshnessAnchor::new(vault_id, epoch, hash);

        assert_eq!(
            ProtectedFreshnessState::Present(anchor),
            ProtectedFreshnessState::Present(anchor)
        );
        assert_ne!(
            ProtectedFreshnessState::Uninitialized,
            ProtectedFreshnessState::Present(anchor)
        );
        assert_eq!(anchor.vault_id(), vault_id);
        assert_eq!(anchor.highest_epoch(), epoch);
        assert_eq!(anchor.manifest_hash(), hash);
    }

    #[test]
    fn lease_values_do_not_implement_revocation() {
        let vault_id = VaultId::from_bytes([3; VAULT_ID_BYTES]);
        let generation = KeyGeneration::new(4).expect("non-zero generation");
        let identity = VaultLeaseIdentity::new(vault_id, generation);

        assert_eq!(identity.vault_id(), vault_id);
        assert_eq!(identity.key_generation(), generation);
        assert_ne!(VaultLeaseState::Active, VaultLeaseState::Revoked);
        assert_ne!(VaultLockState::Locked, VaultLockState::Unlocked);
    }

    #[test]
    fn capabilities_report_actual_provider_state_without_upgrade() {
        let capabilities = ProtectorCapabilities::new(
            AccessScope::SameUserAccount,
            true,
            HardwareBacking::Unknown,
        );

        assert_eq!(
            capabilities.actual_access_scope(),
            AccessScope::SameUserAccount
        );
        assert!(capabilities.requires_user_presence());
        assert_eq!(
            capabilities.hardware_backed_state(),
            HardwareBacking::Unknown
        );
        assert_ne!(HardwareBacking::Unknown, HardwareBacking::HardwareBacked);

        assert_ne!(
            UserPresencePolicy::NotRequired,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock
        );
    }
}

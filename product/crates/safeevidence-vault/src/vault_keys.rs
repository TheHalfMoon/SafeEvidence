//! Portable key-domain, derivation, and secret-lifetime contracts for Specification 004.
//!
//! B104 freezes the reviewed derivation-domain identifiers and teardown ordering.
//! B201 executes only the reviewed HKDF-SHA-256 purpose-key derivation over those
//! frozen inputs. This module does not execute AEAD, Argon2id, SQLCipher, native
//! protector operations, or concrete database/blob I/O.

use crate::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity, VaultLeaseState};
use crate::vault_lease::{KeyedHandleLease, VaultLease};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use std::mem::size_of;
use zeroize::Zeroize;

/// Canonical byte length of owned v1 VRK, Recovery KEK, and purpose-key buffers.
pub const KEY_MATERIAL_BYTES: usize = 32;

const STRUCTURED_DOMAIN: &[u8] = b"HIMSAT/004/STRUCTURED/v1";
const BLOB_DOMAIN: &[u8] = b"HIMSAT/004/BLOB/v1";
const MANIFEST_DOMAIN: &[u8] = b"HIMSAT/004/MANIFEST/v1";
const MEDIA_CHUNK_DOMAIN: &[u8] = b"HIMSAT/005/MEDIA-CHUNK/v1";

/// Reviewed v1 key purpose used to construct an HKDF `info` value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyPurpose {
    /// Structured-store purpose key.
    StructuredStore,
    /// Bounded-blob purpose key.
    BoundedBlob,
    /// Freshness-manifest purpose key.
    FreshnessManifest,
    /// 005A media-chunk purpose key. Additive to the reviewed 004 purposes:
    /// existing derivations are byte-identical, while media chunks receive a
    /// disjoint key even under the same vault and generation, so a nonce need
    /// only be unique within its own protocol.
    MediaChunk,
}

impl KeyPurpose {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::StructuredStore => STRUCTURED_DOMAIN,
            Self::BoundedBlob => BLOB_DOMAIN,
            Self::FreshnessManifest => MANIFEST_DOMAIN,
            Self::MediaChunk => MEDIA_CHUNK_DOMAIN,
        }
    }
}

/// Inputs for the reviewed B104/B201 domain-separation contract.
///
/// B104 freezes the public HKDF salt/info bytes. B201 executes HKDF-SHA-256 over
/// an already-owned 32-byte VRK and returns a new opaque `OwnedKeyMaterial`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyDerivationContext {
    vault_id: VaultId,
    key_generation: KeyGeneration,
    purpose: KeyPurpose,
}

impl KeyDerivationContext {
    /// Creates one reviewed derivation context from already validated identities.
    #[must_use]
    pub const fn new(
        vault_id: VaultId,
        key_generation: KeyGeneration,
        purpose: KeyPurpose,
    ) -> Self {
        Self {
            vault_id,
            key_generation,
            purpose,
        }
    }

    /// Returns the 16 raw `VaultId` bytes reviewed as the v1 HKDF salt.
    #[must_use]
    pub const fn hkdf_salt(self) -> [u8; VAULT_ID_BYTES] {
        self.vault_id.into_bytes()
    }

    /// Returns the exact reviewed v1 HKDF `info` bytes:
    /// `domain || u64be(key_generation)`.
    #[must_use]
    pub fn hkdf_info(self) -> Vec<u8> {
        let domain = self.purpose.domain();
        let mut info = Vec::with_capacity(domain.len() + size_of::<u64>());
        info.extend_from_slice(domain);
        info.extend_from_slice(&self.key_generation.get().to_be_bytes());
        info
    }

    /// Derives the reviewed 32-byte v1 purpose key with HKDF-SHA-256.
    ///
    /// The HKDF salt is the raw 16-byte `VaultId`; the `info` value is the
    /// purpose-specific ASCII domain followed by `key_generation` as `u64be`.
    /// The returned secret stays opaque and inherits `OwnedKeyMaterial`'s owned
    /// buffer zeroization and redacted-debug behavior.
    ///
    /// Provider-internal temporary state is outside the owned-buffer erasure
    /// guarantee and remains covered by the existing runtime/compiler/register/
    /// allocator/swap/crash-dump residual-risk boundary.
    #[must_use]
    pub fn derive_purpose_key(self, vrk: &OwnedKeyMaterial) -> OwnedKeyMaterial {
        let salt = self.hkdf_salt();
        let info = self.hkdf_info();
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), vrk.bytes.as_slice());
        let mut output = [0_u8; KEY_MATERIAL_BYTES];

        hkdf.expand(info.as_slice(), &mut output)
            .expect("32-byte HKDF-SHA-256 output is within the RFC 5869 expansion limit");

        OwnedKeyMaterial::from_bytes(output)
    }

    /// Returns the public vault identity bound to the context.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns the non-zero key generation bound to the context.
    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }

    /// Returns the reviewed purpose bound to the context.
    #[must_use]
    pub const fn purpose(self) -> KeyPurpose {
        self.purpose
    }
}

/// One owned 32-byte secret buffer whose owned bytes are zeroized on drop.
///
/// This type deliberately does not implement `Clone` or `Copy`, and its debug
/// representation never exposes secret bytes. The guarantee is limited to this
/// owned array. It does not claim erasure of compiler/runtime copies, registers,
/// allocator copies, swap, crash dumps, kernel memory, or physical memory.
pub struct OwnedKeyMaterial {
    bytes: [u8; KEY_MATERIAL_BYTES],
}

impl OwnedKeyMaterial {
    /// Takes ownership of one already-produced 32-byte key value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_MATERIAL_BYTES]) -> Self {
        Self { bytes }
    }

    /// Borrows the owned key bytes only for one crate-internal cryptographic operation.
    ///
    /// This keeps the public secret surface opaque while allowing separately
    /// authorized in-crate providers to consume the B201-derived key without
    /// introducing a cloneable/copyable secret getter.
    pub(crate) fn with_bytes<T>(
        &self,
        operation: impl FnOnce(&[u8; KEY_MATERIAL_BYTES]) -> T,
    ) -> T {
        operation(&self.bytes)
    }

    fn zeroize_owned(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for OwnedKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedKeyMaterial([REDACTED; 32 bytes])")
    }
}

impl Drop for OwnedKeyMaterial {
    fn drop(&mut self) {
        self.zeroize_owned();
    }
}

/// Owned secret objects associated with one live vault-key generation.
///
/// `release_all` drops every owned object, invoking `OwnedKeyMaterial` zeroization
/// for each present buffer. Purpose keys may be populated by the reviewed B201
/// derivation path; later cryptographic leaves consume them without changing the
/// B104 lifetime contract.
pub struct VaultKeyMaterial {
    vrk: Option<OwnedKeyMaterial>,
    recovery_kek: Option<OwnedKeyMaterial>,
    structured_store: Option<OwnedKeyMaterial>,
    bounded_blob: Option<OwnedKeyMaterial>,
    freshness_manifest: Option<OwnedKeyMaterial>,
    media_chunk: Option<OwnedKeyMaterial>,
}

impl VaultKeyMaterial {
    /// Creates a live key set that owns exactly one already-unlocked VRK.
    #[must_use]
    pub const fn new(vrk: OwnedKeyMaterial) -> Self {
        Self {
            vrk: Some(vrk),
            recovery_kek: None,
            structured_store: None,
            bounded_blob: None,
            freshness_manifest: None,
            media_chunk: None,
        }
    }

    /// Replaces the optional Recovery KEK, dropping and zeroizing any prior value.
    pub fn set_recovery_kek(&mut self, recovery_kek: OwnedKeyMaterial) {
        self.recovery_kek = Some(recovery_kek);
    }

    /// Replaces one owned purpose key, dropping and zeroizing any prior value.
    pub fn set_purpose_key(&mut self, purpose: KeyPurpose, key: OwnedKeyMaterial) {
        match purpose {
            KeyPurpose::StructuredStore => self.structured_store = Some(key),
            KeyPurpose::BoundedBlob => self.bounded_blob = Some(key),
            KeyPurpose::FreshnessManifest => self.freshness_manifest = Some(key),
            KeyPurpose::MediaChunk => self.media_chunk = Some(key),
        }
    }

    /// Returns whether all B104-owned key objects have been released.
    #[must_use]
    pub fn is_released(&self) -> bool {
        self.vrk.is_none()
            && self.recovery_kek.is_none()
            && self.structured_store.is_none()
            && self.bounded_blob.is_none()
            && self.freshness_manifest.is_none()
            && self.media_chunk.is_none()
    }

    fn release_all(&mut self) {
        self.vrk = None;
        self.recovery_kek = None;
        self.structured_store = None;
        self.bounded_blob = None;
        self.freshness_manifest = None;
        self.media_chunk = None;
    }
}

impl fmt::Debug for VaultKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKeyMaterial")
            .field("vrk_present", &self.vrk.is_some())
            .field("recovery_kek_present", &self.recovery_kek.is_some())
            .field("structured_store_present", &self.structured_store.is_some())
            .field("bounded_blob_present", &self.bounded_blob.is_some())
            .field(
                "freshness_manifest_present",
                &self.freshness_manifest.is_some(),
            )
            .field("media_chunk_present", &self.media_chunk.is_some())
            .finish()
    }
}

/// Bounded abstraction for closing keyed database/blob handles during teardown.
///
/// B104 owns only the ordering contract. B105 owns concrete post-lock database/
/// blob read/write rejection proof.
pub trait KeyedHandleCloser {
    /// Handle-close failure type owned by the concrete later implementation.
    type Error;

    /// Closes keyed handles after lease revocation has already been published.
    fn close_keyed_handles(&mut self) -> Result<(), Self::Error>;
}

/// Bounded abstraction for plaintext cache content owned by one vault session.
pub trait PlaintextCache {
    /// Discards plaintext cache content owned by this session.
    fn discard_plaintext(&mut self);
}

/// Reviewed terminal reason that triggers the same fail-closed B104 teardown order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultTeardownReason {
    /// Explicit user/application vault lock.
    Lock,
    /// Relevant key-rotation transition requiring quiescence.
    Rotation,
    /// Protector/session revocation outside an ordinary lock.
    Revocation,
    /// Fatal integrity, freshness, authentication, or equivalent fail-closed error.
    FatalFailure,
}

/// Portable B104 lifetime coordinator for one live vault session.
///
/// Teardown order is fixed as:
///
/// 1. publish lease revocation and drain already-authorized operations;
/// 2. ask the bounded handle closer to close keyed handles;
/// 3. release owned VRK, Recovery KEK, and purpose-key objects;
/// 4. zeroize their owned buffers through `OwnedKeyMaterial::drop`;
/// 5. discard session-owned plaintext caches.
///
/// Key release and cache discard still run when `close_keyed_handles` returns an
/// error. This contract does not claim cleanup after process abort or a panic that
/// prevents ordinary stack unwinding/control flow from reaching later steps.
pub struct VaultSessionLifetime<H, C> {
    lease: VaultLease,
    handle_closer: H,
    keys: VaultKeyMaterial,
    plaintext_cache: C,
}

impl<H, C> VaultSessionLifetime<H, C>
where
    H: KeyedHandleCloser,
    C: PlaintextCache,
{
    /// Creates a lifetime coordinator from already-created B102/B104 objects.
    #[must_use]
    pub const fn new(
        lease: VaultLease,
        handle_closer: H,
        keys: VaultKeyMaterial,
        plaintext_cache: C,
    ) -> Self {
        Self {
            lease,
            handle_closer,
            keys,
            plaintext_cache,
        }
    }

    /// Returns the immutable vault/generation identity bound to the live lease.
    #[must_use]
    pub const fn identity(&self) -> VaultLeaseIdentity {
        self.lease.identity()
    }

    /// Creates a B102 keyed-handle lease for a concrete keyed handle.
    #[must_use]
    pub fn keyed_handle_lease(&self) -> KeyedHandleLease {
        self.lease.keyed_handle_lease()
    }

    /// Returns the current public lease state.
    #[must_use]
    pub fn lease_state(&self) -> VaultLeaseState {
        self.lease.state()
    }

    /// Returns whether every B104-owned key object has been released.
    #[must_use]
    pub fn keys_released(&self) -> bool {
        self.keys.is_released()
    }

    /// Executes the reviewed fail-closed teardown order.
    ///
    /// A lock preserves B102's typed `Locked` terminal reason. Other terminal
    /// causes preserve B102's generic `Revoked` reason. Repeated calls never
    /// reactivate the lease and key release remains idempotent.
    pub fn teardown(&mut self, reason: VaultTeardownReason) -> Result<(), H::Error> {
        match reason {
            VaultTeardownReason::Lock => {
                self.lease.revoke_for_lock();
            }
            VaultTeardownReason::Rotation
            | VaultTeardownReason::Revocation
            | VaultTeardownReason::FatalFailure => {
                self.lease.revoke();
            }
        }

        let close_result = self.handle_closer.close_keyed_handles();
        self.keys.release_all();
        self.plaintext_cache.discard_plaintext();
        close_result
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, KeyedHandleCloser, OwnedKeyMaterial,
        PlaintextCache, VaultKeyMaterial, VaultSessionLifetime, VaultTeardownReason,
    };
    use crate::vault::{
        KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity, VaultLeaseState,
    };
    use crate::vault_lease::{KeyedHandleError, KeyedHandleLease, VaultLease};

    fn identity() -> VaultLeaseIdentity {
        VaultLeaseIdentity::new(
            VaultId::from_bytes([0x42; VAULT_ID_BYTES]),
            KeyGeneration::new(0x0102_0304_0506_0708).expect("test generation is non-zero"),
        )
    }

    fn key(byte: u8) -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([byte; KEY_MATERIAL_BYTES])
    }

    fn vector_vrk() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes(std::array::from_fn(|index| index as u8))
    }

    fn vector_vault_id() -> VaultId {
        VaultId::from_bytes(std::array::from_fn(|index| index as u8))
    }

    fn to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[test]
    fn derivation_context_freezes_exact_salt_and_domain_info_bytes() {
        let identity = identity();
        let cases = [
            (
                KeyPurpose::StructuredStore,
                b"HIMSAT/004/STRUCTURED/v1".as_slice(),
            ),
            (KeyPurpose::BoundedBlob, b"HIMSAT/004/BLOB/v1".as_slice()),
            (
                KeyPurpose::FreshnessManifest,
                b"HIMSAT/004/MANIFEST/v1".as_slice(),
            ),
            (
                KeyPurpose::MediaChunk,
                b"HIMSAT/005/MEDIA-CHUNK/v1".as_slice(),
            ),
        ];

        for (purpose, domain) in cases {
            let context =
                KeyDerivationContext::new(identity.vault_id(), identity.key_generation(), purpose);
            assert_eq!(context.hkdf_salt(), [0x42; VAULT_ID_BYTES]);

            let mut expected = domain.to_vec();
            expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
            assert_eq!(context.hkdf_info(), expected);
            assert_eq!(context.vault_id(), identity.vault_id());
            assert_eq!(context.key_generation(), identity.key_generation());
            assert_eq!(context.purpose(), purpose);
        }
    }

    #[test]
    fn hkdf_sha256_matches_independent_deterministic_vectors_for_all_v1_purposes() {
        // Oracle recipe (independent Python `hmac`/`hashlib` implementation of
        // RFC 5869, no SafeEvidence code): salt is the 16 raw vault-id bytes
        // (`vector_vault_id`), IKM is vrk bytes `0..32`, info is
        // `domain || u64be(generation)`, output is the first 32 expanded bytes.
        // The recipe was validated by reproducing the three committed 004
        // vectors before deriving the MediaChunk vector below.
        let vrk = vector_vrk();
        let generation =
            KeyGeneration::new(0x0102_0304_0506_0708).expect("test generation is non-zero");
        let cases = [
            (
                KeyPurpose::StructuredStore,
                "0a6857ca8e7804d89a825e7e5bc515bb4cad0e87f2ee6d0b67e54f0313d0808f",
            ),
            (
                KeyPurpose::BoundedBlob,
                "602177c7d772ff6a69462540eb6612b105ec9b9f18115a024c3a410b0008e476",
            ),
            (
                KeyPurpose::FreshnessManifest,
                "19540379cb9fd9b63cad8f3be133c0a985339bcfeb323c26b1bd95e20202d019",
            ),
            (
                KeyPurpose::MediaChunk,
                "7c41a72830f0568a8344ba657cc7c4de02ad631ea6163b4f721c6d8c034cd6d8",
            ),
        ];

        for (purpose, expected_hex) in cases {
            let context = KeyDerivationContext::new(vector_vault_id(), generation, purpose);
            let derived = context.derive_purpose_key(&vrk);
            assert_eq!(to_hex(&derived.bytes), expected_hex);
        }
    }

    #[test]
    fn hkdf_domain_separates_purpose_vault_and_generation() {
        let vrk = vector_vrk();
        let vault_id = vector_vault_id();
        let generation =
            KeyGeneration::new(0x0102_0304_0506_0708).expect("test generation is non-zero");
        let next_generation =
            KeyGeneration::new(0x0102_0304_0506_0709).expect("test generation is non-zero");

        let structured =
            KeyDerivationContext::new(vault_id, generation, KeyPurpose::StructuredStore)
                .derive_purpose_key(&vrk);
        let blob = KeyDerivationContext::new(vault_id, generation, KeyPurpose::BoundedBlob)
            .derive_purpose_key(&vrk);
        let manifest =
            KeyDerivationContext::new(vault_id, generation, KeyPurpose::FreshnessManifest)
                .derive_purpose_key(&vrk);
        let media = KeyDerivationContext::new(vault_id, generation, KeyPurpose::MediaChunk)
            .derive_purpose_key(&vrk);
        let other_vault = KeyDerivationContext::new(
            VaultId::from_bytes([0xa5; VAULT_ID_BYTES]),
            generation,
            KeyPurpose::StructuredStore,
        )
        .derive_purpose_key(&vrk);
        let other_generation =
            KeyDerivationContext::new(vault_id, next_generation, KeyPurpose::StructuredStore)
                .derive_purpose_key(&vrk);

        assert_ne!(structured.bytes, blob.bytes);
        assert_ne!(structured.bytes, manifest.bytes);
        assert_ne!(blob.bytes, manifest.bytes);
        assert_ne!(media.bytes, structured.bytes);
        assert_ne!(media.bytes, blob.bytes);
        assert_ne!(media.bytes, manifest.bytes);
        assert_ne!(structured.bytes, other_vault.bytes);
        assert_ne!(structured.bytes, other_generation.bytes);
    }

    #[test]
    fn owned_key_zeroization_path_clears_only_the_owned_buffer_and_debug_is_redacted() {
        let mut secret = key(0xA7);
        let debug = format!("{secret:?}");
        assert!(!debug.contains("a7"));
        assert!(debug.contains("REDACTED"));

        secret.zeroize_owned();
        assert_eq!(secret.bytes, [0_u8; KEY_MATERIAL_BYTES]);
    }

    #[test]
    fn key_set_releases_all_owned_secret_objects_idempotently() {
        let mut keys = VaultKeyMaterial::new(key(1));
        keys.set_recovery_kek(key(2));
        keys.set_purpose_key(KeyPurpose::StructuredStore, key(3));
        keys.set_purpose_key(KeyPurpose::BoundedBlob, key(4));
        keys.set_purpose_key(KeyPurpose::FreshnessManifest, key(5));
        keys.set_purpose_key(KeyPurpose::MediaChunk, key(6));

        assert!(!keys.is_released());
        keys.release_all();
        assert!(keys.is_released());
        keys.release_all();
        assert!(keys.is_released());
    }

    #[derive(Debug)]
    struct ObservingCloser {
        handle: KeyedHandleLease,
        expected_error: KeyedHandleError,
        calls: usize,
        fail: bool,
    }

    impl KeyedHandleCloser for ObservingCloser {
        type Error = &'static str;

        fn close_keyed_handles(&mut self) -> Result<(), Self::Error> {
            self.calls += 1;
            assert_eq!(self.handle.authorize().err(), Some(self.expected_error));
            if self.fail {
                Err("synthetic close failure")
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug, Default)]
    struct TrackingCache {
        discarded: bool,
        calls: usize,
    }

    impl PlaintextCache for TrackingCache {
        fn discard_plaintext(&mut self) {
            self.discarded = true;
            self.calls += 1;
        }
    }

    fn populated_keys() -> VaultKeyMaterial {
        let mut keys = VaultKeyMaterial::new(key(0x11));
        keys.set_recovery_kek(key(0x22));
        keys.set_purpose_key(KeyPurpose::StructuredStore, key(0x33));
        keys.set_purpose_key(KeyPurpose::BoundedBlob, key(0x44));
        keys.set_purpose_key(KeyPurpose::FreshnessManifest, key(0x55));
        keys.set_purpose_key(KeyPurpose::MediaChunk, key(0x66));
        keys
    }

    #[test]
    fn lock_teardown_revokes_before_handle_close_then_releases_keys_and_cache() {
        let lease = VaultLease::new(identity());
        let closer = ObservingCloser {
            handle: lease.keyed_handle_lease(),
            expected_error: KeyedHandleError::Locked,
            calls: 0,
            fail: false,
        };
        let mut session =
            VaultSessionLifetime::new(lease, closer, populated_keys(), TrackingCache::default());

        assert_eq!(session.lease_state(), VaultLeaseState::Active);
        assert!(!session.keys_released());
        assert_eq!(session.teardown(VaultTeardownReason::Lock), Ok(()));
        assert_eq!(session.lease_state(), VaultLeaseState::Revoked);
        assert!(session.keys_released());
        assert_eq!(session.handle_closer.calls, 1);
        assert!(session.plaintext_cache.discarded);
        assert_eq!(session.plaintext_cache.calls, 1);
    }

    #[test]
    fn non_lock_terminal_reasons_publish_revoked_before_handle_close() {
        for reason in [
            VaultTeardownReason::Rotation,
            VaultTeardownReason::Revocation,
            VaultTeardownReason::FatalFailure,
        ] {
            let lease = VaultLease::new(identity());
            let closer = ObservingCloser {
                handle: lease.keyed_handle_lease(),
                expected_error: KeyedHandleError::Revoked,
                calls: 0,
                fail: false,
            };
            let mut session = VaultSessionLifetime::new(
                lease,
                closer,
                populated_keys(),
                TrackingCache::default(),
            );

            assert_eq!(session.teardown(reason), Ok(()));
            assert_eq!(session.lease_state(), VaultLeaseState::Revoked);
            assert!(session.keys_released());
            assert!(session.plaintext_cache.discarded);
        }
    }

    #[test]
    fn handle_close_error_does_not_skip_key_release_or_cache_discard() {
        let lease = VaultLease::new(identity());
        let closer = ObservingCloser {
            handle: lease.keyed_handle_lease(),
            expected_error: KeyedHandleError::Revoked,
            calls: 0,
            fail: true,
        };
        let mut session =
            VaultSessionLifetime::new(lease, closer, populated_keys(), TrackingCache::default());

        assert_eq!(
            session.teardown(VaultTeardownReason::FatalFailure),
            Err("synthetic close failure")
        );
        assert_eq!(session.lease_state(), VaultLeaseState::Revoked);
        assert!(session.keys_released());
        assert_eq!(session.handle_closer.calls, 1);
        assert!(session.plaintext_cache.discarded);
    }

    #[test]
    fn repeated_teardown_never_reactivates_lease_and_cleanup_is_repeatable() {
        let lease = VaultLease::new(identity());
        let closer = ObservingCloser {
            handle: lease.keyed_handle_lease(),
            expected_error: KeyedHandleError::Locked,
            calls: 0,
            fail: false,
        };
        let mut session =
            VaultSessionLifetime::new(lease, closer, populated_keys(), TrackingCache::default());
        let external_handle = session.keyed_handle_lease();

        assert_eq!(session.teardown(VaultTeardownReason::Lock), Ok(()));
        assert_eq!(session.teardown(VaultTeardownReason::Revocation), Ok(()));
        assert_eq!(
            external_handle.authorize().err(),
            Some(KeyedHandleError::Locked)
        );
        assert_eq!(session.lease_state(), VaultLeaseState::Revoked);
        assert!(session.keys_released());
        assert_eq!(session.handle_closer.calls, 2);
        assert_eq!(session.plaintext_cache.calls, 2);
    }
}

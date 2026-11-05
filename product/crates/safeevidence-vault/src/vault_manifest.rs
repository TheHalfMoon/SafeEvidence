use crate::vault::{FreshnessEpoch, KeyGeneration, ManifestHash, VaultId};
use crate::vault_blob::{
    BOUNDED_BLOB_MAX_ENVELOPE_BYTES, BOUNDED_BLOB_MIN_ENVELOPE_BYTES, BOUNDED_BLOB_NONCE_BYTES,
};
use crate::vault_keys::{KeyDerivationContext, KeyPurpose, OwnedKeyMaterial};
use crate::vault_nonce::{
    NonceLifecycleError, NoncePurpose, NonceReservation, NonceReservationLedger,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use zeroize::Zeroizing;
pub const MANIFEST_MAX_PLAINTEXT_BYTES: usize = 16_777_216;
pub const MANIFEST_NONCE_BYTES: usize = 24;
pub const MANIFEST_TAG_BYTES: usize = 16;
pub const MANIFEST_HEADER_BYTES: usize = 93;
pub const MANIFEST_MAX_ENVELOPE_BYTES: usize = 16_777_325;
pub const MANIFEST_MAX_GENERATIONS: usize = 64;
pub const MANIFEST_MAX_OBJECTS: usize = 262_144;
pub const MANIFEST_BLOB_AUTH_METADATA_BYTES: usize = 28;
const ENVELOPE_DOMAIN: &[u8; 29] = b"\x00\x1bHIMSAT/MANIFEST/ENVELOPE/v1";
const AAD_DOMAIN: &[u8; 24] = b"\x00\x16HIMSAT/MANIFEST/AAD/v1";
const PLAINTEXT_DOMAIN: &[u8; 30] = b"\x00\x1cHIMSAT/MANIFEST/PLAINTEXT/v1";
const ENVELOPE_VERSION: u16 = 1;
const CIPHER_SUITE: u16 = 1;
const AAD_SCHEMA: u16 = 1;
const PLAINTEXT_SCHEMA: u16 = 1;
const BLOB_ENVELOPE_VERSION: u16 = 1;
const BLOB_CIPHER_SUITE: u16 = 1;
const AAD_BYTES: usize = 66;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManifestContext {
    vault_id: VaultId,
    key_generation: KeyGeneration,
    freshness_epoch: FreshnessEpoch,
}
impl ManifestContext {
    #[must_use]
    pub const fn new(
        vault_id: VaultId,
        key_generation: KeyGeneration,
        freshness_epoch: FreshnessEpoch,
    ) -> Self {
        Self {
            vault_id,
            key_generation,
            freshness_epoch,
        }
    }

    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }

    #[must_use]
    pub const fn freshness_epoch(self) -> FreshnessEpoch {
        self.freshness_epoch
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum RotationPhase {
    None = 0,
    Prepare = 1,
    Stage = 2,
    Verify = 3,
    Publish = 4,
    Anchor = 5,
    Activate = 6,
    Retire = 7,
}
impl RotationPhase {
    fn parse(value: u16) -> Result<Self, ManifestError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Stage),
            3 => Ok(Self::Verify),
            4 => Ok(Self::Publish),
            5 => Ok(Self::Anchor),
            6 => Ok(Self::Activate),
            7 => Ok(Self::Retire),
            _ => Err(ManifestError::CorruptOrTampered),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum GenerationState {
    Active = 1,
    Retained = 2,
    Staged = 3,
}
impl GenerationState {
    fn parse(value: u16) -> Result<Self, ManifestError> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retained),
            3 => Ok(Self::Staged),
            _ => Err(ManifestError::CorruptOrTampered),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManifestGeneration {
    generation: KeyGeneration,
    state: GenerationState,
}
impl ManifestGeneration {
    #[must_use]
    pub const fn new(generation: KeyGeneration, state: GenerationState) -> Self {
        Self { generation, state }
    }

    /// Returns the key generation represented by this authenticated manifest entry.
    #[must_use]
    pub const fn generation(self) -> KeyGeneration {
        self.generation
    }

    /// Returns the authenticated lifecycle state for this key generation.
    #[must_use]
    pub const fn state(self) -> GenerationState {
        self.state
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ManifestObjectKind {
    GenericArtifactBlob = 1,
    StructuredStore = 2,
}
impl ManifestObjectKind {
    fn parse(value: u16) -> Result<Self, ManifestError> {
        match value {
            1 => Ok(Self::GenericArtifactBlob),
            2 => Ok(Self::StructuredStore),
            _ => Err(ManifestError::CorruptOrTampered),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ManifestAuthMetadata {
    GenericArtifactBlob {
        nonce: [u8; BOUNDED_BLOB_NONCE_BYTES],
    },
    StructuredStore,
}
impl ManifestAuthMetadata {
    #[must_use]
    pub const fn kind(self) -> ManifestObjectKind {
        match self {
            Self::GenericArtifactBlob { .. } => ManifestObjectKind::GenericArtifactBlob,
            Self::StructuredStore => ManifestObjectKind::StructuredStore,
        }
    }
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManifestObject {
    logical_id: [u8; 16],
    storage_id: [u8; 16],
    key_generation: KeyGeneration,
    ciphertext_length: u64,
    ciphertext_sha256: [u8; 32],
    auth_metadata: ManifestAuthMetadata,
}
impl ManifestObject {
    #[must_use]
    pub const fn new(
        logical_id: [u8; 16],
        storage_id: [u8; 16],
        key_generation: KeyGeneration,
        ciphertext_length: u64,
        ciphertext_sha256: [u8; 32],
        auth_metadata: ManifestAuthMetadata,
    ) -> Self {
        Self {
            logical_id,
            storage_id,
            key_generation,
            ciphertext_length,
            ciphertext_sha256,
            auth_metadata,
        }
    }
    #[must_use]
    pub const fn kind(&self) -> ManifestObjectKind {
        self.auth_metadata.kind()
    }

    /// Returns the authenticated logical object identifier.
    #[must_use]
    pub const fn logical_id(&self) -> [u8; 16] {
        self.logical_id
    }

    /// Returns the opaque storage identifier selected by the authenticated manifest.
    #[must_use]
    pub const fn storage_id(&self) -> [u8; 16] {
        self.storage_id
    }

    /// Returns the key generation that encrypts this stored object.
    #[must_use]
    pub const fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }

    /// Returns the authenticated length of the exact canonical stored ciphertext bytes.
    #[must_use]
    pub const fn ciphertext_length(&self) -> u64 {
        self.ciphertext_length
    }

    /// Returns SHA-256 of the exact canonical stored ciphertext bytes.
    #[must_use]
    pub const fn ciphertext_sha256(&self) -> [u8; 32] {
        self.ciphertext_sha256
    }

    /// Returns the object-kind-specific authenticated metadata.
    #[must_use]
    pub const fn auth_metadata(&self) -> ManifestAuthMetadata {
        self.auth_metadata
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPlaintext {
    vault_id: VaultId,
    freshness_epoch: FreshnessEpoch,
    previous_manifest_hash: ManifestHash,
    active_key_generation: KeyGeneration,
    rotation_phase: RotationPhase,
    rotation_target_generation: Option<KeyGeneration>,
    generations: Vec<ManifestGeneration>,
    objects: Vec<ManifestObject>,
}
impl ManifestPlaintext {
    pub fn new(
        vault_id: VaultId,
        freshness_epoch: FreshnessEpoch,
        previous_manifest_hash: ManifestHash,
        active_key_generation: KeyGeneration,
        rotation: (RotationPhase, Option<KeyGeneration>),
        generations: Vec<ManifestGeneration>,
        objects: Vec<ManifestObject>,
    ) -> Result<Self, ManifestError> {
        let value = Self {
            vault_id,
            freshness_epoch,
            previous_manifest_hash,
            active_key_generation,
            rotation_phase: rotation.0,
            rotation_target_generation: rotation.1,
            generations,
            objects,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn freshness_epoch(&self) -> FreshnessEpoch {
        self.freshness_epoch
    }

    #[must_use]
    pub const fn previous_manifest_hash(&self) -> ManifestHash {
        self.previous_manifest_hash
    }

    /// Returns the vault identity authenticated by this manifest.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the sole active key generation authenticated by this manifest.
    #[must_use]
    pub const fn active_key_generation(&self) -> KeyGeneration {
        self.active_key_generation
    }

    /// Returns the authenticated durable rotation phase.
    #[must_use]
    pub const fn rotation_phase(&self) -> RotationPhase {
        self.rotation_phase
    }

    /// Returns the authenticated target generation while rotation is active.
    #[must_use]
    pub const fn rotation_target_generation(&self) -> Option<KeyGeneration> {
        self.rotation_target_generation
    }

    /// Returns the canonical authenticated key-generation table.
    #[must_use]
    pub fn generations(&self) -> &[ManifestGeneration] {
        &self.generations
    }

    /// Returns the canonical authenticated stored-object inventory.
    #[must_use]
    pub fn objects(&self) -> &[ManifestObject] {
        &self.objects
    }

    pub(crate) fn republish_for_restore(
        &self,
        freshness_epoch: FreshnessEpoch,
        previous_manifest_hash: ManifestHash,
    ) -> Result<Self, ManifestError> {
        Self::new(
            self.vault_id,
            freshness_epoch,
            previous_manifest_hash,
            self.active_key_generation,
            (self.rotation_phase, self.rotation_target_generation),
            self.generations.clone(),
            self.objects.clone(),
        )
    }

    fn validate(&self) -> Result<(), ManifestError> {
        let zero_hash = self
            .previous_manifest_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0);
        if (self.freshness_epoch.get() == 1) != zero_hash {
            return Err(ManifestError::CorruptOrTampered);
        }
        if matches!(self.rotation_phase, RotationPhase::None)
            != self.rotation_target_generation.is_none()
        {
            return Err(ManifestError::CorruptOrTampered);
        }
        if self.generations.is_empty()
            || self.generations.len() > MANIFEST_MAX_GENERATIONS
            || self.objects.len() > MANIFEST_MAX_OBJECTS
        {
            return Err(ManifestError::CorruptOrTampered);
        }
        if !self
            .generations
            .windows(2)
            .all(|pair| pair[0].generation < pair[1].generation)
        {
            return Err(ManifestError::CorruptOrTampered);
        }
        let active_count = self
            .generations
            .iter()
            .filter(|entry| entry.state == GenerationState::Active)
            .count();
        if active_count != 1
            || !self.generations.iter().any(|entry| {
                entry.generation == self.active_key_generation
                    && entry.state == GenerationState::Active
            })
        {
            return Err(ManifestError::CorruptOrTampered);
        }
        if let Some(target) = self.rotation_target_generation {
            let Some(target_entry) = self
                .generations
                .iter()
                .find(|entry| entry.generation == target)
            else {
                return Err(ManifestError::CorruptOrTampered);
            };
            if self.generations.last().map(|entry| entry.generation) != Some(target) {
                return Err(ManifestError::CorruptOrTampered);
            }
            match self.rotation_phase {
                RotationPhase::Prepare | RotationPhase::Stage | RotationPhase::Verify => {
                    if target_entry.state != GenerationState::Staged
                        || self.active_key_generation >= target
                    {
                        return Err(ManifestError::CorruptOrTampered);
                    }
                }
                RotationPhase::Publish
                | RotationPhase::Anchor
                | RotationPhase::Activate
                | RotationPhase::Retire => {
                    if target_entry.state != GenerationState::Active
                        || self.active_key_generation != target
                        || !self.generations.iter().any(|entry| {
                            entry.generation < target && entry.state == GenerationState::Retained
                        })
                    {
                        return Err(ManifestError::CorruptOrTampered);
                    }
                }
                RotationPhase::None => unreachable!("validated absence of rotation target"),
            }
        }
        let generations: HashSet<_> = self
            .generations
            .iter()
            .map(|entry| entry.generation)
            .collect();
        let mut logical_ids = HashSet::new();
        let mut blob_nonces = HashSet::new();
        let mut previous_key: Option<(ManifestObjectKind, [u8; 16])> = None;
        for object in &self.objects {
            let key = (object.kind(), object.logical_id);
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(ManifestError::CorruptOrTampered);
            }
            previous_key = Some(key);
            if !logical_ids.insert(object.logical_id)
                || !generations.contains(&object.key_generation)
            {
                return Err(ManifestError::CorruptOrTampered);
            }
            match object.auth_metadata {
                ManifestAuthMetadata::GenericArtifactBlob { nonce } => {
                    if !(BOUNDED_BLOB_MIN_ENVELOPE_BYTES as u64
                        ..=BOUNDED_BLOB_MAX_ENVELOPE_BYTES as u64)
                        .contains(&object.ciphertext_length)
                        || !blob_nonces.insert((object.key_generation, nonce))
                    {
                        return Err(ManifestError::CorruptOrTampered);
                    }
                }
                ManifestAuthMetadata::StructuredStore => {
                    if object.logical_id != [0_u8; 16] {
                        return Err(ManifestError::CorruptOrTampered);
                    }
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    PlaintextTooLarge,
    TruncatedEnvelope,
    TrailingData,
    InvalidDomain,
    UnsupportedVersion,
    UnsupportedCipherSuite,
    InvalidGeneration,
    InvalidEpoch,
    LengthOverflow,
    LengthMismatch,
    ContextMismatch,
    EncryptionFailed,
    AuthenticationFailed,
    CorruptOrTampered,
}
impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PlaintextTooLarge => "manifest plaintext exceeds the 16 MiB v1 ceiling",
            Self::TruncatedEnvelope => "manifest envelope is truncated",
            Self::TrailingData => "manifest envelope contains trailing data",
            Self::InvalidDomain => "manifest envelope domain is invalid",
            Self::UnsupportedVersion => "manifest envelope version is unsupported",
            Self::UnsupportedCipherSuite => "manifest cipher suite is unsupported",
            Self::InvalidGeneration => "manifest key generation is invalid",
            Self::InvalidEpoch => "manifest freshness epoch is invalid",
            Self::LengthOverflow => "manifest length arithmetic overflowed",
            Self::LengthMismatch => "manifest declared lengths are inconsistent",
            Self::ContextMismatch => "manifest context does not match the requested state",
            Self::EncryptionFailed => "manifest encryption failed",
            Self::AuthenticationFailed => "manifest authentication failed",
            Self::CorruptOrTampered => "manifest plaintext is corrupt or non-canonical",
        })
    }
}
impl Error for ManifestError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshManifestError {
    Nonce(NonceLifecycleError),
    Envelope(ManifestError),
}
impl fmt::Display for FreshManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nonce(error) => write!(f, "manifest nonce lifecycle failed: {error}"),
            Self::Envelope(error) => write!(f, "manifest envelope failed: {error}"),
        }
    }
}
impl Error for FreshManifestError {}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ManifestError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ManifestError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(ManifestError::CorruptOrTampered);
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16, ManifestError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("exact u16"),
        ))
    }
    fn u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("exact u32"),
        ))
    }
    fn u64(&mut self) -> Result<u64, ManifestError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("exact u64"),
        ))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManifestError> {
        Ok(self.take(N)?.try_into().expect("exact array"))
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
fn build_aad(context: ManifestContext, ciphertext_length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_BYTES);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&AAD_SCHEMA.to_be_bytes());
    aad.extend_from_slice(context.vault_id.as_bytes());
    aad.extend_from_slice(&context.key_generation.get().to_be_bytes());
    aad.extend_from_slice(&context.freshness_epoch.get().to_be_bytes());
    aad.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    aad.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
    aad.extend_from_slice(&ciphertext_length.to_be_bytes());
    debug_assert_eq!(aad.len(), AAD_BYTES);
    aad
}
fn encoded_plaintext_len(value: &ManifestPlaintext) -> Result<usize, ManifestError> {
    let generation_bytes = value
        .generations
        .len()
        .checked_mul(10)
        .ok_or(ManifestError::LengthOverflow)?;
    let mut length = (PLAINTEXT_DOMAIN.len() + 82)
        .checked_add(generation_bytes)
        .ok_or(ManifestError::LengthOverflow)?;
    for object in &value.objects {
        let metadata_bytes = match object.auth_metadata {
            ManifestAuthMetadata::GenericArtifactBlob { .. } => MANIFEST_BLOB_AUTH_METADATA_BYTES,
            ManifestAuthMetadata::StructuredStore => 0,
        };
        length = length
            .checked_add(84 + metadata_bytes)
            .ok_or(ManifestError::LengthOverflow)?;
    }
    (length <= MANIFEST_MAX_PLAINTEXT_BYTES)
        .then_some(length)
        .ok_or(ManifestError::PlaintextTooLarge)
}
fn serialize_plaintext(value: &ManifestPlaintext) -> Result<Zeroizing<Vec<u8>>, ManifestError> {
    value.validate()?;
    let encoded_len = encoded_plaintext_len(value)?;
    let mut out = Zeroizing::new(Vec::with_capacity(encoded_len));
    out.extend_from_slice(PLAINTEXT_DOMAIN);
    out.extend_from_slice(&PLAINTEXT_SCHEMA.to_be_bytes());
    out.extend_from_slice(value.vault_id.as_bytes());
    out.extend_from_slice(&value.freshness_epoch.get().to_be_bytes());
    out.extend_from_slice(value.previous_manifest_hash.as_bytes());
    out.extend_from_slice(&value.active_key_generation.get().to_be_bytes());
    out.extend_from_slice(&(value.rotation_phase as u16).to_be_bytes());
    out.extend_from_slice(
        &value
            .rotation_target_generation
            .map_or(0, KeyGeneration::get)
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(value.generations.len())
            .map_err(|_| ManifestError::CorruptOrTampered)?
            .to_be_bytes(),
    );
    for entry in &value.generations {
        out.extend_from_slice(&entry.generation.get().to_be_bytes());
        out.extend_from_slice(&(entry.state as u16).to_be_bytes());
    }
    out.extend_from_slice(
        &u32::try_from(value.objects.len())
            .map_err(|_| ManifestError::CorruptOrTampered)?
            .to_be_bytes(),
    );
    for object in &value.objects {
        out.extend_from_slice(&(object.kind() as u16).to_be_bytes());
        out.extend_from_slice(&object.logical_id);
        out.extend_from_slice(&object.storage_id);
        out.extend_from_slice(&object.key_generation.get().to_be_bytes());
        out.extend_from_slice(&object.ciphertext_length.to_be_bytes());
        out.extend_from_slice(&object.ciphertext_sha256);
        match object.auth_metadata {
            ManifestAuthMetadata::GenericArtifactBlob { nonce } => {
                out.extend_from_slice(&(MANIFEST_BLOB_AUTH_METADATA_BYTES as u16).to_be_bytes());
                out.extend_from_slice(&BLOB_ENVELOPE_VERSION.to_be_bytes());
                out.extend_from_slice(&BLOB_CIPHER_SUITE.to_be_bytes());
                out.extend_from_slice(&nonce);
            }
            ManifestAuthMetadata::StructuredStore => out.extend_from_slice(&0_u16.to_be_bytes()),
        }
    }
    debug_assert_eq!(out.len(), encoded_len);
    Ok(out)
}
fn parse_plaintext(bytes: &[u8]) -> Result<ManifestPlaintext, ManifestError> {
    if bytes.len() > MANIFEST_MAX_PLAINTEXT_BYTES {
        return Err(ManifestError::PlaintextTooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(PLAINTEXT_DOMAIN.len())? != PLAINTEXT_DOMAIN || cursor.u16()? != PLAINTEXT_SCHEMA
    {
        return Err(ManifestError::CorruptOrTampered);
    }
    let vault_id = VaultId::from_bytes(cursor.array()?);
    let freshness_epoch =
        FreshnessEpoch::new(cursor.u64()?).map_err(|_| ManifestError::CorruptOrTampered)?;
    let previous_manifest_hash = ManifestHash::from_bytes(cursor.array()?);
    let active_key_generation =
        KeyGeneration::new(cursor.u64()?).map_err(|_| ManifestError::CorruptOrTampered)?;
    let rotation_phase = RotationPhase::parse(cursor.u16()?)?;
    let raw_target = cursor.u64()?;
    let rotation_target_generation = if raw_target == 0 {
        None
    } else {
        Some(KeyGeneration::new(raw_target).map_err(|_| ManifestError::CorruptOrTampered)?)
    };
    let generation_count = usize::from(cursor.u16()?);
    let generation_bytes = generation_count
        .checked_mul(10)
        .and_then(|bytes| bytes.checked_add(4))
        .ok_or(ManifestError::LengthOverflow)?;
    if generation_count == 0
        || generation_count > MANIFEST_MAX_GENERATIONS
        || cursor.remaining() < generation_bytes
    {
        return Err(ManifestError::CorruptOrTampered);
    }
    let mut generations = Vec::with_capacity(generation_count);
    for _ in 0..generation_count {
        generations.push(ManifestGeneration::new(
            KeyGeneration::new(cursor.u64()?).map_err(|_| ManifestError::CorruptOrTampered)?,
            GenerationState::parse(cursor.u16()?)?,
        ));
    }
    let object_count =
        usize::try_from(cursor.u32()?).map_err(|_| ManifestError::CorruptOrTampered)?;
    const MIN_OBJECT_BYTES: usize = 84;
    let minimum_object_bytes = object_count
        .checked_mul(MIN_OBJECT_BYTES)
        .ok_or(ManifestError::LengthOverflow)?;
    if object_count > MANIFEST_MAX_OBJECTS || cursor.remaining() < minimum_object_bytes {
        return Err(ManifestError::CorruptOrTampered);
    }
    let mut objects = Vec::with_capacity(object_count);
    for _ in 0..object_count {
        let kind = ManifestObjectKind::parse(cursor.u16()?)?;
        let logical_id = cursor.array()?;
        let storage_id = cursor.array()?;
        let key_generation =
            KeyGeneration::new(cursor.u64()?).map_err(|_| ManifestError::CorruptOrTampered)?;
        let ciphertext_length = cursor.u64()?;
        let ciphertext_sha256 = cursor.array()?;
        let metadata_length = usize::from(cursor.u16()?);
        if metadata_length > 64 {
            return Err(ManifestError::CorruptOrTampered);
        }
        let metadata = cursor.take(metadata_length)?;
        let auth_metadata = match kind {
            ManifestObjectKind::GenericArtifactBlob => {
                if metadata.len() != MANIFEST_BLOB_AUTH_METADATA_BYTES
                    || u16::from_be_bytes(metadata[0..2].try_into().expect("blob version"))
                        != BLOB_ENVELOPE_VERSION
                    || u16::from_be_bytes(metadata[2..4].try_into().expect("blob suite"))
                        != BLOB_CIPHER_SUITE
                {
                    return Err(ManifestError::CorruptOrTampered);
                }
                ManifestAuthMetadata::GenericArtifactBlob {
                    nonce: metadata[4..].try_into().expect("blob nonce"),
                }
            }
            ManifestObjectKind::StructuredStore => {
                if !metadata.is_empty() {
                    return Err(ManifestError::CorruptOrTampered);
                }
                ManifestAuthMetadata::StructuredStore
            }
        };
        objects.push(ManifestObject::new(
            logical_id,
            storage_id,
            key_generation,
            ciphertext_length,
            ciphertext_sha256,
            auth_metadata,
        ));
    }
    if !cursor.finished() {
        return Err(ManifestError::CorruptOrTampered);
    }
    ManifestPlaintext::new(
        vault_id,
        freshness_epoch,
        previous_manifest_hash,
        active_key_generation,
        (rotation_phase, rotation_target_generation),
        generations,
        objects,
    )
}
struct ParsedEnvelope<'a> {
    context: ManifestContext,
    nonce: [u8; 24],
    ciphertext: &'a [u8],
}
fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, ManifestError> {
    if bytes.len() < MANIFEST_HEADER_BYTES {
        return Err(ManifestError::TruncatedEnvelope);
    }
    if &bytes[..ENVELOPE_DOMAIN.len()] != ENVELOPE_DOMAIN {
        return Err(ManifestError::InvalidDomain);
    }
    let mut cursor = Cursor {
        bytes,
        offset: ENVELOPE_DOMAIN.len(),
    };
    if cursor.u16()? != ENVELOPE_VERSION {
        return Err(ManifestError::UnsupportedVersion);
    }
    if cursor.u16()? != CIPHER_SUITE {
        return Err(ManifestError::UnsupportedCipherSuite);
    }
    let vault_id = VaultId::from_bytes(cursor.array()?);
    let key_generation =
        KeyGeneration::new(cursor.u64()?).map_err(|_| ManifestError::InvalidGeneration)?;
    let freshness_epoch =
        FreshnessEpoch::new(cursor.u64()?).map_err(|_| ManifestError::InvalidEpoch)?;
    let nonce = cursor.array()?;
    let ciphertext_length =
        usize::try_from(cursor.u32()?).map_err(|_| ManifestError::LengthOverflow)?;
    if !(MANIFEST_TAG_BYTES..=MANIFEST_MAX_PLAINTEXT_BYTES + MANIFEST_TAG_BYTES)
        .contains(&ciphertext_length)
    {
        return Err(ManifestError::LengthMismatch);
    }
    let expected = MANIFEST_HEADER_BYTES
        .checked_add(ciphertext_length)
        .ok_or(ManifestError::LengthOverflow)?;
    if bytes.len() < expected {
        return Err(ManifestError::TruncatedEnvelope);
    }
    if bytes.len() > expected {
        return Err(ManifestError::TrailingData);
    }
    Ok(ParsedEnvelope {
        context: ManifestContext::new(vault_id, key_generation, freshness_epoch),
        nonce,
        ciphertext: &bytes[MANIFEST_HEADER_BYTES..],
    })
}
fn encrypt_manifest_with_nonce(
    vrk: &OwnedKeyMaterial,
    context: ManifestContext,
    nonce: [u8; MANIFEST_NONCE_BYTES],
    plaintext: &ManifestPlaintext,
) -> Result<Vec<u8>, ManifestError> {
    if plaintext.vault_id != context.vault_id
        || plaintext.freshness_epoch != context.freshness_epoch
    {
        return Err(ManifestError::ContextMismatch);
    }
    if !plaintext
        .generations
        .iter()
        .any(|entry| entry.generation == context.key_generation)
    {
        return Err(ManifestError::ContextMismatch);
    }
    let encoded = serialize_plaintext(plaintext)?;
    let ciphertext_length = encoded
        .len()
        .checked_add(MANIFEST_TAG_BYTES)
        .ok_or(ManifestError::LengthOverflow)?;
    let ciphertext_u32 =
        u32::try_from(ciphertext_length).map_err(|_| ManifestError::LengthOverflow)?;
    let aad = build_aad(context, ciphertext_u32);
    let key = KeyDerivationContext::new(
        context.vault_id,
        context.key_generation,
        KeyPurpose::FreshnessManifest,
    )
    .derive_purpose_key(vrk);
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).expect("manifest nonce is exactly 24 bytes");
    let ciphertext = key
        .with_bytes(|bytes| {
            XChaCha20Poly1305::new_from_slice(bytes)
                .expect("manifest key is 32 bytes")
                .encrypt(
                    nonce_ref,
                    Payload {
                        msg: encoded.as_slice(),
                        aad: &aad,
                    },
                )
        })
        .map_err(|_| ManifestError::EncryptionFailed)?;
    if ciphertext.len() != ciphertext_length {
        return Err(ManifestError::LengthMismatch);
    }
    let mut out = Vec::with_capacity(MANIFEST_HEADER_BYTES + ciphertext.len());
    out.extend_from_slice(ENVELOPE_DOMAIN);
    out.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    out.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
    out.extend_from_slice(context.vault_id.as_bytes());
    out.extend_from_slice(&context.key_generation.get().to_be_bytes());
    out.extend_from_slice(&context.freshness_epoch.get().to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext_u32.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    if out.len() > MANIFEST_MAX_ENVELOPE_BYTES {
        return Err(ManifestError::PlaintextTooLarge);
    }
    Ok(out)
}
pub fn encrypt_fresh_manifest(
    ledger: &mut NonceReservationLedger,
    vrk: &OwnedKeyMaterial,
    context: ManifestContext,
    plaintext: &ManifestPlaintext,
) -> Result<(NonceReservation, Vec<u8>), FreshManifestError> {
    let reservation = ledger
        .reserve_fresh_manifest_nonce(context.vault_id, context.key_generation)
        .map_err(FreshManifestError::Nonce)?;
    let envelope = encrypt_manifest_with_nonce(vrk, context, reservation.nonce(), plaintext)
        .map_err(FreshManifestError::Envelope)?;
    Ok((reservation, envelope))
}

pub(crate) fn encrypt_fresh_manifest_avoiding_reservation(
    ledger: &mut NonceReservationLedger,
    vrk: &OwnedKeyMaterial,
    context: ManifestContext,
    plaintext: &ManifestPlaintext,
    forbidden: NonceReservation,
) -> Result<(NonceReservation, Vec<u8>), FreshManifestError> {
    let reservation = ledger
        .reserve_fresh_manifest_nonce_avoiding(context.vault_id, context.key_generation, forbidden)
        .map_err(FreshManifestError::Nonce)?;
    let envelope = encrypt_manifest_with_nonce(vrk, context, reservation.nonce(), plaintext)
        .map_err(FreshManifestError::Envelope)?;
    Ok((reservation, envelope))
}

pub fn decrypt_manifest(
    vrk: &OwnedKeyMaterial,
    expected: ManifestContext,
    envelope: &[u8],
) -> Result<ManifestPlaintext, ManifestError> {
    let parsed = parse_envelope(envelope)?;
    if parsed.context != expected {
        return Err(ManifestError::ContextMismatch);
    }
    let aad = build_aad(
        parsed.context,
        u32::try_from(parsed.ciphertext.len()).map_err(|_| ManifestError::LengthOverflow)?,
    );
    let key = KeyDerivationContext::new(
        parsed.context.vault_id,
        parsed.context.key_generation,
        KeyPurpose::FreshnessManifest,
    )
    .derive_purpose_key(vrk);
    let nonce_ref =
        <&XNonce>::try_from(parsed.nonce.as_slice()).expect("parsed manifest nonce is 24 bytes");
    let plaintext = Zeroizing::new(
        key.with_bytes(|bytes| {
            XChaCha20Poly1305::new_from_slice(bytes)
                .expect("manifest key is 32 bytes")
                .decrypt(
                    nonce_ref,
                    Payload {
                        msg: parsed.ciphertext,
                        aad: &aad,
                    },
                )
        })
        .map_err(|_| ManifestError::AuthenticationFailed)?,
    );
    let decoded = parse_plaintext(plaintext.as_slice())?;
    if decoded.vault_id != parsed.context.vault_id
        || decoded.freshness_epoch != parsed.context.freshness_epoch
        || !decoded
            .generations
            .iter()
            .any(|entry| entry.generation == parsed.context.key_generation)
    {
        return Err(ManifestError::ContextMismatch);
    }
    Ok(decoded)
}
#[must_use]
pub fn manifest_hash(envelope: &[u8]) -> ManifestHash {
    ManifestHash::from_bytes(Sha256::digest(envelope).into())
}

pub fn manifest_context(envelope: &[u8]) -> Result<ManifestContext, ManifestError> {
    Ok(parse_envelope(envelope)?.context)
}

pub(crate) fn manifest_nonce_reservation(
    envelope: &[u8],
) -> Result<NonceReservation, ManifestError> {
    let parsed = parse_envelope(envelope)?;
    Ok(NonceReservation::new(
        parsed.context.vault_id,
        NoncePurpose::FreshnessManifest,
        parsed.context.key_generation,
        parsed.nonce,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn vault() -> VaultId {
        VaultId::from_bytes([0x11; 16])
    }
    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).expect("non-zero")
    }
    fn epoch(value: u64) -> FreshnessEpoch {
        FreshnessEpoch::new(value).expect("non-zero")
    }
    fn key() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([0x22; 32])
    }
    fn base_manifest() -> ManifestPlaintext {
        ManifestPlaintext::new(
            vault(),
            epoch(1),
            ManifestHash::from_bytes([0; 32]),
            generation(1),
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(
                generation(1),
                GenerationState::Active,
            )],
            vec![ManifestObject::new(
                [0; 16],
                [0x33; 16],
                generation(1),
                4096,
                [0x44; 32],
                ManifestAuthMetadata::StructuredStore,
            )],
        )
        .expect("valid manifest")
    }
    #[test]
    fn canonical_round_trip_and_hash_bind_exact_envelope() {
        let context = ManifestContext::new(vault(), generation(1), epoch(1));
        let envelope = encrypt_manifest_with_nonce(&key(), context, [0x55; 24], &base_manifest())
            .expect("encrypt");
        assert_eq!(&envelope[..ENVELOPE_DOMAIN.len()], ENVELOPE_DOMAIN);
        assert_eq!(
            decrypt_manifest(&key(), context, &envelope).expect("decrypt"),
            base_manifest()
        );
        let expected_hash = ManifestHash::from_bytes([
            0x64, 0x96, 0xd1, 0x17, 0x1c, 0xbd, 0xae, 0xbb, 0x01, 0xce, 0x7c, 0xff, 0x14, 0x84,
            0xcd, 0x87, 0xe7, 0xea, 0x10, 0x73, 0x48, 0x88, 0xed, 0xb9, 0xa9, 0xe1, 0x44, 0xc5,
            0xd2, 0x61, 0xd9, 0x44,
        ]);
        assert_eq!(manifest_hash(&envelope), expected_hash);
        let mut tampered = envelope.clone();
        tampered[MANIFEST_HEADER_BYTES] ^= 1;
        assert_ne!(manifest_hash(&tampered), expected_hash);
        assert_eq!(
            decrypt_manifest(&key(), context, &tampered),
            Err(ManifestError::AuthenticationFailed)
        );

        let mut ledger = NonceReservationLedger::new(vault());
        let (reservation, fresh) =
            encrypt_fresh_manifest(&mut ledger, &key(), context, &base_manifest())
                .expect("fresh manifest");
        assert!(ledger.contains(reservation));
        assert_eq!(
            decrypt_manifest(&key(), context, &fresh).expect("decrypt fresh"),
            base_manifest()
        );
    }
    fn manifest_with_objects(
        objects: Vec<ManifestObject>,
    ) -> Result<ManifestPlaintext, ManifestError> {
        ManifestPlaintext::new(
            vault(),
            epoch(1),
            ManifestHash::from_bytes([0; 32]),
            generation(1),
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(
                generation(1),
                GenerationState::Active,
            )],
            objects,
        )
    }

    #[test]
    fn envelope_context_and_structure_fail_closed() {
        let context = ManifestContext::new(vault(), generation(1), epoch(1));
        let envelope = encrypt_manifest_with_nonce(&key(), context, [0x66; 24], &base_manifest())
            .expect("encrypt");
        assert_eq!(
            decrypt_manifest(
                &key(),
                ManifestContext::new(vault(), generation(2), epoch(1)),
                &envelope,
            ),
            Err(ManifestError::ContextMismatch),
        );
        assert_eq!(
            decrypt_manifest(&key(), context, &envelope[..envelope.len() - 1]),
            Err(ManifestError::TruncatedEnvelope),
        );
        let mut trailing = envelope;
        trailing.push(0);
        assert_eq!(
            decrypt_manifest(&key(), context, &trailing),
            Err(ManifestError::TrailingData),
        );
    }

    #[test]
    fn canonical_plaintext_rejects_bad_genesis_rotation_inventory_and_nonce_reuse() {
        assert_eq!(
            ManifestPlaintext::new(
                vault(),
                epoch(2),
                ManifestHash::from_bytes([0; 32]),
                generation(1),
                (RotationPhase::None, None),
                vec![ManifestGeneration::new(
                    generation(1),
                    GenerationState::Active,
                )],
                vec![],
            ),
            Err(ManifestError::CorruptOrTampered),
        );
        assert_eq!(
            ManifestPlaintext::new(
                vault(),
                epoch(1),
                ManifestHash::from_bytes([0; 32]),
                generation(1),
                (RotationPhase::Prepare, None),
                vec![ManifestGeneration::new(
                    generation(1),
                    GenerationState::Active,
                )],
                vec![],
            ),
            Err(ManifestError::CorruptOrTampered),
        );
        let nonce = [0x77; 24];
        let objects = vec![
            ManifestObject::new(
                [1; 16],
                [2; 16],
                generation(1),
                (BOUNDED_BLOB_MIN_ENVELOPE_BYTES - 1) as u64,
                [3; 32],
                ManifestAuthMetadata::GenericArtifactBlob { nonce },
            ),
            ManifestObject::new(
                [2; 16],
                [4; 16],
                generation(1),
                BOUNDED_BLOB_MIN_ENVELOPE_BYTES as u64,
                [5; 32],
                ManifestAuthMetadata::GenericArtifactBlob { nonce },
            ),
        ];
        assert_eq!(
            manifest_with_objects(objects.clone()),
            Err(ManifestError::CorruptOrTampered),
        );
        let mut canonical_length = objects;
        canonical_length[0].ciphertext_length = BOUNDED_BLOB_MIN_ENVELOPE_BYTES as u64;
        assert_eq!(
            manifest_with_objects(canonical_length),
            Err(ManifestError::CorruptOrTampered),
        );
    }
}

use crate::vault::{FreshnessEpoch, KeyGeneration, ManifestHash, VaultId};
use crate::vault_backup::{
    BACKUP_BOOTSTRAP_SLOT_BYTES, BACKUP_CHUNK_PLAINTEXT_MAX, BACKUP_DATA_OBJECT_COUNT_MAX,
    BACKUP_DATA_OBJECT_COUNT_MIN, BACKUP_INDEX_CIPHERTEXT_MAX, BACKUP_INDEX_CIPHERTEXT_MIN,
    BACKUP_NONCE_BYTES, BACKUP_TAG_BYTES, BackupCodecError, BackupObjectId, BackupSetId,
    derive_backup_index_key,
};
use crate::vault_keys::OwnedKeyMaterial;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
pub const BACKUP_INDEX_PLAINTEXT_MAX: usize = 67_108_864;
pub const BACKUP_INDEX_PAYLOAD_COUNT_MIN: u32 = 2;
pub const BACKUP_INDEX_PAYLOAD_COUNT_MAX: u32 = 262_145;
const INDEX_PLAINTEXT_DOMAIN_PREFIX: &[u8] = b"\x00\x20HIMSAT/BACKUP/INDEX/PLAINTEXT/v1";
const INDEX_AAD_DOMAIN_PREFIX: &[u8] = b"\x00\x1aHIMSAT/BACKUP/INDEX/AAD/v1";
const INDEX_SCHEMA_VERSION: u16 = 1;
const INDEX_HEADER_BYTES: usize = 104;
const INDEX_PAYLOAD_FIXED_BYTES: usize = 82;
const INDEX_CHUNK_RECORD_BYTES: usize = 24;
const INDEX_AAD_BYTES: usize = 118;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum BackupIndexPayloadKind {
    Manifest = 1,
    StructuredStore = 2,
    GenericArtifactBlob = 3,
}
impl BackupIndexPayloadKind {
    fn parse(value: u16) -> Result<Self, BackupCodecError> {
        match value {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::StructuredStore),
            3 => Ok(Self::GenericArtifactBlob),
            _ => Err(BackupCodecError::CorruptOrTampered),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupIndexChunk {
    object_id: BackupObjectId,
    plaintext_chunk_length: u32,
}
impl BackupIndexChunk {
    pub fn new(
        object_id: BackupObjectId,
        plaintext_chunk_length: u32,
    ) -> Result<Self, BackupCodecError> {
        if plaintext_chunk_length == 0
            || plaintext_chunk_length as usize > BACKUP_CHUNK_PLAINTEXT_MAX
        {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        Ok(Self {
            object_id,
            plaintext_chunk_length,
        })
    }
    #[must_use]
    pub const fn object_id(&self) -> BackupObjectId {
        self.object_id
    }
    #[must_use]
    pub const fn plaintext_chunk_length(&self) -> u32 {
        self.plaintext_chunk_length
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupIndexPayload {
    kind: BackupIndexPayloadKind,
    logical_id: [u8; 16],
    source_storage_id: [u8; 16],
    exact_payload_length: u64,
    exact_payload_sha256: [u8; 32],
    chunks: Vec<BackupIndexChunk>,
}
impl BackupIndexPayload {
    pub fn new(
        kind: BackupIndexPayloadKind,
        logical_id: [u8; 16],
        source_storage_id: [u8; 16],
        exact_payload_length: u64,
        exact_payload_sha256: [u8; 32],
        chunks: Vec<BackupIndexChunk>,
    ) -> Result<Self, BackupCodecError> {
        let value = Self {
            kind,
            logical_id,
            source_storage_id,
            exact_payload_length,
            exact_payload_sha256,
            chunks,
        };
        value.validate_shape()?;
        Ok(value)
    }
    fn validate_shape(&self) -> Result<(), BackupCodecError> {
        if self.chunks.is_empty() || self.chunks.len() > BACKUP_DATA_OBJECT_COUNT_MAX as usize {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let mut total = 0_u64;
        for chunk in &self.chunks {
            if chunk.plaintext_chunk_length == 0
                || chunk.plaintext_chunk_length as usize > BACKUP_CHUNK_PLAINTEXT_MAX
            {
                return Err(BackupCodecError::CorruptOrTampered);
            }
            total = total
                .checked_add(u64::from(chunk.plaintext_chunk_length))
                .ok_or(BackupCodecError::CorruptOrTampered)?;
        }
        if total != self.exact_payload_length {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        match self.kind {
            BackupIndexPayloadKind::Manifest => {
                if self.logical_id != [0_u8; 16] || self.source_storage_id != [0_u8; 16] {
                    return Err(BackupCodecError::CorruptOrTampered);
                }
            }
            BackupIndexPayloadKind::StructuredStore => {
                if self.logical_id != [0_u8; 16] {
                    return Err(BackupCodecError::CorruptOrTampered);
                }
            }
            BackupIndexPayloadKind::GenericArtifactBlob => {}
        }
        Ok(())
    }
    #[must_use]
    pub const fn kind(&self) -> BackupIndexPayloadKind {
        self.kind
    }
    #[must_use]
    pub const fn logical_id(&self) -> [u8; 16] {
        self.logical_id
    }
    #[must_use]
    pub const fn source_storage_id(&self) -> [u8; 16] {
        self.source_storage_id
    }
    #[must_use]
    pub const fn exact_payload_length(&self) -> u64 {
        self.exact_payload_length
    }
    #[must_use]
    pub const fn exact_payload_sha256(&self) -> [u8; 32] {
        self.exact_payload_sha256
    }
    #[must_use]
    pub fn chunks(&self) -> &[BackupIndexChunk] {
        &self.chunks
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupIndexPlaintext {
    vault_id: VaultId,
    key_generation: KeyGeneration,
    source_freshness_epoch: FreshnessEpoch,
    source_manifest_hash: ManifestHash,
    payloads: Vec<BackupIndexPayload>,
}
impl BackupIndexPlaintext {
    pub fn new(
        vault_id: VaultId,
        key_generation: KeyGeneration,
        source_freshness_epoch: FreshnessEpoch,
        source_manifest_hash: ManifestHash,
        payloads: Vec<BackupIndexPayload>,
    ) -> Result<Self, BackupCodecError> {
        let value = Self {
            vault_id,
            key_generation,
            source_freshness_epoch,
            source_manifest_hash,
            payloads,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<u32, BackupCodecError> {
        if !(BACKUP_INDEX_PAYLOAD_COUNT_MIN as usize..=BACKUP_INDEX_PAYLOAD_COUNT_MAX as usize)
            .contains(&self.payloads.len())
        {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        if self.payloads[0].kind != BackupIndexPayloadKind::Manifest
            || self.payloads[1].kind != BackupIndexPayloadKind::StructuredStore
        {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let mut payload_keys = HashSet::with_capacity(self.payloads.len());
        let mut object_ids = HashSet::new();
        let mut previous_blob_id: Option<[u8; 16]> = None;
        let mut object_count = 0_u32;
        for (ordinal, payload) in self.payloads.iter().enumerate() {
            payload.validate_shape()?;
            if !payload_keys.insert((payload.kind, payload.logical_id)) {
                return Err(BackupCodecError::CorruptOrTampered);
            }
            if ordinal >= 2 {
                if payload.kind != BackupIndexPayloadKind::GenericArtifactBlob
                    || previous_blob_id.is_some_and(|previous| previous >= payload.logical_id)
                {
                    return Err(BackupCodecError::CorruptOrTampered);
                }
                previous_blob_id = Some(payload.logical_id);
            }
            let chunk_count = u32::try_from(payload.chunks.len())
                .map_err(|_| BackupCodecError::CorruptOrTampered)?;
            object_count = object_count
                .checked_add(chunk_count)
                .ok_or(BackupCodecError::CorruptOrTampered)?;
            if object_count > BACKUP_DATA_OBJECT_COUNT_MAX {
                return Err(BackupCodecError::CorruptOrTampered);
            }
            for chunk in &payload.chunks {
                if !object_ids.insert(chunk.object_id) {
                    return Err(BackupCodecError::CorruptOrTampered);
                }
            }
        }
        if !(BACKUP_DATA_OBJECT_COUNT_MIN..=BACKUP_DATA_OBJECT_COUNT_MAX).contains(&object_count) {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        Ok(object_count)
    }
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }
    #[must_use]
    pub const fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }
    #[must_use]
    pub const fn source_freshness_epoch(&self) -> FreshnessEpoch {
        self.source_freshness_epoch
    }
    #[must_use]
    pub const fn source_manifest_hash(&self) -> ManifestHash {
        self.source_manifest_hash
    }
    #[must_use]
    pub fn payloads(&self) -> &[BackupIndexPayload] {
        &self.payloads
    }
    pub fn data_object_count(&self) -> Result<u32, BackupCodecError> {
        self.validate()
    }
}
pub fn encode_backup_index_plaintext(
    index: &BackupIndexPlaintext,
) -> Result<Vec<u8>, BackupCodecError> {
    let data_object_count = index.validate()?;
    let payload_count =
        u32::try_from(index.payloads.len()).map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let payload_bytes = index
        .payloads
        .len()
        .checked_mul(INDEX_PAYLOAD_FIXED_BYTES)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    let chunk_bytes = (data_object_count as usize)
        .checked_mul(INDEX_CHUNK_RECORD_BYTES)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    let encoded_len = INDEX_HEADER_BYTES
        .checked_add(payload_bytes)
        .and_then(|value| value.checked_add(chunk_bytes))
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    if encoded_len > BACKUP_INDEX_PLAINTEXT_MAX {
        return Err(BackupCodecError::PlaintextTooLarge);
    }
    let mut output = Vec::with_capacity(encoded_len);
    output.extend_from_slice(INDEX_PLAINTEXT_DOMAIN_PREFIX);
    output.extend_from_slice(&INDEX_SCHEMA_VERSION.to_be_bytes());
    output.extend_from_slice(index.vault_id.as_bytes());
    output.extend_from_slice(&index.key_generation.get().to_be_bytes());
    output.extend_from_slice(&index.source_freshness_epoch.get().to_be_bytes());
    output.extend_from_slice(index.source_manifest_hash.as_bytes());
    output.extend_from_slice(&payload_count.to_be_bytes());
    for (payload_ordinal, payload) in index.payloads.iter().enumerate() {
        output.extend_from_slice(
            &u32::try_from(payload_ordinal)
                .map_err(|_| BackupCodecError::CorruptOrTampered)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&(payload.kind as u16).to_be_bytes());
        output.extend_from_slice(&payload.logical_id);
        output.extend_from_slice(&payload.source_storage_id);
        output.extend_from_slice(&payload.exact_payload_length.to_be_bytes());
        output.extend_from_slice(&payload.exact_payload_sha256);
        output.extend_from_slice(
            &u32::try_from(payload.chunks.len())
                .map_err(|_| BackupCodecError::CorruptOrTampered)?
                .to_be_bytes(),
        );
        for (chunk_ordinal, chunk) in payload.chunks.iter().enumerate() {
            output.extend_from_slice(
                &u32::try_from(chunk_ordinal)
                    .map_err(|_| BackupCodecError::CorruptOrTampered)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(chunk.object_id.as_bytes());
            output.extend_from_slice(&chunk.plaintext_chunk_length.to_be_bytes());
        }
    }
    if output.len() != encoded_len {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(output)
}
struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], BackupCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(BackupCodecError::CorruptOrTampered)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(BackupCodecError::CorruptOrTampered)?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BackupCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BackupCodecError::CorruptOrTampered)
    }
    fn u16(&mut self) -> Result<u16, BackupCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, BackupCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, BackupCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }
    fn finished(&self) -> bool {
        self.offset == self.input.len()
    }
}
pub fn decode_backup_index_plaintext(
    input: &[u8],
    expected_data_object_count: u32,
) -> Result<BackupIndexPlaintext, BackupCodecError> {
    if input.len() < INDEX_HEADER_BYTES || input.len() > BACKUP_INDEX_PLAINTEXT_MAX {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if !(BACKUP_DATA_OBJECT_COUNT_MIN..=BACKUP_DATA_OBJECT_COUNT_MAX)
        .contains(&expected_data_object_count)
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let mut cursor = Cursor::new(input);
    if cursor.take(INDEX_PLAINTEXT_DOMAIN_PREFIX.len())? != INDEX_PLAINTEXT_DOMAIN_PREFIX
        || cursor.u16()? != INDEX_SCHEMA_VERSION
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let vault_id = VaultId::from_bytes(cursor.array()?);
    let key_generation =
        KeyGeneration::new(cursor.u64()?).map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let source_freshness_epoch =
        FreshnessEpoch::new(cursor.u64()?).map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let source_manifest_hash = ManifestHash::from_bytes(cursor.array()?);
    let payload_count = cursor.u32()?;
    if !(BACKUP_INDEX_PAYLOAD_COUNT_MIN..=BACKUP_INDEX_PAYLOAD_COUNT_MAX).contains(&payload_count) {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let payload_count_usize = payload_count as usize;
    let minimum_payload_bytes = payload_count_usize
        .checked_mul(INDEX_PAYLOAD_FIXED_BYTES)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    if cursor.remaining() < minimum_payload_bytes {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let mut payloads = Vec::with_capacity(payload_count_usize);
    let mut observed_object_count = 0_u32;
    for payload_ordinal in 0..payload_count {
        if cursor.u32()? != payload_ordinal {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let kind = BackupIndexPayloadKind::parse(cursor.u16()?)?;
        let logical_id = cursor.array()?;
        let source_storage_id = cursor.array()?;
        let exact_payload_length = cursor.u64()?;
        let exact_payload_sha256 = cursor.array()?;
        let chunk_count = cursor.u32()?;
        if chunk_count == 0 || chunk_count > BACKUP_DATA_OBJECT_COUNT_MAX {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        observed_object_count = observed_object_count
            .checked_add(chunk_count)
            .ok_or(BackupCodecError::CorruptOrTampered)?;
        if observed_object_count > BACKUP_DATA_OBJECT_COUNT_MAX {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let chunk_count_usize = chunk_count as usize;
        let chunk_bytes = chunk_count_usize
            .checked_mul(INDEX_CHUNK_RECORD_BYTES)
            .ok_or(BackupCodecError::CorruptOrTampered)?;
        let remaining_payload_count = (payload_count - payload_ordinal - 1) as usize;
        let remaining_payload_bytes = remaining_payload_count
            .checked_mul(INDEX_PAYLOAD_FIXED_BYTES)
            .ok_or(BackupCodecError::CorruptOrTampered)?;
        let required_remaining = chunk_bytes
            .checked_add(remaining_payload_bytes)
            .ok_or(BackupCodecError::CorruptOrTampered)?;
        if cursor.remaining() < required_remaining {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let mut chunks = Vec::with_capacity(chunk_count_usize);
        for chunk_ordinal in 0..chunk_count {
            if cursor.u32()? != chunk_ordinal {
                return Err(BackupCodecError::CorruptOrTampered);
            }
            chunks.push(BackupIndexChunk::new(
                BackupObjectId::from_bytes(cursor.array()?)?,
                cursor.u32()?,
            )?);
        }
        payloads.push(BackupIndexPayload::new(
            kind,
            logical_id,
            source_storage_id,
            exact_payload_length,
            exact_payload_sha256,
            chunks,
        )?);
    }
    if !cursor.finished() || observed_object_count != expected_data_object_count {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    BackupIndexPlaintext::new(
        vault_id,
        key_generation,
        source_freshness_epoch,
        source_manifest_hash,
        payloads,
    )
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupIndexContext {
    set_id: BackupSetId,
    key_generation: KeyGeneration,
    data_object_count: u32,
}
impl BackupIndexContext {
    pub fn new(
        set_id: BackupSetId,
        key_generation: KeyGeneration,
        data_object_count: u32,
    ) -> Result<Self, BackupCodecError> {
        if !(BACKUP_DATA_OBJECT_COUNT_MIN..=BACKUP_DATA_OBJECT_COUNT_MAX)
            .contains(&data_object_count)
        {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        Ok(Self {
            set_id,
            key_generation,
            data_object_count,
        })
    }
    #[must_use]
    pub const fn set_id(&self) -> BackupSetId {
        self.set_id
    }
    #[must_use]
    pub const fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }
    #[must_use]
    pub const fn data_object_count(&self) -> u32 {
        self.data_object_count
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBackupIndex {
    nonce: [u8; BACKUP_NONCE_BYTES],
    ciphertext_and_tag: Vec<u8>,
}
impl EncryptedBackupIndex {
    pub fn new(
        nonce: [u8; BACKUP_NONCE_BYTES],
        ciphertext_and_tag: Vec<u8>,
    ) -> Result<Self, BackupCodecError> {
        validate_index_ciphertext_len(ciphertext_and_tag.len())?;
        Ok(Self {
            nonce,
            ciphertext_and_tag,
        })
    }
    #[must_use]
    pub const fn nonce(&self) -> &[u8; BACKUP_NONCE_BYTES] {
        &self.nonce
    }
    #[must_use]
    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }
}
fn validate_index_ciphertext_len(len: usize) -> Result<(), BackupCodecError> {
    if !(BACKUP_INDEX_CIPHERTEXT_MIN..=BACKUP_INDEX_CIPHERTEXT_MAX).contains(&len) {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(())
}
fn index_aad(
    context: BackupIndexContext,
    nonce: &[u8; BACKUP_NONCE_BYTES],
    ciphertext_len: u32,
    bootstrap_slot: &[u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
) -> Vec<u8> {
    let bootstrap_hash = Sha256::digest(bootstrap_slot);
    let mut aad = Vec::with_capacity(INDEX_AAD_BYTES);
    aad.extend_from_slice(INDEX_AAD_DOMAIN_PREFIX);
    aad.extend_from_slice(&INDEX_SCHEMA_VERSION.to_be_bytes());
    aad.extend_from_slice(context.set_id.as_bytes());
    aad.extend_from_slice(&context.key_generation.get().to_be_bytes());
    aad.extend_from_slice(&context.data_object_count.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&ciphertext_len.to_be_bytes());
    aad.extend_from_slice(&bootstrap_hash);
    debug_assert_eq!(aad.len(), INDEX_AAD_BYTES);
    aad
}
fn encrypt_backup_index_with_nonce(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    context: BackupIndexContext,
    bootstrap_slot: &[u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
    nonce: [u8; BACKUP_NONCE_BYTES],
    index: &BackupIndexPlaintext,
) -> Result<EncryptedBackupIndex, BackupCodecError> {
    if index.vault_id != vault_id || index.key_generation != context.key_generation {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if index.validate()? != context.data_object_count {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let plaintext = encode_backup_index_plaintext(index)?;
    let ciphertext_len = plaintext
        .len()
        .checked_add(BACKUP_TAG_BYTES)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    validate_index_ciphertext_len(ciphertext_len)?;
    let ciphertext_len =
        u32::try_from(ciphertext_len).map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let aad = index_aad(context, &nonce, ciphertext_len, bootstrap_slot);
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).expect("B505 index nonce is statically 24 bytes");
    let key = derive_backup_index_key(vrk, vault_id, context.key_generation, context.set_id);
    let ciphertext_and_tag = key
        .with_bytes(|bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(bytes)
                .expect("B505 index key is statically 32 bytes");
            cipher.encrypt(
                nonce_ref,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
        })
        .map_err(|_| BackupCodecError::EncryptionFailed)?;
    if ciphertext_and_tag.len() != ciphertext_len as usize {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    EncryptedBackupIndex::new(nonce, ciphertext_and_tag)
}
pub fn encrypt_backup_index(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    context: BackupIndexContext,
    bootstrap_slot: &[u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
    index: &BackupIndexPlaintext,
) -> Result<EncryptedBackupIndex, BackupCodecError> {
    let mut nonce = [0_u8; BACKUP_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| BackupCodecError::RandomnessUnavailable)?;
    encrypt_backup_index_with_nonce(vrk, vault_id, context, bootstrap_slot, nonce, index)
}
pub fn decrypt_backup_index(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    context: BackupIndexContext,
    bootstrap_slot: &[u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
    encrypted: &EncryptedBackupIndex,
) -> Result<BackupIndexPlaintext, BackupCodecError> {
    validate_index_ciphertext_len(encrypted.ciphertext_and_tag.len())?;
    let ciphertext_len = u32::try_from(encrypted.ciphertext_and_tag.len())
        .map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let aad = index_aad(context, &encrypted.nonce, ciphertext_len, bootstrap_slot);
    let nonce_ref = <&XNonce>::try_from(encrypted.nonce.as_slice())
        .expect("parsed B505 index nonce is statically 24 bytes");
    let key = derive_backup_index_key(vrk, vault_id, context.key_generation, context.set_id);
    let plaintext = key
        .with_bytes(|bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(bytes)
                .expect("B505 index key is statically 32 bytes");
            cipher.decrypt(
                nonce_ref,
                Payload {
                    msg: &encrypted.ciphertext_and_tag,
                    aad: &aad,
                },
            )
        })
        .map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let index = decode_backup_index_plaintext(&plaintext, context.data_object_count)?;
    if index.vault_id != vault_id || index.key_generation != context.key_generation {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(index)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn object_id(value: u8) -> BackupObjectId {
        BackupObjectId::from_bytes([value; 16]).unwrap()
    }
    fn payload(
        kind: BackupIndexPayloadKind,
        logical_id: [u8; 16],
        storage_id: [u8; 16],
        hash_byte: u8,
        chunks: &[(u8, u32)],
    ) -> BackupIndexPayload {
        let chunks: Vec<_> = chunks
            .iter()
            .map(|(id, len)| BackupIndexChunk::new(object_id(*id), *len).unwrap())
            .collect();
        let length = chunks
            .iter()
            .map(|chunk| u64::from(chunk.plaintext_chunk_length()))
            .sum();
        BackupIndexPayload::new(
            kind,
            logical_id,
            storage_id,
            length,
            [hash_byte; 32],
            chunks,
        )
        .unwrap()
    }
    fn fixture_index() -> BackupIndexPlaintext {
        BackupIndexPlaintext::new(
            VaultId::from_bytes([1; 16]),
            KeyGeneration::new(3).unwrap(),
            FreshnessEpoch::new(9).unwrap(),
            ManifestHash::from_bytes([4; 32]),
            vec![
                payload(
                    BackupIndexPayloadKind::Manifest,
                    [0; 16],
                    [0; 16],
                    10,
                    &[(20, 5)],
                ),
                payload(
                    BackupIndexPayloadKind::StructuredStore,
                    [0; 16],
                    [21; 16],
                    11,
                    &[(22, 7)],
                ),
                payload(
                    BackupIndexPayloadKind::GenericArtifactBlob,
                    [23; 16],
                    [24; 16],
                    12,
                    &[(25, 4), (26, 5)],
                ),
            ],
        )
        .unwrap()
    }
    fn context() -> BackupIndexContext {
        BackupIndexContext::new(
            BackupSetId::from_bytes([2; 16]).unwrap(),
            KeyGeneration::new(3).unwrap(),
            4,
        )
        .unwrap()
    }
    #[test]
    fn index_plaintext_round_trip_is_canonical() {
        let index = fixture_index();
        assert_eq!(index.data_object_count().unwrap(), 4);
        let encoded = encode_backup_index_plaintext(&index).unwrap();
        assert_eq!(decode_backup_index_plaintext(&encoded, 4).unwrap(), index);
    }
    #[test]
    fn parser_rejects_bad_ordinal_kind_zero_object_trailing_and_count() {
        let encoded = encode_backup_index_plaintext(&fixture_index()).unwrap();
        let mut bad = encoded.clone();
        bad[INDEX_HEADER_BYTES + 3] = 1;
        assert!(decode_backup_index_plaintext(&bad, 4).is_err());
        let mut bad = encoded.clone();
        bad[INDEX_HEADER_BYTES + 4..INDEX_HEADER_BYTES + 6].copy_from_slice(&9_u16.to_be_bytes());
        assert!(decode_backup_index_plaintext(&bad, 4).is_err());
        let mut bad = encoded.clone();
        let object_offset = INDEX_HEADER_BYTES + INDEX_PAYLOAD_FIXED_BYTES + 4;
        bad[object_offset..object_offset + 16].fill(0);
        assert!(decode_backup_index_plaintext(&bad, 4).is_err());
        let mut bad = encoded.clone();
        bad.push(0);
        assert!(decode_backup_index_plaintext(&bad, 4).is_err());
        assert!(decode_backup_index_plaintext(&encoded, 3).is_err());
    }
    #[test]
    fn model_rejects_duplicate_objects_unsorted_blobs_and_length_mismatch() {
        let duplicate = object_id(30);
        let manifest = BackupIndexPayload::new(
            BackupIndexPayloadKind::Manifest,
            [0; 16],
            [0; 16],
            1,
            [1; 32],
            vec![BackupIndexChunk::new(duplicate, 1).unwrap()],
        )
        .unwrap();
        let store = BackupIndexPayload::new(
            BackupIndexPayloadKind::StructuredStore,
            [0; 16],
            [2; 16],
            1,
            [2; 32],
            vec![BackupIndexChunk::new(duplicate, 1).unwrap()],
        )
        .unwrap();
        assert!(
            BackupIndexPlaintext::new(
                VaultId::from_bytes([1; 16]),
                KeyGeneration::new(1).unwrap(),
                FreshnessEpoch::new(1).unwrap(),
                ManifestHash::from_bytes([1; 32]),
                vec![manifest, store],
            )
            .is_err()
        );
        let mut payloads = fixture_index().payloads().to_vec();
        payloads.push(payload(
            BackupIndexPayloadKind::GenericArtifactBlob,
            [22; 16],
            [31; 16],
            13,
            &[(32, 1)],
        ));
        assert!(
            BackupIndexPlaintext::new(
                VaultId::from_bytes([1; 16]),
                KeyGeneration::new(3).unwrap(),
                FreshnessEpoch::new(9).unwrap(),
                ManifestHash::from_bytes([4; 32]),
                payloads,
            )
            .is_err()
        );
        assert!(
            BackupIndexPayload::new(
                BackupIndexPayloadKind::Manifest,
                [0; 16],
                [0; 16],
                2,
                [0; 32],
                vec![BackupIndexChunk::new(object_id(40), 1).unwrap()],
            )
            .is_err()
        );
    }
    #[test]
    fn encrypted_index_authenticates_context_bootstrap_and_ciphertext() {
        let index = fixture_index();
        let vrk = OwnedKeyMaterial::from_bytes([7; 32]);
        let vault_id = VaultId::from_bytes([1; 16]);
        let context = context();
        let bootstrap = [8_u8; BACKUP_BOOTSTRAP_SLOT_BYTES];
        let encrypted = encrypt_backup_index_with_nonce(
            &vrk,
            vault_id,
            context,
            &bootstrap,
            [9; BACKUP_NONCE_BYTES],
            &index,
        )
        .unwrap();
        assert_eq!(
            decrypt_backup_index(&vrk, vault_id, context, &bootstrap, &encrypted).unwrap(),
            index
        );
        let mut tampered = encrypted.clone();
        let last = tampered.ciphertext_and_tag.len() - 1;
        tampered.ciphertext_and_tag[last] ^= 1;
        assert!(decrypt_backup_index(&vrk, vault_id, context, &bootstrap, &tampered).is_err());
        let wrong_set = BackupIndexContext::new(
            BackupSetId::from_bytes([10; 16]).unwrap(),
            KeyGeneration::new(3).unwrap(),
            4,
        )
        .unwrap();
        assert!(decrypt_backup_index(&vrk, vault_id, wrong_set, &bootstrap, &encrypted).is_err());
        let mut wrong_bootstrap = bootstrap;
        wrong_bootstrap[0] ^= 1;
        assert!(
            decrypt_backup_index(&vrk, vault_id, context, &wrong_bootstrap, &encrypted).is_err()
        );
    }
    #[test]
    fn encryption_rejects_vault_generation_and_count_transplants() {
        let index = fixture_index();
        let vrk = OwnedKeyMaterial::from_bytes([7; 32]);
        let bootstrap = [8_u8; BACKUP_BOOTSTRAP_SLOT_BYTES];
        let context = context();
        assert!(
            encrypt_backup_index_with_nonce(
                &vrk,
                VaultId::from_bytes([99; 16]),
                context,
                &bootstrap,
                [9; BACKUP_NONCE_BYTES],
                &index,
            )
            .is_err()
        );
        let wrong_generation =
            BackupIndexContext::new(context.set_id(), KeyGeneration::new(4).unwrap(), 4).unwrap();
        assert!(
            encrypt_backup_index_with_nonce(
                &vrk,
                VaultId::from_bytes([1; 16]),
                wrong_generation,
                &bootstrap,
                [9; BACKUP_NONCE_BYTES],
                &index,
            )
            .is_err()
        );
        let wrong_count =
            BackupIndexContext::new(context.set_id(), context.key_generation(), 3).unwrap();
        assert!(
            encrypt_backup_index_with_nonce(
                &vrk,
                VaultId::from_bytes([1; 16]),
                wrong_count,
                &bootstrap,
                [9; BACKUP_NONCE_BYTES],
                &index,
            )
            .is_err()
        );
    }
}

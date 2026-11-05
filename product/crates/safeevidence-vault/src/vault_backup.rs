use crate::vault::{KeyGeneration, VaultId};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
pub const BACKUP_OPAQUE_ID_BYTES: usize = 16;
pub const BACKUP_NONCE_BYTES: usize = 24;
pub const BACKUP_TAG_BYTES: usize = 16;
pub const BACKUP_CHUNK_PLAINTEXT_MAX: usize = 33_554_432;
pub const BACKUP_BOOTSTRAP_SLOT_BYTES: usize = 183;
pub const BACKUP_INDEX_CIPHERTEXT_MIN: usize = 16;
pub const BACKUP_INDEX_CIPHERTEXT_MAX: usize = 67_108_880;
pub const BACKUP_DATA_OBJECT_COUNT_MIN: u32 = 2;
pub const BACKUP_DATA_OBJECT_COUNT_MAX: u32 = 1_048_576;
pub const BACKUP_OBJECT_HEADER_BYTES: usize = 108;
pub const BACKUP_SET_DESCRIPTOR_HEADER_BYTES: usize = 334;
const RANDOM_ID_ATTEMPTS: usize = 16;
const ZERO_OBJECT_LEAF: &str = "00000000000000000000000000000000";
const INDEX_KEY_DOMAIN: &[u8] = b"HIMSAT/004/BACKUP-INDEX/v1";
const OBJECT_KEY_DOMAIN: &[u8] = b"HIMSAT/004/BACKUP-OBJECT/v1";
const OBJECT_ENVELOPE_DOMAIN_PREFIX: &[u8] = b"\x00\x20HIMSAT/BACKUP/OBJECT/ENVELOPE/v1";
const OBJECT_AAD_DOMAIN_PREFIX: &[u8] = b"\x00\x1bHIMSAT/BACKUP/OBJECT/AAD/v1";
const SET_DESCRIPTOR_DOMAIN_PREFIX: &[u8] = b"\x00\x1dHIMSAT/BACKUP/SET/ENVELOPE/v1";
const FORMAT_VERSION: u16 = 1;
const XCHACHA20_POLY1305_SUITE: u16 = 1;
const RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1: u16 = 1;
const ARGON2_VERSION: u16 = 0x0013;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_PASSES: u32 = 3;
const ARGON2_PARALLELISM: u16 = 4;
const KDF_OUTPUT_BYTES: u16 = 32;
const OBJECT_AAD_BYTES: usize = 103;
const OBJECT_VERSION_OFFSET: usize = 34;
const OBJECT_SET_ID_OFFSET: usize = 36;
const OBJECT_ID_OFFSET: usize = 52;
const OBJECT_GENERATION_OFFSET: usize = 68;
const OBJECT_PLAINTEXT_LENGTH_OFFSET: usize = 76;
const OBJECT_NONCE_OFFSET: usize = 80;
const OBJECT_CIPHERTEXT_LENGTH_OFFSET: usize = 104;
const DESCRIPTOR_VERSION_OFFSET: usize = 31;
const DESCRIPTOR_SET_ID_OFFSET: usize = 33;
const DESCRIPTOR_GENERATION_OFFSET: usize = 49;
const DESCRIPTOR_DATA_OBJECT_COUNT_OFFSET: usize = 57;
const DESCRIPTOR_BOOTSTRAP_CIPHER_OFFSET: usize = 61;
const DESCRIPTOR_RECOVERY_POLICY_OFFSET: usize = 63;
const DESCRIPTOR_ARGON2_VERSION_OFFSET: usize = 65;
const DESCRIPTOR_MEMORY_KIB_OFFSET: usize = 67;
const DESCRIPTOR_PASSES_OFFSET: usize = 71;
const DESCRIPTOR_PARALLELISM_OFFSET: usize = 75;
const DESCRIPTOR_KDF_OUTPUT_OFFSET: usize = 77;
const DESCRIPTOR_BOOTSTRAP_SALT_OFFSET: usize = 79;
const DESCRIPTOR_BOOTSTRAP_NONCE_OFFSET: usize = 95;
const DESCRIPTOR_BOOTSTRAP_SLOT_LENGTH_OFFSET: usize = 119;
const DESCRIPTOR_BOOTSTRAP_SLOT_OFFSET: usize = 123;
const DESCRIPTOR_INDEX_NONCE_OFFSET: usize = 306;
const DESCRIPTOR_INDEX_CIPHERTEXT_LENGTH_OFFSET: usize = 330;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupCodecError {
    CorruptOrTampered,
    RandomnessUnavailable,
    EmptyPlaintext,
    PlaintextTooLarge,
    EncryptionFailed,
}
impl fmt::Display for BackupCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CorruptOrTampered => "portable backup bytes are corrupt or tampered",
            Self::RandomnessUnavailable => "portable backup randomness is unavailable",
            Self::EmptyPlaintext => "portable backup object plaintext must be non-empty",
            Self::PlaintextTooLarge => "portable backup object plaintext exceeds 32 MiB",
            Self::EncryptionFailed => "portable backup object encryption failed",
        };
        f.write_str(message)
    }
}
impl Error for BackupCodecError {}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupSetId([u8; BACKUP_OPAQUE_ID_BYTES]);
impl BackupSetId {
    pub fn from_bytes(bytes: [u8; BACKUP_OPAQUE_ID_BYTES]) -> Result<Self, BackupCodecError> {
        if is_zero_id(&bytes) {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        Ok(Self(bytes))
    }
    pub fn generate() -> Result<Self, BackupCodecError> {
        generate_nonzero_id(|bytes| getrandom::fill(bytes).map_err(|_| ())).map(Self)
    }
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BACKUP_OPAQUE_ID_BYTES] {
        &self.0
    }
    #[must_use]
    pub const fn into_bytes(self) -> [u8; BACKUP_OPAQUE_ID_BYTES] {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackupObjectId([u8; BACKUP_OPAQUE_ID_BYTES]);
impl BackupObjectId {
    pub fn from_bytes(bytes: [u8; BACKUP_OPAQUE_ID_BYTES]) -> Result<Self, BackupCodecError> {
        if is_zero_id(&bytes) {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        Ok(Self(bytes))
    }
    pub fn generate() -> Result<Self, BackupCodecError> {
        generate_nonzero_id(|bytes| getrandom::fill(bytes).map_err(|_| ())).map(Self)
    }
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BACKUP_OPAQUE_ID_BYTES] {
        &self.0
    }
    #[must_use]
    pub const fn into_bytes(self) -> [u8; BACKUP_OPAQUE_ID_BYTES] {
        self.0
    }
}
fn is_zero_id(bytes: &[u8; BACKUP_OPAQUE_ID_BYTES]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
fn generate_nonzero_id(
    mut fill: impl FnMut(&mut [u8; BACKUP_OPAQUE_ID_BYTES]) -> Result<(), ()>,
) -> Result<[u8; BACKUP_OPAQUE_ID_BYTES], BackupCodecError> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut bytes = [0_u8; BACKUP_OPAQUE_ID_BYTES];
        fill(&mut bytes).map_err(|_| BackupCodecError::RandomnessUnavailable)?;
        if !is_zero_id(&bytes) {
            return Ok(bytes);
        }
    }
    Err(BackupCodecError::RandomnessUnavailable)
}
fn encode_hex_lower(bytes: &[u8; BACKUP_OPAQUE_ID_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(BACKUP_OPAQUE_ID_BYTES * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
fn decode_hex_lower(input: &str) -> Result<[u8; BACKUP_OPAQUE_ID_BYTES], BackupCodecError> {
    if input.len() != BACKUP_OPAQUE_ID_BYTES * 2 {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let bytes = input.as_bytes();
    let mut output = [0_u8; BACKUP_OPAQUE_ID_BYTES];
    for (index, slot) in output.iter_mut().enumerate() {
        let high = decode_hex_nibble(bytes[index * 2])?;
        let low = decode_hex_nibble(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(output)
}
fn decode_hex_nibble(byte: u8) -> Result<u8, BackupCodecError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BackupCodecError::CorruptOrTampered),
    }
}
#[must_use]
pub fn descriptor_provider_key(set_id: BackupSetId) -> String {
    format!(
        "{}/{}",
        encode_hex_lower(set_id.as_bytes()),
        ZERO_OBJECT_LEAF
    )
}
#[must_use]
pub fn object_provider_key(set_id: BackupSetId, object_id: BackupObjectId) -> String {
    format!(
        "{}/{}",
        encode_hex_lower(set_id.as_bytes()),
        encode_hex_lower(object_id.as_bytes())
    )
}
fn split_provider_key(key: &str) -> Result<(&str, &str), BackupCodecError> {
    if key.len() != 65 || key.as_bytes().get(32) != Some(&b'/') {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if key.as_bytes()[33..].contains(&b'/') {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok((&key[..32], &key[33..]))
}
pub fn validate_descriptor_provider_key(
    key: &str,
    expected_set_id: BackupSetId,
) -> Result<(), BackupCodecError> {
    let (set_hex, object_hex) = split_provider_key(key)?;
    let set_bytes = decode_hex_lower(set_hex)?;
    if set_bytes != expected_set_id.into_bytes() || object_hex != ZERO_OBJECT_LEAF {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(())
}
pub fn validate_object_provider_key(
    key: &str,
    expected_set_id: BackupSetId,
    expected_object_id: BackupObjectId,
) -> Result<(), BackupCodecError> {
    let (set_hex, object_hex) = split_provider_key(key)?;
    let set_bytes = decode_hex_lower(set_hex)?;
    let object_bytes = decode_hex_lower(object_hex)?;
    if set_bytes != expected_set_id.into_bytes()
        || object_bytes != expected_object_id.into_bytes()
        || is_zero_id(&object_bytes)
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(())
}
fn derive_backup_key(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    generation: KeyGeneration,
    set_id: BackupSetId,
    domain: &[u8],
) -> OwnedKeyMaterial {
    let mut info = Vec::with_capacity(domain.len() + 8 + BACKUP_OPAQUE_ID_BYTES);
    info.extend_from_slice(domain);
    info.extend_from_slice(&generation.get().to_be_bytes());
    info.extend_from_slice(set_id.as_bytes());
    let mut output = [0_u8; KEY_MATERIAL_BYTES];
    vrk.with_bytes(|bytes| {
        let hkdf = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), bytes);
        hkdf.expand(&info, &mut output)
            .expect("32-byte HKDF-SHA-256 output is within RFC 5869 limits");
    });
    OwnedKeyMaterial::from_bytes(output)
}
#[must_use]
pub fn derive_backup_index_key(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    generation: KeyGeneration,
    set_id: BackupSetId,
) -> OwnedKeyMaterial {
    derive_backup_key(vrk, vault_id, generation, set_id, INDEX_KEY_DOMAIN)
}
#[must_use]
pub fn derive_backup_object_key(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    generation: KeyGeneration,
    set_id: BackupSetId,
) -> OwnedKeyMaterial {
    derive_backup_key(vrk, vault_id, generation, set_id, OBJECT_KEY_DOMAIN)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupObjectContext {
    pub set_id: BackupSetId,
    pub object_id: BackupObjectId,
    pub key_generation: KeyGeneration,
}
fn validate_object_plaintext_len(len: usize) -> Result<u32, BackupCodecError> {
    if len == 0 {
        return Err(BackupCodecError::EmptyPlaintext);
    }
    if len > BACKUP_CHUNK_PLAINTEXT_MAX {
        return Err(BackupCodecError::PlaintextTooLarge);
    }
    u32::try_from(len).map_err(|_| BackupCodecError::CorruptOrTampered)
}
fn object_aad(
    context: BackupObjectContext,
    plaintext_len: u32,
    nonce: &[u8; BACKUP_NONCE_BYTES],
    ciphertext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OBJECT_AAD_BYTES);
    aad.extend_from_slice(OBJECT_AAD_DOMAIN_PREFIX);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(context.set_id.as_bytes());
    aad.extend_from_slice(context.object_id.as_bytes());
    aad.extend_from_slice(&context.key_generation.get().to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&ciphertext_len.to_be_bytes());
    debug_assert_eq!(aad.len(), OBJECT_AAD_BYTES);
    aad
}
fn encrypt_backup_object_with_nonce(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    context: BackupObjectContext,
    nonce: [u8; BACKUP_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, BackupCodecError> {
    let plaintext_len = validate_object_plaintext_len(plaintext.len())?;
    let ciphertext_len = plaintext_len
        .checked_add(BACKUP_TAG_BYTES as u32)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    let aad = object_aad(context, plaintext_len, &nonce, ciphertext_len);
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).expect("B505 nonce is statically exactly 24 bytes");
    let key = derive_backup_object_key(vrk, vault_id, context.key_generation, context.set_id);
    let ciphertext = key
        .with_bytes(|bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(bytes)
                .expect("B505 object key is statically exactly 32 bytes");
            cipher.encrypt(
                nonce_ref,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
        })
        .map_err(|_| BackupCodecError::EncryptionFailed)?;
    if ciphertext.len() != ciphertext_len as usize {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let mut envelope = Vec::with_capacity(BACKUP_OBJECT_HEADER_BYTES + ciphertext.len());
    envelope.extend_from_slice(OBJECT_ENVELOPE_DOMAIN_PREFIX);
    envelope.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    envelope.extend_from_slice(context.set_id.as_bytes());
    envelope.extend_from_slice(context.object_id.as_bytes());
    envelope.extend_from_slice(&context.key_generation.get().to_be_bytes());
    envelope.extend_from_slice(&plaintext_len.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext_len.to_be_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}
pub fn encrypt_backup_object(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    context: BackupObjectContext,
    plaintext: &[u8],
) -> Result<Vec<u8>, BackupCodecError> {
    let mut nonce = [0_u8; BACKUP_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| BackupCodecError::RandomnessUnavailable)?;
    encrypt_backup_object_with_nonce(vrk, vault_id, context, nonce, plaintext)
}
fn parse_u16(input: &[u8], offset: usize) -> Result<u16, BackupCodecError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    Ok(u16::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| BackupCodecError::CorruptOrTampered)?,
    ))
}
fn parse_u32(input: &[u8], offset: usize) -> Result<u32, BackupCodecError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    Ok(u32::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| BackupCodecError::CorruptOrTampered)?,
    ))
}
fn parse_u64(input: &[u8], offset: usize) -> Result<u64, BackupCodecError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| BackupCodecError::CorruptOrTampered)?,
    ))
}
fn parse_array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], BackupCodecError> {
    input
        .get(offset..offset + N)
        .ok_or(BackupCodecError::CorruptOrTampered)?
        .try_into()
        .map_err(|_| BackupCodecError::CorruptOrTampered)
}
struct ParsedBackupObject<'a> {
    context: BackupObjectContext,
    nonce: [u8; BACKUP_NONCE_BYTES],
    plaintext_len: u32,
    ciphertext_len: u32,
    ciphertext: &'a [u8],
}
fn parse_backup_object(envelope: &[u8]) -> Result<ParsedBackupObject<'_>, BackupCodecError> {
    if envelope.len() < BACKUP_OBJECT_HEADER_BYTES {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if envelope.get(..OBJECT_ENVELOPE_DOMAIN_PREFIX.len()) != Some(OBJECT_ENVELOPE_DOMAIN_PREFIX) {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if parse_u16(envelope, OBJECT_VERSION_OFFSET)? != FORMAT_VERSION {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let set_id = BackupSetId::from_bytes(parse_array(envelope, OBJECT_SET_ID_OFFSET)?)?;
    let object_id = BackupObjectId::from_bytes(parse_array(envelope, OBJECT_ID_OFFSET)?)?;
    let key_generation = KeyGeneration::new(parse_u64(envelope, OBJECT_GENERATION_OFFSET)?)
        .map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let plaintext_len = parse_u32(envelope, OBJECT_PLAINTEXT_LENGTH_OFFSET)?;
    if plaintext_len == 0 || plaintext_len as usize > BACKUP_CHUNK_PLAINTEXT_MAX {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let nonce = parse_array(envelope, OBJECT_NONCE_OFFSET)?;
    let ciphertext_len = parse_u32(envelope, OBJECT_CIPHERTEXT_LENGTH_OFFSET)?;
    if ciphertext_len != plaintext_len + BACKUP_TAG_BYTES as u32 {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let expected_total = BACKUP_OBJECT_HEADER_BYTES
        .checked_add(ciphertext_len as usize)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    if envelope.len() != expected_total {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(ParsedBackupObject {
        context: BackupObjectContext {
            set_id,
            object_id,
            key_generation,
        },
        nonce,
        plaintext_len,
        ciphertext_len,
        ciphertext: &envelope[BACKUP_OBJECT_HEADER_BYTES..],
    })
}
/// Returns the public nonce from one structurally valid B505 object envelope.
/// This does not authenticate or decrypt the ciphertext.
pub fn backup_object_nonce(envelope: &[u8]) -> Result<[u8; BACKUP_NONCE_BYTES], BackupCodecError> {
    Ok(parse_backup_object(envelope)?.nonce)
}

pub fn validate_backup_object_binding(
    provider_key: &str,
    expected_context: BackupObjectContext,
    envelope: &[u8],
) -> Result<(), BackupCodecError> {
    validate_object_provider_key(
        provider_key,
        expected_context.set_id,
        expected_context.object_id,
    )?;
    let parsed = parse_backup_object(envelope)?;
    if parsed.context != expected_context {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(())
}

pub fn decrypt_backup_object(
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    expected_context: BackupObjectContext,
    envelope: &[u8],
) -> Result<Vec<u8>, BackupCodecError> {
    let parsed = parse_backup_object(envelope)?;
    if parsed.context != expected_context {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let aad = object_aad(
        parsed.context,
        parsed.plaintext_len,
        &parsed.nonce,
        parsed.ciphertext_len,
    );
    let nonce_ref = <&XNonce>::try_from(parsed.nonce.as_slice())
        .expect("parsed B505 nonce is statically exactly 24 bytes");
    let key = derive_backup_object_key(
        vrk,
        vault_id,
        parsed.context.key_generation,
        parsed.context.set_id,
    );
    key.with_bytes(|bytes| {
        let cipher = XChaCha20Poly1305::new_from_slice(bytes)
            .expect("B505 object key is statically exactly 32 bytes");
        cipher.decrypt(
            nonce_ref,
            Payload {
                msg: parsed.ciphertext,
                aad: &aad,
            },
        )
    })
    .map_err(|_| BackupCodecError::CorruptOrTampered)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSetDescriptor {
    set_id: BackupSetId,
    key_generation: KeyGeneration,
    data_object_count: u32,
    bootstrap_salt: [u8; 16],
    bootstrap_nonce: [u8; BACKUP_NONCE_BYTES],
    bootstrap_slot: [u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
    index_nonce: [u8; BACKUP_NONCE_BYTES],
    index_ciphertext_and_tag: Vec<u8>,
}
impl BackupSetDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        set_id: BackupSetId,
        key_generation: KeyGeneration,
        data_object_count: u32,
        bootstrap_salt: [u8; 16],
        bootstrap_nonce: [u8; BACKUP_NONCE_BYTES],
        bootstrap_slot: [u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
        index_nonce: [u8; BACKUP_NONCE_BYTES],
        index_ciphertext_and_tag: Vec<u8>,
    ) -> Result<Self, BackupCodecError> {
        validate_descriptor_bounds(data_object_count, index_ciphertext_and_tag.len())?;
        Ok(Self {
            set_id,
            key_generation,
            data_object_count,
            bootstrap_salt,
            bootstrap_nonce,
            bootstrap_slot,
            index_nonce,
            index_ciphertext_and_tag,
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
    #[must_use]
    pub const fn bootstrap_salt(&self) -> &[u8; 16] {
        &self.bootstrap_salt
    }
    #[must_use]
    pub const fn bootstrap_slot(&self) -> &[u8; BACKUP_BOOTSTRAP_SLOT_BYTES] {
        &self.bootstrap_slot
    }
    #[must_use]
    pub const fn bootstrap_nonce(&self) -> &[u8; BACKUP_NONCE_BYTES] {
        &self.bootstrap_nonce
    }
    #[must_use]
    pub const fn index_nonce(&self) -> &[u8; BACKUP_NONCE_BYTES] {
        &self.index_nonce
    }
    #[must_use]
    pub fn index_ciphertext_and_tag(&self) -> &[u8] {
        &self.index_ciphertext_and_tag
    }
}
fn validate_descriptor_bounds(
    data_object_count: u32,
    index_len: usize,
) -> Result<(), BackupCodecError> {
    if !(BACKUP_DATA_OBJECT_COUNT_MIN..=BACKUP_DATA_OBJECT_COUNT_MAX).contains(&data_object_count)
        || !(BACKUP_INDEX_CIPHERTEXT_MIN..=BACKUP_INDEX_CIPHERTEXT_MAX).contains(&index_len)
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    Ok(())
}
pub fn encode_set_descriptor(
    descriptor: &BackupSetDescriptor,
) -> Result<Vec<u8>, BackupCodecError> {
    validate_descriptor_bounds(
        descriptor.data_object_count,
        descriptor.index_ciphertext_and_tag.len(),
    )?;
    let index_len = u32::try_from(descriptor.index_ciphertext_and_tag.len())
        .map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let mut output = Vec::with_capacity(
        BACKUP_SET_DESCRIPTOR_HEADER_BYTES + descriptor.index_ciphertext_and_tag.len(),
    );
    output.extend_from_slice(SET_DESCRIPTOR_DOMAIN_PREFIX);
    output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(descriptor.set_id.as_bytes());
    output.extend_from_slice(&descriptor.key_generation.get().to_be_bytes());
    output.extend_from_slice(&descriptor.data_object_count.to_be_bytes());
    output.extend_from_slice(&XCHACHA20_POLY1305_SUITE.to_be_bytes());
    output.extend_from_slice(&RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1.to_be_bytes());
    output.extend_from_slice(&ARGON2_VERSION.to_be_bytes());
    output.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    output.extend_from_slice(&ARGON2_PASSES.to_be_bytes());
    output.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    output.extend_from_slice(&KDF_OUTPUT_BYTES.to_be_bytes());
    output.extend_from_slice(&descriptor.bootstrap_salt);
    output.extend_from_slice(&descriptor.bootstrap_nonce);
    output.extend_from_slice(&(BACKUP_BOOTSTRAP_SLOT_BYTES as u32).to_be_bytes());
    output.extend_from_slice(&descriptor.bootstrap_slot);
    output.extend_from_slice(&descriptor.index_nonce);
    output.extend_from_slice(&index_len.to_be_bytes());
    output.extend_from_slice(&descriptor.index_ciphertext_and_tag);
    Ok(output)
}
pub fn parse_set_descriptor(input: &[u8]) -> Result<BackupSetDescriptor, BackupCodecError> {
    if input.len() < BACKUP_SET_DESCRIPTOR_HEADER_BYTES {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if input.get(..SET_DESCRIPTOR_DOMAIN_PREFIX.len()) != Some(SET_DESCRIPTOR_DOMAIN_PREFIX) {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if parse_u16(input, DESCRIPTOR_VERSION_OFFSET)? != FORMAT_VERSION
        || parse_u16(input, DESCRIPTOR_BOOTSTRAP_CIPHER_OFFSET)? != XCHACHA20_POLY1305_SUITE
        || parse_u16(input, DESCRIPTOR_RECOVERY_POLICY_OFFSET)?
            != RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if parse_u16(input, DESCRIPTOR_ARGON2_VERSION_OFFSET)? != ARGON2_VERSION
        || parse_u32(input, DESCRIPTOR_MEMORY_KIB_OFFSET)? != ARGON2_MEMORY_KIB
        || parse_u32(input, DESCRIPTOR_PASSES_OFFSET)? != ARGON2_PASSES
        || parse_u16(input, DESCRIPTOR_PARALLELISM_OFFSET)? != ARGON2_PARALLELISM
        || parse_u16(input, DESCRIPTOR_KDF_OUTPUT_OFFSET)? != KDF_OUTPUT_BYTES
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    if parse_u32(input, DESCRIPTOR_BOOTSTRAP_SLOT_LENGTH_OFFSET)?
        != BACKUP_BOOTSTRAP_SLOT_BYTES as u32
    {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    let set_id = BackupSetId::from_bytes(parse_array(input, DESCRIPTOR_SET_ID_OFFSET)?)?;
    let key_generation = KeyGeneration::new(parse_u64(input, DESCRIPTOR_GENERATION_OFFSET)?)
        .map_err(|_| BackupCodecError::CorruptOrTampered)?;
    let data_object_count = parse_u32(input, DESCRIPTOR_DATA_OBJECT_COUNT_OFFSET)?;
    let index_len = parse_u32(input, DESCRIPTOR_INDEX_CIPHERTEXT_LENGTH_OFFSET)? as usize;
    validate_descriptor_bounds(data_object_count, index_len)?;
    let expected_total = BACKUP_SET_DESCRIPTOR_HEADER_BYTES
        .checked_add(index_len)
        .ok_or(BackupCodecError::CorruptOrTampered)?;
    if input.len() != expected_total {
        return Err(BackupCodecError::CorruptOrTampered);
    }
    BackupSetDescriptor::new(
        set_id,
        key_generation,
        data_object_count,
        parse_array(input, DESCRIPTOR_BOOTSTRAP_SALT_OFFSET)?,
        parse_array(input, DESCRIPTOR_BOOTSTRAP_NONCE_OFFSET)?,
        parse_array(input, DESCRIPTOR_BOOTSTRAP_SLOT_OFFSET)?,
        parse_array(input, DESCRIPTOR_INDEX_NONCE_OFFSET)?,
        input[BACKUP_SET_DESCRIPTOR_HEADER_BYTES..].to_vec(),
    )
}
pub fn validate_descriptor_binding(
    provider_key: &str,
    descriptor: &BackupSetDescriptor,
) -> Result<(), BackupCodecError> {
    validate_descriptor_provider_key(provider_key, descriptor.set_id())
}
#[cfg(test)]
mod tests {
    use super::*;
    const TEST_VRK: [u8; 32] = [0x11; 32];
    const TEST_VAULT: [u8; 16] = [0x22; 16];
    const TEST_SET: [u8; 16] = [0x33; 16];
    const TEST_OBJECT: [u8; 16] = [0x44; 16];
    const TEST_GENERATION: u64 = 7;
    fn vrk() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes(TEST_VRK)
    }
    fn vault_id() -> VaultId {
        VaultId::from_bytes(TEST_VAULT)
    }
    fn set_id() -> BackupSetId {
        BackupSetId::from_bytes(TEST_SET).unwrap()
    }
    fn object_id() -> BackupObjectId {
        BackupObjectId::from_bytes(TEST_OBJECT).unwrap()
    }
    fn generation() -> KeyGeneration {
        KeyGeneration::new(TEST_GENERATION).unwrap()
    }
    fn object_context() -> BackupObjectContext {
        BackupObjectContext {
            set_id: set_id(),
            object_id: object_id(),
            key_generation: generation(),
        }
    }
    #[test]
    fn provider_keys_are_canonical_and_strict() {
        let descriptor = descriptor_provider_key(set_id());
        let object = object_provider_key(set_id(), object_id());
        assert_eq!(
            descriptor,
            format!("{}/{}", "33".repeat(16), ZERO_OBJECT_LEAF)
        );
        assert_eq!(object, format!("{}/{}", "33".repeat(16), "44".repeat(16)));
        assert_eq!(
            validate_descriptor_provider_key(&descriptor, set_id()),
            Ok(())
        );
        assert_eq!(
            validate_object_provider_key(&object, set_id(), object_id()),
            Ok(())
        );
        let letter_set = BackupSetId::from_bytes([0xab; 16]).unwrap();
        let letter_object = BackupObjectId::from_bytes([0xcd; 16]).unwrap();
        let uppercase = object_provider_key(letter_set, letter_object).to_uppercase();
        assert_eq!(
            validate_object_provider_key(&uppercase, letter_set, letter_object),
            Err(BackupCodecError::CorruptOrTampered)
        );
        for malformed in [
            object.replace('/', "//"),
            format!("{object}.bin"),
            object.replace('/', "_"),
        ] {
            assert_eq!(
                validate_object_provider_key(&malformed, set_id(), object_id()),
                Err(BackupCodecError::CorruptOrTampered)
            );
        }
    }
    #[test]
    fn reserved_zero_identity_is_rejected_and_generation_is_bounded() {
        assert_eq!(
            BackupSetId::from_bytes([0_u8; 16]),
            Err(BackupCodecError::CorruptOrTampered)
        );
        assert_eq!(
            BackupObjectId::from_bytes([0_u8; 16]),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let mut calls = 0_usize;
        let generated = generate_nonzero_id(|bytes| {
            calls += 1;
            if calls == 3 {
                bytes[15] = 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(generated[15], 1);
        assert_eq!(
            generate_nonzero_id(|_| Err(())),
            Err(BackupCodecError::RandomnessUnavailable)
        );
    }
    fn owned_bytes(key: &OwnedKeyMaterial) -> [u8; KEY_MATERIAL_BYTES] {
        key.with_bytes(|bytes| *bytes)
    }
    #[test]
    fn backup_key_domains_sets_and_generations_are_separated() {
        let index = derive_backup_index_key(&vrk(), vault_id(), generation(), set_id());
        let object = derive_backup_object_key(&vrk(), vault_id(), generation(), set_id());
        assert_ne!(owned_bytes(&index), owned_bytes(&object));
        let other_set = BackupSetId::from_bytes([0x55; 16]).unwrap();
        let other_generation = KeyGeneration::new(TEST_GENERATION + 1).unwrap();
        let set_key = derive_backup_object_key(&vrk(), vault_id(), generation(), other_set);
        let generation_key =
            derive_backup_object_key(&vrk(), vault_id(), other_generation, set_id());
        assert_ne!(owned_bytes(&object), owned_bytes(&set_key));
        assert_ne!(owned_bytes(&object), owned_bytes(&generation_key));
    }
    #[test]
    fn object_round_trip_and_tamper_fail_closed() {
        let nonce = [0x66; BACKUP_NONCE_BYTES];
        let envelope = encrypt_backup_object_with_nonce(
            &vrk(),
            vault_id(),
            object_context(),
            nonce,
            b"portable backup chunk",
        )
        .unwrap();
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), object_context(), &envelope).unwrap(),
            b"portable backup chunk"
        );
        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), object_context(), &tampered),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let mut transplanted = object_context();
        transplanted.set_id = BackupSetId::from_bytes([0x77; 16]).unwrap();
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), transplanted, &envelope),
            Err(BackupCodecError::CorruptOrTampered)
        );
        transplanted = object_context();
        transplanted.object_id = BackupObjectId::from_bytes([0x78; 16]).unwrap();
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), transplanted, &envelope),
            Err(BackupCodecError::CorruptOrTampered)
        );
        transplanted = object_context();
        transplanted.key_generation = KeyGeneration::new(TEST_GENERATION + 1).unwrap();
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), transplanted, &envelope),
            Err(BackupCodecError::CorruptOrTampered)
        );
    }
    #[test]
    fn object_structural_bounds_reject_malformed_inputs() {
        assert_eq!(
            encrypt_backup_object_with_nonce(
                &vrk(),
                vault_id(),
                object_context(),
                [1; BACKUP_NONCE_BYTES],
                b"",
            ),
            Err(BackupCodecError::EmptyPlaintext)
        );
        assert_eq!(
            validate_object_plaintext_len(BACKUP_CHUNK_PLAINTEXT_MAX + 1),
            Err(BackupCodecError::PlaintextTooLarge)
        );
        let envelope = encrypt_backup_object_with_nonce(
            &vrk(),
            vault_id(),
            object_context(),
            [2; BACKUP_NONCE_BYTES],
            b"abc",
        )
        .unwrap();
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), object_context(), &envelope[..107]),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let mut trailing = envelope.clone();
        trailing.push(0);
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), object_context(), &trailing),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let mut bad_length = envelope.clone();
        bad_length[OBJECT_CIPHERTEXT_LENGTH_OFFSET..OBJECT_CIPHERTEXT_LENGTH_OFFSET + 4]
            .copy_from_slice(&99_u32.to_be_bytes());
        assert_eq!(
            decrypt_backup_object(&vrk(), vault_id(), object_context(), &bad_length),
            Err(BackupCodecError::CorruptOrTampered)
        );
    }
    fn descriptor() -> BackupSetDescriptor {
        BackupSetDescriptor::new(
            set_id(),
            generation(),
            2,
            [0x81; 16],
            [0x82; BACKUP_NONCE_BYTES],
            [0x83; BACKUP_BOOTSTRAP_SLOT_BYTES],
            [0x84; BACKUP_NONCE_BYTES],
            vec![0x85; BACKUP_INDEX_CIPHERTEXT_MIN],
        )
        .unwrap()
    }
    #[test]
    fn descriptor_round_trip_and_provider_binding() {
        let descriptor = descriptor();
        let encoded = encode_set_descriptor(&descriptor).unwrap();
        let parsed = parse_set_descriptor(&encoded).unwrap();
        assert_eq!(parsed, descriptor);
        assert_eq!(
            validate_descriptor_binding(&descriptor_provider_key(set_id()), &parsed),
            Ok(())
        );
    }
    #[test]
    fn descriptor_rejects_policy_count_and_index_length_mutation() {
        let encoded = encode_set_descriptor(&descriptor()).unwrap();
        let mut bad_policy = encoded.clone();
        bad_policy[DESCRIPTOR_RECOVERY_POLICY_OFFSET + 1] = 2;
        assert_eq!(
            parse_set_descriptor(&bad_policy),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let mut bad_count = encoded.clone();
        bad_count[DESCRIPTOR_DATA_OBJECT_COUNT_OFFSET..DESCRIPTOR_DATA_OBJECT_COUNT_OFFSET + 4]
            .copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            parse_set_descriptor(&bad_count),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let mut bad_index_len = encoded.clone();
        bad_index_len[DESCRIPTOR_INDEX_CIPHERTEXT_LENGTH_OFFSET
            ..DESCRIPTOR_INDEX_CIPHERTEXT_LENGTH_OFFSET + 4]
            .copy_from_slice(&15_u32.to_be_bytes());
        assert_eq!(
            parse_set_descriptor(&bad_index_len),
            Err(BackupCodecError::CorruptOrTampered)
        );
    }
    #[test]
    fn descriptor_rejects_trailing_bytes_and_provider_mismatch() {
        let descriptor = descriptor();
        let mut encoded = encode_set_descriptor(&descriptor).unwrap();
        encoded.push(0);
        assert_eq!(
            parse_set_descriptor(&encoded),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let wrong_set = BackupSetId::from_bytes([0x99; 16]).unwrap();
        assert_eq!(
            validate_descriptor_binding(&descriptor_provider_key(wrong_set), &descriptor),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let nonzero_leaf = object_provider_key(set_id(), object_id());
        assert_eq!(
            validate_descriptor_binding(&nonzero_leaf, &descriptor),
            Err(BackupCodecError::CorruptOrTampered)
        );
    }
}

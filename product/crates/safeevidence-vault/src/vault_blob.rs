//! Versioned bounded-blob authenticated-encryption contract for Specification 004 B202.
//!
//! This module executes only the reviewed generic artifact bounded-blob v1
//! XChaCha20-Poly1305 envelope. Callers supply the exact 24-byte nonce. Production
//! nonce generation, reservation, retry, restore, and collision behavior remain B203.

use crate::vault::{KeyGeneration, VaultId};
use crate::vault_keys::{KeyDerivationContext, KeyPurpose, OwnedKeyMaterial};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use std::error::Error;
use std::fmt;

/// Maximum plaintext size accepted by the v1 bounded-blob envelope.
pub const BOUNDED_BLOB_MAX_PLAINTEXT_BYTES: usize = 67_108_864;
/// Exact XChaCha20-Poly1305 nonce size.
pub const BOUNDED_BLOB_NONCE_BYTES: usize = 24;
/// Exact Poly1305 authentication-tag size.
pub const BOUNDED_BLOB_TAG_BYTES: usize = 16;
/// Exact public header size before ciphertext and tag.
pub const BOUNDED_BLOB_HEADER_BYTES: usize = 107;
/// Minimum complete v1 envelope size for an empty plaintext.
pub const BOUNDED_BLOB_MIN_ENVELOPE_BYTES: usize = 123;
/// Maximum complete v1 envelope size at the 64 MiB plaintext ceiling.
pub const BOUNDED_BLOB_MAX_ENVELOPE_BYTES: usize = 67_108_987;

const ENVELOPE_DOMAIN_PREFIX: &[u8; 25] = b"\x00\x17HIMSAT/BLOB/ENVELOPE/v1";
const AAD_DOMAIN_PREFIX: &[u8; 20] = b"\x00\x12HIMSAT/BLOB/AAD/v1";
const AAD_BYTES: usize = 104;
const ENVELOPE_VERSION: u16 = 1;
const CIPHER_SUITE_XCHACHA20_POLY1305: u16 = 1;
const OBJECT_PURPOSE_GENERIC_ARTIFACT_BLOB: u16 = 1;
const AAD_SCHEMA: u16 = 1;

const VERSION_OFFSET: usize = 25;
const CIPHER_SUITE_OFFSET: usize = 27;
const OBJECT_PURPOSE_OFFSET: usize = 29;
const VAULT_ID_OFFSET: usize = 31;
const ARTIFACT_ID_OFFSET: usize = 47;
const KEY_GENERATION_OFFSET: usize = 63;
const PLAINTEXT_LENGTH_OFFSET: usize = 71;
const NONCE_OFFSET: usize = 79;
const CIPHERTEXT_LENGTH_OFFSET: usize = 103;

/// Exact public cryptographic context for one generic artifact bounded blob.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BoundedBlobContext {
    vault_id: VaultId,
    artifact_id: [u8; 16],
    key_generation: KeyGeneration,
}

impl BoundedBlobContext {
    /// Creates a context from the exact canonical `id128` bytes defined by the
    /// reviewed Specification 004 contract.
    #[must_use]
    pub const fn new(
        vault_id: VaultId,
        artifact_id: [u8; 16],
        key_generation: KeyGeneration,
    ) -> Self {
        Self {
            vault_id,
            artifact_id,
            key_generation,
        }
    }

    /// Returns the public vault identity bound into the envelope and AAD.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns the exact 16 raw canonical artifact-id bytes.
    #[must_use]
    pub const fn artifact_id(self) -> [u8; 16] {
        self.artifact_id
    }

    /// Returns the non-zero key generation bound into the envelope and AAD.
    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }
}

/// Fail-closed bounded-blob envelope errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedBlobError {
    /// Plaintext exceeds the reviewed 64 MiB v1 ceiling.
    PlaintextTooLarge,
    /// Envelope ends before the exact declared canonical length.
    TruncatedEnvelope,
    /// Envelope has bytes after the exact declared canonical length.
    TrailingData,
    /// Public envelope domain prefix is not the exact v1 domain.
    InvalidDomain,
    /// Envelope version is not the reviewed v1 value.
    UnsupportedVersion,
    /// Cipher-suite identifier is not XChaCha20-Poly1305 v1.
    UnsupportedCipherSuite,
    /// Object-purpose identifier is not `GENERIC_ARTIFACT_BLOB` v1.
    UnsupportedObjectPurpose,
    /// Key generation is zero and therefore invalid.
    InvalidGeneration,
    /// Checked length arithmetic failed.
    LengthOverflow,
    /// Public plaintext/ciphertext length fields are inconsistent.
    LengthMismatch,
    /// Parsed vault/artifact/generation context does not match the requested object.
    ContextMismatch,
    /// Provider encryption failed without producing an envelope.
    EncryptionFailed,
    /// Authentication failed and no plaintext was released.
    AuthenticationFailed,
}

impl fmt::Display for BoundedBlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PlaintextTooLarge => "bounded blob plaintext exceeds the 64 MiB v1 ceiling",
            Self::TruncatedEnvelope => "bounded blob envelope is truncated",
            Self::TrailingData => "bounded blob envelope contains trailing data",
            Self::InvalidDomain => "bounded blob envelope domain is invalid",
            Self::UnsupportedVersion => "bounded blob envelope version is unsupported",
            Self::UnsupportedCipherSuite => "bounded blob cipher suite is unsupported",
            Self::UnsupportedObjectPurpose => "bounded blob object purpose is unsupported",
            Self::InvalidGeneration => "bounded blob key generation is invalid",
            Self::LengthOverflow => "bounded blob length arithmetic overflowed",
            Self::LengthMismatch => "bounded blob declared lengths are inconsistent",
            Self::ContextMismatch => {
                "bounded blob envelope context does not match the requested object"
            }
            Self::EncryptionFailed => "bounded blob encryption failed",
            Self::AuthenticationFailed => "bounded blob authentication failed",
        };
        f.write_str(message)
    }
}

impl Error for BoundedBlobError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundedLengths {
    plaintext_u64: u64,
    ciphertext_and_tag_u32: u32,
    ciphertext_and_tag_usize: usize,
}

fn validate_plaintext_length(plaintext_len: usize) -> Result<BoundedLengths, BoundedBlobError> {
    if plaintext_len > BOUNDED_BLOB_MAX_PLAINTEXT_BYTES {
        return Err(BoundedBlobError::PlaintextTooLarge);
    }

    let ciphertext_and_tag_usize = plaintext_len
        .checked_add(BOUNDED_BLOB_TAG_BYTES)
        .ok_or(BoundedBlobError::LengthOverflow)?;
    let plaintext_u64 =
        u64::try_from(plaintext_len).map_err(|_| BoundedBlobError::LengthOverflow)?;
    let ciphertext_and_tag_u32 =
        u32::try_from(ciphertext_and_tag_usize).map_err(|_| BoundedBlobError::LengthOverflow)?;

    Ok(BoundedLengths {
        plaintext_u64,
        ciphertext_and_tag_u32,
        ciphertext_and_tag_usize,
    })
}

fn build_aad(
    context: BoundedBlobContext,
    nonce: &[u8; BOUNDED_BLOB_NONCE_BYTES],
    lengths: BoundedLengths,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_BYTES);
    aad.extend_from_slice(AAD_DOMAIN_PREFIX);
    aad.extend_from_slice(&AAD_SCHEMA.to_be_bytes());
    aad.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    aad.extend_from_slice(&CIPHER_SUITE_XCHACHA20_POLY1305.to_be_bytes());
    aad.extend_from_slice(&OBJECT_PURPOSE_GENERIC_ARTIFACT_BLOB.to_be_bytes());
    aad.extend_from_slice(context.vault_id.as_bytes());
    aad.extend_from_slice(&context.artifact_id);
    aad.extend_from_slice(&context.key_generation.get().to_be_bytes());
    aad.extend_from_slice(&lengths.plaintext_u64.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&lengths.ciphertext_and_tag_u32.to_be_bytes());
    debug_assert_eq!(aad.len(), AAD_BYTES);
    aad
}

fn parse_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("fixed B202 header range"),
    )
}

fn parse_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixed B202 header range"),
    )
}

fn parse_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixed B202 header range"),
    )
}

fn parse_array<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    input[offset..offset + N]
        .try_into()
        .expect("fixed B202 header range")
}

struct ParsedEnvelope<'a> {
    context: BoundedBlobContext,
    nonce: [u8; BOUNDED_BLOB_NONCE_BYTES],
    lengths: BoundedLengths,
    ciphertext_and_tag: &'a [u8],
}

fn parse_envelope(envelope: &[u8]) -> Result<ParsedEnvelope<'_>, BoundedBlobError> {
    if envelope.len() < BOUNDED_BLOB_HEADER_BYTES {
        return Err(BoundedBlobError::TruncatedEnvelope);
    }
    if &envelope[..ENVELOPE_DOMAIN_PREFIX.len()] != ENVELOPE_DOMAIN_PREFIX {
        return Err(BoundedBlobError::InvalidDomain);
    }
    if parse_u16(envelope, VERSION_OFFSET) != ENVELOPE_VERSION {
        return Err(BoundedBlobError::UnsupportedVersion);
    }
    if parse_u16(envelope, CIPHER_SUITE_OFFSET) != CIPHER_SUITE_XCHACHA20_POLY1305 {
        return Err(BoundedBlobError::UnsupportedCipherSuite);
    }
    if parse_u16(envelope, OBJECT_PURPOSE_OFFSET) != OBJECT_PURPOSE_GENERIC_ARTIFACT_BLOB {
        return Err(BoundedBlobError::UnsupportedObjectPurpose);
    }

    let vault_id = VaultId::from_bytes(parse_array(envelope, VAULT_ID_OFFSET));
    let artifact_id = parse_array(envelope, ARTIFACT_ID_OFFSET);
    let key_generation = KeyGeneration::new(parse_u64(envelope, KEY_GENERATION_OFFSET))
        .map_err(|_| BoundedBlobError::InvalidGeneration)?;
    let plaintext_length = parse_u64(envelope, PLAINTEXT_LENGTH_OFFSET);
    let plaintext_len =
        usize::try_from(plaintext_length).map_err(|_| BoundedBlobError::PlaintextTooLarge)?;
    let lengths = validate_plaintext_length(plaintext_len)?;
    if lengths.plaintext_u64 != plaintext_length {
        return Err(BoundedBlobError::LengthMismatch);
    }

    let nonce = parse_array(envelope, NONCE_OFFSET);
    let declared_ciphertext_and_tag = parse_u32(envelope, CIPHERTEXT_LENGTH_OFFSET);
    if declared_ciphertext_and_tag != lengths.ciphertext_and_tag_u32 {
        return Err(BoundedBlobError::LengthMismatch);
    }

    let expected_total = BOUNDED_BLOB_HEADER_BYTES
        .checked_add(lengths.ciphertext_and_tag_usize)
        .ok_or(BoundedBlobError::LengthOverflow)?;
    if envelope.len() < expected_total {
        return Err(BoundedBlobError::TruncatedEnvelope);
    }
    if envelope.len() > expected_total {
        return Err(BoundedBlobError::TrailingData);
    }

    Ok(ParsedEnvelope {
        context: BoundedBlobContext::new(vault_id, artifact_id, key_generation),
        nonce,
        lengths,
        ciphertext_and_tag: &envelope[BOUNDED_BLOB_HEADER_BYTES..],
    })
}

/// Parses the public nonce carried by one canonical bounded-blob envelope.
///
/// This function validates only the public envelope structure; it does **not**
/// authenticate ciphertext or release plaintext. Callers may reuse the nonce as
/// authenticated inventory metadata only after separately authenticating the exact
/// envelope with `decrypt_bounded_blob` under the expected vault/artifact/generation.
pub fn bounded_blob_nonce(
    envelope: &[u8],
) -> Result<[u8; BOUNDED_BLOB_NONCE_BYTES], BoundedBlobError> {
    Ok(parse_envelope(envelope)?.nonce)
}

/// Encrypts one bounded generic artifact into the exact reviewed v1 envelope.
///
/// `nonce` is supplied by the caller. This function deliberately does not
/// generate, reserve, retry, restore, or classify nonces; B203 owns those rules.
///
/// # Errors
///
/// Returns a fail-closed error when the plaintext exceeds the reviewed bound,
/// checked length arithmetic fails, the provider rejects encryption, or the
/// provider returns a length inconsistent with the reviewed suite contract.
pub fn encrypt_bounded_blob(
    vrk: &OwnedKeyMaterial,
    context: BoundedBlobContext,
    nonce: [u8; BOUNDED_BLOB_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, BoundedBlobError> {
    let lengths = validate_plaintext_length(plaintext.len())?;
    let aad = build_aad(context, &nonce, lengths);
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).expect("B202 nonce is statically exactly 24 bytes");
    let blob_key = KeyDerivationContext::new(
        context.vault_id,
        context.key_generation,
        KeyPurpose::BoundedBlob,
    )
    .derive_purpose_key(vrk);
    let ciphertext_and_tag = blob_key
        .with_bytes(|key_bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(key_bytes)
                .expect("B201 purpose key is statically exactly 32 bytes");
            cipher.encrypt(
                nonce_ref,
                Payload {
                    msg: plaintext,
                    aad: aad.as_slice(),
                },
            )
        })
        .map_err(|_| BoundedBlobError::EncryptionFailed)?;

    if ciphertext_and_tag.len() != lengths.ciphertext_and_tag_usize {
        return Err(BoundedBlobError::LengthMismatch);
    }

    let capacity = BOUNDED_BLOB_HEADER_BYTES
        .checked_add(ciphertext_and_tag.len())
        .ok_or(BoundedBlobError::LengthOverflow)?;
    let mut envelope = Vec::with_capacity(capacity);
    envelope.extend_from_slice(ENVELOPE_DOMAIN_PREFIX);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&CIPHER_SUITE_XCHACHA20_POLY1305.to_be_bytes());
    envelope.extend_from_slice(&OBJECT_PURPOSE_GENERIC_ARTIFACT_BLOB.to_be_bytes());
    envelope.extend_from_slice(context.vault_id.as_bytes());
    envelope.extend_from_slice(&context.artifact_id);
    envelope.extend_from_slice(&context.key_generation.get().to_be_bytes());
    envelope.extend_from_slice(&lengths.plaintext_u64.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&lengths.ciphertext_and_tag_u32.to_be_bytes());
    envelope.extend_from_slice(&ciphertext_and_tag);
    debug_assert_eq!(envelope.len(), capacity);
    Ok(envelope)
}

/// Authenticates and decrypts one exact reviewed v1 bounded-blob envelope.
///
/// Parser bounds and the requested vault/artifact/generation context are checked
/// before AEAD invocation. Plaintext is returned only after authentication succeeds.
///
/// # Errors
///
/// Returns a fail-closed error for malformed/unsupported public encoding,
/// inconsistent lengths, requested-context mismatch, or AEAD authentication failure.
pub fn decrypt_bounded_blob(
    vrk: &OwnedKeyMaterial,
    expected_context: BoundedBlobContext,
    envelope: &[u8],
) -> Result<Vec<u8>, BoundedBlobError> {
    let parsed = parse_envelope(envelope)?;
    if parsed.context != expected_context {
        return Err(BoundedBlobError::ContextMismatch);
    }

    let aad = build_aad(parsed.context, &parsed.nonce, parsed.lengths);
    let nonce_ref = <&XNonce>::try_from(parsed.nonce.as_slice())
        .expect("parsed B202 nonce is statically exactly 24 bytes");
    let blob_key = KeyDerivationContext::new(
        parsed.context.vault_id,
        parsed.context.key_generation,
        KeyPurpose::BoundedBlob,
    )
    .derive_purpose_key(vrk);

    blob_key
        .with_bytes(|key_bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(key_bytes)
                .expect("B201 purpose key is statically exactly 32 bytes");
            cipher.decrypt(
                nonce_ref,
                Payload {
                    msg: parsed.ciphertext_and_tag,
                    aad: aad.as_slice(),
                },
            )
        })
        .map_err(|_| BoundedBlobError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VRK: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TEST_VAULT_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const TEST_ARTIFACT_ID: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];
    const TEST_NONCE: [u8; 24] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const TEST_GENERATION: u64 = 0x0102_0304_0506_0708;
    const TEST_PLAINTEXT: &[u8] = b"Himsat B202 deterministic envelope";
    const EXPECTED_ENVELOPE_HEX: &str = concat!(
        "001748494d5341542f424c4f422f454e56454c4f50452f7631000100010001",
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "01020304050607080000000000000022303132333435363738393a3b3c3d3e3f",
        "404142434445464700000032c7843b7408030132c75d7c63f57de88c7242b260",
        "4323f8a62d421303bebc1e916629260df869a0aee3be3d5ef416ffc8bc14"
    );

    fn context() -> BoundedBlobContext {
        BoundedBlobContext::new(
            VaultId::from_bytes(TEST_VAULT_ID),
            TEST_ARTIFACT_ID,
            KeyGeneration::new(TEST_GENERATION).expect("non-zero fixture generation"),
        )
    }

    fn vrk() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes(TEST_VRK)
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

    fn envelope() -> Vec<u8> {
        encrypt_bounded_blob(&vrk(), context(), TEST_NONCE, TEST_PLAINTEXT)
            .expect("fixture encryption must succeed")
    }

    #[test]
    fn deterministic_envelope_matches_independent_vector() {
        let envelope = envelope();
        assert_eq!(to_hex(&envelope), EXPECTED_ENVELOPE_HEX);
        assert_eq!(
            envelope.len(),
            BOUNDED_BLOB_HEADER_BYTES + TEST_PLAINTEXT.len() + BOUNDED_BLOB_TAG_BYTES
        );
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &envelope).unwrap(),
            TEST_PLAINTEXT
        );
    }

    #[test]
    fn empty_plaintext_produces_minimum_envelope() {
        let envelope = encrypt_bounded_blob(&vrk(), context(), [0_u8; 24], b"").unwrap();
        assert_eq!(envelope.len(), BOUNDED_BLOB_MIN_ENVELOPE_BYTES);
        assert!(
            decrypt_bounded_blob(&vrk(), context(), &envelope)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn bounds_are_checked_without_large_allocation() {
        let maximum = validate_plaintext_length(BOUNDED_BLOB_MAX_PLAINTEXT_BYTES).unwrap();
        assert_eq!(maximum.ciphertext_and_tag_usize, 67_108_880);
        assert_eq!(
            BOUNDED_BLOB_HEADER_BYTES + maximum.ciphertext_and_tag_usize,
            BOUNDED_BLOB_MAX_ENVELOPE_BYTES
        );
        assert_eq!(
            validate_plaintext_length(BOUNDED_BLOB_MAX_PLAINTEXT_BYTES + 1),
            Err(BoundedBlobError::PlaintextTooLarge)
        );
    }

    #[test]
    fn fixed_header_identifiers_fail_closed() {
        let original = envelope();
        for (offset, expected) in [
            (VERSION_OFFSET + 1, BoundedBlobError::UnsupportedVersion),
            (
                CIPHER_SUITE_OFFSET + 1,
                BoundedBlobError::UnsupportedCipherSuite,
            ),
            (
                OBJECT_PURPOSE_OFFSET + 1,
                BoundedBlobError::UnsupportedObjectPurpose,
            ),
        ] {
            let mut mutated = original.clone();
            mutated[offset] = 2;
            assert_eq!(
                decrypt_bounded_blob(&vrk(), context(), &mutated),
                Err(expected)
            );
        }
    }

    #[test]
    fn malformed_lengths_truncation_and_trailing_data_fail_closed() {
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &[0_u8; BOUNDED_BLOB_HEADER_BYTES - 1]),
            Err(BoundedBlobError::TruncatedEnvelope)
        );

        let original = envelope();
        let mut mismatched = original.clone();
        mismatched[CIPHERTEXT_LENGTH_OFFSET + 3] ^= 1;
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &mismatched),
            Err(BoundedBlobError::LengthMismatch)
        );

        let mut truncated = original.clone();
        truncated.pop();
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &truncated),
            Err(BoundedBlobError::TruncatedEnvelope)
        );

        let mut trailing = original;
        trailing.push(0);
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &trailing),
            Err(BoundedBlobError::TrailingData)
        );
    }

    #[test]
    fn zero_generation_fails_before_aead() {
        let mut mutated = envelope();
        mutated[KEY_GENERATION_OFFSET..KEY_GENERATION_OFFSET + 8].fill(0);
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &mutated),
            Err(BoundedBlobError::InvalidGeneration)
        );
    }

    #[test]
    fn ciphertext_nonce_and_wrong_key_fail_authentication_without_plaintext() {
        let original = envelope();

        let mut ciphertext_tamper = original.clone();
        ciphertext_tamper[BOUNDED_BLOB_HEADER_BYTES] ^= 0x80;
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &ciphertext_tamper),
            Err(BoundedBlobError::AuthenticationFailed)
        );

        let mut nonce_tamper = original.clone();
        nonce_tamper[NONCE_OFFSET] ^= 0x80;
        assert_eq!(
            decrypt_bounded_blob(&vrk(), context(), &nonce_tamper),
            Err(BoundedBlobError::AuthenticationFailed)
        );

        let wrong_vrk = OwnedKeyMaterial::from_bytes([0xa5; 32]);
        assert_eq!(
            decrypt_bounded_blob(&wrong_vrk, context(), &original),
            Err(BoundedBlobError::AuthenticationFailed)
        );
    }

    #[test]
    fn vault_artifact_and_generation_transplants_fail_closed() {
        let original = envelope();

        let wrong_vault = BoundedBlobContext::new(
            VaultId::from_bytes([0x99; 16]),
            TEST_ARTIFACT_ID,
            context().key_generation(),
        );
        assert_eq!(
            decrypt_bounded_blob(&vrk(), wrong_vault, &original),
            Err(BoundedBlobError::ContextMismatch)
        );

        let wrong_artifact =
            BoundedBlobContext::new(context().vault_id(), [0x88; 16], context().key_generation());
        assert_eq!(
            decrypt_bounded_blob(&vrk(), wrong_artifact, &original),
            Err(BoundedBlobError::ContextMismatch)
        );

        let wrong_generation = BoundedBlobContext::new(
            context().vault_id(),
            TEST_ARTIFACT_ID,
            KeyGeneration::new(TEST_GENERATION + 1).unwrap(),
        );
        assert_eq!(
            decrypt_bounded_blob(&vrk(), wrong_generation, &original),
            Err(BoundedBlobError::ContextMismatch)
        );
    }
}

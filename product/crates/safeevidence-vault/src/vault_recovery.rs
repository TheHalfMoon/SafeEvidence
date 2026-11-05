//! Reviewed recovery-envelope execution for Specification 004 B204.
//!
//! This module implements only the fixed v1 `ARGON2ID_RFC9106_64M_V1`
//! recovery envelope reviewed by Specification 004A. It does not implement
//! backup publication, freshness anchoring, protector integration, rotation,
//! SQLCipher, or Specification 005 behavior.

use crate::vault::{KeyGeneration, VaultId};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use argon2::{Algorithm, Argon2, Error as Argon2Error, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use std::error::Error;
use std::fmt;
use zeroize::Zeroize;

/// Exact byte length of the canonical v1 recovery envelope.
pub const RECOVERY_ENVELOPE_BYTES: usize = 167;
/// Exact byte length of canonical v1 recovery AAD.
pub const RECOVERY_AAD_BYTES: usize = 116;
/// Exact v1 recovery salt length.
pub const RECOVERY_SALT_BYTES: usize = 16;
/// Exact v1 XChaCha20-Poly1305 nonce length.
pub const RECOVERY_NONCE_BYTES: usize = 24;
/// Exact v1 wrapped-VRK ciphertext plus Poly1305 tag length.
pub const RECOVERY_CIPHERTEXT_AND_TAG_BYTES: usize = 48;
/// Minimum v1 recovery passphrase length in Unicode scalar values.
pub const RECOVERY_PASSPHRASE_MIN_UNICODE_SCALARS: usize = 16;
/// Maximum v1 recovery passphrase length in exact UTF-8 bytes.
pub const RECOVERY_PASSPHRASE_MAX_UTF8_BYTES: usize = 1024;

const ENVELOPE_DOMAIN_PREFIX: &[u8; 29] = b"\x00\x1bHIMSAT/RECOVERY/ENVELOPE/v1";
const AAD_DOMAIN_PREFIX: &[u8; 24] = b"\x00\x16HIMSAT/RECOVERY/AAD/v1";
const AAD_SCHEMA: u16 = 1;
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_TYPE_VRK_WRAP: u16 = 1;
const CIPHER_SUITE_XCHACHA20_POLY1305: u16 = 1;
const RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1: u16 = 1;
const ARGON2_VERSION: u16 = 0x0013;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_PASSES: u32 = 3;
const ARGON2_PARALLELISM: u16 = 4;
const KDF_OUTPUT_BYTES: u16 = 32;
const CIPHERTEXT_AND_TAG_LENGTH: u32 = 48;

const VERSION_OFFSET: usize = 29;
const ENVELOPE_TYPE_OFFSET: usize = 31;
const CIPHER_SUITE_OFFSET: usize = 33;
const RECOVERY_POLICY_OFFSET: usize = 35;
const VAULT_ID_OFFSET: usize = 37;
const KEY_GENERATION_OFFSET: usize = 53;
const ARGON2_VERSION_OFFSET: usize = 61;
const MEMORY_KIB_OFFSET: usize = 63;
const PASSES_OFFSET: usize = 67;
const PARALLELISM_OFFSET: usize = 71;
const KDF_OUTPUT_BYTES_OFFSET: usize = 73;
const SALT_OFFSET: usize = 75;
const NONCE_OFFSET: usize = 91;
const CIPHERTEXT_LENGTH_OFFSET: usize = 115;
const CIPHERTEXT_OFFSET: usize = 119;

/// Public vault/generation context authenticated by one recovery envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryContext {
    vault_id: VaultId,
    key_generation: KeyGeneration,
}

impl RecoveryContext {
    /// Creates a recovery context from already validated public identities.
    #[must_use]
    pub const fn new(vault_id: VaultId, key_generation: KeyGeneration) -> Self {
        Self {
            vault_id,
            key_generation,
        }
    }

    /// Returns the public vault identity bound into recovery AAD.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns the non-zero key generation bound into recovery AAD.
    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }
}

/// Fail-closed B204 recovery-envelope errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEnvelopeError {
    /// A new recovery passphrase contains fewer than 16 Unicode scalar values.
    PassphraseTooShort,
    /// A new recovery passphrase exceeds 1024 exact UTF-8 bytes.
    PassphraseTooLong,
    /// The approved OS-CSPRNG failed to fill the required salt or nonce.
    RandomnessUnavailable,
    /// Envelope ends before the exact 167-byte v1 length.
    TruncatedEnvelope,
    /// Envelope contains bytes after the exact 167-byte v1 length.
    TrailingData,
    /// Public recovery-envelope domain is not the exact v1 domain.
    InvalidDomain,
    /// Recovery-envelope version is not the reviewed v1 value.
    UnsupportedVersion,
    /// Envelope type is not the reviewed `VRK_WRAP` value.
    UnsupportedEnvelopeType,
    /// Cipher suite is not XChaCha20-Poly1305 v1.
    UnsupportedCipherSuite,
    /// Recovery policy identifier is not `ARGON2ID_RFC9106_64M_V1`.
    InvalidRecoveryPolicy,
    /// Public Argon2id parameters do not exactly match the reviewed v1 profile.
    InvalidArgon2Parameters,
    /// Key generation is zero and therefore invalid.
    InvalidGeneration,
    /// Public ciphertext/tag length is not exactly 48 bytes.
    LengthMismatch,
    /// The device/provider could not allocate the fixed reviewed Argon2id profile.
    ResourceLimit,
    /// The fixed Argon2id provider rejected an otherwise reviewed operation.
    KdfFailed,
    /// XChaCha20-Poly1305 encryption failed without producing an envelope.
    EncryptionFailed,
    /// Wrong passphrase, AEAD/tag failure, or vault/generation transplant.
    RecoveryAuthenticationFailed,
}

impl fmt::Display for RecoveryEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PassphraseTooShort => {
                "recovery passphrase contains fewer than 16 Unicode scalar values"
            }
            Self::PassphraseTooLong => "recovery passphrase exceeds 1024 UTF-8 bytes",
            Self::RandomnessUnavailable => "approved OS-CSPRNG recovery randomness failed",
            Self::TruncatedEnvelope => "recovery envelope is truncated",
            Self::TrailingData => "recovery envelope contains trailing data",
            Self::InvalidDomain => "recovery envelope domain is invalid",
            Self::UnsupportedVersion => "recovery envelope version is unsupported",
            Self::UnsupportedEnvelopeType => "recovery envelope type is unsupported",
            Self::UnsupportedCipherSuite => "recovery cipher suite is unsupported",
            Self::InvalidRecoveryPolicy => "recovery policy is invalid",
            Self::InvalidArgon2Parameters => "recovery Argon2id parameters are invalid",
            Self::InvalidGeneration => "recovery key generation is invalid",
            Self::LengthMismatch => "recovery ciphertext/tag length is invalid",
            Self::ResourceLimit => "recovery KDF resource limit prevents the fixed v1 profile",
            Self::KdfFailed => "recovery KDF operation failed",
            Self::EncryptionFailed => "recovery envelope encryption failed",
            Self::RecoveryAuthenticationFailed => "recovery authentication failed",
        };
        f.write_str(message)
    }
}

impl Error for RecoveryEnvelopeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedRecoveryEnvelope<'a> {
    context: RecoveryContext,
    salt: [u8; RECOVERY_SALT_BYTES],
    nonce: [u8; RECOVERY_NONCE_BYTES],
    ciphertext_and_tag: &'a [u8],
}

fn parse_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("fixed B204 envelope range"),
    )
}

fn parse_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixed B204 envelope range"),
    )
}

fn parse_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixed B204 envelope range"),
    )
}

fn parse_array<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    input[offset..offset + N]
        .try_into()
        .expect("fixed B204 envelope range")
}

fn parse_recovery_envelope(
    envelope: &[u8],
) -> Result<ParsedRecoveryEnvelope<'_>, RecoveryEnvelopeError> {
    if envelope.len() < RECOVERY_ENVELOPE_BYTES {
        return Err(RecoveryEnvelopeError::TruncatedEnvelope);
    }
    if envelope.len() > RECOVERY_ENVELOPE_BYTES {
        return Err(RecoveryEnvelopeError::TrailingData);
    }
    if &envelope[..ENVELOPE_DOMAIN_PREFIX.len()] != ENVELOPE_DOMAIN_PREFIX {
        return Err(RecoveryEnvelopeError::InvalidDomain);
    }
    if parse_u16(envelope, VERSION_OFFSET) != ENVELOPE_VERSION {
        return Err(RecoveryEnvelopeError::UnsupportedVersion);
    }
    if parse_u16(envelope, ENVELOPE_TYPE_OFFSET) != ENVELOPE_TYPE_VRK_WRAP {
        return Err(RecoveryEnvelopeError::UnsupportedEnvelopeType);
    }
    if parse_u16(envelope, CIPHER_SUITE_OFFSET) != CIPHER_SUITE_XCHACHA20_POLY1305 {
        return Err(RecoveryEnvelopeError::UnsupportedCipherSuite);
    }
    if parse_u16(envelope, RECOVERY_POLICY_OFFSET) != RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1 {
        return Err(RecoveryEnvelopeError::InvalidRecoveryPolicy);
    }
    if parse_u16(envelope, ARGON2_VERSION_OFFSET) != ARGON2_VERSION
        || parse_u32(envelope, MEMORY_KIB_OFFSET) != ARGON2_MEMORY_KIB
        || parse_u32(envelope, PASSES_OFFSET) != ARGON2_PASSES
        || parse_u16(envelope, PARALLELISM_OFFSET) != ARGON2_PARALLELISM
        || parse_u16(envelope, KDF_OUTPUT_BYTES_OFFSET) != KDF_OUTPUT_BYTES
    {
        return Err(RecoveryEnvelopeError::InvalidArgon2Parameters);
    }
    if parse_u32(envelope, CIPHERTEXT_LENGTH_OFFSET) != CIPHERTEXT_AND_TAG_LENGTH {
        return Err(RecoveryEnvelopeError::LengthMismatch);
    }

    let vault_id = VaultId::from_bytes(parse_array(envelope, VAULT_ID_OFFSET));
    let key_generation = KeyGeneration::new(parse_u64(envelope, KEY_GENERATION_OFFSET))
        .map_err(|_| RecoveryEnvelopeError::InvalidGeneration)?;

    Ok(ParsedRecoveryEnvelope {
        context: RecoveryContext::new(vault_id, key_generation),
        salt: parse_array(envelope, SALT_OFFSET),
        nonce: parse_array(envelope, NONCE_OFFSET),
        ciphertext_and_tag: &envelope[CIPHERTEXT_OFFSET..],
    })
}

fn validate_new_passphrase(passphrase: &str) -> Result<(), RecoveryEnvelopeError> {
    if passphrase.len() > RECOVERY_PASSPHRASE_MAX_UTF8_BYTES {
        return Err(RecoveryEnvelopeError::PassphraseTooLong);
    }
    if passphrase.chars().count() < RECOVERY_PASSPHRASE_MIN_UNICODE_SCALARS {
        return Err(RecoveryEnvelopeError::PassphraseTooShort);
    }
    Ok(())
}

fn validate_authentication_passphrase(passphrase: &str) -> Result<(), RecoveryEnvelopeError> {
    if passphrase.len() > RECOVERY_PASSPHRASE_MAX_UTF8_BYTES
        || passphrase.chars().count() < RECOVERY_PASSPHRASE_MIN_UNICODE_SCALARS
    {
        return Err(RecoveryEnvelopeError::RecoveryAuthenticationFailed);
    }
    Ok(())
}

fn build_recovery_aad(
    context: RecoveryContext,
    salt: &[u8; RECOVERY_SALT_BYTES],
    nonce: &[u8; RECOVERY_NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECOVERY_AAD_BYTES);
    aad.extend_from_slice(AAD_DOMAIN_PREFIX);
    aad.extend_from_slice(&AAD_SCHEMA.to_be_bytes());
    aad.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    aad.extend_from_slice(&ENVELOPE_TYPE_VRK_WRAP.to_be_bytes());
    aad.extend_from_slice(&CIPHER_SUITE_XCHACHA20_POLY1305.to_be_bytes());
    aad.extend_from_slice(&RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1.to_be_bytes());
    aad.extend_from_slice(context.vault_id.as_bytes());
    aad.extend_from_slice(&context.key_generation.get().to_be_bytes());
    aad.extend_from_slice(&ARGON2_VERSION.to_be_bytes());
    aad.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    aad.extend_from_slice(&ARGON2_PASSES.to_be_bytes());
    aad.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    aad.extend_from_slice(&KDF_OUTPUT_BYTES.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&CIPHERTEXT_AND_TAG_LENGTH.to_be_bytes());
    debug_assert_eq!(aad.len(), RECOVERY_AAD_BYTES);
    aad
}

fn map_argon2_error(error: Argon2Error) -> RecoveryEnvelopeError {
    match error {
        Argon2Error::OutOfMemory => RecoveryEnvelopeError::ResourceLimit,
        _ => RecoveryEnvelopeError::KdfFailed,
    }
}

fn derive_recovery_kek(
    passphrase: &str,
    salt: &[u8; RECOVERY_SALT_BYTES],
) -> Result<OwnedKeyMaterial, RecoveryEnvelopeError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_PASSES,
        u32::from(ARGON2_PARALLELISM),
        Some(usize::from(KDF_OUTPUT_BYTES)),
    )
    .map_err(map_argon2_error)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; KEY_MATERIAL_BYTES];

    if let Err(error) = argon2.hash_password_into(passphrase.as_bytes(), salt, &mut output) {
        output.zeroize();
        return Err(map_argon2_error(error));
    }

    let recovery_kek = OwnedKeyMaterial::from_bytes(output);
    output.zeroize();
    Ok(recovery_kek)
}

fn encrypt_with_material(
    vrk: &OwnedKeyMaterial,
    context: RecoveryContext,
    passphrase: &str,
    salt: [u8; RECOVERY_SALT_BYTES],
    nonce: [u8; RECOVERY_NONCE_BYTES],
) -> Result<Vec<u8>, RecoveryEnvelopeError> {
    validate_new_passphrase(passphrase)?;
    let recovery_kek = derive_recovery_kek(passphrase, &salt)?;
    let aad = build_recovery_aad(context, &salt, &nonce);
    let nonce_ref = <&XNonce>::try_from(nonce.as_slice())
        .expect("B204 recovery nonce is statically exactly 24 bytes");
    let ciphertext_and_tag = recovery_kek
        .with_bytes(|key_bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(key_bytes)
                .expect("B204 Recovery KEK is statically exactly 32 bytes");
            vrk.with_bytes(|vrk_bytes| {
                cipher.encrypt(
                    nonce_ref,
                    Payload {
                        msg: vrk_bytes,
                        aad: aad.as_slice(),
                    },
                )
            })
        })
        .map_err(|_| RecoveryEnvelopeError::EncryptionFailed)?;

    if ciphertext_and_tag.len() != RECOVERY_CIPHERTEXT_AND_TAG_BYTES {
        return Err(RecoveryEnvelopeError::LengthMismatch);
    }

    let mut envelope = Vec::with_capacity(RECOVERY_ENVELOPE_BYTES);
    envelope.extend_from_slice(ENVELOPE_DOMAIN_PREFIX);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&ENVELOPE_TYPE_VRK_WRAP.to_be_bytes());
    envelope.extend_from_slice(&CIPHER_SUITE_XCHACHA20_POLY1305.to_be_bytes());
    envelope.extend_from_slice(&RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1.to_be_bytes());
    envelope.extend_from_slice(context.vault_id.as_bytes());
    envelope.extend_from_slice(&context.key_generation.get().to_be_bytes());
    envelope.extend_from_slice(&ARGON2_VERSION.to_be_bytes());
    envelope.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    envelope.extend_from_slice(&ARGON2_PASSES.to_be_bytes());
    envelope.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    envelope.extend_from_slice(&KDF_OUTPUT_BYTES.to_be_bytes());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&CIPHERTEXT_AND_TAG_LENGTH.to_be_bytes());
    envelope.extend_from_slice(&ciphertext_and_tag);
    debug_assert_eq!(envelope.len(), RECOVERY_ENVELOPE_BYTES);
    Ok(envelope)
}

fn encrypt_with_random<F>(
    vrk: &OwnedKeyMaterial,
    context: RecoveryContext,
    passphrase: &str,
    mut fill: F,
) -> Result<Vec<u8>, RecoveryEnvelopeError>
where
    F: FnMut(&mut [u8]) -> Result<(), ()>,
{
    validate_new_passphrase(passphrase)?;
    let mut salt = [0_u8; RECOVERY_SALT_BYTES];
    fill(&mut salt).map_err(|()| RecoveryEnvelopeError::RandomnessUnavailable)?;
    let mut nonce = [0_u8; RECOVERY_NONCE_BYTES];
    fill(&mut nonce).map_err(|()| RecoveryEnvelopeError::RandomnessUnavailable)?;
    encrypt_with_material(vrk, context, passphrase, salt, nonce)
}

/// Creates one exact reviewed v1 recovery envelope around a 32-byte VRK.
///
/// Production obtains a fresh 16-byte salt and fresh 24-byte nonce from the
/// approved OS CSPRNG for every attempt. Randomness failure aborts without an
/// envelope or fallback source. The passphrase is consumed as exact UTF-8 bytes;
/// it is never trimmed, case-folded, truncated, or normalized.
///
/// # Errors
///
/// Returns a fail-closed error when passphrase policy, OS randomness, the fixed
/// Argon2id profile, or XChaCha20-Poly1305 execution cannot satisfy v1 exactly.
pub fn encrypt_recovery_envelope(
    vrk: &OwnedKeyMaterial,
    context: RecoveryContext,
    passphrase: &str,
) -> Result<Vec<u8>, RecoveryEnvelopeError> {
    encrypt_with_random(vrk, context, passphrase, |bytes| {
        getrandom::fill(bytes).map_err(|_| ())
    })
}

/// Authenticates one exact reviewed v1 recovery envelope and returns its VRK.
///
/// Public envelope structure and the complete fixed Argon2id policy are checked
/// before KDF allocation. Recovery AAD is rebuilt from the parsed public
/// vault/generation context so every public cryptographic-context field remains
/// authenticated. Only after AEAD succeeds is that authenticated context compared
/// with the caller's expected vault/generation. A mismatch is returned as the same
/// externally visible `RecoveryAuthenticationFailed` result as a wrong passphrase
/// or AEAD/tag failure. No partial VRK is released.
///
/// # Errors
///
/// Returns safe typed pre-authentication errors for malformed/unsupported public
/// structure or fixed-profile resource failure. Every wrong-passphrase, tag, or
/// expected-context authentication failure returns `RecoveryAuthenticationFailed`.
pub fn decrypt_recovery_envelope(
    expected_context: RecoveryContext,
    passphrase: &str,
    envelope: &[u8],
) -> Result<OwnedKeyMaterial, RecoveryEnvelopeError> {
    let parsed = parse_recovery_envelope(envelope)?;
    validate_authentication_passphrase(passphrase)?;
    let recovery_kek = derive_recovery_kek(passphrase, &parsed.salt)?;
    let aad = build_recovery_aad(parsed.context, &parsed.salt, &parsed.nonce);
    let nonce_ref = <&XNonce>::try_from(parsed.nonce.as_slice())
        .expect("parsed B204 recovery nonce is statically exactly 24 bytes");
    let mut plaintext = recovery_kek
        .with_bytes(|key_bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(key_bytes)
                .expect("B204 Recovery KEK is statically exactly 32 bytes");
            cipher.decrypt(
                nonce_ref,
                Payload {
                    msg: parsed.ciphertext_and_tag,
                    aad: aad.as_slice(),
                },
            )
        })
        .map_err(|_| RecoveryEnvelopeError::RecoveryAuthenticationFailed)?;

    if parsed.context != expected_context {
        plaintext.fill(0);
        return Err(RecoveryEnvelopeError::RecoveryAuthenticationFailed);
    }
    if plaintext.len() != KEY_MATERIAL_BYTES {
        plaintext.fill(0);
        return Err(RecoveryEnvelopeError::RecoveryAuthenticationFailed);
    }

    let mut vrk = [0_u8; KEY_MATERIAL_BYTES];
    vrk.copy_from_slice(&plaintext);
    plaintext.fill(0);
    let owned_vrk = OwnedKeyMaterial::from_bytes(vrk);
    vrk.zeroize();
    Ok(owned_vrk)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VRK: [u8; KEY_MATERIAL_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TEST_VAULT_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const TEST_SALT: [u8; RECOVERY_SALT_BYTES] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];
    const TEST_NONCE: [u8; RECOVERY_NONCE_BYTES] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const TEST_GENERATION: u64 = 0x0102_0304_0506_0708;
    const TEST_PASSPHRASE: &str = "correct horse battery staple";
    const EXPECTED_ENVELOPE_HEX: &str = concat!(
        "001b48494d5341542f5245434f564552592f454e56454c4f50452f7631",
        "0001000100010001101112131415161718191a1b1c1d1e1f0102030405060708",
        "0013000100000000000300040020202122232425262728292a2b2c2d2e2f",
        "303132333435363738393a3b3c3d3e3f404142434445464700000030",
        "b02c2407d35111ecf0b5d6ff684fd202aee35ad65c5deca3a699a724e10b97d5",
        "7f43297abcd8ee04f5a695f7859de146"
    );

    fn context() -> RecoveryContext {
        RecoveryContext::new(
            VaultId::from_bytes(TEST_VAULT_ID),
            KeyGeneration::new(TEST_GENERATION).expect("fixture generation is non-zero"),
        )
    }

    fn vrk() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes(TEST_VRK)
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).expect("valid fixture hex");
                let low = char::from(pair[1]).to_digit(16).expect("valid fixture hex");
                u8::try_from((high << 4) | low).expect("one fixture byte")
            })
            .collect()
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
    fn deterministic_envelope_matches_independent_vector_and_round_trips() {
        let envelope =
            encrypt_with_material(&vrk(), context(), TEST_PASSPHRASE, TEST_SALT, TEST_NONCE)
                .expect("fixture encryption must succeed");
        assert_eq!(envelope.len(), RECOVERY_ENVELOPE_BYTES);
        assert_eq!(to_hex(&envelope), EXPECTED_ENVELOPE_HEX);

        let recovered = decrypt_recovery_envelope(context(), TEST_PASSPHRASE, &envelope)
            .expect("fixture recovery must authenticate");
        recovered.with_bytes(|bytes| assert_eq!(bytes, &TEST_VRK));
    }

    #[test]
    fn creation_passphrase_policy_uses_unicode_scalars_and_exact_utf8_bytes() {
        assert_eq!(
            validate_new_passphrase("123456789012345"),
            Err(RecoveryEnvelopeError::PassphraseTooShort)
        );
        assert!(validate_new_passphrase("éééééééééééééééé").is_ok());
        let too_long = "a".repeat(RECOVERY_PASSPHRASE_MAX_UTF8_BYTES + 1);
        assert_eq!(
            validate_new_passphrase(&too_long),
            Err(RecoveryEnvelopeError::PassphraseTooLong)
        );
        assert_ne!("é".as_bytes(), "e\u{301}".as_bytes());
    }

    #[test]
    fn parser_rejects_noncanonical_public_structure_before_kdf() {
        let original = from_hex(EXPECTED_ENVELOPE_HEX);
        assert_eq!(original.len(), RECOVERY_ENVELOPE_BYTES);
        assert_eq!(
            parse_recovery_envelope(&original[..RECOVERY_ENVELOPE_BYTES - 1]).err(),
            Some(RecoveryEnvelopeError::TruncatedEnvelope)
        );

        let mut trailing = original.clone();
        trailing.push(0);
        assert_eq!(
            parse_recovery_envelope(&trailing).err(),
            Some(RecoveryEnvelopeError::TrailingData)
        );

        for (offset, expected) in [
            (2, RecoveryEnvelopeError::InvalidDomain),
            (
                VERSION_OFFSET + 1,
                RecoveryEnvelopeError::UnsupportedVersion,
            ),
            (
                ENVELOPE_TYPE_OFFSET + 1,
                RecoveryEnvelopeError::UnsupportedEnvelopeType,
            ),
            (
                CIPHER_SUITE_OFFSET + 1,
                RecoveryEnvelopeError::UnsupportedCipherSuite,
            ),
            (
                RECOVERY_POLICY_OFFSET + 1,
                RecoveryEnvelopeError::InvalidRecoveryPolicy,
            ),
            (
                ARGON2_VERSION_OFFSET + 1,
                RecoveryEnvelopeError::InvalidArgon2Parameters,
            ),
            (
                MEMORY_KIB_OFFSET + 3,
                RecoveryEnvelopeError::InvalidArgon2Parameters,
            ),
            (
                PASSES_OFFSET + 3,
                RecoveryEnvelopeError::InvalidArgon2Parameters,
            ),
            (
                PARALLELISM_OFFSET + 1,
                RecoveryEnvelopeError::InvalidArgon2Parameters,
            ),
            (
                KDF_OUTPUT_BYTES_OFFSET + 1,
                RecoveryEnvelopeError::InvalidArgon2Parameters,
            ),
            (
                CIPHERTEXT_LENGTH_OFFSET + 3,
                RecoveryEnvelopeError::LengthMismatch,
            ),
        ] {
            let mut mutated = original.clone();
            mutated[offset] ^= 1;
            assert_eq!(parse_recovery_envelope(&mutated).err(), Some(expected));
        }

        let mut zero_generation = original;
        zero_generation[KEY_GENERATION_OFFSET..KEY_GENERATION_OFFSET + 8].fill(0);
        assert_eq!(
            parse_recovery_envelope(&zero_generation).err(),
            Some(RecoveryEnvelopeError::InvalidGeneration)
        );
    }

    #[test]
    fn wrong_passphrase_tag_public_context_and_transplant_fail_uniformly() {
        let original = from_hex(EXPECTED_ENVELOPE_HEX);
        assert_eq!(
            decrypt_recovery_envelope(context(), "wrong horse battery staple", &original).err(),
            Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
        );

        let mut tampered_tag = original.clone();
        tampered_tag[RECOVERY_ENVELOPE_BYTES - 1] ^= 1;
        assert_eq!(
            decrypt_recovery_envelope(context(), TEST_PASSPHRASE, &tampered_tag).err(),
            Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
        );

        let mut tampered_public_context = original.clone();
        tampered_public_context[VAULT_ID_OFFSET] ^= 1;
        assert_eq!(
            decrypt_recovery_envelope(context(), TEST_PASSPHRASE, &tampered_public_context).err(),
            Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
        );

        let other_context = RecoveryContext::new(
            VaultId::from_bytes([0x99; 16]),
            KeyGeneration::new(TEST_GENERATION + 1).expect("fixture generation is non-zero"),
        );
        assert_eq!(
            decrypt_recovery_envelope(other_context, TEST_PASSPHRASE, &original).err(),
            Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
        );
        assert_eq!(
            decrypt_recovery_envelope(context(), "too short", &original).err(),
            Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
        );
    }

    #[test]
    fn randomness_failure_is_fail_closed_without_fallback() {
        let mut calls = 0_usize;
        let result = encrypt_with_random(&vrk(), context(), TEST_PASSPHRASE, |bytes| {
            calls += 1;
            if calls == 1 {
                bytes.fill(0xaa);
                Ok(())
            } else {
                Err(())
            }
        });
        assert_eq!(
            result.err(),
            Some(RecoveryEnvelopeError::RandomnessUnavailable)
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn provider_out_of_memory_maps_to_resource_limit() {
        assert_eq!(
            map_argon2_error(Argon2Error::OutOfMemory),
            RecoveryEnvelopeError::ResourceLimit
        );
        assert_eq!(
            map_argon2_error(Argon2Error::MemoryTooLittle),
            RecoveryEnvelopeError::KdfFailed
        );
    }

    #[test]
    fn aad_is_exact_reviewed_length_and_uses_context() {
        let aad = build_recovery_aad(context(), &TEST_SALT, &TEST_NONCE);
        assert_eq!(aad.len(), RECOVERY_AAD_BYTES);
        assert_eq!(&aad[..AAD_DOMAIN_PREFIX.len()], AAD_DOMAIN_PREFIX);
        assert_eq!(
            &aad[34..50],
            context().vault_id().as_bytes(),
            "vault id follows the fixed AAD identifiers"
        );
        assert_eq!(
            &aad[50..58],
            &context().key_generation().get().to_be_bytes(),
            "generation follows the vault id"
        );
    }

    #[test]
    fn parsed_public_context_is_retained_for_authenticated_aad() {
        let original = from_hex(EXPECTED_ENVELOPE_HEX);
        let parsed = parse_recovery_envelope(&original).expect("fixture envelope is canonical");
        assert_eq!(parsed.context, context());
        assert_eq!(parsed.salt, TEST_SALT);
        assert_eq!(parsed.nonce, TEST_NONCE);
        assert_eq!(
            parsed.ciphertext_and_tag.len(),
            RECOVERY_CIPHERTEXT_AND_TAG_BYTES
        );
    }
}

//! Aggregate Specification 004 B205 adversarial evidence.
//!
//! This file exercises the already reviewed B202-B204 public contracts without
//! changing production cryptographic semantics. Private fault-injection coverage
//! for OS-randomness failure and collision regeneration remains in the canonical
//! B203/B204 unit tests and is re-executed by the normal all-target test gates.

use safeevidence_vault::vault::{KeyGeneration, VaultId};
use safeevidence_vault::vault_blob::{
    BOUNDED_BLOB_HEADER_BYTES, BOUNDED_BLOB_MAX_ENVELOPE_BYTES, BOUNDED_BLOB_MAX_PLAINTEXT_BYTES,
    BOUNDED_BLOB_MIN_ENVELOPE_BYTES, BoundedBlobContext, BoundedBlobError, decrypt_bounded_blob,
    encrypt_bounded_blob,
};
use safeevidence_vault::vault_keys::OwnedKeyMaterial;
use safeevidence_vault::vault_nonce::{
    NonceLifecycleError, NoncePurpose, NonceReservation, NonceReservationLedger,
};
use safeevidence_vault::vault_recovery::{
    RECOVERY_ENVELOPE_BYTES, RecoveryContext, RecoveryEnvelopeError, decrypt_recovery_envelope,
};

const BLOB_VERSION_OFFSET: usize = 25;
const BLOB_SUITE_OFFSET: usize = 27;
const BLOB_PURPOSE_OFFSET: usize = 29;
const BLOB_VAULT_OFFSET: usize = 31;
const BLOB_ARTIFACT_OFFSET: usize = 47;
const BLOB_GENERATION_OFFSET: usize = 63;
const BLOB_PLAINTEXT_LENGTH_OFFSET: usize = 71;
const BLOB_NONCE_OFFSET: usize = 79;
const BLOB_CIPHERTEXT_LENGTH_OFFSET: usize = 103;

const RECOVERY_VERSION_OFFSET: usize = 29;
const RECOVERY_TYPE_OFFSET: usize = 31;
const RECOVERY_SUITE_OFFSET: usize = 33;
const RECOVERY_POLICY_OFFSET: usize = 35;
const RECOVERY_VAULT_OFFSET: usize = 37;
const RECOVERY_GENERATION_OFFSET: usize = 53;
const RECOVERY_ARGON_VERSION_OFFSET: usize = 61;
const RECOVERY_MEMORY_OFFSET: usize = 63;
const RECOVERY_PASSES_OFFSET: usize = 67;
const RECOVERY_PARALLELISM_OFFSET: usize = 71;
const RECOVERY_OUTPUT_OFFSET: usize = 73;
const RECOVERY_SALT_OFFSET: usize = 75;
const RECOVERY_NONCE_OFFSET: usize = 91;
const RECOVERY_CIPHERTEXT_LENGTH_OFFSET: usize = 115;
const RECOVERY_CIPHERTEXT_OFFSET: usize = 119;

const TEST_VRK: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const BLOB_VAULT: [u8; 16] = [0x11; 16];
const BLOB_ARTIFACT: [u8; 16] = [0x22; 16];
const BLOB_NONCE: [u8; 24] = [0x33; 24];
const BLOB_GENERATION: u64 = 7;
const BLOB_PLAINTEXT: &[u8] = b"B205 aggregate bounded-blob adversarial fixture";

const RECOVERY_VAULT: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const RECOVERY_GENERATION: u64 = 0x0102_0304_0506_0708;
const RECOVERY_PASSPHRASE: &str = "correct horse battery staple";
const RECOVERY_ENVELOPE_HEX: &str = concat!(
    "001b48494d5341542f5245434f564552592f454e56454c4f50452f7631",
    "0001000100010001101112131415161718191a1b1c1d1e1f0102030405060708",
    "0013000100000000000300040020202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f404142434445464700000030",
    "b02c2407d35111ecf0b5d6ff684fd202aee35ad65c5deca3a699a724e10b97d5",
    "7f43297abcd8ee04f5a695f7859de146"
);

fn vrk() -> OwnedKeyMaterial {
    OwnedKeyMaterial::from_bytes(TEST_VRK)
}

fn generation(value: u64) -> KeyGeneration {
    KeyGeneration::new(value).expect("fixture generation is non-zero")
}

fn blob_context() -> BoundedBlobContext {
    BoundedBlobContext::new(
        VaultId::from_bytes(BLOB_VAULT),
        BLOB_ARTIFACT,
        generation(BLOB_GENERATION),
    )
}

fn blob_envelope() -> Vec<u8> {
    encrypt_bounded_blob(&vrk(), blob_context(), BLOB_NONCE, BLOB_PLAINTEXT)
        .expect("canonical B205 bounded-blob fixture must encrypt")
}

fn recovery_context() -> RecoveryContext {
    RecoveryContext::new(
        VaultId::from_bytes(RECOVERY_VAULT),
        generation(RECOVERY_GENERATION),
    )
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

fn assert_recovery_authentication_failed(envelope: &[u8], context: RecoveryContext) {
    assert_eq!(
        decrypt_recovery_envelope(context, RECOVERY_PASSPHRASE, envelope).err(),
        Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
    );
}

#[test]
fn bounded_blob_fixed_structure_rejects_each_identifier_and_malformed_length() {
    let original = blob_envelope();

    for (offset, expected) in [
        (0, BoundedBlobError::InvalidDomain),
        (
            BLOB_VERSION_OFFSET + 1,
            BoundedBlobError::UnsupportedVersion,
        ),
        (
            BLOB_SUITE_OFFSET + 1,
            BoundedBlobError::UnsupportedCipherSuite,
        ),
        (
            BLOB_PURPOSE_OFFSET + 1,
            BoundedBlobError::UnsupportedObjectPurpose,
        ),
    ] {
        let mut mutated = original.clone();
        mutated[offset] ^= 1;
        assert_eq!(
            decrypt_bounded_blob(&vrk(), blob_context(), &mutated).err(),
            Some(expected)
        );
    }

    let mut zero_generation = original.clone();
    zero_generation[BLOB_GENERATION_OFFSET..BLOB_GENERATION_OFFSET + 8].fill(0);
    assert_eq!(
        decrypt_bounded_blob(&vrk(), blob_context(), &zero_generation).err(),
        Some(BoundedBlobError::InvalidGeneration)
    );

    let mut length_mismatch = original.clone();
    length_mismatch[BLOB_CIPHERTEXT_LENGTH_OFFSET + 3] ^= 1;
    assert_eq!(
        decrypt_bounded_blob(&vrk(), blob_context(), &length_mismatch).err(),
        Some(BoundedBlobError::LengthMismatch)
    );

    assert_eq!(
        decrypt_bounded_blob(&vrk(), blob_context(), &original[..original.len() - 1]).err(),
        Some(BoundedBlobError::TruncatedEnvelope)
    );
    let mut trailing = original;
    trailing.push(0);
    assert_eq!(
        decrypt_bounded_blob(&vrk(), blob_context(), &trailing).err(),
        Some(BoundedBlobError::TrailingData)
    );
}

#[test]
fn bounded_blob_wrong_key_tamper_and_transplants_fail_closed() {
    let original = blob_envelope();
    let wrong_key = OwnedKeyMaterial::from_bytes([0xa5; 32]);
    assert_eq!(
        decrypt_bounded_blob(&wrong_key, blob_context(), &original).err(),
        Some(BoundedBlobError::AuthenticationFailed)
    );

    for offset in [
        BLOB_NONCE_OFFSET,
        BOUNDED_BLOB_HEADER_BYTES,
        original.len() - 1,
    ] {
        let mut mutated = original.clone();
        mutated[offset] ^= 0x80;
        assert_eq!(
            decrypt_bounded_blob(&vrk(), blob_context(), &mutated).err(),
            Some(BoundedBlobError::AuthenticationFailed)
        );
    }

    for offset in [
        BLOB_VAULT_OFFSET,
        BLOB_ARTIFACT_OFFSET,
        BLOB_GENERATION_OFFSET + 7,
    ] {
        let mut mutated = original.clone();
        mutated[offset] ^= 1;
        assert_eq!(
            decrypt_bounded_blob(&vrk(), blob_context(), &mutated).err(),
            Some(BoundedBlobError::ContextMismatch)
        );
    }

    let other_vault = BoundedBlobContext::new(
        VaultId::from_bytes([0x99; 16]),
        BLOB_ARTIFACT,
        generation(BLOB_GENERATION),
    );
    let other_artifact = BoundedBlobContext::new(
        VaultId::from_bytes(BLOB_VAULT),
        [0x88; 16],
        generation(BLOB_GENERATION),
    );
    let other_generation = BoundedBlobContext::new(
        VaultId::from_bytes(BLOB_VAULT),
        BLOB_ARTIFACT,
        generation(BLOB_GENERATION + 1),
    );
    for expected in [other_vault, other_artifact, other_generation] {
        assert_eq!(
            decrypt_bounded_blob(&vrk(), expected, &original).err(),
            Some(BoundedBlobError::ContextMismatch)
        );
    }
}

#[test]
fn bounded_blob_zero_max_max_plus_one_and_overflow_sized_lengths_are_safe() {
    let empty = encrypt_bounded_blob(&vrk(), blob_context(), [0_u8; 24], b"")
        .expect("zero-length plaintext is canonical");
    assert_eq!(empty.len(), BOUNDED_BLOB_MIN_ENVELOPE_BYTES);
    assert!(
        decrypt_bounded_blob(&vrk(), blob_context(), &empty)
            .expect("zero-length envelope must authenticate")
            .is_empty()
    );

    assert_eq!(
        BOUNDED_BLOB_MAX_ENVELOPE_BYTES,
        BOUNDED_BLOB_HEADER_BYTES + BOUNDED_BLOB_MAX_PLAINTEXT_BYTES + 16
    );

    let original = blob_envelope();
    let mut exact_max_header = original.clone();
    exact_max_header[BLOB_PLAINTEXT_LENGTH_OFFSET..BLOB_PLAINTEXT_LENGTH_OFFSET + 8]
        .copy_from_slice(&(BOUNDED_BLOB_MAX_PLAINTEXT_BYTES as u64).to_be_bytes());
    exact_max_header[BLOB_CIPHERTEXT_LENGTH_OFFSET..BLOB_CIPHERTEXT_LENGTH_OFFSET + 4]
        .copy_from_slice(&((BOUNDED_BLOB_MAX_PLAINTEXT_BYTES as u32) + 16).to_be_bytes());
    assert_eq!(
        decrypt_bounded_blob(&vrk(), blob_context(), &exact_max_header).err(),
        Some(BoundedBlobError::TruncatedEnvelope),
        "exact maximum public lengths must pass bounds arithmetic and then require the exact body without allocating it"
    );

    for rejected_length in [(BOUNDED_BLOB_MAX_PLAINTEXT_BYTES as u64) + 1, u64::MAX] {
        let mut oversized = original.clone();
        oversized[BLOB_PLAINTEXT_LENGTH_OFFSET..BLOB_PLAINTEXT_LENGTH_OFFSET + 8]
            .copy_from_slice(&rejected_length.to_be_bytes());
        assert_eq!(
            decrypt_bounded_blob(&vrk(), blob_context(), &oversized).err(),
            Some(BoundedBlobError::PlaintextTooLarge),
            "maximum-plus-one and overflow-sized public lengths must fail before allocation"
        );
    }
}

#[test]
fn recovery_structure_policy_and_kdf_parameters_fail_before_authentication() {
    let original = from_hex(RECOVERY_ENVELOPE_HEX);
    assert_eq!(original.len(), RECOVERY_ENVELOPE_BYTES);

    for (offset, expected) in [
        (0, RecoveryEnvelopeError::InvalidDomain),
        (
            RECOVERY_VERSION_OFFSET + 1,
            RecoveryEnvelopeError::UnsupportedVersion,
        ),
        (
            RECOVERY_TYPE_OFFSET + 1,
            RecoveryEnvelopeError::UnsupportedEnvelopeType,
        ),
        (
            RECOVERY_SUITE_OFFSET + 1,
            RecoveryEnvelopeError::UnsupportedCipherSuite,
        ),
        (
            RECOVERY_POLICY_OFFSET + 1,
            RecoveryEnvelopeError::InvalidRecoveryPolicy,
        ),
        (
            RECOVERY_ARGON_VERSION_OFFSET + 1,
            RecoveryEnvelopeError::InvalidArgon2Parameters,
        ),
        (
            RECOVERY_PASSES_OFFSET + 3,
            RecoveryEnvelopeError::InvalidArgon2Parameters,
        ),
        (
            RECOVERY_PARALLELISM_OFFSET + 1,
            RecoveryEnvelopeError::InvalidArgon2Parameters,
        ),
        (
            RECOVERY_OUTPUT_OFFSET + 1,
            RecoveryEnvelopeError::InvalidArgon2Parameters,
        ),
    ] {
        let mut mutated = original.clone();
        mutated[offset] ^= 1;
        assert_eq!(
            decrypt_recovery_envelope(recovery_context(), RECOVERY_PASSPHRASE, &mutated).err(),
            Some(expected)
        );
    }

    for memory_kib in [65_535_u32, 65_537_u32] {
        let mut noncanonical = original.clone();
        noncanonical[RECOVERY_MEMORY_OFFSET..RECOVERY_MEMORY_OFFSET + 4]
            .copy_from_slice(&memory_kib.to_be_bytes());
        assert_eq!(
            decrypt_recovery_envelope(recovery_context(), RECOVERY_PASSPHRASE, &noncanonical).err(),
            Some(RecoveryEnvelopeError::InvalidArgon2Parameters),
            "weaker and larger recovery profiles must both fail before KDF allocation"
        );
    }

    let mut zero_generation = original.clone();
    zero_generation[RECOVERY_GENERATION_OFFSET..RECOVERY_GENERATION_OFFSET + 8].fill(0);
    assert_eq!(
        decrypt_recovery_envelope(recovery_context(), RECOVERY_PASSPHRASE, &zero_generation).err(),
        Some(RecoveryEnvelopeError::InvalidGeneration)
    );

    let mut bad_length = original.clone();
    bad_length[RECOVERY_CIPHERTEXT_LENGTH_OFFSET + 3] ^= 1;
    assert_eq!(
        decrypt_recovery_envelope(recovery_context(), RECOVERY_PASSPHRASE, &bad_length).err(),
        Some(RecoveryEnvelopeError::LengthMismatch)
    );

    assert_eq!(
        decrypt_recovery_envelope(
            recovery_context(),
            RECOVERY_PASSPHRASE,
            &original[..RECOVERY_ENVELOPE_BYTES - 1],
        )
        .err(),
        Some(RecoveryEnvelopeError::TruncatedEnvelope)
    );
    let mut trailing = original;
    trailing.push(0);
    assert_eq!(
        decrypt_recovery_envelope(recovery_context(), RECOVERY_PASSPHRASE, &trailing).err(),
        Some(RecoveryEnvelopeError::TrailingData)
    );
}

#[test]
fn recovery_wrong_passphrase_aad_inputs_ciphertext_tag_and_transplants_fail_uniformly() {
    let original = from_hex(RECOVERY_ENVELOPE_HEX);
    assert_eq!(
        decrypt_recovery_envelope(recovery_context(), "wrong horse battery staple", &original)
            .err(),
        Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
    );

    for offset in [
        RECOVERY_SALT_OFFSET,
        RECOVERY_NONCE_OFFSET,
        RECOVERY_VAULT_OFFSET,
        RECOVERY_GENERATION_OFFSET + 7,
        RECOVERY_CIPHERTEXT_OFFSET,
        RECOVERY_ENVELOPE_BYTES - 1,
    ] {
        let mut mutated = original.clone();
        mutated[offset] ^= 1;
        assert_recovery_authentication_failed(&mutated, recovery_context());
    }

    let other_vault = RecoveryContext::new(
        VaultId::from_bytes([0x99; 16]),
        generation(RECOVERY_GENERATION),
    );
    let other_generation = RecoveryContext::new(
        VaultId::from_bytes(RECOVERY_VAULT),
        generation(RECOVERY_GENERATION + 1),
    );
    for expected in [other_vault, other_generation] {
        assert_recovery_authentication_failed(&original, expected);
    }
}

#[test]
fn nonce_inventory_duplicate_is_corrupt_or_tampered() {
    let vault_id = VaultId::from_bytes(BLOB_VAULT);
    let reservation = NonceReservation::new(
        vault_id,
        NoncePurpose::BoundedBlob,
        generation(BLOB_GENERATION),
        BLOB_NONCE,
    );
    assert_eq!(
        NonceReservationLedger::from_authenticated_canonical_reservations(
            vault_id,
            [reservation, reservation],
        )
        .err(),
        Some(NonceLifecycleError::CorruptOrTampered)
    );
}

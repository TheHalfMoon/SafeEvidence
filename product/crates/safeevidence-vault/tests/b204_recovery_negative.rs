//! B204-local negative evidence for the canonical recovery-envelope contract.
//!
//! These cases deliberately stay inside the B204 recovery boundary. Aggregate
//! Specification 004 negative-crypto qualification remains B205.

use safeevidence_vault::vault::{KeyGeneration, VaultId};
use safeevidence_vault::vault_recovery::{
    RECOVERY_ENVELOPE_BYTES, RecoveryContext, RecoveryEnvelopeError, decrypt_recovery_envelope,
};

const TEST_VAULT_ID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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

// Independent fixed vector using exactly sixteen composed U+00E9 scalar values.
// It shares the reviewed public context/salt/nonce but has independently derived
// Argon2id/XChaCha20-Poly1305 ciphertext for the exact composed UTF-8 bytes.
const COMPOSED_UNICODE_ENVELOPE_HEX: &str = concat!(
    "001b48494d5341542f5245434f564552592f454e56454c4f50452f7631",
    "0001000100010001101112131415161718191a1b1c1d1e1f0102030405060708",
    "0013000100000000000300040020202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f404142434445464700000030",
    "92bf72e68c7b9465fbce4bd43fc3f36902657495e40b18de264df964357797b0",
    "43e820e3f2b0335512788ba2390e26bd"
);

const VAULT_ID_OFFSET: usize = 37;
const KEY_GENERATION_OFFSET: usize = 53;
const SALT_OFFSET: usize = 75;
const NONCE_OFFSET: usize = 91;
const CIPHERTEXT_OFFSET: usize = 119;

fn context() -> RecoveryContext {
    RecoveryContext::new(
        VaultId::from_bytes(TEST_VAULT_ID),
        KeyGeneration::new(TEST_GENERATION).expect("fixture generation is non-zero"),
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

fn assert_authentication_failed(passphrase: &str, envelope: &[u8], expected: RecoveryContext) {
    assert_eq!(
        decrypt_recovery_envelope(expected, passphrase, envelope).err(),
        Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
    );
}

#[test]
fn salt_nonce_generation_ciphertext_and_tag_tamper_fail_uniformly() {
    let original = from_hex(EXPECTED_ENVELOPE_HEX);
    assert_eq!(original.len(), RECOVERY_ENVELOPE_BYTES);

    for offset in [
        SALT_OFFSET,
        NONCE_OFFSET,
        KEY_GENERATION_OFFSET + 7,
        CIPHERTEXT_OFFSET,
        RECOVERY_ENVELOPE_BYTES - 1,
    ] {
        let mut tampered = original.clone();
        tampered[offset] ^= 1;
        assert_authentication_failed(TEST_PASSPHRASE, &tampered, context());
    }

    let mut tampered_vault = original;
    tampered_vault[VAULT_ID_OFFSET] ^= 1;
    assert_authentication_failed(TEST_PASSPHRASE, &tampered_vault, context());
}

#[test]
fn cross_vault_and_cross_generation_transplants_fail_uniformly() {
    let original = from_hex(EXPECTED_ENVELOPE_HEX);

    let other_vault = RecoveryContext::new(
        VaultId::from_bytes([0x99; 16]),
        KeyGeneration::new(TEST_GENERATION).expect("fixture generation is non-zero"),
    );
    assert_authentication_failed(TEST_PASSPHRASE, &original, other_vault);

    let other_generation = RecoveryContext::new(
        VaultId::from_bytes(TEST_VAULT_ID),
        KeyGeneration::new(TEST_GENERATION + 1).expect("fixture generation is non-zero"),
    );
    assert_authentication_failed(TEST_PASSPHRASE, &original, other_generation);
}

#[test]
fn passphrase_uses_exact_utf8_without_trim_casefold_truncation_or_normalization() {
    let original = from_hex(EXPECTED_ENVELOPE_HEX);
    assert!(decrypt_recovery_envelope(context(), TEST_PASSPHRASE, &original).is_ok());

    assert_authentication_failed("correct horse battery staple ", &original, context());
    assert_authentication_failed("Correct horse battery staple", &original, context());
    assert_authentication_failed(
        "correct horse battery staple ignored suffix",
        &original,
        context(),
    );

    let unicode_envelope = from_hex(COMPOSED_UNICODE_ENVELOPE_HEX);
    let composed = "é".repeat(16);
    let decomposed = "e\u{301}".repeat(16);
    assert_ne!(composed.as_bytes(), decomposed.as_bytes());
    assert!(decrypt_recovery_envelope(context(), &composed, &unicode_envelope).is_ok());
    assert_authentication_failed(&decomposed, &unicode_envelope, context());
}

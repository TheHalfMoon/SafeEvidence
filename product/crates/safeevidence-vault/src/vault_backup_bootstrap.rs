use crate::vault::{KeyGeneration, VaultId};
use crate::vault_backup::{
    BACKUP_BOOTSTRAP_SLOT_BYTES, BACKUP_NONCE_BYTES, BackupSetDescriptor, BackupSetId,
};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use crate::vault_recovery::{
    RECOVERY_ENVELOPE_BYTES, RECOVERY_PASSPHRASE_MAX_UTF8_BYTES,
    RECOVERY_PASSPHRASE_MIN_UNICODE_SCALARS, RECOVERY_SALT_BYTES, RecoveryContext,
    RecoveryEnvelopeError, decrypt_recovery_envelope,
};
use argon2::{Algorithm, Argon2, Error as Argon2Error, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use zeroize::Zeroize;

const BOOTSTRAP_KEY_DOMAIN: &[u8] = b"HIMSAT/004/BACKUP-BOOTSTRAP/v1";
const BOOTSTRAP_AAD_DOMAIN_PREFIX: &[u8] = b"\x00\x1eHIMSAT/BACKUP/BOOTSTRAP/AAD/v1";
const BOOTSTRAP_AAD_BYTES: usize = 120;
const SET_FORMAT_VERSION: u16 = 1;
const XCHACHA20_POLY1305_SUITE: u16 = 1;
const RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1: u16 = 1;
const ARGON2_VERSION: u16 = 0x0013;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_PASSES: u32 = 3;
const ARGON2_PARALLELISM: u16 = 4;
const KDF_OUTPUT_BYTES: u16 = 32;
const RECOVERY_VAULT_ID_OFFSET: usize = 37;
const RECOVERY_GENERATION_OFFSET: usize = 53;
const RECOVERY_SALT_OFFSET: usize = 75;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupBootstrapError {
    CorruptOrTampered,
    RecoveryAuthenticationFailed,
    ResourceLimit,
    KdfFailed,
    RandomnessUnavailable,
    EncryptionFailed,
}

impl fmt::Display for BackupBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CorruptOrTampered => "portable backup bootstrap is corrupt or tampered",
            Self::RecoveryAuthenticationFailed => "recovery authentication failed",
            Self::ResourceLimit => "recovery KDF resource limit prevents the fixed v1 profile",
            Self::KdfFailed => "recovery KDF operation failed",
            Self::RandomnessUnavailable => "approved OS-CSPRNG backup randomness failed",
            Self::EncryptionFailed => "portable backup bootstrap encryption failed",
        };
        f.write_str(message)
    }
}

impl Error for BackupBootstrapError {}

fn map_recovery_error(error: RecoveryEnvelopeError) -> BackupBootstrapError {
    match error {
        RecoveryEnvelopeError::RecoveryAuthenticationFailed
        | RecoveryEnvelopeError::PassphraseTooShort
        | RecoveryEnvelopeError::PassphraseTooLong => {
            BackupBootstrapError::RecoveryAuthenticationFailed
        }
        RecoveryEnvelopeError::ResourceLimit => BackupBootstrapError::ResourceLimit,
        RecoveryEnvelopeError::KdfFailed => BackupBootstrapError::KdfFailed,
        _ => BackupBootstrapError::CorruptOrTampered,
    }
}

fn key_material_equal(left: &OwnedKeyMaterial, right: &OwnedKeyMaterial) -> bool {
    left.with_bytes(|left_bytes| {
        right.with_bytes(|right_bytes| {
            left_bytes
                .iter()
                .zip(right_bytes.iter())
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0
        })
    })
}

fn map_argon2_error(error: Argon2Error) -> BackupBootstrapError {
    match error {
        Argon2Error::OutOfMemory => BackupBootstrapError::ResourceLimit,
        _ => BackupBootstrapError::KdfFailed,
    }
}

fn derive_recovery_kek(
    passphrase: &str,
    salt: &[u8; RECOVERY_SALT_BYTES],
) -> Result<OwnedKeyMaterial, BackupBootstrapError> {
    if passphrase.len() > RECOVERY_PASSPHRASE_MAX_UTF8_BYTES
        || passphrase.chars().count() < RECOVERY_PASSPHRASE_MIN_UNICODE_SCALARS
    {
        return Err(BackupBootstrapError::RecoveryAuthenticationFailed);
    }
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
    let key = OwnedKeyMaterial::from_bytes(output);
    output.zeroize();
    Ok(key)
}

fn derive_bootstrap_key(
    recovery_kek: &OwnedKeyMaterial,
    set_id: BackupSetId,
    generation: KeyGeneration,
) -> OwnedKeyMaterial {
    let mut info = Vec::with_capacity(BOOTSTRAP_KEY_DOMAIN.len() + 8);
    info.extend_from_slice(BOOTSTRAP_KEY_DOMAIN);
    info.extend_from_slice(&generation.get().to_be_bytes());
    let mut output = [0_u8; KEY_MATERIAL_BYTES];
    recovery_kek.with_bytes(|bytes| {
        let hkdf = Hkdf::<Sha256>::new(Some(set_id.as_bytes()), bytes);
        hkdf.expand(&info, &mut output)
            .expect("32-byte bootstrap HKDF output is within RFC 5869 limits");
    });
    OwnedKeyMaterial::from_bytes(output)
}

fn bootstrap_aad(
    set_id: BackupSetId,
    generation: KeyGeneration,
    salt: &[u8; RECOVERY_SALT_BYTES],
    nonce: &[u8; BACKUP_NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BOOTSTRAP_AAD_BYTES);
    aad.extend_from_slice(BOOTSTRAP_AAD_DOMAIN_PREFIX);
    aad.extend_from_slice(&SET_FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(set_id.as_bytes());
    aad.extend_from_slice(&generation.get().to_be_bytes());
    aad.extend_from_slice(&XCHACHA20_POLY1305_SUITE.to_be_bytes());
    aad.extend_from_slice(&RECOVERY_POLICY_ARGON2ID_RFC9106_64M_V1.to_be_bytes());
    aad.extend_from_slice(&ARGON2_VERSION.to_be_bytes());
    aad.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    aad.extend_from_slice(&ARGON2_PASSES.to_be_bytes());
    aad.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    aad.extend_from_slice(&KDF_OUTPUT_BYTES.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&(BACKUP_BOOTSTRAP_SLOT_BYTES as u32).to_be_bytes());
    debug_assert_eq!(aad.len(), BOOTSTRAP_AAD_BYTES);
    aad
}

fn recovery_public_context(
    envelope: &[u8],
) -> Result<(RecoveryContext, [u8; RECOVERY_SALT_BYTES]), BackupBootstrapError> {
    if envelope.len() != RECOVERY_ENVELOPE_BYTES {
        return Err(BackupBootstrapError::CorruptOrTampered);
    }
    let vault_bytes: [u8; 16] = envelope[RECOVERY_VAULT_ID_OFFSET..RECOVERY_VAULT_ID_OFFSET + 16]
        .try_into()
        .map_err(|_| BackupBootstrapError::CorruptOrTampered)?;
    let generation_bytes: [u8; 8] = envelope
        [RECOVERY_GENERATION_OFFSET..RECOVERY_GENERATION_OFFSET + 8]
        .try_into()
        .map_err(|_| BackupBootstrapError::CorruptOrTampered)?;
    let salt: [u8; RECOVERY_SALT_BYTES] = envelope
        [RECOVERY_SALT_OFFSET..RECOVERY_SALT_OFFSET + RECOVERY_SALT_BYTES]
        .try_into()
        .map_err(|_| BackupBootstrapError::CorruptOrTampered)?;
    let generation = KeyGeneration::new(u64::from_be_bytes(generation_bytes))
        .map_err(|_| BackupBootstrapError::CorruptOrTampered)?;
    Ok((
        RecoveryContext::new(VaultId::from_bytes(vault_bytes), generation),
        salt,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRecoveryBootstrap {
    context: RecoveryContext,
    set_id: BackupSetId,
    salt: [u8; RECOVERY_SALT_BYTES],
    nonce: [u8; BACKUP_NONCE_BYTES],
    slot: [u8; BACKUP_BOOTSTRAP_SLOT_BYTES],
}

impl BackupRecoveryBootstrap {
    #[must_use]
    pub const fn context(&self) -> RecoveryContext {
        self.context
    }

    #[must_use]
    pub const fn set_id(&self) -> BackupSetId {
        self.set_id
    }

    #[must_use]
    pub const fn salt(&self) -> &[u8; RECOVERY_SALT_BYTES] {
        &self.salt
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; BACKUP_NONCE_BYTES] {
        &self.nonce
    }

    #[must_use]
    pub const fn slot(&self) -> &[u8; BACKUP_BOOTSTRAP_SLOT_BYTES] {
        &self.slot
    }
}

fn create_with_nonce(
    active_vrk: &OwnedKeyMaterial,
    expected_context: RecoveryContext,
    recovery_envelope: &[u8],
    passphrase: &str,
    set_id: BackupSetId,
    nonce: [u8; BACKUP_NONCE_BYTES],
) -> Result<BackupRecoveryBootstrap, BackupBootstrapError> {
    let recovered = decrypt_recovery_envelope(expected_context, passphrase, recovery_envelope)
        .map_err(map_recovery_error)?;
    if !key_material_equal(active_vrk, &recovered) {
        return Err(BackupBootstrapError::CorruptOrTampered);
    }
    let (public_context, salt) = recovery_public_context(recovery_envelope)?;
    if public_context != expected_context {
        return Err(BackupBootstrapError::CorruptOrTampered);
    }
    let recovery_kek = derive_recovery_kek(passphrase, &salt)?;
    let key = derive_bootstrap_key(&recovery_kek, set_id, expected_context.key_generation());
    let aad = bootstrap_aad(set_id, expected_context.key_generation(), &salt, &nonce);
    let nonce_ref = <&XNonce>::try_from(nonce.as_slice())
        .expect("B505 bootstrap nonce is statically exactly 24 bytes");
    let ciphertext_and_tag = key
        .with_bytes(|bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(bytes)
                .expect("B505 bootstrap key is statically exactly 32 bytes");
            cipher.encrypt(
                nonce_ref,
                Payload {
                    msg: recovery_envelope,
                    aad: &aad,
                },
            )
        })
        .map_err(|_| BackupBootstrapError::EncryptionFailed)?;
    let slot: [u8; BACKUP_BOOTSTRAP_SLOT_BYTES] = ciphertext_and_tag
        .try_into()
        .map_err(|_| BackupBootstrapError::CorruptOrTampered)?;
    Ok(BackupRecoveryBootstrap {
        context: expected_context,
        set_id,
        salt,
        nonce,
        slot,
    })
}

pub fn create_backup_recovery_bootstrap(
    active_vrk: &OwnedKeyMaterial,
    expected_context: RecoveryContext,
    recovery_envelope: &[u8],
    passphrase: &str,
    set_id: BackupSetId,
) -> Result<BackupRecoveryBootstrap, BackupBootstrapError> {
    let mut nonce = [0_u8; BACKUP_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| BackupBootstrapError::RandomnessUnavailable)?;
    create_with_nonce(
        active_vrk,
        expected_context,
        recovery_envelope,
        passphrase,
        set_id,
        nonce,
    )
}

pub struct RecoveredBackupBootstrap {
    context: RecoveryContext,
    vrk: OwnedKeyMaterial,
}

impl RecoveredBackupBootstrap {
    #[must_use]
    pub const fn context(&self) -> RecoveryContext {
        self.context
    }

    pub fn into_vrk(self) -> OwnedKeyMaterial {
        self.vrk
    }
}

pub fn recover_backup_recovery_bootstrap(
    descriptor: &BackupSetDescriptor,
    passphrase: &str,
) -> Result<RecoveredBackupBootstrap, BackupBootstrapError> {
    let recovery_kek = derive_recovery_kek(passphrase, descriptor.bootstrap_salt())?;
    let key = derive_bootstrap_key(
        &recovery_kek,
        descriptor.set_id(),
        descriptor.key_generation(),
    );
    let aad = bootstrap_aad(
        descriptor.set_id(),
        descriptor.key_generation(),
        descriptor.bootstrap_salt(),
        descriptor.bootstrap_nonce(),
    );
    let nonce_ref = <&XNonce>::try_from(descriptor.bootstrap_nonce().as_slice())
        .expect("B505 bootstrap nonce is statically exactly 24 bytes");
    let mut plaintext = key
        .with_bytes(|bytes| {
            let cipher = XChaCha20Poly1305::new_from_slice(bytes)
                .expect("B505 bootstrap key is statically exactly 32 bytes");
            cipher.decrypt(
                nonce_ref,
                Payload {
                    msg: descriptor.bootstrap_slot(),
                    aad: &aad,
                },
            )
        })
        .map_err(|_| BackupBootstrapError::RecoveryAuthenticationFailed)?;
    if plaintext.len() != RECOVERY_ENVELOPE_BYTES {
        plaintext.zeroize();
        return Err(BackupBootstrapError::RecoveryAuthenticationFailed);
    }
    let (context, inner_salt) = recovery_public_context(&plaintext)?;
    if context.key_generation() != descriptor.key_generation()
        || inner_salt != *descriptor.bootstrap_salt()
    {
        plaintext.zeroize();
        return Err(BackupBootstrapError::CorruptOrTampered);
    }
    let recovered =
        decrypt_recovery_envelope(context, passphrase, &plaintext).map_err(map_recovery_error);
    plaintext.zeroize();
    let vrk = recovered?;
    Ok(RecoveredBackupBootstrap { context, vrk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_backup::BACKUP_INDEX_CIPHERTEXT_MIN;
    use crate::vault_recovery::encrypt_recovery_envelope;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn vrk(byte: u8) -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([byte; KEY_MATERIAL_BYTES])
    }

    fn context() -> RecoveryContext {
        RecoveryContext::new(
            VaultId::from_bytes([0x22; 16]),
            KeyGeneration::new(7).expect("non-zero"),
        )
    }

    fn set_id(byte: u8) -> BackupSetId {
        BackupSetId::from_bytes([byte; 16]).expect("non-zero")
    }

    fn descriptor(bootstrap: &BackupRecoveryBootstrap) -> BackupSetDescriptor {
        BackupSetDescriptor::new(
            bootstrap.set_id(),
            bootstrap.context().key_generation(),
            2,
            *bootstrap.salt(),
            *bootstrap.nonce(),
            *bootstrap.slot(),
            [0x44; BACKUP_NONCE_BYTES],
            vec![0x55; BACKUP_INDEX_CIPHERTEXT_MIN],
        )
        .expect("valid descriptor")
    }

    #[test]
    fn bootstrap_round_trip_preserves_canonical_recovery_identity() {
        let active = vrk(0x11);
        let envelope = encrypt_recovery_envelope(&active, context(), PASSPHRASE).unwrap();
        let bootstrap = create_with_nonce(
            &active,
            context(),
            &envelope,
            PASSPHRASE,
            set_id(0x33),
            [0x66; BACKUP_NONCE_BYTES],
        )
        .unwrap();
        let recovered = recover_backup_recovery_bootstrap(&descriptor(&bootstrap), PASSPHRASE)
            .expect("bootstrap authenticates");
        assert_eq!(recovered.context(), context());
        assert!(key_material_equal(&active, &recovered.into_vrk()));
    }

    #[test]
    fn active_vrk_mismatch_fails_before_bootstrap_publication() {
        let wrapped = vrk(0x11);
        let active = vrk(0x12);
        let envelope = encrypt_recovery_envelope(&wrapped, context(), PASSPHRASE).unwrap();
        assert_eq!(
            create_with_nonce(
                &active,
                context(),
                &envelope,
                PASSPHRASE,
                set_id(0x33),
                [0x66; BACKUP_NONCE_BYTES],
            )
            .err(),
            Some(BackupBootstrapError::CorruptOrTampered)
        );
    }

    #[test]
    fn wrong_passphrase_and_outer_tamper_are_uniform_authentication_failures() {
        let active = vrk(0x11);
        let envelope = encrypt_recovery_envelope(&active, context(), PASSPHRASE).unwrap();
        let bootstrap = create_with_nonce(
            &active,
            context(),
            &envelope,
            PASSPHRASE,
            set_id(0x33),
            [0x66; BACKUP_NONCE_BYTES],
        )
        .unwrap();
        let valid = descriptor(&bootstrap);
        assert_eq!(
            recover_backup_recovery_bootstrap(&valid, "wrong horse battery staple").err(),
            Some(BackupBootstrapError::RecoveryAuthenticationFailed)
        );
        let mut tampered_slot = *bootstrap.slot();
        tampered_slot[0] ^= 1;
        let tampered = BackupSetDescriptor::new(
            bootstrap.set_id(),
            bootstrap.context().key_generation(),
            2,
            *bootstrap.salt(),
            *bootstrap.nonce(),
            tampered_slot,
            [0x44; BACKUP_NONCE_BYTES],
            vec![0x55; BACKUP_INDEX_CIPHERTEXT_MIN],
        )
        .unwrap();
        assert_eq!(
            recover_backup_recovery_bootstrap(&tampered, PASSPHRASE).err(),
            Some(BackupBootstrapError::RecoveryAuthenticationFailed)
        );
    }

    #[test]
    fn cross_set_transplant_fails_outer_authentication() {
        let active = vrk(0x11);
        let envelope = encrypt_recovery_envelope(&active, context(), PASSPHRASE).unwrap();
        let bootstrap = create_with_nonce(
            &active,
            context(),
            &envelope,
            PASSPHRASE,
            set_id(0x33),
            [0x66; BACKUP_NONCE_BYTES],
        )
        .unwrap();
        let transplanted = BackupSetDescriptor::new(
            set_id(0x34),
            bootstrap.context().key_generation(),
            2,
            *bootstrap.salt(),
            *bootstrap.nonce(),
            *bootstrap.slot(),
            [0x44; BACKUP_NONCE_BYTES],
            vec![0x55; BACKUP_INDEX_CIPHERTEXT_MIN],
        )
        .unwrap();
        assert_eq!(
            recover_backup_recovery_bootstrap(&transplanted, PASSPHRASE).err(),
            Some(BackupBootstrapError::RecoveryAuthenticationFailed)
        );
    }
}

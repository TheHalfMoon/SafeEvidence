//! Cross-product cryptographic domain isolation evidence (`SAFEVD/*` vs donor `HIMSAT/*`).
//!
//! Verifies that SafeEvidence's `SAFEVD/` domain separators reject authentic donor `HIMSAT/`
//! envelopes, backup objects, protector records, and HKDF purpose keys fail-closed — both on
//! unmodified donor wire bytes (pre-KDF / pre-AEAD header rejection) and under header-forging
//! attacks where an adversary rewrites the outer magic from `HIMSAT` to `SAFEVD` while keeping
//! the donor ciphertext and authentication tag.

use std::cell::RefCell;

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use safeevidence_vault::VAULT_DOMAIN_VERSION;
use safeevidence_vault::vault::{
    AccessScope, FreshnessEpoch, HardwareBacking, KeyGeneration, ProtectorError, SecretProtector,
    UserPresencePolicy, VaultId,
};
use safeevidence_vault::vault_android_keystore::{
    AndroidKeystoreBackend, AndroidKeystoreConfig, AndroidKeystoreProtector, AndroidProtectorId,
};
use safeevidence_vault::vault_backup::{
    BACKUP_NONCE_BYTES, BackupCodecError, BackupObjectContext, BackupObjectId, BackupSetId,
    decrypt_backup_object, encrypt_backup_object,
};
use safeevidence_vault::vault_blob::{
    BoundedBlobContext, BoundedBlobError, decrypt_bounded_blob, encrypt_bounded_blob,
};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_manifest::{ManifestContext, ManifestError, decrypt_manifest};
use safeevidence_vault::vault_recovery::{
    RECOVERY_ENVELOPE_BYTES, RecoveryContext, RecoveryEnvelopeError, decrypt_recovery_envelope,
};
use sha2::Sha256;

const TEST_VRK: [u8; KEY_MATERIAL_BYTES] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TEST_VAULT_10_1F: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TEST_ARTIFACT_20_2F: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const TEST_GENERATION: u64 = 0x0102_0304_0506_0708;

/// Authentic donor B202 `HIMSAT/BLOB/ENVELOPE/v1` vector.
const DONOR_HIMSAT_BLOB_HEX: &str = concat!(
    "001748494d5341542f424c4f422f454e56454c4f50452f7631000100010001",
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    "01020304050607080000000000000022303132333435363738393a3b3c3d3e3f",
    "404142434445464700000032c7843b7408030132c75d7c63f57de88c7242b260",
    "4323f8a62d421303bebc1e916629260df869a0aee3be3d5ef416ffc8bc14"
);

/// Authentic donor B501A `HIMSAT/MANIFEST/ENVELOPE/v1` vector (SHA-256 `6496d117...d261d944`).
const DONOR_HIMSAT_MANIFEST_HEX: &str = concat!(
    "001b48494d5341542f4d414e49464553542f454e56454c4f50452f763100010001",
    "1111111111111111111111111111111100000000000000010000000000000001",
    "555555555555555555555555555555555555555555555555000000de",
    "da1f7064dc2932faacc0cee064dd9a85ab51da43f1102fa453de63581f9e6689",
    "cddc991164213863f63fe960f955a27336d5b31dd6c3b5ae25bb677e6b9d4602",
    "2a2ce54dc42d3a7700b619aac3714cce359b5e35917d5f6c92fdbb5fb8e21d1e",
    "3e7e418001b031ab0f3a785396ad813a0e273aed862452b7d156245d049250b0",
    "45fad329801579f8484d24e89866ff84a4f011373639d5b18df936a3cb5b0163",
    "6f6bc6a929a1b96ca59fbe54684ceaf3b15ac9496d01d12004d099806033a7a1",
    "85f1aeaf3e6667eb9e99b6b02988fb8d0d5c128433ca71f0882ee3980e4b"
);

/// Authentic donor B204 `HIMSAT/RECOVERY/ENVELOPE/v1` ASCII vector.
const DONOR_HIMSAT_RECOVERY_ASCII_HEX: &str = concat!(
    "001b48494d5341542f5245434f564552592f454e56454c4f50452f7631",
    "0001000100010001101112131415161718191a1b1c1d1e1f0102030405060708",
    "0013000100000000000300040020202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f404142434445464700000030",
    "b02c2407d35111ecf0b5d6ff684fd202aee35ad65c5deca3a699a724e10b97d5",
    "7f43297abcd8ee04f5a695f7859de146"
);

/// Authentic donor B204 `HIMSAT/RECOVERY/ENVELOPE/v1` composed-Unicode vector.
const DONOR_HIMSAT_RECOVERY_UNICODE_HEX: &str = concat!(
    "001b48494d5341542f5245434f564552592f454e56454c4f50452f7631",
    "0001000100010001101112131415161718191a1b1c1d1e1f0102030405060708",
    "0013000100000000000300040020202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f404142434445464700000030",
    "92bf72e68c7b9465fbce4bd43fc3f36902657495e40b18de264df964357797b0",
    "43e820e3f2b0335512788ba2390e26bd"
);

fn from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).expect("valid hex");
            let low = char::from(pair[1]).to_digit(16).expect("valid hex");
            u8::try_from((high << 4) | low).expect("byte")
        })
        .collect()
}

#[test]
fn purpose_hkdf_info_prefixes_are_disjoint_from_donor_domains() {
    assert_eq!(VAULT_DOMAIN_VERSION, "SAFEVD-v1");
    let vault_id = VaultId::from_bytes(std::array::from_fn(|idx| idx as u8));
    let generation = KeyGeneration::new(TEST_GENERATION).expect("generation");

    for (purpose, donor_prefix) in [
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
    ] {
        let context = KeyDerivationContext::new(vault_id, generation, purpose);
        let info = context.hkdf_info();
        assert!(info.starts_with(b"SAFEVD/"));
        assert!(!info.starts_with(donor_prefix));
        assert!(!info.windows(6).any(|w| w == b"HIMSAT"));
    }
}

#[test]
fn donor_bounded_blob_and_forged_header_fail_closed() {
    let vrk = OwnedKeyMaterial::from_bytes(TEST_VRK);
    let context = BoundedBlobContext::new(
        VaultId::from_bytes(TEST_VAULT_10_1F),
        TEST_ARTIFACT_20_2F,
        KeyGeneration::new(TEST_GENERATION).expect("generation"),
    );
    let donor = from_hex(DONOR_HIMSAT_BLOB_HEX);
    assert_eq!(&donor[2..8], b"HIMSAT");
    assert_eq!(
        decrypt_bounded_blob(&vrk, context, &donor),
        Err(BoundedBlobError::InvalidDomain)
    );

    let mut forged = donor;
    forged[2..8].copy_from_slice(b"SAFEVD");
    assert_eq!(
        decrypt_bounded_blob(&vrk, context, &forged),
        Err(BoundedBlobError::AuthenticationFailed)
    );
}

#[test]
fn donor_manifest_and_forged_header_fail_closed() {
    let vrk = OwnedKeyMaterial::from_bytes([0x22; KEY_MATERIAL_BYTES]);
    let context = ManifestContext::new(
        VaultId::from_bytes([0x11; 16]),
        KeyGeneration::new(1).expect("generation"),
        FreshnessEpoch::new(1).expect("epoch"),
    );
    let donor = from_hex(DONOR_HIMSAT_MANIFEST_HEX);
    assert_eq!(&donor[2..8], b"HIMSAT");
    assert_eq!(
        decrypt_manifest(&vrk, context, &donor),
        Err(ManifestError::InvalidDomain)
    );

    let mut forged = donor;
    forged[2..8].copy_from_slice(b"SAFEVD");
    assert_eq!(
        decrypt_manifest(&vrk, context, &forged),
        Err(ManifestError::AuthenticationFailed)
    );
}

#[test]
fn donor_recovery_envelopes_reject_same_passphrase_even_with_forged_header() {
    let context = RecoveryContext::new(
        VaultId::from_bytes(TEST_VAULT_10_1F),
        KeyGeneration::new(TEST_GENERATION).expect("generation"),
    );
    let unicode_passphrase = "\u{00e9}".repeat(16);

    for (hex, passphrase) in [
        (
            DONOR_HIMSAT_RECOVERY_ASCII_HEX,
            "correct horse battery staple",
        ),
        (
            DONOR_HIMSAT_RECOVERY_UNICODE_HEX,
            unicode_passphrase.as_str(),
        ),
    ] {
        let donor = from_hex(hex);
        assert_eq!(donor.len(), RECOVERY_ENVELOPE_BYTES);
        assert_eq!(&donor[2..8], b"HIMSAT");
        // Rejected at structural domain parse before Argon2id runs.
        assert_eq!(
            decrypt_recovery_envelope(context, passphrase, &donor).err(),
            Some(RecoveryEnvelopeError::InvalidDomain)
        );

        // Even if an attacker patches the outer header to SAFEVD, Poly1305 AAD binding rejects it.
        let mut forged = donor;
        forged[2..8].copy_from_slice(b"SAFEVD");
        assert_eq!(
            decrypt_recovery_envelope(context, passphrase, &forged).err(),
            Some(RecoveryEnvelopeError::RecoveryAuthenticationFailed)
        );
    }
}

#[test]
fn donor_backup_object_and_forged_header_fail_closed() {
    let vrk = OwnedKeyMaterial::from_bytes(TEST_VRK);
    let vault_id = VaultId::from_bytes(TEST_VAULT_10_1F);
    let set_id = BackupSetId::from_bytes([0x51; 16]).expect("set id");
    let object_id = BackupObjectId::from_bytes([0x61; 16]).expect("object id");
    let generation = KeyGeneration::new(3).expect("generation");
    let context = BackupObjectContext {
        set_id,
        object_id,
        key_generation: generation,
    };
    let plaintext = b"SafeEvidence portable backup chunk";

    let valid = encrypt_backup_object(&vrk, vault_id, context, plaintext).expect("encrypt");
    assert_eq!(&valid[2..8], b"SAFEVD");
    assert_eq!(
        decrypt_backup_object(&vrk, vault_id, context, &valid).expect("decrypt"),
        plaintext
    );

    // Construct an authentic donor HIMSAT/004/BACKUP-OBJECT/v1 + HIMSAT/BACKUP/OBJECT/AAD/v1 object.
    let nonce = [0x44_u8; BACKUP_NONCE_BYTES];
    let pt_len = u32::try_from(plaintext.len()).expect("u32");
    let ct_len = pt_len + 16;
    let mut donor_aad = Vec::new();
    donor_aad.extend_from_slice(b"\x00\x1bHIMSAT/BACKUP/OBJECT/AAD/v1");
    donor_aad.extend_from_slice(&1_u16.to_be_bytes());
    donor_aad.extend_from_slice(set_id.as_bytes());
    donor_aad.extend_from_slice(object_id.as_bytes());
    donor_aad.extend_from_slice(&generation.get().to_be_bytes());
    donor_aad.extend_from_slice(&pt_len.to_be_bytes());
    donor_aad.extend_from_slice(&nonce);
    donor_aad.extend_from_slice(&ct_len.to_be_bytes());

    let mut donor_info = Vec::new();
    donor_info.extend_from_slice(b"HIMSAT/004/BACKUP-OBJECT/v1");
    donor_info.extend_from_slice(&generation.get().to_be_bytes());
    donor_info.extend_from_slice(set_id.as_bytes());
    let mut donor_key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), &TEST_VRK)
        .expand(&donor_info, &mut donor_key)
        .expect("hkdf");
    let donor_ct = XChaCha20Poly1305::new_from_slice(&donor_key)
        .expect("key")
        .encrypt(
            <&XNonce>::try_from(nonce.as_slice()).expect("nonce"),
            Payload {
                msg: plaintext,
                aad: &donor_aad,
            },
        )
        .expect("encrypt donor");

    let mut donor_env = Vec::new();
    donor_env.extend_from_slice(b"\x00\x20HIMSAT/BACKUP/OBJECT/ENVELOPE/v1");
    donor_env.extend_from_slice(&1_u16.to_be_bytes());
    donor_env.extend_from_slice(set_id.as_bytes());
    donor_env.extend_from_slice(object_id.as_bytes());
    donor_env.extend_from_slice(&generation.get().to_be_bytes());
    donor_env.extend_from_slice(&pt_len.to_be_bytes());
    donor_env.extend_from_slice(&nonce);
    donor_env.extend_from_slice(&ct_len.to_be_bytes());
    donor_env.extend_from_slice(&donor_ct);

    assert_eq!(
        decrypt_backup_object(&vrk, vault_id, context, &donor_env),
        Err(BackupCodecError::CorruptOrTampered)
    );

    let mut forged = donor_env;
    forged[2..8].copy_from_slice(b"SAFEVD");
    assert_eq!(
        decrypt_backup_object(&vrk, vault_id, context, &forged),
        Err(BackupCodecError::CorruptOrTampered)
    );
}

struct MemoryAndroidBackend {
    key_created: RefCell<bool>,
    record: RefCell<Option<Vec<u8>>>,
}

impl MemoryAndroidBackend {
    fn new() -> Self {
        Self {
            key_created: RefCell::new(false),
            record: RefCell::new(None),
        }
    }
}

impl AndroidKeystoreBackend for MemoryAndroidBackend {
    fn verify_environment(&self, _expected_package: &str) -> Result<(), ProtectorError> {
        Ok(())
    }

    fn create_key(&self, _alias: &str) -> Result<HardwareBacking, ProtectorError> {
        *self.key_created.borrow_mut() = true;
        Ok(HardwareBacking::HardwareBacked)
    }

    fn inspect_key(&self, _alias: &str) -> Result<HardwareBacking, ProtectorError> {
        if *self.key_created.borrow() {
            Ok(HardwareBacking::HardwareBacked)
        } else {
            Err(ProtectorError::ItemMissing)
        }
    }

    fn seal(&self, _alias: &str, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, _alias: &str, ciphertext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Ok(ciphertext.to_vec())
    }

    fn read_record(&self, _record_name: &str) -> Result<Vec<u8>, ProtectorError> {
        self.record
            .borrow()
            .clone()
            .ok_or(ProtectorError::ItemMissing)
    }

    fn write_record(&self, _record_name: &str, ciphertext: &[u8]) -> Result<(), ProtectorError> {
        *self.record.borrow_mut() = Some(ciphertext.to_vec());
        Ok(())
    }

    fn delete_record(&self, _record_name: &str) -> Result<(), ProtectorError> {
        *self.record.borrow_mut() = None;
        Ok(())
    }

    fn delete_key(&self, _alias: &str) -> Result<(), ProtectorError> {
        *self.key_created.borrow_mut() = false;
        Ok(())
    }
}

#[test]
fn android_keystore_protector_rejects_donor_record_magic() {
    let vault_id = VaultId::from_bytes(TEST_VAULT_10_1F);
    let generation = KeyGeneration::new(1).expect("generation");
    let vrk = OwnedKeyMaterial::from_bytes(TEST_VRK);
    let config = AndroidKeystoreConfig::from_persisted_id(
        "com.thehalfmoon.safeevidence",
        AndroidProtectorId::from_bytes([0xab; 16]),
    )
    .expect("config");

    let backend = MemoryAndroidBackend::new();
    let mut protector = AndroidKeystoreProtector::new(config.clone(), backend).expect("protector");
    protector
        .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
        .expect("create");
    protector
        .protect_or_store_vrk(vault_id, generation, &vrk)
        .expect("store");
    let unlocked = protector.unlock_vrk(vault_id, generation).expect("unlock");
    let blob_ctx = BoundedBlobContext::new(vault_id, TEST_ARTIFACT_20_2F, generation);
    let sealed_blob = encrypt_bounded_blob(&vrk, blob_ctx, [0x11; 24], b"vrk-equality-probe")
        .expect("encrypt probe");
    assert_eq!(
        decrypt_bounded_blob(&unlocked, blob_ctx, &sealed_blob).expect("same vrk decrypts"),
        b"vrk-equality-probe"
    );

    // Build an authentic donor HIMSAT/ANDROID/VRK/v1\0 record of identical length.
    let mut donor_record = Vec::new();
    donor_record.extend_from_slice(b"HIMSAT/ANDROID/VRK/v1\0");
    donor_record.extend_from_slice(vault_id.as_bytes());
    donor_record.extend_from_slice(&generation.get().to_be_bytes());
    donor_record.push(1); // AppExclusive
    donor_record.push(1); // NotRequired
    donor_record.extend_from_slice(&TEST_VRK);

    let donor_backend = MemoryAndroidBackend {
        key_created: RefCell::new(true),
        record: RefCell::new(Some(donor_record)),
    };
    let mut donor_protector =
        AndroidKeystoreProtector::new(config, donor_backend).expect("protector");
    donor_protector
        .create_protector(AccessScope::AppExclusive, UserPresencePolicy::NotRequired)
        .expect("create");
    assert_eq!(
        donor_protector.unlock_vrk(vault_id, generation).err(),
        Some(ProtectorError::CorruptOrTampered)
    );
}

#[cfg(target_os = "windows")]
mod windows_dpapi_isolation {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use safeevidence_vault::vault::{
        AccessScope, KeyGeneration, ProtectorError, SecretProtector, UserPresencePolicy, VaultId,
    };
    use safeevidence_vault::vault_blob::{
        BoundedBlobContext, decrypt_bounded_blob, encrypt_bounded_blob,
    };
    use safeevidence_vault::vault_keys::OwnedKeyMaterial;
    use safeevidence_vault::vault_windows_dpapi::{
        WindowsDpapiConfig, WindowsDpapiProtector, WindowsProtectorId,
    };
    use windows_dpapi::{Scope, encrypt_data};

    use super::{TEST_ARTIFACT_20_2F, TEST_VAULT_10_1F, TEST_VRK};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn windows_dpapi_rejects_donor_entropy_magic_and_owner_tag_under_same_user() {
        let id_num = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("se-dpapi-domain-{}-{id_num}", std::process::id()));
        let dpapi_dir = root.join("dpapi");
        let protector_bytes = [0x3c_u8; 16];
        let protector_id = WindowsProtectorId::from_bytes(protector_bytes);
        let vault_id = VaultId::from_bytes(TEST_VAULT_10_1F);
        let generation = KeyGeneration::new(1).expect("generation");
        let vrk = OwnedKeyMaterial::from_bytes(TEST_VRK);

        let config = WindowsDpapiConfig::new(&dpapi_dir, protector_id).expect("config");
        let mut protector = WindowsDpapiProtector::new(config);
        protector
            .create_protector(
                AccessScope::SameUserAccount,
                UserPresencePolicy::NotRequired,
            )
            .expect("create");
        protector
            .protect_or_store_vrk(vault_id, generation, &vrk)
            .expect("protect");
        let unlocked = protector
            .unlock_vrk(vault_id, generation)
            .expect("unlock SAFEVD");
        let blob_ctx = BoundedBlobContext::new(vault_id, TEST_ARTIFACT_20_2F, generation);
        let sealed_blob = encrypt_bounded_blob(&vrk, blob_ctx, [0x22; 24], b"dpapi-vrk-probe")
            .expect("encrypt probe");
        assert_eq!(
            decrypt_bounded_blob(&unlocked, blob_ctx, &sealed_blob).expect("same vrk decrypts"),
            b"dpapi-vrk-probe"
        );

        let record_path = dpapi_dir.join(protector_id.file_name());

        // Case 1: Donor HIMSAT entropy + donor HIMSAT record under the exact same Windows user & protector ID.
        let mut donor_entropy = b"HIMSAT/WINDOWS/DPAPI/ENTROPY/v1\0".to_vec();
        donor_entropy.extend_from_slice(&protector_bytes);
        let mut donor_record = Vec::new();
        donor_record.extend_from_slice(b"HIMSAT/WINDOWS/DPAPI/VRK/v1\0");
        donor_record.extend_from_slice(b"HIMSAT/APP/v1\0");
        donor_record.extend_from_slice(vault_id.as_bytes());
        donor_record.extend_from_slice(&generation.get().to_be_bytes());
        donor_record.push(2); // SameUserAccount
        donor_record.push(1); // NotRequired
        donor_record.extend_from_slice(&TEST_VRK);
        let donor_ct =
            encrypt_data(&donor_record, Scope::User, Some(&donor_entropy)).expect("dpapi encrypt");
        fs::write(&record_path, &donor_ct).expect("write donor ciphertext");
        assert_eq!(
            protector.unlock_vrk(vault_id, generation).err(),
            Some(ProtectorError::CorruptOrTampered)
        );

        // Case 2: SAFEVD entropy, but donor HIMSAT record magic or owner tag inside plaintext.
        let mut safevd_entropy = b"SAFEVD/WINDOWS/DPAPI/ENTROPY/v1\0".to_vec();
        safevd_entropy.extend_from_slice(&protector_bytes);
        let mixed_ct =
            encrypt_data(&donor_record, Scope::User, Some(&safevd_entropy)).expect("dpapi encrypt");
        fs::write(&record_path, &mixed_ct).expect("write mixed ciphertext");
        assert_eq!(
            protector.unlock_vrk(vault_id, generation).err(),
            Some(ProtectorError::CorruptOrTampered)
        );

        let _ = fs::remove_dir_all(&root);
    }
}

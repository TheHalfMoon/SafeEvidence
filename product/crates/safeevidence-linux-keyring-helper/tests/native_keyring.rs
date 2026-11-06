//! Real Secret Service runs through the real helper binary and the vault's protector.
//! They need an unlocked provider in the session, so CI runs them in its own step.
#![cfg(target_os = "linux")]

use safeevidence_linux_keyring_helper::{
    APPLICATION_ATTRIBUTE, APPLICATION_ID, CONTENT_TYPE, ITEM_LABEL, PROTECTOR_ATTRIBUTE,
    SCHEMA_ATTRIBUTE, SCHEMA_ID, attribute_value, query_attributes,
};
use safeevidence_vault::vault::{
    AccessScope, KeyGeneration, ProtectorError, SecretProtector, UserPresencePolicy,
    VAULT_ID_BYTES, VaultId,
};
use safeevidence_vault::vault_keys::OwnedKeyMaterial;
use safeevidence_vault::vault_linux_secret_service::{
    KeyringHelperCommand, LinuxProtectorId, LinuxSecretServiceConfig, LinuxSecretServiceProtector,
};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;

const ID: [u8; 16] = [0xb4; 16];

fn protector() -> LinuxSecretServiceProtector {
    let command =
        KeyringHelperCommand::new(env!("CARGO_BIN_EXE_safeevidence-linux-keyring-helper"))
            .expect("absolute helper path");
    LinuxSecretServiceProtector::new(
        LinuxSecretServiceConfig::new(LinuxProtectorId::from_bytes(ID)),
        command,
    )
}

fn vault() -> VaultId {
    VaultId::from_bytes([0x44; VAULT_ID_BYTES])
}

fn generation() -> KeyGeneration {
    KeyGeneration::new(7).expect("non-zero generation")
}

fn key() -> OwnedKeyMaterial {
    OwnedKeyMaterial::from_bytes([0x7a; 32])
}

fn configured() -> LinuxSecretServiceProtector {
    let mut protector = protector();
    protector
        .create_protector(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired,
        )
        .expect("provider accepts the conservative baseline");
    protector
}

#[test]
#[ignore = "requires an unlocked genuine Secret Service provider"]
fn native_keyring_phase_1_store_and_inspect() {
    let mut protector = configured();
    protector
        .protect_or_store_vrk(vault(), generation(), &key())
        .expect("provider stores the VRK");
    protector
        .unlock_vrk(vault(), generation())
        .expect("provider returns the VRK");
    protector
        .protect_or_store_vrk(vault(), generation(), &key())
        .expect("the same VRK matches the stored record");
    assert_eq!(
        protector.protect_or_store_vrk(
            vault(),
            generation(),
            &OwnedKeyMaterial::from_bytes([0x7b; 32])
        ),
        Err(ProtectorError::CorruptOrTampered),
        "a different VRK does not match the stored record"
    );

    let service = SecretService::connect(EncryptionType::Dh).expect("encrypted session");
    let collection = service
        .get_default_collection()
        .expect("default collection");
    collection
        .ensure_unlocked()
        .expect("collection is unlocked");
    let protector_id = attribute_value(&ID);
    let items = collection
        .search_items(query_attributes(&protector_id))
        .expect("query");
    assert_eq!(items.len(), 1, "exactly one protector item must exist");
    let attributes = items[0].get_attributes().expect("attributes");
    assert_eq!(attributes.len(), 3);
    assert_eq!(
        attributes.get(APPLICATION_ATTRIBUTE).map(String::as_str),
        Some(APPLICATION_ID)
    );
    assert_eq!(
        attributes.get(SCHEMA_ATTRIBUTE).map(String::as_str),
        Some(SCHEMA_ID)
    );
    assert_eq!(
        attributes.get(PROTECTOR_ATTRIBUTE).map(String::as_str),
        Some(protector_id.as_str())
    );
    assert_eq!(items[0].get_label().expect("label"), ITEM_LABEL);
    let content_type = items[0].get_secret_content_type().expect("content type");
    assert!(
        content_type == CONTENT_TYPE || content_type == "text/plain",
        "{content_type}"
    );
    assert!(!items[0].is_locked().expect("lock state"));
}

#[test]
#[ignore = "requires the phase-1 item in the same genuine provider session"]
fn native_keyring_phase_2_restart_unlock_delete_and_lock() {
    let mut protector = configured();
    protector
        .unlock_vrk(vault(), generation())
        .expect("a new helper reads the existing VRK");
    assert_eq!(
        protector
            .unlock_vrk(VaultId::from_bytes([0x45; VAULT_ID_BYTES]), generation())
            .map(|_| ()),
        Err(ProtectorError::OwnerMismatch),
        "the record is bound to its vault"
    );
    protector
        .remove_protector(vault())
        .expect("provider deletes the item");

    let service = SecretService::connect(EncryptionType::Dh).expect("provider stays available");
    let collection = service
        .get_default_collection()
        .expect("default collection");
    let protector_id = attribute_value(&ID);
    assert!(
        collection
            .search_items(query_attributes(&protector_id))
            .expect("query")
            .is_empty(),
        "a deleted protector must not remain discoverable"
    );
    collection.lock().expect("provider supports locking");
    let mut locked_probe = self::protector();
    assert_eq!(
        locked_probe.create_protector(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired
        ),
        Err(ProtectorError::Locked),
        "the helper must not unlock a locked collection"
    );
}

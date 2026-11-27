use std::collections::HashMap;

use safeevidence_keyring_wire::{Backend, ProtectorId, SecretBytes, WireError};
use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error as SecretServiceError};
use zeroize::Zeroizing;

pub const APPLICATION_ATTRIBUTE: &str = "application";
pub const APPLICATION_ID: &str = "com.thehalfmoon.safeevidence";
pub const PROTECTOR_ATTRIBUTE: &str = "protector-id";
pub const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
pub const SCHEMA_ID: &str = "com.thehalfmoon.safeevidence";
pub const ITEM_LABEL: &str = "SafeEvidence Vault Protector";
pub const CONTENT_TYPE: &str = "application/octet-stream";

#[must_use]
pub fn attribute_value(id: &ProtectorId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(id.len() * 2);
    for byte in id {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[must_use]
pub fn query_attributes(protector_id: &str) -> HashMap<&'static str, &str> {
    let mut attributes = HashMap::with_capacity(3);
    attributes.insert(APPLICATION_ATTRIBUTE, APPLICATION_ID);
    attributes.insert(SCHEMA_ATTRIBUTE, SCHEMA_ID);
    attributes.insert(PROTECTOR_ATTRIBUTE, protector_id);
    attributes
}

fn session_encryption() -> EncryptionType {
    EncryptionType::Dh
}

fn connect() -> Result<SecretService<'static>, WireError> {
    SecretService::connect(session_encryption()).map_err(map_secret_service_error)
}

fn unlocked_collection<'a>(service: &'a SecretService<'_>) -> Result<Collection<'a>, WireError> {
    let collection = service
        .get_default_collection()
        .map_err(map_collection_error)?;
    collection
        .ensure_unlocked()
        .map_err(map_secret_service_error)?;
    Ok(collection)
}

fn find_single_item<'a>(
    collection: &'a Collection<'a>,
    protector_id: &str,
) -> Result<Option<Item<'a>>, WireError> {
    let mut items = collection
        .search_items(query_attributes(protector_id))
        .map_err(map_secret_service_error)?;
    match items.len() {
        0 => Ok(None),
        1 => Ok(items.pop()),
        _ => Err(WireError::CorruptOrTampered),
    }
}

fn verify_item(item: &Item<'_>, protector_id: &str) -> Result<(), WireError> {
    if item.is_locked().map_err(map_secret_service_error)? {
        return Err(WireError::Locked);
    }
    let attributes = item.get_attributes().map_err(map_secret_service_error)?;
    if attributes.len() != 3
        || attributes.get(APPLICATION_ATTRIBUTE).map(String::as_str) != Some(APPLICATION_ID)
        || attributes.get(SCHEMA_ATTRIBUTE).map(String::as_str) != Some(SCHEMA_ID)
        || attributes.get(PROTECTOR_ATTRIBUTE).map(String::as_str) != Some(protector_id)
    {
        return Err(WireError::OwnerMismatch);
    }
    if item.get_label().map_err(map_secret_service_error)? != ITEM_LABEL {
        return Err(WireError::PolicyMismatch);
    }
    Ok(())
}

/// Serves requests against the session's Secret Service, connecting afresh for each one.
pub struct SecretServiceBackend;

impl Backend for SecretServiceBackend {
    fn ensure_unlocked(&mut self, _id: &ProtectorId) -> Result<(), WireError> {
        let service = connect()?;
        unlocked_collection(&service).map(|_| ())
    }

    fn read(&mut self, id: &ProtectorId) -> Result<Option<SecretBytes>, WireError> {
        let protector_id = attribute_value(id);
        let service = connect()?;
        let collection = unlocked_collection(&service)?;
        let Some(item) = find_single_item(&collection, &protector_id)? else {
            return Ok(None);
        };
        verify_item(&item, &protector_id)?;
        let record = item.get_secret().map_err(map_secret_service_error)?;
        Ok(Some(Zeroizing::new(record)))
    }

    fn create(&mut self, id: &ProtectorId, record: &[u8]) -> Result<(), WireError> {
        let protector_id = attribute_value(id);
        let service = connect()?;
        let collection = unlocked_collection(&service)?;
        let created = collection
            .create_item(
                ITEM_LABEL,
                query_attributes(&protector_id),
                record,
                false,
                CONTENT_TYPE,
            )
            .map_err(map_secret_service_error)?;
        verify_item(&created, &protector_id)?;
        let found = find_single_item(&collection, &protector_id)?.ok_or(WireError::ItemMissing)?;
        if found != created {
            return Err(WireError::CorruptOrTampered);
        }
        Ok(())
    }

    fn delete(&mut self, id: &ProtectorId) -> Result<(), WireError> {
        let protector_id = attribute_value(id);
        let service = connect()?;
        let collection = unlocked_collection(&service)?;
        let Some(item) = find_single_item(&collection, &protector_id)? else {
            return Ok(());
        };
        verify_item(&item, &protector_id)?;
        item.delete().map_err(map_secret_service_error)?;
        if find_single_item(&collection, &protector_id)?.is_some() {
            return Err(WireError::CorruptOrTampered);
        }
        Ok(())
    }
}

fn map_collection_error(error: SecretServiceError) -> WireError {
    if matches!(error, SecretServiceError::NoResult) {
        WireError::Unavailable
    } else {
        map_secret_service_error(error)
    }
}

fn map_secret_service_error(error: SecretServiceError) -> WireError {
    match error {
        SecretServiceError::Locked => WireError::Locked,
        SecretServiceError::NoResult => WireError::ItemMissing,
        SecretServiceError::Prompt => WireError::Denied,
        SecretServiceError::Crypto(_) => WireError::CorruptOrTampered,
        _ => WireError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_metadata_is_fixed_plus_one_opaque_identifier() {
        let value = attribute_value(&[0xa5; 16]);
        let attributes = query_attributes(&value);
        assert_eq!(attributes.len(), 3);
        assert_eq!(attributes.get(APPLICATION_ATTRIBUTE), Some(&APPLICATION_ID));
        assert_eq!(attributes.get(SCHEMA_ATTRIBUTE), Some(&SCHEMA_ID));
        assert_eq!(attributes.get(PROTECTOR_ATTRIBUTE), Some(&value.as_str()));
        assert_eq!(ITEM_LABEL, "SafeEvidence Vault Protector");
        assert_eq!(CONTENT_TYPE, "application/octet-stream");
        assert_eq!(value, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
    }

    #[test]
    fn secret_service_transport_is_always_diffie_hellman_encrypted() {
        assert!(matches!(session_encryption(), EncryptionType::Dh));
    }

    #[test]
    fn provider_errors_are_mapped_fail_closed() {
        assert_eq!(
            map_secret_service_error(SecretServiceError::Locked),
            WireError::Locked
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::NoResult),
            WireError::ItemMissing
        );
        assert_eq!(
            map_collection_error(SecretServiceError::NoResult),
            WireError::Unavailable
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::Prompt),
            WireError::Denied
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::PromptDisconnected),
            WireError::Unavailable
        );
        assert_eq!(
            map_secret_service_error(SecretServiceError::Crypto("test")),
            WireError::CorruptOrTampered
        );
    }
}

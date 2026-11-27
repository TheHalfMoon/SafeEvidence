use crate::vault::{FreshnessEpoch, KeyGeneration, ManifestHash, VaultId};
use crate::vault_backup::{
    BackupCodecError, BackupObjectContext, BackupSetId, decrypt_backup_object, object_provider_key,
    parse_set_descriptor,
};
use crate::vault_backup_bootstrap::{BackupBootstrapError, recover_backup_recovery_bootstrap};
use crate::vault_backup_index::{
    BackupIndexContext, BackupIndexPayload, BackupIndexPayloadKind, EncryptedBackupIndex,
    decrypt_backup_index,
};
use crate::vault_backup_provider::PortableBackupProvider;
use crate::vault_blob::{
    BOUNDED_BLOB_MAX_ENVELOPE_BYTES, BoundedBlobContext, bounded_blob_nonce, decrypt_bounded_blob,
};
use crate::vault_keys::OwnedKeyMaterial;
use crate::vault_manifest::{
    MANIFEST_MAX_ENVELOPE_BYTES, ManifestAuthMetadata, ManifestContext, ManifestObject,
    ManifestObjectKind, ManifestPlaintext, RotationPhase, decrypt_manifest, manifest_hash,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::io::Write;
use zeroize::Zeroize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupSemanticError<E> {
    Provider(E),
    RecoveryAuthenticationFailed,
    ResourceLimit,
    KdfFailed,
    BackupStateNotStable,
    StagingWriteFailed,
    CorruptOrTampered,
}

impl<E: fmt::Display> fmt::Display for BackupSemanticError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "portable backup provider read failed: {error}"),
            Self::RecoveryAuthenticationFailed => f.write_str("recovery authentication failed"),
            Self::ResourceLimit => f.write_str("recovery KDF resource limit"),
            Self::KdfFailed => f.write_str("recovery KDF failed"),
            Self::BackupStateNotStable => f.write_str("backup source state is not stable"),
            Self::StagingWriteFailed => f.write_str("structured-store staging write failed"),
            Self::CorruptOrTampered => f.write_str("portable backup is corrupt or tampered"),
        }
    }
}

impl<E: Error + 'static> Error for BackupSemanticError<E> {}

fn map_bootstrap_error<E>(error: BackupBootstrapError) -> BackupSemanticError<E> {
    match error {
        BackupBootstrapError::RecoveryAuthenticationFailed => {
            BackupSemanticError::RecoveryAuthenticationFailed
        }
        BackupBootstrapError::ResourceLimit => BackupSemanticError::ResourceLimit,
        BackupBootstrapError::KdfFailed => BackupSemanticError::KdfFailed,
        _ => BackupSemanticError::CorruptOrTampered,
    }
}

fn map_codec_error<E>(_: BackupCodecError) -> BackupSemanticError<E> {
    BackupSemanticError::CorruptOrTampered
}

pub struct VerifiedBackupBlob {
    logical_id: [u8; 16],
    source_storage_id: [u8; 16],
    envelope: Vec<u8>,
}

impl VerifiedBackupBlob {
    #[must_use]
    pub const fn logical_id(&self) -> [u8; 16] {
        self.logical_id
    }

    #[must_use]
    pub const fn source_storage_id(&self) -> [u8; 16] {
        self.source_storage_id
    }

    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

pub struct PreSqlCipherVerifiedBackupSet {
    set_id: BackupSetId,
    vault_id: VaultId,
    key_generation: KeyGeneration,
    source_freshness_epoch: FreshnessEpoch,
    source_manifest_hash: ManifestHash,
    source_manifest_envelope: Vec<u8>,
    manifest: ManifestPlaintext,
    structured_store_source_storage_id: [u8; 16],
    structured_store_exact_length: u64,
    structured_store_exact_sha256: [u8; 32],
    generic_artifacts: Vec<VerifiedBackupBlob>,
    vrk: OwnedKeyMaterial,
}

impl PreSqlCipherVerifiedBackupSet {
    #[must_use]
    pub const fn set_id(&self) -> BackupSetId {
        self.set_id
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
    pub fn source_manifest_envelope(&self) -> &[u8] {
        &self.source_manifest_envelope
    }
    #[must_use]
    pub fn manifest(&self) -> &ManifestPlaintext {
        &self.manifest
    }
    #[must_use]
    pub const fn structured_store_source_storage_id(&self) -> [u8; 16] {
        self.structured_store_source_storage_id
    }
    #[must_use]
    pub const fn structured_store_exact_length(&self) -> u64 {
        self.structured_store_exact_length
    }
    #[must_use]
    pub const fn structured_store_exact_sha256(&self) -> [u8; 32] {
        self.structured_store_exact_sha256
    }
    #[must_use]
    pub fn generic_artifacts(&self) -> &[VerifiedBackupBlob] {
        &self.generic_artifacts
    }
    /// Runs a successor structured-store verifier without exposing VRK bytes.
    ///
    /// `OwnedKeyMaterial` keeps its byte accessor crate-private; the callback may
    /// pass the opaque key object only into already-reviewed in-crate providers.
    pub fn with_structured_store_verification_key<T>(
        &self,
        operation: impl FnOnce(&OwnedKeyMaterial, VaultId, KeyGeneration) -> T,
    ) -> T {
        operation(&self.vrk, self.vault_id, self.key_generation)
    }
}

fn reconstruct_bounded_payload<P: PortableBackupProvider>(
    provider: &mut P,
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    set_id: BackupSetId,
    generation: KeyGeneration,
    payload: &BackupIndexPayload,
    maximum_length: usize,
) -> Result<Vec<u8>, BackupSemanticError<P::Error>> {
    let expected_len = usize::try_from(payload.exact_payload_length())
        .map_err(|_| BackupSemanticError::CorruptOrTampered)?;
    if expected_len > maximum_length {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    let mut reconstructed = Vec::new();
    reconstructed
        .try_reserve_exact(expected_len)
        .map_err(|_| BackupSemanticError::ResourceLimit)?;
    let mut hasher = Sha256::new();

    for chunk in payload.chunks() {
        let key = object_provider_key(set_id, chunk.object_id());
        let envelope = provider.read(&key).map_err(BackupSemanticError::Provider)?;
        let mut plaintext = decrypt_backup_object(
            vrk,
            vault_id,
            BackupObjectContext {
                set_id,
                object_id: chunk.object_id(),
                key_generation: generation,
            },
            &envelope,
        )
        .map_err(map_codec_error)?;
        if plaintext.len()
            != usize::try_from(chunk.plaintext_chunk_length())
                .map_err(|_| BackupSemanticError::CorruptOrTampered)?
        {
            plaintext.zeroize();
            return Err(BackupSemanticError::CorruptOrTampered);
        }
        let next_len = reconstructed
            .len()
            .checked_add(plaintext.len())
            .ok_or(BackupSemanticError::CorruptOrTampered)?;
        if next_len > expected_len {
            plaintext.zeroize();
            return Err(BackupSemanticError::CorruptOrTampered);
        }
        hasher.update(&plaintext);
        reconstructed.extend_from_slice(&plaintext);
        plaintext.zeroize();
    }

    let digest: [u8; 32] = hasher.finalize().into();
    if reconstructed.len() != expected_len || digest != payload.exact_payload_sha256() {
        reconstructed.zeroize();
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    Ok(reconstructed)
}

fn stream_structured_store<P: PortableBackupProvider, W: Write>(
    provider: &mut P,
    sink: &mut W,
    vrk: &OwnedKeyMaterial,
    vault_id: VaultId,
    set_id: BackupSetId,
    generation: KeyGeneration,
    payload: &BackupIndexPayload,
) -> Result<(), BackupSemanticError<P::Error>> {
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    for chunk in payload.chunks() {
        let key = object_provider_key(set_id, chunk.object_id());
        let envelope = provider.read(&key).map_err(BackupSemanticError::Provider)?;
        let mut plaintext = decrypt_backup_object(
            vrk,
            vault_id,
            BackupObjectContext {
                set_id,
                object_id: chunk.object_id(),
                key_generation: generation,
            },
            &envelope,
        )
        .map_err(map_codec_error)?;
        if plaintext.len()
            != usize::try_from(chunk.plaintext_chunk_length())
                .map_err(|_| BackupSemanticError::CorruptOrTampered)?
        {
            plaintext.zeroize();
            return Err(BackupSemanticError::CorruptOrTampered);
        }
        total = total
            .checked_add(
                u64::try_from(plaintext.len())
                    .map_err(|_| BackupSemanticError::CorruptOrTampered)?,
            )
            .ok_or(BackupSemanticError::CorruptOrTampered)?;
        if total > payload.exact_payload_length() {
            plaintext.zeroize();
            return Err(BackupSemanticError::CorruptOrTampered);
        }
        hasher.update(&plaintext);
        if sink.write_all(&plaintext).is_err() {
            plaintext.zeroize();
            return Err(BackupSemanticError::StagingWriteFailed);
        }
        plaintext.zeroize();
    }
    if sink.flush().is_err() {
        return Err(BackupSemanticError::StagingWriteFailed);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if total != payload.exact_payload_length() || digest != payload.exact_payload_sha256() {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    Ok(())
}

fn require_stable_manifest<E>(
    manifest: &ManifestPlaintext,
    expected_vault: VaultId,
    expected_generation: KeyGeneration,
    expected_epoch: FreshnessEpoch,
) -> Result<(), BackupSemanticError<E>> {
    if manifest.vault_id() != expected_vault
        || manifest.active_key_generation() != expected_generation
        || manifest.freshness_epoch() != expected_epoch
    {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    if manifest.rotation_phase() != RotationPhase::None
        || manifest.rotation_target_generation().is_some()
        || manifest
            .objects()
            .iter()
            .any(|object| object.key_generation() != expected_generation)
    {
        return Err(BackupSemanticError::BackupStateNotStable);
    }
    Ok(())
}

fn matching_manifest_object<'a, E>(
    manifest: &'a ManifestPlaintext,
    payload: &BackupIndexPayload,
    matched: &mut HashSet<usize>,
) -> Result<&'a ManifestObject, BackupSemanticError<E>> {
    let expected_kind = match payload.kind() {
        BackupIndexPayloadKind::Manifest => return Err(BackupSemanticError::CorruptOrTampered),
        BackupIndexPayloadKind::StructuredStore => ManifestObjectKind::StructuredStore,
        BackupIndexPayloadKind::GenericArtifactBlob => ManifestObjectKind::GenericArtifactBlob,
    };
    let mut found: Option<(usize, &ManifestObject)> = None;
    for (index, object) in manifest.objects().iter().enumerate() {
        if object.kind() == expected_kind && object.logical_id() == payload.logical_id() {
            if found.is_some() {
                return Err(BackupSemanticError::CorruptOrTampered);
            }
            found = Some((index, object));
        }
    }
    let (index, object) = found.ok_or(BackupSemanticError::CorruptOrTampered)?;
    if !matched.insert(index) || object.storage_id() != payload.source_storage_id() {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    if expected_kind == ManifestObjectKind::GenericArtifactBlob
        && (object.ciphertext_length() != payload.exact_payload_length()
            || object.ciphertext_sha256() != payload.exact_payload_sha256())
    {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    Ok(object)
}

pub fn verify_backup_semantics_before_sqlcipher<P: PortableBackupProvider, W: Write>(
    provider: &mut P,
    descriptor_bytes: &[u8],
    passphrase: &str,
    structured_store_sink: &mut W,
) -> Result<PreSqlCipherVerifiedBackupSet, BackupSemanticError<P::Error>> {
    let descriptor = parse_set_descriptor(descriptor_bytes).map_err(map_codec_error)?;
    let recovered =
        recover_backup_recovery_bootstrap(&descriptor, passphrase).map_err(map_bootstrap_error)?;
    let recovery_context = recovered.context();
    let vault_id = recovery_context.vault_id();
    let generation = recovery_context.key_generation();
    if generation != descriptor.key_generation() {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    let vrk = recovered.into_vrk();

    let index_context = BackupIndexContext::new(
        descriptor.set_id(),
        descriptor.key_generation(),
        descriptor.data_object_count(),
    )
    .map_err(map_codec_error)?;
    let encrypted_index = EncryptedBackupIndex::new(
        *descriptor.index_nonce(),
        descriptor.index_ciphertext_and_tag().to_vec(),
    )
    .map_err(map_codec_error)?;
    let index = decrypt_backup_index(
        &vrk,
        vault_id,
        index_context,
        descriptor.bootstrap_slot(),
        &encrypted_index,
    )
    .map_err(map_codec_error)?;

    let manifest_payload = index
        .payloads()
        .first()
        .ok_or(BackupSemanticError::CorruptOrTampered)?;
    if manifest_payload.kind() != BackupIndexPayloadKind::Manifest {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    let manifest_envelope = reconstruct_bounded_payload(
        provider,
        &vrk,
        vault_id,
        descriptor.set_id(),
        generation,
        manifest_payload,
        MANIFEST_MAX_ENVELOPE_BYTES,
    )?;
    if manifest_hash(&manifest_envelope) != index.source_manifest_hash() {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    let manifest_context =
        ManifestContext::new(vault_id, generation, index.source_freshness_epoch());
    let manifest = decrypt_manifest(&vrk, manifest_context, &manifest_envelope)
        .map_err(|_| BackupSemanticError::CorruptOrTampered)?;
    require_stable_manifest(
        &manifest,
        vault_id,
        generation,
        index.source_freshness_epoch(),
    )?;

    if index.payloads().len() != manifest.objects().len() + 1 {
        return Err(BackupSemanticError::CorruptOrTampered);
    }

    let mut matched = HashSet::with_capacity(manifest.objects().len());
    let structured_payload = index
        .payloads()
        .get(1)
        .ok_or(BackupSemanticError::CorruptOrTampered)?;
    let structured_manifest_object =
        matching_manifest_object(&manifest, structured_payload, &mut matched)?;
    if structured_payload.kind() != BackupIndexPayloadKind::StructuredStore
        || structured_manifest_object.auth_metadata() != ManifestAuthMetadata::StructuredStore
    {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    stream_structured_store(
        provider,
        structured_store_sink,
        &vrk,
        vault_id,
        descriptor.set_id(),
        generation,
        structured_payload,
    )?;

    let mut generic_artifacts = Vec::new();
    generic_artifacts
        .try_reserve_exact(index.payloads().len().saturating_sub(2))
        .map_err(|_| BackupSemanticError::ResourceLimit)?;
    for payload in &index.payloads()[2..] {
        let manifest_object = matching_manifest_object(&manifest, payload, &mut matched)?;
        if payload.kind() != BackupIndexPayloadKind::GenericArtifactBlob {
            return Err(BackupSemanticError::CorruptOrTampered);
        }
        let ManifestAuthMetadata::GenericArtifactBlob { nonce } = manifest_object.auth_metadata()
        else {
            return Err(BackupSemanticError::CorruptOrTampered);
        };
        let bytes = reconstruct_bounded_payload(
            provider,
            &vrk,
            vault_id,
            descriptor.set_id(),
            generation,
            payload,
            BOUNDED_BLOB_MAX_ENVELOPE_BYTES,
        )?;
        if bounded_blob_nonce(&bytes).map_err(|_| BackupSemanticError::CorruptOrTampered)? != nonce
        {
            return Err(BackupSemanticError::CorruptOrTampered);
        }
        let mut plaintext = decrypt_bounded_blob(
            &vrk,
            BoundedBlobContext::new(vault_id, payload.logical_id(), generation),
            &bytes,
        )
        .map_err(|_| BackupSemanticError::CorruptOrTampered)?;
        plaintext.zeroize();
        generic_artifacts.push(VerifiedBackupBlob {
            logical_id: payload.logical_id(),
            source_storage_id: payload.source_storage_id(),
            envelope: bytes,
        });
    }

    if matched.len() != manifest.objects().len() {
        return Err(BackupSemanticError::CorruptOrTampered);
    }
    let structured_store_source_storage_id = structured_payload.source_storage_id();

    Ok(PreSqlCipherVerifiedBackupSet {
        set_id: descriptor.set_id(),
        vault_id,
        key_generation: generation,
        source_freshness_epoch: index.source_freshness_epoch(),
        source_manifest_hash: index.source_manifest_hash(),
        source_manifest_envelope: manifest_envelope,
        manifest,
        structured_store_source_storage_id,
        structured_store_exact_length: structured_payload.exact_payload_length(),
        structured_store_exact_sha256: structured_payload.exact_payload_sha256(),
        generic_artifacts,
        vrk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_backup::{BackupSetDescriptor, encode_set_descriptor, encrypt_backup_object};
    use crate::vault_backup_bootstrap::create_backup_recovery_bootstrap;
    use crate::vault_backup_index::{BackupIndexChunk, encrypt_backup_index};
    use crate::vault_blob::encrypt_bounded_blob;
    use crate::vault_manifest::{GenerationState, ManifestGeneration, encrypt_fresh_manifest};
    use crate::vault_nonce::NonceReservationLedger;
    use crate::vault_recovery::{RecoveryContext, encrypt_recovery_envelope};
    use std::collections::HashMap;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProviderError {
        Missing,
        Exists,
    }
    impl fmt::Display for ProviderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                Self::Missing => "missing",
                Self::Exists => "exists",
            })
        }
    }
    impl Error for ProviderError {}

    #[derive(Default)]
    struct MemoryProvider {
        objects: HashMap<String, Vec<u8>>,
    }
    impl PortableBackupProvider for MemoryProvider {
        type Error = ProviderError;
        fn put_if_absent(&mut self, key: &str, bytes: &[u8]) -> Result<(), Self::Error> {
            if self.objects.contains_key(key) {
                return Err(ProviderError::Exists);
            }
            self.objects.insert(key.to_owned(), bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, key: &str) -> Result<Vec<u8>, Self::Error> {
            self.objects.get(key).cloned().ok_or(ProviderError::Missing)
        }
    }

    fn vault_id() -> VaultId {
        VaultId::from_bytes([0x22; 16])
    }
    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).unwrap()
    }
    fn set_id() -> BackupSetId {
        BackupSetId::from_bytes([0x33; 16]).unwrap()
    }
    fn object_id(byte: u8) -> crate::vault_backup::BackupObjectId {
        crate::vault_backup::BackupObjectId::from_bytes([byte; 16]).unwrap()
    }
    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
    fn payload(
        kind: BackupIndexPayloadKind,
        logical_id: [u8; 16],
        storage_id: [u8; 16],
        bytes: &[u8],
        object_id: crate::vault_backup::BackupObjectId,
    ) -> BackupIndexPayload {
        BackupIndexPayload::new(
            kind,
            logical_id,
            storage_id,
            u64::try_from(bytes.len()).unwrap(),
            sha(bytes),
            vec![BackupIndexChunk::new(object_id, u32::try_from(bytes.len()).unwrap()).unwrap()],
        )
        .unwrap()
    }

    struct Fixture {
        provider: MemoryProvider,
        descriptor: Vec<u8>,
        structured_bytes: Vec<u8>,
    }

    fn fixture(
        unstable: bool,
        mismatched_blob_storage: bool,
        structured_inventory_matches_snapshot: bool,
        mismatched_structured_storage: bool,
    ) -> Fixture {
        let vault = vault_id();
        let source_generation = generation(7);
        let vrk = OwnedKeyMaterial::from_bytes([0x11; 32]);
        let epoch = FreshnessEpoch::new(3).unwrap();
        let blob_id = [0x44; 16];
        let blob_storage = [0x55; 16];
        let structured_storage = [0x66; 16];
        let blob_nonce = [0x77; 24];
        let blob_envelope = encrypt_bounded_blob(
            &vrk,
            BoundedBlobContext::new(vault, blob_id, source_generation),
            blob_nonce,
            b"verified generic artifact payload",
        )
        .unwrap();
        let structured_bytes = b"encrypted SQLCipher fixture bytes pending B505J".to_vec();
        let structured_inventory_bytes = if structured_inventory_matches_snapshot {
            structured_bytes.as_slice()
        } else {
            b"pre-checkpoint SQLCipher inventory bytes"
        };

        let mut generations = vec![ManifestGeneration::new(
            source_generation,
            GenerationState::Active,
        )];
        let rotation = if unstable {
            let target = generation(8);
            generations.push(ManifestGeneration::new(target, GenerationState::Staged));
            (RotationPhase::Prepare, Some(target))
        } else {
            (RotationPhase::None, None)
        };
        let manifest = ManifestPlaintext::new(
            vault,
            epoch,
            ManifestHash::from_bytes([0x99; 32]),
            source_generation,
            rotation,
            generations,
            vec![
                ManifestObject::new(
                    blob_id,
                    blob_storage,
                    source_generation,
                    u64::try_from(blob_envelope.len()).unwrap(),
                    sha(&blob_envelope),
                    ManifestAuthMetadata::GenericArtifactBlob { nonce: blob_nonce },
                ),
                ManifestObject::new(
                    [0_u8; 16],
                    structured_storage,
                    source_generation,
                    u64::try_from(structured_inventory_bytes.len()).unwrap(),
                    sha(structured_inventory_bytes),
                    ManifestAuthMetadata::StructuredStore,
                ),
            ],
        )
        .unwrap();
        let mut ledger = NonceReservationLedger::new(vault);
        let (_, manifest_envelope) = encrypt_fresh_manifest(
            &mut ledger,
            &vrk,
            ManifestContext::new(vault, source_generation, epoch),
            &manifest,
        )
        .unwrap();

        let recovery_context = RecoveryContext::new(vault, source_generation);
        let recovery_envelope =
            encrypt_recovery_envelope(&vrk, recovery_context, PASSPHRASE).unwrap();
        let bootstrap = create_backup_recovery_bootstrap(
            &vrk,
            recovery_context,
            &recovery_envelope,
            PASSPHRASE,
            set_id(),
        )
        .unwrap();

        let manifest_object_id = object_id(1);
        let structured_object_id = object_id(2);
        let blob_object_id = object_id(3);
        let blob_index_storage = if mismatched_blob_storage {
            [0x88; 16]
        } else {
            blob_storage
        };
        let structured_index_storage = if mismatched_structured_storage {
            [0x89; 16]
        } else {
            structured_storage
        };
        let index = crate::vault_backup_index::BackupIndexPlaintext::new(
            vault,
            source_generation,
            epoch,
            manifest_hash(&manifest_envelope),
            vec![
                payload(
                    BackupIndexPayloadKind::Manifest,
                    [0; 16],
                    [0; 16],
                    &manifest_envelope,
                    manifest_object_id,
                ),
                payload(
                    BackupIndexPayloadKind::StructuredStore,
                    [0; 16],
                    structured_index_storage,
                    &structured_bytes,
                    structured_object_id,
                ),
                payload(
                    BackupIndexPayloadKind::GenericArtifactBlob,
                    blob_id,
                    blob_index_storage,
                    &blob_envelope,
                    blob_object_id,
                ),
            ],
        )
        .unwrap();
        let index_context = BackupIndexContext::new(set_id(), source_generation, 3).unwrap();
        let encrypted_index =
            encrypt_backup_index(&vrk, vault, index_context, bootstrap.slot(), &index).unwrap();
        let descriptor = BackupSetDescriptor::new(
            set_id(),
            source_generation,
            3,
            *bootstrap.salt(),
            *bootstrap.nonce(),
            *bootstrap.slot(),
            *encrypted_index.nonce(),
            encrypted_index.ciphertext_and_tag().to_vec(),
        )
        .unwrap();
        let descriptor = encode_set_descriptor(&descriptor).unwrap();

        let mut provider = MemoryProvider::default();
        for (id, bytes) in [
            (manifest_object_id, manifest_envelope),
            (structured_object_id, structured_bytes.clone()),
            (blob_object_id, blob_envelope),
        ] {
            let context = BackupObjectContext {
                set_id: set_id(),
                object_id: id,
                key_generation: source_generation,
            };
            let envelope = encrypt_backup_object(&vrk, vault, context, &bytes).unwrap();
            provider
                .objects
                .insert(object_provider_key(set_id(), id), envelope);
        }
        Fixture {
            provider,
            descriptor,
            structured_bytes,
        }
    }

    #[test]
    fn reconstructs_manifest_and_b202_before_sqlcipher() {
        let mut fixture = fixture(false, false, true, false);
        let mut staged = Vec::new();
        let verified = verify_backup_semantics_before_sqlcipher(
            &mut fixture.provider,
            &fixture.descriptor,
            PASSPHRASE,
            &mut staged,
        )
        .unwrap();
        assert_eq!(verified.set_id(), set_id());
        assert_eq!(verified.vault_id(), vault_id());
        assert_eq!(verified.key_generation(), generation(7));
        assert_eq!(staged, fixture.structured_bytes);
        assert_eq!(
            verified.structured_store_exact_length(),
            u64::try_from(fixture.structured_bytes.len()).unwrap()
        );
        assert_eq!(
            verified.structured_store_exact_sha256(),
            sha(&fixture.structured_bytes)
        );
        assert_eq!(verified.generic_artifacts().len(), 1);
        assert_eq!(verified.generic_artifacts()[0].logical_id(), [0x44; 16]);
        assert_eq!(
            verified.generic_artifacts()[0].source_storage_id(),
            [0x55; 16]
        );
        let recovered = verified
            .with_structured_store_verification_key(|vrk, _, _| vrk.with_bytes(|bytes| *bytes));
        assert_eq!(recovered, [0x11; 32]);
    }

    #[test]
    fn authenticated_index_storage_mismatch_is_rejected() {
        let mut fixture = fixture(false, true, true, false);
        assert_eq!(
            verify_backup_semantics_before_sqlcipher(
                &mut fixture.provider,
                &fixture.descriptor,
                PASSPHRASE,
                &mut Vec::new(),
            )
            .err(),
            Some(BackupSemanticError::CorruptOrTampered)
        );
    }

    #[test]
    fn post_checkpoint_structured_snapshot_identity_may_differ_from_manifest_inventory() {
        let mut fixture = fixture(false, false, false, false);
        let mut staged = Vec::new();
        let verified = verify_backup_semantics_before_sqlcipher(
            &mut fixture.provider,
            &fixture.descriptor,
            PASSPHRASE,
            &mut staged,
        )
        .expect(
            "post-checkpoint SQLCipher snapshot remains bound by authenticated storage identity",
        );
        assert_eq!(staged, fixture.structured_bytes);
        assert_eq!(verified.structured_store_source_storage_id(), [0x66; 16]);
    }

    #[test]
    fn post_checkpoint_structured_snapshot_still_requires_exact_storage_binding() {
        let mut fixture = fixture(false, false, false, true);
        assert_eq!(
            verify_backup_semantics_before_sqlcipher(
                &mut fixture.provider,
                &fixture.descriptor,
                PASSPHRASE,
                &mut Vec::new(),
            )
            .err(),
            Some(BackupSemanticError::CorruptOrTampered)
        );
    }

    #[test]
    fn provider_object_tamper_fails_outer_authentication() {
        let mut fixture = fixture(false, false, true, false);
        let key = object_provider_key(set_id(), object_id(3));
        let object = fixture.provider.objects.get_mut(&key).unwrap();
        *object.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            verify_backup_semantics_before_sqlcipher(
                &mut fixture.provider,
                &fixture.descriptor,
                PASSPHRASE,
                &mut Vec::new(),
            )
            .err(),
            Some(BackupSemanticError::CorruptOrTampered)
        );
    }

    #[test]
    fn authenticated_rotation_state_is_not_export_stable() {
        let mut fixture = fixture(true, false, true, false);
        assert_eq!(
            verify_backup_semantics_before_sqlcipher(
                &mut fixture.provider,
                &fixture.descriptor,
                PASSPHRASE,
                &mut Vec::new(),
            )
            .err(),
            Some(BackupSemanticError::BackupStateNotStable)
        );
    }
}

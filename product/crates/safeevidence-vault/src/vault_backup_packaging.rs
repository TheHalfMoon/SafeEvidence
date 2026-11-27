use crate::vault::{KeyGeneration, VaultLeaseIdentity};
use crate::vault_backup::{
    BACKUP_CHUNK_PLAINTEXT_MAX, BACKUP_DATA_OBJECT_COUNT_MAX, BACKUP_NONCE_BYTES,
    BACKUP_OBJECT_HEADER_BYTES, BACKUP_TAG_BYTES, BackupCodecError, BackupObjectContext,
    BackupObjectId, BackupSetDescriptor, BackupSetId, backup_object_nonce, encode_set_descriptor,
    encrypt_backup_object,
};
use crate::vault_backup_bootstrap::{BackupBootstrapError, create_backup_recovery_bootstrap};
use crate::vault_backup_index::{
    BACKUP_INDEX_PAYLOAD_COUNT_MAX, BackupIndexChunk, BackupIndexContext, BackupIndexPayload,
    BackupIndexPayloadKind, BackupIndexPlaintext, encrypt_backup_index,
};
use crate::vault_backup_provider::PreparedBackupObjectSource;
use crate::vault_blob::{
    BOUNDED_BLOB_MAX_ENVELOPE_BYTES, BoundedBlobContext, bounded_blob_nonce, decrypt_bounded_blob,
};
use crate::vault_keys::{KeyDerivationContext, KeyPurpose, OwnedKeyMaterial};
use crate::vault_lease::VaultLease;
use crate::vault_manifest::{
    ManifestAuthMetadata, ManifestObject, ManifestObjectKind, RotationPhase, decrypt_manifest,
    manifest_context, manifest_hash,
};
use crate::vault_recovery::RecoveryContext;
use crate::vault_sqlcipher::{
    SqlCipherBackupSnapshot, SqlCipherIntegrityError, SqlCipherOpenError, open_sqlcipher_database,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const FILE_HASH_BUFFER_BYTES: usize = 1024 * 1024;
const RANDOM_COLLISION_ATTEMPTS: usize = 16;
const DESCRIPTOR_FILENAME: &str = "descriptor.bin";
const MAX_BACKUP_OBJECT_ENVELOPE_BYTES: usize =
    BACKUP_OBJECT_HEADER_BYTES + BACKUP_CHUNK_PLAINTEXT_MAX + BACKUP_TAG_BYTES;

#[derive(Debug)]
pub enum BackupPackagingError {
    BackupStateNotStable,
    RecoveryAuthenticationFailed,
    ResourceLimit,
    KdfFailed,
    RandomnessUnavailable,
    SourceMapMismatch,
    SourceReadFailed,
    SourceIdentityMismatch,
    SourceChanged,
    StructuredStoreOpen(SqlCipherOpenError),
    StructuredStoreIntegrity(SqlCipherIntegrityError),
    StagingWriteFailed,
    EncryptionFailed,
    CorruptOrTampered,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BackupSourceVerification {
    ManifestExact,
    SqlCipherSnapshot {
        source_precheckpoint_byte_length: u64,
        source_precheckpoint_sha256: [u8; 32],
        snapshot_byte_length: u64,
        snapshot_sha256: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSourceFile {
    storage_id: [u8; 16],
    path: PathBuf,
    verification: BackupSourceVerification,
}

impl BackupSourceFile {
    pub fn new(storage_id: [u8; 16], path: impl Into<PathBuf>) -> Self {
        Self {
            storage_id,
            path: path.into(),
            verification: BackupSourceVerification::ManifestExact,
        }
    }

    #[must_use]
    pub const fn storage_id(&self) -> [u8; 16] {
        self.storage_id
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn from_sqlcipher_snapshot(
        storage_id: [u8; 16],
        snapshot: &SqlCipherBackupSnapshot,
    ) -> Self {
        Self {
            storage_id,
            path: snapshot.path().to_path_buf(),
            verification: BackupSourceVerification::SqlCipherSnapshot {
                source_precheckpoint_byte_length: snapshot.source_precheckpoint_byte_length(),
                source_precheckpoint_sha256: snapshot.source_precheckpoint_sha256(),
                snapshot_byte_length: snapshot.byte_length(),
                snapshot_sha256: snapshot.sha256(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DiskPreparedObject {
    object_id: BackupObjectId,
    byte_length: u64,
    sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskBackupSourceError {
    OutOfRange,
    ResourceLimit,
    ReadFailed,
    IdentityMismatch,
}

pub struct DiskPreparedBackupSet {
    descriptor_bytes: Vec<u8>,
    staging_directory: PathBuf,
    objects: Vec<DiskPreparedObject>,
}

impl DiskPreparedBackupSet {
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    fn object_path(&self, index: usize) -> PathBuf {
        self.staging_directory
            .join(format!("object-{index:08x}.bin"))
    }
}

impl PreparedBackupObjectSource for DiskPreparedBackupSet {
    type Error = DiskBackupSourceError;

    fn object_count(&self) -> usize {
        self.objects.len()
    }

    fn object_id(&mut self, index: usize) -> Result<BackupObjectId, Self::Error> {
        self.objects
            .get(index)
            .map(|object| object.object_id)
            .ok_or(DiskBackupSourceError::OutOfRange)
    }

    fn read_object(&mut self, index: usize) -> Result<Vec<u8>, Self::Error> {
        let object = *self
            .objects
            .get(index)
            .ok_or(DiskBackupSourceError::OutOfRange)?;
        read_staged_object(&self.object_path(index), object.byte_length, object.sha256)
    }
}

fn map_codec_error(error: BackupCodecError) -> BackupPackagingError {
    match error {
        BackupCodecError::RandomnessUnavailable => BackupPackagingError::RandomnessUnavailable,
        BackupCodecError::EncryptionFailed => BackupPackagingError::EncryptionFailed,
        _ => BackupPackagingError::CorruptOrTampered,
    }
}

fn map_bootstrap_error(error: BackupBootstrapError) -> BackupPackagingError {
    match error {
        BackupBootstrapError::RecoveryAuthenticationFailed => {
            BackupPackagingError::RecoveryAuthenticationFailed
        }
        BackupBootstrapError::ResourceLimit => BackupPackagingError::ResourceLimit,
        BackupBootstrapError::KdfFailed => BackupPackagingError::KdfFailed,
        BackupBootstrapError::RandomnessUnavailable => BackupPackagingError::RandomnessUnavailable,
        BackupBootstrapError::EncryptionFailed => BackupPackagingError::EncryptionFailed,
        BackupBootstrapError::CorruptOrTampered => BackupPackagingError::CorruptOrTampered,
    }
}

fn regular_file(path: &Path) -> Result<File, BackupPackagingError> {
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| BackupPackagingError::SourceReadFailed)?;
    if !path_metadata.file_type().is_file() {
        return Err(BackupPackagingError::SourceReadFailed);
    }
    let file = File::open(path).map_err(|_| BackupPackagingError::SourceReadFailed)?;
    if !file
        .metadata()
        .map_err(|_| BackupPackagingError::SourceReadFailed)?
        .is_file()
    {
        return Err(BackupPackagingError::SourceReadFailed);
    }
    Ok(file)
}

fn file_identity(path: &Path) -> Result<(u64, [u8; 32]), BackupPackagingError> {
    let mut file = regular_file(path)?;
    let mut buffer = vec![0_u8; FILE_HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| BackupPackagingError::SourceReadFailed)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| BackupPackagingError::ResourceLimit)?)
            .ok_or(BackupPackagingError::ResourceLimit)?;
        hasher.update(&buffer[..read]);
    }
    Ok((total, hasher.finalize().into()))
}

fn read_exact_bounded_file(
    path: &Path,
    expected_length: u64,
    maximum_length: usize,
) -> Result<Vec<u8>, BackupPackagingError> {
    let expected =
        usize::try_from(expected_length).map_err(|_| BackupPackagingError::ResourceLimit)?;
    if expected > maximum_length {
        return Err(BackupPackagingError::CorruptOrTampered);
    }
    let file = regular_file(path)?;
    if file
        .metadata()
        .map_err(|_| BackupPackagingError::SourceReadFailed)?
        .len()
        != expected_length
    {
        return Err(BackupPackagingError::SourceIdentityMismatch);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    file.take(expected_length.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BackupPackagingError::SourceReadFailed)?;
    if bytes.len() != expected {
        return Err(BackupPackagingError::SourceChanged);
    }
    Ok(bytes)
}

fn verify_structured_store(
    path: &Path,
    expected_length: u64,
    expected_sha256: [u8; 32],
    vrk: &OwnedKeyMaterial,
    vault_id: crate::vault::VaultId,
    generation: KeyGeneration,
) -> Result<(), BackupPackagingError> {
    let lease = VaultLease::new(VaultLeaseIdentity::new(vault_id, generation));
    let context = KeyDerivationContext::new(vault_id, generation, KeyPurpose::StructuredStore);
    let handle = open_sqlcipher_database(path, lease.keyed_handle_lease(), context, vrk)
        .map_err(BackupPackagingError::StructuredStoreOpen)?;
    handle
        .verify_integrity()
        .map_err(BackupPackagingError::StructuredStoreIntegrity)?;
    drop(handle);
    let identity = file_identity(path)?;
    if identity != (expected_length, expected_sha256) {
        return Err(BackupPackagingError::SourceChanged);
    }
    Ok(())
}

fn checked_chunk_count(length: u64) -> Result<u32, BackupPackagingError> {
    if length == 0 {
        return Err(BackupPackagingError::CorruptOrTampered);
    }
    let max = u64::try_from(BACKUP_CHUNK_PLAINTEXT_MAX)
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    let chunks = length
        .checked_add(max - 1)
        .ok_or(BackupPackagingError::ResourceLimit)?
        / max;
    u32::try_from(chunks).map_err(|_| BackupPackagingError::ResourceLimit)
}

fn fresh_unique_object_id(
    object_ids: &mut HashSet<BackupObjectId>,
) -> Result<BackupObjectId, BackupPackagingError> {
    for _ in 0..RANDOM_COLLISION_ATTEMPTS {
        let object_id = BackupObjectId::generate().map_err(map_codec_error)?;
        if object_ids.insert(object_id) {
            return Ok(object_id);
        }
    }
    Err(BackupPackagingError::RandomnessUnavailable)
}

struct PackagingState {
    set_id: BackupSetId,
    vault_id: crate::vault::VaultId,
    generation: KeyGeneration,
    staging_directory: PathBuf,
    next_object_index: usize,
    object_ids: HashSet<BackupObjectId>,
    object_nonces: HashSet<[u8; BACKUP_NONCE_BYTES]>,
    objects: Vec<DiskPreparedObject>,
}

impl PackagingState {
    fn new(
        set_id: BackupSetId,
        vault_id: crate::vault::VaultId,
        generation: KeyGeneration,
        staging_directory: PathBuf,
        expected_objects: usize,
    ) -> Result<Self, BackupPackagingError> {
        let mut object_ids = HashSet::new();
        object_ids
            .try_reserve(expected_objects)
            .map_err(|_| BackupPackagingError::ResourceLimit)?;
        let mut object_nonces = HashSet::new();
        object_nonces
            .try_reserve(expected_objects)
            .map_err(|_| BackupPackagingError::ResourceLimit)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(expected_objects)
            .map_err(|_| BackupPackagingError::ResourceLimit)?;
        Ok(Self {
            set_id,
            vault_id,
            generation,
            staging_directory,
            next_object_index: 0,
            object_ids,
            object_nonces,
            objects,
        })
    }

    fn write_chunk(
        &mut self,
        vrk: &OwnedKeyMaterial,
        plaintext: &[u8],
    ) -> Result<BackupIndexChunk, BackupPackagingError> {
        let object_id = fresh_unique_object_id(&mut self.object_ids)?;
        let context = BackupObjectContext {
            set_id: self.set_id,
            object_id,
            key_generation: self.generation,
        };
        for _ in 0..RANDOM_COLLISION_ATTEMPTS {
            let envelope = encrypt_backup_object(vrk, self.vault_id, context, plaintext)
                .map_err(map_codec_error)?;
            let nonce = backup_object_nonce(&envelope).map_err(map_codec_error)?;
            if !self.object_nonces.insert(nonce) {
                continue;
            }
            let index = self.next_object_index;
            let path = self
                .staging_directory
                .join(format!("object-{index:08x}.bin"));
            write_new_synced_file(&path, &envelope)?;
            let byte_length =
                u64::try_from(envelope.len()).map_err(|_| BackupPackagingError::ResourceLimit)?;
            self.objects.push(DiskPreparedObject {
                object_id,
                byte_length,
                sha256: Sha256::digest(&envelope).into(),
            });
            self.next_object_index = self
                .next_object_index
                .checked_add(1)
                .ok_or(BackupPackagingError::ResourceLimit)?;
            let plaintext_chunk_length =
                u32::try_from(plaintext.len()).map_err(|_| BackupPackagingError::ResourceLimit)?;
            return BackupIndexChunk::new(object_id, plaintext_chunk_length)
                .map_err(map_codec_error);
        }
        Err(BackupPackagingError::RandomnessUnavailable)
    }
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) -> Result<(), BackupPackagingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| BackupPackagingError::StagingWriteFailed)?;
    file.write_all(bytes)
        .map_err(|_| BackupPackagingError::StagingWriteFailed)?;
    file.sync_all()
        .map_err(|_| BackupPackagingError::StagingWriteFailed)
}

#[allow(clippy::too_many_arguments)]
fn package_payload<R: Read>(
    reader: &mut R,
    expected_length: u64,
    expected_sha256: [u8; 32],
    kind: BackupIndexPayloadKind,
    logical_id: [u8; 16],
    source_storage_id: [u8; 16],
    vrk: &OwnedKeyMaterial,
    state: &mut PackagingState,
) -> Result<BackupIndexPayload, BackupPackagingError> {
    let chunk_count = checked_chunk_count(expected_length)?;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(
            usize::try_from(chunk_count).map_err(|_| BackupPackagingError::ResourceLimit)?,
        )
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    let mut remaining = expected_length;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(BACKUP_CHUNK_PLAINTEXT_MAX)
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    buffer.resize(BACKUP_CHUNK_PLAINTEXT_MAX, 0);
    while remaining != 0 {
        let take = usize::try_from(remaining.min(BACKUP_CHUNK_PLAINTEXT_MAX as u64))
            .map_err(|_| BackupPackagingError::ResourceLimit)?;
        reader
            .read_exact(&mut buffer[..take])
            .map_err(|_| BackupPackagingError::SourceChanged)?;
        hasher.update(&buffer[..take]);
        chunks.push(state.write_chunk(vrk, &buffer[..take])?);
        remaining -= u64::try_from(take).map_err(|_| BackupPackagingError::ResourceLimit)?;
    }
    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .map_err(|_| BackupPackagingError::SourceReadFailed)?
        != 0
    {
        return Err(BackupPackagingError::SourceChanged);
    }
    if <[u8; 32]>::from(hasher.finalize()) != expected_sha256 {
        return Err(BackupPackagingError::SourceChanged);
    }
    BackupIndexPayload::new(
        kind,
        logical_id,
        source_storage_id,
        expected_length,
        expected_sha256,
        chunks,
    )
    .map_err(map_codec_error)
}

fn read_staged_object(
    path: &Path,
    expected_length: u64,
    expected_sha256: [u8; 32],
) -> Result<Vec<u8>, DiskBackupSourceError> {
    let expected =
        usize::try_from(expected_length).map_err(|_| DiskBackupSourceError::ResourceLimit)?;
    if expected > MAX_BACKUP_OBJECT_ENVELOPE_BYTES {
        return Err(DiskBackupSourceError::IdentityMismatch);
    }
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| DiskBackupSourceError::ReadFailed)?;
    if !path_metadata.file_type().is_file() || path_metadata.len() != expected_length {
        return Err(DiskBackupSourceError::IdentityMismatch);
    }
    let mut file = File::open(path).map_err(|_| DiskBackupSourceError::ReadFailed)?;
    if file
        .metadata()
        .map_err(|_| DiskBackupSourceError::ReadFailed)?
        .len()
        != expected_length
    {
        return Err(DiskBackupSourceError::IdentityMismatch);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| DiskBackupSourceError::ResourceLimit)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| DiskBackupSourceError::ReadFailed)?;
    if bytes.len() != expected || <[u8; 32]>::from(Sha256::digest(&bytes)) != expected_sha256 {
        return Err(DiskBackupSourceError::IdentityMismatch);
    }
    Ok(bytes)
}

pub fn prepare_disk_backed_backup_set(
    active_vrk: &OwnedKeyMaterial,
    recovery_envelope: &[u8],
    passphrase: &str,
    source_manifest_envelope: &[u8],
    source_files: &[BackupSourceFile],
    staging_directory: impl AsRef<Path>,
) -> Result<DiskPreparedBackupSet, BackupPackagingError> {
    let context = manifest_context(source_manifest_envelope)
        .map_err(|_| BackupPackagingError::CorruptOrTampered)?;
    let manifest = decrypt_manifest(active_vrk, context, source_manifest_envelope)
        .map_err(|_| BackupPackagingError::CorruptOrTampered)?;
    let active_generation = manifest.active_key_generation();
    if manifest.vault_id() != context.vault_id()
        || manifest.freshness_epoch() != context.freshness_epoch()
        || active_generation != context.key_generation()
        || manifest.rotation_phase() != RotationPhase::None
        || manifest.rotation_target_generation().is_some()
        || manifest
            .objects()
            .iter()
            .any(|object| object.key_generation() != active_generation)
    {
        return Err(BackupPackagingError::BackupStateNotStable);
    }

    let payload_count = manifest
        .objects()
        .len()
        .checked_add(1)
        .ok_or(BackupPackagingError::ResourceLimit)?;
    if payload_count > BACKUP_INDEX_PAYLOAD_COUNT_MAX as usize {
        return Err(BackupPackagingError::ResourceLimit);
    }

    let set_id = BackupSetId::generate().map_err(map_codec_error)?;
    let recovery_context = RecoveryContext::new(manifest.vault_id(), active_generation);
    let bootstrap = create_backup_recovery_bootstrap(
        active_vrk,
        recovery_context,
        recovery_envelope,
        passphrase,
        set_id,
    )
    .map_err(map_bootstrap_error)?;

    let mut source_by_storage = HashMap::new();
    source_by_storage
        .try_reserve(source_files.len())
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    for source in source_files {
        if source_by_storage
            .insert(source.storage_id, source)
            .is_some()
        {
            return Err(BackupPackagingError::SourceMapMismatch);
        }
    }
    if source_by_storage.len() != manifest.objects().len() {
        return Err(BackupPackagingError::SourceMapMismatch);
    }

    let mut structured_store: Option<(&ManifestObject, &PathBuf, u64, [u8; 32])> = None;
    let mut generic_artifacts = Vec::new();
    generic_artifacts
        .try_reserve(manifest.objects().len())
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    let mut expected_object_count = checked_chunk_count(
        u64::try_from(source_manifest_envelope.len())
            .map_err(|_| BackupPackagingError::ResourceLimit)?,
    )?;

    for object in manifest.objects() {
        let source = source_by_storage
            .get(&object.storage_id())
            .copied()
            .ok_or(BackupPackagingError::SourceMapMismatch)?;
        let path = &source.path;
        let identity = file_identity(path)?;
        let payload_length = match (object.kind(), object.auth_metadata(), &source.verification) {
            (
                ManifestObjectKind::StructuredStore,
                ManifestAuthMetadata::StructuredStore,
                BackupSourceVerification::ManifestExact,
            ) => {
                if identity != (object.ciphertext_length(), object.ciphertext_sha256()) {
                    return Err(BackupPackagingError::SourceIdentityMismatch);
                }
                if structured_store
                    .replace((object, path, identity.0, identity.1))
                    .is_some()
                {
                    return Err(BackupPackagingError::CorruptOrTampered);
                }
                identity.0
            }
            (
                ManifestObjectKind::StructuredStore,
                ManifestAuthMetadata::StructuredStore,
                BackupSourceVerification::SqlCipherSnapshot {
                    source_precheckpoint_byte_length,
                    source_precheckpoint_sha256,
                    snapshot_byte_length,
                    snapshot_sha256,
                },
            ) => {
                if (
                    *source_precheckpoint_byte_length,
                    *source_precheckpoint_sha256,
                ) != (object.ciphertext_length(), object.ciphertext_sha256())
                    || (*snapshot_byte_length, *snapshot_sha256) != identity
                {
                    return Err(BackupPackagingError::SourceIdentityMismatch);
                }
                if structured_store
                    .replace((object, path, identity.0, identity.1))
                    .is_some()
                {
                    return Err(BackupPackagingError::CorruptOrTampered);
                }
                identity.0
            }
            (
                ManifestObjectKind::GenericArtifactBlob,
                ManifestAuthMetadata::GenericArtifactBlob { nonce },
                BackupSourceVerification::ManifestExact,
            ) => {
                if identity != (object.ciphertext_length(), object.ciphertext_sha256()) {
                    return Err(BackupPackagingError::SourceIdentityMismatch);
                }
                let envelope = read_exact_bounded_file(
                    path,
                    object.ciphertext_length(),
                    BOUNDED_BLOB_MAX_ENVELOPE_BYTES,
                )?;
                if <[u8; 32]>::from(Sha256::digest(&envelope)) != object.ciphertext_sha256()
                    || bounded_blob_nonce(&envelope)
                        .map_err(|_| BackupPackagingError::CorruptOrTampered)?
                        != nonce
                {
                    return Err(BackupPackagingError::CorruptOrTampered);
                }
                let blob_context = BoundedBlobContext::new(
                    manifest.vault_id(),
                    object.logical_id(),
                    active_generation,
                );
                let mut plaintext = decrypt_bounded_blob(active_vrk, blob_context, &envelope)
                    .map_err(|_| BackupPackagingError::CorruptOrTampered)?;
                plaintext.zeroize();
                generic_artifacts.push((object, path));
                object.ciphertext_length()
            }
            _ => return Err(BackupPackagingError::CorruptOrTampered),
        };
        expected_object_count = expected_object_count
            .checked_add(checked_chunk_count(payload_length)?)
            .ok_or(BackupPackagingError::ResourceLimit)?;
        if expected_object_count > BACKUP_DATA_OBJECT_COUNT_MAX {
            return Err(BackupPackagingError::ResourceLimit);
        }
    }

    let (structured_object, structured_path, structured_length, structured_sha256) =
        structured_store.ok_or(BackupPackagingError::CorruptOrTampered)?;
    verify_structured_store(
        structured_path,
        structured_length,
        structured_sha256,
        active_vrk,
        manifest.vault_id(),
        active_generation,
    )?;
    generic_artifacts.sort_by_key(|(object, _)| object.logical_id());

    let staging_directory = staging_directory.as_ref().to_path_buf();
    std::fs::create_dir(&staging_directory)
        .map_err(|_| BackupPackagingError::StagingWriteFailed)?;
    let expected_objects =
        usize::try_from(expected_object_count).map_err(|_| BackupPackagingError::ResourceLimit)?;
    let mut state = PackagingState::new(
        set_id,
        manifest.vault_id(),
        active_generation,
        staging_directory.clone(),
        expected_objects,
    )?;
    let mut payloads = Vec::new();
    payloads
        .try_reserve_exact(payload_count)
        .map_err(|_| BackupPackagingError::ResourceLimit)?;

    let manifest_length = u64::try_from(source_manifest_envelope.len())
        .map_err(|_| BackupPackagingError::ResourceLimit)?;
    let manifest_sha256 = manifest_hash(source_manifest_envelope).into_bytes();
    payloads.push(package_payload(
        &mut Cursor::new(source_manifest_envelope),
        manifest_length,
        manifest_sha256,
        BackupIndexPayloadKind::Manifest,
        [0_u8; 16],
        [0_u8; 16],
        active_vrk,
        &mut state,
    )?);

    let mut structured_reader = regular_file(structured_path)?;
    payloads.push(package_payload(
        &mut structured_reader,
        structured_length,
        structured_sha256,
        BackupIndexPayloadKind::StructuredStore,
        [0_u8; 16],
        structured_object.storage_id(),
        active_vrk,
        &mut state,
    )?);

    for (object, path) in generic_artifacts {
        let mut reader = regular_file(path)?;
        payloads.push(package_payload(
            &mut reader,
            object.ciphertext_length(),
            object.ciphertext_sha256(),
            BackupIndexPayloadKind::GenericArtifactBlob,
            object.logical_id(),
            object.storage_id(),
            active_vrk,
            &mut state,
        )?);
    }

    if state.objects.len() != expected_objects {
        return Err(BackupPackagingError::CorruptOrTampered);
    }
    let index = BackupIndexPlaintext::new(
        manifest.vault_id(),
        active_generation,
        manifest.freshness_epoch(),
        manifest_hash(source_manifest_envelope),
        payloads,
    )
    .map_err(map_codec_error)?;
    let index_context = BackupIndexContext::new(set_id, active_generation, expected_object_count)
        .map_err(map_codec_error)?;
    let encrypted_index = encrypt_backup_index(
        active_vrk,
        manifest.vault_id(),
        index_context,
        bootstrap.slot(),
        &index,
    )
    .map_err(map_codec_error)?;
    let descriptor = BackupSetDescriptor::new(
        set_id,
        active_generation,
        expected_object_count,
        *bootstrap.salt(),
        *bootstrap.nonce(),
        *bootstrap.slot(),
        *encrypted_index.nonce(),
        encrypted_index.ciphertext_and_tag().to_vec(),
    )
    .map_err(map_codec_error)?;
    let descriptor_bytes = encode_set_descriptor(&descriptor).map_err(map_codec_error)?;
    write_new_synced_file(
        &staging_directory.join(DESCRIPTOR_FILENAME),
        &descriptor_bytes,
    )?;

    Ok(DiskPreparedBackupSet {
        descriptor_bytes,
        staging_directory,
        objects: state.objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{FreshnessEpoch, ManifestHash, VaultId, VaultLeaseIdentity};
    use crate::vault_backup::parse_set_descriptor;
    use crate::vault_manifest::{
        GenerationState, ManifestContext, ManifestGeneration, ManifestObject, ManifestPlaintext,
        encrypt_fresh_manifest,
    };
    use crate::vault_nonce::NonceReservationLedger;
    use crate::vault_recovery::encrypt_recovery_envelope;
    use crate::vault_sqlcipher::{
        BackupSnapshotQuiescenceGuard, snapshot_quiesced_sqlcipher_database,
    };
    use rusqlite::Connection;
    use std::convert::Infallible;
    use std::fmt::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn vault_id() -> VaultId {
        VaultId::from_bytes([0x21; 16])
    }

    fn generation() -> KeyGeneration {
        KeyGeneration::new(7).unwrap()
    }

    fn unused_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "safeevidence-b505l-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn raw_key_pragma(vrk: &OwnedKeyMaterial) -> String {
        let context =
            KeyDerivationContext::new(vault_id(), generation(), KeyPurpose::StructuredStore);
        let key = context.derive_purpose_key(vrk);
        key.with_bytes(|bytes| {
            let mut hex = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                write!(&mut hex, "{byte:02x}").unwrap();
            }
            format!("PRAGMA key = \"x'{hex}'\";")
        })
    }

    fn create_sqlcipher(path: &Path, vrk: &OwnedKeyMaterial) {
        let connection = Connection::open(path).unwrap();
        connection.execute_batch(&raw_key_pragma(vrk)).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE backup_probe (value INTEGER NOT NULL); INSERT INTO backup_probe VALUES (41);",
            )
            .unwrap();
        drop(connection);
    }

    fn fixture_manifest(vrk: &OwnedKeyMaterial, objects: Vec<ManifestObject>) -> Vec<u8> {
        let epoch = FreshnessEpoch::new(9).unwrap();
        let plaintext = ManifestPlaintext::new(
            vault_id(),
            epoch,
            ManifestHash::from_bytes([0x91_u8; 32]),
            generation(),
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(
                generation(),
                GenerationState::Active,
            )],
            objects,
        )
        .unwrap();
        let mut ledger = NonceReservationLedger::new(vault_id());
        encrypt_fresh_manifest(
            &mut ledger,
            vrk,
            ManifestContext::new(vault_id(), generation(), epoch),
            &plaintext,
        )
        .unwrap()
        .1
    }

    struct QuiescedSnapshotGuard;

    impl BackupSnapshotQuiescenceGuard for QuiescedSnapshotGuard {
        type Error = Infallible;

        fn assert_normal_writes_quiesced(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn wal_checkpoint_snapshot_is_bound_to_precheckpoint_manifest_identity() {
        let key = OwnedKeyMaterial::from_bytes([0x32; 32]);
        let source = unused_path("wal-binding-source.sqlite3");
        let snapshot_path = unused_path("wal-binding-snapshot.sqlite3");
        let staging = unused_path("wal-binding-staging");
        let storage_id = [0x71; 16];

        let connection = Connection::open(&source).unwrap();
        connection.execute_batch(&raw_key_pragma(&key)).unwrap();
        connection
            .execute_batch("CREATE TABLE wal_binding_probe (value INTEGER NOT NULL);")
            .unwrap();
        let mode = connection
            .query_row("PRAGMA journal_mode = WAL;", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap();
        assert_eq!(mode, "wal");
        connection
            .execute_batch("PRAGMA wal_autocheckpoint = 0; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        let precheckpoint_identity = file_identity(&source).unwrap();
        let manifest = fixture_manifest(
            &key,
            vec![ManifestObject::new(
                [0_u8; 16],
                storage_id,
                generation(),
                precheckpoint_identity.0,
                precheckpoint_identity.1,
                ManifestAuthMetadata::StructuredStore,
            )],
        );
        connection
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO wal_binding_probe VALUES (42); COMMIT;")
            .unwrap();
        let wal = PathBuf::from(format!("{}-wal", source.display()));
        assert!(std::fs::metadata(&wal).unwrap().len() > 0);

        let lease = VaultLease::new(VaultLeaseIdentity::new(vault_id(), generation()));
        let context =
            KeyDerivationContext::new(vault_id(), generation(), KeyPurpose::StructuredStore);
        let mut guard = QuiescedSnapshotGuard;
        let snapshot = snapshot_quiesced_sqlcipher_database(
            &mut guard,
            &source,
            &snapshot_path,
            lease.keyed_handle_lease(),
            context,
            &key,
        )
        .unwrap();
        assert_eq!(
            (
                snapshot.source_precheckpoint_byte_length(),
                snapshot.source_precheckpoint_sha256(),
            ),
            precheckpoint_identity,
        );
        assert_ne!(
            (snapshot.byte_length(), snapshot.sha256()),
            precheckpoint_identity,
        );

        let recovery = encrypt_recovery_envelope(
            &key,
            RecoveryContext::new(vault_id(), generation()),
            "correct horse battery staple",
        )
        .unwrap();
        let mut wrong_precheckpoint_sha = precheckpoint_identity.1;
        wrong_precheckpoint_sha[0] ^= 1;
        let wrong_manifest = fixture_manifest(
            &key,
            vec![ManifestObject::new(
                [0_u8; 16],
                storage_id,
                generation(),
                precheckpoint_identity.0,
                wrong_precheckpoint_sha,
                ManifestAuthMetadata::StructuredStore,
            )],
        );
        let rejected_staging = unused_path("wal-binding-rejected-staging");
        assert!(matches!(
            prepare_disk_backed_backup_set(
                &key,
                &recovery,
                "correct horse battery staple",
                &wrong_manifest,
                &[BackupSourceFile::from_sqlcipher_snapshot(
                    storage_id, &snapshot,
                )],
                &rejected_staging,
            ),
            Err(BackupPackagingError::SourceIdentityMismatch)
        ));
        assert!(!rejected_staging.exists());

        let mut prepared = prepare_disk_backed_backup_set(
            &key,
            &recovery,
            "correct horse battery staple",
            &manifest,
            &[BackupSourceFile::from_sqlcipher_snapshot(
                storage_id, &snapshot,
            )],
            &staging,
        )
        .unwrap();
        parse_set_descriptor(prepared.descriptor_bytes()).unwrap();
        for index in 0..prepared.object_count() {
            assert!(!prepared.read_object(index).unwrap().is_empty());
        }

        drop(connection);
        std::fs::remove_dir_all(staging).unwrap();
        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(snapshot_path);
    }

    #[test]
    fn blob_authentication_is_required_even_when_manifest_hash_matches() {
        let key = OwnedKeyMaterial::from_bytes([0x31; 32]);
        let sqlcipher_path = unused_path("blob-source.sqlite3");
        create_sqlcipher(&sqlcipher_path, &key);
        let (db_len, db_sha) = file_identity(&sqlcipher_path).unwrap();
        let db_storage = [0x62; 16];
        let blob_storage = [0x63; 16];
        let blob_id = [0x64; 16];
        let blob_nonce = [0x65; 24];
        let valid_blob = crate::vault_blob::encrypt_bounded_blob(
            &key,
            BoundedBlobContext::new(vault_id(), blob_id, generation()),
            blob_nonce,
            b"authenticated source blob",
        )
        .unwrap();
        let mut blob = valid_blob.clone();
        *blob.last_mut().unwrap() ^= 1;
        let blob_path = unused_path("blob.bin");
        std::fs::write(&blob_path, &blob).unwrap();
        let blob_len = u64::try_from(blob.len()).unwrap();
        let blob_sha: [u8; 32] = Sha256::digest(&blob).into();
        let manifest = fixture_manifest(
            &key,
            vec![
                ManifestObject::new(
                    blob_id,
                    blob_storage,
                    generation(),
                    blob_len,
                    blob_sha,
                    ManifestAuthMetadata::GenericArtifactBlob { nonce: blob_nonce },
                ),
                ManifestObject::new(
                    [0_u8; 16],
                    db_storage,
                    generation(),
                    db_len,
                    db_sha,
                    ManifestAuthMetadata::StructuredStore,
                ),
            ],
        );
        let recovery = encrypt_recovery_envelope(
            &key,
            RecoveryContext::new(vault_id(), generation()),
            "correct horse battery staple",
        )
        .unwrap();
        let staging = unused_path("blob-staging");
        assert!(matches!(
            prepare_disk_backed_backup_set(
                &key,
                &recovery,
                "correct horse battery staple",
                &manifest,
                &[
                    BackupSourceFile::new(blob_storage, &blob_path),
                    BackupSourceFile::new(db_storage, &sqlcipher_path),
                ],
                &staging,
            ),
            Err(BackupPackagingError::CorruptOrTampered)
        ));
        assert!(!staging.exists());

        std::fs::write(&blob_path, &valid_blob).unwrap();
        let valid_manifest = fixture_manifest(
            &key,
            vec![
                ManifestObject::new(
                    blob_id,
                    blob_storage,
                    generation(),
                    valid_blob.len() as u64,
                    Sha256::digest(&valid_blob).into(),
                    ManifestAuthMetadata::GenericArtifactBlob { nonce: blob_nonce },
                ),
                ManifestObject::new(
                    [0_u8; 16],
                    db_storage,
                    generation(),
                    db_len,
                    db_sha,
                    ManifestAuthMetadata::StructuredStore,
                ),
            ],
        );
        let accepted = unused_path("accepted");
        let mut prepared = prepare_disk_backed_backup_set(
            &key,
            &recovery,
            "correct horse battery staple",
            &valid_manifest,
            &[
                BackupSourceFile::new(blob_storage, &blob_path),
                BackupSourceFile::new(db_storage, &sqlcipher_path),
            ],
            &accepted,
        )
        .unwrap();
        parse_set_descriptor(prepared.descriptor_bytes()).unwrap();
        for index in 0..prepared.object_count() {
            assert!(!prepared.read_object(index).unwrap().is_empty());
        }
        assert!(accepted.join(DESCRIPTOR_FILENAME).is_file());
        std::fs::remove_dir_all(accepted).unwrap();
        std::fs::remove_file(blob_path).unwrap();
        std::fs::remove_file(sqlcipher_path).unwrap();
    }
}

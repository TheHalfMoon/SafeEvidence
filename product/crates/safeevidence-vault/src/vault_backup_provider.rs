use crate::vault_backup::{
    BackupCodecError, BackupObjectContext, BackupObjectId, BackupSetDescriptor, BackupSetId,
    descriptor_provider_key, encode_set_descriptor, object_provider_key, parse_set_descriptor,
    validate_backup_object_binding, validate_descriptor_binding,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Provider operations required by the B505 immutable publication boundary.
///
/// `put_if_absent` MUST never overwrite an existing key. An ambiguous provider
/// acknowledgement is represented as `Err`; callers must not upgrade that set
/// to accepted state even if the remote side may have persisted the bytes.
pub trait PortableBackupProvider {
    type Error;

    fn put_if_absent(&mut self, key: &str, bytes: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, key: &str) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBackupObject {
    object_id: BackupObjectId,
    envelope: Vec<u8>,
}

impl PreparedBackupObject {
    #[must_use]
    pub fn new(object_id: BackupObjectId, envelope: Vec<u8>) -> Self {
        Self {
            object_id,
            envelope,
        }
    }

    #[must_use]
    pub const fn object_id(&self) -> BackupObjectId {
        self.object_id
    }

    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBackupSet {
    descriptor: BackupSetDescriptor,
    descriptor_bytes: Vec<u8>,
    objects: Vec<PreparedBackupObject>,
}

impl PreparedBackupSet {
    pub fn new(
        descriptor_bytes: Vec<u8>,
        objects: Vec<PreparedBackupObject>,
    ) -> Result<Self, BackupCodecError> {
        let descriptor = parse_set_descriptor(&descriptor_bytes)?;
        let value = Self {
            descriptor,
            descriptor_bytes,
            objects,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), BackupCodecError> {
        let expected_count = usize::try_from(self.descriptor.data_object_count())
            .map_err(|_| BackupCodecError::CorruptOrTampered)?;
        if self.objects.len() != expected_count {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let descriptor_key = descriptor_provider_key(self.descriptor.set_id());
        validate_descriptor_binding(&descriptor_key, &self.descriptor)?;
        if encode_set_descriptor(&self.descriptor)? != self.descriptor_bytes {
            return Err(BackupCodecError::CorruptOrTampered);
        }
        let mut object_ids = HashSet::with_capacity(self.objects.len());
        for object in &self.objects {
            if !object_ids.insert(object.object_id) {
                return Err(BackupCodecError::CorruptOrTampered);
            }
            let context = BackupObjectContext {
                set_id: self.descriptor.set_id(),
                object_id: object.object_id,
                key_generation: self.descriptor.key_generation(),
            };
            let key = object_provider_key(self.descriptor.set_id(), object.object_id);
            validate_backup_object_binding(&key, context, &object.envelope)?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn set_id(&self) -> BackupSetId {
        self.descriptor.set_id()
    }

    #[must_use]
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    #[must_use]
    pub fn objects(&self) -> &[PreparedBackupObject] {
        &self.objects
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupPublicationError<E> {
    CorruptOrTampered,
    Provider(E),
}

impl<E> From<BackupCodecError> for BackupPublicationError<E> {
    fn from(_: BackupCodecError) -> Self {
        Self::CorruptOrTampered
    }
}

/// Proof returned only after descriptor-last publication and exact provider reread.
///
/// This is transport/publication proof only. It is deliberately not local backup
/// acceptance: B505 must still authenticate the bootstrap/index, reconstruct every
/// payload, and verify the canonical inner formats before any set can be accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RereadVerifiedBackupPublication {
    set_id: BackupSetId,
    data_object_count: u32,
}

impl RereadVerifiedBackupPublication {
    #[must_use]
    pub const fn set_id(&self) -> BackupSetId {
        self.set_id
    }

    #[must_use]
    pub const fn data_object_count(&self) -> u32 {
        self.data_object_count
    }
}

pub fn publish_and_reread_prepared_backup_set<P: PortableBackupProvider>(
    provider: &mut P,
    candidate: &PreparedBackupSet,
) -> Result<RereadVerifiedBackupPublication, BackupPublicationError<P::Error>> {
    candidate.validate()?;
    let set_id = candidate.descriptor.set_id();

    // Data objects are published before the reserved descriptor leaf. A caller
    // cannot obtain reread proof while any object is missing or ambiguous.
    for object in &candidate.objects {
        let key = object_provider_key(set_id, object.object_id);
        provider
            .put_if_absent(&key, &object.envelope)
            .map_err(BackupPublicationError::Provider)?;
    }

    // The descriptor is the final provider-visible write for a candidate set.
    let descriptor_key = descriptor_provider_key(set_id);
    provider
        .put_if_absent(&descriptor_key, &candidate.descriptor_bytes)
        .map_err(BackupPublicationError::Provider)?;

    // Acceptance requires a full exact-byte reread after every write, including
    // descriptor publication. Transport acknowledgement alone is insufficient.
    for object in &candidate.objects {
        let key = object_provider_key(set_id, object.object_id);
        let reread = provider
            .read(&key)
            .map_err(BackupPublicationError::Provider)?;
        if reread != object.envelope {
            return Err(BackupPublicationError::CorruptOrTampered);
        }
        let context = BackupObjectContext {
            set_id,
            object_id: object.object_id,
            key_generation: candidate.descriptor.key_generation(),
        };
        validate_backup_object_binding(&key, context, &reread)?;
    }
    let descriptor_reread = provider
        .read(&descriptor_key)
        .map_err(BackupPublicationError::Provider)?;
    if descriptor_reread != candidate.descriptor_bytes {
        return Err(BackupPublicationError::CorruptOrTampered);
    }
    let parsed = parse_set_descriptor(&descriptor_reread)?;
    validate_descriptor_binding(&descriptor_key, &parsed)?;
    if parsed != candidate.descriptor {
        return Err(BackupPublicationError::CorruptOrTampered);
    }

    Ok(RereadVerifiedBackupPublication {
        set_id,
        data_object_count: candidate.descriptor.data_object_count(),
    })
}

/// Multi-pass source for a prepared backup whose object envelopes may live outside RAM.
///
/// Implementations must expose a stable ordered object sequence for the duration of
/// one publication attempt. The publication boundary independently fingerprints and
/// revalidates every object before any provider-visible descriptor can be accepted.
pub trait PreparedBackupObjectSource {
    type Error;

    fn object_count(&self) -> usize;
    fn object_id(&mut self, index: usize) -> Result<BackupObjectId, Self::Error>;
    fn read_object(&mut self, index: usize) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub enum StreamingBackupPublicationError<ProviderError, SourceError> {
    CorruptOrTampered,
    ResourceLimit,
    Provider(ProviderError),
    Source(SourceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedObjectFingerprint {
    object_id: BackupObjectId,
    byte_length: u64,
    sha256: [u8; 32],
}

fn object_fingerprint(object_id: BackupObjectId, envelope: &[u8]) -> PreparedObjectFingerprint {
    PreparedObjectFingerprint {
        object_id,
        byte_length: u64::try_from(envelope.len())
            .expect("usize always fits in u64 on supported targets"),
        sha256: Sha256::digest(envelope).into(),
    }
}

fn matches_fingerprint(
    fingerprint: PreparedObjectFingerprint,
    object_id: BackupObjectId,
    envelope: &[u8],
) -> bool {
    fingerprint.object_id == object_id
        && fingerprint.byte_length == u64::try_from(envelope.len()).unwrap_or(u64::MAX)
        && fingerprint.sha256 == <[u8; 32]>::from(Sha256::digest(envelope))
}

fn validate_streamed_object<ProviderError, SourceError>(
    descriptor: &BackupSetDescriptor,
    object_id: BackupObjectId,
    envelope: &[u8],
) -> Result<(), StreamingBackupPublicationError<ProviderError, SourceError>> {
    let context = BackupObjectContext {
        set_id: descriptor.set_id(),
        object_id,
        key_generation: descriptor.key_generation(),
    };
    let key = object_provider_key(descriptor.set_id(), object_id);
    validate_backup_object_binding(&key, context, envelope)
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)
}

/// Publishes an immutable backup from a stable multi-pass object source without
/// retaining every encrypted object envelope in memory at once.
///
/// The complete source is validated before the first provider write. Each object
/// is fingerprinted during that preflight, then reloaded and revalidated before
/// upload. The reserved descriptor leaf is written last. After descriptor
/// publication every object is loaded a third time, checked against its frozen
/// preflight fingerprint, compared byte-for-byte with the provider reread, and
/// binding-validated again. Any source instability, partial write, ambiguous
/// acknowledgement, or reread mismatch leaves the set without acceptance proof.
pub fn publish_and_reread_backup_source<P, S>(
    provider: &mut P,
    descriptor_bytes: &[u8],
    source: &mut S,
) -> Result<RereadVerifiedBackupPublication, StreamingBackupPublicationError<P::Error, S::Error>>
where
    P: PortableBackupProvider,
    S: PreparedBackupObjectSource,
{
    let descriptor = parse_set_descriptor(descriptor_bytes)
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)?;
    let descriptor_key = descriptor_provider_key(descriptor.set_id());
    validate_descriptor_binding(&descriptor_key, &descriptor)
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)?;
    if encode_set_descriptor(&descriptor)
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)?
        != descriptor_bytes
    {
        return Err(StreamingBackupPublicationError::CorruptOrTampered);
    }

    let expected_count = usize::try_from(descriptor.data_object_count())
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)?;
    if source.object_count() != expected_count {
        return Err(StreamingBackupPublicationError::CorruptOrTampered);
    }

    // Complete preflight before the first provider-visible write.
    let mut seen = HashSet::new();
    seen.try_reserve(expected_count)
        .map_err(|_| StreamingBackupPublicationError::ResourceLimit)?;
    let mut fingerprints = Vec::new();
    fingerprints
        .try_reserve_exact(expected_count)
        .map_err(|_| StreamingBackupPublicationError::ResourceLimit)?;
    for index in 0..expected_count {
        let object_id = source
            .object_id(index)
            .map_err(StreamingBackupPublicationError::Source)?;
        if !seen.insert(object_id) {
            return Err(StreamingBackupPublicationError::CorruptOrTampered);
        }
        let envelope = source
            .read_object(index)
            .map_err(StreamingBackupPublicationError::Source)?;
        validate_streamed_object::<P::Error, S::Error>(&descriptor, object_id, &envelope)?;
        fingerprints.push(object_fingerprint(object_id, &envelope));
    }

    // Re-read each frozen source object immediately before upload. A source that
    // changed after preflight fails before that changed object can be written.
    for (index, fingerprint) in fingerprints.iter().copied().enumerate() {
        let object_id = source
            .object_id(index)
            .map_err(StreamingBackupPublicationError::Source)?;
        let envelope = source
            .read_object(index)
            .map_err(StreamingBackupPublicationError::Source)?;
        if !matches_fingerprint(fingerprint, object_id, &envelope) {
            return Err(StreamingBackupPublicationError::CorruptOrTampered);
        }
        validate_streamed_object::<P::Error, S::Error>(&descriptor, object_id, &envelope)?;
        let key = object_provider_key(descriptor.set_id(), object_id);
        provider
            .put_if_absent(&key, &envelope)
            .map_err(StreamingBackupPublicationError::Provider)?;
    }

    // Cardinality is part of the frozen source contract as well as descriptor
    // binding. Detect insertions/removals that occurred after preflight before
    // the reserved descriptor leaf becomes provider-visible.
    if source.object_count() != expected_count {
        return Err(StreamingBackupPublicationError::CorruptOrTampered);
    }

    provider
        .put_if_absent(&descriptor_key, descriptor_bytes)
        .map_err(StreamingBackupPublicationError::Provider)?;

    // Descriptor-last publication is not sufficient: prove exact provider bytes
    // against the same frozen source after every provider-visible write completed.
    for (index, fingerprint) in fingerprints.iter().copied().enumerate() {
        let object_id = source
            .object_id(index)
            .map_err(StreamingBackupPublicationError::Source)?;
        let envelope = source
            .read_object(index)
            .map_err(StreamingBackupPublicationError::Source)?;
        if !matches_fingerprint(fingerprint, object_id, &envelope) {
            return Err(StreamingBackupPublicationError::CorruptOrTampered);
        }
        validate_streamed_object::<P::Error, S::Error>(&descriptor, object_id, &envelope)?;
        let key = object_provider_key(descriptor.set_id(), object_id);
        let reread = provider
            .read(&key)
            .map_err(StreamingBackupPublicationError::Provider)?;
        if reread != envelope {
            return Err(StreamingBackupPublicationError::CorruptOrTampered);
        }
        validate_streamed_object::<P::Error, S::Error>(&descriptor, object_id, &reread)?;
    }

    let descriptor_reread = provider
        .read(&descriptor_key)
        .map_err(StreamingBackupPublicationError::Provider)?;
    if descriptor_reread != descriptor_bytes {
        return Err(StreamingBackupPublicationError::CorruptOrTampered);
    }
    let parsed = parse_set_descriptor(&descriptor_reread)
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)?;
    validate_descriptor_binding(&descriptor_key, &parsed)
        .map_err(|_| StreamingBackupPublicationError::CorruptOrTampered)?;
    if parsed != descriptor {
        return Err(StreamingBackupPublicationError::CorruptOrTampered);
    }

    Ok(RereadVerifiedBackupPublication {
        set_id: descriptor.set_id(),
        data_object_count: descriptor.data_object_count(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{KeyGeneration, VaultId};
    use crate::vault_backup::{
        BACKUP_BOOTSTRAP_SLOT_BYTES, BACKUP_NONCE_BYTES, BackupObjectContext, BackupSetDescriptor,
        encode_set_descriptor, encrypt_backup_object,
    };
    use crate::vault_keys::OwnedKeyMaterial;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ProviderError {
        Exists,
        Failed,
        Missing,
    }

    #[derive(Default)]
    struct MemoryProvider {
        bytes: BTreeMap<String, Vec<u8>>,
        operations: Vec<String>,
        fail_write_key: Option<String>,
        ambiguous_write_key: Option<String>,
        corrupt_read_key: Option<String>,
    }

    impl PortableBackupProvider for MemoryProvider {
        type Error = ProviderError;

        fn put_if_absent(&mut self, key: &str, bytes: &[u8]) -> Result<(), Self::Error> {
            self.operations.push(format!("put:{key}"));
            if self.bytes.contains_key(key) {
                return Err(ProviderError::Exists);
            }
            if self.ambiguous_write_key.as_deref() == Some(key) {
                self.bytes.insert(key.to_owned(), bytes.to_vec());
                return Err(ProviderError::Failed);
            }
            if self.fail_write_key.as_deref() == Some(key) {
                return Err(ProviderError::Failed);
            }
            self.bytes.insert(key.to_owned(), bytes.to_vec());
            Ok(())
        }

        fn read(&mut self, key: &str) -> Result<Vec<u8>, Self::Error> {
            self.operations.push(format!("read:{key}"));
            let mut value = self.bytes.get(key).cloned().ok_or(ProviderError::Missing)?;
            if self.corrupt_read_key.as_deref() == Some(key) {
                value[0] ^= 1;
            }
            Ok(value)
        }
    }

    fn fixture_for_set(set_bytes: [u8; 16]) -> PreparedBackupSet {
        let vrk = OwnedKeyMaterial::from_bytes([7; 32]);
        let vault_id = VaultId::from_bytes([8; 16]);
        let set_id = BackupSetId::from_bytes(set_bytes).unwrap();
        let generation = KeyGeneration::new(3).unwrap();
        let object_ids = [
            BackupObjectId::from_bytes([10; 16]).unwrap(),
            BackupObjectId::from_bytes([11; 16]).unwrap(),
        ];
        let objects = object_ids
            .iter()
            .enumerate()
            .map(|(index, object_id)| {
                let context = BackupObjectContext {
                    set_id,
                    object_id: *object_id,
                    key_generation: generation,
                };
                PreparedBackupObject::new(
                    *object_id,
                    encrypt_backup_object(
                        &vrk,
                        vault_id,
                        context,
                        format!("payload-{index}").as_bytes(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let descriptor = BackupSetDescriptor::new(
            set_id,
            generation,
            2,
            [12; 16],
            [13; BACKUP_NONCE_BYTES],
            [14; BACKUP_BOOTSTRAP_SLOT_BYTES],
            [15; BACKUP_NONCE_BYTES],
            vec![16; 16],
        )
        .unwrap();
        PreparedBackupSet::new(encode_set_descriptor(&descriptor).unwrap(), objects).unwrap()
    }

    fn fixture() -> PreparedBackupSet {
        fixture_for_set([9; 16])
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum SourceError {
        Failed,
    }

    struct StreamingSource {
        objects: Vec<PreparedBackupObject>,
        reads: Vec<usize>,
        fail_read: Option<(usize, usize)>,
        mutate_read: Option<(usize, usize)>,
        reported_count_after_reads: Option<(usize, usize)>,
    }

    impl StreamingSource {
        fn from_candidate(candidate: &PreparedBackupSet) -> Self {
            Self {
                objects: candidate.objects.clone(),
                reads: Vec::new(),
                fail_read: None,
                mutate_read: None,
                reported_count_after_reads: None,
            }
        }
    }

    impl PreparedBackupObjectSource for StreamingSource {
        type Error = SourceError;

        fn object_count(&self) -> usize {
            self.reported_count_after_reads
                .filter(|(reads, _)| self.reads.len() >= *reads)
                .map_or(self.objects.len(), |(_, count)| count)
        }

        fn object_id(&mut self, index: usize) -> Result<BackupObjectId, Self::Error> {
            self.objects
                .get(index)
                .map(|object| object.object_id())
                .ok_or(SourceError::Failed)
        }

        fn read_object(&mut self, index: usize) -> Result<Vec<u8>, Self::Error> {
            let ordinal = self.reads.iter().filter(|seen| **seen == index).count() + 1;
            self.reads.push(index);
            if self.fail_read == Some((index, ordinal)) {
                return Err(SourceError::Failed);
            }
            let mut envelope = self
                .objects
                .get(index)
                .map(|object| object.envelope().to_vec())
                .ok_or(SourceError::Failed)?;
            if self.mutate_read == Some((index, ordinal)) {
                envelope[0] ^= 1;
            }
            Ok(envelope)
        }
    }

    #[test]
    fn streaming_publication_preflights_all_objects_before_provider_write() {
        let candidate = fixture();
        let mut source = StreamingSource::from_candidate(&candidate);
        source.fail_read = Some((1, 1));
        let mut provider = MemoryProvider::default();
        assert!(matches!(
            publish_and_reread_backup_source(
                &mut provider,
                candidate.descriptor_bytes(),
                &mut source
            ),
            Err(StreamingBackupPublicationError::Source(SourceError::Failed))
        ));
        assert!(provider.operations.is_empty());
        assert!(provider.bytes.is_empty());
    }

    #[test]
    fn streaming_publication_detects_source_change_before_descriptor() {
        let candidate = fixture();
        let descriptor_key = descriptor_provider_key(candidate.set_id());
        let mut source = StreamingSource::from_candidate(&candidate);
        source.mutate_read = Some((1, 2));
        let mut provider = MemoryProvider::default();
        assert!(matches!(
            publish_and_reread_backup_source(
                &mut provider,
                candidate.descriptor_bytes(),
                &mut source
            ),
            Err(StreamingBackupPublicationError::CorruptOrTampered)
        ));
        assert!(!provider.bytes.contains_key(&descriptor_key));
    }

    #[test]
    fn streaming_publication_detects_cardinality_drift_before_descriptor() {
        let candidate = fixture();
        let descriptor_key = descriptor_provider_key(candidate.set_id());
        let mut source = StreamingSource::from_candidate(&candidate);
        source.reported_count_after_reads = Some((4, 3));
        let mut provider = MemoryProvider::default();
        assert!(matches!(
            publish_and_reread_backup_source(
                &mut provider,
                candidate.descriptor_bytes(),
                &mut source
            ),
            Err(StreamingBackupPublicationError::CorruptOrTampered)
        ));
        assert!(!provider.bytes.contains_key(&descriptor_key));
    }

    #[test]
    fn streaming_publication_is_descriptor_last_and_three_pass_verified() {
        let candidate = fixture();
        let descriptor_key = descriptor_provider_key(candidate.set_id());
        let object_keys: Vec<_> = candidate
            .objects()
            .iter()
            .map(|object| object_provider_key(candidate.set_id(), object.object_id()))
            .collect();
        let mut source = StreamingSource::from_candidate(&candidate);
        let mut provider = MemoryProvider::default();
        let proof = publish_and_reread_backup_source(
            &mut provider,
            candidate.descriptor_bytes(),
            &mut source,
        )
        .unwrap();
        assert_eq!(proof.set_id(), candidate.set_id());
        assert_eq!(proof.data_object_count(), 2);
        assert_eq!(source.reads, vec![0, 1, 0, 1, 0, 1]);
        assert_eq!(
            provider.operations,
            vec![
                format!("put:{}", object_keys[0]),
                format!("put:{}", object_keys[1]),
                format!("put:{descriptor_key}"),
                format!("read:{}", object_keys[0]),
                format!("read:{}", object_keys[1]),
                format!("read:{descriptor_key}"),
            ]
        );
    }

    #[test]
    fn publication_is_descriptor_last_and_reread_before_acceptance() {
        let candidate = fixture();
        let descriptor_key = descriptor_provider_key(candidate.set_id());
        let object_keys: Vec<_> = candidate
            .objects()
            .iter()
            .map(|object| object_provider_key(candidate.set_id(), object.object_id()))
            .collect();
        let mut provider = MemoryProvider::default();
        let accepted = publish_and_reread_prepared_backup_set(&mut provider, &candidate).unwrap();
        assert_eq!(accepted.set_id(), candidate.set_id());
        assert_eq!(accepted.data_object_count(), 2);
        assert_eq!(
            provider.operations,
            vec![
                format!("put:{}", object_keys[0]),
                format!("put:{}", object_keys[1]),
                format!("put:{descriptor_key}"),
                format!("read:{}", object_keys[0]),
                format!("read:{}", object_keys[1]),
                format!("read:{descriptor_key}"),
            ]
        );
    }

    #[test]
    fn failed_object_write_never_publishes_descriptor() {
        let candidate = fixture();
        let failed_key =
            object_provider_key(candidate.set_id(), candidate.objects()[1].object_id());
        let descriptor_key = descriptor_provider_key(candidate.set_id());
        let mut provider = MemoryProvider {
            fail_write_key: Some(failed_key),
            ..MemoryProvider::default()
        };
        assert!(matches!(
            publish_and_reread_prepared_backup_set(&mut provider, &candidate),
            Err(BackupPublicationError::Provider(ProviderError::Failed))
        ));
        assert!(!provider.bytes.contains_key(&descriptor_key));
    }

    #[test]
    fn ambiguous_descriptor_ack_is_never_accepted() {
        let candidate = fixture();
        let descriptor_key = descriptor_provider_key(candidate.set_id());
        let mut provider = MemoryProvider {
            ambiguous_write_key: Some(descriptor_key.clone()),
            ..MemoryProvider::default()
        };
        assert!(matches!(
            publish_and_reread_prepared_backup_set(&mut provider, &candidate),
            Err(BackupPublicationError::Provider(ProviderError::Failed))
        ));
        assert!(provider.bytes.contains_key(&descriptor_key));
        assert!(
            provider
                .operations
                .iter()
                .all(|entry| !entry.starts_with("read:"))
        );
    }

    #[test]
    fn reread_mismatch_is_fail_closed() {
        let candidate = fixture();
        let corrupt_key =
            object_provider_key(candidate.set_id(), candidate.objects()[0].object_id());
        let mut provider = MemoryProvider {
            corrupt_read_key: Some(corrupt_key),
            ..MemoryProvider::default()
        };
        assert_eq!(
            publish_and_reread_prepared_backup_set(&mut provider, &candidate),
            Err(BackupPublicationError::CorruptOrTampered)
        );
    }

    #[test]
    fn existing_key_prevents_in_place_overwrite() {
        let candidate = fixture();
        let key = object_provider_key(candidate.set_id(), candidate.objects()[0].object_id());
        let mut provider = MemoryProvider::default();
        provider.bytes.insert(key, vec![99]);
        assert!(matches!(
            publish_and_reread_prepared_backup_set(&mut provider, &candidate),
            Err(BackupPublicationError::Provider(ProviderError::Exists))
        ));
    }

    #[test]
    fn preparation_rejects_count_duplicates_and_cross_set_envelopes() {
        let candidate = fixture();
        assert_eq!(
            PreparedBackupSet::new(
                candidate.descriptor_bytes.clone(),
                vec![candidate.objects[0].clone()]
            ),
            Err(BackupCodecError::CorruptOrTampered)
        );
        assert_eq!(
            PreparedBackupSet::new(
                candidate.descriptor_bytes.clone(),
                vec![candidate.objects[0].clone(), candidate.objects[0].clone()]
            ),
            Err(BackupCodecError::CorruptOrTampered)
        );
        let other = fixture_for_set([17; 16]);
        let wrong_object = PreparedBackupObject::new(
            candidate.objects[0].object_id(),
            other.objects[1].envelope().to_vec(),
        );
        assert_eq!(
            PreparedBackupSet::new(
                candidate.descriptor_bytes.clone(),
                vec![wrong_object, candidate.objects[1].clone()]
            ),
            Err(BackupCodecError::CorruptOrTampered)
        );
    }
}

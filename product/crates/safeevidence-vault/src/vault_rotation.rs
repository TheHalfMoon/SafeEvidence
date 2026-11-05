//! B503 resumable seven-phase full-VRK rotation.
//!
//! The coordinator executes one durable transition per call. Source and target
//! protectors are distinct opaque provider records, so the source generation is
//! retained until the target state has been published, anchored, reopened, and
//! verified. B504 owns exhaustive before/after fault-injection qualification.

use crate::vault::{
    FreshnessAnchor, FreshnessEpoch, KeyGeneration, ProtectedFreshnessState, ProtectorError,
    SecretProtector, VaultId, VaultLeaseIdentity,
};
use crate::vault_keys::{
    KEY_MATERIAL_BYTES, KeyedHandleCloser, OwnedKeyMaterial, PlaintextCache, VaultSessionLifetime,
    VaultTeardownReason,
};
use crate::vault_manifest::{
    FreshManifestError, GenerationState, ManifestContext, ManifestError, ManifestGeneration,
    ManifestObject, ManifestPlaintext, RotationPhase, decrypt_manifest, encrypt_fresh_manifest,
    manifest_context, manifest_hash, manifest_nonce_reservation,
};
use crate::vault_nonce::NonceReservationLedger;
use crate::vault_protector::ProtectorPolicy;
use crate::vault_recovery::{
    RecoveryContext, RecoveryEnvelopeError, decrypt_recovery_envelope, encrypt_recovery_envelope,
};
use std::error::Error;
use std::fmt;

/// Non-secret identities that bind one full-VRK rotation attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FullRotationIdentity {
    vault_id: VaultId,
    source_generation: KeyGeneration,
    target_generation: KeyGeneration,
}

impl FullRotationIdentity {
    /// Reconstructs the deterministic B503 identity used to resume a persisted
    /// rotation after process restart. The target generation is exactly source+1.
    #[must_use]
    pub fn for_next_generation(
        vault_id: VaultId,
        source_generation: KeyGeneration,
    ) -> Option<Self> {
        let value = source_generation.get().checked_add(1)?;
        let target_generation = KeyGeneration::new(value).ok()?;
        Some(Self {
            vault_id,
            source_generation,
            target_generation,
        })
    }

    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub const fn source_generation(self) -> KeyGeneration {
        self.source_generation
    }

    #[must_use]
    pub const fn target_generation(self) -> KeyGeneration {
        self.target_generation
    }
}

/// Fixed byte length of one opaque provider-visible protector identifier.
pub const ROTATION_PROTECTOR_ID_BYTES: usize = 16;

/// Durable non-secret binding for the exact source and target protector records
/// used by one B503 rotation attempt. The opaque identifiers must be distinct.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FullRotationProtectorBinding {
    source_protector_id: [u8; ROTATION_PROTECTOR_ID_BYTES],
    target_protector_id: [u8; ROTATION_PROTECTOR_ID_BYTES],
}

impl FullRotationProtectorBinding {
    #[must_use]
    pub fn new(
        source_protector_id: [u8; ROTATION_PROTECTOR_ID_BYTES],
        target_protector_id: [u8; ROTATION_PROTECTOR_ID_BYTES],
    ) -> Option<Self> {
        if source_protector_id == target_protector_id {
            return None;
        }
        Some(Self {
            source_protector_id,
            target_protector_id,
        })
    }

    #[must_use]
    pub const fn source_protector_id(self) -> [u8; ROTATION_PROTECTOR_ID_BYTES] {
        self.source_protector_id
    }

    #[must_use]
    pub const fn target_protector_id(self) -> [u8; ROTATION_PROTECTOR_ID_BYTES] {
        self.target_protector_id
    }
}

/// Proof that the prior live session published rotation revocation, drained
/// already-authorized operations, closed keyed handles, and released session keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationQuiesced {
    identity: VaultLeaseIdentity,
}

impl RotationQuiesced {
    #[must_use]
    pub const fn identity(self) -> VaultLeaseIdentity {
        self.identity
    }
}

/// Quiesces normal vault operations before a full root rotation begins or resumes.
pub fn quiesce_for_full_rotation<H, C>(
    session: &mut VaultSessionLifetime<H, C>,
) -> Result<RotationQuiesced, H::Error>
where
    H: KeyedHandleCloser,
    C: PlaintextCache,
{
    let identity = session.identity();
    session.teardown(VaultTeardownReason::Rotation)?;
    Ok(RotationQuiesced { identity })
}

/// Existing opt-in recovery material that must be rewrapped for the target VRK.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryRotationInput<'a> {
    source_envelope: &'a [u8],
    passphrase: &'a str,
}

impl<'a> RecoveryRotationInput<'a> {
    #[must_use]
    pub const fn new(source_envelope: &'a [u8], passphrase: &'a str) -> Self {
        Self {
            source_envelope,
            passphrase,
        }
    }

    /// Returns the existing authenticated recovery envelope for the source VRK.
    #[must_use]
    pub const fn source_envelope(self) -> &'a [u8] {
        self.source_envelope
    }

    /// Returns the exact user passphrase used to authenticate and rewrap recovery.
    #[must_use]
    pub const fn passphrase(self) -> &'a str {
        self.passphrase
    }
}

/// Durable B503 progress returned after exactly one accepted phase transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FullRotationProgress {
    InProgress {
        identity: FullRotationIdentity,
        phase: RotationPhase,
    },
    Complete {
        identity: FullRotationIdentity,
        final_anchor: FreshnessAnchor,
    },
}

/// Storage/data boundary used by the B503 coordinator.
///
/// Implementations must make every method idempotent for an exact repeated input.
/// Publication means durable write/fsync plus exact reread support. Target staging
/// must create separately named encrypted objects under `target_generation`; it
/// must never mutate the only source-generation canonical object in place.
pub trait FullRotationBackend {
    type Error;

    /// Acquires or verifies the concrete exclusion that prevents ordinary vault
    /// writes for the complete coordinator call. On success the implementation
    /// must keep that exclusion effective through all subsequent backend operations
    /// performed by this call, including after process restart. A point-in-time
    /// observation that another writer is merely absent is insufficient.
    fn assert_normal_writes_quiesced(&self) -> Result<(), Self::Error>;

    fn read_rotation_protector_binding(
        &self,
    ) -> Result<Option<FullRotationProtectorBinding>, Self::Error>;
    fn persist_rotation_protector_binding(
        &mut self,
        binding: FullRotationProtectorBinding,
    ) -> Result<(), Self::Error>;
    fn clear_rotation_protector_binding(&mut self) -> Result<(), Self::Error>;

    fn read_rotation_checkpoint(&self) -> Result<Option<Vec<u8>>, Self::Error>;
    fn persist_rotation_checkpoint(&mut self, envelope: &[u8]) -> Result<(), Self::Error>;
    fn clear_rotation_checkpoint(&mut self) -> Result<(), Self::Error>;

    fn read_target_recovery_wrap(&self) -> Result<Option<Vec<u8>>, Self::Error>;
    fn persist_target_recovery_wrap(&mut self, envelope: &[u8]) -> Result<(), Self::Error>;
    fn remove_target_recovery_wrap(&mut self) -> Result<(), Self::Error>;

    fn stage_reencrypted_inventory(
        &mut self,
        source_vrk: &OwnedKeyMaterial,
        target_vrk: &OwnedKeyMaterial,
        source_manifest: &ManifestPlaintext,
        target_generation: KeyGeneration,
        nonce_ledger: &mut NonceReservationLedger,
    ) -> Result<Vec<ManifestObject>, Self::Error>;

    fn verify_staged_inventory(
        &mut self,
        target_vrk: &OwnedKeyMaterial,
        staged_objects: &[ManifestObject],
    ) -> Result<(), Self::Error>;

    fn quarantine_target_inventory(&mut self) -> Result<(), Self::Error>;

    fn publish_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error>;
    fn read_published_manifest(&self) -> Result<Vec<u8>, Self::Error>;

    fn reopen_and_verify_published(
        &mut self,
        target_vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error>;

    fn activate_target_protector(&mut self) -> Result<(), Self::Error>;
    fn retire_source_inventory(
        &mut self,
        source_generation: KeyGeneration,
    ) -> Result<(), Self::Error>;
    fn retire_source_recovery_wrap(&mut self) -> Result<(), Self::Error>;
}

/// Exact B503 failure class. No variant authorizes rollback from PUBLISH or later.
#[derive(Debug)]
pub enum FullRotationError<E> {
    Backend { phase: RotationPhase, source: E },
    Protector(ProtectorError),
    Manifest(ManifestError),
    FreshManifest(FreshManifestError),
    Recovery(RecoveryEnvelopeError),
    InvalidState,
    GenerationOverflow,
    EpochOverflow,
    RandomnessUnavailable,
    KeyMaterialCollision,
    TargetProtectorNotEmpty,
    InventoryMismatch,
}

impl<E: fmt::Display> fmt::Display for FullRotationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { phase, source } => {
                write!(f, "B503 {phase:?} backend failure: {source}")
            }
            Self::Protector(error) => write!(f, "B503 protector failure: {error}"),
            Self::Manifest(error) => write!(f, "B503 manifest failure: {error}"),
            Self::FreshManifest(error) => write!(f, "B503 fresh-manifest failure: {error}"),
            Self::Recovery(error) => write!(f, "B503 recovery-wrap failure: {error}"),
            Self::InvalidState => f.write_str("B503 rotation state is inconsistent"),
            Self::GenerationOverflow => f.write_str("B503 target key generation overflowed"),
            Self::EpochOverflow => f.write_str("B503 freshness epoch overflowed"),
            Self::RandomnessUnavailable => f.write_str("B503 OS randomness is unavailable"),
            Self::KeyMaterialCollision => {
                f.write_str("B503 generated target VRK equals source VRK")
            }
            Self::TargetProtectorNotEmpty => {
                f.write_str("B503 target protector is not a fresh independent record")
            }
            Self::InventoryMismatch => {
                f.write_str("B503 staged inventory does not exactly replace source logical objects")
            }
        }
    }
}

impl<E: Error + 'static> Error for FullRotationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend { source, .. } => Some(source),
            Self::Protector(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::FreshManifest(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::InvalidState
            | Self::GenerationOverflow
            | Self::EpochOverflow
            | Self::RandomnessUnavailable
            | Self::KeyMaterialCollision
            | Self::TargetProtectorNotEmpty
            | Self::InventoryMismatch => None,
        }
    }
}

fn backend<E>(phase: RotationPhase, source: E) -> FullRotationError<E> {
    FullRotationError::Backend { phase, source }
}

fn require_retained_manifest_reservation<E>(
    ledger: &NonceReservationLedger,
    envelope: &[u8],
) -> Result<(), FullRotationError<E>> {
    let reservation = manifest_nonce_reservation(envelope).map_err(FullRotationError::Manifest)?;
    if !ledger.contains(reservation) {
        return Err(FullRotationError::InvalidState);
    }
    Ok(())
}

fn assert_backend_quiesced<B: FullRotationBackend>(
    backend_impl: &B,
    phase: RotationPhase,
) -> Result<(), FullRotationError<B::Error>> {
    backend_impl
        .assert_normal_writes_quiesced()
        .map_err(|error| backend(phase, error))
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

fn generate_target_vrk<E>(
    source_vrk: &OwnedKeyMaterial,
) -> Result<OwnedKeyMaterial, FullRotationError<E>> {
    let mut bytes = [0_u8; KEY_MATERIAL_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| FullRotationError::RandomnessUnavailable)?;
    let target = OwnedKeyMaterial::from_bytes(bytes);
    if key_material_equal(source_vrk, &target) {
        return Err(FullRotationError::KeyMaterialCollision);
    }
    Ok(target)
}

fn next_epoch<E>(current: FreshnessEpoch) -> Result<FreshnessEpoch, FullRotationError<E>> {
    let value = current
        .get()
        .checked_add(1)
        .ok_or(FullRotationError::EpochOverflow)?;
    FreshnessEpoch::new(value).map_err(|_| FullRotationError::EpochOverflow)
}

fn target_generations_pre<E>(
    source: &ManifestPlaintext,
    target: KeyGeneration,
) -> Result<Vec<ManifestGeneration>, FullRotationError<E>> {
    if source
        .generations()
        .iter()
        .any(|entry| entry.generation() >= target)
    {
        return Err(FullRotationError::InvalidState);
    }
    let mut generations = source.generations().to_vec();
    generations.push(ManifestGeneration::new(target, GenerationState::Staged));
    Ok(generations)
}

fn target_generations_post<E>(
    source: &[ManifestGeneration],
    identity: FullRotationIdentity,
) -> Result<Vec<ManifestGeneration>, FullRotationError<E>> {
    let mut saw_source = false;
    let mut saw_target = false;
    let mut output = Vec::with_capacity(source.len());
    for entry in source {
        let generation = entry.generation();
        let state = if generation == identity.source_generation {
            saw_source = true;
            GenerationState::Retained
        } else if generation == identity.target_generation {
            saw_target = true;
            GenerationState::Active
        } else {
            entry.state()
        };
        output.push(ManifestGeneration::new(generation, state));
    }
    if !saw_source || !saw_target {
        return Err(FullRotationError::InvalidState);
    }
    Ok(output)
}

fn build_checkpoint<E>(
    basis: &ManifestPlaintext,
    identity: FullRotationIdentity,
    phase: RotationPhase,
    generations: Vec<ManifestGeneration>,
    objects: Vec<ManifestObject>,
) -> Result<ManifestPlaintext, FullRotationError<E>> {
    ManifestPlaintext::new(
        identity.vault_id,
        basis.freshness_epoch(),
        basis.previous_manifest_hash(),
        if matches!(
            phase,
            RotationPhase::Prepare | RotationPhase::Stage | RotationPhase::Verify
        ) {
            identity.source_generation
        } else {
            identity.target_generation
        },
        (phase, Some(identity.target_generation)),
        generations,
        objects,
    )
    .map_err(FullRotationError::Manifest)
}

fn persist_encrypted_checkpoint<B: FullRotationBackend>(
    backend_impl: &mut B,
    ledger: &mut NonceReservationLedger,
    vrk: &OwnedKeyMaterial,
    identity: FullRotationIdentity,
    plaintext: &ManifestPlaintext,
) -> Result<Vec<u8>, FullRotationError<B::Error>> {
    let context = ManifestContext::new(
        identity.vault_id,
        plaintext.active_key_generation(),
        plaintext.freshness_epoch(),
    );
    let (_, envelope) = encrypt_fresh_manifest(ledger, vrk, context, plaintext)
        .map_err(FullRotationError::FreshManifest)?;
    backend_impl
        .persist_rotation_checkpoint(&envelope)
        .map_err(|error| backend(plaintext.rotation_phase(), error))?;
    let reread = backend_impl
        .read_rotation_checkpoint()
        .map_err(|error| backend(plaintext.rotation_phase(), error))?
        .ok_or(FullRotationError::InvalidState)?;
    if reread != envelope {
        return Err(FullRotationError::InvalidState);
    }
    let authenticated =
        decrypt_manifest(vrk, context, &reread).map_err(FullRotationError::Manifest)?;
    if authenticated != *plaintext {
        return Err(FullRotationError::InvalidState);
    }
    Ok(envelope)
}

fn protector_anchor<P, E>(
    protector: &P,
    vault_id: VaultId,
) -> Result<FreshnessAnchor, FullRotationError<E>>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
{
    match protector
        .read_freshness_anchor(vault_id)
        .map_err(FullRotationError::Protector)?
    {
        ProtectedFreshnessState::Present(anchor) => Ok(anchor),
        ProtectedFreshnessState::Uninitialized => Err(FullRotationError::InvalidState),
    }
}

fn unlock_verified<P, E>(
    protector: &mut P,
    vault_id: VaultId,
    generation: KeyGeneration,
) -> Result<OwnedKeyMaterial, FullRotationError<E>>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
{
    protector
        .unlock_vrk(vault_id, generation)
        .map_err(FullRotationError::Protector)
}

/// Begins B503 at PREPARE after normal writes have been quiesced.
///
/// The target protector must be a distinct fresh opaque provider record. Its VRK
/// and optional recovery envelope are verified before the PREPARE checkpoint is
/// persisted. Its freshness slot is seeded with the exact source anchor so later
/// ANCHOR can perform ordinary compare-and-advance without mutating the source item.
#[allow(clippy::too_many_arguments)]
pub fn begin_full_rotation<Source, Target, B>(
    quiesced: RotationQuiesced,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &mut NonceReservationLedger,
    current_manifest_envelope: &[u8],
    protector_binding: FullRotationProtectorBinding,
    target_policy: ProtectorPolicy,
    recovery: Option<RecoveryRotationInput<'_>>,
) -> Result<FullRotationProgress, FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    assert_backend_quiesced(backend_impl, RotationPhase::Prepare)?;
    if backend_impl
        .read_rotation_checkpoint()
        .map_err(|error| backend(RotationPhase::Prepare, error))?
        .is_some()
    {
        return Err(FullRotationError::InvalidState);
    }

    let source_identity = quiesced.identity();
    require_retained_manifest_reservation(nonce_ledger, current_manifest_envelope)?;
    let context =
        manifest_context(current_manifest_envelope).map_err(FullRotationError::Manifest)?;
    if context.vault_id() != source_identity.vault_id()
        || context.key_generation() != source_identity.key_generation()
        || nonce_ledger.vault_id() != source_identity.vault_id()
    {
        return Err(FullRotationError::InvalidState);
    }

    let source_vrk = unlock_verified(
        source_protector,
        source_identity.vault_id(),
        source_identity.key_generation(),
    )?;
    let source_manifest = decrypt_manifest(&source_vrk, context, current_manifest_envelope)
        .map_err(FullRotationError::Manifest)?;
    if source_manifest.rotation_phase() != RotationPhase::None
        || source_manifest.active_key_generation() != source_identity.key_generation()
        || source_manifest.freshness_epoch() != context.freshness_epoch()
    {
        return Err(FullRotationError::InvalidState);
    }

    let source_anchor = protector_anchor(source_protector, source_identity.vault_id())?;
    if source_anchor.vault_id() != source_identity.vault_id()
        || source_anchor.highest_epoch() != context.freshness_epoch()
        || source_anchor.manifest_hash() != manifest_hash(current_manifest_envelope)
    {
        return Err(FullRotationError::InvalidState);
    }

    let identity = FullRotationIdentity::for_next_generation(
        source_identity.vault_id(),
        source_identity.key_generation(),
    )
    .ok_or(FullRotationError::GenerationOverflow)?;
    let target_generation = identity.target_generation;
    let generations = target_generations_pre(&source_manifest, target_generation)?;

    match backend_impl
        .read_rotation_protector_binding()
        .map_err(|error| backend(RotationPhase::Prepare, error))?
    {
        Some(existing) if existing == protector_binding => {}
        Some(_) => return Err(FullRotationError::InvalidState),
        None => {
            backend_impl
                .persist_rotation_protector_binding(protector_binding)
                .map_err(|error| backend(RotationPhase::Prepare, error))?;
            if backend_impl
                .read_rotation_protector_binding()
                .map_err(|error| backend(RotationPhase::Prepare, error))?
                != Some(protector_binding)
            {
                return Err(FullRotationError::InvalidState);
            }
        }
    }

    target_protector
        .create_protector(
            target_policy.access_scope(),
            target_policy.user_presence_policy(),
        )
        .map_err(FullRotationError::Protector)?;
    let target_vrk = match target_protector.unlock_vrk(identity.vault_id, target_generation) {
        Ok(existing) => existing,
        Err(ProtectorError::ItemMissing) => {
            let generated = generate_target_vrk(&source_vrk)?;
            target_protector
                .protect_or_store_vrk(identity.vault_id, target_generation, &generated)
                .map_err(FullRotationError::Protector)?;
            let reread = unlock_verified(target_protector, identity.vault_id, target_generation)?;
            if !key_material_equal(&generated, &reread) {
                return Err(FullRotationError::InvalidState);
            }
            generated
        }
        Err(_) => return Err(FullRotationError::TargetProtectorNotEmpty),
    };
    if key_material_equal(&source_vrk, &target_vrk) {
        return Err(FullRotationError::KeyMaterialCollision);
    }

    match target_protector
        .read_freshness_anchor(identity.vault_id)
        .map_err(FullRotationError::Protector)?
    {
        ProtectedFreshnessState::Uninitialized => {
            target_protector
                .install_genesis_freshness_anchor(
                    identity.vault_id,
                    ProtectedFreshnessState::Uninitialized,
                    source_anchor,
                )
                .map_err(FullRotationError::Protector)?;
        }
        ProtectedFreshnessState::Present(anchor) if anchor == source_anchor => {}
        ProtectedFreshnessState::Present(_) => {
            return Err(FullRotationError::TargetProtectorNotEmpty);
        }
    }
    if protector_anchor(target_protector, identity.vault_id)? != source_anchor {
        return Err(FullRotationError::InvalidState);
    }

    if recovery.is_none()
        && backend_impl
            .read_target_recovery_wrap()
            .map_err(|error| backend(RotationPhase::Prepare, error))?
            .is_some()
    {
        return Err(FullRotationError::InvalidState);
    }

    if let Some(recovery) = recovery {
        let recovered_source = decrypt_recovery_envelope(
            RecoveryContext::new(identity.vault_id, identity.source_generation),
            recovery.passphrase,
            recovery.source_envelope,
        )
        .map_err(FullRotationError::Recovery)?;
        if !key_material_equal(&source_vrk, &recovered_source) {
            return Err(FullRotationError::InvalidState);
        }
        let target_envelope = match backend_impl
            .read_target_recovery_wrap()
            .map_err(|error| backend(RotationPhase::Prepare, error))?
        {
            Some(existing) => existing,
            None => {
                let envelope = encrypt_recovery_envelope(
                    &target_vrk,
                    RecoveryContext::new(identity.vault_id, identity.target_generation),
                    recovery.passphrase,
                )
                .map_err(FullRotationError::Recovery)?;
                backend_impl
                    .persist_target_recovery_wrap(&envelope)
                    .map_err(|error| backend(RotationPhase::Prepare, error))?;
                let reread = backend_impl
                    .read_target_recovery_wrap()
                    .map_err(|error| backend(RotationPhase::Prepare, error))?
                    .ok_or(FullRotationError::InvalidState)?;
                if reread != envelope {
                    return Err(FullRotationError::InvalidState);
                }
                envelope
            }
        };
        let recovered_target = decrypt_recovery_envelope(
            RecoveryContext::new(identity.vault_id, identity.target_generation),
            recovery.passphrase,
            &target_envelope,
        )
        .map_err(FullRotationError::Recovery)?;
        if !key_material_equal(&target_vrk, &recovered_target) {
            return Err(FullRotationError::InvalidState);
        }
    }

    let checkpoint = build_checkpoint(
        &source_manifest,
        identity,
        RotationPhase::Prepare,
        generations,
        source_manifest.objects().to_vec(),
    )?;
    persist_encrypted_checkpoint(
        backend_impl,
        nonce_ledger,
        &source_vrk,
        identity,
        &checkpoint,
    )?;

    Ok(FullRotationProgress::InProgress {
        identity,
        phase: RotationPhase::Prepare,
    })
}

fn validate_target_inventory<E>(
    source: &[ManifestObject],
    target: &[ManifestObject],
    target_generation: KeyGeneration,
) -> Result<(), FullRotationError<E>> {
    if source.len() != target.len() {
        return Err(FullRotationError::InventoryMismatch);
    }
    for (source, target) in source.iter().zip(target.iter()) {
        if source.kind() != target.kind()
            || source.logical_id() != target.logical_id()
            || source.storage_id() == target.storage_id()
            || target.key_generation() != target_generation
        {
            return Err(FullRotationError::InventoryMismatch);
        }
    }
    Ok(())
}

fn load_checkpoint<Source, Target, B>(
    identity: FullRotationIdentity,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &B,
    nonce_ledger: &NonceReservationLedger,
) -> Result<(Vec<u8>, ManifestPlaintext, OwnedKeyMaterial), FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    let envelope = backend_impl
        .read_rotation_checkpoint()
        .map_err(|error| backend(RotationPhase::Prepare, error))?
        .ok_or(FullRotationError::InvalidState)?;
    require_retained_manifest_reservation(nonce_ledger, &envelope)?;
    let context = manifest_context(&envelope).map_err(FullRotationError::Manifest)?;
    if context.vault_id() != identity.vault_id {
        return Err(FullRotationError::InvalidState);
    }
    let vrk = if context.key_generation() == identity.source_generation {
        unlock_verified(
            source_protector,
            identity.vault_id,
            identity.source_generation,
        )?
    } else if context.key_generation() == identity.target_generation {
        unlock_verified(
            target_protector,
            identity.vault_id,
            identity.target_generation,
        )?
    } else {
        return Err(FullRotationError::InvalidState);
    };
    let plaintext =
        decrypt_manifest(&vrk, context, &envelope).map_err(FullRotationError::Manifest)?;
    if plaintext.vault_id() != identity.vault_id
        || plaintext.rotation_target_generation() != Some(identity.target_generation)
        || plaintext.rotation_phase() == RotationPhase::None
    {
        return Err(FullRotationError::InvalidState);
    }
    Ok((envelope, plaintext, vrk))
}

fn published_target_manifest<B: FullRotationBackend>(
    identity: FullRotationIdentity,
    target_vrk: &OwnedKeyMaterial,
    backend_impl: &B,
    nonce_ledger: &NonceReservationLedger,
    phase: RotationPhase,
) -> Result<(Vec<u8>, ManifestPlaintext), FullRotationError<B::Error>> {
    let envelope = backend_impl
        .read_published_manifest()
        .map_err(|error| backend(phase, error))?;
    require_retained_manifest_reservation(nonce_ledger, &envelope)?;
    let context = manifest_context(&envelope).map_err(FullRotationError::Manifest)?;
    if context.vault_id() != identity.vault_id
        || context.key_generation() != identity.target_generation
    {
        return Err(FullRotationError::InvalidState);
    }
    let manifest =
        decrypt_manifest(target_vrk, context, &envelope).map_err(FullRotationError::Manifest)?;
    Ok((envelope, manifest))
}

fn persist_phase_checkpoint<B: FullRotationBackend>(
    backend_impl: &mut B,
    ledger: &mut NonceReservationLedger,
    key: &OwnedKeyMaterial,
    identity: FullRotationIdentity,
    basis: &ManifestPlaintext,
    phase: RotationPhase,
) -> Result<(), FullRotationError<B::Error>> {
    let checkpoint = build_checkpoint(
        basis,
        identity,
        phase,
        basis.generations().to_vec(),
        basis.objects().to_vec(),
    )?;
    persist_encrypted_checkpoint(backend_impl, ledger, key, identity, &checkpoint)?;
    Ok(())
}

/// Advances exactly one durable B503 phase using a quiescence proof created from
/// the live source session.
#[allow(clippy::too_many_arguments)]
pub fn advance_full_rotation<Source, Target, B>(
    quiesced: RotationQuiesced,
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &mut NonceReservationLedger,
) -> Result<FullRotationProgress, FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    if quiesced.identity().vault_id() != identity.vault_id
        || quiesced.identity().key_generation() != identity.source_generation
    {
        return Err(FullRotationError::InvalidState);
    }
    advance_full_rotation_inner(
        identity,
        protector_binding,
        source_protector,
        target_protector,
        backend_impl,
        nonce_ledger,
    )
}

/// Resumes exactly one durable B503 phase after process restart while the vault
/// remains closed. The concrete backend must prove ordinary writes are still
/// excluded; callers must reconstruct `identity` from persisted non-secret state
/// with `FullRotationIdentity::for_next_generation`.
#[allow(clippy::too_many_arguments)]
pub fn resume_full_rotation_after_restart<Source, Target, B>(
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &mut NonceReservationLedger,
) -> Result<FullRotationProgress, FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    advance_full_rotation_inner(
        identity,
        protector_binding,
        source_protector,
        target_protector,
        backend_impl,
        nonce_ledger,
    )
}

fn recover_stable_target_without_checkpoint<Source, Target, B>(
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &NonceReservationLedger,
) -> Result<FullRotationProgress, FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    match backend_impl
        .read_rotation_protector_binding()
        .map_err(|error| backend(RotationPhase::Retire, error))?
    {
        Some(existing) if existing == protector_binding => {}
        Some(_) => return Err(FullRotationError::InvalidState),
        None => {}
    }
    let target_vrk = unlock_verified(
        target_protector,
        identity.vault_id,
        identity.target_generation,
    )?;
    let (published_envelope, published) = published_target_manifest(
        identity,
        &target_vrk,
        backend_impl,
        nonce_ledger,
        RotationPhase::Retire,
    )?;
    let final_anchor = protector_anchor(target_protector, identity.vault_id)?;
    if published.rotation_phase() != RotationPhase::None
        || published.active_key_generation() != identity.target_generation
        || published.freshness_epoch() != final_anchor.highest_epoch()
        || manifest_hash(&published_envelope) != final_anchor.manifest_hash()
        || published
            .generations()
            .iter()
            .any(|entry| entry.generation() == identity.source_generation)
        || !published.generations().iter().any(|entry| {
            *entry == ManifestGeneration::new(identity.target_generation, GenerationState::Active)
        })
        || published
            .objects()
            .iter()
            .any(|object| object.key_generation() != identity.target_generation)
    {
        return Err(FullRotationError::InvalidState);
    }
    backend_impl
        .reopen_and_verify_published(&target_vrk, &published)
        .map_err(|error| backend(RotationPhase::Retire, error))?;
    backend_impl
        .activate_target_protector()
        .map_err(|error| backend(RotationPhase::Retire, error))?;
    backend_impl
        .retire_source_inventory(identity.source_generation)
        .map_err(|error| backend(RotationPhase::Retire, error))?;
    backend_impl
        .retire_source_recovery_wrap()
        .map_err(|error| backend(RotationPhase::Retire, error))?;
    match source_protector.remove_protector(identity.vault_id) {
        Ok(()) | Err(ProtectorError::ItemMissing) => {}
        Err(error) => return Err(FullRotationError::Protector(error)),
    }
    backend_impl
        .clear_rotation_checkpoint()
        .map_err(|error| backend(RotationPhase::Retire, error))?;
    backend_impl
        .clear_rotation_protector_binding()
        .map_err(|error| backend(RotationPhase::Retire, error))?;
    Ok(FullRotationProgress::Complete {
        identity,
        final_anchor,
    })
}

/// Advances exactly one durable B503 phase from the persisted authenticated checkpoint.
/// Every repeated phase re-verifies prerequisite state; PUBLISH and later never
/// roll backward. Post-PUBLISH checkpoints are target-generation encrypted, so
/// RETIRE can be retried after the source protector has already been removed.
#[allow(clippy::too_many_arguments)]
fn advance_full_rotation_inner<Source, Target, B>(
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &mut NonceReservationLedger,
) -> Result<FullRotationProgress, FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    assert_backend_quiesced(backend_impl, RotationPhase::Prepare)?;
    if nonce_ledger.vault_id() != identity.vault_id {
        return Err(FullRotationError::InvalidState);
    }
    if backend_impl
        .read_rotation_checkpoint()
        .map_err(|error| backend(RotationPhase::Retire, error))?
        .is_none()
    {
        return recover_stable_target_without_checkpoint(
            identity,
            protector_binding,
            source_protector,
            target_protector,
            backend_impl,
            nonce_ledger,
        );
    }
    if backend_impl
        .read_rotation_protector_binding()
        .map_err(|error| backend(RotationPhase::Prepare, error))?
        != Some(protector_binding)
    {
        return Err(FullRotationError::InvalidState);
    }

    let (checkpoint_envelope, checkpoint, checkpoint_key) = load_checkpoint(
        identity,
        source_protector,
        target_protector,
        backend_impl,
        nonce_ledger,
    )?;

    let next_phase = match checkpoint.rotation_phase() {
        RotationPhase::Prepare => {
            let source_vrk = unlock_verified(
                source_protector,
                identity.vault_id,
                identity.source_generation,
            )?;
            let target_vrk = unlock_verified(
                target_protector,
                identity.vault_id,
                identity.target_generation,
            )?;
            let staged = backend_impl
                .stage_reencrypted_inventory(
                    &source_vrk,
                    &target_vrk,
                    &checkpoint,
                    identity.target_generation,
                    nonce_ledger,
                )
                .map_err(|error| backend(RotationPhase::Stage, error))?;
            validate_target_inventory(checkpoint.objects(), &staged, identity.target_generation)?;
            let staged_checkpoint = build_checkpoint(
                &checkpoint,
                identity,
                RotationPhase::Stage,
                checkpoint.generations().to_vec(),
                staged,
            )?;
            persist_encrypted_checkpoint(
                backend_impl,
                nonce_ledger,
                &source_vrk,
                identity,
                &staged_checkpoint,
            )?;
            RotationPhase::Stage
        }
        RotationPhase::Stage => {
            let target_vrk = unlock_verified(
                target_protector,
                identity.vault_id,
                identity.target_generation,
            )?;
            backend_impl
                .verify_staged_inventory(&target_vrk, checkpoint.objects())
                .map_err(|error| backend(RotationPhase::Verify, error))?;
            let source_vrk = unlock_verified(
                source_protector,
                identity.vault_id,
                identity.source_generation,
            )?;
            persist_phase_checkpoint(
                backend_impl,
                nonce_ledger,
                &source_vrk,
                identity,
                &checkpoint,
                RotationPhase::Verify,
            )?;
            RotationPhase::Verify
        }
        RotationPhase::Verify => {
            let target_vrk = unlock_verified(
                target_protector,
                identity.vault_id,
                identity.target_generation,
            )?;
            backend_impl
                .verify_staged_inventory(&target_vrk, checkpoint.objects())
                .map_err(|error| backend(RotationPhase::Verify, error))?;
            let source_anchor = protector_anchor(source_protector, identity.vault_id)?;
            let target_anchor = protector_anchor(target_protector, identity.vault_id)?;
            if source_anchor != target_anchor
                || source_anchor.highest_epoch() != checkpoint.freshness_epoch()
            {
                return Err(FullRotationError::InvalidState);
            }
            let publish_epoch = next_epoch(source_anchor.highest_epoch())?;
            let generations = target_generations_post(checkpoint.generations(), identity)?;
            let publish = ManifestPlaintext::new(
                identity.vault_id,
                publish_epoch,
                source_anchor.manifest_hash(),
                identity.target_generation,
                (RotationPhase::Publish, Some(identity.target_generation)),
                generations,
                checkpoint.objects().to_vec(),
            )
            .map_err(FullRotationError::Manifest)?;
            let context =
                ManifestContext::new(identity.vault_id, identity.target_generation, publish_epoch);
            let (_, envelope) =
                encrypt_fresh_manifest(nonce_ledger, &target_vrk, context, &publish)
                    .map_err(FullRotationError::FreshManifest)?;
            backend_impl
                .publish_manifest(&envelope)
                .map_err(|error| backend(RotationPhase::Publish, error))?;
            let reread = backend_impl
                .read_published_manifest()
                .map_err(|error| backend(RotationPhase::Publish, error))?;
            if reread != envelope
                || decrypt_manifest(&target_vrk, context, &reread)
                    .map_err(FullRotationError::Manifest)?
                    != publish
            {
                return Err(FullRotationError::InvalidState);
            }
            backend_impl
                .persist_rotation_checkpoint(&envelope)
                .map_err(|error| backend(RotationPhase::Publish, error))?;
            let checkpoint_reread = backend_impl
                .read_rotation_checkpoint()
                .map_err(|error| backend(RotationPhase::Publish, error))?
                .ok_or(FullRotationError::InvalidState)?;
            if checkpoint_reread != envelope {
                return Err(FullRotationError::InvalidState);
            }
            RotationPhase::Publish
        }
        RotationPhase::Publish => {
            let context =
                manifest_context(&checkpoint_envelope).map_err(FullRotationError::Manifest)?;
            if context.key_generation() != identity.target_generation {
                return Err(FullRotationError::InvalidState);
            }
            let new_anchor = FreshnessAnchor::new(
                identity.vault_id,
                checkpoint.freshness_epoch(),
                manifest_hash(&checkpoint_envelope),
            );
            let old_epoch = checkpoint
                .freshness_epoch()
                .get()
                .checked_sub(1)
                .and_then(|value| FreshnessEpoch::new(value).ok())
                .ok_or(FullRotationError::InvalidState)?;
            let expected_old = FreshnessAnchor::new(
                identity.vault_id,
                old_epoch,
                checkpoint.previous_manifest_hash(),
            );
            match protector_anchor(target_protector, identity.vault_id)? {
                anchor if anchor == expected_old => target_protector
                    .advance_freshness_anchor(identity.vault_id, expected_old, new_anchor)
                    .map_err(FullRotationError::Protector)?,
                anchor if anchor == new_anchor => {}
                _ => return Err(FullRotationError::InvalidState),
            }
            if protector_anchor(target_protector, identity.vault_id)? != new_anchor {
                return Err(FullRotationError::InvalidState);
            }
            persist_phase_checkpoint(
                backend_impl,
                nonce_ledger,
                &checkpoint_key,
                identity,
                &checkpoint,
                RotationPhase::Anchor,
            )?;
            RotationPhase::Anchor
        }
        RotationPhase::Anchor => {
            let target_vrk = unlock_verified(
                target_protector,
                identity.vault_id,
                identity.target_generation,
            )?;
            let (published_envelope, published) = published_target_manifest(
                identity,
                &target_vrk,
                backend_impl,
                nonce_ledger,
                RotationPhase::Activate,
            )?;
            let anchor = protector_anchor(target_protector, identity.vault_id)?;
            if published.rotation_phase() != RotationPhase::Publish
                || anchor.highest_epoch() != published.freshness_epoch()
                || anchor.manifest_hash() != manifest_hash(&published_envelope)
            {
                return Err(FullRotationError::InvalidState);
            }
            backend_impl
                .reopen_and_verify_published(&target_vrk, &published)
                .map_err(|error| backend(RotationPhase::Activate, error))?;
            backend_impl
                .activate_target_protector()
                .map_err(|error| backend(RotationPhase::Activate, error))?;
            persist_phase_checkpoint(
                backend_impl,
                nonce_ledger,
                &target_vrk,
                identity,
                &checkpoint,
                RotationPhase::Activate,
            )?;
            RotationPhase::Activate
        }
        RotationPhase::Activate => {
            let target_vrk = unlock_verified(
                target_protector,
                identity.vault_id,
                identity.target_generation,
            )?;
            let (_, published) = published_target_manifest(
                identity,
                &target_vrk,
                backend_impl,
                nonce_ledger,
                RotationPhase::Retire,
            )?;
            backend_impl
                .reopen_and_verify_published(&target_vrk, &published)
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            backend_impl
                .activate_target_protector()
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            persist_phase_checkpoint(
                backend_impl,
                nonce_ledger,
                &target_vrk,
                identity,
                &checkpoint,
                RotationPhase::Retire,
            )?;
            RotationPhase::Retire
        }
        RotationPhase::Retire => {
            let target_vrk = unlock_verified(
                target_protector,
                identity.vault_id,
                identity.target_generation,
            )?;
            let current_anchor = protector_anchor(target_protector, identity.vault_id)?;
            let (mut published_envelope, mut published) = published_target_manifest(
                identity,
                &target_vrk,
                backend_impl,
                nonce_ledger,
                RotationPhase::Retire,
            )?;

            let final_anchor = if published.rotation_phase() == RotationPhase::None
                && published.freshness_epoch() == current_anchor.highest_epoch()
                && manifest_hash(&published_envelope) == current_anchor.manifest_hash()
            {
                current_anchor
            } else if published.rotation_phase() == RotationPhase::None
                && published.previous_manifest_hash() == current_anchor.manifest_hash()
                && published.freshness_epoch() == next_epoch(current_anchor.highest_epoch())?
            {
                let candidate_anchor = FreshnessAnchor::new(
                    identity.vault_id,
                    published.freshness_epoch(),
                    manifest_hash(&published_envelope),
                );
                target_protector
                    .advance_freshness_anchor(identity.vault_id, current_anchor, candidate_anchor)
                    .map_err(FullRotationError::Protector)?;
                candidate_anchor
            } else if published.rotation_phase() == RotationPhase::Publish
                && published.freshness_epoch() == current_anchor.highest_epoch()
                && manifest_hash(&published_envelope) == current_anchor.manifest_hash()
            {
                let stable_epoch = next_epoch(current_anchor.highest_epoch())?;
                let stable_generations = published
                    .generations()
                    .iter()
                    .copied()
                    .filter(|entry| entry.generation() != identity.source_generation)
                    .collect();
                let stable = ManifestPlaintext::new(
                    identity.vault_id,
                    stable_epoch,
                    current_anchor.manifest_hash(),
                    identity.target_generation,
                    (RotationPhase::None, None),
                    stable_generations,
                    published.objects().to_vec(),
                )
                .map_err(FullRotationError::Manifest)?;
                let context = ManifestContext::new(
                    identity.vault_id,
                    identity.target_generation,
                    stable_epoch,
                );
                let (_, envelope) =
                    encrypt_fresh_manifest(nonce_ledger, &target_vrk, context, &stable)
                        .map_err(FullRotationError::FreshManifest)?;
                backend_impl
                    .publish_manifest(&envelope)
                    .map_err(|error| backend(RotationPhase::Retire, error))?;
                let reread = backend_impl
                    .read_published_manifest()
                    .map_err(|error| backend(RotationPhase::Retire, error))?;
                if reread != envelope {
                    return Err(FullRotationError::InvalidState);
                }
                published_envelope = envelope;
                published = decrypt_manifest(&target_vrk, context, &published_envelope)
                    .map_err(FullRotationError::Manifest)?;
                let candidate_anchor = FreshnessAnchor::new(
                    identity.vault_id,
                    stable_epoch,
                    manifest_hash(&published_envelope),
                );
                target_protector
                    .advance_freshness_anchor(identity.vault_id, current_anchor, candidate_anchor)
                    .map_err(FullRotationError::Protector)?;
                candidate_anchor
            } else {
                return Err(FullRotationError::InvalidState);
            };

            if protector_anchor(target_protector, identity.vault_id)? != final_anchor
                || published.rotation_phase() != RotationPhase::None
                || published.active_key_generation() != identity.target_generation
                || published.generations().iter().any(|entry| {
                    entry.generation() == identity.source_generation
                        || (entry.generation() == identity.target_generation
                            && entry.state() != GenerationState::Active)
                })
                || !published.generations().iter().any(|entry| {
                    *entry
                        == ManifestGeneration::new(
                            identity.target_generation,
                            GenerationState::Active,
                        )
                })
                || published
                    .objects()
                    .iter()
                    .any(|object| object.key_generation() != identity.target_generation)
            {
                return Err(FullRotationError::InvalidState);
            }
            backend_impl
                .reopen_and_verify_published(&target_vrk, &published)
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            backend_impl
                .activate_target_protector()
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            backend_impl
                .retire_source_inventory(identity.source_generation)
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            backend_impl
                .retire_source_recovery_wrap()
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            match source_protector.remove_protector(identity.vault_id) {
                Ok(()) | Err(ProtectorError::ItemMissing) => {}
                Err(error) => return Err(FullRotationError::Protector(error)),
            }
            backend_impl
                .clear_rotation_checkpoint()
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            backend_impl
                .clear_rotation_protector_binding()
                .map_err(|error| backend(RotationPhase::Retire, error))?;
            return Ok(FullRotationProgress::Complete {
                identity,
                final_anchor,
            });
        }
        RotationPhase::None => return Err(FullRotationError::InvalidState),
    };

    Ok(FullRotationProgress::InProgress {
        identity,
        phase: next_phase,
    })
}

/// Aborts only a PREPARE/STAGE/VERIFY attempt while the source anchor remains canonical.
/// PUBLISH and later phases are never rolled backward by this API.
pub fn abort_prepublication_rotation<Source, Target, B>(
    quiesced: RotationQuiesced,
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &NonceReservationLedger,
) -> Result<(), FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    if quiesced.identity().vault_id() != identity.vault_id
        || quiesced.identity().key_generation() != identity.source_generation
    {
        return Err(FullRotationError::InvalidState);
    }
    abort_prepublication_rotation_inner(
        identity,
        protector_binding,
        source_protector,
        target_protector,
        backend_impl,
        nonce_ledger,
    )
}

/// Aborts a pre-publication rotation after process restart while the vault remains
/// closed. As with restart resume, the backend must maintain concrete ordinary-write
/// exclusion for the complete operation.
pub fn abort_prepublication_rotation_after_restart<Source, Target, B>(
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &NonceReservationLedger,
) -> Result<(), FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    abort_prepublication_rotation_inner(
        identity,
        protector_binding,
        source_protector,
        target_protector,
        backend_impl,
        nonce_ledger,
    )
}

fn abort_prepublication_rotation_inner<Source, Target, B>(
    identity: FullRotationIdentity,
    protector_binding: FullRotationProtectorBinding,
    source_protector: &mut Source,
    target_protector: &mut Target,
    backend_impl: &mut B,
    nonce_ledger: &NonceReservationLedger,
) -> Result<(), FullRotationError<B::Error>>
where
    Source: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    Target: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FullRotationBackend,
{
    assert_backend_quiesced(backend_impl, RotationPhase::Prepare)?;
    if nonce_ledger.vault_id() != identity.vault_id {
        return Err(FullRotationError::InvalidState);
    }
    if backend_impl
        .read_rotation_protector_binding()
        .map_err(|error| backend(RotationPhase::Prepare, error))?
        != Some(protector_binding)
    {
        return Err(FullRotationError::InvalidState);
    }
    let (_, checkpoint, _) = load_checkpoint(
        identity,
        source_protector,
        target_protector,
        backend_impl,
        nonce_ledger,
    )?;
    if !matches!(
        checkpoint.rotation_phase(),
        RotationPhase::Prepare | RotationPhase::Stage | RotationPhase::Verify
    ) {
        return Err(FullRotationError::InvalidState);
    }
    let source_anchor = protector_anchor(source_protector, identity.vault_id)?;
    let target_anchor = protector_anchor(target_protector, identity.vault_id)?;
    if source_anchor != target_anchor
        || source_anchor.highest_epoch() != checkpoint.freshness_epoch()
    {
        return Err(FullRotationError::InvalidState);
    }
    backend_impl
        .quarantine_target_inventory()
        .map_err(|error| backend(checkpoint.rotation_phase(), error))?;
    backend_impl
        .remove_target_recovery_wrap()
        .map_err(|error| backend(checkpoint.rotation_phase(), error))?;
    match target_protector.remove_protector(identity.vault_id) {
        Ok(()) | Err(ProtectorError::ItemMissing) => {}
        Err(error) => return Err(FullRotationError::Protector(error)),
    }
    backend_impl
        .clear_rotation_checkpoint()
        .map_err(|error| backend(checkpoint.rotation_phase(), error))?;
    backend_impl
        .clear_rotation_protector_binding()
        .map_err(|error| backend(checkpoint.rotation_phase(), error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        AccessScope, FreshnessAnchor, FreshnessEpoch, HardwareBacking, KeyGeneration, ManifestHash,
        ProtectedFreshnessState, UserPresencePolicy, VAULT_ID_BYTES, VaultLeaseState,
    };
    use crate::vault_blob::{BoundedBlobContext, bounded_blob_nonce, decrypt_bounded_blob};
    use crate::vault_keys::{
        KeyDerivationContext, KeyPurpose, VaultKeyMaterial, VaultSessionLifetime,
    };
    use crate::vault_lease::{KeyedHandleError, VaultLease};
    use crate::vault_manifest::{ManifestAuthMetadata, ManifestObjectKind};
    use crate::vault_sqlcipher::{
        SqlCipherGenerationEndpoint, open_sqlcipher_database, stage_sqlcipher_generation,
    };
    use rusqlite::{Connection, OpenFlags};
    use sha2::{Digest, Sha256};
    use std::convert::Infallible;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use zeroize::Zeroize;

    const SOURCE_KEY: [u8; KEY_MATERIAL_BYTES] = [0x33; KEY_MATERIAL_BYTES];

    #[derive(Clone)]
    struct Record {
        vault_id: VaultId,
        generation: KeyGeneration,
        key: [u8; KEY_MATERIAL_BYTES],
        freshness: ProtectedFreshnessState,
    }

    struct MemoryProtector {
        configured: bool,
        record: Option<Record>,
    }

    impl MemoryProtector {
        fn empty() -> Self {
            Self {
                configured: false,
                record: None,
            }
        }

        fn source(vault_id: VaultId, generation: KeyGeneration, anchor: FreshnessAnchor) -> Self {
            Self {
                configured: true,
                record: Some(Record {
                    vault_id,
                    generation,
                    key: SOURCE_KEY,
                    freshness: ProtectedFreshnessState::Present(anchor),
                }),
            }
        }

        fn key_bytes(&self) -> [u8; KEY_MATERIAL_BYTES] {
            self.record.as_ref().expect("record exists").key
        }
    }

    impl SecretProtector for MemoryProtector {
        type VaultRootKey = OwnedKeyMaterial;

        fn create_protector(
            &mut self,
            _requested_scope: AccessScope,
            _user_presence_policy: UserPresencePolicy,
        ) -> Result<(), ProtectorError> {
            self.configured = true;
            Ok(())
        }

        fn protect_or_store_vrk(
            &mut self,
            vault_id: VaultId,
            key_generation: KeyGeneration,
            vrk: &OwnedKeyMaterial,
        ) -> Result<(), ProtectorError> {
            if !self.configured {
                return Err(ProtectorError::Unavailable);
            }
            let key = vrk.with_bytes(|bytes| *bytes);
            match &self.record {
                Some(record)
                    if record.vault_id == vault_id
                        && record.generation == key_generation
                        && record.key == key =>
                {
                    Ok(())
                }
                Some(_) => Err(ProtectorError::CorruptOrTampered),
                None => {
                    self.record = Some(Record {
                        vault_id,
                        generation: key_generation,
                        key,
                        freshness: ProtectedFreshnessState::Uninitialized,
                    });
                    Ok(())
                }
            }
        }

        fn unlock_vrk(
            &mut self,
            vault_id: VaultId,
            key_generation: KeyGeneration,
        ) -> Result<OwnedKeyMaterial, ProtectorError> {
            let record = self.record.as_ref().ok_or(ProtectorError::ItemMissing)?;
            if record.vault_id != vault_id || record.generation != key_generation {
                return Err(ProtectorError::OwnerMismatch);
            }
            Ok(OwnedKeyMaterial::from_bytes(record.key))
        }

        fn read_freshness_anchor(
            &self,
            vault_id: VaultId,
        ) -> Result<ProtectedFreshnessState, ProtectorError> {
            let record = self.record.as_ref().ok_or(ProtectorError::ItemMissing)?;
            if record.vault_id != vault_id {
                return Err(ProtectorError::OwnerMismatch);
            }
            Ok(record.freshness)
        }

        fn install_genesis_freshness_anchor(
            &mut self,
            vault_id: VaultId,
            expected_state: ProtectedFreshnessState,
            new_anchor: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            let record = self.record.as_mut().ok_or(ProtectorError::ItemMissing)?;
            if record.vault_id != vault_id || record.freshness != expected_state {
                return Err(ProtectorError::AnchorConflict);
            }
            record.freshness = ProtectedFreshnessState::Present(new_anchor);
            Ok(())
        }

        fn advance_freshness_anchor(
            &mut self,
            vault_id: VaultId,
            expected_old: FreshnessAnchor,
            new_anchor: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            let record = self.record.as_mut().ok_or(ProtectorError::ItemMissing)?;
            if record.vault_id != vault_id {
                return Err(ProtectorError::OwnerMismatch);
            }
            if record.freshness != ProtectedFreshnessState::Present(expected_old) {
                return Err(ProtectorError::AnchorConflict);
            }
            record.freshness = ProtectedFreshnessState::Present(new_anchor);
            Ok(())
        }

        fn replace_protector(&mut self, _vault_id: VaultId) -> Result<(), ProtectorError> {
            Err(ProtectorError::UnsupportedPolicy)
        }

        fn remove_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError> {
            match &self.record {
                Some(record) if record.vault_id == vault_id => {
                    self.record = None;
                    Ok(())
                }
                Some(_) => Err(ProtectorError::OwnerMismatch),
                None => Err(ProtectorError::ItemMissing),
            }
        }

        fn actual_access_scope(&self) -> AccessScope {
            AccessScope::SameUserAccount
        }
        fn requires_user_presence(&self) -> bool {
            false
        }
        fn hardware_backed_state(&self) -> HardwareBacking {
            HardwareBacking::Unknown
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct BackendError(&'static str);

    impl std::fmt::Display for BackendError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for BackendError {}

    #[derive(Default)]
    struct PrepareBackend {
        binding: Option<FullRotationProtectorBinding>,
        checkpoint: Option<Vec<u8>>,
        recovery: Option<Vec<u8>>,
        fail_checkpoint_once: bool,
        staged: Option<Vec<ManifestObject>>,
        published: Option<Vec<u8>>,
        target_activated: bool,
        source_inventory_retired: bool,
        source_recovery_retired: bool,
        quarantined: bool,
        stage_calls: usize,
        verify_calls: usize,
        reopen_calls: usize,
    }

    impl FullRotationBackend for PrepareBackend {
        type Error = BackendError;
        fn assert_normal_writes_quiesced(&self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn read_rotation_protector_binding(
            &self,
        ) -> Result<Option<FullRotationProtectorBinding>, Self::Error> {
            Ok(self.binding)
        }
        fn persist_rotation_protector_binding(
            &mut self,
            binding: FullRotationProtectorBinding,
        ) -> Result<(), Self::Error> {
            self.binding = Some(binding);
            Ok(())
        }
        fn clear_rotation_protector_binding(&mut self) -> Result<(), Self::Error> {
            self.binding = None;
            Ok(())
        }
        fn read_rotation_checkpoint(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.checkpoint.clone())
        }
        fn persist_rotation_checkpoint(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            if self.fail_checkpoint_once {
                self.fail_checkpoint_once = false;
                return Err(BackendError("checkpoint failure"));
            }
            self.checkpoint = Some(envelope.to_vec());
            Ok(())
        }
        fn clear_rotation_checkpoint(&mut self) -> Result<(), Self::Error> {
            self.checkpoint = None;
            Ok(())
        }
        fn read_target_recovery_wrap(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.recovery.clone())
        }
        fn persist_target_recovery_wrap(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            self.recovery = Some(envelope.to_vec());
            Ok(())
        }
        fn remove_target_recovery_wrap(&mut self) -> Result<(), Self::Error> {
            self.recovery = None;
            Ok(())
        }
        fn stage_reencrypted_inventory(
            &mut self,
            _: &OwnedKeyMaterial,
            _: &OwnedKeyMaterial,
            source_manifest: &ManifestPlaintext,
            target_generation: KeyGeneration,
            _: &mut NonceReservationLedger,
        ) -> Result<Vec<ManifestObject>, Self::Error> {
            self.stage_calls += 1;
            let staged: Vec<_> = source_manifest
                .objects()
                .iter()
                .enumerate()
                .map(|(index, object)| {
                    let mut storage_id = object.storage_id();
                    storage_id[15] = storage_id[15].wrapping_add((index as u8).wrapping_add(1));
                    ManifestObject::new(
                        object.logical_id(),
                        storage_id,
                        target_generation,
                        object.ciphertext_length().saturating_add(17),
                        [0x91; 32],
                        object.auth_metadata(),
                    )
                })
                .collect();
            self.staged = Some(staged.clone());
            Ok(staged)
        }
        fn verify_staged_inventory(
            &mut self,
            _: &OwnedKeyMaterial,
            staged_objects: &[ManifestObject],
        ) -> Result<(), Self::Error> {
            if self.staged.as_deref() != Some(staged_objects) {
                return Err(BackendError("staged inventory mismatch"));
            }
            self.verify_calls += 1;
            Ok(())
        }
        fn quarantine_target_inventory(&mut self) -> Result<(), Self::Error> {
            self.staged = None;
            self.quarantined = true;
            Ok(())
        }
        fn publish_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            self.published = Some(envelope.to_vec());
            Ok(())
        }
        fn read_published_manifest(&self) -> Result<Vec<u8>, Self::Error> {
            self.published
                .clone()
                .ok_or(BackendError("published manifest missing"))
        }
        fn reopen_and_verify_published(
            &mut self,
            _: &OwnedKeyMaterial,
            manifest: &ManifestPlaintext,
        ) -> Result<(), Self::Error> {
            if self.staged.as_deref() != Some(manifest.objects()) {
                return Err(BackendError("published inventory mismatch"));
            }
            self.reopen_calls += 1;
            Ok(())
        }
        fn activate_target_protector(&mut self) -> Result<(), Self::Error> {
            self.target_activated = true;
            Ok(())
        }
        fn retire_source_inventory(&mut self, _: KeyGeneration) -> Result<(), Self::Error> {
            self.source_inventory_retired = true;
            Ok(())
        }
        fn retire_source_recovery_wrap(&mut self) -> Result<(), Self::Error> {
            self.source_recovery_retired = true;
            Ok(())
        }
    }

    const REAL_BLOB_ID: [u8; 16] = [0x71; 16];
    const REAL_SOURCE_BLOB_STORAGE: [u8; 16] = [0x72; 16];
    const REAL_TARGET_BLOB_STORAGE: [u8; 16] = [0x73; 16];
    const REAL_SOURCE_DB_STORAGE: [u8; 16] = [0x74; 16];
    const REAL_TARGET_DB_STORAGE: [u8; 16] = [0x75; 16];
    const REAL_DB_MARKER: &str = "SAFEEVIDENCE_B503_REAL_ROTATION_DATA_5D91";
    static NEXT_REAL_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct RealCryptoBackend {
        control: PrepareBackend,
        vault_id: VaultId,
        source_generation: KeyGeneration,
        target_generation: Option<KeyGeneration>,
        source_db_path: PathBuf,
        target_db_path: PathBuf,
        source_blob: Vec<u8>,
        target_blob: Option<Vec<u8>>,
        expected_blob_plaintext: Vec<u8>,
        staged: Vec<ManifestObject>,
    }

    impl RealCryptoBackend {
        fn new(
            vault_id: VaultId,
            source_generation: KeyGeneration,
            source_db_path: PathBuf,
            target_db_path: PathBuf,
            source_blob: Vec<u8>,
            expected_blob_plaintext: Vec<u8>,
        ) -> Self {
            Self {
                control: PrepareBackend::default(),
                vault_id,
                source_generation,
                target_generation: None,
                source_db_path,
                target_db_path,
                source_blob,
                target_blob: None,
                expected_blob_plaintext,
                staged: Vec::new(),
            }
        }

        fn sha256(bytes: &[u8]) -> [u8; 32] {
            Sha256::digest(bytes).into()
        }

        fn source_inventory_matches(&self, manifest: &ManifestPlaintext) -> bool {
            let db = match fs::read(&self.source_db_path) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            manifest.objects().len() == 2
                && manifest.objects().iter().all(|object| match object.kind() {
                    ManifestObjectKind::GenericArtifactBlob => {
                        object.logical_id() == REAL_BLOB_ID
                            && object.storage_id() == REAL_SOURCE_BLOB_STORAGE
                            && object.key_generation() == self.source_generation
                            && object.ciphertext_length() == self.source_blob.len() as u64
                            && object.ciphertext_sha256() == Self::sha256(&self.source_blob)
                            && matches!(
                                object.auth_metadata(),
                                ManifestAuthMetadata::GenericArtifactBlob { nonce }
                                    if bounded_blob_nonce(&self.source_blob) == Ok(nonce)
                            )
                    }
                    ManifestObjectKind::StructuredStore => {
                        object.logical_id() == [0; 16]
                            && object.storage_id() == REAL_SOURCE_DB_STORAGE
                            && object.key_generation() == self.source_generation
                            && object.ciphertext_length() == db.len() as u64
                            && object.ciphertext_sha256() == Self::sha256(&db)
                            && object.auth_metadata() == ManifestAuthMetadata::StructuredStore
                    }
                })
        }

        fn verify_target_data(
            &self,
            target_vrk: &OwnedKeyMaterial,
            objects: &[ManifestObject],
        ) -> Result<(), BackendError> {
            let generation = self
                .target_generation
                .ok_or(BackendError("target generation missing"))?;
            if objects != self.staged.as_slice() || objects.len() != 2 {
                return Err(BackendError("target inventory mismatch"));
            }
            let db = fs::read(&self.target_db_path)
                .map_err(|_| BackendError("target database missing"))?;
            let lease = VaultLease::new(VaultLeaseIdentity::new(self.vault_id, generation));
            let context =
                KeyDerivationContext::new(self.vault_id, generation, KeyPurpose::StructuredStore);
            let handle = open_sqlcipher_database(
                &self.target_db_path,
                lease.keyed_handle_lease(),
                context,
                target_vrk,
            )
            .map_err(|_| BackendError("target database reopen failed"))?;
            handle
                .verify_integrity()
                .map_err(|_| BackendError("target database integrity failed"))?;
            if read_real_database_marker(
                &self.target_db_path,
                self.vault_id,
                generation,
                target_vrk,
            )
            .as_deref()
                != Ok(REAL_DB_MARKER)
            {
                return Err(BackendError("target database semantic marker mismatch"));
            }

            let blob = self
                .target_blob
                .as_ref()
                .ok_or(BackendError("target blob missing"))?;
            let blob_context = BoundedBlobContext::new(self.vault_id, REAL_BLOB_ID, generation);
            let plaintext = decrypt_bounded_blob(target_vrk, blob_context, blob)
                .map_err(|_| BackendError("target blob authentication failed"))?;
            if plaintext != self.expected_blob_plaintext {
                return Err(BackendError("target blob plaintext mismatch"));
            }

            for object in objects {
                match object.kind() {
                    ManifestObjectKind::GenericArtifactBlob => {
                        let nonce = bounded_blob_nonce(blob)
                            .map_err(|_| BackendError("target blob nonce missing"))?;
                        let expected_auth = ManifestAuthMetadata::GenericArtifactBlob { nonce };
                        if object.logical_id() != REAL_BLOB_ID
                            || object.storage_id() != REAL_TARGET_BLOB_STORAGE
                            || object.key_generation() != generation
                            || object.ciphertext_length() != blob.len() as u64
                            || object.ciphertext_sha256() != Self::sha256(blob)
                            || object.auth_metadata() != expected_auth
                        {
                            return Err(BackendError("target blob manifest mismatch"));
                        }
                    }
                    ManifestObjectKind::StructuredStore => {
                        if object.logical_id() != [0; 16]
                            || object.storage_id() != REAL_TARGET_DB_STORAGE
                            || object.key_generation() != generation
                            || object.ciphertext_length() != db.len() as u64
                            || object.ciphertext_sha256() != Self::sha256(&db)
                            || object.auth_metadata() != ManifestAuthMetadata::StructuredStore
                        {
                            return Err(BackendError("target database manifest mismatch"));
                        }
                    }
                }
            }
            Ok(())
        }
    }

    impl FullRotationBackend for RealCryptoBackend {
        type Error = BackendError;

        fn assert_normal_writes_quiesced(&self) -> Result<(), Self::Error> {
            self.control.assert_normal_writes_quiesced()
        }
        fn read_rotation_protector_binding(
            &self,
        ) -> Result<Option<FullRotationProtectorBinding>, Self::Error> {
            self.control.read_rotation_protector_binding()
        }
        fn persist_rotation_protector_binding(
            &mut self,
            binding: FullRotationProtectorBinding,
        ) -> Result<(), Self::Error> {
            self.control.persist_rotation_protector_binding(binding)
        }
        fn clear_rotation_protector_binding(&mut self) -> Result<(), Self::Error> {
            self.control.clear_rotation_protector_binding()
        }
        fn read_rotation_checkpoint(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.control.read_rotation_checkpoint()
        }
        fn persist_rotation_checkpoint(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            self.control.persist_rotation_checkpoint(envelope)
        }
        fn clear_rotation_checkpoint(&mut self) -> Result<(), Self::Error> {
            self.control.clear_rotation_checkpoint()
        }
        fn read_target_recovery_wrap(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.control.read_target_recovery_wrap()
        }
        fn persist_target_recovery_wrap(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            self.control.persist_target_recovery_wrap(envelope)
        }
        fn remove_target_recovery_wrap(&mut self) -> Result<(), Self::Error> {
            self.control.remove_target_recovery_wrap()
        }

        fn stage_reencrypted_inventory(
            &mut self,
            source_vrk: &OwnedKeyMaterial,
            target_vrk: &OwnedKeyMaterial,
            source_manifest: &ManifestPlaintext,
            target_generation: KeyGeneration,
            ledger: &mut NonceReservationLedger,
        ) -> Result<Vec<ManifestObject>, Self::Error> {
            if !self.source_inventory_matches(source_manifest) {
                return Err(BackendError("source inventory mismatch"));
            }
            self.target_generation = Some(target_generation);
            let source_context = KeyDerivationContext::new(
                self.vault_id,
                self.source_generation,
                KeyPurpose::StructuredStore,
            );
            let target_context = KeyDerivationContext::new(
                self.vault_id,
                target_generation,
                KeyPurpose::StructuredStore,
            );
            if !self.target_db_path.exists() {
                let source_lease = VaultLease::new(VaultLeaseIdentity::new(
                    self.vault_id,
                    self.source_generation,
                ));
                let target_lease =
                    VaultLease::new(VaultLeaseIdentity::new(self.vault_id, target_generation));
                let source_endpoint = SqlCipherGenerationEndpoint::new(
                    &self.source_db_path,
                    source_lease.keyed_handle_lease(),
                    source_context,
                    source_vrk,
                );
                let target_endpoint = SqlCipherGenerationEndpoint::new(
                    &self.target_db_path,
                    target_lease.keyed_handle_lease(),
                    target_context,
                    target_vrk,
                );
                drop(
                    stage_sqlcipher_generation(source_endpoint, target_endpoint)
                        .map_err(|_| BackendError("SQLCipher generation staging failed"))?,
                );
            }

            let source_blob_context =
                BoundedBlobContext::new(self.vault_id, REAL_BLOB_ID, self.source_generation);
            let plaintext =
                decrypt_bounded_blob(source_vrk, source_blob_context, &self.source_blob)
                    .map_err(|_| BackendError("source blob authentication failed"))?;
            if plaintext != self.expected_blob_plaintext {
                return Err(BackendError("source blob plaintext mismatch"));
            }
            let target_blob_context =
                BoundedBlobContext::new(self.vault_id, REAL_BLOB_ID, target_generation);
            let nonce = match &self.target_blob {
                Some(existing) => {
                    let reread = decrypt_bounded_blob(target_vrk, target_blob_context, existing)
                        .map_err(|_| BackendError("existing target blob invalid"))?;
                    if reread != self.expected_blob_plaintext {
                        return Err(BackendError("existing target blob mismatch"));
                    }
                    bounded_blob_nonce(existing)
                        .map_err(|_| BackendError("existing target blob nonce invalid"))?
                }
                None => {
                    let candidate = ledger
                        .encrypt_fresh_bounded_blob(target_vrk, target_blob_context, &plaintext)
                        .map_err(|_| BackendError("target blob encryption failed"))?;
                    let nonce = candidate.reservation().nonce();
                    self.target_blob = Some(candidate.into_parts().1);
                    nonce
                }
            };
            let blob = self
                .target_blob
                .as_ref()
                .ok_or(BackendError("target blob missing after staging"))?;
            let db = fs::read(&self.target_db_path)
                .map_err(|_| BackendError("target database missing after staging"))?;
            self.staged = vec![
                ManifestObject::new(
                    REAL_BLOB_ID,
                    REAL_TARGET_BLOB_STORAGE,
                    target_generation,
                    blob.len() as u64,
                    Self::sha256(blob),
                    ManifestAuthMetadata::GenericArtifactBlob { nonce },
                ),
                ManifestObject::new(
                    [0; 16],
                    REAL_TARGET_DB_STORAGE,
                    target_generation,
                    db.len() as u64,
                    Self::sha256(&db),
                    ManifestAuthMetadata::StructuredStore,
                ),
            ];
            Ok(self.staged.clone())
        }

        fn verify_staged_inventory(
            &mut self,
            target_vrk: &OwnedKeyMaterial,
            objects: &[ManifestObject],
        ) -> Result<(), Self::Error> {
            self.verify_target_data(target_vrk, objects)
        }
        fn quarantine_target_inventory(&mut self) -> Result<(), Self::Error> {
            remove_real_database_files(&self.target_db_path);
            self.target_blob = None;
            self.staged.clear();
            self.control.quarantined = true;
            Ok(())
        }
        fn publish_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            self.control.publish_manifest(envelope)
        }
        fn read_published_manifest(&self) -> Result<Vec<u8>, Self::Error> {
            self.control.read_published_manifest()
        }
        fn reopen_and_verify_published(
            &mut self,
            target_vrk: &OwnedKeyMaterial,
            manifest: &ManifestPlaintext,
        ) -> Result<(), Self::Error> {
            self.verify_target_data(target_vrk, manifest.objects())
        }
        fn activate_target_protector(&mut self) -> Result<(), Self::Error> {
            self.control.activate_target_protector()
        }
        fn retire_source_inventory(
            &mut self,
            source_generation: KeyGeneration,
        ) -> Result<(), Self::Error> {
            if source_generation != self.source_generation {
                return Err(BackendError("source generation retirement mismatch"));
            }
            remove_real_database_files(&self.source_db_path);
            self.source_blob.clear();
            self.control.source_inventory_retired = true;
            Ok(())
        }
        fn retire_source_recovery_wrap(&mut self) -> Result<(), Self::Error> {
            self.control.retire_source_recovery_wrap()
        }
    }

    fn remove_real_database_files(path: &Path) {
        let _ = fs::remove_file(path);
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", path.display())));
        }
    }

    fn real_crypto_paths() -> (PathBuf, PathBuf) {
        let sequence = NEXT_REAL_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "safeevidence-b503-real-rotation-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("real rotation fixture directory");
        (directory.join("source.db"), directory.join("target.db"))
    }

    fn real_raw_key_pragma(key: &[u8; KEY_MATERIAL_BYTES]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut sql = String::with_capacity(82);
        sql.push_str("PRAGMA key = \"x'");
        for byte in key {
            sql.push(char::from(HEX[usize::from(byte >> 4)]));
            sql.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        sql.push_str("'\";");
        sql
    }

    fn create_real_source_database(
        path: &Path,
        vault_id: VaultId,
        generation: KeyGeneration,
        vrk: &OwnedKeyMaterial,
    ) {
        remove_real_database_files(path);
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("reviewed SQLCipher provider creates source fixture");
        let key = KeyDerivationContext::new(vault_id, generation, KeyPurpose::StructuredStore)
            .derive_purpose_key(vrk);
        let mut pragma = key.with_bytes(real_raw_key_pragma);
        connection
            .execute_batch(&pragma)
            .expect("source fixture keying succeeds");
        pragma.zeroize();
        connection
            .execute_batch(&format!(
                "PRAGMA journal_mode = DELETE; CREATE TABLE rotation_probe (value TEXT NOT NULL); INSERT INTO rotation_probe VALUES ('{REAL_DB_MARKER}');"
            ))
            .expect("source fixture semantic data persists");
    }

    fn read_real_database_marker(
        path: &Path,
        vault_id: VaultId,
        generation: KeyGeneration,
        vrk: &OwnedKeyMaterial,
    ) -> Result<String, rusqlite::Error> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let key = KeyDerivationContext::new(vault_id, generation, KeyPurpose::StructuredStore)
            .derive_purpose_key(vrk);
        let mut pragma = key.with_bytes(real_raw_key_pragma);
        let keyed = connection.execute_batch(&pragma);
        pragma.zeroize();
        keyed?;
        connection.query_row("SELECT value FROM rotation_probe LIMIT 1", [], |row| {
            row.get(0)
        })
    }

    struct NoopCloser;

    impl KeyedHandleCloser for NoopCloser {
        type Error = Infallible;

        fn close_keyed_handles(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct NoopCache;

    impl PlaintextCache for NoopCache {
        fn discard_plaintext(&mut self) {}
    }

    fn identity() -> VaultLeaseIdentity {
        VaultLeaseIdentity::new(
            VaultId::from_bytes([0x51; VAULT_ID_BYTES]),
            KeyGeneration::new(9).expect("non-zero generation"),
        )
    }

    #[test]
    fn next_generation_identity_is_exact_and_overflow_fails_closed() {
        let current = identity();
        let rotation =
            FullRotationIdentity::for_next_generation(current.vault_id(), current.key_generation())
                .expect("next generation exists");
        assert_eq!(rotation.vault_id(), current.vault_id());
        assert_eq!(rotation.source_generation(), current.key_generation());
        assert_eq!(
            rotation.target_generation().get(),
            current.key_generation().get() + 1
        );

        let max = KeyGeneration::new(u64::MAX).expect("maximum is non-zero");
        assert_eq!(
            FullRotationIdentity::for_next_generation(current.vault_id(), max),
            None
        );
    }

    #[test]
    fn protector_binding_requires_distinct_opaque_records() {
        assert!(FullRotationProtectorBinding::new([0x11; 16], [0x11; 16]).is_none());
        let binding = FullRotationProtectorBinding::new([0x11; 16], [0x12; 16])
            .expect("distinct protector records");
        assert_eq!(binding.source_protector_id(), [0x11; 16]);
        assert_eq!(binding.target_protector_id(), [0x12; 16]);
    }

    #[test]
    fn quiesce_revokes_existing_handles_and_releases_session_keys() {
        let current = identity();
        let lease = VaultLease::new(current);
        let stale = lease.keyed_handle_lease();
        let mut session = VaultSessionLifetime::new(
            lease,
            NoopCloser,
            VaultKeyMaterial::new(OwnedKeyMaterial::from_bytes([0x44; 32])),
            NoopCache,
        );

        let proof = quiesce_for_full_rotation(&mut session).expect("quiescence succeeds");
        assert_eq!(proof.identity(), current);
        assert_eq!(session.lease_state(), VaultLeaseState::Revoked);
        assert!(session.keys_released());
        assert!(matches!(stale.authorize(), Err(KeyedHandleError::Revoked)));
    }

    struct PrepareFixture {
        vault_id: VaultId,
        generation: KeyGeneration,
        envelope: Vec<u8>,
        source: MemoryProtector,
        target: MemoryProtector,
        backend: PrepareBackend,
        ledger: NonceReservationLedger,
        session: VaultSessionLifetime<NoopCloser, NoopCache>,
        source_anchor: FreshnessAnchor,
    }

    fn prepare_fixture() -> PrepareFixture {
        let vault_id = VaultId::from_bytes([0x62; VAULT_ID_BYTES]);
        let generation = KeyGeneration::new(11).expect("non-zero generation");
        let epoch = FreshnessEpoch::new(13).expect("non-zero epoch");
        let source_vrk = OwnedKeyMaterial::from_bytes(SOURCE_KEY);
        let manifest = ManifestPlaintext::new(
            vault_id,
            epoch,
            ManifestHash::from_bytes([0x35; 32]),
            generation,
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(generation, GenerationState::Active)],
            vec![ManifestObject::new(
                [0; 16],
                [0x41; 16],
                generation,
                512,
                [0x52; 32],
                crate::vault_manifest::ManifestAuthMetadata::StructuredStore,
            )],
        )
        .expect("source manifest is canonical");
        let mut ledger = NonceReservationLedger::new(vault_id);
        let context = ManifestContext::new(vault_id, generation, epoch);
        let (_, envelope) = encrypt_fresh_manifest(&mut ledger, &source_vrk, context, &manifest)
            .expect("source manifest encryption succeeds");
        let anchor = FreshnessAnchor::new(vault_id, epoch, manifest_hash(&envelope));
        let source = MemoryProtector::source(vault_id, generation, anchor);
        let target = MemoryProtector::empty();
        let lease = VaultLease::new(VaultLeaseIdentity::new(vault_id, generation));
        let session = VaultSessionLifetime::new(
            lease,
            NoopCloser,
            VaultKeyMaterial::new(OwnedKeyMaterial::from_bytes(SOURCE_KEY)),
            NoopCache,
        );
        PrepareFixture {
            vault_id,
            generation,
            envelope,
            source,
            target,
            backend: PrepareBackend::default(),
            ledger,
            session,
            source_anchor: anchor,
        }
    }

    fn prepare_binding() -> FullRotationProtectorBinding {
        FullRotationProtectorBinding::new([0x21; 16], [0x22; 16])
            .expect("distinct protector identifiers")
    }

    fn prepare_policy() -> ProtectorPolicy {
        ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::NotRequired,
        )
    }

    #[test]
    fn prepare_creates_distinct_target_and_authenticated_checkpoint() {
        let PrepareFixture {
            vault_id,
            generation,
            envelope,
            mut source,
            mut target,
            mut backend,
            mut ledger,
            mut session,
            source_anchor,
        } = prepare_fixture();
        let quiesced = quiesce_for_full_rotation(&mut session).expect("quiescence succeeds");
        let progress = begin_full_rotation(
            quiesced,
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
            &envelope,
            prepare_binding(),
            prepare_policy(),
            None,
        )
        .expect("PREPARE succeeds");
        let identity = match progress {
            FullRotationProgress::InProgress { identity, phase } => {
                assert_eq!(phase, RotationPhase::Prepare);
                identity
            }
            FullRotationProgress::Complete { .. } => panic!("PREPARE cannot complete rotation"),
        };
        assert_eq!(identity.source_generation(), generation);
        assert_eq!(identity.target_generation().get(), generation.get() + 1);
        assert_ne!(target.key_bytes(), SOURCE_KEY);
        assert_eq!(
            target
                .read_freshness_anchor(vault_id)
                .expect("target anchor"),
            ProtectedFreshnessState::Present(source_anchor)
        );
        let checkpoint = backend
            .checkpoint
            .as_ref()
            .expect("PREPARE checkpoint persists");
        let context = manifest_context(checkpoint).expect("checkpoint context parses");
        let decoded = decrypt_manifest(
            &OwnedKeyMaterial::from_bytes(SOURCE_KEY),
            context,
            checkpoint,
        )
        .expect("PREPARE checkpoint authenticates under source generation");
        assert_eq!(decoded.rotation_phase(), RotationPhase::Prepare);
        assert_eq!(
            decoded.rotation_target_generation(),
            Some(identity.target_generation())
        );
        assert!(decoded.generations().iter().any(|entry| {
            entry.generation() == identity.target_generation()
                && entry.state() == GenerationState::Staged
        }));
    }

    #[test]
    fn prepare_retry_reuses_target_key_after_checkpoint_failure() {
        let PrepareFixture {
            envelope,
            mut source,
            mut target,
            mut backend,
            mut ledger,
            mut session,
            ..
        } = prepare_fixture();
        backend.fail_checkpoint_once = true;
        let quiesced = quiesce_for_full_rotation(&mut session).expect("quiescence succeeds");
        let first = begin_full_rotation(
            quiesced,
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
            &envelope,
            prepare_binding(),
            prepare_policy(),
            None,
        );
        assert!(matches!(
            first,
            Err(FullRotationError::Backend {
                phase: RotationPhase::Prepare,
                ..
            })
        ));
        let retained_target_key = target.key_bytes();
        assert!(backend.checkpoint.is_none());

        let second = begin_full_rotation(
            quiesced,
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
            &envelope,
            prepare_binding(),
            prepare_policy(),
            None,
        )
        .expect("PREPARE retry succeeds");
        assert!(matches!(
            second,
            FullRotationProgress::InProgress {
                phase: RotationPhase::Prepare,
                ..
            }
        ));
        assert_eq!(target.key_bytes(), retained_target_key);
        assert!(backend.checkpoint.is_some());
    }

    #[test]
    fn prepublication_abort_quarantines_target_and_preserves_source_anchor() {
        let PrepareFixture {
            envelope,
            mut source,
            mut target,
            mut backend,
            mut ledger,
            mut session,
            source_anchor,
            ..
        } = prepare_fixture();
        let quiesced = quiesce_for_full_rotation(&mut session).expect("quiescence succeeds");
        let prepared = begin_full_rotation(
            quiesced,
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
            &envelope,
            prepare_binding(),
            prepare_policy(),
            None,
        )
        .expect("PREPARE succeeds");
        let identity = match prepared {
            FullRotationProgress::InProgress { identity, phase } => {
                assert_eq!(phase, RotationPhase::Prepare);
                identity
            }
            FullRotationProgress::Complete { .. } => panic!("PREPARE cannot complete rotation"),
        };

        advance_full_rotation(
            quiesced,
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("STAGE succeeds before abort");

        abort_prepublication_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &ledger,
        )
        .expect("prepublication abort succeeds");

        assert!(backend.quarantined);
        assert!(backend.staged.is_none());
        assert!(backend.checkpoint.is_none());
        assert!(backend.binding.is_none());
        assert!(target.record.is_none());
        assert!(source.record.is_some());
        assert_eq!(
            source
                .read_freshness_anchor(identity.vault_id())
                .expect("source freshness survives abort"),
            ProtectedFreshnessState::Present(source_anchor)
        );
        assert!(!backend.source_inventory_retired);
    }

    #[test]
    fn full_rotation_reencrypts_real_sqlcipher_and_bounded_blob_before_retirement() {
        let vault_id = VaultId::from_bytes([0x61; VAULT_ID_BYTES]);
        let source_generation = KeyGeneration::new(11).expect("non-zero source generation");
        let epoch = FreshnessEpoch::new(13).expect("non-zero source epoch");
        let source_vrk = OwnedKeyMaterial::from_bytes(SOURCE_KEY);
        let (source_db_path, target_db_path) = real_crypto_paths();
        create_real_source_database(&source_db_path, vault_id, source_generation, &source_vrk);
        let source_db_bytes = fs::read(&source_db_path).expect("source database bytes");
        assert_eq!(
            read_real_database_marker(&source_db_path, vault_id, source_generation, &source_vrk)
                .expect("source marker reads"),
            REAL_DB_MARKER
        );

        let expected_blob_plaintext = b"HIMSAT_B503_REAL_BLOB_ROTATION_DATA_A271".to_vec();
        let source_blob_context =
            BoundedBlobContext::new(vault_id, REAL_BLOB_ID, source_generation);
        let mut ledger = NonceReservationLedger::new(vault_id);
        let source_blob_candidate = ledger
            .encrypt_fresh_bounded_blob(&source_vrk, source_blob_context, &expected_blob_plaintext)
            .expect("source bounded blob encrypts");
        let source_blob_nonce = source_blob_candidate.reservation().nonce();
        let source_blob = source_blob_candidate.into_parts().1;

        let manifest = ManifestPlaintext::new(
            vault_id,
            epoch,
            ManifestHash::from_bytes([0x35; 32]),
            source_generation,
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(
                source_generation,
                GenerationState::Active,
            )],
            vec![
                ManifestObject::new(
                    REAL_BLOB_ID,
                    REAL_SOURCE_BLOB_STORAGE,
                    source_generation,
                    source_blob.len() as u64,
                    RealCryptoBackend::sha256(&source_blob),
                    ManifestAuthMetadata::GenericArtifactBlob {
                        nonce: source_blob_nonce,
                    },
                ),
                ManifestObject::new(
                    [0; 16],
                    REAL_SOURCE_DB_STORAGE,
                    source_generation,
                    source_db_bytes.len() as u64,
                    RealCryptoBackend::sha256(&source_db_bytes),
                    ManifestAuthMetadata::StructuredStore,
                ),
            ],
        )
        .expect("real source inventory is canonical");
        let context = ManifestContext::new(vault_id, source_generation, epoch);
        let (_, current_envelope) =
            encrypt_fresh_manifest(&mut ledger, &source_vrk, context, &manifest)
                .expect("source manifest encrypts");
        let source_anchor = FreshnessAnchor::new(vault_id, epoch, manifest_hash(&current_envelope));

        let mut source = MemoryProtector::source(vault_id, source_generation, source_anchor);
        let mut target = MemoryProtector::empty();
        let mut backend = RealCryptoBackend::new(
            vault_id,
            source_generation,
            source_db_path.clone(),
            target_db_path.clone(),
            source_blob.clone(),
            expected_blob_plaintext,
        );
        let lease = VaultLease::new(VaultLeaseIdentity::new(vault_id, source_generation));
        let mut session = VaultSessionLifetime::new(
            lease,
            NoopCloser,
            VaultKeyMaterial::new(OwnedKeyMaterial::from_bytes(SOURCE_KEY)),
            NoopCache,
        );
        let quiesced = quiesce_for_full_rotation(&mut session).expect("rotation quiesces writes");
        let prepared = begin_full_rotation(
            quiesced,
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
            &current_envelope,
            prepare_binding(),
            prepare_policy(),
            None,
        )
        .expect("PREPARE succeeds on real encrypted inventory");
        let identity = match prepared {
            FullRotationProgress::InProgress { identity, phase } => {
                assert_eq!(phase, RotationPhase::Prepare);
                identity
            }
            FullRotationProgress::Complete { .. } => panic!("PREPARE cannot complete rotation"),
        };

        for phase in [
            RotationPhase::Stage,
            RotationPhase::Verify,
            RotationPhase::Publish,
            RotationPhase::Anchor,
            RotationPhase::Activate,
            RotationPhase::Retire,
        ] {
            let progress = advance_full_rotation(
                quiesced,
                identity,
                prepare_binding(),
                &mut source,
                &mut target,
                &mut backend,
                &mut ledger,
            )
            .expect("real encrypted rotation phase advances");
            assert_eq!(
                progress,
                FullRotationProgress::InProgress { identity, phase }
            );
            assert_eq!(
                fs::read(&source_db_path).expect("source database retained before retirement"),
                source_db_bytes
            );
            assert_eq!(backend.source_blob, source_blob);
            if phase == RotationPhase::Stage {
                let target_db_bytes =
                    fs::read(&target_db_path).expect("target database staged separately");
                assert_ne!(target_db_bytes, source_db_bytes);
                assert_ne!(
                    backend.target_blob.as_ref().expect("target blob"),
                    &source_blob
                );
                let target_vrk = OwnedKeyMaterial::from_bytes(target.key_bytes());
                backend
                    .verify_target_data(&target_vrk, &backend.staged)
                    .expect("target database and blob authenticate under G+1");
            }
        }

        let complete = advance_full_rotation(
            quiesced,
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("real encrypted retirement completes");
        assert!(matches!(
            complete,
            FullRotationProgress::Complete { identity: completed, .. } if completed == identity
        ));
        assert!(!source_db_path.exists());
        assert!(backend.source_blob.is_empty());
        assert!(target_db_path.exists());
        assert!(backend.target_blob.is_some());
        assert!(backend.control.target_activated);
        assert!(backend.control.source_inventory_retired);
        assert!(source.record.is_none());

        let target_vrk = OwnedKeyMaterial::from_bytes(target.key_bytes());
        let published = backend
            .read_published_manifest()
            .expect("stable target manifest remains published");
        let published_context = manifest_context(&published).expect("stable context parses");
        let stable = decrypt_manifest(&target_vrk, published_context, &published)
            .expect("stable target manifest authenticates under G+1");
        assert_eq!(stable.rotation_phase(), RotationPhase::None);
        assert_eq!(stable.active_key_generation(), identity.target_generation());
        backend
            .verify_target_data(&target_vrk, stable.objects())
            .expect("stable target inventory remains readable after source retirement");

        let parent = target_db_path.parent().map(PathBuf::from);
        remove_real_database_files(&target_db_path);
        if let Some(parent) = parent {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn stage_and_verify_are_distinct_durable_transitions_and_restart_resumes() {
        let PrepareFixture {
            envelope,
            mut source,
            mut target,
            mut backend,
            mut ledger,
            mut session,
            ..
        } = prepare_fixture();
        let quiesced = quiesce_for_full_rotation(&mut session).expect("quiescence succeeds");
        let prepared = begin_full_rotation(
            quiesced,
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
            &envelope,
            prepare_binding(),
            prepare_policy(),
            None,
        )
        .expect("PREPARE succeeds");
        let identity = match prepared {
            FullRotationProgress::InProgress { identity, phase } => {
                assert_eq!(phase, RotationPhase::Prepare);
                identity
            }
            FullRotationProgress::Complete { .. } => panic!("PREPARE cannot complete rotation"),
        };

        let staged = advance_full_rotation(
            quiesced,
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("STAGE succeeds");
        assert_eq!(
            staged,
            FullRotationProgress::InProgress {
                identity,
                phase: RotationPhase::Stage,
            }
        );
        assert_eq!(backend.stage_calls, 1);
        assert_eq!(backend.verify_calls, 0);
        assert!(source.record.is_some());
        let stage_envelope = backend.checkpoint.as_ref().expect("STAGE checkpoint");
        let stage_context = manifest_context(stage_envelope).expect("STAGE context");
        let stage_manifest = decrypt_manifest(
            &OwnedKeyMaterial::from_bytes(SOURCE_KEY),
            stage_context,
            stage_envelope,
        )
        .expect("STAGE checkpoint authenticates");
        assert_eq!(stage_manifest.rotation_phase(), RotationPhase::Stage);
        assert!(
            stage_manifest
                .objects()
                .iter()
                .all(|object| object.key_generation() == identity.target_generation())
        );

        let verified = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("VERIFY resumes after restart");
        assert_eq!(
            verified,
            FullRotationProgress::InProgress {
                identity,
                phase: RotationPhase::Verify,
            }
        );
        assert_eq!(backend.stage_calls, 1);
        assert_eq!(backend.verify_calls, 1);
        assert!(source.record.is_some());
        let verify_envelope = backend.checkpoint.as_ref().expect("VERIFY checkpoint");
        let verify_context = manifest_context(verify_envelope).expect("VERIFY context");
        let verify_manifest = decrypt_manifest(
            &OwnedKeyMaterial::from_bytes(SOURCE_KEY),
            verify_context,
            verify_envelope,
        )
        .expect("VERIFY checkpoint authenticates");
        assert_eq!(verify_manifest.rotation_phase(), RotationPhase::Verify);

        let published = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("PUBLISH resumes after VERIFY");
        assert_eq!(
            published,
            FullRotationProgress::InProgress {
                identity,
                phase: RotationPhase::Publish,
            }
        );
        assert!(source.record.is_some());
        assert!(!backend.target_activated);
        assert!(!backend.source_inventory_retired);

        let anchored = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("ANCHOR resumes after PUBLISH");
        assert_eq!(
            anchored,
            FullRotationProgress::InProgress {
                identity,
                phase: RotationPhase::Anchor,
            }
        );
        assert!(source.record.is_some());

        let activated = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("ACTIVATE resumes after ANCHOR");
        assert_eq!(
            activated,
            FullRotationProgress::InProgress {
                identity,
                phase: RotationPhase::Activate,
            }
        );
        assert!(backend.target_activated);
        assert!(source.record.is_some());

        let retiring = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("RETIRE checkpoint follows ACTIVATE");
        assert_eq!(
            retiring,
            FullRotationProgress::InProgress {
                identity,
                phase: RotationPhase::Retire,
            }
        );
        assert!(source.record.is_some());
        assert!(!backend.source_inventory_retired);

        let completed = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("RETIRE completes from stable target");
        let final_anchor = match completed {
            FullRotationProgress::Complete {
                identity: completed_identity,
                final_anchor,
            } => {
                assert_eq!(completed_identity, identity);
                final_anchor
            }
            FullRotationProgress::InProgress { .. } => panic!("RETIRE must complete rotation"),
        };
        assert!(source.record.is_none());
        assert!(backend.source_inventory_retired);
        assert!(backend.source_recovery_retired);
        assert!(backend.target_activated);
        assert!(backend.reopen_calls >= 2);
        assert!(backend.checkpoint.is_none());
        assert!(backend.binding.is_none());
        assert_eq!(
            target
                .read_freshness_anchor(identity.vault_id())
                .expect("target freshness remains present"),
            ProtectedFreshnessState::Present(final_anchor)
        );

        let recovered = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut source,
            &mut target,
            &mut backend,
            &mut ledger,
        )
        .expect("stable target recovery remains idempotent after checkpoint cleanup");
        assert!(matches!(
            recovered,
            FullRotationProgress::Complete {
                identity: recovered_identity,
                final_anchor: recovered_anchor,
            } if recovered_identity == identity && recovered_anchor == final_anchor
        ));
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum B504FaultOp {
        PersistBinding,
        TargetCreate,
        TargetStore,
        TargetGenesis,
        PersistRecovery,
        StageInventory,
        PersistCheckpoint,
        PublishManifest,
        AdvanceTargetAnchor,
        ActivateTarget,
        RetireSourceInventory,
        RetireSourceRecovery,
        RemoveSourceProtector,
        ClearCheckpoint,
        ClearBinding,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum B504FaultSide {
        Before,
        After,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct B504FaultTarget {
        op: B504FaultOp,
        ordinal: usize,
        side: B504FaultSide,
    }

    #[derive(Default)]
    struct B504FaultState {
        target: Option<B504FaultTarget>,
        calls: std::collections::BTreeMap<B504FaultOp, usize>,
        fired: bool,
    }

    #[derive(Clone)]
    struct B504FaultController(std::rc::Rc<std::cell::RefCell<B504FaultState>>);

    impl B504FaultController {
        fn new(target: B504FaultTarget) -> Self {
            Self(std::rc::Rc::new(std::cell::RefCell::new(B504FaultState {
                target: Some(target),
                ..B504FaultState::default()
            })))
        }

        fn enter(&self, op: B504FaultOp) -> usize {
            let mut state = self.0.borrow_mut();
            let calls = state.calls.entry(op).or_insert(0);
            *calls += 1;
            *calls
        }

        fn should_fail(&self, op: B504FaultOp, ordinal: usize, side: B504FaultSide) -> bool {
            let mut state = self.0.borrow_mut();
            if !state.fired && state.target == Some(B504FaultTarget { op, ordinal, side }) {
                state.fired = true;
                true
            } else {
                false
            }
        }

        fn fired(&self) -> bool {
            self.0.borrow().fired
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum B504ProtectorRole {
        Source,
        Target,
    }

    struct B504FaultingProtector {
        inner: MemoryProtector,
        role: B504ProtectorRole,
        faults: B504FaultController,
    }

    impl B504FaultingProtector {
        fn new(
            inner: MemoryProtector,
            role: B504ProtectorRole,
            faults: B504FaultController,
        ) -> Self {
            Self {
                inner,
                role,
                faults,
            }
        }

        fn before(&self, op: B504FaultOp, ordinal: usize) -> Result<(), ProtectorError> {
            if self.faults.should_fail(op, ordinal, B504FaultSide::Before) {
                Err(ProtectorError::Unavailable)
            } else {
                Ok(())
            }
        }

        fn after(&self, op: B504FaultOp, ordinal: usize) -> Result<(), ProtectorError> {
            if self.faults.should_fail(op, ordinal, B504FaultSide::After) {
                Err(ProtectorError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    impl SecretProtector for B504FaultingProtector {
        type VaultRootKey = OwnedKeyMaterial;

        fn create_protector(
            &mut self,
            requested_scope: AccessScope,
            user_presence_policy: UserPresencePolicy,
        ) -> Result<(), ProtectorError> {
            if self.role != B504ProtectorRole::Target {
                return self
                    .inner
                    .create_protector(requested_scope, user_presence_policy);
            }
            let ordinal = self.faults.enter(B504FaultOp::TargetCreate);
            self.before(B504FaultOp::TargetCreate, ordinal)?;
            self.inner
                .create_protector(requested_scope, user_presence_policy)?;
            self.after(B504FaultOp::TargetCreate, ordinal)
        }

        fn protect_or_store_vrk(
            &mut self,
            vault_id: VaultId,
            key_generation: KeyGeneration,
            vrk: &OwnedKeyMaterial,
        ) -> Result<(), ProtectorError> {
            if self.role != B504ProtectorRole::Target {
                return self
                    .inner
                    .protect_or_store_vrk(vault_id, key_generation, vrk);
            }
            let ordinal = self.faults.enter(B504FaultOp::TargetStore);
            self.before(B504FaultOp::TargetStore, ordinal)?;
            self.inner
                .protect_or_store_vrk(vault_id, key_generation, vrk)?;
            self.after(B504FaultOp::TargetStore, ordinal)
        }

        fn unlock_vrk(
            &mut self,
            vault_id: VaultId,
            key_generation: KeyGeneration,
        ) -> Result<OwnedKeyMaterial, ProtectorError> {
            self.inner.unlock_vrk(vault_id, key_generation)
        }

        fn read_freshness_anchor(
            &self,
            vault_id: VaultId,
        ) -> Result<ProtectedFreshnessState, ProtectorError> {
            self.inner.read_freshness_anchor(vault_id)
        }

        fn install_genesis_freshness_anchor(
            &mut self,
            vault_id: VaultId,
            expected_state: ProtectedFreshnessState,
            new_anchor: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            if self.role != B504ProtectorRole::Target {
                return self.inner.install_genesis_freshness_anchor(
                    vault_id,
                    expected_state,
                    new_anchor,
                );
            }
            let ordinal = self.faults.enter(B504FaultOp::TargetGenesis);
            self.before(B504FaultOp::TargetGenesis, ordinal)?;
            self.inner
                .install_genesis_freshness_anchor(vault_id, expected_state, new_anchor)?;
            self.after(B504FaultOp::TargetGenesis, ordinal)
        }

        fn advance_freshness_anchor(
            &mut self,
            vault_id: VaultId,
            expected_old: FreshnessAnchor,
            new_anchor: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            if self.role != B504ProtectorRole::Target {
                return self
                    .inner
                    .advance_freshness_anchor(vault_id, expected_old, new_anchor);
            }
            let ordinal = self.faults.enter(B504FaultOp::AdvanceTargetAnchor);
            self.before(B504FaultOp::AdvanceTargetAnchor, ordinal)?;
            self.inner
                .advance_freshness_anchor(vault_id, expected_old, new_anchor)?;
            self.after(B504FaultOp::AdvanceTargetAnchor, ordinal)
        }

        fn replace_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError> {
            self.inner.replace_protector(vault_id)
        }

        fn remove_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError> {
            if self.role != B504ProtectorRole::Source {
                return self.inner.remove_protector(vault_id);
            }
            let ordinal = self.faults.enter(B504FaultOp::RemoveSourceProtector);
            self.before(B504FaultOp::RemoveSourceProtector, ordinal)?;
            match self.inner.remove_protector(vault_id) {
                Ok(()) => self.after(B504FaultOp::RemoveSourceProtector, ordinal),
                Err(error) => Err(error),
            }
        }

        fn actual_access_scope(&self) -> AccessScope {
            self.inner.actual_access_scope()
        }

        fn requires_user_presence(&self) -> bool {
            self.inner.requires_user_presence()
        }

        fn hardware_backed_state(&self) -> HardwareBacking {
            self.inner.hardware_backed_state()
        }
    }

    struct B504FaultingBackend {
        inner: PrepareBackend,
        faults: B504FaultController,
    }

    impl B504FaultingBackend {
        fn new(inner: PrepareBackend, faults: B504FaultController) -> Self {
            Self { inner, faults }
        }

        fn before(&self, op: B504FaultOp, ordinal: usize) -> Result<(), BackendError> {
            if self.faults.should_fail(op, ordinal, B504FaultSide::Before) {
                Err(BackendError(
                    "B504 injected failure before durable mutation",
                ))
            } else {
                Ok(())
            }
        }

        fn after(&self, op: B504FaultOp, ordinal: usize) -> Result<(), BackendError> {
            if self.faults.should_fail(op, ordinal, B504FaultSide::After) {
                Err(BackendError("B504 injected failure after durable mutation"))
            } else {
                Ok(())
            }
        }
    }

    impl FullRotationBackend for B504FaultingBackend {
        type Error = BackendError;

        fn assert_normal_writes_quiesced(&self) -> Result<(), Self::Error> {
            self.inner.assert_normal_writes_quiesced()
        }

        fn read_rotation_protector_binding(
            &self,
        ) -> Result<Option<FullRotationProtectorBinding>, Self::Error> {
            self.inner.read_rotation_protector_binding()
        }

        fn persist_rotation_protector_binding(
            &mut self,
            binding: FullRotationProtectorBinding,
        ) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::PersistBinding);
            self.before(B504FaultOp::PersistBinding, ordinal)?;
            self.inner.persist_rotation_protector_binding(binding)?;
            self.after(B504FaultOp::PersistBinding, ordinal)
        }

        fn clear_rotation_protector_binding(&mut self) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::ClearBinding);
            self.before(B504FaultOp::ClearBinding, ordinal)?;
            self.inner.clear_rotation_protector_binding()?;
            self.after(B504FaultOp::ClearBinding, ordinal)
        }

        fn read_rotation_checkpoint(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.read_rotation_checkpoint()
        }

        fn persist_rotation_checkpoint(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::PersistCheckpoint);
            self.before(B504FaultOp::PersistCheckpoint, ordinal)?;
            self.inner.persist_rotation_checkpoint(envelope)?;
            self.after(B504FaultOp::PersistCheckpoint, ordinal)
        }

        fn clear_rotation_checkpoint(&mut self) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::ClearCheckpoint);
            self.before(B504FaultOp::ClearCheckpoint, ordinal)?;
            self.inner.clear_rotation_checkpoint()?;
            self.after(B504FaultOp::ClearCheckpoint, ordinal)
        }

        fn read_target_recovery_wrap(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.read_target_recovery_wrap()
        }

        fn persist_target_recovery_wrap(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::PersistRecovery);
            self.before(B504FaultOp::PersistRecovery, ordinal)?;
            self.inner.persist_target_recovery_wrap(envelope)?;
            self.after(B504FaultOp::PersistRecovery, ordinal)
        }

        fn remove_target_recovery_wrap(&mut self) -> Result<(), Self::Error> {
            self.inner.remove_target_recovery_wrap()
        }

        fn stage_reencrypted_inventory(
            &mut self,
            source_vrk: &OwnedKeyMaterial,
            target_vrk: &OwnedKeyMaterial,
            source_manifest: &ManifestPlaintext,
            target_generation: KeyGeneration,
            nonce_ledger: &mut NonceReservationLedger,
        ) -> Result<Vec<ManifestObject>, Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::StageInventory);
            self.before(B504FaultOp::StageInventory, ordinal)?;
            let staged = self.inner.stage_reencrypted_inventory(
                source_vrk,
                target_vrk,
                source_manifest,
                target_generation,
                nonce_ledger,
            )?;
            self.after(B504FaultOp::StageInventory, ordinal)?;
            Ok(staged)
        }

        fn verify_staged_inventory(
            &mut self,
            target_vrk: &OwnedKeyMaterial,
            staged_objects: &[ManifestObject],
        ) -> Result<(), Self::Error> {
            self.inner
                .verify_staged_inventory(target_vrk, staged_objects)
        }

        fn quarantine_target_inventory(&mut self) -> Result<(), Self::Error> {
            self.inner.quarantine_target_inventory()
        }

        fn publish_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::PublishManifest);
            self.before(B504FaultOp::PublishManifest, ordinal)?;
            self.inner.publish_manifest(envelope)?;
            self.after(B504FaultOp::PublishManifest, ordinal)
        }

        fn read_published_manifest(&self) -> Result<Vec<u8>, Self::Error> {
            self.inner.read_published_manifest()
        }

        fn reopen_and_verify_published(
            &mut self,
            target_vrk: &OwnedKeyMaterial,
            manifest: &ManifestPlaintext,
        ) -> Result<(), Self::Error> {
            self.inner.reopen_and_verify_published(target_vrk, manifest)
        }

        fn activate_target_protector(&mut self) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::ActivateTarget);
            self.before(B504FaultOp::ActivateTarget, ordinal)?;
            self.inner.activate_target_protector()?;
            self.after(B504FaultOp::ActivateTarget, ordinal)
        }

        fn retire_source_inventory(
            &mut self,
            source_generation: KeyGeneration,
        ) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::RetireSourceInventory);
            self.before(B504FaultOp::RetireSourceInventory, ordinal)?;
            self.inner.retire_source_inventory(source_generation)?;
            self.after(B504FaultOp::RetireSourceInventory, ordinal)
        }

        fn retire_source_recovery_wrap(&mut self) -> Result<(), Self::Error> {
            let ordinal = self.faults.enter(B504FaultOp::RetireSourceRecovery);
            self.before(B504FaultOp::RetireSourceRecovery, ordinal)?;
            self.inner.retire_source_recovery_wrap()?;
            self.after(B504FaultOp::RetireSourceRecovery, ordinal)
        }
    }

    struct B504FaultFixture {
        vault_id: VaultId,
        source_generation: KeyGeneration,
        source_anchor: FreshnessAnchor,
        current_envelope: Vec<u8>,
        source: B504FaultingProtector,
        target: B504FaultingProtector,
        backend: B504FaultingBackend,
        ledger: NonceReservationLedger,
        quiesced: RotationQuiesced,
        faults: B504FaultController,
    }

    fn b504_fault_fixture(target: B504FaultTarget) -> B504FaultFixture {
        let PrepareFixture {
            vault_id,
            generation,
            envelope,
            source,
            target: target_protector,
            backend,
            ledger,
            mut session,
            source_anchor,
        } = prepare_fixture();
        let quiesced = quiesce_for_full_rotation(&mut session).expect("B504 quiescence succeeds");
        let faults = B504FaultController::new(target);
        B504FaultFixture {
            vault_id,
            source_generation: generation,
            source_anchor,
            current_envelope: envelope,
            source: B504FaultingProtector::new(source, B504ProtectorRole::Source, faults.clone()),
            target: B504FaultingProtector::new(
                target_protector,
                B504ProtectorRole::Target,
                faults.clone(),
            ),
            backend: B504FaultingBackend::new(backend, faults.clone()),
            ledger,
            quiesced,
            faults,
        }
    }

    fn b504_rehydrate_ledger(fixture: &B504FaultFixture) -> NonceReservationLedger {
        let mut reservations = Vec::new();
        for envelope in [
            Some(fixture.current_envelope.as_slice()),
            fixture.backend.inner.checkpoint.as_deref(),
            fixture.backend.inner.published.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let reservation = manifest_nonce_reservation(envelope)
                .expect("B504 retained manifest reservation parses");
            if !reservations.contains(&reservation) {
                reservations.push(reservation);
            }
        }
        NonceReservationLedger::from_authenticated_canonical_reservations(
            fixture.vault_id,
            reservations,
        )
        .expect("B504 authenticated retained reservations rehydrate")
    }

    fn b504_assert_recoverable_state(fixture: &mut B504FaultFixture, target: B504FaultTarget) {
        let source_present = fixture.source.inner.record.is_some();
        let source_must_be_present = match target.op {
            B504FaultOp::RemoveSourceProtector => target.side == B504FaultSide::Before,
            B504FaultOp::ClearCheckpoint | B504FaultOp::ClearBinding => false,
            _ => true,
        };
        assert_eq!(
            source_present, source_must_be_present,
            "B504 target {target:?} must preserve source protector until its explicit removal boundary"
        );

        if source_present {
            let source_vrk = fixture
                .source
                .inner
                .unlock_vrk(fixture.vault_id, fixture.source_generation)
                .expect("B504 retained source VRK unlocks");
            let context = manifest_context(&fixture.current_envelope)
                .expect("B504 source manifest context parses");
            let source_manifest = decrypt_manifest(&source_vrk, context, &fixture.current_envelope)
                .expect("B504 retained source manifest decrypts");
            assert_eq!(source_manifest.rotation_phase(), RotationPhase::None);
            assert_eq!(
                source_manifest.active_key_generation(),
                fixture.source_generation
            );
            assert_eq!(
                fixture
                    .source
                    .inner
                    .read_freshness_anchor(fixture.vault_id)
                    .expect("B504 source freshness reads"),
                ProtectedFreshnessState::Present(fixture.source_anchor)
            );
        }

        if let Some(published) = fixture.backend.inner.published.as_deref() {
            let target_vrk = OwnedKeyMaterial::from_bytes(fixture.target.inner.key_bytes());
            let context = manifest_context(published).expect("B504 published context parses");
            let manifest = decrypt_manifest(&target_vrk, context, published)
                .expect("B504 published target state decrypts");
            assert_eq!(manifest.active_key_generation(), context.key_generation());
            assert!(matches!(
                manifest.rotation_phase(),
                RotationPhase::Publish | RotationPhase::None
            ));
        }
    }

    fn b504_drive_fault_scenario(target: B504FaultTarget, recovery: Option<(&[u8], &str)>) {
        let mut fixture = b504_fault_fixture(target);
        let identity =
            FullRotationIdentity::for_next_generation(fixture.vault_id, fixture.source_generation)
                .expect("B504 next generation exists");
        let recovery_input =
            recovery.map(|(envelope, passphrase)| RecoveryRotationInput::new(envelope, passphrase));

        let first = begin_full_rotation(
            fixture.quiesced,
            &mut fixture.source,
            &mut fixture.target,
            &mut fixture.backend,
            &mut fixture.ledger,
            &fixture.current_envelope,
            prepare_binding(),
            prepare_policy(),
            recovery_input,
        );
        if first.is_ok() {
            loop {
                match resume_full_rotation_after_restart(
                    identity,
                    prepare_binding(),
                    &mut fixture.source,
                    &mut fixture.target,
                    &mut fixture.backend,
                    &mut fixture.ledger,
                ) {
                    Ok(FullRotationProgress::InProgress { .. }) => {}
                    Ok(FullRotationProgress::Complete { .. }) => {
                        panic!("B504 target {target:?} did not fire before completion")
                    }
                    Err(_) => break,
                }
            }
        }
        assert!(
            fixture.faults.fired(),
            "B504 target {target:?} must inject exactly one failure"
        );
        b504_assert_recoverable_state(&mut fixture, target);

        let rehydrated = b504_rehydrate_ledger(&fixture);
        fixture.ledger = rehydrated;
        if fixture.backend.inner.checkpoint.is_none() && fixture.backend.inner.published.is_none() {
            let retried = begin_full_rotation(
                fixture.quiesced,
                &mut fixture.source,
                &mut fixture.target,
                &mut fixture.backend,
                &mut fixture.ledger,
                &fixture.current_envelope,
                prepare_binding(),
                prepare_policy(),
                recovery_input,
            )
            .expect("B504 pre-checkpoint retry must recover");
            assert_eq!(
                retried,
                FullRotationProgress::InProgress {
                    identity,
                    phase: RotationPhase::Prepare,
                }
            );
        }

        let final_anchor = loop {
            match resume_full_rotation_after_restart(
                identity,
                prepare_binding(),
                &mut fixture.source,
                &mut fixture.target,
                &mut fixture.backend,
                &mut fixture.ledger,
            )
            .expect("B504 restart must roll forward")
            {
                FullRotationProgress::InProgress { .. } => {}
                FullRotationProgress::Complete {
                    identity: completed,
                    final_anchor,
                } => {
                    assert_eq!(completed, identity);
                    break final_anchor;
                }
            }
        };

        assert!(fixture.source.inner.record.is_none());
        assert!(fixture.backend.inner.source_inventory_retired);
        assert!(fixture.backend.inner.source_recovery_retired);
        assert!(fixture.backend.inner.target_activated);
        assert!(fixture.backend.inner.checkpoint.is_none());
        assert!(fixture.backend.inner.binding.is_none());

        let target_vrk = fixture
            .target
            .inner
            .unlock_vrk(fixture.vault_id, identity.target_generation())
            .expect("B504 final target VRK unlocks");
        let published = fixture
            .backend
            .inner
            .published
            .as_deref()
            .expect("B504 stable target manifest remains published");
        let context = manifest_context(published).expect("B504 stable context parses");
        let stable = decrypt_manifest(&target_vrk, context, published)
            .expect("B504 stable target manifest decrypts");
        assert_eq!(stable.rotation_phase(), RotationPhase::None);
        assert_eq!(stable.active_key_generation(), identity.target_generation());
        assert_eq!(
            fixture
                .target
                .inner
                .read_freshness_anchor(fixture.vault_id)
                .expect("B504 final target anchor reads"),
            ProtectedFreshnessState::Present(final_anchor)
        );
        assert_eq!(manifest_hash(published), final_anchor.manifest_hash());

        fixture.ledger = b504_rehydrate_ledger(&fixture);
        let repeated = resume_full_rotation_after_restart(
            identity,
            prepare_binding(),
            &mut fixture.source,
            &mut fixture.target,
            &mut fixture.backend,
            &mut fixture.ledger,
        )
        .expect("B504 stable completion is idempotent after another restart");
        assert_eq!(
            repeated,
            FullRotationProgress::Complete {
                identity,
                final_anchor,
            }
        );

        if let Some((_, passphrase)) = recovery {
            let target_recovery = fixture
                .backend
                .inner
                .recovery
                .as_deref()
                .expect("B504 target recovery wrap remains retained after stable restart");
            let recovered_target = decrypt_recovery_envelope(
                RecoveryContext::new(fixture.vault_id, identity.target_generation()),
                passphrase,
                target_recovery,
            )
            .expect("B504 retained target recovery wrap authenticates after stable restart");
            assert!(key_material_equal(&target_vrk, &recovered_target));
        }
    }

    #[test]
    fn b504_fault_injection_before_after_every_rotation_commit_point_recovers() {
        let points = [
            (B504FaultOp::PersistBinding, 1),
            (B504FaultOp::TargetCreate, 1),
            (B504FaultOp::TargetStore, 1),
            (B504FaultOp::TargetGenesis, 1),
            (B504FaultOp::PersistCheckpoint, 1),
            (B504FaultOp::StageInventory, 1),
            (B504FaultOp::PersistCheckpoint, 2),
            (B504FaultOp::PersistCheckpoint, 3),
            (B504FaultOp::PublishManifest, 1),
            (B504FaultOp::PersistCheckpoint, 4),
            (B504FaultOp::AdvanceTargetAnchor, 1),
            (B504FaultOp::PersistCheckpoint, 5),
            (B504FaultOp::ActivateTarget, 1),
            (B504FaultOp::PersistCheckpoint, 6),
            (B504FaultOp::ActivateTarget, 2),
            (B504FaultOp::PersistCheckpoint, 7),
            (B504FaultOp::PublishManifest, 2),
            (B504FaultOp::AdvanceTargetAnchor, 2),
            (B504FaultOp::ActivateTarget, 3),
            (B504FaultOp::RetireSourceInventory, 1),
            (B504FaultOp::RetireSourceRecovery, 1),
            (B504FaultOp::RemoveSourceProtector, 1),
            (B504FaultOp::ClearCheckpoint, 1),
            (B504FaultOp::ClearBinding, 1),
        ];
        assert_eq!(points.len(), 24);
        for (op, ordinal) in points {
            for side in [B504FaultSide::Before, B504FaultSide::After] {
                b504_drive_fault_scenario(B504FaultTarget { op, ordinal, side }, None);
            }
        }
    }

    #[test]
    fn b504_target_recovery_wrap_before_after_commit_recovers() {
        for side in [B504FaultSide::Before, B504FaultSide::After] {
            let fixture = prepare_fixture();
            let source_vrk = OwnedKeyMaterial::from_bytes(SOURCE_KEY);
            let source_envelope = encrypt_recovery_envelope(
                &source_vrk,
                RecoveryContext::new(fixture.vault_id, fixture.generation),
                "b504-recovery-passphrase",
            )
            .expect("B504 source recovery envelope encrypts");
            b504_drive_fault_scenario(
                B504FaultTarget {
                    op: B504FaultOp::PersistRecovery,
                    ordinal: 1,
                    side,
                },
                Some((&source_envelope, "b504-recovery-passphrase")),
            );
        }
    }
}

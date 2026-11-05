//! B502 explicit restore state-transition semantics.
//!
//! This module intentionally does not implement the B505 portable-backup
//! container or provider transport. It authenticates an already-supplied
//! manifest envelope, freezes the reviewed restore decision, and constructs the
//! exact freshness transition that a later storage coordinator must publish and
//! verify before mutating protected state.

use crate::vault::{FreshnessAnchor, FreshnessEpoch, ProtectedFreshnessState};
use crate::vault_keys::OwnedKeyMaterial;
use crate::vault_manifest::{
    FreshManifestError, ManifestContext, ManifestError, ManifestPlaintext, decrypt_manifest,
    encrypt_fresh_manifest_avoiding_reservation, manifest_context, manifest_hash,
    manifest_nonce_reservation,
};
use crate::vault_nonce::{NonceLifecycleError, NonceReservationLedger};
use std::error::Error;
use std::fmt;

/// Explicit caller assertion that the user confirmed intentional rollback
/// recovery from an older authenticated backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OlderBackupRestoreConfirmed {
    _private: (),
}

impl OlderBackupRestoreConfirmed {
    /// Explicit proof token for a caller that already obtained user confirmation.
    pub const CONFIRMED: Self = Self { _private: () };
}

/// Explicit caller assertion that the user accepted the fresh-device residual
/// risk: SafeEvidence can authenticate the selected backup but cannot prove that it is
/// globally newest without a prior trusted anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshDeviceNewestnessRiskAccepted {
    _private: (),
}

impl FreshDeviceNewestnessRiskAccepted {
    /// Explicit proof token for a caller that already recorded residual-risk acceptance.
    pub const ACCEPTED: Self = Self { _private: () };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreError {
    Manifest(ManifestError),
    FreshManifest(FreshManifestError),
    CorruptOrTampered,
    KeyGenerationMismatch,
    NotOlderBackup,
    EpochExhausted,
    AnchorAlreadyInitialized,
}

impl From<ManifestError> for RestoreError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<FreshManifestError> for RestoreError {
    fn from(value: FreshManifestError) -> Self {
        Self::FreshManifest(value)
    }
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(f, "restore manifest failed: {error}"),
            Self::FreshManifest(error) => write!(f, "restore republication failed: {error}"),
            Self::CorruptOrTampered => f.write_str("restore state is corrupt or tampered"),
            Self::KeyGenerationMismatch => {
                f.write_str("backup key generation does not match current active generation")
            }
            Self::NotOlderBackup => {
                f.write_str("restore candidate is not older than the trusted anchor")
            }
            Self::EpochExhausted => f.write_str("freshness epoch cannot be advanced"),
            Self::AnchorAlreadyInitialized => {
                f.write_str("fresh-device restore genesis is already initialized")
            }
        }
    }
}

impl Error for RestoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::FreshManifest(error) => Some(error),
            _ => None,
        }
    }
}

/// Authenticated older-backup content republished into a new local epoch.
#[derive(Debug, Eq, PartialEq)]
pub struct OlderBackupRestorePublication {
    source_manifest: ManifestPlaintext,
    target_manifest: ManifestPlaintext,
    envelope: Vec<u8>,
    expected_old_anchor: FreshnessAnchor,
    new_anchor: FreshnessAnchor,
}

impl OlderBackupRestorePublication {
    #[must_use]
    pub const fn source_manifest(&self) -> &ManifestPlaintext {
        &self.source_manifest
    }

    #[must_use]
    pub const fn target_manifest(&self) -> &ManifestPlaintext {
        &self.target_manifest
    }

    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    #[must_use]
    pub const fn expected_old_anchor(&self) -> FreshnessAnchor {
        self.expected_old_anchor
    }

    #[must_use]
    pub const fn new_anchor(&self) -> FreshnessAnchor {
        self.new_anchor
    }
}

/// Authenticated fresh-device restore candidate bound to explicit protected
/// genesis and to the recorded global-newestness residual risk.
#[derive(Debug, Eq, PartialEq)]
pub struct FreshDeviceRestoreGenesis {
    manifest: ManifestPlaintext,
    accepted_anchor: FreshnessAnchor,
    global_newestness_proven: bool,
}

impl FreshDeviceRestoreGenesis {
    #[must_use]
    pub const fn manifest(&self) -> &ManifestPlaintext {
        &self.manifest
    }

    #[must_use]
    pub const fn accepted_anchor(&self) -> FreshnessAnchor {
        self.accepted_anchor
    }

    #[must_use]
    pub const fn global_newestness_proven(&self) -> bool {
        self.global_newestness_proven
    }
}

fn authenticate_backup(
    vrk: &OwnedKeyMaterial,
    envelope: &[u8],
) -> Result<(ManifestContext, ManifestPlaintext), RestoreError> {
    let context = manifest_context(envelope)?;
    let manifest = decrypt_manifest(vrk, context, envelope)?;
    Ok((context, manifest))
}

/// Authenticates an older backup first, then republishes its verified manifest
/// semantics at exactly `trusted_anchor.highest_epoch + 1` using a fresh B203
/// manifest nonce. The trusted anchor is never decremented or overwritten here.
/// The supplied nonce ledger must already contain every retained authenticated
/// canonical manifest reservation except the exact backup candidate being restored.
/// B502 rejects a source whose active key generation differs from the current
/// active generation; cross-VRK-generation recovery remains a B503 integration.
///
/// Callers must write/fsync and reread/verify this returned envelope and its
/// complete object set before calling the separately qualified protected
/// `advance_freshness_anchor(expected_old, new_anchor)` operation.
pub fn prepare_older_backup_restore(
    ledger: &mut NonceReservationLedger,
    vrk: &OwnedKeyMaterial,
    trusted_anchor: FreshnessAnchor,
    current_key_generation: crate::vault::KeyGeneration,
    backup_manifest_envelope: &[u8],
    _confirmation: OlderBackupRestoreConfirmed,
) -> Result<OlderBackupRestorePublication, RestoreError> {
    let (source_context, source_manifest) = authenticate_backup(vrk, backup_manifest_envelope)?;
    if source_context.vault_id() != trusted_anchor.vault_id() {
        return Err(RestoreError::CorruptOrTampered);
    }
    if source_context.freshness_epoch() >= trusted_anchor.highest_epoch() {
        return Err(RestoreError::NotOlderBackup);
    }
    if source_context.key_generation() != current_key_generation
        || source_manifest.active_key_generation() != current_key_generation
    {
        return Err(RestoreError::KeyGenerationMismatch);
    }
    let next_epoch = trusted_anchor
        .highest_epoch()
        .get()
        .checked_add(1)
        .ok_or(RestoreError::EpochExhausted)
        .and_then(|value| FreshnessEpoch::new(value).map_err(|_| RestoreError::EpochExhausted))?;
    let source_reservation = manifest_nonce_reservation(backup_manifest_envelope)?;
    if ledger.contains(source_reservation) {
        return Err(RestoreError::FreshManifest(FreshManifestError::Nonce(
            NonceLifecycleError::CorruptOrTampered,
        )));
    }
    let target_manifest =
        source_manifest.republish_for_restore(next_epoch, trusted_anchor.manifest_hash())?;
    let target_context = ManifestContext::new(
        target_manifest.vault_id(),
        target_manifest.active_key_generation(),
        next_epoch,
    );
    let (_reservation, envelope) = encrypt_fresh_manifest_avoiding_reservation(
        ledger,
        vrk,
        target_context,
        &target_manifest,
        source_reservation,
    )?;
    let reread = decrypt_manifest(vrk, target_context, &envelope)?;
    if reread != target_manifest {
        return Err(RestoreError::CorruptOrTampered);
    }
    let new_anchor = FreshnessAnchor::new(
        trusted_anchor.vault_id(),
        next_epoch,
        manifest_hash(&envelope),
    );
    Ok(OlderBackupRestorePublication {
        source_manifest,
        target_manifest,
        envelope,
        expected_old_anchor: trusted_anchor,
        new_anchor,
    })
}

/// Authenticates an accepted backup before making the fresh-device genesis
/// decision. Only an already-existing protected `UNINITIALIZED` record is a
/// valid genesis state; a missing provider item cannot be represented here and
/// must remain a typed provider failure at the adapter boundary.
pub fn prepare_fresh_device_restore_genesis(
    vrk: &OwnedKeyMaterial,
    expected_vault_id: crate::vault::VaultId,
    protected_state: ProtectedFreshnessState,
    backup_manifest_envelope: &[u8],
    _risk_acceptance: FreshDeviceNewestnessRiskAccepted,
) -> Result<FreshDeviceRestoreGenesis, RestoreError> {
    let (context, manifest) = authenticate_backup(vrk, backup_manifest_envelope)?;
    if context.vault_id() != expected_vault_id {
        return Err(RestoreError::CorruptOrTampered);
    }
    if matches!(protected_state, ProtectedFreshnessState::Present(_)) {
        return Err(RestoreError::AnchorAlreadyInitialized);
    }
    let accepted_anchor = FreshnessAnchor::new(
        expected_vault_id,
        context.freshness_epoch(),
        manifest_hash(backup_manifest_envelope),
    );
    Ok(FreshDeviceRestoreGenesis {
        manifest,
        accepted_anchor,
        global_newestness_proven: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{FreshnessEpoch, KeyGeneration, ManifestHash, VaultId};
    use crate::vault_manifest::{
        GenerationState, ManifestAuthMetadata, ManifestGeneration, ManifestObject, RotationPhase,
        encrypt_fresh_manifest,
    };

    fn vault() -> VaultId {
        VaultId::from_bytes([0x51; 16])
    }

    fn key() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([0x52; 32])
    }

    fn generation() -> KeyGeneration {
        KeyGeneration::new(1).expect("generation")
    }

    fn epoch(value: u64) -> FreshnessEpoch {
        FreshnessEpoch::new(value).expect("epoch")
    }

    fn manifest(value: u64, previous: ManifestHash) -> ManifestPlaintext {
        ManifestPlaintext::new(
            vault(),
            epoch(value),
            previous,
            generation(),
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(
                generation(),
                GenerationState::Active,
            )],
            vec![ManifestObject::new(
                [0; 16],
                [0x54; 16],
                generation(),
                4096,
                [0x55; 32],
                ManifestAuthMetadata::StructuredStore,
            )],
        )
        .expect("manifest")
    }

    fn encrypted_manifest(
        ledger: &mut NonceReservationLedger,
        value: u64,
        previous: ManifestHash,
    ) -> Vec<u8> {
        let plaintext = manifest(value, previous);
        let context = ManifestContext::new(vault(), generation(), epoch(value));
        encrypt_fresh_manifest(ledger, &key(), context, &plaintext)
            .expect("encrypt")
            .1
    }

    #[test]
    fn older_backup_is_republished_exactly_above_anchor_with_fresh_hash() {
        let mut source_ledger = NonceReservationLedger::new(vault());
        let backup =
            encrypted_manifest(&mut source_ledger, 2, ManifestHash::from_bytes([0x41; 32]));
        let mut restore_ledger = NonceReservationLedger::new(vault());
        let anchor = FreshnessAnchor::new(vault(), epoch(7), ManifestHash::from_bytes([0x61; 32]));
        let publication = prepare_older_backup_restore(
            &mut restore_ledger,
            &key(),
            anchor,
            generation(),
            &backup,
            OlderBackupRestoreConfirmed::CONFIRMED,
        )
        .expect("restore publication");

        assert_eq!(publication.source_manifest().freshness_epoch(), epoch(2));
        assert_eq!(publication.target_manifest().freshness_epoch(), epoch(8));
        assert_eq!(
            publication.target_manifest().previous_manifest_hash(),
            anchor.manifest_hash()
        );
        assert_eq!(publication.expected_old_anchor(), anchor);
        assert_eq!(publication.new_anchor().highest_epoch(), epoch(8));
        assert_eq!(
            publication.new_anchor().manifest_hash(),
            manifest_hash(publication.envelope())
        );
        assert_ne!(
            publication.new_anchor().manifest_hash(),
            manifest_hash(&backup)
        );
        assert_ne!(publication.envelope(), backup.as_slice());
        assert_eq!(restore_ledger.reservation_count(), 1);
    }

    #[test]
    fn envelope_and_manifest_generations_must_both_match_current_generation() {
        let current_generation = KeyGeneration::new(2).expect("generation");
        let plaintext = ManifestPlaintext::new(
            vault(),
            epoch(2),
            ManifestHash::from_bytes([0x41; 32]),
            generation(),
            (RotationPhase::None, None),
            vec![
                ManifestGeneration::new(generation(), GenerationState::Active),
                ManifestGeneration::new(current_generation, GenerationState::Retained),
            ],
            vec![ManifestObject::new(
                [0; 16],
                [0x54; 16],
                generation(),
                4096,
                [0x55; 32],
                ManifestAuthMetadata::StructuredStore,
            )],
        )
        .expect("manifest");
        let mut source_ledger = NonceReservationLedger::new(vault());
        let context = ManifestContext::new(vault(), current_generation, epoch(2));
        let backup = encrypt_fresh_manifest(&mut source_ledger, &key(), context, &plaintext)
            .expect("encrypt")
            .1;
        let anchor = FreshnessAnchor::new(vault(), epoch(7), ManifestHash::from_bytes([0x61; 32]));
        let mut restore_ledger = NonceReservationLedger::new(vault());

        assert_eq!(
            prepare_older_backup_restore(
                &mut restore_ledger,
                &key(),
                anchor,
                current_generation,
                &backup,
                OlderBackupRestoreConfirmed::CONFIRMED,
            ),
            Err(RestoreError::KeyGenerationMismatch)
        );
        assert_eq!(restore_ledger.reservation_count(), 0);
    }

    #[test]
    fn retry_does_not_poison_the_ledger_with_the_authenticated_source_nonce() {
        let mut source_ledger = NonceReservationLedger::new(vault());
        let backup =
            encrypted_manifest(&mut source_ledger, 2, ManifestHash::from_bytes([0x41; 32]));
        let source_reservation = manifest_nonce_reservation(&backup).expect("source reservation");
        let anchor = FreshnessAnchor::new(vault(), epoch(7), ManifestHash::from_bytes([0x61; 32]));
        let mut restore_ledger = NonceReservationLedger::new(vault());

        let first = prepare_older_backup_restore(
            &mut restore_ledger,
            &key(),
            anchor,
            generation(),
            &backup,
            OlderBackupRestoreConfirmed::CONFIRMED,
        )
        .expect("first candidate");
        assert!(!restore_ledger.contains(source_reservation));
        assert_eq!(restore_ledger.reservation_count(), 1);

        let second = prepare_older_backup_restore(
            &mut restore_ledger,
            &key(),
            anchor,
            generation(),
            &backup,
            OlderBackupRestoreConfirmed::CONFIRMED,
        )
        .expect("retry candidate");
        assert!(!restore_ledger.contains(source_reservation));
        assert_eq!(restore_ledger.reservation_count(), 2);
        assert_ne!(first.envelope(), second.envelope());
    }

    #[test]
    fn duplicate_authenticated_source_nonce_fails_closed_before_republication() {
        let mut source_ledger = NonceReservationLedger::new(vault());
        let backup =
            encrypted_manifest(&mut source_ledger, 2, ManifestHash::from_bytes([0x41; 32]));
        let source_reservation = manifest_nonce_reservation(&backup).expect("source reservation");
        let mut restore_ledger = NonceReservationLedger::new(vault());
        restore_ledger
            .record_authenticated_canonical_reservation(source_reservation)
            .expect("seed duplicate");
        let anchor = FreshnessAnchor::new(vault(), epoch(7), ManifestHash::from_bytes([0x61; 32]));

        assert_eq!(
            prepare_older_backup_restore(
                &mut restore_ledger,
                &key(),
                anchor,
                generation(),
                &backup,
                OlderBackupRestoreConfirmed::CONFIRMED,
            ),
            Err(RestoreError::FreshManifest(FreshManifestError::Nonce(
                crate::vault_nonce::NonceLifecycleError::CorruptOrTampered
            )))
        );
        assert_eq!(restore_ledger.reservation_count(), 1);
    }

    #[test]
    fn existing_anchor_restore_rejects_equal_future_wrong_vault_and_overflow() {
        let mut ledger = NonceReservationLedger::new(vault());
        let current = encrypted_manifest(&mut ledger, 7, ManifestHash::from_bytes([0x60; 32]));
        let future = encrypted_manifest(&mut ledger, 8, manifest_hash(&current));
        let anchor = FreshnessAnchor::new(vault(), epoch(7), manifest_hash(&current));
        for candidate in [&current, &future] {
            assert_eq!(
                prepare_older_backup_restore(
                    &mut ledger,
                    &key(),
                    anchor,
                    generation(),
                    candidate,
                    OlderBackupRestoreConfirmed::CONFIRMED,
                ),
                Err(RestoreError::NotOlderBackup)
            );
        }

        let old = encrypted_manifest(&mut ledger, 2, ManifestHash::from_bytes([0x41; 32]));
        let wrong_vault_anchor = FreshnessAnchor::new(
            VaultId::from_bytes([0x99; 16]),
            epoch(7),
            ManifestHash::from_bytes([0x61; 32]),
        );
        assert_eq!(
            prepare_older_backup_restore(
                &mut ledger,
                &key(),
                wrong_vault_anchor,
                generation(),
                &old,
                OlderBackupRestoreConfirmed::CONFIRMED,
            ),
            Err(RestoreError::CorruptOrTampered)
        );

        assert_eq!(
            prepare_older_backup_restore(
                &mut ledger,
                &key(),
                anchor,
                KeyGeneration::new(2).expect("generation"),
                &old,
                OlderBackupRestoreConfirmed::CONFIRMED,
            ),
            Err(RestoreError::KeyGenerationMismatch)
        );

        let exhausted = FreshnessAnchor::new(
            vault(),
            epoch(u64::MAX),
            ManifestHash::from_bytes([0x62; 32]),
        );
        assert_eq!(
            prepare_older_backup_restore(
                &mut ledger,
                &key(),
                exhausted,
                generation(),
                &old,
                OlderBackupRestoreConfirmed::CONFIRMED,
            ),
            Err(RestoreError::EpochExhausted)
        );
    }

    #[test]
    fn fresh_device_accepts_authenticated_nonzero_epoch_and_records_residual_risk() {
        let mut ledger = NonceReservationLedger::new(vault());
        let backup = encrypted_manifest(&mut ledger, 4, ManifestHash::from_bytes([0x43; 32]));
        let genesis = prepare_fresh_device_restore_genesis(
            &key(),
            vault(),
            ProtectedFreshnessState::Uninitialized,
            &backup,
            FreshDeviceNewestnessRiskAccepted::ACCEPTED,
        )
        .expect("fresh-device genesis");

        assert_eq!(genesis.manifest().freshness_epoch(), epoch(4));
        assert_eq!(genesis.accepted_anchor().highest_epoch(), epoch(4));
        assert_eq!(
            genesis.accepted_anchor().manifest_hash(),
            manifest_hash(&backup)
        );
        assert!(!genesis.global_newestness_proven());
    }

    #[test]
    fn authentication_precedes_restore_state_decisions() {
        let mut ledger = NonceReservationLedger::new(vault());
        let backup = encrypted_manifest(&mut ledger, 2, ManifestHash::from_bytes([0x41; 32]));
        let mut tampered = backup.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let wrong_anchor = FreshnessAnchor::new(
            VaultId::from_bytes([0x99; 16]),
            epoch(7),
            ManifestHash::from_bytes([0x61; 32]),
        );
        assert_eq!(
            prepare_older_backup_restore(
                &mut ledger,
                &key(),
                wrong_anchor,
                generation(),
                &tampered,
                OlderBackupRestoreConfirmed::CONFIRMED,
            ),
            Err(RestoreError::Manifest(ManifestError::AuthenticationFailed))
        );
        let already_present =
            FreshnessAnchor::new(vault(), epoch(7), ManifestHash::from_bytes([0x61; 32]));
        assert_eq!(
            prepare_fresh_device_restore_genesis(
                &key(),
                VaultId::from_bytes([0x99; 16]),
                ProtectedFreshnessState::Present(already_present),
                &tampered,
                FreshDeviceNewestnessRiskAccepted::ACCEPTED,
            ),
            Err(RestoreError::Manifest(ManifestError::AuthenticationFailed))
        );
    }

    #[test]
    fn fresh_device_rejects_present_state_and_wrong_vault_after_authentication() {
        let mut ledger = NonceReservationLedger::new(vault());
        let backup = encrypted_manifest(&mut ledger, 4, ManifestHash::from_bytes([0x43; 32]));
        let present = FreshnessAnchor::new(vault(), epoch(7), ManifestHash::from_bytes([0x61; 32]));
        assert_eq!(
            prepare_fresh_device_restore_genesis(
                &key(),
                vault(),
                ProtectedFreshnessState::Present(present),
                &backup,
                FreshDeviceNewestnessRiskAccepted::ACCEPTED,
            ),
            Err(RestoreError::AnchorAlreadyInitialized)
        );
        assert_eq!(
            prepare_fresh_device_restore_genesis(
                &key(),
                VaultId::from_bytes([0x99; 16]),
                ProtectedFreshnessState::Uninitialized,
                &backup,
                FreshDeviceNewestnessRiskAccepted::ACCEPTED,
            ),
            Err(RestoreError::CorruptOrTampered)
        );
    }
}

//! B506 active-vault deletion contract for Specification 004.
//!
//! This module owns only the bounded deletion coordinator required to retire one
//! active local vault. It defines which local surfaces must be removed, the exact
//! removal order, and the explicit retention/erasure limitations. It performs no
//! cryptographic operation, entropy acquisition, persistence implementation,
//! platform secure-store work, or network/provider deletion.
//!
//! The concrete backend owns every durable removal behind this boundary. The core
//! coordinator never assumes fixed filenames, database layouts, or platform
//! mechanics; each trait method documents the surface family it must cover,
//! including companion filesystem and database artifacts (`-wal`, `-shm`,
//! `-journal`, temp copies, staging directories).
//!
//! Removal order is intentionally crypto-shredding first: all active local
//! wrapped-key material is removed before ciphertext-bearing surfaces, with
//! freshness-anchor records removed before protector references so freshness
//! enumeration stays available through its own stage. An interruption after the
//! key-material stage therefore leaves remaining local ciphertext without its
//! SafeEvidence-managed wraps, provided no key copies survive outside those wraps
//! (allocator, swap, dump, or flash-remnant copies remain a documented
//! limitation). This ordering does not claim physical-media erasure.
//!
//! Required caller flow before invoking the coordinator:
//!
//! 1. quiesce ordinary vault writes (the backend proves exclusion);
//! 2. tear down the live vault session through `VaultSessionLifetime::teardown`,
//!    which revokes the lease, closes keyed handles, releases VRK/KEK/purpose-key
//!    objects, zeroizes owned buffers, and discards session plaintext caches;
//! 3. invoke [`run_active_vault_deletion`] with the terminal lease.
//!
//! The terminal lease is revocation evidence, not teardown proof: it proves no
//! new keyed operation can be authorized and in-flight operations drained, but
//! it does not by itself prove handle closure, key release, or cache discard
//! ran. The caller must perform session teardown first; the coordinator refuses
//! a live lease before touching any durable surface, and every removal is
//! idempotent so a retried deletion after an interruption converges.
//!
//! Explicit non-goals, restated from the canonical Specification 004 deletion
//! limits and repeated in [`ACTIVE_VAULT_DELETION_LIMITATIONS`]:
//!
//! - detached/exported portable backups are independent copies and survive;
//! - provider snapshots, user-made duplicates, and external copies survive;
//! - no physical-media secure erasure is claimed (SSD/flash wear-levelling,
//!   controller remapping, and filesystem behavior may retain recoverable
//!   blocks);
//! - language/runtime zeroization does not erase allocator, swap, crash-dump, or
//!   kernel copies;
//! - provider-side deletion belongs to the connector/sync capability that
//!   controls that provider.

use crate::vault::{VaultLeaseIdentity, VaultLeaseState};
use crate::vault_lease::VaultLease;
use std::error::Error;
use std::fmt;

/// User-facing retention and erasure limitation notice for active-vault deletion.
///
/// SafeEvidence must present this limitation at export/deletion time. Deleting the
/// active local vault cannot remotely revoke, erase, or invalidate detached
/// copies, provider snapshots, or user-made duplicates, and local removal is
/// not guaranteed physical-media erasure.
pub const ACTIVE_VAULT_DELETION_LIMITATIONS: &str = concat!(
    "Deleting the active SafeEvidence vault removes SafeEvidence-managed local vault state, ",
    "including canonical records, encrypted blobs, derived indexes and caches, ",
    "temporary files, local wrapped-key material, structured-store database ",
    "artifacts, manifest and freshness state, backup staging files, protector ",
    "references, and migration/restore/publication remnants bound to this vault. ",
    "Detached or exported portable backups containing ciphertext and their own ",
    "recovery-wrapped vault key remain decryptable with the recovery passphrase ",
    "after the active vault is deleted. Deletion cannot remotely revoke, erase, ",
    "or invalidate detached copies, provider snapshots, or user-made duplicates. ",
    "Local removal is not guaranteed physical-media erasure: SSD and mobile ",
    "flash wear-levelling, storage-controller remapping, and filesystem behavior ",
    "may retain recoverable blocks, and in-memory zeroization does not erase ",
    "allocator, swap, crash-dump, or kernel copies. Provider-side deletion is a ",
    "separate connector/sync concern.",
);

/// Exact durable boundary of one bounded active-vault deletion.
///
/// Variants are listed in coordinator execution order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActiveVaultDeletionStage {
    /// Prove ordinary vault writes are quiesced for the complete call.
    Quiesce,
    /// Remove local wrapped-key material for every generation of this vault.
    WrappedKeyMaterial,
    /// Remove freshness-anchor and checkpoint records bound to this vault.
    FreshnessState,
    /// Remove protector item references for every generation of this vault.
    ProtectorReferences,
    /// Remove canonical structured vault records bound to this vault.
    CanonicalState,
    /// Remove derived indexes, caches, and materialized state.
    DerivedState,
    /// Remove local manifest envelopes including retained history.
    ManifestState,
    /// Remove the structured-store database file and companion artifacts.
    StructuredStore,
    /// Remove encrypted blob objects bound to this vault.
    BlobStore,
    /// Remove SafeEvidence-managed backup-creation staging material.
    BackupStaging,
    /// Remove migration/rotation staging and quarantine remnants.
    MigrationRemnants,
    /// Remove restore staging remnants.
    RestoreRemnants,
    /// Remove temporary publication artifacts.
    PublicationTemp,
    /// Remove remaining temporary files and on-disk plaintext-cache residue.
    TemporaryState,
    /// Reread every surface and prove absence.
    Verification,
}

impl fmt::Display for ActiveVaultDeletionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Quiesce => "quiesce",
            Self::WrappedKeyMaterial => "wrapped-key material",
            Self::ProtectorReferences => "protector references",
            Self::FreshnessState => "freshness state",
            Self::CanonicalState => "canonical state",
            Self::DerivedState => "derived state",
            Self::ManifestState => "manifest state",
            Self::StructuredStore => "structured store",
            Self::BlobStore => "blob store",
            Self::BackupStaging => "backup staging",
            Self::MigrationRemnants => "migration remnants",
            Self::RestoreRemnants => "restore remnants",
            Self::PublicationTemp => "publication temp",
            Self::TemporaryState => "temporary state",
            Self::Verification => "verification",
        };
        f.write_str(label)
    }
}

/// Durable backend boundary for bounded active-vault deletion.
///
/// Every removal must be scoped to [`ActiveVaultDeletionBackend::vault_identity`]
/// and must be idempotent: removing an already-absent surface succeeds. No
/// removal may touch detached/exported backups, provider snapshots, or
/// user-made duplicates; those are independent copies outside this boundary.
/// No removal may claim physical-media secure erasure.
pub trait ActiveVaultDeletionBackend {
    /// Caller-defined failure type shared across every deletion boundary.
    type Error;

    /// Vault/generation identity scoping every removal in this call.
    fn vault_identity(&self) -> VaultLeaseIdentity;

    /// Acquires or verifies the concrete exclusion that prevents ordinary vault
    /// writes for the complete coordinator call. A point-in-time observation
    /// that another writer is merely absent is insufficient.
    fn assert_normal_writes_quiesced(&self) -> Result<(), Self::Error>;

    /// Removes local wrapped-key material for every generation of this vault:
    /// protector-wrapped VRKs, recovery-wrap envelopes, target recovery wraps,
    /// and rotation checkpoints containing key material. Detached backup
    /// recovery wraps are independent copies and must not be touched.
    fn remove_wrapped_key_material(&mut self) -> Result<(), Self::Error>;

    /// Removes SafeEvidence-owned freshness records bound to this vault: protected
    /// freshness-anchor records reachable through the authorized protector
    /// boundary and local freshness markers/checkpoints. Runs before protector
    /// references are removed so freshness enumeration stays available through
    /// this stage. Fails closed when the protector boundary is unavailable.
    fn remove_freshness_state(&mut self) -> Result<(), Self::Error>;

    /// Removes protector item references for every generation of this vault in
    /// each platform secret store holding them (Keychain/Keystore/DPAPI/Secret
    /// Service records, ACL-restricted ciphertext sidecars, opaque lookup
    /// entries). Runs after freshness records are gone. Fails closed when a
    /// holding store is unavailable or locked.
    fn remove_protector_references(&mut self) -> Result<(), Self::Error>;

    /// Removes canonical structured vault records bound to this vault identity.
    fn remove_canonical_state(&mut self) -> Result<(), Self::Error>;

    /// Removes derived state bound to this vault: derived indexes, caches, and
    /// materialized views, including their filesystem and database artifacts.
    fn remove_derived_state(&mut self) -> Result<(), Self::Error>;

    /// Removes local authenticated manifest envelopes bound to this vault,
    /// including retained manifest history.
    fn remove_manifest_state(&mut self) -> Result<(), Self::Error>;

    /// Removes the structured-store database file bound to this vault together
    /// with every companion artifact: `-wal`, `-shm`, `-journal` files and any
    /// SafeEvidence-managed temp copies of the database.
    fn remove_structured_store(&mut self) -> Result<(), Self::Error>;

    /// Removes encrypted blob objects and files bound to this vault.
    fn remove_blob_store(&mut self) -> Result<(), Self::Error>;

    /// Removes SafeEvidence-managed backup-creation staging material: snapshot,
    /// package, and SQLCipher verification-staging copies. Exported/detached
    /// backup packages are independent copies and must not be touched.
    fn remove_backup_staging(&mut self) -> Result<(), Self::Error>;

    /// Removes migration remnants: rotation checkpoints, staged and quarantined
    /// target inventories, and non-canonical staged copies from copy-verify-
    /// publish migration.
    fn remove_migration_remnants(&mut self) -> Result<(), Self::Error>;

    /// Removes restore remnants: fresh-device and existing-device restore
    /// staging state, including non-canonical staging manifests and target
    /// staging inventories that were never published.
    fn remove_restore_remnants(&mut self) -> Result<(), Self::Error>;

    /// Removes temporary publication artifacts: rotation/restore/manifest
    /// publication temp files and reread-acceptance temp state.
    fn remove_publication_temp(&mut self) -> Result<(), Self::Error>;

    /// Removes remaining temporary state: SQLite temp files, file-backed temp
    /// leftovers, export-staging temp, and on-disk plaintext-cache residue
    /// owned by this vault. In-memory caches are already discarded by session
    /// teardown before this coordinator runs.
    fn remove_temporary_state(&mut self) -> Result<(), Self::Error>;

    /// Rereads every deletion surface and succeeds only when all of them are
    /// absent. Each surface must be enumerated by its own native means (its
    /// store, directory listing, or protector lookup); a backend must not
    /// prove absence by walking an index that deletion itself removed, since
    /// orphaned objects outside that index would then pass. Any residue fails
    /// this boundary.
    fn verify_deletion_complete(&self) -> Result<(), Self::Error>;
}

/// Exact B506 failure class.
#[derive(Debug, Eq, PartialEq)]
pub enum ActiveVaultDeletionError<E> {
    /// The supplied lease is still live. No durable surface was touched.
    ActiveHandlesNotRevoked,
    /// The lease identity does not scope this backend. No surface was touched.
    IdentityMismatch,
    /// A durable deletion boundary rejected the operation.
    Backend {
        /// Exact stage that failed; later stages were not attempted.
        stage: ActiveVaultDeletionStage,
        /// Caller-defined underlying failure.
        source: E,
    },
}

impl<E> ActiveVaultDeletionError<E> {
    /// Returns the exact failing deletion stage, if a durable boundary failed.
    #[must_use]
    pub const fn stage(&self) -> Option<ActiveVaultDeletionStage> {
        match self {
            Self::Backend { stage, .. } => Some(*stage),
            Self::ActiveHandlesNotRevoked | Self::IdentityMismatch => None,
        }
    }

    /// Returns the caller-defined underlying failure, if a durable boundary
    /// failed.
    #[must_use]
    pub const fn source_error(&self) -> Option<&E> {
        match self {
            Self::Backend { source, .. } => Some(source),
            Self::ActiveHandlesNotRevoked | Self::IdentityMismatch => None,
        }
    }
}

impl<E: fmt::Display> fmt::Display for ActiveVaultDeletionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveHandlesNotRevoked => {
                f.write_str("B506 active vault deletion refused: vault lease is still live")
            }
            Self::IdentityMismatch => f.write_str(
                "B506 active vault deletion refused: lease identity does not scope this vault",
            ),
            Self::Backend { stage, source } => {
                write!(f, "B506 active vault deletion {stage} failed: {source}")
            }
        }
    }
}

impl<E: Error + 'static> Error for ActiveVaultDeletionError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend { source, .. } => Some(source),
            Self::ActiveHandlesNotRevoked | Self::IdentityMismatch => None,
        }
    }
}

fn stage_failure<E>(stage: ActiveVaultDeletionStage, source: E) -> ActiveVaultDeletionError<E> {
    ActiveVaultDeletionError::Backend { stage, source }
}

/// Proof marker returned only after every deletion surface was removed and the
/// backend reread-verify boundary confirmed absence. It does not cover
/// detached backups, provider snapshots, user-made duplicates, or
/// physical-media erasure; see [`ACTIVE_VAULT_DELETION_LIMITATIONS`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveVaultDeletionComplete {
    _private: (),
}

/// Executes the bounded B506 active-vault deletion sequence.
///
/// Preconditions are checked before any durable surface is touched. The lease
/// must bind exactly this backend's vault identity, including its current key
/// generation: a stale-generation lease for the same vault is refused, so a
/// superseded epoch can never authorize destruction of the current epoch's
/// state, while deletion itself spans every generation of the vault. The lease
/// must already be terminal, which proves revocation (no new keyed operation
/// can be authorized and in-flight operations drained) but does not prove the
/// caller ran handle closure, key release, or cache discard; the caller must
/// perform `VaultSessionLifetime::teardown` first. Removals then run
/// crypto-shredding first so an interruption after the key-material stage
/// leaves remaining ciphertext without its SafeEvidence-managed wraps. Any failure
/// returns immediately at its exact stage so later surfaces are not attempted;
/// every removal is idempotent so a retry converges.
pub fn run_active_vault_deletion<B>(
    backend: &mut B,
    lease: &VaultLease,
) -> Result<ActiveVaultDeletionComplete, ActiveVaultDeletionError<B::Error>>
where
    B: ActiveVaultDeletionBackend,
{
    if lease.identity() != backend.vault_identity() {
        return Err(ActiveVaultDeletionError::IdentityMismatch);
    }
    if lease.state() != VaultLeaseState::Revoked {
        return Err(ActiveVaultDeletionError::ActiveHandlesNotRevoked);
    }
    backend
        .assert_normal_writes_quiesced()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::Quiesce, source))?;
    backend
        .remove_wrapped_key_material()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::WrappedKeyMaterial, source))?;
    backend
        .remove_freshness_state()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::FreshnessState, source))?;
    backend
        .remove_protector_references()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::ProtectorReferences, source))?;
    backend
        .remove_canonical_state()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::CanonicalState, source))?;
    backend
        .remove_derived_state()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::DerivedState, source))?;
    backend
        .remove_manifest_state()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::ManifestState, source))?;
    backend
        .remove_structured_store()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::StructuredStore, source))?;
    backend
        .remove_blob_store()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::BlobStore, source))?;
    backend
        .remove_backup_staging()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::BackupStaging, source))?;
    backend
        .remove_migration_remnants()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::MigrationRemnants, source))?;
    backend
        .remove_restore_remnants()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::RestoreRemnants, source))?;
    backend
        .remove_publication_temp()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::PublicationTemp, source))?;
    backend
        .remove_temporary_state()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::TemporaryState, source))?;
    backend
        .verify_deletion_complete()
        .map_err(|source| stage_failure(ActiveVaultDeletionStage::Verification, source))?;

    Ok(ActiveVaultDeletionComplete { _private: () })
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_VAULT_DELETION_LIMITATIONS, ActiveVaultDeletionBackend, ActiveVaultDeletionComplete,
        ActiveVaultDeletionError, ActiveVaultDeletionStage, run_active_vault_deletion,
    };
    use crate::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
    use crate::vault_keys::{
        KEY_MATERIAL_BYTES, KeyedHandleCloser, OwnedKeyMaterial, PlaintextCache, VaultKeyMaterial,
        VaultSessionLifetime, VaultTeardownReason,
    };
    use crate::vault_lease::VaultLease;
    use std::collections::BTreeSet;
    use std::convert::Infallible;
    use std::error::Error;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestError(ActiveVaultDeletionStage);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "injected {} failure", self.0)
        }
    }

    impl Error for TestError {}

    /// Every durable surface family the B506 backend boundary must cover.
    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum Surface {
        WrappedKeyMaterial,
        ProtectorReferences,
        FreshnessState,
        CanonicalState,
        DerivedState,
        ManifestState,
        StructuredStore,
        BlobStore,
        BackupStaging,
        MigrationRemnants,
        RestoreRemnants,
        PublicationTemp,
        TemporaryState,
    }

    const ALL_SURFACES: [Surface; 13] = [
        Surface::WrappedKeyMaterial,
        Surface::ProtectorReferences,
        Surface::FreshnessState,
        Surface::CanonicalState,
        Surface::DerivedState,
        Surface::ManifestState,
        Surface::StructuredStore,
        Surface::BlobStore,
        Surface::BackupStaging,
        Surface::MigrationRemnants,
        Surface::RestoreRemnants,
        Surface::PublicationTemp,
        Surface::TemporaryState,
    ];

    const EXPECTED_ORDER: [ActiveVaultDeletionStage; 15] = [
        ActiveVaultDeletionStage::Quiesce,
        ActiveVaultDeletionStage::WrappedKeyMaterial,
        ActiveVaultDeletionStage::FreshnessState,
        ActiveVaultDeletionStage::ProtectorReferences,
        ActiveVaultDeletionStage::CanonicalState,
        ActiveVaultDeletionStage::DerivedState,
        ActiveVaultDeletionStage::ManifestState,
        ActiveVaultDeletionStage::StructuredStore,
        ActiveVaultDeletionStage::BlobStore,
        ActiveVaultDeletionStage::BackupStaging,
        ActiveVaultDeletionStage::MigrationRemnants,
        ActiveVaultDeletionStage::RestoreRemnants,
        ActiveVaultDeletionStage::PublicationTemp,
        ActiveVaultDeletionStage::TemporaryState,
        ActiveVaultDeletionStage::Verification,
    ];

    /// Recording backend with one presence flag per surface family, an exact
    /// event log, an injectable failure stage, an optional verification
    /// residue, and a detached backup copy that must survive deletion.
    struct RecordingBackend {
        identity: VaultLeaseIdentity,
        present: BTreeSet<Surface>,
        events: Vec<ActiveVaultDeletionStage>,
        fail_at: Option<ActiveVaultDeletionStage>,
        residue: Option<Surface>,
        detached_backup: Vec<u8>,
    }

    impl RecordingBackend {
        fn full(identity: VaultLeaseIdentity) -> Self {
            Self {
                identity,
                present: ALL_SURFACES.into_iter().collect(),
                events: Vec::new(),
                fail_at: None,
                residue: None,
                detached_backup: vec![0xB6; 256],
            }
        }

        fn record(&mut self, stage: ActiveVaultDeletionStage) -> Result<(), TestError> {
            self.events.push(stage);
            if self.fail_at == Some(stage) {
                return Err(TestError(stage));
            }
            Ok(())
        }

        fn take(
            &mut self,
            stage: ActiveVaultDeletionStage,
            surface: Surface,
        ) -> Result<(), TestError> {
            self.record(stage)?;
            self.present.remove(&surface);
            Ok(())
        }

        /// Simulates reopening the vault through its production open path.
        /// Succeeds only while canonical or structured-store state remains.
        fn reopen_for_read(&self) -> Result<(), &'static str> {
            if self.present.contains(&Surface::CanonicalState)
                || self.present.contains(&Surface::StructuredStore)
            {
                Ok(())
            } else {
                Err("vault state is absent")
            }
        }

        /// Simulates opening the detached backup with the recovery passphrase.
        fn open_detached_backup(&self) -> Result<Vec<u8>, &'static str> {
            if self.detached_backup.is_empty() {
                Err("detached backup is absent")
            } else {
                Ok(self.detached_backup.clone())
            }
        }
    }

    impl ActiveVaultDeletionBackend for RecordingBackend {
        type Error = TestError;

        fn vault_identity(&self) -> VaultLeaseIdentity {
            self.identity
        }

        fn assert_normal_writes_quiesced(&self) -> Result<(), Self::Error> {
            if self.fail_at == Some(ActiveVaultDeletionStage::Quiesce) {
                return Err(TestError(ActiveVaultDeletionStage::Quiesce));
            }
            Ok(())
        }

        fn remove_wrapped_key_material(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::WrappedKeyMaterial,
                Surface::WrappedKeyMaterial,
            )
        }

        fn remove_protector_references(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::ProtectorReferences,
                Surface::ProtectorReferences,
            )
        }

        fn remove_freshness_state(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::FreshnessState,
                Surface::FreshnessState,
            )
        }

        fn remove_canonical_state(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::CanonicalState,
                Surface::CanonicalState,
            )
        }

        fn remove_derived_state(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::DerivedState,
                Surface::DerivedState,
            )
        }

        fn remove_manifest_state(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::ManifestState,
                Surface::ManifestState,
            )
        }

        fn remove_structured_store(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::StructuredStore,
                Surface::StructuredStore,
            )
        }

        fn remove_blob_store(&mut self) -> Result<(), Self::Error> {
            self.take(ActiveVaultDeletionStage::BlobStore, Surface::BlobStore)
        }

        fn remove_backup_staging(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::BackupStaging,
                Surface::BackupStaging,
            )
        }

        fn remove_migration_remnants(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::MigrationRemnants,
                Surface::MigrationRemnants,
            )
        }

        fn remove_restore_remnants(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::RestoreRemnants,
                Surface::RestoreRemnants,
            )
        }

        fn remove_publication_temp(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::PublicationTemp,
                Surface::PublicationTemp,
            )
        }

        fn remove_temporary_state(&mut self) -> Result<(), Self::Error> {
            self.take(
                ActiveVaultDeletionStage::TemporaryState,
                Surface::TemporaryState,
            )
        }

        fn verify_deletion_complete(&self) -> Result<(), Self::Error> {
            if self.fail_at == Some(ActiveVaultDeletionStage::Verification) {
                return Err(TestError(ActiveVaultDeletionStage::Verification));
            }
            let mut remaining: BTreeSet<Surface> = self.present.clone();
            if let Some(residue) = self.residue {
                remaining.insert(residue);
            }
            if remaining.is_empty() {
                Ok(())
            } else {
                Err(TestError(ActiveVaultDeletionStage::Verification))
            }
        }
    }

    /// Removal stages in coordinator order, excluding the quiesce and
    /// verification boundaries which log no surface event.
    const REMOVAL_ORDER: [ActiveVaultDeletionStage; 13] = [
        ActiveVaultDeletionStage::WrappedKeyMaterial,
        ActiveVaultDeletionStage::FreshnessState,
        ActiveVaultDeletionStage::ProtectorReferences,
        ActiveVaultDeletionStage::CanonicalState,
        ActiveVaultDeletionStage::DerivedState,
        ActiveVaultDeletionStage::ManifestState,
        ActiveVaultDeletionStage::StructuredStore,
        ActiveVaultDeletionStage::BlobStore,
        ActiveVaultDeletionStage::BackupStaging,
        ActiveVaultDeletionStage::MigrationRemnants,
        ActiveVaultDeletionStage::RestoreRemnants,
        ActiveVaultDeletionStage::PublicationTemp,
        ActiveVaultDeletionStage::TemporaryState,
    ];

    fn identity() -> VaultLeaseIdentity {
        VaultLeaseIdentity::new(
            VaultId::from_bytes([0xD6; VAULT_ID_BYTES]),
            KeyGeneration::new(3).expect("test generation is non-zero"),
        )
    }

    fn revoked_lease() -> VaultLease {
        let lease = VaultLease::new(identity());
        assert!(lease.revoke());
        lease
    }

    #[test]
    fn deletion_removes_every_surface_in_exact_order_and_verifies() {
        let mut backend = RecordingBackend::full(identity());
        assert!(backend.reopen_for_read().is_ok());

        let result: Result<ActiveVaultDeletionComplete, ActiveVaultDeletionError<TestError>> =
            run_active_vault_deletion(&mut backend, &revoked_lease());

        assert!(result.is_ok());
        assert!(backend.present.is_empty());
        assert_eq!(backend.events, REMOVAL_ORDER);
        // Crypto-shredding first: key material and protector references precede
        // every ciphertext-bearing surface.
        let key_position = backend
            .events
            .iter()
            .position(|stage| *stage == ActiveVaultDeletionStage::WrappedKeyMaterial)
            .expect("key shredding must run");
        let data_position = backend
            .events
            .iter()
            .position(|stage| *stage == ActiveVaultDeletionStage::StructuredStore)
            .expect("structured-store removal must run");
        let blob_position = backend
            .events
            .iter()
            .position(|stage| *stage == ActiveVaultDeletionStage::BlobStore)
            .expect("blob removal must run");
        assert!(key_position < data_position);
        assert!(key_position < blob_position);
        assert!(backend.reopen_for_read().is_err());
    }

    #[test]
    fn live_lease_refuses_deletion_without_touching_durable_state() {
        let live = VaultLease::new(identity());
        let mut backend = RecordingBackend::full(identity());

        let error = run_active_vault_deletion(&mut backend, &live)
            .expect_err("live lease must refuse deletion");

        assert_eq!(error, ActiveVaultDeletionError::ActiveHandlesNotRevoked);
        assert_eq!(error.stage(), None);
        assert!(backend.events.is_empty());
        assert_eq!(backend.present.len(), ALL_SURFACES.len());
        assert!(backend.reopen_for_read().is_ok());
    }

    #[test]
    fn lock_revoked_lease_authorizes_deletion() {
        // Intentional: the public lease state erases the lock/revocation
        // distinction, so any terminal lease authorizes deletion at the gate.
        // Handle closure, key release, and cache discard remain an unenforced
        // caller obligation documented on the coordinator.
        let lease = VaultLease::new(identity());
        assert!(lease.revoke_for_lock());
        let mut backend = RecordingBackend::full(identity());

        let result: Result<ActiveVaultDeletionComplete, ActiveVaultDeletionError<TestError>> =
            run_active_vault_deletion(&mut backend, &lease);

        assert!(result.is_ok());
        assert!(backend.present.is_empty());
    }

    #[test]
    fn identity_mismatch_fails_closed_without_touching_state() {
        let other = VaultLeaseIdentity::new(
            VaultId::from_bytes([0x77; VAULT_ID_BYTES]),
            KeyGeneration::new(3).expect("test generation is non-zero"),
        );
        let lease = VaultLease::new(other);
        assert!(lease.revoke());
        let mut backend = RecordingBackend::full(identity());

        let error = run_active_vault_deletion(&mut backend, &lease)
            .expect_err("mismatched identity must refuse deletion");

        assert_eq!(error, ActiveVaultDeletionError::IdentityMismatch);
        assert_eq!(error.stage(), None);
        assert!(backend.events.is_empty());
        assert_eq!(backend.present.len(), ALL_SURFACES.len());
    }

    #[test]
    fn deletion_is_idempotent_across_retries() {
        let mut backend = RecordingBackend::full(identity());
        let lease = revoked_lease();

        assert!(
            run_active_vault_deletion(&mut backend, &lease).is_ok(),
            "first deletion must succeed"
        );
        let second: Result<ActiveVaultDeletionComplete, ActiveVaultDeletionError<TestError>> =
            run_active_vault_deletion(&mut backend, &lease);
        assert!(second.is_ok(), "retry over absent surfaces must succeed");
        assert!(backend.present.is_empty());
    }

    #[test]
    fn detached_backup_survives_active_vault_deletion() {
        let mut backend = RecordingBackend::full(identity());
        let detached_before = backend
            .open_detached_backup()
            .expect("detached backup must open before deletion");

        assert!(run_active_vault_deletion(&mut backend, &revoked_lease()).is_ok());

        let detached_after = backend
            .open_detached_backup()
            .expect("active deletion must not reach detached copies");
        assert_eq!(detached_before, detached_after);
        assert!(backend.reopen_for_read().is_err());
    }

    #[test]
    fn limitations_notice_states_retention_and_erasure_limits() {
        for required in [
            "Detached or exported portable backups",
            "recovery passphrase",
            "cannot remotely revoke",
            "provider snapshots",
            "user-made duplicates",
            "not guaranteed physical-media erasure",
            "wear-levelling",
            "zeroization does not erase",
            "swap",
            "Provider-side deletion",
        ] {
            assert!(
                ACTIVE_VAULT_DELETION_LIMITATIONS.contains(required),
                "limitations notice must state: {required}"
            );
        }
        for forbidden in ["securely erased", "unrecoverable", "guaranteed erasure"] {
            assert!(
                !ACTIVE_VAULT_DELETION_LIMITATIONS.contains(forbidden),
                "limitations notice must not overclaim: {forbidden}"
            );
        }
    }

    /// Maps each removal stage to the surface it clears.
    fn surface_for_stage(stage: ActiveVaultDeletionStage) -> Option<Surface> {
        match stage {
            ActiveVaultDeletionStage::WrappedKeyMaterial => Some(Surface::WrappedKeyMaterial),
            ActiveVaultDeletionStage::FreshnessState => Some(Surface::FreshnessState),
            ActiveVaultDeletionStage::ProtectorReferences => Some(Surface::ProtectorReferences),
            ActiveVaultDeletionStage::CanonicalState => Some(Surface::CanonicalState),
            ActiveVaultDeletionStage::DerivedState => Some(Surface::DerivedState),
            ActiveVaultDeletionStage::ManifestState => Some(Surface::ManifestState),
            ActiveVaultDeletionStage::StructuredStore => Some(Surface::StructuredStore),
            ActiveVaultDeletionStage::BlobStore => Some(Surface::BlobStore),
            ActiveVaultDeletionStage::BackupStaging => Some(Surface::BackupStaging),
            ActiveVaultDeletionStage::MigrationRemnants => Some(Surface::MigrationRemnants),
            ActiveVaultDeletionStage::RestoreRemnants => Some(Surface::RestoreRemnants),
            ActiveVaultDeletionStage::PublicationTemp => Some(Surface::PublicationTemp),
            ActiveVaultDeletionStage::TemporaryState => Some(Surface::TemporaryState),
            ActiveVaultDeletionStage::Quiesce | ActiveVaultDeletionStage::Verification => None,
        }
    }

    #[test]
    fn every_stage_failure_reports_its_exact_stage_and_stops() {
        for failing_stage in EXPECTED_ORDER {
            let mut backend = RecordingBackend::full(identity());
            backend.fail_at = Some(failing_stage);

            let error = run_active_vault_deletion(&mut backend, &revoked_lease())
                .expect_err("injected stage failure must fail");

            match error {
                ActiveVaultDeletionError::Backend { stage, source } => {
                    assert_eq!(stage, failing_stage);
                    assert_eq!(source, TestError(failing_stage));
                    assert_eq!(error.stage(), Some(failing_stage));
                    assert_eq!(error.source_error(), Some(&TestError(failing_stage)));
                }
                unexpected => panic!("expected backend failure, got {unexpected:?}"),
            }
            // Every removal stage up to and including the failing stage logs
            // its attempt (the recorder logs before injecting the failure);
            // quiesce and verification log no surface event.
            let mut expected_prefix = Vec::new();
            for stage in REMOVAL_ORDER {
                expected_prefix.push(stage);
                if stage == failing_stage {
                    break;
                }
            }
            if failing_stage == ActiveVaultDeletionStage::Quiesce {
                expected_prefix.clear();
            }
            assert_eq!(backend.events, expected_prefix);
            // The failing stage's own surface must still be present, as must
            // every later surface; strictly earlier surfaces must be gone.
            let mut expected_present = BTreeSet::new();
            let mut seen_failure = failing_stage == ActiveVaultDeletionStage::Quiesce;
            for stage in REMOVAL_ORDER {
                if stage == failing_stage {
                    seen_failure = true;
                }
                if seen_failure {
                    expected_present.insert(
                        surface_for_stage(stage).expect("removal stage must map a surface"),
                    );
                }
            }
            if failing_stage == ActiveVaultDeletionStage::Verification {
                expected_present.clear();
            }
            assert_eq!(backend.present, expected_present);
        }
    }

    #[test]
    fn interrupted_deletion_retries_to_success_with_keys_already_gone() {
        let mut backend = RecordingBackend::full(identity());
        backend.fail_at = Some(ActiveVaultDeletionStage::StructuredStore);
        let lease = revoked_lease();

        let error: ActiveVaultDeletionError<TestError> =
            run_active_vault_deletion(&mut backend, &lease)
                .expect_err("injected interruption must fail");
        assert_eq!(
            error.stage(),
            Some(ActiveVaultDeletionStage::StructuredStore)
        );
        // Crypto-shredding already ran: key material is gone while ciphertext
        // surfaces remain, so the interrupted state is keyless but incomplete.
        assert!(!backend.present.contains(&Surface::WrappedKeyMaterial));
        assert!(!backend.present.contains(&Surface::FreshnessState));
        assert!(!backend.present.contains(&Surface::ProtectorReferences));
        assert!(backend.present.contains(&Surface::StructuredStore));
        assert!(backend.present.contains(&Surface::BlobStore));

        backend.fail_at = None;
        assert!(
            run_active_vault_deletion(&mut backend, &lease).is_ok(),
            "retry after clearing the fault must converge"
        );
        assert!(backend.present.is_empty());
        assert!(backend.reopen_for_read().is_err());
    }

    #[test]
    fn verification_detects_hidden_residue_on_every_surface() {
        for residue in ALL_SURFACES {
            let mut backend = RecordingBackend::full(identity());
            backend.residue = Some(residue);

            let error: ActiveVaultDeletionError<TestError> =
                run_active_vault_deletion(&mut backend, &revoked_lease())
                    .expect_err("hidden residue must fail verification");

            match error {
                ActiveVaultDeletionError::Backend { stage, .. } => {
                    assert_eq!(stage, ActiveVaultDeletionStage::Verification);
                }
                unexpected => {
                    panic!("expected verification failure, got {unexpected:?}")
                }
            }
            // Every removal still ran; only the reread proof rejected the
            // result, including residue on the critical key-material surface.
            assert_eq!(backend.events, REMOVAL_ORDER);
        }
    }

    struct RecordingCloser {
        closed: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl KeyedHandleCloser for RecordingCloser {
        type Error = Infallible;

        fn close_keyed_handles(&mut self) -> Result<(), Self::Error> {
            self.closed.set(true);
            Ok(())
        }
    }

    struct RecordingCache {
        discarded: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl PlaintextCache for RecordingCache {
        fn discard_plaintext(&mut self) {
            self.discarded.set(true);
        }
    }

    #[test]
    fn session_teardown_covers_handles_keys_and_caches_before_deletion() {
        let handles_closed = std::rc::Rc::new(std::cell::Cell::new(false));
        let caches_discarded = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut lifetime = VaultSessionLifetime::new(
            VaultLease::new(identity()),
            RecordingCloser {
                closed: std::rc::Rc::clone(&handles_closed),
            },
            VaultKeyMaterial::new(OwnedKeyMaterial::from_bytes([0x1D; KEY_MATERIAL_BYTES])),
            RecordingCache {
                discarded: std::rc::Rc::clone(&caches_discarded),
            },
        );
        // A lock-path revocation authorizes deletion at the lease gate, but the
        // required caller flow still tears the session down first; the flags
        // below prove teardown effects rather than bare revocation.
        lifetime
            .teardown(VaultTeardownReason::Lock)
            .expect("recording teardown cannot fail");
        assert!(handles_closed.get(), "teardown must close keyed handles");
        assert!(
            lifetime.keys_released(),
            "teardown must release key material"
        );
        assert!(
            caches_discarded.get(),
            "teardown must discard plaintext caches"
        );
        assert_eq!(
            lifetime.lease_state(),
            crate::vault::VaultLeaseState::Revoked,
            "teardown must leave the lease terminal"
        );

        let lease = VaultLease::new(identity());
        assert!(lease.revoke());
        let mut backend = RecordingBackend::full(identity());
        assert!(
            run_active_vault_deletion(&mut backend, &lease).is_ok(),
            "revoked lease must authorize deletion after teardown"
        );
        assert!(backend.present.is_empty());
    }

    #[test]
    fn backend_failure_preserves_typed_source() {
        let error: ActiveVaultDeletionError<TestError> = ActiveVaultDeletionError::Backend {
            stage: ActiveVaultDeletionStage::BlobStore,
            source: TestError(ActiveVaultDeletionStage::BlobStore),
        };
        assert_eq!(error.stage(), Some(ActiveVaultDeletionStage::BlobStore));
        assert!(error.source().is_some());
        let rendered = format!("{error}");
        assert!(
            rendered.contains("B506"),
            "display must carry the B506 leaf tag"
        );
        assert!(
            rendered.contains("blob store"),
            "display must name the failing stage"
        );
        let live_refusal: ActiveVaultDeletionError<TestError> =
            ActiveVaultDeletionError::ActiveHandlesNotRevoked;
        assert!(live_refusal.source().is_none());
    }
}

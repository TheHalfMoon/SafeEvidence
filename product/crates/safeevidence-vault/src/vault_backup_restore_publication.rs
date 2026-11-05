//! B505 fresh-device durable local publication and protected-genesis commit.
//!
//! This layer consumes only B505R-prepared material and reuses the already-qualified
//! B307 copy-verify-publish ordering. Durable object publication and reopen behavior
//! remain behind an explicit backend contract; protected freshness mutation stays in
//! the coordinator so the accepted manifest and installed anchor cannot diverge.

use crate::vault::{FreshnessAnchor, ProtectedFreshnessState, ProtectorError, SecretProtector};
use crate::vault_backup_restore::{
    ExistingDevicePreparedRestore, ExistingDeviceRestoreStagingError,
    ExistingDeviceRestoreTargetBackend, FreshDevicePreparedGenesis, current_manifest_is_stable,
    key_material_equal, verify_protected_staging_state,
};
use crate::vault_backup_sqlcipher::{
    BackupSqlCipherVerificationError, SqlCipherVerifiedBackupSet, reverify_staged_sqlcipher_backup,
};
use crate::vault_backup_verify::PreSqlCipherVerifiedBackupSet;
use crate::vault_freshness::{FreshnessDecision, FreshnessError, authenticate_for_open};
use crate::vault_keys::OwnedKeyMaterial;
use crate::vault_manifest::{
    ManifestError, ManifestPlaintext, decrypt_manifest, manifest_context, manifest_hash,
};
use crate::vault_migration::{
    CopyVerifyPublishError, EncryptedMigrationSource, EncryptedMigrationTarget,
    run_copy_verify_publish,
};
use crate::vault_restore::FreshDeviceRestoreGenesis;
use std::error::Error;
use std::fmt;
use std::path::Path;

/// Storage boundary for fresh-device restore publication.
///
/// Implementations must keep every operation idempotent for the exact same input.
/// `stage_verified_backup` must durably copy/fsync the structured store and every
/// authenticated B202 artifact into non-canonical local candidate storage.
/// `verify_staged_backup` must reread the complete candidate set, require exact
/// authenticated identities, and run the applicable SQLCipher/B202 integrity checks.
/// `publish_manifest` must durably publish the exact supplied B501 envelope and make
/// the same bytes available through `read_published_manifest` before it returns.
/// No method may mutate the protected freshness anchor or retire recovery material.
pub trait FreshDeviceRestoreBackend {
    type Error;

    fn stage_verified_backup(
        &mut self,
        structured_store_source: &Path,
        verified: &PreSqlCipherVerifiedBackupSet,
    ) -> Result<(), Self::Error>;

    fn verify_staged_backup(
        &mut self,
        vrk: &OwnedKeyMaterial,
        verified: &PreSqlCipherVerifiedBackupSet,
    ) -> Result<(), Self::Error>;

    fn publish_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error>;

    fn read_published_manifest(&self) -> Result<Vec<u8>, Self::Error>;

    fn reopen_published(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error>;

    fn verify_reopened(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum FreshDevicePublicationOperationError<E> {
    SourceSqlCipher(BackupSqlCipherVerificationError),
    Backend(E),
    Protector(ProtectorError),
    Manifest(ManifestError),
    PublishedManifestMismatch,
    ProtectedStateChanged,
}

impl<E: fmt::Display> fmt::Display for FreshDevicePublicationOperationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceSqlCipher(error) => {
                write!(
                    f,
                    "fresh-device restore source re-verification failed: {error}"
                )
            }
            Self::Backend(error) => write!(f, "fresh-device restore backend failed: {error}"),
            Self::Protector(error) => write!(f, "fresh-device restore protector failed: {error}"),
            Self::Manifest(error) => write!(f, "fresh-device restore manifest failed: {error}"),
            Self::PublishedManifestMismatch => {
                f.write_str("published fresh-device manifest does not match accepted backup")
            }
            Self::ProtectedStateChanged => {
                f.write_str("protected fresh-device state changed during publication")
            }
        }
    }
}

impl<E: Error + 'static> Error for FreshDevicePublicationOperationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SourceSqlCipher(error) => Some(error),
            Self::Backend(error) => Some(error),
            Self::Protector(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::PublishedManifestMismatch | Self::ProtectedStateChanged => None,
        }
    }
}

pub type FreshDeviceRestorePublicationError<E> =
    CopyVerifyPublishError<FreshDevicePublicationOperationError<E>>;

/// Proof returned only after the accepted backup is locally published, its exact
/// protected genesis anchor is installed and reread, and the anchored state is
/// reopened and integrity-verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshDeviceRestoreComplete {
    accepted_anchor: FreshnessAnchor,
    global_newestness_proven: bool,
}

impl FreshDeviceRestoreComplete {
    #[must_use]
    pub const fn accepted_anchor(self) -> FreshnessAnchor {
        self.accepted_anchor
    }

    #[must_use]
    pub const fn global_newestness_proven(self) -> bool {
        self.global_newestness_proven
    }
}

struct FreshDeviceRestoreSource<'a> {
    structured_store_source: &'a Path,
    verified: &'a SqlCipherVerifiedBackupSet,
}

struct FreshDeviceRestoreTarget<'a, P, B> {
    protector: &'a mut P,
    backend: &'a mut B,
    verified: &'a PreSqlCipherVerifiedBackupSet,
    genesis: &'a FreshDeviceRestoreGenesis,
}

impl<'source, 'target, P, B> EncryptedMigrationSource<FreshDeviceRestoreTarget<'target, P, B>>
    for FreshDeviceRestoreSource<'source>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FreshDeviceRestoreBackend,
{
    type Error = FreshDevicePublicationOperationError<B::Error>;

    fn verify_source(&self) -> Result<(), Self::Error> {
        reverify_staged_sqlcipher_backup(self.structured_store_source, self.verified)
            .map_err(FreshDevicePublicationOperationError::SourceSqlCipher)
    }

    fn copy_into(
        &self,
        target: &mut FreshDeviceRestoreTarget<'target, P, B>,
    ) -> Result<(), Self::Error> {
        target
            .backend
            .stage_verified_backup(self.structured_store_source, target.verified)
            .map_err(FreshDevicePublicationOperationError::Backend)
    }
}

impl<P, B> FreshDeviceRestoreTarget<'_, P, B>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FreshDeviceRestoreBackend,
{
    fn verify_published_manifest(
        &mut self,
    ) -> Result<(), FreshDevicePublicationOperationError<B::Error>> {
        let expected = self.verified.source_manifest_envelope();
        let published = self
            .backend
            .read_published_manifest()
            .map_err(FreshDevicePublicationOperationError::Backend)?;
        if published != expected
            || manifest_hash(&published) != self.genesis.accepted_anchor().manifest_hash()
        {
            return Err(FreshDevicePublicationOperationError::PublishedManifestMismatch);
        }

        self.verified.with_structured_store_verification_key(
            |vrk, expected_vault_id, expected_generation| {
                let context = manifest_context(&published)
                    .map_err(FreshDevicePublicationOperationError::Manifest)?;
                if context.vault_id() != expected_vault_id
                    || context.key_generation() != expected_generation
                {
                    return Err(FreshDevicePublicationOperationError::PublishedManifestMismatch);
                }
                let manifest = decrypt_manifest(vrk, context, &published)
                    .map_err(FreshDevicePublicationOperationError::Manifest)?;
                if &manifest != self.genesis.manifest() {
                    return Err(FreshDevicePublicationOperationError::PublishedManifestMismatch);
                }
                Ok(())
            },
        )
    }

    fn unlock_matching_protected_vrk(
        &mut self,
    ) -> Result<OwnedKeyMaterial, FreshDevicePublicationOperationError<B::Error>> {
        self.verified.with_structured_store_verification_key(
            |recovered_vrk, vault_id, key_generation| {
                let protected_vrk = self
                    .protector
                    .unlock_vrk(vault_id, key_generation)
                    .map_err(FreshDevicePublicationOperationError::Protector)?;
                if !key_material_equal(recovered_vrk, &protected_vrk) {
                    return Err(FreshDevicePublicationOperationError::ProtectedStateChanged);
                }
                Ok(protected_vrk)
            },
        )
    }

    fn require_installed_anchor(
        &self,
    ) -> Result<(), FreshDevicePublicationOperationError<B::Error>> {
        let expected = self.genesis.accepted_anchor();
        match self
            .protector
            .read_freshness_anchor(expected.vault_id())
            .map_err(FreshDevicePublicationOperationError::Protector)?
        {
            ProtectedFreshnessState::Present(actual) if actual == expected => Ok(()),
            ProtectedFreshnessState::Uninitialized | ProtectedFreshnessState::Present(_) => {
                Err(FreshDevicePublicationOperationError::ProtectedStateChanged)
            }
        }
    }
}

impl<P, B> EncryptedMigrationTarget for FreshDeviceRestoreTarget<'_, P, B>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FreshDeviceRestoreBackend,
{
    type Error = FreshDevicePublicationOperationError<B::Error>;

    fn verify_staged_copy(&mut self) -> Result<(), Self::Error> {
        self.verified
            .with_structured_store_verification_key(|vrk, _, _| {
                self.backend
                    .verify_staged_backup(vrk, self.verified)
                    .map_err(FreshDevicePublicationOperationError::Backend)
            })
    }

    fn publish_verified_copy(&mut self) -> Result<(), Self::Error> {
        self.backend
            .publish_manifest(self.verified.source_manifest_envelope())
            .map_err(FreshDevicePublicationOperationError::Backend)?;
        self.verify_published_manifest()
    }

    fn anchor_published_copy(&mut self) -> Result<(), Self::Error> {
        let accepted_anchor = self.genesis.accepted_anchor();
        match self
            .protector
            .read_freshness_anchor(accepted_anchor.vault_id())
            .map_err(FreshDevicePublicationOperationError::Protector)?
        {
            ProtectedFreshnessState::Uninitialized => {}
            ProtectedFreshnessState::Present(_) => {
                return Err(FreshDevicePublicationOperationError::ProtectedStateChanged);
            }
        }
        let _protected_vrk = self.unlock_matching_protected_vrk()?;
        self.protector
            .install_genesis_freshness_anchor(
                accepted_anchor.vault_id(),
                ProtectedFreshnessState::Uninitialized,
                accepted_anchor,
            )
            .map_err(FreshDevicePublicationOperationError::Protector)?;
        self.require_installed_anchor()
    }

    fn reopen_published_copy(&mut self) -> Result<(), Self::Error> {
        let protected_vrk = self.unlock_matching_protected_vrk()?;
        self.backend
            .reopen_published(&protected_vrk, self.genesis.manifest())
            .map_err(FreshDevicePublicationOperationError::Backend)
    }

    fn verify_reopened_copy(&mut self) -> Result<(), Self::Error> {
        let protected_vrk = self.unlock_matching_protected_vrk()?;
        self.backend
            .verify_reopened(&protected_vrk, self.genesis.manifest())
            .map_err(FreshDevicePublicationOperationError::Backend)?;
        self.verify_published_manifest()?;
        self.require_installed_anchor()
    }
}

/// Completes fresh-device local publication from B505R-prepared material.
///
/// The external SQLCipher staging source is re-proved immediately before copy.
/// B307 sequencing then requires complete durable staging verification and exact
/// manifest reread/authentication before the first protected anchor is installed.
/// Any failure before anchoring leaves `UNINITIALIZED` authoritative. A failure
/// after a successful anchor installation never rolls the anchor back; restart
/// must recover by opening and verifying the exact anchored manifest.
pub fn publish_prepared_fresh_device_restore<P, B>(
    protector: &mut P,
    backend: &mut B,
    structured_store_source: &Path,
    prepared: FreshDevicePreparedGenesis,
) -> Result<FreshDeviceRestoreComplete, FreshDeviceRestorePublicationError<B::Error>>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: FreshDeviceRestoreBackend,
{
    let accepted_anchor = prepared.genesis().accepted_anchor();
    let global_newestness_proven = prepared.genesis().global_newestness_proven();
    let verified_sqlcipher = prepared.verified_backup().verified_backup();
    let source = FreshDeviceRestoreSource {
        structured_store_source,
        verified: verified_sqlcipher,
    };
    let mut target = FreshDeviceRestoreTarget {
        protector,
        backend,
        verified: verified_sqlcipher.pre_sqlcipher(),
        genesis: prepared.genesis(),
    };
    run_copy_verify_publish(&source, &mut target)?;

    Ok(FreshDeviceRestoreComplete {
        accepted_anchor,
        global_newestness_proven,
    })
}

/// Durable local publication boundary for an existing-device restore.
///
/// The target inventory has already been staged under current generation `H` by
/// B505U. Implementations must durably stage and reread the exact B502 final
/// manifest candidate before publication, verify the complete staged object set,
/// publish only that exact candidate, and reopen/verify the resulting canonical
/// state. This boundary intentionally exposes no delete/retire/provider mutation.
pub trait ExistingDeviceRestorePublicationBackend: ExistingDeviceRestoreTargetBackend {
    fn stage_final_manifest(&mut self, envelope: &[u8]) -> Result<(), Self::Error>;

    fn read_staged_final_manifest(&mut self) -> Result<Vec<u8>, Self::Error>;

    fn verify_staged_restore(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error>;

    fn publish_staged_manifest(&mut self) -> Result<(), Self::Error>;

    fn read_published_restore_manifest(&mut self) -> Result<Vec<u8>, Self::Error>;

    fn reopen_published_restore(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error>;

    fn verify_reopened_restore(
        &mut self,
        vrk: &OwnedKeyMaterial,
        manifest: &ManifestPlaintext,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum ExistingDevicePublicationOperationError<E> {
    Staging(ExistingDeviceRestoreStagingError<E>),
    Backend(E),
    Protector(ProtectorError),
    Manifest(ManifestError),
    CandidateMismatch,
    ProtectedStateChanged,
}

impl<E: fmt::Display> fmt::Display for ExistingDevicePublicationOperationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Staging(error) => write!(f, "existing-device restore state changed: {error}"),
            Self::Backend(error) => {
                write!(f, "existing-device publication backend failed: {error}")
            }
            Self::Protector(error) => write!(f, "existing-device protector failed: {error}"),
            Self::Manifest(error) => write!(f, "existing-device final manifest failed: {error}"),
            Self::CandidateMismatch => {
                f.write_str("existing-device final publication candidate mismatched B502")
            }
            Self::ProtectedStateChanged => {
                f.write_str("existing-device protected state changed during publication")
            }
        }
    }
}

impl<E: Error + 'static> Error for ExistingDevicePublicationOperationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Staging(error) => Some(error),
            Self::Backend(error) => Some(error),
            Self::Protector(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::CandidateMismatch | Self::ProtectedStateChanged => None,
        }
    }
}

pub type ExistingDeviceRestorePublicationError<E> =
    CopyVerifyPublishError<ExistingDevicePublicationOperationError<E>>;

/// Proof returned only after the B502 final candidate is durably published, the
/// exact old protected anchor is advanced to the exact B502 new anchor, and the
/// resulting canonical state is reopened and integrity-verified under current `H`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingDeviceRestoreComplete {
    accepted_anchor: FreshnessAnchor,
}

impl ExistingDeviceRestoreComplete {
    #[must_use]
    pub const fn accepted_anchor(self) -> FreshnessAnchor {
        self.accepted_anchor
    }
}

struct ExistingDeviceRestoreSource<'a> {
    prepared: &'a ExistingDevicePreparedRestore,
}

struct ExistingDeviceRestoreTarget<'a, P, B> {
    protector: &'a mut P,
    backend: &'a mut B,
    prepared: &'a ExistingDevicePreparedRestore,
}

impl ExistingDeviceRestoreSource<'_> {
    fn verify_candidate<E>(&self) -> Result<(), ExistingDevicePublicationOperationError<E>> {
        let staged = self.prepared.staged_restore();
        let gate = staged.gate();
        let publication = self.prepared.publication();
        let identity = gate.current_identity();
        let old_anchor = publication.expected_old_anchor();
        let new_anchor = publication.new_anchor();
        if old_anchor != gate.trusted_anchor()
            || new_anchor.vault_id() != identity.vault_id()
            || publication.target_manifest().vault_id() != identity.vault_id()
            || publication.target_manifest().active_key_generation() != identity.key_generation()
            || publication.target_manifest().objects() != staged.staged_objects()
            || publication.target_manifest().previous_manifest_hash() != old_anchor.manifest_hash()
            || new_anchor.manifest_hash() != manifest_hash(publication.envelope())
        {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        let expected_epoch = old_anchor
            .highest_epoch()
            .get()
            .checked_add(1)
            .ok_or(ExistingDevicePublicationOperationError::CandidateMismatch)?;
        if new_anchor.highest_epoch().get() != expected_epoch
            || publication.target_manifest().freshness_epoch() != new_anchor.highest_epoch()
        {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        let context = manifest_context(publication.envelope())
            .map_err(ExistingDevicePublicationOperationError::Manifest)?;
        if context.vault_id() != identity.vault_id()
            || context.key_generation() != identity.key_generation()
            || context.freshness_epoch() != new_anchor.highest_epoch()
        {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        let authenticated = gate
            .with_current_vrk(|vrk| decrypt_manifest(vrk, context, publication.envelope()))
            .map_err(ExistingDevicePublicationOperationError::Manifest)?;
        if authenticated != *publication.target_manifest() {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        Ok(())
    }
}

impl<P, B> ExistingDeviceRestoreTarget<'_, P, B>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: ExistingDeviceRestorePublicationBackend,
{
    fn require_old_state(
        &mut self,
    ) -> Result<(), ExistingDevicePublicationOperationError<B::Error>> {
        verify_protected_staging_state(
            self.backend,
            self.protector,
            self.prepared.staged_restore().gate(),
        )
        .map_err(ExistingDevicePublicationOperationError::Staging)
    }

    fn unlock_matching_current_vrk(
        &mut self,
    ) -> Result<OwnedKeyMaterial, ExistingDevicePublicationOperationError<B::Error>> {
        let gate = self.prepared.staged_restore().gate();
        let identity = gate.current_identity();
        let protected = self
            .protector
            .unlock_vrk(identity.vault_id(), identity.key_generation())
            .map_err(ExistingDevicePublicationOperationError::Protector)?;
        if !gate.with_current_vrk(|current| key_material_equal(current, &protected)) {
            return Err(ExistingDevicePublicationOperationError::ProtectedStateChanged);
        }
        Ok(protected)
    }

    fn verify_candidate_bytes(
        &mut self,
        candidate: &[u8],
    ) -> Result<(), ExistingDevicePublicationOperationError<B::Error>> {
        let gate = self.prepared.staged_restore().gate();
        let publication = self.prepared.publication();
        let identity = gate.current_identity();
        if candidate != publication.envelope()
            || manifest_hash(candidate) != publication.new_anchor().manifest_hash()
        {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        let context = manifest_context(candidate)
            .map_err(ExistingDevicePublicationOperationError::Manifest)?;
        if context.vault_id() != identity.vault_id()
            || context.key_generation() != identity.key_generation()
            || context.freshness_epoch() != publication.new_anchor().highest_epoch()
        {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        let authenticated = gate
            .with_current_vrk(|vrk| decrypt_manifest(vrk, context, candidate))
            .map_err(ExistingDevicePublicationOperationError::Manifest)?;
        if authenticated != *publication.target_manifest() {
            return Err(ExistingDevicePublicationOperationError::CandidateMismatch);
        }
        Ok(())
    }

    fn require_new_anchor(&self) -> Result<(), ExistingDevicePublicationOperationError<B::Error>> {
        let expected = self.prepared.publication().new_anchor();
        match self
            .protector
            .read_freshness_anchor(expected.vault_id())
            .map_err(ExistingDevicePublicationOperationError::Protector)?
        {
            ProtectedFreshnessState::Present(actual) if actual == expected => Ok(()),
            ProtectedFreshnessState::Uninitialized | ProtectedFreshnessState::Present(_) => {
                Err(ExistingDevicePublicationOperationError::ProtectedStateChanged)
            }
        }
    }
}

impl<'source, 'target, P, B> EncryptedMigrationSource<ExistingDeviceRestoreTarget<'target, P, B>>
    for ExistingDeviceRestoreSource<'source>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: ExistingDeviceRestorePublicationBackend,
{
    type Error = ExistingDevicePublicationOperationError<B::Error>;

    fn verify_source(&self) -> Result<(), Self::Error> {
        self.verify_candidate()
    }

    fn copy_into(
        &self,
        target: &mut ExistingDeviceRestoreTarget<'target, P, B>,
    ) -> Result<(), Self::Error> {
        target.require_old_state()?;
        target
            .backend
            .stage_final_manifest(self.prepared.publication().envelope())
            .map_err(ExistingDevicePublicationOperationError::Backend)
    }
}

impl<P, B> EncryptedMigrationTarget for ExistingDeviceRestoreTarget<'_, P, B>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: ExistingDeviceRestorePublicationBackend,
{
    type Error = ExistingDevicePublicationOperationError<B::Error>;

    fn verify_staged_copy(&mut self) -> Result<(), Self::Error> {
        self.require_old_state()?;
        let staged = self
            .backend
            .read_staged_final_manifest()
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        self.verify_candidate_bytes(&staged)?;
        let current_vrk = self.unlock_matching_current_vrk()?;
        self.backend
            .verify_staged_restore(&current_vrk, self.prepared.publication().target_manifest())
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        self.require_old_state()
    }

    fn publish_verified_copy(&mut self) -> Result<(), Self::Error> {
        self.require_old_state()?;
        let staged = self
            .backend
            .read_staged_final_manifest()
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        self.verify_candidate_bytes(&staged)?;
        self.backend
            .publish_staged_manifest()
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        let published = self
            .backend
            .read_published_restore_manifest()
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        self.verify_candidate_bytes(&published)?;
        self.require_old_state()
    }

    fn anchor_published_copy(&mut self) -> Result<(), Self::Error> {
        self.require_old_state()?;
        let published = self
            .backend
            .read_published_restore_manifest()
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        self.verify_candidate_bytes(&published)?;
        let publication = self.prepared.publication();
        let _current_vrk = self.unlock_matching_current_vrk()?;
        self.protector
            .advance_freshness_anchor(
                publication.new_anchor().vault_id(),
                publication.expected_old_anchor(),
                publication.new_anchor(),
            )
            .map_err(ExistingDevicePublicationOperationError::Protector)?;
        self.require_new_anchor()
    }

    fn reopen_published_copy(&mut self) -> Result<(), Self::Error> {
        self.require_new_anchor()?;
        let current_vrk = self.unlock_matching_current_vrk()?;
        self.backend
            .reopen_published_restore(&current_vrk, self.prepared.publication().target_manifest())
            .map_err(ExistingDevicePublicationOperationError::Backend)
    }

    fn verify_reopened_copy(&mut self) -> Result<(), Self::Error> {
        self.require_new_anchor()?;
        let current_vrk = self.unlock_matching_current_vrk()?;
        self.backend
            .verify_reopened_restore(&current_vrk, self.prepared.publication().target_manifest())
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        let published = self
            .backend
            .read_published_restore_manifest()
            .map_err(ExistingDevicePublicationOperationError::Backend)?;
        self.verify_candidate_bytes(&published)?;
        self.require_new_anchor()
    }
}

/// Completes an already-prepared existing-device restore through B307's exact
/// copy-verify-publish sequence.
///
/// Before anchor advance, every boundary reasserts the original protected anchor,
/// current VRK identity, normal-write quiescence, and current inventory. The exact
/// B502 candidate is staged, reread/authenticated, and the complete restored object
/// set is verified before it is published. Protected freshness advances only via
/// B502's exact `expected_old_anchor -> new_anchor` transition. A failure before
/// that CAS leaves the old anchor authoritative. A failure after the provider has
/// committed the CAS is never rolled back; restart must reopen/verify the exact
/// anchored candidate. No source/current object retirement occurs here.
pub fn publish_prepared_existing_device_restore<P, B>(
    protector: &mut P,
    backend: &mut B,
    prepared: ExistingDevicePreparedRestore,
) -> Result<ExistingDeviceRestoreComplete, ExistingDeviceRestorePublicationError<B::Error>>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: ExistingDeviceRestorePublicationBackend,
{
    let accepted_anchor = prepared.publication().new_anchor();
    let source = ExistingDeviceRestoreSource {
        prepared: &prepared,
    };
    let mut target = ExistingDeviceRestoreTarget {
        protector,
        backend,
        prepared: &prepared,
    };
    run_copy_verify_publish(&source, &mut target)?;
    Ok(ExistingDeviceRestoreComplete { accepted_anchor })
}

#[derive(Debug)]
pub enum ExistingDeviceRestoreRecoveryError<E> {
    Backend(E),
    Protector(ProtectorError),
    Manifest(ManifestError),
    Freshness(FreshnessError),
    CandidateMismatch,
    RestoreStateNotStable,
}

impl<E: fmt::Display> fmt::Display for ExistingDeviceRestoreRecoveryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => write!(
                f,
                "existing-device restore recovery backend failed: {error}"
            ),
            Self::Protector(error) => write!(
                f,
                "existing-device restore recovery protector failed: {error}"
            ),
            Self::Manifest(error) => write!(
                f,
                "existing-device restore recovery manifest failed: {error}"
            ),
            Self::Freshness(error) => write!(
                f,
                "existing-device restore recovery freshness failed: {error}"
            ),
            Self::CandidateMismatch => {
                f.write_str("existing-device restore recovery candidate mismatch")
            }
            Self::RestoreStateNotStable => {
                f.write_str("existing-device restore recovery state is not stable")
            }
        }
    }
}

impl<E: Error + 'static> Error for ExistingDeviceRestoreRecoveryError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            Self::Protector(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::Freshness(error) => Some(error),
            Self::CandidateMismatch | Self::RestoreStateNotStable => None,
        }
    }
}

/// Recovers only a durable existing-device restore attempt whose staged B502
/// final candidate is byte-identical to the published manifest. If the protected
/// anchor is still old, canonical B501 must classify the published manifest as the
/// exact next linked interrupted publication before the anchor may advance. If the
/// new anchor is already installed, the same manifest must authenticate as current.
/// In both cases the complete rebased object set is verified under current `H`
/// before reopen succeeds and ordinary writes may resume.
pub fn recover_existing_device_restore_after_restart<P, B>(
    protector: &mut P,
    backend: &mut B,
    current_identity: crate::vault::VaultLeaseIdentity,
) -> Result<ExistingDeviceRestoreComplete, ExistingDeviceRestoreRecoveryError<B::Error>>
where
    P: SecretProtector<VaultRootKey = OwnedKeyMaterial>,
    B: ExistingDeviceRestorePublicationBackend,
{
    backend
        .assert_normal_writes_quiesced()
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    let staged = backend
        .read_staged_final_manifest()
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    let published = backend
        .read_published_restore_manifest()
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    if staged != published {
        return Err(ExistingDeviceRestoreRecoveryError::CandidateMismatch);
    }
    let context =
        manifest_context(&published).map_err(ExistingDeviceRestoreRecoveryError::Manifest)?;
    if context.vault_id() != current_identity.vault_id()
        || context.key_generation() != current_identity.key_generation()
    {
        return Err(ExistingDeviceRestoreRecoveryError::CandidateMismatch);
    }
    let current_vrk = protector
        .unlock_vrk(
            current_identity.vault_id(),
            current_identity.key_generation(),
        )
        .map_err(ExistingDeviceRestoreRecoveryError::Protector)?;
    let anchor = match protector
        .read_freshness_anchor(current_identity.vault_id())
        .map_err(ExistingDeviceRestoreRecoveryError::Protector)?
    {
        ProtectedFreshnessState::Present(anchor)
            if anchor.vault_id() == current_identity.vault_id() =>
        {
            anchor
        }
        ProtectedFreshnessState::Uninitialized | ProtectedFreshnessState::Present(_) => {
            return Err(ExistingDeviceRestoreRecoveryError::RestoreStateNotStable);
        }
    };
    let authenticated = authenticate_for_open(&current_vrk, anchor, &published)
        .map_err(ExistingDeviceRestoreRecoveryError::Freshness)?;
    if !current_manifest_is_stable(authenticated.manifest(), current_identity) {
        return Err(ExistingDeviceRestoreRecoveryError::RestoreStateNotStable);
    }
    backend
        .verify_staged_restore(&current_vrk, authenticated.manifest())
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;

    let accepted_anchor = match authenticated.decision() {
        FreshnessDecision::Current => anchor,
        FreshnessDecision::RecoverInterruptedPublication {
            expected_old,
            new_anchor,
        } => {
            protector
                .advance_freshness_anchor(current_identity.vault_id(), expected_old, new_anchor)
                .map_err(ExistingDeviceRestoreRecoveryError::Protector)?;
            match protector
                .read_freshness_anchor(current_identity.vault_id())
                .map_err(ExistingDeviceRestoreRecoveryError::Protector)?
            {
                ProtectedFreshnessState::Present(actual) if actual == new_anchor => new_anchor,
                ProtectedFreshnessState::Uninitialized | ProtectedFreshnessState::Present(_) => {
                    return Err(ExistingDeviceRestoreRecoveryError::RestoreStateNotStable);
                }
            }
        }
        FreshnessDecision::InstallGenesis { .. } => {
            return Err(ExistingDeviceRestoreRecoveryError::RestoreStateNotStable);
        }
    };

    backend
        .reopen_published_restore(&current_vrk, authenticated.manifest())
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    backend
        .verify_reopened_restore(&current_vrk, authenticated.manifest())
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    backend
        .verify_staged_restore(&current_vrk, authenticated.manifest())
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    let reread = backend
        .read_published_restore_manifest()
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    if reread != published {
        return Err(ExistingDeviceRestoreRecoveryError::CandidateMismatch);
    }
    let reopened = authenticate_for_open(&current_vrk, accepted_anchor, &reread)
        .map_err(ExistingDeviceRestoreRecoveryError::Freshness)?;
    if reopened.decision() != FreshnessDecision::Current
        || reopened.manifest() != authenticated.manifest()
    {
        return Err(ExistingDeviceRestoreRecoveryError::CandidateMismatch);
    }
    backend
        .assert_normal_writes_quiesced()
        .map_err(ExistingDeviceRestoreRecoveryError::Backend)?;
    Ok(ExistingDeviceRestoreComplete { accepted_anchor })
}

//! Admitted pack store with monotonic epoch + SemVer anti-rollback (`ADM-0016` / `T07`, `TA-28`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-pack/src/store.rs`)
//! under Apache-2.0 (`ADR-0004`). Re-verifies Ed25519 manifest signature on every `admit` call so
//! programmatic manifest mutation cannot bypass cryptographic anti-rollback!

use safeevidence_contracts::objects::OpaqueId;
use safeevidence_contracts::packs::{PackManifestV0, PackPromotionState};

use crate::format::{
    AdmitError, compute_content_digest, validate_no_duplicate_or_prefix_paths,
    validate_relative_artifact_path,
};
use crate::trust::{PackTrustError, pack_signing_payload, verify_pack_signature};

/// Admitted pack registry (Core Host owned).
#[derive(Debug, Default, Clone)]
pub struct PackStore {
    packs: Vec<PackManifestV0>,
}

impl PackStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-verifies manifest cryptographic signature, content digest, artifact kinds, SemVer, and
    /// monotonic anti-rollback before admitting `manifest` (`TA-06` + `TA-28`).
    pub fn admit(&mut self, manifest: PackManifestV0) -> Result<(), AdmitError> {
        let pid = manifest.pack_id.as_str();
        if pid.is_empty() || pid.trim() != pid {
            return Err(AdmitError::InvalidManifest(
                "empty or non-canonical pack_id".into(),
            ));
        }
        if manifest.version.trim() != manifest.version {
            return Err(AdmitError::InvalidManifest("untrimmed version".into()));
        }
        if manifest.rights_uri.is_empty() {
            return Err(AdmitError::MissingRights);
        }
        if manifest.rights_uri.trim() != manifest.rights_uri {
            return Err(AdmitError::InvalidManifest("untrimmed rights_uri".into()));
        }
        if manifest.sbom_ref.is_empty() || manifest.sbom_ref.trim() != manifest.sbom_ref {
            return Err(AdmitError::InvalidManifest(
                "empty or untrimmed sbom_ref".into(),
            ));
        }
        if manifest.trust_root_id.is_empty()
            || manifest.trust_root_id.trim() != manifest.trust_root_id
        {
            return Err(AdmitError::UnknownTrustRoot);
        }
        if manifest.signature_hex.is_empty() {
            return Err(AdmitError::MissingSignature);
        }
        if manifest.signature_hex.trim() != manifest.signature_hex {
            return Err(AdmitError::InvalidSignature);
        }
        if manifest.artifacts.is_empty() {
            return Err(AdmitError::InvalidManifest(
                "pack must declare at least one artifact".into(),
            ));
        }
        for art in &manifest.artifacts {
            if art.kind.is_forbidden_by_default() {
                return Err(AdmitError::ForbiddenKind);
            }
            validate_relative_artifact_path(&art.relative_path)?;
        }
        validate_no_duplicate_or_prefix_paths(
            manifest.artifacts.iter().map(|a| a.relative_path.as_str()),
        )?;
        let incoming_ver = semver::Version::parse(&manifest.version)
            .map_err(|_| AdmitError::InvalidManifest("invalid SemVer".into()))?;
        if compute_content_digest(&manifest.artifacts) != manifest.content_digest {
            return Err(AdmitError::DigestMismatch);
        }
        let payload = pack_signing_payload(
            manifest.pack_id.as_str(),
            &manifest.version,
            manifest.pack_epoch,
            &manifest.content_digest.to_hex(),
            &manifest.rights_uri,
            &manifest.sbom_ref,
            &manifest.runtime_requirements,
            &manifest.benchmark_links,
        );
        match verify_pack_signature(&manifest.trust_root_id, &payload, &manifest.signature_hex) {
            Ok(()) => {}
            Err(PackTrustError::UnknownTrustRoot) => return Err(AdmitError::UnknownTrustRoot),
            Err(PackTrustError::InvalidEncoding | PackTrustError::VerifyFailed) => {
                return Err(AdmitError::InvalidSignature);
            }
        }

        if let Some(existing) = self.packs.iter().find(|p| p.pack_id == manifest.pack_id) {
            if is_rollback(existing, &manifest, &incoming_ver)? {
                return Err(AdmitError::AntiRollback);
            }
            if existing.pack_epoch == manifest.pack_epoch
                && existing.version == manifest.version
                && existing.content_digest != manifest.content_digest
            {
                // Equivocation guard: same (pack_id, epoch, version) with different content_digest
                // is refused as DigestMismatch!
                return Err(AdmitError::DigestMismatch);
            }
        }
        self.insert_unchecked(manifest);
        Ok(())
    }

    fn insert_unchecked(&mut self, manifest: PackManifestV0) {
        if let Some(existing) = self
            .packs
            .iter_mut()
            .find(|p| p.pack_id == manifest.pack_id)
        {
            *existing = manifest;
        } else {
            self.packs.push(manifest);
        }
    }

    #[must_use]
    pub fn list(&self) -> Vec<PackManifestV0> {
        self.packs.clone()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.packs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }

    #[must_use]
    pub fn get(&self, pack_id: &OpaqueId) -> Option<PackManifestV0> {
        self.packs
            .iter()
            .find(|pack| &pack.pack_id == pack_id)
            .cloned()
    }

    #[must_use]
    pub fn current_pack_id(&self) -> Option<OpaqueId> {
        self.packs
            .iter()
            .find(|p| p.promotion_state == PackPromotionState::Current)
            .map(|p| p.pack_id.clone())
    }

    /// Promote pack; fail closed if target state transition is invalid.
    pub fn promote(
        &mut self,
        pack_id: &OpaqueId,
        to: PackPromotionState,
    ) -> Result<PackManifestV0, &'static str> {
        let idx = self
            .packs
            .iter()
            .position(|p| &p.pack_id == pack_id)
            .ok_or("pack not found")?;
        match to {
            PackPromotionState::Current => {
                if self.packs[idx].promotion_state != PackPromotionState::Candidate
                    && self.packs[idx].promotion_state != PackPromotionState::Canary
                {
                    return Err("current requires candidate or canary");
                }
                for p in &mut self.packs {
                    if p.promotion_state == PackPromotionState::Current {
                        p.promotion_state = PackPromotionState::LastGreen;
                    }
                }
                self.packs[idx].promotion_state = PackPromotionState::Current;
            }
            PackPromotionState::Canary
            | PackPromotionState::LastGreen
            | PackPromotionState::Candidate => {
                self.packs[idx].promotion_state = to;
            }
        }
        Ok(self.packs[idx].clone())
    }
}

fn is_rollback(
    existing: &PackManifestV0,
    incoming: &PackManifestV0,
    incoming_ver: &semver::Version,
) -> Result<bool, AdmitError> {
    let existing_ver = semver::Version::parse(&existing.version)
        .map_err(|_| AdmitError::InvalidManifest("existing SemVer invalid".into()))?;
    if incoming.pack_epoch < existing.pack_epoch {
        return Ok(true);
    }
    if incoming.pack_epoch > existing.pack_epoch {
        // Even when epoch advances, version regression is treated as rollback (`TA-28`).
        return Ok(incoming_ver < &existing_ver);
    }
    Ok(incoming_ver < &existing_ver)
}

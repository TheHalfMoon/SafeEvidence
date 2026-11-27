//! Pack v0 contracts (`ADM-0016` / `T07`: content-addressed manifest, Ed25519 signer & monotonic
//! anti-rollback, `TA-06`, `TA-28`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/packs/mod.rs`)
//! under Apache-2.0 (`ADR-0004`). Runtime model execution (`runtime.rs`) is excluded per F8.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::objects::{DigestSha256, OpaqueId};

/// Promotion lifecycle for admitted packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPromotionState {
    Candidate,
    Current,
    LastGreen,
    Canary,
}

/// Artifact class declared in a pack (fail-closed on forbidden executable/pickle kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackArtifactKind {
    FixtureBytes,
    CorpusJsonl,
    GuidelineMetadata,
    TokenizerMeta,
    ModelMetadata,
    OnnxModel,
    /// Data-only safetensors weights. No executable content.
    SafetensorsModel,
    /// Forbidden by default (arbitrary code execution vector).
    Pickle,
    /// Forbidden by default (code-bearing binary).
    CodeBin,
    /// Forbidden unless signed custom-op admission.
    OnnxCustomOp,
}

impl PackArtifactKind {
    /// Returns true when default policy must deny admission (`TA-06` / `TA-28`).
    #[must_use]
    pub const fn is_forbidden_by_default(self) -> bool {
        matches!(self, Self::Pickle | Self::CodeBin | Self::OnnxCustomOp)
    }
}

/// Signed provenance for one model/pack artifact source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSourceProvenance {
    pub source_kind: String,
    pub repository: String,
    pub revision: String,
    pub original_file: String,
    pub source_sha256: String,
    pub transform: String,
    pub fixed_sequence_length: u32,
    pub task: String,
    pub export_format: String,
    pub runtime_family: String,
    pub license_id: String,
    pub upstream_rights_uri: String,
}

/// One artifact entry in `PackManifestV0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackArtifactEntry {
    pub relative_path: String,
    pub kind: PackArtifactKind,
    pub digest: DigestSha256,
}

/// Content-addressed Pack v0 manifest (`TA-06` + `TA-28` signer + monotonic epoch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackManifestV0 {
    pub pack_id: OpaqueId,
    pub version: String,
    /// Monotonic anti-rollback epoch (`TA-28`).
    pub pack_epoch: u64,
    pub content_digest: DigestSha256,
    pub artifacts: Vec<PackArtifactEntry>,
    pub rights_uri: String,
    pub sbom_ref: String,
    pub runtime_requirements: String,
    pub benchmark_links: Vec<String>,
    pub promotion_state: PackPromotionState,
    /// Must match an admitted Ed25519 pack trust root id (e.g. `synthetic-pack-trust-v1`).
    pub trust_root_id: String,
    /// Hex-encoded RFC 8032 Ed25519 signature over the canonical signing payload.
    pub signature_hex: String,
}

/// Doctor axis for packs / store posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacksRuntimeDoctorStatus {
    pub present: bool,
    pub offline_only: bool,
    pub admitted_count: u32,
    pub current_pack_id: Option<String>,
    pub confinement_claim: String,
    pub online_download_authorized: bool,
}

/// Evidence-only proposal record from deterministic local fixture inspection (never `ClinicalAssertion`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackProposalRecord {
    pub pack_id: OpaqueId,
    pub content_digest: DigestSha256,
    pub evidence_only: bool,
    pub proposal_payload: Value,
    pub audit_id: OpaqueId,
}

/// Pack signer / trust `READY_BASE` posture (`OS_CA_CODE_SIGNED = FALSE` per `ADR-0004`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSignerDoctorStatus {
    pub present: bool,
    pub ready_base: bool,
    pub synthetic_trust_root: bool,
    pub anti_rollback: bool,
    pub release_ready: bool,
}

impl PackSignerDoctorStatus {
    #[must_use]
    pub fn ready_base() -> Self {
        Self {
            present: true,
            ready_base: true,
            synthetic_trust_root: true,
            anti_rollback: true,
            release_ready: false,
        }
    }

    #[must_use]
    pub fn is_honest_ready_base(&self) -> bool {
        self.present
            && self.ready_base
            && self.synthetic_trust_root
            && self.anti_rollback
            && !self.release_ready
    }
}

/// Admission decision reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackAdmitReason {
    Ok,
    MissingRights,
    DigestMismatch,
    ForbiddenArtifactKind,
    InvalidManifest,
    OnlinePathRefused,
    MissingSignature,
    InvalidSignature,
    UnknownTrustRoot,
    AntiRollback,
}

/// Result of local pack install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackAdmitResult {
    pub admitted: bool,
    pub reason: PackAdmitReason,
    pub pack_id: Option<OpaqueId>,
    pub audit_id: OpaqueId,
}

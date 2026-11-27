//! Answer proof manifest (`docs/P00_PROOF_ADMISSION_CONTRACT.md`). This validates the
//! manifest's shape only. Atomic commit and span verification belong to WP-12 and WP-08.
//! There is no confidence field: V1 shows no clinical confidence percentage.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::assurance::{ProofState, ReasonCode, TerminalOutcome};
use crate::objects::DigestSha256;
use crate::study::{Known, ResultId, StudyId};

/// Exact coordinates of evidence in one immutable source version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpan {
    pub source_id: String,
    pub source_version: String,
    pub source_digest: DigestSha256,
    pub start_scalar: u64,
    pub end_scalar: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportLabel {
    Supported,
    Unsupported,
    Contradicted,
    Unverifiable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofClaim {
    pub claim_id: String,
    pub material: bool,
    pub support: SupportLabel,
    pub spans: Vec<EvidenceSpan>,
    pub studies: Known<Vec<StudyId>>,
    pub results: Known<Vec<ResultId>>,
}

/// Versions of everything that shaped the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofComponents {
    pub retriever: String,
    pub reranker: Option<String>,
    pub translator: Option<String>,
    pub ocr: Option<String>,
    pub verifier: String,
    pub generator: Option<String>,
    pub tools: Vec<String>,
    pub prompts: Vec<String>,
    pub policy: String,
    pub thresholds: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicabilityState {
    Applicable,
    ApplicableWithLimits,
    Unresolved,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContradictionState {
    None,
    NonMaterial,
    Material,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerProofManifest {
    pub proof_id: String,
    pub question_snapshot_digest: DigestSha256,
    pub final_text_digest: DigestSha256,
    pub claims: Vec<ProofClaim>,
    pub rights_grant_version: String,
    pub validity_epoch: u64,
    pub components: ProofComponents,
    pub applicability: ApplicabilityState,
    pub contradiction: ContradictionState,
    pub outcome: TerminalOutcome,
    pub reason: ReasonCode,
    pub post_verification_passed: bool,
    pub verified_at_utc: String,
    pub state: ProofState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestDefect {
    NoMaterialClaim,
    DuplicateClaimId(String),
    MaterialClaimNotSupported(String),
    ClaimWithoutSpan(String),
    InvalidSpan(String),
    PostVerificationFailed,
    OutcomeCannotCommit,
    MissingRightsGrant,
    StateCannotCommit,
    ReasonForbidsCommit,
    MaterialContradiction,
    ApplicabilityForbidsCommit,
    LimitsRequireCaution,
    MissingIdentity,
    MissingValidityEpoch,
}

fn state_can_commit(state: ProofState) -> bool {
    matches!(
        state,
        ProofState::VerifiedUncommitted | ProofState::Committed
    )
}

/// Limits are allowed only as an explicit caution. Every other reason denies a commit.
fn is_caution_reason(reason: ReasonCode) -> bool {
    matches!(reason, ReasonCode::CurrentnessUnknown)
}

/// Defects that forbid this manifest from backing a committed answer.
#[must_use]
pub fn commit_defects(manifest: &AnswerProofManifest) -> Vec<ManifestDefect> {
    let mut defects = Vec::new();
    if !manifest.outcome.may_commit() {
        defects.push(ManifestDefect::OutcomeCannotCommit);
    }
    if !state_can_commit(manifest.state) {
        defects.push(ManifestDefect::StateCannotCommit);
    }
    if !manifest.post_verification_passed {
        defects.push(ManifestDefect::PostVerificationFailed);
    }
    if manifest.rights_grant_version.trim().is_empty() {
        defects.push(ManifestDefect::MissingRightsGrant);
    }
    if manifest.reason != ReasonCode::None && !is_caution_reason(manifest.reason) {
        defects.push(ManifestDefect::ReasonForbidsCommit);
    }
    if manifest.contradiction == ContradictionState::Material {
        defects.push(ManifestDefect::MaterialContradiction);
    }
    if matches!(
        manifest.applicability,
        ApplicabilityState::Unresolved | ApplicabilityState::NotApplicable
    ) {
        defects.push(ManifestDefect::ApplicabilityForbidsCommit);
    }
    let limited = is_caution_reason(manifest.reason)
        || manifest.applicability == ApplicabilityState::ApplicableWithLimits;
    if limited && manifest.outcome == TerminalOutcome::Answer {
        defects.push(ManifestDefect::LimitsRequireCaution);
    }
    if manifest.proof_id.trim().is_empty()
        || manifest.verified_at_utc.trim().is_empty()
        || manifest.components.retriever.trim().is_empty()
        || manifest.components.verifier.trim().is_empty()
        || manifest.components.policy.trim().is_empty()
        || manifest.components.thresholds.trim().is_empty()
    {
        defects.push(ManifestDefect::MissingIdentity);
    }
    if manifest.validity_epoch == 0 {
        defects.push(ManifestDefect::MissingValidityEpoch);
    }
    if !manifest.claims.iter().any(|claim| claim.material) {
        defects.push(ManifestDefect::NoMaterialClaim);
    }
    let mut seen = BTreeSet::new();
    for claim in &manifest.claims {
        if claim.claim_id.trim().is_empty() {
            defects.push(ManifestDefect::MissingIdentity);
        }
        if !seen.insert(claim.claim_id.as_str()) {
            defects.push(ManifestDefect::DuplicateClaimId(claim.claim_id.clone()));
        }
        if claim.material && claim.support != SupportLabel::Supported {
            defects.push(ManifestDefect::MaterialClaimNotSupported(
                claim.claim_id.clone(),
            ));
        }
        if claim.material && claim.spans.is_empty() {
            defects.push(ManifestDefect::ClaimWithoutSpan(claim.claim_id.clone()));
        }
        if claim
            .spans
            .iter()
            .any(|span| span.start_scalar >= span.end_scalar)
        {
            defects.push(ManifestDefect::InvalidSpan(claim.claim_id.clone()));
        }
    }
    defects
}

//! Proposal and clinical assertion types (must remain distinct).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{MedicalTime, ObjectHeader, OpaqueId};
use crate::assurance::{AssuredSurfaceGateError, json_contains_confidence_key};

/// Producer of a proposal — never grants clinical authority by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerKind {
    Human,
    Rule,
    WorkerStub,
    /// A Spec 077 `AgentIdentity` (by id) produced this proposal. Added
    /// additively for MedAgent Workbench; carries no clinical/research
    /// authority beyond any other `Proposal`, and this variant alone never
    /// implies promotion to `ClinicalAssertion` (`security.md` T1 in
    /// `specs/077-medagent-workbench/`).
    Agent(OpaqueId),
    Other(String),
}

/// Non-authoritative candidate claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub header: ObjectHeader,
    pub subject_ref: Option<OpaqueId>,
    pub claim_kind: String,
    pub payload: Value,
    pub confidence: Option<f64>,
    pub evidence_refs: Vec<OpaqueId>,
    pub producer: ProducerKind,
}

/// Authorized clinical truth claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClinicalAssertion {
    pub header: ObjectHeader,
    pub subject_ref: OpaqueId,
    pub claim_kind: String,
    pub payload: Value,
    pub promoted_from_proposal_id: Option<OpaqueId>,
    pub authorized_by: OpaqueId,
    pub effective_time: Option<MedicalTime>,
    pub recorded_time: MedicalTime,
}

impl Proposal {
    /// Proposals are non-authoritative candidates and must never reach an assured V1 surface.
    pub const fn validate_assured_surface(&self) -> Result<(), AssuredSurfaceGateError> {
        Err(AssuredSurfaceGateError::ProposalCannotReachAssuredSurface)
    }

    /// Validates internal candidate shape; `confidence` remains strictly internal and bounded to
    /// `[0.0, 1.0]` when present, never emitted as clinical confidence (`P00_DECISION_ASSURANCE_CONTRACT`).
    pub fn validate_internal_candidate(&self) -> Result<(), AssuredSurfaceGateError> {
        if self.header.id.as_str().trim().is_empty()
            || self.header.realm_id.as_opaque().as_str().trim().is_empty()
            || self
                .header
                .authority_scope_id
                .as_opaque()
                .as_str()
                .trim()
                .is_empty()
            || self.claim_kind.trim().is_empty()
        {
            return Err(AssuredSurfaceGateError::MissingRequiredAuthorityField);
        }
        if let Some(score) = self.confidence
            && (!score.is_finite() || !(0.0..=1.0).contains(&score))
        {
            return Err(AssuredSurfaceGateError::InvalidProposalConfidence);
        }
        Ok(())
    }
}

impl ClinicalAssertion {
    /// Enforces `P00_DECISION_ASSURANCE_CONTRACT` on promoted assertions: explicit actor authority,
    /// non-empty identifiers, and zero heuristic confidence fields in `payload`.
    pub fn validate_p00_contract(&self) -> Result<(), AssuredSurfaceGateError> {
        if self.header.id.as_str().trim().is_empty()
            || self.header.realm_id.as_opaque().as_str().trim().is_empty()
            || self
                .header
                .authority_scope_id
                .as_opaque()
                .as_str()
                .trim()
                .is_empty()
            || self.subject_ref.as_str().trim().is_empty()
            || self.claim_kind.trim().is_empty()
            || self.authorized_by.as_str().trim().is_empty()
        {
            return Err(AssuredSurfaceGateError::MissingRequiredAuthorityField);
        }
        if json_contains_confidence_key(&self.payload) {
            return Err(AssuredSurfaceGateError::ForbiddenConfidenceField);
        }
        Ok(())
    }
}

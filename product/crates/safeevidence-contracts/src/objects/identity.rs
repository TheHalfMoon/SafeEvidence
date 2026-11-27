//! Identity assertion and explicit merge decision.

use serde::{Deserialize, Serialize};

use super::{ObjectHeader, OpaqueId};
use crate::assurance::AssuredSurfaceGateError;

/// Explicit identity statement — not a silent merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssertion {
    pub header: ObjectHeader,
    pub subject_id: OpaqueId,
    pub identifier_system: String,
    pub identifier_value: String,
    pub confidence: Option<f64>,
    pub evidence_refs: Vec<OpaqueId>,
}

/// Explicit decision required to unify subject identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMergeDecision {
    pub header: ObjectHeader,
    pub surviving_subject_id: OpaqueId,
    pub merged_subject_ids: Vec<OpaqueId>,
    pub authorized_by: OpaqueId,
    pub rationale: String,
    pub evidence_refs: Vec<OpaqueId>,
}

impl IdentityAssertion {
    /// Rejects any identity assertion carrying a heuristic `confidence` score or blank identifiers
    /// from assured V1 surfaces (`P00_DECISION_ASSURANCE_CONTRACT`).
    pub fn validate_assured_surface(&self) -> Result<(), AssuredSurfaceGateError> {
        if self.header.id.as_str().trim().is_empty()
            || self.header.realm_id.as_opaque().as_str().trim().is_empty()
            || self
                .header
                .authority_scope_id
                .as_opaque()
                .as_str()
                .trim()
                .is_empty()
            || self.subject_id.as_str().trim().is_empty()
            || self.identifier_system.trim().is_empty()
            || self.identifier_value.trim().is_empty()
        {
            return Err(AssuredSurfaceGateError::MissingRequiredAuthorityField);
        }
        if self.confidence.is_some() {
            return Err(AssuredSurfaceGateError::ForbiddenConfidenceField);
        }
        Ok(())
    }
}

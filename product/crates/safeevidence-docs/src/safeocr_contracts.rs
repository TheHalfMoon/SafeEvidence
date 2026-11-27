//! SafeOCR verification contracts (`ADM-0020` / `T16`, `TA-15`).
//!
//! Adapted in pure safe Rust from `AbdulazizShehri/safeOCR` (`src/safeocr/contracts.py`)
//! under Apache-2.0 (`ADR-0004`; donor `LICENSE` and `NOTICE` preserved in `tests/fixtures/t16/`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SafeOcrContractError {
    #[error("bounding box coordinates invalid (require 0 <= x1 < x2 and 0 <= y1 < y2)")]
    InvalidBoundingBox,
    #[error("bounding box exceeds page dimensions")]
    BoxOutsidePage,
    #[error("SHA-256 hex digest must be 64 hexadecimal characters")]
    InvalidSha256Hex,
    #[error("page dimensions must be strictly positive")]
    InvalidPageDimensions,
    #[error("required string field `{0}` must be non-empty")]
    EmptyField(&'static str),
    #[error("engine-native OCR score must be finite in [0.0, 1.0]")]
    InvalidScore,
    #[error("laboratory/study field must reference at least one source span")]
    EmptySourceSpans,
    #[error("field cannot combine source spans from multiple documents")]
    CrossDocumentSpans,
    #[error("decision record does not match fail-closed F1 policy derivation")]
    DecisionMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Criticality {
    Critical,
    High,
    Normal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionState {
    VerifiedAuto,
    ReviewRequired,
    Abstained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundingBox {
    pub x1: u32,
    pub y1: u32,
    pub x2: u32,
    pub y2: u32,
}

impl BoundingBox {
    pub fn new(x1: u32, y1: u32, x2: u32, y2: u32) -> Result<Self, SafeOcrContractError> {
        if x2 <= x1 || y2 <= y1 {
            return Err(SafeOcrContractError::InvalidBoundingBox);
        }
        Ok(Self { x1, y1, x2, y2 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageAsset {
    pub document_sha256: String,
    pub page_index: u32,
    pub width_px: u32,
    pub height_px: u32,
    pub page_sha256: String,
}

fn normalize_sha256_hex(raw: &str) -> Result<String, SafeOcrContractError> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SafeOcrContractError::InvalidSha256Hex);
    }
    Ok(raw.to_ascii_lowercase())
}

impl PageAsset {
    pub fn new(
        document_sha256: &str,
        page_index: u32,
        width_px: u32,
        height_px: u32,
        page_sha256: &str,
    ) -> Result<Self, SafeOcrContractError> {
        if width_px == 0 || height_px == 0 {
            return Err(SafeOcrContractError::InvalidPageDimensions);
        }
        Ok(Self {
            document_sha256: normalize_sha256_hex(document_sha256)?,
            page_index,
            width_px,
            height_px,
            page_sha256: normalize_sha256_hex(page_sha256)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSpan {
    pub page: PageAsset,
    pub bbox: BoundingBox,
    pub text: String,
    pub engine_name: String,
    pub engine_version: String,
    pub engine_score: Option<f64>,
}

impl CandidateSpan {
    pub fn new(
        page: PageAsset,
        bbox: BoundingBox,
        text: impl Into<String>,
        engine_name: impl Into<String>,
        engine_version: impl Into<String>,
        engine_score: Option<f64>,
    ) -> Result<Self, SafeOcrContractError> {
        let text = text.into();
        let engine_name = engine_name.into();
        let engine_version = engine_version.into();
        if text.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("text"));
        }
        if engine_name.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("engine_name"));
        }
        if engine_version.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("engine_version"));
        }
        if bbox.x2 > page.width_px || bbox.y2 > page.height_px {
            return Err(SafeOcrContractError::BoxOutsidePage);
        }
        if let Some(s) = engine_score
            && (!s.is_finite() || !(0.0..=1.0).contains(&s))
        {
            return Err(SafeOcrContractError::InvalidScore);
        }
        Ok(Self {
            page,
            bbox,
            text,
            engine_name,
            engine_version,
            engine_score,
        })
    }
    pub fn validate(&self) -> Result<(), SafeOcrContractError> {
        if self.page.width_px == 0 || self.page.height_px == 0 {
            return Err(SafeOcrContractError::InvalidPageDimensions);
        }
        normalize_sha256_hex(&self.page.document_sha256)?;
        normalize_sha256_hex(&self.page.page_sha256)?;
        if self.bbox.x2 <= self.bbox.x1 || self.bbox.y2 <= self.bbox.y1 {
            return Err(SafeOcrContractError::InvalidBoundingBox);
        }
        if self.text.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("text"));
        }
        if self.engine_name.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("engine_name"));
        }
        if self.engine_version.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("engine_version"));
        }
        if self.bbox.x2 > self.page.width_px || self.bbox.y2 > self.page.height_px {
            return Err(SafeOcrContractError::BoxOutsidePage);
        }
        if let Some(s) = self.engine_score
            && (!s.is_finite() || !(0.0..=1.0).contains(&s))
        {
            return Err(SafeOcrContractError::InvalidScore);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabFieldCandidate {
    pub analyte_text: String,
    pub value_text: String,
    pub unit_text: Option<String>,
    pub criticality: Criticality,
    pub source_spans: Vec<CandidateSpan>,
}

impl LabFieldCandidate {
    pub fn new(
        analyte_text: impl Into<String>,
        value_text: impl Into<String>,
        unit_text: Option<String>,
        criticality: Criticality,
        source_spans: Vec<CandidateSpan>,
    ) -> Result<Self, SafeOcrContractError> {
        let candidate = Self {
            analyte_text: analyte_text.into(),
            value_text: value_text.into(),
            unit_text,
            criticality,
            source_spans,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn validate(&self) -> Result<(), SafeOcrContractError> {
        if self.analyte_text.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("analyte_text"));
        }
        if self.value_text.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("value_text"));
        }
        if let Some(u) = &self.unit_text
            && u.trim().is_empty()
        {
            return Err(SafeOcrContractError::EmptyField("unit_text"));
        }
        let Some(first_span) = self.source_spans.first() else {
            return Err(SafeOcrContractError::EmptySourceSpans);
        };
        for span in &self.source_spans {
            span.validate()?;
        }
        let first_doc = &first_span.page.document_sha256;
        if self
            .source_spans
            .iter()
            .any(|s| &s.page.document_sha256 != first_doc)
        {
            return Err(SafeOcrContractError::CrossDocumentSpans);
        }
        Ok(())
    }
}

/// Explicit boolean verification policy signals (not calibrated probabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSignals {
    pub candidate_present: bool,
    pub visual_grounded: bool,
    pub independent_agreement: bool,
    pub perturbation_stable: bool,
    pub structural_association: bool,
    pub numeric_parse_unambiguous: bool,
    pub unit_valid: bool,
    pub patient_linkage_unambiguous: bool,
    pub runtime_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub state: DecisionState,
    pub criticality: Criticality,
    pub failed_gates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub field: LabFieldCandidate,
    pub signals: VerificationSignals,
    pub decision: DecisionRecord,
    pub policy_version: String,
}

impl EvidenceRecord {
    pub fn build(
        field: LabFieldCandidate,
        signals: VerificationSignals,
        policy_version: impl Into<String>,
    ) -> Result<Self, SafeOcrContractError> {
        field.validate()?;
        let policy_version = policy_version.into();
        if policy_version.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("policy_version"));
        }
        let decision = decide(&signals, field.criticality);
        Ok(Self {
            field,
            signals,
            decision,
            policy_version,
        })
    }

    /// Validates all field/span invariants and verifies `self.decision` equals the fail-closed
    /// F1 policy derivation over `self.signals` and `self.field.criticality`.
    pub fn validate(&self) -> Result<(), SafeOcrContractError> {
        self.field.validate()?;
        if self.policy_version.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("policy_version"));
        }
        let expected = decide(&self.signals, self.field.criticality);
        if self.decision != expected {
            return Err(SafeOcrContractError::DecisionMismatch);
        }
        Ok(())
    }
}

/// Fail-closed F1 terminal decision policy (`T16`).
#[must_use]
pub fn decide(signals: &VerificationSignals, criticality: Criticality) -> DecisionRecord {
    if !signals.candidate_present {
        return DecisionRecord {
            state: DecisionState::Abstained,
            criticality,
            failed_gates: vec!["candidate_present".to_owned()],
        };
    }
    if !signals.visual_grounded {
        return DecisionRecord {
            state: DecisionState::Abstained,
            criticality,
            failed_gates: vec!["visual_grounded".to_owned()],
        };
    }
    if !signals.runtime_healthy {
        return DecisionRecord {
            state: DecisionState::Abstained,
            criticality,
            failed_gates: vec!["runtime_healthy".to_owned()],
        };
    }

    let mut failed = Vec::new();
    for (ok, name) in [
        (signals.independent_agreement, "independent_agreement"),
        (signals.perturbation_stable, "perturbation_stable"),
        (signals.structural_association, "structural_association"),
        (
            signals.numeric_parse_unambiguous,
            "numeric_parse_unambiguous",
        ),
        (signals.unit_valid, "unit_valid"),
        (
            signals.patient_linkage_unambiguous,
            "patient_linkage_unambiguous",
        ),
    ] {
        if !ok {
            failed.push(name.to_owned());
        }
    }
    if !failed.is_empty() {
        return DecisionRecord {
            state: DecisionState::ReviewRequired,
            criticality,
            failed_gates: failed,
        };
    }
    DecisionRecord {
        state: DecisionState::VerifiedAuto,
        criticality,
        failed_gates: Vec::new(),
    }
}

#[must_use]
pub fn export_allowed(evidence: &EvidenceRecord) -> bool {
    evidence.validate().is_ok() && evidence.decision.state == DecisionState::VerifiedAuto
}

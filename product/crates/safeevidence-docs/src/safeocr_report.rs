//! SafeOCR deterministic evidence report builder (`ADM-0020` / `T16`).
//!
//! Adapted in pure safe Rust from `AbdulazizShehri/safeOCR` (`src/safeocr/report.py`)
//! under Apache-2.0 (`ADR-0004`).

use safeevidence_contracts::objects::DigestSha256;
use serde::{Deserialize, Serialize};

use crate::safeocr_contracts::{
    BoundingBox, Criticality, DecisionState, EvidenceRecord, SafeOcrContractError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReportField {
    pub field_id: String,
    pub analyte_text: String,
    pub value_text: String,
    pub unit_text: Option<String>,
    pub criticality: Criticality,
    pub state: DecisionState,
    pub failed_gates: Vec<String>,
    pub policy_version: String,
    pub page_sha256: String,
    pub source_box: BoundingBox,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeOcrAuditReport {
    pub document_sha256: String,
    pub fields: Vec<EvidenceReportField>,
    pub verified_auto_count: usize,
    pub review_required_count: usize,
    pub abstained_count: usize,
    pub report_digest: DigestSha256,
}

/// Builds a deterministic audit report over verified/quarantined SafeOCR fields (`T16`).
pub fn build_safeocr_audit_report(
    records: &[(String, EvidenceRecord)],
) -> Result<SafeOcrAuditReport, SafeOcrContractError> {
    let Some((_, first_rec)) = records.first() else {
        return Err(SafeOcrContractError::EmptySourceSpans);
    };
    first_rec.validate()?;
    let doc_sha = first_rec
        .field
        .source_spans
        .first()
        .ok_or(SafeOcrContractError::EmptySourceSpans)?
        .page
        .document_sha256
        .clone();
    let mut fields = Vec::with_capacity(records.len());
    let mut verified_auto_count = 0_usize;
    let mut review_required_count = 0_usize;
    let mut abstained_count = 0_usize;

    for (field_id, rec) in records {
        if field_id.trim().is_empty() {
            return Err(SafeOcrContractError::EmptyField("field_id"));
        }
        rec.validate()?;
        let span = rec
            .field
            .source_spans
            .first()
            .ok_or(SafeOcrContractError::EmptySourceSpans)?;
        if span.page.document_sha256 != doc_sha {
            return Err(SafeOcrContractError::CrossDocumentSpans);
        }
        match rec.decision.state {
            DecisionState::VerifiedAuto => verified_auto_count += 1,
            DecisionState::ReviewRequired => review_required_count += 1,
            DecisionState::Abstained => abstained_count += 1,
        }
        fields.push(EvidenceReportField {
            field_id: field_id.clone(),
            analyte_text: rec.field.analyte_text.clone(),
            value_text: rec.field.value_text.clone(),
            unit_text: rec.field.unit_text.clone(),
            criticality: rec.field.criticality,
            state: rec.decision.state,
            failed_gates: rec.decision.failed_gates.clone(),
            policy_version: rec.policy_version.clone(),
            page_sha256: span.page.page_sha256.clone(),
            source_box: span.bbox,
        });
    }

    let serialized = serde_json::to_vec(&fields).unwrap_or_default();
    let report_digest = DigestSha256::of(&serialized);
    Ok(SafeOcrAuditReport {
        document_sha256: doc_sha,
        fields,
        verified_auto_count,
        review_required_count,
        abstained_count,
        report_digest,
    })
}

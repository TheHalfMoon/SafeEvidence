//! Deterministic, privacy-conscious audits for overlapping evidence spans (`T17`, `ADM-0004`).
//!
//! Ported to Rust from `maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86`
//! (`openmed/clinical/evidence_span_audit.py`, Apache-2.0; see `PROVENANCE.md` and
//! `tests/fixtures/t17/NOTICE`).
//!
//! Compares caller-supplied half-open Unicode scalar ranges `[start, end)` and retains only
//! opaque SHA-256 identifiers, offsets, overlap classifications, counts, and canonical SHA-256
//! fingerprints. It never reads or retains source surface text, calls a network service, or
//! selects a winning span.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proof::EvidenceSpan;

/// Canonical schema version for serialized evidence-span audit reports.
pub const EVIDENCE_SPAN_AUDIT_SCHEMA_VERSION: &str = "1.0";

/// Mandatory non-clinical advisory carried in serialized audit reports.
pub const EVIDENCE_SPAN_AUDIT_ADVISORY: &str = "Evidence-span overlap findings are assistive review signals, not a clinical decision or automatic provenance resolution.";

/// Pairwise overlap classification between two half-open evidence spans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapKind {
    Exact,
    Nested,
    Partial,
    CrossSource,
}

impl OverlapKind {
    /// Canonical snake_case classification label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Nested => "nested",
            Self::Partial => "partial",
            Self::CrossSource => "cross_source",
        }
    }

    const fn sort_rank(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::Nested => 1,
            Self::Partial => 2,
            Self::CrossSource => 3,
        }
    }
}

/// Safe, PHI-redacted validation failure for evidence-span audit inputs.
///
/// Error messages never echo caller-supplied identifiers, source paths, or surface text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanAuditError {
    EmptySourceId,
    EmptyEvidenceId,
    InvalidOpaqueIdentifier,
    InvalidRangeBounds,
    InvalidAuditIntegrity,
}

impl fmt::Display for SpanAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::EmptySourceId => "source_id must be a non-empty string",
            Self::EmptyEvidenceId => "evidence_id must be a non-empty string",
            Self::InvalidOpaqueIdentifier => "audit identifier must be canonical sha256:<64hex>",
            Self::InvalidRangeBounds => "evidence span end must be greater than start",
            Self::InvalidAuditIntegrity => {
                "deserialized evidence span audit failed canonical integrity verification"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SpanAuditError {}

fn is_prefixed_sha256_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Hashes any raw caller-supplied identifier as `sha256:<64hex>`, keeping already-hashed
/// `sha256:<64hex>` identifiers idempotent so revalidation stays deterministic while caller or
/// patient strings never enter audit records, JSON reports, or `Debug` output.
#[must_use]
pub fn opaque_audit_identifier(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_prefixed_sha256_digest(trimmed) {
        return Some(trimmed.to_owned());
    }
    let digest = Sha256::digest(trimmed.as_bytes());
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    Some(out)
}

fn canonical_sha256_prefixed(json_value: &serde_json::Value) -> String {
    // serde_json::Value uses BTreeMap by default (no preserve_order feature), so to_string emits
    // lexicographically sorted object keys with compact `,` and `:` separators matching Python
    // `json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))` on ASCII-only
    // opaque payloads.
    let canonical = serde_json::to_string(json_value).expect("ASCII JSON value serializes");
    let digest = Sha256::digest(canonical.as_bytes());
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[derive(Deserialize)]
struct RawAuditedEvidenceSpan {
    source_id: String,
    evidence_id: String,
    start: u64,
    end: u64,
}

/// Opaque identity and half-open Unicode scalar range `[start, end)` for one evidence span.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawAuditedEvidenceSpan")]
pub struct AuditedEvidenceSpan {
    source_id: String,
    evidence_id: String,
    start: u64,
    end: u64,
}

impl TryFrom<RawAuditedEvidenceSpan> for AuditedEvidenceSpan {
    type Error = SpanAuditError;

    fn try_from(raw: RawAuditedEvidenceSpan) -> Result<Self, Self::Error> {
        if !is_prefixed_sha256_digest(&raw.source_id)
            || !is_prefixed_sha256_digest(&raw.evidence_id)
        {
            return Err(SpanAuditError::InvalidOpaqueIdentifier);
        }
        if raw.end <= raw.start {
            return Err(SpanAuditError::InvalidRangeBounds);
        }
        Ok(Self {
            source_id: raw.source_id,
            evidence_id: raw.evidence_id,
            start: raw.start,
            end: raw.end,
        })
    }
}

impl AuditedEvidenceSpan {
    /// Validates `end > start` and hashes raw identifiers into opaque `sha256:<64hex>` references.
    ///
    /// # Errors
    /// Returns a redacted [`SpanAuditError`] without echoing caller values.
    pub fn try_new(
        source_id: &str,
        evidence_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Self, SpanAuditError> {
        let opaque_source =
            opaque_audit_identifier(source_id).ok_or(SpanAuditError::EmptySourceId)?;
        let opaque_evidence =
            opaque_audit_identifier(evidence_id).ok_or(SpanAuditError::EmptyEvidenceId)?;
        if end <= start {
            return Err(SpanAuditError::InvalidRangeBounds);
        }
        Ok(Self {
            source_id: opaque_source,
            evidence_id: opaque_evidence,
            start,
            end,
        })
    }

    /// Converts a canonical [`EvidenceSpan`] plus opaque claim/extraction identifier into an
    /// [`AuditedEvidenceSpan`].
    ///
    /// # Errors
    /// Returns [`SpanAuditError`] if identifiers are empty or `end_scalar <= start_scalar`.
    pub fn from_evidence_span(
        span: &EvidenceSpan,
        evidence_id: &str,
    ) -> Result<Self, SpanAuditError> {
        Self::try_new(
            &span.source_id,
            evidence_id,
            span.start_scalar,
            span.end_scalar,
        )
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    fn sort_key(&self) -> (&str, u64, u64, &str) {
        (&self.source_id, self.start, self.end, &self.evidence_id)
    }

    fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "start": self.start,
            "end": self.end,
        })
    }
}

#[derive(Deserialize)]
struct RawEvidenceSpanOverlap {
    first: AuditedEvidenceSpan,
    second: AuditedEvidenceSpan,
    kind: OverlapKind,
    overlap_start: u64,
    overlap_end: u64,
    fingerprint: String,
}

/// Deterministic overlap finding between two [`AuditedEvidenceSpan`] records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawEvidenceSpanOverlap")]
pub struct EvidenceSpanOverlap {
    first: AuditedEvidenceSpan,
    second: AuditedEvidenceSpan,
    kind: OverlapKind,
    overlap_start: u64,
    overlap_end: u64,
    fingerprint: String,
}

impl TryFrom<RawEvidenceSpanOverlap> for EvidenceSpanOverlap {
    type Error = SpanAuditError;

    fn try_from(raw: RawEvidenceSpanOverlap) -> Result<Self, Self::Error> {
        if raw.first.sort_key() > raw.second.sort_key() {
            return Err(SpanAuditError::InvalidAuditIntegrity);
        }
        let Some(recomputed) = classify_overlap(&raw.first, &raw.second) else {
            return Err(SpanAuditError::InvalidRangeBounds);
        };
        if recomputed.kind != raw.kind
            || recomputed.overlap_start != raw.overlap_start
            || recomputed.overlap_end != raw.overlap_end
            || recomputed.fingerprint != raw.fingerprint
        {
            return Err(SpanAuditError::InvalidAuditIntegrity);
        }
        Ok(recomputed)
    }
}

impl EvidenceSpanOverlap {
    fn build(
        first: AuditedEvidenceSpan,
        second: AuditedEvidenceSpan,
        kind: OverlapKind,
        overlap_start: u64,
        overlap_end: u64,
    ) -> Self {
        let payload = serde_json::json!({
            "first": first.to_json_value(),
            "kind": kind.as_str(),
            "overlap": [overlap_start, overlap_end],
            "second": second.to_json_value(),
        });
        let fingerprint = canonical_sha256_prefixed(&payload);
        Self {
            first,
            second,
            kind,
            overlap_start,
            overlap_end,
            fingerprint,
        }
    }

    #[must_use]
    pub const fn first(&self) -> &AuditedEvidenceSpan {
        &self.first
    }

    #[must_use]
    pub const fn second(&self) -> &AuditedEvidenceSpan {
        &self.second
    }

    #[must_use]
    pub const fn kind(&self) -> OverlapKind {
        self.kind
    }

    #[must_use]
    pub const fn overlap_start(&self) -> u64 {
        self.overlap_start
    }

    #[must_use]
    pub const fn overlap_end(&self) -> u64 {
        self.overlap_end
    }

    #[must_use]
    pub const fn overlap_length(&self) -> u64 {
        self.overlap_end.saturating_sub(self.overlap_start)
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn fingerprint_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "first": self.first.to_json_value(),
            "kind": self.kind.as_str(),
            "overlap": [self.overlap_start, self.overlap_end],
            "second": self.second.to_json_value(),
        })
    }

    fn to_report_value(&self) -> serde_json::Value {
        serde_json::json!({
            "fingerprint": self.fingerprint,
            "first": self.first.to_json_value(),
            "kind": self.kind.as_str(),
            "overlap": [self.overlap_start, self.overlap_end],
            "overlap_length": self.overlap_length(),
            "second": self.second.to_json_value(),
        })
    }
}

/// Immutable per-kind overlap counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlapCounts {
    pub exact: usize,
    pub nested: usize,
    pub partial: usize,
    pub cross_source: usize,
}

impl OverlapCounts {
    #[must_use]
    pub const fn total(self) -> usize {
        self.exact
            .saturating_add(self.nested)
            .saturating_add(self.partial)
            .saturating_add(self.cross_source)
    }

    fn to_json_value(self) -> serde_json::Value {
        serde_json::json!({
            "cross_source": self.cross_source,
            "exact": self.exact,
            "nested": self.nested,
            "partial": self.partial,
        })
    }
}

#[derive(Deserialize)]
struct RawEvidenceSpanAudit {
    spans: Vec<AuditedEvidenceSpan>,
    overlaps: Vec<EvidenceSpanOverlap>,
    counts: OverlapCounts,
    fingerprint: String,
}

/// Complete deterministic evidence-span overlap audit with no automatic winner resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawEvidenceSpanAudit")]
pub struct EvidenceSpanAudit {
    spans: Vec<AuditedEvidenceSpan>,
    overlaps: Vec<EvidenceSpanOverlap>,
    counts: OverlapCounts,
    fingerprint: String,
}

impl TryFrom<RawEvidenceSpanAudit> for EvidenceSpanAudit {
    type Error = SpanAuditError;

    fn try_from(raw: RawEvidenceSpanAudit) -> Result<Self, Self::Error> {
        let canonical = audit_evidence_spans(&raw.spans);
        if canonical.spans != raw.spans
            || canonical.overlaps != raw.overlaps
            || canonical.counts != raw.counts
            || canonical.fingerprint != raw.fingerprint
        {
            return Err(SpanAuditError::InvalidAuditIntegrity);
        }
        Ok(canonical)
    }
}

impl EvidenceSpanAudit {
    #[must_use]
    pub fn spans(&self) -> &[AuditedEvidenceSpan] {
        &self.spans
    }

    #[must_use]
    pub fn overlaps(&self) -> &[EvidenceSpanOverlap] {
        &self.overlaps
    }

    #[must_use]
    pub const fn counts(&self) -> OverlapCounts {
        self.counts
    }

    #[must_use]
    pub fn overlap_count(&self) -> usize {
        self.overlaps.len()
    }

    #[must_use]
    pub fn source_count(&self) -> usize {
        let distinct: BTreeSet<&str> = self.spans.iter().map(|s| s.source_id.as_str()).collect();
        distinct.len()
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Serializes the PHI-free audit report to deterministic compact JSON matching the OpenMed
    /// `EvidenceSpanAudit.to_json()` schema.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let report = serde_json::json!({
            "advisory": EVIDENCE_SPAN_AUDIT_ADVISORY,
            "counts": self.counts.to_json_value(),
            "fingerprint": self.fingerprint,
            "overlap_count": self.overlap_count(),
            "overlaps": self.overlaps.iter().map(EvidenceSpanOverlap::to_report_value).collect::<Vec<_>>(),
            "schema_version": EVIDENCE_SPAN_AUDIT_SCHEMA_VERSION,
            "source_count": self.source_count(),
            "span_count": self.spans.len(),
            "spans": self.spans.iter().map(AuditedEvidenceSpan::to_json_value).collect::<Vec<_>>(),
        });
        serde_json::to_string(&report).expect("audit report JSON serializes")
    }
}

fn classify_overlap(
    first: &AuditedEvidenceSpan,
    second: &AuditedEvidenceSpan,
) -> Option<EvidenceSpanOverlap> {
    let overlap_start = first.start.max(second.start);
    let overlap_end = first.end.min(second.end);
    if overlap_start >= overlap_end {
        return None;
    }
    let kind = if first.source_id != second.source_id {
        OverlapKind::CrossSource
    } else if first.start == second.start && first.end == second.end {
        OverlapKind::Exact
    } else if (first.start <= second.start && second.end <= first.end)
        || (second.start <= first.start && first.end <= second.end)
    {
        OverlapKind::Nested
    } else {
        OverlapKind::Partial
    };
    Some(EvidenceSpanOverlap::build(
        first.clone(),
        second.clone(),
        kind,
        overlap_start,
        overlap_end,
    ))
}

/// Audits all pairwise overlaps across `spans` in canonical deterministic order.
///
/// Touching half-open intervals (`[0, 4)` and `[4, 9)`) do not overlap. Input ordering never
/// changes the resulting report or its SHA-256 fingerprint.
#[must_use]
pub fn audit_evidence_spans(spans: &[AuditedEvidenceSpan]) -> EvidenceSpanAudit {
    let mut normalized = spans.to_vec();
    normalized.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut overlaps = Vec::new();
    for (idx, first) in normalized.iter().enumerate() {
        for second in &normalized[idx + 1..] {
            if let Some(overlap) = classify_overlap(first, second) {
                overlaps.push(overlap);
            }
        }
    }
    overlaps.sort_by(|a, b| {
        (a.kind.sort_rank(), a.first.sort_key(), a.second.sort_key()).cmp(&(
            b.kind.sort_rank(),
            b.first.sort_key(),
            b.second.sort_key(),
        ))
    });

    let mut counts = OverlapCounts::default();
    for ov in &overlaps {
        match ov.kind {
            OverlapKind::Exact => counts.exact += 1,
            OverlapKind::Nested => counts.nested += 1,
            OverlapKind::Partial => counts.partial += 1,
            OverlapKind::CrossSource => counts.cross_source += 1,
        }
    }

    let fingerprint_payload = serde_json::json!({
        "counts": counts.to_json_value(),
        "overlaps": overlaps.iter().map(EvidenceSpanOverlap::fingerprint_payload).collect::<Vec<_>>(),
        "schema_version": EVIDENCE_SPAN_AUDIT_SCHEMA_VERSION,
        "spans": normalized.iter().map(AuditedEvidenceSpan::to_json_value).collect::<Vec<_>>(),
    });
    let fingerprint = canonical_sha256_prefixed(&fingerprint_payload);

    EvidenceSpanAudit {
        spans: normalized,
        overlaps,
        counts,
        fingerprint,
    }
}

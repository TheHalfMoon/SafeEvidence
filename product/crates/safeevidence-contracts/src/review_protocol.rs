//! SafeEvidence-owned Deep Review protocol lock, hash-chained audit export (`WP-14` greenfield
//! slice), and quote-anchored structured effect extraction (`WP-15`, `TA-17`).
//!
//! Copy-first boundary: `T15` (`MedOrigin` `litdb` screening/PRISMA event logs) and `T18`/`T19`
//! (`ASReview` active-learning screening / `statsmodels` meta-analysis inside the `WP-23a`
//! sandboxed Python worker) are NOT reimplemented here and remain fenced on `EXT-01`.
//!
//! Invariants (`TA-17`):
//! 1. 100% of `StructuredEffectExtraction` records carry a valid `EvidenceSpan` (`quote_span`)
//!    whose exact raw Unicode scalar substring in the source matches `quote_text` AND contains
//!    every reported numeric estimate/interval token.
//! 2. Extractions start in `ExtractionState::Proposed` and never qualify for downstream synthesis
//!    (`qualifies_for_synthesis() == false`) until promoted via `confirm_by_human` with a
//!    non-empty human `authorized_by` identifier.
//! 3. Zero heuristic `confidence` percentages exist on the wire (`D-13`).

use serde::{Deserialize, Serialize};

use crate::bilingual::{extract_raw_scalar_span, is_forbidden_bidi_control};
use crate::objects::DigestSha256;
use crate::proof::EvidenceSpan;
use crate::study::{Known, ReportVersionId, ResultId, StudyId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPicoCriteria {
    pub population: String,
    pub intervention: String,
    pub comparator: String,
    pub primary_outcomes: Vec<String>,
    pub eligible_designs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolAmendment {
    pub amendment_id: String,
    pub prior_version: u32,
    pub new_version: u32,
    pub rationale: String,
    pub authorized_by: String,
    pub recorded_at_utc: String,
}

/// Versioned, digest-pinned systematic review protocol (`WP-14` greenfield protocol object).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProtocol {
    pub protocol_id: String,
    pub version: u32,
    pub title: String,
    pub pico: ReviewPicoCriteria,
    pub inclusion_rules: Vec<String>,
    pub exclusion_rules: Vec<String>,
    pub locked_by: String,
    pub locked_at_utc: String,
    pub amendments: Vec<ProtocolAmendment>,
    pub protocol_digest: DigestSha256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolAuditEvent {
    pub seq: u64,
    pub event_type: String,
    pub actor_id: String,
    pub subject_id: String,
    pub detail: String,
    pub recorded_at_utc: String,
    pub prev_event_digest: Option<DigestSha256>,
    pub event_digest: DigestSha256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolAuditBundle {
    pub protocol: ReviewProtocol,
    pub events: Vec<ProtocolAuditEvent>,
    pub bundle_digest: DigestSha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectMeasureKind {
    RiskRatio,
    OddsRatio,
    HazardRatio,
    RiskDifference,
    MeanDifference,
    StandardizedMeanDifference,
}

/// Governance state of a structured extraction (`WP-15`, `TA-17`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ExtractionState {
    Proposed {
        extractor: String,
    },
    Confirmed {
        authorized_by: String,
        confirmed_at_utc: String,
    },
    Rejected {
        authorized_by: String,
        reason: String,
    },
}

/// Quote-anchored structured quantitative result extraction (`WP-15`, `TA-17`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredEffectExtraction {
    pub extraction_id: String,
    pub study_id: StudyId,
    pub report_version: ReportVersionId,
    pub result_id: ResultId,
    pub outcome_label: String,
    pub measure_kind: EffectMeasureKind,
    pub point_estimate_text: String,
    pub interval_low_text: Known<String>,
    pub interval_high_text: Known<String>,
    pub denominator: Known<u64>,
    pub timepoint: String,
    /// Preserves source table row/column or paragraph location (`P00_STUDY_INDEPENDENCE_CONTRACT`).
    pub source_location: String,
    pub quote_text: String,
    pub quote_span: EvidenceSpan,
    pub state: ExtractionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolExtractionError {
    EmptyRequiredField(&'static str),
    ControlOrBidiCharacter(&'static str),
    ProtocolDigestMismatch,
    InvalidProtocolVersionSequence,
    AuditChainBroken(u64),
    SourceDigestMismatch,
    QuoteSpanMismatch,
    EstimateNotAnchoredInQuote(String),
    EmptyHumanActor,
    InvalidStateTransition,
    Serialization(String),
}

fn check_clean_non_empty(value: &str, field: &'static str) -> Result<(), ProtocolExtractionError> {
    if value.trim().is_empty() {
        return Err(ProtocolExtractionError::EmptyRequiredField(field));
    }
    if value
        .chars()
        .any(|c| (c.is_control() && c != '\n') || is_forbidden_bidi_control(c))
    {
        return Err(ProtocolExtractionError::ControlOrBidiCharacter(field));
    }
    Ok(())
}

impl ReviewProtocol {
    /// Constructs and locks a versioned `ReviewProtocol` with its canonical `protocol_digest`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_locked(
        protocol_id: String,
        version: u32,
        title: String,
        pico: ReviewPicoCriteria,
        inclusion_rules: Vec<String>,
        exclusion_rules: Vec<String>,
        locked_by: String,
        locked_at_utc: String,
        amendments: Vec<ProtocolAmendment>,
    ) -> Result<Self, ProtocolExtractionError> {
        let mut proto = Self {
            protocol_id,
            version,
            title,
            pico,
            inclusion_rules,
            exclusion_rules,
            locked_by,
            locked_at_utc,
            amendments,
            protocol_digest: DigestSha256::of(b""),
        };
        proto.protocol_digest = proto.compute_digest()?;
        proto.validate()?;
        Ok(proto)
    }

    fn compute_digest(&self) -> Result<DigestSha256, ProtocolExtractionError> {
        let mut basis = self.clone();
        basis.protocol_digest = DigestSha256::of(b"");
        let bytes = serde_json::to_vec(&basis)
            .map_err(|e| ProtocolExtractionError::Serialization(e.to_string()))?;
        Ok(DigestSha256::of(&bytes))
    }

    /// Validates protocol completeness, amendment version lineage, and digest integrity.
    pub fn validate(&self) -> Result<(), ProtocolExtractionError> {
        check_clean_non_empty(&self.protocol_id, "protocol_id")?;
        check_clean_non_empty(&self.title, "title")?;
        check_clean_non_empty(&self.pico.population, "pico.population")?;
        check_clean_non_empty(&self.pico.intervention, "pico.intervention")?;
        check_clean_non_empty(&self.pico.comparator, "pico.comparator")?;
        check_clean_non_empty(&self.locked_by, "locked_by")?;
        check_clean_non_empty(&self.locked_at_utc, "locked_at_utc")?;
        if self.version == 0 {
            return Err(ProtocolExtractionError::InvalidProtocolVersionSequence);
        }
        if self.pico.primary_outcomes.is_empty() || self.inclusion_rules.is_empty() {
            return Err(ProtocolExtractionError::EmptyRequiredField(
                "primary_outcomes/inclusion_rules",
            ));
        }
        for outcome in &self.pico.primary_outcomes {
            check_clean_non_empty(outcome, "pico.primary_outcomes")?;
        }
        for design in &self.pico.eligible_designs {
            check_clean_non_empty(design, "pico.eligible_designs")?;
        }
        for rule in &self.inclusion_rules {
            check_clean_non_empty(rule, "inclusion_rules")?;
        }
        for rule in &self.exclusion_rules {
            check_clean_non_empty(rule, "exclusion_rules")?;
        }
        for (idx, amd) in self.amendments.iter().enumerate() {
            check_clean_non_empty(&amd.amendment_id, "amendment_id")?;
            check_clean_non_empty(&amd.rationale, "amendment.rationale")?;
            check_clean_non_empty(&amd.authorized_by, "amendment.authorized_by")?;
            check_clean_non_empty(&amd.recorded_at_utc, "amendment.recorded_at_utc")?;
            let expected_prior = u32::try_from(idx + 1).unwrap_or(0);
            if amd.prior_version != expected_prior || amd.new_version != expected_prior + 1 {
                return Err(ProtocolExtractionError::InvalidProtocolVersionSequence);
            }
        }
        if self.version != u32::try_from(self.amendments.len() + 1).unwrap_or(0) {
            return Err(ProtocolExtractionError::InvalidProtocolVersionSequence);
        }
        if self.compute_digest()? != self.protocol_digest {
            return Err(ProtocolExtractionError::ProtocolDigestMismatch);
        }
        Ok(())
    }
}

/// Appends a hash-chained `ProtocolAuditEvent` to `events`.
pub fn append_protocol_audit_event(
    events: &mut Vec<ProtocolAuditEvent>,
    event_type: &str,
    actor_id: &str,
    subject_id: &str,
    detail: &str,
    recorded_at_utc: &str,
) -> Result<ProtocolAuditEvent, ProtocolExtractionError> {
    check_clean_non_empty(event_type, "event_type")?;
    check_clean_non_empty(actor_id, "actor_id")?;
    check_clean_non_empty(subject_id, "subject_id")?;
    check_clean_non_empty(detail, "detail")?;
    check_clean_non_empty(recorded_at_utc, "recorded_at_utc")?;

    let seq = (events.len() as u64) + 1;
    let prev = events.last().map(|e| e.event_digest.clone());
    let mut candidate = ProtocolAuditEvent {
        seq,
        event_type: event_type.to_owned(),
        actor_id: actor_id.to_owned(),
        subject_id: subject_id.to_owned(),
        detail: detail.to_owned(),
        recorded_at_utc: recorded_at_utc.to_owned(),
        prev_event_digest: prev,
        event_digest: DigestSha256::of(b""),
    };
    let bytes = serde_json::to_vec(&candidate)
        .map_err(|e| ProtocolExtractionError::Serialization(e.to_string()))?;
    candidate.event_digest = DigestSha256::of(&bytes);
    events.push(candidate.clone());
    Ok(candidate)
}

/// Verifies the protocol and every hash-chained audit event and emits a deterministic
/// `ProtocolAuditBundle` (`WP-14`).
pub fn export_protocol_audit_bundle(
    protocol: &ReviewProtocol,
    events: &[ProtocolAuditEvent],
) -> Result<ProtocolAuditBundle, ProtocolExtractionError> {
    protocol.validate()?;
    let mut prev: Option<DigestSha256> = None;
    for (idx, event) in events.iter().enumerate() {
        check_clean_non_empty(&event.event_type, "event_type")?;
        check_clean_non_empty(&event.actor_id, "actor_id")?;
        check_clean_non_empty(&event.subject_id, "subject_id")?;
        check_clean_non_empty(&event.detail, "detail")?;
        check_clean_non_empty(&event.recorded_at_utc, "recorded_at_utc")?;
        let expected_seq = (idx as u64) + 1;
        if event.seq != expected_seq || event.prev_event_digest != prev {
            return Err(ProtocolExtractionError::AuditChainBroken(expected_seq));
        }
        let mut basis = event.clone();
        basis.event_digest = DigestSha256::of(b"");
        let encoded = serde_json::to_vec(&basis)
            .map_err(|e| ProtocolExtractionError::Serialization(e.to_string()))?;
        if DigestSha256::of(&encoded) != event.event_digest {
            return Err(ProtocolExtractionError::AuditChainBroken(expected_seq));
        }
        prev = Some(event.event_digest.clone());
    }
    let mut bundle = ProtocolAuditBundle {
        protocol: protocol.clone(),
        events: events.to_vec(),
        bundle_digest: DigestSha256::of(b""),
    };
    let encoded = serde_json::to_vec(&bundle)
        .map_err(|e| ProtocolExtractionError::Serialization(e.to_string()))?;
    bundle.bundle_digest = DigestSha256::of(&encoded);
    Ok(bundle)
}

fn contains_anchored_estimate(quote: &str, token: &str) -> bool {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return false;
    }
    let first = trimmed.chars().next().expect("non-empty");
    let second = trimmed.chars().nth(1);
    let last = trimmed.chars().next_back().expect("non-empty");

    for (byte_idx, _) in quote.match_indices(trimmed) {
        let before = &quote[..byte_idx];
        let after = &quote[byte_idx + trimmed.len()..];
        let prev = before.chars().next_back();
        let next = after.chars().next();

        if first.is_ascii_digit() {
            let bad_prefix = match prev {
                Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => true,
                Some('.') => before[..before.len() - 1]
                    .chars()
                    .next_back()
                    .is_some_and(|d| d.is_ascii_digit()),
                _ => false,
            };
            if bad_prefix {
                continue;
            }
        } else if (first == '-' || first == '+')
            && second.is_some_and(|c| c.is_ascii_digit())
            && prev.is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }

        if last.is_ascii_digit() {
            let bad_suffix = match next {
                Some(c) if c.is_ascii_digit() => true,
                Some('.') => after[1..]
                    .chars()
                    .next()
                    .is_some_and(|d| d.is_ascii_digit()),
                _ => false,
            };
            if bad_suffix {
                continue;
            }
        }

        return true;
    }
    false
}

impl StructuredEffectExtraction {
    /// Creates a new quote-anchored extraction in mandatory `Proposed` state (`TA-17`) and
    /// verifies its `quote_span` and numeric tokens against `raw_source_text`.
    #[allow(clippy::too_many_arguments)]
    pub fn propose_anchored(
        extraction_id: String,
        study_id: StudyId,
        report_version: ReportVersionId,
        result_id: ResultId,
        outcome_label: String,
        measure_kind: EffectMeasureKind,
        point_estimate_text: String,
        interval_low_text: Known<String>,
        interval_high_text: Known<String>,
        denominator: Known<u64>,
        timepoint: String,
        source_location: String,
        quote_text: String,
        quote_span: EvidenceSpan,
        extractor: String,
        raw_source_text: &str,
    ) -> Result<Self, ProtocolExtractionError> {
        let record = Self {
            extraction_id,
            study_id,
            report_version,
            result_id,
            outcome_label,
            measure_kind,
            point_estimate_text,
            interval_low_text,
            interval_high_text,
            denominator,
            timepoint,
            source_location,
            quote_text,
            quote_span,
            state: ExtractionState::Proposed { extractor },
        };
        record.verify_against_source(raw_source_text)?;
        Ok(record)
    }

    /// Verifies `TA-17` quote-span integrity against `raw_source_text`:
    /// 1. `DigestSha256::of(raw_source_text)` equals `quote_span.source_digest`.
    /// 2. `extract_raw_scalar_span` on `[start_scalar, end_scalar)` equals `quote_text`.
    /// 3. `point_estimate_text` and any `Known` confidence-interval bound appear verbatim inside
    ///    `quote_text` (preventing hallucinated or altered numeric values).
    /// 4. `Confirmed` state carries a non-empty `authorized_by` human identifier.
    pub fn verify_against_source(
        &self,
        raw_source_text: &str,
    ) -> Result<(), ProtocolExtractionError> {
        check_clean_non_empty(&self.extraction_id, "extraction_id")?;
        check_clean_non_empty(&self.outcome_label, "outcome_label")?;
        check_clean_non_empty(&self.point_estimate_text, "point_estimate_text")?;
        check_clean_non_empty(&self.timepoint, "timepoint")?;
        check_clean_non_empty(&self.source_location, "source_location")?;
        check_clean_non_empty(&self.quote_text, "quote_text")?;
        check_clean_non_empty(&self.quote_span.source_id, "quote_span.source_id")?;

        if DigestSha256::of(raw_source_text.as_bytes()) != self.quote_span.source_digest {
            return Err(ProtocolExtractionError::SourceDigestMismatch);
        }
        let extracted_quote = extract_raw_scalar_span(
            raw_source_text,
            self.quote_span.start_scalar,
            self.quote_span.end_scalar,
        )
        .map_err(|_| ProtocolExtractionError::QuoteSpanMismatch)?;
        if extracted_quote != self.quote_text {
            return Err(ProtocolExtractionError::QuoteSpanMismatch);
        }

        if !contains_anchored_estimate(&self.quote_text, &self.point_estimate_text) {
            return Err(ProtocolExtractionError::EstimateNotAnchoredInQuote(
                self.point_estimate_text.clone(),
            ));
        }
        if let Known::Known(low) = &self.interval_low_text {
            check_clean_non_empty(low, "interval_low_text")?;
            if !contains_anchored_estimate(&self.quote_text, low) {
                return Err(ProtocolExtractionError::EstimateNotAnchoredInQuote(
                    low.clone(),
                ));
            }
        }
        if let Known::Known(high) = &self.interval_high_text {
            check_clean_non_empty(high, "interval_high_text")?;
            if !contains_anchored_estimate(&self.quote_text, high) {
                return Err(ProtocolExtractionError::EstimateNotAnchoredInQuote(
                    high.clone(),
                ));
            }
        }

        match &self.state {
            ExtractionState::Proposed { extractor } => {
                check_clean_non_empty(extractor, "extractor")?;
            }
            ExtractionState::Confirmed {
                authorized_by,
                confirmed_at_utc,
            } => {
                if authorized_by.trim().is_empty() {
                    return Err(ProtocolExtractionError::EmptyHumanActor);
                }
                check_clean_non_empty(authorized_by, "authorized_by")?;
                check_clean_non_empty(confirmed_at_utc, "confirmed_at_utc")?;
            }
            ExtractionState::Rejected {
                authorized_by,
                reason,
            } => {
                if authorized_by.trim().is_empty() {
                    return Err(ProtocolExtractionError::EmptyHumanActor);
                }
                check_clean_non_empty(authorized_by, "authorized_by")?;
                check_clean_non_empty(reason, "reason")?;
            }
        }
        Ok(())
    }

    /// Promotes a `Proposed` extraction to `Confirmed` only when a non-empty human `authorized_by`
    /// actor confirms it against `raw_source_text` (`TA-17`). Does not mutate `self` on error.
    pub fn confirm_by_human(
        &mut self,
        authorized_by: &str,
        confirmed_at_utc: &str,
        raw_source_text: &str,
    ) -> Result<(), ProtocolExtractionError> {
        if !matches!(self.state, ExtractionState::Proposed { .. }) {
            return Err(ProtocolExtractionError::InvalidStateTransition);
        }
        if authorized_by.trim().is_empty() {
            return Err(ProtocolExtractionError::EmptyHumanActor);
        }
        let mut candidate = self.clone();
        candidate.state = ExtractionState::Confirmed {
            authorized_by: authorized_by.to_owned(),
            confirmed_at_utc: confirmed_at_utc.to_owned(),
        };
        candidate.verify_against_source(raw_source_text)?;
        self.state = candidate.state;
        Ok(())
    }

    /// True ONLY when `state` is `Confirmed` with a non-empty human actor (`TA-17`).
    #[must_use]
    pub fn qualifies_for_synthesis(&self) -> bool {
        matches!(
            &self.state,
            ExtractionState::Confirmed { authorized_by, confirmed_at_utc }
                if !authorized_by.trim().is_empty() && !confirmed_at_utc.trim().is_empty()
        )
    }
}

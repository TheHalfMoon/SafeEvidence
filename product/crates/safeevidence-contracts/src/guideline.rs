//! Guideline currency/supersession governance, multi-outcome GRADE Summary-of-Findings tables,
//! and source-loss-aware `EvidenceSnapshot` reproduction (`WP-10`, `WP-12`, `WP-18`; `TA-06`,
//! `TA-12`, `TA-14`).
//!
//! All types in this module are non-clinical research governance contracts (`ADR-0003`) and
//! enforce `P00_DECISION_ASSURANCE_CONTRACT` invariants: zero heuristic confidence percentages on
//! assured surfaces, explicit supersession and issuer-conflict surfacing, and honest
//! `PartialReproduction` downgrade whenever cited source bytes are missing or revoked.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::appraisal::{AppraisalConfirmation, CertaintyLevel, SummaryOfFindingsRow};
use crate::bilingual::is_forbidden_bidi_control;
use crate::objects::DigestSha256;
use crate::proof::{
    AnswerProofManifest, ContradictionState, EvidenceSpan, ManifestDefect, commit_defects,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuidelineStatus {
    Current,
    Superseded,
    Withdrawn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecommendationStrength {
    StrongFor,
    ConditionalFor,
    ConditionalAgainst,
    StrongAgainst,
    NoRecommendation,
}

impl RecommendationStrength {
    #[must_use]
    pub const fn polarity(self) -> i8 {
        match self {
            Self::StrongFor | Self::ConditionalFor => 1,
            Self::StrongAgainst | Self::ConditionalAgainst => -1,
            Self::NoRecommendation => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuidelineMetadata {
    pub guideline_id: String,
    pub issuer: String,
    pub topic_concept: String,
    pub version: String,
    pub issued_date: String,
    pub status: GuidelineStatus,
    pub supersedes_guideline_id: Option<String>,
    pub recommendation: RecommendationStrength,
    pub rationale_summary: String,
    pub certainty: CertaintyLevel,
    pub source_digest: DigestSha256,
    pub cited_spans: Vec<EvidenceSpan>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConflict {
    pub topic_concept: String,
    pub guideline_a_id: String,
    pub issuer_a: String,
    pub recommendation_a: RecommendationStrength,
    pub guideline_b_id: String,
    pub issuer_b: String,
    pub recommendation_b: RecommendationStrength,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuidelineSetEvaluation {
    pub active_guideline_ids: Vec<String>,
    pub superseded_guideline_ids: Vec<String>,
    pub withdrawn_guideline_ids: Vec<String>,
    pub issuer_conflicts: Vec<IssuerConflict>,
    pub contradiction_state: ContradictionState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryOfFindingsTable {
    pub table_id: String,
    pub comparison_label: String,
    pub population_summary: String,
    pub intervention_summary: String,
    pub comparator_summary: String,
    pub rows: Vec<SummaryOfFindingsRow>,
    pub confirmation: AppraisalConfirmation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotDegradationReason {
    MissingSourceBytes,
    SourceRevoked,
    DigestMismatch,
    SpanOutOfBounds,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DegradedSnapshotSource {
    pub source_id: String,
    pub reason: SnapshotDegradationReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reproduction_state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotReproductionState {
    FullReproduction {
        verified_sources: Vec<String>,
    },
    PartialReproduction {
        verified_sources: Vec<String>,
        missing_or_revoked_sources: Vec<DegradedSnapshotSource>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSnapshot {
    pub snapshot_id: String,
    pub question_text: String,
    pub pack_epoch: u64,
    pub manifest: AnswerProofManifest,
    pub cited_source_digests: BTreeMap<String, DigestSha256>,
    pub snapshot_digest: DigestSha256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuidelineError {
    EmptyField(&'static str),
    ForbiddenControlOrConfidence(&'static str),
    InvalidIsoDate(String),
    SelfSupersession(String),
    SupersessionCycle(String),
    UnknownSupersededTarget {
        guideline_id: String,
        target_id: String,
    },
    DuplicateIdentifier(String),
    EmptySpans,
    InvalidSpanBounds,
    EmptyRows,
    UnconfirmedRowInConfirmedTable(String),
    InvalidConfirmation,
    SnapshotManifestDefects(Vec<ManifestDefect>),
    SnapshotSourceSetMismatch(String),
    SnapshotDigestMismatch,
}

fn has_forbidden_surface_tokens(text: &str) -> bool {
    if text
        .chars()
        .any(|c| is_forbidden_bidi_control(c) || (c.is_control() && c != '\n'))
    {
        return true;
    }
    if text.contains('%') || text.contains('\u{066A}') {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| matches!(tok, "percent" | "percentage" | "confidence"))
}

fn is_valid_iso_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let Ok(year) = date[0..4].parse::<u16>() else {
        return false;
    };
    let Ok(month) = date[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(day) = date[8..10].parse::<u8>() else {
        return false;
    };
    if !(1900..=2100).contains(&year) || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day <= max_day
}

fn validate_confirmation_strict(c: &AppraisalConfirmation) -> Result<(), GuidelineError> {
    match c {
        AppraisalConfirmation::Proposed { generator } => {
            if generator.trim().is_empty() {
                return Err(GuidelineError::InvalidConfirmation);
            }
        }
        AppraisalConfirmation::Confirmed {
            authorized_by,
            confirmed_at_utc,
        } => {
            if authorized_by.trim().is_empty() || confirmed_at_utc.trim().is_empty() {
                return Err(GuidelineError::InvalidConfirmation);
            }
        }
    }
    Ok(())
}

impl GuidelineMetadata {
    /// Validates structural, date, span, and P00 zero-confidence invariants.
    ///
    /// # Errors
    /// Fails closed on empty identifiers, invalid ISO-8601 date, self-supersession, invalid spans,
    /// or forbidden BiDi/confidence-percentage tokens.
    pub fn validate(&self) -> Result<(), GuidelineError> {
        let required = [
            ("guideline_id", self.guideline_id.as_str()),
            ("issuer", self.issuer.as_str()),
            ("topic_concept", self.topic_concept.as_str()),
            ("version", self.version.as_str()),
            ("rationale_summary", self.rationale_summary.as_str()),
        ];
        for (field, val) in required {
            if val.trim().is_empty() {
                return Err(GuidelineError::EmptyField(field));
            }
            if has_forbidden_surface_tokens(val) {
                return Err(GuidelineError::ForbiddenControlOrConfidence(field));
            }
        }
        if !is_valid_iso_date(&self.issued_date) {
            return Err(GuidelineError::InvalidIsoDate(self.issued_date.clone()));
        }
        if let Some(sup) = &self.supersedes_guideline_id {
            if sup.trim().is_empty() {
                return Err(GuidelineError::EmptyField("supersedes_guideline_id"));
            }
            if sup == &self.guideline_id {
                return Err(GuidelineError::SelfSupersession(self.guideline_id.clone()));
            }
        }
        if self.cited_spans.is_empty() {
            return Err(GuidelineError::EmptySpans);
        }
        for span in &self.cited_spans {
            if span.source_id.trim().is_empty()
                || span.source_version.trim().is_empty()
                || span.start_scalar >= span.end_scalar
            {
                return Err(GuidelineError::InvalidSpanBounds);
            }
        }
        Ok(())
    }
}

/// Evaluates currency, supersession chains, withdrawal status, and conflicting active
/// recommendations across a set of guidelines (`WP-12`, `TA-14`).
///
/// # Errors
/// Fails closed if any guideline fails validation, duplicates an ID, references a missing
/// superseded target, or forms a supersession cycle.
pub fn evaluate_guideline_set(
    guidelines: &[GuidelineMetadata],
) -> Result<GuidelineSetEvaluation, GuidelineError> {
    let mut by_id: BTreeMap<&str, &GuidelineMetadata> = BTreeMap::new();
    for g in guidelines {
        g.validate()?;
        if by_id.insert(g.guideline_id.as_str(), g).is_some() {
            return Err(GuidelineError::DuplicateIdentifier(g.guideline_id.clone()));
        }
    }

    let mut superseded_by_newer: BTreeSet<&str> = BTreeSet::new();
    for g in guidelines {
        if let Some(target) = g.supersedes_guideline_id.as_deref() {
            if !by_id.contains_key(target) {
                return Err(GuidelineError::UnknownSupersededTarget {
                    guideline_id: g.guideline_id.clone(),
                    target_id: target.to_owned(),
                });
            }
            if g.status != GuidelineStatus::Withdrawn {
                superseded_by_newer.insert(target);
            }
        }
    }

    // Cycle check across supersession pointers.
    for g in guidelines {
        let mut visited = BTreeSet::new();
        let mut cursor = Some(g.guideline_id.as_str());
        while let Some(curr_id) = cursor {
            if !visited.insert(curr_id) {
                return Err(GuidelineError::SupersessionCycle(curr_id.to_owned()));
            }
            cursor = by_id
                .get(curr_id)
                .and_then(|item| item.supersedes_guideline_id.as_deref());
        }
    }

    let mut active = Vec::new();
    let mut superseded = Vec::new();
    let mut withdrawn = Vec::new();

    for g in by_id.values() {
        match g.status {
            GuidelineStatus::Withdrawn => withdrawn.push(g.guideline_id.clone()),
            GuidelineStatus::Superseded => superseded.push(g.guideline_id.clone()),
            GuidelineStatus::Current => {
                if superseded_by_newer.contains(g.guideline_id.as_str()) {
                    superseded.push(g.guideline_id.clone());
                } else {
                    active.push(*g);
                }
            }
        }
    }

    let mut conflicts = Vec::new();
    for (idx, a) in active.iter().enumerate() {
        for b in active.iter().skip(idx + 1) {
            let same_topic = a
                .topic_concept
                .trim()
                .eq_ignore_ascii_case(b.topic_concept.trim());
            if !same_topic {
                continue;
            }
            let pa = a.recommendation.polarity();
            let pb = b.recommendation.polarity();
            // Flag conflict when one favors and one opposes, or when one recommends action and
            // another active issuer explicitly declares NoRecommendation.
            let disagrees = (pa != 0 && pb != 0 && pa != pb)
                || (pa != pb && (pa == 0 || pb == 0) && a.issuer != b.issuer);
            if disagrees {
                conflicts.push(IssuerConflict {
                    topic_concept: a.topic_concept.clone(),
                    guideline_a_id: a.guideline_id.clone(),
                    issuer_a: a.issuer.clone(),
                    recommendation_a: a.recommendation,
                    guideline_b_id: b.guideline_id.clone(),
                    issuer_b: b.issuer.clone(),
                    recommendation_b: b.recommendation,
                });
            }
        }
    }

    let contradiction_state = if conflicts.is_empty() {
        ContradictionState::None
    } else {
        ContradictionState::Material
    };

    Ok(GuidelineSetEvaluation {
        active_guideline_ids: active.iter().map(|g| g.guideline_id.clone()).collect(),
        superseded_guideline_ids: superseded,
        withdrawn_guideline_ids: withdrawn,
        issuer_conflicts: conflicts,
        contradiction_state,
    })
}

impl SummaryOfFindingsTable {
    /// Validates a multi-outcome GRADE Summary-of-Findings table (`WP-10`, `TA-12`).
    ///
    /// # Errors
    /// Fails closed on empty rows, duplicate `outcome_id`s, P00 confidence-percentage tokens,
    /// or `PROPOSED` rows inside a `Confirmed` table.
    pub fn validate(&self) -> Result<(), GuidelineError> {
        let fields = [
            ("table_id", self.table_id.as_str()),
            ("comparison_label", self.comparison_label.as_str()),
            ("population_summary", self.population_summary.as_str()),
            ("intervention_summary", self.intervention_summary.as_str()),
            ("comparator_summary", self.comparator_summary.as_str()),
        ];
        for (name, value) in fields {
            if value.trim().is_empty() {
                return Err(GuidelineError::EmptyField(name));
            }
            if has_forbidden_surface_tokens(value) {
                return Err(GuidelineError::ForbiddenControlOrConfidence(name));
            }
        }
        validate_confirmation_strict(&self.confirmation)?;
        if self.rows.is_empty() {
            return Err(GuidelineError::EmptyRows);
        }
        let mut seen_outcomes = BTreeSet::new();
        for row in &self.rows {
            if row.outcome_id.trim().is_empty() {
                return Err(GuidelineError::EmptyField("row.outcome_id"));
            }
            if !seen_outcomes.insert(row.outcome_id.as_str()) {
                return Err(GuidelineError::DuplicateIdentifier(row.outcome_id.clone()));
            }
            if row.outcome_definition.trim().is_empty() || row.effect_summary_text.trim().is_empty()
            {
                return Err(GuidelineError::EmptyField("row.effect_summary_text"));
            }
            if has_forbidden_surface_tokens(&row.outcome_definition)
                || has_forbidden_surface_tokens(&row.effect_summary_text)
                || row
                    .certainty_reasons
                    .iter()
                    .any(|r| r.trim().is_empty() || has_forbidden_surface_tokens(r))
            {
                return Err(GuidelineError::ForbiddenControlOrConfidence(
                    "row.effect_summary_text",
                ));
            }
            if row.study_count == 0 || row.certainty_reasons.len() != 8 {
                return Err(GuidelineError::EmptyField("row.certainty_reasons"));
            }
            match row.workflow_status.as_str() {
                "CONFIRMED" => {
                    if row
                        .authorized_by
                        .as_deref()
                        .is_none_or(|a| a.trim().is_empty())
                    {
                        return Err(GuidelineError::InvalidConfirmation);
                    }
                }
                "PROPOSED" => {
                    if self.confirmation.is_human_confirmed() {
                        return Err(GuidelineError::UnconfirmedRowInConfirmedTable(
                            row.outcome_id.clone(),
                        ));
                    }
                }
                _ => return Err(GuidelineError::InvalidConfirmation),
            }
        }
        Ok(())
    }
}

fn push_lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn compute_snapshot_digest(
    snapshot_id: &str,
    question_text: &str,
    pack_epoch: u64,
    manifest: &AnswerProofManifest,
    cited_source_digests: &BTreeMap<String, DigestSha256>,
) -> DigestSha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"safeevidence.evidence_snapshot.v1\0");
    push_lp(&mut hasher, snapshot_id.as_bytes());
    push_lp(&mut hasher, question_text.as_bytes());
    hasher.update(pack_epoch.to_be_bytes());
    push_lp(&mut hasher, manifest.proof_id.as_bytes());
    push_lp(
        &mut hasher,
        manifest.question_snapshot_digest.to_hex().as_bytes(),
    );
    push_lp(&mut hasher, manifest.final_text_digest.to_hex().as_bytes());
    hasher.update((manifest.claims.len() as u64).to_be_bytes());
    for claim in &manifest.claims {
        push_lp(&mut hasher, claim.claim_id.as_bytes());
        hasher.update([u8::from(claim.material)]);
        hasher.update((claim.spans.len() as u64).to_be_bytes());
        for span in &claim.spans {
            push_lp(&mut hasher, span.source_id.as_bytes());
            push_lp(&mut hasher, span.source_digest.to_hex().as_bytes());
            hasher.update(span.start_scalar.to_be_bytes());
            hasher.update(span.end_scalar.to_be_bytes());
        }
    }
    hasher.update((cited_source_digests.len() as u64).to_be_bytes());
    for (src_id, digest) in cited_source_digests {
        push_lp(&mut hasher, src_id.as_bytes());
        push_lp(&mut hasher, digest.to_hex().as_bytes());
    }
    DigestSha256::from_bytes(hasher.finalize().into())
}

impl EvidenceSnapshot {
    /// Builds a validated, content-addressed `EvidenceSnapshot` from a committed proof manifest.
    ///
    /// # Errors
    /// Fails closed if `manifest` has commit defects, `snapshot_id`/`question_text` is empty,
    /// `pack_epoch == 0`, or `cited_source_digests` does not match all manifest-cited sources.
    pub fn build(
        snapshot_id: impl Into<String>,
        question_text: impl Into<String>,
        pack_epoch: u64,
        manifest: AnswerProofManifest,
    ) -> Result<Self, GuidelineError> {
        let snapshot_id = snapshot_id.into();
        let question_text = question_text.into();
        if snapshot_id.trim().is_empty() {
            return Err(GuidelineError::EmptyField("snapshot_id"));
        }
        if question_text.trim().is_empty() {
            return Err(GuidelineError::EmptyField("question_text"));
        }
        if pack_epoch == 0 || manifest.validity_epoch != pack_epoch {
            return Err(GuidelineError::EmptyField("pack_epoch"));
        }
        let defects = commit_defects(&manifest);
        if !defects.is_empty() {
            return Err(GuidelineError::SnapshotManifestDefects(defects));
        }
        let mut cited_source_digests = BTreeMap::new();
        for claim in &manifest.claims {
            for span in &claim.spans {
                if let Some(prev) =
                    cited_source_digests.insert(span.source_id.clone(), span.source_digest.clone())
                    && prev != span.source_digest
                {
                    return Err(GuidelineError::SnapshotSourceSetMismatch(
                        span.source_id.clone(),
                    ));
                }
            }
        }
        let snapshot_digest = compute_snapshot_digest(
            &snapshot_id,
            &question_text,
            pack_epoch,
            &manifest,
            &cited_source_digests,
        );
        Ok(Self {
            snapshot_id,
            question_text,
            pack_epoch,
            manifest,
            cited_source_digests,
            snapshot_digest,
        })
    }

    /// Validates `snapshot_digest`, manifest commit invariants, and cited-source map consistency.
    ///
    /// # Errors
    /// Fails closed on tampered `snapshot_digest`, uncommitted manifest, or source-set drift.
    pub fn validate(&self) -> Result<(), GuidelineError> {
        if self.snapshot_id.trim().is_empty() || self.question_text.trim().is_empty() {
            return Err(GuidelineError::EmptyField("snapshot_id"));
        }
        if self.pack_epoch == 0 || self.manifest.validity_epoch != self.pack_epoch {
            return Err(GuidelineError::EmptyField("pack_epoch"));
        }
        let defects = commit_defects(&self.manifest);
        if !defects.is_empty() {
            return Err(GuidelineError::SnapshotManifestDefects(defects));
        }
        let mut expected_sources = BTreeMap::new();
        for claim in &self.manifest.claims {
            for span in &claim.spans {
                if let Some(prev) =
                    expected_sources.insert(span.source_id.clone(), span.source_digest.clone())
                    && prev != span.source_digest
                {
                    return Err(GuidelineError::SnapshotSourceSetMismatch(
                        span.source_id.clone(),
                    ));
                }
            }
        }
        if expected_sources != self.cited_source_digests {
            return Err(GuidelineError::SnapshotSourceSetMismatch(
                "cited_source_digests differs from manifest spans".to_owned(),
            ));
        }
        let expected_digest = compute_snapshot_digest(
            &self.snapshot_id,
            &self.question_text,
            self.pack_epoch,
            &self.manifest,
            &self.cited_source_digests,
        );
        if expected_digest != self.snapshot_digest {
            return Err(GuidelineError::SnapshotDigestMismatch);
        }
        Ok(())
    }
}

/// Evaluates whether an `EvidenceSnapshot` can be reproduced in full or must downgrade to
/// `PartialReproduction` because one or more cited source artifacts are missing, revoked,
/// or modified (`TA-06`, `TA-14`).
///
/// `available_sources` maps `source_id -> (utf8_bytes, is_revoked)`.
///
/// # Errors
/// Fails closed if `snapshot.validate()` fails.
pub fn verify_snapshot_reproduction(
    snapshot: &EvidenceSnapshot,
    available_sources: &BTreeMap<String, (&[u8], bool)>,
) -> Result<SnapshotReproductionState, GuidelineError> {
    snapshot.validate()?;
    let mut verified_sources = Vec::new();
    let mut degraded = Vec::new();

    for (source_id, expected_digest) in &snapshot.cited_source_digests {
        let Some((bytes, is_revoked)) = available_sources.get(source_id) else {
            degraded.push(DegradedSnapshotSource {
                source_id: source_id.clone(),
                reason: SnapshotDegradationReason::MissingSourceBytes,
            });
            continue;
        };
        if *is_revoked {
            degraded.push(DegradedSnapshotSource {
                source_id: source_id.clone(),
                reason: SnapshotDegradationReason::SourceRevoked,
            });
            continue;
        }
        if &DigestSha256::of(bytes) != expected_digest {
            degraded.push(DegradedSnapshotSource {
                source_id: source_id.clone(),
                reason: SnapshotDegradationReason::DigestMismatch,
            });
            continue;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            degraded.push(DegradedSnapshotSource {
                source_id: source_id.clone(),
                reason: SnapshotDegradationReason::SpanOutOfBounds,
            });
            continue;
        };
        let scalar_len = text.chars().count() as u64;
        let spans_ok = snapshot
            .manifest
            .claims
            .iter()
            .flat_map(|c| &c.spans)
            .filter(|s| &s.source_id == source_id)
            .all(|s| s.start_scalar < s.end_scalar && s.end_scalar <= scalar_len);
        if !spans_ok {
            degraded.push(DegradedSnapshotSource {
                source_id: source_id.clone(),
                reason: SnapshotDegradationReason::SpanOutOfBounds,
            });
            continue;
        }
        verified_sources.push(source_id.clone());
    }

    if degraded.is_empty() {
        Ok(SnapshotReproductionState::FullReproduction { verified_sources })
    } else {
        Ok(SnapshotReproductionState::PartialReproduction {
            verified_sources,
            missing_or_revoked_sources: degraded,
        })
    }
}

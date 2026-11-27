//! Append-only human screening decisions & reproducible PRISMA 2020 flow counts (`ADM-0019` /
//! `T15`, `TA-16`).
//!
//! Adapted in safe Rust from `TheHalfMoon/MedOrigin` (`src/medscale/litdb/review.py`).

use std::collections::{BTreeMap, BTreeSet};

use safeevidence_contracts::bilingual::is_forbidden_bidi_control;
use safeevidence_contracts::objects::DigestSha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::screening::ScreeningStage;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrismaReviewError {
    #[error("required string field `{0}` must be non-empty")]
    EmptyField(&'static str),
    #[error("string field `{0}` contains forbidden BiDi or control characters")]
    ForbiddenControlCharacters(&'static str),
    #[error("PENDING is the initial state, not an applied human screening decision")]
    CannotApplyPending,
    #[error("review event must change decision state (self-transition `{0:?}` is invalid)")]
    NoOpDecisionTransition(ReviewDecision),
    #[error("git_sha must be 7..=40 lowercase hexadecimal characters")]
    InvalidGitSha,
    #[error("EXCLUDE and DUPLICATE_CONFIRMED decisions require an explicit ExclusionReason")]
    MissingExclusionReason,
    #[error("exclusion_reason is forbidden on {0:?} decisions")]
    UnexpectedExclusionReason(ReviewDecision),
    #[error("DUPLICATE_CONFIRMED requires exclusion_reason = Duplicate")]
    DuplicateReasonMismatch,
    #[error(
        "previous_decision mismatch on replay for `{record_id}`: expected {expected:?}, got {actual:?}"
    )]
    PreviousDecisionMismatch {
        record_id: String,
        expected: ReviewDecision,
        actual: ReviewDecision,
    },
    #[error("malformed JSONL review event: {0}")]
    MalformedJsonl(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Pending,
    Include,
    Exclude,
    Uncertain,
    DuplicateConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    NotRelevant,
    WrongPopulation,
    WrongIntervention,
    WrongOutcome,
    WrongStudyDesign,
    NoPrimaryEvidence,
    Duplicate,
    Other,
}

impl ExclusionReason {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::NotRelevant => "not_relevant",
            Self::WrongPopulation => "wrong_population",
            Self::WrongIntervention => "wrong_intervention",
            Self::WrongOutcome => "wrong_outcome",
            Self::WrongStudyDesign => "wrong_study_design",
            Self::NoPrimaryEvidence => "no_primary_evidence",
            Self::Duplicate => "duplicate",
            Self::Other => "other",
        }
    }
}

#[must_use]
pub const fn stage_for_decision(decision: ReviewDecision) -> ScreeningStage {
    match decision {
        ReviewDecision::Pending | ReviewDecision::Uncertain => ScreeningStage::Deduped,
        ReviewDecision::Include => ScreeningStage::Screened,
        ReviewDecision::Exclude | ReviewDecision::DuplicateConfirmed => ScreeningStage::Excluded,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvent {
    pub record_id: String,
    pub previous_decision: ReviewDecision,
    pub new_decision: ReviewDecision,
    pub reviewer: String,
    pub decided_at: String,
    pub software_version: String,
    pub git_sha: String,
    pub exclusion_reason: Option<ExclusionReason>,
    pub notes: String,
}

impl ReviewEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_id: impl Into<String>,
        previous_decision: ReviewDecision,
        new_decision: ReviewDecision,
        reviewer: impl Into<String>,
        decided_at: impl Into<String>,
        software_version: impl Into<String>,
        git_sha: impl Into<String>,
        exclusion_reason: Option<ExclusionReason>,
        notes: impl Into<String>,
    ) -> Result<Self, PrismaReviewError> {
        let ev = Self {
            record_id: record_id.into(),
            previous_decision,
            new_decision,
            reviewer: reviewer.into(),
            decided_at: decided_at.into(),
            software_version: software_version.into(),
            git_sha: git_sha.into(),
            exclusion_reason,
            notes: notes.into(),
        };
        ev.validate()?;
        Ok(ev)
    }

    pub fn validate(&self) -> Result<(), PrismaReviewError> {
        let has_bad_ctrl = |s: &str| {
            s.chars()
                .any(|c| is_forbidden_bidi_control(c) || (c.is_control() && c != '\n'))
        };
        for (field, val) in [
            ("record_id", self.record_id.as_str()),
            ("reviewer", self.reviewer.as_str()),
            ("decided_at", self.decided_at.as_str()),
            ("software_version", self.software_version.as_str()),
        ] {
            if val.trim().is_empty() {
                return Err(PrismaReviewError::EmptyField(field));
            }
            if has_bad_ctrl(val) {
                return Err(PrismaReviewError::ForbiddenControlCharacters(field));
            }
        }
        if has_bad_ctrl(&self.notes) {
            return Err(PrismaReviewError::ForbiddenControlCharacters("notes"));
        }
        if self.new_decision == ReviewDecision::Pending {
            return Err(PrismaReviewError::CannotApplyPending);
        }
        if self.previous_decision == self.new_decision {
            return Err(PrismaReviewError::NoOpDecisionTransition(self.new_decision));
        }
        let sha_ok = (7..=40).contains(&self.git_sha.len())
            && self
                .git_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'));
        if !sha_ok {
            return Err(PrismaReviewError::InvalidGitSha);
        }
        match (self.new_decision, self.exclusion_reason) {
            (ReviewDecision::Exclude, None) | (ReviewDecision::DuplicateConfirmed, None) => {
                return Err(PrismaReviewError::MissingExclusionReason);
            }
            (ReviewDecision::DuplicateConfirmed, Some(r)) if r != ExclusionReason::Duplicate => {
                return Err(PrismaReviewError::DuplicateReasonMismatch);
            }
            (ReviewDecision::Include | ReviewDecision::Uncertain, Some(_)) => {
                return Err(PrismaReviewError::UnexpectedExclusionReason(
                    self.new_decision,
                ));
            }
            _ => {}
        }
        Ok(())
    }

    #[must_use]
    pub const fn previous_stage(&self) -> ScreeningStage {
        stage_for_decision(self.previous_decision)
    }

    #[must_use]
    pub const fn new_stage(&self) -> ScreeningStage {
        stage_for_decision(self.new_decision)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordReview {
    pub decision: ReviewDecision,
    pub exclusion_reason: Option<ExclusionReason>,
}

/// Serializes validated `events` to canonical LF-terminated JSON Lines and returns `(jsonl, sha256)`.
pub fn render_review_log_jsonl(
    events: &[ReviewEvent],
) -> Result<(String, DigestSha256), PrismaReviewError> {
    let mut out = String::new();
    for ev in events {
        ev.validate()?;
        let line = serde_json::to_string(ev)
            .map_err(|e| PrismaReviewError::MalformedJsonl(e.to_string()))?;
        out.push_str(&line);
        out.push('\n');
    }
    let digest = DigestSha256::of(out.as_bytes());
    Ok((out, digest))
}

/// Replays an append-only JSONL review log, verifying state transitions (`previous_decision`)
/// and structural validity on every event (`TA-16`).
pub fn replay_reviews_jsonl(
    jsonl: &str,
) -> Result<BTreeMap<String, RecordReview>, PrismaReviewError> {
    let mut state: BTreeMap<String, RecordReview> = BTreeMap::new();
    for line in jsonl.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let ev: ReviewEvent = serde_json::from_str(trimmed)
            .map_err(|e| PrismaReviewError::MalformedJsonl(e.to_string()))?;
        ev.validate()?;
        let expected_prev = state
            .get(&ev.record_id)
            .map_or(ReviewDecision::Pending, |r| r.decision);
        if ev.previous_decision != expected_prev {
            return Err(PrismaReviewError::PreviousDecisionMismatch {
                record_id: ev.record_id,
                expected: expected_prev,
                actual: ev.previous_decision,
            });
        }
        state.insert(
            ev.record_id,
            RecordReview {
                decision: ev.new_decision,
                exclusion_reason: ev.exclusion_reason,
            },
        );
    }
    Ok(state)
}

/// Returns unscreened (`Pending`) record IDs first in caller order, followed by `Uncertain` IDs.
#[must_use]
pub fn pending_queue(
    record_ids: &[String],
    reviews: &BTreeMap<String, RecordReview>,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut never = Vec::new();
    let mut uncertain = Vec::new();
    for id in record_ids {
        if !seen.insert(id.as_str()) {
            continue;
        }
        match reviews.get(id) {
            None => never.push(id.clone()),
            Some(r) if r.decision == ReviewDecision::Uncertain => uncertain.push(id.clone()),
            _ => {}
        }
    }
    never.extend(uncertain);
    never
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrismaSummary {
    pub identified: Option<usize>,
    pub deduplicated: usize,
    pub screened: usize,
    pub included: usize,
    pub excluded: usize,
    pub uncertain: usize,
    pub pending: usize,
    pub exclusion_breakdown: BTreeMap<String, usize>,
}

/// Computes deterministic PRISMA 2020 flow diagram counts over deduplicated `record_ids` and
/// `reviews` (`TA-16`).
#[must_use]
pub fn prisma_summary(
    record_ids: &[String],
    reviews: &BTreeMap<String, RecordReview>,
    identified: Option<usize>,
) -> PrismaSummary {
    let mut seen = BTreeSet::new();
    let mut included = 0_usize;
    let mut excluded = 0_usize;
    let mut uncertain = 0_usize;
    let mut pending = 0_usize;
    let mut breakdown: BTreeMap<String, usize> = BTreeMap::new();

    for id in record_ids {
        if !seen.insert(id.as_str()) {
            continue;
        }
        let rev = reviews.get(id);
        let dec = rev.map_or(ReviewDecision::Pending, |r| r.decision);
        match dec {
            ReviewDecision::Include => included += 1,
            ReviewDecision::Exclude | ReviewDecision::DuplicateConfirmed => {
                excluded += 1;
                if let Some(reason) = rev.and_then(|r| r.exclusion_reason) {
                    *breakdown.entry(reason.as_code().to_owned()).or_insert(0) += 1;
                }
            }
            ReviewDecision::Uncertain => uncertain += 1,
            ReviewDecision::Pending => pending += 1,
        }
    }

    let dedup_count = seen.len();
    PrismaSummary {
        identified: identified.map(|m| m.max(dedup_count)),
        deduplicated: dedup_count,
        screened: included + excluded,
        included,
        excluded,
        uncertain,
        pending,
        exclusion_breakdown: breakdown,
    }
}

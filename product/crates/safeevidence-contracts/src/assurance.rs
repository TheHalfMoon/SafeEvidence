//! Decision vocabulary and proof states
//! (`docs/P00_DECISION_ASSURANCE_CONTRACT.md`, `docs/P00_PROOF_ADMISSION_CONTRACT.md`).

use serde::{Deserialize, Serialize};

/// Bounded internal operations; never evidence-answer outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlAction {
    RetrieveEvidence,
    UseTool,
    RequestContext,
}

/// Exactly one per request. `EmergencyNotice` is reserved and disabled in V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalOutcome {
    Answer,
    AnswerWithCaution,
    AskMore,
    Conflict,
    Abstain,
    Escalate,
    Blocked,
    EmergencyNotice,
}

impl TerminalOutcome {
    /// A commit also needs a committed manifest and a material claim; this is
    /// only the necessary outcome condition.
    #[must_use]
    pub const fn may_commit(self) -> bool {
        matches!(self, Self::Answer | Self::AnswerWithCaution)
    }
}

/// The allowed codes; additions require versioned schema review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    SecurityDenied,
    RightsUnresolved,
    SourceUnavailable,
    SourceInvalidOrRetracted,
    EvidenceInsufficient,
    MissingCriticalContext,
    ApplicabilityUnresolved,
    MaterialContradiction,
    ToolFailure,
    TimeBudgetExhausted,
    ClinicianAuthorityRequired,
    PostVerificationFailed,
    ProofRaceInvalidated,
    CurrentnessUnknown,
    UnsupportedLanguage,
    None,
}

/// Proof admission states. Only `Committed` may reach an assured surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofState {
    DraftPrivate,
    CandidateFrozen,
    Verifying,
    VerifiedUncommitted,
    Committed,
    Rejected,
    CurrentlyInvalidated,
    CurrentnessUnknown,
}

impl ProofState {
    /// The contract's state machine. Post-commit states change current
    /// validity only; historical bytes and the manifest stay unchanged. A
    /// proof cannot regain assured status: requalifying means a new proof.
    #[must_use]
    pub const fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::DraftPrivate, Self::CandidateFrozen)
                | (Self::CandidateFrozen, Self::Verifying)
                | (Self::Verifying, Self::VerifiedUncommitted | Self::Rejected)
                | (Self::VerifiedUncommitted, Self::Committed | Self::Rejected)
                | (
                    Self::Committed,
                    Self::CurrentlyInvalidated | Self::CurrentnessUnknown
                )
                | (Self::CurrentnessUnknown, Self::CurrentlyInvalidated)
        )
    }

    /// Whether an answer in this state may show as currently assured.
    #[must_use]
    pub const fn is_currently_assured(self) -> bool {
        matches!(self, Self::Committed)
    }
}

/// Fail-closed gate errors enforcing `docs/P00_DECISION_ASSURANCE_CONTRACT.md` on donor object types:
/// unpromoted proposals and heuristic confidence percentages must never enter an assured V1 surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuredSurfaceGateError {
    /// Non-authoritative `Proposal` records are forbidden on assured surfaces.
    ProposalCannotReachAssuredSurface,
    /// Internal candidate confidence score is NaN, infinite, or outside `[0.0, 1.0]`.
    InvalidProposalConfidence,
    /// Required identifier or authority actor field is empty.
    MissingRequiredAuthorityField,
    /// Heuristic confidence percentage/score is forbidden on assured V1 surfaces and assertions.
    ForbiddenConfidenceField,
}

/// Recursively inspects a JSON value and returns `true` if any object key carries a heuristic
/// confidence field (`confidence`, `confidence_pct`/`confidencePct`, `confidence_percent`/
/// `confidencePercent`, `confidence_score`/`confidenceScore`, `clinical_confidence`/
/// `clinicalConfidence`, case-insensitively and separator-agnostically).
#[must_use]
pub fn json_contains_confidence_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, child)| {
            let normalized: String = key
                .trim()
                .chars()
                .filter(|c| *c != '_' && *c != '-')
                .map(|c| c.to_ascii_lowercase())
                .collect();
            matches!(
                normalized.as_str(),
                "confidence"
                    | "confidencepct"
                    | "confidencepercent"
                    | "confidencescore"
                    | "clinicalconfidence"
            ) || json_contains_confidence_key(child)
        }),
        serde_json::Value::Array(items) => items.iter().any(json_contains_confidence_key),
        _ => false,
    }
}

//! PRISMA 2020 screening stage state machine (`ADM-0019` / `T15`, `TA-16`).
//!
//! Adapted in safe Rust from `TheHalfMoon/MedOrigin` (`src/medscale/litdb/screening.py`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScreeningStageError {
    #[error("EXCLUDED stage requires a non-empty reason")]
    MissingExclusionReason,
    #[error("exclusion reason is only permitted on EXCLUDED stage, not {0:?}")]
    UnexpectedReasonOnNonExcluded(ScreeningStage),
    #[error("illegal PRISMA screening transition: {from:?} -> {to:?}")]
    IllegalTransition {
        from: ScreeningStage,
        to: ScreeningStage,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreeningStage {
    Identified,
    Deduped,
    Screened,
    Eligibility,
    Included,
    Excluded,
}

impl ScreeningStage {
    #[must_use]
    pub const fn can_transition_to(self, to: Self) -> bool {
        match self {
            Self::Identified => matches!(to, Self::Deduped | Self::Excluded),
            Self::Deduped => matches!(to, Self::Screened | Self::Excluded),
            Self::Screened => matches!(to, Self::Eligibility | Self::Excluded),
            Self::Eligibility => matches!(to, Self::Included | Self::Excluded),
            Self::Included => matches!(to, Self::Excluded),
            Self::Excluded => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreeningState {
    pub stage: ScreeningStage,
    pub reason: Option<String>,
}

impl ScreeningState {
    pub fn new(stage: ScreeningStage, reason: Option<String>) -> Result<Self, ScreeningStageError> {
        match (stage, &reason) {
            (ScreeningStage::Excluded, Some(r)) if !r.trim().is_empty() => {
                Ok(Self { stage, reason })
            }
            (ScreeningStage::Excluded, _) => Err(ScreeningStageError::MissingExclusionReason),
            (_, Some(_)) => Err(ScreeningStageError::UnexpectedReasonOnNonExcluded(stage)),
            (_, None) => Ok(Self {
                stage,
                reason: None,
            }),
        }
    }
}

pub fn advance_stage(
    current: &ScreeningState,
    to: ScreeningStage,
    reason: Option<String>,
) -> Result<ScreeningState, ScreeningStageError> {
    if !current.stage.can_transition_to(to) {
        return Err(ScreeningStageError::IllegalTransition {
            from: current.stage,
            to,
        });
    }
    ScreeningState::new(to, reason)
}

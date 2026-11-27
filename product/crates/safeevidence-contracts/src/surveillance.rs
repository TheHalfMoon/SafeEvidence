//! Living-evidence watch query and cause-named surveillance alert contracts (`WP-17`, `TA-19`,
//! and `TA-30` outbound opt-in / patient-narrative exclusion rules).

use serde::{Deserialize, Serialize};

use crate::assurance::ProofState;
use crate::objects::{AmendmentRecord, MedicalTime};

/// Per-query surveillance subscription stored only in the private encrypted vault (`D-16`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedWatchQuery {
    pub watch_id: String,
    pub canonical_pico_query: String,
    pub condition: String,
    pub intervention: String,
    pub population: Option<String>,
    pub linked_proof_id: Option<String>,
    pub cited_source_ids: Vec<String>,
    /// Defaults to `false`: saved queries are never eligible for outbound update requests without
    /// an explicit per-query opt-in (`TA-30`).
    #[serde(default)]
    pub outbound_opt_in: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurveillanceUpdateEvent {
    RetractSource {
        source_id: String,
        rationale: String,
        authorized_by: String,
        recorded_time: MedicalTime,
    },
    AmendSource {
        prior_source_id: String,
        superseding_source_id: String,
        superseding_bytes: Vec<u8>,
        amendment: AmendmentRecord,
    },
    RotateRightsGrant {
        new_grant_version: String,
        reason: String,
    },
    NewTrialPublished {
        doc_id: String,
        study_id: String,
        condition: String,
        intervention: String,
        contradicts_existing: bool,
        summary: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertCauseCode {
    SourceRetracted,
    SourceAmended,
    RightsGrantChanged,
    NewContradictingTrial,
    NewSupportingTrial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveillanceAlert {
    pub alert_id: String,
    pub watch_id: String,
    pub epoch: u64,
    pub cause_code: AlertCauseCode,
    pub subject_id: String,
    pub explanation: String,
    pub affected_proof_id: Option<String>,
    pub affected_proof_state: Option<ProofState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchRegistry {
    pub watches: Vec<SavedWatchQuery>,
    pub alerts: Vec<SurveillanceAlert>,
}

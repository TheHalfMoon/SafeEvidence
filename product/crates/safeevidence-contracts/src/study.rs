//! Study/report/result identities and the double-count guard
//! (`docs/P00_STUDY_INDEPENDENCE_CONTRACT.md`). A report is never a study.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A value that may be explicitly unknown; never a coerced null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Known<T> {
    Known(T),
    Unknown { reason: String },
}

/// Scoped, versioned identity shared by every typed ID in this module.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedId {
    pub scope: String,
    pub id: String,
    pub version: u32,
}

impl ScopedId {
    /// The same entity at any version. Independence never depends on a version.
    #[must_use]
    pub fn same_entity(&self, other: &Self) -> bool {
        self.scope == other.scope && self.id == other.id
    }
}

macro_rules! typed_id {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub ScopedId);
    )+};
}

typed_id!(
    StudyId,
    ReportId,
    ReportVersionId,
    StudyArmId,
    AnalysisId,
    OutcomeId,
    ResultId,
    ArmObservationId,
    ComparisonId,
    EffectEstimateId,
    ReviewId,
    ParticipantOverlapGroupId,
    PooledStudySetId,
    CovarianceRef,
);

/// Machine-suggested links stay `Proposed` until corroborated or confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinkStatus {
    Proposed,
    Corroborated,
    HumanConfirmed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyReportLink {
    pub study: StudyId,
    pub report: ReportVersionId,
    pub status: LinkStatus,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportVersionKind {
    Protocol,
    Registry,
    Abstract,
    Preprint,
    Published,
    FollowUp,
    Correction,
    ExpressionOfConcern,
    Retraction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyArm {
    pub id: StudyArmId,
    pub study: StudyId,
    pub intervention: String,
    pub randomized_n: Known<u64>,
    pub eligible_n: Known<u64>,
    pub analyzed_n: Known<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalysisPopulation {
    Itt,
    Mitt,
    PerProtocol,
    Subgroup(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisUnit {
    Study(StudyId),
    PooledStudySet(PooledStudySetId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Analysis {
    pub id: AnalysisId,
    pub unit: AnalysisUnit,
    pub population: AnalysisPopulation,
    pub model: Known<String>,
    pub adjusted_covariates: Known<Vec<String>>,
    pub timepoint: String,
    pub estimand: Known<String>,
}

/// Registered and reported outcomes stay separate so discrepancies survive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeDefinition {
    pub id: OutcomeId,
    pub definition: String,
    pub unit: Known<String>,
    pub timepoint: String,
    pub method: Known<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeReconciliation {
    pub registered: Known<OutcomeDefinition>,
    pub reported: OutcomeDefinition,
}

impl OutcomeReconciliation {
    /// True when the report differs from its registration, or none is known.
    #[must_use]
    pub fn has_discrepancy(&self) -> bool {
        match &self.registered {
            Known::Known(registered) => {
                registered.definition != self.reported.definition
                    || registered.timepoint != self.reported.timepoint
                    || registered.unit != self.reported.unit
                    || registered.method != self.reported.method
            }
            Known::Unknown { .. } => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OverlapState {
    Confirmed,
    Possible,
    Unknown,
}

/// Declared participant overlap. All results named under one `group`, by any
/// of its links, are treated as sharing participants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlapLink {
    pub group: ParticipantOverlapGroupId,
    pub first: ResultId,
    pub second: ResultId,
    pub state: OverlapState,
}

/// One candidate contribution to a pooled estimate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynthesisInput {
    pub result: ResultId,
    pub study: StudyId,
    /// The participants this contribution draws on.
    pub participants: Known<ParticipantOverlapGroupId>,
    pub denominator: Known<u64>,
    /// Supplied covariance structure covering any shared participants.
    pub covariance: Known<CovarianceRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PoolingRefusal {
    PoolingRefusedUnitOfAnalysis { results: Vec<ResultId> },
    PoolingRefusedMissingDenominator { results: Vec<ResultId> },
}

fn shares_declared_group(
    first: &ResultId,
    second: &ResultId,
    members: &BTreeMap<String, Vec<&ResultId>>,
) -> bool {
    members.values().any(|group| {
        group.iter().any(|member| member.0.same_entity(&first.0))
            && group.iter().any(|member| member.0.same_entity(&second.0))
    })
}

/// Pooled inputs need one independent contribution per participant group, or
/// one shared covariance reference for those that share participants. Otherwise
/// refuse; narrative synthesis remains available to the caller. This compares
/// covariance references only: whether a reference truly covers the structure
/// belongs to the statistical method that consumes it.
///
/// # Errors
/// Returns the refusal naming every affected result. Empty input is refused
/// with an empty list: nothing can be pooled.
pub fn decide_pooling(
    inputs: &[SynthesisInput],
    overlaps: &[OverlapLink],
) -> Result<Vec<ResultId>, PoolingRefusal> {
    if inputs.is_empty() {
        return Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis { results: vec![] });
    }
    let missing: Vec<ResultId> = inputs
        .iter()
        .filter(|input| !matches!(input.denominator, Known::Known(total) if total > 0))
        .map(|input| input.result.clone())
        .collect();
    if !missing.is_empty() {
        return Err(PoolingRefusal::PoolingRefusedMissingDenominator { results: missing });
    }

    let mut members: BTreeMap<String, Vec<&ResultId>> = BTreeMap::new();
    for link in overlaps {
        let key = format!("{}\0{}", link.group.0.scope, link.group.0.id);
        let group = members.entry(key).or_default();
        group.push(&link.first);
        group.push(&link.second);
    }

    let mut refused = BTreeSet::new();
    for (position, first) in inputs.iter().enumerate() {
        if matches!(first.participants, Known::Unknown { .. }) {
            refused.insert(first.result.clone());
        }
        for second in &inputs[position + 1..] {
            let same_result = first.result.0.same_entity(&second.result.0);
            let shared_study = first.study.0.same_entity(&second.study.0);
            let shared_group = matches!(
                (&first.participants, &second.participants),
                (Known::Known(a), Known::Known(b)) if a.0.same_entity(&b.0)
            );
            let declared = shares_declared_group(&first.result, &second.result, &members);
            let covered = matches!(
                (&first.covariance, &second.covariance),
                (Known::Known(a), Known::Known(b)) if a.0.same_entity(&b.0)
            );
            if same_result || ((shared_study || shared_group || declared) && !covered) {
                refused.insert(first.result.clone());
                refused.insert(second.result.clone());
            }
        }
    }
    if refused.is_empty() {
        Ok(inputs.iter().map(|input| input.result.clone()).collect())
    } else {
        Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis {
            results: refused.into_iter().collect(),
        })
    }
}

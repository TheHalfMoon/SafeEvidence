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

/// Current publication standing of a report version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationState {
    Current,
    Corrected,
    ExpressionOfConcern,
    Retracted,
    Withdrawn,
    Superseded,
    Unknown,
}

impl PublicationState {
    /// Only a known-current version may support a claim. A corrected source must be
    /// re-read at its corrected version first, as the proof contract requires.
    #[must_use]
    pub const fn citable(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// A monotonic local validity watermark. It says nothing beyond its last update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidityEpoch(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportVersionLink {
    pub report: ReportId,
    pub version: ReportVersionId,
    pub kind: ReportVersionKind,
    pub links_to: Option<ReportVersionId>,
    pub publication_state: PublicationState,
    pub validity_epoch: ValidityEpoch,
}

impl ReportVersionLink {
    /// A retraction or correction notice cannot leave its target looking current.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        match self.kind {
            ReportVersionKind::Retraction => {
                matches!(self.publication_state, PublicationState::Retracted)
            }
            ReportVersionKind::ExpressionOfConcern => {
                matches!(
                    self.publication_state,
                    PublicationState::ExpressionOfConcern
                )
            }
            ReportVersionKind::Correction => {
                !matches!(self.publication_state, PublicationState::Current)
            }
            _ => true,
        }
    }
}

/// Which study and result a review includes, and the decision behind it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewIncludedStudyLink {
    pub review: ReviewId,
    pub study: StudyId,
    pub result: Known<ResultId>,
    pub status: LinkStatus,
    pub decision: String,
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

/// Declared participant overlap. Links join their two results, their group,
/// and any input drawing on that group into one overlapping set. Overlap chains
/// across groups are refused too; relaxing that needs a statistician's ruling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlapLink {
    pub group: ParticipantOverlapGroupId,
    pub first: ResultId,
    pub second: ResultId,
    pub state: OverlapState,
}

/// What a contribution is. Reviews and pooled IPD syntheses are never new
/// independent studies, with or without a declared overlap link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContributionKind {
    PrimaryStudy,
    SystematicReview,
    PooledIpd,
}

/// One candidate contribution to a pooled estimate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynthesisInput {
    pub result: ResultId,
    pub study: StudyId,
    pub kind: ContributionKind,
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

/// Accepted inputs. When `requires_covariance_method` is true they share
/// participants, so only a method using the named covariance may pool them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolingDecision {
    pub accepted: Vec<ResultId>,
    pub requires_covariance_method: bool,
}

fn is_named_reference(reference: &CovarianceRef) -> bool {
    !reference.0.scope.trim().is_empty() && !reference.0.id.trim().is_empty()
}

/// Node in the overlap graph; a typed tuple so strings cannot collide.
type OverlapNode = (bool, String, String);

fn result_node(result: &ResultId) -> OverlapNode {
    (false, result.0.scope.clone(), result.0.id.clone())
}

fn group_node(group: &ParticipantOverlapGroupId) -> OverlapNode {
    (true, group.0.scope.clone(), group.0.id.clone())
}

fn find(parents: &mut BTreeMap<OverlapNode, OverlapNode>, node: &OverlapNode) -> OverlapNode {
    let mut current = node.clone();
    while let Some(parent) = parents.get(&current) {
        if *parent == current {
            break;
        }
        current = parent.clone();
    }
    parents.insert(node.clone(), current.clone());
    current
}

fn join(parents: &mut BTreeMap<OverlapNode, OverlapNode>, a: &OverlapNode, b: &OverlapNode) {
    let (root_a, root_b) = (find(parents, a), find(parents, b));
    parents.insert(root_a, root_b);
}

fn overlap_sets(
    inputs: &[SynthesisInput],
    overlaps: &[OverlapLink],
) -> BTreeMap<OverlapNode, OverlapNode> {
    let mut parents = BTreeMap::new();
    for link in overlaps {
        let group = group_node(&link.group);
        join(&mut parents, &group, &result_node(&link.first));
        join(&mut parents, &group, &result_node(&link.second));
    }
    for input in inputs {
        if let Known::Known(group) = &input.participants {
            join(
                &mut parents,
                &group_node(group),
                &result_node(&input.result),
            );
        }
    }
    parents
}

/// Pooled inputs need one independent contribution per participant group, or
/// one shared covariance reference at one exact version for those that share
/// participants. Otherwise refuse; narrative synthesis remains available to the
/// caller. This compares references only: whether one truly covers the structure
/// belongs to the statistical method that consumes it.
///
/// # Errors
/// Returns the refusal naming every affected result. Empty input is refused
/// with an empty list: nothing can be pooled.
pub fn decide_pooling(
    inputs: &[SynthesisInput],
    overlaps: &[OverlapLink],
) -> Result<PoolingDecision, PoolingRefusal> {
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

    let mut parents = overlap_sets(inputs, overlaps);
    let mut refused = BTreeSet::new();
    let mut requires_covariance_method = false;
    for (position, first) in inputs.iter().enumerate() {
        let secondary = first.kind != ContributionKind::PrimaryStudy;
        if matches!(first.participants, Known::Unknown { .. }) || (secondary && inputs.len() > 1) {
            refused.insert(first.result.clone());
        }
        for second in &inputs[position + 1..] {
            let same_result = first.result.0.same_entity(&second.result.0);
            let shared_study = first.study.0.same_entity(&second.study.0);
            let (node_a, node_b) = (result_node(&first.result), result_node(&second.result));
            let overlapping = find(&mut parents, &node_a) == find(&mut parents, &node_b);
            let covered = matches!(
                (&first.covariance, &second.covariance),
                (Known::Known(a), Known::Known(b)) if a == b && is_named_reference(a)
            );
            let dependent = shared_study || overlapping;
            if same_result || (dependent && !covered) {
                refused.insert(first.result.clone());
                refused.insert(second.result.clone());
            }
            requires_covariance_method |= dependent;
        }
    }
    if refused.is_empty() {
        Ok(PoolingDecision {
            accepted: inputs.iter().map(|input| input.result.clone()).collect(),
            requires_covariance_method,
        })
    } else {
        Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis {
            results: refused.into_iter().collect(),
        })
    }
}

/// The recorded decision about one synthesis: what was accepted or refused, on what
/// independence evidence, for which model and source version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynthesisInputDecision {
    pub outcome: Result<PoolingDecision, PoolingRefusal>,
    pub independence_evidence: Vec<String>,
    pub model: Known<String>,
    pub source_version: String,
}

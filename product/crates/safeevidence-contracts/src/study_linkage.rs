//! Deterministic Study/Report/Result/Overlap linkage (`WP-05`, `TA-07`,
//! `docs/P00_STUDY_INDEPENDENCE_CONTRACT.md`, and `T28c` `REFERENCE` registry/review linkage).
//!
//! Copy-first boundary: this module implements SafeEvidence-owned canonical study/report/result
//! independence, registry/PMID/parent-version/review containment linkage (`T28c` algorithm
//! reference), outcome-switch reconciliation, and double-count prevention (`SOURCE_TRANSPLANT_MATRIX_V1`
//! section 5). Generic fuzzy paper title/author deduplication (`T15` `MedOrigin` `litdb`
//! `dedupe.py`/`uncertain.py`) is NOT reimplemented here and remains fenced on `EXT-01`; matching
//! titles never merge studies (`P00_STUDY_INDEPENDENCE_CONTRACT`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::study::{
    AnalysisPopulation, ContributionKind, CovarianceRef, Known, LinkStatus, OutcomeDefinition,
    OutcomeReconciliation, OverlapLink, OverlapState, ParticipantOverlapGroupId, PoolingDecision,
    PoolingRefusal, PublicationState, ReportId, ReportVersionId, ReportVersionKind,
    ReportVersionLink, ResultId, ReviewId, ReviewIncludedStudyLink, ScopedId, StudyArmId, StudyId,
    StudyReportLink, SynthesisInput, ValidityEpoch, decide_pooling,
};

/// Normalized metadata for one immutable report version entering study/result linkage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportMetadataRecord {
    pub report_id: ReportId,
    pub version_id: ReportVersionId,
    pub result_id: ResultId,
    pub kind: ReportVersionKind,
    pub publication_state: PublicationState,
    pub validity_epoch: ValidityEpoch,
    /// Never used for study identity: distinct trials with identical titles must stay separate.
    pub title: String,
    /// Human-adjudicated canonical study identity when already established.
    pub human_confirmed_study: Option<StudyId>,
    /// Trial registry identifiers (for example `NCT00000001`, `ISRCTN00000001`).
    pub trial_registrations: Vec<String>,
    /// Stable bibliographic identifier (`PMID`), distinct from `StudyId`.
    pub pmid: Option<String>,
    /// Digital object identifier (`DOI`), distinct from `StudyId`.
    pub doi: Option<String>,
    /// Explicit artifact-version parent (for example follow-up, correction, or preprint->published).
    pub parent_report_version: Option<ReportVersionId>,
    pub contribution_kind: ContributionKind,
    /// For `SystematicReview` or `PooledIpd`: included trial registrations (`T28c` linkage).
    pub included_registrations: Vec<String>,
    /// For `SystematicReview` or `PooledIpd`: included primary report `PMID`s (`T28c` linkage).
    pub included_pmids: Vec<String>,
    pub arms: Vec<StudyArmId>,
    pub population: Known<AnalysisPopulation>,
    pub timepoint: Known<String>,
    pub registered_outcome: Known<OutcomeDefinition>,
    pub reported_outcome: OutcomeDefinition,
    pub denominator: Known<u64>,
    pub participants: Known<ParticipantOverlapGroupId>,
    pub covariance: Known<CovarianceRef>,
}

/// Validation failure when input report metadata violates P00 consistency rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkageError {
    DuplicateReportVersion(ReportVersionId),
    DuplicateResultId(ResultId),
    InconsistentVersionStanding(ReportVersionId),
    ConflictingHumanStudyAssignment(Box<(ReportVersionId, StudyId, StudyId)>),
}

/// Complete deterministic resolution of studies, report versions, review inclusions, overlaps,
/// and outcome discrepancies over a batch of report metadata records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkageResolution {
    pub study_links: Vec<StudyReportLink>,
    pub version_links: Vec<ReportVersionLink>,
    pub review_links: Vec<ReviewIncludedStudyLink>,
    pub overlap_links: Vec<OverlapLink>,
    pub synthesis_inputs: Vec<SynthesisInput>,
    pub outcome_discrepancies: Vec<(ReportVersionId, OutcomeReconciliation)>,
}

fn normalize_token(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_uppercase();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn version_key(id: &ReportVersionId) -> (String, String, u32) {
    (id.0.scope.clone(), id.0.id.clone(), id.0.version)
}

fn find_root(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}

fn union_roots(parents: &mut [usize], left: usize, right: usize) {
    let root_left = find_root(parents, left);
    let root_right = find_root(parents, right);
    if root_left != root_right {
        let (keep, merge) = if root_left < root_right {
            (root_left, root_right)
        } else {
            (root_right, root_left)
        };
        parents[merge] = keep;
    }
}

/// Deterministically resolves `StudyId` clusters, `StudyReportLink` statuses (`Proposed`,
/// `Corroborated`, `HumanConfirmed`), `ReviewIncludedStudyLink` (`T28c`), `OverlapLink` sets,
/// and `OutcomeReconciliation` discrepancies without ever merging on title similarity.
///
/// # Errors
/// Fails closed on duplicate `ReportVersionId` / `ResultId`, inconsistent retraction/correction
/// standing (`ReportVersionLink::is_consistent`), or conflicting `HumanConfirmed` `StudyId`s
/// within one registry/version-linked cluster.
pub fn resolve_study_linkage(
    records: &[ReportMetadataRecord],
) -> Result<LinkageResolution, LinkageError> {
    let mut seen_versions = BTreeSet::new();
    let mut seen_results = BTreeSet::new();
    let mut version_to_index = BTreeMap::new();
    let mut pmid_to_indices: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut reg_to_primary_indices: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut doi_to_primary_indices: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for (idx, record) in records.iter().enumerate() {
        if !seen_versions.insert(version_key(&record.version_id)) {
            return Err(LinkageError::DuplicateReportVersion(
                record.version_id.clone(),
            ));
        }
        let rkey = (
            record.result_id.0.scope.clone(),
            record.result_id.0.id.clone(),
            record.result_id.0.version,
        );
        if !seen_results.insert(rkey) {
            return Err(LinkageError::DuplicateResultId(record.result_id.clone()));
        }
        let vlink = ReportVersionLink {
            report: record.report_id.clone(),
            version: record.version_id.clone(),
            kind: record.kind,
            links_to: record.parent_report_version.clone(),
            publication_state: record.publication_state,
            validity_epoch: record.validity_epoch,
        };
        if !vlink.is_consistent() {
            return Err(LinkageError::InconsistentVersionStanding(
                record.version_id.clone(),
            ));
        }
        version_to_index.insert(version_key(&record.version_id), idx);
        if let Some(pmid) = record.pmid.as_deref().and_then(normalize_token) {
            pmid_to_indices.entry(pmid).or_default().push(idx);
        }
        if record.contribution_kind == ContributionKind::PrimaryStudy {
            for reg in &record.trial_registrations {
                if let Some(norm) = normalize_token(reg) {
                    reg_to_primary_indices.entry(norm).or_default().push(idx);
                }
            }
            if let Some(doi) = record.doi.as_deref().and_then(normalize_token) {
                doi_to_primary_indices.entry(doi).or_default().push(idx);
            }
        }
    }

    let mut parents: Vec<usize> = (0..records.len()).collect();

    // Join primary study artifacts sharing an exact trial registration, exact DOI, explicit
    // parent_report_version chain, shared StudyArmId, or identical human_confirmed_study.
    // Matching titles are deliberately ignored.
    for indices in reg_to_primary_indices.values() {
        for pair in indices.windows(2) {
            union_roots(&mut parents, pair[0], pair[1]);
        }
    }
    for indices in doi_to_primary_indices.values() {
        for pair in indices.windows(2) {
            union_roots(&mut parents, pair[0], pair[1]);
        }
    }
    for (idx, record) in records.iter().enumerate() {
        if let Some(parent_ver) = &record.parent_report_version
            && let Some(&parent_idx) = version_to_index.get(&version_key(parent_ver))
            && record.contribution_kind == records[parent_idx].contribution_kind
        {
            union_roots(&mut parents, idx, parent_idx);
        }
    }
    for left in 0..records.len() {
        for right in (left + 1)..records.len() {
            if records[left].contribution_kind == ContributionKind::PrimaryStudy
                && records[right].contribution_kind == ContributionKind::PrimaryStudy
            {
                let same_report = records[left]
                    .report_id
                    .0
                    .same_entity(&records[right].report_id.0);
                let same_pmid = matches!(
                    (
                        records[left].pmid.as_deref().and_then(normalize_token),
                        records[right].pmid.as_deref().and_then(normalize_token),
                    ),
                    (Some(a), Some(b)) if a == b
                );
                let shared_arm = records[left]
                    .arms
                    .iter()
                    .any(|a| records[right].arms.iter().any(|b| a.0.same_entity(&b.0)));
                let same_human = matches!(
                    (&records[left].human_confirmed_study, &records[right].human_confirmed_study),
                    (Some(a), Some(b)) if a.0.same_entity(&b.0)
                );
                if same_report || same_pmid || shared_arm || same_human {
                    union_roots(&mut parents, left, right);
                }
            }
        }
    }

    // Group indices by resolved cluster root and verify no two human-confirmed StudyIds disagree.
    let mut clusters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for idx in 0..records.len() {
        let root = find_root(&mut parents, idx);
        clusters.entry(root).or_default().push(idx);
    }

    let mut cluster_study_id: BTreeMap<usize, StudyId> = BTreeMap::new();
    for (&root, members) in &clusters {
        let mut confirmed: Option<StudyId> = None;
        for &idx in members {
            if let Some(human_id) = &records[idx].human_confirmed_study {
                if let Some(existing) = &confirmed {
                    if !existing.0.same_entity(&human_id.0) {
                        return Err(LinkageError::ConflictingHumanStudyAssignment(Box::new((
                            records[idx].version_id.clone(),
                            existing.clone(),
                            human_id.clone(),
                        ))));
                    }
                } else {
                    confirmed = Some(human_id.clone());
                }
            }
        }
        let study_id = if let Some(human_id) = confirmed {
            human_id
        } else {
            let anchor = &records[members[0]];
            let reg_anchor = members
                .iter()
                .flat_map(|&idx| records[idx].trial_registrations.iter())
                .filter_map(|r| normalize_token(r))
                .min();
            let id_str = match (anchor.contribution_kind, reg_anchor) {
                (ContributionKind::PrimaryStudy, Some(reg)) => {
                    format!("study-reg-{}", reg.to_ascii_lowercase())
                }
                (ContributionKind::PrimaryStudy, None) => {
                    format!("study-auto-{}", anchor.report_id.0.id)
                }
                (ContributionKind::SystematicReview, _) => {
                    format!("review-unit-{}", anchor.report_id.0.id)
                }
                (ContributionKind::PooledIpd, _) => {
                    format!("pooled-ipd-unit-{}", anchor.report_id.0.id)
                }
            };
            StudyId(ScopedId {
                scope: anchor.report_id.0.scope.clone(),
                id: id_str,
                version: 1,
            })
        };
        cluster_study_id.insert(root, study_id);
    }

    // Build StudyReportLink, ReportVersionLink, and OutcomeReconciliation discrepancies.
    let mut study_links = Vec::with_capacity(records.len());
    let mut version_links = Vec::with_capacity(records.len());
    let mut outcome_discrepancies = Vec::new();

    for (idx, record) in records.iter().enumerate() {
        let root = find_root(&mut parents, idx);
        let study = cluster_study_id[&root].clone();
        let members = &clusters[&root];

        let mut signals = Vec::new();
        if record.human_confirmed_study.is_some() {
            signals.push("human_confirmed_study");
        }
        if record
            .trial_registrations
            .iter()
            .any(|r| normalize_token(r).is_some())
        {
            signals.push("trial_registration");
        }
        if record
            .parent_report_version
            .as_ref()
            .is_some_and(|pv| version_to_index.contains_key(&version_key(pv)))
        {
            signals.push("parent_report_version");
        }
        if members.len() > 1
            && record.arms.iter().any(|arm| {
                members.iter().any(|&other| {
                    other != idx && records[other].arms.iter().any(|b| arm.0.same_entity(&b.0))
                })
            })
        {
            signals.push("shared_study_arm");
        }

        let status = if record.human_confirmed_study.is_some() {
            LinkStatus::HumanConfirmed
        } else if signals.len() >= 2 {
            LinkStatus::Corroborated
        } else {
            LinkStatus::Proposed
        };
        let evidence = if signals.is_empty() {
            "isolated_report_proposed_study".to_owned()
        } else {
            signals.join("+")
        };

        study_links.push(StudyReportLink {
            study,
            report: record.version_id.clone(),
            status,
            evidence,
        });

        version_links.push(ReportVersionLink {
            report: record.report_id.clone(),
            version: record.version_id.clone(),
            kind: record.kind,
            links_to: record.parent_report_version.clone(),
            publication_state: record.publication_state,
            validity_epoch: record.validity_epoch,
        });

        let reconciliation = OutcomeReconciliation {
            registered: record.registered_outcome.clone(),
            reported: record.reported_outcome.clone(),
        };
        if reconciliation.has_discrepancy() {
            outcome_discrepancies.push((record.version_id.clone(), reconciliation));
        }
    }

    // Resolve T28c review / pooled-IPD containment links (`ReviewIncludedStudyLink`) and build
    // `OverlapLink` edges so neither reviews, pooled IPDs, shared-arm reports, nor multi-report
    // clusters can ever be double-counted.
    let mut review_links = Vec::new();
    let mut overlap_links = Vec::new();
    let mut synthesis_inputs = Vec::with_capacity(records.len());

    // Emit intra-cluster overlap links across multiple results of the same primary study.
    for (&root, members) in &clusters {
        if members.len() > 1 {
            let study = &cluster_study_id[&root];
            let group = ParticipantOverlapGroupId(ScopedId {
                scope: study.0.scope.clone(),
                id: format!("overlap-{}", study.0.id),
                version: 1,
            });
            for pair in members.windows(2) {
                overlap_links.push(OverlapLink {
                    group: group.clone(),
                    first: records[pair[0]].result_id.clone(),
                    second: records[pair[1]].result_id.clone(),
                    state: OverlapState::Confirmed,
                });
            }
        }
    }

    for (idx, record) in records.iter().enumerate() {
        let root = find_root(&mut parents, idx);
        let study = cluster_study_id[&root].clone();
        let mut contained_studies: BTreeSet<StudyId> = BTreeSet::new();
        let mut matched_component_indices: BTreeSet<usize> = BTreeSet::new();

        if record.contribution_kind != ContributionKind::PrimaryStudy {
            let mut matched_by_reg: BTreeSet<StudyId> = BTreeSet::new();
            let mut matched_by_pmid: BTreeSet<StudyId> = BTreeSet::new();
            for reg in &record.included_registrations {
                if let Some(norm) = normalize_token(reg)
                    && let Some(targets) = reg_to_primary_indices.get(&norm)
                {
                    for &target_idx in targets {
                        let target_root = find_root(&mut parents, target_idx);
                        let sid = cluster_study_id[&target_root].clone();
                        contained_studies.insert(sid.clone());
                        matched_by_reg.insert(sid);
                        matched_component_indices.insert(target_idx);
                    }
                }
            }
            for pmid in &record.included_pmids {
                if let Some(norm) = normalize_token(pmid)
                    && let Some(targets) = pmid_to_indices.get(&norm)
                {
                    for &target_idx in targets {
                        if records[target_idx].contribution_kind == ContributionKind::PrimaryStudy {
                            let target_root = find_root(&mut parents, target_idx);
                            let sid = cluster_study_id[&target_root].clone();
                            contained_studies.insert(sid.clone());
                            matched_by_pmid.insert(sid);
                            matched_component_indices.insert(target_idx);
                        }
                    }
                }
            }

            let review_id = ReviewId(ScopedId {
                scope: record.report_id.0.scope.clone(),
                id: record.report_id.0.id.clone(),
                version: record.version_id.0.version,
            });
            for included_study in &contained_studies {
                let representative_result = matched_component_indices
                    .iter()
                    .copied()
                    .find(|&comp_idx| {
                        let comp_root = find_root(&mut parents, comp_idx);
                        cluster_study_id[&comp_root]
                            .0
                            .same_entity(&included_study.0)
                    })
                    .map(|comp_idx| Known::Known(records[comp_idx].result_id.clone()))
                    .unwrap_or_else(|| Known::Unknown {
                        reason: "component result not indexed".to_owned(),
                    });
                let status = if matched_by_reg.contains(included_study)
                    && matched_by_pmid.contains(included_study)
                {
                    LinkStatus::Corroborated
                } else {
                    LinkStatus::Proposed
                };
                review_links.push(ReviewIncludedStudyLink {
                    review: review_id.clone(),
                    study: included_study.clone(),
                    result: representative_result,
                    status,
                    decision: "included_in_secondary_synthesis".to_owned(),
                });
            }
        }

        let effective_participants = match &record.participants {
            Known::Known(group) => Known::Known(group.clone()),
            Known::Unknown { reason } => {
                if record.contribution_kind == ContributionKind::PrimaryStudy {
                    Known::Known(ParticipantOverlapGroupId(ScopedId {
                        scope: study.0.scope.clone(),
                        id: format!("participants-{}", study.0.id),
                        version: 1,
                    }))
                } else {
                    Known::Unknown {
                        reason: reason.clone(),
                    }
                }
            }
        };

        synthesis_inputs.push(SynthesisInput {
            result: record.result_id.clone(),
            study,
            kind: record.contribution_kind,
            title: record.title.clone(),
            report_kind: Known::Known(record.kind),
            population: record.population.clone(),
            timepoint: record.timepoint.clone(),
            arms: record.arms.clone(),
            contains: contained_studies.into_iter().collect(),
            participants: effective_participants,
            denominator: record.denominator.clone(),
            covariance: record.covariance.clone(),
        });
    }

    Ok(LinkageResolution {
        study_links,
        version_links,
        review_links,
        overlap_links,
        synthesis_inputs,
        outcome_discrepancies,
    })
}

impl LinkageResolution {
    /// Clusters `ReportVersionId`s by canonical `StudyId` for primary studies only.
    /// Systematic reviews and pooled IPD syntheses are never counted as independent primary studies.
    #[must_use]
    pub fn primary_study_clusters(&self) -> BTreeMap<StudyId, Vec<ReportVersionId>> {
        let secondary_results: BTreeSet<(String, String)> = self
            .synthesis_inputs
            .iter()
            .filter(|input| input.kind != ContributionKind::PrimaryStudy)
            .map(|input| (input.study.0.scope.clone(), input.study.0.id.clone()))
            .collect();

        let mut map: BTreeMap<StudyId, Vec<ReportVersionId>> = BTreeMap::new();
        for link in &self.study_links {
            if link.status != LinkStatus::Rejected
                && !secondary_results
                    .contains(&(link.study.0.scope.clone(), link.study.0.id.clone()))
            {
                map.entry(link.study.clone())
                    .or_default()
                    .push(link.report.clone());
            }
        }
        map
    }

    /// Counts distinct independent primary studies represented by `selected_versions`.
    /// Secondary syntheses (`SystematicReview`, `PooledIpd`), retracted/withdrawn versions, and
    /// duplicate reports/timepoints/subgroups of an already-counted primary study never increment
    /// the independent study count.
    #[must_use]
    pub fn independent_primary_study_count(&self, selected_versions: &[ReportVersionId]) -> usize {
        let wanted: BTreeSet<(String, String, u32)> =
            selected_versions.iter().map(version_key).collect();
        let withdrawn_studies: BTreeSet<(String, String)> = self
            .version_links
            .iter()
            .zip(self.study_links.iter())
            .filter(|(vlink, _)| {
                matches!(
                    vlink.publication_state,
                    PublicationState::Retracted | PublicationState::Withdrawn
                )
            })
            .map(|(_, slink)| (slink.study.0.scope.clone(), slink.study.0.id.clone()))
            .collect();
        let primary_studies: BTreeSet<(String, String)> = self
            .synthesis_inputs
            .iter()
            .filter(|input| input.kind == ContributionKind::PrimaryStudy)
            .map(|input| (input.study.0.scope.clone(), input.study.0.id.clone()))
            .collect();

        let mut distinct: BTreeSet<(String, String)> = BTreeSet::new();
        for (slink, vlink) in self.study_links.iter().zip(self.version_links.iter()) {
            if wanted.contains(&version_key(&slink.report))
                && slink.status != LinkStatus::Rejected
                && vlink.publication_state.citable()
            {
                let skey = (slink.study.0.scope.clone(), slink.study.0.id.clone());
                if primary_studies.contains(&skey) && !withdrawn_studies.contains(&skey) {
                    distinct.insert(skey);
                }
            }
        }
        distinct.len()
    }

    /// Evaluates `decide_pooling` over a subset of `ResultId`s using the resolved `SynthesisInput`s
    /// and `OverlapLink`s.
    ///
    /// # Errors
    /// Propagates `PoolingRefusal` (`PoolingRefusedUnitOfAnalysis` or
    /// `PoolingRefusedMissingDenominator`) whenever independence, denominator, or covariance rules
    /// fail.
    pub fn decide_subset_pooling(
        &self,
        selected_results: &[ResultId],
    ) -> Result<PoolingDecision, PoolingRefusal> {
        if selected_results.is_empty() {
            return Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis { results: vec![] });
        }
        let withdrawn_studies: BTreeSet<(String, String)> = self
            .version_links
            .iter()
            .zip(self.study_links.iter())
            .filter(|(vlink, _)| {
                matches!(
                    vlink.publication_state,
                    PublicationState::Retracted | PublicationState::Withdrawn
                )
            })
            .map(|(_, slink)| (slink.study.0.scope.clone(), slink.study.0.id.clone()))
            .collect();

        let mut subset = Vec::with_capacity(selected_results.len());
        let mut refused_early: BTreeSet<ResultId> = BTreeSet::new();
        let mut seen_entities: BTreeSet<(String, String)> = BTreeSet::new();

        for wanted_id in selected_results {
            if !seen_entities.insert((wanted_id.0.scope.clone(), wanted_id.0.id.clone())) {
                refused_early.insert(wanted_id.clone());
            }
            let pos = self
                .synthesis_inputs
                .iter()
                .position(|input| input.result == *wanted_id);
            let Some(idx) = pos else {
                refused_early.insert(wanted_id.clone());
                continue;
            };
            let vlink = &self.version_links[idx];
            let slink = &self.study_links[idx];
            if !vlink.publication_state.citable()
                || slink.status == LinkStatus::Rejected
                || withdrawn_studies
                    .contains(&(slink.study.0.scope.clone(), slink.study.0.id.clone()))
            {
                refused_early.insert(wanted_id.clone());
            }
            subset.push(self.synthesis_inputs[idx].clone());
        }

        if !refused_early.is_empty() {
            return Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis {
                results: refused_early.into_iter().collect(),
            });
        }
        decide_pooling(&subset, &self.overlap_links)
    }
}

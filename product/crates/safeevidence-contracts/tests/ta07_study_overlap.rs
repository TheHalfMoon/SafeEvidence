//! `WP-05` / `TA-07`: Study/report/result linkage, overlap groups, outcome-switch reconciliation,
//! and double-count guard (`docs/P00_STUDY_INDEPENDENCE_CONTRACT.md` + `T28c` `REFERENCE`).

use std::collections::BTreeSet;

use safeevidence_contracts::study::{
    AnalysisPopulation, ContributionKind, CovarianceRef, Known, LinkStatus, OutcomeDefinition,
    ParticipantOverlapGroupId, PoolingRefusal, PublicationState, ReportId, ReportVersionId,
    ReportVersionKind, ResultId, ScopedId, StudyArmId, StudyId, ValidityEpoch,
};
use safeevidence_contracts::study_linkage::{
    LinkageError, ReportMetadataRecord, resolve_study_linkage,
};

fn sid(id: &str, version: u32) -> ScopedId {
    ScopedId {
        scope: "ta07-synthetic".to_owned(),
        id: id.to_owned(),
        version,
    }
}

fn outcome(id: &str, def: &str, timepoint: &str) -> OutcomeDefinition {
    OutcomeDefinition {
        id: safeevidence_contracts::study::OutcomeId(sid(id, 1)),
        definition: def.to_owned(),
        unit: Known::Known("points".to_owned()),
        timepoint: timepoint.to_owned(),
        method: Known::Known("synthetic-scale".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
fn primary_record(
    report_id: &str,
    version: u32,
    result_id: &str,
    kind: ReportVersionKind,
    state: PublicationState,
    title: &str,
    registrations: &[&str],
    pmid: Option<&str>,
    parent_version: Option<(&str, u32)>,
    arms: &[&str],
    population: AnalysisPopulation,
    timepoint: &str,
    reg_outcome: OutcomeDefinition,
    rep_outcome: OutcomeDefinition,
    denominator: Known<u64>,
) -> ReportMetadataRecord {
    ReportMetadataRecord {
        report_id: ReportId(sid(report_id, 1)),
        version_id: ReportVersionId(sid(report_id, version)),
        result_id: ResultId(sid(result_id, 1)),
        kind,
        publication_state: state,
        validity_epoch: ValidityEpoch(10),
        title: title.to_owned(),
        human_confirmed_study: None,
        trial_registrations: registrations.iter().map(|s| (*s).to_owned()).collect(),
        pmid: pmid.map(str::to_owned),
        doi: None,
        parent_report_version: parent_version.map(|(r, v)| ReportVersionId(sid(r, v))),
        contribution_kind: ContributionKind::PrimaryStudy,
        included_registrations: vec![],
        included_pmids: vec![],
        arms: arms.iter().map(|a| StudyArmId(sid(a, 1))).collect(),
        population: Known::Known(population),
        timepoint: Known::Known(timepoint.to_owned()),
        registered_outcome: Known::Known(reg_outcome),
        reported_outcome: rep_outcome,
        denominator,
        participants: Known::Unknown {
            reason: "resolved by study cluster".to_owned(),
        },
        covariance: Known::Unknown {
            reason: "no covariance supplied".to_owned(),
        },
    }
}

#[test]
fn ta07_multi_report_benchmark_achieves_unit_precision_and_recall_with_zero_double_counts() {
    let primary_out = outcome("out-12w", "Glimmer composite score", "12 weeks");
    let switched_out = outcome("out-24w-surrogate", "Secondary biomarker index", "24 weeks");

    // Study 1 (`NCT00090001`): 7 report versions across the full lifecycle
    // (protocol, registry, abstract, preprint, primary published, 24w follow-up with switched
    // outcome, and a formal correction version).
    let s1_protocol = primary_record(
        "rep-s1-protocol",
        1,
        "res-s1-protocol",
        ReportVersionKind::Protocol,
        PublicationState::Current,
        "Synthetic Veltrixamine Phase III Protocol",
        &["NCT00090001"],
        Some("900001"),
        None,
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(240),
    );
    let s1_registry = primary_record(
        "rep-s1-registry",
        1,
        "res-s1-registry",
        ReportVersionKind::Registry,
        PublicationState::Current,
        "Registry Entry NCT00090001",
        &["nct00090001"],
        None,
        None,
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(240),
    );
    let s1_abstract = primary_record(
        "rep-s1-abstract",
        1,
        "res-s1-abstract",
        ReportVersionKind::Abstract,
        PublicationState::Current,
        "Conference Abstract: Veltrixamine in Glimmer Syndrome",
        &["NCT00090001"],
        None,
        Some(("rep-s1-registry", 1)),
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(240),
    );
    let s1_preprint = primary_record(
        "rep-s1-preprint",
        1,
        "res-s1-preprint",
        ReportVersionKind::Preprint,
        PublicationState::Superseded,
        "Veltrixamine in Glimmer Syndrome: Randomized Trial",
        &["NCT00090001"],
        None,
        Some(("rep-s1-protocol", 1)),
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(240),
    );
    let s1_primary = primary_record(
        "rep-s1-primary",
        1,
        "res-s1-primary-itt",
        ReportVersionKind::Published,
        PublicationState::Current,
        "Veltrixamine in Glimmer Syndrome: Randomized Trial",
        &["NCT00090001"],
        Some("900002"),
        Some(("rep-s1-preprint", 1)),
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(240),
    );
    let s1_pp = primary_record(
        "rep-s1-pp",
        1,
        "res-s1-primary-pp",
        ReportVersionKind::Published,
        PublicationState::Current,
        "Per-Protocol Companion Analysis of Veltrixamine",
        &["NCT00090001"],
        Some("900003"),
        Some(("rep-s1-primary", 1)),
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::PerProtocol,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(218),
    );
    let s1_subgroup = primary_record(
        "rep-s1-subgroup",
        1,
        "res-s1-subgroup-renal",
        ReportVersionKind::FollowUp,
        PublicationState::Current,
        "Renal Subgroup and 24-Week Follow-up of NCT00090001",
        &["NCT00090001"],
        Some("900004"),
        Some(("rep-s1-primary", 1)),
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Subgroup("mild_renal_impairment".to_owned()),
        "24 weeks",
        primary_out.clone(),
        switched_out.clone(),
        Known::Known(84),
    );
    let s1_correction = primary_record(
        "rep-s1-primary",
        2,
        "res-s1-correction",
        ReportVersionKind::Correction,
        PublicationState::Corrected,
        "Erratum: Veltrixamine in Glimmer Syndrome",
        &["NCT00090001"],
        Some("900005"),
        Some(("rep-s1-primary", 1)),
        &["arm-s1-active", "arm-s1-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(240),
    );

    // Study 2 (`NCT00090002`): DIFFERENT trial with the EXACT SAME title as `s1_primary`!
    // Must NEVER merge with Study 1 (`P00_STUDY_INDEPENDENCE_CONTRACT`).
    let s2_same_title = primary_record(
        "rep-s2-primary",
        1,
        "res-s2-primary",
        ReportVersionKind::Published,
        PublicationState::Current,
        "Veltrixamine in Glimmer Syndrome: Randomized Trial",
        &["NCT00090002"],
        Some("900010"),
        None,
        &["arm-s2-active", "arm-s2-placebo"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(310),
    );

    // Study 3 (`NCT00090003`): Shared-control multi-arm trial (low-dose vs control, high-dose vs
    // shared control arm `arm-s3-control`).
    let s3_low_dose = primary_record(
        "rep-s3-low",
        1,
        "res-s3-low",
        ReportVersionKind::Published,
        PublicationState::Current,
        "Multi-Arm Trial Low-Dose Contrast",
        &["NCT00090003"],
        Some("900020"),
        None,
        &["arm-s3-low", "arm-s3-control"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(180),
    );
    let s3_high_dose = primary_record(
        "rep-s3-high",
        1,
        "res-s3-high",
        ReportVersionKind::Published,
        PublicationState::Current,
        "Multi-Arm Trial High-Dose Contrast",
        &[],
        Some("900021"),
        None,
        &["arm-s3-high", "arm-s3-control"],
        AnalysisPopulation::Itt,
        "12 weeks",
        primary_out.clone(),
        primary_out.clone(),
        Known::Known(182),
    );

    // Secondary syntheses: one Pooled IPD and one Systematic Review containing Study 1 + Study 2.
    let pooled_ipd = ReportMetadataRecord {
        report_id: ReportId(sid("rep-ipd-1", 1)),
        version_id: ReportVersionId(sid("rep-ipd-1", 1)),
        result_id: ResultId(sid("res-ipd-1", 1)),
        kind: ReportVersionKind::Published,
        publication_state: PublicationState::Current,
        validity_epoch: ValidityEpoch(10),
        title: "Individual Participant Data Meta-Analysis of Veltrixamine".to_owned(),
        human_confirmed_study: None,
        trial_registrations: vec![],
        pmid: Some("900050".to_owned()),
        doi: None,
        parent_report_version: None,
        contribution_kind: ContributionKind::PooledIpd,
        included_registrations: vec!["NCT00090001".to_owned(), "NCT00090002".to_owned()],
        included_pmids: vec!["900002".to_owned(), "900010".to_owned()],
        arms: vec![],
        population: Known::Known(AnalysisPopulation::Itt),
        timepoint: Known::Known("12 weeks".to_owned()),
        registered_outcome: Known::Known(primary_out.clone()),
        reported_outcome: primary_out.clone(),
        denominator: Known::Known(550),
        participants: Known::Known(ParticipantOverlapGroupId(sid("ipd-group", 1))),
        covariance: Known::Unknown {
            reason: "secondary synthesis".to_owned(),
        },
    };

    let sys_review = ReportMetadataRecord {
        report_id: ReportId(sid("rep-sr-1", 1)),
        version_id: ReportVersionId(sid("rep-sr-1", 1)),
        result_id: ResultId(sid("res-sr-1", 1)),
        kind: ReportVersionKind::Published,
        publication_state: PublicationState::Current,
        validity_epoch: ValidityEpoch(10),
        title: "Systematic Review of Veltrixamine Trials".to_owned(),
        human_confirmed_study: None,
        trial_registrations: vec![],
        pmid: Some("900060".to_owned()),
        doi: None,
        parent_report_version: None,
        contribution_kind: ContributionKind::SystematicReview,
        included_registrations: vec!["NCT00090001".to_owned()],
        included_pmids: vec!["900010".to_owned()],
        arms: vec![],
        population: Known::Known(AnalysisPopulation::Itt),
        timepoint: Known::Known("12 weeks".to_owned()),
        registered_outcome: Known::Known(primary_out.clone()),
        reported_outcome: primary_out.clone(),
        denominator: Known::Known(550),
        participants: Known::Known(ParticipantOverlapGroupId(sid("sr-group", 1))),
        covariance: Known::Unknown {
            reason: "secondary synthesis".to_owned(),
        },
    };

    let records = vec![
        s1_protocol,
        s1_registry,
        s1_abstract,
        s1_preprint,
        s1_primary,
        s1_pp,
        s1_subgroup,
        s1_correction,
        s2_same_title,
        s3_low_dose,
        s3_high_dose,
        pooled_ipd,
        sys_review,
    ];

    let resolution = resolve_study_linkage(&records).expect("linkage succeeds");

    // 1. Study-level clustering precision & recall on the 11 primary study reports:
    // Ground-truth primary clusters:
    // - Cluster A (`NCT00090001`): 8 report versions
    // - Cluster B (`NCT00090002`): 1 report version (matching title did NOT merge!)
    // - Cluster C (`NCT00090003`, joined via shared `arm-s3-control`): 2 report versions
    let clusters = resolution.primary_study_clusters();
    assert_eq!(clusters.len(), 3, "exact 3 primary studies");

    let expected_clusters: Vec<BTreeSet<String>> = vec![
        [
            "rep-s1-protocol:1",
            "rep-s1-registry:1",
            "rep-s1-abstract:1",
            "rep-s1-preprint:1",
            "rep-s1-primary:1",
            "rep-s1-pp:1",
            "rep-s1-subgroup:1",
            "rep-s1-primary:2",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        ["rep-s2-primary:1"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ["rep-s3-low:1", "rep-s3-high:1"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    ];

    let predicted_clusters: Vec<BTreeSet<String>> = clusters
        .values()
        .map(|vers| {
            vers.iter()
                .map(|v| format!("{}:{}", v.0.id, v.0.version))
                .collect()
        })
        .collect();

    // Pairwise coreference precision & recall across all 11 primary report versions:
    let primary_versions: Vec<String> = records
        .iter()
        .filter(|r| r.contribution_kind == ContributionKind::PrimaryStudy)
        .map(|r| format!("{}:{}", r.version_id.0.id, r.version_id.0.version))
        .collect();
    let same_in = |sets: &[BTreeSet<String>], a: &str, b: &str| {
        sets.iter().any(|set| set.contains(a) && set.contains(b))
    };
    let mut tp = 0_usize;
    let mut fp = 0_usize;
    let mut fn_count = 0_usize;
    for i in 0..primary_versions.len() {
        for j in (i + 1)..primary_versions.len() {
            let gold = same_in(
                &expected_clusters,
                &primary_versions[i],
                &primary_versions[j],
            );
            let pred = same_in(
                &predicted_clusters,
                &primary_versions[i],
                &primary_versions[j],
            );
            match (gold, pred) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => fn_count += 1,
                (false, false) => {}
            }
        }
    }
    let precision = tp as f64 / (tp + fp) as f64;
    let recall = tp as f64 / (tp + fn_count) as f64;
    assert_eq!(precision, 1.0);
    assert_eq!(recall, 1.0);

    // 2. Link status corroboration: `s1_primary` has registration + parent + shared arm -> Corroborated;
    // `s2_same_title` has single registration only -> Proposed.
    let s1_link = resolution
        .study_links
        .iter()
        .find(|l| l.report == ReportVersionId(sid("rep-s1-primary", 1)))
        .unwrap();
    assert_eq!(s1_link.status, LinkStatus::Corroborated);
    let s2_link = resolution
        .study_links
        .iter()
        .find(|l| l.report == ReportVersionId(sid("rep-s2-primary", 1)))
        .unwrap();
    assert_eq!(s2_link.status, LinkStatus::Proposed);

    // 3. T28c review/IPD containment links resolved to both Study 1 and Study 2:
    assert_eq!(resolution.review_links.len(), 4);

    // 4. Outcome switch after registration caught on `rep-s1-subgroup`:
    assert_eq!(resolution.outcome_discrepancies.len(), 1);
    assert_eq!(
        resolution.outcome_discrepancies[0].0,
        ReportVersionId(sid("rep-s1-subgroup", 1))
    );

    // 5. Zero double-counted studies across all 13 records (including IPD + SR + follow-ups + PP):
    let all_versions: Vec<ReportVersionId> = records.iter().map(|r| r.version_id.clone()).collect();
    assert_eq!(
        resolution.independent_primary_study_count(&all_versions),
        3,
        "reviews, pooled IPD, follow-ups, subgroups, and PP never add independent study count"
    );

    // 6. Pooling accepts one independent primary result per study (`s1`, `s2`, `s3_low`):
    let clean_pool = resolution
        .decide_subset_pooling(&[
            ResultId(sid("res-s1-primary-itt", 1)),
            ResultId(sid("res-s2-primary", 1)),
            ResultId(sid("res-s3-low", 1)),
        ])
        .expect("three independent studies pool cleanly");
    assert_eq!(clean_pool.accepted.len(), 3);
    assert!(!clean_pool.requires_covariance_method);

    // 7. Pooling refuses ITT + PP, primary + follow-up subgroup, shared-control multi-arm without
    // covariance, primary + Pooled IPD, and primary + Systematic Review!
    for invalid_pair in [
        [
            ResultId(sid("res-s1-primary-itt", 1)),
            ResultId(sid("res-s1-primary-pp", 1)),
        ],
        [
            ResultId(sid("res-s1-primary-itt", 1)),
            ResultId(sid("res-s1-subgroup-renal", 1)),
        ],
        [
            ResultId(sid("res-s3-low", 1)),
            ResultId(sid("res-s3-high", 1)),
        ],
        [
            ResultId(sid("res-s1-primary-itt", 1)),
            ResultId(sid("res-ipd-1", 1)),
        ],
        [
            ResultId(sid("res-s2-primary", 1)),
            ResultId(sid("res-sr-1", 1)),
        ],
    ] {
        assert!(
            matches!(
                resolution.decide_subset_pooling(&invalid_pair),
                Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis { .. })
            ),
            "must refuse dependent pair {invalid_pair:?}"
        );
    }

    // 8. Supplying a named shared CovarianceRef across `s3_low` + `s3_high` permits covariance-aware
    // pooling (`requires_covariance_method == true`), whereas missing denominator fails closed!
    let mut with_cov = records.clone();
    let cov = Known::Known(CovarianceRef(sid("cov-nct00090003-multiarm", 1)));
    with_cov[9].covariance = cov.clone();
    with_cov[10].covariance = cov;
    let cov_res = resolve_study_linkage(&with_cov).unwrap();
    let cov_decision = cov_res
        .decide_subset_pooling(&[
            ResultId(sid("res-s3-low", 1)),
            ResultId(sid("res-s3-high", 1)),
        ])
        .expect("shared named covariance permits multi-arm contrast");
    assert!(cov_decision.requires_covariance_method);

    let mut missing_denom = records;
    missing_denom[8].denominator = Known::Unknown {
        reason: "table omitted randomized N".to_owned(),
    };
    let denom_res = resolve_study_linkage(&missing_denom).unwrap();
    assert!(matches!(
        denom_res.decide_subset_pooling(&[ResultId(sid("res-s2-primary", 1))]),
        Err(PoolingRefusal::PoolingRefusedMissingDenominator { .. })
    ));
}

#[test]
fn inconsistent_retraction_or_conflicting_human_study_assignment_fails_closed() {
    let out = outcome("o1", "Score", "12w");
    let mut bad_retraction = primary_record(
        "rep-bad",
        1,
        "res-bad",
        ReportVersionKind::Retraction,
        PublicationState::Current,
        "Retraction Notice",
        &["NCT00099999"],
        None,
        None,
        &[],
        AnalysisPopulation::Itt,
        "12w",
        out.clone(),
        out.clone(),
        Known::Known(100),
    );
    assert!(matches!(
        resolve_study_linkage(&[bad_retraction.clone()]),
        Err(LinkageError::InconsistentVersionStanding(_))
    ));

    bad_retraction.kind = ReportVersionKind::Published;
    bad_retraction.human_confirmed_study = Some(StudyId(sid("human-study-a", 1)));
    let mut second = bad_retraction.clone();
    second.report_id = ReportId(sid("rep-bad-2", 1));
    second.version_id = ReportVersionId(sid("rep-bad-2", 1));
    second.result_id = ResultId(sid("res-bad-2", 1));
    second.human_confirmed_study = Some(StudyId(sid("human-study-b", 1)));
    assert!(matches!(
        resolve_study_linkage(&[bad_retraction, second]),
        Err(LinkageError::ConflictingHumanStudyAssignment(_))
    ));
}

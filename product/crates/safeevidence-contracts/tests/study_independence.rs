//! Fixtures for the guard's independence rules, following the qualification list in
//! `P00_STUDY_INDEPENDENCE_CONTRACT.md`. This tests declared structure only, not extraction or
//! statistics. Synthetic identifiers only.

use safeevidence_contracts::study::{
    AnalysisPopulation, ContributionKind, CovarianceRef, Known, OutcomeDefinition, OutcomeId,
    OutcomeReconciliation, OverlapLink, OverlapState, ParticipantOverlapGroupId, PoolingRefusal,
    ReportVersionKind, ResultId, ScopedId, StudyArmId, StudyId, SynthesisInput, decide_pooling,
};

fn sid(id: &str) -> ScopedId {
    ScopedId {
        scope: "synthetic".into(),
        id: id.into(),
        version: 1,
    }
}

fn result(id: &str) -> ResultId {
    ResultId(sid(id))
}

fn unknown<T>() -> Known<T> {
    Known::Unknown {
        reason: "not reported".into(),
    }
}

fn input(id: &str, study: &str, group: &str) -> SynthesisInput {
    SynthesisInput {
        result: result(id),
        study: StudyId(sid(study)),
        kind: ContributionKind::PrimaryStudy,
        title: format!("Title of {study}"),
        report_kind: Known::Known(ReportVersionKind::Published),
        population: Known::Known(AnalysisPopulation::Itt),
        timepoint: Known::Known("12m".into()),
        arms: vec![],
        contains: vec![],
        participants: Known::Known(ParticipantOverlapGroupId(sid(group))),
        denominator: Known::Known(100),
        covariance: unknown(),
    }
}

fn with_covariance(mut value: SynthesisInput) -> SynthesisInput {
    value.covariance = Known::Known(CovarianceRef(sid("cov")));
    value
}

fn overlap(first: &str, second: &str, state: OverlapState) -> OverlapLink {
    OverlapLink {
        group: ParticipantOverlapGroupId(sid("overlap")),
        first: result(first),
        second: result(second),
        state,
    }
}

fn assert_unit_refusal(inputs: &[SynthesisInput], overlaps: &[OverlapLink]) {
    assert!(matches!(
        decide_pooling(inputs, overlaps),
        Err(PoolingRefusal::PoolingRefusedUnitOfAnalysis { .. })
    ));
}

#[test]
fn every_report_type_of_one_rct_is_refused_even_with_separate_groups() {
    for kind in [
        ReportVersionKind::Protocol,
        ReportVersionKind::Registry,
        ReportVersionKind::Abstract,
        ReportVersionKind::Preprint,
        ReportVersionKind::FollowUp,
        ReportVersionKind::Correction,
    ] {
        let mut other = input("other", "rct", "p_two");
        other.report_kind = Known::Known(kind);
        assert_unit_refusal(&[input("primary", "rct", "p_one"), other], &[]);
    }
}

#[test]
fn different_trials_with_matching_titles_are_not_falsely_merged() {
    let mut first = input("a", "trial_a", "pa");
    let mut second = input("b", "trial_b", "pb");
    first.title = "Shared trial title".into();
    second.title = "Shared trial title".into();
    let accepted = decide_pooling(&[first, second], &[]).expect("independent trials pool");
    assert_eq!(accepted.accepted, vec![result("a"), result("b")]);
    assert!(!accepted.requires_covariance_method);
}

#[test]
fn one_trial_under_different_titles_is_not_falsely_split() {
    let mut first = input("a", "rct", "p_one");
    let mut second = input("b", "rct", "p_two");
    first.title = "Title in the journal".into();
    second.title = "Title in the registry".into();
    assert_unit_refusal(&[first, second], &[]);
}

#[test]
fn shared_control_multi_arm_needs_known_covariance() {
    let control = StudyArmId(sid("control"));
    let arm = |id: &str, own: &str| {
        let mut value = input(id, "rct", id);
        value.arms = vec![StudyArmId(sid(own)), control.clone()];
        value
    };
    let arms = [arm("t1_vs_c", "t1"), arm("t2_vs_c", "t2")];
    assert_unit_refusal(&arms, &[]);
    let covered = arms.map(with_covariance);
    assert!(
        decide_pooling(&covered, &[])
            .unwrap()
            .requires_covariance_method
    );
}

#[test]
fn shared_arm_is_refused_even_when_studies_and_groups_differ() {
    let mut first = input("a", "s1", "g1");
    let mut second = input("b", "s2", "g2");
    first.arms = vec![StudyArmId(sid("control"))];
    second.arms = vec![StudyArmId(sid("control"))];
    assert_unit_refusal(&[first, second], &[]);
    let mut first = input("a", "s1", "g1");
    let mut second = input("b", "s2", "g2");
    first.arms = vec![StudyArmId(sid("control_a"))];
    second.arms = vec![StudyArmId(sid("control_b"))];
    assert!(decide_pooling(&[first, second], &[]).is_ok());
}

#[test]
fn mixed_itt_and_per_protocol_from_one_trial_refused() {
    let mut per_protocol = input("pp", "rct", "p");
    per_protocol.population = Known::Known(AnalysisPopulation::PerProtocol);
    assert_unit_refusal(&[input("itt", "rct", "p"), per_protocol], &[]);
}

#[test]
fn repeat_timepoints_from_one_trial_refused() {
    let mut later = input("m12", "rct", "p");
    later.timepoint = Known::Known("24m".into());
    assert_unit_refusal(&[input("m6", "rct", "p"), later], &[]);
}

#[test]
fn subgroup_plus_parent_cohort_refused_with_or_without_a_link() {
    let mut subgroup = input("sub", "cohort", "older");
    subgroup.population = Known::Known(AnalysisPopulation::Subgroup("age over 65".into()));
    let parent = input("parent", "cohort", "all");
    assert_unit_refusal(&[parent.clone(), subgroup.clone()], &[]);
    assert_unit_refusal(
        &[parent, subgroup],
        &[overlap("parent", "sub", OverlapState::Confirmed)],
    );
}

#[test]
fn secondary_with_its_own_component_is_refused() {
    for kind in [
        ContributionKind::PooledIpd,
        ContributionKind::SystematicReview,
    ] {
        let mut secondary = input("secondary", "synthesis", "g1");
        secondary.kind = kind;
        secondary.contains = vec![StudyId(sid("trial"))];
        assert_unit_refusal(&[secondary.clone(), input("component", "trial", "g2")], &[]);
        let with = |v: SynthesisInput| with_covariance(v);
        assert_unit_refusal(
            &[with(secondary), with(input("component", "trial", "g2"))],
            &[],
        );
    }
}

#[test]
fn secondary_contribution_refused_among_three_inputs() {
    let mut review = input("review", "s0", "g0");
    review.kind = ContributionKind::SystematicReview;
    assert_unit_refusal(
        &[review, input("t1", "s1", "g1"), input("t2", "s2", "g2")],
        &[],
    );
}

#[test]
fn dependence_detected_between_non_adjacent_inputs() {
    assert_unit_refusal(
        &[
            input("a", "s1", "g1"),
            input("b", "s2", "g2"),
            input("c", "s1", "g3"),
        ],
        &[],
    );
    assert_unit_refusal(
        &[
            input("a", "s1", "g1"),
            input("b", "s2", "g2"),
            input("a", "s3", "g3"),
        ],
        &[],
    );
}

#[test]
fn lone_secondary_contribution_is_not_double_counted() {
    let mut review = input("review", "s0", "g0");
    review.kind = ContributionKind::SystematicReview;
    assert!(decide_pooling(&[review], &[]).is_ok());
}

#[test]
fn empty_covariance_reference_does_not_cover() {
    let blank = |mut value: SynthesisInput| {
        value.covariance = Known::Known(CovarianceRef(ScopedId {
            scope: String::new(),
            id: " ".into(),
            version: 0,
        }));
        value
    };
    assert_unit_refusal(
        &[blank(input("a", "s", "g")), blank(input("b", "s", "g"))],
        &[],
    );
}

#[test]
fn declared_overlap_refused_at_every_state() {
    for state in [
        OverlapState::Confirmed,
        OverlapState::Possible,
        OverlapState::Unknown,
    ] {
        assert_unit_refusal(
            &[input("a", "s1", "g1"), input("b", "s2", "g2")],
            &[overlap("a", "b", state)],
        );
    }
}

#[test]
fn input_participant_group_joins_declared_overlap_group() {
    let mut member = input("a", "s1", "g1");
    member.participants = Known::Known(ParticipantOverlapGroupId(sid("overlap")));
    assert_unit_refusal(
        &[member, input("x", "s2", "g2")],
        &[overlap("b", "x", OverlapState::Possible)],
    );
}

#[test]
fn overlap_chain_across_groups_refused() {
    let link = |group: &str, first: &str, second: &str| OverlapLink {
        group: ParticipantOverlapGroupId(sid(group)),
        first: result(first),
        second: result(second),
        state: OverlapState::Possible,
    };
    assert_unit_refusal(
        &[input("a", "s1", "g1"), input("c", "s2", "g2")],
        &[link("g_one", "a", "x"), link("g_two", "x", "c")],
    );
}

#[test]
fn identity_ignores_version_but_not_scope_or_id() {
    let at_version = |id: &str, version: u32| ScopedId {
        scope: "synthetic".into(),
        id: id.into(),
        version,
    };
    let mut later = input("a", "s2", "g2");
    later.result = ResultId(at_version("a", 2));
    assert_unit_refusal(&[input("a", "s1", "g1"), later], &[]);

    let mut later_study = input("b", "s1", "g2");
    later_study.study = StudyId(at_version("s1", 2));
    assert_unit_refusal(&[input("a", "s1", "g1"), later_study], &[]);

    let mut later_link = overlap("a", "b", OverlapState::Possible);
    later_link.first = ResultId(at_version("a", 2));
    later_link.second = ResultId(at_version("b", 3));
    assert_unit_refusal(
        &[input("a", "s1", "g1"), input("b", "s2", "g2")],
        &[later_link],
    );

    let mut other_scope = input("a", "s2", "g2");
    other_scope.result.0.scope = "other".into();
    assert!(decide_pooling(&[input("a", "s1", "g1"), other_scope], &[]).is_ok());
}

#[test]
fn strings_with_separators_do_not_collide_group_identities() {
    let group = |scope: &str, id: &str| {
        Known::Known(ParticipantOverlapGroupId(ScopedId {
            scope: scope.into(),
            id: id.into(),
            version: 1,
        }))
    };
    let mut first = input("a", "s1", "g1");
    first.participants = group("p\0q", "r");
    let mut second = input("b", "s2", "g2");
    second.participants = group("p", "q\0r");
    assert!(decide_pooling(&[first, second], &[]).is_ok());
}

#[test]
fn covariance_must_match_at_one_exact_version() {
    let mut first = with_covariance(input("a", "s", "g"));
    let mut second = with_covariance(input("b", "s", "g"));
    if let Known::Known(reference) = &mut second.covariance {
        reference.0.version = 2;
    }
    assert_unit_refusal(&[first.clone(), second.clone()], &[]);
    first.covariance = second.covariance.clone();
    assert!(decide_pooling(&[first, second], &[]).is_ok());
}

#[test]
fn duplicate_result_never_pools_even_with_covariance() {
    assert_unit_refusal(&[input("a", "s1", "g1"), input("a", "s2", "g2")], &[]);
    let same = with_covariance(input("a", "s", "g"));
    assert_unit_refusal(&[same.clone(), same], &[]);
}

#[test]
fn different_covariance_references_do_not_cover_shared_participants() {
    let mut first = input("a", "s", "g");
    let mut second = input("b", "s", "g");
    first.covariance = Known::Known(CovarianceRef(sid("c1")));
    second.covariance = Known::Known(CovarianceRef(sid("c2")));
    assert_unit_refusal(&[first, second], &[]);
}

#[test]
fn one_sided_covariance_does_not_cover() {
    assert_unit_refusal(
        &[with_covariance(input("a", "s", "g")), input("b", "s", "g")],
        &[],
    );
}

#[test]
fn version_bump_does_not_make_a_new_study_or_group() {
    let mut later = input("b", "s", "g");
    later.study.0.version = 2;
    if let Known::Known(group) = &mut later.participants {
        group.0.version = 2;
    }
    assert_unit_refusal(&[input("a", "s", "g"), later], &[]);
    let mut other_study_same_group = input("b", "other", "g");
    if let Known::Known(group) = &mut other_study_same_group.participants {
        group.0.version = 2;
    }
    assert_unit_refusal(&[input("a", "s", "g"), other_study_same_group], &[]);
}

#[test]
fn shared_participants_across_studies_refused() {
    assert_unit_refusal(&[input("a", "s1", "g"), input("b", "s2", "g")], &[]);
}

#[test]
fn overlap_link_applies_in_either_direction() {
    let inputs = [input("a", "s1", "g1"), input("b", "s2", "g2")];
    assert_unit_refusal(&inputs, &[overlap("a", "b", OverlapState::Possible)]);
    assert_unit_refusal(&inputs, &[overlap("b", "a", OverlapState::Possible)]);
}

#[test]
fn overlap_group_reaches_results_through_an_absent_member() {
    assert_unit_refusal(
        &[input("a", "s1", "g1"), input("c", "s2", "g2")],
        &[
            overlap("a", "b", OverlapState::Confirmed),
            overlap("b", "c", OverlapState::Confirmed),
        ],
    );
}

#[test]
fn overlap_links_on_other_results_do_not_block_independent_inputs() {
    let accepted = decide_pooling(
        &[input("a", "s1", "g1"), input("c", "s2", "g2")],
        &[overlap("x", "y", OverlapState::Confirmed)],
    );
    assert!(accepted.is_ok());
}

#[test]
fn zero_denominator_is_treated_as_missing() {
    let mut zero = input("a", "s1", "g1");
    zero.denominator = Known::Known(0);
    assert!(matches!(
        decide_pooling(&[zero, input("b", "s2", "g2")], &[]),
        Err(PoolingRefusal::PoolingRefusedMissingDenominator { .. })
    ));
}

#[test]
fn switched_outcome_keeps_discrepancy() {
    let definition = |text: &str, timepoint: &str| OutcomeDefinition {
        id: OutcomeId(sid(text)),
        definition: text.into(),
        unit: Known::Known("events".into()),
        timepoint: timepoint.into(),
        method: unknown(),
    };
    let switched = OutcomeReconciliation {
        registered: Known::Known(definition("mortality", "12m")),
        reported: definition("composite", "6m"),
    };
    assert!(switched.has_discrepancy());
    let matching = OutcomeReconciliation {
        registered: Known::Known(definition("mortality", "12m")),
        reported: definition("mortality", "12m"),
    };
    assert!(!matching.has_discrepancy());
    let unregistered = OutcomeReconciliation {
        registered: unknown(),
        reported: definition("mortality", "12m"),
    };
    assert!(unregistered.has_discrepancy());
    for changed in [
        definition("composite", "12m"),
        definition("mortality", "6m"),
    ] {
        let single_change = OutcomeReconciliation {
            registered: Known::Known(definition("mortality", "12m")),
            reported: changed,
        };
        assert!(single_change.has_discrepancy());
    }
    let mut other_unit = definition("mortality", "12m");
    other_unit.unit = Known::Known("deaths per 1000".into());
    let unit_changed = OutcomeReconciliation {
        registered: Known::Known(definition("mortality", "12m")),
        reported: other_unit,
    };
    assert!(unit_changed.has_discrepancy());
    let mut other_method = definition("mortality", "12m");
    other_method.method = Known::Known("adjudicated".into());
    let method_changed = OutcomeReconciliation {
        registered: Known::Known(definition("mortality", "12m")),
        reported: other_method,
    };
    assert!(method_changed.has_discrepancy());
}

#[test]
fn unknown_participants_refused() {
    let mut mystery = input("a", "trial_a", "pa");
    mystery.participants = unknown();
    assert_unit_refusal(&[mystery, input("b", "trial_b", "pb")], &[]);
}

#[test]
fn unknown_covariance_alone_does_not_refuse_independent_trials() {
    assert!(decide_pooling(&[input("a", "s1", "g1"), input("b", "s2", "g2")], &[]).is_ok());
}

#[test]
fn missing_denominator_refused_with_its_own_reason() {
    let mut missing = input("a", "trial_a", "pa");
    missing.denominator = unknown();
    assert_eq!(
        decide_pooling(&[missing, input("b", "trial_b", "pb")], &[]),
        Err(PoolingRefusal::PoolingRefusedMissingDenominator {
            results: vec![result("a")]
        })
    );
}

#[test]
fn empty_input_is_not_a_successful_pool() {
    assert!(decide_pooling(&[], &[]).is_err());
}

#[test]
fn unknown_round_trips_explicitly_and_null_is_rejected() {
    let value: Known<u64> = unknown();
    let text = serde_json::to_string(&value).unwrap();
    assert_eq!(serde_json::from_str::<Known<u64>>(&text).unwrap(), value);
    assert!(serde_json::from_str::<Known<u64>>("null").is_err());
}

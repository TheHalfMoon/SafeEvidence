//! P02 qualification fixtures named by `P00_STUDY_INDEPENDENCE_CONTRACT.md`.
//! Synthetic identifiers only.

use safeevidence_contracts::study::{
    ContributionKind, CovarianceRef, Known, OutcomeDefinition, OutcomeId, OutcomeReconciliation,
    OverlapLink, OverlapState, ParticipantOverlapGroupId, PoolingRefusal, ResultId, ScopedId,
    StudyId, SynthesisInput, decide_pooling,
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
fn reports_of_one_rct_are_not_independent_studies() {
    for pair in [
        ("protocol", "primary"),
        ("registry", "primary"),
        ("abstract", "primary"),
        ("preprint", "primary"),
        ("primary", "follow_up"),
        ("primary", "correction"),
    ] {
        assert_unit_refusal(
            &[input(pair.0, "rct", "p_one"), input(pair.1, "rct", "p_two")],
            &[],
        );
    }
}

#[test]
fn independent_trials_are_not_falsely_merged() {
    let accepted = decide_pooling(
        &[input("a", "trial_a", "pa"), input("b", "trial_b", "pb")],
        &[],
    )
    .expect("independent trials pool");
    assert_eq!(accepted, vec![result("a"), result("b")]);
}

#[test]
fn shared_control_multi_arm_needs_known_covariance() {
    let arms = [input("t1_vs_c", "rct", "p"), input("t2_vs_c", "rct", "p")];
    assert_unit_refusal(&arms, &[]);
    let covered = arms.map(with_covariance);
    assert!(decide_pooling(&covered, &[]).is_ok());
}

#[test]
fn two_analyses_of_one_trial_refused() {
    // Covers mixed ITT/PP and repeat timepoints. The guard sees only that both
    // draw on one trial; it has no population or timepoint field to compare.
    assert_unit_refusal(
        &[input("first", "rct", "p"), input("second", "rct", "p")],
        &[],
    );
}

#[test]
fn subgroup_plus_parent_cohort_refused() {
    assert_unit_refusal(
        &[
            input("parent", "cohort", "all"),
            input("sub", "cohort", "older"),
        ],
        &[overlap("parent", "sub", OverlapState::Confirmed)],
    );
}

#[test]
fn pooled_ipd_or_review_is_never_a_new_study_even_without_a_link() {
    for kind in [
        ContributionKind::PooledIpd,
        ContributionKind::SystematicReview,
    ] {
        let mut secondary = input("secondary", "s1", "g1");
        secondary.kind = kind;
        assert_unit_refusal(&[secondary.clone(), input("trial", "s2", "g2")], &[]);
        secondary = with_covariance(secondary);
        let covered_trial = with_covariance(input("trial", "s2", "g2"));
        assert_unit_refusal(&[secondary, covered_trial], &[]);
    }
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

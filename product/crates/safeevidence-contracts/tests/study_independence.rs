//! P02 qualification fixtures named by `P00_STUDY_INDEPENDENCE_CONTRACT.md`.
//! Synthetic identifiers only.

use safeevidence_contracts::study::{
    CovarianceRef, Known, OutcomeDefinition, OutcomeId, OutcomeReconciliation, OverlapLink,
    OverlapState, ParticipantOverlapGroupId, PoolingRefusal, ResultId, ScopedId, StudyId,
    SynthesisInput, decide_pooling,
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
            &[input(pair.0, "rct", "rct_p"), input(pair.1, "rct", "rct_p")],
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
fn mixed_itt_and_per_protocol_from_one_trial_refused() {
    assert_unit_refusal(&[input("itt", "rct", "p"), input("pp", "rct", "p")], &[]);
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
fn repeat_timepoints_refused() {
    assert_unit_refusal(&[input("m6", "rct", "p"), input("m12", "rct", "p")], &[]);
}

#[test]
fn pooled_ipd_plus_component_trials_refused() {
    assert_unit_refusal(
        &[
            input("ipd", "pooled", "ipd_p"),
            input("comp", "trial_a", "pa"),
        ],
        &[overlap("ipd", "comp", OverlapState::Confirmed)],
    );
}

#[test]
fn review_plus_included_trial_refused_even_when_overlap_only_possible() {
    assert_unit_refusal(
        &[
            input("review", "review", "rp"),
            input("trial", "trial_a", "pa"),
        ],
        &[overlap("review", "trial", OverlapState::Possible)],
    );
    assert_unit_refusal(
        &[
            input("review", "review", "rp"),
            input("trial", "trial_a", "pa"),
        ],
        &[overlap("review", "trial", OverlapState::Unknown)],
    );
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
fn unknown_covariance_or_participants_refused() {
    let mut mystery = input("a", "trial_a", "pa");
    mystery.participants = unknown();
    assert_unit_refusal(&[mystery, input("b", "trial_b", "pb")], &[]);
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

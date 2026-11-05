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
fn different_trials_with_matching_titles_are_not_falsely_merged() {
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
fn excluded_overlap_within_one_study_allows_disjoint_cohorts() {
    let inputs = [
        input("north", "registry", "pn"),
        input("south", "registry", "ps"),
    ];
    assert_unit_refusal(&inputs, &[]);
    assert!(
        decide_pooling(
            &inputs,
            &[overlap("north", "south", OverlapState::Excluded)]
        )
        .is_ok()
    );
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

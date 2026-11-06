//! TA-13's fixture subset as amended by `plan-v1.4`: the rules the donor's own pipeline fired on its
//! fixture cases, from `bench/oracles/commandmed_spec006/generate_case_vectors.py`, resolve to its state.

use safeevidence_assurance::{Cause, FiredRule, Requirement, Resolution, evaluate_precedence};
use safeevidence_contracts::assurance::{ControlAction, TerminalOutcome};
use serde::Deserialize;

const FILES: [&str; 3] = [
    include_str!("fixtures/t13_cases_us1_tool_routing.json"),
    include_str!("fixtures/t13_cases_us2_context_safety.json"),
    include_str!("fixtures/t13_cases_us3_injection_spoof.json"),
];

#[derive(Deserialize)]
struct Document {
    commit: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    lexical_emergency: bool,
    fired: Vec<(String, u32, String)>,
    donor_state: Option<String>,
}

fn requirement(state: &str) -> Requirement {
    match state {
        "ASK_MORE" => Requirement::Outcome(TerminalOutcome::AskMore),
        "ABSTAIN" => Requirement::Outcome(TerminalOutcome::Abstain),
        "ESCALATE" => Requirement::Outcome(TerminalOutcome::Escalate),
        "USE_TOOL" => Requirement::Action(ControlAction::UseTool),
        "RETRIEVE_EVIDENCE" => Requirement::Action(ControlAction::RetrieveEvidence),
        other => panic!("unmapped donor state {other}"),
    }
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for file in FILES {
        let document: Document = serde_json::from_str(file).expect("case vectors parse");
        assert_eq!(document.commit, "51f73ec05750137e5bd94ffa0765f6383f475fee");
        cases.extend(document.cases);
    }
    cases
}

#[test]
fn the_subset_is_the_seventeen_donor_cases_less_the_four_listed_exclusions() {
    let cases = cases();
    assert_eq!(cases.len(), 17);
    let mut excluded: Vec<&str> = cases
        .iter()
        .filter(|case| case.lexical_emergency)
        .map(|case| case.case_id.as_str())
        .collect();
    excluded.sort_unstable();
    assert_eq!(
        excluded,
        [
            "ambiguous-risk-fails-toward-escalation-not-answer",
            "emergency-keyword-ar-msa",
            "emergency-keyword-en",
            "injection-suppressed-emergency-preserved",
        ]
    );
    for case in cases.iter().filter(|case| case.lexical_emergency) {
        assert!(case.fired.is_empty() && case.donor_state.is_none());
    }
}

#[test]
fn every_included_case_resolves_the_donors_fired_rules_to_the_donors_state() {
    let mut checked = 0;
    for case in cases().iter().filter(|case| !case.lexical_emergency) {
        let state = case
            .donor_state
            .as_deref()
            .expect("included case has a state");
        let rules: Vec<FiredRule> = case
            .fired
            .iter()
            .map(|(rule_id, precedence, required)| FiredRule {
                rule_id: rule_id.clone(),
                precedence: *precedence,
                requirement: requirement(required),
                revoked: false,
            })
            .collect();
        let resolved = evaluate_precedence(&rules);
        if state == "ANSWER" {
            // The deliberate difference: no rule firing is not an answer, because a commit needs its own proof.
            assert!(rules.is_empty(), "{}", case.case_id);
            assert_eq!(resolved, Resolution::NoRuleFired, "{}", case.case_id);
        } else {
            let Resolution::Decided {
                requirement: got,
                cause,
                winners,
            } = resolved
            else {
                panic!("{}: no decision", case.case_id);
            };
            assert_eq!(got, requirement(state), "{}", case.case_id);
            assert_eq!(cause, Cause::RuleWon, "{}", case.case_id);
            assert_eq!(winners, [case.fired[0].0.clone()], "{}", case.case_id);
        }
        checked += 1;
    }
    assert_eq!(checked, 13);
}

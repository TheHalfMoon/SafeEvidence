//! Parity with the donor's `evaluate_precedence`, using outputs from running the donor's code
//! (`bench/oracles/commandmed_spec006/generate_vectors.py`), plus its deliberate differences.

use safeevidence_assurance::{Cause, FiredRule, Requirement, Resolution, evaluate_precedence};
use safeevidence_contracts::assurance::{ControlAction, TerminalOutcome};
use serde::Deserialize;

const VECTORS: &str = include_str!("fixtures/t13_precedence_vectors.json");

#[derive(Deserialize)]
struct Document {
    commit: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    rules: Vec<(String, u32)>,
    state: String,
    conflict: bool,
    winners: Vec<usize>,
}

fn requirement(state: &str) -> Requirement {
    match state {
        "ANSWER" => Requirement::Outcome(TerminalOutcome::Answer),
        "ASK_MORE" => Requirement::Outcome(TerminalOutcome::AskMore),
        "ABSTAIN" => Requirement::Outcome(TerminalOutcome::Abstain),
        "ESCALATE" => Requirement::Outcome(TerminalOutcome::Escalate),
        "USE_TOOL" => Requirement::Action(ControlAction::UseTool),
        "RETRIEVE_EVIDENCE" => Requirement::Action(ControlAction::RetrieveEvidence),
        other => panic!("unmapped donor state {other}"),
    }
}

fn rule(id: &str, precedence: u32, requirement: Requirement) -> FiredRule {
    FiredRule {
        rule_id: id.to_owned(),
        precedence,
        requirement,
        revoked: false,
    }
}

const ABSTAIN: Requirement = Requirement::Outcome(TerminalOutcome::Abstain);
const ESCALATE: Requirement = Requirement::Outcome(TerminalOutcome::Escalate);
const ASK_MORE: Requirement = Requirement::Outcome(TerminalOutcome::AskMore);
const EMERGENCY: Requirement = Requirement::Outcome(TerminalOutcome::EmergencyNotice);

#[test]
fn every_donor_vector_matches() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document.commit, "51f73ec05750137e5bd94ffa0765f6383f475fee");
    assert_eq!(document.vectors.len(), 1329);
    let mut conflicts = 0;
    for vector in &document.vectors {
        let rules: Vec<FiredRule> = vector
            .rules
            .iter()
            .enumerate()
            .map(|(index, (state, precedence))| {
                rule(&index.to_string(), *precedence, requirement(state))
            })
            .collect();
        let expected_winners: Vec<String> =
            vector.winners.iter().map(ToString::to_string).collect();
        let Resolution::Decided {
            requirement: got,
            cause,
            winners,
        } = evaluate_precedence(&rules)
        else {
            panic!("no decision for {:?}", vector.rules);
        };
        assert_eq!(got, requirement(&vector.state), "{:?}", vector.rules);
        assert_eq!(
            cause == Cause::ConflictingRules,
            vector.conflict,
            "{:?}",
            vector.rules
        );
        assert_eq!(winners, expected_winners, "{:?}", vector.rules);
        conflicts += usize::from(vector.conflict);
    }
    assert_eq!(conflicts, 465, "the grid must exercise conflicts");
}

#[test]
fn no_rules_fired_is_not_an_answer_unlike_the_donor() {
    assert_eq!(evaluate_precedence(&[]), Resolution::NoRuleFired);
}

#[test]
fn emergency_fails_closed_at_any_precedence_unlike_the_donor() {
    for rules in [
        vec![rule("e", 1, EMERGENCY)],
        vec![rule("a", 1, ASK_MORE), rule("e", 9, EMERGENCY)],
        vec![rule("e", 1, EMERGENCY), rule("x", 1, ESCALATE)],
    ] {
        assert_eq!(
            evaluate_precedence(&rules),
            Resolution::Decided {
                requirement: ABSTAIN,
                cause: Cause::EmergencyDisabled,
                winners: vec!["e".to_owned()],
            }
        );
    }
}

#[test]
fn a_revoked_rule_fails_the_whole_evaluation_closed() {
    let mut revoked = rule("r", 9, ASK_MORE);
    revoked.revoked = true;
    assert_eq!(
        evaluate_precedence(&[rule("a", 1, ESCALATE), revoked]),
        Resolution::Decided {
            requirement: ABSTAIN,
            cause: Cause::RevokedRule,
            winners: vec!["r".to_owned()],
        }
    );
}

#[test]
fn donor_named_conflict_cases_hold() {
    let use_tool = Requirement::Action(ControlAction::UseTool);
    let retrieve = Requirement::Action(ControlAction::RetrieveEvidence);
    let Resolution::Decided {
        requirement, cause, ..
    } = evaluate_precedence(&[rule("a", 5, use_tool), rule("b", 5, retrieve)])
    else {
        panic!("expected a decision");
    };
    assert_eq!((requirement, cause), (ABSTAIN, Cause::ConflictingRules));
    let Resolution::Decided {
        requirement, cause, ..
    } = evaluate_precedence(&[rule("a", 4, ESCALATE), rule("b", 4, ASK_MORE)])
    else {
        panic!("expected a decision");
    };
    assert_eq!((requirement, cause), (ESCALATE, Cause::ConflictingRules));
}

//! TA-13's fixture subset as amended by `plan-v1.4`: the rules the donor's own pipeline fired on its
//! fixture cases, from `bench/oracles/commandmed_spec006/generate_case_vectors.py`, resolve to its state.
//! This is resolution only. The mechanics vectors carry precedence and conflict behaviour: every case
//! here fires one rule or none, so this mainly checks real rule identities pass through unchanged.

use safeevidence_assurance::{Cause, FiredRule, Requirement, Resolution, evaluate_precedence};
use safeevidence_contracts::assurance::{ControlAction, TerminalOutcome};
use serde::Deserialize;

const FILES: [&str; 3] = [
    include_str!("fixtures/t13_cases_us1_tool_routing.json"),
    include_str!("fixtures/t13_cases_us2_context_safety.json"),
    include_str!("fixtures/t13_cases_us3_injection_spoof.json"),
];
const TOOL_LAYER: &str = "SCAFFOLD::TOOL_LAYER";
const MISSING_DOSE: &str = "R006-DOSAGE-INTENT-INCOMPLETE-V1";
type PinnedCase = (&'static str, Option<(&'static str, u32)>, &'static str);

/// Case, rule the donor fired with its precedence, and final state, so a changed fixture fails here.
const INCLUDED: [PinnedCase; 12] = [
    (
        "tool-available-routes-to-tool",
        Some((TOOL_LAYER, 6)),
        "USE_TOOL",
    ),
    (
        "evidence-class-retrieves-evidence",
        Some((TOOL_LAYER, 6)),
        "RETRIEVE_EVIDENCE",
    ),
    ("no-requested-tool-plain-answer", None, "ANSWER"),
    (
        "unknown-tool-fails-closed",
        Some((TOOL_LAYER, 6)),
        "ABSTAIN",
    ),
    (
        "clinical-score-gate-closed-t017",
        Some((TOOL_LAYER, 6)),
        "ABSTAIN",
    ),
    (
        "interaction-lookup-gate-closed-t018",
        Some((TOOL_LAYER, 6)),
        "ABSTAIN",
    ),
    (
        "tool-unavailable-fails-closed",
        Some((TOOL_LAYER, 6)),
        "ABSTAIN",
    ),
    (
        "tool-timeout-fails-closed",
        Some((TOOL_LAYER, 6)),
        "ABSTAIN",
    ),
    (
        "missing-slot-asks-more-en",
        Some((MISSING_DOSE, 7)),
        "ASK_MORE",
    ),
    (
        "injection-suppressed-missing-slot-preserved",
        Some((MISSING_DOSE, 7)),
        "ASK_MORE",
    ),
    (
        "spoofed-provenance-rejected",
        Some((TOOL_LAYER, 6)),
        "ABSTAIN",
    ),
    (
        "genuine-provenance-accepted",
        Some((TOOL_LAYER, 6)),
        "USE_TOOL",
    ),
];

#[derive(Deserialize)]
struct Document {
    commit: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    excluded_reason: Option<String>,
    fired: Vec<(String, u32, String)>,
    donor_state: Option<String>,
}

fn requirement(state: &str) -> Requirement {
    match state {
        "ASK_MORE" => Requirement::Outcome(TerminalOutcome::AskMore),
        "ABSTAIN" => Requirement::Outcome(TerminalOutcome::Abstain),
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
fn the_subset_is_the_seventeen_donor_cases_less_the_five_listed_exclusions() {
    let cases = cases();
    assert_eq!(cases.len(), 17);
    let mut excluded: Vec<&str> = cases
        .iter()
        .filter(|case| case.excluded_reason.is_some())
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
            "severe-pattern-escalates",
        ]
    );
    for case in cases.iter().filter(|case| case.excluded_reason.is_some()) {
        assert!(case.fired.is_empty() && case.donor_state.is_none());
        assert!(
            !case
                .excluded_reason
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        );
    }
}

#[test]
fn the_included_fixtures_are_the_pinned_rules_and_states() {
    let cases = cases();
    let included: Vec<&Case> = cases
        .iter()
        .filter(|case| case.excluded_reason.is_none())
        .collect();
    assert_eq!(included.len(), INCLUDED.len());
    for (id, rule, state) in INCLUDED {
        let case = included
            .iter()
            .find(|case| case.case_id == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        assert_eq!(case.donor_state.as_deref(), Some(state), "{id}");
        let fired: Vec<(&str, u32)> = case
            .fired
            .iter()
            .map(|(rule_id, precedence, _)| (rule_id.as_str(), *precedence))
            .collect();
        assert_eq!(fired, rule.into_iter().collect::<Vec<_>>(), "{id}");
    }
}

#[test]
fn every_included_case_resolves_the_donors_fired_rules_to_the_donors_state() {
    for case in cases().iter().filter(|case| case.excluded_reason.is_none()) {
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
    }
}

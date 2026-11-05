//! Exhaustive vocabulary and state-machine checks against the P00 contracts.

use safeevidence_contracts::assurance::{ControlAction, ProofState, ReasonCode, TerminalOutcome};
use serde::de::DeserializeOwned;

const STATES: [ProofState; 8] = [
    ProofState::DraftPrivate,
    ProofState::CandidateFrozen,
    ProofState::Verifying,
    ProofState::VerifiedUncommitted,
    ProofState::Committed,
    ProofState::Rejected,
    ProofState::CurrentlyInvalidated,
    ProofState::CurrentnessUnknown,
];

fn parses<T: DeserializeOwned>(wire: &str) -> bool {
    serde_json::from_str::<T>(&format!("\"{wire}\"")).is_ok()
}

#[test]
fn every_contract_wire_name_parses() {
    for wire in ["RETRIEVE_EVIDENCE", "USE_TOOL", "REQUEST_CONTEXT"] {
        assert!(parses::<ControlAction>(wire), "{wire}");
    }
    for wire in [
        "ANSWER",
        "ANSWER_WITH_CAUTION",
        "ASK_MORE",
        "CONFLICT",
        "ABSTAIN",
        "ESCALATE",
        "BLOCKED",
        "EMERGENCY_NOTICE",
    ] {
        assert!(parses::<TerminalOutcome>(wire), "{wire}");
    }
    for wire in [
        "SECURITY_DENIED",
        "RIGHTS_UNRESOLVED",
        "SOURCE_UNAVAILABLE",
        "SOURCE_INVALID_OR_RETRACTED",
        "EVIDENCE_INSUFFICIENT",
        "MISSING_CRITICAL_CONTEXT",
        "APPLICABILITY_UNRESOLVED",
        "MATERIAL_CONTRADICTION",
        "TOOL_FAILURE",
        "TIME_BUDGET_EXHAUSTED",
        "CLINICIAN_AUTHORITY_REQUIRED",
        "POST_VERIFICATION_FAILED",
        "PROOF_RACE_INVALIDATED",
        "CURRENTNESS_UNKNOWN",
        "NONE",
    ] {
        assert!(parses::<ReasonCode>(wire), "{wire}");
    }
}

#[test]
fn actions_are_not_outcomes_and_unknown_codes_are_rejected() {
    assert!(!parses::<TerminalOutcome>("RETRIEVE_EVIDENCE"));
    assert!(!parses::<ControlAction>("ANSWER"));
    assert!(!parses::<ReasonCode>("NO_EVIDENCE"));
    assert!(!parses::<TerminalOutcome>("answer"));
}

#[test]
fn only_answers_may_commit() {
    use TerminalOutcome::{
        Abstain, Answer, AnswerWithCaution, AskMore, Blocked, Conflict, EmergencyNotice, Escalate,
    };
    assert!(Answer.may_commit() && AnswerWithCaution.may_commit());
    for outcome in [
        AskMore,
        Conflict,
        Abstain,
        Escalate,
        Blocked,
        EmergencyNotice,
    ] {
        assert!(!outcome.may_commit(), "{outcome:?}");
    }
}

#[test]
fn proof_transitions_are_exactly_the_allowed_set() {
    use ProofState::{
        CandidateFrozen, Committed, CurrentlyInvalidated, CurrentnessUnknown, DraftPrivate,
        Rejected, VerifiedUncommitted, Verifying,
    };
    let allowed = [
        (DraftPrivate, CandidateFrozen),
        (CandidateFrozen, Verifying),
        (Verifying, VerifiedUncommitted),
        (Verifying, Rejected),
        (VerifiedUncommitted, Committed),
        (VerifiedUncommitted, Rejected),
        (Committed, CurrentlyInvalidated),
        (Committed, CurrentnessUnknown),
        (CurrentnessUnknown, CurrentlyInvalidated),
    ];
    for from in STATES {
        for to in STATES {
            assert_eq!(
                from.may_transition_to(to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn nothing_reaches_committed_except_from_verified() {
    for from in STATES {
        assert_eq!(
            from.may_transition_to(ProofState::Committed),
            from == ProofState::VerifiedUncommitted,
            "{from:?}"
        );
    }
}

#[test]
fn stale_proof_cannot_regain_assured_status() {
    for to in STATES {
        assert_eq!(
            ProofState::CurrentnessUnknown.may_transition_to(to),
            to == ProofState::CurrentlyInvalidated,
            "{to:?}"
        );
    }
}

#[test]
fn proof_state_wire_names_match_the_contract() {
    for (state, wire) in [
        (ProofState::DraftPrivate, "DRAFT_PRIVATE"),
        (ProofState::CandidateFrozen, "CANDIDATE_FROZEN"),
        (ProofState::Verifying, "VERIFYING"),
        (ProofState::VerifiedUncommitted, "VERIFIED_UNCOMMITTED"),
        (ProofState::Committed, "COMMITTED"),
        (ProofState::Rejected, "REJECTED"),
        (ProofState::CurrentlyInvalidated, "CURRENTLY_INVALIDATED"),
        (ProofState::CurrentnessUnknown, "CURRENTNESS_UNKNOWN"),
    ] {
        assert_eq!(
            serde_json::to_string(&state).unwrap(),
            format!("\"{wire}\"")
        );
    }
}

#[test]
fn rejected_and_invalidated_are_terminal() {
    for to in STATES {
        assert!(!ProofState::Rejected.may_transition_to(to));
        assert!(!ProofState::CurrentlyInvalidated.may_transition_to(to));
    }
}

#[test]
fn only_committed_is_currently_assured() {
    for state in STATES {
        assert_eq!(state.is_currently_assured(), state == ProofState::Committed);
    }
}

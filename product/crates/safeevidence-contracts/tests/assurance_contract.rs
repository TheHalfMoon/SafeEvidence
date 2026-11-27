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
        "UNSUPPORTED_LANGUAGE",
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

#[test]
fn doctor_ready_base_never_claims_scale_corpus_generator_or_clinical_quality() {
    use safeevidence_contracts::evidence::EvidenceCorpusDoctorStatus;

    let status = EvidenceCorpusDoctorStatus::ready_base("synthetic-lexical", "0.1.0");
    assert!(!status.scale_corpus_generator_present);
    assert!(!status.clinical_quality_claimed);
    assert!(!status.release_ready);
    assert_eq!(status.validate_non_clinical(), Ok(()));

    let mut invalid = status.clone();
    invalid.scale_corpus_generator_present = true;
    assert!(invalid.validate_non_clinical().is_err());
}

#[test]
fn t01_proposal_and_confidence_fields_are_gated_from_assured_v1_surfaces() {
    use safeevidence_contracts::AUTHORITY_SCHEMA_VERSION;
    use safeevidence_contracts::assurance::AssuredSurfaceGateError;
    use safeevidence_contracts::objects::{
        AuthorityScopeId, ClinicalAssertion, IdentityAssertion, MedicalTime, ObjectHeader,
        OpaqueId, ProducerKind, Proposal, RealmId, TimePrecision,
    };

    let header = ObjectHeader {
        id: OpaqueId::new("obj-1"),
        schema_version: AUTHORITY_SCHEMA_VERSION,
        realm_id: RealmId::new("synthetic"),
        authority_scope_id: AuthorityScopeId::new("local"),
    };
    let mut proposal = Proposal {
        header: header.clone(),
        subject_ref: Some(OpaqueId::new("subj-1")),
        claim_kind: "finding".to_owned(),
        payload: serde_json::json!({"direction": "improved"}),
        confidence: Some(0.85),
        evidence_refs: vec![OpaqueId::new("src-1")],
        producer: ProducerKind::Rule,
    };
    assert_eq!(
        proposal.validate_assured_surface(),
        Err(AssuredSurfaceGateError::ProposalCannotReachAssuredSurface)
    );
    assert_eq!(proposal.validate_internal_candidate(), Ok(()));
    proposal.confidence = Some(1.5);
    assert_eq!(
        proposal.validate_internal_candidate(),
        Err(AssuredSurfaceGateError::InvalidProposalConfidence)
    );

    let mut assertion = ClinicalAssertion {
        header: header.clone(),
        subject_ref: OpaqueId::new("subj-1"),
        claim_kind: "finding".to_owned(),
        payload: serde_json::json!({"effect": "improved"}),
        promoted_from_proposal_id: Some(OpaqueId::new("prop-1")),
        authorized_by: OpaqueId::new("clinician-1"),
        effective_time: None,
        recorded_time: MedicalTime::new("2026-11-26T00:00:00Z", TimePrecision::Instant, false),
    };
    assert_eq!(assertion.validate_p00_contract(), Ok(()));
    for bad_payload in [
        serde_json::json!({"nested": {"confidence_pct": 92}}),
        serde_json::json!({"nested": {"confidencePct": 92}}),
        serde_json::json!({"nested": {"clinical-confidence": 0.9}}),
    ] {
        assertion.payload = bad_payload;
        assert_eq!(
            assertion.validate_p00_contract(),
            Err(AssuredSurfaceGateError::ForbiddenConfidenceField)
        );
    }

    let mut identity = IdentityAssertion {
        header,
        subject_id: OpaqueId::new("subj-1"),
        identifier_system: "nct".to_owned(),
        identifier_value: "NCT00000001".to_owned(),
        confidence: None,
        evidence_refs: vec![OpaqueId::new("src-1")],
    };
    assert_eq!(identity.validate_assured_surface(), Ok(()));
    identity.confidence = Some(0.99);
    assert_eq!(
        identity.validate_assured_surface(),
        Err(AssuredSurfaceGateError::ForbiddenConfidenceField)
    );
}

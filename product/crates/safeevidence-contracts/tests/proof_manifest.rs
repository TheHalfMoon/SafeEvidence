//! Shape rules for `AnswerProofManifest`. Synthetic values only.

use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{
    AnswerProofManifest, ApplicabilityState, ContradictionState, EvidenceSpan, ManifestDefect,
    ProofClaim, ProofComponents, SupportLabel, commit_defects,
};
use safeevidence_contracts::study::{
    Known, PublicationState, ReportId, ReportVersionId, ReportVersionKind, ReportVersionLink,
    ScopedId, ValidityEpoch,
};

fn digest() -> DigestSha256 {
    DigestSha256::of(b"synthetic")
}

fn span() -> EvidenceSpan {
    EvidenceSpan {
        source_id: "synthetic-source".into(),
        source_version: "1".into(),
        source_digest: digest(),
        start_scalar: 3,
        end_scalar: 9,
    }
}

fn claim(id: &str) -> ProofClaim {
    ProofClaim {
        claim_id: id.into(),
        material: true,
        support: SupportLabel::Supported,
        spans: vec![span()],
        studies: Known::Known(vec![]),
        results: Known::Known(vec![]),
    }
}

fn manifest() -> AnswerProofManifest {
    AnswerProofManifest {
        proof_id: "proof-1".into(),
        question_snapshot_digest: digest(),
        final_text_digest: digest(),
        claims: vec![claim("c1")],
        rights_grant_version: "rights-1".into(),
        validity_epoch: 1,
        components: ProofComponents {
            retriever: "fts5-1".into(),
            reranker: None,
            translator: None,
            ocr: None,
            verifier: "deterministic-1".into(),
            generator: None,
            tools: vec![],
            prompts: vec![],
            policy: "policy-1".into(),
            thresholds: "thresholds-1".into(),
        },
        applicability: ApplicabilityState::Applicable,
        contradiction: ContradictionState::None,
        outcome: TerminalOutcome::AnswerWithCaution,
        reason: ReasonCode::None,
        post_verification_passed: true,
        verified_at_utc: "2026-11-05T00:00:00Z".into(),
        state: ProofState::VerifiedUncommitted,
    }
}

#[test]
fn well_formed_manifest_has_no_defects() {
    assert!(commit_defects(&manifest()).is_empty());
}

#[test]
fn every_non_supported_material_claim_is_refused_even_with_caution() {
    for support in [
        SupportLabel::Unsupported,
        SupportLabel::Contradicted,
        SupportLabel::Unverifiable,
    ] {
        let mut value = manifest();
        value.claims.push(ProofClaim {
            support,
            ..claim("c2")
        });
        assert_eq!(
            commit_defects(&value),
            vec![ManifestDefect::MaterialClaimNotSupported("c2".into())]
        );
    }
}

#[test]
fn immaterial_unsupported_claim_does_not_block_but_material_claim_is_required() {
    let mut value = manifest();
    value.claims.push(ProofClaim {
        material: false,
        support: SupportLabel::Unsupported,
        spans: vec![],
        ..claim("c2")
    });
    assert!(commit_defects(&value).is_empty());
    value.claims.remove(0);
    assert!(commit_defects(&value).contains(&ManifestDefect::NoMaterialClaim));
}

#[test]
fn material_claim_needs_a_valid_span() {
    let mut value = manifest();
    value.claims[0].spans.clear();
    assert!(commit_defects(&value).contains(&ManifestDefect::ClaimWithoutSpan("c1".into())));
    let mut value = manifest();
    value.claims[0].spans[0].end_scalar = 3;
    assert!(commit_defects(&value).contains(&ManifestDefect::InvalidSpan("c1".into())));
}

#[test]
fn non_committing_outcomes_are_refused() {
    for outcome in [
        TerminalOutcome::AskMore,
        TerminalOutcome::Conflict,
        TerminalOutcome::Abstain,
        TerminalOutcome::Escalate,
        TerminalOutcome::Blocked,
        TerminalOutcome::EmergencyNotice,
    ] {
        let mut value = manifest();
        value.outcome = outcome;
        assert!(commit_defects(&value).contains(&ManifestDefect::OutcomeCannotCommit));
    }
}

#[test]
fn only_verified_or_committed_states_can_commit() {
    for state in [
        ProofState::DraftPrivate,
        ProofState::CandidateFrozen,
        ProofState::Verifying,
        ProofState::Rejected,
        ProofState::CurrentlyInvalidated,
        ProofState::CurrentnessUnknown,
    ] {
        let mut value = manifest();
        value.state = state;
        assert_eq!(
            commit_defects(&value),
            vec![ManifestDefect::StateCannotCommit],
            "{state:?}"
        );
    }
    let mut value = manifest();
    value.state = ProofState::Committed;
    assert!(commit_defects(&value).is_empty());
}

#[test]
fn every_denying_reason_is_refused() {
    for reason in [
        ReasonCode::SecurityDenied,
        ReasonCode::RightsUnresolved,
        ReasonCode::SourceUnavailable,
        ReasonCode::SourceInvalidOrRetracted,
        ReasonCode::EvidenceInsufficient,
        ReasonCode::MissingCriticalContext,
        ReasonCode::ApplicabilityUnresolved,
        ReasonCode::MaterialContradiction,
        ReasonCode::ToolFailure,
        ReasonCode::TimeBudgetExhausted,
        ReasonCode::ClinicianAuthorityRequired,
        ReasonCode::PostVerificationFailed,
        ReasonCode::ProofRaceInvalidated,
        ReasonCode::UnsupportedLanguage,
    ] {
        let mut value = manifest();
        value.reason = reason;
        assert_eq!(
            commit_defects(&value),
            vec![ManifestDefect::ReasonForbidsCommit],
            "{reason:?}"
        );
    }
}

#[test]
fn stated_limits_need_the_caution_outcome() {
    let mut value = manifest();
    value.reason = ReasonCode::CurrentnessUnknown;
    assert!(commit_defects(&value).is_empty());
    value.outcome = TerminalOutcome::Answer;
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::LimitsRequireCaution]
    );

    let mut value = manifest();
    value.applicability = ApplicabilityState::ApplicableWithLimits;
    assert!(commit_defects(&value).is_empty());
    value.outcome = TerminalOutcome::Answer;
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::LimitsRequireCaution]
    );

    let mut value = manifest();
    value.outcome = TerminalOutcome::Answer;
    assert!(commit_defects(&value).is_empty());
}

#[test]
fn material_contradiction_and_failed_applicability_are_refused() {
    let mut value = manifest();
    value.contradiction = ContradictionState::Material;
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::MaterialContradiction]
    );
    let mut value = manifest();
    value.contradiction = ContradictionState::NonMaterial;
    assert!(commit_defects(&value).is_empty());
    for applicability in [
        ApplicabilityState::Unresolved,
        ApplicabilityState::NotApplicable,
    ] {
        let mut value = manifest();
        value.applicability = applicability;
        assert_eq!(
            commit_defects(&value),
            vec![ManifestDefect::ApplicabilityForbidsCommit]
        );
    }
}

#[test]
fn blank_identities_and_zero_epoch_are_refused() {
    let setters: [fn(&mut AnswerProofManifest); 7] = [
        |m| m.proof_id = " ".into(),
        |m| m.verified_at_utc = String::new(),
        |m| m.components.retriever = String::new(),
        |m| m.components.verifier = String::new(),
        |m| m.components.policy = String::new(),
        |m| m.components.thresholds = String::new(),
        |m| m.claims[0].claim_id = " ".into(),
    ];
    for set in setters {
        let mut value = manifest();
        set(&mut value);
        assert_eq!(
            commit_defects(&value),
            vec![ManifestDefect::MissingIdentity]
        );
    }
    let mut value = manifest();
    value.validity_epoch = 0;
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::MissingValidityEpoch]
    );
}

#[test]
fn span_with_end_before_start_is_refused() {
    let mut value = manifest();
    value.claims[0].spans[0].end_scalar = 2;
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::InvalidSpan("c1".into())]
    );
    value.claims[0].spans[0].end_scalar = 4;
    assert!(commit_defects(&value).is_empty());
}

#[test]
fn only_current_publication_state_is_citable() {
    for (state, citable) in [
        (PublicationState::Current, true),
        (PublicationState::Corrected, false),
        (PublicationState::ExpressionOfConcern, false),
        (PublicationState::Retracted, false),
        (PublicationState::Withdrawn, false),
        (PublicationState::Superseded, false),
        (PublicationState::Unknown, false),
    ] {
        assert_eq!(state.citable(), citable, "{state:?}");
    }
}

#[test]
fn only_established_rights_are_admissible() {
    for (rights, admissible) in [
        (EvidenceCorpusRights::SyntheticOwned, true),
        (EvidenceCorpusRights::PublicDomain, true),
        (EvidenceCorpusRights::OpenLicense, true),
        (EvidenceCorpusRights::Restricted, false),
        (EvidenceCorpusRights::Unknown, false),
    ] {
        assert_eq!(rights.admissible(), admissible, "{rights:?}");
    }
}

#[test]
fn notices_cannot_leave_their_target_looking_current() {
    let id = || ScopedId {
        scope: "synthetic".into(),
        id: "r".into(),
        version: 1,
    };
    let link = |kind, publication_state| ReportVersionLink {
        report: ReportId(id()),
        version: ReportVersionId(id()),
        kind,
        links_to: None,
        publication_state,
        validity_epoch: ValidityEpoch(1),
    };
    assert!(!link(ReportVersionKind::Retraction, PublicationState::Current).is_consistent());
    assert!(link(ReportVersionKind::Retraction, PublicationState::Retracted).is_consistent());
    assert!(!link(ReportVersionKind::Correction, PublicationState::Current).is_consistent());
    assert!(link(ReportVersionKind::Correction, PublicationState::Corrected).is_consistent());
    assert!(
        !link(
            ReportVersionKind::ExpressionOfConcern,
            PublicationState::Current
        )
        .is_consistent()
    );
    assert!(link(ReportVersionKind::Published, PublicationState::Current).is_consistent());
}

#[test]
fn failed_verification_missing_rights_and_duplicates_are_refused() {
    let mut value = manifest();
    value.post_verification_passed = false;
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::PostVerificationFailed]
    );
    let mut value = manifest();
    value.rights_grant_version = " ".into();
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::MissingRightsGrant]
    );
    let mut value = manifest();
    value.claims.push(claim("c1"));
    assert_eq!(
        commit_defects(&value),
        vec![ManifestDefect::DuplicateClaimId("c1".into())]
    );
}

#[test]
fn manifest_rejects_a_confidence_field_on_the_wire() {
    let mut json = serde_json::to_value(manifest()).unwrap();
    json["confidence"] = serde_json::json!(0.97);
    assert!(serde_json::from_value::<AnswerProofManifest>(json.clone()).is_err());
    json.as_object_mut().unwrap().remove("confidence");
    assert_eq!(
        serde_json::from_value::<AnswerProofManifest>(json).unwrap(),
        manifest()
    );
}

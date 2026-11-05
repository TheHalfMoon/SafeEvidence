//! Shape rules for `AnswerProofManifest`. Synthetic values only.

use safeevidence_contracts::assurance::{ProofState, ReasonCode, TerminalOutcome};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::{
    AnswerProofManifest, EvidenceSpan, ManifestDefect, ProofClaim, ProofComponents, SupportLabel,
    commit_defects,
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
        studies: vec![],
        results: vec![],
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
            policy: "policy-1".into(),
            thresholds: "thresholds-1".into(),
        },
        applicability: "applicable".into(),
        contradiction: "none".into(),
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
fn assured_state_with_a_non_committing_outcome_is_flagged() {
    let mut value = manifest();
    value.outcome = TerminalOutcome::Abstain;
    value.state = ProofState::Committed;
    assert!(commit_defects(&value).contains(&ManifestDefect::AssuredStateWithoutCommit));
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

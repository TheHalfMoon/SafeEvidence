//! `WP-10` / `TA-12`: Risk-of-Bias profiles (`RoB 2`, `ROBINS-I`, `QUADAS-2`, `AMSTAR 2`),
//! 8-domain `GRADE` certainty assembly, mandatory human confirmation gate, and EBMonFHIR JSON
//! crosswalk validation (`T26` standard reference).

use safeevidence_contracts::appraisal::{
    AppraisalConfirmation, AppraisalError, BiasLevel, CertaintyAssessment, CertaintyLevel,
    DomainJudgment, DowngradeDomain, DowngradeStep, EBMONFHIR_CERTAINTY_PROFILE,
    EBMONFHIR_ROB_PROFILE, EbmArtifactAssessment, GradeCertaintyDomains, RiskOfBiasAssessment,
    RiskOfBiasTool, StartingDesign, UpgradeDomain, UpgradeStep, build_summary_of_findings_row,
    export_certainty_to_ebmonfhir_json, export_rob_to_ebmonfhir_json,
    validate_ebmonfhir_assessment,
};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::proof::EvidenceSpan;
use safeevidence_contracts::study::{OutcomeId, ReportVersionId, ScopedId, StudyId};

fn sid(id: &str) -> ScopedId {
    ScopedId {
        scope: "ta12-synthetic".to_owned(),
        id: id.to_owned(),
        version: 1,
    }
}

fn sample_span() -> EvidenceSpan {
    EvidenceSpan {
        source_id: "doc-synthetic-1".to_owned(),
        source_version: "1".to_owned(),
        source_digest: DigestSha256::of(b"synthetic trial methods paragraph"),
        start_scalar: 0,
        end_scalar: 33,
    }
}

fn clean_grade_domains() -> GradeCertaintyDomains {
    GradeCertaintyDomains {
        risk_of_bias: DowngradeDomain {
            step: DowngradeStep::None,
            reason: "Centralized allocation concealment and blinded outcome adjudication."
                .to_owned(),
        },
        inconsistency: DowngradeDomain {
            step: DowngradeStep::None,
            reason: "Consistent effect direction across both independent synthetic trials."
                .to_owned(),
        },
        indirectness: DowngradeDomain {
            step: DowngradeStep::SeriousMinusOne,
            reason: "Surrogate 12-week scale endpoint rather than 52-week functional remission."
                .to_owned(),
        },
        imprecision: DowngradeDomain {
            step: DowngradeStep::None,
            reason: "Sample size meets optimal information size without crossing null.".to_owned(),
        },
        publication_bias: DowngradeDomain {
            step: DowngradeStep::None,
            reason: "All registered trials reported results matching protocol.".to_owned(),
        },
        large_magnitude_of_effect: UpgradeDomain {
            step: UpgradeStep::None,
            reason: "Not applicable to downgraded randomized trial body.".to_owned(),
        },
        dose_response_gradient: UpgradeDomain {
            step: UpgradeStep::None,
            reason: "Single fixed dose evaluated.".to_owned(),
        },
        plausible_residual_confounding: UpgradeDomain {
            step: UpgradeStep::None,
            reason: "No residual confounding expected in randomized design.".to_owned(),
        },
    }
}

#[test]
fn all_four_rob_instruments_enforce_complete_domains_and_rationales() {
    for tool in [
        RiskOfBiasTool::Rob2,
        RiskOfBiasTool::RobinsI,
        RiskOfBiasTool::Quadas2,
        RiskOfBiasTool::Amstar2,
    ] {
        let domains: Vec<DomainJudgment> = tool
            .required_domains()
            .iter()
            .map(|&code| DomainJudgment {
                domain_code: code.to_owned(),
                level: BiasLevel::Low,
                rationale: format!("Synthetic methods text addresses {code}."),
                supporting_spans: vec![sample_span()],
            })
            .collect();
        let mut rob = RiskOfBiasAssessment {
            assessment_id: format!("rob-{tool:?}").to_ascii_lowercase(),
            study: StudyId(sid("study-1")),
            report_version: ReportVersionId(sid("report-1")),
            outcome: OutcomeId(sid("outcome-1")),
            tool,
            domains,
            overall: BiasLevel::Low,
            overall_rationale: "All instrument domains rated low risk on synthetic fixture."
                .to_owned(),
            confirmation: AppraisalConfirmation::Confirmed {
                authorized_by: "reviewer-clinician-01".to_owned(),
                confirmed_at_utc: "2026-11-26T12:00:00Z".to_owned(),
            },
        };
        rob.validate().expect("complete instrument validates");

        let json = export_rob_to_ebmonfhir_json(&rob).expect("EBMonFHIR RoB export");
        let parsed: EbmArtifactAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.meta.profile, vec![EBMONFHIR_ROB_PROFILE]);
        validate_ebmonfhir_assessment(&parsed).expect("exported RoB validates");

        // Removing a required domain or blanking a domain rationale must fail closed:
        let mut missing_reason = rob.clone();
        missing_reason.domains[0].rationale = "   ".to_owned();
        assert!(matches!(
            missing_reason.validate(),
            Err(AppraisalError::EmptyDomainReason(_))
        ));

        rob.domains.pop();
        assert!(matches!(
            rob.validate(),
            Err(AppraisalError::MissingDomain(_))
        ));
    }
}

#[test]
fn ta12_certainty_enforces_domain_reasons_human_actor_gate_and_ebmonfhir_schema() {
    let domains = clean_grade_domains();
    assert_eq!(
        domains.compute_certainty(StartingDesign::RandomizedTrial),
        CertaintyLevel::Moderate
    );

    // 1. Proposed rating validates structurally, exports as PROPOSED, and NEVER qualifies as
    // human-confirmed assured appraisal.
    let proposed = CertaintyAssessment {
        assessment_id: "cert-veltrix-01".to_owned(),
        outcome: OutcomeId(sid("out-glimmer-12w")),
        studies: vec![StudyId(sid("study-1")), StudyId(sid("study-2"))],
        starting_design: StartingDesign::RandomizedTrial,
        domains: domains.clone(),
        final_certainty: CertaintyLevel::Moderate,
        summary_rationale: "Moderate certainty due to serious indirectness of 12-week endpoint."
            .to_owned(),
        confirmation: AppraisalConfirmation::Proposed {
            generator: "rule-draft-v1".to_owned(),
        },
    };
    proposed.validate().expect("proposed validates");
    assert!(!proposed.qualifies_for_assured_surface());

    let proposed_json = export_certainty_to_ebmonfhir_json(&proposed).unwrap();
    assert!(!proposed_json.to_ascii_lowercase().contains("confidence"));
    assert!(!proposed_json.contains('%'));
    let parsed_proposed: EbmArtifactAssessment = serde_json::from_str(&proposed_json).unwrap();
    assert_eq!(parsed_proposed.content[0].workflow_status, "PROPOSED");
    assert!(parsed_proposed.content[0].author.is_none());

    // 2. Confirmed rating WITHOUT human actor ID is rejected (`TA-12` mandatory rule):
    let mut missing_actor = proposed.clone();
    missing_actor.confirmation = AppraisalConfirmation::Confirmed {
        authorized_by: "   ".to_owned(),
        confirmed_at_utc: "2026-11-26T12:00:00Z".to_owned(),
    };
    assert_eq!(
        missing_actor.validate(),
        Err(AppraisalError::EmptyConfirmedActor)
    );
    assert!(!missing_actor.qualifies_for_assured_surface());

    // 3. Confirmed rating WITH human actor ID validates, qualifies, and exports to both
    // EBMonFHIR `ArtifactAssessment` and `SummaryOfFindingsRow`:
    let mut confirmed = proposed.clone();
    confirmed.confirmation = AppraisalConfirmation::Confirmed {
        authorized_by: "dr-amira-hassan".to_owned(),
        confirmed_at_utc: "2026-11-26T12:05:00Z".to_owned(),
    };
    assert!(confirmed.qualifies_for_assured_surface());

    let confirmed_json = export_certainty_to_ebmonfhir_json(&confirmed).unwrap();
    let parsed_confirmed: EbmArtifactAssessment = serde_json::from_str(&confirmed_json).unwrap();
    assert_eq!(
        parsed_confirmed.meta.profile,
        vec![EBMONFHIR_CERTAINTY_PROFILE]
    );
    assert_eq!(parsed_confirmed.content[0].workflow_status, "CONFIRMED");
    assert_eq!(
        parsed_confirmed.content[0].author.as_deref(),
        Some("dr-amira-hassan")
    );
    assert_eq!(parsed_confirmed.content[0].components.len(), 8);
    validate_ebmonfhir_assessment(&parsed_confirmed).expect("pinned EBMonFHIR schema passes");

    let sof = build_summary_of_findings_row(
        &confirmed,
        "12-week synthetic glimmer composite score",
        Some(550),
        "Mean difference -4.2 points vs placebo across 2 RCTs",
    )
    .expect("SoF row builds");
    assert_eq!(sof.certainty, CertaintyLevel::Moderate);
    assert_eq!(sof.certainty_reasons.len(), 8);
    assert_eq!(sof.authorized_by.as_deref(), Some("dr-amira-hassan"));

    // 4. Empty reason in any of the 8 domains, arithmetic mismatch, or upgrade+downgrade mix fails:
    let mut empty_pub_bias = confirmed.clone();
    empty_pub_bias.domains.publication_bias.reason.clear();
    assert_eq!(
        empty_pub_bias.validate(),
        Err(AppraisalError::EmptyDomainReason(
            "publication_bias".to_owned()
        ))
    );

    let mut wrong_level = confirmed.clone();
    wrong_level.final_certainty = CertaintyLevel::High;
    assert!(matches!(
        wrong_level.validate(),
        Err(AppraisalError::CertaintyArithmeticMismatch {
            expected: CertaintyLevel::Moderate,
            declared: CertaintyLevel::High
        })
    ));

    let mut upgrade_with_downgrade = confirmed;
    upgrade_with_downgrade
        .domains
        .large_magnitude_of_effect
        .step = UpgradeStep::PlusOne;
    assert_eq!(
        upgrade_with_downgrade.validate(),
        Err(AppraisalError::UpgradeForbiddenAfterDowngrade)
    );
}

//! Structured study risk-of-bias profiles, GRADE certainty assembly, and EBMonFHIR JSON crosswalk
//! (`WP-10`, `TA-12`; `SOURCE_TRANSPLANT_MATRIX_V1` section 5 + `T26` `HL7/ebm` standard reference).
//!
//! Invariants (`TA-12`):
//! 1. Every domain judgment and certainty domain adjustment carries a non-empty human-readable reason.
//! 2. No appraisal or certainty rating may enter `Confirmed` state without a non-empty human
//!    `authorized_by` actor identifier (`Proposed` records never satisfy quality-appraisal gates).
//! 3. Exported EBMonFHIR `ArtifactAssessment` and Summary-of-Findings JSON objects carry zero
//!    numeric confidence percentages (`D-13`) and validate deterministically against pinned profile
//!    constraints.

use serde::{Deserialize, Serialize};

use crate::proof::EvidenceSpan;
use crate::study::{OutcomeId, ReportVersionId, StudyId};

pub const EBMONFHIR_CERTAINTY_PROFILE: &str =
    "http://hl7.org/fhir/uv/ebm/StructureDefinition/certainty-of-evidence";
pub const EBMONFHIR_ROB_PROFILE: &str =
    "http://hl7.org/fhir/uv/ebm/StructureDefinition/risk-of-bias";

/// Proposal vs human-confirmed governance state (`WP-10` / `TA-12`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum AppraisalConfirmation {
    Proposed {
        generator: String,
    },
    Confirmed {
        authorized_by: String,
        confirmed_at_utc: String,
    },
}

impl AppraisalConfirmation {
    #[must_use]
    pub const fn is_human_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BiasLevel {
    Low,
    SomeConcerns,
    Moderate,
    Serious,
    Critical,
    High,
    NoInformation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainJudgment {
    pub domain_code: String,
    pub level: BiasLevel,
    pub rationale: String,
    pub supporting_spans: Vec<EvidenceSpan>,
}

/// Design-specific Risk-of-Bias instruments (`WP-10`: RoB 2, ROBINS-I, QUADAS-2, AMSTAR 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskOfBiasTool {
    Rob2,
    RobinsI,
    Quadas2,
    Amstar2,
}

impl RiskOfBiasTool {
    /// Required canonical domain codes for each instrument.
    #[must_use]
    pub const fn required_domains(self) -> &'static [&'static str] {
        match self {
            Self::Rob2 => &[
                "randomization_process",
                "deviations_from_intended_interventions",
                "missing_outcome_data",
                "measurement_of_outcome",
                "selection_of_reported_result",
            ],
            Self::RobinsI => &[
                "confounding",
                "selection_of_participants",
                "classification_of_interventions",
                "deviations_from_intended_interventions",
                "missing_data",
                "measurement_of_outcomes",
                "selection_of_reported_result",
            ],
            Self::Quadas2 => &[
                "patient_selection",
                "index_test",
                "reference_standard",
                "flow_and_timing",
            ],
            Self::Amstar2 => &[
                "protocol_registered",
                "literature_search_adequacy",
                "excluded_studies_justified",
                "risk_of_bias_assessed",
                "meta_analysis_methods_appropriate",
                "risk_of_bias_interpreted",
                "publication_bias_assessed",
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskOfBiasAssessment {
    pub assessment_id: String,
    pub study: StudyId,
    pub report_version: ReportVersionId,
    pub outcome: OutcomeId,
    pub tool: RiskOfBiasTool,
    pub domains: Vec<DomainJudgment>,
    pub overall: BiasLevel,
    pub overall_rationale: String,
    pub confirmation: AppraisalConfirmation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertaintyLevel {
    VeryLow,
    Low,
    Moderate,
    High,
}

impl CertaintyLevel {
    const fn rank(self) -> i8 {
        match self {
            Self::VeryLow => 1,
            Self::Low => 2,
            Self::Moderate => 3,
            Self::High => 4,
        }
    }

    const fn from_rank(rank: i8) -> Self {
        match rank {
            i8::MIN..=1 => Self::VeryLow,
            2 => Self::Low,
            3 => Self::Moderate,
            4..=i8::MAX => Self::High,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StartingDesign {
    RandomizedTrial,
    ObservationalStudy,
}

impl StartingDesign {
    #[must_use]
    pub const fn initial_certainty(self) -> CertaintyLevel {
        match self {
            Self::RandomizedTrial => CertaintyLevel::High,
            Self::ObservationalStudy => CertaintyLevel::Low,
        }
    }
}

/// Allowed downgrade magnitudes (`0`, `-1` serious, `-2` very serious / extremely serious).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DowngradeStep {
    None,
    SeriousMinusOne,
    VerySeriousMinusTwo,
}

impl DowngradeStep {
    const fn delta(self) -> i8 {
        match self {
            Self::None => 0,
            Self::SeriousMinusOne => -1,
            Self::VerySeriousMinusTwo => -2,
        }
    }
}

/// Allowed upgrade magnitudes (`0`, `+1` large effect / dose-response / plausible confounding, `+2` very large effect).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpgradeStep {
    None,
    PlusOne,
    PlusTwo,
}

impl UpgradeStep {
    const fn delta(self) -> i8 {
        match self {
            Self::None => 0,
            Self::PlusOne => 1,
            Self::PlusTwo => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DowngradeDomain {
    pub step: DowngradeStep,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeDomain {
    pub step: UpgradeStep,
    pub reason: String,
}

/// All 5 GRADE downgrade domains and 3 upgrade domains (`WP-10`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GradeCertaintyDomains {
    pub risk_of_bias: DowngradeDomain,
    pub inconsistency: DowngradeDomain,
    pub indirectness: DowngradeDomain,
    pub imprecision: DowngradeDomain,
    pub publication_bias: DowngradeDomain,
    pub large_magnitude_of_effect: UpgradeDomain,
    pub dose_response_gradient: UpgradeDomain,
    pub plausible_residual_confounding: UpgradeDomain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertaintyAssessment {
    pub assessment_id: String,
    pub outcome: OutcomeId,
    pub studies: Vec<StudyId>,
    pub starting_design: StartingDesign,
    pub domains: GradeCertaintyDomains,
    pub final_certainty: CertaintyLevel,
    pub summary_rationale: String,
    pub confirmation: AppraisalConfirmation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppraisalError {
    EmptyIdentifier(&'static str),
    MissingDomain(&'static str),
    DuplicateDomain(String),
    UnexpectedDomain(String),
    EmptyDomainReason(String),
    EmptySummaryRationale,
    EmptyConfirmedActor,
    EmptyConfirmedTimestamp,
    EmptyProposalGenerator,
    NoStudiesInCertainty,
    UpgradeForbiddenAfterDowngrade,
    CertaintyArithmeticMismatch {
        expected: CertaintyLevel,
        declared: CertaintyLevel,
    },
    InvalidSpanBounds,
    SchemaValidation(String),
}

fn validate_confirmation(confirmation: &AppraisalConfirmation) -> Result<(), AppraisalError> {
    match confirmation {
        AppraisalConfirmation::Proposed { generator } => {
            if generator.trim().is_empty() {
                return Err(AppraisalError::EmptyProposalGenerator);
            }
        }
        AppraisalConfirmation::Confirmed {
            authorized_by,
            confirmed_at_utc,
        } => {
            if authorized_by.trim().is_empty() {
                return Err(AppraisalError::EmptyConfirmedActor);
            }
            if confirmed_at_utc.trim().is_empty() {
                return Err(AppraisalError::EmptyConfirmedTimestamp);
            }
        }
    }
    Ok(())
}

impl RiskOfBiasAssessment {
    /// Validates completeness of required instrument domains, non-empty per-domain rationales,
    /// span bounds, and human actor presence when `Confirmed`.
    pub fn validate(&self) -> Result<(), AppraisalError> {
        if self.assessment_id.trim().is_empty() {
            return Err(AppraisalError::EmptyIdentifier("assessment_id"));
        }
        if self.overall_rationale.trim().is_empty() {
            return Err(AppraisalError::EmptySummaryRationale);
        }
        validate_confirmation(&self.confirmation)?;

        let required = self.tool.required_domains();
        let mut seen = std::collections::BTreeSet::new();
        for domain in &self.domains {
            let code = domain.domain_code.trim();
            if !required.contains(&code) {
                return Err(AppraisalError::UnexpectedDomain(domain.domain_code.clone()));
            }
            if !seen.insert(code.to_owned()) {
                return Err(AppraisalError::DuplicateDomain(domain.domain_code.clone()));
            }
            if domain.rationale.trim().is_empty() {
                return Err(AppraisalError::EmptyDomainReason(
                    domain.domain_code.clone(),
                ));
            }
            if domain
                .supporting_spans
                .iter()
                .any(|span| span.start_scalar >= span.end_scalar)
            {
                return Err(AppraisalError::InvalidSpanBounds);
            }
        }
        for &req in required {
            if !seen.contains(req) {
                return Err(AppraisalError::MissingDomain(req));
            }
        }
        Ok(())
    }
}

impl GradeCertaintyDomains {
    /// Computes deterministic net GRADE certainty from `starting_design`.
    #[must_use]
    pub fn compute_certainty(&self, starting_design: StartingDesign) -> CertaintyLevel {
        let base = starting_design.initial_certainty().rank();
        let down = self.risk_of_bias.step.delta()
            + self.inconsistency.step.delta()
            + self.indirectness.step.delta()
            + self.imprecision.step.delta()
            + self.publication_bias.step.delta();
        let up = self.large_magnitude_of_effect.step.delta()
            + self.dose_response_gradient.step.delta()
            + self.plausible_residual_confounding.step.delta();
        CertaintyLevel::from_rank(base + down + up)
    }

    fn has_any_downgrade(&self) -> bool {
        !matches!(self.risk_of_bias.step, DowngradeStep::None)
            || !matches!(self.inconsistency.step, DowngradeStep::None)
            || !matches!(self.indirectness.step, DowngradeStep::None)
            || !matches!(self.imprecision.step, DowngradeStep::None)
            || !matches!(self.publication_bias.step, DowngradeStep::None)
    }

    fn has_any_upgrade(&self) -> bool {
        !matches!(self.large_magnitude_of_effect.step, UpgradeStep::None)
            || !matches!(self.dose_response_gradient.step, UpgradeStep::None)
            || !matches!(self.plausible_residual_confounding.step, UpgradeStep::None)
    }
}

impl CertaintyAssessment {
    /// Validates all 8 GRADE domain reasons, GRADE upgrade-after-downgrade prohibition on
    /// observational bodies, deterministic certainty arithmetic, and `Confirmed` human actor gate.
    pub fn validate(&self) -> Result<(), AppraisalError> {
        if self.assessment_id.trim().is_empty() {
            return Err(AppraisalError::EmptyIdentifier("assessment_id"));
        }
        if self.studies.is_empty() {
            return Err(AppraisalError::NoStudiesInCertainty);
        }
        if self.summary_rationale.trim().is_empty() {
            return Err(AppraisalError::EmptySummaryRationale);
        }
        validate_confirmation(&self.confirmation)?;

        let domain_reasons = [
            ("risk_of_bias", &self.domains.risk_of_bias.reason),
            ("inconsistency", &self.domains.inconsistency.reason),
            ("indirectness", &self.domains.indirectness.reason),
            ("imprecision", &self.domains.imprecision.reason),
            ("publication_bias", &self.domains.publication_bias.reason),
            (
                "large_magnitude_of_effect",
                &self.domains.large_magnitude_of_effect.reason,
            ),
            (
                "dose_response_gradient",
                &self.domains.dose_response_gradient.reason,
            ),
            (
                "plausible_residual_confounding",
                &self.domains.plausible_residual_confounding.reason,
            ),
        ];
        for (name, reason) in domain_reasons {
            if reason.trim().is_empty() {
                return Err(AppraisalError::EmptyDomainReason(name.to_owned()));
            }
        }
        if self.domains.has_any_upgrade()
            && (self.starting_design == StartingDesign::RandomizedTrial
                || self.domains.has_any_downgrade())
        {
            return Err(AppraisalError::UpgradeForbiddenAfterDowngrade);
        }
        let expected = self.domains.compute_certainty(self.starting_design);
        if expected != self.final_certainty {
            return Err(AppraisalError::CertaintyArithmeticMismatch {
                expected,
                declared: self.final_certainty,
            });
        }
        Ok(())
    }

    /// True only when validated AND human-confirmed (`TA-12` + `Ask` `quality_appraised` gate).
    #[must_use]
    pub fn qualifies_for_assured_surface(&self) -> bool {
        self.confirmation.is_human_confirmed() && self.validate().is_ok()
    }
}

/// Pinned FSH-derived EBMonFHIR `ArtifactAssessment` JSON representation (`T26` crosswalk).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EbmFhirMeta {
    pub profile: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EbmFhirCoding {
    pub system: String,
    pub code: String,
    pub display: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EbmFhirCodeableConcept {
    pub coding: Vec<EbmFhirCoding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EbmFhirComponent {
    pub summary: String,
    pub classifier: Vec<EbmFhirCodeableConcept>,
    pub rating: Vec<EbmFhirCodeableConcept>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EbmFhirContent {
    pub information_type: String,
    pub summary: String,
    pub classifier: Vec<EbmFhirCodeableConcept>,
    pub author: Option<String>,
    pub workflow_status: String,
    pub components: Vec<EbmFhirComponent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EbmArtifactAssessment {
    pub resource_type: String,
    pub id: String,
    pub meta: EbmFhirMeta,
    pub artifact_reference: String,
    pub cited_studies: Vec<String>,
    pub starting_design: Option<String>,
    pub confirmed_at_utc: Option<String>,
    pub generator: Option<String>,
    pub content: Vec<EbmFhirContent>,
}

/// Summary-of-Findings (`SoF`) table row for deterministic GRADE export (`WP-10`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryOfFindingsRow {
    pub outcome_id: String,
    pub outcome_definition: String,
    pub study_count: usize,
    pub total_participants: Option<u64>,
    pub effect_summary_text: String,
    pub certainty: CertaintyLevel,
    pub certainty_reasons: Vec<String>,
    pub workflow_status: String,
    pub authorized_by: Option<String>,
}

fn concept(system: &str, code: &str, display: &str) -> EbmFhirCodeableConcept {
    EbmFhirCodeableConcept {
        coding: vec![EbmFhirCoding {
            system: system.to_owned(),
            code: code.to_owned(),
            display: display.to_owned(),
        }],
    }
}

fn certainty_code(level: CertaintyLevel) -> (&'static str, &'static str) {
    match level {
        CertaintyLevel::High => ("high", "High quality"),
        CertaintyLevel::Moderate => ("moderate", "Moderate quality"),
        CertaintyLevel::Low => ("low", "Low quality"),
        CertaintyLevel::VeryLow => ("very-low", "Very low quality"),
    }
}

fn downgrade_code(step: DowngradeStep) -> (&'static str, &'static str) {
    match step {
        DowngradeStep::None => ("no-change", "no serious concern (0)"),
        DowngradeStep::SeriousMinusOne => ("downcode1", "serious (-1)"),
        DowngradeStep::VerySeriousMinusTwo => ("downcode2", "very serious (-2)"),
    }
}

fn upgrade_code(step: UpgradeStep) -> (&'static str, &'static str) {
    match step {
        UpgradeStep::None => ("no-change", "none (0)"),
        UpgradeStep::PlusOne => ("upcode1", "increased (+1)"),
        UpgradeStep::PlusTwo => ("upcode2", "strongly increased (+2)"),
    }
}

/// Exports a validated `CertaintyAssessment` to an EBMonFHIR `ArtifactAssessment` JSON string.
///
/// # Errors
/// Fails closed if `assessment.validate()` fails or schema validation fails.
pub fn export_certainty_to_ebmonfhir_json(
    assessment: &CertaintyAssessment,
) -> Result<String, AppraisalError> {
    assessment.validate()?;
    let (overall_code, overall_display) = certainty_code(assessment.final_certainty);
    let (workflow_status, author, confirmed_at_utc, generator) = match &assessment.confirmation {
        AppraisalConfirmation::Proposed { generator } => {
            ("PROPOSED".to_owned(), None, None, Some(generator.clone()))
        }
        AppraisalConfirmation::Confirmed {
            authorized_by,
            confirmed_at_utc,
        } => (
            "CONFIRMED".to_owned(),
            Some(authorized_by.clone()),
            Some(confirmed_at_utc.clone()),
            None,
        ),
    };

    let down_entries = [
        (
            "RiskOfBias",
            "Risk of bias",
            &assessment.domains.risk_of_bias,
        ),
        (
            "Inconsistency",
            "Inconsistency",
            &assessment.domains.inconsistency,
        ),
        (
            "Indirectness",
            "Indirectness",
            &assessment.domains.indirectness,
        ),
        (
            "Imprecision",
            "Imprecision",
            &assessment.domains.imprecision,
        ),
        (
            "PublicationBias",
            "Publication bias",
            &assessment.domains.publication_bias,
        ),
    ];
    let up_entries = [
        (
            "LargeEffect",
            "Large magnitude of effect",
            &assessment.domains.large_magnitude_of_effect,
        ),
        (
            "DoseResponseGradient",
            "Dose-response gradient",
            &assessment.domains.dose_response_gradient,
        ),
        (
            "PlausibleConfounding",
            "Plausible residual confounding",
            &assessment.domains.plausible_residual_confounding,
        ),
    ];

    let mut components = Vec::with_capacity(8);
    for (code, display, dom) in down_entries {
        let (rcode, rdisplay) = downgrade_code(dom.step);
        components.push(EbmFhirComponent {
            summary: dom.reason.clone(),
            classifier: vec![concept("http://hl7.org/fhir/certainty-type", code, display)],
            rating: vec![concept(
                "http://hl7.org/fhir/certainty-rating",
                rcode,
                rdisplay,
            )],
        });
    }
    for (code, display, dom) in up_entries {
        let (rcode, rdisplay) = upgrade_code(dom.step);
        components.push(EbmFhirComponent {
            summary: dom.reason.clone(),
            classifier: vec![concept("http://hl7.org/fhir/certainty-type", code, display)],
            rating: vec![concept(
                "http://hl7.org/fhir/certainty-rating",
                rcode,
                rdisplay,
            )],
        });
    }

    let starting = match assessment.starting_design {
        StartingDesign::RandomizedTrial => "RANDOMIZED_TRIAL",
        StartingDesign::ObservationalStudy => "OBSERVATIONAL_STUDY",
    };

    let resource = EbmArtifactAssessment {
        resource_type: "ArtifactAssessment".to_owned(),
        id: assessment.assessment_id.clone(),
        meta: EbmFhirMeta {
            profile: vec![EBMONFHIR_CERTAINTY_PROFILE.to_owned()],
        },
        artifact_reference: format!(
            "EvidenceVariable/{}:{}:{}",
            assessment.outcome.0.scope, assessment.outcome.0.id, assessment.outcome.0.version
        ),
        cited_studies: assessment
            .studies
            .iter()
            .map(|s| format!("{}:{}:{}", s.0.scope, s.0.id, s.0.version))
            .collect(),
        starting_design: Some(starting.to_owned()),
        confirmed_at_utc,
        generator,
        content: vec![EbmFhirContent {
            information_type: "rating".to_owned(),
            summary: assessment.summary_rationale.clone(),
            classifier: vec![concept(
                "http://hl7.org/fhir/certainty-rating",
                overall_code,
                overall_display,
            )],
            author,
            workflow_status,
            components,
        }],
    };
    validate_ebmonfhir_assessment(&resource)?;
    serde_json::to_string_pretty(&resource)
        .map_err(|err| AppraisalError::SchemaValidation(err.to_string()))
}

/// Exports a validated `RiskOfBiasAssessment` to an EBMonFHIR `ArtifactAssessment` JSON string.
///
/// # Errors
/// Fails closed if `assessment.validate()` fails or schema validation fails.
pub fn export_rob_to_ebmonfhir_json(
    assessment: &RiskOfBiasAssessment,
) -> Result<String, AppraisalError> {
    assessment.validate()?;
    let (workflow_status, author, confirmed_at_utc, generator) = match &assessment.confirmation {
        AppraisalConfirmation::Proposed { generator } => {
            ("PROPOSED".to_owned(), None, None, Some(generator.clone()))
        }
        AppraisalConfirmation::Confirmed {
            authorized_by,
            confirmed_at_utc,
        } => (
            "CONFIRMED".to_owned(),
            Some(authorized_by.clone()),
            Some(confirmed_at_utc.clone()),
            None,
        ),
    };
    let components: Vec<EbmFhirComponent> = assessment
        .domains
        .iter()
        .map(|d| EbmFhirComponent {
            summary: d.rationale.clone(),
            classifier: vec![concept(
                "https://safeevidence.org/fhir/CodeSystem/rob-domain",
                &d.domain_code,
                &d.domain_code,
            )],
            rating: vec![concept(
                "https://safeevidence.org/fhir/CodeSystem/bias-level",
                &format!("{:?}", d.level).to_ascii_lowercase(),
                &format!("{:?}", d.level),
            )],
        })
        .collect();
    let resource = EbmArtifactAssessment {
        resource_type: "ArtifactAssessment".to_owned(),
        id: assessment.assessment_id.clone(),
        meta: EbmFhirMeta {
            profile: vec![EBMONFHIR_ROB_PROFILE.to_owned()],
        },
        artifact_reference: format!(
            "Citation/{}:{}:{}",
            assessment.report_version.0.scope,
            assessment.report_version.0.id,
            assessment.report_version.0.version
        ),
        cited_studies: vec![format!(
            "{}:{}:{}",
            assessment.study.0.scope, assessment.study.0.id, assessment.study.0.version
        )],
        starting_design: None,
        confirmed_at_utc,
        generator,
        content: vec![EbmFhirContent {
            information_type: "rating".to_owned(),
            summary: assessment.overall_rationale.clone(),
            classifier: vec![concept(
                "https://safeevidence.org/fhir/CodeSystem/bias-level",
                &format!("{:?}", assessment.overall).to_ascii_lowercase(),
                &format!("{:?}", assessment.overall),
            )],
            author,
            workflow_status,
            components,
        }],
    };
    validate_ebmonfhir_assessment(&resource)?;
    serde_json::to_string_pretty(&resource)
        .map_err(|err| AppraisalError::SchemaValidation(err.to_string()))
}

/// Validates an EBMonFHIR `ArtifactAssessment` against pinned FSH-derived structural and
/// P00 governance rules (`TA-12`).
pub fn validate_ebmonfhir_assessment(
    resource: &EbmArtifactAssessment,
) -> Result<(), AppraisalError> {
    if resource.resource_type != "ArtifactAssessment" {
        return Err(AppraisalError::SchemaValidation(
            "resourceType must be ArtifactAssessment".to_owned(),
        ));
    }
    if resource.id.trim().is_empty() || resource.artifact_reference.trim().is_empty() {
        return Err(AppraisalError::SchemaValidation(
            "id and artifactReference must be non-empty".to_owned(),
        ));
    }
    let valid_profile = resource.meta.profile.len() == 1
        && matches!(
            resource.meta.profile[0].as_str(),
            EBMONFHIR_CERTAINTY_PROFILE | EBMONFHIR_ROB_PROFILE
        );
    if !valid_profile {
        return Err(AppraisalError::SchemaValidation(
            "meta.profile must contain one pinned EBMonFHIR profile URL".to_owned(),
        ));
    }
    if resource.cited_studies.is_empty() {
        return Err(AppraisalError::SchemaValidation(
            "citedStudies must not be empty".to_owned(),
        ));
    }
    if resource.content.len() != 1 {
        return Err(AppraisalError::SchemaValidation(
            "content must contain exactly one top-level rating".to_owned(),
        ));
    }
    let content = &resource.content[0];
    if content.summary.trim().is_empty() {
        return Err(AppraisalError::SchemaValidation(
            "top-level summary rationale must not be empty".to_owned(),
        ));
    }
    if content.classifier.is_empty() {
        return Err(AppraisalError::SchemaValidation(
            "top-level classifier must not be empty".to_owned(),
        ));
    }
    match content.workflow_status.as_str() {
        "CONFIRMED" => {
            if content
                .author
                .as_deref()
                .is_none_or(|author| author.trim().is_empty())
            {
                return Err(AppraisalError::EmptyConfirmedActor);
            }
        }
        "PROPOSED" => {
            if content.author.is_some() {
                return Err(AppraisalError::SchemaValidation(
                    "PROPOSED rating must not claim human author confirmation".to_owned(),
                ));
            }
        }
        other => {
            return Err(AppraisalError::SchemaValidation(format!(
                "unsupported workflowStatus: {other}"
            )));
        }
    }
    if resource.meta.profile[0] == EBMONFHIR_CERTAINTY_PROFILE && content.components.len() != 8 {
        return Err(AppraisalError::SchemaValidation(
            "certainty-of-evidence profile requires all 8 GRADE domain components".to_owned(),
        ));
    }
    if resource.meta.profile[0] == EBMONFHIR_ROB_PROFILE && content.components.len() < 4 {
        return Err(AppraisalError::SchemaValidation(
            "risk-of-bias profile requires at least 4 domain components".to_owned(),
        ));
    }
    for component in &content.components {
        if component.summary.trim().is_empty() {
            return Err(AppraisalError::SchemaValidation(
                "every component summary rationale must be non-empty".to_owned(),
            ));
        }
        if component.classifier.is_empty() || component.rating.is_empty() {
            return Err(AppraisalError::SchemaValidation(
                "every component requires classifier and rating concepts".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Builds a validated `SummaryOfFindingsRow` from a `CertaintyAssessment` (`WP-10`).
pub fn build_summary_of_findings_row(
    assessment: &CertaintyAssessment,
    outcome_definition: &str,
    total_participants: Option<u64>,
    effect_summary_text: &str,
) -> Result<SummaryOfFindingsRow, AppraisalError> {
    assessment.validate()?;
    if outcome_definition.trim().is_empty() || effect_summary_text.trim().is_empty() {
        return Err(AppraisalError::SchemaValidation(
            "outcome_definition and effect_summary_text must be non-empty".to_owned(),
        ));
    }
    let (workflow_status, authorized_by) = match &assessment.confirmation {
        AppraisalConfirmation::Proposed { .. } => ("PROPOSED".to_owned(), None),
        AppraisalConfirmation::Confirmed { authorized_by, .. } => {
            ("CONFIRMED".to_owned(), Some(authorized_by.clone()))
        }
    };
    let reasons = vec![
        format!("risk_of_bias: {}", assessment.domains.risk_of_bias.reason),
        format!("inconsistency: {}", assessment.domains.inconsistency.reason),
        format!("indirectness: {}", assessment.domains.indirectness.reason),
        format!("imprecision: {}", assessment.domains.imprecision.reason),
        format!(
            "publication_bias: {}",
            assessment.domains.publication_bias.reason
        ),
        format!(
            "large_magnitude_of_effect: {}",
            assessment.domains.large_magnitude_of_effect.reason
        ),
        format!(
            "dose_response_gradient: {}",
            assessment.domains.dose_response_gradient.reason
        ),
        format!(
            "plausible_residual_confounding: {}",
            assessment.domains.plausible_residual_confounding.reason
        ),
    ];
    Ok(SummaryOfFindingsRow {
        outcome_id: format!(
            "{}:{}:{}",
            assessment.outcome.0.scope, assessment.outcome.0.id, assessment.outcome.0.version
        ),
        outcome_definition: outcome_definition.to_owned(),
        study_count: assessment.studies.len(),
        total_participants,
        effect_summary_text: effect_summary_text.to_owned(),
        certainty: assessment.final_certainty,
        certainty_reasons: reasons,
        workflow_status,
        authorized_by,
    })
}

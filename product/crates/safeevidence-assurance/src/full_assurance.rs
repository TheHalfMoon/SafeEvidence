//! `WP-11` (`TA-13`): Full deterministic decision assurance combining `T13` guard precedence with
//! methodological appraisal (`CertaintyAssessment`, `AppraisalState`), study independence, and
//! applicability/freshness limits.

use safeevidence_contracts::appraisal::{AppraisalConfirmation, BiasLevel, CertaintyLevel};
use safeevidence_contracts::assurance::{ReasonCode, TerminalOutcome};

use crate::{Cause, FiredRule, Requirement, Resolution, evaluate_precedence};

/// Structured evidence, appraisal, and policy inputs for full `WP-11` decision assurance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullAssuranceInput {
    pub rights_admissible: bool,
    pub security_permitted: bool,
    pub patient_specific_care_requested: bool,
    pub independent_material_contradiction: bool,
    pub missing_answer_changing_context: bool,
    pub all_sources_retracted_or_invalid: bool,
    pub applicable_independent_studies: usize,
    pub all_material_claims_verified: bool,
    pub applicability_has_limits: bool,
    pub currentness_unknown: bool,
    pub certainty_level: Option<CertaintyLevel>,
    pub certainty_confirmation: Option<AppraisalConfirmation>,
    pub worst_risk_of_bias: Option<BiasLevel>,
}

/// Deterministic `WP-11` decision output pairing the single [`TerminalOutcome`] with its primary [`ReasonCode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullAssuranceDecision {
    pub outcome: TerminalOutcome,
    pub reason: ReasonCode,
}

/// Evaluates `WP-11` full decision assurance strictly following the guarded precedence order of
/// `P00_DECISION_ASSURANCE_CONTRACT.md` §"Terminal decision precedence", integrating `WP-10`
/// GRADE certainty (`Confirmed` vs `Proposed`) and Risk-of-Bias appraisal without rendering any
/// numeric confidence percentage (`D-13`).
#[must_use]
pub fn evaluate_full_assurance(input: &FullAssuranceInput) -> FullAssuranceDecision {
    let mut rules: Vec<FiredRule> = Vec::new();

    if !input.security_permitted {
        rules.push(FiredRule {
            rule_id: "p00.guard.security_denied".to_owned(),
            precedence: 10,
            requirement: Requirement::Outcome(TerminalOutcome::Blocked),
            revoked: false,
        });
    }
    if !input.rights_admissible {
        rules.push(FiredRule {
            rule_id: "p00.guard.rights_unresolved".to_owned(),
            precedence: 10,
            requirement: Requirement::Outcome(TerminalOutcome::Blocked),
            revoked: false,
        });
    }
    if input.patient_specific_care_requested {
        rules.push(FiredRule {
            rule_id: "p00.guard.patient_care_escalate".to_owned(),
            precedence: 20,
            requirement: Requirement::Outcome(TerminalOutcome::Escalate),
            revoked: false,
        });
    }
    if input.independent_material_contradiction {
        rules.push(FiredRule {
            rule_id: "p00.guard.material_contradiction".to_owned(),
            precedence: 30,
            requirement: Requirement::Outcome(TerminalOutcome::Conflict),
            revoked: false,
        });
    }
    if input.missing_answer_changing_context {
        rules.push(FiredRule {
            rule_id: "p00.guard.missing_critical_context".to_owned(),
            precedence: 40,
            requirement: Requirement::Outcome(TerminalOutcome::AskMore),
            revoked: false,
        });
    }
    if input.all_sources_retracted_or_invalid {
        rules.push(FiredRule {
            rule_id: "p00.guard.retracted_or_invalid".to_owned(),
            precedence: 50,
            requirement: Requirement::Outcome(TerminalOutcome::Abstain),
            revoked: false,
        });
    } else if input.applicable_independent_studies == 0 {
        rules.push(FiredRule {
            rule_id: "p00.guard.insufficient_applicable_studies".to_owned(),
            precedence: 50,
            requirement: Requirement::Outcome(TerminalOutcome::Abstain),
            revoked: false,
        });
    } else if !input.all_material_claims_verified {
        rules.push(FiredRule {
            rule_id: "p00.guard.post_verification_failed".to_owned(),
            precedence: 50,
            requirement: Requirement::Outcome(TerminalOutcome::Abstain),
            revoked: false,
        });
    }

    match evaluate_precedence(&rules) {
        Resolution::Decided {
            requirement: Requirement::Outcome(outcome),
            cause: Cause::RuleWon | Cause::ConflictingRules,
            winners,
        } => {
            let leader = winners.first().map(String::as_str).unwrap_or("");
            let reason = match (outcome, leader) {
                (TerminalOutcome::Blocked, "p00.guard.security_denied") => {
                    ReasonCode::SecurityDenied
                }
                (TerminalOutcome::Blocked, _) => ReasonCode::RightsUnresolved,
                (TerminalOutcome::Escalate, _) => ReasonCode::ClinicianAuthorityRequired,
                (TerminalOutcome::Conflict, _) => ReasonCode::MaterialContradiction,
                (TerminalOutcome::AskMore, _) => ReasonCode::MissingCriticalContext,
                (TerminalOutcome::Abstain, "p00.guard.retracted_or_invalid") => {
                    ReasonCode::SourceInvalidOrRetracted
                }
                (TerminalOutcome::Abstain, "p00.guard.post_verification_failed") => {
                    ReasonCode::PostVerificationFailed
                }
                _ => ReasonCode::EvidenceInsufficient,
            };
            return FullAssuranceDecision { outcome, reason };
        }
        Resolution::Decided { .. } => {
            return FullAssuranceDecision {
                outcome: TerminalOutcome::Abstain,
                reason: ReasonCode::EvidenceInsufficient,
            };
        }
        Resolution::NoRuleFired => {}
    }

    // All blocking/abstention guards cleared and >= 1 applicable independent study has verified claims.
    // Evaluate methodological appraisal (GRADE certainty, confirmation state, RoB) and currentness/applicability:
    if matches!(input.certainty_level, Some(CertaintyLevel::VeryLow))
        && input.applicable_independent_studies < 2
    {
        return FullAssuranceDecision {
            outcome: TerminalOutcome::Abstain,
            reason: ReasonCode::EvidenceInsufficient,
        };
    }

    if input.currentness_unknown {
        return FullAssuranceDecision {
            outcome: TerminalOutcome::AnswerWithCaution,
            reason: ReasonCode::CurrentnessUnknown,
        };
    }

    if input.applicability_has_limits {
        return FullAssuranceDecision {
            outcome: TerminalOutcome::AnswerWithCaution,
            reason: ReasonCode::None,
        };
    }

    let human_confirmed = matches!(
        &input.certainty_confirmation,
        Some(AppraisalConfirmation::Confirmed {
            authorized_by,
            confirmed_at_utc,
        }) if !authorized_by.trim().is_empty() && !confirmed_at_utc.trim().is_empty()
    );
    let appraisal_confirmed_strong = human_confirmed
        && matches!(
            input.certainty_level,
            Some(CertaintyLevel::High | CertaintyLevel::Moderate)
        )
        && matches!(
            input.worst_risk_of_bias,
            Some(BiasLevel::Low | BiasLevel::SomeConcerns | BiasLevel::Moderate)
        );

    if appraisal_confirmed_strong && input.applicable_independent_studies >= 2 {
        FullAssuranceDecision {
            outcome: TerminalOutcome::Answer,
            reason: ReasonCode::None,
        }
    } else {
        FullAssuranceDecision {
            outcome: TerminalOutcome::AnswerWithCaution,
            reason: ReasonCode::None,
        }
    }
}

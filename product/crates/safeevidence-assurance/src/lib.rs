//! Fired-rule precedence, a Rust port of the mechanics of T13 (`ADM-0005`; see `PROVENANCE.md`).
//!
//! The lowest precedence number wins. Different outcomes at equal precedence fail closed and are
//! never averaged. Exactly one resolution comes back for any input. This resolves rules; deciding
//! which rules fire is the caller's job, and `safeevidence-ask` does not use this yet.

use safeevidence_contracts::assurance::{ControlAction, TerminalOutcome};

/// What a fired rule requires: a bounded action, or a terminal outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    Action(ControlAction),
    Outcome(TerminalOutcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiredRule {
    pub rule_id: String,
    pub precedence: u32,
    pub requirement: Requirement,
    pub revoked: bool,
}

/// Why the resolution came out as it did. Mapping these to reason codes is the caller's job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// One requirement held at the top precedence.
    RuleWon,
    /// Different requirements at the top precedence.
    ConflictingRules,
    /// A revoked rule fired. The whole evaluation fails closed.
    RevokedRule,
    /// A rule required the emergency notice, which P00 disables in V1.
    EmergencyDisabled,
    /// A rule had a blank identity.
    MalformedRule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// No rule fired. Unlike the donor this is not an answer: a commit needs its own proof.
    NoRuleFired,
    Decided {
        requirement: Requirement,
        cause: Cause,
        winners: Vec<String>,
    },
}

fn fail_closed(cause: Cause, winners: Vec<String>) -> Resolution {
    Resolution::Decided {
        requirement: Requirement::Outcome(TerminalOutcome::Abstain),
        cause,
        winners,
    }
}

/// Resolves fired rules into exactly one result.
#[must_use]
pub fn evaluate_precedence(rules: &[FiredRule]) -> Resolution {
    if rules.iter().any(|rule| rule.rule_id.trim().is_empty()) {
        return fail_closed(Cause::MalformedRule, Vec::new());
    }
    if let Some(rule) = rules.iter().find(|rule| rule.revoked) {
        return fail_closed(Cause::RevokedRule, vec![rule.rule_id.clone()]);
    }
    let emergency = Requirement::Outcome(TerminalOutcome::EmergencyNotice);
    if let Some(rule) = rules.iter().find(|rule| rule.requirement == emergency) {
        return fail_closed(Cause::EmergencyDisabled, vec![rule.rule_id.clone()]);
    }
    let Some(top) = rules.iter().map(|rule| rule.precedence).min() else {
        return Resolution::NoRuleFired;
    };
    let leaders: Vec<&FiredRule> = rules.iter().filter(|rule| rule.precedence == top).collect();
    let winners: Vec<String> = leaders.iter().map(|rule| rule.rule_id.clone()).collect();
    let first = leaders[0].requirement;
    if leaders.iter().all(|rule| rule.requirement == first) {
        // The donor names only the first of several agreeing leaders.
        return Resolution::Decided {
            requirement: first,
            cause: Cause::RuleWon,
            winners: vec![winners[0].clone()],
        };
    }
    // Fails toward the contract's guard order, then ABSTAIN. Never averaged.
    let requirement = [
        TerminalOutcome::Blocked,
        TerminalOutcome::Escalate,
        TerminalOutcome::Conflict,
    ]
    .into_iter()
    .map(Requirement::Outcome)
    .find(|wanted| leaders.iter().any(|rule| rule.requirement == *wanted))
    .unwrap_or(Requirement::Outcome(TerminalOutcome::Abstain));
    Resolution::Decided {
        requirement,
        cause: Cause::ConflictingRules,
        winners,
    }
}

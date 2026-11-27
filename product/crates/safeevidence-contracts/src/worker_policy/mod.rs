//! Worker supervision policy (`ADM-0018` / `T10` — deny-by-default ambient capability model, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/worker_policy/mod.rs`)
//! under Apache-2.0 (`ADR-0004`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Explicit capability grant to a sandboxed worker (expiring, enumerated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCapabilityGrant {
    pub name: String,
    pub expires_at_unix_ms: Option<u64>,
}

/// Supervision policy: all ambient privileges default to `false` (`TA-26`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSupervisionPolicy {
    pub allow_ambient_canonical_db: bool,
    pub allow_master_keys: bool,
    pub allow_unrestricted_filesystem: bool,
    pub allow_network: bool,
    pub allow_secrets: bool,
    pub allow_authority: bool,
    /// Confinement profile identifier; OS `PLATFORM_QUALIFIED` remains separate.
    pub confinement_profile: String,
    pub grants: Vec<WorkerCapabilityGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WorkerPolicyError {
    #[error("worker supervision policy grants forbidden ambient privilege: {0}")]
    AmbientPrivilegeAllowed(&'static str),
    #[error("worker supervision policy missing confinement_profile")]
    EmptyProfile,
}

impl WorkerSupervisionPolicy {
    /// Deny-by-default policy with empty grants.
    #[must_use]
    pub fn deny_by_default() -> Self {
        Self {
            allow_ambient_canonical_db: false,
            allow_master_keys: false,
            allow_unrestricted_filesystem: false,
            allow_network: false,
            allow_secrets: false,
            allow_authority: false,
            confinement_profile: "policy_ambient_deny_v0".to_owned(),
            grants: Vec::new(),
        }
    }

    /// Bind confinement profile id to OS sandbox scaffold evidence (not `PLATFORM_QUALIFIED`).
    #[must_use]
    pub fn with_os_sandbox_scaffold_profile(mut self) -> Self {
        self.confinement_profile = "os_sandbox_scaffold_not_platform_qualified".to_owned();
        self
    }

    /// Returns true when no ambient privilege is enabled.
    #[must_use]
    pub fn ambient_denied(&self) -> bool {
        !self.allow_ambient_canonical_db
            && !self.allow_master_keys
            && !self.allow_unrestricted_filesystem
            && !self.allow_network
            && !self.allow_secrets
            && !self.allow_authority
    }
}

/// Fail-closed validator verifying that `policy` denies every ambient capability (`TA-26`).
pub fn validate_worker_policy_deny_default(
    policy: &WorkerSupervisionPolicy,
) -> Result<(), WorkerPolicyError> {
    if policy.confinement_profile.trim().is_empty() {
        return Err(WorkerPolicyError::EmptyProfile);
    }
    if policy.allow_ambient_canonical_db {
        return Err(WorkerPolicyError::AmbientPrivilegeAllowed(
            "allow_ambient_canonical_db",
        ));
    }
    if policy.allow_master_keys {
        return Err(WorkerPolicyError::AmbientPrivilegeAllowed(
            "allow_master_keys",
        ));
    }
    if policy.allow_unrestricted_filesystem {
        return Err(WorkerPolicyError::AmbientPrivilegeAllowed(
            "allow_unrestricted_filesystem",
        ));
    }
    if policy.allow_network {
        return Err(WorkerPolicyError::AmbientPrivilegeAllowed("allow_network"));
    }
    if policy.allow_secrets {
        return Err(WorkerPolicyError::AmbientPrivilegeAllowed("allow_secrets"));
    }
    if policy.allow_authority {
        return Err(WorkerPolicyError::AmbientPrivilegeAllowed(
            "allow_authority",
        ));
    }
    Ok(())
}

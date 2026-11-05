//! Portable `SecretProtector` behavior for Specification 004B1 B103.
//!
//! This module validates requested portable policy, provider-reported
//! capabilities, and protector-record binding. It does not implement any
//! platform secure store, cryptographic operation, persistence mechanism, or
//! vault-root-key lifetime behavior.

use crate::vault::{
    AccessScope, KeyGeneration, ProtectorCapabilities, ProtectorError, SecretProtector,
    UserPresencePolicy, VaultId,
};

/// Portable protector policy requested by SafeEvidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtectorPolicy {
    access_scope: AccessScope,
    user_presence_policy: UserPresencePolicy,
}

impl ProtectorPolicy {
    /// Creates a portable requested policy.
    #[must_use]
    pub const fn new(access_scope: AccessScope, user_presence_policy: UserPresencePolicy) -> Self {
        Self {
            access_scope,
            user_presence_policy,
        }
    }

    /// Requested access scope.
    #[must_use]
    pub const fn access_scope(self) -> AccessScope {
        self.access_scope
    }

    /// Requested user-presence policy.
    #[must_use]
    pub const fn user_presence_policy(self) -> UserPresencePolicy {
        self.user_presence_policy
    }
}

/// Portable classification of the owner/application metadata on a protector
/// record.
///
/// Native adapters remain responsible for proving their real application or
/// owner identity. B103 deliberately does not invent a cross-platform native
/// identity encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtectorOwner {
    /// Native metadata was proven to belong to the SafeEvidence application.
    SafeEvidenceApplication,
    /// Native metadata is foreign, missing, ambiguous, or otherwise unproven.
    ForeignOrUnknown,
}

/// Portable binding metadata that must match before a protector record can be
/// used for an unlock request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtectorRecordBinding {
    owner: ProtectorOwner,
    vault_id: VaultId,
    key_generation: KeyGeneration,
    policy: ProtectorPolicy,
}

impl ProtectorRecordBinding {
    /// Creates a provider-neutral binding snapshot from already interpreted
    /// native record metadata.
    #[must_use]
    pub const fn new(
        owner: ProtectorOwner,
        vault_id: VaultId,
        key_generation: KeyGeneration,
        policy: ProtectorPolicy,
    ) -> Self {
        Self {
            owner,
            vault_id,
            key_generation,
            policy,
        }
    }

    /// Owner/application classification reported for this record.
    #[must_use]
    pub const fn owner(self) -> ProtectorOwner {
        self.owner
    }

    /// Vault identity bound to this record.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Key generation bound to this record.
    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }

    /// Portable policy bound to this record.
    #[must_use]
    pub const fn policy(self) -> ProtectorPolicy {
        self.policy
    }
}

/// Returns whether an actual provider scope can conservatively satisfy the
/// requested portable scope without silently weakening it.
///
/// `AppExclusive` is accepted for either same-user request because it is a
/// narrower application boundary. B103 intentionally does not invent an
/// ordering between `SameUserAccount` and `SameUserSession`; those classes only
/// satisfy themselves unless the provider can prove `AppExclusive`.
#[must_use]
pub const fn access_scope_satisfies(actual: AccessScope, requested: AccessScope) -> bool {
    match requested {
        AccessScope::AppExclusive => matches!(actual, AccessScope::AppExclusive),
        AccessScope::SameUserAccount => {
            matches!(
                actual,
                AccessScope::AppExclusive | AccessScope::SameUserAccount
            )
        }
        AccessScope::SameUserSession => {
            matches!(
                actual,
                AccessScope::AppExclusive | AccessScope::SameUserSession
            )
        }
    }
}

/// Validates that provider-reported capabilities satisfy the requested policy.
///
/// Unsupported or unproven policy fails closed with `UnsupportedPolicy`.
pub fn validate_requested_policy(
    capabilities: ProtectorCapabilities,
    requested: ProtectorPolicy,
) -> Result<(), ProtectorError> {
    if !access_scope_satisfies(capabilities.actual_access_scope(), requested.access_scope()) {
        return Err(ProtectorError::UnsupportedPolicy);
    }

    if matches!(
        requested.user_presence_policy(),
        UserPresencePolicy::RequiredEachSafeEvidenceUnlock
    ) && !capabilities.requires_user_presence()
    {
        return Err(ProtectorError::UnsupportedPolicy);
    }

    Ok(())
}

/// Validates owner, vault, generation, and stored policy binding for one record.
///
/// Owner/vault/generation mismatches use `OwnerMismatch`; a stored-policy
/// mismatch uses `PolicyMismatch`. No mismatched record is permitted to reach a
/// later VRK-returning operation.
pub fn validate_record_binding(
    record: ProtectorRecordBinding,
    expected_vault_id: VaultId,
    expected_key_generation: KeyGeneration,
    expected_policy: ProtectorPolicy,
) -> Result<(), ProtectorError> {
    if record.owner() != ProtectorOwner::SafeEvidenceApplication
        || record.vault_id() != expected_vault_id
        || record.key_generation() != expected_key_generation
    {
        return Err(ProtectorError::OwnerMismatch);
    }

    if record.policy() != expected_policy {
        return Err(ProtectorError::PolicyMismatch);
    }

    Ok(())
}

/// Captures exactly what a `SecretProtector` reports without upgrading unknown
/// or weaker properties.
#[must_use]
pub fn reported_capabilities<P: SecretProtector>(protector: &P) -> ProtectorCapabilities {
    ProtectorCapabilities::new(
        protector.actual_access_scope(),
        protector.requires_user_presence(),
        protector.hardware_backed_state(),
    )
}

/// Performs the portable B103 pre-unlock checks without executing a native
/// unlock or returning key material.
///
/// The returned capability snapshot contains only the provider's actual
/// reported values. Native unlock, cryptography, key lifetime, and revocation
/// sequencing remain owned by later bounded leaves.
pub fn validate_unlock_request<P: SecretProtector>(
    protector: &P,
    record: ProtectorRecordBinding,
    expected_vault_id: VaultId,
    expected_key_generation: KeyGeneration,
    requested_policy: ProtectorPolicy,
) -> Result<ProtectorCapabilities, ProtectorError> {
    let capabilities = reported_capabilities(protector);
    validate_requested_policy(capabilities, requested_policy)?;
    validate_record_binding(
        record,
        expected_vault_id,
        expected_key_generation,
        requested_policy,
    )?;
    Ok(capabilities)
}

#[cfg(test)]
mod tests {
    use super::{
        ProtectorOwner, ProtectorPolicy, ProtectorRecordBinding, access_scope_satisfies,
        reported_capabilities, validate_record_binding, validate_requested_policy,
        validate_unlock_request,
    };
    use crate::vault::{
        AccessScope, FreshnessAnchor, HardwareBacking, KeyGeneration, ProtectedFreshnessState,
        ProtectorCapabilities, ProtectorError, SecretProtector, UserPresencePolicy, VAULT_ID_BYTES,
        VaultId,
    };

    #[derive(Debug)]
    struct ReportingProtector {
        scope: AccessScope,
        presence: bool,
        hardware: HardwareBacking,
    }

    impl SecretProtector for ReportingProtector {
        type VaultRootKey = ();

        fn create_protector(
            &mut self,
            _requested_scope: AccessScope,
            _user_presence_policy: UserPresencePolicy,
        ) -> Result<(), ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn protect_or_store_vrk(
            &mut self,
            _vault_id: VaultId,
            _key_generation: KeyGeneration,
            _vrk: &Self::VaultRootKey,
        ) -> Result<(), ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn unlock_vrk(
            &mut self,
            _vault_id: VaultId,
            _key_generation: KeyGeneration,
        ) -> Result<Self::VaultRootKey, ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn read_freshness_anchor(
            &self,
            _vault_id: VaultId,
        ) -> Result<ProtectedFreshnessState, ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn install_genesis_freshness_anchor(
            &mut self,
            _vault_id: VaultId,
            _expected_state: ProtectedFreshnessState,
            _new_anchor: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn advance_freshness_anchor(
            &mut self,
            _vault_id: VaultId,
            _expected_old: FreshnessAnchor,
            _new_anchor: FreshnessAnchor,
        ) -> Result<(), ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn replace_protector(&mut self, _vault_id: VaultId) -> Result<(), ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn remove_protector(&mut self, _vault_id: VaultId) -> Result<(), ProtectorError> {
            Err(ProtectorError::Unavailable)
        }

        fn actual_access_scope(&self) -> AccessScope {
            self.scope
        }

        fn requires_user_presence(&self) -> bool {
            self.presence
        }

        fn hardware_backed_state(&self) -> HardwareBacking {
            self.hardware
        }
    }

    fn vault(byte: u8) -> VaultId {
        VaultId::from_bytes([byte; VAULT_ID_BYTES])
    }

    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).expect("test generation is non-zero")
    }

    #[test]
    fn scope_validation_is_conservative_and_never_silently_weakens() {
        assert!(access_scope_satisfies(
            AccessScope::AppExclusive,
            AccessScope::AppExclusive
        ));
        assert!(access_scope_satisfies(
            AccessScope::AppExclusive,
            AccessScope::SameUserAccount
        ));
        assert!(access_scope_satisfies(
            AccessScope::AppExclusive,
            AccessScope::SameUserSession
        ));
        assert!(access_scope_satisfies(
            AccessScope::SameUserAccount,
            AccessScope::SameUserAccount
        ));
        assert!(access_scope_satisfies(
            AccessScope::SameUserSession,
            AccessScope::SameUserSession
        ));

        assert!(!access_scope_satisfies(
            AccessScope::SameUserAccount,
            AccessScope::AppExclusive
        ));
        assert!(!access_scope_satisfies(
            AccessScope::SameUserSession,
            AccessScope::AppExclusive
        ));
        assert!(!access_scope_satisfies(
            AccessScope::SameUserAccount,
            AccessScope::SameUserSession
        ));
        assert!(!access_scope_satisfies(
            AccessScope::SameUserSession,
            AccessScope::SameUserAccount
        ));
    }

    #[test]
    fn required_presence_needs_positive_provider_evidence() {
        let requested = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        let without_presence = ProtectorCapabilities::new(
            AccessScope::SameUserAccount,
            false,
            HardwareBacking::Unknown,
        );
        assert_eq!(
            validate_requested_policy(without_presence, requested),
            Err(ProtectorError::UnsupportedPolicy)
        );

        let with_presence = ProtectorCapabilities::new(
            AccessScope::SameUserAccount,
            true,
            HardwareBacking::SoftwareBacked,
        );
        assert_eq!(validate_requested_policy(with_presence, requested), Ok(()));
    }

    #[test]
    fn stronger_presence_does_not_get_downgraded_for_not_required_policy() {
        let requested = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired,
        );
        let capabilities = ProtectorCapabilities::new(
            AccessScope::SameUserSession,
            true,
            HardwareBacking::Unknown,
        );
        assert_eq!(validate_requested_policy(capabilities, requested), Ok(()));
    }

    #[test]
    fn record_binding_fails_closed_on_owner_vault_generation_or_policy_mismatch() {
        let expected_vault = vault(1);
        let expected_generation = generation(7);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::NotRequired,
        );
        let good = ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            expected_vault,
            expected_generation,
            policy,
        );
        assert_eq!(
            validate_record_binding(good, expected_vault, expected_generation, policy),
            Ok(())
        );

        let foreign = ProtectorRecordBinding::new(
            ProtectorOwner::ForeignOrUnknown,
            expected_vault,
            expected_generation,
            policy,
        );
        assert_eq!(
            validate_record_binding(foreign, expected_vault, expected_generation, policy),
            Err(ProtectorError::OwnerMismatch)
        );

        let wrong_vault = ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            vault(2),
            expected_generation,
            policy,
        );
        assert_eq!(
            validate_record_binding(wrong_vault, expected_vault, expected_generation, policy),
            Err(ProtectorError::OwnerMismatch)
        );

        let wrong_generation = ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            expected_vault,
            generation(8),
            policy,
        );
        assert_eq!(
            validate_record_binding(
                wrong_generation,
                expected_vault,
                expected_generation,
                policy
            ),
            Err(ProtectorError::OwnerMismatch)
        );

        let other_policy = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        let wrong_policy = ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            expected_vault,
            expected_generation,
            other_policy,
        );
        assert_eq!(
            validate_record_binding(wrong_policy, expected_vault, expected_generation, policy),
            Err(ProtectorError::PolicyMismatch)
        );
    }

    #[test]
    fn capability_reporting_preserves_unknown_and_actual_values() {
        let protector = ReportingProtector {
            scope: AccessScope::SameUserSession,
            presence: false,
            hardware: HardwareBacking::Unknown,
        };
        let capabilities = reported_capabilities(&protector);
        assert_eq!(
            capabilities.actual_access_scope(),
            AccessScope::SameUserSession
        );
        assert!(!capabilities.requires_user_presence());
        assert_eq!(
            capabilities.hardware_backed_state(),
            HardwareBacking::Unknown
        );
    }

    #[test]
    fn unlock_validation_checks_capability_and_binding_without_unlocking() {
        let protector = ReportingProtector {
            scope: AccessScope::AppExclusive,
            presence: true,
            hardware: HardwareBacking::HardwareBacked,
        };
        let expected_vault = vault(3);
        let expected_generation = generation(9);
        let requested = ProtectorPolicy::new(
            AccessScope::SameUserAccount,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        let record = ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            expected_vault,
            expected_generation,
            requested,
        );

        let capabilities = validate_unlock_request(
            &protector,
            record,
            expected_vault,
            expected_generation,
            requested,
        )
        .expect("matching portable protector request must validate");

        assert_eq!(
            capabilities.actual_access_scope(),
            AccessScope::AppExclusive
        );
        assert!(capabilities.requires_user_presence());
        assert_eq!(
            capabilities.hardware_backed_state(),
            HardwareBacking::HardwareBacked
        );
    }

    #[test]
    fn unlock_validation_rejects_unproven_scope_before_key_material_is_requested() {
        let protector = ReportingProtector {
            scope: AccessScope::SameUserAccount,
            presence: false,
            hardware: HardwareBacking::SoftwareBacked,
        };
        let expected_vault = vault(4);
        let expected_generation = generation(10);
        let requested =
            ProtectorPolicy::new(AccessScope::AppExclusive, UserPresencePolicy::NotRequired);
        let record = ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            expected_vault,
            expected_generation,
            requested,
        );

        assert_eq!(
            validate_unlock_request(
                &protector,
                record,
                expected_vault,
                expected_generation,
                requested,
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );
    }
}

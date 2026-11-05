//! B405 aggregate protector fail-closed regression evidence.
//!
//! This test does not add native protector semantics. It freezes the portable
//! pre-unlock boundary and verifies that mismatched capability/binding state is
//! rejected before any key-returning operation is invoked.

use std::cell::Cell;

use safeevidence_vault::vault::{
    AccessScope, FreshnessAnchor, HardwareBacking, KeyGeneration, ProtectedFreshnessState,
    ProtectorError, SecretProtector, UserPresencePolicy, VaultId,
};
use safeevidence_vault::vault_protector::{
    ProtectorOwner, ProtectorPolicy, ProtectorRecordBinding, validate_unlock_request,
};

#[derive(Debug)]
struct SpyProtector {
    scope: AccessScope,
    presence: bool,
    unlock_calls: Cell<usize>,
    unlock_result: Result<[u8; 32], ProtectorError>,
}

impl SpyProtector {
    fn new(
        scope: AccessScope,
        presence: bool,
        unlock_result: Result<[u8; 32], ProtectorError>,
    ) -> Self {
        Self {
            scope,
            presence,
            unlock_calls: Cell::new(0),
            unlock_result,
        }
    }
}

impl SecretProtector for SpyProtector {
    type VaultRootKey = [u8; 32];

    fn create_protector(
        &mut self,
        _: AccessScope,
        _: UserPresencePolicy,
    ) -> Result<(), ProtectorError> {
        Ok(())
    }
    fn protect_or_store_vrk(
        &mut self,
        _: VaultId,
        _: KeyGeneration,
        _: &Self::VaultRootKey,
    ) -> Result<(), ProtectorError> {
        Ok(())
    }
    fn unlock_vrk(
        &mut self,
        _: VaultId,
        _: KeyGeneration,
    ) -> Result<Self::VaultRootKey, ProtectorError> {
        self.unlock_calls.set(self.unlock_calls.get() + 1);
        self.unlock_result
    }
    fn read_freshness_anchor(&self, _: VaultId) -> Result<ProtectedFreshnessState, ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }
    fn install_genesis_freshness_anchor(
        &mut self,
        _: VaultId,
        _: ProtectedFreshnessState,
        _: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }
    fn advance_freshness_anchor(
        &mut self,
        _: VaultId,
        _: FreshnessAnchor,
        _: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }
    fn replace_protector(&mut self, _: VaultId) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }
    fn remove_protector(&mut self, _: VaultId) -> Result<(), ProtectorError> {
        Ok(())
    }
    fn actual_access_scope(&self) -> AccessScope {
        self.scope
    }
    fn requires_user_presence(&self) -> bool {
        self.presence
    }
    fn hardware_backed_state(&self) -> HardwareBacking {
        HardwareBacking::Unknown
    }
}

fn vault(byte: u8) -> VaultId {
    VaultId::from_bytes([byte; 16])
}
fn generation(value: u64) -> KeyGeneration {
    KeyGeneration::new(value).expect("non-zero generation")
}
fn policy() -> ProtectorPolicy {
    ProtectorPolicy::new(
        AccessScope::SameUserAccount,
        UserPresencePolicy::NotRequired,
    )
}
fn good_record() -> ProtectorRecordBinding {
    ProtectorRecordBinding::new(
        ProtectorOwner::SafeEvidenceApplication,
        vault(1),
        generation(1),
        policy(),
    )
}

fn assert_preunlock_rejected(
    record: ProtectorRecordBinding,
    requested: ProtectorPolicy,
    expected: ProtectorError,
) {
    let protector = SpyProtector::new(AccessScope::SameUserAccount, false, Ok([0xA5; 32]));
    assert_eq!(
        validate_unlock_request(&protector, record, vault(1), generation(1), requested),
        Err(expected)
    );
    assert_eq!(
        protector.unlock_calls.get(),
        0,
        "pre-unlock rejection must not request key material"
    );
}

#[test]
fn owner_vault_generation_policy_and_capability_mismatches_reject_before_unlock() {
    assert_preunlock_rejected(
        ProtectorRecordBinding::new(
            ProtectorOwner::ForeignOrUnknown,
            vault(1),
            generation(1),
            policy(),
        ),
        policy(),
        ProtectorError::OwnerMismatch,
    );
    assert_preunlock_rejected(
        ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            vault(2),
            generation(1),
            policy(),
        ),
        policy(),
        ProtectorError::OwnerMismatch,
    );
    assert_preunlock_rejected(
        ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            vault(1),
            generation(2),
            policy(),
        ),
        policy(),
        ProtectorError::OwnerMismatch,
    );
    let other_policy = ProtectorPolicy::new(
        AccessScope::SameUserAccount,
        UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
    );
    assert_preunlock_rejected(
        ProtectorRecordBinding::new(
            ProtectorOwner::SafeEvidenceApplication,
            vault(1),
            generation(1),
            other_policy,
        ),
        policy(),
        ProtectorError::PolicyMismatch,
    );

    let protector = SpyProtector::new(AccessScope::SameUserSession, false, Ok([0xA5; 32]));
    let requested =
        ProtectorPolicy::new(AccessScope::AppExclusive, UserPresencePolicy::NotRequired);
    assert_eq!(
        validate_unlock_request(
            &protector,
            good_record(),
            vault(1),
            generation(1),
            requested
        ),
        Err(ProtectorError::UnsupportedPolicy)
    );
    assert_eq!(protector.unlock_calls.get(), 0);
}

#[test]
fn unavailable_locked_and_invalidated_unlocks_never_return_a_vrk() {
    for error in [
        ProtectorError::Unavailable,
        ProtectorError::Locked,
        ProtectorError::Invalidated,
    ] {
        let mut protector = SpyProtector::new(AccessScope::SameUserAccount, false, Err(error));
        validate_unlock_request(&protector, good_record(), vault(1), generation(1), policy())
            .expect("matching portable state must reach the provider boundary");
        assert_eq!(protector.unlock_vrk(vault(1), generation(1)), Err(error));
        assert_eq!(protector.unlock_calls.get(), 1);
    }
}

//! `ADM-0018` / `T10` deny-by-default worker supervision policy (`TA-26`).

use safeevidence_contracts::worker_policy::{
    WorkerPolicyError, WorkerSupervisionPolicy, validate_worker_policy_deny_default,
};

#[test]
fn worker_policy_defaults_to_full_ambient_denial() {
    let policy = WorkerSupervisionPolicy::deny_by_default();
    assert!(policy.ambient_denied());
    assert!(validate_worker_policy_deny_default(&policy).is_ok());

    let scaffold = WorkerSupervisionPolicy::deny_by_default().with_os_sandbox_scaffold_profile();
    assert!(scaffold.ambient_denied());
    assert!(validate_worker_policy_deny_default(&scaffold).is_ok());

    let mut bad = WorkerSupervisionPolicy::deny_by_default();
    bad.allow_network = true;
    assert_eq!(
        validate_worker_policy_deny_default(&bad),
        Err(WorkerPolicyError::AmbientPrivilegeAllowed("allow_network"))
    );
}

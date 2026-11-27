//! `ADM-0018` / `T10` macOS App Sandbox entitlements `ReadyBaseMeasured` honesty (`TA-26`).

use safeevidence_contracts::os_sandbox::{
    OsSandboxApplyError, OsSandboxDoctorStatus, OsSandboxPlan, OsSandboxQualification,
    app_sandbox_container_active, resolve_entitlements_path, try_apply_os_sandbox,
    validate_entitlements_artifact,
};

#[test]
fn doctor_macos_app_sandbox_entitlements_honest() {
    let d = OsSandboxDoctorStatus::ready_base();
    assert!(d.is_honest_ready_base());
    assert!(d.macos_app_sandbox_entitlements_measured);
    assert!(!d.macos_app_sandbox_enforcement_measured);
    assert!(!d.platform_qualified);
}

#[test]
fn entitlements_artifact_validates() {
    let path = resolve_entitlements_path().expect("entitlements fixture present");
    validate_entitlements_artifact(&path).expect("valid entitlements");
}

#[test]
fn detection_probe_runs_without_panic() {
    let _ = app_sandbox_container_active();
}

#[test]
fn ready_base_apply_validates_artifact() {
    try_apply_os_sandbox(&OsSandboxPlan::macos_app_sandbox_entitlements_ready_base())
        .expect("entitlements ReadyBaseMeasured apply");
}

#[test]
fn platform_qualified_never_honored() {
    let mut plan = OsSandboxPlan::macos_app_sandbox_entitlements_ready_base();
    plan.qualification = OsSandboxQualification::PlatformQualified;
    assert_eq!(
        try_apply_os_sandbox(&plan),
        Err(OsSandboxApplyError::NotPlatformQualified)
    );
}

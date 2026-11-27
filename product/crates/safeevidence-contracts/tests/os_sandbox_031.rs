//! `ADM-0018` / `T10` macOS Seatbelt `READY_BASE` honesty + measured deny (`TA-26`).

use safeevidence_contracts::os_sandbox::{
    OsSandboxApplyError, OsSandboxDoctorStatus, OsSandboxPlan, OsSandboxQualification,
    try_apply_os_sandbox,
};

#[test]
fn doctor_macos_measured_honest() {
    let d = OsSandboxDoctorStatus::ready_base();
    assert!(d.is_honest_ready_base());
    assert!(d.macos_measured);
    assert!(!d.platform_qualified);
    assert!(!d.release_ready);
}

#[test]
fn macos_scaffold_still_not_platform_qualified() {
    assert!(!OsSandboxPlan::macos_seatbelt_scaffold().claims_platform_qualified());
    assert_eq!(
        try_apply_os_sandbox(&OsSandboxPlan::macos_seatbelt_scaffold()),
        Err(OsSandboxApplyError::NotPlatformQualified)
    );
}

#[test]
fn platform_qualified_never_honored() {
    let mut plan = OsSandboxPlan::macos_seatbelt_ready_base();
    plan.qualification = OsSandboxQualification::PlatformQualified;
    assert_eq!(
        try_apply_os_sandbox(&plan),
        Err(OsSandboxApplyError::NotPlatformQualified)
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_ready_base_not_ready_off_macos() {
    assert_eq!(
        try_apply_os_sandbox(&OsSandboxPlan::macos_seatbelt_ready_base()),
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_measured_denies_network() {
    use std::process::Command;

    let probe = env!("CARGO_BIN_EXE_safeevidence-os-sandbox-probe");
    let output = Command::new(probe)
        .output()
        .expect("spawn safeevidence-os-sandbox-probe");
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 0,
        "expected measured network-deny (exit 0); got {code}; stderr={stderr}"
    );
    assert!(
        stderr.contains("network denied") || stderr.contains("OK:"),
        "stderr={stderr}"
    );
}

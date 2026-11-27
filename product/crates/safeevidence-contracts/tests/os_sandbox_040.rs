//! `ADM-0018` / `T10` Windows AppContainer LPAC `READY_BASE` honesty + measured deny (`TA-26`).

use safeevidence_contracts::os_sandbox::{
    OsSandboxApplyError, OsSandboxDoctorStatus, OsSandboxPlan, OsSandboxQualification,
    try_apply_os_sandbox,
};

#[test]
fn doctor_windows_appcontainer_lpac_measured_honest() {
    let d = OsSandboxDoctorStatus::ready_base();
    assert!(d.is_honest_ready_base());
    assert!(d.windows_appcontainer_lpac_measured);
    assert!(!d.platform_qualified);
}

#[test]
fn scaffold_still_not_platform_qualified_composition_residual() {
    assert!(!OsSandboxPlan::windows_appcontainer_scaffold().claims_platform_qualified());
    assert!(
        OsSandboxPlan::windows_appcontainer_lpac_ready_base()
            .mechanisms
            .iter()
            .any(|m| m.contains("lpac"))
    );
}

#[test]
fn platform_qualified_never_honored() {
    let mut plan = OsSandboxPlan::windows_appcontainer_lpac_ready_base();
    plan.qualification = OsSandboxQualification::PlatformQualified;
    assert_eq!(
        try_apply_os_sandbox(&plan),
        Err(OsSandboxApplyError::NotPlatformQualified)
    );
}

#[cfg(not(windows))]
#[test]
fn appcontainer_lpac_not_ready_off_windows() {
    assert_eq!(
        try_apply_os_sandbox(&OsSandboxPlan::windows_appcontainer_lpac_ready_base()),
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    );
}

#[cfg(windows)]
#[test]
fn appcontainer_lpac_measured_identity_fs_network() {
    use std::process::Command;

    let probe = env!("CARGO_BIN_EXE_safeevidence-os-sandbox-probe");
    let output = Command::new(probe)
        .arg("appcontainer-lpac")
        .output()
        .expect("spawn safeevidence-os-sandbox-probe appcontainer-lpac");
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 0,
        "expected AppContainer LPAC deny (exit 0); got {code}; stderr={stderr}"
    );
    assert!(
        stderr.contains("AppContainer LPAC deny") || stderr.contains("OK:"),
        "stderr={stderr}"
    );
}

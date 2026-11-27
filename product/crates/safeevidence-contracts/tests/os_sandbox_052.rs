//! `ADM-0018` / `T10` Linux Landlock FS + TCP + rlimit composition (`TA-26`).

use safeevidence_contracts::os_sandbox::{
    OsSandboxCompositionInventory, OsSandboxDoctorStatus, OsSandboxPlan,
};

#[test]
fn composition_plan_never_claims_platform_qualified() {
    let plan = OsSandboxPlan::linux_landlock_composition_ready_base(vec!["/tmp".into()]);
    assert!(plan.claims_ready_base_measured());
    assert!(!plan.claims_platform_qualified());
    assert!(plan.mechanisms.iter().any(|m| m.contains("rlimit")));
    assert!(plan.mechanisms.iter().any(|m| m.contains("network")));
}

#[test]
fn doctor_linux_composition_axis_honest() {
    let d = OsSandboxDoctorStatus::ready_base();
    assert!(d.linux_landlock_composition_measured);
    assert!(!d.platform_qualified);
    assert!(d.is_honest_ready_base());
    let inv = OsSandboxCompositionInventory::trusted_v1_ready_base();
    assert!(
        inv.axes_ready_base_measured
            .contains(&"linux_landlock_composition".to_owned())
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn composition_not_ready_on_non_linux() {
    use safeevidence_contracts::os_sandbox::{OsSandboxApplyError, try_apply_os_sandbox};

    let plan =
        OsSandboxPlan::linux_landlock_composition_ready_base(vec!["C:\\Windows\\Temp".into()]);
    assert_eq!(
        try_apply_os_sandbox(&plan),
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_composition_measures_fs_net_rlimit() {
    use std::process::Command;

    let probe = env!("CARGO_BIN_EXE_safeevidence-os-sandbox-probe");
    let output = Command::new(probe)
        .arg("landlock-composition")
        .output()
        .expect("spawn safeevidence-os-sandbox-probe landlock-composition");
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 0,
        "expected Landlock composition measure (exit 0); got {code}; stderr={stderr}"
    );
    assert!(stderr.contains("OK:"), "stderr={stderr}");
}

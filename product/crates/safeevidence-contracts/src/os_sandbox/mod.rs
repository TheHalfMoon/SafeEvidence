//! OS worker sandbox (`ADM-0018` / `T10`, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/os_sandbox/mod.rs`)
//! under Apache-2.0 (`ADR-0004`). Implements Linux Landlock (direct UAPI syscalls 444/445/446 +
//! `RLIMIT_NOFILE`), Linux seccomp-bpf strict allowlist (`SIGSYS` child measurement), Windows
//! Job Object + AppContainer FS/network/LPAC, macOS Seatbelt `sandbox_init`, and macOS App Sandbox
//! entitlements artifact verification (`OS_CA_CODE_SIGNED = FALSE` per `ADR-0004`).

#[cfg(target_os = "linux")]
mod linux_rlimit;
#[cfg(target_os = "linux")]
mod linux_seccomp;
mod macos_app_sandbox;
#[cfg(target_os = "macos")]
mod macos_seatbelt;
#[cfg(windows)]
mod windows_appcontainer;
#[cfg(windows)]
mod windows_job;

#[cfg(windows)]
pub use windows_appcontainer::{
    APPCONTAINER_FS_CHILD_ARG, APPCONTAINER_FS_PARENT_ARG, APPCONTAINER_LPAC_CHILD_ARG,
    APPCONTAINER_LPAC_PARENT_ARG, APPCONTAINER_NET_CHILD_ARG, APPCONTAINER_NET_PARENT_ARG,
    appcontainer_fs_child_exit_code, appcontainer_lpac_child_exit_code,
    appcontainer_net_child_exit_code, measure_appcontainer_fs_deny, measure_appcontainer_lpac_deny,
    measure_appcontainer_net_deny, resolve_appcontainer_child_exe,
};

#[cfg(target_os = "linux")]
pub use linux_seccomp::{
    SECCOMP_CHILD_ARG, SECCOMP_PARENT_ARG, measure_seccomp_composition, resolve_seccomp_probe_exe,
    seccomp_child_exit_code,
};

pub use macos_app_sandbox::{
    ENTITLEMENTS_REL_PATH, app_sandbox_container_active, resolve_entitlements_path,
    validate_entitlements_artifact,
};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Qualification claim for an OS confinement backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsSandboxQualification {
    NotPlatformQualified,
    ReadyBaseMeasured,
    PlatformQualified,
}

/// Target OS confinement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsSandboxTarget {
    LinuxLandlock,
    LinuxLandlockComposition,
    LinuxSeccompComposition,
    WindowsAppContainerJobObject,
    WindowsAppContainerFs,
    WindowsAppContainerNetwork,
    WindowsAppContainerLpac,
    MacosSeatbeltSandbox,
    MacosAppSandboxEntitlements,
}

/// Documented confinement plan for one OS backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsSandboxPlan {
    pub target: OsSandboxTarget,
    pub qualification: OsSandboxQualification,
    pub mechanisms: Vec<String>,
    pub evidence_path: String,
    pub limitations: Vec<String>,
    #[serde(default)]
    pub allow_paths: Vec<String>,
}

impl OsSandboxPlan {
    #[must_use]
    pub fn linux_landlock_ready_base(allow_paths: Vec<String>) -> Self {
        Self {
            target: OsSandboxTarget::LinuxLandlock,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "landlock_abi_v1".to_owned(),
                "path_beneath_allowlist".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_052.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured on Linux only — not multi-OS PLATFORM_QUALIFIED".to_owned(),
                "Signed macOS App Sandbox enforcement remains external (OS_CA_CODE_SIGNED = FALSE)"
                    .to_owned(),
            ],
            allow_paths,
        }
    }

    #[must_use]
    pub fn linux_landlock_composition_ready_base(allow_paths: Vec<String>) -> Self {
        Self {
            target: OsSandboxTarget::LinuxLandlockComposition,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "landlock_abi_fs_allowlist".to_owned(),
                "landlock_tcp_network_deny".to_owned(),
                "rlimit_nofile".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_052.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured Linux composition only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
                "Requires Landlock TCP (ABI V4+) on the host kernel".to_owned(),
            ],
            allow_paths,
        }
    }

    #[must_use]
    pub fn linux_seccomp_composition_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::LinuxSeccompComposition,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "seccomp_bpf_strict_allowlist".to_owned(),
                "sigsys_deny_child_measured".to_owned(),
                "no_new_privs".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_053.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured Linux seccomp composition only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
                "x86_64 + aarch64 filter tables only; other arches NotReadyOnThisHost".to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn windows_job_object_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::WindowsAppContainerJobObject,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "job_object_active_process_limit".to_owned(),
                "job_object_kill_on_job_close".to_owned(),
                "appcontainer_profile_scaffold".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_030.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured Job Object process-limit only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn windows_appcontainer_fs_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::WindowsAppContainerFs,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "appcontainer_profile_create_derive".to_owned(),
                "proc_thread_security_capabilities".to_owned(),
                "host_temp_marker_fs_deny".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_033.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured AppContainer child FS deny only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
                "Requires safeevidence-os-sandbox-probe helper for CreateProcess child".to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn windows_appcontainer_network_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::WindowsAppContainerNetwork,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "appcontainer_profile_create_derive".to_owned(),
                "proc_thread_security_capabilities_zero_caps".to_owned(),
                "tcp_connect_network_deny".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_038.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured AppContainer child network deny only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
                "Requires safeevidence-os-sandbox-probe helper for CreateProcess child".to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn windows_appcontainer_lpac_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::WindowsAppContainerLpac,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "appcontainer_profile_create_derive".to_owned(),
                "proc_thread_security_capabilities_zero_caps".to_owned(),
                "all_application_packages_opt_out_lpac".to_owned(),
                "lpac_identity_no_all_app_packages".to_owned(),
                "host_temp_marker_fs_deny".to_owned(),
                "tcp_connect_network_deny".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_040.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured LPAC identity/FS/network only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
                "Requires safeevidence-os-sandbox-probe helper for CreateProcess child".to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn windows_appcontainer_scaffold() -> Self {
        Self {
            target: OsSandboxTarget::WindowsAppContainerJobObject,
            qualification: OsSandboxQualification::NotPlatformQualified,
            mechanisms: vec![
                "brokered_handles_candidate".to_owned(),
                "multi_os_composition_candidate".to_owned(),
            ],
            evidence_path: "docs/plan/ARCHITECTURE_SPEC_V1.md".to_owned(),
            limitations: vec!["Not PLATFORM_QUALIFIED".to_owned()],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn macos_seatbelt_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::MacosSeatbeltSandbox,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "sandbox_init_sbpl".to_owned(),
                "seatbelt_network_deny".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_031.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured Seatbelt network-deny only — not multi-OS PLATFORM_QUALIFIED"
                    .to_owned(),
                "Signed App Sandbox enforcement remains external (OS_CA_CODE_SIGNED = FALSE)"
                    .to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn macos_app_sandbox_entitlements_ready_base() -> Self {
        Self {
            target: OsSandboxTarget::MacosAppSandboxEntitlements,
            qualification: OsSandboxQualification::ReadyBaseMeasured,
            mechanisms: vec![
                "entitlements_plist_artifact".to_owned(),
                "app_sandbox_container_id_probe".to_owned(),
            ],
            evidence_path: "product/crates/safeevidence-contracts/tests/os_sandbox_041.rs"
                .to_owned(),
            limitations: vec![
                "ReadyBaseMeasured entitlements artifact + detection probe only — not signed enforcement"
                    .to_owned(),
                "Runtime App Sandbox enforcement requires paid Apple Developer codesign (OS_CA_CODE_SIGNED = FALSE)"
                    .to_owned(),
            ],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn macos_seatbelt_scaffold() -> Self {
        Self {
            target: OsSandboxTarget::MacosSeatbeltSandbox,
            qualification: OsSandboxQualification::NotPlatformQualified,
            mechanisms: vec![
                "xpc_pattern_candidate".to_owned(),
                "signed_app_sandbox_enforcement_candidate".to_owned(),
            ],
            evidence_path: "docs/plan/ARCHITECTURE_SPEC_V1.md".to_owned(),
            limitations: vec!["Not PLATFORM_QUALIFIED".to_owned()],
            allow_paths: vec![],
        }
    }

    #[must_use]
    pub fn all_plans() -> Vec<Self> {
        vec![
            Self::linux_landlock_ready_base(vec![]),
            Self::linux_landlock_composition_ready_base(vec![]),
            Self::linux_seccomp_composition_ready_base(),
            Self::windows_job_object_ready_base(),
            Self::windows_appcontainer_fs_ready_base(),
            Self::windows_appcontainer_network_ready_base(),
            Self::windows_appcontainer_lpac_ready_base(),
            Self::windows_appcontainer_scaffold(),
            Self::macos_seatbelt_ready_base(),
            Self::macos_app_sandbox_entitlements_ready_base(),
            Self::macos_seatbelt_scaffold(),
        ]
    }

    #[must_use]
    pub fn claims_platform_qualified(&self) -> bool {
        matches!(
            self.qualification,
            OsSandboxQualification::PlatformQualified
        )
    }

    #[must_use]
    pub fn claims_ready_base_measured(&self) -> bool {
        matches!(
            self.qualification,
            OsSandboxQualification::ReadyBaseMeasured
        )
    }
}

/// OS sandbox doctor axis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsSandboxDoctorStatus {
    pub present: bool,
    pub ready_base: bool,
    pub linux_measured: bool,
    pub linux_landlock_composition_measured: bool,
    pub linux_seccomp_composition_measured: bool,
    pub windows_measured: bool,
    pub windows_appcontainer_fs_measured: bool,
    pub windows_appcontainer_network_measured: bool,
    pub windows_appcontainer_lpac_measured: bool,
    pub macos_measured: bool,
    pub macos_app_sandbox_entitlements_measured: bool,
    pub macos_app_sandbox_enforcement_measured: bool,
    pub composition_inventory_present: bool,
    pub composition_residuals_open: Vec<String>,
    pub platform_qualified: bool,
    pub release_ready: bool,
}

impl OsSandboxDoctorStatus {
    #[must_use]
    pub fn ready_base() -> Self {
        Self {
            present: true,
            ready_base: true,
            linux_measured: true,
            linux_landlock_composition_measured: true,
            linux_seccomp_composition_measured: true,
            windows_measured: true,
            windows_appcontainer_fs_measured: true,
            windows_appcontainer_network_measured: true,
            windows_appcontainer_lpac_measured: true,
            macos_measured: true,
            macos_app_sandbox_entitlements_measured: true,
            macos_app_sandbox_enforcement_measured: false,
            composition_inventory_present: true,
            composition_residuals_open: composition_residuals_open(),
            platform_qualified: false,
            release_ready: false,
        }
    }

    #[must_use]
    pub fn is_honest_ready_base(&self) -> bool {
        self.present
            && self.ready_base
            && self.linux_measured
            && self.linux_landlock_composition_measured
            && self.linux_seccomp_composition_measured
            && self.windows_measured
            && self.windows_appcontainer_fs_measured
            && self.windows_appcontainer_network_measured
            && self.windows_appcontainer_lpac_measured
            && self.macos_measured
            && self.macos_app_sandbox_entitlements_measured
            && !self.macos_app_sandbox_enforcement_measured
            && self.composition_inventory_present
            && !self.composition_residuals_open.is_empty()
            && !self.platform_qualified
            && !self.release_ready
    }
}

#[must_use]
pub fn composition_residuals_open() -> Vec<String> {
    vec![
        "macos_app_sandbox_signed_enforcement".to_owned(),
        "multi_os_platform_qualified_composition".to_owned(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsSandboxCompositionInventory {
    pub axes_ready_base_measured: Vec<String>,
    pub residuals_open: Vec<String>,
    pub platform_qualified: bool,
}

impl OsSandboxCompositionInventory {
    #[must_use]
    pub fn trusted_v1_ready_base() -> Self {
        Self {
            axes_ready_base_measured: vec![
                "linux_landlock".to_owned(),
                "linux_landlock_composition".to_owned(),
                "linux_seccomp_composition".to_owned(),
                "windows_job_object".to_owned(),
                "windows_appcontainer_fs".to_owned(),
                "windows_appcontainer_network".to_owned(),
                "windows_appcontainer_lpac".to_owned(),
                "macos_seatbelt".to_owned(),
                "macos_app_sandbox_entitlements".to_owned(),
            ],
            residuals_open: composition_residuals_open(),
            platform_qualified: false,
        }
    }

    #[must_use]
    pub fn is_honest(&self) -> bool {
        !self.platform_qualified
            && !self.axes_ready_base_measured.is_empty()
            && !self.residuals_open.is_empty()
    }
}

/// Runtime apply errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsSandboxApplyError {
    NotPlatformQualified,
    NotReadyOnThisHost,
    EmptyAllowlist,
    ApplyFailed(String),
}

pub fn try_apply_os_sandbox(plan: &OsSandboxPlan) -> Result<(), OsSandboxApplyError> {
    if plan.claims_platform_qualified() || !plan.claims_ready_base_measured() {
        return Err(OsSandboxApplyError::NotPlatformQualified);
    }

    match plan.target {
        OsSandboxTarget::LinuxLandlock => apply_linux_ready_base(plan),
        OsSandboxTarget::LinuxLandlockComposition => apply_linux_composition_ready_base(plan),
        OsSandboxTarget::LinuxSeccompComposition => apply_linux_seccomp_ready_base(plan),
        OsSandboxTarget::WindowsAppContainerJobObject => apply_windows_job_ready_base(plan),
        OsSandboxTarget::WindowsAppContainerFs => apply_windows_appcontainer_fs_ready_base(plan),
        OsSandboxTarget::WindowsAppContainerNetwork => {
            apply_windows_appcontainer_net_ready_base(plan)
        }
        OsSandboxTarget::WindowsAppContainerLpac => {
            apply_windows_appcontainer_lpac_ready_base(plan)
        }
        OsSandboxTarget::MacosSeatbeltSandbox => apply_macos_ready_base(plan),
        OsSandboxTarget::MacosAppSandboxEntitlements => {
            apply_macos_app_sandbox_entitlements_ready_base(plan)
        }
    }
}

fn apply_linux_ready_base(plan: &OsSandboxPlan) -> Result<(), OsSandboxApplyError> {
    if plan.allow_paths.is_empty() {
        return Err(OsSandboxApplyError::EmptyAllowlist);
    }
    #[cfg(target_os = "linux")]
    {
        apply_landlock_linux(plan, false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = plan;
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_linux_composition_ready_base(plan: &OsSandboxPlan) -> Result<(), OsSandboxApplyError> {
    if plan.allow_paths.is_empty() {
        return Err(OsSandboxApplyError::EmptyAllowlist);
    }
    #[cfg(target_os = "linux")]
    {
        apply_landlock_linux(plan, true)?;
        apply_rlimit_nofile_linux()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = plan;
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_linux_seccomp_ready_base(_plan: &OsSandboxPlan) -> Result<(), OsSandboxApplyError> {
    #[cfg(target_os = "linux")]
    {
        let exe = resolve_seccomp_probe_exe()?;
        measure_seccomp_composition(&exe)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_windows_job_ready_base(_plan: &OsSandboxPlan) -> Result<(), OsSandboxApplyError> {
    #[cfg(windows)]
    {
        windows_job::apply_job_object_windows()
    }
    #[cfg(not(windows))]
    {
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_windows_appcontainer_fs_ready_base(
    _plan: &OsSandboxPlan,
) -> Result<(), OsSandboxApplyError> {
    #[cfg(windows)]
    {
        windows_appcontainer::apply_appcontainer_fs_windows()
    }
    #[cfg(not(windows))]
    {
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_windows_appcontainer_net_ready_base(
    _plan: &OsSandboxPlan,
) -> Result<(), OsSandboxApplyError> {
    #[cfg(windows)]
    {
        windows_appcontainer::apply_appcontainer_net_windows()
    }
    #[cfg(not(windows))]
    {
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_windows_appcontainer_lpac_ready_base(
    _plan: &OsSandboxPlan,
) -> Result<(), OsSandboxApplyError> {
    #[cfg(windows)]
    {
        windows_appcontainer::apply_appcontainer_lpac_windows()
    }
    #[cfg(not(windows))]
    {
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_macos_ready_base(_plan: &OsSandboxPlan) -> Result<(), OsSandboxApplyError> {
    #[cfg(target_os = "macos")]
    {
        macos_seatbelt::apply_seatbelt_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

fn apply_macos_app_sandbox_entitlements_ready_base(
    _plan: &OsSandboxPlan,
) -> Result<(), OsSandboxApplyError> {
    macos_app_sandbox::apply_macos_app_sandbox_entitlements()
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_landlock_linux(
    plan: &OsSandboxPlan,
    require_tcp_deny: bool,
) -> Result<(), OsSandboxApplyError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const ACCESS_FS_V1_ALL: u64 = (1_u64 << 13) - 1;
    const ACCESS_FS_V2_ALL: u64 = (1_u64 << 14) - 1;
    const ACCESS_FS_V3_ALL: u64 = (1_u64 << 15) - 1;
    const ACCESS_NET_V4_TCP: u64 = (1_u64 << 0) | (1_u64 << 1);

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C, packed)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    let paths: Vec<PathBuf> = plan.allow_paths.iter().map(PathBuf::from).collect();
    for p in &paths {
        if !p.is_absolute() {
            return Err(OsSandboxApplyError::ApplyFailed(
                "allow_paths must be absolute".to_owned(),
            ));
        }
    }

    // SAFETY: Linux Landlock UAPI syscalls 444/445/446 with repr(C) structs and closed fds.
    unsafe {
        let abi = libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        );
        if abi < 1 {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "landlock ABI query failed: errno={}",
                *libc::__errno_location()
            )));
        }
        if require_tcp_deny && abi < 4 {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "landlock TCP network deny unavailable on host ABI v{abi} (need ABI v4+)"
            )));
        }

        let access_fs = if abi >= 3 {
            ACCESS_FS_V3_ALL
        } else if abi == 2 {
            ACCESS_FS_V2_ALL
        } else {
            ACCESS_FS_V1_ALL
        };
        let access_net = if require_tcp_deny {
            ACCESS_NET_V4_TCP
        } else {
            0
        };
        let attr = LandlockRulesetAttr {
            handled_access_fs: access_fs,
            handled_access_net: access_net,
        };
        let attr_size = if require_tcp_deny {
            std::mem::size_of::<LandlockRulesetAttr>()
        } else {
            std::mem::size_of::<u64>()
        };

        let ruleset_fd = libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &raw const attr,
            attr_size,
            0_u32,
        );
        if ruleset_fd < 0 {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "landlock_create_ruleset failed: errno={}",
                *libc::__errno_location()
            )));
        }
        let ruleset_fd = ruleset_fd as i32;

        for p in &paths {
            let c_path = CString::new(p.as_os_str().as_bytes()).map_err(|_| {
                let _ = libc::close(ruleset_fd);
                OsSandboxApplyError::ApplyFailed("allow_path contains interior NUL".to_owned())
            })?;
            let path_fd = libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if path_fd < 0 {
                let err = *libc::__errno_location();
                let _ = libc::close(ruleset_fd);
                return Err(OsSandboxApplyError::ApplyFailed(format!(
                    "open(O_PATH) failed for {}: errno={err}",
                    p.display()
                )));
            }
            let rule = LandlockPathBeneathAttr {
                allowed_access: access_fs,
                parent_fd: path_fd,
            };
            let rc = libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &raw const rule,
                0_u32,
            );
            let _ = libc::close(path_fd);
            if rc != 0 {
                let err = *libc::__errno_location();
                let _ = libc::close(ruleset_fd);
                return Err(OsSandboxApplyError::ApplyFailed(format!(
                    "landlock_add_rule failed: errno={err}"
                )));
            }
        }

        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            let err = *libc::__errno_location();
            let _ = libc::close(ruleset_fd);
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: errno={err}"
            )));
        }

        let rc = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0_u32);
        let _ = libc::close(ruleset_fd);
        if rc != 0 {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "landlock_restrict_self failed: errno={}",
                *libc::__errno_location()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn linux_rlimit_nofile_soft() -> Option<u64> {
    linux_rlimit::soft_nofile()
}

#[cfg(target_os = "linux")]
fn apply_rlimit_nofile_linux() -> Result<(), OsSandboxApplyError> {
    linux_rlimit::apply_rlimit_nofile()
}

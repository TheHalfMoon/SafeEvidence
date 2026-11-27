//! Windows AppContainer filesystem + network + LPAC `ReadyBaseMeasured` (`ADM-0018` / `T10`, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/os_sandbox/windows_appcontainer.rs`)
//! under Apache-2.0 (`ADR-0004`). Uses direct Win32 `kernel32` / `advapi32` / `userenv` / `ws2_32`
//! FFI with zero external crate additions.

#![allow(unsafe_code)]

use super::OsSandboxApplyError;
use std::ffi::OsStr;
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

pub const APPCONTAINER_FS_CHILD_ARG: &str = "appcontainer-fs-child";
pub const APPCONTAINER_FS_PARENT_ARG: &str = "appcontainer-fs";
pub const APPCONTAINER_NET_CHILD_ARG: &str = "appcontainer-net-child";
pub const APPCONTAINER_NET_PARENT_ARG: &str = "appcontainer-net";
pub const APPCONTAINER_LPAC_CHILD_ARG: &str = "appcontainer-lpac-child";
pub const APPCONTAINER_LPAC_PARENT_ARG: &str = "appcontainer-lpac";

const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

#[allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]
mod ffi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type PSID = *mut c_void;
    pub type PWSTR = *mut u16;
    pub type PCWSTR = *const u16;
    pub type BOOL = i32;
    pub type HRESULT = i32;
    pub type SOCKET = usize;

    pub const INVALID_SOCKET: SOCKET = usize::MAX;
    pub const SOCKET_ERROR: i32 = -1;
    pub const AF_INET: u16 = 2;
    pub const SOCK_STREAM: i32 = 1;
    pub const IPPROTO_TCP: i32 = 6;

    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_IS_APP_CONTAINER_CLASS: i32 = 29;
    pub const WIN_BUILTIN_ANY_PACKAGE_SID: i32 = 84;

    pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    pub const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
    pub const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;

    #[repr(C)]
    pub struct WSADATA {
        pub wVersion: u16,
        pub wHighVersion: u16,
        pub iMaxSockets: u16,
        pub iMaxUdpDg: u16,
        pub lpVendorInfo: *mut i8,
        pub szDescription: [i8; 257],
        pub szSystemStatus: [i8; 129],
    }

    #[repr(C)]
    pub struct SOCKADDR_IN {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    pub struct SECURITY_CAPABILITIES {
        pub AppContainerSid: PSID,
        pub Capabilities: *mut c_void,
        pub CapabilityCount: u32,
        pub Reserved: u32,
    }

    #[repr(C)]
    pub struct STARTUPINFOW {
        pub cb: u32,
        pub lpReserved: PWSTR,
        pub lpDesktop: PWSTR,
        pub lpTitle: PWSTR,
        pub dwX: u32,
        pub dwY: u32,
        pub dwXSize: u32,
        pub dwYSize: u32,
        pub dwXCountChars: u32,
        pub dwYCountChars: u32,
        pub dwFillAttribute: u32,
        pub dwFlags: u32,
        pub wShowWindow: u16,
        pub cbReserved2: u16,
        pub lpReserved2: *mut u8,
        pub hStdInput: HANDLE,
        pub hStdOutput: HANDLE,
        pub hStdError: HANDLE,
    }

    #[repr(C)]
    pub struct STARTUPINFOEXW {
        pub StartupInfo: STARTUPINFOW,
        pub lpAttributeList: *mut c_void,
    }

    #[repr(C)]
    pub struct PROCESS_INFORMATION {
        pub hProcess: HANDLE,
        pub hThread: HANDLE,
        pub dwProcessId: u32,
        pub dwThreadId: u32,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        pub fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WSADATA) -> i32;
        pub fn WSACleanup() -> i32;
        pub fn WSAGetLastError() -> i32;
        pub fn socket(af: i32, kind: i32, protocol: i32) -> SOCKET;
        pub fn connect(s: SOCKET, name: *const SOCKADDR_IN, namelen: i32) -> i32;
        pub fn closesocket(s: SOCKET) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: u32,
            TokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn GetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: i32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> BOOL;
        pub fn CreateWellKnownSid(
            WellKnownSidType: i32,
            DomainSid: PSID,
            pSid: PSID,
            cbSid: *mut u32,
        ) -> BOOL;
        pub fn CheckTokenMembership(
            TokenHandle: HANDLE,
            SidToCheck: PSID,
            IsMember: *mut BOOL,
        ) -> BOOL;
        pub fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut PWSTR) -> BOOL;
        pub fn FreeSid(pSid: PSID) -> *mut c_void;
    }

    #[link(name = "userenv")]
    unsafe extern "system" {
        pub fn CreateAppContainerProfile(
            pszAppContainerName: PCWSTR,
            pszDisplayName: PCWSTR,
            pszDescription: PCWSTR,
            pCapabilities: *const c_void,
            dwCapabilityCount: u32,
            ppSidAppContainerSid: *mut PSID,
        ) -> HRESULT;
        pub fn DeriveAppContainerSidFromAppContainerName(
            pszAppContainerName: PCWSTR,
            ppsidAppContainerSid: *mut PSID,
        ) -> HRESULT;
        pub fn DeleteAppContainerProfile(pszAppContainerName: PCWSTR) -> HRESULT;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn InitializeProcThreadAttributeList(
            lpAttributeList: *mut c_void,
            dwAttributeCount: u32,
            dwFlags: u32,
            lpSize: *mut usize,
        ) -> BOOL;
        pub fn UpdateProcThreadAttribute(
            lpAttributeList: *mut c_void,
            dwFlags: u32,
            Attribute: usize,
            lpValue: *mut c_void,
            cbSize: usize,
            lpPreviousValue: *mut c_void,
            lpReturnSize: *const usize,
        ) -> BOOL;
        pub fn DeleteProcThreadAttributeList(lpAttributeList: *mut c_void);
        pub fn CreateProcessW(
            lpApplicationName: PCWSTR,
            lpCommandLine: PWSTR,
            lpProcessAttributes: *const c_void,
            lpThreadAttributes: *const c_void,
            bInheritHandles: BOOL,
            dwCreationFlags: u32,
            lpEnvironment: *const c_void,
            lpCurrentDirectory: PCWSTR,
            lpStartupInfo: *const STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> BOOL;
        pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
        pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;
        pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut u32) -> BOOL;
    }
}

fn wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn path_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Child entry: attempt to read `marker`; requires active AppContainer token first, then exits 0
/// on `PermissionDenied`, 2 if readable or unconfined.
#[must_use]
pub fn appcontainer_fs_child_exit_code(marker: &Path) -> i32 {
    match token_is_app_container() {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(()) => return 11,
    }
    match fs::read(marker) {
        Ok(_) => 2,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => 0,
        Err(e) if e.raw_os_error() == Some(5) => 0,
        Err(_) => 1,
    }
}

/// Child entry: attempt TCP connect inside kernel-verified zero-capability AppContainer to prove
/// the OS sandbox denies outbound sockets (`product/clippy.toml` negative-control exception).
/// Refuses immediately (exit 2) without opening any socket if the process token is not an
/// AppContainer!
#[must_use]
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub fn appcontainer_net_child_exit_code() -> i32 {
    use std::io::ErrorKind;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    match token_is_app_container() {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(()) => return 11,
    }

    let addr: SocketAddr = "203.0.113.1:9"
        .parse()
        .expect("static TEST-NET-3 discard endpoint");
    match TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        Ok(_) => 2,
        Err(err) => {
            let denied = err.kind() == ErrorKind::PermissionDenied
                || err.raw_os_error() == Some(5)
                || err.raw_os_error() == Some(10013)
                || err.to_string().contains("Permission denied")
                || err
                    .to_string()
                    .contains("An attempt was made to access a socket in a way forbidden")
                || err
                    .to_string()
                    .contains("forbidden by its access permissions");
            if denied { 0 } else { 2 }
        }
    }
}

/// Panic-free TCP deny probe for LPAC (requires active AppContainer token before any WinSock call).
#[must_use]
pub fn appcontainer_lpac_net_child_exit_code() -> i32 {
    use ffi::{
        AF_INET, INVALID_SOCKET, IPPROTO_TCP, SOCK_STREAM, SOCKADDR_IN, SOCKET_ERROR, WSACleanup,
        WSADATA, WSAGetLastError, WSAStartup, closesocket, connect, socket,
    };

    match token_is_app_container() {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(()) => return 11,
    }

    // SAFETY: WinSock2 startup/connect/cleanup for a one-shot deny probe inside AppContainer.
    unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        let startup = WSAStartup(0x0202, &mut wsa);
        if startup != 0 {
            return 0;
        }
        let s = socket(i32::from(AF_INET), SOCK_STREAM, IPPROTO_TCP);
        if s == INVALID_SOCKET {
            let err = WSAGetLastError();
            let _ = WSACleanup();
            // WSAEACCES (10013), WSAEINVAL (10022), WSAEPROTONOSUPPORT (10043),
            // WSAESOCKTNOSUPPORT (10044), WSAEPROVIDERFAILEDINIT (10106)
            return if matches!(err, 10013 | 10022 | 10043 | 10044 | 10106) {
                0
            } else {
                20
            };
        }
        let mut addr: SOCKADDR_IN = std::mem::zeroed();
        addr.sin_family = AF_INET;
        addr.sin_port = 9_u16.to_be();
        addr.sin_addr = u32::from_ne_bytes([203, 0, 113, 1]);

        let rc = connect(s, &raw const addr, size_of::<SOCKADDR_IN>() as i32);
        let err = if rc == SOCKET_ERROR {
            WSAGetLastError()
        } else {
            0
        };
        let _ = closesocket(s);
        let _ = WSACleanup();

        // Require explicit WinSock access/capability denial codes (WSAEACCES 10013, etc.),
        // never route-unreachable or timeout errors.
        if rc == SOCKET_ERROR && matches!(err, 10013 | 10022 | 10043 | 10044 | 10106) {
            0
        } else {
            2
        }
    }
}

fn token_is_app_container() -> Result<bool, ()> {
    use ffi::{
        CloseHandle, GetCurrentProcess, GetTokenInformation, HANDLE, OpenProcessToken,
        TOKEN_IS_APP_CONTAINER_CLASS, TOKEN_QUERY,
    };

    // SAFETY: standard token query on current process.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(());
        }
        let mut is_ac: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_IS_APP_CONTAINER_CLASS,
            (&raw mut is_ac).cast(),
            size_of::<u32>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        if ok == 0 {
            return Err(());
        }
        Ok(is_ac != 0)
    }
}

fn token_has_all_application_packages() -> Result<bool, i32> {
    use ffi::{CheckTokenMembership, CreateWellKnownSid, WIN_BUILTIN_ANY_PACKAGE_SID};

    // SAFETY: well-known SID + membership against current process/thread token (NULL handle).
    unsafe {
        let mut sid_buf = [0u8; 68];
        let mut sid_size = sid_buf.len() as u32;
        if CreateWellKnownSid(
            WIN_BUILTIN_ANY_PACKAGE_SID,
            ptr::null_mut(),
            sid_buf.as_mut_ptr().cast(),
            &mut sid_size,
        ) == 0
        {
            return Err(14);
        }

        let mut is_member: i32 = 0;
        let ok = CheckTokenMembership(ptr::null_mut(), sid_buf.as_mut_ptr().cast(), &mut is_member);
        if ok == 0 {
            return Err(13);
        }
        Ok(is_member != 0)
    }
}

/// Child entry: LPAC identity + FS deny + network deny.
#[must_use]
pub fn appcontainer_lpac_child_exit_code(marker: &Path) -> i32 {
    match token_is_app_container() {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(()) => return 11,
    }
    match token_has_all_application_packages() {
        Ok(false) => {}
        Ok(true) => return 2,
        Err(14) => return 14,
        Err(_) => return 13,
    }
    let fs_code = appcontainer_fs_child_exit_code(marker);
    if fs_code != 0 {
        return fs_code;
    }
    appcontainer_lpac_net_child_exit_code()
}

/// Locate the AppContainer child helper executable.
#[must_use]
pub fn resolve_appcontainer_child_exe() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_safeevidence-os-sandbox-probe") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(cur) = std::env::current_exe() {
        if cur
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("safeevidence-os-sandbox-probe"))
        {
            return Some(cur);
        }
        let sibling = cur.with_file_name("safeevidence-os-sandbox-probe.exe");
        if sibling.is_file() {
            return Some(sibling);
        }
        if let Some(parent) = cur.parent().and_then(Path::parent) {
            let up = parent.join("safeevidence-os-sandbox-probe.exe");
            if up.is_file() {
                return Some(up);
            }
        }
    }
    None
}

pub fn measure_appcontainer_fs_deny(child_exe: &Path) -> Result<(), OsSandboxApplyError> {
    if !child_exe.is_file() {
        return Err(OsSandboxApplyError::ApplyFailed(format!(
            "AppContainer FS child exe missing: {}",
            child_exe.display()
        )));
    }
    let pid = std::process::id();
    let profile_name = format!("safeevidence.ac.033.{pid}");
    let marker = std::env::temp_dir().join(format!("safeevidence-ac-033-{pid}.marker"));
    fs::write(&marker, b"safeevidence-033-host-marker").map_err(|e| {
        OsSandboxApplyError::ApplyFailed(format!("failed to plant host marker: {e}"))
    })?;
    let cmdline_extra = format!("{APPCONTAINER_FS_CHILD_ARG} \"{}\"", marker.display());
    let result = measure_with_profile(
        &profile_name,
        "SafeEvidence AppContainer FS",
        "Synthetic AppContainer FS ReadyBaseMeasured profile",
        child_exe,
        &cmdline_extra,
        "FS",
        false,
    );
    let _ = fs::remove_file(&marker);
    let _ = delete_profile(&profile_name);
    result
}

pub fn measure_appcontainer_net_deny(child_exe: &Path) -> Result<(), OsSandboxApplyError> {
    if !child_exe.is_file() {
        return Err(OsSandboxApplyError::ApplyFailed(format!(
            "AppContainer network child exe missing: {}",
            child_exe.display()
        )));
    }
    let pid = std::process::id();
    let profile_name = format!("safeevidence.ac.038.{pid}");
    let result = measure_with_profile(
        &profile_name,
        "SafeEvidence AppContainer Network",
        "Synthetic AppContainer network ReadyBaseMeasured profile",
        child_exe,
        APPCONTAINER_NET_CHILD_ARG,
        "network",
        false,
    );
    let _ = delete_profile(&profile_name);
    result
}

pub fn measure_appcontainer_lpac_deny(child_exe: &Path) -> Result<(), OsSandboxApplyError> {
    if !child_exe.is_file() {
        return Err(OsSandboxApplyError::ApplyFailed(format!(
            "AppContainer LPAC child exe missing: {}",
            child_exe.display()
        )));
    }
    let pid = std::process::id();
    let profile_name = format!("safeevidence.ac.040.{pid}");
    let marker = std::env::temp_dir().join(format!("safeevidence-ac-040-{pid}.marker"));
    fs::write(&marker, b"safeevidence-040-host-marker").map_err(|e| {
        OsSandboxApplyError::ApplyFailed(format!("failed to plant host marker: {e}"))
    })?;
    let cmdline_extra = format!("{APPCONTAINER_LPAC_CHILD_ARG} \"{}\"", marker.display());
    let result = measure_with_profile(
        &profile_name,
        "SafeEvidence AppContainer LPAC",
        "Synthetic AppContainer LPAC ReadyBaseMeasured profile",
        child_exe,
        &cmdline_extra,
        "LPAC",
        true,
    );
    let _ = fs::remove_file(&marker);
    let _ = delete_profile(&profile_name);
    result
}

pub(super) fn apply_appcontainer_fs_windows() -> Result<(), OsSandboxApplyError> {
    let child = resolve_appcontainer_child_exe().ok_or_else(|| {
        OsSandboxApplyError::ApplyFailed(
            "AppContainer FS measure needs safeevidence-os-sandbox-probe".to_owned(),
        )
    })?;
    measure_appcontainer_fs_deny(&child)
}

pub(super) fn apply_appcontainer_net_windows() -> Result<(), OsSandboxApplyError> {
    let child = resolve_appcontainer_child_exe().ok_or_else(|| {
        OsSandboxApplyError::ApplyFailed(
            "AppContainer network measure needs safeevidence-os-sandbox-probe".to_owned(),
        )
    })?;
    measure_appcontainer_net_deny(&child)
}

pub(super) fn apply_appcontainer_lpac_windows() -> Result<(), OsSandboxApplyError> {
    let child = resolve_appcontainer_child_exe().ok_or_else(|| {
        OsSandboxApplyError::ApplyFailed(
            "AppContainer LPAC measure needs safeevidence-os-sandbox-probe".to_owned(),
        )
    })?;
    measure_appcontainer_lpac_deny(&child)
}

fn delete_profile(profile_name: &str) -> Result<(), OsSandboxApplyError> {
    let name = wide_null(profile_name);
    // SAFETY: profile name is a valid NUL-terminated UTF-16 string.
    let _ = unsafe { ffi::DeleteAppContainerProfile(name.as_ptr()) };
    Ok(())
}

fn measure_with_profile(
    profile_name: &str,
    display: &str,
    desc: &str,
    child_exe: &Path,
    child_args: &str,
    kind: &str,
    lpac: bool,
) -> Result<(), OsSandboxApplyError> {
    use ffi::{
        CloseHandle, ConvertSidToStringSidW, CreateAppContainerProfile, CreateProcessW,
        DeleteProcThreadAttributeList, DeriveAppContainerSidFromAppContainerName,
        EXTENDED_STARTUPINFO_PRESENT, FreeSid, GetExitCodeProcess, HANDLE,
        InitializeProcThreadAttributeList, LocalFree,
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, PSID, PWSTR,
        SECURITY_CAPABILITIES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    let name_w = wide_null(profile_name);
    let display_w = wide_null(display);
    let desc_w = wide_null(desc);
    let attr_count: u32 = if lpac { 2 } else { 1 };

    let mut sid: PSID = ptr::null_mut();

    // SAFETY: Win32 AppContainer profile APIs; SID freed via FreeSid on all paths below.
    unsafe {
        let hr = CreateAppContainerProfile(
            name_w.as_ptr(),
            display_w.as_ptr(),
            desc_w.as_ptr(),
            ptr::null(),
            0,
            &mut sid,
        );
        if hr < 0 {
            if hr == -2147024713_i32 {
                let hr2 = DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut sid);
                if hr2 < 0 || sid.is_null() {
                    return Err(OsSandboxApplyError::ApplyFailed(format!(
                        "DeriveAppContainerSidFromAppContainerName failed: HRESULT=0x{hr2:08X}"
                    )));
                }
            } else {
                return Err(OsSandboxApplyError::ApplyFailed(format!(
                    "CreateAppContainerProfile failed: HRESULT=0x{hr:08X}"
                )));
            }
        } else if sid.is_null() {
            return Err(OsSandboxApplyError::ApplyFailed(
                "CreateAppContainerProfile returned null SID".to_owned(),
            ));
        }

        let mut sid_str: PWSTR = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut sid_str) == 0 || sid_str.is_null() {
            let _ = FreeSid(sid);
            return Err(OsSandboxApplyError::ApplyFailed(
                "ConvertSidToStringSidW failed".to_owned(),
            ));
        }
        let _ = LocalFree(sid_str.cast());

        let mut caps = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };

        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(ptr::null_mut(), attr_count, 0, &mut attr_size);
        if attr_size == 0 {
            let _ = FreeSid(sid);
            return Err(OsSandboxApplyError::ApplyFailed(
                "InitializeProcThreadAttributeList size query failed".to_owned(),
            ));
        }
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = attr_buf.as_mut_ptr().cast();
        if InitializeProcThreadAttributeList(attr_list, attr_count, 0, &mut attr_size) == 0 {
            let _ = FreeSid(sid);
            return Err(OsSandboxApplyError::ApplyFailed(
                "InitializeProcThreadAttributeList failed".to_owned(),
            ));
        }

        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            (&raw mut caps).cast(),
            size_of::<SECURITY_CAPABILITIES>(),
            ptr::null_mut(),
            ptr::null(),
        ) == 0
        {
            DeleteProcThreadAttributeList(attr_list);
            let _ = FreeSid(sid);
            return Err(OsSandboxApplyError::ApplyFailed(
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed".to_owned(),
            ));
        }

        let mut lpac_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        if lpac
            && UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                (&raw mut lpac_policy).cast(),
                size_of::<u32>(),
                ptr::null_mut(),
                ptr::null(),
            ) == 0
        {
            DeleteProcThreadAttributeList(attr_list);
            let _ = FreeSid(sid);
            return Err(OsSandboxApplyError::ApplyFailed(
                "UpdateProcThreadAttribute(ALL_APPLICATION_PACKAGES_POLICY / LPAC) failed"
                    .to_owned(),
            ));
        }

        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION {
            hProcess: ptr::null_mut(),
            hThread: ptr::null_mut(),
            dwProcessId: 0,
            dwThreadId: 0,
        };

        let app = path_wide_null(child_exe);
        let cmdline_str = format!("\"{}\" {child_args}", child_exe.display());
        let mut cmdline = wide_null(&cmdline_str);

        let created = CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &raw const si.StartupInfo,
            &mut pi,
        );

        DeleteProcThreadAttributeList(attr_list);
        let _ = FreeSid(sid);

        if created == 0 {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "CreateProcessW into AppContainer ({kind}) failed"
            )));
        }

        let process: HANDLE = pi.hProcess;
        let thread: HANDLE = pi.hThread;
        let wait_rc = WaitForSingleObject(process, 30_000);
        if wait_rc != 0 {
            let _ = ffi::TerminateProcess(process, 124);
            let _ = WaitForSingleObject(process, 5_000);
            let _ = CloseHandle(thread);
            let _ = CloseHandle(process);
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "AppContainer ({kind}) child timed out or wait failed ({wait_rc})"
            )));
        }
        let mut code: u32 = 1;
        let _ = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);

        match code {
            0 => Ok(()),
            2 => Err(OsSandboxApplyError::ApplyFailed(format!(
                "AppContainer child ambient {kind} still allowed or LPAC identity not observed"
            ))),
            11 => Err(OsSandboxApplyError::ApplyFailed(
                "AppContainer LPAC child TokenIsAppContainer query failed".to_owned(),
            )),
            13 => Err(OsSandboxApplyError::ApplyFailed(
                "AppContainer LPAC child ALL_APPLICATION_PACKAGES membership check failed"
                    .to_owned(),
            )),
            14 => Err(OsSandboxApplyError::ApplyFailed(
                "AppContainer LPAC child CreateWellKnownSid failed".to_owned(),
            )),
            other => Err(OsSandboxApplyError::ApplyFailed(format!(
                "AppContainer {kind} child exited unexpectedly: {other}"
            ))),
        }
    }
}

//! Windows Job Object `READY_BASE` apply (`ADM-0018` / `T10`, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/os_sandbox/windows_job.rs`)
//! under Apache-2.0 (`ADR-0004`). Uses direct Win32 `kernel32` FFI with zero external crates.

#![allow(unsafe_code)]

use super::OsSandboxApplyError;

#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(windows)]
static JOB_APPLIED: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
#[allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]
mod ffi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;

    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;

    #[repr(C)]
    pub struct IO_COUNTERS {
        pub ReadOperationCount: u64,
        pub WriteOperationCount: u64,
        pub OtherOperationCount: u64,
        pub ReadTransferCount: u64,
        pub WriteTransferCount: u64,
        pub OtherTransferCount: u64,
    }

    #[repr(C)]
    pub struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        pub PerProcessUserTimeLimit: i64,
        pub PerJobUserTimeLimit: i64,
        pub LimitFlags: u32,
        pub MinimumWorkingSetSize: usize,
        pub MaximumWorkingSetSize: usize,
        pub ActiveProcessLimit: u32,
        pub Affinity: usize,
        pub PriorityClass: u32,
        pub SchedulingClass: u32,
    }

    #[repr(C)]
    pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        pub BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        pub IoInfo: IO_COUNTERS,
        pub ProcessMemoryLimit: usize,
        pub JobMemoryLimit: usize,
        pub PeakProcessMemoryUsed: usize,
        pub PeakJobMemoryUsed: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateJobObjectW(lpJobAttributes: *const c_void, lpName: *const u16) -> HANDLE;
        pub fn SetInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: i32,
            lpJobObjectInformation: *const c_void,
            cbJobObjectInformationLength: u32,
        ) -> BOOL;
        pub fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetLastError() -> u32;
    }
}

/// Apply Job Object limits to the current process (`ReadyBaseMeasured`).
#[cfg(windows)]
pub(super) fn apply_job_object_windows() -> Result<(), OsSandboxApplyError> {
    use ffi::{
        AssignProcessToJobObject, CloseHandle, CreateJobObjectW, GetCurrentProcess, GetLastError,
        HANDLE, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        SetInformationJobObject,
    };
    use std::mem::{size_of, zeroed};

    if JOB_APPLIED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // SAFETY: Win32 Job Object APIs; handles validated before use; job handle leaked by design so
    // `KILL_ON_JOB_CLOSE` stays active for the lifetime of the confined worker process.
    unsafe {
        let job: HANDLE = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "CreateJobObjectW failed: {}",
                GetLastError()
            )));
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        info.BasicLimitInformation.ActiveProcessLimit = 1;

        let ok = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            std::ptr::from_ref(&info).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()
                .try_into()
                .expect("job info size fits u32"),
        );
        if ok == 0 {
            let err = GetLastError();
            let _ = CloseHandle(job);
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "SetInformationJobObject failed: {err}"
            )));
        }

        let process = GetCurrentProcess();
        let assigned = AssignProcessToJobObject(job, process);
        if assigned == 0 {
            let err = GetLastError();
            let _ = CloseHandle(job);
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "AssignProcessToJobObject failed: {err}"
            )));
        }

        let _leaked_job: HANDLE = job;
    }

    JOB_APPLIED.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn apply_job_object_windows() -> Result<(), OsSandboxApplyError> {
    Err(OsSandboxApplyError::NotReadyOnThisHost)
}

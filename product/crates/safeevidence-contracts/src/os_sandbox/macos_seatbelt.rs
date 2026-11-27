//! macOS Seatbelt `READY_BASE` apply (`ADM-0018` / `T10`, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/os_sandbox/macos_seatbelt.rs`)
//! under Apache-2.0 (`ADR-0004`).

#![allow(unsafe_code)]

use super::OsSandboxApplyError;

#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "macos")]
static SEATBELT_APPLIED: AtomicBool = AtomicBool::new(false);

/// SBPL profile: allow default ambient behavior, deny all network operations.
#[cfg(target_os = "macos")]
pub(super) const NETWORK_DENY_PROFILE: &str = "\
(version 1)
(allow default)
(deny network*)
";

/// Apply Seatbelt network-deny profile to the current process (`ReadyBaseMeasured`).
#[cfg(target_os = "macos")]
pub(super) fn apply_seatbelt_macos() -> Result<(), OsSandboxApplyError> {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};
    use std::ptr;

    if SEATBELT_APPLIED.load(Ordering::SeqCst) {
        return Ok(());
    }

    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    let profile = CString::new(NETWORK_DENY_PROFILE).map_err(|_| {
        OsSandboxApplyError::ApplyFailed("seatbelt profile contained interior NUL".to_owned())
    })?;

    let mut errbuf: *mut c_char = ptr::null_mut();
    // SAFETY: sandbox_init writes an optional NUL-terminated error string into errbuf;
    // freed via sandbox_free_error below.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut errbuf) };
    if rc != 0 {
        let msg = if errbuf.is_null() {
            format!("sandbox_init failed rc={rc}")
        } else {
            // SAFETY: errbuf is a valid C string owned by libSystem until sandbox_free_error.
            let owned = unsafe { CStr::from_ptr(errbuf) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(errbuf) };
            owned
        };
        return Err(OsSandboxApplyError::ApplyFailed(msg));
    }

    SEATBELT_APPLIED.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn apply_seatbelt_macos() -> Result<(), OsSandboxApplyError> {
    Err(OsSandboxApplyError::NotReadyOnThisHost)
}

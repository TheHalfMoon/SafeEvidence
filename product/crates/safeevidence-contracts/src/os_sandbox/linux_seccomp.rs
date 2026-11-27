//! Linux seccomp-bpf strict allowlist composition (`ADM-0018` / `T10`, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/os_sandbox/linux_seccomp.rs`)
//! under Apache-2.0 (`ADR-0004`).

#![allow(unsafe_code)]

use super::OsSandboxApplyError;
use std::path::Path;
use std::process::Command;

/// Probe child entry: install the filter, prove write works, attempt socket.
pub const SECCOMP_CHILD_ARG: &str = "seccomp-child";
/// Probe parent mode: spawn the child and verify SIGSYS death.
pub const SECCOMP_PARENT_ARG: &str = "seccomp-composition";
/// Marker the child must emit (via allowed write) before the denied syscall.
pub const SECCOMP_FILTER_ACTIVE_MARKER: &str = "SAFEEVIDENCE_SECCOMP_FILTER_ACTIVE";
/// SIGSYS signal number on Linux.
pub const SIGSYS: i32 = 31;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH_X86_64_UAPI: u32 = 0xC000_003E;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn audit_arch() -> u32 {
    AUDIT_ARCH_X86_64_UAPI
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn allowed_syscalls() -> [libc::c_long; 5] {
    [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
    ]
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH_AARCH64_UAPI: u32 = 0xC000_00B7;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn audit_arch() -> u32 {
    AUDIT_ARCH_AARCH64_UAPI
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn allowed_syscalls() -> [libc::c_long; 5] {
    [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
    ]
}

/// Classic BPF program: arch check, then allowlist jumps, else `KILL_PROCESS`.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn build_filter(allowed: &[libc::c_long]) -> Vec<libc::sock_filter> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt,
        jf,
        k,
    };

    let allow_idx = 3 + allowed.len() as u8;
    let kill_idx = allow_idx + 1;
    let mut prog = vec![
        stmt(BPF_LD_W_ABS, 4),
        jump(audit_arch(), 0, kill_idx - 2),
        stmt(BPF_LD_W_ABS, 0),
    ];
    for (n, nr) in allowed.iter().enumerate() {
        let i = (3 + n) as u8;
        let jf = if n + 1 == allowed.len() {
            kill_idx - i - 1
        } else {
            0
        };
        prog.push(jump(*nr as u32, allow_idx - i - 1, jf));
    }
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    prog
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn install_filter() -> Result<(), OsSandboxApplyError> {
    let allowed = allowed_syscalls();
    let prog = build_filter(&allowed);
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: prctl with integer args and a stack-pinned fprog; standard Linux FFI.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(OsSandboxApplyError::ApplyFailed(
                "prctl(PR_SET_NO_NEW_PRIVS) failed".to_owned(),
            ));
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &raw const fprog as libc::c_ulong,
        ) != 0
        {
            return Err(OsSandboxApplyError::ApplyFailed(
                "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Child entry: returns an exit code only when the filter did NOT confine.
#[must_use]
pub fn seccomp_child_exit_code() -> i32 {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        if let Err(e) = install_filter() {
            eprintln!("seccomp install failed: {e:?}");
            return 1;
        }
        eprintln!("{SECCOMP_FILTER_ACTIVE_MARKER}");
        // SAFETY: direct denied syscall to prove KILL_PROCESS confinement.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        eprintln!("FAIL: denied socket() survived seccomp (fd={fd})");
        // SAFETY: allowed exit_group under the installed filter.
        unsafe { libc::_exit(2) }
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        eprintln!("seccomp child: unsupported host");
        3
    }
}

/// Parent measurement: spawn `probe_exe seccomp-child`; PASS requires marker on stderr AND death by SIGSYS.
pub fn measure_seccomp_composition(probe_exe: &Path) -> Result<(), OsSandboxApplyError> {
    #[cfg(target_os = "linux")]
    {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = probe_exe;
            Err(OsSandboxApplyError::NotReadyOnThisHost)
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            use std::os::unix::process::ExitStatusExt;

            let out = Command::new(probe_exe)
                .arg(SECCOMP_CHILD_ARG)
                .output()
                .map_err(|e| {
                    OsSandboxApplyError::ApplyFailed(format!("spawn seccomp child: {e}"))
                })?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains(SECCOMP_FILTER_ACTIVE_MARKER) {
                return Err(OsSandboxApplyError::ApplyFailed(format!(
                    "seccomp child never proved allowed write (status={:?} stderr={stderr:?})",
                    out.status
                )));
            }
            match out.status.signal() {
                Some(SIGSYS) => Ok(()),
                other => Err(OsSandboxApplyError::ApplyFailed(format!(
                    "denied socket() did not die by SIGSYS (signal={other:?} status={:?})",
                    out.status
                ))),
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = probe_exe;
        Err(OsSandboxApplyError::NotReadyOnThisHost)
    }
}

/// Resolve the probe helper next to the current executable.
pub fn resolve_seccomp_probe_exe() -> Result<std::path::PathBuf, OsSandboxApplyError> {
    let cur = std::env::current_exe().map_err(|e| {
        OsSandboxApplyError::ApplyFailed(format!("current_exe for seccomp probe: {e}"))
    })?;
    let dir = cur.parent().ok_or_else(|| {
        OsSandboxApplyError::ApplyFailed("seccomp probe has no parent dir".to_owned())
    })?;
    #[cfg(windows)]
    let name = "safeevidence-os-sandbox-probe.exe";
    #[cfg(not(windows))]
    let name = "safeevidence-os-sandbox-probe";
    let direct = dir.join(name);
    if direct.is_file() {
        return Ok(direct);
    }
    if let Some(parent) = dir.parent() {
        let up = parent.join(name);
        if up.is_file() {
            return Ok(up);
        }
    }
    Ok(direct)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[cfg(test)]
mod filter_tests {
    use super::build_filter;

    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    fn target(prog: &[libc::sock_filter], i: usize, jump_taken: bool) -> usize {
        let ins = &prog[i];
        assert_eq!(ins.code, BPF_JMP_JEQ_K, "ins {i} must be JEQ_K");
        let off = if jump_taken { ins.jt } else { ins.jf } as usize;
        i + 1 + off
    }

    #[test]
    fn every_path_ends_in_explicit_allow_or_kill() {
        let prog = build_filter(&[0, 1, 2, 3, 4]);
        let n = prog.len();
        assert_eq!(
            (prog[n - 2].code, prog[n - 2].k),
            (BPF_RET_K, SECCOMP_RET_ALLOW)
        );
        assert_eq!(
            (prog[n - 1].code, prog[n - 1].k),
            (BPF_RET_K, SECCOMP_RET_KILL_PROCESS)
        );
        assert_eq!(target(&prog, 1, true), 2);
        assert_eq!(target(&prog, 1, false), n - 1);
        for i in 3..n - 2 {
            assert_eq!(target(&prog, i, true), n - 2, "ins {i} match must allow");
            let miss = target(&prog, i, false);
            if i + 1 == n - 2 {
                assert_eq!(miss, n - 1, "last mismatch must kill");
            } else {
                assert_eq!(miss, i + 1, "ins {i} mismatch must chain");
            }
        }
    }
}

//! OS privacy probes with an honesty classification, and a plaintext residue scan for a store's
//! directory (T12, part of `TA-05`).
//!
//! Probes report whether a surface exists. They never claim measured swap, hibernate, snapshot or
//! core-dump **protection**, and they spawn no programs. The scan finds exact byte markers in a
//! directory. It cannot see the OS swap file, freed disk blocks or the WebView's own storage.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Best-effort existence result for OS residual privacy surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFileProbeResult {
    Detected,
    NotFound,
    NotReadable,
    NotApplicable,
}

impl OsFileProbeResult {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::NotFound => "not_found",
            Self::NotReadable => "not_readable",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Honesty class for a residual privacy surface.
///
/// `ProtectionMeasured` is defined for the taxonomy but **must not** be returned for
/// swap, pagefile, hibernate, snapshot or core dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeHonestyClass {
    ConfigurationDetected,
    ProtectionMeasured,
    NotMeasurableOnHost,
    OwnerOrOsPolicyRequired,
}

impl ProbeHonestyClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationDetected => "configuration_detected",
            Self::ProtectionMeasured => "protection_measured",
            Self::NotMeasurableOnHost => "not_measurable_on_host",
            Self::OwnerOrOsPolicyRequired => "owner_or_os_policy_required",
        }
    }
}

/// One residual surface: existence probe + honesty classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedResidualSurface {
    pub existence: OsFileProbeResult,
    /// Existence / configuration claim for this surface.
    pub existence_honesty: ProbeHonestyClass,
    /// Protection claim, which these probes always leave unmeasured.
    pub protection_honesty: ProbeHonestyClass,
}

impl ClassifiedResidualSurface {
    #[must_use]
    fn from_existence(existence: OsFileProbeResult) -> Self {
        let existence_honesty = match existence {
            OsFileProbeResult::Detected => ProbeHonestyClass::ConfigurationDetected,
            // A path check that finds nothing does not show the surface is absent.
            OsFileProbeResult::NotFound
            | OsFileProbeResult::NotReadable
            | OsFileProbeResult::NotApplicable => ProbeHonestyClass::NotMeasurableOnHost,
        };
        Self {
            existence,
            existence_honesty,
            protection_honesty: ProbeHonestyClass::OwnerOrOsPolicyRequired,
        }
    }
}

/// Aggregated privacy probe report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyProbeReport {
    pub pagefile: ClassifiedResidualSurface,
    pub hibernate: ClassifiedResidualSurface,
    pub swap: ClassifiedResidualSurface,
    pub snapshot: ClassifiedResidualSurface,
    pub core_dump_config: ClassifiedResidualSurface,
    pub residual_risk_classes_open: Vec<&'static str>,
}

/// Residual risk classes that stay open: nothing here measures their protection.
#[must_use]
pub fn residual_risk_classes_open() -> Vec<&'static str> {
    vec!["swap", "hibernate", "snapshot", "pagefile", "core_dump"]
}

/// Probe OS residual privacy surfaces (existence + honesty; fail-soft).
#[must_use]
pub fn probe_os_privacy_surfaces() -> PrivacyProbeReport {
    let (pagefile, hibernate, swap, snapshot, core_dump) = platform_classified_probes();
    PrivacyProbeReport {
        pagefile: ClassifiedResidualSurface::from_existence(pagefile),
        hibernate: ClassifiedResidualSurface::from_existence(hibernate),
        swap: ClassifiedResidualSurface::from_existence(swap),
        snapshot: ClassifiedResidualSurface::from_existence(snapshot),
        core_dump_config: ClassifiedResidualSurface::from_existence(core_dump),
        residual_risk_classes_open: residual_risk_classes_open(),
    }
}

/// One file holding a marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidueHit {
    pub path: PathBuf,
    pub marker_index: usize,
}

/// What a residue scan covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidueScan {
    pub files_scanned: Vec<PathBuf>,
    pub hits: Vec<ResidueHit>,
}

/// Scans every file under `root` for exact byte markers. An unreadable file or directory is an
/// error, not a clean result. Empty markers are refused, because they would match everything.
/// Keep markers well under a database page: overflow pages split longer text, so a long marker can
/// miss plaintext that is there. Files removed during the scan can be missed or cause an error.
///
/// # Errors
/// Returns the first I/O error, or `InvalidInput` for an empty marker.
pub fn scan_for_plaintext(root: &Path, markers: &[&[u8]]) -> std::io::Result<ResidueScan> {
    if markers.is_empty() || markers.iter().any(|marker| marker.is_empty()) {
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }
    let mut scan = ResidueScan {
        files_scanned: Vec::new(),
        hits: Vec::new(),
    };
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let bytes = std::fs::read(&path)?;
            for (marker_index, marker) in markers.iter().enumerate() {
                if bytes.windows(marker.len()).any(|window| window == *marker) {
                    scan.hits.push(ResidueHit {
                        path: path.clone(),
                        marker_index,
                    });
                }
            }
            scan.files_scanned.push(path);
        }
    }
    Ok(scan)
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn probe_path(path: &Path) -> OsFileProbeResult {
    match std::fs::metadata(path) {
        Ok(_) => OsFileProbeResult::Detected,
        Err(e) if e.kind() == ErrorKind::NotFound => OsFileProbeResult::NotFound,
        // Windows often returns PermissionDenied for an existing pagefile or hiberfil.
        #[cfg(windows)]
        Err(e) if e.kind() == ErrorKind::PermissionDenied => OsFileProbeResult::Detected,
        Err(_) => OsFileProbeResult::NotReadable,
    }
}

#[cfg(windows)]
fn platform_classified_probes() -> (
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
) {
    let pagefile = probe_path(Path::new(r"C:\pagefile.sys"));
    let hibernate = probe_path(Path::new(r"C:\hiberfil.sys"));
    let swap = probe_path(Path::new(r"C:\swapfile.sys"));
    // The restore surface only. Listing shadow copies would need a spawned tool and elevation.
    let snapshot = probe_path(Path::new(r"C:\System Volume Information"));
    let core_dump = windows_core_dump_config_probe();
    (pagefile, hibernate, swap, snapshot, core_dump)
}

#[cfg(windows)]
fn windows_core_dump_config_probe() -> OsFileProbeResult {
    // Crash dump folder / Wer config surface — existence only.
    let dumps = probe_path(Path::new(r"C:\Windows\Minidump"));
    if dumps != OsFileProbeResult::NotFound {
        return dumps;
    }
    probe_path(Path::new(r"C:\Users\Public\Documents\WER"))
}

#[cfg(target_os = "linux")]
fn platform_classified_probes() -> (
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
) {
    let swap = match std::fs::read_to_string("/proc/swaps") {
        Ok(s) => {
            let data_lines = s.lines().skip(1).filter(|l| !l.trim().is_empty()).count();
            if data_lines > 0 {
                OsFileProbeResult::Detected
            } else {
                OsFileProbeResult::NotFound
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => OsFileProbeResult::NotFound,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => OsFileProbeResult::NotReadable,
        Err(_) => OsFileProbeResult::NotReadable,
    };
    // Linux has no pagefile, so that class maps to swap.
    let pagefile = swap;
    let hibernate = match std::fs::read_to_string("/sys/power/disk") {
        Ok(s) if s.trim().is_empty() => OsFileProbeResult::NotFound,
        Ok(_) => OsFileProbeResult::Detected,
        Err(e) if e.kind() == ErrorKind::NotFound => OsFileProbeResult::NotFound,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => OsFileProbeResult::NotReadable,
        Err(_) => OsFileProbeResult::NotReadable,
    };
    let snapshot = linux_snapshot_probe();
    let core_dump = match std::fs::read_to_string("/proc/sys/kernel/core_pattern") {
        Ok(s) if s.trim().is_empty() => OsFileProbeResult::NotFound,
        Ok(_) => OsFileProbeResult::Detected,
        Err(e) if e.kind() == ErrorKind::NotFound => OsFileProbeResult::NotFound,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => OsFileProbeResult::NotReadable,
        Err(_) => OsFileProbeResult::NotReadable,
    };
    (pagefile, hibernate, swap, snapshot, core_dump)
}

#[cfg(target_os = "linux")]
fn linux_snapshot_probe() -> OsFileProbeResult {
    for candidate in [
        Path::new("/.snapshots"),
        Path::new("/mnt/.snapshots"),
        Path::new("/var/lib/snapd/snapshots"),
    ] {
        match probe_path(candidate) {
            OsFileProbeResult::Detected => return OsFileProbeResult::Detected,
            OsFileProbeResult::NotReadable => return OsFileProbeResult::NotReadable,
            _ => {}
        }
    }
    // btrfs filesystem present is a configuration hint, not a snapshot inventory.
    match std::fs::read_dir("/sys/fs/btrfs") {
        // The filesystem type is only a hint, and snapshots themselves are not enumerated.
        Ok(_) => OsFileProbeResult::NotFound,
        Err(e) if e.kind() == ErrorKind::NotFound => OsFileProbeResult::NotFound,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => OsFileProbeResult::NotReadable,
        Err(_) => OsFileProbeResult::NotReadable,
    }
}

#[cfg(target_os = "macos")]
fn platform_classified_probes() -> (
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
) {
    let vm = Path::new("/private/var/vm");
    let swap = match std::fs::read_dir(vm) {
        Ok(entries) => {
            let any_swap = entries
                .filter_map(Result::ok)
                .any(|e| e.file_name().to_string_lossy().starts_with("swapfile"));
            if any_swap {
                OsFileProbeResult::Detected
            } else {
                OsFileProbeResult::NotFound
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => OsFileProbeResult::NotFound,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => OsFileProbeResult::NotReadable,
        Err(_) => OsFileProbeResult::NotReadable,
    };
    let pagefile = swap;
    let hibernate = probe_path(Path::new("/private/var/vm/sleepimage"));
    // The local backup path only. Listing APFS snapshots would need a spawned tool.
    let snapshot = probe_path(Path::new("/Volumes/MobileBackups"));
    let core_dump = probe_path(Path::new("/cores"));
    (pagefile, hibernate, swap, snapshot, core_dump)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn platform_classified_probes() -> (
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
    OsFileProbeResult,
) {
    (
        OsFileProbeResult::NotApplicable,
        OsFileProbeResult::NotApplicable,
        OsFileProbeResult::NotApplicable,
        OsFileProbeResult::NotApplicable,
        OsFileProbeResult::NotApplicable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn probe_report_lists_open_residual_classes_and_never_claims_protection() {
        let r = probe_os_privacy_surfaces();
        assert_eq!(
            r.residual_risk_classes_open,
            vec!["swap", "hibernate", "snapshot", "pagefile", "core_dump"]
        );
        for surface in [
            r.pagefile,
            r.hibernate,
            r.swap,
            r.snapshot,
            r.core_dump_config,
        ] {
            assert_eq!(
                surface.protection_honesty,
                ProbeHonestyClass::OwnerOrOsPolicyRequired
            );
            assert_ne!(
                surface.existence_honesty,
                ProbeHonestyClass::ProtectionMeasured
            );
        }
    }

    #[test]
    fn existence_maps_to_an_honest_class() {
        for (existence, class) in [
            (
                OsFileProbeResult::Detected,
                ProbeHonestyClass::ConfigurationDetected,
            ),
            (
                OsFileProbeResult::NotFound,
                ProbeHonestyClass::NotMeasurableOnHost,
            ),
            (
                OsFileProbeResult::NotReadable,
                ProbeHonestyClass::NotMeasurableOnHost,
            ),
            (
                OsFileProbeResult::NotApplicable,
                ProbeHonestyClass::NotMeasurableOnHost,
            ),
        ] {
            assert_eq!(
                ClassifiedResidualSurface::from_existence(existence).existence_honesty,
                class
            );
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("se-residue-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("nested")).unwrap();
        root
    }

    #[test]
    fn scan_finds_a_marker_in_any_file_and_reports_coverage() {
        let root = temp_root("hit");
        fs::write(root.join("clean.bin"), b"nothing here").unwrap();
        fs::write(root.join("nested").join("db-wal"), b"xx secret yy").unwrap();
        let scan = scan_for_plaintext(&root, &[b"absent", b"secret"]).unwrap();
        assert_eq!(scan.files_scanned.len(), 2);
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].marker_index, 1);
        assert!(scan.hits[0].path.ends_with("db-wal"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_marker_split_across_a_read_boundary_is_still_found() {
        let root = temp_root("large");
        let mut bytes = vec![0_u8; 1 << 20];
        bytes[(1 << 19) - 3..(1 << 19) + 3].copy_from_slice(b"secret");
        fs::write(root.join("large.bin"), bytes).unwrap();
        assert_eq!(
            scan_for_plaintext(&root, &[b"secret"]).unwrap().hits.len(),
            1
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_scan_that_cannot_run_is_an_error_not_a_clean_result() {
        let root = temp_root("error");
        assert!(scan_for_plaintext(&root.join("missing"), &[b"x"]).is_err());
        assert!(scan_for_plaintext(&root, &[]).is_err());
        assert!(scan_for_plaintext(&root, &[b""]).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}

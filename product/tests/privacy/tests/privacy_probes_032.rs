//! Adapted from `crates/medscale-core/tests/privacy_probes_032.rs` (`ADM-0007`, `T12`); see `PROVENANCE.md`.

use std::path::Path;

use safeevidence_privacy_probes::{
    OsFileProbeResult, ProbeHonestyClass, build_privacy_doctor_report, probe_os_privacy_surfaces,
    residual_risk_classes_open,
};

#[test]
fn vault_privacy_probes_present_and_residuals_open() {
    let notices_present = Path::new("../../../THIRD_PARTY_NOTICES.md").is_file()
        || Path::new("../THIRD_PARTY_NOTICES.md").is_file();
    let report = build_privacy_doctor_report(true, notices_present);
    let v = &report.vault_privacy;
    assert!(v.present);
    assert!(v.probes_present);
    assert!(v.swap_snapshot_honesty_present);
    assert!(!v.private_data_ready);
    assert!(v.vault_leftover_scan_available);
    assert!(v.crash_sidecar_detect_available);
    assert_eq!(
        v.residual_risk_classes_open,
        vec![
            "swap".to_owned(),
            "hibernate".to_owned(),
            "snapshot".to_owned(),
            "pagefile".to_owned(),
            "core_dump".to_owned()
        ]
    );
    assert!(matches!(
        v.pagefile_existence,
        OsFileProbeResult::Detected
            | OsFileProbeResult::NotFound
            | OsFileProbeResult::NotReadable
            | OsFileProbeResult::NotApplicable
    ));
    assert!(matches!(
        v.snapshot_existence,
        OsFileProbeResult::Detected
            | OsFileProbeResult::NotFound
            | OsFileProbeResult::NotReadable
            | OsFileProbeResult::NotApplicable
    ));
    assert_ne!(
        v.snapshot_protection_honesty,
        ProbeHonestyClass::ProtectionMeasured
    );
    assert_eq!(
        v.snapshot_protection_honesty,
        ProbeHonestyClass::OwnerOrOsPolicyRequired
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("Privacy honesty") && n.contains("PRIVATE_DATA_READY=false"))
    );
}

#[test]
fn release_qualification_notice_inventory_with_license_decision() {
    let report = build_privacy_doctor_report(true, true);
    let rq = &report.release_qualification;
    assert!(rq.notice_inventory_present);
    assert!(rq.rights_license_decision);
    assert!(rq.is_honest_prep());
    assert!(!rq.release_ready);
    assert!(
        !rq.missing_evidence_classes
            .contains(&"public_source_license_choice".to_owned())
    );
    assert!(
        rq.missing_evidence_classes
            .contains(&"ext05_release_signing_keys".to_owned())
    );
}

#[test]
fn storage_probe_api_matches_doctor_residual_classes() {
    let r = probe_os_privacy_surfaces();
    assert!(r.probes_present);
    assert!(r.swap_snapshot_honesty_present);
    assert_eq!(r.residual_risk_classes_open, residual_risk_classes_open());
}

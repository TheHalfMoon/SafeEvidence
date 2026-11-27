//! Adapted from `crates/medscale-core/tests/vault_privacy_023.rs` (`ADM-0007`, `T12`); see `PROVENANCE.md`.

use safeevidence_privacy_probes::{KeyStoreAvailability, build_privacy_doctor_report};

#[test]
fn doctor_vault_privacy_023() {
    let report = build_privacy_doctor_report(true, true);
    let v = &report.vault_privacy;
    assert!(v.present);
    assert!(!v.private_data_ready);
    assert!(v.sealed_at_close);
    assert!(v.work_wipe_on_close);
    assert!(v.sqlcipher_enabled);
    assert!(v.open_work_page_encrypted);
    // Residual in-memory / OS swap plaintext risk remains honestly disclosed.
    assert!(v.open_work_plaintext_risk);
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("PRIVATE_DATA_READY=false")),
        "doctor notes must state PRIVATE_DATA_READY=false"
    );
}

#[test]
fn doctor_os_keyring_028_honesty() {
    for available in [true, false] {
        let report = build_privacy_doctor_report(available, true);
        let v = &report.vault_privacy;
        assert!(!v.private_data_ready);
        if v.os_keyring_used {
            assert!(v.os_keyring_available);
            assert_eq!(report.key_store, KeyStoreAvailability::OsStoreAvailable);
        } else {
            assert_eq!(report.key_store, KeyStoreAvailability::Unavailable);
        }
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("Privacy honesty") && n.contains("PRIVATE_DATA_READY=false")),
            "doctor notes must mention Privacy honesty + PRIVATE_DATA_READY=false"
        );
    }
}

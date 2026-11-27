# Provenance: safeevidence-privacy-probes

Admission `ADM-0007` (T12) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-storage/src/privacy_probes.rs`, Apache-2.0.
- Adapted: the OS-surface probes, `PrivacyDoctorReport` (`VaultPrivacyDoctorAxis`, `KeyStoreAvailability`,
  `ReleaseQualificationHonesty`), and honesty classes in `src/lib.rs`, plus adapted Rust integration suites
  `tests/privacy_probes_032.rs`, `tests/vault_privacy_023.rs` (bound to `safeevidence-vault` `T03` + `safeevidence-proofstore`
  `verify_record_semantics_doctor` rather than the excluded donor vault), and `tests/hostile_mime_010.rs` (bound to
  `safeevidence_contracts::document_intake::mime_decision`). A missing path reads as not measurable, and
  `PermissionDenied` means detected on Windows only.
- Removed: everything tied to the donor's `EncryptedVault`, which the P00 decisions rule out, and the `vssadmin` and `tmutil` calls, so the
  probes spawn no programs. Snapshot presence is a path check on Windows and macOS, and a hint on Linux, so `not_found` does not mean no snapshots exist. Windows paths assume `C:`.
- SafeEvidence-written: `scan_for_plaintext` and `tests/store_residue.rs`.

## Limits

`safeevidence-proofstore/tests/ta05_diskfull_and_recovery.rs` and `tests/proof_commit.rs` cover SQLite `PRAGMA max_page_count`
disk-full rollback, process kills, Argon2id `SAFEVD/RECOVERY/ENVELOPE/v1` key-loss recovery, and B505 portable backup
clean-directory restore. Here, `scan_for_plaintext` scans exact bytes in one directory; it does not cover OS swap,
freed disk blocks, SQLite temp files outside that directory, or the desktop WebView's storage. Probes report existence
and never claim OS-level residual-risk protection (`PRIVATE_DATA_READY = false`, `RELEASE_QUALIFIED = false`).

The scan's markers must stay well under a database page, because overflow pages split longer text: in a review run on an unencrypted store, a 12,000-byte
marker got no hits while its first 64 bytes did. Today's longest marker is 358 bytes, and the same review confirmed all 17 markers hit with encryption
bypassed. No test in this repository keeps that true, so the control only proves the scanner works. All four pinned `ADM-0007` (`T12`) files are now
adapted and verified in `product/tests/privacy/`.

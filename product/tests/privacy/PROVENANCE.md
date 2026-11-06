# Provenance: safeevidence-privacy-probes

Admission `ADM-0007` (T12) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-storage/src/privacy_probes.rs`, Apache-2.0.
- Adapted: the OS-surface probes and honesty classes. Their tests are rewritten, because the donor's depend on its doctor report.
- Removed: everything tied to MedScale's `EncryptedVault`, which the P00 decisions rule out, and the `vssadmin` and `tmutil` calls, so the
  probes spawn no programs. Snapshot presence is now a path check only on Windows and macOS, so a `not_found` there does not mean no snapshots exist.
- Not copied: `privacy_probes_032.rs` and `vault_privacy_023.rs`, which test the donor's doctor report, and `hostile_mime_010.rs`, which tests a
  document intake SafeEvidence does not have yet. T12 must return for the MIME test at WP-13.
- SafeEvidence-written: `scan_for_plaintext` and `tests/store_residue.rs`.

## Limits

This covers part of `TA-05`'s residue clause, so `TA-05` is not claimed. The scan looks for exact bytes in one directory. It does not cover OS swap,
freed disk blocks, SQLite temp files outside that directory, a killed store's files, or the desktop WebView's storage. Probes report existence and never
measure protection.

# Provenance: safeevidence-privacy-probes

Admission `ADM-0007` (T12) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-storage/src/privacy_probes.rs`, Apache-2.0.
- Adapted: the OS-surface probes and honesty classes, with one probe test adapted from the donor's inline tests. A missing path now reads as not measurable, and `PermissionDenied` means detected on Windows only.
- Removed: everything tied to MedScale's `EncryptedVault`, which the P00 decisions rule out, and the `vssadmin` and `tmutil` calls, so the
  probes spawn no programs. Snapshot presence is a path check on Windows and macOS, and a hint on Linux, so `not_found` does not mean no snapshots exist. Windows paths assume `C:`.
- Not copied: `privacy_probes_032.rs` and `vault_privacy_023.rs`, which test the donor's doctor report, and `hostile_mime_010.rs`, which tests a
  document intake SafeEvidence does not have yet. T12 must return for the MIME test at WP-13.
- SafeEvidence-written: `scan_for_plaintext` and `tests/store_residue.rs`.

## Limits

This covers part of `TA-05`'s residue clause, so `TA-05` is not claimed. The scan looks for exact bytes in one directory. It does not cover OS swap,
freed disk blocks, SQLite temp files outside that directory, a killed store's files, or the desktop WebView's storage. Probes report existence and never
measure protection.

The scan's markers must stay well under a database page, because overflow pages split longer text: in a review run on an unencrypted store, a 12,000-byte
marker got no hits while its first 64 bytes did. Today's longest marker is 358 bytes, and the same review confirmed all 17 markers hit with encryption
bypassed. No test in this repository keeps that true, so the control only proves the scanner works. T12's matrix row is narrowed here: none of its three
listed test files was copied.

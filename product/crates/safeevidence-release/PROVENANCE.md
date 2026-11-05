# Provenance: safeevidence-release

Admission `ADM-0002` (T11) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, Apache-2.0.
- Adapted: `src/lib.rs` from `release_sbom.rs`, renamed, with Cargo.lock coverage and native-library helpers added;
  `tests/release_sbom_054.rs`, renamed, nine of eleven donor tests, with coverage tests added.
- Not carried: the committed-document and doctor tests (donor files and modules); `generate-release-sbom.ps1`.
- `src/bin/sbom.rs` is SafeEvidence-written; it replaces the donor script.
- This is engineering evidence. `release_ready` stays false; no signing or reproducible build is claimed. Native
  entries are a hand-kept list, so a new native dependency needs adding by hand.

# Provenance: safeevidence-release

Admission `ADM-0002` (T11) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, Apache-2.0.
- Adapted: `src/lib.rs` from `release_sbom.rs`, renamed, with `product/Cargo.lock`, desktop `src-tauri/Cargo.lock`,
  desktop `package-lock.json` npm coverage, and 31 native-library classifications added;
  `tests/release_sbom_054.rs`, renamed, nine of eleven donor tests, with Cargo, desktop Cargo, npm, and native-binding coverage tests added.
- Not carried: the committed-document and doctor tests (donor files and modules); `generate-release-sbom.ps1`.
- `src/bin/sbom.rs` and `src/staging.rs` (plus `tests/unsigned_staging_bundle.rs`) are SafeEvidence-written;
  `src/bin/sbom.rs` replaces the donor script, and `src/staging.rs` verifies unsigned offline staging bundles
  against CycloneDX 1.5 SBOM, `THIRD_PARTY_NOTICES.md`, and `tauri.conf.json` (`bundle.active == false`,
  `signed == false`, `release_qualified == false`, `blocking_gate == "EXT-05"`).
- This is engineering evidence. `release_ready` stays false; no signing or reproducible build is claimed. Native
  bindings come from a hand-kept table; an unlisted `links` or `-sys` crate fails the run. The document has not
  been validated against the CycloneDX schema.

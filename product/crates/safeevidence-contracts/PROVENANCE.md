# Provenance: safeevidence-contracts

Admission `ADM-0001` (T01) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-contracts/`, Apache-2.0.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- Copied unchanged: `src/objects/*.rs`.
- Adapted: `src/evidence/mod.rs` (one comment renamed; CRLF line endings normalized to LF);
  `tests/object_*.rs` (crate name only).
- `src/lib.rs` is SafeEvidence-written apart from `AUTHORITY_SCHEMA_VERSION` and its doc
  comment, copied from the donor's `lib.rs` (listed in the row, outside the frozen T01 pins).
- Copied unchanged, listed in the row but outside the frozen T01 pins: `src/text/*.rs`, needed by the pinned
  `tests/text_span_coords.rs`, which is adapted by crate name.
- Adapted from pinned donor tests: `tests/record_semantics_019.rs` keeps four of six tests, with imports changed;
  `tests/source_immutability.rs` is rewritten around `SourceRecord`, because the donor used a store helper and an
  always-failing overwrite stub. Exclusions: `docs/plan/PLAN_AMENDMENT_V1_3.md`.
- `tests/fixtures/t17/` is admission `ADM-0004` (T17): the frozen fixture plus its source note, which is outside
  the frozen pins, with the donor's LICENSE and NOTICE. T17's span code and Python are not copied.
- T01 still carries `ClinicalAssertion` and `confidence` fields; see the ledger's gating note.
- `src/study.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED, transplant matrix §5).
  `src/assurance.rs` is SafeEvidence-written; it encodes the P00 contract vocabulary directly.
- `src/proof.rs` is SafeEvidence-written from the P00 proof contract: shape only, with no atomic commit or verification.
- `decide_pooling` checks independence declarations only. It has no population or timepoint
  input, and is not statistical validation. Refusing overlap chains across groups awaits a
  statistician's ruling.

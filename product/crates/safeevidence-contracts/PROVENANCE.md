# Provenance: safeevidence-contracts

Admission `ADM-0001` (T01) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-contracts/`, Apache-2.0.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- Copied unchanged: `src/objects/*.rs`.
- Adapted: `src/evidence/mod.rs` (one comment renamed; CRLF line endings normalized to LF);
  `tests/*.rs` (crate name only).
- `src/lib.rs` is SafeEvidence-written apart from `AUTHORITY_SCHEMA_VERSION` and its doc
  comment, copied from the donor's `lib.rs` (listed in the row, outside the frozen T01 pins).
- Not copied: three pinned `medscale-core` tests, which need donor modules outside T01.
- `src/study.rs` and `src/assurance.rs` are SafeEvidence-written from the P00 contracts
  (GREENFIELD_JUSTIFIED in the transplant matrix §5).
- Not yet done: the rights and publication fields required by T01's adaptation.

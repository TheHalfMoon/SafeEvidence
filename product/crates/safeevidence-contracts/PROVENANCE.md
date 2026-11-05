# Provenance: safeevidence-contracts

Admission `ADM-0001` (T01) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-contracts/`, Apache-2.0.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- Copied unchanged: `src/objects/*.rs`.
- Adapted: `src/evidence/mod.rs` (one comment renamed); `tests/*.rs` (crate name only).
- `src/lib.rs` is SafeEvidence-written; it re-declares `AUTHORITY_SCHEMA_VERSION` from the donor's `lib.rs`.
- Not copied: three pinned `medscale-core` tests, which need donor modules outside T01.
- Not yet done: WP-02 Study/Report types; the rights and publication fields required by T01's adaptation.

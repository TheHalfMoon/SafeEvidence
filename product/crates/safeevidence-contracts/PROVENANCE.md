# Provenance: safeevidence-contracts

Admission `ADM-0001` (T01) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `crates/medscale-contracts/`, Apache-2.0.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- Copied unchanged: `src/objects/{eval_proj_audit,ids,mod,record_semantics,scope,source,time_effect}.rs`.
- Adapted: `src/evidence/mod.rs` (comment renamed; `scale_corpus_generator_present` set to `false` in `ready_base` with
  `validate_non_clinical()` guard; CRLF line endings normalized to LF);
  `src/objects/authority_classes.rs` and `src/objects/identity.rs` (added fail-closed `P00_DECISION_ASSURANCE_CONTRACT`
  validation methods rejecting unpromoted `Proposal` records and heuristic `confidence` fields on assured V1 surfaces);
  `tests/object_*.rs` (crate name only).
- `src/lib.rs` is SafeEvidence-written apart from `AUTHORITY_SCHEMA_VERSION` and its doc
  comment, copied from the donor's `lib.rs` (listed in the row, outside the frozen T01 pins).
- Copied unchanged, listed in the row but outside the frozen T01 pins: `src/text/*.rs`, needed by the pinned
  `tests/text_span_coords.rs`, which is adapted by crate name.
- Adapted from pinned donor tests: `tests/record_semantics_019.rs` keeps four of six tests, with imports changed;
  `tests/source_immutability.rs` is rewritten around `SourceRecord`, because the donor used a store helper and an
  always-failing overwrite stub. Exclusions: `docs/plan/PLAN_AMENDMENT_V1_3.md`.
- `tests/fixtures/t17/`, `src/span_audit.rs`, `src/offset_projection.rs`, and `tests/t17_span_audit_parity.rs` are
  admission `ADM-0004` (T17, `maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86`, Apache-2.0,
  authorized under Issue #5 D2 for Apache-2.0 span logic and tests only): `tests/fixtures/t17/` carries the frozen
  fixture plus donor `LICENSE` and `NOTICE` (`modification: "none"`), while `src/span_audit.rs`,
  `src/offset_projection.rs`, and `tests/t17_span_audit_parity.rs` are pure-Rust ports of
  `openmed/clinical/evidence_span_audit.py`, `openmed/structured/offset_properties.py`, and
  `tests/unit/clinical/test_evidence_span_audit.py` with bit-for-bit HMAC-SHA256 parity vectors (`openmed/core/schemas/span.py`
  remains `not_copied` because `EvidenceSpan` already resides in `src/proof.rs`; the 6 T17 worker/decoding files remain
  isolated and uncopied in `ADM-0041`).
- `src/document_intake.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED fail-closed magic-byte and hostile-MIME
  quarantine contract supporting `ADM-0007` `T12` `hostile_mime_010.rs` and desktop diagnostics).
- T01's `ClinicalAssertion`, `Proposal.confidence`, and `IdentityAssertion.confidence` are gated against
  `docs/P00_DECISION_ASSURANCE_CONTRACT.md` via `validate_assured_surface()` / `validate_p00_contract()` so no
  unpromoted proposal or heuristic confidence percentage can enter an assured V1 surface.
- `src/study.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED, transplant matrix §5).
  `src/study_linkage.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED `WP-05` + `T28c` `REFERENCE`
  registry/PMID/review containment algorithm; `T15` `litdb` fuzzy title dedupe is not copied and
  remains fenced on `EXT-01`).
  `src/appraisal.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED `WP-10` + `T26` `HL7/ebm`
  `STANDARD_REFERENCE` JSON export crosswalk).
  `src/bilingual.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED `WP-06` Unicode scalar
  normalization and bidirectional coordinate projection, tested against `ADM-0004` `T17` fixtures).
  `src/surveillance.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED `WP-17` watch-query and
  cause-named surveillance alert schemas).
  `src/review_protocol.rs` is SafeEvidence-written (GREENFIELD_JUSTIFIED `WP-14` protocol lock &
  hash-chained audit export and `WP-15` / `TA-17` quote-anchored `Proposed` -> human `Confirmed`
  effect extraction contracts; `T15` screening/PRISMA and `T18`/`T19` worker execution remain
  fenced on `EXT-01`).
  `src/assurance.rs` is SafeEvidence-written; it encodes the P00 contract vocabulary directly.
- `src/proof.rs` is SafeEvidence-written from the P00 proof contract: shape only, with no atomic commit or verification.
- `src/network/mod.rs` is admission `ADM-0015` (T05, `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`,
  Apache-2.0, `ADR-0004`): adapted network mode, allowlist, broker decision, and `TA-30` preview receipt contracts.
- `src/packs/mod.rs` is admission `ADM-0016` (T07, `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`,
  Apache-2.0, `ADR-0004`): adapted Pack v0 manifest, content-addressed entry, and anti-rollback state contracts.
- `src/fhir/mod.rs` is admission `ADM-0017` (T09, `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`,
  Apache-2.0, `ADR-0004`): adapted FHIR R4 interchange, loss-aware diagnostic, and non-clinical scope refusal contracts.
- `src/worker_policy/mod.rs`, `src/os_sandbox/*.rs`, `src/bin/os_sandbox_probe.rs`, `fixtures/worker.entitlements.plist`,
  `tests/os_sandbox_030_*.rs`..`tests/os_sandbox_053_*.rs`, and `tests/worker_policy_deny_default.rs` are admission
  `ADM-0018` (T10, `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, Apache-2.0, `ADR-0004`):
  adapted cross-platform OS worker sandbox plans, probes, and deny-by-default worker supervision policy (`TA-26`).
- `decide_pooling` checks independence declarations only. It has no population or timepoint
  input, and is not statistical validation. Refusing overlap chains across groups awaits a
  statistician's ruling.

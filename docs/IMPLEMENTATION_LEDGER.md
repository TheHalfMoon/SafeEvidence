# SafeEvidence Implementation Ledger

Durable progress record. Status words apply only to the engineering scope named.
Nothing here implies clinical validation, regulatory status or product readiness.

Vocabulary: `NOT_STARTED`, `IMPLEMENTED_UNTESTED`, `TESTED_FAILED`, `TESTED_PASSED`,
`BLOCKED_EXTERNAL`, `ENGINEERING_COMPLETE`, `CLINICALLY_EVALUATED`, `RELEASE_QUALIFIED`.

## Current state (2026-11-05)

| Field | Value |
|---|---|
| `main` at last update | `e284f60c9854f1f1f59d11b094d6d8ab52979c1b` |
| Milestone | M0, in progress |
| Active packet | WP-00 and WP-01 |
| Admissions | ADM-0001 (T01), ADM-0002 (T11 `deny.toml`); G01a baseline holds `NO_ADMISSIONS` |
| Product code | T01 contracts; WP-02 decision vocabulary, proof states and pooling guard. TA-04 not claimed |
| Next executable task | WP-02 Study/Report/Proof types; T11 SBOM generator (TA-02); TA-29 script |

## Milestones

| Milestone | Status | Blocked by |
|---|---|---|
| M0 Admission | `IMPLEMENTED_UNTESTED` for TA-01 until CI passes on the merged commit | Rows beyond ADM-0001 and ADM-0002 ([D2](https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204)), TA-02, TA-03, TA-29 |
| M1 VS-1 (synthetic) | `NOT_STARTED` | M0 |
| M2 Evidence V1 | `NOT_STARTED` | M1; EXT-07 for model work |
| M3 Deep Review | `NOT_STARTED` | M2 |
| M4 Desktop V1 | `NOT_STARTED` | M3 |
| M5 Mobile | `NOT_STARTED` | M4; EGM finding V5 |
| M6 Release candidate | `NOT_STARTED` | EXT-05 |
| Clinical evaluation | Not an engineering milestone | EXT-03 (Issue #4) |

## Verified on `1a10bc5` (Windows, local, 2026-11-05)

| Check | Result |
|---|---|
| `plan_baseline_check.py` | PASS, freeze state FROZEN |
| `p01_preentry_check.py` | Structural PASS; P01-G01 BLOCKED |
| `p01_candidate_integrity.py` | structure PASS; `source_imports` BLOCKED |
| Governance unit tests | 145 run, OK, 21 skipped |
| `cargo test --offline --locked --all-targets` | 3 passed |
| Hosted post-merge CI at `1a10bc5` | P00, P01, G01a all success |
| `cargo fmt`, `cargo clippy` locally | **Not run.** Local 1.97.1 toolchain lacks `cargo-fmt.exe` and `cargo-clippy.exe`; hosted CI covers both |

## Known defects

Before WP-02 closes: T01 carries `ClinicalAssertion` and a `confidence` field, and
`evidence/mod.rs` has a constructor that hardcodes `scale_corpus_generator_present: true`.
All are inert today (no consumer or UI). They must be gated against the P00 contracts
(no V1 clinical confidence percentage) before anything uses them.

See `docs/reviews/EGM_PLAN_CHALLENGE_2026-11-05.md`. Six P0 plan and tooling defects
are verified; none is corrected yet.

## Source imports

See `docs/evidence/source_admissions.json`.

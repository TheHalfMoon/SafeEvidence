# SafeEvidence Implementation Ledger

Durable progress record. Status words apply only to the engineering scope named.
Nothing here implies clinical validation, regulatory status or product readiness.

Vocabulary: `NOT_STARTED`, `IMPLEMENTED_UNTESTED`, `TESTED_FAILED`, `TESTED_PASSED`,
`BLOCKED_EXTERNAL`, `ENGINEERING_COMPLETE`, `CLINICALLY_EVALUATED`, `RELEASE_QUALIFIED`.

## Current state (2026-11-05)

| Field | Value |
|---|---|
| `main` at last update | `61fd74c6f1a7b63f116bd1b91dd17a56af5093c4` |
| Milestone | M0, in progress |
| Active packet | WP-00 and WP-01 |
| Admissions | ADM-0001 (T01), ADM-0002 (T11 `deny.toml`), ADM-0003 (T03); G01a baseline holds `NO_ADMISSIONS` |
| Product code | T01 contracts; WP-02 decision vocabulary, proof states and pooling guard. TA-04 not claimed ; T03 vault slice, TA-05 not claimed |
| Next executable task | WP-02 Study/Report/Proof types; T11 SBOM generator (TA-02); TA-29 script |

Required checks on `main` (founder decision, 2026-11-05): `foundation-documents`, `preentry structure`, `synthetic-only`
and `product`, the last three on Ubuntu, Windows and macOS.

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

**TA-03:** Linux (empty network namespace) and macOS (sandbox profile) run all checks under OS-level denial.
Windows blocks named programs only, because default-deny outbound lost the hosted runner. Its build and build
scripts run before the block, and unlisted programs are not blocked. TA-03 and A4 require isolation on all three
OSes, so TA-03 stays unpassed unless a versioned amendment accepts the Windows form.

**Sequencing breach:** T03 merged before TA-03 and TA-04 passed, ahead of the frozen WP-01 and WP-02
exits it depends on. Publication cannot be undone. WP-01, WP-02, M0 and M1 exit stay open until both pass.

T03 shares `HIMSAT/...` domain strings with the donor. Windows DPAPI entropy and recovery envelopes are
therefore compatible across the two products. Separate these before any release; independent test
vectors must be recomputed outside the code when that happens, and fixed wire offsets must not shift.

Before WP-02 closes: T01 carries `ClinicalAssertion` and a `confidence` field, and
`evidence/mod.rs` has a constructor that hardcodes `scale_corpus_generator_present: true`.
All are inert today (no consumer or UI). They must be gated against the P00 contracts
(no V1 clinical confidence percentage) before anything uses them.

See `docs/reviews/EGM_PLAN_CHALLENGE_2026-11-05.md`. Six P0 plan and tooling defects
are verified; none is corrected yet.

## Source imports

See `docs/evidence/source_admissions.json`.

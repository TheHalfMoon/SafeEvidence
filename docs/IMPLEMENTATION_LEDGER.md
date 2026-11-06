# SafeEvidence Implementation Ledger

Durable progress record. Status words apply only to the engineering scope named.
Nothing here implies clinical validation, regulatory status or product readiness.

Vocabulary: `NOT_STARTED`, `IMPLEMENTED_UNTESTED`, `TESTED_FAILED`, `TESTED_PASSED`,
`BLOCKED_EXTERNAL`, `ENGINEERING_COMPLETE`, `CLINICALLY_EVALUATED`, `RELEASE_QUALIFIED`.

## Current state (2026-11-05)

| Field | Value |
|---|---|
| `main` at last update | `ec04607010abac35e38f5084a9d71bad269f1707` |
| Milestone | M0 open for rows; M1 VS-1 steps 1 and 3 in review |
| Active packet | WP-00 and WP-01 rows; VS-1a headless path |
| Admissions | ADM-0001 (T01), ADM-0002 (T11 `deny.toml` and SBOM generator), ADM-0003 (T03), ADM-0004 (T17 fixture), ADM-0005 (T13, no files copied); G01a baseline holds `NO_ADMISSIONS` |
| Product code | T01 contracts; WP-02 decision vocabulary, proof states and pooling guard. TA-04 passed as narrowed by `plan-v1.3`; T03 vault slice, TA-05 not claimed; headless Ask over an invented fixture, with an atomic proof commit in the keyed vault |
| Next executable task | Tauri Ask view (`plan-v1.1` §C step 4); rows for T12, T30, T36; socket-crate defect |

Required checks on `main` (founder decision, 2026-11-05): `foundation-documents`, `preentry structure`, `synthetic-only`
and `product`, the last three on Ubuntu, Windows and macOS.

## Milestones

| Milestone | Status | Blocked by |
|---|---|---|
| M0 Admission | In progress: TA-01 `TESTED_PASSED` in CI; TA-03 `TESTED_PASSED` under `plan-v1.2`; TA-04 `TESTED_PASSED` as narrowed by `plan-v1.3`; TA-29 HTTP-client clause `TESTED_PASSED`; TA-02 `TESTED_PASSED` | Rows for T12, T13, T30, T36 |
| M1 VS-1 (synthetic) | Steps 1 and 3 of `plan-v1.1` §C `TESTED_PASSED` at their own scope; step 2 partial | M0 rows; TA-13; desktop; open defects below |
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

**TA-13 is not met.** T13 is ported as mechanics, with 1,329 parity vectors from the donor's code. Its fixture subset does
not run: those cases need a tool and slot layer and a role V1 does not serve. Exactly-one `TerminalOutcome` is not yet a property of
this crate. `safeevidence-ask` resolves its evidence guards through it, but `plan-v1.1` §C step 2's parity is incomplete. Amend or build this
before M1 exit.

**Sockets in the core's tree:** TA-29's named HTTP clients are absent, but `mio` and `socket2` are present through
`tokio` and `zbus`, for the Linux Secret Service protector in T03. Architecture §2 says the core opens no sockets, and
TA-29 does not name these crates. `zbus` also contains TCP transport code, so a local-only rule would need an address
restriction. Resolve before M1 exit: move the protector out of the core process, or amend the rule with TA-21 evidence.
TA-29's tree check covers normal dependencies. Build-only crates such as `cc` and `openssl-src` are covered by the
`cargo deny` bans.

**`plan-v1.3` immutability:** tested against the keyed vault store in `safeevidence-proofstore`, with triggers and guarded SQL.
**`plan-v1.3` lineage: partly owed.** The store amends sources, not the prior assertion, and keeps no `AmendmentRecord` fields.
This guards against bugs, not malicious in-process code, and covers process kills, not power loss. P00 proof steps 1 and 2 are the
caller's job, and `ProofStore::commit` trusts them. `COMMIT_UNKNOWN` is surfaced with no recovery flow beyond idempotent retry. The guard's fixtures test declared structure only, not extraction or statistics.

**TA-03:** Linux (empty network namespace) and macOS (sandbox profile) run all checks under OS-level denial.
Windows blocks named programs only, because default-deny outbound lost the hosted runner. Its build and build
scripts run before the block, and unlisted programs are not blocked. Post-merge CI passed at `e06f7ea`, so TA-03 passes
under `plan-v1.2`. TA-03 and A4 require isolation on all three
OSes. The founder accepted the Windows form for now (`docs/plan/PLAN_AMENDMENT_V1_2.md`), to be revisited before
any release. TA-03 passes only when its controls pass in CI on all three OSes on the exact commit.

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

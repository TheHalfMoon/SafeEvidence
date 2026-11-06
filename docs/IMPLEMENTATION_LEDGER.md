# SafeEvidence Implementation Ledger

Durable progress record. Status words apply only to the engineering scope named.
Nothing here implies clinical validation, regulatory status or product readiness.

Vocabulary: `NOT_STARTED`, `IMPLEMENTED_UNTESTED`, `TESTED_FAILED`, `TESTED_PASSED`,
`BLOCKED_EXTERNAL`, `ENGINEERING_COMPLETE`, `CLINICALLY_EVALUATED`, `RELEASE_QUALIFIED`.

## Current state (2026-11-06)

| Field | Value |
|---|---|
| `main` at last update | `50a1caf6f037e617f8db97e8e2a5ab67175c83e4` |
| Milestone | M0 open for its exit review; M1 VS-1 in progress, per the table below |
| Active packet | WP-00 and WP-01 rows; WP-18a Ask view |
| Admissions | ADM-0001 (T01), ADM-0002 (T11 `deny.toml` and SBOM generator), ADM-0003 (T03), ADM-0004 (T17 fixture), ADM-0005 (T13, no code copied), ADM-0006 (T36), ADM-0007 (T12), ADM-0008 (T30), ADM-0009 (T03's Linux helper); G01a baseline holds `NO_ADMISSIONS` |
| Product code | T01 contracts; WP-02 decision vocabulary, proof states and pooling guard. TA-04 passed as narrowed by `plan-v1.3`; T03 vault slice, TA-05 not claimed; headless Ask over an invented fixture, with an atomic proof commit in the keyed vault |
| Next executable task | M1 exit items: key custody with helper packaging, end-to-end WebView test |

Required checks on `main` (founder decisions, 2026-11-05 and 2026-11-06): `foundation-documents`, `preentry structure`,
`synthetic-only`, `product` and `desktop`, the last four on Ubuntu, Windows and macOS.

## Milestones

| Milestone | Status | Blocked by |
|---|---|---|
| M0 Admission | In progress: TA-01 `TESTED_PASSED` in CI; TA-03 `TESTED_PASSED` under `plan-v1.2`; TA-04 `TESTED_PASSED` as narrowed by `plan-v1.3`; TA-29 HTTP-client clause `TESTED_PASSED`; TA-02 `TESTED_PASSED` | Exit review, including crate closures; open defects below |
| M1 VS-1 (synthetic) | Steps 1 and 3 of `plan-v1.1` §C `TESTED_PASSED` at their own scope; step 2 partial; step 4 `IMPLEMENTED_UNTESTED` end to end, TA-20 not claimed | M0 exit review; desktop; helper packaging and key custody; open defects below |
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

**TA-13 for VS-1 is narrowed by `plan-v1.4`** (founder decisions, 2026-11-06). Its VS-1 clauses have tests: 1,329 mechanics vectors, 12 of 17 donor fixture cases at resolution level, all 17 questions
through `ask`, and the lexical-emergency test. This shows little beyond the vectors, because no case runs through V1 to a matching outcome, and the amendment states that. TA-13 as a whole is not met: its DAL vectors are
owed at WP-11. Ask also uses `EVIDENCE_INSUFFICIENT` for a question it could not parse, before retrieval runs, because no allowed code fits better.

**Sockets in the core's tree:** the founder chose a separate helper process (2026-11-06). `safeevidence-linux-keyring-helper` now holds the Secret Service and D-Bus code, and the vault reaches it over stdin and stdout.
`tools/ci/core_no_sockets.py` checks the core crates' normal dependencies on each desktop target, and `ta29_desktop_denial.py` holds the desktop shell, the process that hosts the core, to the crates that give it sockets. `tokio` remains there for Tauri,
with no `mio`. These read dependency trees, so they do not detect a socket opened through `std::net`, and TA-21 has not observed the running process. **Still open before M1 exit:** nothing installs the helper beside the app, and the shell does not use the
protector, which waits on key custody. TA-29's tree check covers normal dependencies. Build-only crates such as `cc` and `openssl-src` are covered by the
`cargo deny` bans.

**T30 is narrower than WP-00 names:** only the tool-source audit is adapted. The donor's registry and its notice and SBOM generators are not copied, because
`source_admission_check.py`, the T11 SBOM generator and `cargo deny` already do that work, and a second registry would have to be kept in sync. The audit runs in
the governance tests. It does not cover shell scripts or the app's npm tree, and it lists named modules only, so `requests` would pass. No TA row relied on the
donor's registry or generators.

**Crate closures:** `plan-v1.1` B6 also lists crate closures keyed to `product/Cargo.lock`. No `CRATE-*` admission row exists. Today `Cargo.lock` is the exact closure
and `cargo deny` enforces it. Whether that meets B6 is open for M0's exit review, not settled.

**T12:** the residue scan covers one store directory, live and closed, so `TA-05` is not claimed. Its MIME test returns at WP-13.

**Desktop shell:** the Ask view uses a new in-memory key and a throwaway store per launch, so answers do not survive a restart, and T03's OS
protectors are not wired in. Tests use Tauri's mock runtime, so TA-20, TA-21 and TA-22 are not claimed. The app's trees are outside TA-02's SBOM
and `product/deny.toml`. Tauri pulls `reqwest` and `hyper` on Android and iOS: resolve before M5.

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

# Plan Amendment `plan-v1.1` (2026-11-05)

State: **PROPOSED until merged with its review record.** Amends the `plan-v1.0.0`
baseline by pointer. The frozen artifacts and their digests in `docs/PLAN_FREEZE.md`
stay unchanged; where they differ, this amendment controls.

Evidence: `docs/reviews/EGM_PLAN_CHALLENGE_2026-11-05.md`. Frozen decisions D-01 to D-16
are kept. This amendment closes no rights, clinical, trust or regulatory gate, and lowers
no acceptance threshold.

## A. Repository layout

| ID | Amends | Change | Reason |
|---|---|---|---|
| A1 | C16, EXT-02 | G01a stays unchanged at the root. Product code uses the nested `product/` workspace on Rust 1.98.1 | Keeps the qualified baseline; already ratified in `docs/decisions/M0_EXT02_RATIFICATION_2026-11-05.md` |
| A2 | Matrix destinations | `crates/...` destinations become `product/crates/...` | Follows A1 |
| A3 | TA-01, WP-00 | TA-01 is implemented by `tools/governance/source_admission_check.py`. `p01_candidate_integrity.py` keeps rejecting admissions | The old checker rejects all admissions by design |
| A4 | TA-03 | "Network disabled after fetch" means Cargo `--offline` on hosted CI, not OS-level isolation | States what CI really does; OS-level egress stays TA-21 |

## B. Specification corrections

| ID | Amends | Change | Reason |
|---|---|---|---|
| B1 | WP-22, TA-25, D-01 | PDF and OCR leave M5 until an OS-isolated mobile process passes a mobile TA-26 row. Mobile Ask and saved briefs stay in scope | Architecture §2 forbids parsing documents in the core |
| B2 | TA-10, WP-08, D-07 | The engineering holdout must be named, with labeller and denominator, before the run. The gate uses the CI upper bound and a pre-registered minimum coverage. If no verifier model passes, the path is `ABSTAIN` | A refuse-everything verifier passes today's gate |
| B3 | TA-06, §4 store table | Validity changes arrive as a signed delta overlay. Retracted items are excluded from citation and stay visible with explicit state | Resolves the conflict with `docs/ARCHITECTURE.md:262` |
| B4 | §4 worker scratch | A per-job key is issued to the worker, or the worker runs memory-only and fails closed | A worker cannot use a key held only by the core |
| B5 | Master plan §7.2, register | For private donors with published admission, rows list exact paths and blob OIDs once publication is decided (T03, T30: Issue #5, D4). For the rest, commitment rows are allowed but no bytes enter the public tree | Resolves the conflict between §7.2 and EXT-08 |
| B6 | WP-00 | The first rows are T01, T03, T11, T12, T13, T17 (span logic and tests only), T30 and T36, plus crate closures keyed to `product/Cargo.lock` | Frozen list omits T11 and T30, which WP-00 itself copies |

## C. VS-1a route

Acceptance is unchanged: vault and desktop are still required before VS-1 is done.

1. Headless path: fixture, FTS5, deterministic checks, applicability, sufficiency, outcome.
   Stops at `VERIFIED_UNCOMMITTED`.
2. T03 subset and atomic `AnswerProofManifest` commit.
3. T13 parity on the P00-conformant subset.
4. Tauri Ask view (T36).

Deferred from VS-1a: T05, T07, T14, T15, WP-23a (to M2 entry) and Arabic normalization.
Arabic queries return reason-coded abstention, which TA-08 allows. RTL rendering and
Arabic offsets stay in scope. A digest-checked fixture loader replaces T07 for VS-1a; it
gives no pack-trust claim.

## D. Open, not adopted

These EGM reports have not been independently verified. Each needs checking before it is
adopted or rejected: ONNX in-core sandbox gap; TA-09 study-labelled set and paired
statistics; hybrid fusion definition; PICO path without a generator; budget coverage and
WP-M0 ordering; TA-29 coverage of non-Rust code; satisfiability of TA-14, TA-21, TA-29 and
TA-09 for VS-1; npm in SBOM and license gates; free-CI fit of TA-15 and TA-25; VS-1b double
counting before WP-05; T28b, T28d, T34 and T27b risk.

## E. Review record

Required by `docs/GAP_REVIEW.md`: two independent reviews, recorded on the PR that merges
this file. Whether a second independent reviewer of a different kind is available is stated
there. An AI agent review does not satisfy EXT-06.

# Plan Amendment `plan-v1.1` (2026-11-05)

State: **PROPOSED. Not in force until merged with the reviews in §F.** Amends the
`plan-v1.0.0` baseline by pointer. The frozen artifacts and their digests in
`docs/PLAN_FREEZE.md` stay unchanged; where they differ, this amendment controls.

Evidence: `docs/reviews/EGM_PLAN_CHALLENGE_2026-11-05.md`. This amendment closes no rights,
clinical, trust or regulatory gate and lowers no acceptance threshold. It amends the
specifics of D-01 (B1) and D-07 (B2), and the M1 and VS-1 scope (§C). Other frozen decisions
are unchanged.

## A. Repository layout

| ID | Amends | Change | Reason |
|---|---|---|---|
| A1 | C16, EXT-02 | G01a stays unchanged at the root. Product code uses the nested `product/` workspace on Rust 1.98.1 | Keeps the qualified baseline; ratified in `docs/decisions/M0_EXT02_RATIFICATION_2026-11-05.md` |
| A2 | Matrix destinations | `crates/...` becomes `product/crates/...`; T36 `apps/desktop` becomes `product/apps/desktop`; T12 `tests/privacy` becomes `product/tests/privacy`; T30 `tools/governance` becomes `tools/governance/donor` | Follows A1; these are the validator's admitted roots |
| A3 | TA-01, WP-00 | TA-01 is implemented by `tools/governance/source_admission_check.py`. `p01_candidate_integrity.py` keeps rejecting admissions | The old checker rejects all admissions by design |
| A4 | None (clarification) | **TA-03 is unchanged.** Current `product` CI uses Cargo `--offline`, which is not network-disabled, so TA-03 stays unpassed until OS-level isolation runs on all three OSes | Records the gap without lowering the row |

## B. Specification corrections

| ID | Amends | Change | Reason |
|---|---|---|---|
| B1 | WP-22, TA-25, D-01 | PDF and OCR leave M5 until an OS-isolated mobile process passes a mobile TA-26 row. Mobile Ask and saved briefs stay in scope | Architecture §2 forbids parsing documents in the core |
| B2 | TA-10, WP-08, D-07 | All TA-10 gates stay. Added: the engineering holdout is named, with labeller and denominator, before the run; its limit uses the CI upper bound; a pre-registered, nonzero minimum coverage applies. If no verifier passes, TA-10 stays FAIL, M2 stays not done, and Ask uses deterministic checks or `ABSTAIN` | The unsupported-claim limit alone can be met by refusing everything |
| B3 | TA-06, §4 store table | TA-06 search removal stays. Validity changes, including correction and supersession, arrive as a signed delta overlay with a monotonic epoch. Affected sources are refused at proof admission and stay visible with explicit state. Historical proofs keep their bytes and show `CURRENTLY_INVALIDATED` | Resolves the store conflict and `docs/ARCHITECTURE.md:262`, consistent with the proof contract |
| B4 | §4 worker scratch | A per-job key is issued to the worker, or the worker runs memory-only and fails closed | A worker cannot use a key held only by the core |
| B5 | Master plan §7.2, register | T03 and T30: rows list exact paths and blob OIDs, because publication was approved (Issue #5, D4). Other private donors, including T14: paths stay withheld under EXT-08, and no row or bytes enter the public tree until publication is approved. The validator has no commitment-row form | Resolves the conflict between §7.2 and EXT-08 |
| B6 | WP-00 | First rows: T01, T03, T11, T12, T13, T17 (span logic and tests only), T30, T36, plus crate closures keyed to `product/Cargo.lock`. Removed from the first set: T05, T07, T14, T15. Added: T11, T12, T30 | The frozen list omits files WP-00 and WP-03 copy; removals follow §C |
| B7 | P00 decision contract reason codes | Reason-code schema v1.1 adds `UNSUPPORTED_LANGUAGE`, used with `ABSTAIN`. The contract and the Rust enum change in the same PR as this file | Architecture §6 requires a reason-coded outcome; no allowed code fits |

## C. VS-1a route

Amends the M1 packet list and the VS-1 execution order. Reason: earliest end-to-end proof,
with no reduction in what VS-1 must finally pass.

1. Headless path: fixture, PICO normalization, FTS5, deterministic checks, applicability,
   sufficiency, template brief, outcome. The brief is frozen as the candidate. Stops at
   `VERIFIED_UNCOMMITTED`.
2. T13 parity on the P00-conformant subset.
3. T03 subset and atomic `AnswerProofManifest` commit.
4. Tauri Ask view (T36).

Deferred from VS-1a: T14, T15, WP-23a (to M2 entry, valid only while VS-1a runs no worker
process), and Arabic normalization (returns with WP-06's V1 promotion gate). With no worker in
VS-1a, TA-14's crash and timeout clauses use fault injection at the brief step, and the real
worker clauses return with the WP-12 generator. Arabic queries return `ABSTAIN` with
`UNSUPPORTED_LANGUAGE`, which TA-08's VS-1 gate allows. RTL rendering and Arabic offsets stay
in scope. TA-08 joins the VS-1 done list.

T05 and T07 are deferred from VS-1a only. VS-1a records `NETWORK_LOCKED` capture evidence; that
is evidence, not a TA-21 pass. T05 returns before VS-1 is done, because TA-21 needs both halves. A digest-checked fixture
loader replaces T07 for VS-1a; it carries a validity epoch and rights state, fails closed when
either is absent, and gives no pack-trust claim.

TA-29 splits by clause: its Xberg clauses bind WP-13, where T20 enters; the HTTP-client denial
clause binds WP-01 and VS-1 as written. This moves when the Xberg clauses apply, not what they require.

## D. Open, not adopted

These EGM reports have not been independently verified. Each needs checking before it is adopted
or rejected: ONNX in-core sandbox gap; TA-09 study-labelled set and paired statistics; hybrid fusion
definition; PICO path without a generator; budget coverage and WP-M0 ordering; TA-29 coverage of
non-Rust code; satisfiability of TA-14, TA-21, TA-29 and TA-09 for VS-1; npm in SBOM and license
gates; free-CI fit of TA-15 and TA-25; VS-1b double counting before WP-05; T28b, T28d, T34 and T27b
risk.

## E. Work not dependent on this amendment

The frozen sequence continues meanwhile where it needs nothing here, including WP-03 (T03) and
WP-06 span work under existing rows and decisions. §C ordering and B7 apply only once in force.

## F. Review requirements

`docs/GAP_REVIEW.md` names Codex and Claude/Opus reviews. The founder instructed on 2026-11-05: "do not
use codex". No Codex review of this amendment exists, and none will be run. It needs an independent
review of its final text, recorded on the PR that merges this file. An AI agent review does not satisfy
EXT-06.

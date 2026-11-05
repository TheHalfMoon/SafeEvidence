# EGM Challenge of Plan V1 — Difference Report (2026-11-05)

Target: `main` `1a10bc59e452c6486aced95227fa1e8be53bad20` (tag `plan-v1.0.0`).
State: **PROPOSALS ONLY.** No frozen artifact changes here. Adoption needs a
versioned `plan-v1.x` amendment (`docs/PLAN_FREEZE.md` §1). This report approves
no import, scope, rights, clinical or release gate.

## 1. Reviews actually run

| Review | Tool | Result |
|---|---|---|
| Design critic | EGM 0.1.0 (`google/elephant-goldfish-model`, plugin SHA `403d8881`), `egm-design`, zero-context | 2 P0, 9 P1, 1 P2 |
| Implementation readiness | EGM `egm-implementation-readiness`, zero-context | 3 P0, 8 P1, 1 P2 |
| Scope | EGM `egm-zoom-out`, zero-context | 2 blockers, 6 major |
| Author verification | Claude Opus 5.5, direct reading of the cited lines | See "Verified" column |

All three EGM reviews were static document and code reading. EGM reviewers are
AI agents: this is not independent human review and does not satisfy EXT-06.

Not completed:

- **D1 (`d1_decide`):** server online; three calls with different question
  shapes each returned HTTP 400. No D1 result exists.
- **Alibaba Open Code Review:** `ocr` v1.13.5 is installed; not run because this
  change contains no code.
- **PStack:** no installed tool. A skills mirror is checked out locally
  (`backnotprop/pstack` @ `18b6c36`); no PStack review was run.

## 2. Findings verified by the author

| # | Sev | Defect | Evidence | Smallest correction | Route |
|---|---|---|---|---|---|
| V1 | P0 | Required CI forces gates to stay closed: naming an owner, or recording any admission, fails | `tools/governance/p01_preentry_check.py:177,188`; `p01_candidate_integrity.py:223`; `.github/workflows/p00-foundation-docs.yml:60` | One state validator: empty ledger **or** every row passes TA-01; tracker row open **or** carries owner plus evidence. Stricter than today | Governance PR |
| V2 | P0 | G01a locks the root workspace: one lockfile package, one member, toolchain 1.97.1, while C16 requires ≥ 1.98.1 | `tools/governance/g01a_synthetic_check.py:153-180` | Move G01a to its own nested workspace unchanged; TA-03 and TA-29 govern the new root | Signed EXT-02 PR |
| V3 | P0 | Workflow cannot build third-party crates: all steps are offline, with no fetch step | `.github/workflows/g01a-synthetic-reproducibility.yml:55,58` | Add a locked-fetch step in a separate workflow; re-pin workflow fingerprints | Signed EXT-02 PR |
| V4 | P0 | WP-00 admission list omits what WP-00 itself copies (T11, T30) | `IMPLEMENTATION_WORK_PACKETS_V1.md:17` | Correct the row list (see §4) | `plan-v1.1` |
| V5 | P0 | Mobile compiles document parsing into the core, which the architecture forbids | `ARCHITECTURE_SPEC_V1.md` §2 vs `IMPLEMENTATION_WORK_PACKETS_V1.md:41` | Remove PDF/OCR from M5 until an isolated mobile process passes a mobile TA-26 row | `plan-v1.1` |
| V6 | P0 | TA-10 can pass by refusing everything: no coverage floor, and "engineering holdout" is undefined | `TEST_ACCEPTANCE_MATRIX_V1.md:22` | Define the holdout; gate on CI upper bound plus minimum coverage | `plan-v1.1` |
| V7 | P1 | Validity overlays conflict with a store that changes "only by installing a new signed pack"; TA-06 removes retracted items while the architecture keeps them visible | `ARCHITECTURE_SPEC_V1.md` §4; `TEST_ACCEPTANCE_MATRIX_V1.md:18` | Signed delta overlay; retracted sources flagged and non-citable | `plan-v1.1` |
| V8 | P1 | Worker scratch key is "held only by the core", so a worker cannot use its own scratch | `ARCHITECTURE_SPEC_V1.md` §4 | Per-job key issued to the worker, or memory-only and fail closed | `plan-v1.1` |
| V9 | P1 | Private-donor rows cannot satisfy per-file blob OIDs, because paths are withheld; copying T03 into this public tree publishes that code anyway | Master plan §7.2; `PLAN_FREEZE.md` EXT-08 | Founder publication decision (D4 in the decision packet) | Founder + `plan-v1.1` |
| V10 | P1 | Existing candidate pin for T11 differs from the transplant pin (`37f5ae8` vs `5c33d77`) | `docs/evidence/p01_donor_candidates_2026-10-08.json`; matrix T11 | Admit at one exact revision | Admission row |

## 3. Reported by EGM, not yet independently verified

Carry into `plan-v1.1` review; treat as unproven until checked.

- ONNX inference runs inside the core process, outside TA-26 (design 10).
- TA-09 lacks a study-labelled held-out set and paired statistics (design 5).
- Hybrid fusion across stores is undefined (design 6).
- PICO extraction has no production path without a generator (design 3).
- Budget gaps: dense and NLI steps, and WP-M0 ordering (design 8, 9).
- TA-29 misses non-denylisted clients and non-Rust code (design 12).
- TA-14, TA-21, TA-29 and TA-09 are unsatisfiable as written for VS-1 (readiness 4-7).
- VS-1 done-list gaps: TA-08 absent, TA-05 subset undefined (readiness 8).
- npm dependencies are outside SBOM and license gates (readiness 11).
- TA-15 and TA-25 may not fit free hosted CI (readiness 12; the reviewer marked these unverified).
- VS-1b could double-count studies before WP-05 (scope 7).
- T28b, T28d, T34 and T27b add risk beyond their value (scope 8).

## 4. Proposed shortest route to VS-1a

Needs `plan-v1.1`. The acceptance bar does not fall: vault and desktop remain
required before VS-1 is done.

1. Headless path: fixture → FTS5 → deterministic checks → applicability →
   sufficiency → outcome. Stops at an uncommitted, verified state.
2. T03 subset and atomic AnswerProofManifest commit.
3. T13 parity on the P00-conformant subset.
4. Tauri Ask view (T36).

Proposed first admission set: T01, T03, T11, T12, T13, T17 (span logic and tests
only), T30, T36, plus the crate closures of `rusqlite` and `tauri`.

Deferred from VS-1a: T05, T07, T14, T15, WP-23a (to M2 entry) and Arabic
normalization. Arabic queries return reason-coded abstention, which TA-08 allows;
RTL rendering and offsets stay in scope.

## 5. Facts that have changed since the freeze

- `TheHalfMoon/MedScale` now resolves to `AbdulazizShehri/MedScale`. The T01 pin
  still resolves.
- `TheHalfMoon/MedOrigin` now resolves to `AbdulazizShehri/MedOrigin`, which is
  **private**. The matrix and pins record T15 as public. The pin still resolves.
- `main` protection has `required_approving_review_count: 0`. The written founder
  waiver covers "the planning freeze only" (`PLAN_FREEZE.md` §1). See D3 in the
  decision packet.

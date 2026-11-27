# Wave 4 (`plan-v1.7` / PR #101) Hybrid Retrieval, Bilingual NLI, Systematic Review, Meta-Analysis & 12-Split Bench Review Record

- **Date:** `2026-11-27`
- **Branch:** `safeevidence/wave4-hybrid-retrieval-review-meta-bench-20261127`
- **Base `main` SHA:** `a55ebf8b5a5e680105e42be68c9dc514ff258187` (PRs #91–#100 & PR #43 merged; 7/7 post-merge `main` workflows `success`: `46063728056`, `46063728089`, `46063728087`, `46063728135`, `46063728076`, `46063728106`, `46063728083`)
- **Governing Authorities:** `docs/plan/PLAN_AMENDMENT_V1_7.md`, `docs/adr/0001..0004`, `docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md`, `docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`, `SECURITY.md`
- **Truth-in-Qualification Declaration:** `AI_ASSISTED_SECURITY_QUALIFICATION = ACTIVE`, `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`, `OS_CA_CODE_SIGNED = FALSE`, `ACTUAL_CLINICAL_VALIDATION = FALSE`, `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`.

---

## 1. Public-License Source Admissions Promoted (`ADR-0004`) & Lockfile Closure Audit

1. **`ADM-0019` (`T15`, `TA-16` — PRISMA 2020 Screening State Machine, Log Replay & 2-Pass Conflict-Safe Deduplication):**
   - Donor: `TheHalfMoon/MedOrigin` @ `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8` (`Apache-2.0`).
   - Targets: `product/crates/safeevidence-review` (`src/{records,screening,dedupe,prisma_review}.rs`, `tests/t15_litdb_{dedupe,prisma_review}.rs`, `PROVENANCE.md`).
2. **`ADM-0021` (`T18`, `TA-16` — Active-Learning Screening Classifiers, Queriers, Stoppers & `WSS@95` Metrics):**
   - Donor: `asreview/asreview` @ `79d568212b2b0a78f9fd7be3c5117dfb890489f9` (`Apache-2.0`; verbatim `LICENSE` preserved at `tests/fixtures/t18/LICENSE`).
   - Targets: `product/crates/safeevidence-review` (`src/{active_metrics,classifiers,queriers,stoppers}.rs`, `tests/t18_asreview_screening.rs`).
3. **`ADM-0022` (`T19`, `TA-07`, `TA-18` — Quantitative Meta-Analysis & Study-Independence Pre-Gate):**
   - Donor: `statsmodels/statsmodels` @ `b7ec3a7c1a448ed79d75489da4cde6c304c79a21` (`BSD-3-Clause`; full copyright & license notice in `THIRD_PARTY_NOTICES.md`).
   - Targets: `product/crates/safeevidence-meta` (`src/lib.rs`, `tests/t19_meta_analysis.rs`, `PROVENANCE.md`).
4. **`ADM-0030` (`T27` — Benchmark-Only SciFact Sentence/Abstract F1 Evaluator):**
   - Donor: `allenai/scifact` @ `68b98a56d93e0f9da0d2aab4e6c3294699a0f72e` (`Apache-2.0`; verbatim `LICENSE.md` preserved in `bench/scifact/LICENSE.md`).
   - Targets: `bench/scifact/{scifact_data.py,scifact_metrics.py,test_scifact_eval.py,PROVENANCE.md}` (Python stdlib only; never imported by shipped product binaries).
5. **`ADM-0032` (`T28` — Benchmark-Only Evidence-Inference PICO Span & 3-Class Macro-F1 Evaluator):**
   - Donor: `jayded/evidence-inference` @ `a661e8c14f973398380c8865cf2f27a535aaaf6d` (`MIT`; verbatim `LICENSE` preserved in `bench/evidence_inference/LICENSE`).
   - Targets: `bench/evidence_inference/{ei_schema.py,ei_eval.py,test_ei_eval.py,PROVENANCE.md}` (Python stdlib only; never imported by shipped product binaries).
6. **Lockfile Closures (`ADM-0010` & `ADM-0011`):**
   - `ADM-0010` (`product/Cargo.lock`): `181` packages (`179 -> 181` internal workspace crates `safeevidence-meta` and `safeevidence-review`; zero new external crates.io packages).
   - `ADM-0011` (`product/apps/desktop/src-tauri/Cargo.lock`): `464` packages (`462 -> 464` internal workspace crates; `619` total CycloneDX SBOM components verified by `TA-02`).

---

## 2. Google EGM Hostile Mathematical, Statistical & Security Review (`827a8139`) — `11/11 RESOLVED`

- **`B-1` (`safeevidence-meta` Numerical Stability, Boundary $\tau^2=0$ PM Convergence & Non-Poolable Report Kinds):**
  - Evaluated $Q(0)$ at $\tau^2 = 0$ prior to Newton-style Paule-Mandel iteration in `fit_tau_iterative` so homogeneous ($Q(0) = 0$) or low-dispersion ($Q(0) - \text{df} \le \text{atol}$) sets deterministically return `(0.0, true)` regardless of `tau2_start`.
  - Validated `tau2_start.is_finite() && tau2_start >= 0.0`, `atol.is_finite() && atol > 0.0`, `maxiter > 0`, `row_names` length, and `(1.0 / v).is_finite()` fail-closed in `combine_effects_with_options`, returning `Err(MetaError::ConvergenceFailed)` if `!tau2_converged`.
  - Scaled `effectsize_smd` pooled SD by `s1.max(s2)` to prevent $s^2$ underflow/overflow at extreme magnitudes (`1e-200`..`1e200`), guarded zero-variance proportion arms (`RiskDifference` all-zero/all-event with `ZeroCorrection::None`), used `(-p).ln_1p()` in `LogOddsRatio`, added domain guards to `normal_isf`, `student_t_isf`, `fit_tau_mm`, and `fit_tau_iter_mm`, and refused `ReportVersionKind::Retraction | ExpressionOfConcern` in `combine_independent_studies`.
- **`B-2` (`safeevidence-review` Pass-1 Connected-Component Deduplication & Empty-ID Guard):**
  - Normalized all four identifier fields consistently via `norm_opt` in `Identifiers::canonical_record_id()`, kept invalid/empty-ID records unmerged (routing each to `UncertainEntry`), and upgraded Pass 1 in `dedupe_records` to union-find connected components across shared non-empty normalized `(doi, pmid, arxiv_id, s2_corpus_id)` values (merging conflict-free partial tuples while routing conflicting secondary IDs or >1-year gaps to `UncertainEntry`).
- **`B-3` (`safeevidence-contracts/src/guideline.rs` `EvidenceSnapshot` Full-Manifest Digest & `Committed` Gate):**
  - Enforced `manifest.state == ProofState::Committed` and BiDi/control checks on `snapshot_id`/`question_text` in `EvidenceSnapshot::build` and `validate`, and bound every field of `AnswerProofManifest`, `ProofComponents` (all 10 fields), `ProofClaim` (`support`, `studies`, `results`), and `EvidenceSpan` (`source_version`) via length-prefixed SHA-256 framing in `compute_snapshot_digest`.
- **`B-4` (`safeevidence-ask/src/nli_verifier.rs` Clause Polarity, Comparator Role Swap, Contradiction Precedence & Composed Effect Polarity):**
  - Scanned all candidate sentences in `source` before returning `Entails` (`Contradicts` > `Entails` > `Neutral`), resolved mixed-direction sentences (`increased A and reduced B`) at sub-clause granularity, added `has_comparative_role_swap` (`more than`, `vs`, `compared with`, `مقابل`, etc.), canonicalized decimal/comma-grouped numbers with `(number, optional_unit)` binding, and replaced raw `na != nb` conflict checks in `detect_corpus_contradictions` with `ComposedEffect` polarity so compatible null/benefit findings (`did not increase mortality` + `reduced mortality`) are not misclassified as `Material` contradictions.
- **`B-5` (`safeevidence-ask/src/hybrid_retrieval.rs` Corpus Rights, Retraction & Language-Promotion Gates):**
  - Added `validate_and_filter_corpus` enforcing `validity_epoch > 0`, non-empty `rights_grant_version`, unique `doc_id`s, fail-closed `RightsUnresolved` on `!doc.rights.admissible()`, study-wide `Retracted`/`Withdrawn` + non-citable exclusion, and `TextLanguage::Ar` exclusion when `!corpus.arabic_path_promoted`.
- **`B-6` (`bench/scifact/` Full-Gold Recall Denominator & Sentence-Level `MAX_ABSTRACT_SENTS` Cap):**
  - Rejected duplicate `claim_id`s and negative sentence indices in `PredictedDataset`, applied order-preserving deduplication + `[:MAX_ABSTRACT_SENTS]` cap across both abstract-level and sentence-level metrics, and iterated over all `preds.gold.claims` in `compute_metrics` so omitted claims penalize recall.
- **`NB-1`..`NB-5`:** All 5 non-blocking polish items resolved (`normal_isf`/`student_t_isf` guards, `prisma_summary` deduplication + BiDi/no-op transition checks + unbiased `SplitMix64` shuffle + `NaN` quantile guard, same-issuer active guideline conflict + `\u{FE6A}`/`\u{FF05}`/camelCase/Arabic confidence checks, typographic punctuation allowlist + zero-norm `embed()` rejection, and `ei_schema.py`/`ei_eval.py` bool/`iou_threshold` guards).

---

## 3. Alibaba Open Code Review (`ocr v1.14.4` Delegated Review) & PStack `/ps-review` Exact-Head Verification (`300f2d67`)

- **Alibaba `ocr v1.14.4` Delegated Coverage:** `total_files = 52`, `reviewed_files = 27` (`100%` of `ocr` reviewable files across 5 Rule Groups: `LICENSE`, Python benchmark/CI scripts, `source_admissions.json`, `Cargo.toml` manifests, and 16 Rust library modules), `excluded_files = 25` (`PROVENANCE.md`, `README.md`, ledgers, `Cargo.lock`, and `tests/*.rs` audited directly by host agent + `300f2d67` + `827a8139`).
- **Independent Verifier (`300f2d67`) Round 1 Findings Resolved (`8/8`):**
  1. `B-1`: `EvidenceSnapshot` `ProofState::Committed` gate + full-manifest `snapshot_digest` + BiDi/control validation (`ta10_nli_and_guidelines.rs`).
  2. `B-2`: Clause-level polarity & mixed-direction / comparative-swap refusal in `verify_bilingual_entailment` (`ta10_nli_and_guidelines.rs`).
  3. `B-3`: Pass-1 connected-component deduplication + invalid-record isolation (`dedupe.rs`, `t15_litdb_dedupe.rs`) and `labeled_history.iter().any(|&b| b)` guard on `NConsecutiveIrrelevant` (`stoppers.rs`, `t18_asreview_screening.rs`).
  4. `B-4`: `HKSJ` $t_{k-1}$ critical value + Cochrane Handbook §10.10.4.4 / Rover-Knapp-Friede `max(sd_hksj, sd_conv)` floor (`t19_meta_analysis.rs`) + fail-closed `tau2_start`/`atol`/`maxiter` validation.
  5. `NB-1`..`NB-4`: Typographic punctuation + `top_k == 0` + `i64::try_from` in `hybrid_retrieval.rs`; `record_ids` deduplication in `prisma_summary`; `version = "=0.0.0"` in `safeevidence-{meta,review}/Cargo.toml` + same-issuer active guideline conflict check; updated `SAFEEVIDENCE_ENGINEERING_STATUS.md` & `ADM-0032.transitive`.

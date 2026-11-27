# Google EGM Deep Review — Governance Simplification and V1 Completion Audit (2026-11-27)

Target baseline: `main` @ `ccbea102f8fb159da26372d176c41173f5b7351a` (PR #98 merged; 7/7 post-merge workflows `success`).
Authority: Executed pursuant to §4 of the 2026-11-27 Founder Directive (*"Use Google EGM to conduct a deep review of every remaining external gate and founder-decision requirement"*).
Adoption vehicle: `docs/plan/PLAN_AMENDMENT_V1_7.md` (`plan-v1.7`) and `docs/adr/0001`–`0004`.

---

## 1. Independent EGM Goldfish Reviewers Executed

| Persona | Subagent Conversation ID | Focus & Scope Audited | Key Output |
|---|---|---|---|
| `egm-zoom-out` | `ee544208-0058-4457-8c22-353d4c0a4ee3` | High-altitude audit of `EXT-01`..`EXT-09`, `D5`..`D12`, `WP-00`..`WP-24`, Zero-Cost Rule, and Copy-First vs validator deadlocks | Classified all gates into **Class (A)** self-imposed internal friction (unblocked via `plan-v1.7`) vs **Class (B)** genuine legal, privacy, cryptographic, and clinical/regulatory boundaries |
| `egm-design` | `552a625b-31e2-47b0-9411-fead384aed8e` | Clean-room mathematical specification replacing `DAL` (`T14`), `P00 D-13` isolation, code-level security audit, and 6-target deterministic property/fuzz design | Specified exact Neumaier/clamped-NLL/ECE/tie-exact-AURC/E-AURC/Wilson/SplitMix64 math (`1e-12`), identified 5 concrete edge-case hardening items in Rust crates, and scoped zero-cost pure-Rust V1 completions |
| `egm-implementation-readiness` | `a2ba078c-6d37-44d1-85ef-faa5aa8bddcd` | Line-by-line validator & CI pin audit (`plan_baseline_check.py`, `p01_preentry_check.py`, `source_admission_check.py`, `test_workflow_action_pinning.py`, `PR #43`) | Verified exact single-PR re-freeze invariants for removing `T14`, mandatory P00/P01 fail-closed strings, and non-force-push merge path for `PR #43` (`SECURITY.md`) |

*Disclosure: Google EGM Goldfish reviewers are independent AI review agents (`AI_ASSISTED_SECURITY_QUALIFICATION`), never represented as human reviewers (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`).*

---

## 2. Core Findings and Adopted Simplifications

1. **Eliminate the Copy-First vs `DECISION_REF` Catch-22 (`Class A`):**
   - Live GitHub API inspection confirmed `AbdulazizShehri/MedScale`, `TheHalfMoon/MedOrigin`, and `AbdulazizShehri/safeOCR` are **public (`private: false`) `Apache-2.0` repositories**. Blocking permissive `PUBLIC_LICENSE` code and open `CC0`/`CC-BY`/`ODC-By` benchmarks behind an external GitHub `issuecomment` regex while barring greenfield implementations stalled legitimate V1 engineering.
   - *Adopted in `ADR-0004` & `source_admission_check.py`:* Allow `PUBLIC_LICENSE` admissions from verified public repositories to cite ratified in-repo `docs/adr/000*.md` or `docs/plan/PLAN_AMENDMENT_V1_7.md`, and allow `CC0-1.0`/`CC-BY-4.0`/`ODC-By-1.0` strictly under `bench/`. Keep private repositories (`DAL` permanently banned; `kernux`, `Morize`, etc. withheld), `GPL` (`T34`, `T28b`), `NOASSERTION` (`T35`), `NC`/`ND` articles, and UMLS fail-closed (`Class B`).
2. **Permanently Remove `DAL` (`T14`, `D6`) & Adopt Pure-Rust Mathematical Verification (`ADR-0001`):**
   - Remove `T14` from `source_transplant_pins_2026-10-19.json` and `SOURCE_TRANSPLANT_MATRIX_V1.md`, hard-ban `thehalfmoon/dal` in `source_admission_check.py`, and implement Brier, clamped NLL, ECE/MCE, tie-exact AURC/E-AURC, and all 5 `P00` selective-assurance rates in pure Rust (`safeevidence_assurance::eval_metrics`) verified to `1e-12`.
3. **Replace Unfunded External Human/Clinical/CA Deadlocks with Honest Scoped Qualification (`ADR-0002`, `ADR-0003`, `ADR-0004`):**
   - Replace `EXT-06` / `D12` human review blocker with `AI_ASSISTED_SECURITY_QUALIFICATION` + 6-target deterministic property/fuzz suites + live E2E + `PR #43` GitHub Private Vulnerability Reporting `SECURITY.md` (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`).
   - Scope V1 strictly as a **Research & Evidence-Analysis Workstation** (`V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`): defer `WP-21` (`TA-24` FHIR patient context) and paid mobile app-store packaging (`WP-22`), qualify scientific performance via `SafeEvidenceBench` (`AUTOMATED_SCIENTIFIC_EVALUATION`), and qualify $0 reproducible offline research bundles (`RESEARCH_RELEASE_QUALIFIED`) while keeping `OS_CA_CODE_SIGNED = FALSE`, `ACTUAL_CLINICAL_VALIDATION = FALSE`, and `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`.
4. **Close Pre-Release Platform Revisits & Technical Hardening Findings:**
   - Ratify `plan-v1.2` (`TA-03`) and `plan-v1.5` (`TA-20`) dispositions, map the 41 P00 P1 rows (`EXT-04`) to executable `TA-01`..`TA-30` tests, and schedule all 5 code-level hardening fixes identified by `egm-design` (`document_intake.rs`, `bilingual.rs`, `perturbation.rs`, `staging.rs`, `surveillance.rs`) into the immediate engineering wave.

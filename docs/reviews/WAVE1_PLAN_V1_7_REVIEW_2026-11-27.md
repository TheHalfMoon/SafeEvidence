# Wave 1 (`plan-v1.7` / PR #99) Multi-Layer Engineering, Mathematical & Security Review Record

- **Date:** `2026-11-27`
- **Branch:** `safeevidence/plan-v1-7-founder-directive-20261127`
- **Base `main` SHA:** `ccbea102f8fb159da26372d176c41173f5b7351a`
- **Round 1 Audited SHA:** `c7033faf8aa4187a25e5425345d374caa982ad25`
- **Governing Authorities:** `docs/plan/PLAN_AMENDMENT_V1_7.md`, `docs/adr/0001..0004`, `docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md`, `docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`
- **Truth-in-Qualification Declaration:** `AI_ASSISTED_SECURITY_QUALIFICATION = ACTIVE`, `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`, `OS_CA_CODE_SIGNED = FALSE`, `ACTUAL_CLINICAL_VALIDATION = FALSE`, `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`.

---

## 1. Alibaba Open Code Review (`ocr v1.14.4` Delegated Host-Agent Review)

Executed `ocr delegate preview --from main` and `ocr delegate rule --from main` across all changed non-test source files (`docs/evidence/source_transplant_pins_2026-10-19.json`, `tools/governance/source_admission_check.py`, `product/crates/safeevidence-assurance/src/{lib,eval_metrics,full_assurance}.rs`, `product/crates/safeevidence-ask/src/{bench_runner,perturbation}.rs`, `product/crates/safeevidence-contracts/src/{bilingual,document_intake}.rs`, `product/crates/safeevidence-proofstore/src/{lib,surveillance}.rs`, `product/crates/safeevidence-release/src/staging.rs`):

- **Rule Group 1 (`**/*.json`):** `source_transplant_pins_2026-10-19.json` carries valid, typo-free canonical keys (`packets`, `commit`, `files`, `path`, `git_blob_oid`, `bytes`), deletes `T14` (`39 -> 38` packets), and withholds `EXT-08` private paths (`T06`, `T32`).
- **Rule Group 2 (`**/*.rs` — Ownership, Error/Panic Safety, Unsafe Boundaries, Concurrency, Security):**
  - Zero `unsafe` blocks added across all changed crates.
  - Zero `unwrap()` / `expect()` on caller-controlled inputs in library paths (`SplitMix64::from_domain` slices a fixed 32-byte SHA-256 output `[..8]`; `serde_json::to_vec` errors propagate via `Result`).
  - `neumaier_sum` hardened against `±Inf` subtraction generating `NaN` (`if !v.is_finite() { return v; }` / `if !t.is_finite() { return t; }`).
  - `ProofStore::execute_surveillance_batch` wraps `advance_epoch` and all `RetractSource` / `AmendSource` / `RotateRightsGrant` / `NewTrialPublished` mutations inside one SQLite `IMMEDIATE` transaction so mid-batch failures roll back atomically.
- **Rule Group 3 (`**/*.py` — Type/Edge-Case Safety, Exceptions, Security):**
  - Fixed unhashable `row["packet"]` type hazard in `source_admission_check.py` (`pkt_str = row["packet"] if isinstance(row["packet"], str) else ""`) before set membership check (`test_malformed_identity_fields_deny` verified).
  - Zero `eval`/`exec`/`shell=True`/network imports; all file resolutions traverse `resolve_regular_file` rejecting symlinks and NTFS junctions.

---

## 2. Round 1 Independent Review Findings & Round 2 Resolutions

### 2.1 Zero-Context Security/Governance/PStack Verifier (`300f2d67`)
- **`B-1` (Source-Admission `PUBLIC_LICENSE` Allowlist & ADR Pinning):** Resolved in `tools/governance/source_admission_check.py` + `test_source_admission_check.py`. Pinned `PUBLIC_LICENSE_ADR_REFS` to exact `ADR-0004` and `PLAN_AMENDMENT_V1_7.md` paths, added `ADR0004_EXCLUDED_REPOS` / `ADR0004_EXCLUDED_PACKETS` (`T27b`, `T28b`, `T34`, `T35`), and restricted `valid_adr_ref` to `ADR0004_VERIFIED_PUBLIC_REPOS`.
- **`B-2` (Residual Active `T14`/`DAL` & Dropped `T27b` References):** Resolved across `bench/safeevidencebench/README.md`, `bench_runner.rs` (`T27-SCIFACT-T28-EVIDENCE-INFERENCE`), `perturbation.rs`, `ta23_safeevidence_bench.rs`, `REUSE_FIRST_IMPLEMENTATION_MAP.md`, `IMPLEMENTATION_LEDGER.md`, `ANTIGRAVITY_EXECUTION_LEDGER.md`, `SAFEEVIDENCE_ENGINEERING_STATUS.md`, `SAFEEVIDENCE_FINAL_QUALIFICATION.md`, and `V1_GATE_AND_ADMISSION_AUDIT_2026-11-27.md`.
- **`B-3` (`document_intake.rs` `/JS` & `/AA` DOI False-Quarantine and XMP/`<svg` Binary Scan):** Resolved in `document_intake.rs` + `prop_document_intake.rs`. Restored ISO 32000-1 value-starter guards on 2-byte `/JS` and `/AA`, removed bare `<?xml` from binary polyglot scan so XMP metadata in PDFs/PNGs/JPEGs is admitted, and required `<svg`/`<html`/`<iframe`/`<object`/`<embed` tag boundary delimiters.
- **`NB-1` (`MAX_CALIBRATION_BINS` Bound):** Capped `MAX_CALIBRATION_BINS = 10_000` in `eval_metrics.rs`.
- **`NB-2` (`ResearchReleaseManifest` Getters & Cross-Verifier):** Added public getters and `verify_research_release_manifest` in `staging.rs` + regression tests in `prop_staging.rs`.
- **`NB-3` (PNG 12-Byte `IEND` Framing):** Enforced `bytes.len() >= 45` and full `\x00\x00\x00\x00IEND\xaeB`\x82` suffix in `document_intake.rs`.

### 2.2 Google EGM Hostile Mathematical & Security Critic (`552a625b`)
- **`EGM-M1` (`neumaier_sum` Overflow, `SplitMix64::from_domain` Injectivity, Compensated `AURC` Prefix Sum):** Guarded non-finite values in `neumaier_sum`, switched `SplitMix64::from_domain` to 8-byte big-endian length-prefixed framing (`("a:b", "c") != ("a", "b:c")`), and added Neumaier compensation across tie-group prefix sums in `evaluate_selective_prediction`.
- **`EGM-M2` (`P00AssuranceCase` Identity & Calibration/Selective Target Alignment):** Added `EvalMetricsError::InvalidCaseIdentity` rejecting empty/whitespace or duplicate `case_id`/`study_cluster_id`, aligned calibration target to `safe_and_supported && !requires_non_commit`, and wired fail-closed denominator/risk checks + full case digesting in `eval_assurance_calibration_split`.
- **`EGM-M3` (`full_assurance.rs` Positive `BiasLevel` Allowlist & Non-Empty Human Actor):** Required non-empty `authorized_by` and `confirmed_at_utc` on `AppraisalConfirmation::Confirmed` and positive `Some(BiasLevel::Low | SomeConcerns | Moderate)` allowlisting so unassessed (`None` / `NoInformation`) RoB downgrades to `AnswerWithCaution`.
- **`EGM-S1` (Single-Transaction Atomic `apply_surveillance_cycle` & Leading C1 NEL Check):** Moved surveillance batch mutations into a single SQLite `IMMEDIATE` transaction (`ProofStore::execute_surveillance_batch`) verifying `prior_assertion_id` / `superseding_assertion_id` equivalence and retired grants atomically, and checked `decoded.strip_prefix('\u{feff}')` in `document_intake.rs` so leading C1 NEL (`\u{0085}`) and misplaced/double BOMs quarantine as `InvalidUtf8Text`.
- **`EGM-P1` (Exact Defect Variant & Prefix Collision Property Assertions):** Upgraded `prop_perturbation.rs` to assert exact `ClaimVerificationDefect` variants across all 1,500 trials and added file-vs-directory prefix collision rejection in `staging.rs` (`prop_staging.rs`).

---

## 3. PStack `/ps-review` 4-Bar Panel Summary (Post-Round-2 Fixes)

- **Correctness:** `PASS` — Closed-form `1e-12` calibration/AURC/ECE tests, 1,000-trial mathematical property suite, atomic `IMMEDIATE` surveillance batching, and cross-profile `--debug`/`--release` `SafeEvidenceBench` packet digest (`1d13f21f91e63f85cc8cc25ded61182d498f6b0cec4db6424536ab35e6d2ad92`) verified.
- **Parsimony:** `PASS` — Zero Cargo/npm dependency additions, zero lockfile churn, zero unused abstractions.
- **Product (`plan-v1.7` Alignment):** `PASS` — `DAL` (`T14`) and `T27b` removed cleanly, 7-axis qualification enforced in docs and `ResearchReleaseManifest`, 8/8 `SafeEvidenceBench` splits green.
- **Security:** `PASS` — `source_admission_check.py` allowlists verified `ADR-0004` public repos and blocks copyleft/unlicensed/unverified repos; `document_intake.rs` blocks PDF active actions, polyglots, C1/BiDi controls, and malformed PNG/JPEG trailers without false-quarantining scientific DOIs or XMP metadata.

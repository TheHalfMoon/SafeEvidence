# Plan Amendment `plan-v1.7` (2026-11-27)

State: **In force upon normal merge to `main` with exact-head CI and independent multi-agent review.** Enacts the 2026-11-27 Founder Directive across the canonical V1 planning baseline (`docs/PLAN_FREEZE.md`), Architecture Decision Records (`docs/adr/0001`–`0004`), governance validators, and qualification ledgers.

Evidence & companion records:
- `docs/reviews/EGM_GOVERNANCE_SIMPLIFICATION_2026-11-27.md` (`egm-zoom-out`, `egm-design`, `egm-implementation-readiness`)
- `docs/adr/0001-permanently-remove-dal-and-adopt-clean-room-calibration-math.md`
- `docs/adr/0002-ai-assisted-security-qualification-framework.md`
- `docs/adr/0003-v1-research-workstation-scope-and-automated-scientific-evaluation.md`
- `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`
- `docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`
- `docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md`

---

## 1. Permanent Removal of `DAL` (`T14`, `D6`) and Clean-Room Mathematical Replacement

1. **Permanent exclusion:** `TheHalfMoon/DAL`, source packet `T14`, DAL numerical parity vectors, DAL-specific dependencies, and external founder decision `D6` are permanently removed from SafeEvidence V1. SafeEvidence shall never copy, expose, publish, or depend on DAL (`tools/governance/source_admission_check.py` enforces an explicit fail-closed ban on `thehalfmoon/dal` and `T14`).
2. **Historical preservation:** Historical pre-amendment documents mentioning `DAL` or `T14` (`docs/SOURCE_LEDGER.md`, `docs/COPY_FIRST_SOURCE_PLAN.md`, `docs/P00_DECISION_ASSURANCE_CONTRACT.md` line 95, `docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md`) remain untouched as dated historical audit records and are superseded by this amendment.
3. **`GREENFIELD_JUSTIFIED` mathematical engine (`WP-11`, `WP-20`, `TA-13`, `TA-23`):** All scientifically justified calibration, reliability, and selective-prediction metrics are retained and implemented natively in zero-dependency Rust (`safeevidence_assurance::eval_metrics` + `SafeEvidenceBench`) from published mathematical definitions:
   - Brier score (Brier 1950) with Neumaier compensated summation;
   - Cancellation-free clamped binary Negative Log-Likelihood (`NLL`, $\varepsilon = 10^{-15}$);
   - Equal-width $M$-bin Expected Calibration Error (`ECE`), Maximum Calibration Error (`MCE`), and reliability diagram bins (Naeini et al. 2015; Guo et al. 2017);
   - Tie-exact permutation-invariant Risk–Coverage curves, Area Under the Risk–Coverage Curve (`AURC`), and exact finite-$N$ Excess-AURC (`E-AURC`) (Geifman & El-Yaniv 2017; Jaeger et al. 2023);
   - All five `P00_DECISION_ASSURANCE_CONTRACT` domain rates (`unsafe_commit_rate_on_non_commit_cases`, `overall_unsafe_commit_rate`, `useful_coverage`, `over_abstention_rate`, `false_escalation_rate`) with exact Wilson 95% score intervals and SplitMix64 cluster/item bootstrap 95% CIs;
   - Verified against closed-form analytical derivations and property invariants to `1e-12` precision, while keeping zero confidence percentages on user-facing UI surfaces (`P00 D-13`).

---

## 2. Independent AI-Assisted Security Qualification Framework (`EXT-06`, `D12`, `PR #43`, `Issue #17`)

1. Mandatory human engineering and security review is removed as a founder prerequisite for SafeEvidence V1 engineering completion, `SECURITY.md` (`PR #43`) integration, and V1 research release qualification (`D12` withdrawn).
2. Internal review authority is replaced by **Independent AI-Assisted Security Qualification Supported by Executable Evidence** (`docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md`):
   - Multi-perspective fresh-context reviews distinct from the authoring agent (Google EGM Goldfish reviewers, Alibaba `ocr` local delegation, `jev`, PStack `/ps-review`, and independent Antigravity review agents, plus a self-contained ChatGPT independent review packet at release milestones);
   - Static analysis (`clippy -D warnings`), supply-chain/socket gates (`cargo deny`, CycloneDX 1.5 SBOM, `TA-29`, `core_no_sockets.py`), threat modeling, deterministic structure-aware property/fuzz and adversarial suites, real WebView2/WebKitGTK end-to-end verification, and exact-head verification of every blocking finding.
3. **Strict honesty rule:** No human signature may ever be forged, and AI reviewers are never represented as human reviewers (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`).

---

## 3. Research Intended-Use Boundary & Automated Scientific Evaluation (`EXT-03`, `EXT-09`, `D11`, `Issue #4`, `WP-21`)

1. SafeEvidence V1 is scoped and qualified strictly as a **Local-First Research and Evidence-Analysis Workstation (`RESEARCH_INTENDED_USE_V1`)** (`docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`).
2. Mandatory human clinician adjudication (`D11`, `EXT-03` holdout clause) is not required for V1 research engineering completion or V1 research release. Research qualification uses **Automated Scientific Evaluation** in `SafeEvidenceBench` (reproducible protocols, deterministic citation/span verification, critical-number & `EffectMeasureSwap` verification, statistical/calibration/AURC/ECE correctness, PICO applicability, contradiction detection, bilingual parity, permissive biomedical benchmarks, and explicit error/uncertainty intervals).
3. Patient-specific clinical decision support, real PHI processing, `WP-21` (`TA-24` FHIR patient context), and regulated medical-device (`SaMD`) claims remain **excluded and deferred** outside V1 research scope unless separately qualified under `Issue #4` (`EXT-03`) and `EXT-09`.

---

## 4. Governance & Platform Blocker Simplifications (`EXT-01`, `EXT-04`, `EXT-05`, `EXT-07`, `plan-v1.2`, `plan-v1.5`, `WP-22`)

| Item | Amendment Disposition |
|---|---|
| `EXT-01` (`D5`, `D7`) | Permissive `PUBLIC_LICENSE` code/crates (`Apache-2.0`, `MIT`, `BSD-3-Clause`, `MPL-2.0`) and open benchmarks (`CC0-1.0`, `CC-BY-4.0`, `ODC-By-1.0` strictly under `bench/`) from verified public repositories (`MedScale`, `MedOrigin`, `safeOCR`, `openmed`, `asreview`, `statsmodels`, `xberg`, `tough`, `scifact`, `evidence-inference` `CC-BY`/`CC0` subset, `SYNERGY`) may bind `docs/adr/0004-...md` or `docs/plan/PLAN_AMENDMENT_V1_7.md` in `source_admissions.json`. Where heavy Python wheels impair sandbox/size budgets (`D-03` exit rule), Rust ports verified against donor reference vectors are authorized. Copyleft (`GPL` `T34`/`T28b`), `NOASSERTION` (`T35`), `NC`/`ND` articles, UMLS, and private repos remain strictly blocked. |
| `EXT-04` (`D10`, `Issue #3`) | Under `EXT-02` founder engineering ownership, all in-scope technical items of the 41 original P1 findings are satisfied via executable `TA-01`..`TA-30` test traceability (§6 below); `P13`/`P14`/`P17` rows remain `DEFERRED`, and human clinical/CA rows remain excluded from V1 research scope without fabricating GitHub `issuecomment` assignments. |
| `EXT-05` (`D9`, `WP-24`, `TA-28`) | Under the Zero-Cost Rule, V1 qualifies reproducible unsigned offline research bundles (`RESEARCH_RELEASE_QUALIFIED = TRUE`) + CycloneDX 1.5 SBOM + `THIRD_PARTY_NOTICES.md` + `T25` TUF update/rollback conformance on domain-separated test roots, while recording `OS_CA_CODE_SIGNED = FALSE` and `PRODUCTION_TUF_ROOT_PROVISIONED = FALSE`. |
| `EXT-07` (`D8`) | Drops `T27b` `MultiVerS` (`RIGHTS_UNKNOWN` checkpoint); permits only `Apache-2.0` / `MIT` / verified `US-PD` model weights with pinned SHA-256 + model-card provenance; keeps optional GGUF/ONNX weights out of Git history and keeps deterministic lexical/template paths default. |
| `plan-v1.2` & `plan-v1.5` | Ratifies `TA-03` three-OS offline isolation (`unshare -rn` on Linux, `sandbox-exec` on macOS, firewall + offline `--locked` verification on Windows) and `TA-20` (`21/21` Windows WebView2 `incognito: true` E2E + `20/20` Linux WebKitGTK E2E + shipped `incognito: true` `strace -ff` zero-socket/zero-residue capture) as permanent V1 controls. |
| `WP-22` (`TA-25`) | Paid Apple App Store / Google Play packaging and mobile PDF/OCR (`plan-v1.1` B1) are deferred to post-V1 (`DEFERRED` to V1.1); V1 ships the complete local-first desktop research workstation. |

---

## 5. Seven Canonical V1 Qualification Axes (Mandatory Non-Conflation Vocabulary)

Every release and qualification report must report these seven axes separately:

1. `COMPLETED_ENGINEERING` — Code, contracts, and automated unit/integration/E2E suites implemented and passing on exact `HEAD`.
2. `INDEPENDENTLY_VERIFIED_ENGINEERING` — Verified on exact `HEAD` by fresh-context multi-agent reviewers (`EGM`, `ocr`, `jev`, `PStack`) and cross-platform CI (`Ubuntu`, `Windows`, `macOS`).
3. `AI_ASSISTED_SECURITY_QUALIFICATION` — Threat model, supply-chain/socket denial (`TA-29`), vault/crypto (`TA-05`), hostile-intake (`TA-15`), prompt-injection (`TA-27`), property/fuzz suites, `SECURITY.md`, and independent AI security review complete (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`).
4. `AUTOMATED_SCIENTIFIC_EVALUATION` — Reproducible `SafeEvidenceBench` (`TA-23`) passing retrieval (`TA-09`), bilingual (`TA-08`), claim-perturbation (`TA-10`), applicability (`TA-11`), study-independence (`TA-07`), appraisal/guideline (`TA-12`), extraction (`TA-17`), meta-analysis (`TA-18`), and `1e-12` calibration/AURC/ECE (`TA-13`) gates.
5. `RESEARCH_RELEASE_QUALIFICATION` — Reproducible offline desktop research bundle, CycloneDX 1.5 SBOM (`TA-02`), `THIRD_PARTY_NOTICES.md`, pack/rollback verification (`TA-28`), and `V1_RESEARCH_INTENDED_USE_CHARTER` active (`OS_CA_CODE_SIGNED = FALSE`).
6. `ACTUAL_CLINICAL_VALIDATION` — `FALSE` unless clinician-adjudicated patient/clinical trials are executed under a signed `Issue #4` clinical charter.
7. `ACTUAL_REGULATORY_AUTHORIZATION` — `FALSE` unless cleared/authorized by a competent regulatory authority (`SFDA`, `FDA`, `CE`, etc.).

---

## 6. Traceability of the 41 Original P00 P1 Findings Under V1 Research Scope

| P1 Register Rows | V1 Research Workstation Disposition & Executable Verification |
|---|---|
| `CODEX-P00-07`, `OPUS-P00-003` (Vault encryption, SQLCipher, WAL/temp zero-residue, durability, recovery) | **Engineering Verified:** `safeevidence-vault` (`SAFEVD-v1`) + `safeevidence-proofstore` + `TA-05` (`proof_commit.rs`, `ta05_diskfull_and_recovery.rs`, `privacy_probes_032.rs`, `vault_privacy_023.rs`). Real PHI remains disabled in V1 research scope. |
| `CODEX-P00-08`, `OPUS-P00-004` (Pack integrity, epoch anti-rollback, TUF trust separation) | **Engineering Verified in V1 Research Scope:** `overlay.rs`, `staging.rs`, and `WP-04`/`WP-24` pack anti-rollback/expiry verification (`TA-06`, `TA-28`); production offline root key custody stays `FALSE` until externally provisioned. |
| `CODEX-P00-09..12`, `OPUS-P00-005..008` (Study independence, canonical contracts, precedence, proof admission, zero UI %) | **Engineering Verified:** `safeevidence-contracts`, `study_linkage.rs`, `safeevidence-assurance`, `safeevidence-proofstore`, `safeevidence-ask` (`TA-04`, `TA-07`, `TA-13`, `TA-14`). |
| `CODEX-P00-13..18`, `OPUS-P00-009..013` (Retrieval funnel, claim support, PICO applicability, GRADE/RoB, bilingual/RTL, living updates) | **Engineering Verified:** `ta09_hard_bm25.rs`, `perturbation.rs`, `appraisal.rs`, `bilingual_ask.rs`, `surveillance.rs`, `rtl-snapshots.test.ts` (`TA-06`, `TA-08`..`TA-12`, `TA-19`, `TA-22`). |
| `CODEX-P00-19..23`, `OPUS-P00-014..016` (Calibration/abstention evaluation, screening/PRISMA, quote extraction, meta-analysis, `SafeEvidenceBench`) | **Engineering Verified in V1 Research Scope:** `safeevidence_assurance::eval_metrics` (`1e-12` analytical parity, `TA-13`), `review_protocol.rs` (`TA-16`, `TA-17`), independence-gated pooling (`TA-18`), `SafeEvidenceBench` (`TA-23`). |
| `CODEX-P00-24..27`, `OPUS-P00-017..018` (No silent egress, outbound query preview, hostile document quarantine, prompt-injection, desktop CSP/capabilities) | **Engineering Verified:** `core_no_sockets.py`, `ta29_*`, `document_intake.rs` (`TA-15`), `ta27_prompt_injection.rs` (`TA-27`), `surveillance.rs` (`TA-30`), live 21-check E2E (`TA-20`, `TA-21`). |
| `CODEX-P00-28..29` (`P13` computable guidelines, `P14` FHIR patient context, `P17` sync) | **Explicitly Deferred Out of V1:** `WP-21` (`P14`), `P13`, `P17`, `P19` remain `DEFERRED`. |
| `CODEX-P00-30`, `OPUS-P00-019` (Exact source provenance, notices, SBOM, clinical charter boundary) | **Verified / Bounded:** `source_admission_check.py` (`TA-01`), CycloneDX 1.5 SBOM + `THIRD_PARTY_NOTICES.md` (`TA-02`), and `V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md` (`ACTUAL_CLINICAL_VALIDATION = FALSE`). |

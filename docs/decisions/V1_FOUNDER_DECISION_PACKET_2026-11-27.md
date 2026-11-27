# SafeEvidence V1 External Founder and Expert Decision Packet (Revised Under `plan-v1.7`)

State: **REVISED BY 2026-11-27 FOUNDER DIRECTIVE (`plan-v1.7`) — `D6`, `D11`, `D12` SUPERSEDED; PERMISSIVE `PUBLIC_LICENSE` SLICES UNBLOCKED**
Date: `2026-11-27`
Evaluated `main` baseline: `ccbea102f8fb159da26372d176c41173f5b7351a`
Governing amendments & ADRs:
- [PLAN_AMENDMENT_V1_7.md](../plan/PLAN_AMENDMENT_V1_7.md)
- [0001-permanently-remove-dal-and-adopt-clean-room-calibration-math.md](../adr/0001-permanently-remove-dal-and-adopt-clean-room-calibration-math.md)
- [0002-ai-assisted-security-qualification-framework.md](../adr/0002-ai-assisted-security-qualification-framework.md)
- [0003-v1-research-workstation-scope-and-automated-scientific-evaluation.md](../adr/0003-v1-research-workstation-scope-and-automated-scientific-evaluation.md)
- [0004-public-license-source-admission-and-zero-cost-governance-simplification.md](../adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md)
- [V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md](V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md)
- [AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md](AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md)

---

## 1. Summary of Decisions Superseded or Simplified by the 2026-11-27 Founder Directive

| Historical ID | Original Blocker | Status Under `plan-v1.7` | Controlling Resolution |
|---|---|---|---|
| `D5` | Public `Apache-2.0` slices (`T05`, `T07`, `T09`, `T10`, `T15`, `T16`) | **SIMPLIFIED / UNBLOCKED FOR V1 RESEARCH SCOPE** | Live GitHub check verified `AbdulazizShehri/MedScale`, `TheHalfMoon/MedOrigin`, and `AbdulazizShehri/safeOCR` are public (`private: false`) `Apache-2.0` repositories. Admissible under `PUBLIC_LICENSE` (`ADR-0004`) with full `THIRD_PARTY_NOTICES.md` attribution (or `D-03` Rust port where size/sandbox-justified); `T09` (`WP-21` FHIR patient context) deferred outside V1 research scope (`ADR-0003`). |
| `D6` | Private `TheHalfMoon/DAL` (`T14`) ownership & publication | **PERMANENTLY SUPERSEDED & WITHDRAWN** | `DAL` (`T14`) permanently removed from SafeEvidence V1 (`ADR-0001`). Never copied, exposed, published, or depended upon. Replaced by clean-room pure-Rust Brier, clamped NLL, ECE/MCE, tie-exact AURC/E-AURC, and `P00` assurance rates (`1e-12`). |
| `D7` | External permissive worker/crate/benchmark slices & copyleft boundary | **SIMPLIFIED / ENFORCED** | Permissive public slices (`Apache-2.0`, `MIT`, `BSD-3-Clause`, `MPL-2.0`, and `CC0-1.0`/`CC-BY-4.0`/`ODC-By-1.0` strictly under `bench/`) unblocked via `ADR-0004`; permanent in-tree denial ratified for `T34` (`GPL-3.0`), `T28b` (`GPL-2.0`/UMLS), `T35` (`NOASSERTION`), and `NC`/`ND` articles. |
| `D8` | Model-card & weight redistribution (`EXT-07`) | **BOUNDED TO PERMISSIVE / OPTIONAL PACKS** | `T27b` `MultiVerS` (`RIGHTS_UNKNOWN`) dropped; only `Apache-2.0` / `MIT` / verified `US-PD` weights with pinned SHA-256 + model-card provenance may enter optional `ModelPack`s; deterministic lexical/template paths remain default and self-sufficient for V1 research release. |
| `D9` | Commercial OS CA signing, TUF root custody, `plan-v1.2`, `plan-v1.5` | **SPLIT (ZERO-COST V1 UNBLOCKED)** | `plan-v1.2` (`TA-03`) and `plan-v1.5` (`TA-20`) closed in `plan-v1.7`; V1 qualifies $0 reproducible offline research bundles (`RESEARCH_RELEASE_QUALIFIED = TRUE`) + `T25` TUF mechanics on test roots, while keeping paid commercial OS CA signing (`OS_CA_CODE_SIGNED = FALSE`) and production offline TUF root private-key custody (`PRODUCTION_TUF_ROOT_PROVISIONED = FALSE`) strictly optional. |
| `D10` | `Issue #3` 41 P00 P1 phase-owner rows (`EXT-04`) | **SATISFIED FOR V1 RESEARCH ENGINEERING** | Under `EXT-02` founder engineering ownership, all in-scope technical P1 items map directly to executable `TA-01`..`TA-30` tests (`PLAN_AMENDMENT_V1_7.md` §6); `P13`/`P14`/`P17` rows stay `DEFERRED`, and zero fabricated GitHub `issuecomment` assignments are created. |
| `D11` | Mandatory human clinician-adjudication charter (`EXT-03`, `Issue #4`) | **SUPERSEDED FOR V1 RESEARCH RELEASE** | V1 is released under `V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md` (`ADR-0003`) using Automated Scientific Evaluation (`SafeEvidenceBench`), while explicitly preserving `ACTUAL_CLINICAL_VALIDATION = FALSE`, `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`, and `PHI_AUTHORIZED = FALSE`. |
| `D12` | Mandatory human engineering/security review (`EXT-06`, `Issue #17`, `PR #43`) | **SUPERSEDED BY AI-ASSISTED SECURITY QUALIFICATION** | Replaced by `AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md` (`ADR-0002`), unblocking `PR #43` (`SECURITY.md` via $0 GitHub Private Vulnerability Reporting) while recording `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`. |

---

## 2. Genuine External Actions Remaining Outside V1 Zero-Cost Research Scope (Non-Blocking for V1 Research Completion)

None of the items below block V1 research workstation engineering completion, automated scientific evaluation, or zero-cost research release qualification; they apply **only** if SafeEvidence later expands beyond its V1 research boundary:

1. **Paid Commercial OS Code-Signing Certificates & Production Offline TUF Hardware Root (`EXT-05`):** Required only to flip `OS_CA_CODE_SIGNED` (`Windows Authenticode` / `Apple Developer ID`) or `PRODUCTION_TUF_ROOT_PROVISIONED` from `FALSE` to `TRUE`.
2. **Clinical Decision-Support / Patient-Record (`PHI`) Expansion (`EXT-03`, `Issue #4`, `WP-21`):** Required only before enabling `WP-21` (`TA-24` FHIR patient context), ingesting real PHI, or claiming `ACTUAL_CLINICAL_VALIDATION = TRUE`.
3. **Jurisdictional Medical-Device (`SaMD`) Clearance (`EXT-09`):** Required before any clinical diagnosis, treatment, triage, or medical-device marketing claim (`ACTUAL_REGULATORY_AUTHORIZATION = TRUE`).
4. **Separate Proprietary / Copyleft Rightsholder Grants (`Issue #5`):** Required only if future versions wish to copy `GPL` (`T34`, `T28b`), unlicensed (`T35`), or restricted terminology (`UMLS`/`RxNorm`/`LOINC`) material.

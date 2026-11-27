# SafeEvidence V1 Research and Evidence-Analysis Intended-Use Charter

State: **ACTIVE FOR V1 RESEARCH WORKSTATION SCOPE (`RESEARCH_INTENDED_USE_V1`)**
Date: `2026-11-27`
Authority: 2026-11-27 Founder Directive (`docs/plan/PLAN_AMENDMENT_V1_7.md`, `docs/adr/0003-v1-research-workstation-scope-and-automated-scientific-evaluation.md`)

> **Important Non-Clinical Boundary:** This charter governs the **research and evidence-analysis workstation** release of SafeEvidence V1. It is **not** a clinical trial protocol, medical-device (`SaMD`) clearance, IRB approval, or patient-care authorization. `ACTUAL_CLINICAL_VALIDATION = FALSE` and `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`.

---

## 1. Authorized Intended Use (V1 Research Scope)

SafeEvidence V1 is a **local-first, bilingual (English/Arabic) biomedical literature research, evidence-appraisal, and decision-assurance workstation** designed for researchers, systematic reviewers, and scientifically trained users analyzing population-level research questions offline or over explicitly user-previewed public bibliographic queries.

Authorized V1 capabilities include:
1. Population-level PICO literature retrieval with full retrieval-funnel accounting (`TA-09`).
2. Deterministic claim-to-source span verification, critical-number/unit/negation/`EffectMeasureSwap` verification, and atomic `AnswerProofManifest` proof commitment (`TA-10`, `TA-14`).
3. Explicit first-class uncertainty, contradiction, and refusal outcomes (`ANSWER`, `ANSWER_WITH_CAUTION`, `ASK_MORE`, `CONFLICT`, `ABSTAIN`, `ESCALATE`, `BLOCKED`) with zero user-facing confidence percentages (`P00 D-13`, `TA-13`).
4. Study-vs-report deduplication and participant-overlap double-count prevention (`TA-07`).
5. Design-specific methodological appraisal (`RoB 2`, `ROBINS-I`, `QUADAS-2`, `AMSTAR 2`), `GRADE` certainty profiles, clinical guideline document metadata/jurisdiction/supersession analysis, `SummaryOfFindings` tables, and `EBMonFHIR` / `EvidenceSnapshot` research exports (`TA-12`, `TA-14`).
6. Systematic-review protocol registration, hash-chained screening/PRISMA accounting, quote-anchored effect extraction (`PROPOSED` until human-confirmed), and independence-gated pairwise meta-analysis (`TA-16`–`TA-18`).
7. Local validity-overlay replay, retraction/correction invalidation of historical proofs, and opt-in query-previewed living literature surveillance (`TA-06`, `TA-19`, `TA-30`).

---

## 2. Explicitly Prohibited / Out-of-Scope Uses in V1

1. **No patient-specific clinical decision-making:** SafeEvidence V1 must **not** be used to diagnose, treat, cure, mitigate, prevent, triage, dose, or prescribe for any individual patient. Patient-specific requests trigger deterministic `ESCALATE` (`CLINICIAN_AUTHORITY_REQUIRED`).
2. **No Protected Health Information (`PHI`) or patient-record ingestion:** `WP-21` (`TA-24` FHIR patient context) is deferred outside V1 research scope (`PHI_AUTHORIZED = FALSE`).
3. **No medical-device or clinical-validation claims:** Output displays and benchmark packets carry explicit non-clinical notices and never claim clinician endorsement, patient safety demonstration, or regulatory clearance (`EXT-09`).

---

## 3. Automated Scientific Evaluation Protocol (Replacing Mandatory Human Clinical Adjudication for V1 Research Release)

For V1 research qualification (`AUTOMATED_SCIENTIFIC_EVALUATION`), SafeEvidence replaces human clinician-adjudicated holdout requirements with deterministic, reproducible, pre-registered computational benchmarks in `SafeEvidenceBench` (`WP-20`, `TA-23`):

1. **Deterministic Citation & Grounding Verification:** 100% of committed answer claims carry verified Unicode scalar spans, source SHA-256 digests, support labels, and validity epochs (`TA-04`, `TA-08`, `TA-14`).
2. **Adversarial Perturbation & Critical-Number Verification:** 100% detection across numeric, sign, decimal, unit (`40 mg` vs `40 mcg`), timeframe, comparator, population, negation, splice, and `EffectMeasureSwap` (`RR`/`AR`/`RD`/`OR`/`HR`/`MD`) perturbations (`TA-10`, `TA-15`) plus prompt/retrieval-injection immunity (`TA-27`).
3. **Contradiction & Applicability Gates:** 100% blocking/abstention or caution downgrading on conflicting independent studies (`CONFLICT`), retracted/superseded sources, unresolved rights, and PICO population/intervention/jurisdiction mismatches (`TA-06`, `TA-11`, `TA-13`).
4. **Mathematical Statistical & Calibration Verification:** Exact `1e-12` analytical parity and permutation-invariance across Brier score, clamped NLL, ECE/MCE reliability bins, tie-exact AURC/E-AURC, pairwise meta-analysis (`1e-6`), and all five `P00` selective-assurance rates with Wilson 95% score intervals and SplitMix64 bootstrap 95% CIs (`TA-13`, `TA-18`).
5. **Reproducible Multi-Split Reporting:** Byte-identical `BenchPacket` SHA-256 digests across clean builds, reporting English and Arabic slices and recording negative/abstention results transparently (`TA-08`, `TA-23`).

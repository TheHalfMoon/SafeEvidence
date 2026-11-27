# 0003. Scope SafeEvidence V1 as a Research Workstation with Automated Scientific Evaluation

Status: accepted (2026-11-27)

## Context
`ARCHITECTURE_SPEC_V1.md` §1 already defined SafeEvidence V1 as a population-level clinical evidence research workstation rather than patient-specific decision support, yet `EXT-03`, `D11`, `TA-10`, and `WP-20` gated V1 completion on recruiting a human clinician adjudicator panel (`Issue #4`) and left `WP-21` (`TA-24` FHIR patient context) ambiguously coupled to V1. On 2026-11-27, the Founder directed that V1 be qualified and released strictly within a documented research and evidence-analysis intended-use boundary without mandatory human clinical adjudication.

## Decision
SafeEvidence V1 is scoped strictly as a **Local-First Research and Evidence-Analysis Workstation (`RESEARCH_INTENDED_USE_V1`)** (`docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`). Patient-specific clinical decision support, real PHI ingestion, `WP-21` (`TA-24` FHIR patient context), and regulated medical-device (`SaMD`) claims are excluded and deferred outside V1 research scope unless separately qualified under `Issue #4` (`EXT-03`) and `EXT-09`. Human clinician-adjudication gates for V1 research qualification (`D11`, `TA-10`, `TA-23`) are replaced by **Automated Scientific Evaluation** in `SafeEvidenceBench` (reproducible protocols, deterministic citation/span verification, critical-number & `EffectMeasureSwap` checks, statistical/calibration/AURC/ECE correctness, PICO applicability, contradiction detection, bilingual parity, permissive biomedical benchmarks, and explicit uncertainty intervals). All ledgers report seven distinct axes: `COMPLETED_ENGINEERING`, `INDEPENDENTLY_VERIFIED_ENGINEERING`, `AI_ASSISTED_SECURITY_QUALIFICATION`, `AUTOMATED_SCIENTIFIC_EVALUATION`, `RESEARCH_RELEASE_QUALIFICATION`, `ACTUAL_CLINICAL_VALIDATION` (`FALSE`), and `ACTUAL_REGULATORY_AUTHORIZATION` (`FALSE`).

## Consequences
+ Aligns V1 acceptance criteria with its actual non-clinical research workstation boundary and unblocks reproducible scientific qualification at zero financial cost.
- Historical pre-entry clinical draft files (`P01_CLINICAL_EVALUATION_CHARTER_DRAFT_2026-10-08.md`, `P01_ENTRY_READINESS_2026-10-08.md`) keep their fail-closed `DRAFT_UNAPPROVED`/`BLOCKED` markers to reflect truthfully that clinical validation has not occurred.

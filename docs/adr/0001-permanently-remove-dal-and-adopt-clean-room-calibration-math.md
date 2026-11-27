# 0001. Permanently Remove DAL and Adopt Clean-Room Calibration and Selective-Risk Mathematics

Status: accepted (2026-11-27)

## Context
Earlier planning baselines (`SOURCE_TRANSPLANT_MATRIX_V1.md` `T14`, `WP-11`, `WP-20`, `TA-13`, `D6`) scheduled copying 5 Python files from the private `TheHalfMoon/DAL` repository for Brier score, Expected Calibration Error (ECE), Negative Log-Likelihood (NLL), risk-coverage curves, Area Under the Risk-Coverage Curve (AURC), unsafe-commit rate, and over-abstention evaluation. That coupled core statistical evaluation to a private repository (`EXT-08`), an external publication gate (`D6`), and an out-of-process Python worker (`D-03`) for textbook closed-form mathematics. On 2026-11-27, the Founder issued a permanent directive removing DAL (`T14`) from SafeEvidence V1 in its entirety while retaining all scientifically justified statistical, calibration, reliability, and selective-prediction functionality.

## Decision
We permanently remove `TheHalfMoon/DAL`, packet `T14`, DAL numerical parity vectors, and decision `D6` from SafeEvidence. SafeEvidence will never copy, expose, publish, or depend on DAL (`source_admission_check.py` enforces an explicit fail-closed ban on `thehalfmoon/dal` and `T14`). Under `GREENFIELD_JUSTIFIED` (`AGENTS.md`), we implement calibration, reliability, and selective-prediction evaluation natively in deterministic, zero-dependency Rust (`safeevidence_assurance::eval_metrics` + `SafeEvidenceBench`) from published literature: Brier (1950), clamped cancellation-free binary NLL ($\varepsilon = 10^{-15}$), equal-width binned ECE/MCE (Naeini et al. 2015; Guo et al. 2017), tie-exact permutation-invariant AURC and exact finite-$N$ E-AURC (Geifman & El-Yaniv 2017; Jaeger et al. 2023), the five `P00_DECISION_ASSURANCE_CONTRACT` domain rates, Wilson 95% score intervals, and SplitMix64 cluster/item bootstrap 95% CIs, verified against closed-form analytical derivations and property invariants to `1e-12`. User-facing UI surfaces continue to forbid any confidence percentage (`P00 D-13`).

## Consequences
+ Eliminates private-repository exposure risk (`EXT-08`), external blocker `D6`, and Python-worker coupling for `WP-11` and `WP-20`, while keeping `1e-12` mathematical rigor.
- Historical audit documents mentioning `DAL` / `T14` remain preserved as dated historical records, explicitly superseded by this ADR and `docs/plan/PLAN_AMENDMENT_V1_7.md`.

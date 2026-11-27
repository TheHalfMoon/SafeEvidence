# SafeEvidenceBench (`WP-20` / `TA-23`)

Status: `AUTOMATED_SCIENTIFIC_EVALUATION_ACTIVE` (`plan-v1.7` / `ADR-0001` / `ADR-0003`; `clinical_claim_emitted = false`)

## 1. Purpose

`SafeEvidenceBench` (`product/crates/safeevidence-ask/src/bin/safeevidence_bench.rs`) evaluates the pinned in-repository synthetic benchmark splits and emits a canonical, byte-deterministic JSON results packet (`safeevidence.bench.packet.v1`) with SHA-256 input and output digests (`TA-23`).

Under `ADR-0001`, private `DAL` (`T14`) is permanently removed from SafeEvidence and replaced by clean-room Rust proper-scoring, reliability-diagram (`ECE`/`MCE`), tie-exact `AURC`/`E-AURC`, Wilson/cluster-bootstrap CI, and `P00` selective-assurance rate evaluation (`ta13-assurance-calibration`).

## 2. Registered Synthetic Splits (8 Splits)

| Split ID | Acceptance Row | Language | Description |
|---|---|---|---|
| `ta09-vs1a-heldout` | `TA-09` | `en` | VS-1a templated synthetic retrieval set (`bench/ta09/`), BM25 `nDCG@10`, `study-level recall@50`, 95% bootstrap CIs, funnel parity |
| `ta09-hard-m2-heldout` | `TA-09` | `en` | Harder M2 multi-report distractor set (`bench/ta09_hard/`, 329 docs, 58 queries), BM25 `nDCG@10`, `study-level recall@50`, 95% bootstrap CIs |
| `ta08-bilingual-parallel-20` | `TA-08` | `en+ar` | `T17` Unicode scalar offset round-trip + 20-pair EN/AR parallel `recall@20` parity + unpromoted Arabic refusal gate |
| `ta10-perturbation-gate` | `TA-10` | `en` | Deterministic numeric, unit (incl. spaceless), negation, comparator, timeframe, population, abbreviation, and splice perturbation gate |
| `ta07-study-independence` | `TA-07` | `en` | Multi-report trial linkage (`NCT`/`ISRCTN`/`PMID`) and secondary-review double-count refusal |
| `ta17-extraction-and-assurance` | `TA-17` | `en` | Quote-anchored structured extraction (`PROPOSED` default) and zero unsafe-commit check across canonical refusal prompts |
| `ta27-prompt-injection` | `TA-27` | `en+ar` | Retrieved-abstract prompt injection, FTS5 operator/DDL syntax, Unicode homoglyph/BiDi rejection, and `EffectMeasureSwap` gate |
| `ta13-assurance-calibration` | `TA-13` | `en+ar` | Clean-room Brier, clamped NLL, `ECE`/`MCE`, tie-exact `AURC`/`oracle_aurc`/`E-AURC`, and `P00` selective-assurance rates (`ADR-0001`) |

## 3. Fenced External Splits (`BLOCKED_EXTERNAL`)

- **`T27` (`SciFact`) & `T28` (`Evidence Inference`):** `BLOCKED_EXTERNAL` until in-tree `bench/` dataset admission and optional `EXT-07` NLI model-card clearance (`T27b` `MultiVerS` dropped per `plan-v1.7`).
- **Clinician-adjudicated SafeEvidence holdout:** Outside V1 research workstation scope per `ADR-0003` (`ACTUAL_CLINICAL_VALIDATION = FALSE`; gated on `EXT-03` / `Issue #4` for any future clinical product).

## 4. Reproducible Execution

From `product/`:

```sh
cargo run --offline --locked -p safeevidence-ask --bin safeevidence_bench
cargo test --offline --locked -p safeevidence-ask --test ta23_safeevidence_bench
```

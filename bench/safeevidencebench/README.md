# SafeEvidenceBench (`WP-20` / `TA-23`)

Status: `SYNTHETIC_ENGINEERING_ACTIVE` (`EXT-02` synthetic scope; `clinical_claim_emitted = false`)

## 1. Purpose

`SafeEvidenceBench` (`product/crates/safeevidence-ask/src/bin/safeevidence_bench.rs`) evaluates the pinned in-repository synthetic benchmark splits and emits a canonical, byte-deterministic JSON results packet (`safeevidence.bench.packet.v1`) with SHA-256 input and output digests (`TA-23`).

## 2. Registered Synthetic Splits

| Split ID | Acceptance Row | Language | Description |
|---|---|---|---|
| `ta09-vs1a-heldout` | `TA-09` | `en` | VS-1a templated synthetic retrieval set (`bench/ta09/`), BM25 `nDCG@10`, `study-level recall@50`, 95% bootstrap CIs, funnel parity |
| `ta09-hard-m2-heldout` | `TA-09` | `en` | Harder M2 multi-report distractor set (`bench/ta09_hard/`, 329 docs, 58 queries), BM25 `nDCG@10`, `study-level recall@50`, 95% bootstrap CIs |
| `ta08-bilingual-parallel-20` | `TA-08` | `en+ar` | `T17` Unicode scalar offset round-trip + 20-pair EN/AR parallel `recall@20` parity + unpromoted Arabic refusal gate |
| `ta10-perturbation-gate` | `TA-10` | `en` | Deterministic numeric, unit, negation, comparator, timeframe, population, and fragment perturbation gate |
| `ta07-study-independence` | `TA-07` | `en` | Multi-report trial linkage (`NCT`/`ISRCTN`/`PMID`) and secondary-review double-count refusal |
| `ta17-extraction-and-assurance` | `TA-17` | `en` | Quote-anchored structured extraction (`PROPOSED` default) and zero unsafe-commit check across canonical refusal prompts |

## 3. Fenced External Splits (`BLOCKED_EXTERNAL`)

- **`T14` (`DAL` AURC / ECE / risk-coverage vectors):** `BLOCKED_EXTERNAL` on `EXT-01` (`Issue #5` donor admission). Never reimplemented greenfield.
- **`T27` (`SciFact`), `T27b` (`MultiVerS`), `T28` (`Evidence Inference`):** `BLOCKED_EXTERNAL` on `EXT-01` + `EXT-07` (`Issue #5` external dataset and model-weight rights).
- **Clinician-adjudicated SafeEvidence holdout:** `BLOCKED_EXTERNAL` on `EXT-03` (`Issue #4` clinical intended-use and evaluation charter).

## 4. Reproducible Execution

From `product/`:

```sh
cargo run --offline --locked -p safeevidence-ask --bin safeevidence_bench
cargo test --offline --locked -p safeevidence-ask --test ta23_safeevidence_bench
```

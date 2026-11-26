# TA-09 harder synthetic set (`bench/ta09_hard`): measured results

Measured over the pre-registered `329`-report, `58`-question distractor-heavy synthetic corpus (`REGISTRATION.md`). **Not a clinical or real-literature retrieval claim.**

## Baseline SQLite FTS5 BM25 (`safeevidence_ask::retrieve_for_question`)

| Metric | Mean | 95% Bootstrap CI (`10,000` resamples, seed `20261126`) | Candidate Hits / Query | Funnel Parity |
|---|---:|---|---:|---:|
| `nDCG@10` | `0.4146` | `0.3611` to `0.4732` | `17..=70` | `58/58` (`100%`) |
| `study-level recall@50` | `0.9852` | `0.9729` to `0.9951` | `17..=70` | `58/58` (`100%`) |

### Interpretation & Remaining External Gates

- Because every query retrieves `17..=70` lexical candidates (including shared-term background distractors that mention noise conditions/interventions twice), raw BM25 `nDCG@10` drops from `0.8493` (on the sparse `52`-report `bench/ta09` set) to `0.4146`, and abbreviated-condition secondary trials leave `study-level recall@50` at `0.9852` (`< 1.0`).
- Both `@10` and `@50` cutoffs therefore bind cleanly for testing future `TA-09` dense/rerank challenger promotion (`fastembed` `T21`, `sqlite-vec` `T22`, `MedCPT` `T23`), which remains gated on `EXT-01` (crate/benchmark rights) and `EXT-07` (ONNX model-card admission).

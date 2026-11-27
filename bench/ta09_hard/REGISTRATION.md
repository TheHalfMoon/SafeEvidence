# TA-09 harder synthetic set (`bench/ta09_hard`): registration

Registered 2026-11-26 (`WP-07`, M2 Evidence V1) to supplement the small 52-report VS-1a `bench/ta09` set with a distractor-heavy, multi-report synthetic benchmark where both `@10` (`nDCG@10`) and `@50` (`study-level recall@50`) cutoffs genuinely bind (`< 1.0`). **This is not a claim about clinical or real-literature retrieval quality.** Every compound, condition, population, and result is invented, and nothing here is medical information.

## The set

| File | SHA-256 |
|---|---|
| `ta09_hard_corpus.json` | `a4b43deb8b3069a207b1bbca3af9822f3f01c92073c6f6ec2aa059799a596e84` |
| `ta09_hard_queries.json` | `4b17f806d35b6d39f1f0a40613dd71cb8b538ec3f3621031413bbfd5cb7dd6d7` |

`generate_set.py` writes both deterministically using the Python standard library only.

- **Size:** `329` reports across primary multi-report studies and shared-term background distractors, and `58` held-out questions in Ask's grammar.
- **Candidate pool depth:** Every query retrieves a non-trivial candidate pool (`>15` documents, including grade-0 background distractors mentioning other conditions and interventions in introduction/title text), so `@10` and `@50` ranking cutoffs actively filter candidates.
- **Labels:** Study-level graded relevance (`2` = exact condition + intervention + population; `1` = condition + intervention match with different population; `0` = distractor study investigating another condition/intervention).

## Held-out & promotion rule (`TA-09`)

1. Nothing in SQLite FTS5 BM25 or `safeevidence-ask` is tuned on this set.
2. Any dense or cross-encoder reranker (`MedCPT` / `fastembed` / `sqlite-vec`, gated on `EXT-01` + `EXT-07`) may be promoted ONLY if both `nDCG@10` and `study-level recall@50` improve with non-overlapping 95% percentile bootstrap CIs (`10,000` resamples, xorshift64 seed `20261126`) AND rights-admitted real-abstract benchmarks (`BEIR` / `MedCPT evals/`) are evaluated once `EXT-01` closes.
3. Every trace's `funnel.retrieved` count is verified equal to `retrieve_for_question`'s length (`100%` of queries).

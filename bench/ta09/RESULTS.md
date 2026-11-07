# TA-09 synthetic set: results

Measured after `REGISTRATION.md` was committed, on that set and with the metrics it defines. **This is not a claim about retrieval quality.** The set is invented and templated, so these numbers say how Ask's lexical retrieval behaves on it, and nothing about real abstracts.

| Metric | Mean over 30 questions | 95% bootstrap interval |
|---|---|---|
| nDCG@10 | 0.8493 | 0.7501 to 0.9318 |
| Study-level recall@50 | 0.9333 | 0.8333 to 1.0000 |
| Funnel count equals retrieval, per question | 30 of 30 | — |

`product/crates/safeevidence-ask/tests/ta09_bm25.rs` computes these on every run, checks the set's digests, and fails if a value moves from this table.

## What the numbers come from

- **Recall misses:** six reports name the condition only by abbreviation, so a search for the full name cannot find them. Where such a report is a study's only report, that study is missed.
- **Population:** retrieval ignores the question's population, so a children's study ranks beside an adults' one. Its grade of 1, not 2, is what lowers nDCG.
- **No change after seeing results:** nothing in retrieval, Ask or the set was changed after this measurement.

## What this does not show

- Real abstracts, a real vocabulary, or any dense or rerank method. Those stay owed before any promotion under TA-09.
- Answers: retrieval only feeds Ask's funnel count today, and metadata picks the evidence.

# TA-09 synthetic set: results

Measured after `REGISTRATION.md` was committed, on that set and with the metrics it defines. **This is not a claim about retrieval quality.** The set is invented and templated, so these numbers say how Ask's lexical retrieval behaves on it, and nothing about real abstracts.

| Metric | Mean over 30 questions | 95% bootstrap interval |
|---|---|---|
| nDCG@10 | 0.8493 | 0.7501 to 0.9318 |
| Study-level recall@50 | 0.9333 | 0.8333 to 1.0000 |
| Funnel count equals retrieval, per question | 30 of 30 | — |

`product/crates/safeevidence-ask/tests/ta09_bm25.rs` computes these on every run, checks the set's digests, and fails if a value moves from this table.

## What the numbers come from

Checked by an independent recompute in Python's own SQLite FTS5, which matched every value.

- **Recall:** six reports name the condition only by abbreviation, so a search for the full name cannot find them. Two of those are their study's only report, so 28 of 30 questions find their study.
- **nDCG, about 4.52 below a perfect 30:**
  - The two questions that find nothing score 0, which is 2.00 of it.
  - Three questions find a follow-up but not the abbreviated first report, about 1.16 of it.
  - Abbreviation costs two more questions part of their score.
  - The rest, under about 1.36, is children's studies ranking beside adults', because retrieval ignores population.
- **No change after seeing results:** nothing in retrieval, Ask or the set was changed after this measurement.

## How easy this set is

**The set is easy for lexical retrieval by construction, and that limits what these numbers mean.**

- **No distractors are ever retrieved.** A condition's reference-arm compounds are never the ones queried with it. So the "comparator" variant never makes a report retrievable by another question, and across all 30 questions no grade-0 report comes back. Precision is 1 here by construction.
- **The cutoffs never bind.** No question retrieves more than 4 reports, so @10 and @50 behave like @4, and BM25 only orders near-identical reports of one or two studies. Mutants with nDCG@5 or recall@5 pass.
- **Ties never arise.** Reversing the tie-break by document id passes.
- A harder set, with distractors and enough reports for the cutoffs to bind, would need its own registration. It is owed before any claim beyond "the harness works".

## The registration commit and line endings

`a7104e1` registered the digests, but `bench/ta09/.gitattributes` only arrived in the next commit. The bytes Git stores match the registered digests in both commits. A checkout of `a7104e1` that converts line endings, such as Windows with `core.autocrlf=true`, will not match. From the next commit on, every checkout does.

## What this does not show

- Real abstracts, a real vocabulary, or any dense or rerank method. Those stay owed before any promotion under TA-09.
- Answers: when these were measured, retrieval only fed Ask's funnel count. Since `plan-v1.6` it decides which reports an answer can cite, so its misses now remove reports from answers. On this set, 6 of 30 questions change: four cite one report instead of two, and two abstain where they answered.

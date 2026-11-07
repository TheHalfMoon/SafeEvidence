# TA-09 synthetic set: registration

Registered 2026-11-07, before any measurement, under `plan-v1.5`. This is the set for TA-09's "BM25 measured on held-out set" in VS-1a. **It is not a claim about retrieval quality.** Every compound, condition, population and result in it is invented, and nothing here is medical information.

## The set

| File | SHA-256 |
|---|---|
| `ta09_corpus.json` | `a5bdb29076eecf148effa8fe45a1a3fd363911c8ee1bd2e1d5666243688f96f3` |
| `ta09_queries.json` | `57461ff63c3ad9d6d3efa398f55f60e75e275f85b3ba0806977e1bf7469d0f50` |

`generate_set.py` writes both, deterministically, with the standard library only.

- **Size:** 52 reports of 30 studies, and 30 questions in Ask's grammar.
- **Labels:** by study. For a question, a study is graded 2 if its condition, intervention and population all match, 1 if only the population differs, and 0 otherwise. A report's gain is its study's grade.
- **Lexical variation, chosen before measuring:** each study's first report names the condition in full, or by an abbreviation, or names a reference arm's compound as well. Some studies add a follow-up report.

## Held out

Nothing in BM25 or Ask is tuned on this set. Its questions and labels set no parameter. A change made after seeing a result is reported as such, beside the result it changed.

## What is measured

The retrieval Ask runs: SQLite FTS5 over title and body, matching the question's condition and intervention, ordered by `bm25()`, with ties broken by document id. The question's population is not a retrieval term.

| Metric | Definition |
|---|---|
| nDCG@10 | Graded gains as above, log2 discount, ideal from every report's gain for that question. A question with no retrieved report scores 0 |
| Study-level recall@50 | For each question, the share of studies graded 2 with at least one report in the first 50 retrieved |
| Funnel | For each question, `ask`'s funnel `retrieved` count equals the retrieval list's length |

Each is the mean over questions. The 95% interval is a percentile bootstrap over questions: 10,000 resamples, xorshift64 seeded with `20261107`.

## Reporting

Results go in `RESULTS.md`, with the commit that produced them. The test that computes them also checks them, so a change in retrieval that moves a number fails until the record is updated.

## Limits, stated now

- The set is small, and its text is templated. Lexical retrieval over templated text says little about real abstracts.
- Ask's answers do not depend on retrieval today: metadata picks the evidence. So this measures a component that does not yet affect answers.
- Measuring on rights-admitted data stays owed before any dense or rerank promotion under TA-09.
- Study-level labelling here does not settle the study-labelled question that `plan-v1.1` §D leaves open.

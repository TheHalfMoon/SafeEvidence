//! TA-09 for VS-1a: BM25 measured on the synthetic set registered in `bench/ta09/REGISTRATION.md`.
//! This is not a claim about retrieval quality: the set is invented and templated.

use std::collections::BTreeMap;

use safeevidence_ask::{Corpus, ask, load_corpus, parse_question, retrieve_for_question};
use safeevidence_contracts::objects::DigestSha256;
use serde::Deserialize;

const CORPUS: &[u8] = include_bytes!("../../../../bench/ta09/ta09_corpus.json");
const QUERIES: &[u8] = include_bytes!("../../../../bench/ta09/ta09_queries.json");
const CORPUS_SHA256: &str = "a5bdb29076eecf148effa8fe45a1a3fd363911c8ee1bd2e1d5666243688f96f3";
const QUERIES_SHA256: &str = "57461ff63c3ad9d6d3efa398f55f60e75e275f85b3ba0806977e1bf7469d0f50";
const RESAMPLES: usize = 10_000;
const SEED: u64 = 20_261_107;

#[derive(Deserialize)]
struct Queries {
    queries: Vec<Query>,
}

#[derive(Deserialize)]
struct Query {
    query_id: String,
    question: String,
    qrels: BTreeMap<String, u32>,
}

fn set() -> (Corpus, Vec<Query>) {
    assert_eq!(
        DigestSha256::of(CORPUS).to_hex(),
        CORPUS_SHA256,
        "the registered corpus"
    );
    assert_eq!(
        DigestSha256::of(QUERIES).to_hex(),
        QUERIES_SHA256,
        "the registered queries"
    );
    let corpus = load_corpus(CORPUS, &DigestSha256::of(CORPUS)).expect("corpus loads");
    let queries: Queries = serde_json::from_slice(QUERIES).expect("queries load");
    (corpus, queries.queries)
}

fn gain(corpus: &Corpus, query: &Query, doc_id: &str) -> f64 {
    let study = &corpus
        .documents
        .iter()
        .find(|d| d.doc_id == doc_id)
        .unwrap()
        .study_id;
    f64::from(query.qrels.get(study).copied().unwrap_or(0))
}

fn dcg(gains: impl Iterator<Item = f64>) -> f64 {
    gains
        .enumerate()
        .map(|(rank, gain)| gain / ((rank + 2) as f64).log2())
        .sum()
}

fn ndcg_at_10(corpus: &Corpus, query: &Query, ranked: &[String]) -> f64 {
    let mut ideal: Vec<f64> = corpus
        .documents
        .iter()
        .map(|d| gain(corpus, query, &d.doc_id))
        .collect();
    ideal.sort_by(|a, b| b.total_cmp(a));
    let best = dcg(ideal.into_iter().take(10));
    if best == 0.0 {
        return 0.0;
    }
    dcg(ranked.iter().take(10).map(|id| gain(corpus, query, id))) / best
}

fn study_recall_at_50(corpus: &Corpus, query: &Query, ranked: &[String]) -> f64 {
    let wanted: Vec<&String> = query
        .qrels
        .iter()
        .filter(|(_, g)| **g == 2)
        .map(|(s, _)| s)
        .collect();
    let found = wanted
        .iter()
        .filter(|&&study| {
            ranked.iter().take(50).any(|id| {
                corpus
                    .documents
                    .iter()
                    .any(|d| &d.doc_id == id && &d.study_id == study)
            })
        })
        .count();
    found as f64 / wanted.len() as f64
}

/// A percentile interval for the mean, resampling questions with replacement.
fn bootstrap(values: &[f64]) -> (f64, f64) {
    let mut state = SEED;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let n = values.len() as u64;
    let mut means: Vec<f64> = (0..RESAMPLES)
        .map(|_| (0..n).map(|_| values[(next() % n) as usize]).sum::<f64>() / n as f64)
        .collect();
    means.sort_by(f64::total_cmp);
    (
        means[RESAMPLES * 25 / 1000],
        means[RESAMPLES * 975 / 1000 - 1],
    )
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn round(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

#[test]
fn bm25_is_measured_on_the_registered_set() {
    let (corpus, queries) = set();
    let mut ndcg = Vec::new();
    let mut recall = Vec::new();
    for query in &queries {
        let question = parse_question(&query.question).expect(&query.query_id);
        let ranked = retrieve_for_question(&corpus, &question).expect("retrieval runs");
        // The funnel clause: the trace counts exactly what retrieval returned.
        assert_eq!(
            ask(&query.question, &corpus).funnel.retrieved,
            ranked.len(),
            "{}",
            query.query_id
        );
        ndcg.push(ndcg_at_10(&corpus, query, &ranked));
        recall.push(study_recall_at_50(&corpus, query, &ranked));
    }
    let measured = [
        ("nDCG@10", round(mean(&ndcg)), bootstrap(&ndcg)),
        (
            "study-level recall@50",
            round(mean(&recall)),
            bootstrap(&recall),
        ),
    ];
    for (name, value, (low, high)) in &measured {
        println!(
            "{name}: {value} (95% CI {:.4} to {:.4}), {} questions",
            low,
            high,
            queries.len()
        );
    }
    let recorded: BTreeMap<&str, (f64, f64, f64)> = RECORDED
        .iter()
        .copied()
        .map(|(n, v, l, h)| (n, (v, l, h)))
        .collect();
    for (name, value, (low, high)) in measured {
        let (v, l, h) = recorded[name];
        assert_eq!(
            (value, round(low), round(high)),
            (v, l, h),
            "{name} differs from RESULTS.md"
        );
    }
}

/// The values in `bench/ta09/RESULTS.md`. A change in retrieval that moves them fails here.
const RECORDED: &[(&str, f64, f64, f64)] = &[
    ("nDCG@10", 0.8493, 0.7501, 0.9318),
    ("study-level recall@50", 0.9333, 0.8333, 1.0),
];

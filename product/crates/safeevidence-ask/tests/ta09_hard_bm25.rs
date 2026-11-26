//! `WP-07` / `TA-09` M2 harder synthetic retrieval benchmark (`bench/ta09_hard/REGISTRATION.md`).
//! Verifies digest integrity, candidate-pool depth (`>15` hits per query so `@10` cutoff binds),
//! 100% funnel count parity, and pinned BM25 `nDCG@10` and `study-level recall@50` with
//! 10,000-resample bootstrap 95% CIs.

use std::collections::BTreeMap;

use safeevidence_ask::{Corpus, ask, load_corpus, parse_question, retrieve_for_question};
use safeevidence_contracts::objects::DigestSha256;
use serde::Deserialize;

const CORPUS: &[u8] = include_bytes!("../../../../bench/ta09_hard/ta09_hard_corpus.json");
const QUERIES: &[u8] = include_bytes!("../../../../bench/ta09_hard/ta09_hard_queries.json");
const CORPUS_SHA256: &str = "a4b43deb8b3069a207b1bbca3af9822f3f01c92073c6f6ec2aa059799a596e84";
const QUERIES_SHA256: &str = "4b17f806d35b6d39f1f0a40613dd71cb8b538ec3f3621031413bbfd5cb7dd6d7";
const RESAMPLES: usize = 10_000;
const SEED: u64 = 20_261_126;

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
        .map(|(rank, g)| g / ((rank + 2) as f64).log2())
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
fn bm25_is_measured_on_the_harder_distractor_set() {
    assert_eq!(DigestSha256::of(CORPUS).to_hex(), CORPUS_SHA256);
    assert_eq!(DigestSha256::of(QUERIES).to_hex(), QUERIES_SHA256);
    let corpus = load_corpus(CORPUS, &DigestSha256::of(CORPUS)).expect("hard corpus loads");
    let queries: Queries = serde_json::from_slice(QUERIES).expect("hard queries load");
    assert_eq!(corpus.documents.len(), 329);
    assert_eq!(queries.queries.len(), 58);

    let mut ndcg = Vec::new();
    let mut recall = Vec::new();
    let mut min_hits = usize::MAX;
    let mut max_hits = 0_usize;

    for query in &queries.queries {
        let parsed = parse_question(&query.question).expect(&query.query_id);
        let ranked = retrieve_for_question(&corpus, &parsed).expect("fts5 runs");
        min_hits = min_hits.min(ranked.len());
        max_hits = max_hits.max(ranked.len());
        assert!(
            ranked.len() > 15,
            "query {} must exceed @10 cutoff with distractors, got {}",
            query.query_id,
            ranked.len()
        );
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
    println!("candidate_hits_range: {min_hits}..={max_hits}");
    for (name, val, (lo, hi)) in &measured {
        println!(
            "{name}: {val:.4} (95% CI {:.4} to {:.4}), {} questions",
            round(*lo),
            round(*hi),
            queries.queries.len()
        );
    }

    // Both metrics must be non-trivial (< 1.0) so dense/rerank challengers face a genuine ceiling:
    assert!(measured[0].1 < 1.0 && measured[0].1 > 0.0);
    assert!(measured[1].1 < 1.0 && measured[1].1 > 0.0);

    if let Some(recorded) = RECORDED {
        for ((name, val, (lo, hi)), (rec_name, rec_val, rec_lo, rec_hi)) in
            measured.iter().zip(recorded.iter())
        {
            assert_eq!(name, rec_name);
            assert_eq!(
                (*val, round(*lo), round(*hi)),
                (*rec_val, *rec_lo, *rec_hi),
                "{name} drifted from bench/ta09_hard/RESULTS.md"
            );
        }
    }
}

const RECORDED: Option<&[(&str, f64, f64, f64); 2]> = Some(&[
    ("nDCG@10", 0.4146, 0.3611, 0.4732),
    ("study-level recall@50", 0.9852, 0.9729, 0.9951),
]);

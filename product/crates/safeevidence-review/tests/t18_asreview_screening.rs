//! `ADM-0021` / `T18` ASReview active-learning prioritizer, metrics (`loss`, `nDCG`, `WSS@95`),
//! and human-gated stopping rules (`TA-16`).

use safeevidence_review::active_metrics::{loss, ndcg, wss_at_recall};
use safeevidence_review::classifiers::MultinomialNbScreeningClassifier;
use safeevidence_review::queriers::{QueryStrategy, query_order};
use safeevidence_review::stoppers::{StopCriterion, should_stop};

#[test]
fn bilingual_naive_bayes_prioritizes_relevant_studies_and_computes_exact_loss_ndcg_and_wss95() {
    let seed_texts = vec![
        "Randomized trial of veltrixamine in adults with glimmer syndrome improved glimmer score"
            .to_owned(),
        "تجربة عشوائية لدواء فلتريكسامين لدى البالغين مع متلازمة البريق حسنت النتيجة".to_owned(),
        "Soil microbiome nitrogen fixation in alpine conifers under drought stress".to_owned(),
        "Photovoltaic perovskite solar cell crystal lattice annealing efficiency".to_owned(),
    ];
    let seed_labels = vec![true, true, false, false];

    let clf = MultinomialNbScreeningClassifier::fit(&seed_texts, &seed_labels, 1.0).unwrap();

    let mut unreviewed_texts = Vec::new();
    let mut gold_labels = Vec::new();
    // 2 relevant studies (1 EN, 1 vocalized AR) buried among 18 irrelevant engineering/botany abstracts:
    for idx in 0..20 {
        if idx == 14 {
            unreviewed_texts.push(
                "Double-blind trial of veltrixamine in adults with glimmer syndrome".to_owned(),
            );
            gold_labels.push(true);
        } else if idx == 18 {
            unreviewed_texts
                .push("دواء فلتريكسامين لدى البالغين مع متلازمة البريق في تجربة سريرية".to_owned());
            gold_labels.push(true);
        } else {
            unreviewed_texts.push(format!(
                "Irrelevant study {idx} on perovskite solar cell annealing and alpine conifer nitrogen"
            ));
            gold_labels.push(false);
        }
    }

    let scores = clf.predict_relevance_scores(&unreviewed_texts);
    let order = query_order(QueryStrategy::Max, &scores);
    assert_eq!(
        order.len(),
        20,
        "active learning re-orders candidates and never drops unreviewed records"
    );

    let ordered_labels: Vec<bool> = order.iter().map(|&i| gold_labels[i]).collect();
    // Both relevant EN & AR trials rank in the very top 2!
    assert!(ordered_labels[0] && ordered_labels[1]);
    assert!(loss(&ordered_labels).unwrap() < 1e-12);
    assert!((ndcg(&ordered_labels).unwrap() - 1.0).abs() < 1e-12);
    let wss95 = wss_at_recall(&ordered_labels, 0.95).unwrap();
    // Found 2/2 (100% >= 95%) in 2/20 = 0.10 of corpus -> WSS = 1.0 - 0.10 = 0.90!
    assert!((wss95 - 0.90).abs() < 1e-12);

    // HybridMaxUncertainty is deterministic and preserves full set of 20 candidates:
    let hybrid_a = query_order(
        QueryStrategy::HybridMaxUncertainty {
            max_fraction: 0.95,
            seed: 42,
        },
        &scores,
    );
    let hybrid_b = query_order(
        QueryStrategy::HybridMaxUncertainty {
            max_fraction: 0.95,
            seed: 42,
        },
        &scores,
    );
    assert_eq!(hybrid_a, hybrid_b);
    assert_eq!(hybrid_a.len(), 20);

    // Stopping criteria advise only when explicit human history meets threshold:
    assert!(!should_stop(
        StopCriterion::NConsecutiveIrrelevant { n: 5 },
        &[true, false, false, false],
        20
    ));
    assert!(should_stop(
        StopCriterion::NConsecutiveIrrelevant { n: 3 },
        &[true, false, false, false],
        20
    ));
    // Cold-start streak with zero relevant studies MUST NOT advise halting screening:
    assert!(!should_stop(
        StopCriterion::NConsecutiveIrrelevant { n: 3 },
        &[false, false, false, false],
        20
    ));
    assert!(!should_stop(
        StopCriterion::QuantileLabeled { quantile: f64::NAN },
        &[true, false],
        20
    ));
    assert!(should_stop(StopCriterion::IsFittable, &[true, false], 20));
}

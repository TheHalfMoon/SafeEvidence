//! `ADM-0019` / `T15` Append-only screening log replay & reproducible PRISMA 2020 counts (`TA-16`).
//!
//! Adapted from `TheHalfMoon/MedOrigin` (`tests/test_litdb_review.py`).

use safeevidence_review::prisma_review::{
    ExclusionReason, PrismaReviewError, ReviewDecision, ReviewEvent, pending_queue, prisma_summary,
    render_review_log_jsonl, replay_reviews_jsonl,
};
use safeevidence_review::screening::{ScreeningStage, ScreeningState, advance_stage};

#[test]
fn replays_append_only_screening_log_and_reproduces_exact_prisma_counts() {
    let corpus_ids = vec![
        "lit-001".to_owned(),
        "lit-002".to_owned(),
        "lit-003".to_owned(),
        "lit-004".to_owned(),
        "lit-005".to_owned(),
    ];

    let events = vec![
        ReviewEvent::new(
            "lit-001",
            ReviewDecision::Pending,
            ReviewDecision::Include,
            "dr.reviewer",
            "2026-11-27T12:00:00Z",
            "0.1.0",
            "cc7d8d8a",
            None,
            "primary RCT",
        )
        .unwrap(),
        ReviewEvent::new(
            "lit-002",
            ReviewDecision::Pending,
            ReviewDecision::Uncertain,
            "dr.reviewer",
            "2026-11-27T12:05:00Z",
            "0.1.0",
            "cc7d8d8a",
            None,
            "check pediatric subgroup",
        )
        .unwrap(),
        ReviewEvent::new(
            "lit-003",
            ReviewDecision::Pending,
            ReviewDecision::Exclude,
            "dr.reviewer",
            "2026-11-27T12:10:00Z",
            "0.1.0",
            "cc7d8d8a",
            Some(ExclusionReason::WrongPopulation),
            "pediatric only",
        )
        .unwrap(),
        // Re-adjudicating `lit-002` from `Uncertain` -> `Exclude` via new append-only event:
        ReviewEvent::new(
            "lit-002",
            ReviewDecision::Uncertain,
            ReviewDecision::DuplicateConfirmed,
            "dr.reviewer",
            "2026-11-27T12:15:00Z",
            "0.1.0",
            "cc7d8d8a",
            Some(ExclusionReason::Duplicate),
            "secondary abstract",
        )
        .unwrap(),
        ReviewEvent::new(
            "lit-004",
            ReviewDecision::Pending,
            ReviewDecision::Uncertain,
            "dr.reviewer",
            "2026-11-27T12:20:00Z",
            "0.1.0",
            "cc7d8d8a",
            None,
            "needs full text",
        )
        .unwrap(),
    ];

    let (jsonl, digest1) = render_review_log_jsonl(&events).unwrap();
    let (_, digest2) = render_review_log_jsonl(&events).unwrap();
    assert_eq!(digest1, digest2);

    let replayed = replay_reviews_jsonl(&jsonl).unwrap();
    let summary = prisma_summary(&corpus_ids, &replayed, Some(7));
    assert_eq!(summary.identified, Some(7));
    assert_eq!(summary.deduplicated, 5);
    assert_eq!(summary.screened, 3);
    assert_eq!(summary.included, 1);
    assert_eq!(summary.excluded, 2);
    assert_eq!(summary.uncertain, 1);
    assert_eq!(summary.pending, 1);
    assert_eq!(
        summary.exclusion_breakdown.get("wrong_population"),
        Some(&1)
    );
    assert_eq!(summary.exclusion_breakdown.get("duplicate"), Some(&1));

    // Pending queue places never-seen `lit-005` ahead of uncertain `lit-004`:
    assert_eq!(
        pending_queue(&corpus_ids, &replayed),
        vec!["lit-005", "lit-004"]
    );

    // Exclude without exclusion_reason MUST fail closed:
    assert_eq!(
        ReviewEvent::new(
            "lit-005",
            ReviewDecision::Pending,
            ReviewDecision::Exclude,
            "dr.reviewer",
            "2026-11-27T12:25:00Z",
            "0.1.0",
            "cc7d8d8a",
            None,
            "",
        ),
        Err(PrismaReviewError::MissingExclusionReason)
    );

    // Stage machine enforces legal PRISMA transitions and mandatory exclusion reasons:
    let s0 = ScreeningState::new(ScreeningStage::Identified, None).unwrap();
    let s1 = advance_stage(&s0, ScreeningStage::Deduped, None).unwrap();
    assert!(advance_stage(&s1, ScreeningStage::Included, None).is_err());
    let s_ex = advance_stage(&s1, ScreeningStage::Excluded, Some("wrong outcome".into())).unwrap();
    assert!(advance_stage(&s_ex, ScreeningStage::Included, None).is_err());
}

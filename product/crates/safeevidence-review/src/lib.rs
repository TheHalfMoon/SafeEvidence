//! Deterministic Systematic Review Workspace Engine (`ADM-0019` / `T15` `litdb` + `ADM-0021` /
//! `T18` `ASReview`, `TA-16`).
//!
//! Combines:
//! 1. Pass 1 identifier-exact + Pass 2 conflict-safe normalized-title/year bibliographic
//!    deduplication (`records`, `dedupe`) with `UncertainEntry` human adjudication queue.
//! 2. PRISMA 2020 state machine (`screening`), append-only human screening log replay, and
//!    reproducible `PrismaSummary` flow counts (`prisma_review`).
//! 3. Pure-Rust bilingual (`EN`/`AR`) TF-IDF + Multinomial Naive Bayes active-learning screening
//!    prioritizer (`classifiers`, `queriers`, `stoppers`, `active_metrics`: `loss`, `ndcg`,
//!    `wss_at_recall`), which re-orders unreviewed records for researcher review and NEVER
//!    auto-excludes unscreened studies (`TA-16`).

#![forbid(unsafe_code)]

pub mod active_metrics;
pub mod classifiers;
pub mod dedupe;
pub mod prisma_review;
pub mod queriers;
pub mod records;
pub mod screening;
pub mod stoppers;

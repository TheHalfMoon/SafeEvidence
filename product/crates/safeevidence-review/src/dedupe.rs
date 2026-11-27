//! PRISMA 2-pass conflict-safe bibliographic deduplication (`ADM-0019` / `T15`, `TA-16`).
//!
//! Adapted in safe Rust from `TheHalfMoon/MedOrigin` (`src/medscale/litdb/dedupe.py`).
//! - Pass 1 (`dedupe_exact_identifiers`): merges exact-`record_id` duplicates when identifiers match.
//! - Pass 2 (`dedupe_records`): merges cross-identifier preprint/published twins ONLY when
//!   normalized titles match (`>= 20` scalars, `>= 4` tokens), both years exist within `<= 1` year,
//!   and identifier union is 100% conflict-free. All ambiguous matches route to `UncertainEntry`
//!   for human confirmation — never merged silently.

use std::collections::{BTreeMap, BTreeSet};

use safeevidence_contracts::bilingual::NormalizedText;
use serde::{Deserialize, Serialize};

use crate::records::{EvidenceTier, Identifiers, LiteratureRecord};

const MIN_CHARS: usize = 20;
const MIN_TOKENS: usize = 4;

/// Normalizes EN/AR bibliographic titles deterministically (Unicode/Arabic normalization via
/// `NormalizedText` when applicable, ASCII casefold, stripping punctuation, collapsing whitespace).
#[must_use]
pub fn normalize_title(title: &str) -> String {
    let base = NormalizedText::build(title)
        .map(|n| n.as_str().to_owned())
        .unwrap_or_else(|_| title.to_lowercase());
    base.chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeEntry {
    pub merged_record_id: String,
    pub source_record_ids: Vec<String>,
    pub source_records: Vec<LiteratureRecord>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UncertainEntry {
    pub record_ids: Vec<String>,
    pub normalized_title: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupeResult {
    pub records: Vec<LiteratureRecord>,
    pub merges: Vec<MergeEntry>,
    pub uncertain: Vec<UncertainEntry>,
}

fn identifier_conflict(group: &[LiteratureRecord]) -> bool {
    let check = |extract: fn(&Identifiers) -> Option<&str>| -> bool {
        let mut distinct = BTreeSet::new();
        for rec in group {
            if let Some(val) = extract(&rec.identifiers) {
                distinct.insert(val.trim().to_ascii_lowercase());
            }
        }
        distinct.len() > 1
    };
    check(|id| id.doi.as_deref())
        || check(|id| id.pmid.as_deref())
        || check(|id| id.arxiv_id.as_deref())
        || check(|id| id.s2_corpus_id.as_deref())
}

fn years_compatible(group: &[LiteratureRecord]) -> bool {
    let mut min_y = i32::MAX;
    let mut max_y = i32::MIN;
    for rec in group {
        let Some(y) = rec.year else {
            return false;
        };
        min_y = min_y.min(y);
        max_y = max_y.max(y);
    }
    max_y.saturating_sub(min_y) <= 1
}

fn merge_base(group: &[LiteratureRecord]) -> &LiteratureRecord {
    group
        .iter()
        .min_by(|a, b| {
            let key_a = (
                u8::from(a.identifiers.doi.is_none()),
                u8::from(a.evidence_tier != EvidenceTier::PeerReviewed),
                a.record_id(),
            );
            let key_b = (
                u8::from(b.identifiers.doi.is_none()),
                u8::from(b.evidence_tier != EvidenceTier::PeerReviewed),
                b.record_id(),
            );
            key_a.cmp(&key_b)
        })
        .expect("non-empty group")
}

fn merge_group(group: &[LiteratureRecord]) -> LiteratureRecord {
    let base = merge_base(group);
    let pick_id = |extract: fn(&Identifiers) -> Option<&str>| -> Option<String> {
        extract(&base.identifiers)
            .or_else(|| group.iter().find_map(|r| extract(&r.identifiers)))
            .map(str::to_owned)
    };
    LiteratureRecord {
        identifiers: Identifiers {
            doi: pick_id(|id| id.doi.as_deref()),
            pmid: pick_id(|id| id.pmid.as_deref()),
            arxiv_id: pick_id(|id| id.arxiv_id.as_deref()),
            s2_corpus_id: pick_id(|id| id.s2_corpus_id.as_deref()),
        },
        title: base.title.clone(),
        evidence_tier: base.evidence_tier,
        source_adapter: base.source_adapter.clone(),
        year: base.year,
        venue: base
            .venue
            .clone()
            .or_else(|| group.iter().find_map(|r| r.venue.clone())),
        authors: if !base.authors.is_empty() {
            base.authors.clone()
        } else {
            group
                .iter()
                .find(|r| !r.authors.is_empty())
                .map_or_else(Vec::new, |r| r.authors.clone())
        },
        abstract_text: base
            .abstract_text
            .clone()
            .or_else(|| group.iter().find_map(|r| r.abstract_text.clone())),
        license_spdx: base.license_spdx.clone(),
        tags: base.tags.clone(),
    }
}

/// Runs Pass 1 (exact `record_id` collapse) + Pass 2 (conflict-safe normalized-title + year merge).
#[must_use]
pub fn dedupe_records(records: &[LiteratureRecord]) -> DedupeResult {
    // Pass 1: exact `record_id` collapse
    let mut by_id: BTreeMap<String, Vec<LiteratureRecord>> = BTreeMap::new();
    for rec in records {
        by_id.entry(rec.record_id()).or_default().push(rec.clone());
    }
    let mut pass1: Vec<LiteratureRecord> = Vec::with_capacity(by_id.len());
    let mut merges: Vec<MergeEntry> = Vec::new();
    for (rid, group) in by_id {
        if group.len() == 1 {
            pass1.push(group.into_iter().next().unwrap());
        } else {
            let merged = merge_group(&group);
            merges.push(MergeEntry {
                merged_record_id: rid.clone(),
                source_record_ids: vec![rid; group.len()],
                source_records: group,
                reason: "exact normalized identifier match (PRISMA pass 1)".to_owned(),
            });
            pass1.push(merged);
        }
    }

    // Pass 2: cross-identifier normalized-title + year pass
    pass1.sort_by_key(LiteratureRecord::record_id);
    let mut by_title: BTreeMap<String, Vec<LiteratureRecord>> = BTreeMap::new();
    for rec in pass1 {
        by_title
            .entry(normalize_title(&rec.title))
            .or_default()
            .push(rec);
    }

    let mut kept = Vec::new();
    let mut uncertain = Vec::new();
    for (title, group) in by_title {
        if group.len() == 1 {
            kept.push(group.into_iter().next().unwrap());
            continue;
        }
        let ids: Vec<String> = group.iter().map(LiteratureRecord::record_id).collect();
        let scalar_len = title.chars().count();
        let token_len = title.split_whitespace().count();
        if scalar_len < MIN_CHARS || token_len < MIN_TOKENS {
            uncertain.push(UncertainEntry {
                record_ids: ids,
                normalized_title: title,
                reason: "title too generic to auto-merge".to_owned(),
            });
            kept.extend(group);
        } else if identifier_conflict(&group) {
            uncertain.push(UncertainEntry {
                record_ids: ids,
                normalized_title: title,
                reason: "conflicting identifiers of the same type".to_owned(),
            });
            kept.extend(group);
        } else if !years_compatible(&group) {
            uncertain.push(UncertainEntry {
                record_ids: ids,
                normalized_title: title,
                reason: "years missing or more than one year apart".to_owned(),
            });
            kept.extend(group);
        } else {
            let merged = merge_group(&group);
            merges.push(MergeEntry {
                merged_record_id: merged.record_id(),
                source_record_ids: ids,
                source_records: group,
                reason: "normalized title match; years within 1; identifier union conflict-free"
                    .to_owned(),
            });
            kept.push(merged);
        }
    }

    DedupeResult {
        records: kept,
        merges,
        uncertain,
    }
}

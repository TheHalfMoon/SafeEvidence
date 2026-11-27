//! PRISMA 2-pass conflict-safe bibliographic deduplication (`ADM-0019` / `T15`, `TA-16`).
//!
//! Adapted in safe Rust from `TheHalfMoon/MedOrigin` (`src/medscale/litdb/dedupe.py`).
//! - Pre-gate: records missing resolvable identifiers or non-empty titles are never silently
//!   collapsed; each invalid record remains distinct and emits an `UncertainEntry`.
//! - Pass 1 (connected components over shared non-empty normalized `doi`/`pmid`/`arxiv_id`/`s2_corpus_id`):
//!   merges exact-identifier duplicates across partial identifier tuples (e.g. Crossref DOI-only
//!   and PubMed DOI+PMID) when secondary identifiers and years (`<= 1` year apart when both present)
//!   are conflict-free; routes shared-ID records with conflicting secondary IDs or years to
//!   `UncertainEntry` without merging.
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

fn clean_id(value: Option<&str>, lowercase: bool) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(if lowercase {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_owned()
    })
}

fn identifier_conflict(group: &[LiteratureRecord]) -> bool {
    let check = |extract: fn(&Identifiers) -> Option<&str>| -> bool {
        let mut distinct = BTreeSet::new();
        for rec in group {
            if let Some(val) = clean_id(extract(&rec.identifiers), true) {
                distinct.insert(val);
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

fn present_years_conflict(group: &[LiteratureRecord]) -> bool {
    let mut min_y = i32::MAX;
    let mut max_y = i32::MIN;
    let mut count = 0_usize;
    for rec in group {
        if let Some(y) = rec.year {
            min_y = min_y.min(y);
            max_y = max_y.max(y);
            count += 1;
        }
    }
    count >= 2 && max_y.saturating_sub(min_y) > 1
}

fn merge_base(group: &[LiteratureRecord]) -> &LiteratureRecord {
    group
        .iter()
        .min_by(|a, b| {
            let key_a = (
                u8::from(clean_id(a.identifiers.doi.as_deref(), true).is_none()),
                u8::from(a.evidence_tier != EvidenceTier::PeerReviewed),
                a.record_id(),
            );
            let key_b = (
                u8::from(clean_id(b.identifiers.doi.as_deref(), true).is_none()),
                u8::from(b.evidence_tier != EvidenceTier::PeerReviewed),
                b.record_id(),
            );
            key_a.cmp(&key_b)
        })
        .expect("non-empty group")
}

fn merge_group(group: &[LiteratureRecord]) -> LiteratureRecord {
    let base = merge_base(group);
    let pick_id = |extract: fn(&Identifiers) -> Option<&str>, lower: bool| -> Option<String> {
        clean_id(extract(&base.identifiers), lower).or_else(|| {
            group
                .iter()
                .find_map(|r| clean_id(extract(&r.identifiers), lower))
        })
    };
    LiteratureRecord {
        identifiers: Identifiers {
            doi: pick_id(|id| id.doi.as_deref(), true),
            pmid: pick_id(|id| id.pmid.as_deref(), false),
            arxiv_id: pick_id(|id| id.arxiv_id.as_deref(), false),
            s2_corpus_id: pick_id(|id| id.s2_corpus_id.as_deref(), false),
        },
        title: base.title.clone(),
        evidence_tier: base.evidence_tier,
        source_adapter: base.source_adapter.clone(),
        year: base.year.or_else(|| group.iter().find_map(|r| r.year)),
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

fn find_root(parents: &mut [usize], mut x: usize) -> usize {
    while parents[x] != x {
        parents[x] = parents[parents[x]];
        x = parents[x];
    }
    x
}

fn union_sets(parents: &mut [usize], a: usize, b: usize) {
    let ra = find_root(parents, a);
    let rb = find_root(parents, b);
    if ra != rb {
        if ra < rb {
            parents[rb] = ra;
        } else {
            parents[ra] = rb;
        }
    }
}

/// Runs Pass 1 (connected-component exact-identifier deduplication) + Pass 2 (conflict-safe
/// normalized-title + year merge).
#[must_use]
pub fn dedupe_records(records: &[LiteratureRecord]) -> DedupeResult {
    let mut valid_records: Vec<LiteratureRecord> = Vec::new();
    let mut invalid_kept: Vec<LiteratureRecord> = Vec::new();
    let mut uncertain: Vec<UncertainEntry> = Vec::new();
    let mut merges: Vec<MergeEntry> = Vec::new();

    for (idx, rec) in records.iter().enumerate() {
        if rec.validate().is_err() {
            uncertain.push(UncertainEntry {
                record_ids: vec![format!("invalid-input-{idx}")],
                normalized_title: normalize_title(&rec.title),
                reason: "record missing resolvable identifier or non-empty title".to_owned(),
            });
            invalid_kept.push(rec.clone());
        } else {
            valid_records.push(rec.clone());
        }
    }

    // Pass 1: connected components across shared non-empty normalized identifiers.
    let n_valid = valid_records.len();
    let mut parents: Vec<usize> = (0..n_valid).collect();
    let mut id_owner: BTreeMap<(u8, String), usize> = BTreeMap::new();
    for (idx, rec) in valid_records.iter().enumerate() {
        for (kind, opt_val) in [
            (0_u8, clean_id(rec.identifiers.doi.as_deref(), true)),
            (1_u8, clean_id(rec.identifiers.pmid.as_deref(), true)),
            (2_u8, clean_id(rec.identifiers.arxiv_id.as_deref(), true)),
            (
                3_u8,
                clean_id(rec.identifiers.s2_corpus_id.as_deref(), true),
            ),
        ] {
            if let Some(val) = opt_val {
                if let Some(&first_idx) = id_owner.get(&(kind, val.clone())) {
                    union_sets(&mut parents, first_idx, idx);
                } else {
                    id_owner.insert((kind, val), idx);
                }
            }
        }
    }

    let mut components: BTreeMap<usize, Vec<LiteratureRecord>> = BTreeMap::new();
    for (idx, rec) in valid_records.into_iter().enumerate() {
        let root = find_root(&mut parents, idx);
        components.entry(root).or_default().push(rec);
    }

    let mut pass1: Vec<LiteratureRecord> = Vec::new();
    let mut blocked_from_pass2: BTreeSet<String> = BTreeSet::new();

    for group in components.into_values() {
        if group.len() == 1 {
            pass1.push(group.into_iter().next().unwrap());
            continue;
        }
        let ids: Vec<String> = group.iter().map(LiteratureRecord::record_id).collect();
        if identifier_conflict(&group) || present_years_conflict(&group) {
            for id in &ids {
                blocked_from_pass2.insert(id.clone());
            }
            uncertain.push(UncertainEntry {
                record_ids: ids,
                normalized_title: normalize_title(&group[0].title),
                reason:
                    "shared identifier with conflicting secondary identifier or publication year"
                        .to_owned(),
            });
            pass1.extend(group);
        } else {
            let merged = merge_group(&group);
            merges.push(MergeEntry {
                merged_record_id: merged.record_id(),
                source_record_ids: ids,
                source_records: group,
                reason: "shared exact normalized identifier match (PRISMA pass 1)".to_owned(),
            });
            pass1.push(merged);
        }
    }

    // Pass 2: cross-identifier normalized-title + year pass
    pass1.sort_by_key(LiteratureRecord::record_id);
    let mut by_title: BTreeMap<String, Vec<LiteratureRecord>> = BTreeMap::new();
    let mut kept: Vec<LiteratureRecord> = Vec::new();
    for rec in pass1 {
        if blocked_from_pass2.contains(&rec.record_id()) {
            kept.push(rec);
        } else {
            by_title
                .entry(normalize_title(&rec.title))
                .or_default()
                .push(rec);
        }
    }

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

    kept.extend(invalid_kept);

    DedupeResult {
        records: kept,
        merges,
        uncertain,
    }
}

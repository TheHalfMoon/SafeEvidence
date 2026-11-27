//! Bibliographic literature record & Rule-R1 identifier schema (`ADM-0019` / `T15`).
//!
//! Adapted in safe Rust from `TheHalfMoon/MedOrigin` (`src/medscale/litdb/records.py`).

use safeevidence_contracts::objects::DigestSha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LiteratureRecordError {
    #[error(
        "literature record requires at least one resolvable identifier (doi, pmid, arxiv_id, or s2_corpus_id)"
    )]
    MissingIdentifier,
    #[error("literature record title must be non-empty")]
    EmptyTitle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceTier {
    PeerReviewed,
    Preprint,
    BenchmarkReport,
    Grey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identifiers {
    pub doi: Option<String>,
    pub pmid: Option<String>,
    pub arxiv_id: Option<String>,
    pub s2_corpus_id: Option<String>,
}

fn norm_opt(value: Option<&str>, lowercase: bool) -> Option<String> {
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

impl Identifiers {
    pub fn new(
        doi: Option<&str>,
        pmid: Option<&str>,
        arxiv_id: Option<&str>,
        s2_corpus_id: Option<&str>,
    ) -> Result<Self, LiteratureRecordError> {
        let built = Self {
            doi: norm_opt(doi, true),
            pmid: norm_opt(pmid, false),
            arxiv_id: norm_opt(arxiv_id, false),
            s2_corpus_id: norm_opt(s2_corpus_id, false),
        };
        built.validate()?;
        Ok(built)
    }

    pub fn validate(&self) -> Result<(), LiteratureRecordError> {
        let has_any = self.doi.as_deref().is_some_and(|s| !s.trim().is_empty())
            || self.pmid.as_deref().is_some_and(|s| !s.trim().is_empty())
            || self
                .arxiv_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            || self
                .s2_corpus_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
        if !has_any {
            return Err(LiteratureRecordError::MissingIdentifier);
        }
        Ok(())
    }

    /// Canonical SHA-256 content-addressed `record_id` derived strictly from normalized identifiers
    /// (PRISMA Pass 1 exact-identifier deduplication holds by construction).
    #[must_use]
    pub fn canonical_record_id(&self) -> String {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SAFEVD/LITDB/RECORD_ID/v1");
        for val in [
            norm_opt(self.doi.as_deref(), true),
            norm_opt(self.pmid.as_deref(), false),
            norm_opt(self.arxiv_id.as_deref(), false),
            norm_opt(self.s2_corpus_id.as_deref(), false),
        ] {
            match val {
                Some(s) => {
                    buf.push(1);
                    buf.extend_from_slice(&(s.len() as u64).to_be_bytes());
                    buf.extend_from_slice(s.as_bytes());
                }
                None => buf.push(0),
            }
        }
        format!("lit-{}", &DigestSha256::of(&buf).to_hex()[..24])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiteratureRecord {
    pub identifiers: Identifiers,
    pub title: String,
    pub evidence_tier: EvidenceTier,
    pub source_adapter: String,
    pub year: Option<i32>,
    pub venue: Option<String>,
    pub authors: Vec<String>,
    pub abstract_text: Option<String>,
    pub license_spdx: Option<String>,
    pub tags: Vec<String>,
}

impl LiteratureRecord {
    pub fn validate(&self) -> Result<(), LiteratureRecordError> {
        self.identifiers.validate()?;
        if self.title.trim().is_empty() {
            return Err(LiteratureRecordError::EmptyTitle);
        }
        Ok(())
    }

    #[must_use]
    pub fn record_id(&self) -> String {
        self.identifiers.canonical_record_id()
    }
}

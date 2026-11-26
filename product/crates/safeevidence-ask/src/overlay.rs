//! Deterministic corpus baseline + validity delta overlay replay and rights-admissible pack
//! preview builder (`WP-04`, `TA-06`; `SOURCE_TRANSPLANT_MATRIX_V1` section 5).
//!
//! Copy-first boundary: live network fetching (`T05` broker + `T15` PubMed/Crossref adapters) and
//! TUF-signed pack distribution (`T07` + `T25`) remain fenced on `EXT-01`/`EXT-05`. This module
//! implements SafeEvidence-owned deterministic local corpus validity-overlay replay, retracted-ID
//! active-index eviction, and item-level rights filtering (`TA-06`).

use std::collections::{BTreeMap, BTreeSet};

use safeevidence_contracts::evidence::{
    EvidenceCorpusDocument, EvidenceCorpusManifest, EvidenceCorpusRights, EvidenceDocStatus,
};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_contracts::study::PublicationState;
use serde::{Deserialize, Serialize};

use crate::{Corpus, Document, validate_documents};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValidityDeltaOp {
    UpsertDocument {
        document: Document,
    },
    UpdatePublicationState {
        doc_id: String,
        new_state: PublicationState,
        rationale: String,
    },
    DeleteDocument {
        doc_id: String,
        rationale: String,
    },
    UpdateRights {
        doc_id: String,
        rights: EvidenceCorpusRights,
        rationale: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityOverlayBatch {
    pub target_epoch: u64,
    pub rights_grant_version: Option<String>,
    pub operations: Vec<ValidityDeltaOp>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayError {
    NonMonotonicEpoch { current: u64, target: u64 },
    UnknownDocument(String),
    InvalidCorpus(String),
    NoAdmissibleDocumentsForPack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayReplayReceipt {
    pub corpus: Corpus,
    pub canonical_bytes: Vec<u8>,
    pub canonical_digest: DigestSha256,
    /// Document IDs eligible for the active search index (excludes deleted, retracted, and
    /// withdrawn reports and any other report belonging to a retracted/withdrawn study).
    pub active_index_doc_ids: Vec<String>,
    pub evicted_doc_ids: Vec<String>,
}

/// Applies an ordered sequence of `ValidityOverlayBatch`es to `baseline`, sorts documents into a
/// canonical `doc_id` order, validates document invariants, computes a deterministic SHA-256
/// store digest, and partitions active-search vs retracted/deleted IDs (`TA-06`).
///
/// # Errors
/// Fails closed if any batch fails to strictly advance `validity_epoch`, references an unknown
/// `doc_id`, or leaves an invalid corpus.
pub fn replay_validity_overlays(
    baseline: &Corpus,
    batches: &[ValidityOverlayBatch],
) -> Result<OverlayReplayReceipt, OverlayError> {
    validate_documents(baseline).map_err(|e| OverlayError::InvalidCorpus(format!("{e:?}")))?;

    let mut current_epoch = baseline.validity_epoch;
    let mut rights_grant = baseline.rights_grant_version.clone();
    let mut docs_by_id: BTreeMap<String, Document> = baseline
        .documents
        .iter()
        .map(|d| (d.doc_id.clone(), d.clone()))
        .collect();
    let mut deleted_ids: BTreeSet<String> = BTreeSet::new();

    for batch in batches {
        if batch.target_epoch <= current_epoch {
            return Err(OverlayError::NonMonotonicEpoch {
                current: current_epoch,
                target: batch.target_epoch,
            });
        }
        current_epoch = batch.target_epoch;
        if let Some(grant) = &batch.rights_grant_version {
            if grant.trim().is_empty() {
                return Err(OverlayError::InvalidCorpus(
                    "empty rights_grant_version in overlay".to_owned(),
                ));
            }
            rights_grant = grant.clone();
        }
        for op in &batch.operations {
            match op {
                ValidityDeltaOp::UpsertDocument { document } => {
                    deleted_ids.remove(&document.doc_id);
                    docs_by_id.insert(document.doc_id.clone(), document.clone());
                }
                ValidityDeltaOp::UpdatePublicationState {
                    doc_id, new_state, ..
                } => {
                    let doc = docs_by_id
                        .get_mut(doc_id)
                        .ok_or_else(|| OverlayError::UnknownDocument(doc_id.clone()))?;
                    doc.publication_state = *new_state;
                }
                ValidityDeltaOp::DeleteDocument { doc_id, .. } => {
                    if docs_by_id.remove(doc_id).is_none() {
                        return Err(OverlayError::UnknownDocument(doc_id.clone()));
                    }
                    deleted_ids.insert(doc_id.clone());
                }
                ValidityDeltaOp::UpdateRights { doc_id, rights, .. } => {
                    let doc = docs_by_id
                        .get_mut(doc_id)
                        .ok_or_else(|| OverlayError::UnknownDocument(doc_id.clone()))?;
                    doc.rights = *rights;
                }
            }
        }
    }

    let documents: Vec<Document> = docs_by_id.into_values().collect();
    let corpus = Corpus {
        description: baseline.description.clone(),
        validity_epoch: current_epoch,
        rights_grant_version: rights_grant,
        quality_appraised: baseline.quality_appraised,
        documents,
    };
    validate_documents(&corpus).map_err(|e| OverlayError::InvalidCorpus(format!("{e:?}")))?;

    let withdrawn_studies: BTreeSet<&str> = corpus
        .documents
        .iter()
        .filter(|d| {
            matches!(
                d.publication_state,
                PublicationState::Retracted | PublicationState::Withdrawn
            )
        })
        .map(|d| d.study_id.as_str())
        .collect();

    let mut active_index_doc_ids = Vec::new();
    let mut evicted_doc_ids: Vec<String> = deleted_ids.into_iter().collect();
    for doc in &corpus.documents {
        if withdrawn_studies.contains(doc.study_id.as_str()) || !doc.publication_state.citable() {
            evicted_doc_ids.push(doc.doc_id.clone());
        } else {
            active_index_doc_ids.push(doc.doc_id.clone());
        }
    }
    evicted_doc_ids.sort();
    evicted_doc_ids.dedup();

    let canonical_bytes =
        serde_json::to_vec(&corpus).map_err(|e| OverlayError::InvalidCorpus(e.to_string()))?;
    let canonical_digest = DigestSha256::of(&canonical_bytes);

    Ok(OverlayReplayReceipt {
        corpus,
        canonical_bytes,
        canonical_digest,
        active_index_doc_ids,
        evicted_doc_ids,
    })
}

/// Builds a deterministic local `EvidenceCorpusManifest` excluding every item with `Unknown` or
/// `Restricted` rights and excluding retracted/withdrawn documents (`TA-06`: *"rights-unknown item
/// never in a built pack"*).
///
/// # Errors
/// Fails closed if no admissible active documents remain.
pub fn build_rights_admissible_manifest(
    corpus_id: &str,
    version: &str,
    rights_uri: &str,
    corpus: &Corpus,
) -> Result<EvidenceCorpusManifest, OverlayError> {
    let mut pack_docs = Vec::new();
    for doc in &corpus.documents {
        if !doc.rights.admissible() {
            continue;
        }
        if matches!(
            doc.publication_state,
            PublicationState::Retracted | PublicationState::Withdrawn
        ) {
            continue;
        }
        if !doc.publication_state.citable() {
            continue;
        }
        pack_docs.push(EvidenceCorpusDocument {
            doc_id: doc.doc_id.clone(),
            text: doc.text.clone(),
            content_digest: DigestSha256::of(doc.text.as_bytes()),
            status: EvidenceDocStatus::Active,
            freshness_marker: Some(format!("epoch:{}", corpus.validity_epoch)),
            conflict_marker: None,
        });
    }
    if pack_docs.is_empty() {
        return Err(OverlayError::NoAdmissibleDocumentsForPack);
    }
    pack_docs.sort_by(|a, b| a.doc_id.cmp(&b.doc_id));
    let joined_digests: String = pack_docs
        .iter()
        .map(|d| format!("{}:{}", d.doc_id, d.content_digest.to_hex()))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(EvidenceCorpusManifest {
        corpus_id: corpus_id.to_owned(),
        version: version.to_owned(),
        content_digest: DigestSha256::of(joined_digests.as_bytes()),
        rights: EvidenceCorpusRights::SyntheticOwned,
        rights_uri: rights_uri.to_owned(),
        documents: pack_docs,
    })
}

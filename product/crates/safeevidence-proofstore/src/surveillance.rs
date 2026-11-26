//! Local living-evidence surveillance watch registry and cause-named alert engine (`WP-17`,
//! `TA-19`, and local-only `TA-30` opt-in guard).
//!
//! Copy-first boundary: external live fetch (`T05` broker + `T15` adapters) stays fenced on
//! `EXT-01`. This module operates over `ProofStore` and encrypted `safeevidence_vault::vault_blob`
//! storage (`SAFEVD/` XChaCha20-Poly1305 AEAD), ensuring:
//! 1. Injected retractions, source amendments, rights revocations, or new trials advance
//!    `ProofStore` `validity_epoch` and emit cause-named `SurveillanceAlert`s within one cycle.
//! 2. Already-committed historical proofs transition to `ProofState::CurrentlyInvalidated` while
//!    their historical `final_text` bytes and `AnswerProofManifest` remain byte-for-byte unchanged
//!    (`TA-19`).
//! 3. Saved queries default to `outbound_opt_in: false`, may never be marked eligible for outbound
//!    refresh without explicit per-query opt-in, and reject patient-specific narrative (`TA-30`).

use safeevidence_contracts::assurance::ProofState;
use safeevidence_contracts::bilingual::{NormalizedText, is_forbidden_bidi_control};
use safeevidence_contracts::objects::DigestSha256;
pub use safeevidence_contracts::surveillance::{
    AlertCauseCode, SavedWatchQuery, SurveillanceAlert, SurveillanceUpdateEvent, WatchRegistry,
};
use safeevidence_vault::vault_blob::{
    BOUNDED_BLOB_NONCE_BYTES, BoundedBlobContext, BoundedBlobError, decrypt_bounded_blob,
    encrypt_bounded_blob,
};
use safeevidence_vault::vault_keys::OwnedKeyMaterial;

use crate::{ProofStore, StoreError};

/// Fixed 16-byte canonical `id128` artifact identifier binding surveillance watch registries under
/// `SAFEVD/BLOB/AAD/v1`.
pub const WATCH_REGISTRY_ARTIFACT_ID: [u8; 16] = *b"SAFEVD-WATCH-V01";

#[derive(Debug)]
pub enum SurveillanceError {
    Store(StoreError),
    VaultBlob(BoundedBlobError),
    Serialization(String),
    PatientNarrativeForbidden(String),
    OutboundOptInRequired(String),
    DuplicateWatchId(String),
}

impl From<StoreError> for SurveillanceError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<BoundedBlobError> for SurveillanceError {
    fn from(value: BoundedBlobError) -> Self {
        Self::VaultBlob(value)
    }
}

fn contains_patient_narrative(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const FORBIDDEN_EN: &[&str] = &[
        "my patient",
        "this patient",
        "my child",
        "my mother",
        "my father",
        "mrn",
        "dob",
        "date of birth",
        "should i prescribe",
        "should i give",
        "year-old",
        "yo male",
        "yo female",
    ];
    const FORBIDDEN_AR: &[&str] = &[
        "\u{0645}\u{0631}\u{064a}\u{0636}\u{064a}",
        "\u{0647}\u{0630}\u{0627} \u{0627}\u{0644}\u{0645}\u{0631}\u{064a}\u{0636}",
        "\u{0637}\u{0641}\u{0644}\u{064a}",
        "\u{0648}\u{0627}\u{0644}\u{062f}\u{064a}",
        "\u{0648}\u{0627}\u{0644}\u{062f}\u{062a}\u{064a}",
        "\u{0647}\u{0644} \u{0627}\u{0635}\u{0641}",
        "\u{0647}\u{0644} \u{0627}\u{0639}\u{0637}\u{064a}",
    ];
    if FORBIDDEN_EN.iter().any(|needle| lower.contains(needle)) {
        return true;
    }
    let Ok(norm) = NormalizedText::build(text) else {
        return true;
    };
    let collapsed = norm
        .as_str()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    FORBIDDEN_AR.iter().any(|raw_ar| {
        NormalizedText::build(raw_ar).map_or(true, |nar| collapsed.contains(nar.as_str()))
    })
}

fn has_unsafe_query_chars(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() || c == '"' || is_forbidden_bidi_control(c))
}

fn validate_watch_safety(watch: &SavedWatchQuery) -> Result<(), SurveillanceError> {
    if watch.watch_id.trim().is_empty()
        || watch.canonical_pico_query.trim().is_empty()
        || watch.condition.trim().is_empty()
        || watch.intervention.trim().is_empty()
    {
        return Err(SurveillanceError::Serialization(
            "watch_id, canonical_pico_query, condition, and intervention must be non-empty"
                .to_owned(),
        ));
    }
    if has_unsafe_query_chars(&watch.watch_id)
        || has_unsafe_query_chars(&watch.canonical_pico_query)
        || has_unsafe_query_chars(&watch.condition)
        || has_unsafe_query_chars(&watch.intervention)
        || watch
            .population
            .as_deref()
            .is_some_and(has_unsafe_query_chars)
    {
        return Err(SurveillanceError::Serialization(
            "watch fields must not contain quotes, control characters, or BiDi overrides"
                .to_owned(),
        ));
    }
    if contains_patient_narrative(&watch.canonical_pico_query)
        || contains_patient_narrative(&watch.condition)
        || contains_patient_narrative(&watch.intervention)
        || watch
            .population
            .as_deref()
            .is_some_and(contains_patient_narrative)
    {
        return Err(SurveillanceError::PatientNarrativeForbidden(
            watch.watch_id.clone(),
        ));
    }
    Ok(())
}

/// Registers a `SavedWatchQuery` after verifying it carries no patient-specific free-text
/// narrative (`TA-30` / `P00 D7`).
pub fn register_watch(
    registry: &mut WatchRegistry,
    watch: SavedWatchQuery,
) -> Result<(), SurveillanceError> {
    validate_watch_safety(&watch)?;
    if registry
        .watches
        .iter()
        .any(|w| w.watch_id == watch.watch_id)
    {
        return Err(SurveillanceError::DuplicateWatchId(watch.watch_id));
    }
    registry.watches.push(watch);
    Ok(())
}

/// Produces a sanitized outbound query preview ONLY when `outbound_opt_in == true` and zero
/// patient narrative or unsafe characters exist across any field (`TA-30`). Never opens a socket;
/// returns data for user-visible preview only.
pub fn prepare_outbound_preview(
    registry: &WatchRegistry,
    watch_id: &str,
) -> Result<String, SurveillanceError> {
    let watch = registry
        .watches
        .iter()
        .find(|w| w.watch_id == watch_id)
        .ok_or_else(|| SurveillanceError::Serialization(format!("unknown watch_id {watch_id}")))?;
    if !watch.outbound_opt_in {
        return Err(SurveillanceError::OutboundOptInRequired(
            watch.watch_id.clone(),
        ));
    }
    validate_watch_safety(watch)?;
    Ok(format!(
        "condition=\"{}\" AND intervention=\"{}\"",
        watch.condition.trim(),
        watch.intervention.trim()
    ))
}

/// Encrypts `registry` into a `SAFEVD/` bounded XChaCha20-Poly1305 AEAD blob (`safeevidence-vault`).
pub fn seal_watch_registry_blob(
    registry: &WatchRegistry,
    vrk: &OwnedKeyMaterial,
    blob_context: BoundedBlobContext,
    nonce: [u8; BOUNDED_BLOB_NONCE_BYTES],
) -> Result<Vec<u8>, SurveillanceError> {
    let plaintext = serde_json::to_vec(registry)
        .map_err(|e| SurveillanceError::Serialization(e.to_string()))?;
    Ok(encrypt_bounded_blob(vrk, blob_context, nonce, &plaintext)?)
}

/// Decrypts and authenticates a `WatchRegistry` from a `SAFEVD/` bounded AEAD blob.
pub fn open_watch_registry_blob(
    vrk: &OwnedKeyMaterial,
    expected_context: BoundedBlobContext,
    sealed: &[u8],
) -> Result<WatchRegistry, SurveillanceError> {
    let plaintext = decrypt_bounded_blob(vrk, expected_context, sealed)?;
    serde_json::from_slice(&plaintext).map_err(|e| SurveillanceError::Serialization(e.to_string()))
}

/// Applies one living-surveillance update cycle to `store` and `registry`, advancing
/// `validity_epoch` to `new_epoch` and returning the newly emitted cause-named
/// `SurveillanceAlert`s (`TA-19`).
pub fn apply_surveillance_cycle(
    store: &mut ProofStore,
    registry: &mut WatchRegistry,
    new_epoch: u64,
    events: &[SurveillanceUpdateEvent],
) -> Result<Vec<SurveillanceAlert>, SurveillanceError> {
    store.advance_epoch(new_epoch)?;
    let mut emitted = Vec::new();

    for event in events {
        match event {
            SurveillanceUpdateEvent::RetractSource {
                source_id,
                rationale,
                authorized_by,
                recorded_time,
            } => {
                store.retract_source(source_id, rationale, authorized_by, recorded_time)?;
                for watch in &registry.watches {
                    if watch.cited_source_ids.iter().any(|s| s == source_id) {
                        let proof_state = match &watch.linked_proof_id {
                            Some(pid) => Some(store.read(pid)?.state),
                            None => None,
                        };
                        let alert = make_alert(
                            &watch.watch_id,
                            new_epoch,
                            AlertCauseCode::SourceRetracted,
                            source_id,
                            format!("Cited source {source_id} retracted: {rationale}"),
                            watch.linked_proof_id.clone(),
                            proof_state,
                        );
                        emitted.push(alert);
                    }
                }
            }
            SurveillanceUpdateEvent::AmendSource {
                prior_source_id,
                superseding_source_id,
                superseding_bytes,
                amendment,
            } => {
                store.put_source(superseding_source_id, superseding_bytes)?;
                store.amend(amendment)?;
                for watch in &registry.watches {
                    if watch.cited_source_ids.iter().any(|s| s == prior_source_id) {
                        let proof_state = match &watch.linked_proof_id {
                            Some(pid) => Some(store.read(pid)?.state),
                            None => None,
                        };
                        let alert = make_alert(
                            &watch.watch_id,
                            new_epoch,
                            AlertCauseCode::SourceAmended,
                            prior_source_id,
                            format!(
                                "Cited source {prior_source_id} superseded by {superseding_source_id}: {}",
                                amendment.rationale
                            ),
                            watch.linked_proof_id.clone(),
                            proof_state,
                        );
                        emitted.push(alert);
                    }
                }
            }
            SurveillanceUpdateEvent::RotateRightsGrant {
                new_grant_version,
                reason,
            } => {
                store.set_rights_grant(new_grant_version)?;
                for watch in &registry.watches {
                    let proof_state = match &watch.linked_proof_id {
                        Some(pid) => Some(store.read(pid)?.state),
                        None => None,
                    };
                    let alert = make_alert(
                        &watch.watch_id,
                        new_epoch,
                        AlertCauseCode::RightsGrantChanged,
                        new_grant_version,
                        format!("Active rights grant rotated to {new_grant_version}: {reason}"),
                        watch.linked_proof_id.clone(),
                        proof_state,
                    );
                    emitted.push(alert);
                }
            }
            SurveillanceUpdateEvent::NewTrialPublished {
                doc_id,
                study_id,
                condition,
                intervention,
                contradicts_existing,
                summary,
            } => {
                store.put_source(doc_id, summary.as_bytes())?;
                for watch in &registry.watches {
                    if watch.condition.eq_ignore_ascii_case(condition)
                        && watch.intervention.eq_ignore_ascii_case(intervention)
                    {
                        let proof_state = match &watch.linked_proof_id {
                            Some(pid) => Some(store.read(pid)?.state),
                            None => None,
                        };
                        let cause_code = if *contradicts_existing {
                            AlertCauseCode::NewContradictingTrial
                        } else {
                            AlertCauseCode::NewSupportingTrial
                        };
                        let alert = make_alert(
                            &watch.watch_id,
                            new_epoch,
                            cause_code,
                            doc_id,
                            format!("New trial {study_id} ({doc_id}): {summary}"),
                            watch.linked_proof_id.clone(),
                            proof_state,
                        );
                        emitted.push(alert);
                    }
                }
            }
        }
    }

    registry.alerts.extend(emitted.clone());
    Ok(emitted)
}

fn make_alert(
    watch_id: &str,
    epoch: u64,
    cause_code: AlertCauseCode,
    subject_id: &str,
    explanation: String,
    affected_proof_id: Option<String>,
    affected_proof_state: Option<ProofState>,
) -> SurveillanceAlert {
    let seed = format!("{watch_id}:{epoch}:{cause_code:?}:{subject_id}");
    let alert_id = format!(
        "alert-{}",
        &DigestSha256::of(seed.as_bytes()).to_hex()[..16]
    );
    SurveillanceAlert {
        alert_id,
        watch_id: watch_id.to_owned(),
        epoch,
        cause_code,
        subject_id: subject_id.to_owned(),
        explanation,
        affected_proof_id,
        affected_proof_state,
    }
}

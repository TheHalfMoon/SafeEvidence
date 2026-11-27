//! Pack format gates and local-path content-addressed admission (`ADM-0016` / `T07`, `TA-06`,
//! `TA-28`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-pack/src/format.rs`)
//! under Apache-2.0 (`ADR-0004`).

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use safeevidence_contracts::objects::{DigestSha256, OpaqueId};
use safeevidence_contracts::packs::{
    PackAdmitReason, PackArtifactEntry, PackArtifactKind, PackManifestV0, PackPromotionState,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::trust::{
    PackTrustError, SYNTHETIC_PACK_TRUST_ROOT_ID, pack_signing_payload, verify_pack_signature,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmitError {
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("missing rights_uri")]
    MissingRights,
    #[error("forbidden artifact kind")]
    ForbiddenKind,
    #[error("digest mismatch")]
    DigestMismatch,
    #[error("missing signature")]
    MissingSignature,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unknown trust root")]
    UnknownTrustRoot,
    #[error("anti-rollback")]
    AntiRollback,
    #[error("io: {0}")]
    Io(String),
}

impl AdmitError {
    #[must_use]
    pub fn reason(&self) -> PackAdmitReason {
        match self {
            Self::MissingRights => PackAdmitReason::MissingRights,
            Self::ForbiddenKind => PackAdmitReason::ForbiddenArtifactKind,
            Self::DigestMismatch => PackAdmitReason::DigestMismatch,
            Self::MissingSignature => PackAdmitReason::MissingSignature,
            Self::InvalidSignature => PackAdmitReason::InvalidSignature,
            Self::UnknownTrustRoot => PackAdmitReason::UnknownTrustRoot,
            Self::AntiRollback => PackAdmitReason::AntiRollback,
            Self::InvalidManifest(_) | Self::Io(_) => PackAdmitReason::InvalidManifest,
        }
    }
}

#[must_use]
pub fn forbidden_reason(kind: PackArtifactKind) -> Option<PackAdmitReason> {
    kind.is_forbidden_by_default()
        .then_some(PackAdmitReason::ForbiddenArtifactKind)
}

const MAX_MANIFEST_BYTES: u64 = 1_048_576;

pub(crate) const fn artifact_size_limit(kind: PackArtifactKind) -> u64 {
    match kind {
        PackArtifactKind::OnnxModel | PackArtifactKind::SafetensorsModel => 1_073_741_824,
        PackArtifactKind::TokenizerMeta
        | PackArtifactKind::FixtureBytes
        | PackArtifactKind::CorpusJsonl
        | PackArtifactKind::GuidelineMetadata => 67_108_864,
        PackArtifactKind::ModelMetadata => 1_048_576,
        PackArtifactKind::Pickle | PackArtifactKind::CodeBin | PackArtifactKind::OnnxCustomOp => 0,
    }
}

fn read_bounded_artifact(path: &Path, kind: PackArtifactKind) -> Result<Vec<u8>, AdmitError> {
    let limit = artifact_size_limit(kind);
    let metadata = fs::symlink_metadata(path).map_err(|err| AdmitError::Io(err.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(AdmitError::InvalidManifest(
            "artifact is symlink, non-regular file, or exceeds admitted byte bound".into(),
        ));
    }
    let file = fs::File::open(path).map_err(|err| AdmitError::Io(err.to_string()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| AdmitError::Io(err.to_string()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(AdmitError::InvalidManifest(
            "artifact exceeds admitted byte bound".into(),
        ));
    }
    Ok(bytes)
}

fn is_canonical_lower_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn parse_hex_digest(hex: &str) -> Result<DigestSha256, AdmitError> {
    if !is_canonical_lower_hex(hex, 64) {
        return Err(AdmitError::InvalidManifest(
            "digest must be 64 canonical lowercase hex chars".into(),
        ));
    }
    let raw = hex::decode(hex).map_err(|_| AdmitError::InvalidManifest("digest hex".into()))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| AdmitError::InvalidManifest("digest len".into()))?;
    Ok(DigestSha256::from_bytes(bytes))
}

fn is_windows_reserved_stem(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub(crate) fn validate_relative_artifact_path(relative: &str) -> Result<(), AdmitError> {
    let rel = Path::new(relative);
    if relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || relative.chars().any(char::is_control)
        || rel.is_absolute()
        || rel
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AdmitError::InvalidManifest(
            "artifact path escapes pack root or uses forbidden characters".into(),
        ));
    }
    for seg in relative.split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.starts_with(' ')
            || seg.ends_with(' ')
            || seg.ends_with('.')
            || is_windows_reserved_stem(seg)
        {
            return Err(AdmitError::InvalidManifest(
                "artifact path contains empty, reserved, or non-canonical segment".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_no_duplicate_or_prefix_paths<'a>(
    paths: impl Iterator<Item = &'a str>,
) -> Result<(), AdmitError> {
    let mut lowered: Vec<String> = paths.map(str::to_ascii_lowercase).collect();
    lowered.sort();
    for pair in lowered.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        if a == b
            || (b.len() > a.len() && b.starts_with(a.as_str()) && b.as_bytes()[a.len()] == b'/')
        {
            return Err(AdmitError::InvalidManifest(
                "duplicate or file-vs-directory colliding artifact relative_path".into(),
            ));
        }
    }
    Ok(())
}

fn safe_artifact_path(root: &Path, relative: &str) -> Result<PathBuf, AdmitError> {
    validate_relative_artifact_path(relative)?;
    let rel = Path::new(relative);
    let canonical_root = root
        .canonicalize()
        .map_err(|err| AdmitError::Io(err.to_string()))?;
    let mut probe = root.to_path_buf();
    for component in rel.components() {
        probe.push(component);
        let meta = fs::symlink_metadata(&probe).map_err(|err| AdmitError::Io(err.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(AdmitError::InvalidManifest(
                "artifact path traverses a symlink".into(),
            ));
        }
    }
    let canonical_candidate = probe
        .canonicalize()
        .map_err(|err| AdmitError::Io(err.to_string()))?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(AdmitError::InvalidManifest(
            "artifact path escapes pack root".into(),
        ));
    }
    Ok(canonical_candidate)
}

fn normalize_lf(bytes: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                out.push(b'\n');
                i += 2;
                continue;
            }
            out.push(b'\n');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePackArtifact {
    pub relative_path: String,
    pub kind: PackArtifactKind,
    pub digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePackManifest {
    pub pack_id: String,
    pub version: String,
    pub pack_epoch: u64,
    pub content_digest: String,
    pub artifacts: Vec<WirePackArtifact>,
    pub rights_uri: String,
    pub sbom_ref: String,
    pub runtime_requirements: String,
    #[serde(default)]
    pub benchmark_links: Vec<String>,
    pub promotion_state: PackPromotionState,
    pub trust_root_id: String,
    pub signature_hex: String,
}

fn artifact_kind_tag(kind: PackArtifactKind) -> &'static str {
    match kind {
        PackArtifactKind::OnnxModel => "onnx_model",
        PackArtifactKind::SafetensorsModel => "safetensors_model",
        PackArtifactKind::TokenizerMeta => "tokenizer_meta",
        PackArtifactKind::FixtureBytes => "fixture_bytes",
        PackArtifactKind::CorpusJsonl => "corpus_jsonl",
        PackArtifactKind::GuidelineMetadata => "guideline_metadata",
        PackArtifactKind::ModelMetadata => "model_metadata",
        PackArtifactKind::Pickle => "pickle",
        PackArtifactKind::CodeBin => "code_bin",
        PackArtifactKind::OnnxCustomOp => "onnx_custom_op",
    }
}

/// Computes the canonical length-prefixed `content_digest` over sorted
/// `(relative_path, kind, digest)` entries (`TA-06` / `TA-28`).
#[must_use]
pub fn compute_content_digest(artifacts: &[PackArtifactEntry]) -> DigestSha256 {
    let mut sorted = artifacts.to_vec();
    sorted.sort_by(|a, b| {
        a.relative_path
            .cmp(&b.relative_path)
            .then_with(|| artifact_kind_tag(a.kind).cmp(artifact_kind_tag(b.kind)))
            .then_with(|| a.digest.as_bytes().cmp(b.digest.as_bytes()))
    });
    let mut buf = Vec::new();
    buf.extend_from_slice(b"SAFEVD/PACK/CONTENT/v0");
    buf.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
    for a in &sorted {
        buf.extend_from_slice(&(a.relative_path.len() as u64).to_be_bytes());
        buf.extend_from_slice(a.relative_path.as_bytes());
        let ktag = artifact_kind_tag(a.kind);
        buf.extend_from_slice(&(ktag.len() as u64).to_be_bytes());
        buf.extend_from_slice(ktag.as_bytes());
        buf.extend_from_slice(a.digest.as_bytes());
    }
    DigestSha256::of(&buf)
}

/// Loads and validates a pack directory containing `pack.manifest.json` + content-addressed artifacts.
pub fn admit_pack_dir(path: &Path) -> Result<PackManifestV0, AdmitError> {
    let manifest_path = safe_artifact_path(path, "pack.manifest.json")?;
    let metadata =
        fs::symlink_metadata(&manifest_path).map_err(|err| AdmitError::Io(err.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(AdmitError::InvalidManifest(
            "pack manifest exceeds admitted byte bound".into(),
        ));
    }
    let file = fs::File::open(&manifest_path).map_err(|err| AdmitError::Io(err.to_string()))?;
    let mut raw = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|err| AdmitError::Io(err.to_string()))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(AdmitError::InvalidManifest(
            "pack manifest exceeds admitted byte bound".into(),
        ));
    }
    let wire: WirePackManifest =
        serde_json::from_slice(&raw).map_err(|err| AdmitError::InvalidManifest(err.to_string()))?;

    if wire.pack_id.is_empty() || wire.pack_id.trim() != wire.pack_id {
        return Err(AdmitError::InvalidManifest(
            "empty or untrimmed pack_id".into(),
        ));
    }
    if wire.version.trim() != wire.version || semver::Version::parse(&wire.version).is_err() {
        return Err(AdmitError::InvalidManifest(
            "pack version must be canonical untrimmed SemVer".into(),
        ));
    }
    if wire.rights_uri.is_empty() {
        return Err(AdmitError::MissingRights);
    }
    if wire.rights_uri.trim() != wire.rights_uri {
        return Err(AdmitError::InvalidManifest("untrimmed rights_uri".into()));
    }
    if wire.sbom_ref.is_empty() || wire.sbom_ref.trim() != wire.sbom_ref {
        return Err(AdmitError::InvalidManifest(
            "empty or untrimmed sbom_ref".into(),
        ));
    }
    if wire.signature_hex.is_empty() {
        return Err(AdmitError::MissingSignature);
    }
    if wire.signature_hex.trim() != wire.signature_hex {
        return Err(AdmitError::InvalidSignature);
    }
    if wire.trust_root_id.is_empty() || wire.trust_root_id.trim() != wire.trust_root_id {
        return Err(AdmitError::UnknownTrustRoot);
    }
    if wire.artifacts.is_empty() {
        return Err(AdmitError::InvalidManifest(
            "pack must declare at least one artifact".into(),
        ));
    }

    for art in &wire.artifacts {
        validate_relative_artifact_path(&art.relative_path)?;
    }
    validate_no_duplicate_or_prefix_paths(wire.artifacts.iter().map(|a| a.relative_path.as_str()))?;

    let mut artifacts = Vec::new();
    for art in &wire.artifacts {
        if forbidden_reason(art.kind).is_some() {
            return Err(AdmitError::ForbiddenKind);
        }
        let file = safe_artifact_path(path, &art.relative_path)?;
        let mut bytes = read_bounded_artifact(&file, art.kind)?;
        if matches!(
            art.kind,
            PackArtifactKind::FixtureBytes
                | PackArtifactKind::CorpusJsonl
                | PackArtifactKind::GuidelineMetadata
                | PackArtifactKind::TokenizerMeta
                | PackArtifactKind::ModelMetadata
        ) {
            bytes = normalize_lf(bytes);
        }
        let dig = DigestSha256::of(&bytes);
        let expected = parse_hex_digest(&art.digest)?;
        if dig != expected {
            return Err(AdmitError::DigestMismatch);
        }
        artifacts.push(PackArtifactEntry {
            relative_path: art.relative_path.clone(),
            kind: art.kind,
            digest: dig,
        });
    }

    let expected_content = compute_content_digest(&artifacts);
    let declared = parse_hex_digest(&wire.content_digest)?;
    if expected_content != declared {
        return Err(AdmitError::DigestMismatch);
    }

    let payload = pack_signing_payload(
        &wire.pack_id,
        &wire.version,
        wire.pack_epoch,
        &wire.content_digest,
        &wire.rights_uri,
        &wire.sbom_ref,
        &wire.runtime_requirements,
        &wire.benchmark_links,
    );
    match verify_pack_signature(&wire.trust_root_id, &payload, &wire.signature_hex) {
        Ok(()) => {}
        Err(PackTrustError::UnknownTrustRoot) => return Err(AdmitError::UnknownTrustRoot),
        Err(PackTrustError::InvalidEncoding | PackTrustError::VerifyFailed) => {
            return Err(AdmitError::InvalidSignature);
        }
    }
    if wire.trust_root_id != SYNTHETIC_PACK_TRUST_ROOT_ID {
        return Err(AdmitError::UnknownTrustRoot);
    }

    let mut promotion_state = wire.promotion_state;
    if !matches!(
        promotion_state,
        PackPromotionState::Candidate | PackPromotionState::LastGreen
    ) {
        promotion_state = PackPromotionState::Candidate;
    }

    Ok(PackManifestV0 {
        pack_id: OpaqueId::new(wire.pack_id),
        version: wire.version,
        pack_epoch: wire.pack_epoch,
        content_digest: declared,
        artifacts,
        rights_uri: wire.rights_uri,
        sbom_ref: wire.sbom_ref,
        runtime_requirements: wire.runtime_requirements,
        benchmark_links: wire.benchmark_links,
        promotion_state,
        trust_root_id: wire.trust_root_id,
        signature_hex: wire.signature_hex,
    })
}

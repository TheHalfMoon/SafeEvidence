//! Deterministic unsigned offline staging manifest and verifier (`WP-24` / `TA-28` preparation).
//!
//! Binds compiled staging artifacts, CycloneDX 1.5 SBOM (`verify_release_sbom`),
//! `THIRD_PARTY_NOTICES.md`, and `tauri.conf.json` (`bundle.active == false`, no updater/signing)
//! into a reproducible unsigned staging manifest while preserving `signed = false`,
//! `installer_bundle_active = false`, `release_qualified = false`, and `blocking_gate = "EXT-05"`.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{ExpectedBinding, sha256_hex, verify_release_sbom};

/// Schema identifier for unsigned offline staging manifests.
pub const STAGING_SCHEMA_VERSION: &str = "safeevidence.release.unsigned_staging.v1";

/// External gate blocking signed installers, auto-updaters, and public release qualification.
pub const BLOCKING_SIGNING_GATE: &str = "EXT-05";

/// One staged binary or support file bound by relative staging path, byte length, and SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedArtifactEntry {
    pub name: String,
    pub relative_path: String,
    pub byte_len: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingManifestBody {
    schema_version: String,
    source_sha: String,
    tree_sha: String,
    signed: bool,
    installer_bundle_active: bool,
    release_qualified: bool,
    blocking_gate: String,
    sbom_sha256: String,
    third_party_notices_sha256: String,
    tauri_conf_sha256: String,
    artifacts: Vec<StagedArtifactEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnsignedStagingManifest {
    schema_version: String,
    source_sha: String,
    tree_sha: String,
    signed: bool,
    installer_bundle_active: bool,
    release_qualified: bool,
    blocking_gate: String,
    sbom_sha256: String,
    third_party_notices_sha256: String,
    tauri_conf_sha256: String,
    artifacts: Vec<StagedArtifactEntry>,
    manifest_sha256: String,
}

/// Canonical unsigned offline staging manifest (`signed == false`, `release_qualified == false`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawUnsignedStagingManifest")]
pub struct UnsignedStagingManifest {
    schema_version: String,
    source_sha: String,
    tree_sha: String,
    signed: bool,
    installer_bundle_active: bool,
    release_qualified: bool,
    blocking_gate: String,
    sbom_sha256: String,
    third_party_notices_sha256: String,
    tauri_conf_sha256: String,
    artifacts: Vec<StagedArtifactEntry>,
    manifest_sha256: String,
}

impl UnsignedStagingManifest {
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub const fn signed(&self) -> bool {
        self.signed
    }

    #[must_use]
    pub const fn installer_bundle_active(&self) -> bool {
        self.installer_bundle_active
    }

    #[must_use]
    pub const fn release_qualified(&self) -> bool {
        self.release_qualified
    }

    #[must_use]
    pub fn blocking_gate(&self) -> &str {
        &self.blocking_gate
    }

    #[must_use]
    pub fn artifacts(&self) -> &[StagedArtifactEntry] {
        &self.artifacts
    }

    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Renders canonical LF-terminated JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, String> {
        let mut out = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        out.push('\n');
        Ok(out)
    }
}

fn is_lower_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_safe_relative_path(rel: &str) -> bool {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.contains('\\')
        || rel.contains(':')
        || rel.contains('\0')
    {
        return false;
    }
    rel.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn validate_artifacts(artifacts: &[StagedArtifactEntry]) -> Result<(), String> {
    if artifacts.is_empty() {
        return Err("staging manifest must list at least one artifact".to_owned());
    }
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut prev_name: Option<&str> = None;
    for entry in artifacts {
        if entry.name.trim().is_empty() {
            return Err("artifact name must not be empty".to_owned());
        }
        if let Some(prev) = prev_name
            && prev >= entry.name.as_str()
        {
            return Err("artifacts must be strictly sorted by name".to_owned());
        }
        prev_name = Some(&entry.name);
        if !names.insert(entry.name.as_str()) {
            return Err(format!("duplicate artifact name '{}'", entry.name));
        }
        if !is_safe_relative_path(&entry.relative_path) {
            return Err(format!(
                "unsafe artifact relative_path '{}'",
                entry.relative_path
            ));
        }
        if !paths.insert(entry.relative_path.as_str()) {
            return Err(format!(
                "duplicate artifact relative_path '{}'",
                entry.relative_path
            ));
        }
        if entry.byte_len == 0 {
            return Err(format!("artifact '{}' has zero byte_len", entry.name));
        }
        if !is_lower_hex(&entry.sha256, 64) {
            return Err(format!(
                "artifact '{}' has invalid sha256 digest",
                entry.name
            ));
        }
    }
    Ok(())
}

fn compute_body_sha256(body: &StagingManifestBody) -> Result<String, String> {
    let canonical = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    Ok(sha256_hex(&canonical))
}

impl TryFrom<RawUnsignedStagingManifest> for UnsignedStagingManifest {
    type Error = String;

    fn try_from(raw: RawUnsignedStagingManifest) -> Result<Self, Self::Error> {
        if raw.schema_version != STAGING_SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version '{}'",
                raw.schema_version
            ));
        }
        if raw.signed || raw.installer_bundle_active || raw.release_qualified {
            return Err(
                "unsigned staging manifest must never claim signed, active bundle, or release_qualified"
                    .to_owned(),
            );
        }
        if raw.blocking_gate != BLOCKING_SIGNING_GATE {
            return Err(format!(
                "blocking_gate must be '{BLOCKING_SIGNING_GATE}', got '{}'",
                raw.blocking_gate
            ));
        }
        if !is_lower_hex(&raw.source_sha, 40) || !is_lower_hex(&raw.tree_sha, 40) {
            return Err("source_sha and tree_sha must be 40-char lowercase hex".to_owned());
        }
        if !is_lower_hex(&raw.sbom_sha256, 64)
            || !is_lower_hex(&raw.third_party_notices_sha256, 64)
            || !is_lower_hex(&raw.tauri_conf_sha256, 64)
        {
            return Err("metadata sha256 fields must be 64-char lowercase hex".to_owned());
        }
        validate_artifacts(&raw.artifacts)?;

        let body = StagingManifestBody {
            schema_version: raw.schema_version,
            source_sha: raw.source_sha,
            tree_sha: raw.tree_sha,
            signed: false,
            installer_bundle_active: false,
            release_qualified: false,
            blocking_gate: raw.blocking_gate,
            sbom_sha256: raw.sbom_sha256,
            third_party_notices_sha256: raw.third_party_notices_sha256,
            tauri_conf_sha256: raw.tauri_conf_sha256,
            artifacts: raw.artifacts,
        };
        let expected_digest = compute_body_sha256(&body)?;
        if raw.manifest_sha256 != expected_digest {
            return Err("manifest_sha256 does not match canonical body digest".to_owned());
        }

        Ok(Self {
            schema_version: body.schema_version,
            source_sha: body.source_sha,
            tree_sha: body.tree_sha,
            signed: false,
            installer_bundle_active: false,
            release_qualified: false,
            blocking_gate: body.blocking_gate,
            sbom_sha256: body.sbom_sha256,
            third_party_notices_sha256: body.third_party_notices_sha256,
            tauri_conf_sha256: body.tauri_conf_sha256,
            artifacts: body.artifacts,
            manifest_sha256: expected_digest,
        })
    }
}

fn validate_tauri_conf_unsigned(tauri_conf_bytes: &[u8]) -> Result<(), String> {
    let conf: serde_json::Value =
        serde_json::from_slice(tauri_conf_bytes).map_err(|e| format!("tauri.conf.json: {e}"))?;
    if conf.get("productName").and_then(serde_json::Value::as_str) != Some("SafeEvidence") {
        return Err("tauri.conf.json productName must be 'SafeEvidence'".to_owned());
    }
    let bundle = conf
        .get("bundle")
        .ok_or_else(|| "tauri.conf.json missing bundle section".to_owned())?;
    if bundle.get("active").and_then(serde_json::Value::as_bool) != Some(false) {
        return Err("tauri.conf.json bundle.active must remain false under EXT-05".to_owned());
    }
    if bundle
        .get("createUpdaterArtifacts")
        .is_some_and(|v| !v.is_null() && v.as_bool() != Some(false))
    {
        return Err("tauri.conf.json must not enable updater artifacts under EXT-05".to_owned());
    }
    if bundle
        .get("windows")
        .and_then(|w| {
            w.get("certificateThumbprint")
                .or_else(|| w.get("signCommand"))
        })
        .is_some_and(|v| !v.is_null())
    {
        return Err("tauri.conf.json must not configure Windows signing under EXT-05".to_owned());
    }
    if bundle
        .get("macOS")
        .and_then(|m| m.get("signingIdentity"))
        .is_some_and(|v| !v.is_null())
    {
        return Err("tauri.conf.json must not configure macOS signing under EXT-05".to_owned());
    }
    if conf.get("plugins").and_then(|p| p.get("updater")).is_some() {
        return Err("tauri.conf.json must not configure updater plugin under EXT-05".to_owned());
    }
    Ok(())
}

fn validate_notices(notices_bytes: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(notices_bytes).map_err(|_| "THIRD_PARTY_NOTICES.md not UTF-8")?;
    if !text.contains("# SafeEvidence Third-Party Notices")
        || !text.contains("## Admitted copied components")
    {
        return Err("THIRD_PARTY_NOTICES.md missing required attribution sections".to_owned());
    }
    Ok(())
}

fn read_staged_regular_file(staging_root: &Path, relative_path: &str) -> Result<Vec<u8>, String> {
    if !is_safe_relative_path(relative_path) {
        return Err(format!("unsafe artifact relative_path '{relative_path}'"));
    }
    let root_meta = std::fs::symlink_metadata(staging_root)
        .map_err(|e| format!("{}: {e}", staging_root.display()))?;
    if root_meta.file_type().is_symlink() || !root_meta.file_type().is_dir() {
        return Err(format!(
            "staging_root {} is not a non-symlink directory",
            staging_root.display()
        ));
    }

    let segments: Vec<&str> = relative_path.split('/').collect();
    let mut cursor = staging_root.to_path_buf();
    for (idx, seg) in segments.iter().enumerate() {
        cursor.push(seg);
        let meta =
            std::fs::symlink_metadata(&cursor).map_err(|e| format!("{}: {e}", cursor.display()))?;
        let is_last = idx + 1 == segments.len();
        if meta.file_type().is_symlink() {
            return Err(format!("{} must not be a symlink", cursor.display()));
        }
        if is_last {
            if !meta.file_type().is_file() {
                return Err(format!("{} is not a regular file", cursor.display()));
            }
        } else if !meta.file_type().is_dir() {
            return Err(format!(
                "{} is not an intermediate directory",
                cursor.display()
            ));
        }
    }
    std::fs::read(&cursor).map_err(|e| format!("{}: {e}", cursor.display()))
}

fn extract_sbom_artifacts(sbom_json: &str) -> Result<BTreeSet<(String, String)>, String> {
    let sbom_val: serde_json::Value =
        serde_json::from_str(sbom_json).map_err(|e| format!("SBOM JSON: {e}"))?;
    let mut out = BTreeSet::new();
    for c in sbom_val["components"].as_array().into_iter().flatten() {
        if c.get("type").and_then(serde_json::Value::as_str) != Some("file") {
            continue;
        }
        let Some(name) = c.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let expected_ref = format!("pkg:safeevidence/artifact/{name}");
        if c.get("bom-ref").and_then(serde_json::Value::as_str) != Some(expected_ref.as_str()) {
            continue;
        }
        let Some(hash) = c
            .get("hashes")
            .and_then(serde_json::Value::as_array)
            .and_then(|arr| {
                arr.iter()
                    .find(|h| h.get("alg").and_then(serde_json::Value::as_str) == Some("SHA-256"))
            })
            .and_then(|h| h.get("content"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        out.insert((name.to_owned(), hash.to_owned()));
    }
    Ok(out)
}

/// Builds a canonical [`UnsignedStagingManifest`] after validating `tauri.conf.json`,
/// `THIRD_PARTY_NOTICES.md`, SBOM bindings, and staged files on disk.
///
/// # Errors
/// Fails closed if any input violates `EXT-05` unsigned invariants, path hygiene, or SBOM checks.
pub fn build_unsigned_staging_manifest(
    staging_root: &Path,
    mut artifacts: Vec<StagedArtifactEntry>,
    sbom_json: &str,
    expected_binding: &ExpectedBinding,
    third_party_notices_bytes: &[u8],
    tauri_conf_bytes: &[u8],
) -> Result<UnsignedStagingManifest, String> {
    let sbom_report = verify_release_sbom(sbom_json, expected_binding);
    if !sbom_report.ok {
        return Err(format!(
            "SBOM verification failed: {}",
            sbom_report.failures.join("; ")
        ));
    }
    validate_notices(third_party_notices_bytes)?;
    validate_tauri_conf_unsigned(tauri_conf_bytes)?;

    artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    validate_artifacts(&artifacts)?;

    let sbom_artifacts = extract_sbom_artifacts(sbom_json)?;

    for entry in &artifacts {
        let bytes = read_staged_regular_file(staging_root, &entry.relative_path)?;
        if bytes.len() as u64 != entry.byte_len {
            return Err(format!("artifact '{}' byte length mismatch", entry.name));
        }
        if sha256_hex(&bytes) != entry.sha256 {
            return Err(format!("artifact '{}' sha256 mismatch", entry.name));
        }
        if !sbom_artifacts.contains(&(entry.name.clone(), entry.sha256.clone())) {
            return Err(format!(
                "artifact '{}' ({}) missing from CycloneDX SBOM artifact inventory",
                entry.name, entry.sha256
            ));
        }
    }

    let body = StagingManifestBody {
        schema_version: STAGING_SCHEMA_VERSION.to_owned(),
        source_sha: expected_binding.source_sha.clone(),
        tree_sha: expected_binding.tree_sha.clone(),
        signed: false,
        installer_bundle_active: false,
        release_qualified: false,
        blocking_gate: BLOCKING_SIGNING_GATE.to_owned(),
        sbom_sha256: sha256_hex(sbom_json.as_bytes()),
        third_party_notices_sha256: sha256_hex(third_party_notices_bytes),
        tauri_conf_sha256: sha256_hex(tauri_conf_bytes),
        artifacts,
    };
    let manifest_sha256 = compute_body_sha256(&body)?;

    Ok(UnsignedStagingManifest {
        schema_version: body.schema_version,
        source_sha: body.source_sha,
        tree_sha: body.tree_sha,
        signed: false,
        installer_bundle_active: false,
        release_qualified: false,
        blocking_gate: body.blocking_gate,
        sbom_sha256: body.sbom_sha256,
        third_party_notices_sha256: body.third_party_notices_sha256,
        tauri_conf_sha256: body.tauri_conf_sha256,
        artifacts: body.artifacts,
        manifest_sha256,
    })
}

/// Outcome of verifying an unsigned offline staging directory against its manifest and SBOM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingVerificationReport {
    pub ok: bool,
    pub failures: Vec<String>,
    pub verified_artifact_count: usize,
}

/// Verifies a serialized `manifest_json` against `staging_root`, `sbom_json`, `expected_binding`,
/// `third_party_notices_bytes`, and `tauri_conf_bytes`.
#[must_use]
pub fn verify_unsigned_staging_bundle(
    staging_root: &Path,
    manifest_json: &str,
    sbom_json: &str,
    expected_binding: &ExpectedBinding,
    third_party_notices_bytes: &[u8],
    tauri_conf_bytes: &[u8],
) -> StagingVerificationReport {
    let mut failures = Vec::new();
    let parsed: UnsignedStagingManifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => {
            return StagingVerificationReport {
                ok: false,
                failures: vec![format!("manifest parse/invariant error: {e}")],
                verified_artifact_count: 0,
            };
        }
    };

    let sbom_report = verify_release_sbom(sbom_json, expected_binding);
    if !sbom_report.ok {
        failures.extend(
            sbom_report
                .failures
                .into_iter()
                .map(|f| format!("sbom: {f}")),
        );
    }
    if parsed.source_sha != expected_binding.source_sha {
        failures.push("source_sha mismatch against expected_binding".to_owned());
    }
    if parsed.tree_sha != expected_binding.tree_sha {
        failures.push("tree_sha mismatch against expected_binding".to_owned());
    }
    if parsed.sbom_sha256 != sha256_hex(sbom_json.as_bytes()) {
        failures.push("sbom_sha256 mismatch".to_owned());
    }
    if let Err(e) = validate_notices(third_party_notices_bytes) {
        failures.push(e);
    }
    if parsed.third_party_notices_sha256 != sha256_hex(third_party_notices_bytes) {
        failures.push("third_party_notices_sha256 mismatch".to_owned());
    }
    if let Err(e) = validate_tauri_conf_unsigned(tauri_conf_bytes) {
        failures.push(e);
    }
    if parsed.tauri_conf_sha256 != sha256_hex(tauri_conf_bytes) {
        failures.push("tauri_conf_sha256 mismatch".to_owned());
    }

    let sbom_artifacts = match extract_sbom_artifacts(sbom_json) {
        Ok(set) => set,
        Err(e) => {
            failures.push(e);
            BTreeSet::new()
        }
    };

    let mut verified_count = 0;
    for entry in &parsed.artifacts {
        if !sbom_artifacts.contains(&(entry.name.clone(), entry.sha256.clone())) {
            failures.push(format!(
                "artifact '{}' ({}) missing from CycloneDX SBOM artifact inventory",
                entry.name, entry.sha256
            ));
            continue;
        }
        match read_staged_regular_file(staging_root, &entry.relative_path) {
            Ok(bytes) => {
                if bytes.len() as u64 != entry.byte_len {
                    failures.push(format!("artifact '{}' byte_len mismatch", entry.name));
                } else if sha256_hex(&bytes) != entry.sha256 {
                    failures.push(format!("artifact '{}' sha256 mismatch", entry.name));
                } else {
                    verified_count += 1;
                }
            }
            Err(e) => failures.push(format!("artifact '{}': {e}", entry.name)),
        }
    }

    StagingVerificationReport {
        ok: failures.is_empty(),
        failures,
        verified_artifact_count: verified_count,
    }
}

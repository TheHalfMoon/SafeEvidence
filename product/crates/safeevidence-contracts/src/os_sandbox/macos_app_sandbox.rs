//! macOS App Sandbox entitlements `ReadyBaseMeasured` (`ADM-0018` / `T10`, `TA-26`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/os_sandbox/macos_app_sandbox.rs`)
//! under Apache-2.0 (`ADR-0004`). Separates Seatbelt `sandbox_init`, the worker entitlements plist
//! artifact + detection probe, and signed runtime App Sandbox enforcement (`OS_CA_CODE_SIGNED = FALSE`).

use super::OsSandboxApplyError;
use std::path::{Path, PathBuf};

/// Relative path of the worker entitlements fixture inside the repository.
pub const ENTITLEMENTS_REL_PATH: &str =
    "product/crates/safeevidence-contracts/fixtures/worker.entitlements.plist";

/// Locate worker entitlements plist fixture from `CARGO_MANIFEST_DIR` or repo-relative parents.
#[must_use]
pub fn resolve_entitlements_path() -> Option<PathBuf> {
    let manifest_fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/worker.entitlements.plist");
    if manifest_fixture.is_file() {
        return Some(manifest_fixture);
    }
    let candidates = [
        PathBuf::from(ENTITLEMENTS_REL_PATH),
        PathBuf::from("crates/safeevidence-contracts/fixtures/worker.entitlements.plist"),
        PathBuf::from("fixtures/worker.entitlements.plist"),
        PathBuf::from("..").join(ENTITLEMENTS_REL_PATH),
        PathBuf::from("../..").join(ENTITLEMENTS_REL_PATH),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

/// True if process appears to be running inside an App Sandbox container.
#[must_use]
pub fn app_sandbox_container_active() -> bool {
    std::env::var_os("APP_SANDBOX_CONTAINER_ID").is_some_and(|v| !v.is_empty())
}

fn plist_key_value_after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("<key>{key}</key>");
    let idx = text.find(&needle)?;
    let mut rest = &text[idx + needle.len()..];
    loop {
        rest = rest.trim_start();
        if let Some(after_comment_open) = rest.strip_prefix("<!--") {
            let end = after_comment_open.find("-->")?;
            rest = &after_comment_open[end + 3..];
            continue;
        }
        break;
    }
    Some(rest)
}

fn plist_bool_for_key(text: &str, key: &str) -> Option<bool> {
    let rest = plist_key_value_after(text, key)?;
    if rest.starts_with("<true/>") || rest.starts_with("<true />") {
        Some(true)
    } else if rest.starts_with("<false/>") || rest.starts_with("<false />") {
        Some(false)
    } else {
        None
    }
}

/// Validate entitlements plist contains explicit `com.apple.security.app-sandbox = true` and does
/// not grant ambient `com.apple.security.network.client` or `network.server`.
pub fn validate_entitlements_artifact(path: &Path) -> Result<(), OsSandboxApplyError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        OsSandboxApplyError::ApplyFailed(format!(
            "failed to read entitlements {}: {e}",
            path.display()
        ))
    })?;
    if plist_bool_for_key(&text, "com.apple.security.app-sandbox") != Some(true) {
        return Err(OsSandboxApplyError::ApplyFailed(
            "entitlements must enable com.apple.security.app-sandbox = true".to_owned(),
        ));
    }
    for net_key in [
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    ] {
        if plist_bool_for_key(&text, net_key) == Some(true) {
            return Err(OsSandboxApplyError::ApplyFailed(format!(
                "entitlements must not enable ambient {net_key}"
            )));
        }
    }
    Ok(())
}

pub(super) fn apply_macos_app_sandbox_entitlements() -> Result<(), OsSandboxApplyError> {
    let path = resolve_entitlements_path().ok_or_else(|| {
        OsSandboxApplyError::ApplyFailed(format!(
            "App Sandbox entitlements fixture missing ({ENTITLEMENTS_REL_PATH})"
        ))
    })?;
    validate_entitlements_artifact(&path)?;
    let _active = app_sandbox_container_active();
    Ok(())
}

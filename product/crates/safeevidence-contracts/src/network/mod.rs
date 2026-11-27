//! Network Broker & Governed Egress contract types (`ADM-0015` / `T05`, `TA-21`, `TA-30`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/network/mod.rs`)
//! under Apache-2.0 (`ADR-0004`), extended with SafeEvidence `NetworkMode` (`NetworkLocked`
//! default vs `EvidenceUpdateOnly`) and `TA-30` `OutboundQueryPreview` / `EgressApprovalReceipt`.

use serde::{Deserialize, Serialize};

use crate::objects::{DigestSha256, OpaqueId};

/// Maximum URL character length accepted by governed egress validation.
pub const URL_MAX_CHARS: usize = 2048;

/// SafeEvidence workstation network posture (`TA-21` / `TA-30`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Strict air-gapped default: every outbound broker request is refused fail-closed.
    #[default]
    NetworkLocked,
    /// Governed update-only mode: permits HTTPS-only allowlisted literature/pack endpoints
    /// ONLY when accompanied by a verified `EgressApprovalReceipt` matching the exact previewed
    /// request payload.
    EvidenceUpdateOnly,
}

/// Purpose of a brokered egress attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPurpose {
    SmartDiscovery,
    SmartTokenFixture,
    FhirReadFixture,
    FhirSearchFixture,
    ProfileOracleFixture,
    IntegrityCheck,
    ConformanceEvidenceAttach,
    DatasetMirrorRead,
    LiteratureRefreshQuery,
    EvidencePackUpdateCheck,
}

/// Data class declared on the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressDataClass {
    SyntheticFixture,
    NonPhiMetadata,
    RedactedEvidence,
    /// Explicitly refused for product egress on every path (`ADR-0003`, `TA-21`, `TA-30`).
    RealPhiForbidden,
}

/// Allowlist match decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerDecision {
    Allow,
    Deny,
}

/// Typed deny / outcome reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerReasonCode {
    NetworkLocked,
    UserPreviewRequired,
    PreviewDigestMismatch,
    UnsafeUrlOrAddress,
    UnknownDestination,
    PurposeMismatch,
    DataClassRefused,
    Unauthorized,
    EmptyAllowlist,
    ExternalGateRequired,
    TransportFixtureOk,
    TransportTimeout,
    TransportFailed,
    IntegrityMismatch,
    Ok,
}

/// URL validation refusal reason for governed HTTPS browse/update calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowseDenyReason {
    MalformedUrl,
    SchemeNotHttps,
    PortNotAllowed,
    IpLiteralHost,
    ForbiddenResolvedIp,
}

/// One allowlist entry (exact DNS host + unambiguous path prefix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressAllowlistEntry {
    pub host: String,
    pub path_prefix: String,
    pub purposes: Vec<EgressPurpose>,
    pub data_classes: Vec<EgressDataClass>,
    pub enabled: bool,
}

/// Broker request envelope (no secrets or patient identifiers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBrokerRequest {
    pub destination_host: String,
    pub destination_path: String,
    pub purpose: EgressPurpose,
    pub data_class: EgressDataClass,
    pub authorization_token_id: Option<OpaqueId>,
    pub body_digest: Option<DigestSha256>,
    pub fixture_id: Option<String>,
}

/// Exact outbound query disclosure shown to the researcher before any `EvidenceUpdateOnly`
/// request can be approved (`TA-30`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundQueryPreview {
    pub canonical_https_url: String,
    pub destination_host: String,
    pub destination_path: String,
    pub purpose: EgressPurpose,
    pub data_class: EgressDataClass,
    pub sanitized_query_summary: String,
    pub preview_digest: DigestSha256,
}

/// Explicit user-approved receipt binding one `OutboundQueryPreview` (`TA-30`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressApprovalReceipt {
    pub preview_digest: DigestSha256,
    pub user_confirmed_opt_in: bool,
}

/// Broker response + receipt binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBrokerResult {
    pub decision: BrokerDecision,
    pub reason: BrokerReasonCode,
    pub audit_id: OpaqueId,
    pub evaluation_id: Option<OpaqueId>,
    pub transport_sent: bool,
    pub fixture_body: Option<String>,
}

/// Doctor section for network broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBrokerDoctorStatus {
    pub present: bool,
    pub mode: NetworkMode,
    pub default_deny: bool,
    pub allowlist_entries: u32,
    pub live_partner_authorized: bool,
    pub http_client: String,
}

/// Validates a canonical lowercase DNS host name (1..=253 ASCII chars, non-empty labels 1..=63
/// `[a-z0-9-]`, no leading/trailing `-`, and at least two labels so single-label intranet names
/// are refused).
#[must_use]
pub fn is_dns_host_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// Rejects path traversal, fragments (`#`), backslashes, double slashes, control bytes, and
/// percent-encoded slash/dot/fragment sequences (`%2f`, `%5c`, `%2e`, `%00`, `%23`) that a server
/// or client might normalize across an allowlist prefix or preview boundary.
#[must_use]
pub fn is_unambiguous_url_path(path: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') || path.contains('#')
    {
        return false;
    }
    if path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return false;
    }
    let lower_full = path.to_ascii_lowercase();
    if lower_full.contains("%00") || lower_full.contains("%23") {
        return false;
    }
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only.contains("//") {
        return false;
    }
    for seg in path_only.split('/') {
        if seg == "." || seg == ".." {
            return false;
        }
    }
    let lower = path_only.to_ascii_lowercase();
    for forbidden in ["%2f", "%5c", "%2e", "%00"] {
        if lower.contains(forbidden) {
            return false;
        }
    }
    true
}

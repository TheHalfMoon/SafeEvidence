//! SafeEvidence Network Broker (`ADM-0015` / `T05`, `TA-21`, `TA-30`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-network/src/lib.rs`)
//! under Apache-2.0 (`ADR-0004`). Enforces:
//! 1. `NetworkMode::NetworkLocked` default denial (zero egress without explicit mode switch).
//! 2. `EgressDataClass::RealPhiForbidden` unconditional refusal.
//! 3. `TA-30` `OutboundQueryPreview` + `EgressApprovalReceipt` cryptographic digest binding before
//!    any `EvidenceUpdateOnly` request is dispatched.

#![forbid(unsafe_code)]

mod adapters;
mod allowlist;
mod browse;
mod transport;

pub use adapters::{
    FhirPartnerAdapter, SmartAuthAdapter, StubFhirAdapter, StubSmartAdapter, live_partner_refused,
};
pub use allowlist::{AllowlistDecision, evaluate_allowlist};
pub use browse::{
    BrowseFileResponse, BrowseHttpResponse, BrowseTransport, BrowseTransportError,
    ScriptedBrowseTransport, ValidatedUrl, filter_public_socket_addrs, is_forbidden_ip,
    resolve_redirect, validate_url,
};
pub use transport::{
    BrokerTransport, FixtureTransport, LockedLiveTransport, TransportError, TransportRequest,
};

use safeevidence_contracts::bilingual::is_forbidden_bidi_control;
use safeevidence_contracts::network::{
    BrokerDecision, BrokerReasonCode, EgressAllowlistEntry, EgressApprovalReceipt, EgressDataClass,
    NetworkBrokerDoctorStatus, NetworkBrokerRequest, NetworkMode, OutboundQueryPreview,
};
use safeevidence_contracts::objects::DigestSha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerInvokeOutcome {
    pub decision: BrokerDecision,
    pub reason: BrokerReasonCode,
    pub transport_sent: bool,
    pub fixture_body: Option<String>,
}

fn append_len_framed(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Builds a deterministic `TA-30` `OutboundQueryPreview` for user inspection prior to egress.
/// Refuses `RealPhiForbidden`, BiDi control characters, fragments (`#`), port/dot host ambiguity,
/// or malformed/non-HTTPS URLs.
pub fn build_outbound_query_preview(
    request: &NetworkBrokerRequest,
    sanitized_query_summary: &str,
) -> Result<OutboundQueryPreview, BrokerReasonCode> {
    if request.data_class == EgressDataClass::RealPhiForbidden {
        return Err(BrokerReasonCode::DataClassRefused);
    }
    if sanitized_query_summary.trim().is_empty()
        || sanitized_query_summary
            .chars()
            .any(|c| c.is_control() || is_forbidden_bidi_control(c))
    {
        return Err(BrokerReasonCode::UnsafeUrlOrAddress);
    }
    let host_trimmed = request.destination_host.trim();
    let path_trimmed = request.destination_path.trim();
    if host_trimmed.contains(':')
        || host_trimmed.ends_with('.')
        || !path_trimmed.starts_with('/')
        || path_trimmed.contains('#')
    {
        return Err(BrokerReasonCode::UnsafeUrlOrAddress);
    }
    let raw_url = format!("https://{host_trimmed}{path_trimmed}");
    let validated = validate_url(&raw_url).map_err(|_| BrokerReasonCode::UnsafeUrlOrAddress)?;
    if validated.host != host_trimmed.to_ascii_lowercase() || validated.path != path_trimmed {
        return Err(BrokerReasonCode::UnsafeUrlOrAddress);
    }

    let mut canonical_bytes = Vec::new();
    canonical_bytes.extend_from_slice(b"SAFEVD/EGRESS/PREVIEW/v1");
    append_len_framed(&mut canonical_bytes, validated.url.as_bytes());
    append_len_framed(
        &mut canonical_bytes,
        format!("{:?}", request.purpose).as_bytes(),
    );
    append_len_framed(
        &mut canonical_bytes,
        format!("{:?}", request.data_class).as_bytes(),
    );
    match &request.authorization_token_id {
        Some(tok) => {
            canonical_bytes.push(1);
            append_len_framed(&mut canonical_bytes, tok.as_str().as_bytes());
        }
        None => canonical_bytes.push(0),
    }
    match &request.body_digest {
        Some(body_digest) => {
            canonical_bytes.push(1);
            canonical_bytes.extend_from_slice(body_digest.as_bytes());
        }
        None => canonical_bytes.push(0),
    }
    match &request.fixture_id {
        Some(fid) => {
            canonical_bytes.push(1);
            append_len_framed(&mut canonical_bytes, fid.as_bytes());
        }
        None => canonical_bytes.push(0),
    }
    append_len_framed(
        &mut canonical_bytes,
        sanitized_query_summary.trim().as_bytes(),
    );

    let preview_digest = DigestSha256::of(&canonical_bytes);
    Ok(OutboundQueryPreview {
        canonical_https_url: validated.url,
        destination_host: validated.host,
        destination_path: validated.path,
        purpose: request.purpose,
        data_class: request.data_class,
        sanitized_query_summary: sanitized_query_summary.trim().to_owned(),
        preview_digest,
    })
}

/// Evaluates full SafeEvidence governed egress policy (`NetworkMode` + `TA-30` preview receipt +
/// allowlist + transport).
#[must_use]
pub fn broker_invoke_governed(
    mode: NetworkMode,
    allowlist: &[EgressAllowlistEntry],
    request: &NetworkBrokerRequest,
    expected_preview: Option<&OutboundQueryPreview>,
    approval: Option<&EgressApprovalReceipt>,
    transport: &dyn BrokerTransport,
) -> BrokerInvokeOutcome {
    if request.data_class == EgressDataClass::RealPhiForbidden {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::DataClassRefused,
            transport_sent: false,
            fixture_body: None,
        };
    }
    if mode == NetworkMode::NetworkLocked {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::NetworkLocked,
            transport_sent: false,
            fixture_body: None,
        };
    }
    let (Some(preview), Some(receipt)) = (expected_preview, approval) else {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::UserPreviewRequired,
            transport_sent: false,
            fixture_body: None,
        };
    };
    if !receipt.user_confirmed_opt_in {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::UserPreviewRequired,
            transport_sent: false,
            fixture_body: None,
        };
    }
    let Ok(recomputed) = build_outbound_query_preview(request, &preview.sanitized_query_summary)
    else {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::UnsafeUrlOrAddress,
            transport_sent: false,
            fixture_body: None,
        };
    };
    if recomputed != *preview || receipt.preview_digest != preview.preview_digest {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::PreviewDigestMismatch,
            transport_sent: false,
            fixture_body: None,
        };
    }

    let canonical_request = NetworkBrokerRequest {
        destination_host: preview.destination_host.clone(),
        destination_path: preview.destination_path.clone(),
        purpose: preview.purpose,
        data_class: preview.data_class,
        authorization_token_id: request.authorization_token_id.clone(),
        body_digest: request.body_digest.clone(),
        fixture_id: request.fixture_id.clone(),
    };
    broker_invoke(allowlist, &canonical_request, transport)
}

/// Evaluate allowlist policy then invoke `transport` (used directly by offline fixture tests and
/// internally after `broker_invoke_governed` verifies `EvidenceUpdateOnly` + `TA-30` receipt).
pub fn broker_invoke(
    allowlist: &[EgressAllowlistEntry],
    request: &NetworkBrokerRequest,
    transport: &dyn BrokerTransport,
) -> BrokerInvokeOutcome {
    if request.data_class == EgressDataClass::RealPhiForbidden {
        return BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason: BrokerReasonCode::DataClassRefused,
            transport_sent: false,
            fixture_body: None,
        };
    }

    match evaluate_allowlist(allowlist, request) {
        AllowlistDecision::Deny(reason) => BrokerInvokeOutcome {
            decision: BrokerDecision::Deny,
            reason,
            transport_sent: false,
            fixture_body: None,
        },
        AllowlistDecision::Allow => match transport.send(&TransportRequest {
            host: request.destination_host.trim().to_ascii_lowercase(),
            path: request.destination_path.trim().to_owned(),
            purpose: request.purpose,
            fixture_id: request.fixture_id.clone(),
        }) {
            Ok(body) => BrokerInvokeOutcome {
                decision: BrokerDecision::Allow,
                reason: BrokerReasonCode::TransportFixtureOk,
                transport_sent: true,
                fixture_body: Some(body),
            },
            Err(TransportError::ExternalGateRequired) => BrokerInvokeOutcome {
                decision: BrokerDecision::Deny,
                reason: BrokerReasonCode::ExternalGateRequired,
                transport_sent: false,
                fixture_body: None,
            },
            Err(TransportError::Timeout(_)) => BrokerInvokeOutcome {
                decision: BrokerDecision::Deny,
                reason: BrokerReasonCode::TransportTimeout,
                transport_sent: true,
                fixture_body: None,
            },
            Err(TransportError::Failed(_)) => BrokerInvokeOutcome {
                decision: BrokerDecision::Deny,
                reason: BrokerReasonCode::TransportFailed,
                transport_sent: true,
                fixture_body: None,
            },
        },
    }
}

/// Constant-time 32-byte SHA-256 hex digest comparison (accumulates XOR across all 32 bytes
/// without early exit).
#[must_use]
pub fn integrity_matches(expected_hex: &str, bytes: &[u8]) -> bool {
    let expected = expected_hex.trim();
    if expected.len() != 64 {
        return false;
    }
    let mut parsed = [0_u8; 32];
    for (idx, pair) in expected.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let Ok(s) = std::str::from_utf8(pair) else {
            return false;
        };
        let Ok(val) = u8::from_str_radix(s, 16) else {
            return false;
        };
        parsed[idx] = val;
    }
    let actual = DigestSha256::of(bytes);
    let mut diff = 0_u8;
    for (&a, &b) in actual.as_bytes().iter().zip(&parsed) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Builds honest `NetworkBrokerDoctorStatus` for current mode & allowlist.
#[must_use]
pub fn doctor_status(
    mode: NetworkMode,
    allowlist: &[EgressAllowlistEntry],
) -> NetworkBrokerDoctorStatus {
    NetworkBrokerDoctorStatus {
        present: true,
        mode,
        default_deny: mode == NetworkMode::NetworkLocked || allowlist.is_empty(),
        allowlist_entries: u32::try_from(allowlist.iter().filter(|e| e.enabled).count())
            .unwrap_or(u32::MAX),
        live_partner_authorized: false,
        http_client: "none_ta29_fixture_only".to_owned(),
    }
}

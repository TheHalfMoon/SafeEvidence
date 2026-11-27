//! Fail-closed egress allowlist (`ADM-0015` / `T05`, `TA-21`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-network/src/allowlist.rs`)
//! under Apache-2.0 (`ADR-0004`).

use safeevidence_contracts::network::{
    BrokerReasonCode, EgressAllowlistEntry, NetworkBrokerRequest, is_dns_host_name,
    is_unambiguous_url_path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistDecision {
    Allow,
    Deny(BrokerReasonCode),
}

/// Empty allowlist => all `Deny(EmptyAllowlist)`. Also enforces unambiguous URL path and canonical
/// DNS host syntax so path-traversal or IP-literal hosts cannot slip past an allowlist prefix.
#[must_use]
pub fn evaluate_allowlist(
    allowlist: &[EgressAllowlistEntry],
    request: &NetworkBrokerRequest,
) -> AllowlistDecision {
    if !allowlist.iter().any(|e| e.enabled) {
        return AllowlistDecision::Deny(BrokerReasonCode::EmptyAllowlist);
    }
    let host_norm = request.destination_host.trim().to_ascii_lowercase();
    let path_norm = request.destination_path.trim();
    if !is_dns_host_name(&host_norm) || !is_unambiguous_url_path(path_norm) {
        return AllowlistDecision::Deny(BrokerReasonCode::UnsafeUrlOrAddress);
    }

    let mut host_seen = false;
    let mut mismatch_reason: Option<BrokerReasonCode> = None;
    for entry in allowlist {
        if !entry.enabled {
            continue;
        }
        let entry_host = entry.host.trim().to_ascii_lowercase();
        if !is_dns_host_name(&entry_host) || !is_unambiguous_url_path(&entry.path_prefix) {
            continue;
        }
        if entry_host != host_norm {
            continue;
        }
        host_seen = true;
        let Some(rem) = path_norm.strip_prefix(&entry.path_prefix) else {
            continue;
        };
        if !(rem.is_empty()
            || entry.path_prefix.ends_with('/')
            || rem.starts_with('/')
            || rem.starts_with('?'))
        {
            continue;
        }
        if !entry.purposes.contains(&request.purpose) {
            mismatch_reason.get_or_insert(BrokerReasonCode::PurposeMismatch);
            continue;
        }
        if !entry.data_classes.contains(&request.data_class) {
            mismatch_reason = Some(BrokerReasonCode::DataClassRefused);
            continue;
        }
        return AllowlistDecision::Allow;
    }

    if let Some(reason) = mismatch_reason {
        AllowlistDecision::Deny(reason)
    } else if host_seen {
        AllowlistDecision::Deny(BrokerReasonCode::PurposeMismatch)
    } else {
        AllowlistDecision::Deny(BrokerReasonCode::UnknownDestination)
    }
}

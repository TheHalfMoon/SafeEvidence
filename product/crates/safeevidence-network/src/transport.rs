//! Broker transport trait + deterministic offline fixture backends (`ADM-0015` / `T05`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-network/src/transport.rs`)
//! under Apache-2.0 (`ADR-0004`). Denied third-party HTTP clients (`ureq`, `reqwest`, `hyper`)
//! are excluded in compliance with `TA-29`.

use safeevidence_contracts::network::EgressPurpose;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRequest {
    pub host: String,
    pub path: String,
    pub purpose: EgressPurpose,
    pub fixture_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    #[error("external gate required for live partner")]
    ExternalGateRequired,
    #[error("transport timeout: {0}")]
    Timeout(String),
    #[error("transport failed: {0}")]
    Failed(String),
}

pub trait BrokerTransport: Send + Sync {
    fn send(&self, req: &TransportRequest) -> Result<String, TransportError>;
}

/// Offline fixture transport — opens zero sockets.
#[derive(Debug, Default)]
pub struct FixtureTransport;

impl BrokerTransport for FixtureTransport {
    fn send(&self, req: &TransportRequest) -> Result<String, TransportError> {
        let id = req.fixture_id.as_deref().unwrap_or("default");
        match id {
            "fail:timeout" => Err(TransportError::Timeout(
                "synthetic fixture timeout".to_owned(),
            )),
            "fail:transport" => Err(TransportError::Failed(
                "synthetic fixture transport failure".to_owned(),
            )),
            _ => Ok(serde_json::json!({
                "fixture": true,
                "host": req.host,
                "path": req.path,
                "purpose": format!("{:?}", req.purpose),
                "fixture_id": id,
            })
            .to_string()),
        }
    }
}

/// Fail-closed live transport placeholder — refuses live sockets unless an external partner gate
/// is explicitly opened (`TA-21` / `TA-29`).
#[derive(Debug, Default)]
pub struct LockedLiveTransport;

impl BrokerTransport for LockedLiveTransport {
    fn send(&self, _req: &TransportRequest) -> Result<String, TransportError> {
        Err(TransportError::ExternalGateRequired)
    }
}

//! Fail-closed hostile-MIME and payload intake quarantine (`T12`, `ADM-0007` / `WP-13`).
//!
//! Enforces strict pre-parser MIME allowlisting, non-empty size bounds, and magic-header
//! verification so active/executable, HTML/script, Office macro/OOXML, arbitrary binary, empty,
//! oversized, or header-spoofed payloads are quarantined before reaching any parser worker.

use serde::{Deserialize, Serialize};

/// Maximum intake payload size accepted for bounded local document verification (32 MiB).
pub const MAX_DOCUMENT_INTAKE_BYTES: usize = 32 * 1024 * 1024;

/// Declared document MIME classifications at the intake boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocumentMimeClass {
    TextPlain,
    ApplicationPdf,
    ImagePng,
    ImageJpeg,
    ApplicationOctetStream,
    TextHtml,
    OfficeOpenXml,
    ApplicationJavascript,
    Unknown,
}

/// Fail-closed quarantine disposition for a candidate document intake payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineDecision {
    AdmitToSandboxedParser,
    Quarantine,
}

/// Typed reason code recorded when a document payload is quarantined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocumentDenyReason {
    None,
    MimeDenied,
    EmptyPayload,
    OversizedPayload,
    MagicHeaderMismatch,
    InvalidUtf8Text,
}

/// Bounded intake request evaluated before any parser or OCR worker sees bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentIntakeRequest {
    pub mime: DocumentMimeClass,
    pub bytes: Vec<u8>,
    pub fixture_id: Option<String>,
}

fn looks_like_html_or_script(bytes: &[u8]) -> bool {
    let trimmed = bytes.trim_ascii_start();
    let prefix = &trimmed[..trimmed.len().min(64)];
    let lower: Vec<u8> = prefix.iter().map(u8::to_ascii_lowercase).collect();
    lower.starts_with(b"<!doctype html")
        || lower.starts_with(b"<html")
        || lower.starts_with(b"<script")
        || lower.starts_with(b"<svg")
}

/// Evaluates `req` fail-closed, quarantining denied MIME classes, empty/oversized payloads,
/// invalid UTF-8 plain text, HTML/script polyglots disguised as plain text, and PDF/PNG/JPEG
/// magic-header mismatches.
#[must_use]
pub fn mime_decision(req: &DocumentIntakeRequest) -> (QuarantineDecision, DocumentDenyReason) {
    match req.mime {
        DocumentMimeClass::ApplicationOctetStream
        | DocumentMimeClass::TextHtml
        | DocumentMimeClass::OfficeOpenXml
        | DocumentMimeClass::ApplicationJavascript
        | DocumentMimeClass::Unknown => {
            return (
                QuarantineDecision::Quarantine,
                DocumentDenyReason::MimeDenied,
            );
        }
        DocumentMimeClass::TextPlain
        | DocumentMimeClass::ApplicationPdf
        | DocumentMimeClass::ImagePng
        | DocumentMimeClass::ImageJpeg => {}
    }

    if req.bytes.is_empty() {
        return (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::EmptyPayload,
        );
    }
    if req.bytes.len() > MAX_DOCUMENT_INTAKE_BYTES {
        return (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::OversizedPayload,
        );
    }

    match req.mime {
        DocumentMimeClass::TextPlain => {
            if std::str::from_utf8(&req.bytes).is_err() {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::InvalidUtf8Text,
                );
            }
            if looks_like_html_or_script(&req.bytes) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied,
                );
            }
        }
        DocumentMimeClass::ApplicationPdf => {
            if !req.bytes.starts_with(b"%PDF-") {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
        }
        DocumentMimeClass::ImagePng => {
            if !req.bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
        }
        DocumentMimeClass::ImageJpeg => {
            if !req.bytes.starts_with(&[0xff, 0xd8, 0xff]) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
        }
        _ => unreachable!("denied MIME classes returned early"),
    }

    (
        QuarantineDecision::AdmitToSandboxedParser,
        DocumentDenyReason::None,
    )
}

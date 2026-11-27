//! Fail-closed hostile-MIME and payload intake quarantine (`T12`, `ADM-0007` / `WP-13`).
//!
//! Enforces strict pre-parser MIME allowlisting, non-empty size bounds, control-byte/BOM hygiene,
//! polyglot active-markup detection, and magic-header verification so active/executable,
//! HTML/XML/script, Office macro/OOXML, arbitrary binary, empty, oversized, or header-spoofed
//! payloads are quarantined before reaching any parser worker.

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

fn has_disallowed_control_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|&b| b == 0x7f || (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c)))
}

fn starts_with_binary_or_container_magic(trimmed: &str) -> bool {
    let raw = trimmed.as_bytes();
    raw.starts_with(b"%PDF-")
        || raw.starts_with(b"PK\x03\x04")
        || raw.starts_with(b"PK\x05\x06")
        || raw.starts_with(b"PK\x07\x08")
        || raw.starts_with(b"MZ")
        || raw.starts_with(b"\x7fELF")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|window| {
        window
            .iter()
            .zip(needle_lower.iter())
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

fn has_inline_event_handler_markup(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'<' {
            let close = bytes[idx + 1..]
                .iter()
                .position(|&b| b == b'>')
                .map_or(bytes.len(), |rel| idx + 1 + rel);
            let tag_slice = &bytes[idx + 1..close];
            for pos in 0..tag_slice.len() {
                let prev_ws = pos == 0 || tag_slice[pos - 1].is_ascii_whitespace();
                if prev_ws
                    && pos + 3 < tag_slice.len()
                    && tag_slice[pos].eq_ignore_ascii_case(&b'o')
                    && tag_slice[pos + 1].eq_ignore_ascii_case(&b'n')
                    && tag_slice[pos + 2].is_ascii_alphabetic()
                {
                    let mut scan = pos + 2;
                    while scan < tag_slice.len() && tag_slice[scan].is_ascii_alphabetic() {
                        scan += 1;
                    }
                    while scan < tag_slice.len() && tag_slice[scan].is_ascii_whitespace() {
                        scan += 1;
                    }
                    if scan < tag_slice.len() && tag_slice[scan] == b'=' {
                        return true;
                    }
                }
            }
            idx = close.saturating_add(1);
        } else {
            idx += 1;
        }
    }
    false
}

fn looks_like_active_markup_or_script(text: &str) -> bool {
    let raw = text.as_bytes();
    const DENIED_MARKUP_TOKENS: &[&[u8]] = &[
        b"<!doctype",
        b"<html",
        b"<head",
        b"<body",
        b"<script",
        b"<svg",
        b"<iframe",
        b"<object",
        b"<embed",
        b"<applet",
        b"<meta",
        b"<link",
        b"<style",
        b"<form",
        b"<?xml",
        b"<!--",
        b"javascript:",
        b"vbscript:",
        b"data:text/html",
    ];
    DENIED_MARKUP_TOKENS
        .iter()
        .any(|token| contains_ascii_case_insensitive(raw, token))
        || has_inline_event_handler_markup(text)
}

fn pdf_contains_active_action(bytes: &[u8]) -> bool {
    const DENIED_PDF_TOKENS: &[&[u8]] = &[b"/javascript", b"/js", b"/launch", b"/richmedia"];
    DENIED_PDF_TOKENS
        .iter()
        .any(|token| contains_ascii_case_insensitive(bytes, token))
}

/// Evaluates `req` fail-closed, quarantining denied MIME classes, empty/oversized payloads,
/// invalid UTF-8 or control-byte plain text, BOM/whitespace/mid-body HTML/XML/script polyglots,
/// active PDF script actions, and PDF/PNG/JPEG magic-header mismatches.
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
            let Ok(decoded) = std::str::from_utf8(&req.bytes) else {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::InvalidUtf8Text,
                );
            };
            let without_bom = decoded.strip_prefix('\u{feff}').unwrap_or(decoded);
            let trimmed = without_bom.trim_start();
            if trimmed.is_empty() {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::EmptyPayload,
                );
            }
            if starts_with_binary_or_container_magic(trimmed) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
            if has_disallowed_control_bytes(&req.bytes) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::InvalidUtf8Text,
                );
            }
            if looks_like_active_markup_or_script(without_bom) {
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
            if pdf_contains_active_action(&req.bytes) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied,
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

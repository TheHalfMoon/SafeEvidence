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
        if bytes[idx] != b'<' || idx + 1 >= bytes.len() || !bytes[idx + 1].is_ascii_alphabetic() {
            idx += 1;
            continue;
        }
        let Some(rel_angle) = bytes[idx + 1..]
            .iter()
            .position(|&b| b == b'<' || b == b'>')
        else {
            idx += 1;
            continue;
        };
        let angle_pos = idx + 1 + rel_angle;
        if bytes[angle_pos] != b'>' {
            idx += 1;
            continue;
        }
        let tag_slice = &bytes[idx + 1..angle_pos];
        let mut name_end = 0;
        while name_end < tag_slice.len()
            && (tag_slice[name_end].is_ascii_alphanumeric()
                || matches!(tag_slice[name_end], b'-' | b':'))
        {
            name_end += 1;
        }
        if name_end < tag_slice.len()
            && (tag_slice[name_end].is_ascii_whitespace() || tag_slice[name_end] == b'/')
        {
            for pos in name_end..tag_slice.len() {
                let prev = tag_slice[pos - 1];
                let prev_delim = prev.is_ascii_whitespace() || matches!(prev, b'/' | b'"' | b'\'');
                if prev_delim
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
        }
        idx = angle_pos.saturating_add(1);
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

const fn is_pdf_delim_or_ws(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t'
            | b'\r'
            | b'\n'
            | b'\x0c'
            | b'\0'
            | b'('
            | b')'
            | b'<'
            | b'>'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'/'
            | b'%'
    )
}

fn decode_pdf_name_token(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.len() > 64 || !raw.iter().all(|&b| (0x21..=0x7e).contains(&b)) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut idx = 0;
    while idx < raw.len() {
        if raw[idx] == b'#' {
            if idx + 2 >= raw.len() {
                return None;
            }
            let hi = (raw[idx + 1] as char).to_digit(16)?;
            let lo = (raw[idx + 2] as char).to_digit(16)?;
            let decoded = u8::try_from((hi << 4) | lo).ok()?;
            out.push(decoded);
            idx += 3;
        } else {
            out.push(raw[idx]);
            idx += 1;
        }
    }
    Some(out)
}

fn pdf_contains_active_action(bytes: &[u8]) -> bool {
    let mut idx = 0;
    while idx < bytes.len() {
        // Skip `%` comment lines after line 0 so URLs in comments never collide.
        if bytes[idx] == b'%' && idx > 0 {
            while idx < bytes.len() && !matches!(bytes[idx], b'\r' | b'\n') {
                idx += 1;
            }
            continue;
        }
        if bytes[idx] == b'/' && (idx == 0 || is_pdf_delim_or_ws(bytes[idx - 1])) {
            let start = idx + 1;
            let mut end = start;
            while end < bytes.len() && !is_pdf_delim_or_ws(bytes[end]) && end - start <= 64 {
                end += 1;
            }
            if end > start
                && (end == bytes.len() || is_pdf_delim_or_ws(bytes[end]))
                && let Some(decoded) = decode_pdf_name_token(&bytes[start..end])
            {
                if decoded.eq_ignore_ascii_case(b"javascript")
                    || decoded.eq_ignore_ascii_case(b"launch")
                    || decoded.eq_ignore_ascii_case(b"richmedia")
                {
                    return true;
                }
                if decoded.as_slice() == b"JS"
                    && end < bytes.len()
                    && matches!(
                        bytes[end],
                        b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0' | b'(' | b'<' | b'/'
                    )
                {
                    return true;
                }
            }
            idx = end;
        } else {
            idx += 1;
        }
    }
    false
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
            let trimmed =
                decoded.trim_start_matches(|c: char| c == '\u{feff}' || c.is_whitespace());
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
            if looks_like_active_markup_or_script(trimmed) {
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

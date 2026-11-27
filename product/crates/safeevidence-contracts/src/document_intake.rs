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

fn has_disallowed_unicode_controls(trimmed: &str) -> bool {
    trimmed.chars().any(|ch| {
        ('\u{0080}'..='\u{009F}').contains(&ch) || crate::bilingual::is_forbidden_bidi_control(ch)
    })
}

fn starts_with_binary_or_container_magic(trimmed: &str) -> bool {
    let raw = trimmed.as_bytes();
    raw.starts_with(b"%PDF-")
        || raw.starts_with(b"PK\x03\x04")
        || raw.starts_with(b"PK\x05\x06")
        || raw.starts_with(b"PK\x07\x08")
        || raw.starts_with(b"MZ")
        || raw.starts_with(b"\x7fELF")
        || raw.starts_with(b"{\\rtf")
}

fn has_binary_tag_prefix(bytes: &[u8], tag_lower: &[u8]) -> bool {
    let want_len = tag_lower.len() + 1;
    if bytes.len() < want_len {
        return false;
    }
    bytes.windows(want_len).any(|w| {
        w[..tag_lower.len()]
            .iter()
            .zip(tag_lower.iter())
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
            && (w[tag_lower.len()].is_ascii_whitespace()
                || matches!(w[tag_lower.len()], b'/' | b'>'))
    })
}

fn contains_binary_polyglot_script(bytes: &[u8]) -> bool {
    const DIRECT_SCRIPT_TOKENS: &[&[u8]] = &[
        b"<!doctype",
        b"<script",
        b"javascript:",
        b"vbscript:",
        b"data:text/html",
    ];
    const BOUNDED_TAG_TOKENS: &[&[u8]] = &[b"<html", b"<svg", b"<iframe", b"<object", b"<embed"];
    DIRECT_SCRIPT_TOKENS
        .iter()
        .any(|tok| contains_ascii_case_insensitive(bytes, tok))
        || BOUNDED_TAG_TOKENS
            .iter()
            .any(|tag| has_binary_tag_prefix(bytes, tag))
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
        let mut cursor = idx + 1;
        let mut in_quote: Option<u8> = None;
        let mut close_pos: Option<usize> = None;
        while cursor < bytes.len() {
            let b = bytes[cursor];
            if let Some(q) = in_quote {
                if b == q {
                    in_quote = None;
                }
            } else if matches!(b, b'"' | b'\'') {
                in_quote = Some(b);
            } else if b == b'<' {
                break;
            } else if b == b'>' {
                close_pos = Some(cursor);
                break;
            }
            cursor += 1;
        }
        let Some(angle_pos) = close_pos else {
            idx += 1;
            continue;
        };
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
            let mut attr_quote: Option<u8> = None;
            for pos in name_end..tag_slice.len() {
                let cur = tag_slice[pos];
                if let Some(q) = attr_quote {
                    if cur == q {
                        attr_quote = None;
                    }
                    continue;
                }
                if matches!(cur, b'"' | b'\'') {
                    attr_quote = Some(cur);
                    continue;
                }
                let prev = tag_slice[pos - 1];
                let prev_delim = prev.is_ascii_whitespace() || matches!(prev, b'/' | b'"' | b'\'');
                if prev_delim
                    && pos + 3 < tag_slice.len()
                    && cur.eq_ignore_ascii_case(&b'o')
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
        if bytes[idx] == b'/' {
            let start = idx + 1;
            let mut end = start;
            while end < bytes.len() && !is_pdf_delim_or_ws(bytes[end]) && end - start <= 64 {
                end += 1;
            }
            if end > start
                && (end == bytes.len() || is_pdf_delim_or_ws(bytes[end]))
                && let Some(decoded) = decode_pdf_name_token(&bytes[start..end])
            {
                let long_active = decoded.eq_ignore_ascii_case(b"javascript")
                    || decoded.eq_ignore_ascii_case(b"launch")
                    || decoded.eq_ignore_ascii_case(b"richmedia")
                    || decoded.eq_ignore_ascii_case(b"openaction")
                    || decoded.eq_ignore_ascii_case(b"submitform")
                    || decoded.eq_ignore_ascii_case(b"importdata")
                    || decoded.eq_ignore_ascii_case(b"gotor")
                    || decoded.eq_ignore_ascii_case(b"gotoe")
                    || decoded.eq_ignore_ascii_case(b"embeddedfiles")
                    || decoded.eq_ignore_ascii_case(b"xfa");
                let js_active = decoded.as_slice() == b"JS"
                    && end < bytes.len()
                    && matches!(
                        bytes[end],
                        b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' | b'(' | b'<' | b'['
                    );
                let aa_active = decoded.as_slice() == b"AA"
                    && end < bytes.len()
                    && matches!(
                        bytes[end],
                        b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' | b'<'
                    );
                if long_active || js_active || aa_active {
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
/// invalid UTF-8 or control-byte/BiDi plain text, BOM/whitespace/mid-body HTML/XML/script polyglots,
/// active PDF script/launch/form/embedded actions, and PDF/PNG/JPEG header/trailer mismatches.
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
            if looks_like_active_markup_or_script(trimmed) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied,
                );
            }
            let body_without_single_bom = decoded.strip_prefix('\u{feff}').unwrap_or(decoded);
            if has_disallowed_control_bytes(&req.bytes)
                || has_disallowed_unicode_controls(body_without_single_bom)
            {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::InvalidUtf8Text,
                );
            }
        }
        DocumentMimeClass::ApplicationPdf => {
            if req.bytes.len() < 7
                || !req.bytes.starts_with(b"%PDF-")
                || !req.bytes[5].is_ascii_digit()
            {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
            if pdf_contains_active_action(&req.bytes) || contains_binary_polyglot_script(&req.bytes)
            {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied,
                );
            }
        }
        DocumentMimeClass::ImagePng => {
            if req.bytes.len() < 45
                || !req.bytes.starts_with(b"\x89PNG\r\n\x1a\n")
                || &req.bytes[12..16] != b"IHDR"
                || !req.bytes.ends_with(b"\x00\x00\x00\x00IEND\xaeB`\x82")
            {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
            if contains_binary_polyglot_script(&req.bytes) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied,
                );
            }
        }
        DocumentMimeClass::ImageJpeg => {
            if req.bytes.len() < 4
                || !req.bytes.starts_with(&[0xff, 0xd8, 0xff])
                || !req.bytes.ends_with(&[0xff, 0xd9])
            {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MagicHeaderMismatch,
                );
            }
            if contains_binary_polyglot_script(&req.bytes) {
                return (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied,
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

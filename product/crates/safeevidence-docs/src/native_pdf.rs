//! Pure-Rust deterministic native PDF text & Unicode scalar page-span extractor (`TA-15`).
//!
//! Security & Determinism Guarantees (`#![forbid(unsafe_code)]`):
//! 1. **Mandatory Hostile-MIME Quarantine Pre-Gate:** Every PDF byte slice MUST pass
//!    `safeevidence_contracts::document_intake::inspect_document_intake` (`application/pdf`) before
//!    any PDF object or stream is parsed. Active-content PDFs (`/JS`, `/JavaScript`, `/OpenAction`,
//!    `/AA`, `/Launch`, `/RichMedia`, `/EmbeddedFiles`, `/XFA`), polyglots, and malformed headers
//!    are refused fail-closed (`PdfExtractError::Quarantined`).
//! 2. **Bounded RFC 1950 / RFC 1951 (`FlateDecode`) Decompression:** Supports both uncompressed and
//!    zlib/deflate-compressed PDF content streams with Adler-32 integrity verification and a hard
//!    `MAX_DECOMPRESSED_STREAM_BYTES` (`16 MiB`) cap defeating zip/decompression bombs.
//! 3. **Bilingual EN/AR Text & Exact Scalar Spans:** Decodes PDF literal strings `(...)` (with
//!    octal/escape sequences), UTF-16BE hex strings `<FEFF...>` (including surrogate pairs and
//!    Arabic script), and `Tj` / `TJ` / `'` / `"` / `Td` / `TD` / `T*` operators, emitting exact
//!    half-open Unicode scalar spans `[start_scalar, end_scalar)` into `full_text` per page.
//! 4. **Scanned / Degraded PDF Abstain Gate (`TA-15`):** Pages lacking extractable text are flagged
//!    `is_scanned_or_empty = true`, and `extract_native_pdf_strict` abstains fail-closed rather
//!    than fabricating text from unverified scans.

use std::collections::{BTreeMap, BTreeSet};

use safeevidence_contracts::bilingual::is_forbidden_bidi_control;
use safeevidence_contracts::document_intake::{
    DocumentDenyReason, DocumentIntakeRequest, DocumentMimeClass, QuarantineDecision, mime_decision,
};
use safeevidence_contracts::objects::DigestSha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_PDF_INPUT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DECOMPRESSED_STREAM_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PDF_OBJECTS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PdfExtractError {
    #[error("PDF quarantined by hostile-document intake gate: {0:?}")]
    Quarantined(DocumentDenyReason),
    #[error("PDF structural parse error: {0}")]
    MalformedPdf(String),
    #[error("FlateDecode stream exceeded decompression budget or failed Adler-32 check: {0}")]
    DecompressionFailed(String),
    #[error("PDF contains zero pages")]
    NoPages,
    #[error(
        "scanned or image-only PDF page {page_number} requires verified OCR; abstaining fail-closed"
    )]
    ScannedPageRequiresOcr { page_number: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractedPdfPage {
    pub page_number: u32,
    pub text: String,
    pub start_scalar: usize,
    pub end_scalar: usize,
    pub is_scanned_or_empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractedPdfDocument {
    pub document_sha256: DigestSha256,
    pub page_count: u32,
    pub pages: Vec<ExtractedPdfPage>,
    pub full_text: String,
    pub requires_ocr_or_abstain: bool,
}

/// Strictly extracts native text from `pdf_bytes`, abstaining fail-closed if any page is a scanned
/// image lacking extractable text (`TA-15`).
pub fn extract_native_pdf_strict(
    file_name: &str,
    pdf_bytes: &[u8],
) -> Result<ExtractedPdfDocument, PdfExtractError> {
    let doc = extract_native_pdf(file_name, pdf_bytes)?;
    for page in &doc.pages {
        if page.is_scanned_or_empty {
            return Err(PdfExtractError::ScannedPageRequiresOcr {
                page_number: page.page_number,
            });
        }
    }
    Ok(doc)
}

/// Extracts deterministic page-by-page text and Unicode scalar spans from `pdf_bytes` after
/// enforcing `inspect_document_intake` hostile-PDF quarantine.
pub fn extract_native_pdf(
    file_name: &str,
    pdf_bytes: &[u8],
) -> Result<ExtractedPdfDocument, PdfExtractError> {
    if pdf_bytes.len() > MAX_PDF_INPUT_BYTES {
        return Err(PdfExtractError::Quarantined(
            DocumentDenyReason::OversizedPayload,
        ));
    }
    let (decision, reason) = mime_decision(&DocumentIntakeRequest {
        mime: DocumentMimeClass::ApplicationPdf,
        bytes: pdf_bytes.to_vec(),
        fixture_id: Some(file_name.to_owned()),
    });
    if decision != QuarantineDecision::AdmitToSandboxedParser {
        return Err(PdfExtractError::Quarantined(reason));
    }
    let raw_sha256 = DigestSha256::of(pdf_bytes);

    let objects = parse_indirect_objects(pdf_bytes)?;
    let ordered_page_ids = resolve_ordered_page_ids(&objects);
    let mut page_content_refs: Vec<Vec<u32>> = Vec::with_capacity(ordered_page_ids.len());
    for obj_num in ordered_page_ids {
        if let Some(body) = objects.get(&obj_num) {
            let header = stream_header_slice(body);
            page_content_refs.push(extract_contents_refs(header, obj_num));
        }
    }

    if page_content_refs.is_empty() {
        return Err(PdfExtractError::NoPages);
    }

    let mut pages = Vec::with_capacity(page_content_refs.len());
    let mut full_text = String::new();
    let mut cursor_scalars = 0_usize;
    let mut total_decompressed = 0_usize;
    let mut requires_ocr_or_abstain = false;

    for (idx, stream_ids) in page_content_refs.iter().enumerate() {
        let page_number = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        let mut combined_stream = Vec::new();
        for sid in stream_ids {
            if let Some(obj_bytes) = objects.get(sid)
                && let Some(decoded) = decode_object_stream(obj_bytes, &mut total_decompressed)?
            {
                if !combined_stream.is_empty() {
                    combined_stream.push(b'\n');
                }
                combined_stream.extend_from_slice(&decoded);
            }
        }
        let page_text = extract_text_from_content_stream(&combined_stream);
        if page_text.chars().any(|c| {
            is_forbidden_bidi_control(c) || (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        }) {
            return Err(PdfExtractError::Quarantined(
                DocumentDenyReason::InvalidUtf8Text,
            ));
        }
        let is_scanned_or_empty = page_text.trim().is_empty();
        if is_scanned_or_empty {
            requires_ocr_or_abstain = true;
        }
        if idx > 0 && !full_text.is_empty() && !page_text.is_empty() {
            full_text.push('\n');
            cursor_scalars += 1;
        }
        let start_scalar = cursor_scalars;
        let len_scalars = page_text.chars().count();
        full_text.push_str(&page_text);
        cursor_scalars += len_scalars;
        pages.push(ExtractedPdfPage {
            page_number,
            text: page_text,
            start_scalar,
            end_scalar: cursor_scalars,
            is_scanned_or_empty,
        });
    }

    Ok(ExtractedPdfDocument {
        document_sha256: raw_sha256,
        page_count: u32::try_from(pages.len()).unwrap_or(u32::MAX),
        pages,
        full_text,
        requires_ocr_or_abstain,
    })
}

fn parse_indirect_objects(pdf: &[u8]) -> Result<BTreeMap<u32, &[u8]>, PdfExtractError> {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < pdf.len() {
        if pdf[i].is_ascii_digit() && (i == 0 || is_pdf_ws_or_delim(pdf[i - 1])) {
            let num_start = i;
            while i < pdf.len() && pdf[i].is_ascii_digit() {
                i += 1;
            }
            let num_slice = &pdf[num_start..i];
            let ws1 = i;
            while i < pdf.len() && is_pdf_ws(pdf[i]) {
                i += 1;
            }
            if i > ws1 && i < pdf.len() && pdf[i].is_ascii_digit() {
                let gen_start = i;
                while i < pdf.len() && pdf[i].is_ascii_digit() {
                    i += 1;
                }
                let _gen_slice = &pdf[gen_start..i];
                let ws2 = i;
                while i < pdf.len() && is_pdf_ws(pdf[i]) {
                    i += 1;
                }
                if i > ws2
                    && i + 3 <= pdf.len()
                    && &pdf[i..i + 3] == b"obj"
                    && (i + 3 == pdf.len() || is_pdf_ws_or_delim(pdf[i + 3]))
                {
                    i += 3;
                    let body_start = i;
                    if let Some(rel_end) = find_subslice(&pdf[body_start..], b"endobj") {
                        let body_end = body_start + rel_end;
                        if let Ok(num_s) = std::str::from_utf8(num_slice)
                            && let Ok(obj_id) = num_s.parse::<u32>()
                        {
                            if map.len() >= MAX_PDF_OBJECTS {
                                return Err(PdfExtractError::MalformedPdf(
                                    "exceeded MAX_PDF_OBJECTS".to_owned(),
                                ));
                            }
                            map.insert(obj_id, &pdf[body_start..body_end]);
                        }
                        i = body_end + 6;
                        continue;
                    }
                }
            }
            continue;
        }
        i += 1;
    }
    Ok(map)
}

/// Locates the ISO 32000-1 §7.3.8.1 `stream` keyword strictly after a dictionary closing `>>`
/// (with optional intervening PDF whitespace/comments) and immediately followed by `\r\n` or `\n`.
/// Returns `(stream_keyword_pos, stream_data_start)`.
fn find_stream_keyword(obj_body: &[u8]) -> Option<(usize, usize)> {
    let mut idx = 0;
    while idx + 2 <= obj_body.len() {
        if &obj_body[idx..idx + 2] == b">>" {
            let mut cursor = idx + 2;
            skip_pdf_ws_and_comments(obj_body, &mut cursor);
            if cursor + 6 <= obj_body.len() && &obj_body[cursor..cursor + 6] == b"stream" {
                let after = cursor + 6;
                if after + 2 <= obj_body.len() && &obj_body[after..after + 2] == b"\r\n" {
                    return Some((cursor, after + 2));
                }
                if after < obj_body.len() && obj_body[after] == b'\n' {
                    return Some((cursor, after + 1));
                }
            }
        }
        idx += 1;
    }
    None
}

fn stream_header_slice(obj_body: &[u8]) -> &[u8] {
    match find_stream_keyword(obj_body) {
        Some((pos, _)) => &obj_body[..pos],
        None => obj_body,
    }
}

fn dict_has_type(dict_bytes: &[u8], expected: &[u8]) -> bool {
    let mut i = 0;
    while i + 5 <= dict_bytes.len() {
        if &dict_bytes[i..i + 5] == b"/Type" && is_pdf_ws_or_delim(dict_bytes[i + 5]) {
            let mut j = i + 5;
            skip_pdf_ws_and_comments(dict_bytes, &mut j);
            if j + expected.len() <= dict_bytes.len()
                && &dict_bytes[j..j + expected.len()] == expected
                && (j + expected.len() == dict_bytes.len()
                    || is_pdf_ws_or_delim(dict_bytes[j + expected.len()]))
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_page_object_dict(dict_bytes: &[u8]) -> bool {
    dict_has_type(dict_bytes, b"/Page")
}

fn is_pages_tree_dict(dict_bytes: &[u8]) -> bool {
    dict_has_type(dict_bytes, b"/Pages")
}

fn is_catalog_dict(dict_bytes: &[u8]) -> bool {
    dict_has_type(dict_bytes, b"/Catalog")
}

fn extract_key_refs(dict_bytes: &[u8], key: &[u8]) -> Option<Vec<u32>> {
    let mut search_from = 0;
    while search_from + key.len() <= dict_bytes.len() {
        let rel = find_subslice(&dict_bytes[search_from..], key)?;
        let pos = search_from + rel;
        let after = pos + key.len();
        if after == dict_bytes.len() || is_pdf_ws_or_delim(dict_bytes[after]) {
            let mut i = after;
            skip_pdf_ws_and_comments(dict_bytes, &mut i);
            if i >= dict_bytes.len() {
                return Some(Vec::new());
            }
            if dict_bytes[i] == b'[' {
                let end = find_subslice(&dict_bytes[i + 1..], b"]")
                    .map(|r| i + 1 + r)
                    .unwrap_or(dict_bytes.len());
                return Some(parse_obj_refs_in_slice(&dict_bytes[i + 1..end]));
            }
            let refs = parse_obj_refs_in_slice(&dict_bytes[i..]);
            return Some(refs.into_iter().take(1).collect());
        }
        search_from = pos + 1;
    }
    None
}

fn walk_pages_tree(
    node_id: u32,
    objects: &BTreeMap<u32, &[u8]>,
    visited: &mut BTreeSet<u32>,
    ordered: &mut Vec<u32>,
) {
    if !visited.insert(node_id) {
        return;
    }
    let Some(body) = objects.get(&node_id) else {
        return;
    };
    let header = stream_header_slice(body);
    if is_page_object_dict(header) {
        ordered.push(node_id);
        return;
    }
    if is_pages_tree_dict(header)
        && let Some(kids) = extract_key_refs(header, b"/Kids")
    {
        for kid in kids {
            walk_pages_tree(kid, objects, visited, ordered);
        }
    }
}

fn resolve_ordered_page_ids(objects: &BTreeMap<u32, &[u8]>) -> Vec<u32> {
    let mut ordered = Vec::new();
    let mut visited = BTreeSet::new();
    for body in objects.values() {
        let header = stream_header_slice(body);
        if is_catalog_dict(header)
            && let Some(pages_roots) = extract_key_refs(header, b"/Pages")
        {
            for root_id in pages_roots {
                walk_pages_tree(root_id, objects, &mut visited, &mut ordered);
            }
        }
    }
    if ordered.is_empty() {
        for (&obj_id, body) in objects {
            let header = stream_header_slice(body);
            if is_pages_tree_dict(header) && extract_key_refs(header, b"/Parent").is_none() {
                walk_pages_tree(obj_id, objects, &mut visited, &mut ordered);
            }
        }
    }
    for (&obj_id, body) in objects {
        if !visited.contains(&obj_id) && is_page_object_dict(stream_header_slice(body)) {
            ordered.push(obj_id);
        }
    }
    ordered
}

fn extract_contents_refs(dict_bytes: &[u8], self_obj: u32) -> Vec<u32> {
    extract_key_refs(dict_bytes, b"/Contents").unwrap_or_else(|| vec![self_obj])
}

fn parse_obj_refs_in_slice(slice: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < slice.len() {
        if slice[i].is_ascii_digit() {
            let s1 = i;
            while i < slice.len() && slice[i].is_ascii_digit() {
                i += 1;
            }
            let n_str = std::str::from_utf8(&slice[s1..i]).unwrap_or("");
            let ws1 = i;
            while i < slice.len() && is_pdf_ws(slice[i]) {
                i += 1;
            }
            if i > ws1 && i < slice.len() && slice[i].is_ascii_digit() {
                while i < slice.len() && slice[i].is_ascii_digit() {
                    i += 1;
                }
                let ws2 = i;
                while i < slice.len() && is_pdf_ws(slice[i]) {
                    i += 1;
                }
                if i > ws2
                    && i < slice.len()
                    && slice[i] == b'R'
                    && (i + 1 == slice.len() || is_pdf_ws_or_delim(slice[i + 1]))
                {
                    if let Ok(id) = n_str.parse::<u32>() {
                        out.push(id);
                    }
                    i += 1;
                    continue;
                }
            }
            continue;
        }
        if slice[i] == b'/' || slice[i] == b'>' {
            break;
        }
        i += 1;
    }
    out
}

fn find_pdf_dict_key(header: &[u8], key: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + key.len() <= header.len() {
        if &header[i..i + key.len()] == key
            && (i == 0 || is_pdf_ws_or_delim(header[i - 1]))
            && (i + key.len() == header.len() || is_pdf_ws_or_delim(header[i + key.len()]))
        {
            return Some(i + key.len());
        }
        i += 1;
    }
    None
}

fn read_pdf_name_token<'a>(bytes: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    skip_pdf_ws_and_comments(bytes, i);
    if *i >= bytes.len() || bytes[*i] != b'/' {
        return None;
    }
    let start = *i;
    *i += 1;
    while *i < bytes.len() && !is_pdf_ws_or_delim(bytes[*i]) {
        *i += 1;
    }
    Some(&bytes[start..*i])
}

/// Validates stream `/Filter` and `/DecodeParms` dictionary entries fail-closed (`TA-15`):
/// - Rejects `/DecodeParms` or `/DP` (e.g. PNG/TIFF predictors).
/// - Admits uncompressed streams (no `/Filter` / `/F`, or empty `[]`) as `Ok(false)`.
/// - Admits single `/FlateDecode` / `/Fl` (or `[/FlateDecode]` / `[/Fl]`) as `Ok(true)`.
/// - Rejects any other `/Filter` (`/ASCII85Decode`, `/LZWDecode`, `/Crypt`, multi-filter pipelines)
///   with `Err(PdfExtractError::MalformedPdf(...))`.
fn classify_stream_filters(header: &[u8]) -> Result<bool, PdfExtractError> {
    if find_pdf_dict_key(header, b"/DecodeParms").is_some()
        || find_pdf_dict_key(header, b"/DP").is_some()
    {
        return Err(PdfExtractError::MalformedPdf(
            "unsupported stream /DecodeParms".to_owned(),
        ));
    }
    let filter_val_pos =
        find_pdf_dict_key(header, b"/Filter").or_else(|| find_pdf_dict_key(header, b"/F"));
    let Some(mut pos) = filter_val_pos else {
        return Ok(false);
    };
    skip_pdf_ws_and_comments(header, &mut pos);
    if pos >= header.len() {
        return Err(PdfExtractError::MalformedPdf(
            "truncated stream /Filter".to_owned(),
        ));
    }
    if header[pos] == b'/' {
        let name = read_pdf_name_token(header, &mut pos).unwrap_or(b"");
        if name == b"/FlateDecode" || name == b"/Fl" {
            return Ok(true);
        }
        return Err(PdfExtractError::MalformedPdf(format!(
            "unsupported stream /Filter {}",
            String::from_utf8_lossy(name)
        )));
    }
    if header[pos] == b'[' {
        pos += 1;
        skip_pdf_ws_and_comments(header, &mut pos);
        if pos < header.len() && header[pos] == b']' {
            return Ok(false);
        }
        let Some(name) = read_pdf_name_token(header, &mut pos) else {
            return Err(PdfExtractError::MalformedPdf(
                "malformed stream /Filter array".to_owned(),
            ));
        };
        if name != b"/FlateDecode" && name != b"/Fl" {
            return Err(PdfExtractError::MalformedPdf(format!(
                "unsupported stream /Filter {}",
                String::from_utf8_lossy(name)
            )));
        }
        skip_pdf_ws_and_comments(header, &mut pos);
        if pos >= header.len() || header[pos] != b']' {
            return Err(PdfExtractError::MalformedPdf(
                "multi-stage stream /Filter pipeline unsupported".to_owned(),
            ));
        }
        return Ok(true);
    }
    Err(PdfExtractError::MalformedPdf(
        "unsupported stream /Filter value".to_owned(),
    ))
}

fn decode_object_stream(
    obj_body: &[u8],
    total_decompressed: &mut usize,
) -> Result<Option<Vec<u8>>, PdfExtractError> {
    let Some((s_pos, data_start)) = find_stream_keyword(obj_body) else {
        return Ok(None);
    };
    let header = &obj_body[..s_pos];
    let Some(rel_end) = find_subslice(&obj_body[data_start..], b"endstream") else {
        return Err(PdfExtractError::MalformedPdf(
            "stream missing endstream".to_owned(),
        ));
    };
    let mut raw_stream = &obj_body[data_start..data_start + rel_end];
    if raw_stream.ends_with(b"\r\n") {
        raw_stream = &raw_stream[..raw_stream.len() - 2];
    } else if raw_stream.ends_with(b"\n") || raw_stream.ends_with(b"\r") {
        raw_stream = &raw_stream[..raw_stream.len() - 1];
    }

    let is_flate = classify_stream_filters(header)?;
    let decoded = if is_flate {
        zlib_decompress_bounded(
            raw_stream,
            MAX_DECOMPRESSED_STREAM_BYTES - *total_decompressed,
        )?
    } else {
        if raw_stream.len() > MAX_DECOMPRESSED_STREAM_BYTES - *total_decompressed {
            return Err(PdfExtractError::DecompressionFailed(
                "uncompressed stream exceeds budget".to_owned(),
            ));
        }
        raw_stream.to_vec()
    };
    *total_decompressed += decoded.len();
    Ok(Some(decoded))
}

fn extract_text_from_content_stream(stream: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let mut pending_strings: Vec<String> = Vec::new();

    while i < stream.len() {
        skip_pdf_ws_and_comments(stream, &mut i);
        if i >= stream.len() {
            break;
        }
        match stream[i] {
            b'(' => {
                let s = parse_pdf_literal_string(stream, &mut i);
                pending_strings.push(s);
            }
            b'<' if i + 1 < stream.len() && stream[i + 1] != b'<' => {
                let s = parse_pdf_hex_string(stream, &mut i);
                pending_strings.push(s);
            }
            b'<' => {
                i += 2;
            }
            b'>' if i + 1 < stream.len() && stream[i + 1] == b'>' => {
                i += 2;
            }
            b'[' => {
                let arr_text = parse_tj_array(stream, &mut i);
                pending_strings.clear();
                pending_strings.push(arr_text);
            }
            b'/' => {
                i += 1;
                while i < stream.len() && !is_pdf_ws_or_delim(stream[i]) {
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                if let Some(s) = pending_strings.pop() {
                    out.push_str(&s);
                }
                pending_strings.clear();
            }
            b'"' => {
                i += 1;
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                if let Some(s) = pending_strings.pop() {
                    out.push_str(&s);
                }
                pending_strings.clear();
            }
            _ => {
                let start = i;
                while i < stream.len() && !is_pdf_ws_or_delim(stream[i]) {
                    i += 1;
                }
                let tok = &stream[start..i];
                match tok {
                    b"Tj" => {
                        if let Some(s) = pending_strings.pop() {
                            out.push_str(&s);
                        }
                        pending_strings.clear();
                    }
                    b"TJ" => {
                        if let Some(s) = pending_strings.pop() {
                            out.push_str(&s);
                        }
                        pending_strings.clear();
                    }
                    b"T*" | b"Td" | b"TD" => {
                        if !out.is_empty() && !out.ends_with('\n') && !out.ends_with(' ') {
                            out.push('\n');
                        }
                        pending_strings.clear();
                    }
                    b"ET" => {
                        if !out.is_empty() && !out.ends_with('\n') {
                            out.push('\n');
                        }
                        pending_strings.clear();
                    }
                    _ => {}
                }
            }
        }
    }
    out.trim().to_owned()
}

fn parse_tj_array(stream: &[u8], i: &mut usize) -> String {
    *i += 1; // '['
    let mut acc = String::new();
    while *i < stream.len() {
        skip_pdf_ws_and_comments(stream, i);
        if *i >= stream.len() {
            break;
        }
        match stream[*i] {
            b']' => {
                *i += 1;
                break;
            }
            b'(' => acc.push_str(&parse_pdf_literal_string(stream, i)),
            b'<' if *i + 1 < stream.len() && stream[*i + 1] != b'<' => {
                acc.push_str(&parse_pdf_hex_string(stream, i));
            }
            b'-' | b'+' | b'.' | b'0'..=b'9' => {
                let start = *i;
                *i += 1;
                while *i < stream.len() && (stream[*i].is_ascii_digit() || stream[*i] == b'.') {
                    *i += 1;
                }
                if let Ok(num_s) = std::str::from_utf8(&stream[start..*i])
                    && let Ok(val) = num_s.parse::<f64>()
                    && val <= -120.0
                    && !acc.ends_with(' ')
                {
                    acc.push(' ');
                }
            }
            _ => {
                *i += 1;
            }
        }
    }
    acc
}

fn parse_pdf_literal_string(stream: &[u8], i: &mut usize) -> String {
    *i += 1; // '('
    let mut depth = 1_usize;
    let mut bytes = Vec::new();
    while *i < stream.len() && depth > 0 {
        let b = stream[*i];
        *i += 1;
        match b {
            b'\\' => {
                if *i >= stream.len() {
                    break;
                }
                let esc = stream[*i];
                *i += 1;
                match esc {
                    b'n' => bytes.push(b'\n'),
                    b'r' => bytes.push(b'\r'),
                    b't' => bytes.push(b'\t'),
                    b'b' => bytes.push(0x08),
                    b'f' => bytes.push(0x0c),
                    b'(' => bytes.push(b'('),
                    b')' => bytes.push(b')'),
                    b'\\' => bytes.push(b'\\'),
                    b'\r' => {
                        if *i < stream.len() && stream[*i] == b'\n' {
                            *i += 1;
                        }
                    }
                    b'\n' => {}
                    b'0'..=b'7' => {
                        let mut oct = u32::from(esc - b'0');
                        for _ in 0..2 {
                            if *i < stream.len() && (b'0'..=b'7').contains(&stream[*i]) {
                                oct = (oct << 3) | u32::from(stream[*i] - b'0');
                                *i += 1;
                            } else {
                                break;
                            }
                        }
                        bytes.push((oct & 0xff) as u8);
                    }
                    other => bytes.push(other),
                }
            }
            b'(' => {
                depth += 1;
                bytes.push(b'(');
            }
            b')' => {
                depth -= 1;
                if depth > 0 {
                    bytes.push(b')');
                }
            }
            other => bytes.push(other),
        }
    }
    decode_pdf_string_bytes(&bytes)
}

fn parse_pdf_hex_string(stream: &[u8], i: &mut usize) -> String {
    *i += 1; // '<'
    let mut nibbles = Vec::new();
    while *i < stream.len() {
        let b = stream[*i];
        *i += 1;
        if b == b'>' {
            break;
        }
        if is_pdf_ws(b) {
            continue;
        }
        if let Some(d) = (b as char).to_digit(16) {
            nibbles.push(d as u8);
        }
    }
    if !nibbles.len().is_multiple_of(2) {
        nibbles.push(0);
    }
    let mut bytes = Vec::with_capacity(nibbles.len() / 2);
    for &[hi, lo] in nibbles.as_chunks::<2>().0 {
        bytes.push((hi << 4) | lo);
    }
    decode_pdf_string_bytes(&bytes)
}

fn decode_pdf_string_bytes(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let body = &bytes[2..];
        let mut units = Vec::with_capacity(body.len() / 2);
        for &[hi, lo] in body.as_chunks::<2>().0 {
            units.push(u16::from_be_bytes([hi, lo]));
        }
        return String::from_utf16_lossy(&units);
    }
    if let Ok(utf8) = std::str::from_utf8(bytes) {
        return utf8.to_owned();
    }
    bytes.iter().map(|&b| char::from(b)).collect()
}

fn skip_pdf_ws_and_comments(bytes: &[u8], i: &mut usize) {
    loop {
        while *i < bytes.len() && is_pdf_ws(bytes[*i]) {
            *i += 1;
        }
        if *i < bytes.len() && bytes[*i] == b'%' {
            while *i < bytes.len() && bytes[*i] != b'\n' && bytes[*i] != b'\r' {
                *i += 1;
            }
            continue;
        }
        break;
    }
}

fn is_pdf_ws(b: u8) -> bool {
    matches!(b, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

fn is_pdf_ws_or_delim(b: u8) -> bool {
    is_pdf_ws(b)
        || matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- Pure Safe-Rust RFC 1950 / RFC 1951 Zlib + Deflate Decompressor (Bounded + Adler-32) ---

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Result<u32, PdfExtractError> {
        if self.byte_pos >= self.data.len() {
            return Err(PdfExtractError::DecompressionFailed(
                "truncated deflate bitstream".to_owned(),
            ));
        }
        let bit = u32::from((self.data[self.byte_pos] >> self.bit_pos) & 1);
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Ok(bit)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32, PdfExtractError> {
        let mut val = 0_u32;
        for shift in 0..count {
            val |= self.read_bit()? << shift;
        }
        Ok(val)
    }

    fn align_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn read_u16_le(&mut self) -> Result<u16, PdfExtractError> {
        self.align_byte();
        if self.byte_pos + 2 > self.data.len() {
            return Err(PdfExtractError::DecompressionFailed(
                "truncated stored block header".to_owned(),
            ));
        }
        let val = u16::from_le_bytes([self.data[self.byte_pos], self.data[self.byte_pos + 1]]);
        self.byte_pos += 2;
        Ok(val)
    }
}

struct HuffmanTree {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl HuffmanTree {
    fn build(lengths: &[u8]) -> Result<Self, PdfExtractError> {
        let mut counts = [0_u16; 16];
        for &len in lengths {
            if usize::from(len) > 15 {
                return Err(PdfExtractError::DecompressionFailed(
                    "invalid Huffman code length".to_owned(),
                ));
            }
            if len > 0 {
                counts[usize::from(len)] += 1;
            }
        }
        let mut kraft_used = 0_u32;
        for (bits, &count) in counts.iter().enumerate().skip(1) {
            kraft_used = kraft_used.saturating_add(u32::from(count) << (15 - bits));
        }
        if kraft_used > (1_u32 << 15) {
            return Err(PdfExtractError::DecompressionFailed(
                "oversubscribed Huffman code lengths violate Kraft inequality".to_owned(),
            ));
        }
        let mut offsets = [0_u16; 16];
        let mut total = 0_u16;
        for bits in 1..=15 {
            offsets[bits] = total;
            total = total.saturating_add(counts[bits]);
        }
        let mut symbols = vec![0_u16; usize::from(total)];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let idx = usize::from(offsets[usize::from(len)]);
                offsets[usize::from(len)] += 1;
                symbols[idx] = sym as u16;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, PdfExtractError> {
        let mut code = 0_i32;
        let mut first = 0_i32;
        let mut index = 0_i32;
        for len in 1..=15 {
            code |= reader.read_bit()? as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                let sym_idx = (index + (code - first)) as usize;
                return self.symbols.get(sym_idx).copied().ok_or_else(|| {
                    PdfExtractError::DecompressionFailed("Huffman symbol out of range".to_owned())
                });
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(PdfExtractError::DecompressionFailed(
            "invalid Huffman prefix code".to_owned(),
        ))
    }
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

pub fn zlib_decompress_bounded(input: &[u8], max_out: usize) -> Result<Vec<u8>, PdfExtractError> {
    if input.len() < 6 {
        return Err(PdfExtractError::DecompressionFailed(
            "zlib stream shorter than 6 bytes".to_owned(),
        ));
    }
    let cmf = input[0];
    let flg = input[1];
    let header_word = (u16::from(cmf) << 8) | u16::from(flg);
    if (cmf & 0x0f) != 8 || (cmf >> 4) > 7 || !header_word.is_multiple_of(31) || (flg & 0x20) != 0 {
        return Err(PdfExtractError::DecompressionFailed(
            "invalid RFC 1950 zlib header".to_owned(),
        ));
    }

    let mut reader = BitReader::new(&input[2..]);
    let mut out = Vec::new();

    const LEN_BASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LEN_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST_BASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    const CL_ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    loop {
        let bfinal = reader.read_bit()?;
        let btype = reader.read_bits(2)?;
        match btype {
            0 => {
                let len = usize::from(reader.read_u16_le()?);
                let nlen = usize::from(reader.read_u16_le()?);
                if (len ^ 0xffff) != nlen {
                    return Err(PdfExtractError::DecompressionFailed(
                        "stored block LEN/NLEN mismatch".to_owned(),
                    ));
                }
                if out.len().saturating_add(len) > max_out {
                    return Err(PdfExtractError::DecompressionFailed(
                        "decompression budget exceeded".to_owned(),
                    ));
                }
                if reader.byte_pos + len > reader.data.len() {
                    return Err(PdfExtractError::DecompressionFailed(
                        "truncated stored block payload".to_owned(),
                    ));
                }
                out.extend_from_slice(&reader.data[reader.byte_pos..reader.byte_pos + len]);
                reader.byte_pos += len;
            }
            1 | 2 => {
                let (lit_tree, dist_tree) = if btype == 1 {
                    let mut lit_lens = vec![0_u8; 288];
                    lit_lens[..=143].fill(8);
                    lit_lens[144..=255].fill(9);
                    lit_lens[256..=279].fill(7);
                    lit_lens[280..=287].fill(8);
                    let dist_lens = vec![5_u8; 32];
                    (
                        HuffmanTree::build(&lit_lens)?,
                        HuffmanTree::build(&dist_lens)?,
                    )
                } else {
                    let hlit = reader.read_bits(5)? as usize + 257;
                    let hdist = reader.read_bits(5)? as usize + 1;
                    let hclen = reader.read_bits(4)? as usize + 4;
                    let mut cl_lens = [0_u8; 19];
                    for idx in 0..hclen {
                        cl_lens[CL_ORDER[idx]] = reader.read_bits(3)? as u8;
                    }
                    let cl_tree = HuffmanTree::build(&cl_lens)?;
                    let mut all_lens = Vec::with_capacity(hlit + hdist);
                    while all_lens.len() < hlit + hdist {
                        let sym = cl_tree.decode(&mut reader)?;
                        match sym {
                            0..=15 => all_lens.push(sym as u8),
                            16 => {
                                let prev = *all_lens.last().ok_or_else(|| {
                                    PdfExtractError::DecompressionFailed(
                                        "repeat code with no previous length".to_owned(),
                                    )
                                })?;
                                let rep = reader.read_bits(2)? as usize + 3;
                                for _ in 0..rep {
                                    all_lens.push(prev);
                                }
                            }
                            17 => {
                                let rep = reader.read_bits(3)? as usize + 3;
                                all_lens.resize(all_lens.len() + rep, 0);
                            }
                            18 => {
                                let rep = reader.read_bits(7)? as usize + 11;
                                all_lens.resize(all_lens.len() + rep, 0);
                            }
                            _ => {
                                return Err(PdfExtractError::DecompressionFailed(
                                    "invalid code-length symbol".to_owned(),
                                ));
                            }
                        }
                    }
                    if all_lens.len() != hlit + hdist {
                        return Err(PdfExtractError::DecompressionFailed(
                            "code-length table overflow".to_owned(),
                        ));
                    }
                    (
                        HuffmanTree::build(&all_lens[..hlit])?,
                        HuffmanTree::build(&all_lens[hlit..])?,
                    )
                };

                loop {
                    let sym = lit_tree.decode(&mut reader)?;
                    if sym < 256 {
                        if out.len() + 1 > max_out {
                            return Err(PdfExtractError::DecompressionFailed(
                                "decompression budget exceeded".to_owned(),
                            ));
                        }
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        let l_idx = usize::from(sym - 257);
                        if l_idx >= LEN_BASE.len() {
                            return Err(PdfExtractError::DecompressionFailed(
                                "invalid length code".to_owned(),
                            ));
                        }
                        let copy_len = usize::from(LEN_BASE[l_idx])
                            + reader.read_bits(LEN_EXTRA[l_idx])? as usize;
                        let d_sym = usize::from(dist_tree.decode(&mut reader)?);
                        if d_sym >= DIST_BASE.len() {
                            return Err(PdfExtractError::DecompressionFailed(
                                "invalid distance code".to_owned(),
                            ));
                        }
                        let dist = usize::from(DIST_BASE[d_sym])
                            + reader.read_bits(DIST_EXTRA[d_sym])? as usize;
                        if dist == 0 || dist > out.len() {
                            return Err(PdfExtractError::DecompressionFailed(
                                "LZ77 distance exceeds window".to_owned(),
                            ));
                        }
                        if out.len().saturating_add(copy_len) > max_out {
                            return Err(PdfExtractError::DecompressionFailed(
                                "decompression budget exceeded".to_owned(),
                            ));
                        }
                        for _ in 0..copy_len {
                            let b = out[out.len() - dist];
                            out.push(b);
                        }
                    }
                }
            }
            _ => {
                return Err(PdfExtractError::DecompressionFailed(
                    "reserved deflate block type 3".to_owned(),
                ));
            }
        }
        if bfinal == 1 {
            break;
        }
    }

    reader.align_byte();
    if reader.byte_pos + 4 > reader.data.len() {
        return Err(PdfExtractError::DecompressionFailed(
            "missing Adler-32 trailer".to_owned(),
        ));
    }
    let expected_adler = u32::from_be_bytes([
        reader.data[reader.byte_pos],
        reader.data[reader.byte_pos + 1],
        reader.data[reader.byte_pos + 2],
        reader.data[reader.byte_pos + 3],
    ]);
    if adler32(&out) != expected_adler {
        return Err(PdfExtractError::DecompressionFailed(
            "Adler-32 checksum mismatch".to_owned(),
        ));
    }
    Ok(out)
}

/// Helper for tests: wraps raw bytes in a valid RFC 1950 zlib stored-block container.
#[must_use]
pub fn zlib_compress_stored(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01]; // CMF=0x78 (deflate, 32K), FLG=0x01 (check bits valid: 0x7801 % 31 == 0)
    if payload.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    } else {
        let chunks: Vec<&[u8]> = payload.chunks(65_535).collect();
        for (idx, chunk) in chunks.iter().enumerate() {
            let bfinal = u8::from(idx + 1 == chunks.len());
            out.push(bfinal); // BFINAL | (BTYPE=00 << 1)
            let len = chunk.len() as u16;
            let nlen = !len;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }
    out.extend_from_slice(&adler32(payload).to_be_bytes());
    out
}

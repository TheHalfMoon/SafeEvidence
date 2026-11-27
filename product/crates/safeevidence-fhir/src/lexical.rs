//! Fail-closed lexical & research-scope checks for FHIR R4 JSON interchange (`ADM-0017` / `T09`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-fhir/src/lexical.rs`)
//! under Apache-2.0 (`ADR-0004`). Enforces `FhirUsageScope::SyntheticResearchFixture` (`ADR-0003`:
//! live clinical patient context is refused fail-closed).

use std::collections::HashSet;

use safeevidence_contracts::FHIR_R4_VERSION;
use safeevidence_contracts::fhir::FhirUsageScope;
use serde_json::Value;
use thiserror::Error;

use crate::{MAX_INGEST_BYTES, MAX_JSON_DEPTH};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LexicalError {
    #[error(
        "live clinical patient context is forbidden in SafeEvidence V1 research scope (ADR-0003)"
    )]
    LiveClinicalPatientForbidden,
    #[error("payload exceeds size limit")]
    TooLarge,
    #[error("truncated or invalid JSON: {0}")]
    InvalidJson(String),
    #[error("duplicate object key: {0}")]
    DuplicateKey(String),
    #[error("JSON nesting too deep")]
    TooDeep,
    #[error("silent f64 clinical decimal coercion forbidden")]
    UnsafeDecimal,
    #[error("FHIR version not admitted: {0:?}")]
    Version(Option<String>),
    #[error("media type must be application/fhir+json")]
    MediaType,
    #[error("missing resourceType")]
    MissingResourceType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalReport {
    pub resource_type: String,
    pub fhir_version: String,
}

/// Runs lexical, structural, and `ADR-0003` research-scope gate on exact bytes.
pub fn gate_fhir_json_scoped(
    scope: FhirUsageScope,
    media_type: &str,
    bytes: &[u8],
    version_hint: Option<&str>,
) -> Result<LexicalReport, LexicalError> {
    if scope == FhirUsageScope::LiveClinicalPatientForbidden {
        return Err(LexicalError::LiveClinicalPatientForbidden);
    }
    gate_fhir_json(media_type, bytes, version_hint)
}

/// Runs lexical/structural gate for synthetic research FHIR R4 JSON fixtures.
pub fn gate_fhir_json(
    media_type: &str,
    bytes: &[u8],
    version_hint: Option<&str>,
) -> Result<LexicalReport, LexicalError> {
    if media_type != "application/fhir+json" {
        return Err(LexicalError::MediaType);
    }
    if bytes.len() > MAX_INGEST_BYTES {
        return Err(LexicalError::TooLarge);
    }
    reject_duplicate_keys(bytes)?;
    reject_unsafe_decimals(bytes)?;

    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| LexicalError::InvalidJson(e.to_string()))?;
    check_depth(&value, 0)?;

    let resource_type = value
        .get("resourceType")
        .and_then(Value::as_str)
        .ok_or(LexicalError::MissingResourceType)?
        .to_owned();

    let declared = value
        .get("fhirVersion")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| version_hint.map(str::to_owned));

    let fhir_version = match declared.as_deref() {
        None => FHIR_R4_VERSION.to_owned(),
        Some(v) if v == FHIR_R4_VERSION => v.to_owned(),
        Some(_) => return Err(LexicalError::Version(declared)),
    };

    Ok(LexicalReport {
        resource_type,
        fhir_version,
    })
}

/// Extract `Patient.identifier` pairs from synthetic research fixtures (no identity merge).
/// Enforces `gate_fhir_json` (`MAX_INGEST_BYTES`, `reject_duplicate_keys`, `MAX_JSON_DEPTH`)
/// before inspecting JSON fields.
#[must_use]
pub fn extract_patient_identifiers(bytes: &[u8]) -> Vec<(String, String)> {
    if gate_fhir_json("application/fhir+json", bytes, None).is_err() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_identifiers(&value, &mut out);
    if value.get("resourceType").and_then(Value::as_str) == Some("Bundle")
        && let Some(entries) = value.get("entry").and_then(Value::as_array)
    {
        for entry in entries {
            if let Some(resource) = entry.get("resource") {
                collect_identifiers(resource, &mut out);
            }
        }
    }
    out
}

fn collect_identifiers(value: &Value, out: &mut Vec<(String, String)>) {
    if value.get("resourceType").and_then(Value::as_str) != Some("Patient") {
        return;
    }
    let Some(ids) = value.get("identifier").and_then(Value::as_array) else {
        return;
    };
    for id in ids {
        let system = id
            .get("system")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let val = id
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if !system.is_empty() && !val.is_empty() {
            out.push((system, val));
        }
    }
}

fn check_depth(value: &Value, depth: usize) -> Result<(), LexicalError> {
    if depth > MAX_JSON_DEPTH {
        return Err(LexicalError::TooDeep);
    }
    match value {
        Value::Array(items) => {
            for item in items {
                check_depth(item, depth + 1)?;
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                check_depth(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), LexicalError> {
    let text = std::str::from_utf8(bytes).map_err(|e| LexicalError::InvalidJson(e.to_string()))?;
    let mut i = 0;
    let chars: Vec<char> = text.chars().collect();
    scan_value(&chars, &mut i, 0)?;
    skip_ws(&chars, &mut i);
    if i != chars.len() {
        return Err(LexicalError::InvalidJson("trailing content".to_owned()));
    }
    Ok(())
}

fn skip_ws(chars: &[char], i: &mut usize) {
    while *i < chars.len() && chars[*i].is_whitespace() {
        *i += 1;
    }
}

fn scan_value(chars: &[char], i: &mut usize, depth: usize) -> Result<(), LexicalError> {
    if depth > MAX_JSON_DEPTH {
        return Err(LexicalError::TooDeep);
    }
    skip_ws(chars, i);
    if *i >= chars.len() {
        return Err(LexicalError::InvalidJson("unexpected end".to_owned()));
    }
    match chars[*i] {
        '{' => scan_object(chars, i, depth + 1),
        '[' => scan_array(chars, i, depth + 1),
        '"' => {
            scan_string(chars, i)?;
            Ok(())
        }
        't' | 'f' | 'n' | '-' | '0'..='9' => scan_literal_or_number(chars, i),
        other => Err(LexicalError::InvalidJson(format!("unexpected {other}"))),
    }
}

fn scan_object(chars: &[char], i: &mut usize, depth: usize) -> Result<(), LexicalError> {
    *i += 1;
    let mut keys = HashSet::new();
    skip_ws(chars, i);
    if *i < chars.len() && chars[*i] == '}' {
        *i += 1;
        return Ok(());
    }
    loop {
        skip_ws(chars, i);
        let key = scan_string(chars, i)?;
        if !keys.insert(key.clone()) {
            return Err(LexicalError::DuplicateKey(key));
        }
        skip_ws(chars, i);
        if *i >= chars.len() || chars[*i] != ':' {
            return Err(LexicalError::InvalidJson("expected ':'".to_owned()));
        }
        *i += 1;
        scan_value(chars, i, depth)?;
        skip_ws(chars, i);
        if *i >= chars.len() {
            return Err(LexicalError::InvalidJson("unterminated object".to_owned()));
        }
        match chars[*i] {
            ',' => {
                *i += 1;
                continue;
            }
            '}' => {
                *i += 1;
                return Ok(());
            }
            _ => return Err(LexicalError::InvalidJson("expected ',' or '}'".to_owned())),
        }
    }
}

fn scan_array(chars: &[char], i: &mut usize, depth: usize) -> Result<(), LexicalError> {
    *i += 1;
    skip_ws(chars, i);
    if *i < chars.len() && chars[*i] == ']' {
        *i += 1;
        return Ok(());
    }
    loop {
        scan_value(chars, i, depth)?;
        skip_ws(chars, i);
        if *i >= chars.len() {
            return Err(LexicalError::InvalidJson("unterminated array".to_owned()));
        }
        match chars[*i] {
            ',' => {
                *i += 1;
                continue;
            }
            ']' => {
                *i += 1;
                return Ok(());
            }
            _ => return Err(LexicalError::InvalidJson("expected ',' or ']'".to_owned())),
        }
    }
}

fn scan_string(chars: &[char], i: &mut usize) -> Result<String, LexicalError> {
    if *i >= chars.len() || chars[*i] != '"' {
        return Err(LexicalError::InvalidJson("expected string".to_owned()));
    }
    *i += 1;
    let mut out = String::new();
    while *i < chars.len() {
        let c = chars[*i];
        *i += 1;
        if (c as u32) < 0x20 {
            return Err(LexicalError::InvalidJson(
                "unescaped control character in string".to_owned(),
            ));
        }
        match c {
            '"' => return Ok(out),
            '\\' => {
                if *i >= chars.len() {
                    return Err(LexicalError::InvalidJson("bad escape".to_owned()));
                }
                let esc = chars[*i];
                *i += 1;
                match esc {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        if *i + 4 > chars.len() {
                            return Err(LexicalError::InvalidJson("short \\u escape".to_owned()));
                        }
                        let hex_s: String = chars[*i..*i + 4].iter().collect();
                        *i += 4;
                        let code = u32::from_str_radix(&hex_s, 16)
                            .map_err(|_| LexicalError::InvalidJson("bad \\u hex".to_owned()))?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            if *i + 6 > chars.len() || chars[*i] != '\\' || chars[*i + 1] != 'u' {
                                return Err(LexicalError::InvalidJson(
                                    "unpaired high surrogate".to_owned(),
                                ));
                            }
                            let lo_hex: String = chars[*i + 2..*i + 6].iter().collect();
                            *i += 6;
                            let lo = u32::from_str_radix(&lo_hex, 16)
                                .map_err(|_| LexicalError::InvalidJson("bad \\u hex".to_owned()))?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err(LexicalError::InvalidJson(
                                    "invalid low surrogate".to_owned(),
                                ));
                            }
                            let scalar = 0x1_0000 + ((code - 0xD800) << 10) + (lo - 0xDC00);
                            let decoded = char::from_u32(scalar).ok_or_else(|| {
                                LexicalError::InvalidJson("invalid surrogate scalar".to_owned())
                            })?;
                            out.push(decoded);
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            return Err(LexicalError::InvalidJson(
                                "unpaired low surrogate".to_owned(),
                            ));
                        } else {
                            let decoded = char::from_u32(code).ok_or_else(|| {
                                LexicalError::InvalidJson("invalid \\u scalar".to_owned())
                            })?;
                            out.push(decoded);
                        }
                    }
                    other => {
                        return Err(LexicalError::InvalidJson(format!(
                            "invalid escape \\{other}"
                        )));
                    }
                }
            }
            _ => out.push(c),
        }
    }
    Err(LexicalError::InvalidJson("unterminated string".to_owned()))
}

fn scan_literal_or_number(chars: &[char], i: &mut usize) -> Result<(), LexicalError> {
    let start = *i;
    if chars[*i] == '-' {
        *i += 1;
    }
    if *i < chars.len() && chars[*i] == 't' {
        return expect_ident(chars, i, "true");
    }
    if *i < chars.len() && chars[*i] == 'f' {
        return expect_ident(chars, i, "false");
    }
    if *i < chars.len() && chars[*i] == 'n' {
        return expect_ident(chars, i, "null");
    }
    while *i < chars.len() && chars[*i].is_ascii_digit() {
        *i += 1;
    }
    if *i < chars.len() && chars[*i] == '.' {
        *i += 1;
        while *i < chars.len() && chars[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    if *i < chars.len() && (chars[*i] == 'e' || chars[*i] == 'E') {
        *i += 1;
        if *i < chars.len() && (chars[*i] == '+' || chars[*i] == '-') {
            *i += 1;
        }
        while *i < chars.len() && chars[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    if start == *i {
        return Err(LexicalError::InvalidJson("expected literal".to_owned()));
    }
    Ok(())
}

fn expect_ident(chars: &[char], i: &mut usize, word: &str) -> Result<(), LexicalError> {
    for ch in word.chars() {
        if *i >= chars.len() || chars[*i] != ch {
            return Err(LexicalError::InvalidJson(format!("expected {word}")));
        }
        *i += 1;
    }
    Ok(())
}

fn reject_unsafe_decimals(bytes: &[u8]) -> Result<(), LexicalError> {
    let text = std::str::from_utf8(bytes).map_err(|e| LexicalError::InvalidJson(e.to_string()))?;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' {
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if chars[i] == '-' || chars[i].is_ascii_digit() {
            let start = i;
            if chars[i] == '-' {
                i += 1;
            }
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let mut unsafe_num = false;
            if i < chars.len() && chars[i] == '.' {
                unsafe_num = true;
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < chars.len() && (chars[i] == 'e' || chars[i] == 'E') {
                unsafe_num = true;
                i += 1;
                if i < chars.len() && (chars[i] == '+' || chars[i] == '-') {
                    i += 1;
                }
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if unsafe_num && start < i {
                return Err(LexicalError::UnsafeDecimal);
            }
            continue;
        }
        i += 1;
    }
    Ok(())
}

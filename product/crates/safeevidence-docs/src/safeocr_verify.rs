//! SafeOCR critical-number, decimal, comparator, unit, and negation verifier (`ADM-0020` / `T16`,
//! `TA-15`).
//!
//! Adapted in pure safe Rust from `AbdulazizShehri/safeOCR` (`src/safeocr/verification.py`)
//! under Apache-2.0 (`ADR-0004`). Performs exact canonical decimal/sign/comparator/negation
//! equivalence checks (zero IEEE-754 float coercion!) and UCUM unit validation via
//! `safeevidence_fhir::evaluate_unit`.

use safeevidence_fhir::evaluate_unit;
use serde::{Deserialize, Serialize};

use crate::safeocr_contracts::{
    Criticality, EvidenceRecord, LabFieldCandidate, SafeOcrContractError, VerificationSignals,
};

pub const APPROVED_PERTURBATIONS: [&str; 4] = [
    "brightness_095",
    "brightness_105",
    "contrast_105",
    "scale_110",
];

pub const SAFEOCR_POLICY_VERSION: &str = "safeocr-f1-rust-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueKind {
    Numeric,
    Qualitative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedCriticalValue {
    pub kind: ValueKind,
    pub normalized_text: String,
    pub comparator: Option<String>,
    /// Canonical scaled decimal `(sign_negative, unscaled_digits, fractional_places)` with trailing
    /// fractional zeros trimmed so `5.0` and `5.00` compare equal while `5.0` vs `50` or `-5.0`
    /// never collide and zero float rounding ever occurs.
    pub canonical_decimal: Option<String>,
    pub qualitative_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerturbationRead {
    pub name: String,
    pub image_sha256: String,
    pub text: Option<String>,
    pub runtime_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentCropRead {
    pub engine_name: String,
    pub text: Option<String>,
    pub runtime_healthy: bool,
}

/// Whitespace-collapsing normalization that preserves every digit, punctuation mark, and letter.
#[must_use]
pub fn normalize_evidence_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

const QUALITATIVE_TOKENS: &[&str] = &[
    "POSITIVE",
    "NEGATIVE",
    "DETECTED",
    "NOT DETECTED",
    "REACTIVE",
    "NONREACTIVE",
    "NON-REACTIVE",
];

fn canonicalize_decimal_literal(raw_num: &str) -> Option<String> {
    let s = raw_num.trim();
    if s.is_empty() {
        return None;
    }
    // Reject OCR confusable letters (e.g. `1.O`, `l.5`, `5,0` ambiguous comma decimal).
    if s.contains(',') {
        return None;
    }
    let (neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    if rest.is_empty() {
        return None;
    }

    let (mantissa, exp_part) = match rest.find(['e', 'E']) {
        Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
        None => (rest, None),
    };
    let exp: i32 = match exp_part {
        Some(e_str) => {
            if e_str.is_empty() {
                return None;
            }
            let e_digits = e_str.strip_prefix(['+', '-']).unwrap_or(e_str);
            if e_digits.is_empty() || !e_digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let parsed = e_str.parse::<i32>().ok()?;
            if !(-64..=64).contains(&parsed) {
                return None;
            }
            parsed
        }
        None => 0,
    };

    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, f)) => {
            if f.contains('.') {
                return None;
            }
            (i, f)
        }
        None => (mantissa, ""),
    };
    if (int_part.is_empty() && frac_part.is_empty())
        || !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let combined = format!("{int_part}{frac_part}");
    if combined.bytes().all(|b| b == b'0') {
        return Some("0".to_owned());
    }

    let shift = exp - i32::try_from(frac_part.len()).ok()?;
    let mut digits: Vec<u8> = combined.into_bytes();
    let point_pos: isize = isize::try_from(digits.len()).ok()? + (shift as isize);

    let rendered = if point_pos <= 0 {
        let zeros = "0".repeat((-point_pos) as usize);
        let tail = String::from_utf8(digits).ok()?;
        let trimmed_tail = tail.trim_end_matches('0');
        format!("0.{zeros}{trimmed_tail}")
    } else if (point_pos as usize) >= digits.len() {
        let extra = "0".repeat((point_pos as usize) - digits.len());
        let head = String::from_utf8(digits).ok()?;
        let trimmed_head = head.trim_start_matches('0');
        format!("{trimmed_head}{extra}")
    } else {
        let split = point_pos as usize;
        let right = digits.split_off(split);
        let head_s = String::from_utf8(digits).ok()?;
        let tail_s = String::from_utf8(right).ok()?;
        let head_clean = {
            let t = head_s.trim_start_matches('0');
            if t.is_empty() { "0" } else { t }
        };
        let tail_clean = tail_s.trim_end_matches('0');
        if tail_clean.is_empty() {
            head_clean.to_owned()
        } else {
            format!("{head_clean}.{tail_clean}")
        }
    };

    if neg {
        Some(format!("-{rendered}"))
    } else {
        Some(rendered)
    }
}

/// Parses an unambiguous critical numeric or qualitative laboratory/study value (`T16`).
#[must_use]
pub fn parse_critical_value(text: &str) -> Option<ParsedCriticalValue> {
    let normalized = normalize_evidence_text(text);
    if normalized.is_empty() {
        return None;
    }
    let upper = normalized.to_ascii_uppercase();
    if QUALITATIVE_TOKENS.contains(&upper.as_str()) {
        let canonical_qual = if upper == "NON-REACTIVE" {
            "NONREACTIVE".to_owned()
        } else {
            upper
        };
        return Some(ParsedCriticalValue {
            kind: ValueKind::Qualitative,
            normalized_text: normalized,
            comparator: None,
            canonical_decimal: None,
            qualitative_token: Some(canonical_qual),
        });
    }

    let (comparator, rest) = if let Some(r) = normalized.strip_prefix("<=") {
        (Some("<=".to_owned()), r.trim_start())
    } else if let Some(r) = normalized.strip_prefix(">=") {
        (Some(">=".to_owned()), r.trim_start())
    } else if let Some(r) = normalized.strip_prefix('<') {
        (Some("<".to_owned()), r.trim_start())
    } else if let Some(r) = normalized.strip_prefix('>') {
        (Some(">".to_owned()), r.trim_start())
    } else {
        (None, normalized.as_str())
    };

    let canonical_decimal = canonicalize_decimal_literal(rest)?;
    Some(ParsedCriticalValue {
        kind: ValueKind::Numeric,
        normalized_text: normalized,
        comparator,
        canonical_decimal: Some(canonical_decimal),
        qualitative_token: None,
    })
}

fn values_semantically_identical(a: &ParsedCriticalValue, b: &ParsedCriticalValue) -> bool {
    a.kind == b.kind
        && a.comparator == b.comparator
        && a.canonical_decimal == b.canonical_decimal
        && a.qualitative_token == b.qualitative_token
}

fn min_required_ocr_score(criticality: Criticality) -> f64 {
    match criticality {
        Criticality::Critical => 0.90,
        Criticality::High => 0.80,
        Criticality::Normal => 0.70,
    }
}

/// Evaluates all 9 SafeOCR verification gates on `field`, independent read, perturbation reads,
/// structural row alignment, and document/study linkage (`T16` / `TA-15`).
pub fn verify_critical_field(
    field: LabFieldCandidate,
    independent_read: Option<&IndependentCropRead>,
    perturbation_reads: &[PerturbationRead],
    structural_row_aligned: bool,
    study_linkage_unambiguous: bool,
) -> Result<EvidenceRecord, SafeOcrContractError> {
    field.validate()?;
    let min_score = min_required_ocr_score(field.criticality);
    let visual_grounded = !field.source_spans.is_empty()
        && field.source_spans.iter().all(|s| {
            s.engine_score
                .is_some_and(|sc| sc.is_finite() && (0.0..=1.0).contains(&sc) && sc >= min_score)
        });

    let parsed_primary = parse_critical_value(&field.value_text);
    let numeric_parse_unambiguous = parsed_primary.is_some();

    let unit_valid = match (&parsed_primary, &field.unit_text) {
        (Some(p), None) if p.kind == ValueKind::Qualitative => true,
        (_, Some(u)) => evaluate_unit(u).admitted,
        _ => false,
    };

    let ind_healthy = independent_read.is_some_and(|r| r.runtime_healthy);
    let pert_healthy = perturbation_reads.len() == APPROVED_PERTURBATIONS.len()
        && APPROVED_PERTURBATIONS
            .iter()
            .all(|expected| perturbation_reads.iter().any(|p| p.name == *expected))
        && perturbation_reads.iter().all(|p| {
            p.runtime_healthy
                && p.image_sha256.len() == 64
                && p.image_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        });
    let runtime_healthy = ind_healthy && pert_healthy;

    let primary_engine = &field
        .source_spans
        .first()
        .ok_or(SafeOcrContractError::EmptySourceSpans)?
        .engine_name;
    let independent_agreement = match (&parsed_primary, independent_read) {
        (Some(primary), Some(ind)) if ind.runtime_healthy && &ind.engine_name != primary_engine => {
            ind.text
                .as_deref()
                .and_then(parse_critical_value)
                .is_some_and(|parsed_ind| values_semantically_identical(primary, &parsed_ind))
        }
        _ => false,
    };

    let perturbation_stable = match &parsed_primary {
        Some(primary) if pert_healthy => perturbation_reads.iter().all(|p| {
            p.text
                .as_deref()
                .and_then(parse_critical_value)
                .is_some_and(|pv| values_semantically_identical(primary, &pv))
        }),
        _ => false,
    };

    let signals = VerificationSignals {
        candidate_present: !field.value_text.trim().is_empty(),
        visual_grounded,
        independent_agreement,
        perturbation_stable,
        structural_association: structural_row_aligned,
        numeric_parse_unambiguous,
        unit_valid,
        patient_linkage_unambiguous: study_linkage_unambiguous,
        runtime_healthy,
    };

    EvidenceRecord::build(field, signals, SAFEOCR_POLICY_VERSION)
}

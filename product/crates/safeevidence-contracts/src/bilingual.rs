//! Bilingual Arabic/English Unicode scalar normalization and exact span coordinate projection
//! (`WP-06`, `TA-08`).
//!
//! Copy-first boundary: implements SafeEvidence-owned Arabic/Latin text normalization and exact
//! bidirectional Unicode scalar offset projection (`PORT_TO_RUST` span-projection requirement in
//! `WP-06`, verified against `ADM-0004` `T17` parity fixtures + vocalized Arabic clinical spans).
//! `openmed` terminology grounding/calibration Python modules (`T17` worker slice) are not copied
//! and remain fenced on `EXT-01`.

use crate::text::{byte_to_scalar_offset, scalar_to_byte_offset};

/// Errors produced when normalizing text or projecting between normalized and raw scalar spans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpanProjectionError {
    /// Source contains a Trojan-Source / BiDi directional override or isolate character.
    BidiControlForbidden { scalar_index: usize, codepoint: u32 },
    /// Span coordinates are inverted, empty, or out of bounds.
    OutOfBounds {
        start: usize,
        end: usize,
        limit: usize,
    },
    /// Raw UTF-8 coordinate conversion failed.
    Utf8CoordFailure,
}

/// Normalized string paired with an exact scalar-offset map back to the raw source text.
///
/// For each normalized Unicode scalar at index `k` (`0..norm_scalars`), `norm_to_raw_range[k]`
/// gives the inclusive-exclusive raw scalar interval `(raw_start, raw_end)` (`raw_start < raw_end`)
/// covering that normalized scalar plus any stripped combining diacritics (`harakat`) or `tatweel`
/// immediately attached to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedText {
    raw_scalar_len: usize,
    normalized: String,
    norm_to_raw_range: Vec<(usize, usize)>,
    raw_to_norm_index: Vec<Option<usize>>,
}

/// Returns `true` if `ch` is an explicit BiDi directional control, isolate, or zero-width
/// no-break space (`U+061C`, `U+200E`, `U+200F`, `U+202A..=U+202E`, `U+2066..=U+2069`, `U+FEFF`).
#[must_use]
pub const fn is_forbidden_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Returns `true` if `ch` is an Arabic diacritic (`harakat` / Quranic annotation) or `tatweel`
/// (`kashida`, `U+0640`) stripped during lexical normalization.
#[must_use]
pub const fn is_arabic_ignorable_mark(ch: char) -> bool {
    matches!(
        ch,
        '\u{0640}'
            | '\u{064B}'..='\u{065F}'
            | '\u{0670}'
            | '\u{06D6}'..='\u{06ED}'
    )
}

/// Canonicalizes a single non-ignorable Unicode scalar for bilingual Arabic/English matching:
/// - Alef variants (`U+0622`, `U+0623`, `U+0625`, `U+0671`) -> bare Alef (`U+0627`)
/// - Alef Maqsura (`U+0649`) and Farsi Yeh (`U+06CC`) -> Arabic Yeh (`U+064A`)
/// - Teh Marbuta (`U+0629`) -> Heh (`U+0647`) for morphological stem parity
/// - Waw/Yeh with Hamza (`U+0624` -> `U+0648`, `U+0626` -> `U+064A`)
/// - Arabic question/comma punctuation (`U+061F` -> `'?'`, `U+060C` -> `','`)
/// - Eastern Arabic-Indic (`U+0660..=U+0669`) and Extended Arabic-Indic (`U+06F0..=U+06F9`)
///   digits -> ASCII `'0'..='9'`
/// - ASCII uppercase -> ASCII lowercase
#[must_use]
pub const fn canonicalize_scalar(ch: char) -> char {
    match ch {
        '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0671}' => '\u{0627}',
        '\u{0649}' | '\u{06CC}' => '\u{064A}',
        '\u{0629}' => '\u{0647}',
        '\u{0624}' => '\u{0648}',
        '\u{0626}' => '\u{064A}',
        '\u{061F}' => '?',
        '\u{060C}' => ',',
        '\u{0660}'..='\u{0669}' => {
            let offset = (ch as u32) - ('\u{0660}' as u32);
            char::from_u32(('0' as u32) + offset).unwrap()
        }
        '\u{06F0}'..='\u{06F9}' => {
            let offset = (ch as u32) - ('\u{06F0}' as u32);
            char::from_u32(('0' as u32) + offset).unwrap()
        }
        'A'..='Z' => ch.to_ascii_lowercase(),
        other => other,
    }
}

/// Returns `true` when `text` contains at least one Arabic-script character (`U+0600..=U+08FF`,
/// `U+FB50..=U+FDFF`, `U+FE70..=U+FEFC`).
#[must_use]
pub fn contains_arabic_script(text: &str) -> bool {
    text.chars().any(|ch| {
        !is_forbidden_bidi_control(ch)
            && matches!(
                ch,
                '\u{0600}'..='\u{06FF}'
                    | '\u{0750}'..='\u{08FF}'
                    | '\u{FB50}'..='\u{FDFF}'
                    | '\u{FE70}'..='\u{FEFC}'
            )
    })
}

impl NormalizedText {
    /// Normalizes `raw` while recording exact raw scalar coordinate intervals for every emitted
    /// normalized scalar (`TA-08`).
    ///
    /// # Errors
    /// Fails closed on any forbidden BiDi override/isolate control character.
    pub fn build(raw: &str) -> Result<Self, SpanProjectionError> {
        let raw_chars: Vec<char> = raw.chars().collect();
        let mut normalized = String::with_capacity(raw.len());
        let mut norm_to_raw_range: Vec<(usize, usize)> = Vec::with_capacity(raw_chars.len());
        let mut raw_to_norm_index: Vec<Option<usize>> = vec![None; raw_chars.len()];
        let mut pending_leading_start: Option<usize> = None;

        for (raw_idx, &ch) in raw_chars.iter().enumerate() {
            if is_forbidden_bidi_control(ch) {
                return Err(SpanProjectionError::BidiControlForbidden {
                    scalar_index: raw_idx,
                    codepoint: ch as u32,
                });
            }
            if is_arabic_ignorable_mark(ch) {
                if let Some(last_norm_idx) = norm_to_raw_range.len().checked_sub(1) {
                    norm_to_raw_range[last_norm_idx].1 = raw_idx + 1;
                } else if pending_leading_start.is_none() {
                    pending_leading_start = Some(raw_idx);
                }
                continue;
            }
            let canon = canonicalize_scalar(ch);
            let norm_idx = norm_to_raw_range.len();
            let start = pending_leading_start.take().unwrap_or(raw_idx);
            normalized.push(canon);
            norm_to_raw_range.push((start, raw_idx + 1));
            raw_to_norm_index[raw_idx] = Some(norm_idx);
        }

        Ok(Self {
            raw_scalar_len: raw_chars.len(),
            normalized,
            norm_to_raw_range,
            raw_to_norm_index,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub fn norm_scalar_len(&self) -> usize {
        self.norm_to_raw_range.len()
    }

    #[must_use]
    pub const fn raw_scalar_len(&self) -> usize {
        self.raw_scalar_len
    }

    /// Projects a half-open scalar span `[norm_start, norm_end)` on `self.as_str()` back to exact
    /// raw Unicode scalar offsets `(raw_start, raw_end)` suitable for `EvidenceSpan`.
    ///
    /// # Errors
    /// Fails closed if `norm_start >= norm_end` or `norm_end > self.norm_scalar_len()`.
    pub fn project_norm_span_to_raw(
        &self,
        norm_start: usize,
        norm_end: usize,
    ) -> Result<(u64, u64), SpanProjectionError> {
        let limit = self.norm_to_raw_range.len();
        if norm_start >= norm_end || norm_end > limit {
            return Err(SpanProjectionError::OutOfBounds {
                start: norm_start,
                end: norm_end,
                limit,
            });
        }
        let raw_start = self.norm_to_raw_range[norm_start].0 as u64;
        let raw_end = self.norm_to_raw_range[norm_end - 1].1 as u64;
        Ok((raw_start, raw_end))
    }

    /// Projects a half-open raw scalar span `[raw_start, raw_end)` into the normalized scalar
    /// span `[norm_start, norm_end)`.
    ///
    /// # Errors
    /// Fails closed if out of bounds or if the slice contains only ignorable marks.
    pub fn project_raw_span_to_norm(
        &self,
        raw_start: usize,
        raw_end: usize,
    ) -> Result<(usize, usize), SpanProjectionError> {
        if raw_start >= raw_end || raw_end > self.raw_scalar_len {
            return Err(SpanProjectionError::OutOfBounds {
                start: raw_start,
                end: raw_end,
                limit: self.raw_scalar_len,
            });
        }
        let slice = &self.raw_to_norm_index[raw_start..raw_end];
        let first = slice.iter().flatten().min().copied();
        let last = slice.iter().flatten().max().copied();
        match (first, last) {
            (Some(s), Some(e)) => Ok((s, e + 1)),
            _ => Err(SpanProjectionError::OutOfBounds {
                start: raw_start,
                end: raw_end,
                limit: self.raw_scalar_len,
            }),
        }
    }
}

/// Extracts the exact raw UTF-8 substring covered by Unicode scalar coordinates
/// `[start_scalar, end_scalar)` using `scalar_to_byte_offset` + `byte_to_scalar_offset` (`TA-08`).
///
/// # Errors
/// Fails closed if coordinates are inverted or exceed the raw scalar length of `raw`.
pub fn extract_raw_scalar_span(
    raw: &str,
    start_scalar: u64,
    end_scalar: u64,
) -> Result<&str, SpanProjectionError> {
    let start = usize::try_from(start_scalar).map_err(|_| SpanProjectionError::Utf8CoordFailure)?;
    let end = usize::try_from(end_scalar).map_err(|_| SpanProjectionError::Utf8CoordFailure)?;
    let total = raw.chars().count();
    if start >= end || end > total {
        return Err(SpanProjectionError::OutOfBounds {
            start,
            end,
            limit: total,
        });
    }
    let bytes = raw.as_bytes();
    let start_byte =
        scalar_to_byte_offset(bytes, start).map_err(|_| SpanProjectionError::Utf8CoordFailure)?;
    let end_byte =
        scalar_to_byte_offset(bytes, end).map_err(|_| SpanProjectionError::Utf8CoordFailure)?;
    let roundtrip_start = byte_to_scalar_offset(bytes, start_byte)
        .map_err(|_| SpanProjectionError::Utf8CoordFailure)?;
    let roundtrip_end = byte_to_scalar_offset(bytes, end_byte)
        .map_err(|_| SpanProjectionError::Utf8CoordFailure)?;
    if roundtrip_start != start || roundtrip_end != end {
        return Err(SpanProjectionError::Utf8CoordFailure);
    }
    raw.get(start_byte..end_byte)
        .ok_or(SpanProjectionError::Utf8CoordFailure)
}

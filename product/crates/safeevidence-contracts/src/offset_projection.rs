//! Deterministic Unicode scalar offset-projection contract for document adapters (`T17`, `ADM-0004`).
//!
//! Ported to Rust from `maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86`
//! (`openmed/structured/offset_properties.py`, Apache-2.0; see `PROVENANCE.md` and
//! `tests/fixtures/t17/NOTICE`).
//!
//! Validates half-open Unicode scalar (`char`) spans across normalized adapter text, projecting
//! detector/citation spans onto ordered, non-overlapping source spans while retaining only
//! aggregate counts, offsets, and SHA-256 text hashes in public reports.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default deterministic seed selecting synthetic layout markers.
pub const DEFAULT_SYNTHETIC_SEED: usize = 2519;

const SYNTHETIC_MARKERS: [&str; 4] = ["alpha", "beta", "gamma", "delta"];

/// Canonical normalized document adapter format names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterFormat {
    Pdf,
    Ocr,
    Rtf,
    Odt,
    Presentation,
}

impl AdapterFormat {
    pub const ALL: [Self; 5] = [
        Self::Pdf,
        Self::Ocr,
        Self::Rtf,
        Self::Odt,
        Self::Presentation,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Ocr => "ocr",
            Self::Rtf => "rtf",
            Self::Odt => "odt",
            Self::Presentation => "presentation",
        }
    }

    const fn synthetic_prefix(self) -> &'static str {
        match self {
            Self::Pdf => "page",
            Self::Ocr => "scan",
            Self::Rtf => "legacy",
            Self::Odt => "writer",
            Self::Presentation => "slide",
        }
    }
}

/// Safe, categorized failure codes for offset projection without echoing raw text or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffsetFailureCategory {
    InvalidInput,
    InvalidOffsets,
    SpanOrder,
    SpanOverlap,
    TextMismatch,
    UnmappedSpan,
    UnsupportedFormat,
    MissingDependency,
    AdapterError,
}

impl OffsetFailureCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::InvalidOffsets => "invalid_offsets",
            Self::SpanOrder => "span_order",
            Self::SpanOverlap => "span_overlap",
            Self::TextMismatch => "text_mismatch",
            Self::UnmappedSpan => "unmapped_span",
            Self::UnsupportedFormat => "unsupported_format",
            Self::MissingDependency => "missing_dependency",
            Self::AdapterError => "adapter_error",
        }
    }
}

/// Categorized error whose formatted message never embeds source text, file paths, or payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffsetProjectionError {
    category: OffsetFailureCategory,
}

impl OffsetProjectionError {
    #[must_use]
    pub const fn new(category: OffsetFailureCategory) -> Self {
        Self { category }
    }

    #[must_use]
    pub const fn category(self) -> OffsetFailureCategory {
        self.category
    }
}

impl fmt::Display for OffsetProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offset projection failed ({})", self.category.as_str())
    }
}

impl std::error::Error for OffsetProjectionError {}

/// Resolves a format string (including `"pptx"` / `"powerpoint"` aliases) to [`AdapterFormat`].
///
/// # Errors
/// Returns [`OffsetProjectionError`] (`UnsupportedFormat` or `InvalidInput`) if unrecognized.
pub fn canonical_format_name(format_name: &str) -> Result<AdapterFormat, OffsetProjectionError> {
    let trimmed = format_name.trim();
    if trimmed.is_empty() {
        return Err(OffsetProjectionError::new(
            OffsetFailureCategory::InvalidInput,
        ));
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "pdf" => Ok(AdapterFormat::Pdf),
        "ocr" => Ok(AdapterFormat::Ocr),
        "rtf" => Ok(AdapterFormat::Rtf),
        "odt" => Ok(AdapterFormat::Odt),
        "pptx" | "powerpoint" | "presentation" => Ok(AdapterFormat::Presentation),
        _ => Err(OffsetProjectionError::new(
            OffsetFailureCategory::UnsupportedFormat,
        )),
    }
}

/// Half-open Unicode scalar (`char`) span `[start, end)` with optional non-exported test label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffsetSpan {
    start: usize,
    end: usize,
    label: Option<String>,
}

impl OffsetSpan {
    /// Creates a half-open `[start, end)` span (`end >= start`). Zero-width spans (`start == end`)
    /// are valid for boundary/redaction probes.
    ///
    /// # Errors
    /// Returns `InvalidOffsets` when `end < start`.
    pub fn try_new(
        start: usize,
        end: usize,
        label: Option<&str>,
    ) -> Result<Self, OffsetProjectionError> {
        if end < start {
            return Err(OffsetProjectionError::new(
                OffsetFailureCategory::InvalidOffsets,
            ));
        }
        Ok(Self {
            start,
            end,
            label: label.map(str::to_owned),
        })
    }

    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    #[must_use]
    pub const fn offsets(&self) -> (usize, usize) {
        (self.start, self.end)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Deliberately omits `label` so PHI-safe serialized records carry numeric coordinates only.
    #[must_use]
    pub fn to_offset_record(&self) -> serde_json::Value {
        serde_json::json!({
            "end": self.end,
            "start": self.start,
        })
    }
}

/// Projection of one normalized-text span onto overlapping `source_spans` indexes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffsetProjection {
    pub start: usize,
    pub end: usize,
    pub source_span_indexes: Vec<usize>,
}

impl OffsetProjection {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    #[must_use]
    pub fn is_mapped(&self) -> bool {
        !self.source_span_indexes.is_empty()
    }
}

/// Aggregate PHI-safe offset projection report containing counts, coordinates, and text SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffsetProjectionReport {
    pub format_name: Option<AdapterFormat>,
    pub text_length: usize,
    pub source_span_count: usize,
    pub redaction_span_count: usize,
    pub empty_redaction_count: usize,
    pub mapped_redaction_count: usize,
    pub unmapped_redaction_count: usize,
    pub source_text_sha256: String,
    pub projections: Vec<OffsetProjection>,
}

impl OffsetProjectionReport {
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.unmapped_redaction_count == 0
    }
}

/// Parser-free cross-format synthetic offset fixture with multi-column Unicode text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticOffsetCase {
    format_name: AdapterFormat,
    text: String,
    source_spans: Vec<OffsetSpan>,
    redaction_spans: Vec<OffsetSpan>,
    column_ranges: Vec<OffsetSpan>,
}

impl SyntheticOffsetCase {
    /// Validates span bounds, source non-overlap, and ordering against `text.chars().count()`.
    ///
    /// # Errors
    /// Returns [`OffsetProjectionError`] on out-of-bounds, out-of-order, or overlapping source spans.
    pub fn try_new(
        format_name: &str,
        text: String,
        source_spans: Vec<OffsetSpan>,
        redaction_spans: Vec<OffsetSpan>,
        column_ranges: Vec<OffsetSpan>,
    ) -> Result<Self, OffsetProjectionError> {
        let canonical = canonical_format_name(format_name)?;
        let scalar_len = text.chars().count();
        let normalized_source = normalize_spans(&source_spans, scalar_len, true)?;
        let normalized_redactions = normalize_spans(&redaction_spans, scalar_len, false)?;
        let normalized_columns = normalize_spans(&column_ranges, scalar_len, true)?;
        Ok(Self {
            format_name: canonical,
            text,
            source_spans: normalized_source,
            redaction_spans: normalized_redactions,
            column_ranges: normalized_columns,
        })
    }

    #[must_use]
    pub const fn format_name(&self) -> AdapterFormat {
        self.format_name
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn source_spans(&self) -> &[OffsetSpan] {
        &self.source_spans
    }

    #[must_use]
    pub fn redaction_spans(&self) -> &[OffsetSpan] {
        &self.redaction_spans
    }

    #[must_use]
    pub fn column_ranges(&self) -> &[OffsetSpan] {
        &self.column_ranges
    }

    #[must_use]
    pub fn source_text_sha256(&self) -> String {
        text_sha256_hex(&self.text)
    }
}

/// Minimal output contract returned by a document-format adapter under test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterExtractionResult {
    pub text: String,
    pub spans: Vec<OffsetSpan>,
}

fn text_sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn normalize_spans(
    spans: &[OffsetSpan],
    text_scalar_length: usize,
    reject_overlap: bool,
) -> Result<Vec<OffsetSpan>, OffsetProjectionError> {
    let mut prev: Option<(usize, usize)> = None;
    for span in spans {
        if span.end > text_scalar_length {
            return Err(OffsetProjectionError::new(
                OffsetFailureCategory::InvalidOffsets,
            ));
        }
        let key = (span.start, span.end);
        if let Some((prev_start, prev_end)) = prev {
            if key < (prev_start, prev_end) {
                return Err(OffsetProjectionError::new(OffsetFailureCategory::SpanOrder));
            }
            if reject_overlap && prev_end > span.start {
                return Err(OffsetProjectionError::new(
                    OffsetFailureCategory::SpanOverlap,
                ));
            }
        }
        prev = Some(key);
    }
    Ok(spans.to_vec())
}

fn project_normalized(
    source_spans: &[OffsetSpan],
    redaction_spans: &[OffsetSpan],
    require_coverage: bool,
) -> Result<Vec<OffsetProjection>, OffsetProjectionError> {
    let mut projections = Vec::with_capacity(redaction_spans.len());
    for redaction in redaction_spans {
        let indexes: Vec<usize> = source_spans
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| {
                (source.start < redaction.end && source.end > redaction.start).then_some(idx)
            })
            .collect();
        if require_coverage && !redaction.is_empty() && indexes.is_empty() {
            return Err(OffsetProjectionError::new(
                OffsetFailureCategory::UnmappedSpan,
            ));
        }
        projections.push(OffsetProjection {
            start: redaction.start,
            end: redaction.end,
            source_span_indexes: indexes,
        });
    }
    Ok(projections)
}

/// Projects normalized-text `redaction_spans` onto overlapping `source_spans` indexes.
///
/// # Errors
/// Returns [`OffsetProjectionError`] on invalid bounds, out-of-order spans, overlapping source
/// spans, or unmapped non-empty spans when `require_coverage` is `true`.
pub fn project_offset_spans(
    text: &str,
    source_spans: &[OffsetSpan],
    redaction_spans: &[OffsetSpan],
    require_coverage: bool,
) -> Result<Vec<OffsetProjection>, OffsetProjectionError> {
    let scalar_len = text.chars().count();
    let normalized_source = normalize_spans(source_spans, scalar_len, true)?;
    let normalized_redactions = normalize_spans(redaction_spans, scalar_len, false)?;
    project_normalized(&normalized_source, &normalized_redactions, require_coverage)
}

/// Validates ordering, Unicode scalar bounds, and redaction coverage for one adapter output.
///
/// # Errors
/// Returns [`OffsetProjectionError`] on invalid format name, invalid/overlapping spans, or
/// unmapped non-empty spans when `require_coverage` is `true`.
pub fn validate_offset_projection(
    text: &str,
    source_spans: &[OffsetSpan],
    redaction_spans: &[OffsetSpan],
    format_name: Option<&str>,
    require_coverage: bool,
) -> Result<OffsetProjectionReport, OffsetProjectionError> {
    let canonical = match format_name {
        Some(name) => Some(canonical_format_name(name)?),
        None => None,
    };
    let scalar_len = text.chars().count();
    let normalized_source = normalize_spans(source_spans, scalar_len, true)?;
    let normalized_redactions = normalize_spans(redaction_spans, scalar_len, false)?;
    let projections =
        project_normalized(&normalized_source, &normalized_redactions, require_coverage)?;
    let empty_count = projections.iter().filter(|p| p.is_empty()).count();
    let mapped_count = projections
        .iter()
        .filter(|p| p.is_mapped() && !p.is_empty())
        .count();
    let non_empty_count = projections.len() - empty_count;

    Ok(OffsetProjectionReport {
        format_name: canonical,
        text_length: scalar_len,
        source_span_count: normalized_source.len(),
        redaction_span_count: normalized_redactions.len(),
        empty_redaction_count: empty_count,
        mapped_redaction_count: mapped_count,
        unmapped_redaction_count: non_empty_count - mapped_count,
        source_text_sha256: text_sha256_hex(text),
        projections,
    })
}

fn non_whitespace_scalar_spans(text: &str) -> Vec<OffsetSpan> {
    let mut spans = Vec::new();
    let mut token_start: Option<usize> = None;
    for (idx, ch) in text.chars().enumerate() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                spans.push(OffsetSpan {
                    start,
                    end: idx,
                    label: Some("source".to_owned()),
                });
            }
        } else if token_start.is_none() {
            token_start = Some(idx);
        }
    }
    if let Some(start) = token_start {
        spans.push(OffsetSpan {
            start,
            end: text.chars().count(),
            label: Some("source".to_owned()),
        });
    }
    spans
}

/// Builds the 5 deterministic multi-column Unicode synthetic offset cases (`pdf`, `ocr`, `rtf`,
/// `odt`, `presentation`) matching OpenMed's `build_synthetic_offset_cases`.
#[must_use]
pub fn build_synthetic_offset_cases(seed: usize) -> Vec<SyntheticOffsetCase> {
    let marker = SYNTHETIC_MARKERS[seed % SYNTHETIC_MARKERS.len()];
    let mut cases = Vec::with_capacity(AdapterFormat::ALL.len());
    for fmt in AdapterFormat::ALL {
        let col0 = format!(
            "{} line \u{03b1} synthetic-{marker}\nline \u{03b2} \u{6771}\u{4eac}",
            fmt.synthetic_prefix()
        );
        let col1 = "column \u{03b3} caf\u{00e9}\ncolumn \u{03b4} \u{1f9ea}";
        let col0_len = col0.chars().count();
        let col1_start = col0_len + 2;
        let text = format!("{col0}\n\n{col1}");
        let total_len = text.chars().count();
        let column_ranges = vec![
            OffsetSpan {
                start: 0,
                end: col0_len,
                label: Some("column-0".to_owned()),
            },
            OffsetSpan {
                start: col1_start,
                end: total_len,
                label: Some("column-1".to_owned()),
            },
        ];
        let source_spans = non_whitespace_scalar_spans(&text);
        let mut empty_positions: Vec<usize> = vec![0, total_len];
        for (idx, ch) in text.chars().enumerate() {
            if ch == '\n' {
                empty_positions.push(idx);
            }
        }
        empty_positions.sort_unstable();
        empty_positions.dedup();

        let mut redactions = Vec::new();
        for (idx, span) in source_spans.iter().enumerate() {
            if idx % 2 == 0 {
                redactions.push(OffsetSpan {
                    start: span.start,
                    end: span.end,
                    label: Some("redaction".to_owned()),
                });
            }
        }
        for pos in empty_positions {
            redactions.push(OffsetSpan {
                start: pos,
                end: pos,
                label: Some("empty".to_owned()),
            });
        }
        if source_spans.len() >= 3 {
            redactions.push(OffsetSpan {
                start: source_spans[0].start,
                end: source_spans[2].end,
                label: Some("cross-line".to_owned()),
            });
        }
        redactions.sort_by_key(|s| (s.start, s.end));

        cases.push(SyntheticOffsetCase {
            format_name: fmt,
            text,
            source_spans,
            redaction_spans: redactions,
            column_ranges,
        });
    }
    cases
}

/// Runs the common offset-projection property suite across registered format adapters.
///
/// # Errors
/// Returns a categorized [`OffsetProjectionError`] on duplicate/unknown format names, missing
/// adapters, adapter failures, text mismatch, or unmapped spans.
pub fn run_offset_property_suite<F>(
    adapters: &[(&str, F)],
    cases: Option<&[SyntheticOffsetCase]>,
    seed: usize,
) -> Result<Vec<OffsetProjectionReport>, OffsetProjectionError>
where
    F: Fn(&SyntheticOffsetCase) -> Result<AdapterExtractionResult, OffsetFailureCategory>,
{
    let mut registry: BTreeMap<AdapterFormat, &F> = BTreeMap::new();
    for (name, adapter) in adapters {
        let canonical = canonical_format_name(name)?;
        if registry.insert(canonical, adapter).is_some() {
            return Err(OffsetProjectionError::new(
                OffsetFailureCategory::InvalidInput,
            ));
        }
    }
    let default_cases;
    let selected: &[SyntheticOffsetCase] = match cases {
        Some(provided) => provided,
        None => {
            default_cases = build_synthetic_offset_cases(seed);
            &default_cases
        }
    };
    if selected.is_empty() {
        return Err(OffsetProjectionError::new(
            OffsetFailureCategory::InvalidInput,
        ));
    }

    let mut reports = Vec::with_capacity(selected.len());
    for case in selected {
        let adapter = registry
            .get(&case.format_name)
            .ok_or_else(|| OffsetProjectionError::new(OffsetFailureCategory::UnsupportedFormat))?;
        let extracted = adapter(case).map_err(OffsetProjectionError::new)?;
        if extracted.text != case.text {
            return Err(OffsetProjectionError::new(
                OffsetFailureCategory::TextMismatch,
            ));
        }
        reports.push(validate_offset_projection(
            &extracted.text,
            &extracted.spans,
            &case.redaction_spans,
            Some(case.format_name.as_str()),
            true,
        )?);
    }
    Ok(reports)
}

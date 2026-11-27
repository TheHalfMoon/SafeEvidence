//! FHIR R4 interchange support matrix, UCUM presentation contracts, and loss-aware export
//! (`ADM-0017` / `T09`, gated strictly to non-clinical research fixtures under `ADR-0003`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-contracts/src/fhir/mod.rs`)
//! under Apache-2.0 (`ADR-0004`). External validator output remains evidence, never authority,
//! and live clinical patient-context activation (`WP-21`) is refused fail-closed.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::FHIR_R4_VERSION;
use crate::objects::{DigestSha256, LossClass, OpaqueId};

/// Text representation basis for a FHIR field byte/scalar citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextRepresentation {
    SourceBytes,
    NormalizedUtf8,
}

/// Coordinate system for a `TextSpan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinateSystem {
    RawByte,
    UnicodeScalar,
}

/// Half-open `[start, end)` span bound to a `TextRepresentation` and `CoordinateSystem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextSpan {
    pub representation: TextRepresentation,
    pub coordinate_system: CoordinateSystem,
    pub start: u64,
    pub end: u64,
}

/// Pinned UCUM subset identifier for `T09` research Observation unit comparability.
pub const UCUM_SUBSET_ID: &str = "safeevidence-ucum-r4-research-subset-v1";

/// SHA-256 hex digest of the sorted LF-terminated `ADMITTED_UCUM_CODES` table.
pub const UCUM_SUBSET_DIGEST_HEX: &str =
    "947866ded10e36783aa1f15d5eb8e90b79513f1fec1a9e27528bd1c7b1904303";

/// Scope mode under `ADR-0003`: V1 admits synthetic/de-identified research fixtures only and
/// refuses live clinical patient context (`WP-21` / `EXT-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FhirUsageScope {
    /// Synthetic or de-identified research / EBMonFHIR study fixture inspection.
    SyntheticResearchFixture,
    /// Live clinical patient-record / bedside decision context — refused in V1 (`ADR-0003`).
    LiveClinicalPatientForbidden,
}

/// Unit comparability classification within the pinned UCUM subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitComparability {
    Comparable,
    Incomparable,
    Unrecognized,
}

/// Result of evaluating a raw UCUM string against the pinned subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSemanticResult {
    pub raw_unit: String,
    pub admitted: bool,
    pub canonical_unit: Option<String>,
    pub comparability: UnitComparability,
}

/// Field coverage status emitted by closed typed FHIR extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Present,
    Absent,
    UnhealthyEvidence,
    UnsupportedResourceType,
    IncomparableUnits,
    Unknown,
}

/// Whole-resource provenance citation binding a structural JSON path to a source digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WholeResourceCitation {
    pub source_id: OpaqueId,
    pub content_digest: DigestSha256,
    pub structural_path_note: Option<String>,
}

/// Span or whole-resource citation attached to an extracted FHIR field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpanCitation {
    TextSpan { source_id: OpaqueId, span: TextSpan },
    WholeResource { citation: WholeResourceCitation },
}

/// One typed field extracted from a synthetic FHIR R4 JSON resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractedField {
    pub field_key: String,
    pub value: Option<Value>,
    pub status: CoverageStatus,
    pub evidence_refs: Vec<OpaqueId>,
    pub span_citations: Vec<SpanCitation>,
    pub unit: Option<String>,
    pub unit_semantic: Option<UnitSemanticResult>,
}

/// Per-axis support honesty for FHIR interchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Actively qualified by SafeEvidence tests for this axis.
    Qualified,
    /// Narrow subset only; not full axis coverage.
    Partial,
    /// Not supported; must not be assumed present.
    Unsupported,
    /// External tool output may be attached as evidence only.
    EvidenceOnly,
}

/// Named support axes for FHIR R4 interchange honesty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportAxis {
    Lexical,
    Structural,
    Profile,
    Terminology,
    References,
    Provenance,
    ClinicalInterpretation,
}

/// Axis levels for one resource type (or default row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSupportStatus {
    pub resource_type: String,
    pub lexical: SupportLevel,
    pub structural: SupportLevel,
    pub profile: SupportLevel,
    pub terminology: SupportLevel,
    pub references: SupportLevel,
    pub provenance: SupportLevel,
    pub clinical_interpretation: SupportLevel,
    pub notes: Vec<String>,
}

impl ResourceSupportStatus {
    #[must_use]
    pub fn level(&self, axis: SupportAxis) -> SupportLevel {
        match axis {
            SupportAxis::Lexical => self.lexical,
            SupportAxis::Structural => self.structural,
            SupportAxis::Profile => self.profile,
            SupportAxis::Terminology => self.terminology,
            SupportAxis::References => self.references,
            SupportAxis::Provenance => self.provenance,
            SupportAxis::ClinicalInterpretation => self.clinical_interpretation,
        }
    }
}

/// Machine-readable FHIR support matrix (not a live clinical CapabilityStatement server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FhirSupportMatrix {
    pub fhir_version: String,
    pub synthetic_only: bool,
    pub full_conformance_claimed: bool,
    pub release_ready: bool,
    pub validator_is_authority: bool,
    pub resources: Vec<ResourceSupportStatus>,
    pub default_unsupported: ResourceSupportStatus,
    pub limitations: Vec<String>,
}

impl FhirSupportMatrix {
    /// Canonical V1 research `READY_BASE` matrix — honest narrow subset only (`ADR-0003`).
    #[must_use]
    pub fn trusted_v1_ready_base() -> Self {
        let patient = ResourceSupportStatus {
            resource_type: "Patient".to_owned(),
            lexical: SupportLevel::Qualified,
            structural: SupportLevel::Partial,
            profile: SupportLevel::Unsupported,
            terminology: SupportLevel::Unsupported,
            references: SupportLevel::Unsupported,
            provenance: SupportLevel::Partial,
            clinical_interpretation: SupportLevel::Unsupported,
            notes: vec![
                "Closed synthetic research fixture extractor patient.v1: id, birthDate, name.family/given only; live PHI refused (ADR-0003)"
                    .to_owned(),
            ],
        };
        let observation = ResourceSupportStatus {
            resource_type: "Observation".to_owned(),
            lexical: SupportLevel::Qualified,
            structural: SupportLevel::Partial,
            profile: SupportLevel::Unsupported,
            terminology: SupportLevel::Partial,
            references: SupportLevel::Unsupported,
            provenance: SupportLevel::Partial,
            clinical_interpretation: SupportLevel::Unsupported,
            notes: vec![
                "Closed extractor observation.v1; UCUM subset pin only — not full terminology"
                    .to_owned(),
            ],
        };
        let condition = ResourceSupportStatus {
            resource_type: "Condition".to_owned(),
            lexical: SupportLevel::Qualified,
            structural: SupportLevel::Partial,
            profile: SupportLevel::Unsupported,
            terminology: SupportLevel::Unsupported,
            references: SupportLevel::Unsupported,
            provenance: SupportLevel::Partial,
            clinical_interpretation: SupportLevel::Unsupported,
            notes: vec!["Closed extractor condition.v1: code + clinicalStatus subset".to_owned()],
        };
        let default_unsupported = ResourceSupportStatus {
            resource_type: "*".to_owned(),
            lexical: SupportLevel::Partial,
            structural: SupportLevel::Unsupported,
            profile: SupportLevel::Unsupported,
            terminology: SupportLevel::Unsupported,
            references: SupportLevel::Unsupported,
            provenance: SupportLevel::EvidenceOnly,
            clinical_interpretation: SupportLevel::Unsupported,
            notes: vec![
                "Non-extracted resource types may pass lexical JSON gate only; no structural claim"
                    .to_owned(),
                "External validator outcomes attach as EvaluationRecord evidence only".to_owned(),
            ],
        };
        Self {
            fhir_version: FHIR_R4_VERSION.to_owned(),
            synthetic_only: true,
            full_conformance_claimed: false,
            release_ready: false,
            validator_is_authority: false,
            resources: vec![patient, observation, condition],
            default_unsupported,
            limitations: vec![
                "Narrow typed subset is not FHIR R4 full conformance".to_owned(),
                "Profile validation not qualified".to_owned(),
                "Reference resolution not qualified".to_owned(),
                "Clinical interpretation and live patient care never authorized in V1 (ADR-0003)"
                    .to_owned(),
                "RELEASE_READY remains false".to_owned(),
            ],
        }
    }

    #[must_use]
    pub fn status_for(&self, resource_type: &str) -> &ResourceSupportStatus {
        self.resources
            .iter()
            .find(|r| r.resource_type == resource_type)
            .unwrap_or(&self.default_unsupported)
    }

    /// Honesty invariant for `READY_BASE`.
    #[must_use]
    pub fn is_honest_ready_base(&self) -> bool {
        !self.full_conformance_claimed
            && !self.release_ready
            && !self.validator_is_authority
            && self.synthetic_only
            && self.fhir_version == FHIR_R4_VERSION
            && self.resources.iter().all(|r| {
                r.profile == SupportLevel::Unsupported
                    && r.clinical_interpretation == SupportLevel::Unsupported
                    && r.references == SupportLevel::Unsupported
            })
    }
}

/// Doctor axis for FHIR interchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FhirInterchangeDoctorStatus {
    pub present: bool,
    pub ready_base: bool,
    pub fhir_version: String,
    pub full_conformance_claimed: bool,
    pub validator_is_authority: bool,
    pub release_ready: bool,
}

impl FhirInterchangeDoctorStatus {
    #[must_use]
    pub fn ready_base() -> Self {
        Self {
            present: true,
            ready_base: true,
            fhir_version: FHIR_R4_VERSION.to_owned(),
            full_conformance_claimed: false,
            validator_is_authority: false,
            release_ready: false,
        }
    }
}

/// One field-level loss recorded during export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FhirFieldLoss {
    pub fhir_path: String,
    pub loss_class: LossClass,
    pub note: String,
}

/// Synthetic loss-aware FHIR export result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FhirLossAwareExport {
    pub fhir_version: String,
    pub resource_type: String,
    pub exported_json: Value,
    pub field_losses: Vec<FhirFieldLoss>,
    /// Unsupported field paths preserved for provenance / re-export honesty.
    pub unsupported_fields_preserved: Vec<String>,
    pub full_conformance_claimed: bool,
}

fn supported_paths_for(resource_type: &str) -> &'static [&'static str] {
    match resource_type {
        "Patient" => &["resourceType", "id", "birthDate", "name"],
        "Observation" => &[
            "resourceType",
            "id",
            "code",
            "valueQuantity",
            "effectiveDateTime",
            "status",
        ],
        "Condition" => &["resourceType", "id", "code", "clinicalStatus"],
        _ => &["resourceType"],
    }
}

/// Export a synthetic FHIR JSON resource with explicit loss documentation.
#[must_use]
pub fn loss_aware_export(resource: &Value) -> FhirLossAwareExport {
    let resource_type = resource
        .get("resourceType")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_owned();
    let supported = supported_paths_for(&resource_type);
    let mut exported = Map::new();
    let mut field_losses = Vec::new();
    let mut unsupported_fields_preserved = Vec::new();

    if let Some(obj) = resource.as_object() {
        for (key, value) in obj {
            if supported.contains(&key.as_str()) {
                exported.insert(key.clone(), value.clone());
            } else {
                let path = format!("{resource_type}.{key}");
                unsupported_fields_preserved.push(path.clone());
                field_losses.push(FhirFieldLoss {
                    fhir_path: path,
                    loss_class: LossClass::Lossy,
                    note: "field outside closed READY_BASE extractor subset; preserved in loss inventory"
                        .to_owned(),
                });
            }
        }
    } else {
        field_losses.push(FhirFieldLoss {
            fhir_path: resource_type.clone(),
            loss_class: LossClass::Unknown,
            note: "non-object FHIR payload; export refused structural claim".to_owned(),
        });
    }

    field_losses.push(FhirFieldLoss {
        fhir_path: format!("{resource_type}.clinical_interpretation"),
        loss_class: LossClass::Unknown,
        note: "clinical interpretation axis unsupported; export does not invent meaning".to_owned(),
    });

    FhirLossAwareExport {
        fhir_version: FHIR_R4_VERSION.to_owned(),
        resource_type,
        exported_json: Value::Object(exported),
        field_losses,
        unsupported_fields_preserved,
        full_conformance_claimed: false,
    }
}

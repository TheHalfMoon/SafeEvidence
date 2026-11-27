//! Closed typed FHIR R4 resource extractors (`ADM-0017` / `T09`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-fhir/src/extractors/mod.rs`)
//! under Apache-2.0 (`ADR-0004`).

use safeevidence_contracts::fhir::{
    CoordinateSystem, CoverageStatus, ExtractedField, SpanCitation, TextRepresentation, TextSpan,
    UnitComparability, WholeResourceCitation,
};
use safeevidence_contracts::objects::{DigestSha256, OpaqueId};
use serde_json::Value;

use crate::units::{compare_units, evaluate_unit};

pub const PATIENT_V1: &str = "patient.v1";
pub const OBSERVATION_V1: &str = "observation.v1";
pub const CONDITION_V1: &str = "condition.v1";

#[derive(Debug, Clone)]
pub struct ExtractContext {
    pub source_id: Option<OpaqueId>,
    pub content_digest: Option<DigestSha256>,
    pub source_bytes: Option<Vec<u8>>,
    pub evidence_healthy: bool,
}

impl Default for ExtractContext {
    fn default() -> Self {
        Self {
            source_id: None,
            content_digest: None,
            source_bytes: None,
            evidence_healthy: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Extraction {
    pub resource_type: String,
    pub extractor_id: String,
    pub fields: Vec<ExtractedField>,
    pub summary: Value,
    pub unsupported: bool,
}

pub trait TypedResourceExtractor {
    fn extractor_id(&self) -> &'static str;
    fn resource_type(&self) -> &'static str;
    fn extract(&self, resource: &Value, ctx: &ExtractContext) -> Extraction;
}

fn citation(ctx: &ExtractContext, path_note: &str) -> Vec<SpanCitation> {
    match (&ctx.source_id, &ctx.content_digest) {
        (Some(sid), Some(digest)) => {
            let mut cites = vec![SpanCitation::WholeResource {
                citation: WholeResourceCitation {
                    source_id: sid.clone(),
                    content_digest: digest.clone(),
                    structural_path_note: Some(path_note.to_owned()),
                },
            }];
            if let Some(bytes) = &ctx.source_bytes
                && let Some(span) = find_raw_byte_span(bytes, resource_key_hint(path_note))
            {
                cites.insert(
                    0,
                    SpanCitation::TextSpan {
                        source_id: sid.clone(),
                        span,
                    },
                );
            }
            cites
        }
        _ => vec![],
    }
}

fn resource_key_hint(path_note: &str) -> Option<&'static str> {
    match path_note {
        p if p.ends_with("birthDate") => Some("\"birthDate\""),
        p if p.ends_with("valueQuantity") => Some("\"valueQuantity\""),
        p if p.ends_with("code") => Some("\"code\""),
        p if p.ends_with("clinicalStatus") => Some("\"clinicalStatus\""),
        p if p.contains("family") => Some("\"family\""),
        _ => None,
    }
}

fn find_raw_byte_span(bytes: &[u8], needle: Option<&str>) -> Option<TextSpan> {
    let needle = needle?;
    let hay = std::str::from_utf8(bytes).ok()?;
    let start = hay.find(needle)? as u64;
    let end = start + needle.len() as u64;
    Some(TextSpan {
        representation: TextRepresentation::SourceBytes,
        coordinate_system: CoordinateSystem::RawByte,
        start,
        end,
    })
}

fn evidence_refs(ctx: &ExtractContext) -> Vec<OpaqueId> {
    ctx.source_id.iter().cloned().collect()
}

fn present_field(
    key: &str,
    value: Value,
    ctx: &ExtractContext,
    path_note: &str,
    unit: Option<String>,
) -> ExtractedField {
    let status = if !ctx.evidence_healthy && ctx.source_id.is_some() {
        CoverageStatus::UnhealthyEvidence
    } else {
        CoverageStatus::Present
    };
    let unit_semantic = unit.as_ref().map(|u| evaluate_unit(u));
    ExtractedField {
        field_key: key.to_owned(),
        value: Some(value),
        status,
        evidence_refs: evidence_refs(ctx),
        span_citations: citation(ctx, path_note),
        unit,
        unit_semantic,
    }
}

fn absent_field(key: &str, ctx: &ExtractContext) -> ExtractedField {
    ExtractedField {
        field_key: key.to_owned(),
        value: None,
        status: CoverageStatus::Absent,
        evidence_refs: evidence_refs(ctx),
        span_citations: vec![],
        unit: None,
        unit_semantic: None,
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PatientExtractor;

impl TypedResourceExtractor for PatientExtractor {
    fn extractor_id(&self) -> &'static str {
        PATIENT_V1
    }

    fn resource_type(&self) -> &'static str {
        "Patient"
    }

    fn extract(&self, resource: &Value, ctx: &ExtractContext) -> Extraction {
        let mut fields = Vec::new();
        match resource.get("birthDate").and_then(Value::as_str) {
            Some(bd) => fields.push(present_field(
                "patient.birthDate",
                Value::String(bd.to_owned()),
                ctx,
                "Patient.birthDate",
                None,
            )),
            None => fields.push(absent_field("patient.birthDate", ctx)),
        }
        let family = resource
            .get("name")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|n| n.get("family"))
            .and_then(Value::as_str);
        match family {
            Some(f) => fields.push(present_field(
                "patient.name.family",
                Value::String(f.to_owned()),
                ctx,
                "Patient.name.family",
                None,
            )),
            None => fields.push(absent_field("patient.name.family", ctx)),
        }
        let given = resource
            .get("name")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|n| n.get("given"))
            .cloned();
        match given {
            Some(g) => fields.push(present_field(
                "patient.name.given",
                g,
                ctx,
                "Patient.name.given",
                None,
            )),
            None => fields.push(absent_field("patient.name.given", ctx)),
        }
        let id = resource.get("id").cloned().unwrap_or(Value::Null);
        Extraction {
            resource_type: "Patient".to_owned(),
            extractor_id: PATIENT_V1.to_owned(),
            summary: serde_json::json!({
                "resourceType": "Patient",
                "id": id,
                "birthDate": resource.get("birthDate"),
            }),
            fields,
            unsupported: false,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ObservationExtractor;

impl TypedResourceExtractor for ObservationExtractor {
    fn extractor_id(&self) -> &'static str {
        OBSERVATION_V1
    }

    fn resource_type(&self) -> &'static str {
        "Observation"
    }

    fn extract(&self, resource: &Value, ctx: &ExtractContext) -> Extraction {
        let mut fields = Vec::new();
        let code = resource
            .pointer("/code/coding/0/code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match &code {
            Some(c) => fields.push(present_field(
                "observation.code",
                Value::String(c.clone()),
                ctx,
                "Observation.code",
                None,
            )),
            None => fields.push(absent_field("observation.code", ctx)),
        }
        let vq = resource.get("valueQuantity");
        match vq {
            Some(q) => {
                let value = q.get("value").cloned().unwrap_or(Value::Null);
                let unit = q
                    .get("code")
                    .or_else(|| q.get("unit"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                fields.push(present_field(
                    "observation.valueQuantity",
                    value,
                    ctx,
                    "Observation.valueQuantity",
                    unit,
                ));
            }
            None => fields.push(absent_field("observation.valueQuantity", ctx)),
        }
        let effective = resource
            .get("effectiveDateTime")
            .or_else(|| resource.get("effectiveInstant"))
            .cloned();
        if let Some(eff) = &effective {
            fields.push(present_field(
                "observation.effective",
                eff.clone(),
                ctx,
                "Observation.effectiveDateTime",
                None,
            ));
        } else {
            fields.push(absent_field("observation.effective", ctx));
        }
        Extraction {
            resource_type: "Observation".to_owned(),
            extractor_id: OBSERVATION_V1.to_owned(),
            summary: serde_json::json!({
                "resourceType": "Observation",
                "code": code,
                "valueQuantity": vq,
                "effective": effective,
            }),
            fields,
            unsupported: false,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ConditionExtractor;

impl TypedResourceExtractor for ConditionExtractor {
    fn extractor_id(&self) -> &'static str {
        CONDITION_V1
    }

    fn resource_type(&self) -> &'static str {
        "Condition"
    }

    fn extract(&self, resource: &Value, ctx: &ExtractContext) -> Extraction {
        let mut fields = Vec::new();
        let code = resource
            .pointer("/code/coding/0/code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match &code {
            Some(c) => fields.push(present_field(
                "condition.code",
                Value::String(c.clone()),
                ctx,
                "Condition.code",
                None,
            )),
            None => fields.push(absent_field("condition.code", ctx)),
        }
        let status = resource
            .pointer("/clinicalStatus/coding/0/code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match &status {
            Some(s) => fields.push(present_field(
                "condition.clinicalStatus",
                Value::String(s.clone()),
                ctx,
                "Condition.clinicalStatus",
                None,
            )),
            None => fields.push(absent_field("condition.clinicalStatus", ctx)),
        }
        Extraction {
            resource_type: "Condition".to_owned(),
            extractor_id: CONDITION_V1.to_owned(),
            summary: serde_json::json!({
                "resourceType": "Condition",
                "code": code,
                "clinicalStatus": status,
            }),
            fields,
            unsupported: false,
        }
    }
}

#[must_use]
pub fn extract_resource(resource: &Value, ctx: &ExtractContext) -> Extraction {
    let rt = resource
        .get("resourceType")
        .and_then(Value::as_str)
        .unwrap_or("");
    match rt {
        "Patient" => PatientExtractor.extract(resource, ctx),
        "Observation" => ObservationExtractor.extract(resource, ctx),
        "Condition" => ConditionExtractor.extract(resource, ctx),
        other => Extraction {
            resource_type: other.to_owned(),
            extractor_id: "unsupported".to_owned(),
            fields: vec![ExtractedField {
                field_key: "resource.unsupported".to_owned(),
                value: None,
                status: CoverageStatus::UnsupportedResourceType,
                evidence_refs: evidence_refs(ctx),
                span_citations: vec![],
                unit: None,
                unit_semantic: None,
            }],
            summary: serde_json::json!({ "resourceType": other, "unsupported": true }),
            unsupported: true,
        },
    }
}

#[must_use]
pub fn unit_conflict_status(fields: &[&ExtractedField]) -> Option<CoverageStatus> {
    if fields.len() < 2 {
        return None;
    }
    let units: Vec<&str> = fields.iter().filter_map(|f| f.unit.as_deref()).collect();
    if units.len() < 2 {
        return None;
    }
    for i in 0..units.len() {
        for j in (i + 1)..units.len() {
            match compare_units(units[i], units[j]) {
                UnitComparability::Incomparable => return Some(CoverageStatus::IncomparableUnits),
                UnitComparability::Unrecognized => return Some(CoverageStatus::Unknown),
                UnitComparability::Comparable => {}
            }
        }
    }
    None
}

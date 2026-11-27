//! `ADM-0017` / `T09` FHIR R4 lexical, UCUM, loss-aware export & `ADR-0003` research-scope tests.

use safeevidence_contracts::FHIR_R4_VERSION;
use safeevidence_contracts::fhir::{
    CoverageStatus, FhirInterchangeDoctorStatus, FhirSupportMatrix, FhirUsageScope, SupportLevel,
    loss_aware_export,
};
use safeevidence_contracts::objects::{DigestSha256, LossClass, OpaqueId};
use safeevidence_fhir::{
    ExtractContext, LexicalError, extract_resource, gate_fhir_json, gate_fhir_json_scoped,
    unit_conflict_status,
};
use serde_json::json;

#[test]
fn matrix_honesty_axes_separated_and_doctor_honest() {
    let m = FhirSupportMatrix::trusted_v1_ready_base();
    assert!(m.is_honest_ready_base());
    assert_eq!(m.fhir_version, FHIR_R4_VERSION);
    assert!(!m.full_conformance_claimed);
    assert!(!m.release_ready);
    assert!(!m.validator_is_authority);

    let patient = m.status_for("Patient");
    assert_eq!(patient.lexical, SupportLevel::Qualified);
    assert_eq!(patient.structural, SupportLevel::Partial);
    assert_eq!(patient.profile, SupportLevel::Unsupported);
    assert_eq!(patient.clinical_interpretation, SupportLevel::Unsupported);

    let doc = FhirInterchangeDoctorStatus::ready_base();
    assert!(doc.present);
    assert!(doc.ready_base);
    assert!(!doc.full_conformance_claimed);
    assert!(!doc.release_ready);
}

#[test]
fn live_clinical_patient_scope_duplicate_keys_and_float_decimals_fail_closed() {
    let valid_bytes =
        br#"{"resourceType":"Observation","valueQuantity":{"value":"72","code":"/min"}}"#;
    assert_eq!(
        gate_fhir_json_scoped(
            FhirUsageScope::LiveClinicalPatientForbidden,
            "application/fhir+json",
            valid_bytes,
            None,
        ),
        Err(LexicalError::LiveClinicalPatientForbidden)
    );
    assert!(
        gate_fhir_json_scoped(
            FhirUsageScope::SyntheticResearchFixture,
            "application/fhir+json",
            valid_bytes,
            None,
        )
        .is_ok()
    );

    // Duplicate key including unicode-escaped collision (`\u0069d` == `id`) rejected!
    let dup = br#"{"resourceType":"Patient","id":"p1","\u0069d":"p2"}"#;
    assert_eq!(
        gate_fhir_json("application/fhir+json", dup, None),
        Err(LexicalError::DuplicateKey("id".to_owned()))
    );

    let frac = br#"{"resourceType":"Observation","valueQuantity":{"value":1.5}}"#;
    assert_eq!(
        gate_fhir_json("application/fhir+json", frac, None),
        Err(LexicalError::UnsafeDecimal)
    );
}

#[test]
fn closed_extractors_ucum_conflicts_and_loss_aware_export() {
    let obs_kg = json!({
        "resourceType": "Observation",
        "id": "o1",
        "status": "final",
        "code": {"coding": [{"code": "29463-7"}]},
        "valueQuantity": {"value": 70, "unit": "kg", "code": "kg"},
        "interpretation": [{"text": "synthetic"}],
        "note": [{"text": "unsupported on READY_BASE export"}]
    });
    let obs_cel = json!({
        "resourceType": "Observation",
        "id": "o2",
        "code": {"coding": [{"code": "8310-5"}]},
        "valueQuantity": {"value": 37, "unit": "Cel", "code": "Cel"}
    });
    let raw = serde_json::to_vec(&obs_kg).unwrap();
    let ctx = ExtractContext {
        source_id: Some(OpaqueId::new("src-obs-1")),
        content_digest: Some(DigestSha256::of(&raw)),
        source_bytes: Some(raw),
        evidence_healthy: true,
    };
    let ex1 = extract_resource(&obs_kg, &ctx);
    let ex2 = extract_resource(&obs_cel, &ctx);
    let vq1 = ex1
        .fields
        .iter()
        .find(|f| f.field_key == "observation.valueQuantity")
        .unwrap();
    let vq2 = ex2
        .fields
        .iter()
        .find(|f| f.field_key == "observation.valueQuantity")
        .unwrap();
    assert_eq!(
        unit_conflict_status(&[vq1, vq2]),
        Some(CoverageStatus::IncomparableUnits)
    );

    let export = loss_aware_export(&obs_kg);
    assert!(!export.full_conformance_claimed);
    assert!(export.exported_json.get("valueQuantity").is_some());
    assert!(export.exported_json.get("interpretation").is_none());
    assert!(
        export
            .field_losses
            .iter()
            .any(|l| l.fhir_path == "Observation.note" && l.loss_class == LossClass::Lossy)
    );
}

#[test]
fn duplicate_keys_via_utf16_surrogate_pairs_and_invalid_escapes_rejected() {
    // Literal astral char `🧪` (U+1F9EA) collided with UTF-16 surrogate pair `\uD83E\uDDEA`:
    let surrogate_dup = "{\"resourceType\":\"Patient\",\"\u{1F9EA}\":1,\"\\uD83E\\uDDEA\":2}";
    assert_eq!(
        gate_fhir_json("application/fhir+json", surrogate_dup.as_bytes(), None),
        Err(LexicalError::DuplicateKey("\u{1F9EA}".to_owned()))
    );

    // Unpaired high surrogate and invalid escape sequence fail closed:
    let unpaired = br#"{"resourceType":"Patient","id":"\uD83E"}"#;
    assert!(matches!(
        gate_fhir_json("application/fhir+json", unpaired, None),
        Err(LexicalError::InvalidJson(_))
    ));
    let bad_esc = br#"{"resourceType":"Patient","id":"\q"}"#;
    assert!(matches!(
        gate_fhir_json("application/fhir+json", bad_esc, None),
        Err(LexicalError::InvalidJson(_))
    ));
}

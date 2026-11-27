//! Lexical/structural gate, UCUM subset pin, and closed typed extractors for synthetic FHIR R4
//! research fixtures (`ADM-0017` / `T09`, `ADR-0003` non-clinical research scope).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-fhir/src/lib.rs`)
//! under Apache-2.0 (`ADR-0004`).

#![forbid(unsafe_code)]

mod extractors;
mod lexical;
mod units;

pub use extractors::{
    CONDITION_V1, ConditionExtractor, ExtractContext, Extraction, OBSERVATION_V1,
    ObservationExtractor, PATIENT_V1, PatientExtractor, TypedResourceExtractor, extract_resource,
    unit_conflict_status,
};
pub use lexical::{
    LexicalError, LexicalReport, extract_patient_identifiers, gate_fhir_json, gate_fhir_json_scoped,
};
pub use units::{ADMITTED_UCUM_CODES, compare_units, evaluate_unit, subset_pin};

pub const MAX_INGEST_BYTES: usize = 1_048_576;
pub const MAX_JSON_DEPTH: usize = 64;

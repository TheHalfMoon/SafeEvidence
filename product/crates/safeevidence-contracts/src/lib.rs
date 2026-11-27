//! SafeEvidence canonical contracts. Admission ADM-0001 (T01), ADM-0015 (T05), ADM-0016 (T07),
//! ADM-0017 (T09), ADM-0018 (T10); see `PROVENANCE.md`.

pub mod appraisal;
pub mod assurance;
pub mod bilingual;
pub mod document_intake;
pub mod evidence;
pub mod fhir;
pub mod guideline;
pub mod network;
pub mod objects;
pub mod offset_projection;
pub mod os_sandbox;
pub mod packs;
pub mod proof;
pub mod review_protocol;
pub mod span_audit;
pub mod study;
pub mod study_linkage;
pub mod surveillance;
pub mod text;
pub mod worker_policy;

/// Authority-bearing envelope schema version (Spec 002 base; 003 extends bodies).
pub const AUTHORITY_SCHEMA_VERSION: u32 = 1;

/// Admitted HL7 FHIR interchange version for synthetic/de-identified research contracts (`ADR-0003`).
pub const FHIR_R4_VERSION: &str = "4.0.1";

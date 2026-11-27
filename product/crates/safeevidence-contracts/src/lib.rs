//! SafeEvidence canonical contracts. Admission ADM-0001 (T01); see `PROVENANCE.md`.

pub mod appraisal;
pub mod assurance;
pub mod bilingual;
pub mod document_intake;
pub mod evidence;
pub mod objects;
pub mod offset_projection;
pub mod proof;
pub mod review_protocol;
pub mod span_audit;
pub mod study;
pub mod study_linkage;
pub mod surveillance;
pub mod text;

/// Authority-bearing envelope schema version (Spec 002 base; 003 extends bodies).
pub const AUTHORITY_SCHEMA_VERSION: u32 = 1;

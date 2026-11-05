//! SafeEvidence canonical contracts. Admission ADM-0001 (T01); see `PROVENANCE.md`.

pub mod assurance;
pub mod evidence;
pub mod objects;
pub mod proof;
pub mod study;
pub mod text;

/// Authority-bearing envelope schema version (Spec 002 base; 003 extends bodies).
pub const AUTHORITY_SCHEMA_VERSION: u32 = 1;

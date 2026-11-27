//! SafeEvidence content-addressed Pack v0 store, Ed25519 manifest verification & anti-rollback
//! (`ADM-0016` / `T07`, `TA-06`, `TA-28`).
//!
//! Runtime model execution (`runtime.rs`) is intentionally excluded (`not_copied` per F8).

#![forbid(unsafe_code)]

pub mod format;
pub mod store;
pub mod trust;

pub use format::{
    AdmitError, WirePackArtifact, WirePackManifest, admit_pack_dir, compute_content_digest,
    forbidden_reason,
};
pub use store::PackStore;
pub use trust::{
    PackTrustError, SYNTHETIC_PACK_TRUST_ROOT_ID, ed25519_public_key, ed25519_sign, ed25519_verify,
    pack_signing_payload, sign_pack_payload, verify_pack_signature,
};

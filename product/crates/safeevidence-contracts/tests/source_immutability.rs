//! Adapted from the donor test, which used a store helper and an always-failing overwrite stub.
//! `SourceRecord` has no overwrite API here, so tampering is tested through its digest check.

use safeevidence_contracts::AUTHORITY_SCHEMA_VERSION;
use safeevidence_contracts::objects::{
    AuthorityScopeId, DigestSha256, ObjectHeader, OpaqueId, RealmId, SourceRecord,
};

fn record(bytes: &[u8]) -> SourceRecord {
    SourceRecord {
        header: ObjectHeader {
            id: OpaqueId::new("src-1"),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            realm_id: RealmId::new("r"),
            authority_scope_id: AuthorityScopeId::new("s"),
        },
        bytes: bytes.to_vec(),
        content_digest: DigestSha256::of(bytes),
        media_type: "text/plain".to_owned(),
        acquired_at: None,
        provenance_note: None,
    }
}

#[test]
fn digest_verifies_for_unchanged_bytes() {
    let source = record(b"data");
    assert!(source.digest_valid());
    assert_eq!(source.content_digest, DigestSha256::of(b"data"));
}

#[test]
fn changed_bytes_or_digest_fail_verification() {
    let mut changed_bytes = record(b"data");
    changed_bytes.bytes = b"other".to_vec();
    assert!(!changed_bytes.digest_valid());
    let mut changed_digest = record(b"data");
    changed_digest.content_digest = DigestSha256::of(b"other");
    assert!(!changed_digest.digest_valid());
}

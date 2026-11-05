//! Spec 019 record semantics, adapted from the donor test: the first four tests only.
//! `amendment_lineage_append_only` and `doctor_record_semantics_axis` need the donor facade;
//! see `docs/plan/PLAN_AMENDMENT_V1_3.md`.

use safeevidence_contracts::AUTHORITY_SCHEMA_VERSION;
use safeevidence_contracts::objects::{
    AmendmentKind, AmendmentRecord, AuthorityScopeId, IdentityAssertion, MedicalTime,
    MissingnessKind, ObjectHeader, OpaqueId, RealmId, TimePrecision,
    find_unresolved_identity_candidates,
};

#[test]
fn partial_date_precision_preserved() {
    let t = MedicalTime::parse_validated("2019", TimePrecision::Year, true, None).unwrap();
    assert_eq!(t.precision, TimePrecision::Year);
    assert!(t.approximate);
    let (start, end) = t.precision_bounds();
    assert_eq!(start, "2019-01-01");
    assert_eq!(end, "2019-12-31");
    assert!(!t.timeline_sort_key().contains("Instant"));
    assert!(t.timeline_sort_key().contains("|p01|"));
}

#[test]
fn refuse_false_instant_upgrade() {
    let t = MedicalTime::new("2019-06", TimePrecision::Month, false);
    let err = t.try_with_precision(TimePrecision::Instant).unwrap_err();
    assert!(err.to_string().contains("refusing false"));
}

#[test]
fn missingness_roundtrip() {
    let kinds = [
        MissingnessKind::Unknown,
        MissingnessKind::ExplicitAbsence,
        MissingnessKind::NotObserved,
        MissingnessKind::NotApplicable,
        MissingnessKind::Withheld,
        MissingnessKind::Conflict,
    ];
    for kind in kinds {
        let v = serde_json::to_value(kind).unwrap();
        let back: MissingnessKind = serde_json::from_value(v).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn identity_unresolved_candidates() {
    let a = IdentityAssertion {
        header: ObjectHeader {
            id: OpaqueId::new("ia-1"),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            realm_id: RealmId::new("realm-a"),
            authority_scope_id: AuthorityScopeId::new("scope-a"),
        },
        subject_id: OpaqueId::new("subj-a"),
        identifier_system: "mrn".to_owned(),
        identifier_value: "SYN-100".to_owned(),
        confidence: None,
        evidence_refs: vec![],
    };
    let b = IdentityAssertion {
        header: ObjectHeader {
            id: OpaqueId::new("ia-2"),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            realm_id: RealmId::new("realm-a"),
            authority_scope_id: AuthorityScopeId::new("scope-a"),
        },
        subject_id: OpaqueId::new("subj-b"),
        identifier_system: "mrn".to_owned(),
        identifier_value: "SYN-100".to_owned(),
        confidence: None,
        evidence_refs: vec![],
    };
    let set = find_unresolved_identity_candidates(&[a, b], &[]);
    assert_eq!(set.candidates.len(), 1);
    assert_eq!(set.candidates[0].subject_a.as_str(), "subj-a");
    assert_eq!(set.candidates[0].subject_b.as_str(), "subj-b");
}

/// Shape coverage only. Append-only behavior is an obligation in `plan-v1.3`.
#[test]
fn amendment_record_round_trips_with_both_lineage_ids() {
    let record = AmendmentRecord {
        header: ObjectHeader {
            id: OpaqueId::new("am-1"),
            schema_version: AUTHORITY_SCHEMA_VERSION,
            realm_id: RealmId::new("realm-a"),
            authority_scope_id: AuthorityScopeId::new("scope-a"),
        },
        prior_assertion_id: OpaqueId::new("a-1"),
        superseding_assertion_id: OpaqueId::new("a-2"),
        kind: AmendmentKind::Supersession,
        rationale: "synthetic".into(),
        authorized_by: OpaqueId::new("actor"),
        recorded_time: MedicalTime::new("1970-01-01T00:00:00Z", TimePrecision::Instant, false),
    };
    let text = serde_json::to_string(&record).unwrap();
    assert_eq!(
        serde_json::from_str::<AmendmentRecord>(&text).unwrap(),
        record
    );
}

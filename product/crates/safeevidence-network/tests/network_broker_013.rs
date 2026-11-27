//! `ADM-0015` / `T05` Network Broker, SSRF URL/IP defense & `TA-30` preview receipt tests.

use std::net::{IpAddr, SocketAddr};

use safeevidence_contracts::network::{
    BrokerDecision, BrokerReasonCode, BrowseDenyReason, EgressAllowlistEntry,
    EgressApprovalReceipt, EgressDataClass, EgressPurpose, NetworkBrokerRequest, NetworkMode,
};
use safeevidence_network::{
    AllowlistDecision, FhirPartnerAdapter, FixtureTransport, LockedLiveTransport, SmartAuthAdapter,
    StubFhirAdapter, StubSmartAdapter, broker_invoke, broker_invoke_governed,
    build_outbound_query_preview, doctor_status, evaluate_allowlist, filter_public_socket_addrs,
    integrity_matches, is_forbidden_ip, live_partner_refused, validate_url,
};

#[test]
fn broker_deny_empty_allowlist_no_transport() {
    let req = NetworkBrokerRequest {
        destination_host: "partner.fixture".to_owned(),
        destination_path: "/fhir/Patient/1".to_owned(),
        purpose: EgressPurpose::FhirReadFixture,
        data_class: EgressDataClass::SyntheticFixture,
        authorization_token_id: None,
        body_digest: None,
        fixture_id: Some("p1".to_owned()),
    };
    let out = broker_invoke(&[], &req, &FixtureTransport);
    assert_eq!(out.decision, BrokerDecision::Deny);
    assert_eq!(out.reason, BrokerReasonCode::EmptyAllowlist);
    assert!(!out.transport_sent);
}

#[test]
fn network_locked_default_denies_even_when_allowlisted() {
    let allowlist = vec![EgressAllowlistEntry {
        host: "eutils.ncbi.nlm.nih.gov".to_owned(),
        path_prefix: "/entrez/eutils/".to_owned(),
        purposes: vec![EgressPurpose::LiteratureRefreshQuery],
        data_classes: vec![EgressDataClass::NonPhiMetadata],
        enabled: true,
    }];
    let req = NetworkBrokerRequest {
        destination_host: "eutils.ncbi.nlm.nih.gov".to_owned(),
        destination_path: "/entrez/eutils/esearch.fcgi?term=metformin".to_owned(),
        purpose: EgressPurpose::LiteratureRefreshQuery,
        data_class: EgressDataClass::NonPhiMetadata,
        authorization_token_id: None,
        body_digest: None,
        fixture_id: Some("pubmed-1".to_owned()),
    };
    let preview = build_outbound_query_preview(
        &req,
        "condition=\"diabetes\" AND intervention=\"metformin\"",
    )
    .expect("preview");
    let receipt = EgressApprovalReceipt {
        preview_digest: preview.preview_digest.clone(),
        user_confirmed_opt_in: true,
    };

    let locked = broker_invoke_governed(
        NetworkMode::NetworkLocked,
        &allowlist,
        &req,
        Some(&preview),
        Some(&receipt),
        &FixtureTransport,
    );
    assert_eq!(locked.decision, BrokerDecision::Deny);
    assert_eq!(locked.reason, BrokerReasonCode::NetworkLocked);
    assert!(!locked.transport_sent);

    let missing_receipt = broker_invoke_governed(
        NetworkMode::EvidenceUpdateOnly,
        &allowlist,
        &req,
        Some(&preview),
        None,
        &FixtureTransport,
    );
    assert_eq!(missing_receipt.decision, BrokerDecision::Deny);
    assert_eq!(
        missing_receipt.reason,
        BrokerReasonCode::UserPreviewRequired
    );

    let allowed = broker_invoke_governed(
        NetworkMode::EvidenceUpdateOnly,
        &allowlist,
        &req,
        Some(&preview),
        Some(&receipt),
        &FixtureTransport,
    );
    assert_eq!(allowed.decision, BrokerDecision::Allow);
    assert!(allowed.transport_sent);

    // Mutating the request path after preview approval fails closed with PreviewDigestMismatch!
    let mut mutated_req = req.clone();
    mutated_req.destination_path = "/entrez/eutils/esearch.fcgi?term=secret".to_owned();
    let mismatch = broker_invoke_governed(
        NetworkMode::EvidenceUpdateOnly,
        &allowlist,
        &mutated_req,
        Some(&preview),
        Some(&receipt),
        &FixtureTransport,
    );
    assert_eq!(mismatch.decision, BrokerDecision::Deny);
    assert_eq!(mismatch.reason, BrokerReasonCode::PreviewDigestMismatch);
    assert!(!mismatch.transport_sent);
}

#[test]
fn real_phi_and_ssrf_targets_always_refused() {
    let outcome = broker_invoke(
        &[],
        &NetworkBrokerRequest {
            destination_host: "partner.fixture".to_owned(),
            destination_path: "/".to_owned(),
            purpose: EgressPurpose::FhirReadFixture,
            data_class: EgressDataClass::RealPhiForbidden,
            authorization_token_id: None,
            body_digest: None,
            fixture_id: None,
        },
        &FixtureTransport,
    );
    assert_eq!(outcome.reason, BrokerReasonCode::DataClassRefused);
    assert!(!outcome.transport_sent);

    assert_eq!(
        validate_url("http://eutils.ncbi.nlm.nih.gov/entrez"),
        Err(BrowseDenyReason::SchemeNotHttps)
    );
    assert_eq!(
        validate_url("https://169.254.169.254/latest/meta-data"),
        Err(BrowseDenyReason::IpLiteralHost)
    );
    assert_eq!(
        validate_url("https://0x7f.1/admin"),
        Err(BrowseDenyReason::IpLiteralHost)
    );
    assert_eq!(
        validate_url("https://eutils.ncbi.nlm.nih.gov:8443/entrez"),
        Err(BrowseDenyReason::PortNotAllowed)
    );
    assert_eq!(
        validate_url("https://eutils.ncbi.nlm.nih.gov/entrez/../admin"),
        Err(BrowseDenyReason::MalformedUrl)
    );
    assert_eq!(
        validate_url("https://eutils.ncbi.nlm.nih.gov/entrez/%2e%2e/admin"),
        Err(BrowseDenyReason::MalformedUrl)
    );

    for raw in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "fe80::1",
        "fc00::1",
        "2002:7f00:0001::1",
    ] {
        let ip: IpAddr = raw.parse().unwrap();
        assert!(is_forbidden_ip(ip), "{raw} must be forbidden");
    }
    let priv_sock: SocketAddr = "169.254.169.254:443".parse().unwrap();
    assert_eq!(
        filter_public_socket_addrs(&[priv_sock]),
        Err(BrowseDenyReason::ForbiddenResolvedIp)
    );
    let pub_sock: SocketAddr = "130.14.29.110:443".parse().unwrap();
    assert_eq!(
        filter_public_socket_addrs(&[priv_sock, pub_sock]),
        Ok(vec![pub_sock])
    );
}

#[test]
fn stub_adapters_timeout_failure_and_integrity_helpers() {
    let list = vec![
        EgressAllowlistEntry {
            host: "smart.fixture".to_owned(),
            path_prefix: "/".to_owned(),
            purposes: vec![EgressPurpose::SmartDiscovery],
            data_classes: vec![EgressDataClass::SyntheticFixture],
            enabled: true,
        },
        EgressAllowlistEntry {
            host: "fhir.fixture".to_owned(),
            path_prefix: "/fhir/".to_owned(),
            purposes: vec![EgressPurpose::FhirReadFixture],
            data_classes: vec![EgressDataClass::SyntheticFixture],
            enabled: true,
        },
    ];
    assert_eq!(
        StubSmartAdapter
            .discover(&list, &FixtureTransport, "smart.fixture")
            .decision,
        BrokerDecision::Allow
    );
    assert_eq!(
        StubFhirAdapter
            .read_fixture(
                &list,
                &FixtureTransport,
                "fhir.fixture",
                "/fhir/Patient/1",
                "p1"
            )
            .decision,
        BrokerDecision::Allow
    );
    assert_eq!(
        StubFhirAdapter
            .read_fixture(
                &list,
                &LockedLiveTransport,
                "fhir.fixture",
                "/fhir/Patient/1",
                "p1"
            )
            .reason,
        BrokerReasonCode::ExternalGateRequired
    );
    assert_eq!(
        live_partner_refused().reason,
        BrokerReasonCode::ExternalGateRequired
    );

    assert_eq!(
        evaluate_allowlist(
            &list,
            &NetworkBrokerRequest {
                destination_host: "fhir.fixture".to_owned(),
                destination_path: "/fhir/Patient/1".to_owned(),
                purpose: EgressPurpose::SmartDiscovery,
                data_class: EgressDataClass::SyntheticFixture,
                authorization_token_id: None,
                body_digest: None,
                fixture_id: None,
            },
        ),
        AllowlistDecision::Deny(BrokerReasonCode::PurposeMismatch)
    );

    let timeout_out = StubFhirAdapter.read_fixture(
        &list,
        &FixtureTransport,
        "fhir.fixture",
        "/fhir/Patient/1",
        "fail:timeout",
    );
    assert_eq!(timeout_out.reason, BrokerReasonCode::TransportTimeout);

    let fail_out = StubFhirAdapter.read_fixture(
        &list,
        &FixtureTransport,
        "fhir.fixture",
        "/fhir/Patient/1",
        "fail:transport",
    );
    assert_eq!(fail_out.reason, BrokerReasonCode::TransportFailed);

    assert!(integrity_matches(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        b"hello"
    ));
    assert!(!integrity_matches("00", b"hello"));

    let doc = doctor_status(NetworkMode::NetworkLocked, &list);
    assert!(doc.default_deny);
    assert!(!doc.live_partner_authorized);
}

#[test]
fn rejects_url_fragments_prefix_boundary_escape_and_post_preview_metadata_drift() {
    assert_eq!(
        validate_url("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi#secret"),
        Err(BrowseDenyReason::MalformedUrl)
    );

    let allowlist = vec![EgressAllowlistEntry {
        host: "packs.safeevidence.fixture".to_owned(),
        path_prefix: "/v1/pack".to_owned(),
        purposes: vec![EgressPurpose::EvidencePackUpdateCheck],
        data_classes: vec![EgressDataClass::NonPhiMetadata],
        enabled: true,
    }];

    // Sibling prefix `/v1/pack-admin/...` MUST NOT match `/v1/pack`:
    let sibling_req = NetworkBrokerRequest {
        destination_host: "packs.safeevidence.fixture".to_owned(),
        destination_path: "/v1/pack-admin/secret".to_owned(),
        purpose: EgressPurpose::EvidencePackUpdateCheck,
        data_class: EgressDataClass::NonPhiMetadata,
        authorization_token_id: None,
        body_digest: None,
        fixture_id: Some("f1".to_owned()),
    };
    assert_eq!(
        evaluate_allowlist(&allowlist, &sibling_req),
        AllowlistDecision::Deny(BrokerReasonCode::PurposeMismatch)
    );

    // Exact `/v1/pack` and `/v1/pack/index.json` and `/v1/pack?epoch=2` ARE allowed:
    for ok_path in ["/v1/pack", "/v1/pack/index.json", "/v1/pack?epoch=2"] {
        let mut req = sibling_req.clone();
        req.destination_path = ok_path.to_owned();
        assert_eq!(
            evaluate_allowlist(&allowlist, &req),
            AllowlistDecision::Allow,
            "{ok_path} should match segment boundary"
        );
    }

    // Mutating `fixture_id` or appending `#fragment` after preview approval MUST fail closed:
    let mut base_req = sibling_req;
    base_req.destination_path = "/v1/pack/index.json".to_owned();
    let preview = build_outbound_query_preview(&base_req, "check pack index epoch=2").unwrap();
    let receipt = EgressApprovalReceipt {
        preview_digest: preview.preview_digest.clone(),
        user_confirmed_opt_in: true,
    };

    let mut frag_req = base_req.clone();
    frag_req.destination_path = "/v1/pack/index.json#secret-mrn".to_owned();
    assert_eq!(
        broker_invoke_governed(
            NetworkMode::EvidenceUpdateOnly,
            &allowlist,
            &frag_req,
            Some(&preview),
            Some(&receipt),
            &FixtureTransport,
        )
        .reason,
        BrokerReasonCode::UnsafeUrlOrAddress
    );

    let mut drifted_fixture = base_req;
    drifted_fixture.fixture_id = Some("swapped-fixture".to_owned());
    assert_eq!(
        broker_invoke_governed(
            NetworkMode::EvidenceUpdateOnly,
            &allowlist,
            &drifted_fixture,
            Some(&preview),
            Some(&receipt),
            &FixtureTransport,
        )
        .reason,
        BrokerReasonCode::PreviewDigestMismatch
    );
}

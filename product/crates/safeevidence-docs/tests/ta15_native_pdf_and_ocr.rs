//! `TA-15` Native PDF extraction (uncompressed + `FlateDecode` + Arabic UTF-16BE + scalar spans
//! + hostile-PDF quarantine + scanned-page abstain gate).

use safeevidence_contracts::bilingual::extract_raw_scalar_span;
use safeevidence_contracts::document_intake::DocumentDenyReason;
use safeevidence_docs::native_pdf::{
    PdfExtractError, extract_native_pdf, extract_native_pdf_strict, zlib_compress_stored,
};

fn build_two_page_bilingual_flate_pdf() -> Vec<u8> {
    // Page 1: FlateDecode-compressed English trial finding with TJ kerning array.
    let stream1_raw = b"BT /F1 12 Tf 72 720 Td [(Veltrixamine) -220 (improved) -200 (glimmer) -200 (score) -200 (by) -200 (9) -200 (points.)] TJ ET";
    let stream1_zlib = zlib_compress_stored(stream1_raw);

    // Page 2: Arabic UTF-16BE hex string ("حسن فلتريكسامين النتيجة")
    let ar_text = "حسن فلتريكسامين النتيجة";
    let mut hex_utf16 = String::from("FEFF");
    for unit in ar_text.encode_utf16() {
        hex_utf16.push_str(&format!("{unit:04X}"));
    }
    let stream2_raw = format!("BT /F1 12 Tf 72 700 Td <{hex_utf16}> Tj ET").into_bytes();

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>\nendobj\n");
    pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n");
    pdf.extend_from_slice(
        format!(
            "4 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            stream1_zlib.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&stream1_zlib);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    pdf.extend_from_slice(b"5 0 obj\n<< /Type /Page /Parent 2 0 R /Contents [6 0 R] >>\nendobj\n");
    pdf.extend_from_slice(
        format!("6 0 obj\n<< /Length {} >>\nstream\n", stream2_raw.len()).as_bytes(),
    );
    pdf.extend_from_slice(&stream2_raw);
    pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
    pdf
}

#[test]
fn extracts_bilingual_flatedecode_pdf_pages_with_exact_scalar_spans() {
    let pdf = build_two_page_bilingual_flate_pdf();
    let doc = extract_native_pdf_strict("trial.pdf", &pdf).expect("extract native PDF");
    assert_eq!(doc.page_count, 2);
    assert!(!doc.requires_ocr_or_abstain);
    assert_eq!(
        doc.pages[0].text,
        "Veltrixamine improved glimmer score by 9 points."
    );
    assert_eq!(doc.pages[1].text, "حسن فلتريكسامين النتيجة");

    for p in &doc.pages {
        let sliced =
            extract_raw_scalar_span(&doc.full_text, p.start_scalar as u64, p.end_scalar as u64)
                .unwrap();
        assert_eq!(sliced, p.text);
    }
}

#[test]
fn quarantines_active_javascript_pdf_and_abstains_on_scanned_image_only_page() {
    let hostile = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS(app.alert(1)) >> >>\nendobj\n%%EOF\n";
    assert_eq!(
        extract_native_pdf_strict("evil.pdf", hostile),
        Err(PdfExtractError::Quarantined(DocumentDenyReason::MimeDenied))
    );

    // Comment-delimited `/JS%comment\n(payload)` caught by updated document_intake!
    let comment_js =
        b"%PDF-1.7\n1 0 obj\n<< /Type /Page /JS%comment\n(alert(1)) >>\nendobj\n%%EOF\n";
    assert_eq!(
        extract_native_pdf_strict("evil_comment.pdf", comment_js),
        Err(PdfExtractError::Quarantined(DocumentDenyReason::MimeDenied))
    );

    // Scanned image-only page (empty content stream) flags `requires_ocr_or_abstain = true` and
    // causes `extract_native_pdf_strict` to abstain fail-closed (`TA-15`).
    let scanned = b"%PDF-1.7\n1 0 obj\n<< /Type /Page /Contents 2 0 R >>\nendobj\n2 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n%%EOF\n";
    let non_strict = extract_native_pdf("scanned.pdf", scanned).unwrap();
    assert!(non_strict.requires_ocr_or_abstain);
    assert!(non_strict.pages[0].is_scanned_or_empty);
    assert_eq!(
        extract_native_pdf_strict("scanned.pdf", scanned),
        Err(PdfExtractError::ScannedPageRequiresOcr { page_number: 1 })
    );
}

#[test]
fn preserves_kids_page_order_ignores_stream_substring_in_dict_and_quarantines_bidi_override() {
    // Out-of-order page objects (`10 0 obj` is Page 1, `3 0 obj` is Page 2 via `/Kids [10 0 R 3 0 R]`),
    // AND `/Producer (Trialstreamer)` contains `"stream"` before `/Contents`!
    let s1 = b"BT /F1 12 Tf 72 720 Td (First logical page.) Tj ET";
    let s2 = b"BT /F1 12 Tf 72 700 Td (Second logical page.) Tj ET";
    let mut reordered = Vec::new();
    reordered.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    reordered
        .extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [10 0 R 3 0 R] /Count 2 >>\nendobj\n");
    reordered.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Producer (Trialstreamer) /Contents 4 0 R >>\nendobj\n",
    );
    reordered
        .extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", s2.len()).as_bytes());
    reordered.extend_from_slice(s2);
    reordered.extend_from_slice(b"\nendstream\nendobj\n");
    reordered.extend_from_slice(
        b"10 0 obj\n<< /Type /Page /Parent 2 0 R /Title (Downstream Study) /Contents 11 0 R >>\nendobj\n",
    );
    reordered
        .extend_from_slice(format!("11 0 obj\n<< /Length {} >>\nstream\n", s1.len()).as_bytes());
    reordered.extend_from_slice(s1);
    reordered.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");

    let doc = extract_native_pdf_strict("reordered.pdf", &reordered).unwrap();
    assert_eq!(doc.page_count, 2);
    assert_eq!(doc.pages[0].text, "First logical page.");
    assert_eq!(doc.pages[1].text, "Second logical page.");

    // Trojan-Source BiDi override (`U+202E`) compressed inside `FlateDecode` stream MUST be quarantined:
    let bidi_stream = zlib_compress_stored(b"BT /F1 12 Tf 72 720 Td <FEFF202E0041> Tj ET");
    let mut bidi_pdf = Vec::new();
    bidi_pdf.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Type /Page /Contents 2 0 R >>\nendobj\n");
    bidi_pdf.extend_from_slice(
        format!(
            "2 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            bidi_stream.len()
        )
        .as_bytes(),
    );
    bidi_pdf.extend_from_slice(&bidi_stream);
    bidi_pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
    assert_eq!(
        extract_native_pdf_strict("bidi.pdf", &bidi_pdf),
        Err(PdfExtractError::Quarantined(
            DocumentDenyReason::InvalidUtf8Text
        ))
    );

    // Unsupported `/Filter` (`/ASCII85Decode`), multi-filter pipeline (`[/ASCII85Decode /FlateDecode]`),
    // and `/DecodeParms` MUST fail closed (`MalformedPdf`) rather than parsing encoded bytes!
    for bad_header in [
        "<< /Length 12 /Filter /ASCII85Decode >>",
        "<< /Length 12 /Filter [/ASCII85Decode /FlateDecode] >>",
        "<< /Length 12 /Filter /FlateDecode /DecodeParms << /Predictor 12 >> >>",
    ] {
        let bad_pdf = format!(
            "%PDF-1.7\n1 0 obj\n<< /Type /Page /Contents 2 0 R >>\nendobj\n2 0 obj\n{bad_header}\nstream\n(fake text!)\nendstream\nendobj\n%%EOF\n"
        );
        assert!(
            matches!(
                extract_native_pdf_strict("bad_filter.pdf", bad_pdf.as_bytes()),
                Err(PdfExtractError::MalformedPdf(_))
            ),
            "{bad_header} must fail closed"
        );
    }
}

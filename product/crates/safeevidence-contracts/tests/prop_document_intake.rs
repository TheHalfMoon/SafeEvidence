//! Structure-aware deterministic property and fuzz suite for `safeevidence_contracts::document_intake`
//! (`ADR-0002`, `WP-13`, `TA-15`).

use safeevidence_contracts::document_intake::{
    DocumentDenyReason, DocumentIntakeRequest, DocumentMimeClass, QuarantineDecision, mime_decision,
};

struct Prng(u64);

impl Prng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bounded(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }

    fn fill_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push((self.next_u64() & 0xff) as u8);
        }
        out
    }
}

fn minimal_valid_png() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    v.extend_from_slice(&13_u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&[0_u8; 17]);
    v.extend_from_slice(&0_u32.to_be_bytes());
    v.extend_from_slice(b"IEND\xaeB`\x82");
    v
}

#[test]
fn security_regressions_pdf_actions_bidi_c1_and_image_polyglots_quarantine() {
    // 1. Expanded PDF active/auto-exec/launch/embedded names & compact /JS delimiters:
    for payload in [
        &b"%PDF-1.7\n<</S/JavaScript/JS/PayloadName>>"[..],
        &b"%PDF-1.7\n<</S/JavaScript/JS[(app.alert(1))]>>"[..],
        &b"%PDF-1.7\n<</JS"[..],
        &b"%PDF-1.7\n<</OpenAction 2 0 R>>"[..],
        &b"%PDF-1.7\n<</AA <</O 3 0 R>>>>"[..],
        &b"%PDF-1.7\n<</S /Launch /F (cmd.exe)>>"[..],
        &b"%PDF-1.7\n<</S /SubmitForm /F (https://evil.invalid)>>"[..],
        &b"%PDF-1.7\n<</S /ImportData /F (payload.fdf)>>"[..],
        &b"%PDF-1.7\n<</S /GoToR /F (other.pdf)>>"[..],
        &b"%PDF-1.7\n<</S /GoToE /F (embed.pdf)>>"[..],
        &b"%PDF-1.7\n<</Names <</EmbeddedFiles 4 0 R>>>>"[..],
        &b"%PDF-1.7\n<</AcroForm <</XFA 5 0 R>>>>"[..],
        &b"%PDF-1.7\n%<script>alert(1)</script>"[..],
    ] {
        let req = DocumentIntakeRequest {
            mime: DocumentMimeClass::ApplicationPdf,
            bytes: payload.to_vec(),
            fixture_id: None,
        };
        assert_eq!(
            mime_decision(&req),
            (
                QuarantineDecision::Quarantine,
                DocumentDenyReason::MimeDenied
            ),
            "active PDF vector {:?} must quarantine",
            String::from_utf8_lossy(payload)
        );
    }

    // 2. BiDi directional overrides and C1 controls (U+0085 NEL, U+009B CSI) in TextPlain quarantine:
    for bad_text in [
        "Dose 40 \u{202E}mg daily",
        "Dose 40 \u{2066}mg\u{2069} daily",
        "Mid-string BOM \u{FEFF} token",
        "C1 CSI \u{009B}31m escape",
        "C1 NEL \u{0085} line",
    ] {
        let req = DocumentIntakeRequest {
            mime: DocumentMimeClass::TextPlain,
            bytes: bad_text.as_bytes().to_vec(),
            fixture_id: None,
        };
        assert_eq!(
            mime_decision(&req),
            (
                QuarantineDecision::Quarantine,
                DocumentDenyReason::InvalidUtf8Text
            )
        );
    }

    // 3. Valid PNG and JPEG pass, while truncated trailers or HTML/script polyglots quarantine:
    let clean_png = minimal_valid_png();
    assert_eq!(
        mime_decision(&DocumentIntakeRequest {
            mime: DocumentMimeClass::ImagePng,
            bytes: clean_png.clone(),
            fixture_id: None,
        }),
        (
            QuarantineDecision::AdmitToSandboxedParser,
            DocumentDenyReason::None
        )
    );

    let truncated_png = b"\x89PNG\r\n\x1a\ntruncated".to_vec();
    assert_eq!(
        mime_decision(&DocumentIntakeRequest {
            mime: DocumentMimeClass::ImagePng,
            bytes: truncated_png,
            fixture_id: None,
        }),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::MagicHeaderMismatch
        )
    );

    let mut polyglot_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR<script>evil()</script>".to_vec();
    polyglot_png.extend_from_slice(b"IEND\xaeB`\x82");
    assert_eq!(
        mime_decision(&DocumentIntakeRequest {
            mime: DocumentMimeClass::ImagePng,
            bytes: polyglot_png,
            fixture_id: None,
        }),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::MimeDenied
        )
    );

    let clean_jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0xff, 0xd9];
    assert_eq!(
        mime_decision(&DocumentIntakeRequest {
            mime: DocumentMimeClass::ImageJpeg,
            bytes: clean_jpeg,
            fixture_id: None,
        }),
        (
            QuarantineDecision::AdmitToSandboxedParser,
            DocumentDenyReason::None
        )
    );
    assert_eq!(
        mime_decision(&DocumentIntakeRequest {
            mime: DocumentMimeClass::ImageJpeg,
            bytes: vec![0xff, 0xd8, 0xff, 0xe0],
            fixture_id: None,
        }),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::MagicHeaderMismatch
        )
    );
    let mut polyglot_jpeg = vec![0xff, 0xd8, 0xff, 0xfe];
    polyglot_jpeg.extend_from_slice(b"<svg onload=alert(1)>");
    polyglot_jpeg.extend_from_slice(&[0xff, 0xd9]);
    assert_eq!(
        mime_decision(&DocumentIntakeRequest {
            mime: DocumentMimeClass::ImageJpeg,
            bytes: polyglot_jpeg,
            fixture_id: None,
        }),
        (
            QuarantineDecision::Quarantine,
            DocumentDenyReason::MimeDenied
        )
    );
}

#[test]
fn fuzz_2000_structured_and_random_intake_payloads_never_panic_or_admit_hostile_vectors() {
    const ALL_MIMES: [DocumentMimeClass; 9] = [
        DocumentMimeClass::TextPlain,
        DocumentMimeClass::ApplicationPdf,
        DocumentMimeClass::ImagePng,
        DocumentMimeClass::ImageJpeg,
        DocumentMimeClass::ApplicationOctetStream,
        DocumentMimeClass::TextHtml,
        DocumentMimeClass::OfficeOpenXml,
        DocumentMimeClass::ApplicationJavascript,
        DocumentMimeClass::Unknown,
    ];
    let mut rng = Prng::new(0xD0C5_1A7A_2026_1127);

    for _ in 0..2_000 {
        let mime = ALL_MIMES[rng.bounded(ALL_MIMES.len())];
        let len = rng.bounded(192);
        let mut bytes = match rng.bounded(6) {
            0 => rng.fill_bytes(len),
            1 => {
                let mut v = b"%PDF-1.7\n".to_vec();
                v.extend_from_slice(&rng.fill_bytes(len));
                v
            }
            2 => {
                let mut v = minimal_valid_png();
                let extra = rng.fill_bytes(len % 32);
                v.splice(20..20, extra);
                v
            }
            3 => {
                let mut v = vec![0xff, 0xd8, 0xff];
                v.extend_from_slice(&rng.fill_bytes(len));
                if rng.bounded(2) == 0 {
                    v.extend_from_slice(&[0xff, 0xd9]);
                }
                v
            }
            4 => {
                let tokens = [
                    "Synthetic cohort ",
                    "<img src=x onerror=1>",
                    "/J#61vaScript",
                    "\u{202E}",
                    "p < 0.05",
                    "PK\x03\x04",
                    "javascript:void(0)",
                ];
                let mut s = String::new();
                for _ in 0..(1 + rng.bounded(5)) {
                    s.push_str(tokens[rng.bounded(tokens.len())]);
                }
                s.into_bytes()
            }
            _ => Vec::new(),
        };
        if rng.bounded(8) == 0 {
            bytes.extend_from_slice(b"<script>x()</script>");
        }

        let req = DocumentIntakeRequest {
            mime,
            bytes,
            fixture_id: Some("fuzz".to_owned()),
        };
        let out_a = mime_decision(&req);
        let out_b = mime_decision(&req);
        assert_eq!(out_a, out_b, "mime_decision must be deterministic");

        if matches!(
            mime,
            DocumentMimeClass::ApplicationOctetStream
                | DocumentMimeClass::TextHtml
                | DocumentMimeClass::OfficeOpenXml
                | DocumentMimeClass::ApplicationJavascript
                | DocumentMimeClass::Unknown
        ) {
            assert_eq!(
                out_a,
                (
                    QuarantineDecision::Quarantine,
                    DocumentDenyReason::MimeDenied
                )
            );
        }
        if out_a.0 == QuarantineDecision::AdmitToSandboxedParser {
            assert_eq!(out_a.1, DocumentDenyReason::None);
            assert!(!req.bytes.is_empty());
            let lower_ascii: Vec<u8> = req.bytes.iter().map(u8::to_ascii_lowercase).collect();
            assert!(
                !lower_ascii.windows(7).any(|w| w == b"<script"),
                "admitted payload must never contain <script"
            );
        }
    }
}

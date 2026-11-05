//! T17 parity spans against their source note, plus Arabic-script offset round trips (TA-08).

use safeevidence_contracts::text::{TextCoordError, byte_to_scalar_offset, scalar_to_byte_offset};

const NOTE: &str = include_str!("fixtures/t17/synthetic_clinical_note.txt");
const SPANS: &str = include_str!("fixtures/t17/expected_spans.json");

#[test]
fn donor_spans_are_ordered_and_land_on_boundaries_of_their_note() {
    let document: serde_json::Value = serde_json::from_str(SPANS).unwrap();
    let spans = document["spans"].as_array().unwrap();
    assert!(!spans.is_empty());
    let total = NOTE.chars().count() as u64;
    let mut previous_end = 0;
    for span in spans {
        let start = span["start"].as_u64().unwrap();
        let end = span["end"].as_u64().unwrap();
        assert!(
            previous_end <= start && start < end && end <= total,
            "{span}"
        );
        previous_end = end;
        let byte_start = scalar_to_byte_offset(NOTE.as_bytes(), start as usize).unwrap();
        let byte_end = scalar_to_byte_offset(NOTE.as_bytes(), end as usize).unwrap();
        let slice = &NOTE[byte_start..byte_end];
        assert_eq!(slice.chars().count() as u64, end - start);
        assert_eq!(slice, slice.trim(), "{span} has stray whitespace");
        // A shifted offset would split a token, so each edge must fall on a token boundary.
        let before = NOTE[..byte_start].chars().next_back();
        let after = NOTE[byte_end..].chars().next();
        assert!(
            !before.is_some_and(char::is_alphanumeric),
            "{span} starts inside a token"
        );
        assert!(
            !after.is_some_and(char::is_alphanumeric),
            "{span} ends inside a token"
        );
        let label = span["label"].as_str().unwrap();
        let digits = slice.chars().filter(char::is_ascii_digit).count();
        match label {
            "patient_name" => assert_eq!(digits, 0, "{span}"),
            "email" => assert!(slice.contains('@'), "{span}"),
            "date" | "date_of_birth" => assert_eq!(digits, 8, "{span}"),
            "medical_record_number" | "phone_number" => assert!(digits > 0, "{span}"),
            other => panic!("unexpected label {other}"),
        }
    }
}

#[test]
fn arabic_offsets_round_trip_at_every_scalar() {
    // Letters, Arabic-Indic digits, a combining mark, a Latin unit and an emoji.
    let text = "الجرعة ٥٠ مَلْغ mg 😀 نهاية";
    let bytes = text.as_bytes();
    assert!(bytes.len() > text.chars().count());
    for scalar in 0..=text.chars().count() {
        let byte = scalar_to_byte_offset(bytes, scalar).unwrap();
        assert_eq!(byte_to_scalar_offset(bytes, byte).unwrap(), scalar);
    }
    assert_eq!(
        scalar_to_byte_offset(bytes, text.chars().count() + 1),
        Err(TextCoordError::OutOfBounds)
    );
}

#[test]
fn offset_inside_an_arabic_letter_fails_closed() {
    let bytes = "ا".as_bytes();
    assert_eq!(bytes.len(), 2);
    assert_eq!(
        byte_to_scalar_offset(bytes, 1),
        Err(TextCoordError::NotScalarBoundary)
    );
}

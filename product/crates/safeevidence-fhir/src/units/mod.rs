//! Bounded UCUM subset — no silent unit conversion outside admitted table (`ADM-0017` / `T09`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-fhir/src/units/mod.rs`)
//! under Apache-2.0 (`ADR-0004`).

use safeevidence_contracts::fhir::{
    UCUM_SUBSET_DIGEST_HEX, UCUM_SUBSET_ID, UnitComparability, UnitSemanticResult,
};

/// Admitted UCUM codes for V1 research Observation fixtures (sorted canonical list).
pub const ADMITTED_UCUM_CODES: &[&str] = &[
    "%",
    "/min",
    "Cel",
    "L",
    "[degF]",
    "g",
    "g/dL",
    "kg",
    "lb",
    "mL",
    "mg",
    "mm[Hg]",
    "mmol/L",
    "{beats}/min",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitGroup {
    Mass,
    Rate,
    Pressure,
    Temperature,
    Volume,
    ConcentrationMass,
    ConcentrationMolar,
    Fraction,
}

fn group_of(code: &str) -> Option<UnitGroup> {
    match code {
        "kg" | "g" | "mg" | "lb" => Some(UnitGroup::Mass),
        "/min" | "{beats}/min" => Some(UnitGroup::Rate),
        "mm[Hg]" => Some(UnitGroup::Pressure),
        "Cel" | "[degF]" => Some(UnitGroup::Temperature),
        "mL" | "L" => Some(UnitGroup::Volume),
        "g/dL" => Some(UnitGroup::ConcentrationMass),
        "mmol/L" => Some(UnitGroup::ConcentrationMolar),
        "%" => Some(UnitGroup::Fraction),
        _ => None,
    }
}

fn canonical_of(code: &str) -> Option<&'static str> {
    ADMITTED_UCUM_CODES.iter().copied().find(|&c| c == code)
}

#[must_use]
pub fn evaluate_unit(raw_unit: &str) -> UnitSemanticResult {
    let trimmed = raw_unit.trim();
    match canonical_of(trimmed) {
        Some(canon) => UnitSemanticResult {
            raw_unit: trimmed.to_owned(),
            admitted: true,
            canonical_unit: Some(canon.to_owned()),
            comparability: UnitComparability::Comparable,
        },
        None => UnitSemanticResult {
            raw_unit: trimmed.to_owned(),
            admitted: false,
            canonical_unit: None,
            comparability: UnitComparability::Unrecognized,
        },
    }
}

#[must_use]
pub fn compare_units(a: &str, b: &str) -> UnitComparability {
    let ea = evaluate_unit(a);
    let eb = evaluate_unit(b);
    if !ea.admitted || !eb.admitted {
        return UnitComparability::Unrecognized;
    }
    let ga = group_of(ea.canonical_unit.as_deref().unwrap_or(""));
    let gb = group_of(eb.canonical_unit.as_deref().unwrap_or(""));
    match (ga, gb) {
        (Some(x), Some(y)) if x == y => UnitComparability::Comparable,
        (Some(_), Some(_)) => UnitComparability::Incomparable,
        _ => UnitComparability::Unrecognized,
    }
}

#[must_use]
pub fn subset_pin() -> (&'static str, &'static str) {
    (UCUM_SUBSET_ID, UCUM_SUBSET_DIGEST_HEX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn subset_digest_matches_sorted_list() {
        let mut joined = ADMITTED_UCUM_CODES.join("\n");
        joined.push('\n');
        let digest = Sha256::digest(joined.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, UCUM_SUBSET_DIGEST_HEX);
    }

    #[test]
    fn incompatible_and_unrecognized_units_fail_closed() {
        assert_eq!(compare_units("kg", "Cel"), UnitComparability::Incomparable);
        assert_eq!(compare_units("kg", "g"), UnitComparability::Comparable);
        let r = evaluate_unit("furlong");
        assert!(!r.admitted);
        assert_eq!(r.comparability, UnitComparability::Unrecognized);
    }
}

//! `ADM-0019` / `T15` PRISMA 2-pass conflict-safe deduplication tests (`TA-16`).
//!
//! Adapted from `TheHalfMoon/MedOrigin` (`tests/test_litdb_dedupe.py`).

use safeevidence_review::dedupe::{dedupe_records, normalize_title};
use safeevidence_review::records::{EvidenceTier, Identifiers, LiteratureRecord};

fn make_rec(
    doi: Option<&str>,
    pmid: Option<&str>,
    arxiv: Option<&str>,
    title: &str,
    year: Option<i32>,
    tier: EvidenceTier,
) -> LiteratureRecord {
    LiteratureRecord {
        identifiers: Identifiers::new(doi, pmid, arxiv, None).unwrap(),
        title: title.to_owned(),
        evidence_tier: tier,
        source_adapter: "synthetic".to_owned(),
        year,
        venue: None,
        authors: vec!["Ada Researcher".to_owned()],
        abstract_text: Some("Synthetic randomized trial abstract.".to_owned()),
        license_spdx: Some("CC-BY-4.0".to_owned()),
        tags: Vec::new(),
    }
}

#[test]
fn merges_preprint_and_published_twin_while_routing_conflicting_dois_and_short_titles_to_uncertain()
{
    assert_eq!(
        normalize_title("  Veltrixamine: A Randomized, Double-Blind Trial! "),
        "veltrixamine a randomized double blind trial"
    );

    // 1. Preprint (arXiv) + Published (DOI + PMID) within 1 year -> conflict-free auto-merge:
    let preprint = make_rec(
        None,
        None,
        Some("2501.00001"),
        "Veltrixamine in Adults With Synthetic Glimmer Syndrome: Randomized Trial",
        Some(2025),
        EvidenceTier::Preprint,
    );
    let published = make_rec(
        Some("10.1000/veltrix.2026"),
        Some("990001"),
        None,
        "Veltrixamine in adults with synthetic glimmer syndrome — randomized trial!",
        Some(2026),
        EvidenceTier::PeerReviewed,
    );

    // 2. Two distinct DOIs sharing an identical title -> MUST NOT merge; goes to `uncertain`!
    let conflict_a = make_rec(
        Some("10.1000/orbalin.part1"),
        None,
        None,
        "Multicenter Evaluation of Orbalin for Adult Ember Fatigue Outcomes",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );
    let conflict_b = make_rec(
        Some("10.1000/orbalin.part2"),
        None,
        None,
        "Multicenter Evaluation of Orbalin for Adult Ember Fatigue Outcomes",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );

    // 3. Generic short title (`Editorial`) -> MUST NOT merge; goes to `uncertain`!
    let short_a = make_rec(
        Some("10.1000/ed1"),
        None,
        None,
        "Clinical Editorial",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );
    let short_b = make_rec(
        None,
        Some("880002"),
        None,
        "Clinical editorial",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );

    let res = dedupe_records(&[
        preprint, published, conflict_a, conflict_b, short_a, short_b,
    ]);
    assert_eq!(res.merges.len(), 1);
    assert_eq!(res.uncertain.len(), 2);
    assert_eq!(res.records.len(), 5);

    let merged = res
        .records
        .iter()
        .find(|r| r.identifiers.doi.as_deref() == Some("10.1000/veltrix.2026"))
        .expect("merged peer-reviewed record");
    assert_eq!(merged.identifiers.arxiv_id.as_deref(), Some("2501.00001"));
    assert_eq!(merged.identifiers.pmid.as_deref(), Some("990001"));
    assert_eq!(merged.evidence_tier, EvidenceTier::PeerReviewed);
}

#[test]
fn pass1_merges_partial_id_tuples_refuses_shared_doi_pmid_conflicts_and_never_merges_empty_ids() {
    // Crossref (DOI only) + PubMed (same DOI + PMID) with subtitle difference -> Pass 1 merge:
    let crossref = make_rec(
        Some(" 10.1000/SHARED.77 "),
        None,
        None,
        "Veltrixamine Trial",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );
    let pubmed = make_rec(
        Some("10.1000/shared.77"),
        Some("770011"),
        None,
        "Veltrixamine Trial: Primary Report",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );
    let r1 = dedupe_records(&[crossref, pubmed]);
    assert_eq!(r1.records.len(), 1);
    assert_eq!(r1.merges.len(), 1);
    assert_eq!(r1.records[0].identifiers.pmid.as_deref(), Some("770011"));

    // Shared DOI with conflicting PMIDs -> routed to uncertain without merging:
    let bad_p1 = make_rec(
        Some("10.1000/conflict.1"),
        Some("111"),
        None,
        "Trial Part A",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );
    let bad_p2 = make_rec(
        Some("10.1000/conflict.1"),
        Some("222"),
        None,
        "Trial Part B",
        Some(2025),
        EvidenceTier::PeerReviewed,
    );
    let r2 = dedupe_records(&[bad_p1, bad_p2]);
    assert_eq!(r2.records.len(), 2);
    assert_eq!(r2.merges.len(), 0);
    assert_eq!(r2.uncertain.len(), 1);

    // Unvalidated records missing all identifiers MUST NOT collapse together in Pass 1:
    let empty_a = LiteratureRecord {
        identifiers: Identifiers {
            doi: None,
            pmid: None,
            arxiv_id: None,
            s2_corpus_id: None,
        },
        title: "Unidentified Study Alpha".to_owned(),
        evidence_tier: EvidenceTier::Grey,
        source_adapter: "raw".to_owned(),
        year: Some(2025),
        venue: None,
        authors: Vec::new(),
        abstract_text: None,
        license_spdx: None,
        tags: Vec::new(),
    };
    let mut empty_b = empty_a.clone();
    empty_b.title = "Unidentified Study Beta".to_owned();
    let r3 = dedupe_records(&[empty_a, empty_b]);
    assert_eq!(r3.records.len(), 2);
    assert_eq!(r3.merges.len(), 0);
    assert_eq!(r3.uncertain.len(), 2);
}

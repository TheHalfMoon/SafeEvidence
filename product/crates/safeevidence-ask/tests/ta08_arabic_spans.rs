//! `WP-06` / `TA-08`: Arabic/English Unicode scalar offset round-trip parity (against `T17`
//! fixtures and vocalized Arabic clinical sentences), BiDi Trojan-Source rejection, unpromoted vs
//! promoted Arabic Ask behavior, and pre-registered 20-pair parallel-query `recall@20` parity.

use safeevidence_ask::Direction;
use safeevidence_ask::bilingual_ask::{
    BilingualConcept, BilingualCorpus, BilingualDocument, TextLanguage, ask_bilingual,
    parse_bilingual_question, project_bilingual_finding_span, retrieve_bilingual,
};
use safeevidence_contracts::assurance::{ReasonCode, TerminalOutcome};
use safeevidence_contracts::bilingual::{
    NormalizedText, SpanProjectionError, extract_raw_scalar_span,
};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::study::PublicationState;

const T17_NOTE: &str =
    include_str!("../../safeevidence-contracts/tests/fixtures/t17/synthetic_clinical_note.txt");
const T17_SPANS: &str =
    include_str!("../../safeevidence-contracts/tests/fixtures/t17/expected_spans.json");

#[test]
fn t17_spans_and_vocalized_arabic_offsets_round_trip_100_percent() {
    // 1. Verify 100% round-trip across all admitted ADM-0004 T17 spans:
    let norm_note = NormalizedText::build(T17_NOTE).expect("T17 note normalizes");
    let parsed_t17: serde_json::Value = serde_json::from_str(T17_SPANS).unwrap();
    for entry in parsed_t17["spans"].as_array().unwrap() {
        let raw_start = entry["start"].as_u64().unwrap() as usize;
        let raw_end = entry["end"].as_u64().unwrap() as usize;
        let (norm_start, norm_end) = norm_note
            .project_raw_span_to_norm(raw_start, raw_end)
            .expect("raw->norm projection");
        let (back_start, back_end) = norm_note
            .project_norm_span_to_raw(norm_start, norm_end)
            .expect("norm->raw projection");
        assert_eq!(
            (back_start as usize, back_end as usize),
            (raw_start, raw_end)
        );
        let raw_sub = extract_raw_scalar_span(T17_NOTE, back_start, back_end).unwrap();
        let norm_sub: String = norm_note
            .as_str()
            .chars()
            .skip(norm_start)
            .take(norm_end - norm_start)
            .collect();
        assert_eq!(raw_sub.to_ascii_lowercase(), norm_sub);
    }

    // 2. Vocalized Arabic with harakat (fatha/damma/kasra/shadda/sukun), tatweel (U+0640),
    // Alef-with-hamza (U+0623 / U+0625), Teh Marbuta (U+0629), Eastern Arabic-Indic numerals
    // (U+0664 U+0660 = 40, U+0661 U+0662 = 12), and embedded ASCII unit ("mg"):
    // Two synthetic Arabic sentences encoded via Unicode scalar escapes:
    let vocalized_text = "\u{062a}\u{0644}\u{0642}\u{0649} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{0648}\u{0646} \u{062c}\u{0640}\u{0631}\u{0639}\u{0640}\u{0629} \u{0664}\u{0660} \u{0645}\u{0644}\u{063a} \u{064a}\u{0648}\u{0645}\u{064a}\u{0627}\u{064b}. \u{062a}\u{064e}\u{062d}\u{064e}\u{0633}\u{0651}\u{064e}\u{0646}\u{064e}\u{062a}\u{0652} \u{0627}\u{0644}\u{062f}\u{0651}\u{064e}\u{0631}\u{064e}\u{062c}\u{064e}\u{0629}\u{064f} \u{0628}\u{0645}\u{0642}\u{062f}\u{0627}\u{0631} \u{0666} \u{0646}\u{0642}\u{0627}\u{0637} \u{0639}\u{0646}\u{062f} \u{0661}\u{0662} \u{0623}\u{0633}\u{0628}\u{0648}\u{0639}\u{0627}\u{064b}.";
    // Unvocalized finding query (same second sentence without harakat and with ASCII digits!):
    let unvocalized_finding = "\u{062a}\u{062d}\u{0633}\u{0646}\u{062a} \u{0627}\u{0644}\u{062f}\u{0631}\u{062c}\u{0629} \u{0628}\u{0645}\u{0642}\u{062f}\u{0627}\u{0631} 6 \u{0646}\u{0642}\u{0627}\u{0637} \u{0639}\u{0646}\u{062f} 12 \u{0627}\u{0633}\u{0628}\u{0648}\u{0639}\u{0627}.";

    let doc = BilingualDocument {
        doc_id: "doc-ar-vocalized".to_owned(),
        study_id: "study-ar-1".to_owned(),
        language: TextLanguage::Ar,
        title: "\u{062f}\u{0631}\u{0627}\u{0633}\u{0629} \u{0627}\u{0635}\u{0637}\u{0646}\u{0627}\u{0639}\u{064a}\u{0629}".to_owned(),
        text: vocalized_text.to_owned(),
        finding: unvocalized_finding.to_owned(),
        population_concept: "pop_adults".to_owned(),
        condition_concept: "cond_glimmer".to_owned(),
        intervention_concept: "int_veltrix".to_owned(),
        direction: Direction::Benefit,
        publication_state: PublicationState::Current,
        rights: EvidenceCorpusRights::SyntheticOwned,
    };

    let span = project_bilingual_finding_span(&doc).expect("vocalized span projects cleanly");
    let raw_extracted =
        extract_raw_scalar_span(vocalized_text, span.start_scalar, span.end_scalar).unwrap();
    assert!(raw_extracted.starts_with("\u{062a}\u{064e}\u{062d}"));
    assert!(raw_extracted.ends_with("\u{0623}\u{0633}\u{0628}\u{0648}\u{0639}\u{0627}\u{064b}."));

    // 3. Trojan-Source BiDi directional override (RLO U+202E / LRI U+2066) is rejected fail-closed:
    let spoofed = "Dose 40 \u{202E}mg daily";
    assert!(matches!(
        NormalizedText::build(spoofed),
        Err(SpanProjectionError::BidiControlForbidden {
            codepoint: 0x202E,
            ..
        })
    ));
}

fn build_parallel_bilingual_fixture() -> (BilingualCorpus, Vec<(String, String, String)>) {
    let conditions = [
        (
            "cond_glimmer",
            "glimmer syndrome",
            "\u{0645}\u{062a}\u{0644}\u{0627}\u{0632}\u{0645}\u{0629} \u{0627}\u{0644}\u{0648}\u{0645}\u{064a}\u{0636}",
        ),
        (
            "cond_ember",
            "ember fatigue",
            "\u{0625}\u{0631}\u{0647}\u{0627}\u{0642} \u{0627}\u{0644}\u{062c}\u{0645}\u{0631}",
        ),
        (
            "cond_hollow",
            "hollow cough",
            "\u{0627}\u{0644}\u{0633}\u{0639}\u{0627}\u{0644} \u{0627}\u{0644}\u{0623}\u{062c}\u{0648}\u{0641}",
        ),
        (
            "cond_marble",
            "marble rash",
            "\u{0627}\u{0644}\u{0637}\u{0641}\u{062d} \u{0627}\u{0644}\u{0631}\u{062e}\u{0627}\u{0645}\u{064a}",
        ),
        (
            "cond_quiet",
            "quiet tremor",
            "\u{0627}\u{0644}\u{0631}\u{0639}\u{0627}\u{0634} \u{0627}\u{0644}\u{0647}\u{0627}\u{062f}\u{0626}",
        ),
    ];
    let interventions = [
        (
            "int_veltrix",
            "veltrixamine",
            "\u{0641}\u{0644}\u{062a}\u{0631}\u{064a}\u{0643}\u{0633}\u{0627}\u{0645}\u{064a}\u{0646}",
        ),
        (
            "int_orbalin",
            "orbalin",
            "\u{0623}\u{0648}\u{0631}\u{0628}\u{0627}\u{0644}\u{064a}\u{0646}",
        ),
        (
            "int_quenzil",
            "quenzil",
            "\u{0643}\u{0648}\u{064a}\u{0646}\u{0632}\u{064a}\u{0644}",
        ),
        (
            "int_tessarine",
            "tessarine",
            "\u{062a}\u{064a}\u{0633}\u{0627}\u{0631}\u{064a}\u{0646}",
        ),
    ];
    let populations = [
        (
            "pop_adults",
            "adults",
            "\u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}",
        ),
        (
            "pop_children",
            "children",
            "\u{0627}\u{0644}\u{0623}\u{0637}\u{0641}\u{0627}\u{0644}",
        ),
    ];

    let mut lexicon = Vec::new();
    for (cid, en, ar) in &conditions {
        lexicon.push(BilingualConcept {
            concept_id: (*cid).to_owned(),
            en_terms: vec![(*en).to_owned()],
            ar_terms: vec![(*ar).to_owned()],
        });
    }
    for (iid, en, ar) in &interventions {
        lexicon.push(BilingualConcept {
            concept_id: (*iid).to_owned(),
            en_terms: vec![(*en).to_owned()],
            ar_terms: vec![(*ar).to_owned()],
        });
    }
    for (pid, en, ar) in &populations {
        lexicon.push(BilingualConcept {
            concept_id: (*pid).to_owned(),
            en_terms: vec![(*en).to_owned()],
            ar_terms: vec![(*ar).to_owned()],
        });
    }

    let mut documents = Vec::new();
    let mut query_pairs = Vec::new();
    let mut pair_index = 0_usize;

    for (cid, cond_en, cond_ar) in &conditions {
        for (iid, int_en, int_ar) in &interventions {
            pair_index += 1;
            let study_id = format!("study-bi-{pair_index:02}");
            let en_finding = format!(
                "Symptom score improved by {} points compared with placebo at 12 weeks.",
                3 + (pair_index % 5)
            );
            let ar_finding = format!(
                "\u{062a}\u{064e}\u{062d}\u{064e}\u{0633}\u{0651}\u{064e}\u{0646}\u{064e}\u{062a}\u{0652} \u{062f}\u{0631}\u{062c}\u{0629} \u{0627}\u{0644}\u{0623}\u{0639}\u{0631}\u{0627}\u{0636} \u{0628}\u{0645}\u{0642}\u{062f}\u{0627}\u{0631} {} \u{0646}\u{0642}\u{0627}\u{0637} \u{0639}\u{0646}\u{062f} \u{0661}\u{0662} \u{0623}\u{0633}\u{0628}\u{0648}\u{0639}\u{0627}\u{064b}.",
                3 + (pair_index % 5)
            );
            documents.push(BilingualDocument {
                doc_id: format!("doc-bi-en-{pair_index:02}"),
                study_id: study_id.clone(),
                language: TextLanguage::En,
                title: format!("Synthetic {int_en} trial in adults with {cond_en}"),
                text: format!("Adults with {cond_en} received {int_en} daily. {en_finding}"),
                finding: en_finding,
                population_concept: "pop_adults".to_owned(),
                condition_concept: (*cid).to_owned(),
                intervention_concept: (*iid).to_owned(),
                direction: Direction::Benefit,
                publication_state: PublicationState::Current,
                rights: EvidenceCorpusRights::SyntheticOwned,
            });
            documents.push(BilingualDocument {
                doc_id: format!("doc-bi-ar-{pair_index:02}"),
                study_id: study_id.clone(),
                language: TextLanguage::Ar,
                title: format!("\u{062a}\u{062c}\u{0631}\u{0628}\u{0629} {int_ar} \u{0644}\u{062f}\u{0649} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646} \u{0645}\u{0639} {cond_ar}"),
                text: format!("\u{062a}\u{0644}\u{0642}\u{0649} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646} {int_ar} \u{0644}\u{0639}\u{0644}\u{0627}\u{062c} {cond_ar}. {ar_finding}"),
                finding: ar_finding,
                population_concept: "pop_adults".to_owned(),
                condition_concept: (*cid).to_owned(),
                intervention_concept: (*iid).to_owned(),
                direction: Direction::Benefit,
                publication_state: PublicationState::Current,
                rights: EvidenceCorpusRights::SyntheticOwned,
            });

            let en_q = format!("Does {int_en} help adults with {cond_en}?");
            let ar_q = format!(
                "\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f} {int_ar} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646} \u{0645}\u{0639} {cond_ar}\u{061f}"
            );
            query_pairs.push((study_id, en_q, ar_q));
        }
    }

    let corpus = BilingualCorpus {
        description: "Invented bilingual synthetic fixture for TA-08.".to_owned(),
        validity_epoch: 5,
        rights_grant_version: "synthetic-owned-wp06-1".to_owned(),
        arabic_path_promoted: true,
        quality_appraised: false,
        lexicon,
        documents,
    };
    (corpus, query_pairs)
}

#[test]
fn ta08_parallel_arabic_english_queries_exceed_090_recall_ratio_and_preserve_guards() {
    let (mut corpus, pairs) = build_parallel_bilingual_fixture();
    assert_eq!(pairs.len(), 20);

    // 1. When `arabic_path_promoted == false`, 100% of Arabic queries return reason-coded ABSTAIN
    // (`UNSUPPORTED_LANGUAGE`), satisfying the VS-1 clause of TA-08!
    corpus.arabic_path_promoted = false;
    for (_, _, ar_q) in &pairs {
        let res = ask_bilingual(ar_q, &corpus);
        assert_eq!(res.outcome, TerminalOutcome::Abstain);
        assert_eq!(res.reason, ReasonCode::UnsupportedLanguage);
    }

    // 2. When `arabic_path_promoted == true`, measure parallel study-level recall@20 across all
    // 20 English/Arabic query pairs AND verify `ask_bilingual` produces valid raw-scalar proofs!
    corpus.arabic_path_promoted = true;
    let mut en_recalls = Vec::new();
    let mut ar_recalls = Vec::new();

    for (target_study, en_q, ar_q) in &pairs {
        let parsed_en = parse_bilingual_question(en_q, &corpus.lexicon).expect("EN parses");
        let parsed_ar = parse_bilingual_question(ar_q, &corpus.lexicon).expect("AR parses");

        let hits_en = retrieve_bilingual(&corpus, &parsed_en, 20).expect("EN retrieves");
        let hits_ar = retrieve_bilingual(&corpus, &parsed_ar, 20).expect("AR retrieves");

        let study_found = |hits: &[String]| -> f64 {
            let found = hits.iter().any(|doc_id| {
                corpus
                    .documents
                    .iter()
                    .any(|d| &d.doc_id == doc_id && &d.study_id == target_study)
            });
            if found { 1.0 } else { 0.0 }
        };
        en_recalls.push(study_found(&hits_en));
        ar_recalls.push(study_found(&hits_ar));

        let ans_en = ask_bilingual(en_q, &corpus);
        let ans_ar = ask_bilingual(ar_q, &corpus);
        assert_eq!(ans_en.outcome, TerminalOutcome::AnswerWithCaution);
        assert_eq!(ans_ar.outcome, TerminalOutcome::AnswerWithCaution);
        assert_eq!(ans_en.funnel.independent_studies, 1);
        assert_eq!(ans_ar.funnel.independent_studies, 1);
        let ar_manifest = ans_ar.manifest.expect("Arabic manifest");
        assert_eq!(ar_manifest.claims.len(), 2);
        for claim in &ar_manifest.claims {
            let span = &claim.spans[0];
            let doc = corpus
                .documents
                .iter()
                .find(|d| d.doc_id == span.source_id)
                .unwrap();
            let extracted =
                extract_raw_scalar_span(&doc.text, span.start_scalar, span.end_scalar).unwrap();
            assert!(!extracted.is_empty());
        }
    }

    let mean_en: f64 = en_recalls.iter().sum::<f64>() / en_recalls.len() as f64;
    let mean_ar: f64 = ar_recalls.iter().sum::<f64>() / ar_recalls.len() as f64;
    let ratio = mean_ar / mean_en;
    assert!(
        ratio >= 0.90,
        "TA-08 requires AR/EN recall@20 ratio >= 0.90, got {ratio:.4}"
    );
    assert_eq!(ratio, 1.0);

    // 3. Arabic missing-population query returns ASK_MORE (`MISSING_CRITICAL_CONTEXT`):
    let ar_missing_pop = "\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f} \u{0641}\u{0644}\u{062a}\u{0631}\u{064a}\u{0643}\u{0633}\u{0627}\u{0645}\u{064a}\u{0646} \u{0645}\u{0639} \u{0645}\u{062a}\u{0644}\u{0627}\u{0632}\u{0645}\u{0629} \u{0627}\u{0644}\u{0648}\u{0645}\u{064a}\u{0636}\u{061f}";
    let ask_more = ask_bilingual(ar_missing_pop, &corpus);
    assert_eq!(ask_more.outcome, TerminalOutcome::AskMore);
    assert_eq!(ask_more.reason, ReasonCode::MissingCriticalContext);

    // 4. Arabic patient-specific care query returns ESCALATE (`CLINICIAN_AUTHORITY_REQUIRED`):
    let ar_patient = "\u{0647}\u{0644} \u{0623}\u{0635}\u{0641} \u{0641}\u{0644}\u{062a}\u{0631}\u{064a}\u{0643}\u{0633}\u{0627}\u{0645}\u{064a}\u{0646} \u{0644}\u{0645}\u{0631}\u{064a}\u{0636}\u{064a}\u{061f}";
    let esc = ask_bilingual(ar_patient, &corpus);
    assert_eq!(esc.outcome, TerminalOutcome::Escalate);
    assert_eq!(esc.reason, ReasonCode::ClinicianAuthorityRequired);

    // 5. Unmapped Arabic intervention returns ABSTAIN (`EVIDENCE_INSUFFICIENT`):
    let ar_unknown = "\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f} \u{0645}\u{0631}\u{0643}\u{0628}\u{0645}\u{062c}\u{0647}\u{0648}\u{0644} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646} \u{0645}\u{0639} \u{0645}\u{062a}\u{0644}\u{0627}\u{0632}\u{0645}\u{0629} \u{0627}\u{0644}\u{0648}\u{0645}\u{064a}\u{0636}\u{061f}";
    let unk = ask_bilingual(ar_unknown, &corpus);
    assert_eq!(unk.outcome, TerminalOutcome::Abstain);
    assert_eq!(unk.reason, ReasonCode::EvidenceInsufficient);
}

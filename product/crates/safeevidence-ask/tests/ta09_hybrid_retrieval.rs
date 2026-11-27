//! `TA-08` & `TA-09` bilingual (`EN` + vocalized `AR`) hybrid `BM25 + Dense` RRF retrieval and
//! PICO cross-reranking integration tests.

use safeevidence_ask::Direction;
use safeevidence_ask::bilingual_ask::{
    BilingualConcept, BilingualCorpus, BilingualDocument, TextLanguage,
};
use safeevidence_ask::hybrid_retrieval::{
    BilingualDenseEmbedder, DEFAULT_RRF_K, EMBEDDING_DIM, FlatVectorIndex, HybridRetrievalError,
    PicoIntentKind, cosine_similarity, hybrid_retrieve_bilingual, parse_extended_pico_question,
    reciprocal_rank_fusion,
};
use safeevidence_contracts::evidence::EvidenceCorpusRights;
use safeevidence_contracts::study::PublicationState;

fn sample_bilingual_corpus(arabic_promoted: bool) -> BilingualCorpus {
    let lexicon = vec![
        BilingualConcept {
            concept_id: "int_metformin".to_owned(),
            en_terms: vec!["metformin".to_owned(), "biguanide therapy".to_owned()],
            ar_terms: vec![
                "\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646}"
                    .to_owned(),
                "\u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646}"
                    .to_owned(),
            ],
        },
        BilingualConcept {
            concept_id: "int_placebo".to_owned(),
            en_terms: vec!["placebo".to_owned()],
            ar_terms: vec![
                "\u{0627}\u{0644}\u{0639}\u{0644}\u{0627}\u{062c} \u{0627}\u{0644}\u{0648}\u{0647}\u{0645}\u{064a}".to_owned(),
                "\u{0648}\u{0647}\u{0645}\u{064a}".to_owned(),
            ],
        },
        BilingualConcept {
            concept_id: "pop_adults".to_owned(),
            en_terms: vec!["adults".to_owned()],
            ar_terms: vec![
                "\u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}".to_owned(),
                "\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}".to_owned(),
            ],
        },
        BilingualConcept {
            concept_id: "cond_glycemic".to_owned(),
            en_terms: vec!["glycemic control".to_owned(), "hyperglycemia".to_owned()],
            ar_terms: vec![
                "\u{0636}\u{0628}\u{0637} \u{0627}\u{0644}\u{0633}\u{0643}\u{0631}".to_owned(),
                "\u{0627}\u{0631}\u{062a}\u{0641}\u{0627}\u{0639} \u{0627}\u{0644}\u{0633}\u{0643}\u{0631}".to_owned(),
            ],
        },
        BilingualConcept {
            concept_id: "out_lactic_acidosis".to_owned(),
            en_terms: vec!["lactic acidosis".to_owned()],
            ar_terms: vec![
                "\u{0627}\u{0644}\u{062d}\u{0645}\u{0627}\u{0636} \u{0627}\u{0644}\u{0644}\u{0628}\u{0646}\u{064a}".to_owned(),
            ],
        },
    ];

    let documents = vec![
        BilingualDocument {
            doc_id: "doc-en-metformin-1".to_owned(),
            study_id: "study-met-101".to_owned(),
            language: TextLanguage::En,
            title: "Synthetic Trial of Biguanide Therapy in Adults".to_owned(),
            text: "Synthetic trial report. Metformin improved glycemic control in adults over 12 weeks."
                .to_owned(),
            finding: "Metformin improved glycemic control in adults over 12 weeks.".to_owned(),
            population_concept: "pop_adults".to_owned(),
            condition_concept: "cond_glycemic".to_owned(),
            intervention_concept: "int_metformin".to_owned(),
            direction: Direction::Benefit,
            publication_state: PublicationState::Current,
            rights: EvidenceCorpusRights::SyntheticOwned,
        },
        BilingualDocument {
            doc_id: "doc-ar-metformin-2".to_owned(),
            study_id: "study-met-102".to_owned(),
            language: TextLanguage::Ar,
            title: "\u{062a}\u{062c}\u{0631}\u{0628}\u{0629} \u{0627}\u{0635}\u{0637}\u{0646}\u{0627}\u{0639}\u{064a}\u{0629} \u{0644}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646}"
                .to_owned(),
            text: "\u{062d}\u{064e}\u{0633}\u{0651}\u{064e}\u{0646}\u{064e} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} \u{0636}\u{0628}\u{0637} \u{0627}\u{0644}\u{0633}\u{0643}\u{0631} \u{0644}\u{062f}\u{0649} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}."
                .to_owned(),
            finding: "\u{062d}\u{064e}\u{0633}\u{0651}\u{064e}\u{0646}\u{064e} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} \u{0636}\u{0628}\u{0637} \u{0627}\u{0644}\u{0633}\u{0643}\u{0631} \u{0644}\u{062f}\u{0649} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}."
                .to_owned(),
            population_concept: "pop_adults".to_owned(),
            condition_concept: "cond_glycemic".to_owned(),
            intervention_concept: "int_metformin".to_owned(),
            direction: Direction::Benefit,
            publication_state: PublicationState::Current,
            rights: EvidenceCorpusRights::SyntheticOwned,
        },
        BilingualDocument {
            doc_id: "doc-en-distractor-3".to_owned(),
            study_id: "study-dist-999".to_owned(),
            language: TextLanguage::En,
            title: "Unrelated Dermatology Emollient Study".to_owned(),
            text: "Topical emollient cream did not alter skin hydration in adults.".to_owned(),
            finding: "Topical emollient cream did not alter skin hydration in adults.".to_owned(),
            population_concept: "pop_adults".to_owned(),
            condition_concept: "cond_skin".to_owned(),
            intervention_concept: "int_emollient".to_owned(),
            direction: Direction::NoBenefit,
            publication_state: PublicationState::Current,
            rights: EvidenceCorpusRights::SyntheticOwned,
        },
    ];

    BilingualCorpus {
        description: "Synthetic Wave 4 hybrid retrieval fixture".to_owned(),
        validity_epoch: 1,
        rights_grant_version: "SYNTHETIC-V1".to_owned(),
        arabic_path_promoted: arabic_promoted,
        quality_appraised: true,
        lexicon,
        documents,
    }
}

#[test]
fn dense_embedder_aligns_vocalized_arabic_and_english_concepts_on_unit_sphere() {
    let corpus = sample_bilingual_corpus(true);
    let embedder = BilingualDenseEmbedder::new(&corpus.lexicon);

    let v_en = embedder
        .embed("biguanide therapy for hyperglycemia in adults")
        .expect("embed EN");
    // Vocalized Arabic with harakat & tatweel: الْمِيتفُورمِين لضبط السُّكَّر لدى البالِغين
    let v_ar = embedder
        .embed("\u{0627}\u{0644}\u{0652}\u{0645}\u{0650}\u{064a}\u{062a}\u{0640}\u{0641}\u{064f}\u{0648}\u{0631}\u{0645}\u{0650}\u{064a}\u{0646} \u{0644}\u{0636}\u{0628}\u{0637} \u{0627}\u{0644}\u{0633}\u{064f}\u{0651}\u{0643}\u{064e}\u{0651}\u{0631} \u{0644}\u{062f}\u{0649} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{0650}\u{063a}\u{064a}\u{0646}")
        .expect("embed vocalized AR");
    let v_unrel = embedder
        .embed("topical emollient lotion for dry skin")
        .expect("embed distractor");

    assert_eq!(v_en.len(), EMBEDDING_DIM);
    let norm_en: f64 = v_en.iter().map(|x| x * x).sum::<f64>().sqrt();
    assert!((norm_en - 1.0).abs() < 1e-12);

    let sim_cross = cosine_similarity(&v_en, &v_ar);
    let sim_unrel = cosine_similarity(&v_en, &v_unrel);
    assert!(
        sim_cross > 0.35 && sim_cross > sim_unrel + 0.25,
        "expected cross-lingual concept similarity ({sim_cross}) >> distractor ({sim_unrel})"
    );

    let mut index = FlatVectorIndex::new();
    index.upsert("doc-ar", v_ar);
    index.upsert("doc-unrel", v_unrel);
    let hits = index.search(&v_en, 2);
    assert_eq!(hits[0].0, "doc-ar");
}

#[test]
fn rrf_and_hybrid_bilingual_retrieval_retrieve_both_en_and_ar_studies() {
    let lex = vec!["doc-a".to_owned(), "doc-b".to_owned()];
    let dense = vec!["doc-b".to_owned(), "doc-c".to_owned()];
    let fused = reciprocal_rank_fusion(&lex, &dense, DEFAULT_RRF_K);
    assert_eq!(
        fused[0].0, "doc-b",
        "doc-b present in both lists must rank first"
    );

    let corpus = sample_bilingual_corpus(true);
    let ar_query = "\u{0647}\u{0644} \u{064a}\u{0633}\u{0627}\u{0639}\u{062f} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} \u{0645}\u{0642}\u{0627}\u{0628}\u{0644} \u{0627}\u{0644}\u{0639}\u{0644}\u{0627}\u{062c} \u{0627}\u{0644}\u{0648}\u{0647}\u{0645}\u{064a} \u{0645}\u{0639} \u{0636}\u{0628}\u{0637} \u{0627}\u{0644}\u{0633}\u{0643}\u{0631}\u{061F}";
    let trace = hybrid_retrieve_bilingual(&corpus, ar_query, 3).expect("hybrid AR retrieval");
    assert_eq!(trace.query_language, TextLanguage::Ar);
    let pico = trace.parsed_pico.expect("comparative AR PICO parsed");
    assert_eq!(pico.intent, PicoIntentKind::ComparativeEffectiveness);
    assert_eq!(pico.intervention_concept.as_deref(), Some("int_metformin"));
    assert_eq!(pico.comparator_concept.as_deref(), Some("int_placebo"));
    assert_eq!(
        pico.condition_or_outcome_concept.as_deref(),
        Some("cond_glycemic")
    );
    assert!(
        trace.reranked_doc_ids.len() >= 2
            && trace.reranked_doc_ids[..2].contains(&"doc-en-metformin-1".to_owned())
            && trace.reranked_doc_ids[..2].contains(&"doc-ar-metformin-2".to_owned()),
        "top-2 reranked docs must be the EN and AR metformin studies: {:?}",
        trace.reranked_doc_ids
    );
}

#[test]
fn extended_pico_parses_harm_and_enforces_language_and_patient_gates() {
    let corpus_unpromoted = sample_bilingual_corpus(false);
    let ar_q = "\u{0647}\u{0644} \u{064a}\u{0632}\u{064a}\u{062f} \u{0627}\u{0644}\u{0645}\u{064a}\u{062a}\u{0641}\u{0648}\u{0631}\u{0645}\u{064a}\u{0646} \u{0627}\u{0644}\u{062d}\u{0645}\u{0627}\u{0636} \u{0627}\u{0644}\u{0644}\u{0628}\u{0646}\u{064a} \u{0641}\u{064a} \u{0627}\u{0644}\u{0628}\u{0627}\u{0644}\u{063a}\u{064a}\u{0646}\u{061F}";
    assert_eq!(
        hybrid_retrieve_bilingual(&corpus_unpromoted, ar_q, 3),
        Err(HybridRetrievalError::UnsupportedLanguage)
    );

    let corpus = sample_bilingual_corpus(true);
    let parsed_ar_harm = parse_extended_pico_question(ar_q, &corpus.lexicon).expect("AR harm PICO");
    assert_eq!(parsed_ar_harm.intent, PicoIntentKind::HarmOrSafety);
    assert_eq!(
        parsed_ar_harm.condition_or_outcome_concept.as_deref(),
        Some("out_lactic_acidosis")
    );

    let parsed_en_harm = parse_extended_pico_question(
        "Does metformin increase lactic acidosis in adults?",
        &corpus.lexicon,
    )
    .expect("EN harm PICO");
    assert_eq!(parsed_en_harm.intent, PicoIntentKind::HarmOrSafety);
    assert_eq!(
        parsed_en_harm.population_concept.as_deref(),
        Some("pop_adults")
    );

    // Patient-specific & BiDi override queries fail closed:
    assert_eq!(
        hybrid_retrieve_bilingual(&corpus, "Should I prescribe metformin to my patient?", 3),
        Err(HybridRetrievalError::PatientSpecificRequest)
    );
    assert_eq!(
        hybrid_retrieve_bilingual(&corpus, "Does \u{202E}metformin help adults?", 3),
        Err(HybridRetrievalError::ForbiddenTextControl)
    );
}

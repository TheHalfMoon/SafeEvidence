# SafeEvidence Feature Coverage Matrix — V1

Status: **PLANNING_BASELINE_V1** — freeze state is recorded only in `docs/PLAN_FREEZE.md`. Every planned feature maps to a
source (T##, or `G` = greenfield-justified in `SOURCE_TRANSPLANT_MATRIX_V1.md`
§5), a work packet, an acceptance test, and a V1 scope state. REA lesson IDs
(L#) refer to `docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md` §6.

Scope: `V1` = in first release scope; `VS-1` = in the first vertical slice;
`V1-PARTIAL` = bounded subset in V1; `DEFERRED` = planned, not V1.

| ID | Feature | Source(s) | Reuse mode | WP | Test | REA lesson | Scope |
|---|---|---|---|---|---|---|---|
| F01 | Clinical evidence question (English) | T01, T13, G | C/P/G | WP-07, WP-11a, WP-12, WP-18a | TA-13, TA-14, TA-20 | L5 | VS-1 |
| F02 | Arabic question, Arabic/RTL UI | T17, G | C/G | WP-06, WP-19 | TA-08, TA-22 | — | VS-1 (query + RTL) |
| F03 | Lexical retrieval (FTS5/BM25) | SQLite FTS5, MedScale retriever (oracle) | D/O | WP-07 | TA-09 | — | VS-1 |
| F04 | Biomedical dense retrieval + rerank | T21, T23, T22 | D/ARTIFACT | WP-07 | TA-09 | — | V1 (promotion-gated) |
| F05 | Retrieval funnel transparency | G | G | WP-07, WP-18 | TA-09, TA-20 | L7 | VS-1 |
| F06 | Exact claim-to-source span verification | T01, T17, T27, G | C/G | WP-08, WP-12 | TA-10, TA-14 | L6 | VS-1 |
| F07 | Numeric/unit/negation checks | T16, T09 (UCUM subset), G | C/P/G | WP-08, WP-13 | TA-10, TA-15 | — | VS-1 |
| F08 | Scientific contradiction detection (`CONFLICT`) | T27b (oracle), T32 (vocab), G | BENCH/REF/G | WP-08, WP-11 | TA-10, TA-13 | L6 | V1 |
| F09 | Evidence certainty (GRADE structures) | T26, G | REF/G | WP-10 | TA-12 | L1, L2, L11 | V1 |
| F10 | Design-specific appraisal (RoB 2, ROBINS-I, QUADAS, AMSTAR 2) | T26, T28b/T34 (oracle), G | REF/BENCH/G | WP-10 | TA-12 | L2 | V1-PARTIAL (structures + human entry; automated RoB = benchmark only) |
| F11 | Patient/population applicability | T28, T28d (bench), G | BENCH/G | WP-09 | TA-11 | L4 | VS-1 |
| F12 | Calibrated uncertainty & abstention (categorical, no %) | T13, T14, G | P/C/G | WP-11a, WP-11 | TA-13 | L1, L5 | VS-1 |
| F13 | Study-level dedup & overlap control | T15, T28c, G | C/REF/G | WP-05 | TA-07 | L3 | V1 |
| F14 | Effect / result extraction with quotes | T28, T28d, T28b (bench), G | BENCH/G | WP-15 | TA-17 | L9 | V1-PARTIAL (proposals + confirmation) |
| F15 | Systematic review screening & prioritisation | T15, T18 | C/W | WP-14 | TA-16 | L8 | V1 |
| F16 | PRISMA 2020 accounting & export | T15 | C | WP-14 | TA-16 | L8 | V1 |
| F17 | Meta-analysis | T19 (metafor oracle) | D/W | WP-16 | TA-18 | L3 | V1-PARTIAL (pairwise, independence-gated) |
| F18 | Clinical guideline analysis | T07 (GuidelinePack), T13 (D-12), G | C/G | WP-04, WP-10 | TA-06, TA-12 | — | V1-PARTIAL (document-level, version/jurisdiction/supersession) |
| F19 | Freshness, correction, retraction tracking | T15, T05, G | C/G | WP-04 | TA-06, TA-19 | L10 | V1 |
| F20 | Living surveillance alerts | T15, T28c, G | A/REF/G | WP-17 | TA-19 | L10 | V1 |
| F21 | Secure document ingestion | T20, T10, T12 | D/C | WP-13 | TA-15, TA-26 | — | V1 |
| F22 | OCR (EN/AR) + critical-value verification | T20, T29, T16 | D/ARTIFACT/C | WP-13 | TA-15 | — | V1 |
| F23 | Private local vault | T03, T02, T04 | C | WP-03 | TA-05 | — | VS-1 |
| F24 | Packs & signed offline updates | T07, T25 | C/D | WP-04, WP-24 | TA-06, TA-28 | — | V1 |
| F25 | No-silent-egress network broker | T05, T06 | C/REF | WP-04, WP-23 | TA-21, TA-29, TA-30 | — | VS-1 |
| F26 | Local synthesis with template fallback | llama.cpp (D-06), G | D/G | WP-12 | TA-14 | — | VS-1 (template) / V1 (generator) |
| F27 | AnswerProofManifest & reproducible snapshot | G (P00 contract) | G | WP-12 | TA-14 | L7 | VS-1 |
| F28 | Desktop workstation | T36 | C | WP-18a, WP-18 | TA-20 | — | VS-1 (Ask) / V1 |
| F29 | Accessibility | T36 tests, G | C/G | WP-19 | TA-22 | — | V1 |
| F30 | FHIR patient context (read-only) | T09, T17 | C | WP-21 | TA-24 | — | DEFERRED until Issue #4 (patient context is clinical scope) |
| F31 | Mobile Ask / Scan / Saved | T24, T03, T20, T29 | D/C | WP-22 | TA-25 | — | V1-PARTIAL (after desktop V1) |
| F32 | Desktop↔mobile pairing/sync | iroh (candidate) | D | — | — | — | DEFERRED (P17) |
| F33 | Interop exports (EBMonFHIR, RIS, SoF, EvidenceSnapshot) | T26, T15, T18 | REF/C/W | WP-10, WP-14 | TA-12, TA-16 | L11 | V1 |
| F34 | SafeEvidenceBench | T14, T27, T28, SYNERGY, BEIR | C/BENCH | WP-20 | TA-23 | — | V1 |
| F35 | Citation-context signal (supporting/contrasting) | none admissible | — | — | — | L6 | DEFERRED |
| F36 | Voice | sherpa-onnx (candidate) | D | — | — | — | DEFERRED (P19) |
| F37 | Computable guidelines (CQL/CPG) | T33 | W | — | — | — | DEFERRED (P13) |
| F38 | Release packaging, SBOM, notices | T11, T25, Tauri bundler | C/D | WP-24 | TA-02, TA-28 | — | V1 (Windows first) |
| F39 | Security/privacy qualification | T10, T12 | C/G | WP-23a, WP-23 | TA-21, TA-26, TA-27, TA-29 | — | V1 |

Coverage check: 39 features; 39 have a source decision; 34 are scheduled in
V1/VS-1 with a WP and an acceptance test; 5 are explicitly DEFERRED with a
named future phase or gate (F30 keeps its WP-21/TA-24 definition for when
Issue #4 admits patient context). No feature is planned as
generic greenfield where a donor exists (verified in
`docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md`).

# SafeEvidence — REA Competitor Dossier and Copy-First Planning Handoff
**Date:** 2026-10-19 (Asia/Riyadh)  
**Repository:** TheHalfMoon/SafeEvidence  
**Status:** RESEARCH COMPLETE FOR PUBLIC-SURFACE BASELINE; AUTHENTICATED PRODUCT FLOWS NOT EXAMINED. PLANNING ONLY. NO PRODUCT CODE IMPLEMENTED.

## Scope and evidence discipline
This dossier was produced for a founder-authorized, *planning-only* competitor/source study using the official morluto/rea CLI (rea-agents 6.7.0) on an isolated, new Vivaldi headless profile on the founder's Mac. REA observed publicly accessible website pages using CDP; it did not inspect behind-login workflows, private APIs, server algorithms, or protected code. Evidence IDs below correspond to raw machine-readable files in `docs/research/rea-2026-10-19/`.

**Evidence levels:** REA_OBSERVED = concrete public page DOM/accessibility/script metadata; OFFICIAL_DOC = the vendor's public documentation/product claims (not independent performance verification); INFERRED = architecture/design recommendation; BLOCKED = live REA observation did not succeed.

No code was extracted from closed-source products. Do not call public website JavaScript the full proprietary product source. Permissions to copy/modify/rebrand source code are asserted by the founder; source accessibility, per-component rights, embedded assets, distribution conditions, and provenance still need exact adoption records without publishing the founder's sensitive agreements.

## Ranked competitor research targets

| Rank | Target | Observation | Differentiator to study | SafeEvidence design requirement |
|---|---|---|---|---|
| 1 | OpenEvidence | REA_OBSERVED on public EvidenceGrade article (127 recorded scripts, 642 accessibility nodes); not logged-in application | Physician query-to-evidence experience and EvidenceGrade certainty visualization | Clinician-facing response with claim-level supporting passages, strength/sufficiency/applicability distinct, and ASK_MORE/ABSTAIN |
| 2 | Elicit | REA_OBSERVED public systematic review product page (7 scripts), vendor workflow documentation | Reproducible search, dual screening, inclusion/exclusion reasons, source-anchored extraction, PRISMA | Reuse actual screening/extraction code donors, preserve protocol and all decisions |
| 3 | Scite | BLOCKED (403 CloudFront from Mac); OFFICIAL_DOC available | Smart Citations support/contrast/mention, reference checks, alerts on retractions | Citation-context module **plus** direct claim-to-span verification: do not confuse citing with proving |
| 4 | GRADEpro | REA_OBSERVED public help feature page (13 scripts) | PICO evidence tables, GRADE certainty, Evidence-to-Decision frameworks, recommendation workspaces | Transparent study-design-specific evidence appraisal, SoF/EtD with explicit authorship and uncertainty |
| 5 | Consensus | REA_OBSERVED public home page (18 scripts) | Medical Mode, Deep Search, yes/no/mixed evidence presentation | Source-scoped evidence search, contradiction navigator, study/setting specificity, avoid misleading consensus percent |
| 6 | Epistemonikos | BLOCKED (403 CloudFront from Mac); OFFICIAL_DOC available | Evidence Matrix, systematic review-to-primary-study connections, deduplication of reports | Study/Report/SourceArtifact separation, publication-thread grouping and overlap matrix |

### Exact REA evidence IDs and inspected target URLs
- **OpenEvidence** — `ev_a466c92514e9b400f46b5f2817bb56a78058ef6c25efa31b8b1428f39b848c5d` — https://www.openevidence.foundation/blog/introducing-evidencegrade-grading-the-strength-of-medical-evidence-in-real-time — `openevidence-inspect.json`
- **Elicit** — `ev_c1eebb63042099f501493595c576a939c17269f0b37cdbcfc9177faf5b194f05` — https://elicit.com/solutions/literature-review — `elicit-inspect.json`, `elicit-summary.json`
- **Scite** — `ev_735a6eef6b50be7db0bbf1c3f2af64a3c3f95c8f012e9f97f4d2b73ef5d18e41` — https://scite.ai/features — 403; `scite-inspect.json`
- **GRADEpro** — `ev_a09edf8ae1b20d5b7d807878d5735b63dd69b8ee627612e20635955ccac8a7e8` — https://help.gradepro.org/support/solutions/articles/204000075706-key-features-explained — `gradepro-inspect.json`, `gradepro-summary.json`
- **Consensus** — `ev_e0515394d85dbae30495bd95be017bb9845a91c029ca42c46f2b2691785433be` — https://consensus.app/home (redirect observed to https://consensus.app/) — `consensus-inspect.json`, `consensus-summary.json`
- **Epistemonikos** — `ev_57fd73c6d02af94cf365ad8246813d2a4e9227e185e32e8067f74c3ccb264bae` — https://www.epistemonikos.org/en/ — 403; `epistemonikos-inspect.json`

**REA process limitation:** A separate attempt to run `analyze-web-bundle` on OpenEvidence's public Next.js page exhausted the default Node.js ~2 GiB heap; no bundle-analysis output was produced. A successful passive `inspect-web-page` capture exists and must not be conflated with successful bundle decompilation. Reattempt only with a bounded resource budget if actually needed.

### Official references (public product documentation, not implementation proof)
- OpenEvidence EvidenceGrade launch (2026-07-09): https://www.openevidence.foundation/blog/introducing-evidencegrade-grading-the-strength-of-medical-evidence-in-real-time
- Scite features: https://scite.ai/features ; Scite September updates released 2026-10-06: https://scite.ai/blog/september-2026-release-notes
- Elicit current workflows: https://support.elicit.com/en/articles/14757543-getting-started-with-elicit-which-workflow-should-i-use (Find Papers / Extract Data became Research Agent skills on 2026-09-30)
- Elicit review pipeline: https://elicit.com/solutions/literature-review ; vendor accuracy marketing is not independently validated
- GRADEpro key features: https://help.gradepro.org/support/solutions/articles/204000075706-key-features-explained
- GRADEpro EtD: https://help.gradepro.org/support/solutions/articles/204000076809-etd-templates
- Consensus Medical Mode: https://help.consensus.app/en/articles/13404479-medical-mode
- Consensus Meter documented caveats (2026-04-22): https://help.consensus.app/en/articles/10069920-the-consensus-meter
- Epistemonikos study/report matrix: https://test.epistemonikos.org/en/about_us/how_to_use ; https://test.epistemonikos.org/en/about_us/methods
- Official REA tool: https://github.com/morluto/rea

## Important findings for differentiation

1. **OpenEvidence / EvidenceGrade:** A visible confidence-strength display is not automatically an independently validated formal GRADE evaluation. SafeEvidence must separate source quality, design-level certainty, patient applicability, conflicts, coverage, freshness, model confidence and signed review state. Every material claim gets source-span verification.
2. **Scite:** Support/contrast/mention is a *citation statement* classification, not a direct assessment that a published result supports an arbitrary patient-specific claim. Add direct biomedical entailment/rationale checks and review of actual linked results.
3. **Elicit:** Search, screen, extract and synthesize form a reproducible pipeline, not an AI chat overlay. Capture query history, databases, screening criteria, exclusions, reviewers, quote provenance, quality-control and PRISMA accounting. Remember the September 2026 Research Agent workflow update.
4. **GRADEpro:** Keep evidence-to-decision separate from automatic recommendations; enable explicit GRADE downgrade/upgrade rationale, SoF tables and audit of reviewer decisions. Medical decision claims remain release-gated.
5. **Consensus:** The documented Meter summarizes a selected set of papers and can ignore PICO detail (the company's own example discusses adult-vs-child mismatch). SafeEvidence must not equate vote counts with evidence certainty. Its Medical Mode is a useful benchmark for specialty/journal/guideline filters, not a substitute for transparent corpus rights.
6. **Epistemonikos:** Model a canonical Study distinctly from each Report/SourceArtifact, map primary studies to overlapping reviews, avoid double-counting repeated study reports, and show publication-thread provenance. Highlight supersession/retraction events.

## Copy-first candidate donor map already present in SafeEvidence
These are *existing candidate decisions from the repository*, not verified latest import pins. Claude must recheck live code and rights-admission by exact source SHA before promoting any source.

| Capability | Reuse candidates already documented | Best adoption posture |
|---|---|---|
| Evidence identity, private key custody, FHIR, packs, network | TheHalfMoon/MedScale | COHERENT_COPY bounded Rust modules, tests and fixtures; not whole workspace |
| Persistent SQLCipher/WAL private vault | TheHalfMoon/ottari + MedScale key/writer-lock helpers | Compare qualified slices; do NOT take MedScale whole-file EncryptedVault as canonical |
| Deterministic safety/policy and abstention | TheHalfMoon/commandMed | Copy behavior + tests; adapt clinician evidence semantics |
| Calibration and selective risk | TheHalfMoon/DAL | Copy benchmark code/calibration metrics and test harnesses |
| Medical grounding and terminology | maziyarpanahi/openmed + MedScale + SafeOCR | Copy/adapter behind SafeEvidence contracts, carry span tests |
| Scientific claim check | MultiVerS + SciFact + evidence-inference | Qualified worker/benchmarks; verify model/data terms separately |
| Systematic review screening | ASReview + evidence-surveillance/es3 | Copy/worker with exclusion and provenance logs |
| PICO/effect extraction | PICOX + Evidence Inference + RRnlp | Copy selected modules only after concrete suitability evidence |
| Meta-analysis | statsmodels / suitably qualified metafor | Depend/selected worker; don't rewrite standard stats |
| PDF ingestion + OCR | Xberg vs docling.rs; PaddleOCR; SafeOCR | Empirical bake-off; select default, preserve fallback if warranted |
| Search/rerank | SQLite FTS5, MedCPT, fastembed-rs, sqlite-vec | Reuse libraries and model with exact model/data admission |
| Guidelines, decision forms | cqframework/clinical_quality_language, HL7/EBMonFHIR | Vendor/depend on standard execution tools after qualification |
| Native mobile | UniFFI + ottari | Depend on bindings, copy only compatible local/mobile contracts |
| No-silent-egress security | Kernux + MedScale | Transplant policy/tests, verify isolated networking |

Other founder repos named in SOURCE_LEDGER.md should be inspected for newer/stronger code, including Morize, Inercative, Wispral and safety/tooling repos. Do not assume they improve the selected architecture without actual source comparison.

## Planning decisions Claude must make
1. Produce a **verified candidate SOURCE→EXACT FILE/CRATE→DESTINATION map**. Each row needs revision, dependency closure, test fixtures, copy method (copy/vendor/depend/worker/FFI/reference), evidence, test gate and known trade-offs.
2. **Build vs copy:** prohibit generic greenfield engineering where a qualified implementation exists. Legitimate new code is confined to canonical evidence semantics, claim-proof admission, result/patient applicability, Arabic/English UX, and glue.
3. **One cohesive MVP vertical slice** from question → PICO → retrieval → document parsing → claims → sufficiency/contradiction → evidence brief or abstention, then stage systematic review/SoF/EtD/mobile.
4. Separate **engineering-ready** from **clinically validated / regulatorily qualified**. No patient-specific diagnosis, prescribing or triage release from synthetic-only tests.
5. Preserve SafeEvidence core principles: local-first; useful offline; no mandatory paid/cloud backend; no silent remote fallback; Arabic+English; measured 16-GB CPU desktop first; native mobile later; source and pack rights; current-validity overlays; no model-generated clinical claim committed without AnswerProofManifest.
6. Reconcile existing P00 CLOSED_CANONICAL, P01 PRE_ENTRY_GATES_PENDING and current issue gates; do not manufacture approval. Do not demand public disclosure of founder's confidential grant documents; non-sensitive durable reference, who/what scope, and separate transitive license analysis suffice for planning.
7. Use falsifiable metrics: source retrieval recall and coverage, source-span entailment accuracy, unsupported-claim rate, contradiction detection, study-level dedup, screening sensitivity and audit completeness, abstention selective risk, bilingual robustness, memory/CPU/latency, privacy/no-network tests.
8. Document required **authenticated REA follow-ups** (Scite, OpenEvidence application flow, Elicit Research Agent if available, Epistemonikos; only from authorized access, no bypass). Do not invent observations.

## Requested Claude deliverables — PLANNING ONLY
- Updated coherent `docs/MASTER_PLAN.md`, `docs/COPY_FIRST_SOURCE_PLAN.md`, `docs/REUSE_FIRST_IMPLEMENTATION_MAP.md`, `docs/SOURCE_LEDGER.md` as necessary; preserve binding safety rules.
- New `docs/research/REA_TO_FEATURE_GAP_MATRIX_2026-10-19.md` and `docs/PLAN_READY_TO_IMPLEMENT_2026-10-19.md`.
- Complete source transplant work packets (exact paths and tests), phase dependency order, and launch qualification gates.
- Evidence-backed comparison matrix vs OpenEvidence/Scite/Elicit/GRADEpro/Consensus/Epistemonikos, tagged OBSERVED/CLAIM/INFERRED/UNVERIFIED.
- Explicit deferred issues and blockers, with owners/acceptance criteria; no false blanket status COMPLETE.
- No application-code changes, no copying donor bytes, no large install, no releases.
- Run doc consistency tests, open a reviewable planning PR when ready; do not merge without normal governance checks.

**End of research dossier.**

# SafeEvidence Implementation Work Packets — V1

Status: **PLANNING_BASELINE_V1** — freeze state is recorded only in `docs/PLAN_FREEZE.md`. Each packet is one bounded branch/PR
series. `T##` refers to `SOURCE_TRANSPLANT_MATRIX_V1.md`; `TA-##` to
`TEST_ACCEPTANCE_MATRIX_V1.md`; `D-##` to `ARCHITECTURE_SPEC_V1.md`.

Gate states (see `docs/PLAN_FREEZE.md` §4):
- `GATE_ADMISSION` — needs a signed `VERIFIED_ALLOWED` rights row for the listed T## (Issue #5) **and** a founder-signed synthetic-engineering scope extension beyond G01a (stdlib-only today).
- `GATE_CLINICAL` — additionally needs the intended-use/evaluation charter (Issue #4) and named phase owner (Issue #3).
- `GATE_TRUST` — additionally needs release/key-custody owner (Issue #5).
- `DEFERRED` — out of V1.

Reuse codes per task: **C** copy, **V** vendor, **D** depend, **A** adapt, **W** worker, **P** port, **G** greenfield-justified.

| WP | Title (phase) | Tasks with reuse code | Depends on | Exit criteria (all objective) | Gate |
|---|---|---|---|---|---|
| WP-00 | Rights admission & provenance tooling (P01) | C: T11 SBOM generator + `deny.toml`; C: T30 provenance gate; G: admission-row validator extending `p01_candidate_integrity.py` | — | TA-01, TA-02 pass; first admission rows for VS-1 donors (T01,T03,T05,T07,T13,T14,T15,T17,T36 + crates `rusqlite`,`tauri`) signed by rights owner; model-bearing crates (`ort`, `fastembed`) admitted with their first model row (EXT-07) | GATE_ADMISSION (owner signature) |
| WP-01 | Workspace, CI, supply chain (P01) | C: MedScale CI patterns (pinned 2026-10-08 candidates); D: `cargo-deny`, `cargo-audit`; A: extend existing exact-head workflows; G: toolchain bump to ≥ 1.98.1 for T03 (C16); separate Cargo workspace for the docs worker (D-01) | WP-00 | Clean checkout builds/tests on Windows/Ubuntu/macOS; `cargo deny check` 0 errors; SBOM emitted; TA-03 and TA-29 pass | GATE_ADMISSION |
| WP-02 | Canonical contracts (P02) | C: T01; G: Study/Report/StudyArm/Result/Comparison/OverlapGroup/AnswerProofManifest/ControlAction/TerminalOutcome types per P00 contracts; C: T17 span tests | WP-01 | TA-04 (round-trip, no-coercion, span-coordinate, study-independence fixtures) 100% pass | GATE_ADMISSION |
| WP-03 | Private vault & keys (P02) | C: T03 slice (single key hierarchy); REF/fallback: T02; C: T04 only if needed; C: T12 probes | WP-02 | TA-05 durability campaign (kill-at-every-commit-point, disk-full, restore-to-clean, key loss, WAL/temp residue) per `P00_VAULT_DURABILITY_CONTRACT.md`; donor tests pass unchanged except the adapted journal-kill test (T03) | GATE_ADMISSION |
| WP-04 | Evidence acquisition, public store, validity overlay (P03) | C+W: T15 adapters/parsers (fetch via broker); C: T05 broker; C: T07 pack format; D: T25 tough; G: PubMed baseline+daily-update replay, Crossref/Retraction Watch overlay, Europe PMC full-text rights gate, validity epochs; G: outbound-query preview/consent and private query-derived store (D-16) | WP-02, WP-03 | TA-06: replaying a recorded baseline+update fixture is byte-deterministic; deleted/retracted PMIDs leave active search; rights-unknown items never enter a pack; `NETWORK_LOCKED` = 0 bytes (TA-21); TA-30 outbound-query disclosure | GATE_ADMISSION (+ corpus rights per item) |
| WP-05 | Study/report linkage & dedup (P02/P03) | C: T15 `dedupe.py`/`uncertain.py`; A: T28c linkage logic (PMID↔NCT↔review); G: overlap groups and double-count guard | WP-02, WP-04 | TA-07: on the synthetic multi-report fixture set, study-level dedup precision = recall = 1.0; zero double-counted studies in any pooled or vote output | GATE_ADMISSION |
| WP-06 | Bilingual text & query layer (P04/P05) | C/P: T17 span projection; D: ICU/unicode-normalization; G: Arabic→English PICO normalization; tournament: multilingual encoder vs translate-then-retrieve | WP-02 | TA-08: Arabic-script offsets round-trip 100%; Arabic/English parallel query set recall@20 ratio ≥ 0.90 or Arabic Ask returns reason-coded `ASK_MORE`/`ABSTAIN` | GATE_ADMISSION |
| WP-07 | Retrieval: FTS5 → MedCPT → sqlite-vec (P04/P05) | D: rusqlite bundled SQLCipher (FTS5); D: T21 fastembed (no default features); ARTIFACT: T23 MedCPT ONNX; D: T22 sqlite-vec (gated); O: MedScale lexical retriever as oracle; G: retrieval funnel trace | WP-04, WP-06 | TA-09: BM25 baseline measured first; dense layer promoted only if nDCG@10 and study-level recall@50 improve on held-out set with non-overlapping 95% bootstrap CI; funnel counts present in 100% of traces | GATE_ADMISSION |
| WP-08 | Claim-support verification (P06) | C: T27 SciFact evaluator; W: T27b MultiVerS oracle; G: span/number/unit/negation checks; tournament: NLI cross-encoder (ONNX) | WP-02, WP-07 | TA-10: on SciFact dev, label macro-F1 reported vs MultiVerS oracle; on synthetic numeric-perturbation set, 100% of altered numbers/units/negations flagged; unsupported-claim rate on engineering holdout ≤ 5% at chosen operating point (clinical holdout = GATE_CLINICAL) | GATE_ADMISSION / GATE_CLINICAL for holdout |
| WP-09 | Applicability gate (P07) | G: per-source PICO-vs-question applicability with reasons; benchmark: T28/T28d PICO corpora | WP-06, WP-07 | TA-11: on the population-mismatch fixture (modelled on observed R-CO-2 failure), 100% of mismatched sources are excluded or downgraded with reason | GATE_ADMISSION |
| WP-10 | Appraisal & GRADE structures, SoF export (P07) | REF: T26 EBMonFHIR profiles; G: design profiles (RoB 2, ROBINS-I, QUADAS, AMSTAR 2 fields as data), 5 downgrade + 3 upgrade domains, proposal vs confirmed state; benchmark: T28b/T34 RoB (oracle only) | WP-02, WP-05 | TA-12: every certainty rating carries per-domain reasons; no rating marked CONFIRMED without a human actor; SoF/EBM export validates against pinned FSH-derived JSON schemas | GATE_ADMISSION |
| WP-11a | Decision assurance, VS-1 subset (P08) | P: T13 mechanics → Rust; O: P00-conformant T13 fixture subset; G: deterministic sufficiency rules over support + applicability only | WP-08, WP-09 | TA-13 on the P00-conformant subset; exactly one TerminalOutcome per run; no percentage rendered (D-13) | GATE_ADMISSION |
| WP-11 | Decision assurance, full (P08/P09) | extends WP-11a with appraisal inputs; C: T14 metrics | WP-11a, WP-10 | TA-13 full row; DAL metrics reproduce DAL test vectors | GATE_ADMISSION |
| WP-12 | Synthesis & proof admission (P10) | G: deterministic evidence-brief template (always available); D: llama.cpp (D-06) tournament as sandboxed out-of-process worker; G: AnswerProofManifest atomic admission | WP-03, WP-11a | TA-14: generator disabled ⇒ template brief still produced; every committed claim has span + support label + validity epoch; draft never shown as committed; generator crash ⇒ reason-coded outcome | GATE_ADMISSION |
| WP-13 | Documents & OCR (P12) | D: T20 Xberg core (`pdf-native` only) + `xberg-paddle-ocr` incumbent; BENCH: T20c docling.rs (no default features); ARTIFACT: T29 PaddleOCR ONNX (EN+AR); C/W→P: T16 SafeOCR verification (`ocr.py` excluded); C: T10 probes | WP-02, WP-03, WP-23a | TA-15: fuzz 24 h no crash escapes worker; page/region coordinates preserved; critical-number fixture: 0 silent wrong values (conflicts → unresolved); Arabic OCR CER reported per pre-registered fixture | GATE_ADMISSION |
| WP-14 | Deep Review: protocol, screening, PRISMA (P18) | C+W: T15 screening/review logs, PRISMA summary; W: T18 ASReview; G: protocol object and audit export | WP-04, WP-05 | TA-16: replay of review event log reproduces identical PRISMA counts; on SYNERGY subset ASReview worker WSS@95 within ±2 pts of upstream ASReview simulation at same seed; prioritisation never auto-excludes | GATE_ADMISSION |
| WP-15 | Structured extraction (P18) | G: quote-anchored extraction proposals (generator or rule); BENCH: T28 Evidence Inference, T28d PICOX, T28b RRnlp | WP-12, WP-14 | TA-17: 100% extracted values carry source quote span; extraction accuracy reported on Evidence Inference test split; values remain PROPOSED until confirmed | GATE_ADMISSION |
| WP-16 | Meta-analysis (P18) | D+W: T19 statsmodels; O: metafor (dev only) | WP-05, WP-15 | TA-18: pooled estimates match statsmodels and metafor reference outputs to 1e-6 on golden fixtures; pooling refused when overlap/independence unknown | GATE_ADMISSION |
| WP-17 | Living surveillance & alerts (P03/P18) | A: T15 adapters + WP-04 overlay; REF: T28c, Elicit Routines behavior; G: per-query opt-in surveillance (D-16) | WP-04, WP-12 | TA-19: injected retraction/new-trial fixture changes validity epoch and produces an alert naming the cause within one update cycle; historical answers unchanged; TA-30: no saved query is sent without its own opt-in | GATE_ADMISSION |
| WP-18a | Desktop shell + Ask view, VS-1 subset (P11) | C: T36 shell (CSP tightened); G: Ask view with funnel, span jump, outcome display | WP-02 (skeleton with mocked core), WP-12 (Ask wiring) | TA-20 Ask subset; TA-21 | GATE_ADMISSION |
| WP-18 | Desktop workstation, full (P11) | extends WP-18a; G: Evidence/Deep Review/Documents/Packs/Settings views | WP-18a, WP-13, WP-14 | TA-20: shell checklist (cache, crash dumps, clipboard, WebView storage, CSP, capability allowlist) passes; E2E Ask flow via tester-army/e2e-derived spec; network monitor shows 0 bytes in LOCKED mode | GATE_ADMISSION |
| WP-19 | Bilingual UX, RTL, accessibility (P11) | G: Arabic/English strings, RTL layouts; D: platform a11y APIs | WP-18 | TA-22: axe-core 0 serious violations; keyboard-only completion of Ask; RTL snapshot tests pass for all views | GATE_ADMISSION |
| WP-20 | SafeEvidenceBench (P20) | C: T14; C: T27; BENCH: SYNERGY, BEIR, T28; G: task design + split governance | WP-07..WP-12 | TA-23: benchmark build reproducible from pinned inputs (identical digests); results packet per run; no clinical claim emitted | GATE_ADMISSION (+ GATE_CLINICAL for clinician holdout) |
| WP-21 | FHIR patient context (P14) | C: T09; C: T17 FHIR tests where useful | WP-02, WP-03 | TA-24: donor FHIR tests pass; answer shows exactly which context facts were used; no external writes possible | GATE_CLINICAL (patient-context use) |
| WP-22 | Mobile foundation + Ask/Scan (P15/P16) | D: T24 UniFFI; C: T03 protectors (Keychain/Keystore); D: T20 FFI + T29 models; G: native shells | WP-03, WP-07, WP-11, WP-13 | TA-25: opens vault, loads ≤ 500 MB pack, answers offline within mobile ceilings; screenshot/app-switch privacy tests pass | GATE_ADMISSION |
| WP-23a | Sandbox launcher spike (P21, early) | C: T10 plans/probes; G: worker launcher prototype | WP-01 | TA-26 subset: embedded CPython (research worker), ORT (docs worker) and llama.cpp (generator) each start, run a fixture job and are denied sockets/out-of-dir reads on Windows AppContainer, Linux Landlock+seccomp, macOS Seatbelt — or the blocking platform is recorded and D-03/D-06 exit tests trigger | GATE_ADMISSION |
| WP-23 | Security & privacy qualification (P21) | C: T10, T12; G: production worker launcher (T10 is partial), threat-model closure, support-bundle redaction | all runtime WPs, WP-23a | TA-21 (no-egress), TA-26 (sandbox escape attempts denied), TA-27 (prompt-injection in retrieved/doc content cannot change outcome or trigger tools) | GATE_ADMISSION; real-PHI readiness = GATE_CLINICAL |
| WP-24 | Release & packaging (P22) | C: T11; D: T25; D: Tauri bundler; G: offline installer + pack updater | WP-18, WP-23 | TA-28: reproducible SBOM; signed installer for Windows first; offline install + pack update + rollback demonstrated | GATE_TRUST |
| WP-M0 | Measurement baseline (cross-cutting) | C: MedScale perf harness pattern (`perf_harness_027.rs`) | WP-07, WP-12, WP-13 | Freezes §5 budgets with measured values on the reference machine (versioned amendment) | GATE_ADMISSION |
| — | Guideline computability (P13) | REF/W: T33 CQL | — | — | DEFERRED |
| — | Desktop↔mobile pairing/sync (P17) | candidate `iroh` | — | — | DEFERRED |
| — | Voice (P19) | candidate `sherpa-onnx` | — | — | DEFERRED |
| — | Citation-context (Scite-like) signal | BENCH: none admissible | WP-07 | discovery-only signal | DEFERRED (L6) |

## First end-to-end vertical slice (VS-1)

**Path:** question (EN or AR) → PICO normalization → FTS5 retrieval with
funnel counts → evidence spans → deterministic + NLI support check →
applicability → sufficiency → `ANSWER_WITH_CAUTION` evidence brief (template)
**or** reason-coded `ABSTAIN`/`ASK_MORE`/`CONFLICT` → AnswerProofManifest
committed in the vault → shown in the desktop Ask view with span jump.

**Packets:** WP-00, WP-01, WP-02, WP-03 (vault open/commit/restart only),
WP-04 (offline import of a recorded fixture pack, no live fetch), WP-06
(normalization + RTL rendering), WP-07 (BM25 only), WP-08 (deterministic
checks only in VS-1a; the NLI model joins in VS-1b after its EXT-07 model row),
WP-09, WP-11a, WP-12 (template only), WP-18a.

**Corpus:** VS-1a = synthetic fixture corpus and no model weights (rights
dependency limited to code rows); VS-1b = rights-admitted public subset and the
first admitted NLI model once Issue #5 records item and model rights.

**VS-1 done when:** TA-04, TA-05 (subset), TA-09 (BM25 measured), TA-10
(numeric set), TA-11, TA-13 (P00-conformant subset), TA-14, TA-20 (Ask E2E),
TA-21, TA-29 all pass on the
same commit on Windows + Ubuntu CI; resource values recorded against §5.

# SafeEvidence Source Transplant Matrix — V1

Status: **PLANNING_BASELINE_V1** — freeze state is recorded only in `docs/PLAN_FREEZE.md`.
Admission state: **NO_ADMISSIONS**. Nothing in this file authorizes copying a byte.
Machine-readable pins: `docs/evidence/source_transplant_pins_2026-10-19.json`
(332 files across 39 packets, Git blob OID + size, pinned at heads observed
2026-10-19; upstream heads may have moved since: re-verify at admission).

## 1. How to read this matrix

- **Mode** uses the `AGENTS.md` vocabulary. `COPY_BOUNDED` = copy the listed
  files (and their tests) into the named destination, rename to SafeEvidence
  identifiers, keep original notices. `DEPEND` = pinned crate/package, no copy.
  `WORKER` = runs only inside the sandboxed local research worker (§4).
  `ARTIFACT_IMPORT` = model/data bytes via a verified Pack.
- **Rights state** is the state *today*. Every row still needs a
  `VERIFIED_ALLOWED` row in `docs/DONOR_RIGHTS_REGISTER.md` before import
  (Issue #5). For founder-owned repositories the founder asserts permission;
  the register still records contributor scope and the non-sensitive grant
  reference. Confidential grant documents are never published.
- **Branding:** copied code is renamed to `safeevidence-*` crates / `safeevidence`
  Python packages. Original copyright headers, `LICENSE`, `NOTICE` and author
  credits are retained in `THIRD_PARTY_NOTICES.md` and per-directory notices.
- **Visibility note:** as of 2026-10-19, `DAL`, `ottari`, `kernux` and `Morize`
  are **private** (they were public when first listed in `SOURCE_LEDGER.md`).
  Their identities were already disclosed in this public repository. Path-level
  pins for them are **not** published: the pins JSON carries only a SHA-256
  commitment, file count and size per packet; the full list is a founder-held
  private record. Other private founder repositories inspected are not named.

## 2. Founder-owned donors (inspected by clone at the pinned head)

| ID | Capability | Repo @ commit | Exact files (pins JSON) | Mode | SafeEvidence destination | Required adaptation | Tests that travel | Rights state |
|---|---|---|---|---|---|---|---|---|
| T01 | Source identity, IDs, scope, derived-artifact loss class, evidence corpus manifest, retrieval-hit-is-relevance-only | MedScale @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | `crates/medscale-contracts/src/objects/*.rs`, `src/evidence/mod.rs` (15 files, 47.9 KB) | COPY_BOUNDED + extend | `crates/safeevidence-contracts/src/{objects,evidence}` | Add Study/Report/Result/Overlap types (P00 Study Independence Contract), rights class, publication state, validity epoch; drop `SyntheticOwned`-only rights enum | `object_roundtrip.rs`, `object_no_coercion.rs`, `source_immutability.rs`, `text_span_coords.rs`, `record_semantics_019.rs` | PUBLIC_LICENSE Apache-2.0 + FOUNDER_OWNED |
| T02 | Key provider, DEK wrap, Argon2 passphrase, recovery codes, OS keystore abstraction | MedScale @ same | `crates/medscale-keys/src/*.rs` (8 files pinned for reference) | REFERENCE; COPY_BOUNDED fallback limited to `provider.rs`/`recovery.rs`/`aead_wrap.rs` **only** if WP-03 finds a function T03 lacks | `crates/safeevidence-vault` (no separate keys crate) | T03 is the single key hierarchy (D-04); `pack_trust.rs` and `device_key.rs` (synthetic signing seeds) are **not** copied; pack trust has one path (T07 manifest digests + T25 TUF metadata) | in-file unit tests if fallback used | same |
| T03 | **Private vault**: SQLCipher, lease/single writer, nonce, manifest, migration, recovery, restore, deletion, rotation, backup (create/verify/restore/publication), OS protectors (DPAPI, Apple Keychain, Android Keystore, Linux Secret Service) | ottari @ `73706029849bcbe51243624e37f03a1969dc74ca` | vault modules of the `himsat-core` crate, excluding unrelated product modules (37 files incl. tests; path list held in the founder's private pin record, public commitment in the pins JSON) | COPY_BOUNDED (coherent slice) | `crates/safeevidence-vault` | Remove coupling to unrelated donor-product modules; replace the donor event crate with SafeEvidence audit events; pin rusqlite `bundled-sqlcipher-vendored-openssl` | six donor vault tests (journal kill, recovery negatives, crypto adversarial, plaintext spill, copy/verify/publish, protector fail-closed); the journal-kill test is **adapted** because it depends on an excluded module | Apache-2.0 + FOUNDER_OWNED; repo now private |
| T04 | Writer lock / path claim | MedScale @ `5c33d77…` | `medscale-storage/src/{writer_lock,claim}.rs` | COPY_BOUNDED | `safeevidence-vault::lock` | Only if T03 lease fails a P02 test; otherwise REFERENCE | `lease_single_writer.rs` | Apache-2.0 |
| T05 | Network broker: allowlist fail-closed, typed purpose/data class, fixture transport, URL/private-IP/redirect validation | MedScale @ same | `crates/medscale-network/src/*.rs`, `contracts/src/network/mod.rs` | COPY_BOUNDED | `crates/safeevidence-network` | Modes `NETWORK_LOCKED / EVIDENCE_UPDATE_ONLY / SELECTED_CONNECTORS`; add PubMed/Crossref/Europe PMC destinations | `network_broker_013.rs` | Apache-2.0 |
| T06 | Egress/decision vocabulary | kernux @ `2085b6ed1121b1a94c66c076bdd6b578da4dad0d` | policy-crate egress/decision modules (3 files; private pin record) | REFERENCE (copy tests only if T05 lacks a case) | `safeevidence-network` tests | none | — | Apache-2.0; repo private |
| T07 | Pack manifest/admission/store, content addressing, epoch/anti-rollback | MedScale @ same | `medscale-pack/src/{format,store,runtime}.rs`, `contracts/src/packs/mod.rs` | COPY_BOUNDED (slice; **not** the 26 kLoC `medscale-pack` crate; `pack_runtime.rs` excluded because it imports the candle/tract runtimes) | `crates/safeevidence-pack` | Pack kinds Evidence/Model/Terminology/Guideline/Benchmark; item-level rights; signatures verified only through T25 TUF targets metadata | `packs_008.rs` (copy); `pack_signer_026.rs` (reference only) | Apache-2.0 |
| T09 | FHIR R4 lexical gate + Patient/Condition/Observation extractors + UCUM subset | MedScale @ same | `crates/medscale-fhir/**` (7 files) | COPY_BOUNDED | `crates/safeevidence-fhir` | Add MedicationStatement/AllergyIntolerance only when P14 demands | `fhir_interchange_020.rs` | Apache-2.0 |
| T10 | OS sandbox plans (Windows Job/AppContainer, Linux Landlock/seccomp/rlimit, macOS Seatbelt) + worker deny-default policy | MedScale @ same | `contracts/src/os_sandbox/*.rs`, `worker_policy/mod.rs`, `bin/os_sandbox_probe.rs` | COPY_BOUNDED (probes, plans, tests; **partial**: the donor header states platform qualification remains OPEN and macOS App Sandbox enforcement is external) | `crates/safeevidence-sandbox` | The launcher that confines the research, docs and generator workers is GREENFIELD_JUSTIFIED work in WP-23; spike WP-23a proves embedded CPython and ORT run under AppContainer/Landlock/Seatbelt before M2 | `os_sandbox_0{30,31,33,38,40,41,52,53}.rs`, `worker_policy_deny_default.rs` | Apache-2.0 |
| T11 | CycloneDX-style release SBOM + deny.toml | MedScale @ same | `medscale-core/src/release_sbom.rs`, `scripts/generate-release-sbom.ps1`, `deny.toml` | COPY_BOUNDED | `tools/release/` | Already a P01 reference candidate (2026-10-08 ledger) | `release_sbom_054.rs` | Apache-2.0 |
| T12 | Privacy probes (temp/WAL/cache residue), hostile MIME | MedScale @ same | `medscale-storage/src/privacy_probes.rs` + tests | COPY_BOUNDED (tests first) | `tests/privacy/` | Point probes at SafeEvidence paths | `privacy_probes_032.rs`, `vault_privacy_023.rs`, `hostile_mime_010.rs` | Apache-2.0 |
| T13 | Deterministic safety/policy state machine (precedence, conflict fail-closed, tool provenance, exactly-one terminal) | commandMed @ `51f73ec05750137e5bd94ffa0765f6383f475fee` | `src/commandmed/spec006/*.py`, spec006 fixtures, `tests/spec006/*` (`data/eval/safety_policy.json` pinned as oracle-only data, never shipped) | ORACLE_COPY (Python, benchmark) + PORT_TO_RUST of mechanics only | `bench/oracles/commandmed_spec006/` + `crates/safeevidence-assurance` | Map vocabulary to `ControlAction`/`TerminalOutcome`; patient lexical policy **not** copied; lexical EMERGENCY classification disabled in V1 (`P00_DECISION_ASSURANCE_CONTRACT.md`) | parity on the **P00-conformant subset** of spec006 fixtures; excluded: `us2-context-safety.json` cases `emergency-keyword-en`, `emergency-keyword-ar-msa` and any other lexical-symptom EMERGENCY case | Apache-2.0 |
| T14 | Calibration & selective-risk metrics (Brier, ECE, NLL, risk–coverage, AURC, unsafe-commit, over-abstain) | DAL @ `e460e766566d233c79b1270d6e425cb2005d9514` | metrics and selective-prediction modules with their tests, as listed in `REUSE_FIRST_IMPLEMENTATION_MAP.md` §5.2, plus one statistics helper (5 files; private pin record) | COPY_BOUNDED (Python, import-path changes only) | `bench/safeevidencebench/metrics/` | Only import paths; keep DAL negative Study-0 results as prior evidence | donor metric tests | Apache-2.0; repo private |
| T15 | **Literature acquisition & review log**: PubMed/OpenAlex/S2/arXiv adapters, provenance-anchored deterministic parsers, title/ID dedupe with uncertain-merge list, append-only screening & review event logs with `ExclusionReason`, PRISMA summary, integrity/lineage | MedOrigin (formerly MESC) @ `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8` | `src/medscale/litdb/*.py`, `src/medscale/provenance.py`, `src/medscale/_layout.py`, `tests/test_litdb_*.py` (38 files, stdlib-only) | COPY_BOUNDED (Python worker) | `workers/research/safeevidence_research/litdb/` | Route all fetches through T05 broker (worker has no sockets; broker returns archived payload); add Europe PMC/Crossref parsers; rename package `medscale` → `safeevidence_research` | all `test_litdb_*` | Apache-2.0; public |
| T16 | Critical-value OCR verification (`VERIFIED_AUTO / REVIEW_REQUIRED / ABSTAINED`), UCUM unit checks, lab-report contracts | SafeOCR @ `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4` | `src/safeocr/{contracts,verification,report,labgold}.py` + 3 tests, `LICENSE`, `NOTICE` (`ocr.py` = REFERENCE: it adds a second OCR route incl. subprocess Tesseract) | COPY_BOUNDED (worker) → PORT_TO_RUST of verification rules after parity | `workers/research/.../ocrverify/` then `crates/safeevidence-docverify` | Generalize from lab reports to dose/decimal/negation categories; Arabic numerals; OCR input comes only from T20 | `test_verification.py`, `test_foundation_contracts.py`, `test_labgold.py` | Apache-2.0; public |
| T30 | Provenance gate tooling | ottari @ `73706029…` | `tools/provenance.py`, `tools/provenance_gate.py` | REFERENCE → COPY_BOUNDED for P01 admission tooling | `tools/governance/` | Already pinned as P01 candidates | — | Apache-2.0; repo private |
| T31 | Study-type → evidence level helper | MedOrigin @ `ec8b1b6…` | `evidence/{grading,models}.py`, `evidence_checks.py` | REFERENCE | — | Too thin; GRADE structures come from T26 | — | Apache-2.0 |
| T32 | Memory relation vocabulary (supports/contradicts/supersedes) | Morize @ `62fc04d01d398da93b4dacf0ab2f33e3f1440462` | relation/decision vocabulary modules (2 files; private pin record) | REFERENCE | — | Vocabulary only; no graph engine exists to copy | — | Apache-2.0; repo private |
| T36 | **Desktop shell skeleton**: Tauri 2 + React 19, strict CSP, capability/permission allowlist, IPC wrapper + tests, bundle config tests | MedScale @ `5c33d77…` | `apps/desktop-tauri/{package.json,vite.config.ts,tsconfig.json,index.html,qa/*}`, `src-tauri/{Cargo.toml,build.rs,tauri.conf.json,capabilities/default.json,src/*}`, `src/{ipc,routes,main}.ts(x)`, `src/*.test.ts` (27 files) | COPY_BOUNDED | `apps/desktop/` | Replace MedScale commands with SafeEvidence command set; keep CSP & capability discipline; drop autogenerated permissions of unrelated features | `routes.test.ts`, `ipc.test.ts`, `bundle-config.test.ts`, `contrast.test.ts`, `identity.test.ts`; tighten donor CSP (`style-src` still allows `'unsafe-inline'`) | Apache-2.0 |

Founder repositories inspected and **not** selected: `Inercative` (TypeScript
product-builder platform; no evidence capability — REJECT_DEFAULT),
`Sentrdel` (security control plane for dev workflows — PROCESS_REFERENCE),
`Signthos` (no license file at head; REFERENCE_ONLY_PENDING_RIGHTS),
`Wispral` (voice; no license file at head; deferred to P19), MedScale
`medscale-pack` model runtimes (`candle_runtime`, `gliner_runtime`,
`onnx_runtime` on tract — REFERENCE; decision D-01 selects ONNX Runtime),
MedScale `encrypted_vault.rs` (P00: not canonical), MedScale lexical
retriever (`core/src/authority/retrieval.rs`: token-overlap scorer —
ORACLE only, FTS5 replaces it).

## 3. External donors (heads pinned 2026-10-19)

| ID | Capability | Repo @ commit (license) | Exact files / artifact | Mode | Destination | Notes / obligations | Rights state |
|---|---|---|---|---|---|---|---|
| T17 | Unicode span/offset integrity, evidence-span audit, terminology matcher/candidates/calibration, multilingual | `maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86` (Apache-2.0; v3.0.0 2026-10-07) | `openmed/core/schemas/span.py`, `core/decoding/spans.py`, `structured/offset_properties.py`, `clinical/evidence_span_audit.py`, `clinical/grounding/{matcher,candidate_generator,calibration,multilingual}.py`, `linkers/base.py`, `fixtures/parity/expected_spans.json` | COPY_BOUNDED (tests + span logic) / PORT_TO_RUST (span projection only) | `crates/safeevidence-text` + worker | Restricted vocab loaders (`athena`, `rxnorm`, `loinc`) excluded; terminology bytes never copied | PUBLIC_LICENSE |
| T18 | Active-learning screening prioritisation, stopping heuristics, RIS IO, simulation | `asreview/asreview` @ `79d568212b2b0a78f9fd7be3c5117dfb890489f9` (Apache-2.0; v3.0.8) | `asreview/models/*.py`, `data/{ris,loader,record}.py`, `metrics.py`, `simulation/simulate.py` | WORKER (pinned wheel) | research worker | Web app excluded; prioritisation is never proof of completeness (P00R) | PUBLIC_LICENSE |
| T19 | Meta-analysis (fixed/random effects, SMD, 2×2 effect sizes) | `statsmodels/statsmodels` @ `b7ec3a7c1a448ed79d75489da4cde6c304c79a21` (BSD-3) | `statsmodels/stats/meta_analysis.py` + `tests/test_meta.py` | DEPEND (worker wheel) | research worker | `metafor` (GPL ≥2, `bc2016e1…`) = development oracle only | PUBLIC_LICENSE |
| T20 | Document extraction + OCR | `xberg-io/xberg` @ `a46c9c9e8b568c71b5a1127978b52b3d5c211c69` (MIT; workspace 1.3.11, latest release v1.3.10) | crate `xberg` with `default-features = false, features = ["pdf-native"]` **only**, plus crate `xberg-paddle-ocr` (`ort` backend; its own dependencies carry no HTTP client). **Not admitted:** `xberg` features `paddle-ocr*` and OCR presets (pull `hf-hub`, `reqwest`, `ureq`), and `xberg-ffi` (defaults include `liter-llm`, `url-ingestion`, `api`, `mcp-http`, `translation`, `summarization-llm`) | DEPEND (exact feature set) | `safeevidence-docs` worker binary in its own Cargo workspace (D-01) | Only the `xberg` core-crate defaults are network-free; TA-29 dependency-tree denial enforces the feature set; mobile uses UniFFI over SafeEvidence crates, not `xberg-ffi` | PUBLIC_LICENSE; native/transitive closure review pending |
| T20c | Document extraction challenger | `docling-project/docling.rs` @ `69eaf416a8c291307c722f1d0eaeb27d23ccf540` (MIT; v2.42.0) | crate `docling` | BENCHMARK_ONLY (challenger) | qualification harness | **Default features enable network** (`fetch-url`, `fetch-images`, `youtube`, remote `vlm`); only `--no-default-features --features pdf` admissible | PUBLIC_LICENSE |
| T21 | Local embeddings + cross-encoder reranking | `anush008/fastembed-rs` @ `473fff39e0b0dfcb89603040a3b1b0e7d4f0934e` (Apache-2.0; v7.1.1; pins `ort =2.0.0-rc.13`) | crate `fastembed` with `default-features = false` (+ `ort-load-dynamic` or bundled ORT) | DEPEND | `crates/safeevidence-retrieval` | Defaults download ORT binaries and use `hf-hub` → both disabled; models loaded only from verified Packs | PUBLIC_LICENSE |
| T22 | Vector projection | `asg017/sqlite-vec` @ `04d28bd21773981e2d266bbf6aa4efbd011eb4f6` (MIT/Apache; v0.1.9, pre-1.0) | `sqlite-vec.c` via `sqlite-vec` crate | DEPEND (gated) | public evidence index DB | Pre-1.0: admitted only if WP-07 maturity tests pass; fallback = exact flat scan in Rust | PUBLIC_LICENSE |
| T23 | Biomedical retriever + reranker | `ncbi/MedCPT` @ `11e129be74102c98d16a11c310b0b5ce74c1db5e` (code: US-Gov public domain); HF weights Query `d83a36cc…`, Article `d05a736d…`, Cross `71caf65d…` (`license: other`) | `retriever/models.py`, `reranker/models.py`, `evals/*` | ARTIFACT_IMPORT (ONNX export → ModelPack) + BENCHMARK | ModelPack | Weight terms read and recorded before export; English-only → Arabic needs WP-06 | weights: RIGHTS_UNKNOWN until model-card review |
| T24 | Rust↔Swift/Kotlin bindings | `mozilla/uniffi-rs` @ `c31f4bc025c7a31eae56b49107f50e6d38e76bc7` (MPL-2.0) | crate `uniffi` | DEPEND | `crates/safeevidence-ffi` | MPL file-level obligations; no modification of MPL files | PUBLIC_LICENSE |
| T25 | TUF client/repo for pack & app updates | `awslabs/tough` @ `98d8eb8b2ce63515d9b4981c938ef6453c5b5771` (MIT OR Apache-2.0) | crate `tough` | DEPEND | `safeevidence-pack::update` | Key custody owner required (Issue #5) | PUBLIC_LICENSE |
| T26 | GRADE / certainty / RoB / recommendation / evidence-report / citation structures | `HL7/ebm` @ `6d29967cc20c07ca2870d25cd3f48a069a1a57bb` (IG `1.0.0-ballot3`, FHIR `6.0.0-snapshot1`) | `input/fsh/artifact-assessment/p-{certainty-of-evidence,risk-of-bias,recommendation-rating}.fsh`, `composition/p-{comparative-evidence-report,guideline}.fsh`, `citation/p-journal-article-citation.fsh` | REFERENCE / EXPORT_CROSSWALK | `docs/specs/ebm-crosswalk` + export module | Internal model stays SafeEvidence-owned; export only; IG license line not asserted in `sushi-config.yaml` — confirm HL7 terms | STANDARD_REFERENCE |
| T27 | Claim/rationale verification benchmark | `allenai/scifact` @ `68b98a56d93e0f9da0d2aab4e6c3294699a0f72e` (code Apache-2.0; claims CC BY 4.0; abstracts ODC-By 1.0) | `verisci/evaluate/lib/{metrics,data}.py` + data release | BENCHMARK (copy evaluator) | `bench/scifact/` | Attribution for CC BY / ODC-By | PUBLIC_LICENSE (separate data terms recorded) |
| T27b | Scientific verifier oracle | `dwadden/multivers` @ `a6ce033f0e17ae38c1f102eae1ee4ca213fbbe2e` (MIT; last push 2023) | `multivers/{predict,model,metrics}.py` + checkpoint | BENCHMARK_ONLY worker | qualification harness | Old torch/Lightning stack; checkpoint terms separate | code PUBLIC_LICENSE; checkpoint RIGHTS_UNKNOWN |
| T28 | Intervention/comparator/outcome result inference corpus | `jayded/evidence-inference` @ `a661e8c14f973398380c8865cf2f27a535aaaf6d` (MIT) | `evidence_inference/models/pipeline.py`, annotations | BENCHMARK | `bench/evidence-inference/` | Article texts are PMC OA items with their own terms | code PUBLIC_LICENSE |
| T28b | RCT/PICO/RoB/design/sample-size classifiers | `bwallace/RRnlp` @ `e1a26b4ed1c8d65f2c2e2558dc9f0918572306d0` (code MIT) | `rrnlp/models/*.py`, `weights_manifest.json` | BENCHMARK_ONLY (was COPY_BOUNDED) | qualification harness | **Weights = Zenodo 5139998 / 5939332 "RobotReviewer v2 models", GPL-2.0**; `minimap/*.pck` are UMLS-derived CUI maps (UMLS license) | code PUBLIC_LICENSE; weights GPL-2.0; minimap RIGHTS_RESTRICTED |
| T28c | Trial↔review linkage helpers | `evidence-surveillance/es3` @ `fa845217690e179d3f8151e97773aabc035d6cfe` (MIT) | `ecitmatch_tools.py`, `update_trials.py`, `bot.py` | REFERENCE (algorithm) | — | Flask/Celery/Postgres app is REJECT_DEFAULT; linkage re-expressed in T15 adapters | PUBLIC_LICENSE |
| T28d | Overlapping PICO extraction | `WengLab-InformaticsResearch/PICOX` @ `f3351c4786bf197efacfcefc1c1e66c36c245842` (MIT) | notebooks + `PICO-corpus-output.zip` | BENCHMARK (was COPY_BOUNDED) | `bench/picox/` | Repository contains notebooks only — no importable module | PUBLIC_LICENSE; corpus terms separate |
| T29 | OCR models (multilingual incl. Arabic) | `PaddlePaddle/PaddleOCR` @ `dab3fe35379033fdcb2d0e9572fac0b36c9a9ebf` (Apache-2.0) | ONNX model artifacts consumed by T20 `xberg-paddle-ocr` | ARTIFACT_IMPORT | OCR ModelPack | Per-model card check; Arabic recognizer must pass WP-06/WP-13 gates | code PUBLIC_LICENSE; models per-card |
| T33 | CQL translator/engine | `cqframework/clinical_quality_language` @ `fb8055df5ff4a2e9be468b7953d37d7cb7bf3263` (Apache-2.0) | Java/Kotlin toolchain | DEFERRED WORKER (dev-time only) | P13 | JVM not admitted in runtime; compilation ≠ clinical correctness | PUBLIC_LICENSE |
| T34 | RCT/RoB automation oracle | `ijmarshall/robotreviewer` @ `9a2781974c3edc6322b4fb329b1ea0348af7b8a1` (GPL-3.0) | `LICENSE.txt` | BENCHMARK_ONLY | — | No distribution without GPL decision or verified grant | GPL |
| T35 | Living RCT ingestion | `ijmarshall/trialstreamer` @ `a97cb8332c039e228ef42188c9d966440894e354` (no license file) | — | REFERENCE_ONLY_PENDING_RIGHTS | — | Founder-asserted grant must be recorded before any copy | REFERENCE_ONLY_PENDING_RIGHTS |
| — | Runtimes (not copied) | SQLite FTS5 (public domain, via `rusqlite` bundled SQLCipher); ONNX Runtime via `ort`; `llama.cpp` @ `31288c9c…` (MIT); `mistral.rs` @ `df35aace…` (MIT); Tauri @ `1d7b93fc…` (Apache/MIT); `iroh` @ `c6fba1b1…` (Apache/MIT); `sherpa-onnx` @ `1a9d234a…` (Apache-2.0); Presidio @ `2523c7b7…` (MIT) | — | DEPEND / tournament | — | One primary engine per capability (`RUNTIME_BUDGET.md`) | PUBLIC_LICENSE |
| — | Benchmarks | SYNERGY @ `dc2dadfd…` (CC0-1.0), BEIR @ `ef83d293…` (Apache-2.0; per-dataset terms) | — | BENCHMARK | `bench/` | — | per-dataset |

## 4. The one sandboxed research worker (decision D-03)

Copy-first requires running ASReview, statsmodels, MedOrigin `litdb`, DAL
metrics, commandMed oracle and SafeOCR verification with **only** import-path,
package-rename and broker-fetch adaptations rather than rewriting them in Rust. They run in **one** on-demand local Python process
(not a daemon fleet), packaged with a pinned embedded interpreter and a
hash-locked wheel set, launched under the T10 sandbox plan with **no network
capability**, JSON-lines over stdio, cancellable, memory-capped. It is a
desktop Deep Review / benchmark component; the Ask vertical slice and mobile
never require it. Exit strategy: any worker module that becomes
latency-critical is ported to Rust with the copied Python tests as parity oracle.

## 5. Remaining original engineering (GREENFIELD_JUSTIFIED)

No inspected donor implements these; each is SafeEvidence-specific semantics:

| Component | Why no donor fits | WP |
|---|---|---|
| Study/Report/Result/Overlap canonical model and double-count guard | Donors model papers, not studies with overlap groups (observed failure in Consensus, lag in Epistemonikos) | WP-05 |
| Applicability gate (per-source PICO vs question) | No donor implements per-source applicability with reasons | WP-09 |
| Claim-support policy + AnswerProofManifest admission | P00 contract is unique; donors provide spans (T01/T17) and benchmarks (T27) only | WP-08, WP-12 |
| GRADE-structured certainty assembly (proposal + human confirmation) | GRADEpro is closed; EBMonFHIR gives schema only | WP-10 |
| Clinical query → PICO decomposition orchestration | research extractors are benchmarks/GPL; LLM prompt + schema is product-specific | WP-07 |
| Current-validity overlay & alert explanation | Data sources exist; overlay semantics are P00-specific | WP-04 |
| Clinician workstation UX and Arabic/English presentation | UX is product-specific; shell is copied (T36) | WP-18, WP-19 |
| SafeEvidenceBench assembly | Metrics copied (T14); task design is product-specific | WP-20 |

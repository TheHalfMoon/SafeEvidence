# SafeEvidence Source Ledger

Status: `FOUNDATION_DRAFT`

This ledger defines the candidate source universe for SafeEvidence. Inclusion is not adoption authority. A source becomes adoptable only after the exact revision, exact paths/artifacts, controlling terms/permission, embedded dependencies, notices, modifications, security placement, tests, update strategy, and exit strategy are recorded.

## 1. Adoption modes

```text
COPY_BOUNDED     Copy the minimum useful implementation/test/rule slice with provenance.
ADAPT            Use a donor as a close implementation basis behind SafeEvidence-owned contracts.
PORT_TO_RUST     Reimplement bounded behavior/contracts/tests in Rust while preserving provenance.
DEPEND           Use a pinned upstream dependency.
VENDOR           Store an immutable source/runtime snapshot after explicit justification.
FFI              Use a native library behind a narrow Rust-owned ABI/lifetime/error boundary.
WORKER           Run a dependency/model/parser in a constrained local process.
ARTIFACT_IMPORT  Admit immutable model/evidence/terminology artifacts through a verified Pack path.
REFERENCE        Study behavior, architecture, tests, UX, or research; do not inherit runtime authority.
BENCHMARK_ONLY   Use only as a comparator/evaluation input.
REJECT_DEFAULT   Do not adopt as default architecture unless later evidence reverses the decision.
```

Permission expands what is legally/contractually possible; it does not determine the correct architecture.

## 2. Founder-owned / sibling repositories — primary public sources

The following public repositories are the strongest internal sources discovered during the SafeEvidence foundation review.

| Source | SafeEvidence candidate value | Default mode |
|---|---|---|
| `TheHalfMoon/MedScale` | primary evidence architecture; source identity; rights-aware acquisition; claim-support verification; Packs; local-first privacy; FHIR/interoperability patterns; evidence evaluation protocol | `ADAPT / COPY_BOUNDED / PORT_TO_RUST / REFERENCE` |
| `TheHalfMoon/DAL` | decision assurance; explicit commit-vs-abstain semantics; calibration/selective-risk metrics; MedQAbstain work; typed decision baselines; negative-result discipline | `ADAPT / COPY_BOUNDED / BENCHMARK_ONLY` |
| `TheHalfMoon/commandMed` | deterministic patient-safety state machine; `ANSWER/ASK_MORE/USE_TOOL/RETRIEVE_EVIDENCE/ABSTAIN/ESCALATE/EMERGENCY`; tool-over-generation precedence; medical evaluation discipline | `ADAPT / COPY_BOUNDED / REFERENCE` |
| `TheHalfMoon/MESC` | medical model/evidence research governance; exact model identity; resource-first qualification; abstention/uncertainty contracts; immutable corpus snapshots; evaluation discipline | `REFERENCE / COPY_BOUNDED` |
| `TheHalfMoon/Morize` | temporal truth, contradiction/supersession, evidence graph, explainable recall, rebuildable indexes, typed promotion decisions | `ADAPT / COPY_BOUNDED / REFERENCE` |
| `TheHalfMoon/ottari` | Rust-first local desktop/mobile architecture; document IR; evidence refs; OCR/document boundaries; capture/voice; local model runtime isolation; vault/search/sync patterns; broad donor registry | `ADAPT / COPY_BOUNDED / REFERENCE` |
| `TheHalfMoon/kernux` | capability kernel; permission-before-power; explicit local/remote boundaries; replay/evidence; provider-neutral workers; no silent cloud fallback | `ADAPT / COPY_BOUNDED / REFERENCE` |
| `TheHalfMoon/Signthos` | QR/mobile reference patterns; AGPL public tree and founder-asserted separate permission require exact clearance | `REFERENCE_ONLY_PENDING_RIGHTS` |
| `TheHalfMoon/Wispral` | future voice interaction; interruption/steering; command-vs-context semantics; local speech evaluation methodology | `REFERENCE / COPY_BOUNDED` |
| `TheHalfMoon/Inercative` | CLM research; deterministic-vs-decision-vs-generative routing; source-adoption discipline; qualification harness patterns | `REFERENCE / COPY_BOUNDED` |
| `TheHalfMoon/Ecra` | browser/search/agent capability routing and execution-receipt patterns when governed external evidence acquisition is added | `REFERENCE` |
| `TheHalfMoon/Sentrdel` | security evidence/control-plane patterns; stable schemas; evidence adjudication | `REFERENCE / COPY_BOUNDED` |
| `TheHalfMoon/SpecGrain` | recursive bounded planning, explicit readiness, WorkPackets, evidence-first execution | `PROCESS_REFERENCE` |
| `TheHalfMoon/Diffcipline` | proof-before-done change discipline and exact-change verification | `PROCESS_REFERENCE` |
| `TheHalfMoon/Delethos` | bounded delegation and proof-carrying change patterns | `REFERENCE` |

### Private sibling sources

Authorized private repositories were inspected during founder review. Because SafeEvidence is public, this public ledger intentionally does **not** disclose private repository names or private file paths without separate explicit authorization for public disclosure. If a private source is selected for implementation, its exact identity and permission basis must be recorded in a non-public founder-controlled provenance record or disclosed here only after explicit authorization.

### Implementation-ready internal anchors

The following are confirmed code surfaces, not merely architecture references:

| Donor | Concrete reusable surfaces |
|---|---|
| MedScale | `medscale-keys`; encrypted vault/storage; sealed blobs; migrations/writer lock; source/evidence contracts; network broker; FHIR R4 extractors; Pack admission/store/runtime/ONNX path; lexical retrieval baseline |
| DAL | calibration/selective-risk metrics, Brier/ECE, unsafe-commit/over-abstain, risk-coverage tests and evaluation scripts |
| commandMed | implemented policy validation/precedence, deterministic safety scaffold, tool registry/provenance and trace fixtures |

Exact paths and observed heads are recorded in `REUSE_FIRST_IMPLEMENTATION_MAP.md`.

## 3. Primary evidence/discovery sources

These are candidate source adapters, not bundled content rights.

| Source | Candidate role | Default mode |
|---|---|---|
| PubMed / NCBI | biomedical bibliographic discovery, PMID identity, metadata | `DEPEND/API_ADAPTER` |
| PubMed Central | open/full-text evidence where article-level rights permit | `DEPEND/API_ADAPTER` |
| Crossref | DOI metadata, citation identity, correction/retraction metadata | `DEPEND/API_ADAPTER` |
| OpenAlex | optional discovery/graph metadata; not clinical authority | `DEPEND/API_ADAPTER / REFERENCE` |
| ClinicalTrials.gov | structured trial discovery and candidate matching | `DEPEND/API_ADAPTER` |
| publisher/guideline metadata | authoritative version/correction/jurisdiction metadata where terms permit | `ADAPTER` |
| user-provided local documents | local evidence ingestion subject to user rights and policy | `CORE_INPUT` |
| institution-owned guidelines/protocols | institution-scoped local evidence packs | `CORE_INPUT` |

Source access and content redistribution are separate decisions. A public URL is not a redistribution license.

## 4. Medical standards and terminology

| Source | Candidate role | Rule |
|---|---|---|
| HL7 FHIR R4 4.0.1 | primary interchange reference | `REFERENCE`; SafeEvidence keeps its own canonical authority model |
| SMART on FHIR | future read-only connector/auth reference | separately qualified adapter |
| CQL / CPG-on-FHIR | computable guideline/evidence logic reference | verification-first; no compilation-equals-correctness assumption |
| NPHIES | Saudi interoperability reference where applicable | exact profile/version and deployment authority required |
| SNOMED CT | terminology pack | rights/version/checksum controlled; never assumed redistributable |
| LOINC | terminology/lab identity pack | rights/version/checksum controlled |
| UCUM | units and numeric normalization | versioned deterministic tooling |
| ICD | coding/interchange reference | edition/rights controlled |
| ATC | medication classification reference | version/rights controlled |
| UMLS / Athena vocabularies | optional terminology mapping | user/institution license boundary |

## 5. Evidence/retrieval architecture candidates

SafeEvidence owns retrieval contracts. Heavy RAG systems are references or optional workers, not default product authority.

| Source | Candidate value | Default mode |
|---|---|---|
| SQLite / FTS5 | canonical local metadata + lexical retrieval foundation | `DEPEND` |
| `Anush008/fastembed-rs` | local embeddings/reranking | `DEPEND` candidate; model rights separately |
| `asg017/sqlite-vec` | small local vector projection | `DEPEND` behind abstraction; maturity gate |
| Tantivy | higher-scale lexical index | `DEPEND` only after measured need |
| USearch | vector projection candidate | `DEPEND/FFI` only after benchmark |
| `langflow-ai/openrag` | ingestion/RAG architecture reference or isolated worker | `REFERENCE/WORKER`; not trusted core |
| Onyx | enterprise retrieval/search reference | `REFERENCE` |
| AnythingLLM | local knowledge/LLM UX reference | `REFERENCE` |
| Graphify | graph/context patterns | `REFERENCE` |
| code-graph-rag | graph retrieval patterns | `REFERENCE` |
| OpenSearch / Meilisearch | scale candidates | `REJECT_DEFAULT`; adopt only if local measurements justify server complexity |
| Qdrant / LanceDB | vector-service/storage candidates | `REJECT_DEFAULT`; no load-bearing server dependency without evidence |

Default V1 direction: scoped lexical retrieval + optional local embeddings + reranking, with indexes treated as sensitive rebuildable projections.

## 6. Decision assurance and calibration candidates

No candidate is trusted because it emits a probability. Every model is benchmarked under SafeEvidence's own protocol.

| Source | Candidate role | Default mode |
|---|---|---|
| Decision 2.0 family | compact typed-choice/yes-no/score decision models; phone/desktop tournament candidate | `ARTIFACT_IMPORT / BENCHMARK_ONLY` until qualified |
| Laya | compact typed-decision baseline | `ADAPT / ARTIFACT_IMPORT / BENCHMARK_ONLY` |
| `Mapika/decider` | one-pass typed boolean/choice/score decision surface | `ADAPT / BENCHMARK_ONLY` |
| `Contrastive-LM/CLM` | contrastive state/action baseline | `BENCHMARK_ONLY / REFERENCE` |
| `ikermoel/open-alternative-jev` | restricted-logit/no-task-training control | `BENCHMARK_ONLY / REFERENCE` |
| TypeSafe Jev | optional black-box comparison when reproducible access/terms permit | `BENCHMARK_ONLY` |
| BioClinical ModernBERT family | clinical encoder control / specialized classifier candidate | `ARTIFACT_IMPORT / BENCHMARK_ONLY` |
| Qwen structured-output models | generative structured-output control | `ARTIFACT_IMPORT / BENCHMARK_ONLY` |
| `TheoLeeCJ/SemIf` | option-logit scoring/calibration patterns | `REFERENCE / COPY_BOUNDED` |

Required evaluation includes calibration, Brier/ECE/NLL where meaningful, risk-coverage, unsafe-commit rate, over-abstention, abstention precision/recall, distribution shift, and missing-information behavior.

## 7. Local generation and model runtimes

| Source | Candidate role | Default mode |
|---|---|---|
| ONNX Runtime | specialist/encoder/OCR runtime | `DEPEND/FFI` |
| `ggml-org/llama.cpp` | broad GGUF local inference | `DEPEND/VENDOR/FFI` candidate |
| `EricLBuehler/mistral.rs` | Rust-native local LLM inference | `DEPEND` candidate |
| Hugging Face Candle | Rust-native specialist runtime | `DEPEND` candidate |
| Burn | Rust-native inference/training comparator | `DEPEND` candidate |
| MLX / mlx-lm | Apple accelerator path | platform adapter only |

Model weights, tokenizer files, processors, and code libraries have separate identities and rights.

## 8. Documents, PDF, OCR and extraction

| Source | Candidate role | Default mode |
|---|---|---|
| `xberg-io/xberg` | Rust-first document extraction/IR/parser candidate | `DEPEND/ADAPT/COPY_BOUNDED` after security/maturity tests |
| historical Kreuzberg/Kreuzberg-LTS | historical document extraction implementation/research | exact-revision `REFERENCE/COPY_BOUNDED` only |
| `docling-project/docling.rs` | Rust document parsing candidate | `DEPEND` candidate |
| Docling / docling-core | layout/table/formula/document-IR quality | `WORKER/REFERENCE/COPY_BOUNDED` |
| PaddleOCR | scanned-document and multilingual OCR candidate | `WORKER/VENDOR` after Arabic medical benchmark |
| MinerU | document parsing quality/IR candidate | `REFERENCE/COPY_BOUNDED` subject to exact rights |
| MarkItDown | conversion UX/normalization/security reference | `REFERENCE/COPY_BOUNDED` |
| tokimo file parser | pure-Rust PDF/Office extraction candidate | `EXPERIMENT/DEPEND` |
| Magika | MIME/file classification candidate | `DEPEND` only if benchmarked |
| Presidio | PII/de-identification taxonomy/rules reference | `REFERENCE/COPY_BOUNDED` |
| medSpaCy | clinical NLP patterns/tests | `REFERENCE` |

The document boundary must quarantine hostile inputs and preserve source page/region/table coordinates. OCR output is advisory until admitted through validation. Critical numbers, decimal points, units, doses, negation, and laboratory values require dedicated verification tests.

## 9. Desktop, mobile, storage and local sync

| Source / technology | Candidate role | Default mode |
|---|---|---|
| Tauri 2 | desktop shell candidate | `DEPEND`, conditional on PHI/cache/crash/accessibility qualification |
| React/TypeScript | shared desktop UI where appropriate | product UI only; never authority |
| Swift / SwiftUI | iOS/iPadOS native surface and platform integrations | native client |
| Kotlin / Jetpack Compose | Android native surface and platform integrations | native client |
| SQLCipher | encrypted SQLite candidate | `DEPEND/FFI`; durability/key tests mandatory |
| OS Keychain/Keystore/secure credential APIs | key-wrapping/custody candidate | platform-specific qualification |
| `n0-computer/iroh` | optional authenticated local/P2P sync transport | `DEPEND` candidate; no silent public relay |
| QR bootstrap pattern from sibling work | short-lived authenticated local desktop-mobile pairing | `ADAPT`; QR never carries raw patient data or long-lived secrets |

Mobile must remain a native, scoped product rather than an identical desktop WebView.

## 10. Audio/voice — deferred but pre-registered candidate universe

Voice is not required for the initial evidence wedge. When promoted, candidates include:

- `k2-fsa/sherpa-onnx`;
- `ggml-org/whisper.cpp`;
- NVIDIA NeMo-Speech.cpp;
- Moonshine;
- OpenWhispr / OpenSuperWhisper;
- Meetily;
- Silero VAD / TEN VAD;
- WebRTC AudioProcessing / Sonora;
- DeepFilterNet / RNNoise;
- pyannote-audio;
- multilingual/Arabic and medical-specialized ASR challengers.

Speech model/runtime rights and device-specific performance must be qualified independently.

## 11. FHIR, imaging and scientific ecosystem references

- Medplum / HAPI FHIR — FHIR integration/reference comparators;
- Synthea — synthetic healthcare fixture generation;
- OHIF / Orthanc / dcm4che / dicom-rs — future imaging/DICOM path;
- OMOP tooling — research export/mapping candidate, not a second canonical clinical DB;
- DuckDB / Polars / Arrow / DataFusion — later research/data-workbench candidates, not evidence-core prerequisites.

## 12. Security, supply chain and sandbox candidates

- Extism / Wasmtime — optional bounded plugin/worker host only if a plugin need is proven;
- TUF/tough — offline-verifiable pack/update trust;
- sigstore-rs — optional attestation/signature path;
- cargo-deny / RustSec / OSV / cargo-vet / cargo-auditable — supply-chain evidence;
- Syft / Trivy — SBOM/artifact scanning where applicable;
- platform sandbox primitives — exact OS confinement must be demonstrated, not declared.

## 13. OpenMed code-donor boundary and competitive references

OpenMed is both a product comparator and an eligible bounded code/test donor. MedScale previously froze and studied OpenMed v2.2.0 at commit `59d9cb0a2e0ccbba8fa3d891a66d83ffaf45e837`; SafeEvidence must reverify exact upstream identity before adoption.

High-value donor families include terminology grounding/snapshot/provenance, FHIR/profile/integrity/SDC tests, Unicode/span projection, PII/NER/de-identification evaluation rules, document/OCR adapters, and hard-negative/multilingual fixtures. Prefer an isolated local worker when that avoids unnecessary Rust reimplementation; port only trusted-core behavior that must live in Rust. Restricted terminology/data/model assets remain separately governed.

The following also guide product or evaluation but are not automatically code donors or evidence-content sources:

- OpenEvidence;
- Abridge;
- commercial clinical evidence products;
- commercial medical-scribe products;
- first-party OS health/document/mobile features.

Competitor behavior must not be reverse-engineered into unsupported clinical claims. Comparative evaluation requires matched dated conditions and explicit source-access differences.

## 14. Sources explicitly not chosen as default architecture

The following are not banned, but they must earn adoption through measured need:

```text
mandatory Qdrant/LanceDB server
mandatory Neo4j/GraphRAG server
mandatory PostgreSQL service
mandatory Docker/Kubernetes for end users
mandatory Python service fleet
mandatory OpenRAG/Onyx/AnythingLLM runtime
mandatory hosted inference
mandatory hosted auth
mandatory hosted telemetry
mandatory cloud synchronization
```

## 15. Source-admission record

Before copied/adapted/vendored/runtime material becomes canonical, create a record containing at least:

```text
source_name
source_repository_or_artifact_uri
exact_revision_or_digest
source_path_or_artifact_files
public_license
separate_permission_basis_if_used
permission_scope_if_used
embedded_or_transitive_material
model_dataset_asset_rights
copyright_notice_requirements
SafeEvidence_target
adoption_mode
why_reuse_beats_native
security_trust_placement
network/filesystem/key capabilities
tests_and_benchmarks
modifications
update_strategy
rollback_or_exit_strategy
review_evidence
```

No "all source is permitted" statement overrides third-party/model/data/asset provenance or the requirement to bind the adopted bytes to an exact identity.

## Gap-closing sources promoted 2026-10-07

Exact live revision must be reverified at adoption.

| Source | Observed revision | Role | Disposition |
|---|---|---|---|
| NCBI MedCPT | `11e129be74102c98d16a11c310b0b5ce74c1db5e` | biomedical retriever/reranker challenger | `MODEL/BENCHMARK/REFERENCE` |
| HL7/ebm | `374b48bb956e26a51dfdece365d98786ccc90e62` | EBMonFHIR evidence/citation/assessment crosswalk | `STANDARD/REFERENCE` |
| ASReview | `79d568212b2b0a78f9fd7be3c5117dfb890489f9` | Deep Review screening/dedup | `WORKER/COPY_BOUNDED` |
| SYNERGY | `dc2dadfdbb98eb1b4259604789abd640aa3b693e` | systematic-review inclusion benchmark | `BENCHMARK` |
| Mozilla UniFFI | `bc9fb38556d9efad4cb74a8a61b5c8a7e741fcea` | Rust↔Swift/Kotlin bindings | `DEPEND` |
| awslabs/tough | `98d8eb8b2ce63515d9b4981c938ef6453c5b5771` | TUF Rust candidate | `QUALIFY` |
| BEIR | `ef83d29307061c65d04b035b4f4e7c18bd8374af` | retrieval evaluation | `BENCHMARK` |
| SciFact | `68b98a56d93e0f9da0d2aab4e6c3294699a0f72e` | claim/rationale verification benchmark | `BENCHMARK/CODE_REFERENCE` |
| MultiVerS | `a6ce033f0e17ae38c1f102eae1ee4ca213fbbe2e` | scientific verifier research oracle | `WORKER/BENCHMARK_ONLY` |
| CQL toolchain | `c41c21f5616a0da82d49e32a9cc3a5b3ca299bc2` | guideline conformance validation | `WORKER/REFERENCE` |
| Tantivy | `1783018f9e6c0ffa4a884df3812011d8d13e4b52` | large lexical-index challenger | `DEPEND/BENCHMARK` |
| vLLM Semantic Router | `f53701a387197d95ee4c2d1dfb4acaa1adca5b3f` | typed decision-model research source | `MODEL/REFERENCE` |

Also promote the following data/source routes: PubMed annual baseline + ordered
daily updates; PMC Open Access article datasets; Europe PMC; Crossref REST +
Retraction Watch; MeSH; rights-gated RxNorm; ClinicalTrials.gov status
snapshots.

### SafeOCR status

`AbdulazizShehri/SafeOCR` is no longer empty. Independent review inspected a
live critical-value verification implementation and tests. It is now a
`COPY_BOUNDED / BENCHMARK` candidate for critical OCR verification, subject
to exact pin, dependency/model rights and clinical/Arabic qualification.


## Evidence-synthesis sources promoted 2026-10-07

Exact live revision and controlling terms must be reverified at adoption.

| Source | Observed revision | Role | Disposition |
|---|---|---|---|
| `evidence-surveillance/es3` | `fa845217690e179d3f8151e97773aabc035d6cfe` | trial↔review links and living-surveillance patterns | `COPY_BOUNDED / REFERENCE` |
| `ijmarshall/trialstreamer` | `a97cb8332c039e228ef42188c9d966440894e354` | living RCT acquisition, classification, PICO extraction | `REFERENCE_ONLY_PENDING_RIGHTS` |
| `ijmarshall/robotreviewer` | `9a2781974c3edc6322b4fb329b1ea0348af7b8a1` | RCT PICO/risk-of-bias automation oracle | `REFERENCE / BENCHMARK`, distribution under GPL-compatible decision or verified alternate grant only |
| `bwallace/RRnlp` | `e1a26b4ed1c8d65f2c2e2558dc9f0918572306d0` | evidence-based-medicine NLP implementation research | `COPY_BOUNDED / BENCHMARK` |
| `jayded/evidence-inference` | `a661e8c14f973398380c8865cf2f27a535aaaf6d` | intervention/comparator/outcome result and evidence extraction | `COPY_BOUNDED / BENCHMARK` |
| `WengLab-InformaticsResearch/PICOX` | `f3351c4786bf197efacfcefc1c1e66c36c245842` | overlapping PICO extraction | `COPY_BOUNDED / BENCHMARK` |
| `statsmodels/statsmodels` | `8278e2d218cc85bac2c7af02feb9a19a0e499b04` | meta-analysis/effect-size/statistical synthesis | `DEPEND / VENDOR_SELECTED` |

Method/standard references:

- PRISMA 2020 for systematic-review reporting and deterministic flow accounting;
- current Cochrane Handbook for study-vs-report linkage, multiplicity, unit-of-analysis and synthesis methodology;
- RoB 2 for randomized trials;
- ROBINS-I / ROBINS-E where applicable and version-pinned;
- current QUADAS family for diagnostic-accuracy appraisal;
- AMSTAR 2 for systematic-review appraisal.

These method sources do not automatically authorize redistribution of their
tool content. SafeEvidence may implement compatible internal structures and
link/reference the methods subject to their exact terms.


## Independent-review donor corrections

The Opus and Codex reviews supersede donor assumptions that were based only on
repository availability.

- private vault: ottari SQLCipher/WAL is the primary P02 hypothesis; MedScale
  EncryptedVault whole-file sealing is not copied as canonical authority;
- SafeOCR: live donor candidate;
- commandMed: mechanics/oracle only; patient lexical rules require SafeEvidence
  clinician policy;
- DAL: metrics reusable; negative Study-0 results are prior evidence;
- statsmodels meta-analysis: restricted supported-method source, not a complete
  synthesis engine;
- metafor: stronger statistical oracle/optional worker candidate subject to
  copyleft/runtime decision;
- trialstreamer: reference-only until separate permission reference is recorded;
- Non-public guideline-verification research reference: identity withheld
  from public documentation; research-only, no assumed code admission or
  implementation readiness; exact source inspection and an appropriate
  permission basis are required before adoption;
- parser/model dependencies: default network/download/telemetry features are not
  admitted implicitly.

Rights disposition is canonical in `docs/DONOR_RIGHTS_REGISTER.md`.

## Binding source eligibility for P00 repair

All adoption-mode hints in this ledger are **discovery only**. Before any
copy/vendor/worker distribution, the exact repo, commit, selected file hashes,
SPDX/grant and separated model/data/terminology/native/asset terms must appear
as VERIFIED_ALLOWED in `docs/DONOR_RIGHTS_REGISTER.md`. Unknown and
SEPARATE_PERMISSION_ASSERTED are **not** permission to import bytes. Ready
source code is preferred after rights admission, not before.

The ottari SQLCipher/WAL private vault is a P02 qualification candidate;
MedScale whole-file EncryptedVault is not eligible for canonical private
authority as-is. SafeOCR is a real critical OCR field-verification donor
candidate subject to qualification; DAL's negative abstention results are
prior evidence, not a promotion claim.

## 2026-10-19 live-head audit corrections

- `TheHalfMoon/MESC` redirects to `TheHalfMoon/MedOrigin`; its `litdb`
  package (literature adapters, screening/review logs, PRISMA summary) is now
  a COPY_BOUNDED candidate (T15).
- Repository visibility changed: DAL, ottari, kernux, Morize, Inercative,
  Signthos, Wispral, Sentrdel and Ecra are private as of 2026-10-19.
  Section 2's "public" wording is historical.
- RRnlp model weights (Zenodo 5139998, 5939332) are GPL-2.0; minimap tables
  are UMLS-derived. BENCHMARK only.
- docling.rs default features enable URL/image/YouTube/remote-VLM network
  fetch; fastembed-rs defaults download ONNX Runtime binaries and use hf-hub.
- MedCPT code is a US-Government public-domain work; Hugging Face weights
  declare `license: other` and need separate review.
- Authoritative per-file pins: `docs/evidence/source_transplant_pins_2026-10-19.json`.

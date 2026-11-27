# SafeEvidence Copy-First Source Plan

Status: `P00_BINDING`

## 1. Founder authorization

The founder has explicitly asserted permission to copy, modify, combine,
adapt, vendor, and rebrand the discussed source-code donors.

This assertion is preserved, but SafeEvidence does not infer external copyright
rights from a blanket statement. Every adopted source must have an allowed
entry in `docs/DONOR_RIGHTS_REGISTER.md` based on a public license, founder
ownership, or a recorded separate permission reference.

It does **not** erase obligations attached to embedded third-party code,
datasets, terminology, model weights, fonts, documents, or other separately
licensed material. Those remain tracked independently.

## 2. Engineering rule

SafeEvidence MUST NOT reimplement an already-good capability from scratch when
a rights-admitted source already contains a usable implementation.

Default decision order:

```text
1. COPY coherent product-specific implementation
2. VENDOR a stable generic implementation when independence is desirable
3. DEPEND on a generic library when direct dependency is clearly lower-risk
4. ADAPT copied code behind SafeEvidence contracts
5. PORT only when a trust/platform boundary requires it
6. GREENFIELD only when no suitable ready source exists
```

"Cleaner to rewrite" is not a valid reason.

The objective is maximum reuse of proven implementation while avoiding
unnecessary donor-product coupling.

## 3. Copy styles

### A. COHERENT_COPY

Copy a complete, bounded implementation slice together with tests and fixtures.

Use for sibling-product code that SafeEvidence should own after import.

### B. VENDOR_SNAPSHOT

Import an upstream implementation under `third_party/` or an equivalent
vendored location at an exact revision.

Use when SafeEvidence wants deterministic ownership of the bytes without
rewriting them.

### C. DIRECT_DEPENDENCY

Use upstream as a pinned dependency when maintaining a copy would create more
work than value.

This still satisfies the founder's "do not start from scratch" rule because the
ready implementation is used unchanged.

### D. ORACLE_COPY

Copy reference implementation/tests into benchmark or compatibility tooling,
then implement only the minimal trusted-core adapter necessary.

### E. WORKER_COPY

Vendor/copy a specialist stack as an isolated local worker when porting it
would waste time.

## 4. Copy matrix — foundation

| Capability | Primary source | Observed head | Copy strategy | SafeEvidence destination |
|---|---|---|---|---|
| cryptographic key handling | `TheHalfMoon/MedScale` | `1e2b7d94e970256b38bda15fa91f62bc397e825a` | COHERENT_COPY | `crates/safeevidence-keys/` |
| private SQLCipher vault | ottari `himsat-core` (primary hypothesis) + selected MedScale lock/claim helpers | exact adopted revisions at P02 | COPY_BOUNDED after crash/backup bake-off | `crates/safeevidence-vault/` |
| private blob/storage primitives | ottari + selected MedScale helpers | exact adopted revisions at P02 | COPY_BOUNDED after threat-model qualification | vault/storage modules |
| path claims / local custody | MedScale | same | COHERENT_COPY | vault/core |
| writer ownership | MedScale `writer_lock.rs` | same | COHERENT_COPY incl. cross-process tests | vault |
| migrations/restart integrity | ottari primary + compatible donor tests | exact adopted revisions at P02 | COPY_BOUNDED after kill/recovery qualification | vault |
| source identity | MedScale contracts | same | COHERENT_COPY + extend | `safeevidence-contracts` |
| evidence corpus contracts | MedScale | same | COHERENT_COPY + extend | contracts/evidence |
| network broker | MedScale | same | COHERENT_COPY | `safeevidence-network` |
| pack admission/signing | MedScale | same | COHERENT_COPY | `safeevidence-pack` |
| local ONNX specialist runtime | MedScale | same | COPY reusable runtime slice | pack/inference |
| FHIR R4 typed extraction | MedScale | same | COHERENT_COPY | `safeevidence-fhir` |
| lexical evidence baseline | MedScale | same | ORACLE_COPY | retrieval baseline |
| sandbox/privacy test patterns | MedScale + Kernux | `1e2b7d...` / `a0c4aaee...` | COPY tests/policies | security tests |

### Important MedScale rule

Do not copy the entire current MedScale workspace.

Copy the best **behavioral slice** from its qualified evolution. Current
MedScale contains unrelated product modules and schema history.

In particular, SafeEvidence should copy:

```text
medscale-keys
encrypted vault primitives
sealed blob storage
source/evidence contracts
writer_lock
network broker
pack admission/runtime
FHIR typed extraction
privacy/sandbox tests
selected durability/migration tests
```

and leave behind unrelated analytics, collaboration, audio, huddles, model
fleet, project graph, etc.

## 5. Copy matrix — clinical safety and decision assurance

| Capability | Source | Observed head | Strategy |
|---|---|---|---|
| deterministic safety state machine | `TheHalfMoon/commandMed` | `51f73ec05750137e5bd94ffa0765f6383f475fee` | ORACLE_COPY then bounded Rust adaptation |
| policy precedence | commandMed | same | COPY semantics + fixtures |
| ASK_MORE/ABSTAIN/ESCALATE/EMERGENCY behavior | commandMed | same | COPY tests + port only trusted runtime |
| calibration metrics | `TheHalfMoon/DAL` | `8fcf29f2e0c1b6cf78661acd2f5e1340a578ac03` | COPY Python benchmark code |
| Brier/ECE/NLL/selective risk | DAL | same | COPY unchanged where possible |
| unsafe-commit / over-abstain | DAL | same | COPY unchanged |
| decision-model tournament harness | DAL/Inercative/MESC | current pinned heads | COPY benchmark/eval infrastructure |
| typed decision model source | vLLM Semantic Router Decision family | current qualified pin at adoption | VENDOR/ARTIFACT_IMPORT candidate |

No reason exists to rewrite standard calibration formulas or benchmark harnesses.

## 6. Copy matrix — evidence NLP / grounding

| Capability | Source | Observed head | Strategy |
|---|---|---|---|
| clinical grounding | `maziyarpanahi/openmed` | `252806aa946c200f3857cc0f6fda37fd83a5cc85` | COPY bounded modules/tests |
| terminology candidate/ranking | OpenMed | same | COPY/ADAPT |
| terminology cache/provenance | OpenMed | same | COPY/ADAPT |
| Unicode/span projection | OpenMed | same | COPY tests + implementation |
| FHIR integrity/profile tests | OpenMed | same | COPY tests/adapters where useful |
| de-identification/PII testing | OpenMed | same | COPY selected code/tests |
| document/OCR adapter tests | OpenMed | same | COPY into qualification harness |
| scientific support benchmark | SciFact | exact pin at admission | COPY benchmark code/data subject to dataset terms |
| verifier oracle | MultiVerS | exact pin at admission | VENDOR/WORKER_COPY |

Do not copy OpenMed's entire service/cloud/orchestration dependency universe by
default. Copy the useful clinical algorithms and tests.

## 7. Copy matrix — documents and OCR

### Xberg

Observed head:
`42c03edd06964accd6f8b796fba1647da2b8121d`

Ready source includes native PDF/document extraction, PDFium path, OCR
integrations, FFI, Swift/Dart/JNI support, and broad document parsing.

Default:
`VENDOR_SNAPSHOT / DIRECT_DEPENDENCY`.

### docling.rs

Observed head:
`8aea8d543de832116ebb29436d9281bfe7e82d73`

Ready source includes document IR, converters, PDF pipeline, ONNX layout/OCR,
RAG/chunking, FFI and WASM surfaces.

Default:
`VENDOR_SNAPSHOT / DIRECT_DEPENDENCY`.

### Selection

SafeEvidence MUST NOT build a PDF parser, Office parser, layout engine, table
extractor, or OCR framework from scratch.

Run Xberg vs docling.rs qualification. Copy/vendor the winner as the default
document engine. Preserve the second only as a challenger/fallback if evidence
justifies it.

PaddleOCR can be copied/vendored as an OCR backend where it wins medical/Arabic
fixtures.

## 8. Copy matrix — retrieval

| Capability | Ready source | Strategy |
|---|---|---|
| lexical storage/search | SQLite FTS5 | DEPEND |
| larger lexical engine | Tantivy | DEPEND or VENDOR |
| embeddings/rerank runtime | `fastembed-rs` @ `29059745...` | DEPEND or VENDOR |
| biomedical retriever/reranker | NCBI MedCPT @ `11e129be...` | ARTIFACT/CODE COPY for qualification/runtime subject to model terms |
| vector projection | sqlite-vec / USearch | DEPEND/VENDOR |
| retrieval benchmark | BEIR | COPY benchmark harness/datasets per terms |

No vector database is built from scratch.

## 9. Copy matrix — Deep Review

| Capability | Source | Strategy |
|---|---|---|
| active-learning screening | ASReview @ `79d568...` | COPY/WORKER_COPY |
| screening benchmark | SYNERGY | COPY benchmark data per terms |
| dedup/screening workflow ideas | ASReview | COPY/ADAPT |
| systematic review audit trail | SafeEvidence-specific | build only missing integration semantics |

SafeEvidence should not rebuild generic active-learning screening.

## 10. Copy matrix — mobile

| Capability | Source | Strategy |
|---|---|---|
| Rust↔Swift/Kotlin bindings | UniFFI @ `bc9fb385...` | DEPEND or VENDOR |
| mobile security contracts | MedScale | COPY |
| QR pairing threat model/patterns | Signthos (AGPL public tree; separate permission asserted but not verified) | REFERENCE_ONLY_PENDING_RIGHTS; no transplant until per-slice grant/license decision |
| platform architecture patterns | ottari @ `b7948b5...` | COPY/ADAPT |
| iOS/Android document bridge ideas | Xberg | COPY/REFERENCE |

Do not hand-write two complete FFI layers if UniFFI qualifies.

## 11. Copy matrix — guidelines and evidence standards

| Capability | Source | Strategy |
|---|---|---|
| guideline verification research patterns | Non-public, unqualified research reference (identity withheld from public documentation) | REFERENCE_ONLY; no code copy, adaptation or implementation readiness asserted |
| CQL translation/conformance | `cqframework/clinical_quality_language` @ `c41c21...` | VENDOR/WORKER_COPY |
| evidence interoperability | HL7/EBMonFHIR | COPY schemas/examples as reference/export mappings |
| FHIR patient context | MedScale + OpenMed tests | COPY |

SafeEvidence owns the simplified internal model; it does not reimplement CQL
tooling.

## 12. Copy matrix — updates/security

| Capability | Source | Strategy |
|---|---|---|
| TUF update semantics | TUF spec/conformance suite | COPY tests/spec fixtures |
| Rust implementation candidate | awslabs/tough @ `98d8eb...` | VENDOR/DEPEND after qualification |
| capability/no-silent-egress patterns | Kernux @ `a0c4aa...` | COPY bounded policy/tests |
| release/SBOM patterns | MedScale/sibling repos | COPY workflows/scripts |

Do not implement a custom secure updater protocol.

## 13. What SafeEvidence still has to build

Copy-first does **not** mean there is no original engineering.

SafeEvidence-specific integration remains:

- the canonical Evidence/Claim/Answer semantic model;
- item-level evidence rights policy;
- PubMed/PMC/Crossref/Europe PMC update lifecycle;
- query decomposition and PICO/PICOTS orchestration;
- exact clinical claim↔evidence support policy;
- contradiction resolution/presentation;
- evidence quality vs patient applicability separation;
- calibrated commit/abstain semantics;
- current-validity overlay over immutable historical answers;
- clinician workstation UX;
- Arabic/English medical benchmark suite;
- SafeEvidenceBench;
- product-level integration, packaging and qualification.

These are the areas where new code is justified.

## 14. Mandatory agent behavior

Before an agent writes more than trivial glue code, it must answer:

```text
WHAT READY SOURCE ALREADY IMPLEMENTS THIS?
WHAT EXACT FILES/CRATES CAN BE COPIED?
WHY ARE WE NOT COPYING THEM?
```

If the first two answers identify a good implementation, copying/adapting it is
the default action.

## 15. P00 closure condition

P00 cannot close until Codex and Opus independently verify that:

- every P01-P15 major capability has a copy/vendor/dependency source where one
  exists;
- there is no generic subsystem scheduled for greenfield work while an
  authorized good implementation exists;
- copy boundaries avoid importing unrelated donor-product architecture;
- donor tests/fixtures are included in the copy plan;
- third-party nested terms are tracked separately;
- every truly greenfield component is SafeEvidence-specific.


## 16. Copy matrix — evidence synthesis

| Capability | Ready source | Copy strategy |
|---|---|---|
| study/report surveillance and trial-review links | `evidence-surveillance/es3` | COPY_BOUNDED |
| living RCT ingestion/PICO patterns | `ijmarshall/trialstreamer` | REFERENCE_ONLY_PENDING_RIGHTS (no observed public license; documented grant needed before copy) |
| RCT PICO/risk-of-bias automation | `ijmarshall/robotreviewer` | REFERENCE / BENCHMARK; GPL-compliant distribution or separately verified grant required to ship code/worker |
| EBM NLP models/patterns | `bwallace/RRnlp` | COPY_BOUNDED |
| treatment-result/evidence extraction | `jayded/evidence-inference` | COPY_BOUNDED / BENCHMARK |
| overlapping PICO extraction | `WengLab-InformaticsResearch/PICOX` | COPY_BOUNDED / BENCHMARK |
| meta-analysis/effect-size calculations | `statsmodels.stats.meta_analysis` | DEPEND / VENDOR_SELECTED |
| screening/dedup | ASReview | COPY/WORKER |
| PRISMA flow/accounting | existing review tooling + official PRISMA reference | COPY_BOUNDED / STANDARD_REFERENCE |

SafeEvidence must not independently reimplement standard meta-analysis formulas,
systematic-review screening engines, PICO extraction models, living-RCT update
machinery, or generic PRISMA counting when ready authorized code exists.

SafeEvidence-specific work is limited to the canonical Study/Report/Outcome/
EffectEstimate semantics, provenance/admission, rights, clinician-facing
workflow, and integration with SafeEvidence decision assurance.


## 17. Reconciliation corrections

- Private vault default hypothesis changes from MedScale EncryptedVault to the
  ottari SQLCipher/WAL vault slice. MedScale lock/path/key helpers remain
  candidates, not a coherent vault by themselves.
- SafeOCR is a live critical-value verification donor candidate.
- Trialstreamer is reference-only until its asserted separate permission is
  documented in the donor-rights register.
- RobotReviewer and Signthos follow their public copyleft terms unless a
  separately verified permission/relicense record is attached.
- statsmodels is a restricted statistical implementation/oracle; broader
  synthesis methods should use mature existing implementations such as metafor
  where rights/runtime qualification permits.
- commandMed decision mechanics are reusable; its patient lexical policy content
  is not copied unchanged for clinician evidence questions.

## 18. V1 transplant matrix supersedes candidate rows (2026-10-19)

Live-head inspection on 2026-10-19 produced the file-level
`docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md` and blob-pinned
`docs/evidence/source_transplant_pins_2026-10-19.json`. Corrections to this
file: PICOX and RRnlp move to BENCHMARK (notebook-only repository; GPL-2.0
model weights), es3 moves to REFERENCE (web application), docling.rs is a
challenger built without default network features, MedScale "encrypted vault
primitives" are not copy targets (ottari vault slice T03 is), OpenMed is
re-pinned at `8440bdac59621981372d318f43c8bfb2d6625b86` (v3.0.0), and MESC is
now `TheHalfMoon/MedOrigin`. Admission rules in this file are unchanged.

# SafeEvidence Reuse-First Implementation Map

Status: `P00_FOUNDATION_AMENDMENT`  
Review date: 2026-10-06

## 1. Purpose

SafeEvidence MUST NOT rebuild a subsystem from scratch when a qualified code source already implements the required behavior well enough to copy, adapt, depend on, or use as a bounded local worker.

The product still owns its contracts, clinical semantics, trust boundaries, tests, and release claims. Owning a contract does **not** imply rewriting every implementation.

The default implementation order is:

```text
DEPEND / COPY_BOUNDED
        ↓
ADAPT behind SafeEvidence contract
        ↓
PORT only when trust/language/platform boundary requires it
        ↓
GREENFIELD only after explicit justification
```

Permission makes reuse eligible. Exact source identity, path, transitive material, notices, security review, tests, and SafeEvidence acceptance evidence make reuse adoptable.

## 2. Greenfield authorization rule

Before any implementation grain writes a new subsystem, it MUST produce a donor decision containing:

1. required SafeEvidence behavior/contract;
2. code sources inspected at exact revisions;
3. concrete files/crates/modules that already implement the behavior;
4. smallest viable reuse mode for each candidate;
5. transplant/dependency risks;
6. tests/fixtures that can travel with the code;
7. measured or review-backed reason for rejecting stronger reuse;
8. selected action.

Allowed selected actions:

```text
DEPEND
COPY_BOUNDED
ADAPT
PORT_TO_RUST
WORKER
FFI
ARTIFACT_IMPORT
GREENFIELD_JUSTIFIED
```

`GREENFIELD_JUSTIFIED` is valid only when the record explains why available code is materially worse on correctness, privacy/security, portability, maintenance, resource cost, rights/provenance, or product fit.

"SafeEvidence should own this" is not by itself a valid greenfield reason.

## 3. Frozen donor heads observed during this review

These are review anchors, not permanent update locks. Reverify live heads before actual transplant.

| Source | Observed review head | Main value |
|---|---|---|
| `TheHalfMoon/MedScale` | `1e2b7d94e970256b38bda15fa91f62bc397e825a` | valuable Rust donor: keys, source/evidence contracts, network broker, FHIR, packs, runtime and selected vault tests; **not canonical whole-file private vault** |
| `TheHalfMoon/DAL` | `8fcf29f2e0c1b6cf78661acd2f5e1340a578ac03` | calibration/selective-risk/abstention benchmark code |
| `TheHalfMoon/commandMed` | `51f73ec05750137e5bd94ffa0765f6383f475fee` | implemented deterministic safety policy/scaffold |
| `TheHalfMoon/Morize` | `62fc04d01d398da93b4dacf0ab2f33e3f1440462` | temporal/evidence-graph semantics, mostly reference at this stage |
| `TheHalfMoon/ottari` | `fb6ba054435931e0fc1d18d18c2bf21ca74c41c5` | Rust/native platform and document/runtime donor research |
| `TheHalfMoon/kernux` | `4b5450d40f89de7541bbd5fc4f85e7a63c173f8d` | capability/no-silent-egress patterns and growing implementation |
| `TheHalfMoon/Signthos` | `f945f12fd1a2b600c2c61493162e3654b4d5b50c` | desktop/mobile and QR handoff patterns |
| `TheHalfMoon/Inercative` | `3a4713c47d36722c564f185bc4a8c02ad57da05c` | CLM/decision-plane adoption research |
| `TheHalfMoon/MESC` | `f9b7579189b77b06379d1a71d104d4b0267cf500` | medical model/evidence qualification discipline |

Private source identities remain outside this public file unless separately authorized for public disclosure.

## 4. Direct transplant candidates from MedScale

MedScale is not merely a conceptual reference. It contains real reusable Rust code. SafeEvidence should begin by transplanting/adapting qualified slices instead of recreating them.

### 4.1 Local vault and keys — HISTORICAL CANDIDATES, NOT ADOPTED

Candidate source paths:

```text
crates/medscale-keys/
crates/medscale-storage/src/encrypted_vault.rs
crates/medscale-storage/src/sqlite_meta.rs
crates/medscale-storage/src/sealed_blob.rs
crates/medscale-storage/src/blob.rs
crates/medscale-storage/src/backup.rs
crates/medscale-storage/src/migrate.rs
crates/medscale-storage/src/writer_lock.rs
```

Existing useful behavior includes:

- SQLCipher-backed working metadata;
- vault DEK and key-provider abstraction;
- Argon2 passphrase flow;
- recovery codes;
- OS keyring abstraction;
- AES-GCM sealed blobs;
- migration journal;
- backup/restore;
- work/WAL/SHM/journal cleanup handling;
- source metadata and durable authority rows;
- single-writer/exclusive-writer work and tests.

**Current binding decision (supersedes the historical path list above):** Do **not** adopt MedScale whole-file `EncryptedVault` / `encrypted_vault.rs` as SafeEvidence authority. P02 qualifies ottari's persistent SQLCipher/WAL vault as the primary coherent lifecycle candidate and may selectively transplant independently qualified MedScale writer-lock, path-claim and key/recovery helpers/tests. See `docs/P00_VAULT_DURABILITY_CONTRACT.md`. No code transplant is authorized by the historical list.

### 4.2 Source and evidence contracts — COPY/ADAPT first

Candidate source paths:

```text
crates/medscale-contracts/src/objects/source.rs
crates/medscale-contracts/src/objects/ids.rs
crates/medscale-contracts/src/objects/scope.rs
crates/medscale-contracts/src/evidence/mod.rs
```

Useful existing concepts/code:

- immutable `SourceRecord`;
- source identity separate from content digest;
- `DerivedSourceArtifact` with transform version and loss class;
- versioned evidence corpus;
- active/retracted document state;
- retrieval result explicitly marked relevance-only;
- digest validation.

**SafeEvidence delta:** expand rights/source classes beyond MedScale's synthetic evidence baseline and add richer publication/correction/licensing metadata. Extend; do not restart.

### 4.3 Network broker — COPY/ADAPT first

Candidate paths:

```text
crates/medscale-network/
crates/medscale-contracts/src/network/
```

Existing behavior:

- one brokered product-egress boundary;
- explicit allowlist;
- fail-closed empty allowlist;
- typed destination/purpose/data class;
- no ambient worker network;
- fixture transport;
- real-PHI-forbidden data-class denial;
- URL/private-network/browser validation work in later modules.

**SafeEvidence direction:** adapt this to `NETWORK_LOCKED / EVIDENCE_UPDATE_ONLY / SELECTED_CONNECTORS`. Evidence source adapters call the broker; core/model/OCR workers do not gain direct sockets.

### 4.4 FHIR — COPY/ADAPT first

Candidate path:

```text
crates/medscale-fhir/
```

Existing implemented baseline:

- bounded FHIR R4 JSON lexical/structural gate;
- Patient extractor;
- Condition extractor;
- Observation extractor;
- evidence/source context on extracted fields;
- UCUM subset/unit conflict handling;
- payload/depth limits.

**SafeEvidence direction:** use this crate as the initial read-only patient-context adapter and extend resource/profile coverage only as demanded. Do not create a second FHIR parser/database from scratch.

### 4.5 Pack admission and local specialist runtime — COPY/ADAPT first

Candidate paths:

```text
crates/medscale-contracts/src/packs/
crates/medscale-pack/src/format.rs
crates/medscale-pack/src/store.rs
crates/medscale-pack/src/runtime.rs
crates/medscale-pack/src/onnx_runtime.rs
```

Existing behavior:

- content-addressed Pack manifest;
- version/epoch/anti-rollback semantics;
- artifact digest checks;
- admitted Pack registry;
- proposal/evidence-only runtime boundary;
- real CPU ONNX token-classifier execution through `tract-onnx`.

**SafeEvidence direction:** evolve this into `ModelPack / EvidencePack / GuidelinePack / TerminologyPack / BenchmarkPack`. Reuse admission, hashing, signer/epoch, and runtime patterns instead of inventing a new package format.

### 4.6 Lexical retrieval baseline — COPY/ADAPT as oracle/baseline

MedScale has implemented deterministic lexical retrieval contracts and code with immutable corpus identity and retraction handling.

**SafeEvidence direction:** copy it as a correctness/reference baseline and fixture path, then add real FTS5/BM25. Do not confuse the existing simple ranker with the final retrieval engine.

## 5. Decision/safety/calibration code reuse

### 5.1 commandMed deterministic safety scaffold — USE AS ORACLE + PORT/ADAPT

Candidate paths:

```text
src/commandmed/spec006/scaffold.py
src/commandmed/spec006/policy.py
src/commandmed/spec006/registry.py
src/commandmed/spec006/trace.py
data/eval/safety_policy.json
specs/006-patient-safety-scaffold/fixtures/
```

Implemented behavior already includes:

- closed behavioral state vocabulary;
- frozen policy validation;
- deterministic precedence;
- conflict fail-closed behavior;
- unknown/unavailable tool handling;
- evidence prerequisites;
- tool-output provenance checks;
- injection/spoof fail-closed behavior;
- exactly one terminal state.

**SafeEvidence direction:** preserve fixtures and semantics as an executable oracle. Port/adapt the trusted deterministic subset to Rust rather than redesigning the state machine from a blank file.

### 5.2 DAL metrics/selective prediction — COPY/ADAPT benchmark tooling

Candidate paths:

```text
src/gaxbench/metrics.py
src/gaxbench/selective.py
tests/test_metrics.py
tests/test_selective.py
scripts/run_p08_final_evaluation.py
```

Existing code includes:

- Brier metrics;
- expected calibration error;
- NLL-related reporting;
- unsafe-commit rate;
- over-abstain rate;
- risk/coverage metrics;
- abstention/selective evaluation.

**SafeEvidence direction:** transplant/adapt this into SafeEvidenceBench/P08/P09. Keep it in Python initially if that is the fastest reproducible benchmark path; production Rust does not require rewriting scientific evaluation utilities.

## 6. OpenMed should be treated as a code donor, not only a competitor

MedScale already froze and studied OpenMed v2.2.0:

```text
repository: maziyarpanahi/openmed
tag: v2.2.0
commit: 59d9cb0a2e0ccbba8fa3d891a66d83ffaf45e837
tree: 1c949e35b2b8f2ea69da4284b370074fc4bf84ab
public license at reviewed root: Apache-2.0
```

Reverify the live/upstream revision and exact paths before any transplant.

High-value code/test families already identified:

```text
openmed/clinical/grounding/
openmed/interop/fhir/
openmed/structured/offset_properties.py
openmed/training/synthetic/offset_projection.py
document/OCR/de-identification adapters and tests
FHIR/profile/integrity/SDC tests
Unicode/span integrity fixtures
terminology snapshot/cache/provenance code
grounding conflict/ranking/calibration tests
```

### Preferred reuse shape

Do not automatically port every Python module to Rust.

For non-authoritative specialist work, first compare:

```text
A) run selected OpenMed code as a local isolated worker
B) copy/port a bounded algorithm/test slice into Rust
C) depend on a lower-level Rust donor that already solves the same task
```

A local worker can be the fastest safe path for terminology, de-identification, or document preprocessing while the trusted SafeEvidence core remains Rust and network-denied.

Never copy restricted terminology tables merely because surrounding code is reusable.

## 7. Document/OCR stack — depend before writing parsers

### Xberg

Observed workspace is a current Rust document platform with crates for native PDF, PDFium rendering, PaddleOCR integration, Candle OCR, FFI/JNI/Swift/Dart bridges, and broad document extraction.

**Default:** `DEPEND / ADAPT / COPY_BOUNDED` after security and native/transitive review.

### docling.rs

A Rust port/workspace already provides:

- `docling-core` document model;
- `docling` converters;
- `docling-pdf`;
- ONNX layout/OCR;
- ASR;
- FFI/WASM;
- optional RAG.

**Default:** `DEPEND / WORKER` candidate.

### Rule for P12

SafeEvidence MUST NOT author a PDF/Office parser, layout engine, table parser, or OCR framework from scratch before Xberg/docling.rs/OpenMed/PaddleOCR routes are benchmarked against the required medical fixtures.

SafeEvidence-owned work should focus on:

- hostile-input boundary;
- source-coordinate/evidence-span normalization;
- critical medical number/negation validation;
- provenance/admission;
- product UX.

## 8. Semantic retrieval — depend on existing local engines

### fastembed-rs

Existing Rust library provides local ONNX embeddings and reranking and supports user-supplied local model files.

**Default:** direct `DEPEND` candidate with network/download features disabled for the packaged/offline product path.

### sqlite-vec / USearch

Use behind SafeEvidence's projection abstraction if benchmarks justify them. Do not implement a vector database.

## 9. Desktop/mobile/sync reuse

### Desktop

Do not blindly copy a domain-specific sibling UI. Reuse:

- core/vault/contracts;
- desktop process/IPC/capability patterns that are proven;
- native file/key integration;
- tests and privacy probes.

The clinician UX itself may remain SafeEvidence-specific.

### Mobile

Reuse existing contracts/patterns before inventing new FFI:

- MedScale mobile security contracts and tests;
- Xberg Swift/Dart/FFI bridge ideas where compatible;
- native SwiftUI/Kotlin platform shells;
- existing secure-storage/keychain/keystore libraries rather than custom crypto wrappers.

### Pairing/sync

Use an existing authenticated transport such as Iroh only if direct/LAN/no-silent-relay behavior qualifies. Reuse sibling QR bootstrap threat-model/test patterns. Do not design a new transport protocol casually.

## 10. Voice later

When P19 is promoted, use an existing offline engine such as sherpa-onnx/whisper.cpp after qualification. sherpa-onnx already has desktop/iOS/Android offline ASR examples.

Do not build ASR from scratch.

## 11. Phase-by-phase reuse default

| SafeEvidence phase | Reuse-first default |
|---|---|
| P01 repo/governance | transplant sibling CI/provenance/governance patterns; SpecGrain/Diffcipline process |
| P02 contracts/vault | **ottari SQLCipher/WAL vault primary qualification hypothesis**; selected MedScale keys/lock/path claims and source contracts only after coherent crash/durability qualification |
| P03 evidence acquisition | MedScale evidence identities + OpenMed provenance/snapshot patterns; write only source-specific adapters/glue |
| P04 lexical retrieval | MedScale lexical baseline + SQLite FTS5 |
| P05 semantic/rerank | **fastembed-rs** + sqlite-vec/USearch tournament |
| P06 claim support | reuse MedScale evidence evaluation schemas/protocols; SafeEvidence-specific verifier remains core new work |
| P07 appraisal/applicability | reuse MedScale evidence strategy/evaluation semantics; extend clinical model |
| P08 decision assurance | **commandMed safety oracle/port + DAL harness + external typed-decision providers** |
| P09 calibration | **DAL metrics/selective tooling** |
| P10 synthesis/runtime | **MedScale Pack admission/runtime** + llama.cpp/mistral.rs provider |
| P11 desktop | reuse core/platform primitives; SafeEvidence-specific clinician UX |
| P12 documents/OCR | **Xberg/docling.rs/OpenMed/PaddleOCR**; no custom parser stack |
| P13 guidelines | reuse authorized guideline-verification research/code where exact provenance permits; build only missing SafeEvidence adapter/IR pieces |
| P14 FHIR | **MedScale FHIR** + selected OpenMed tests/algorithms |
| P15 mobile | MedScale mobile contracts + native platform code + existing FFI patterns |
| P16 mobile Ask/Scan | same retrieval/model/document donors, device-qualified |
| P17 pairing/sync | existing authenticated transport + sibling QR protocol/test patterns |
| P18 Deep Review | compose already-admitted retrieval/verification/appraisal components |
| P19 voice | sherpa-onnx/whisper.cpp/etc. |
| P20 SafeEvidenceBench | **DAL + MedScale evaluation tooling/protocol patterns** |
| P21 privacy/security | **MedScale vault/network/sandbox/privacy adversarial tests** + Kernux capability patterns |
| P22 release | reuse mature sibling release/SBOM/signing workflows |
| P23 claims/publication | reuse evidence/claim-ledger discipline, not empirical results |

## 12. What is genuinely new SafeEvidence work

Reuse does not remove the product's novel integration work. Likely SafeEvidence-specific engineering/research remains:

- public medical evidence acquisition lifecycle and evidence packs at product scale;
- clinical query decomposition and source-family strategy;
- exact claim-to-evidence support verifier integrated with product UX;
- evidence-quality/applicability presentation;
- categorical commitment/abstention states with explicit reasons; any future probability requires a separately validated estimand;
- integration of deterministic safety + typed decision models + retrieval sufficiency;
- contradiction-first synthesis;
- clinician evidence workstation UX;
- mobile evidence experience;
- Deep Review reproducibility;
- SafeEvidenceBench and matched product-level validation.

These are where engineering effort should concentrate. Generic storage, encryption, FHIR parsing, model packaging, OCR frameworks, embedding runtimes, calibration metric formulas, and network-policy plumbing should be reused whenever possible.

## 13. P00 closure amendment

P00 cannot close until:

- this reuse map is reviewed against live donor heads;
- every P01–P10 phase has at least one explicit code-reuse decision;
- direct-transplant candidates have exact paths and initial provenance records;
- Codex and Opus independently challenge whether any planned greenfield subsystem duplicates available code;
- every accepted greenfield subsystem has a `GREENFIELD_JUSTIFIED` record.

The objective is not maximum copying. The objective is **minimum unnecessary rebuilding** while keeping SafeEvidence coherent, local, secure, auditable, and independently testable.


## Independent-review reconciliation corrections

This map is subordinate to:
- `docs/P00_INDEPENDENT_REVIEW_RECONCILIATION_2026-10-07.md`;
- `docs/P00_FOUNDATION_DECISIONS_2026-10-07.md`;
- `docs/DONOR_RIGHTS_REGISTER.md`.

Corrections:
- private vault default hypothesis is ottari SQLCipher/WAL, not MedScale
  whole-file EncryptedVault;
- SafeOCR is a live critical-value donor candidate;
- commandMed policy mechanics are reusable, but its patient lexical policy is
  not copied unchanged;
- DAL negative Study-0 evidence must be retained;
- V1 has no user-facing clinical confidence percentage;
- every donor is copied only when its rights register allows the exact mode.

## V1 file-level map (2026-10-19)

Phase-by-phase reuse in §11 is now realized as work packets WP-00…WP-24 in
`docs/plan/IMPLEMENTATION_WORK_PACKETS_V1.md`, each citing transplant packets
T01…T36 with exact blob pins. The MedScale lexical retriever is confirmed to be
a token-overlap scorer (oracle only); `medscale-pack` is copied as a
format/store/runtime slice, not the full crate; the MedScale Tauri 2 shell
(`apps/desktop-tauri`) is the desktop copy donor (T36).

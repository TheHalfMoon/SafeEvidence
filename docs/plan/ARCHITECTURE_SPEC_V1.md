# SafeEvidence Architecture Specification — V1

Status: **PLANNING_BASELINE_V1** — freeze state is recorded only in `docs/PLAN_FREEZE.md`. Subordinate to `AGENTS.md` and the
binding P00 contracts (`P00_*_CONTRACT.md`), which remain in force unchanged.
This file resolves the open decisions listed in `ARCHITECTURE.md` §24 to the
extent evidence allows, and states the qualification test that can still
overturn each decision (exit criteria). Nothing here authorizes import or release.

## 1. Product boundary

SafeEvidence V1 is a **local-first, bilingual (English/Arabic) clinical
evidence research workstation** for population-level questions by clinicians
and researchers. It is research support, **not** clinically validated decision
support: no patient-specific diagnosis, treatment, dosing, triage or prescribing
output is released by V1 (P01 proposed wedge; ratification is Issue #4).

## 2. Component boundaries

```text
┌───────────────────────── Desktop app (Tauri 2 + React; T36) ─────────────────────────┐
│ Ask · Evidence · Deep Review · Documents · Packs · Settings&Privacy   (EN/AR, RTL)     │
└───────────────▲──────────────────────── typed IPC (capability allowlist) ────────────┘
                │
┌───────────────┴──────────── safeevidence-core (Rust, one process, no sockets) ───────┐
│ contracts (T01+)  assurance (T13 port)  verify  appraise  applicability  proof-admit  │
│ retrieval (FTS5 + fastembed/MedCPT + sqlite-vec)  query/PICO  text spans (T17)       │
│ vault (T03 SQLCipher, private plane)   evidence store (public plane, signed packs)   │
└──────▲───────────────▲──────────────────────▲────────────────────────▲───────────────┘
       │ stdio JSON     │ stdio JSON           │ stdio JSON             │ only egress path
┌──────┴─────┐  ┌──────┴────────────┐  ┌──────┴──────────┐   ┌────────┴──────────────┐
│ docs worker│  │ research worker   │  │ generator       │   │ network broker (T05)  │
│ Xberg+OCR  │  │ Python, pinned:   │  │ llama.cpp GGUF  │   │ allowlist, modes:     │
│ (T20,T29)  │  │ litdb T15, ASReview│ │ (D-06), optional│   │ LOCKED / UPDATE_ONLY /│
│ sandboxed  │  │ T18, statsmodels   │  │ sandboxed, no   │   │ SELECTED_CONNECTORS   │
│ no network │  │ T19, DAL T14,      │  │ net, no keys    │   └───────────────────────┘
│            │  │                    │  └─────────────────┘
└────────────┘  │ SafeOCR T16; no net│
                └────────────────────┘
Mobile (P15/P16): SwiftUI / Compose shells → UniFFI (T24) → same Rust core subset
(contracts, vault protectors, lexical+compact rerank, assurance, proof admission).
```

Trust rules (unchanged from P00): workers propose, core admits; only the
broker opens sockets; derived indexes are rebuildable projections; private
plane never enters public packs; model output never grants authority. Every
worker (documents, research, generator) is a separate sandboxed process with
no network capability and no access to vault keys; untrusted model files and
documents are never parsed inside the core process. Only the
`safeevidence-network` crate may depend on an HTTP client (enforced by TA-29).

## 3. Frozen decisions

| ID | Decision | Selected | Evidence | Exit/overturn test |
|---|---|---|---|---|
| D-01 | Tensor/ONNX runtime (one primary) | **ONNX Runtime via `ort`**; `tract` only where ORT cannot link (wasm/Android x86 emulator) | fastembed-rs (T21) and xberg-paddle-ocr (T20) both use `ort`, but pin different exact versions (`=2.0.0-rc.13` vs `=2.0.0-rc.14`); because the docs worker is a separate binary it lives in its own Cargo workspace so each side resolves one `ort`; WP-01 attempts alignment to a single version first | ORT fails WP-23 sandbox/no-network or WP-24 packaging on a tier-1 OS |
| D-02 | Primary document engine | **Xberg** incumbent; docling.rs challenger | Xberg core crate with `pdf-native` only plus `xberg-paddle-ocr` is network-free (xberg OCR presets and `xberg-ffi` are not: see T20); docling.rs defaults include URL/image/YouTube/VLM network features | docling.rs (no-default-features) beats Xberg on WP-13 medical fixtures by the pre-registered margin |
| D-03 | Python | **One** sandboxed, on-demand, network-less research worker (desktop only) | Copy-first: ASReview, statsmodels, litdb, DAL, SafeOCR, commandMed oracle are Python and tested; rewriting them violates `AGENTS.md` | Worker cannot meet WP-23 sandbox or WP-24 install-size ceiling → port the failing module with copied tests as oracle |
| D-04 | Private vault & keys | **ottari `himsat-core` vault slice (T03)** is the single key hierarchy; MedScale T02 is reference with a bounded fallback | T03 has SQLCipher, lease, backup/restore/verify, rotation, deletion, four OS protectors and kill/spill/adversarial tests | Fails `P00_VAULT_DURABILITY_CONTRACT.md` campaign in WP-03 |
| D-05 | Retrieval stack | **SQLite FTS5 BM25** (public plane DB) → **MedCPT** query/article encoders + **MedCPT cross-encoder** via fastembed-rs (ONNX) → **sqlite-vec** projection, exact flat-scan fallback | P00 requires MedCPT benchmark; donors exist for every layer | Dense layer not admitted unless it beats BM25 on WP-07 held-out set (P05 promotion rule) |
| D-06 | Local generator | **llama.cpp** (GGUF, CPU) incumbent, `mistral.rs` challenger; model chosen by WP-12 tournament among Apache-2.0/MIT-weight instruct models that fit the RAM ceiling | Broadest CPU/OS support; runs as a sandboxed out-of-process worker; deterministic template fallback keeps the generator off the critical path | Challenger wins WP-12 on quality-per-RAM |
| D-07 | Claim-support verifier | Deterministic span/number/negation checks **+** one NLI/cross-encoder model (ONNX) selected by WP-08 tournament; MultiVerS = oracle only | No admissible production donor; SciFact/MultiVerS are benchmarks | — (tournament inside WP-08) |
| D-08 | Desktop shell | **Tauri 2 + React** from MedScale `apps/desktop-tauri` (T36) | MedScale already hardened this shell (strict CSP except `style-src 'unsafe-inline'`, named-command capability allowlist) with IPC/bundle tests; it is **not** qualified for SafeEvidence until TA-20 passes; P00R left shell OPEN_TOURNAMENT → now incumbent with exit | Fails WP-18 cache/crash/clipboard/a11y/PHI-leak checklist → Slint (MedScale also uses Slint 1.16.1) |
| D-09 | Mobile FFI | **UniFFI** (T24) | P00 mandate to evaluate UniFFI first | UniFFI cannot express a required async/cancellation contract |
| D-10 | Pack/app update trust | MedScale pack manifest (T07) **+ TUF metadata via `tough`** (T25) | P00 requires TUF-style semantics | Key-custody owner (Issue #5) rejects TUF roles |
| D-11 | Sync transport | **Deferred** (P17). Candidate `iroh`; no transport in V1 | P00R: no ready sibling pairing engine | — |
| D-12 | Guideline computability | **Deferred** (P13). V1 treats guidelines as rights-admitted documents with version/jurisdiction metadata; CQL toolchain is a dev-time JVM worker only | Compilation ≠ clinical correctness (P00) | — |
| D-13 | Confidence display | **No clinical percentage in V1** (P00). Categorical outcome + reason codes + per-domain certainty | P00 binding | Frozen estimand + calibration split + clinical owner sign-off |
| D-14 | Arabic/English | Arabic UI/RTL from day one; Arabic **query** layer maps to English evidence via bilingual PICO normalization + multilingual encoder challenger; Arabic evidence corpus is a separate pack class | MedCPT is English-only | WP-06 parity gate fails → Arabic Ask ships as `ASK_MORE`/`ABSTAIN` with explicit reason, never silent degradation |
| D-15 | Performance budgets | Provisional ceilings in §5, frozen after WP-M0 measurement | `RUNTIME_BUDGET.md` forbids invented targets; ceilings are gates, not claims | Measured baseline shows a ceiling is infeasible → versioned amendment |
| D-16 | Online discovery and living surveillance | P00 D7 applied: every outbound query is shown to the user verbatim before sending; default queries are built from structured concepts/keywords; raw narrative and patient context are never sent; saved-query surveillance runs only for queries the user individually opted in, re-showing the query on change; query-derived results and caches are stored in the **private vault**, never in public packs | `P00_FOUNDATION_DECISIONS_2026-10-07.md` D7 | none (binding) |

## 4. Data planes and stores

| Store | Engine | Contents | Encryption |
|---|---|---|---|
| Public evidence store | SQLite (FTS5 + sqlite-vec) per signed EvidencePack, read-only | citation metadata, rights-admitted abstracts/full text, validity overlays, embeddings; changes only by installing a new signed pack | integrity-verified (pack digest + TUF), not secret |
| Private query-derived store | SQLCipher (inside the private vault) | live-fetched records and caches produced by the user's own queries (D-16), private FTS/vector projections | vault DEK |
| Private vault | SQLCipher (T03) | questions, answers, AnswerProofManifests, EvidenceSnapshots, user documents/OCR, patient context, private projections | DEK wrapped by OS protector (DPAPI/Keychain/Keystore/Secret Service) |
| Pack store | content-addressed files (T07) | Evidence/Model/Terminology/Guideline/Benchmark packs | signed; anti-rollback epoch |
| Worker scratch | in-memory where feasible; otherwise a per-job directory encrypted with a per-job key held only by the core | parser/OCR intermediates | key discarded and directory deleted on job end; residue probed by T12 tests |

## 5. Performance and memory budgets (provisional ceilings, D-15)

Reference machine: Windows 11, 4-core x86-64 CPU, 16 GB RAM, SSD, no GPU.
Reference pack: 100,000 English abstracts. All values are **gates for
engineering acceptance, not product claims**.

| Budget | Desktop ceiling | Mobile ceiling (P16) |
|---|---|---|
| Installer size without packs | ≤ 450 MB (incl. research worker) | ≤ 150 MB |
| Idle resident memory | ≤ 350 MB | ≤ 200 MB |
| Cold start to interactive UI | ≤ 5 s | ≤ 3 s |
| Ask, lexical + rerank, warm, p95 (no generator) | ≤ 4 s | ≤ 4 s (lexical + compact rerank) |
| Ask with local generator, p95 | ≤ 45 s | not required in V1 |
| Peak resident memory during Ask with generator | ≤ 7 GB | ≤ 1.5 GB (no generator) |
| Reference pack on disk (text + FTS + int8 vectors) | ≤ 1.5 GB | ≤ 500 MB selected subset |
| Born-digital PDF import, 20 pages | ≤ 15 s | — |
| OCR per scanned page (CPU) | ≤ 10 s | ≤ 12 s |
| Deep Review screening step, 2,000 records | ≤ 60 s per prioritisation round | — |
| Network bytes in `NETWORK_LOCKED` mode | **0** (hard gate) | **0** |

Sequential model loading is mandatory: generator, reranker and OCR models are
never co-resident unless the peak ceiling still holds.

## 6. Failure semantics (unchanged contracts, restated for implementers)

`ControlAction` ∈ {RETRIEVE_EVIDENCE, USE_TOOL, REQUEST_CONTEXT};
`TerminalOutcome` ∈ {ANSWER, ANSWER_WITH_CAUTION, ASK_MORE, CONFLICT, ABSTAIN,
ESCALATE, BLOCKED, EMERGENCY_NOTICE}. Automatic EMERGENCY_NOTICE classification
from lexical symptoms is **disabled in V1** (P00 decision-assurance contract);
the value stays in the vocabulary for a future approved policy. Worker crash, missing pack, stale validity
epoch, rights revocation, unverifiable claim, or unsupported language each map
to a reason-coded terminal outcome; none maps to "no evidence".

## 7. Interoperability

- Import: RIS/MEDLINE/CSV via litdb (T15) and ASReview IO (T18); FHIR R4 read-only patient context (T09).
- Export: EvidenceSnapshot JSON; RIS; PRISMA 2020 counts; SoF table; EBMonFHIR crosswalk bundles (`Citation`, `Evidence`, `ArtifactAssessment` certainty/RoB) per T26.
- No external writes (EHR, registries) in V1.

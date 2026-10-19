# SafeEvidence Master Plan

Status: `FOUNDATION_DRAFT`

This is a program plan, not implementation authority. Each phase must be decomposed into bounded specs/grains before execution. A phase closes only on exact evidence, not narrative progress.

## Program rules

1. Planning and implementation are separate gates.
2. No clinical, safety, privacy, superiority, or readiness claim outruns exact evidence.
3. Negative, blocked, null, and abstention results are valid outcomes.
4. Every source adoption is exact-revision/path/artifact bound.
5. User data and medical evidence do not become training data implicitly.
6. No mandatory SafeEvidence cloud or founder-funded runtime dependency.
7. No automatic remote inference fallback.
8. Desktop and mobile use shared contracts but may use different native implementations.
9. Arabic/English and accessibility are tested continuously.
10. Release readiness and real-PHI readiness are separate gates.
11. Copying ready authorized implementations is the default before greenfield implementation. SafeEvidence must copy, vendor, or directly use existing good code rather than rewrite equivalent generic subsystems.
12. Every implementation phase begins with an exact donor-code inspection and reuse decision. `GREENFIELD_JUSTIFIED` requires an explicit rejection reason for available implementations.
13. Donor tests and fixtures travel with reused behavior where practical; empirical claims never transfer automatically.

## Copy-first gate for every phase

Before writing new subsystem code, the owning grain MUST execute:

```text
R0  define required SafeEvidence contract/behavior
R1  inspect exact donor implementations
R2  identify the largest coherent safe slice that avoids unrelated donor-product code
R3  choose COHERENT_COPY / VENDOR / DEPEND / WORKER
R4  copy donor tests/fixtures with behavior
R5  adapt only the integration boundary
R6  write GREENFIELD_JUSTIFIED only when no good ready implementation exists
```

The primary copy authority is `docs/COPY_FIRST_SOURCE_PLAN.md`; `docs/REUSE_FIRST_IMPLEMENTATION_MAP.md` remains the detailed donor map.

A phase is not implementation-ready if it says only "build X" while known code already implements X and no reuse decision exists.

Examples already confirmed during P00:

- P02 starts with an ottari SQLCipher/WAL vault bake-off and reuses only compatible, independently qualified MedScale key/writer-lock/path/source-contract helpers; the MedScale whole-file EncryptedVault is NOT canonical;
- P04 starts from MedScale lexical retrieval contracts/baseline and then promotes FTS5/BM25;
- P08 starts from commandMed's deterministic safety scaffold and DAL's evaluation harness;
- P09 starts from DAL calibration/selective-risk code;
- P10 starts from MedScale Pack admission/runtime;
- P12 depends on/adapts Xberg/docling.rs/OpenMed/PaddleOCR rather than authoring document/OCR engines;
- P14 starts from MedScale's existing FHIR R4 crate;
- P20 reuses DAL/MedScale evaluation tooling.

Reuse does not transfer donor empirical claims, clinical validation, release readiness, or safety status. SafeEvidence re-runs its own acceptance evidence after transplantation.

---

# P00 — Foundation challenge and freeze

## Goal

Turn the initial thesis into a challenged, gap-tracked, implementation-ready foundation before large code lands.

## Work

- independent Codex architecture/product/source review;
- independent Claude/Opus architecture/product/source review;
- reconcile disagreements into a gap register;
- verify every major source family and remove weak/duplicative candidates;
- define canonical terminology for evidence, source, claim, confidence, sufficiency, authority, applicability, snapshot, pack, and review state;
- freeze non-goals and cloud/privacy invariants;
- draft threat model;
- draft data lifecycle map;
- draft intended-use/claims register;
- decide initial license strategy;
- decide initial governance and merge/CI rules.

## Closure gate

- no unresolved P0 planning gap;
- every unresolved P1 has owner, decision gate, and phase;
- open architecture decisions are explicit rather than silently assumed;
- source ledger is complete enough for the first implementation horizon;
- `docs/REUSE_FIRST_IMPLEMENTATION_MAP.md` is reconciled against live donor heads;
- P01-P10 each have at least one explicit reuse decision or `GREENFIELD_JUSTIFIED` record;
- implementation roadmap is internally consistent.

---

# P01 — Repository, governance and reproducibility foundation

## G01a synthetic engineering qualified — full P01 remains pending

FOUNDER_OPTION_B_RATIFIED / G01A_SYNTHETIC_QUALIFIED / INDEPENDENT_REVIEW_PENDING / NO_ADMISSIONS.

The founder selected bounded Option B and accepted G01a engineering ownership (Issue #17).
Signed governance PR #19 merged at 5f1623c9cdd11cf43989efe37f638cba230e7ff2;
synthetic implementation PR #20 merged at 91bd597e377a8b902499a6e0b66e567e89ba7bd5;
build-target hardening PR #21 merged at d6645e169d643b6b6eae7ad06e17a605edcb0687.
Post-main P00, P01 and G01a CI passed, including Windows and Ubuntu.
Founder record: https://github.com/TheHalfMoon/SafeEvidence/issues/17

Only the standard-library-only, synthetic fixture, offline format/test/lint
and exact-revision CI engineering baseline is qualified. Independent technical
review remains pending. This is not full P01-G01 authorization or P01 closure.

NO_ADMISSIONS and the original 41 P1 findings remain in force. Issue #3
continues to require phase owner decisions; Issue #4 requires qualified
clinical intended-use and evaluation authority; Issue #5 requires exact
source/contributor rights, pack and release-trust decisions. These gates
are BLOCKED for dependent clinical/product/source work. No patient data,
models, donor sources, signed packs, production release, or P02 are admitted.

## Goal

Create the minimum engineering substrate that makes later evidence trustworthy.

## Work

- Rust workspace and toolchain pin;
- formatting/lint/test baseline;
- CI for Windows/Linux/macOS where available and relevant;
- exact-head CI/evidence discipline;
- dependency/source provenance schema;
- SBOM/advisory baseline;
- deterministic fixture/test conventions;
- versioned schemas;
- benchmark artifact identity contract;
- release/claim ledger skeleton;
- secure-development and vulnerability-reporting docs.

## Closure gate

A clean repository can reproduce the baseline checks from a fresh checkout with no hidden service dependency.

P01 cannot close until donor-rights admission/SBOM/notice mechanisms exist,
the owner signs the initial intended-use/evaluation charter, the public/private
placement and durable-authority contracts are incorporated into P02 specs, and
each original Codex/Opus P1 has an owning issue/phase-entry acceptance gate.
The required acceptance source is the two P00 P1 registers.

---

# P02 — Canonical contracts and local vault

## Goal

Establish durable local authority before adding AI.

## Work

- `SourceArtifact`;
- `EvidenceSpan`;
- `Claim`;
- `EvidenceSnapshot`;
- `PatientContext`;
- `AnswerArtifact`;
- pack manifests;
- audit/event contracts;
- explicit scope/realm contracts;
- encrypted metadata/blob prototype;
- key provider abstraction;
- backup/restore;
- one-writer or qualified concurrency policy;
- deletion/tombstone semantics;
- migrations and crash recovery.

## Required campaigns

- restart equivalence;
- interrupted write/migration;
- disk-full behavior;
- backup/restore into a clean location;
- key-loss/recovery semantics;
- temp/WAL/journal/cache inspection;
- scope leakage tests.

## Closure gate

Durable source/evidence state survives restart/recovery without AI or network
access. The P02 gate also requires the chosen private vault to pass
`docs/P00_VAULT_DURABILITY_CONTRACT.md`, the Study/Result independence
fixtures, and the atomic AnswerProofManifest authority contract. No donor's
standalone tests are accepted as equivalent to integrated crash qualification.

---

# P03 — Evidence corpus and source acquisition

## Goal

Build rights-aware, versioned local evidence ingestion.

## Work

- PubMed/NCBI metadata adapter;
- Crossref DOI/metadata adapter;
- PMC open-full-text adapter where rights permit;
- optional OpenAlex discovery adapter;
- user-provided document import;
- institution-provided evidence import;
- retraction/correction/supersession metadata;
- source deduplication/identity reconciliation;
- immutable evidence snapshots;
- evidence-pack build/update pipeline;
- offline pack import/export.

## Closure gate

A corpus can be created, updated, inspected, exported, and reproduced with source identities and rights state intact.

---

# P04 — Retrieval baseline

## Goal

Establish a strong model-light retrieval baseline before semantic complexity.

## Work

- scope filtering;
- exact identifier lookup;
- FTS5/BM25;
- medical terminology normalization;
- PICO/PICOTS query representation;
- source-family and recency filters;
- deterministic ranking baseline;
- retrieval trace/snapshot;
- held-out retrieval benchmark.

## Metrics

- recall@k;
- precision@k;
- nDCG;
- source-family coverage;
- recency;
- retraction exclusion;
- rights-policy compliance;
- cold/warm latency;
- memory/disk footprint.

## Closure gate

Lexical retrieval quality and failure modes are measured before embeddings are promoted.

---

# P05 — Semantic retrieval and reranking tournament

## Goal

Add only semantic components that produce measured value over P04.

## Work

- embedding candidates;
- local vector projection candidates;
- reranker candidates;
- reciprocal/fusion strategies;
- multilingual/cross-language retrieval;
- source-diversity constraints;
- Arabic/English benchmark slices;
- resource/latency accounting.

## Promotion rule

No embedding/vector/reranker becomes canonical unless it improves held-out performance enough to justify RAM, disk, startup, privacy, update, and model-rights cost.

---

# P06 — Citation identity and exact claim-support verification

## Goal

Prevent real-but-irrelevant citations from legitimizing unsupported claims.

## Work

### Stage A — citation identity

Outcomes:

```text
VERIFIED_IDENTITY
PARTIAL_METADATA_MATCH
AMBIGUOUS
NOT_FOUND
RETRACTED
CORRECTED
SOURCE_UNAVAILABLE
```

### Stage B — claim support

Outcomes:

```text
SUPPORTS
PARTIALLY_SUPPORTS
CONTRADICTS
DOES_NOT_ESTABLISH
UNRESOLVED
```

- exact evidence spans;
- citation placement;
- contradiction links;
- unsupported-claim detection;
- numeric/safety/high-consequence claim categories;
- verifier benchmark and human adjudication protocol.

## Closure gate

The verifier itself is evaluated; it is not treated as ground truth because it is model-assisted.

---

# P07 — Evidence appraisal and applicability

## Goal

Separate evidence quality from patient/jurisdiction applicability.

## Work

- study-design representation;
- risk-of-bias inputs where available;
- directness/precision/consistency representation;
- population/intervention/comparator/outcome applicability;
- recency;
- jurisdiction;
- guideline version/issuer;
- contradiction;
- explicit missing patient context;
- no hidden single-number evidence score.

## Closure gate

UI/API can explain why evidence is strong/weak and why it does/does not apply without conflating those judgments.

---

# P08 — Decision assurance tournament

## Goal

Select a replaceable decision-assurance strategy through evidence, not preference.

## Candidate universe

- deterministic sufficiency rules;
- Decision 2.0 compact models;
- Laya;
- Mapika/decider;
- CLM;
- restricted-logit/open-Jev alternatives;
- BioClinical encoder controls;
- structured-output LLM control;
- Jev comparison when reproducible and permitted.

## Required typed state contract

```text
ControlAction = RETRIEVE_EVIDENCE | USE_TOOL | REQUEST_CONTEXT
TerminalOutcome = ANSWER | ANSWER_WITH_CAUTION | ASK_MORE | CONFLICT |
                  ABSTAIN | ESCALATE | BLOCKED | EMERGENCY_NOTICE
```

See `docs/P00_DECISION_ASSURANCE_CONTRACT.md` for total precedence, reason
codes, finite action budget, commit/abstention metrics and V1 disablement of
unqualified emergency symptom heuristics.

## Metrics

- action/state accuracy where gold exists;
- unsafe-commit rate;
- over-abstain rate;
- risk-coverage/AURC;
- abstention precision/recall/F1;
- Brier/ECE/NLL where scores are meaningful;
- missing-information behavior;
- distribution-shift behavior;
- latency/RAM/disk;
- Arabic/English slices.

## Closure gate

No model's raw confidence is exposed as medical truth. A deterministic-only baseline remains available.

---

# P09 — Calibration layer

## Goal

Define what any user-visible probability actually means.

## Work

Potential separately calibrated targets:

- probability evidence is sufficient for commitment;
- probability a claim is supported by the bound evidence;
- probability an answer is evidence-supported under a defined benchmark;
- probability abstention/ask-more is the correct state;
- applicability classification confidence.

- calibration-set governance;
- temporal/domain shift monitoring;
- reliability diagrams;
- bin-level sample counts;
- no percentage outside measured domain;
- UI language for calibrated vs uncalibrated outputs.

## Closure gate

Every visible percentage has a documented estimand and calibration identity.

---

# P10 — Local synthesis and post-answer verification

## Goal

Use generation as constrained synthesis over verified evidence.

## Work

- local generator tournament by device tier;
- structured evidence context compiler;
- citation-aware answer format;
- unsupported-claim post-check;
- numeric/dose/safety claim checks;
- contradiction preservation;
- concise clinician mode vs deep-review mode;
- deterministic fallback template when generation is unavailable.

## Closure gate

Generator failure never removes access to evidence or forces cloud fallback.

---

# P11 — Desktop Doctor Workstation

## Goal

Deliver the complete local clinician evidence experience.

## Core navigation

```text
Ask
Evidence / Sources
Deep Review
Documents
Packs
Settings & Privacy
```

Patient context is contextual rather than a separate EHR product.

## UX requirements

- answer + evidence side by side;
- exact source-span jump;
- contradiction visible;
- calibrated/uncalibrated state visible;
- evidence quality and applicability separate;
- network/offline/pack freshness visible;
- loading/empty/error/blocked states;
- keyboard-first navigation;
- screen-reader semantics;
- zoom/reflow;
- RTL/Arabic;
- no remote fonts/analytics by default.

## Shell qualification

Tauri remains a candidate until cache/crash/clipboard/storage/accessibility tests pass.

---

# P12 — Document/PDF/OCR subsystem

## Goal

Turn local clinical documents into source-addressable evidence without trusting extraction blindly.

## Work

- file quarantine/classification;
- born-digital PDF parsing;
- scanned PDF/image OCR;
- layout/table/formula extraction;
- page/region/cell coordinate preservation;
- OCR engine tournament;
- Arabic/English OCR;
- critical numeric verifier;
- de-identification/PII classification where explicitly used;
- hostile-input fuzz/resource campaigns;
- parser crash isolation.

## Medical OCR benchmark

Dedicated categories:

- drug names;
- dose/decimal;
- units;
- negation;
- laboratory values;
- dates/times;
- bilingual Arabic/English;
- tables;
- handwriting only if separately promoted.

## Closure gate

Conflicting critical extraction returns unresolved/null rather than silently choosing a value.

---

# P13 — Guideline verification engine

## Goal

Represent and verify guideline recommendations beyond PDF retrieval.

## Work

- guideline identity/version/jurisdiction;
- recommendation IDs/spans;
- population/criteria/contraindications;
- stated strength/certainty;
- supersession;
- computable intermediate representation research;
- CQL/CPG-on-FHIR interoperability experiments;
- semantic faithfulness verification;
- applicability mapping;
- conflicting-guideline handling;
- non-computability/human-review state.

## Closure gate

Schema validity or CQL compilation is never treated as proof that generated logic preserves clinical meaning.

---

# P14 — FHIR patient-context boundary

## Goal

Use clinical context without becoming a replacement EHR.

## Work

- FHIR R4 read/import subset;
- profile/version-aware mapping;
- unsupported/loss report;
- patient identity/subject confirmation;
- medication/condition/lab/allergy context;
- exact source provenance;
- read-only SMART research after local path is proven;
- NPHIES research as separate Saudi adapter;
- no external clinical writes.

## Closure gate

The same answer can explain exactly which patient-context facts were used and where they came from.

---

# P15 — Native mobile foundation

## Goal

Establish iOS and Android as native, secure, offline-capable clients sharing SafeEvidence contracts.

## Work

- Rust core FFI boundary;
- SwiftUI shell;
- Kotlin/Compose shell;
- Keychain/Keystore;
- biometric-lock policy;
- encrypted local subset vault;
- app-switch/screenshot/notification privacy;
- import/share-sheet/file-provider integration;
- pack storage/resource quotas;
- offline mode;
- background lifecycle rules;
- Arabic/RTL/accessibility.

## Closure gate

Mobile can open a local vault, load a bounded evidence pack, and operate without a SafeEvidence server.

---

# P16 — Mobile Ask / Scan / Saved / Patient

## Goal

Ship the focused mobile product.

## Ask

- local retrieval;
- compact reranker;
- compact decision assurance;
- local synthesis or structured fallback;
- citation review.

## Scan

```text
camera
 -> edge/perspective correction
 -> recoverable local capture
 -> OCR
 -> critical-number validation
 -> local document/evidence admission
```

## Saved

Offline evidence briefs and specialty packs.

## Patient

Explicit bounded context, never a hidden comprehensive record.

---

# P17 — Desktop-mobile local pairing and selective sync

## Goal

Allow controlled local transfer without central cloud dependence.

## Work

- one-time short-lived QR bootstrap;
- authenticated pairing;
- encrypted direct/LAN preference;
- device identity and revocation;
- selective pack/artifact/context sync;
- conflict/revision semantics;
- no raw keys in transfer bootstrap;
- no silent public relay;
- interrupted/replay/race/revocation tests.

## Closure gate

Paired devices synchronize only selected scopes and each remains usable independently.

---

# P18 — Deep Review

## Goal

Deliver extended evidence synthesis with transparent research process.

## Required artifact

```text
research plan
queries/retrieval traces
source inclusion/exclusion
source set
subquestion synthesis
contradictions
gaps
applicability
evidence profile
claim-support report
calibration/decision state
immutable evidence snapshot
limitations
```

## Closure gate

A reviewer can reproduce which evidence produced the report and distinguish source statements from SafeEvidence inference.

---

# P19 — Voice evidence mode (optional promotion)

## Goal

Add voice only after the text/evidence product is trustworthy.

## Work

- local microphone path;
- medical ASR tournament;
- Arabic/English/code-switch evaluation;
- spoken query editing/confirmation;
- interruption/barge-in;
- concise spoken answer;
- full citations remain visible in text;
- voice never lowers evidence standards.

---

# P20 — SafeEvidenceBench

## Goal

Create the qualification system that makes product claims auditable.

## Benchmark families

### Retrieval

- diagnosis;
- treatment;
- screening/prevention;
- prognosis;
- adverse effects/interactions;
- pregnancy/pediatrics;
- renal/hepatic adjustment;
- rare disease;
- multimorbidity;
- rapidly changing evidence;
- insufficient evidence;
- retracted/corrected evidence;
- conflicting guidelines;
- jurisdiction-specific questions;
- patient-context questions.

### Citation/support

- citation identity;
- exact-span support;
- unsupported cited-claim rate;
- contradiction miss rate;
- citation placement.

### Abstention/decision assurance

- missing information;
- irrelevant evidence;
- weak evidence;
- conflicting evidence;
- stale pack;
- unavailable source;
- model/worker failure.

### Calibration

- reliability;
- Brier/ECE/NLL where applicable;
- risk-coverage;
- temporal and specialty shift.

### OCR/documents

- critical numeric categories;
- Arabic/English;
- tables/layout;
- hostile documents.

### Privacy/security

- no-silent-egress;
- scope leakage;
- cache/index deletion;
- backup/restore;
- worker capability isolation;
- prompt injection in retrieved/document content.

### Resource/performance

- cold/warm latency;
- CPU/GPU/RAM;
- disk/index size;
- battery/mobile thermal behavior;
- long-running deep review;
- degraded/low-memory behavior.

### Human review

Qualified clinician/researcher review where authorized, with predefined rubrics, blinded versions where feasible, adjudication, and inter-rater agreement.

## Closure gate

No single aggregate score is sufficient for release or superiority claims.

---

# P21 — Privacy, security and real-data qualification

## Goal

Separate useful synthetic functionality from real sensitive-data readiness.

## Campaigns

- threat model closure;
- OS key custody;
- at-rest and unlocked-state storage inspection;
- temp/WAL/cache/crash/log review;
- worker sandbox/capability tests;
- network observation/no-egress campaign;
- backup/restore/deletion behavior;
- mobile backup/notification/app-preview behavior;
- update/supply-chain integrity;
- support-bundle redaction;
- permission revocation;
- clinical data lifecycle map.

## Rule

Architecture and tests do not self-certify HIPAA, GDPR, PDPL, SFDA, medical-device, or other compliance claims. Legal/regulatory claims need appropriate external authority/evidence.

---

# P22 — Release engineering and distribution

## Goal

Produce installable, reproducible, recoverable desktop/mobile artifacts.

## Work

- versioning/migrations;
- deterministic/reproducible build evidence where feasible;
- SBOM;
- signatures/pack trust;
- rollback/revocation;
- Windows installer;
- macOS package/signing/notarization strategy;
- Linux packages;
- Android distribution;
- iOS distribution gate;
- offline install/update packs;
- dependency/model/license notices;
- clean-install usability.

---

# P23 — Claims, competitive evaluation and publication

## Goal

Publish only claims supported by matched evidence.

## Work

- claims registry;
- intended-use statement;
- limitations;
- SafeEvidenceBench release packet;
- matched comparisons where legally/technically permitted;
- independent reproduction path;
- research manuscript(s) for retrieval/verification/decision assurance/calibration where genuinely novel and supported;
- public model/system cards.

---

# Cross-cutting workstreams

Every phase must consider:

- provenance and exact identity;
- rights/license/NOTICE;
- privacy/data lifecycle;
- security/capabilities;
- deterministic failure semantics;
- Arabic/English;
- accessibility;
- resource budgets;
- offline behavior;
- cancellation/recovery;
- benchmark/evidence impact;
- migration/rollback;
- documentation/user comprehension.

# Canonical sequence principle

The plan is intentionally ordered so that evidence/source truth and evaluation precede model glamour:

```text
truth contracts
 -> local custody
 -> sources
 -> retrieval
 -> claim verification
 -> applicability
 -> decision assurance
 -> calibration
 -> synthesis
 -> desktop/mobile UX
 -> advanced features
 -> clinical/privacy/release qualification
```

Agents may propose a different ordering only with explicit dependency/risk evidence. They must not skip an earlier trust prerequisite because a later feature is easier to demo.

# P00A — SafeEvidence foundation re-audit amendment (2026-10-07)

Before implementation promotion, reconcile
`docs/FOUNDATION_GAP_AUDIT_2026-10-07.md`.

Binding additions:

- P03 owns PubMed baseline/daily updates, revisions/deletions,
  Crossref/Retraction Watch overlays, PMC/Europe PMC rights-aware full text,
  canonical identifier reconciliation, and current-validity overlays.
- P05 adds NCBI MedCPT to the biomedical retrieval/reranker tournament and uses
  biomedical/systematic-review benchmarks.
- P06 adds SciFact-style rationale evaluation, a MultiVerS research oracle, and
  a clinician-adjudicated SafeEvidence claim/span holdout.
- P09 freezes the estimand, calibration/final split and change-invalidating
  policy as research prerequisites; V1 has NO clinical confidence percentage UI.
- P12 chooses one primary document engine through Xberg vs docling.rs medical
  qualification; SafeOCR is a live critical-value verification code donor candidate,
  with exact pin/rights/tests/Arabic qualification required before adoption.
- P13 initially supports user- or institution-provided guideline documents and
  metadata-only links to publicly identified guideline sources, subject to
  per-item rights and issuer/jurisdiction/version checks. CQL/CQF is an
  independently qualified syntax/execution reference, not proof of clinical
  recommendation correctness. Semantic guideline verification remains
  research-only until qualified; non-public source code is not an admitted
  implementation donor.
- P15 evaluates UniFFI as the default Rust-to-Swift/Kotlin binding strategy.
- P18 may reuse ASReview screening/dedup patterns; stopping remains
  human/evidence governed.
- P21/P22 define TUF-style signed update/freeze/rollback semantics for app and
  pack distribution and qualify the concrete implementation.
- evidence/citation/appraisal schemas receive an explicit EBMonFHIR crosswalk.
- every transplant follows `DONOR_TRANSPLANT_PROTOCOL.md`.
- every production engine follows `RUNTIME_BUDGET.md`.

P00A closes only after Codex and Opus independently challenge these additions
against exact live sources and no unresolved P0 planning gap remains.


# Copy-first implementation amendment

The founder explicitly authorizes copying, modifying, combining, adapting,
vendoring, and rebranding the source-code donors discussed for SafeEvidence.

Therefore implementation phases must follow `docs/COPY_FIRST_SOURCE_PLAN.md`.
The project is not expected to independently recreate commodity subsystems that
already exist in authorized sources.

The preferred P01-P15 behavior is:

```text
copy ready implementation
-> remove unrelated donor-product scope
-> preserve provenance and donor tests
-> adapt naming/contracts
-> qualify under SafeEvidence
-> build only the missing SafeEvidence-specific semantics
```


# P00B — Pre-build kill review amendment

Canonical authority: `docs/PREBUILD_KILL_REVIEW_2026-10-07.md`.

Binding corrections:

- P02 adds Study, StudyReportLink, OutcomeDefinition, EffectEstimate,
  ReviewProtocol, SynthesisProtocol and SynthesisResult contracts.
- P03 adds publication-state classification, trial/registry linkage,
  funding/COI provenance, living-surveillance triggers, and study/report
  reconciliation.
- P04/P05 measure report retrieval and study-level recall separately.
- P06 adds structured effect extraction using Evidence Inference/PICOX/RRnlp
  donors/benchmarks where appropriate.
- P07 uses versioned design-specific appraisal profiles instead of a universal
  quality score.
- P18 owns review protocol, screening audit, study-level dedup/linkage,
  extraction, appraisal, PRISMA-compatible accounting, living surveillance, and
  optional quantitative synthesis.
- P20 adds study-linkage, extraction, double-counting, multiplicity,
  meta-analysis golden fixtures, appraisal-agreement, and surveillance tests.
- statsmodels or an equivalently qualified existing statistical implementation
  is reused for synthesis; SafeEvidence does not rewrite standard meta-analysis
  formulas.
- preprints, protocols, registry results, regulatory reports, corrections and
  retraction notices remain distinct publication states.
- failure/partial/unavailable states never collapse into "no evidence."

The internal review's "no known P0" status is superseded. Independent Codex
and Claude/Opus reviews found P0 findings, now addressed only through the
canonical reconciliation documents.


# P00R — Independent review reconciliation

Authority:
- `docs/P00_INDEPENDENT_REVIEW_RECONCILIATION_2026-10-07.md`
- `docs/P00_FOUNDATION_DECISIONS_2026-10-07.md`
- `docs/DONOR_RIGHTS_REGISTER.md`

The prior internal "no known P0" statement is superseded by two independent
reviews. Their P0 findings are now resolved as planning decisions; P1 findings
are bound to owning phases.

Before P01 close:
- donor-rights register and source-admission mechanics exist;
- initial intended-use wedge is frozen;
- public/private data-plane placement is frozen;
- no broad product implementation begins outside that wedge.

P02 now owns:
- ottari-vs-alternative private vault qualification;
- key custody and crash/backup semantics;
- StudyArm/AnalysisPopulation/Result/Comparison/overlap contracts;
- ControlAction/TerminalOutcome contracts;
- AnswerProofManifest;
- source coordinate and privacy exposure contracts.

P03 additionally owns:
- default corpus scope and measured distribution/build budget;
- PubMed ordered-update completeness and replay;
- correction/retraction/expression-of-concern/version semantics;
- item/field rights and publication states.

P06 reuses SafeOCR critical-value verification where qualified and treats
research extraction stacks as proposals/oracles until admitted.

P08 incumbent is deterministic sufficiency + verifier evidence. Learned
decision models must beat it on a fresh SafeEvidence holdout. DAL negative
Study-0 results are prior evidence.

P09 cannot ship a user-facing clinical confidence percentage in V1.

P10 production pack consumers require qualified production trust; synthetic
signing seeds are test-only.

P11 shell remains OPEN_TOURNAMENT.

P12 uses narrow offline parser builds with network/download/telemetry features
disabled unless explicitly admitted, and process-level hostile-input limits.

P13 CQL validation never substitutes for guideline semantic/jurisdiction
validation.

P17 does not assume a ready sibling pairing engine.

P18 refuses pooling when independence/covariance/method support is not
qualified. ASReview prioritization is not proof of review completeness.

P20 evaluation planning prerequisites move earlier: intended-use population,
human adjudication, bilingual/Arabic expertise, split policy and label budget.

P21/P22 include OS residual surfaces, worker/socket confinement, production
TUF-style trust and safe diagnostic receipts.

P23 claims remain narrower than the roadmap.

P00R status (historical, now superseded):
`SUPERSEDED_BY_P00_REPAIR_2026_10_08`.

P00 closes only after Codex and Opus independently re-check the exact
reconciliation head and report zero unresolved P0.

## P00 repaired-contract precedence (2026-10-08)

Use `docs/P00_REPAIR_CLOSEOUT_PLAN_2026-10-08.md` to interpret the P00
reconciliation. Binding sheets for data placement, crash durability,
statistical study/result independence, decision semantics, proof admission and
per-slice donor rights supersede conflicting earlier candidate descriptions.

Before activating any P01-P23 work, resolve every applicable original P1 row in:
- `docs/P00_CODEX_P1_ACCEPTANCE_REGISTER.md`
- `docs/P00_OPUS_P1_ACCEPTANCE_REGISTER.md`

The first intended-use target is a CPU-only Windows desktop evidence workstation
for English/Arabic **population-level adult clinical evidence** research,
focused on sources, their support, contradictions, and limitations; no
patient-specific treatment or emergency triage authority is claimed.
Unqualified specialties, settings and territories are not marketed as covered.
P01 product/clinical owner must approve the exact test-domain cohort, language
and geography before evaluation/model/UX promotion. The V1 output has no
clinical probability percentage.

P00 remains OPEN until real independent post-repair reviewer reports support
closeout. Do not implement product code or merge this repair into main
prematurely.

## V1 planning baseline (2026-10-19)

The executable copy-first roadmap is `docs/plan/SAFEEVIDENCE_MASTER_PLAN_V1.md`
with its companion architecture, transplant, feature, work-packet and test
matrices. Freeze state is recorded only in `docs/PLAN_FREEZE.md`. This program
plan remains valid for phase vocabulary and history; where the V1 baseline is
more specific (decisions D-01…D-16, conflicts C1…C21), the V1 baseline governs
implementation sequencing. No gate in this file is relaxed by the V1 baseline.

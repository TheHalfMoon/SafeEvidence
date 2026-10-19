# SafeEvidence Agent Rules

These rules apply to Codex, Claude/Opus, Cursor, and any other engineering agent working in this repository.

## Communication and repository language

- Repository code, comments, commands, commits, branches, issues, PRs, specs, reports, research notes, evidence, and review artifacts are **English only**.
- User-facing conversation may be Arabic.

## Current project state

P00 is **CLOSED_CANONICAL** at main `ad9f7b972d4d0cb3dc388ce4caa6c18e369e3b22`, with real Codex/Opus reviews and exact-head/post-merge documentation CI. This closes the foundation **planning** gate only.

P01 is **PRE_ENTRY_GATES_PENDING**. A broad request to finish the project does not substitute for a qualified clinical safety owner, clinical evaluation plan, signed source rights, or approved scientific acceptance. Document and research the pending gates without beginning unapproved implementation. Current entry authority: `docs/P01_ENTRY_READINESS_2026-10-08.md`.

## G01a synthetic engineering qualified — independent review pending

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

## Authority order

Read in this order before planning or changing architecture:

1. `AGENTS.md`
2. `README.md`
3. `docs/PRODUCT_THESIS.md`
4. `docs/ARCHITECTURE.md`
5. `docs/SOURCE_LEDGER.md`
6. `docs/COPY_FIRST_SOURCE_PLAN.md`
7. `docs/REUSE_FIRST_IMPLEMENTATION_MAP.md`
8. `docs/DONOR_TRANSPLANT_PROTOCOL.md`
9. `docs/RUNTIME_BUDGET.md`
10. `docs/FOUNDATION_GAP_AUDIT_2026-10-07.md`
11. `docs/P00_REPAIR_CLOSEOUT_PLAN_2026-10-08.md`
12. `docs/P00_DATA_PLACEMENT_CONTRACT.md`
13. `docs/P00_VAULT_DURABILITY_CONTRACT.md`
14. `docs/P00_STUDY_INDEPENDENCE_CONTRACT.md`
15. `docs/P00_DECISION_ASSURANCE_CONTRACT.md`
16. `docs/P00_PROOF_ADMISSION_CONTRACT.md`
17. `docs/DONOR_RIGHTS_REGISTER.md`
18. `docs/P00_CODEX_P1_ACCEPTANCE_REGISTER.md`
19. `docs/P00_OPUS_P1_ACCEPTANCE_REGISTER.md`
20. `docs/P00_INDEPENDENT_REVIEW_RECONCILIATION_2026-10-07.md`
21. `docs/P00_FOUNDATION_DECISIONS_2026-10-07.md`
22. `docs/PREBUILD_KILL_REVIEW_2026-10-07.md`
23. `docs/MASTER_PLAN.md`
24. `docs/GAP_REVIEW.md`
25. active specs/decision records once created
26. `docs/P01_ENTRY_READINESS_2026-10-08.md` (current P01 entry state)
27. `docs/P01_CLINICAL_EVALUATION_CHARTER_DRAFT_2026-10-08.md` (unapproved)
28. `docs/P01_P1_GATE_TRACKER_2026-10-08.md` (41 original gates, unassigned)
29. `docs/PLAN_FREEZE.md` and `docs/plan/*_V1.md` (V1 copy-first planning baseline; implementation sequencing, never gate relaxation)

If documents conflict, stop treating the conflict as resolved and record it explicitly.

## Core invariants

- Local-first and useful offline.
- No mandatory SafeEvidence cloud.
- No silent remote inference, search, storage, telemetry, auth, or sync fallback.
- Zero founder-funded runtime COGS is a design target.
- Evidence first, language second.
- Model output never grants clinical or action authority.
- Confidence, evidence quality, applicability, authority, and review state remain separate.
- `ASK_MORE`, `CONFLICT`, `ABSTAIN`, `BLOCKED`, and negative results are legitimate outcomes.
- Deterministic validated tools/policies outrank generative text where applicable.
- Derived indexes/graphs/summaries are rebuildable projections, not canonical truth.
- Desktop is the complete workstation; mobile is native and scoped rather than a blind desktop clone.
- Arabic/English, RTL, accessibility, and resource limits are architecture concerns from the start.
- Source permission does not waive exact provenance, embedded third-party review, model/data/asset rights, notices, security review, or tests.

## Source reuse — mandatory copy-first rule

SafeEvidence MUST NOT rebuild a subsystem from scratch when a rights-admitted ready source already implements it well.

Before greenfield implementation, inspect `docs/COPY_FIRST_SOURCE_PLAN.md`, `docs/DONOR_RIGHTS_REGISTER.md`, actual donor code, and `docs/REUSE_FIRST_IMPLEMENTATION_MAP.md`.

The founder has asserted permission for the discussed source universe. Agents must still require an allowed per-source admission basis before copying bytes into the Apache-2.0 product tree. External copyright, copyleft, model, dataset, terminology, publication and asset rights are not inferred from a blanket statement.

Prefer in this order:

```text
COHERENT_COPY / VENDOR_SNAPSHOT
        ↓
DIRECT_DEPENDENCY when lower-maintenance
        ↓
ADAPT copied code behind SafeEvidence contracts
        ↓
PORT only for a real trust/platform boundary
        ↓
GREENFIELD_JUSTIFIED
```

Copying proven code is the default when it is suitable. Owning a SafeEvidence interface does not require owning an independently rewritten implementation.

Never wholesale-copy a repository merely because permission exists. Reuse the smallest coherent implementation slice that preserves correctness and maintainability.

For every implementation-relevant source, classify it as one of:

```text
COPY_BOUNDED
ADAPT
PORT_TO_RUST
DEPEND
VENDOR
FFI
WORKER
ARTIFACT_IMPORT
REFERENCE
BENCHMARK_ONLY
REJECT_DEFAULT
GREENFIELD_JUSTIFIED
```

A new subsystem may use `GREENFIELD_JUSTIFIED` only after a donor decision records the exact sources inspected and why reuse is materially worse on correctness, security/privacy, portability, maintenance, resource cost, provenance/rights, or product fit. "We prefer our own implementation" is not sufficient.

Before copied/adapted/vendored/runtime material becomes canonical, bind exact revision/digest, paths/artifacts, license/permission basis, transitive material, notices, modifications, trust placement, tests, update strategy, and exit strategy. Bring useful donor tests/fixtures with the implementation whenever possible.

Private source identities must not be disclosed in this public repository without explicit founder authorization for public disclosure.

## Evidence discipline

Never fabricate:

- tests;
- benchmark results;
- model quality;
- CI state;
- PR/issue state;
- SHAs;
- mergeability;
- source permissions;
- licenses;
- clinical claims;
- privacy/security guarantees;
- regulatory/compliance status.

Bind material claims to exact artifacts/revisions/evidence.

## Planning discipline

During P00:

- challenge the plan, do not defend it reflexively;
- search sibling/source repositories when a material decision depends on them;
- identify duplicate capability across SafeEvidence and sibling projects;
- minimize architecture before expanding it;
- prefer measurable promotion gates over framework preference;
- preserve genuine reviewer disagreement until evidence resolves it;
- convert gaps into explicit owners/phases/decision records;
- do not silently decide unresolved architecture questions.

Follow `docs/GAP_REVIEW.md` for independent Codex and Claude/Opus reviews.

## Implementation discipline after P00

Once implementation is authorized:

- use bounded branches/PRs;
- normal merge commits are preferred;
- no force-push;
- no rebase/history rewriting for shared review branches;
- verify exact PR head before merge;
- rerun/inspect relevant post-merge evidence;
- preserve provenance across copied/adapted code;
- keep migrations backward/recovery aware;
- avoid adding mandatory services before measured need.

## Review tools

Alibaba Open Code Review and Jev are required review components where they are applicable and available in the authorized environment. They complement, not replace, tests and human/agent reasoning.

Do not use CodeRabbit, Qodo, or Cubic as required proof/evidence for SafeEvidence.

Never claim a review tool ran unless exact output/evidence exists.

## Medical/scientific claim rule

Repository status words such as `CLOSED`, `PROVEN`, or `READY` apply only to the exact engineering/research scope defined by the owning artifact. They do not imply clinical validation, medical-device approval, patient safety, regulatory compliance, or superiority.

Any strong clinical or comparative claim requires a dedicated protocol, frozen evaluation boundary where appropriate, and evidence packet.

## Cost rule

Do not introduce paid APIs, paid compute, paid SaaS, or paid cloud infrastructure as mandatory development/product gates without explicit founder authorization.

Optional institution/user-provided external services may exist behind explicit adapters, but the supported local product must not silently depend on them.

## Completion rule

Agent self-report is not completion authority.

A task is complete only when its owning acceptance criteria are satisfied and evidence is bound to the exact revision. If evidence is incomplete, report the task as partial, blocked, or not proven instead of forcing `done`.

## SafeEvidence 2026-10-07 P00 amendment

The findings in `docs/FOUNDATION_GAP_AUDIT_2026-10-07.md` are mandatory P00
inputs. Agents must not close P00 by reviewing only the older foundation set.

In particular, do not:
- ignore PubMed update/delete/retraction lifecycle;
- omit item-level rights from packs/sync/export;
- build retrieval without benchmarking MedCPT;
- build claim verification without scientific-rationale evaluation and a
  clinician-adjudicated SafeEvidence holdout;
- display a confidence percentage without a frozen estimand/calibration split;
- invent mobile FFI before evaluating UniFFI;
- author generic parser/OCR/search/update frameworks when admitted donors exist.


## Pre-build kill review rule

`docs/PREBUILD_KILL_REVIEW_2026-10-07.md` is mandatory P00 authority.

Agents must preserve the distinction between Study and SourceArtifact/report,
prevent double-counting across multiple reports of one study, carry structured
effect-extraction provenance, and use design-specific appraisal profiles.

Do not implement generic systematic-review, meta-analysis, PICO extraction,
study-screening, or evidence-surveillance machinery from scratch when the
copy-first source plan identifies a qualified donor.


## P00 independent-review reconciliation authority

The independent Opus and Codex reviews of
`136cdffc2cd14133e01018ca56833241dd50bc4e` found the foundation not ready.

Agents MUST follow:
- `docs/P00_INDEPENDENT_REVIEW_RECONCILIATION_2026-10-07.md`;
- `docs/P00_FOUNDATION_DECISIONS_2026-10-07.md`;
- `docs/DONOR_RIGHTS_REGISTER.md`.

Binding consequences:
- public/rebuildable evidence and private authority are separate data planes;
- MedScale whole-file EncryptedVault is not the default SafeEvidence vault;
- report/study/result independence is explicit;
- ControlAction and TerminalOutcome are separate;
- generated text is not committed until AnswerProofManifest admission;
- V1 shows no clinical confidence percentage;
- SafeOCR is a real donor candidate and must not be described as empty;
- founder permission assertions do not bypass per-source rights records;
- no product implementation begins until post-reconciliation Codex and Opus
  re-checks close P00.

## P00 repair authority — 2026-10-08

The binding P00 contract sheets take precedence over older donor hypotheses and
generic roadmap statements. If a conflict remains, stop; do not resolve by
ignoring the new contract or copying code.

This paragraph was written during P00 repair and is retained as history:
P00 has now been independently closed as a planning phase. Its binding contracts
remain in force. P1 items are still OPEN_PHASE_GATES; a documented owner role
does not constitute a named individual or actual sign-off.

No production import without VERIFIED_ALLOWED rights-admission row. No
MedScale whole-file EncryptedVault adoption. No V1 clinical confidence
percentage. No model-generated clinical claim can be published as COMMITTED
without atomic final-text AnswerProofManifest verification and durable commit.

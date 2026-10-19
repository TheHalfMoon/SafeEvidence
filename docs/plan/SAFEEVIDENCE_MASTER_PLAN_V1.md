# SafeEvidence Copy-First Master Plan — V1

Status: **PLANNING_BASELINE_V1** — freeze state is recorded only in `docs/PLAN_FREEZE.md`.
This is the canonical implementation roadmap. It **adds** an executable layer
on top of `docs/MASTER_PLAN.md` (P00–P23 program plan), which remains valid as
program history and phase vocabulary. Binding P00 contracts, `AGENTS.md`, the
donor-rights register and all P01 gates are unchanged.

Companion artifacts (all V1):

| Artifact | File |
|---|---|
| Architecture specification | `docs/plan/ARCHITECTURE_SPEC_V1.md` |
| Source Transplant Matrix | `docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md` + `docs/evidence/source_transplant_pins_2026-10-19.json` |
| Feature Coverage Matrix | `docs/plan/FEATURE_COVERAGE_MATRIX_V1.md` |
| Implementation Work Packets | `docs/plan/IMPLEMENTATION_WORK_PACKETS_V1.md` |
| Test and Acceptance Matrix | `docs/plan/TEST_ACCEPTANCE_MATRIX_V1.md` |
| REA Research Dossier | `docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md` |
| Independent validation | `docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md` |

## 1. Objective and claim boundary

Build a local-first, bilingual clinical **evidence research** and
decision-assurance workstation (desktop first, scoped native mobile) that
retrieves evidence, verifies every material claim against exact source spans,
appraises certainty with design-specific structures, checks applicability,
separates studies from reports, tracks corrections/retractions, supports
systematic reviews, and abstains or asks for more when evidence does not
justify an answer.

Three completion states are always reported separately:

1. **Engineering complete** — WP exit criteria and TA rows pass on an exact commit.
2. **Clinically evaluated** — Issue #4 charter executed by qualified, named
   clinical owners with adjudicated holdouts. Not scheduled by engineering.
3. **Regulatorily qualified** — any jurisdiction-specific determination
   (e.g., SFDA, FDA, CE). Not planned or claimed; out of scope for V1.

V1 makes no safety, performance, superiority or regulatory claim.

## 2. Product architecture (summary)

Rust core (contracts, assurance, verification, appraisal, applicability,
retrieval, vault, proof admission) → Tauri 2/React desktop shell copied from
MedScale → three sandboxed, network-less, out-of-process workers (documents/OCR via Xberg;
one Python research worker for litdb/ASReview/statsmodels/DAL/SafeOCR; optional
llama.cpp generator) → one network broker as the only egress path → two data
planes (public signed evidence packs; private SQLCipher vault). Mobile reuses
the Rust core via UniFFI. Full specification and the 16 frozen decisions:
`ARCHITECTURE_SPEC_V1.md`.

## 3. Copy-first summary (what is reused vs built)

- **Copied/adapted founder code (14 slices):** MedScale contracts, keys,
  network broker, pack format, FHIR, OS sandbox, SBOM, privacy probes, Tauri
  shell; ottari vault; commandMed assurance (oracle + Rust port of mechanics);
  DAL metrics; MedOrigin litdb; SafeOCR verification.
- **Dependencies/workers (external):** Xberg, PaddleOCR models, fastembed-rs,
  MedCPT weights, sqlite-vec, SQLite FTS5, ONNX Runtime, UniFFI, tough,
  ASReview, statsmodels, llama.cpp, OpenMed span/grounding slices.
- **Benchmarks/oracles only:** SciFact, MultiVerS, Evidence Inference, PICOX,
  RRnlp (GPL-2.0 weights), RobotReviewer (GPL-3.0), SYNERGY, BEIR, metafor.
- **Justified original engineering:** Study/Report/Overlap model,
  applicability gate, claim-support policy and AnswerProofManifest, GRADE
  assembly, PICO orchestration, validity overlay, clinician UX, bilingual
  presentation, SafeEvidenceBench task design (`SOURCE_TRANSPLANT_MATRIX_V1.md` §5).

## 4. Reconciliation of conflicts found in the 2026-10-19 audit

Each item is resolved here and reflected in the companion artifacts; the
older documents are amended by pointer, not silently rewritten.

| # | Conflict / outdated assumption | Evidence | Resolution |
|---|---|---|---|
| C1 | `TheHalfMoon/MESC` named as donor | GitHub redirects to `TheHalfMoon/MedOrigin` | Use MedOrigin @ `ec8b1b6f…`; Python package still named `medscale` → renamed on copy |
| C2 | `SOURCE_LEDGER.md` calls DAL, ottari, kernux, Morize, Inercative, Signthos, Wispral public | All private at 2026-10-19 | Visibility recorded per packet; identities were already public; founder may redact path pins |
| C3 | PICOX listed `COPY_BOUNDED` | Repo contains notebooks + corpus zip only | `BENCHMARK` |
| C4 | RRnlp listed `COPY_BOUNDED` | Weights are Zenodo "RobotReviewer v2 models", GPL-2.0; minimap pickles are UMLS-derived | `BENCHMARK_ONLY`; no distribution |
| C5 | docling.rs listed as `DEPEND` default | Default features enable URL/image/YouTube/remote-VLM fetch | Challenger only, `--no-default-features --features pdf` |
| C6 | fastembed-rs `DEPEND` | Default features download ORT binaries and use hf-hub | `default-features = false`; models from Packs only |
| C7 | "MedScale lexical retrieval baseline" | `retrieval.rs` is a 142-line token-overlap scorer | Oracle only; FTS5 is the baseline |
| C8 | "Copy MedScale pack admission/runtime" | `medscale-pack` is 26 kLoC incl. candle/gliner/HF runtimes | Copy `format/store/runtime/pack_runtime` slice only (T07) |
| C9 | OpenMed pinned at v2.2.0 / `252806aa…` | Live head `8440bdac…`, release v3.0.0 (2026-10-07) | Re-pin T17 to v3 head; restricted vocab loaders excluded |
| C10 | `COPY_FIRST_SOURCE_PLAN.md` §4 still lists MedScale "encrypted vault primitives / sealed blob" as copy targets | P00 forbids MedScale whole-file vault | T03 (ottari) is the vault; MedScale vault files excluded |
| C11 | es3 `COPY_BOUNDED` | Flask/Celery/Postgres web app | `REFERENCE`; linkage logic re-expressed in T15 |
| C12 | P11 shell `OPEN_TOURNAMENT` | MedScale ships a hardened Tauri 2 shell with tests (T36) | Tauri incumbent with Slint exit test (D-08) |
| C13 | `RUNTIME_BUDGET.md`: no invented targets; mission requires budgets | — | Provisional ceilings as gates, frozen by WP-M0 measurement (D-15) |
| C14 | "No Python daemon fleet" vs copy-first Python donors | — | One on-demand, sandboxed, network-less research worker (D-03) |
| C15 | MedScale ONNX path uses `tract`; Xberg/fastembed use `ort` | crate manifests | ORT primary, tract fallback only (D-01) |
| C16 | SafeEvidence toolchain 1.97.1 | ottari `himsat-core` declares `rust-version = 1.98.1` | WP-01 bumps toolchain via reviewed G01a re-pin before T03 import |
| C17 | MedScale rusqlite 0.37 vs ottari 0.40.1 | manifests | Adopt ottari's pinned SQLCipher stack (vault owner) |
| C18 | Signthos "AGPL public tree" | No license file at head; private | `REFERENCE_ONLY_PENDING_RIGHTS` unchanged |
| C19 | trialstreamer "founder asserts permission" | No license file | Unchanged: reference only until grant reference is recorded |
| C20 | Consensus-style vote meters and "Strong" labels considered as UX | Observed population mismatch and overlapping-review double counting (R-CO-2) | Rejected; categorical outcome with reasons (L5) |
| C21 | Independent review F1–F21 (2026-10-19) | `docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md` | All P1/P2 items fixed in this baseline (fix log in that report); F7 disclosure is founder decision EXT-08 |

## 5. Phase map (program phase → work packets → milestone)

| Milestone | Contents | Packets | Done when |
|---|---|---|---|
| M0 Admission | First rights rows, SBOM/notice tooling, synthetic scope extension signed | WP-00, WP-01 | TA-01..TA-03 pass; signed rows exist |
| M1 VS-1 (synthetic) | Ask vertical slice on synthetic corpus | WP-02, WP-03*, WP-04*, WP-06*, WP-07 (BM25), WP-08*, WP-09, WP-11a, WP-12 (template), WP-18a, WP-23a | VS-1 criteria in work-packet file |
| M2 Evidence V1 | Live acquisition (rights-admitted subset), dense retrieval tournament, appraisal, dedup, documents/OCR, measurement | WP-04, WP-05, WP-07, WP-10, WP-11, WP-13, WP-M0 | TA-05..TA-15, TA-29, TA-30, TA-M0; live fetch stays disabled (fixture transport only) until TA-29 and TA-30 pass |
| M3 Deep Review | Screening, PRISMA, extraction, meta-analysis, living alerts, exports | WP-14..WP-17 | TA-16..TA-19 |
| M4 Desktop V1 engineering | Full workstation, bilingual UX, security qualification, benchmark | WP-18, WP-19, WP-20, WP-23 | TA-20..TA-23, TA-26, TA-27, TA-29, TA-30 (re-run on the full product) |
| M5 Mobile | iOS/Android foundation, Ask/Scan | WP-22 | TA-25 |
| M6 Release candidate | Signed offline installer, TUF pack updates | WP-24 | TA-28 + GATE_TRUST |
| External | Clinical evaluation (Issue #4), patient context (WP-21), real-PHI readiness | — | owned outside engineering |

`*` = VS-1 subset of that packet.

## 6. Implementation execution order

Strictly dependency-ordered; parallel lanes allowed only where no file
overlaps. Each step is one bounded PR series; each cites its admission IDs.

1. **WP-00** rights rows + SBOM/notice tooling → **WP-01** workspace/CI/toolchain bump (C16, C17), docs-worker workspace, TA-29.
2. **WP-02** contracts (T01 copy + P00 study/proof types) ∥ **WP-23a** sandbox launcher spike.
3. Lane A: **WP-03** vault (T03). Lane B: **WP-06** text/RTL (T17). Lane C: **WP-18a** shell skeleton (T36) with mocked core.
4. **WP-04** (fixture-import path only) → **WP-07** BM25 + funnel.
5. **WP-08** deterministic checks (VS-1a) → **WP-09** applicability.
6. **WP-11a** assurance subset (T13 port) → **WP-12** template brief + AnswerProofManifest → wire **WP-18a** Ask view.
7. **VS-1 integration** → **M1 exit review** (Codex + Opus + OCR review per `GAP_REVIEW.md`).
8. **WP-04** live acquisition via broker with D-16 query preview (rights-admitted subset; enabled only after TA-29 and TA-30 pass) ∥ **WP-05** dedup/overlap ∥ **WP-13** documents/OCR.
9. **WP-08** NLI model (VS-1b, after EXT-07) → **WP-07** dense tournament (MedCPT/fastembed/sqlite-vec) → **WP-10** appraisal/GRADE → **WP-11** full assurance (T14 metrics) → **WP-M0** measurement (freeze budgets).
10. **WP-14** screening/PRISMA → **WP-15** extraction → **WP-16** meta-analysis → **WP-17** living alerts (per-query opt-in).
11. **WP-12** generator tournament (D-06, sandboxed worker) ∥ **WP-18** full workstation ∥ **WP-19** bilingual/a11y ∥ **WP-20** benchmark.
12. **WP-23** security/privacy qualification → **M4 exit review**.
13. **WP-22** mobile → **WP-24** release (Windows first, then macOS/Linux, then mobile stores).

## 7. Source provenance and licensing controls

1. No byte enters the tree without a `VERIFIED_ALLOWED` row (unchanged).
2. Every copy PR: cites admission ID, donor repo, commit, each file's blob OID
   from the pins JSON, and records modifications in a per-directory `PROVENANCE.md`.
3. `THIRD_PARTY_NOTICES.md` updated in the same PR; CI (TA-02) fails otherwise.
4. Dependency changes re-admitted (cargo-deny license allowlist: Apache-2.0,
   MIT, BSD-2/3, ISC, Zlib, Unicode-3.0, MPL-2.0 file-level; GPL/AGPL denied in
   distributed artifacts).
5. Model weights, datasets, terminology and fonts get their own rows; Packs
   refuse items without rights state.
6. Donor updates: quarterly re-pin review per packet; security advisories
   trigger immediate review; every re-pin re-runs the packet's TA rows.

## 8. Release packaging and deployment

- Desktop: Tauri bundler; Windows NSIS current-user installer first (MedScale
  config pattern), macOS signed/notarized DMG, Linux AppImage/deb. Offline
  installer bundles core + research worker; Packs installed separately.
- Updates: TUF metadata (tough) for app and Packs; anti-rollback epochs;
  offline USB/side-load supported; no auto-update without consent.
- Mobile: App Store / Play distribution after M5; packs selected per device.
- No SafeEvidence-hosted service is required; optional institutional pack
  mirrors are static files.
- Zero founder-funded runtime cost: all inference/search runs on the user's device.

## 9. Gates that engineering cannot close

Listed with owners and evidence in `docs/PLAN_FREEZE.md` §5. Summary: rights
rows (Issue #5), synthetic-scope extension beyond stdlib-only G01a (founder
signature), intended-use & clinical evaluation charter (Issue #4), phase
owners for the 41 P1 findings (Issue #3), key custody/release trust (Issue #5),
G01a independent review (Issue #17), authenticated REA follow-ups (optional).

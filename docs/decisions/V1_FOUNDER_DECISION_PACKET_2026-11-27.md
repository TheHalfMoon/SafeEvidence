# SafeEvidence V1 External Founder and Expert Decision Packet

Date: `2026-11-27`
Evaluated `main` baseline: `69fea4c32eaa1384e5305e425fa1076e4b630d94`
Companion technical & rights dossier: [V1_GATE_AND_ADMISSION_AUDIT_2026-11-27.md](../handoff/V1_GATE_AND_ADMISSION_AUDIT_2026-11-27.md)

---

## Purpose and Governance Boundary

Autonomous engineering has completed all M0-M4 synthetic baseline PRs (`#91`-#`95` merged on `main` @ `69fea4c3`) and is executing all remaining `EXT-02` / D2-authorized engineering tasks. Under `AGENTS.md` and `docs/PLAN_FREEZE.md`, autonomous engineering **cannot** invent founder source-rights grants, disclose private-repository paths, sign clinical charters, hold production TUF/code-signing keys, or substitute an AI review for an independent human expert review.

This packet consolidates the exact external decisions required across **Issue #5**, **Issue #3**, **Issue #4**, **Issue #17**, and **PR #43** (`D5` through `D12`, continuing the numbering from `docs/decisions/M0_FOUNDER_DECISION_PACKET_2026-11-05.md` `D1`-`D4`).

---

## 1. Issue #5 — Unresolved Source/Model Rights and Release Trust (`EXT-01`, `EXT-05`, `EXT-07`, `EXT-08`)

Tracking issue: [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5)
Prior signed baseline: [D2 & D4 (`issuecomment-6647500204`)](https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204) authorized `T01`, `T03`, `T11`, `T12`, `T13`, `T17` (public-license route), `T30`, `T36`, and crate lockfile closures (`ADM-0001`..`ADM-0012`).

### Decision D5 — Founder-Owned Public-Repository Slice Admissions (`T05`, `T07`, `T09`, `T10`, `T15`, `T16`)
- **Pinned slices verified byte-for-byte on GitHub (`ADM-0015`..`ADM-0020`):**
  - `T05` (`AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `8` files, `52,284` B, `Apache-2.0`) — network broker (`safeevidence-network`).
  - `T07` (`AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `6` files, `33,171` B, `Apache-2.0`; `pack_runtime.rs` excluded per F8) — pack manifest/store (`safeevidence-pack`).
  - `T09` (`AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `7` files, `51,418` B, `Apache-2.0`) — FHIR R4 lexical gate & extractors (`safeevidence-fhir`; clinical use still gated on Issue #4 `EXT-03`).
  - `T10` (`AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `18` files, `115,612` B, `Apache-2.0`) — OS sandbox plans/probes (`safeevidence-sandbox`).
  - `T15` (`TheHalfMoon/MedOrigin` @ `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8`, `38` files, `197,171` B, `Apache-2.0`) — Python stdlib `litdb` acquisition, dedupe, screening, and PRISMA log.
  - `T16` (`AbdulazizShehri/safeOCR` @ `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4`, `9` files, `103,411` B, `Apache-2.0`; `ocr.py` excluded per F11) — critical-value verification.
- **Options:**
  - **Option D5-A (Approve all 6 slices):** Confirm sole founder ownership/authority over `T05`, `T07`, `T09`, `T10`, `T15`, and `T16` at the pinned commits and authorize flipping `ADM-0015`..`ADM-0020` to `VERIFIED_ALLOWED` (`FOUNDER_OWNED`, `Apache-2.0`), while keeping `T09` patient-care runtime disabled until Issue #4 (`EXT-03`) closes.
  - **Option D5-B (Approve subset):** Specify exact packet IDs approved now and hold the rest as `CANDIDATE`.
  - **Option D5-C (Hold):** Keep `ADM-0015`..`ADM-0020` at `CANDIDATE` (`copy_authorized = false`).
- **Required evidence:** Signed founder comment on [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5) citing `D5-A` (or subset).
- **Consequences & unlocked work:** Unlocks `WP-23a` (`T10` OS worker sandbox spike), `WP-04` (`T05` network broker + `T07` pack store + `T15` `litdb` replay), `TA-21` OS firewall/broker egress qualification, `WP-05` (`T15` fuzzy dedupe), `WP-14` (`T15` PRISMA replay), `WP-13` (`T16` critical-value verification), and `T09` synthetic contract tests.

### Decision D6 — Private Repository `T14` (`TheHalfMoon/DAL`) Ownership & Public Path/Code Publication (`EXT-01` + `EXT-08`)
- **Pinned slice (paths withheld per `EXT-08`):** `TheHalfMoon/DAL` @ `e460e766566d233c79b1270d6e425cb2005d9514` (`private: true`, `Apache-2.0`, `5` files, `64,525` B, SHA-256 path commitment `52150bf16545f246865a5505410899aad48102b380f836b7a2882fbe80851d49`, sole author `TheHalfMoon` / `Abdulaziz`).
- **Options:**
  - **Option D6-A (Approve `T14` ownership + D4-style public publication):** Confirm founder ownership of `TheHalfMoon/DAL` @ `e460e766566d233c79b1270d6e425cb2005d9514` and explicitly authorize publishing those 5 files (and their paths in `source_admissions.json`) under `Apache-2.0` in public `SafeEvidence` (matching D4 for `ottari` `T03`/`T30`).
  - **Option D6-B (Keep `DAL` private; authorize clean-room mathematical implementation):** Keep `TheHalfMoon/DAL` uncopied and unpublished, and amend `SOURCE_TRANSPLANT_MATRIX_V1.md` (`plan-v1.7`) to authorize a clean-room implementation of standard published calibration/selective-risk formulas (Brier, ECE, NLL, AURC).
  - **Option D6-C (Hold):** Keep `T14` uncopied and paths unpublished.
- **Required evidence:** Signed founder comment on [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5).
- **Consequences & unlocked work:** Unlocks full `WP-11` (`TA-13` calibration & selective-risk parity vectors to `1e-12`) and `WP-20` (`SafeEvidenceBench` AURC/ECE reporting). (`T06` `kernux` and `T32` `Morize` remain `REFERENCE_ONLY` with paths withheld.)

### Decision D7 — External Public-License Worker, Crate, Benchmark, and Copyleft Boundary (`EXT-01`)
- **Options:**
  - **Option D7-A (Approve permissive slices with explicit asset boundaries; enforce copyleft/no-license denials):**
    1. Approve `PUBLIC_LICENSE` code admission (subject to `WP-23a` sandbox + hash-locked dependency closure) for: `T18` (`asreview`, `Apache-2.0`), `T19` (`statsmodels`, `BSD-3-Clause`), `T20` (`xberg` `pdf-native` only, `MIT`, in separate `safeevidence-docs` workspace), and `T24` (`uniffi`, `MPL-2.0`, unmodified crate at M5).
    2. Approve benchmark-only admission (`bench/`, never shipped in desktop/mobile binaries) for `T27` (`allenai/scifact`: code `Apache-2.0`, claims `CC-BY-4.0`, abstracts `ODC-By-1.0` with mandatory attribution) and `T28` (`jayded/evidence-inference`: code `MIT`, filtered strictly to permissive `CC-BY`/`CC0` PMC OA articles).
    3. Ratify permanent in-tree **denial** (`DENIED` / `RIGHTS_UNKNOWN`, zero bytes copied or distributed) for `T34` (`ijmarshall/robotreviewer`, `GPL-3.0-only`), `T28b` Zenodo weights (`GPL-2.0`) & UMLS `minimap`, and `T35` (`ijmarshall/trialstreamer`, no license file) unless a separate written rightsholder grant is later filed.
  - **Option D7-B (Modify scope / hold):** Specify per-packet overrides on Issue #5.
- **Required evidence:** Signed founder comment on [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5).
- **Consequences & unlocked work:** Unlocks `WP-14` (`TA-16` ASReview WSS@95), `WP-16` (`TA-18` `statsmodels` meta-analysis), `WP-13` native PDF extraction (`T20` `pdf-native`), `TA-10` SciFact evaluation (`T27`), and `TA-17` Evidence Inference evaluation (`T28`).

### Decision D8 — Model-Card & Weight Redistribution Clearance (`EXT-07`)
- **Affected items:** `T23` (`ncbi/MedCPT` HF weights declare `license: other`), `T29` (`PaddleOCR` printed EN + AR ONNX weights), `WP-08` NLI cross-encoder ONNX model, `WP-12` optional local LLM generator (`llama.cpp` GGUF), plus model-bearing crates `ort` and `fastembed` (`T21`).
- **Options:**
  - **Option D8-A (Admit only Apache-2.0 / MIT-licensed ONNX/GGUF weights first):** Select and record exact SHA-256 digests + model-card URLs on Issue #5 for models carrying explicit `Apache-2.0` or `MIT` model-card licenses (e.g., `PaddleOCR` Apache-2.0 ONNX models and an Apache-2.0/MIT biomedical embedding/NLI model), while holding `T23` `MedCPT` (`license: other`) and `T27b` `MultiVerS` (`RIGHTS_UNKNOWN`) until rightsholder clarification.
  - **Option D8-B (Obtain/record NCBI `MedCPT` clarification):** Record documentary evidence confirming US-Gov public-domain / permissive redistribution of `MedCPT` Query/Article/Cross weights before admitting `T23`.
  - **Option D8-C (Hold all model weights):** Keep SafeEvidence 100% deterministic/lexical (`FTS5` + template brief + deterministic verifiers) until model-card review completes.
- **Required evidence:** Per-model row on [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5) naming model card URL, exact weight SHA-256, license SPDX, and training/redistribution restrictions.
- **Consequences & unlocked work:** Unlocks `ort` + `fastembed` (`T21`), `sqlite-vec` (`T22`), OCR recognition (`T20` `xberg-paddle-ocr` + `T29`), VS-1b NLI claim verification (`WP-08`), and optional local synthesis (`WP-12`).

### Decision D9 — Release Signing Keys, TUF Ceremony, and Installer Bundling (`EXT-05`)
- **Affected items:** `WP-24` (`TA-28`), `T25` (`awslabs/tough`), and `tauri.conf.json` (`bundle.active`).
- **Options:**
  - **Option D9-A (Establish offline root + targets TUF ceremony & OS signing identity):** Name the human key-custody owner on Issue #5, generate offline hardware-backed TUF Root/Targets/Snapshot/Timestamp public keys (committing only public root metadata `root.json`), and provision Windows Authenticode / macOS Developer ID signing in release CI.
  - **Option D9-B (Defer release signing until clinical & human security gates close):** Keep `bundle.active = false`, `RELEASE_QUALIFIED = FALSE`, and zero GitHub Releases while qualifying unsigned offline staging artifacts in CI.
- **Required evidence:** Signed custody record on [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5) + committed public TUF `1.root.json` (never private keys).
- **Consequences & unlocked work:** Unlocks `T25` `tough` pack update/rollback verification, `bundle.active = true` signed Windows/macOS/Linux installers, and `WP-24` (`TA-28`) M6 release candidate qualification.

---

## 2. Issue #3 — Accountable Phase Owners and P01 Entry Authorization (`EXT-04`)

Tracking issue: [Issue #3](https://github.com/TheHalfMoon/SafeEvidence/issues/3)

### Decision D10 — Assign Named Human Owners in `docs/P01_P1_GATE_TRACKER_2026-10-08.md`
- **Current engineering readiness:** `tools/governance/p01_preentry_check.py` (updated in PR #91) already validates issue-comment-bound owner rows of the exact form `ASSIGNED — @<github-handle> (https://github.com/TheHalfMoon/SafeEvidence/issues/3#issuecomment-<id>)` while keeping `p01_g01_activation = "BLOCKED"` until Issues #4 and #5 also close.
- **Options:**
  - **Option D10-A (Single-founder phase ownership where qualified + open clinical/security roles held honest):** Post a signed comment on [Issue #3](https://github.com/TheHalfMoon/SafeEvidence/issues/3) assigning `@TheHalfMoon` to engineering/architecture/product phases (`P01`-`P12`, `P15`-`P22` engineering ownership) while keeping clinical evaluation (`Issue #4`) and independent security review (`Issue #17`) explicitly `UNASSIGNED` until named human specialists accept them.
  - **Option D10-B (Full roster assignment):** Post signed comments on Issue #3 naming `@TheHalfMoon` plus the clinical lead and independent security reviewer handles once retained.
- **Required evidence:** Authenticated comment(s) on [Issue #3](https://github.com/TheHalfMoon/SafeEvidence/issues/3) from the assigned GitHub account(s).
- **Consequences & unlocked work:** Transitions engineering phase rows in `P01_P1_GATE_TRACKER_2026-10-08.md` from `UNASSIGNED` to `ASSIGNED` with cryptographic issue-comment binding.

---

## 3. Issue #4 — Clinical Intended-Use and Evaluation Charter (`EXT-03`, `EXT-09`)

Tracking issue: [Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4)

### Decision D11 — Sign Clinical Intended-Use Wedge, Adjudicator Protocol, and Regulatory Boundary
- **Options:**
  - **Option D11-A (Research & Literature Assurance Workstation Charter First — Non-Patient-Specific):** Sign a bounded V1 charter defining SafeEvidence V1 strictly as a **literature-level clinical evidence & systematic-review assurance workstation** (no patient-record ingestion, `WP-21` FHIR patient context disabled in V1, mandatory clinician adjudicator panel & pre-registered holdout thresholds for `TA-10` clinical holdout).
  - **Option D11-B (Full Clinical Decision-Support & Patient-Context Charter):** Sign a full clinical intended-use charter with a qualified clinical lead, regulatory/SaMD jurisdiction determination, PHI governance, and blinded multi-clinician adjudication protocol enabling both `TA-10` clinical holdouts and `WP-21` (`TA-24`) FHIR patient context.
  - **Option D11-C (Hold clinical charter during engineering phase):** Keep `CLINICALLY_EVALUATED = FALSE` and `CLINICAL_USE_AUTHORIZED = FALSE` across all builds.
- **Required evidence:** Signed charter document committed under `docs/clinical/` and referenced in an authenticated comment on [Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4) by the accountable clinical/founder owners.
- **Consequences & unlocked work:** Unlocks clinician-adjudicated holdout creation (`WP-08` `TA-10` clinical clause, `WP-20` `SafeEvidenceBench` clinical split) and — under Option D11-B — `WP-21` (`TA-24`) FHIR patient context.

---

## 4. Issue #17 and PR #43 — Independent Human Technical/Security Review & Security Policy (`EXT-06`)

Tracking items: [Issue #17](https://github.com/TheHalfMoon/SafeEvidence/issues/17) and [PR #43](https://github.com/TheHalfMoon/SafeEvidence/pull/43)

### Decision D12 — Independent Expert Review and `SECURITY.md` (`PR #43`) Merge Gate
- **Non-negotiable rule:** AI exit reviews (`docs/reviews/M0_M1_EXIT_REVIEW_2026-11-26.md` and per-PR independent subagent audits) are internal engineering quality gates only and **never** satisfy `EXT-06` or `PR #43`'s human review requirement.
- **Scope prepared for the human reviewer:**
  1. Root stdlib-only G01a reproducibility package (`crates/g01a-synthetic`, `g01a_synthetic_check.py`).
  2. `safeevidence-vault` (`SAFEVD/` domain separation, SQLCipher `4.14.0` + OpenSSL `3.6.3`, `RUSTSEC-2026-0459` WAL guard, OS protectors, recovery/backup flows) and `safeevidence-proofstore` (`plan-v1.3` append-only triggers, span bounds, `CommitUnknown` reconciliation).
  3. Desktop Tauri 2 security boundary (`CSP`, `capabilities/default.json`, navigation deny-all, Linux keyring helper isolation, Windows/Linux socket captures).
  4. Open [PR #43](https://github.com/TheHalfMoon/SafeEvidence/pull/43) (`SECURITY.md` coordinated vulnerability disclosure mailbox, response SLA, and PGP/advisory process).
- **Options:**
  - **Option D12-A (External independent security/Rust reviewer):** Retain an independent human engineer (distinct from the author/founder and not an AI agent) to audit `main` + `PR #43`, post a signed review on [Issue #17](https://github.com/TheHalfMoon/SafeEvidence/issues/17) and an authenticated GitHub `APPROVE` review on [PR #43](https://github.com/TheHalfMoon/SafeEvidence/pull/43), rebase `PR #43` onto `main`, pass exact-head CI, and merge `PR #43`.
  - **Option D12-B (Staged review — `PR #43` policy check first, full `EXT-06` code audit at M6):** Have a qualified human reviewer verify the `SECURITY.md` contact channel live and approve `PR #43` now, keeping `EXT-06` (`SECURITY_REVIEW_COMPLETE = FALSE`) open until all `D5`-`D8` donor/worker slices are integrated for a single comprehensive pre-release security audit.
- **Required evidence:** Authenticated human GitHub PR review on `PR #43` + signed human assessment report linked on `Issue #17`.
- **Consequences & unlocked work:** Merges `SECURITY.md` (`PR #43`) cleanly and, upon full audit completion, transitions `SECURITY_REVIEW_COMPLETE` from `FALSE` to `TRUE` for the audited SHA.

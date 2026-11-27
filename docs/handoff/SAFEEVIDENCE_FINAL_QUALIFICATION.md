# SafeEvidence Final Engineering Qualification Dossier

Status: `V1_RESEARCH_COMPLETION_ACTIVE` (`plan-v1.7` Founder Directive Enacted; 7-Axis Qualification Model)
Date: `2026-11-27`
Repository: `https://github.com/TheHalfMoon/SafeEvidence` (`Apache-2.0` for SafeEvidence-owned code)
Canonical branch: `main`
Recovered baseline SHA: `5ccecd7688f1d10fa8474a697d6b6670d8eafec8` (`2026-11-09`)
Verified `main` SHA: `ccbea102f8fb159da26372d176c41173f5b7351a` (`2026-11-27`, PR #98 merged; 7/7 post-merge workflows `success`), extended by PR #99 (`safeevidence/plan-v1-7-founder-directive-20261127`)
Authorized development workstation: Windows 11 PC (`C:\Users\Shehr\.gemini\antigravity\scratch\SafeEvidence`) under explicit user override (`"use this pc , dont use mac"`), paired with hosted Ubuntu, Windows, and macOS GitHub Actions checks.

---

## 1. Executive Qualification Statement

Under the 2026-11-27 Founder Directive (`docs/plan/PLAN_AMENDMENT_V1_7.md`, `ADR-0001`..`ADR-0004`), SafeEvidence V1 is governed as a **zero-cost, local-first Research and Evidence-Analysis Workstation (`RESEARCH_WORKSTATION_NON_CLINICAL_V1`)**:
1. **Permanent Removal of `DAL` (`ADR-0001`):** Private `TheHalfMoon/DAL` (`T14`, `D6`) is permanently deleted from V1 plans and pins (`39 -> 38` packets in `source_transplant_pins_2026-10-19.json`), banned fail-closed in `source_admission_check.py`, and replaced by clean-room Rust calibration, `ECE`/`MCE`, tie-exact `AURC`/`E-AURC`, Wilson/cluster-bootstrap CIs, and `P00` assurance metrics (`safeevidence-assurance/src/eval_metrics.rs`, verified to `1e-12` analytical precision).
2. **Independent AI-Assisted Security Qualification (`ADR-0002`):** Mandatory internal human review (`EXT-06`, `D12`) is superseded by multi-agent independent review (`Google EGM` Goldfish, Alibaba `ocr delegate`, PStack `/ps-review`, `jev`), 6 structure-aware deterministic property/fuzz suites, static/supply-chain/adversarial/E2E gates, and exact-head verification, while truthfully preserving `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`.
3. **V1 Research Scope & Automated Scientific Evaluation (`ADR-0003`):** V1 research qualification uses automated reproducible `SafeEvidenceBench` (`8/8` splits `PASS`, `30f3f081ec3348fde765954d73da26b1c5312e70121b03dbb779d0d9bbe49056`), while patient-specific CDS (`WP-21`), PHI, clinical validation (`ACTUAL_CLINICAL_VALIDATION = FALSE`), and medical-device claims (`ACTUAL_REGULATORY_AUTHORIZATION = FALSE`) remain strictly outside V1 scope.

---

## 2. Seven-Axis V1 Qualification Status (`plan-v1.7`)

| Qualification Axis | Status | Governing Authority & Boundary |
|---|---|---|
| `COMPLETED_ENGINEERING` | `IN_PROGRESS_FINAL_V1_WAVES` | PRs `#91`–`#98` merged (`ccbea102`); PR #99 completes `plan-v1.7`, clean-room `WP-11` (`TA-13`), 8-split `SafeEvidenceBench`, 5 `egm-design` security fixes, `ResearchReleaseManifest`, and 6 property/fuzz suites; Wave 2 (`PR #43`) & Wave 3 (`PR #100`) follow immediately |
| `INDEPENDENTLY_VERIFIED_ENGINEERING` | `VERIFIED_THROUGH_PR_98` (+ PR #99 review panel) | Multi-agent independent reviews + `15/15` PR checks + `7/7` post-merge `main` workflows (`ccbea102`) |
| `AI_ASSISTED_SECURITY_QUALIFICATION` | `ACTIVE` (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`) | `docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md` (`ADR-0002`) |
| `AUTOMATED_SCIENTIFIC_EVALUATION` | `ACTIVE` (`8/8` splits `PASS`, `30f3f081...`) | `docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md` (`ADR-0003`) |
| `RESEARCH_RELEASE_QUALIFICATION` | `STAGING_AND_7AXIS_VERIFIER_ACTIVE` (`OS_CA_CODE_SIGNED = FALSE`) | `safeevidence-release/src/staging.rs` (`UnsignedStagingManifest` + `ResearchReleaseManifest`; `ADR-0003`, `ADR-0004`) |
| `ACTUAL_CLINICAL_VALIDATION` | `FALSE` | Out of V1 research scope (`EXT-03` -- [Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4)) |
| `ACTUAL_REGULATORY_AUTHORIZATION` | `FALSE` | Out of V1 research scope (`EXT-09` -- non-clinical research workstation only) |

---

## 3. Integrated Pull Request Lineage (`5ccecd7` -> `main`)

| PR | Title / Engineering Deliverables | Head SHA | Merge SHA | Hosted CI |
|---|---|---|---|---|
| [#91](https://github.com/TheHalfMoon/SafeEvidence/pull/91) | **M0 Admission, SBOM & SQLCipher WAL Guard:** `ADM-0010`..`ADM-0012` 3-lockfile closure checks (`product/Cargo.lock`, `src-tauri/Cargo.lock`, `package-lock.json`), `613`-component CycloneDX 1.5 SBOM (`TA-02`), `RUSTSEC-2026-0459` pre-open `-wal` page-size guard, `T01` proposal/confidence gates (`TA-04`), `T30` `tool_audit.py` expansion, `p01_preentry_check.py` issue-bound `ASSIGNED` support, `ANTIGRAVITY_RECOVERY.md` | `37e757b84f812b698cbc030b53384a792df7ac5b` | `e08684d824cf20cd737dc0353cc0860582991ce7` | `15/15 PASS` |
| [#92](https://github.com/TheHalfMoon/SafeEvidence/pull/92) | **M0 Vault Cryptographic Domain Separation & Durability:** 24-constant `HIMSAT/` -> `SAFEVD/` (`VAULT_DOMAIN_VERSION = "SAFEVD-v1"`) separation with independent Python-oracle vectors & cross-product negative tests (`domain_separation.rs`), desktop store-key isolation, `open_existing` 8-point kill/contention/snapshot-restore durability (`TA-05` subset) | `3fa3ffc26cee77154d541370a6a54ca08946a30f` | `82df2cdf398a5b1bda52dd5119c5249fd72df796` | `15/15 PASS` |
| [#93](https://github.com/TheHalfMoon/SafeEvidence/pull/93) | **M1 VS-1a Ask Lineage, Proof Reconciliation & Exit Reviews:** `plan-v1.3` `ClinicalAssertion` storage & `AmendmentRecord` lineage, superseding-free `retract_source`, `EvidenceSpan` UTF-8 scalar & SHA-256 verification, `ANSWER` vs `ANSWER_WITH_CAUTION`, `plan-v1.6` per-population `ASK_MORE`, `ESCALATE` ahead of non-ASCII names, manifest-verified `CommitUnknown` reconciliation, typed UI exclusion codes, `17/17` Win WebView2 & `16/16` Linux WebKitGTK E2E, `M0_M1_EXIT_REVIEW_2026-11-26.md` | `45921e7a57a102ecf049fff03ddad263c8e67a07` | `bd22f0abf3df19bddf137b6ba472d6fa46c10ecf` | `15/15 PASS` |
| [#94](https://github.com/TheHalfMoon/SafeEvidence/pull/94) | **M2 Evidence V1 Greenfield Subsystems:** `study_linkage.rs` (`T28c` REFERENCE registry/PMID/review containment, `TA-07`), `appraisal.rs` (`RoB 2`, `ROBINS-I`, `QUADAS-2`, `AMSTAR 2`, `GRADE`, `EBMonFHIR`, `TA-12`), `bilingual.rs` + `bilingual_ask.rs` (`TA-08`), `overlay.rs` + `surveillance.rs` (`TA-06`, `TA-19`, local `TA-30`), `bench/ta09_hard/` (`329` docs, `58` queries, `TA-09`), `perturbation.rs` (`25/25` perturbations + PICO mismatch, `TA-10`/`TA-11`) | `457d60e40436648be0ea6f9a9631827a2d9231e9` | `55ce7276c6460b63c358b7620546549e8dfb1e92` | `15/15 PASS` |
| [#95](https://github.com/TheHalfMoon/SafeEvidence/pull/95) | **M3/M4 Protocol Extraction, Multi-Pane Bilingual Workstation, SafeEvidenceBench & TA-M0 Baseline:** `review_protocol.rs` (`WP-14`/`WP-15`, `TA-17`), multi-pane `EN`/`AR` + `RTL` + WCAG 2.1 AA desktop workstation (`WP-18`/`WP-19`, `19/19` Win WebView2 E2E & `18/18` hosted Linux WebKitGTK E2E `PASS`), `SafeEvidenceBench` (`WP-20`, `TA-23`), `RUNTIME_BUDGET_BASELINE_2026-11-26.md` (`WP-M0`, `TA-M0`), final qualification dossier | `66224e134c6d02ec6594c680bb542d7c8092d290` | `69fea4c32eaa1384e5305e425fa1076e4b630d94` | `15/15 PASS` (+ `7/7` post-merge) |
| [#96](https://github.com/TheHalfMoon/SafeEvidence/pull/96) | **V1 Gate Audit, 39-Packet Pin Verification & Candidate Admissions:** line-by-line V1 gate audit (`V1_GATE_AND_ADMISSION_AUDIT_2026-11-27.md`), non-authorizing candidate rows `ADM-0013`..`ADM-0041` (`copy_authorized = false`, `EXT-08` private-repo tripwire), `ADM-0004` `T17` D2 span-logic/test slice binding, and `V1_FOUNDER_DECISION_PACKET_2026-11-27.md` | `212e097aa645175321a16767bacfa16989173c10` | `12d9d583b472afdf609e85d3899e879d17602e5a` | `15/15 PASS` (+ `7/7` post-merge) |
| [#97](https://github.com/TheHalfMoon/SafeEvidence/pull/97) | **T17 Span Audit/Projection, T12 Privacy/Hostile-MIME, TA-05 Disk-Full & Key-Loss/Backup Recovery:** `ADM-0004` `span_audit.rs` + `offset_projection.rs`, `document_intake.rs` + `ADM-0007` `privacy_probes_032` / `vault_privacy_023` / `hostile_mime_010`, `PRAGMA max_page_count` disk-full rollback + `verify_record_semantics_doctor()` + `SAFEVD/RECOVERY/ENVELOPE/v1` Argon2id key-loss recovery + B505 portable backup restore, bilingual desktop integration | `962b2e9518ed4ec911748a49f884a76b7000675b` | `caab864ee2ea0520f922c4646a883b38e0ac02e7` | `15/15 PASS` (+ `7/7` post-merge) |
| [#98](https://github.com/TheHalfMoon/SafeEvidence/pull/98) | **TA-27 Adversarial Injection, 7-Split SafeEvidenceBench, 5-View RTL SSR Snapshots, Clipboard/Crashpad E2E & Unsigned Staging:** `ta27_prompt_injection.rs` + `EffectMeasureSwap`, `ta27-prompt-injection` split (`TA-23`), `rtl-snapshots.test.ts` (`TA-22`), `21/21` Win & `20/20` Linux E2E (`TA-20`), `safeevidence-release/src/staging.rs` (`TA-28` prep under `EXT-05`), final ledger reconciliation | `60e462a58707a16866c90328b0526405f1c31778` | `ccbea102f8fb159da26372d176c41173f5b7351a` | `15/15 PASS` (+ `7/7` post-merge) |
| PR #99 | **`plan-v1.7` Founder Directive, Permanent DAL Removal, Clean-Room Calibration/AURC/ECE (`TA-13`), 8-Split SafeEvidenceBench & 6 Property/Fuzz Suites:** `ADR-0001`..`ADR-0004`, `PLAN_AMENDMENT_V1_7.md`, `PLAN_FREEZE.md` (`T14` deleted), `eval_metrics.rs` + `full_assurance.rs` (`1e-12` precision), `ta13-assurance-calibration` (`30f3f081...`), 5 `egm-design` fixes (`ResearchReleaseManifest`), and 6 deterministic property/fuzz suites | `(recorded on branch)` | `(recorded on main)` | `15/15` exact-head checks |

---

## 4. Complete Acceptance-Matrix (`TA-01` .. `TA-30`, `TA-M0`) Disposition

| Row | Target | Disposition | Verified Evidence / Blocking Gate |
|---|---|---|---|
| `TA-01` | Admission schema & pin integrity | `TESTED_PASSED` | `source_admission_check.py`, `p01_candidate_integrity.py`, `208` Python governance tests (`ADM-0001`..`ADM-0041`) |
| `TA-02` | CycloneDX 1.5 SBOM & notices | `TESTED_PASSED` | `safeevidence-release` (`613` components across 3 lockfiles) + `THIRD_PARTY_NOTICES.md` |
| `TA-03` | Fresh-checkout offline reproducibility | `TESTED_PASSED` (`plan-v1.2`) | `product-ci.yml` (`fmt`, `clippy -D warnings`, `test --locked`, `deny check`) on Ubuntu, Windows, macOS |
| `TA-04` | Canonical contracts, no coercion, spans, study independence | `TESTED_PASSED` (`plan-v1.3` + `ADM-0004` `T17`) | `safeevidence-contracts` (`span_audit.rs`, `offset_projection.rs`, `t17_span_audit_parity.rs`) + `safeevidence-proofstore` vault immutability/lineage + `verify_record_semantics_doctor()` |
| `TA-05` | Vault durability & plaintext residue | `TESTED_PASSED` (synthetic/engineering scope; `EXT-03` PHI open) | `domain_separation.rs`, `proof_commit.rs`, `ta05_diskfull_and_recovery.rs` (`PRAGMA max_page_count` disk-full rollback, B505 portable backup fresh-device restore), `custody.rs` (`SAFEVD/RECOVERY/ENVELOPE/v1` Argon2id key-loss recovery), `ADM-0007` `privacy_probes_032` & `vault_privacy_023` |
| `TA-06` | Corpus replay & rights filtering | `PARTIAL` (local slice `TESTED_PASSED`; `EXT-01` open) | `overlay.rs` + `ta06_ta19_validity_overlay.rs`; live `T05`/`T07`/`T15` gated on `EXT-01`/`EXT-05` |
| `TA-07` | Study-level deduplication & overlap | `PARTIAL` (`GREENFIELD_JUSTIFIED` `TESTED_PASSED`; `EXT-01` open) | `study_linkage.rs` + `ta07_study_overlap.rs` (`precision = recall = 1.0`, `0` double counts); `T15` `litdb` gated on `EXT-01` |
| `TA-08` | Arabic/English offsets & parallel recall | `PARTIAL` (synthetic slice `TESTED_PASSED`; `EXT-01`/`EXT-07` open) | `bilingual.rs` + `offset_projection.rs` + `bilingual_ask.rs` + `ta08_arabic_spans.rs` + `ta27_prompt_injection.rs` (`100%` `T17`/vocalized/tatweel round-trip, `1.00 >= 0.90` parallel `recall@20`); `T17` worker & neural encoders gated |
| `TA-09` | Retrieval baseline & funnel parity | `PARTIAL` (BM25 `TESTED_PASSED`; `EXT-01`/`EXT-07` open) | `bench/ta09/` + `bench/ta09_hard/` (`nDCG@10 = 0.4146`, `recall@50 = 0.9852`, `100%` funnel parity); dense/rerank gated on `EXT-01`/`EXT-07` |
| `TA-10` | Claim support verification | `PARTIAL` (perturbation + `EffectMeasureSwap` `TESTED_PASSED`; `EXT-01`/`EXT-03`/`EXT-07` open) | `perturbation.rs` + `ta10_ta11_verification.rs` + `ta27_prompt_injection.rs` (`25/25` perturbations + RR/AR/OR/HR/MD `EffectMeasureSwap` flagged); `T27` SciFact, `T27b` MultiVerS, and clinical holdout gated |
| `TA-11` | PICO applicability mismatch | `TESTED_PASSED` (synthetic scope) | `evaluate_pico_applicability` (`ta10_ta11_verification.rs`) + Ask typed `ReasonCode` exclusions |
| `TA-12` | Appraisal structures & EBMonFHIR | `TESTED_PASSED` (synthetic scope) | `appraisal.rs` + `ta12_appraisal_ebmonfhir.rs` (`RoB 2`, `ROBINS-I`, `QUADAS-2`, `AMSTAR 2`, `GRADE`, human actor gate, `EBMonFHIR` JSON crosswalk) |
| `TA-13` | Assurance determinism, clean-room calibration/AURC/ECE & zero UI percentage | `TESTED_PASSED` (`plan-v1.7`, `ADR-0001`) | `safeevidence-assurance` (`1,329` `T13` vectors + `17` cases + `full_assurance.rs` + clean-room `eval_metrics.rs` verified to `1e-12` analytical parity & 1,000-trial property suite in `ta13_calibration_metrics.rs`) + UI zero-percentage check; `T14` (`DAL`) permanently removed |
| `TA-14` | Atomic proof admission & fault withholding | `PARTIAL` (`VS-1a` `TESTED_PASSED`; `EXT-07` open) | `answer_faults.rs`, `proof_commit.rs`, `ask_command.rs` (`CommitUnknown` reconciliation); LLM worker kill tests gated on `EXT-07` |
| `TA-15` | Document parsing & OCR | `PARTIAL` (`ADM-0007` hostile-MIME quarantine `TESTED_PASSED`; PDF/OCR worker `BLOCKED_EXTERNAL`) | `document_intake.rs` + `hostile_mime_010.rs` quarantine binary/container/HTML/XML/PDF-active polyglots, BOM, and control bytes; PDF/OCR worker gated on `EXT-01` (`T16`, `T20`), `EXT-07` (`T29` PaddleOCR models), and `WP-23a` (`T10` sandbox) |
| `TA-16` | Screening replay & ASReview WSS@95 | `PARTIAL` (protocol audit `TESTED_PASSED`; `EXT-01` open) | `review_protocol.rs` hash-chained `ProtocolAuditBundle` (`ta17_protocol_extraction.rs`); `T15` PRISMA & `T18` `ASReview` gated on `EXT-01` |
| `TA-17` | Quote-anchored structured extraction | `PARTIAL` (gating rule `TESTED_PASSED`; `EXT-01` open) | `StructuredEffectExtraction` (`100%` quote span + verbatim estimate check + `PROPOSED` until human confirms); `T28` Evidence Inference split gated on `EXT-01` |
| `TA-18` | Meta-analysis pooling & refusal | `PARTIAL` (refusal gate `TESTED_PASSED`; `EXT-01` open) | `decide_pooling` + `decide_subset_pooling`; `T19` `statsmodels` golden numerical worker gated on `EXT-01` + `WP-23a` |
| `TA-19` | Living validity updates & alerts | `PARTIAL` (local engine `TESTED_PASSED`; `EXT-01` open) | `surveillance.rs` + `ta06_ta19_validity_overlay.rs` (single-cycle cause-named alert, unchanged historical proof bytes) |
| `TA-20` | Desktop end-to-end journey & shell checklist | `PARTIAL` (`21/21` Win E2E & `20/20` Linux E2E `TESTED_PASSED`; `T07`/`D9` open) | `e2e/ask_checks.mjs` (Ask, span jump, refusals, Evidence/Deep Review/Packs/Privacy panes, CSP, capability refusal, clipboard non-mutation, restart, post-kill `dataDir`/vault/`Crashpad` zero-residue); signed pack import (`T07`) & `D9` shipped-Linux-incognito ruling remain open |
| `TA-21` | No silent network egress | `PARTIAL` (captures active; `EXT-01` open) | Linux `strace -ff` + Windows `netstat`/port-80 0-byte captures; full `T05` OS broker firewall harness gated on `EXT-01` |
| `TA-22` | Accessibility & RTL | `PARTIAL` (WCAG AA + 5-view SSR snapshots + live RTL E2E `TESTED_PASSED`) | `accessibility-rtl.test.ts` + `rtl-snapshots.test.ts` (16 deterministic `EN`/`AR` HTML/ARIA snapshots across all 5 views) + live E2E keyboard/RTL checks; `axe-core` package remains unadmitted under zero-lockfile-churn `ADM-0012` |
| `TA-23` | `SafeEvidenceBench` reproducibility | `TESTED_PASSED` (8 synthetic V1 research splits under `ADR-0003`; external `T27` corpora optional) | `safeevidence_bench` (`ta23_safeevidence_bench.rs`, `8` splits incl. `ta27-prompt-injection` & `ta13-assurance-calibration`) produces identical SHA-256 input (`3c123819...`) & output (`30f3f081...`) digests with zero `DAL` or `confidence` tokens |
| `TA-24` | FHIR patient context | `BLOCKED_EXTERNAL` | Gated on `EXT-01` (`T09`) and `EXT-03` ([Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4)) |
| `TA-25` | Mobile offline shell | `BLOCKED_EXTERNAL` | Gated on `EXT-01` (`T20`, `T24`) + EGM finding V5 (`reqwest`/`hyper` in Tauri mobile targets) |
| `TA-26` | OS worker sandboxing | `BLOCKED_EXTERNAL` | Gated on `EXT-01` (`T10` sandbox launcher slice) |
| `TA-27` | Prompt-injection immunity | `PARTIAL` (deterministic suite `TESTED_PASSED`; worker `BLOCKED_EXTERNAL`) | `ta27_prompt_injection.rs` verifies retrieved-abstract prompt injections, FTS5 operator/homoglyph/BiDi query injections, and closed-grammar Ask withholding; generative LLM worker prompt-injection suite gated on `EXT-07` |
| `TA-28` | Signed installer & TUF pack rollback | `PARTIAL` (unsigned offline staging `TESTED_PASSED`; signing & TUF `BLOCKED_EXTERNAL`) | `safeevidence-release/src/staging.rs` (`unsigned_staging_bundle.rs`) verifies deterministic unsigned staging manifests (`signed = false`, `bundle.active = false`, `release_qualified = false`); signed installers & TUF rollback (`T25`) gated on `EXT-05` ([Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5)) |
| `TA-29` | Dependency-tree HTTP/model denial | `TESTED_PASSED` | `ta29_dependency_denial.py`, `core_no_sockets.py`, `ta29_desktop_denial.py`, and `deny.toml` across all 3 desktop targets |
| `TA-30` | Outbound-query disclosure (`P00 D7`) | `PARTIAL` (local contract `TESTED_PASSED`; `EXT-01` open) | `surveillance.rs` (`outbound_opt_in: false` default, patient-narrative rejection, exact `prepare_outbound_preview`); live `T05` transport gated on `EXT-01` |
| `TA-M0` | Reference-machine runtime budgets | `TESTED_PASSED` (synthetic scope) | `docs/RUNTIME_BUDGET_BASELINE_2026-11-26.md` (`14.00 MiB` release exe, `2.50 s` cold start, `3.8 ms` `p50` warm Ask, `25.58 MiB` host RSS / `364.70 MiB` WebView2 tree) |

---

## 5. Reproducible Verification Commands

From the repository root (`SafeEvidence/`):

```powershell
# 1. Governance, freeze, admission, and G01a stdlib baseline checks
python -m unittest discover -s tools/governance/tests -v
python tools/governance/plan_baseline_check.py --root .
python tools/governance/p01_preentry_check.py
python tools/governance/p01_candidate_integrity.py
python tools/governance/source_admission_check.py
python tools/governance/g01a_synthetic_check.py
cargo test --offline --locked --all-targets

# 2. Product Rust workspace, supply-chain, SBOM, and SafeEvidenceBench (from product/)
cd product
cargo fmt --all -- --check
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo test --offline --locked --workspace
cargo run --offline --locked -p safeevidence-release --bin sbom -- "$env:TEMP\sbom.cdx.json"
cargo run --offline --locked -p safeevidence-ask --bin safeevidence_bench
python ../tools/ci/ta29_dependency_denial.py
python ../tools/ci/core_no_sockets.py
python ../tools/ci/ta29_desktop_denial.py

# 3. Desktop frontend, Tauri backend, and live 21-check WebView2 E2E (from product/apps/desktop/)
cd apps/desktop
npm test
npm run build
cd src-tauri
cargo fmt --all -- --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo build --offline --locked --features custom-protocol,e2e
cd ..
node e2e/ask_e2e.mjs "<target-dir>/debug/safeevidence-desktop.exe"
```

---

## 6. Explicit Remaining External Actions (Non-Delegable to Autonomous Engineering)

1. **[Issue #3](https://github.com/TheHalfMoon/SafeEvidence/issues/3) (`EXT-04`):** Assign accountable human phase owners in `docs/P01_P1_GATE_TRACKER_2026-10-08.md` (`ASSIGNED -- @<owner> (<issuecomment-url>)` is now supported by `p01_preentry_check.py`).
2. **[Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4) (`EXT-03`):** Sign the clinical intended-use wedge, clinician evaluation charter, and adjudicator protocol before creating clinical holdouts or enabling `WP-21` patient context.
3. **[Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5) (`EXT-01`, `EXT-05`, `EXT-07`):**
   - Record signed `VERIFIED_ALLOWED` rows in `docs/evidence/source_admissions.json` for remaining donors/crates (`T05`, `T07`, `T09`, `T10`, `T14`, `T15`, `T16`, `T18`-`T23`, `T27`, `T28`).
   - Record model-card license clearances (`EXT-07`) before admitting `ort`/`fastembed` or any ONNX/LLM weights.
   - Establish release signing keys and TUF role custody (`EXT-05`) before enabling installer bundling (`bundle.active = true`) in `WP-24`.
4. **[Issue #17](https://github.com/TheHalfMoon/SafeEvidence/issues/17) & [PR #43](https://github.com/TheHalfMoon/SafeEvidence/pull/43) (`EXT-06`):** Complete independent human technical/security review of G01a, M0/M1 exit artifacts, and the coordinated security disclosure policy (`SECURITY.md`).

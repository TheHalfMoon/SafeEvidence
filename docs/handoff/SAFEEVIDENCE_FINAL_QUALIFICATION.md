# SafeEvidence Final Engineering Qualification Dossier

Status: `AUTHORIZED_ENGINEERING_COMPLETE` (`EXTERNAL_GATES_OPEN` for full V1 clinical, source-rights, human-review, and release closure)
Date: `2026-11-27`
Repository: `https://github.com/TheHalfMoon/SafeEvidence` (`Apache-2.0` for SafeEvidence-owned code)
Canonical branch: `main`
Recovered baseline SHA: `5ccecd7688f1d10fa8474a697d6b6670d8eafec8` (`2026-11-09`)
Verified `main` SHA: `caab864ee2ea0520f922c4646a883b38e0ac02e7` (`2026-11-27`, PR #97 merged; 7/7 post-merge workflows `success`), extended by PR #98 (`safeevidence/adversarial-a11y-rtl-staging-20261127`)
Authorized development workstation: Windows 11 PC (`C:\Users\Shehr\.gemini\antigravity\scratch\SafeEvidence`) under explicit user override (`"use this pc , dont use mac"`), paired with hosted Ubuntu, Windows, and macOS GitHub Actions checks.

---

## 1. Executive Qualification Statement

Every engineering requirement authorized under `EXT-02` (`docs/decisions/M0_EXT02_RATIFICATION_2026-11-05.md`) and `Issue #5` D2 (`ADM-0010`..`ADM-0012` + `ADM-0001`..`ADM-0009`) has been implemented, deterministically tested, independently audited, and qualified across bounded pull requests `#91`–`#98` (`main` @ `caab864ee2ea0520f922c4646a883b38e0ac02e7` through PR #97 with `15/15` PR checks and all 7 post-merge workflows `success`, plus PR #98 `safeevidence/adversarial-a11y-rtl-staging-20261127`). All external gates (`EXT-01`, `EXT-03`..`EXT-07`, `EXT-09`) remain strictly fail-closed (`docs/handoff/V1_GATE_AND_ADMISSION_AUDIT_2026-11-27.md`, `docs/decisions/V1_FOUNDER_DECISION_PACKET_2026-11-27.md`).

In strict compliance with `AGENTS.md` and `docs/PLAN_FREEZE.md`:
1. **Frozen baselines remain byte-identical:** the root stdlib-only G01a baseline (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.gitattributes`, `crates/g01a-synthetic/*`, `fixtures/g01a_synthetic_v1.txt`, `docs/evidence/g01a_synthetic_manifest.json`), all 9 frozen planning artifacts in `docs/PLAN_FREEZE.md`, and every `"modification": "none"` donor file in `docs/evidence/source_admissions.json` remain untouched.
2. **Copy-first and donor-rights discipline is preserved:** zero unadmitted donor code (`T05`, `T07`, `T09`, `T10`, `T14`, `T15`, `T16`, `T18`-`T23`) was copied, and zero donor-assigned `COPY_BOUNDED` / `WORKER` / `DEPEND` subsystems (`T14` DAL selective-risk metrics, `T15` `MedOrigin` `litdb` fuzzy dedupe/screening, `T18` `ASReview`, `T19` `statsmodels` pooling) were reimplemented greenfield.
3. **Separate qualification axes are never conflated:** `ENGINEERING_COMPLETE` for the `EXT-02` synthetic scope does **not** claim `CLINICALLY_EVALUATED`, `SOURCE_RIGHTS_CLEARED` (for unadmitted slices), `SECURITY_REVIEW_COMPLETE`, `RELEASE_QUALIFIED`, `PUBLIC_RELEASED`, or `CLINICAL_USE_AUTHORIZED`.

---

## 2. Multi-Axis Qualification Status

| Qualification Axis | Status | Governing Authority & Remaining External Gate |
|---|---|---|
| `ENGINEERING_COMPLETE` | `AUTHORIZED_SCOPE_COMPLETE` (`FALSE` for full V1) | All `EXT-02` + Issue #5 D2 (`ADM-0001`..`ADM-0012`) engineering slices implemented and verified across PRs `#91`–`#98` (`docs/handoff/V1_GATE_AND_ADMISSION_AUDIT_2026-11-27.md`); unadmitted V1 packets remain `BLOCKED_EXTERNAL` |
| `MILESTONE_QUALIFIED` | `G01A_AND_M0_ENGINEERING_COMPLETE` (`AI_ONLY`; `EXT-06` open) | `docs/reviews/M0_M1_EXIT_REVIEW_2026-11-26.md`; human review (`EXT-06`) and `T05` (`EXT-01`) remain open |
| `CLINICALLY_EVALUATED` | `FALSE` (`BLOCKED_EXTERNAL`) | `EXT-03` -- [Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4) clinical intended-use & evaluation charter |
| `SOURCE_RIGHTS_CLEARED` | `PARTIAL_BOUNDED` (`ADM-0001`..`ADM-0012` only) | `EXT-01` & `EXT-07` -- [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5) exact-source, dataset, and model-weight admissions |
| `SECURITY_REVIEW_COMPLETE` | `FALSE` (`BLOCKED_EXTERNAL`) | `EXT-06` ([Issue #17](https://github.com/TheHalfMoon/SafeEvidence/issues/17)) & open [PR #43](https://github.com/TheHalfMoon/SafeEvidence/pull/43) independent human security review |
| `RELEASE_QUALIFIED` | `FALSE` (`BLOCKED_EXTERNAL`) | `EXT-05` -- [Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5) signing key custody, TUF ceremony, and installer signing |
| `PUBLIC_RELEASED` | `FALSE` | Zero GitHub Releases published |
| `CLINICAL_USE_AUTHORIZED` | `FALSE` (`BLOCKED_EXTERNAL`) | `EXT-03` + `EXT-09` -- invented synthetic engineering fixtures only; never for patient care |

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
| PR #98 | **TA-27 Adversarial Injection, 7-Split SafeEvidenceBench, 5-View RTL SSR Snapshots, Clipboard/Crashpad E2E & Unsigned Staging:** `ta27_prompt_injection.rs` + `EffectMeasureSwap`, `ta27-prompt-injection` split (`TA-23`), `rtl-snapshots.test.ts` (`TA-22`), `21/21` Win & `20/20` Linux E2E (`TA-20`), `safeevidence-release/src/staging.rs` (`TA-28` prep under `EXT-05`), final ledger reconciliation | `(recorded on branch)` | `(recorded on main)` | `15/15` exact-head checks |

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
| `TA-13` | Assurance determinism & zero UI percentage | `PARTIAL` (`plan-v1.4` `TESTED_PASSED`; `EXT-01` open) | `safeevidence-assurance` (`1,329` vectors + `17` cases + lexical-emergency ban) + UI zero-percentage check; `T14` DAL vectors gated on `EXT-01` |
| `TA-14` | Atomic proof admission & fault withholding | `PARTIAL` (`VS-1a` `TESTED_PASSED`; `EXT-07` open) | `answer_faults.rs`, `proof_commit.rs`, `ask_command.rs` (`CommitUnknown` reconciliation); LLM worker kill tests gated on `EXT-07` |
| `TA-15` | Document parsing & OCR | `PARTIAL` (`ADM-0007` hostile-MIME quarantine `TESTED_PASSED`; PDF/OCR worker `BLOCKED_EXTERNAL`) | `document_intake.rs` + `hostile_mime_010.rs` quarantine binary/container/HTML/XML/PDF-active polyglots, BOM, and control bytes; PDF/OCR worker gated on `EXT-01` (`T16`, `T20`), `EXT-07` (`T29` PaddleOCR models), and `WP-23a` (`T10` sandbox) |
| `TA-16` | Screening replay & ASReview WSS@95 | `PARTIAL` (protocol audit `TESTED_PASSED`; `EXT-01` open) | `review_protocol.rs` hash-chained `ProtocolAuditBundle` (`ta17_protocol_extraction.rs`); `T15` PRISMA & `T18` `ASReview` gated on `EXT-01` |
| `TA-17` | Quote-anchored structured extraction | `PARTIAL` (gating rule `TESTED_PASSED`; `EXT-01` open) | `StructuredEffectExtraction` (`100%` quote span + verbatim estimate check + `PROPOSED` until human confirms); `T28` Evidence Inference split gated on `EXT-01` |
| `TA-18` | Meta-analysis pooling & refusal | `PARTIAL` (refusal gate `TESTED_PASSED`; `EXT-01` open) | `decide_pooling` + `decide_subset_pooling`; `T19` `statsmodels` golden numerical worker gated on `EXT-01` + `WP-23a` |
| `TA-19` | Living validity updates & alerts | `PARTIAL` (local engine `TESTED_PASSED`; `EXT-01` open) | `surveillance.rs` + `ta06_ta19_validity_overlay.rs` (single-cycle cause-named alert, unchanged historical proof bytes) |
| `TA-20` | Desktop end-to-end journey & shell checklist | `PARTIAL` (`21/21` Win E2E & `20/20` Linux E2E `TESTED_PASSED`; `T07`/`D9` open) | `e2e/ask_checks.mjs` (Ask, span jump, refusals, Evidence/Deep Review/Packs/Privacy panes, CSP, capability refusal, clipboard non-mutation, restart, post-kill `dataDir`/vault/`Crashpad` zero-residue); signed pack import (`T07`) & `D9` shipped-Linux-incognito ruling remain open |
| `TA-21` | No silent network egress | `PARTIAL` (captures active; `EXT-01` open) | Linux `strace -ff` + Windows `netstat`/port-80 0-byte captures; full `T05` OS broker firewall harness gated on `EXT-01` |
| `TA-22` | Accessibility & RTL | `PARTIAL` (WCAG AA + 5-view SSR snapshots + live RTL E2E `TESTED_PASSED`) | `accessibility-rtl.test.ts` + `rtl-snapshots.test.ts` (16 deterministic `EN`/`AR` HTML/ARIA snapshots across all 5 views) + live E2E keyboard/RTL checks; `axe-core` package remains unadmitted under zero-lockfile-churn `ADM-0012` |
| `TA-23` | `SafeEvidenceBench` reproducibility | `PARTIAL` (7 synthetic splits `TESTED_PASSED`; `EXT-01`/`EXT-03` open) | `safeevidence_bench` (`ta23_safeevidence_bench.rs`, `7` splits incl. `ta27-prompt-injection`) produces identical SHA-256 input (`3c123819...`) & output (`acb62ab5...`) digests across `--debug` and `--release` |
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

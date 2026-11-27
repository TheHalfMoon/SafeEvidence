# SafeEvidence Engineering Status

Status: `AUTHORIZED_ENGINEERING_COMPLETE` (`EXTERNAL_GATES_OPEN` for full V1 clinical/release milestones)
Repository: `https://github.com/TheHalfMoon/SafeEvidence`
Canonical branch: `main`
Verified `main` SHA: `caab864ee2ea0520f922c4646a883b38e0ac02e7` (PRs #91–#97 merged; 7/7 post-merge workflows `success`), extended by PR #98 (`safeevidence/adversarial-a11y-rtl-staging-20261127`)
Authorized development workstation: Windows 11 PC (`C:\Users\Shehr\.gemini\antigravity\scratch\SafeEvidence`) under explicit user override (`"use this pc , dont use mac"`), paired with hosted Ubuntu, Windows, and macOS GitHub Actions checks.

Status labels below describe verified engineering scope only and never imply clinical validation, medical-device clearance, patient-data readiness, or source-rights approval outside recorded founder decisions.

---

## 1. Qualification State Summary

| Status Field | Value | Scope & Authority Boundary |
|---|---|---|
| `ENGINEERING_COMPLETE` | `AUTHORIZED_SCOPE_COMPLETE` (`FALSE` for full V1) | All engineering slices authorized under `EXT-02` + Issue #5 D2 (`ADM-0001`..`ADM-0012`) implemented and verified across PRs `#91`–`#98` (`T17` span audit/projection, `T12` `ADM-0007` privacy/MIME quarantine, `TA-05` disk-full & Argon2id key-loss/backup-restore, `TA-27` adversarial injection, `TA-20`/`TA-22` 5-view RTL SSR snapshots & clipboard/crash-dump E2E, unsigned offline staging); unadmitted donor/model/sandbox/clinical/signing items remain `BLOCKED_EXTERNAL` |
| `MILESTONE_QUALIFIED` | `G01A_AND_M0_ENGINEERING_COMPLETE` (`AI_ONLY`; `EXT-06` open) | Root G01a qualified; M0 admission engineering complete; M1 VS-1a synthetic engineering complete; M2/M3/M4 `GREENFIELD_JUSTIFIED` slices complete (`EXT-01` / `EXT-03` / `EXT-06` / `EXT-07` gates open) |
| `CLINICALLY_EVALUATED` | `FALSE` | Blocked on `EXT-03` ([Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4)); all fixtures are synthetic/invented |
| `SOURCE_RIGHTS_CLEARED` | `PARTIAL` | `ADM-0001`..`ADM-0012` cleared under [Issue #5 D2](https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204); `T05`, `T07`, `T09`, `T10`, `T14`, `T15`, `T16`, `T18`-`T23`, `T27`-`T29` remain `BLOCKED_EXTERNAL` |
| `SECURITY_REVIEW_COMPLETE` | `FALSE` | Automated + adversarial crypto/SQL/CSP/socket tests active; PR #43 and Issue #17 human reviews remain open |
| `RELEASE_QUALIFIED` | `FALSE` | Blocked on `EXT-05` ([Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5)) signing keys, installer bundling, and external gates |
| `PUBLIC_RELEASED` | `FALSE` | No GitHub Release published |
| `CLINICAL_USE_AUTHORIZED` | `FALSE` | Strictly synthetic engineering workstation; clinical diagnosis and treatment remain prohibited |

---

## 2. Subsystem Status Inventory

| Crate / Component | Location | Current State | Verified Capabilities & Open External Gates |
|---|---|---|---|
| Root G01a Synthetic Baseline | `crates/g01a-synthetic` | `TESTED_PASSED` | Frozen std-only Rust `1.97.1` baseline (`3/3` tests, `g01a_synthetic_check.py` `PASS`) |
| Governance & Provenance Guards | `tools/governance`, `tools/ci` | `TESTED_PASSED` (PR #91 `e08684d` + `ADM-0013`..`ADM-0041` audit) | `208` unit tests passing; `CRATE-*` lockfile closure checks (`ADM-0010`..`ADM-0012`), non-authorizing candidate ledger (`ADM-0013`..`ADM-0041`, `EXT-08` private-repo tripwire), `T30` `tool_audit.py` expansion, and issue-bound `ASSIGNED` support in `p01_preentry_check.py` active |
| `safeevidence-contracts` | `product/crates/safeevidence-contracts` | `TESTED_PASSED` (PR #91, #94, #95, #97) | Canonical P00 decision outcomes, proof states, span coordinates, `ADM-0004` (`T17`) opaque span-overlap audit (`span_audit.rs`) + PHI-safe scalar offset projection (`offset_projection.rs`), hostile-MIME/polyglot/container intake quarantine (`document_intake.rs`), study-overlap linkage (`study_linkage.rs`, `TA-07`), `RoB 2`/`ROBINS-I`/`QUADAS-2`/`AMSTAR 2` + `GRADE` + `EBMonFHIR` crosswalk (`appraisal.rs`, `TA-12`), Arabic/Latin scalar normalization (`bilingual.rs`, `TA-08`), surveillance schemas (`surveillance.rs`), and `ReviewProtocol` + hash-chained `ProtocolAuditBundle` + quote-anchored `StructuredEffectExtraction` (`review_protocol.rs`, `TA-17`) |
| `safeevidence-assurance` | `product/crates/safeevidence-assurance` | `TESTED_PASSED` (VS-1 scope) | Precedence mechanics (`1,329` vectors + `17` `T13` cases under `plan-v1.4`; `T14` DAL metrics gated on `EXT-01`) |
| `safeevidence-vault` & `safeevidence-linux-keyring-helper` | `product/crates/safeevidence-vault` | `TESTED_PASSED` (PR #92 `82df2cd` + PR #97 `caab864e`) | SQLCipher `4.14.0` + OpenSSL `3.6.3` (`libsqlite3-sys 0.38.2`) + OS protectors + pre-open `-wal` page-size guard (`RUSTSEC-2026-0459`) + `SAFEVD/` cryptographic domain separation (`domain_separation.rs`) + `page_count()` / `set_max_page_count()` (`0 -> 0x3fff_ffff`) |
| `safeevidence-proofstore` & `safeevidence-privacy-probes` | `product/crates/safeevidence-proofstore`, `product/tests/privacy` | `TESTED_PASSED` (PR #93, #94, #97) | Atomic proof commits, `open_existing`/contention/snapshot-restore durability, `PRAGMA max_page_count` disk-full rollback (`ta05_diskfull_and_recovery.rs`), `plan-v1.3` `ClinicalAssertion` lineage + `verify_record_semantics_doctor()`, superseding-free `retract_source`, B505 encrypted backup fresh-device restore, `ADM-0007` (`T12`) `privacy_probes_032` + `vault_privacy_023` + `hostile_mime_010`, and `SAFEVD/` bounded-blob living surveillance engine (`surveillance.rs`, `TA-19`/`TA-30` local guard) |
| `safeevidence-ask` & `safeevidence_bench` | `product/crates/safeevidence-ask` | `TESTED_PASSED` (PR #93, #94, #95, #98) | Synthetic Ask (`ANSWER`, `ANSWER_WITH_CAUTION`, `ASK_MORE`, `CONFLICT`, `ABSTAIN`, `ESCALATE`, `BLOCKED`), bilingual EN/AR Ask (`bilingual_ask.rs`, `TA-08`), deterministic corpus validity overlay (`overlay.rs`, `TA-06`), harder `329`-doc BM25 benchmark (`bench/ta09_hard/`, `TA-09`), perturbation + `EffectMeasureSwap` + PICO mismatch verifier (`perturbation.rs`, `TA-10`/`TA-11`), `TA-27` adversarial prompt/FTS5/homoglyph/BiDi suite (`ta27_prompt_injection.rs`), and 7-split reproducible `SafeEvidenceBench` packet runner (`bench_runner.rs`, `TA-23`) |
| `safeevidence-release` | `product/crates/safeevidence-release` | `TESTED_PASSED` (PR #91 `e08684d` + PR #98) | Deterministic CycloneDX 1.5 SBOM generator & verifier covering `product/Cargo.lock`, desktop `src-tauri/Cargo.lock`, and `package-lock.json` (`613` components), plus deterministic unsigned offline staging manifest & verifier (`staging.rs`, `unsigned_staging_bundle.rs`, keeping `signed = false` & `bundle.active = false` under `EXT-05`) |
| Desktop Workstation (`Tauri 2.12` + `React 19.3`) | `product/apps/desktop` | `TESTED_PASSED` (synthetic M4 scope in PRs #95, #97, #98) | Strict CSP (`default-src 'none'; style-src 'self'`), minimal named capability (`allow-ask-question`, `allow-workstation-overview`), single-instance lock, OS-protected vault custody + `SAFEVD/RECOVERY/ENVELOPE/v1` Argon2id key-loss recovery (`custody.rs`), multi-pane workstation (`Ask`, `Evidence & Sources`, `Deep Review`, `Packs & Validity`, `Privacy & Diagnostics`), `EN`/`AR` + `RTL` WAI-ARIA keyboarding, 16 deterministic SSR HTML/ARIA snapshots (`rtl-snapshots.test.ts`), WCAG 2.1 AA contrast (`>= 4.5:1`), `21/21` Windows WebView2 E2E & `20/20` Ubuntu WebKitGTK E2E (incl. clipboard & post-kill `Crashpad`/vault zero-residue), and `TA-M0` measured baseline (`docs/RUNTIME_BUDGET_BASELINE_2026-11-26.md`) |

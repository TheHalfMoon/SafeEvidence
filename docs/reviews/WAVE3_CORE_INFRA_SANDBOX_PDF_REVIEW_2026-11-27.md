# Wave 3 (`plan-v1.7` / PR #100) Core Infrastructure, OS Sandbox, Network Broker, Signed Packs, FHIR R4 & Native PDF/SafeOCR Review Record

- **Date:** `2026-11-27`
- **Branch:** `safeevidence/wave3-sandbox-network-packs-pdf-fhir-20261127`
- **Base `main` SHA:** `3dda47947cffa9c0231f79133a5eea36e6792e4b` (PRs #91–#99 & PR #43 merged; 7/7 post-merge `main` workflows `success`)
- **Governing Authorities:** `docs/plan/PLAN_AMENDMENT_V1_7.md`, `docs/adr/0001..0004`, `docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md`, `docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`, `SECURITY.md`
- **Truth-in-Qualification Declaration:** `AI_ASSISTED_SECURITY_QUALIFICATION = ACTIVE`, `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`, `OS_CA_CODE_SIGNED = FALSE`, `ACTUAL_CLINICAL_VALIDATION = FALSE`, `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`.

---

## 1. Public-License Source Admissions Promoted (`ADR-0004`) & Lockfile Closure Audit

1. **`ADM-0018` (`T10`, `TA-26` — OS Worker Sandbox & Supervision Policy):**
   - Donor: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`).
   - Targets: `safeevidence-contracts/src/worker_policy/mod.rs`, `safeevidence-contracts/src/os_sandbox/{mod.rs,linux_rlimit.rs,linux_seccomp.rs,macos_app_sandbox.rs,macos_seatbelt.rs,windows_appcontainer.rs,windows_job.rs}`, `safeevidence-contracts/src/bin/os_sandbox_probe.rs`, `safeevidence-contracts/fixtures/worker.entitlements.plist`, and 9 integration tests (`os_sandbox_030`..`053`, `worker_policy_deny_default`).
2. **`ADM-0015` (`T05`, `TA-21`, `TA-30` — Network Broker & Governed Egress Policy):**
   - Donor: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`).
   - Targets: `safeevidence-contracts/src/network/mod.rs` and workspace crate `product/crates/safeevidence-network` (`allowlist.rs`, `adapters.rs`, `browse.rs`, `transport.rs`, `lib.rs`, `tests/network_broker_013.rs`, `PROVENANCE.md`), with `ureq` removed to preserve `TA-29` zero-HTTP-client workspace invariants.
3. **`ADM-0016` (`T07`, `TA-06`, `TA-28` — Content-Addressed Pack Store & RFC 8032 Ed25519 Anti-Rollback):**
   - Donor: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`).
   - Targets: `safeevidence-contracts/src/packs/mod.rs` and workspace crate `product/crates/safeevidence-pack` (`trust.rs` clean-room `#![forbid(unsafe_code)]` RFC 8032 Ed25519 verified against official RFC 8032 §7.1 test vectors 1 & 2, `format.rs`, `store.rs`, `lib.rs`, `tests/pack_signer_026.rs`, `tests/packs_008.rs`, `PROVENANCE.md`; `runtime.rs` kept `not_copied` per F8).
4. **`ADM-0017` (`T09` — FHIR R4 Lexical Gate, UCUM Subset & Closed Extractors):**
   - Donor: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`).
   - Targets: `safeevidence-contracts/src/fhir/mod.rs` and workspace crate `product/crates/safeevidence-fhir` (`units/mod.rs`, `lexical.rs`, `extractors/mod.rs`, `lib.rs`, `tests/fhir_interchange_020.rs`, `PROVENANCE.md`), enforcing `FhirUsageScope::LiveClinicalPatientForbidden` refusal per `ADR-0003`.
5. **`ADM-0020` (`T16`, `TA-15` — SafeOCR Critical-Value Verifier & Pure-Rust Native PDF Extractor):**
   - Donor: `AbdulazizShehri/safeOCR` @ `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4` (`Apache-2.0`; verbatim `LICENSE` and `NOTICE` preserved in `tests/fixtures/t16/`).
   - Targets: workspace crate `product/crates/safeevidence-docs` (`safeocr_contracts.rs`, `safeocr_verify.rs`, `safeocr_report.rs`, `native_pdf.rs`, `tests/t16_safeocr_verification.rs`, `tests/ta15_native_pdf_and_ocr.rs`, `PROVENANCE.md`) + 9th `SafeEvidenceBench` split `ta15-native-pdf-and-safeocr`.
6. **Lockfile Closures (`ADM-0010` & `ADM-0011`):**
   - `ADM-0010` (`product/Cargo.lock`): `179` packages (`175 -> 179` internal workspace crates; zero new external crates.io packages added except permissive `num-bigint 0.4.6` / `num-integer 0.1.46` / `num-traits 0.2.19` / `semver 1.0.27` already audited under `product/deny.toml`).
   - `ADM-0011` (`product/apps/desktop/src-tauri/Cargo.lock`): `462` packages (`460 -> 462` internal workspace crates `safeevidence-docs` and `safeevidence-fhir`; zero new external crates).

---

## 2. Google EGM Hostile Design, Cryptographic & Security Review (`827a8139`)

### 2.1 Wave 1 Polish Verification (`5/5 PASS`)
- `source_admission_check.py`: `pkt_str.startswith("T14")` and `pkt_str.startswith(("T27b", "T28b", "T34", "T35"))` verified.
- `document_intake.rs`: `b'%'` PDF comment delimiter added to `js_active` and `aa_active`.
- `eval_metrics.rs`: exact IEEE-754 monotonic upper bin boundary enforced across `1..=10_000` calibration bins.
- `bench_runner.rs`: conservative outer 95% CI envelope `(b_lo.min(w_lo), b_hi.max(w_hi))` and `<metric>_denominator` metrics verified.
- `surveillance.rs`: pre-check of all `watch.linked_proof_id` entries before `execute_surveillance_batch` and ASCII word-boundary matching for `"mrn"`/`"dob"` verified.

### 2.2 Round 1 Blocking & Non-Blocking Findings and Exact Remediations (`10/10 RESOLVED`)
- **`B-1` (`TA-30` Preview/Receipt URL Fragment & Allowlist Prefix-Boundary Bypass):**
  - Rejected `'#'` and `"%23"` in `is_unambiguous_url_path` (`safeevidence-contracts/src/network/mod.rs`) and `validate_url` (`safeevidence-network/src/browse.rs`).
  - Bound `authorization_token_id`, `body_digest`, and `fixture_id` with 8-byte big-endian length prefixes in `build_outbound_query_preview`, enforced post-validation host/path identity and canonical `preview` dispatch in `broker_invoke_governed`, trimmed `destination_host`/`destination_path` in `broker_invoke`, and enforced segment/query boundary matching (`rem.is_empty() || entry.path_prefix.ends_with('/') || rem.starts_with('/') || rem.starts_with('?')`) in `allowlist.rs`. Covered by `rejects_url_fragments_prefix_boundary_escape_and_post_preview_metadata_drift` in `network_broker_013.rs`.
- **`B-2` (`T07` Pack Content Digest / Signing Framing & `PackStore::admit` Forbidden-Kind Gate):**
  - Switched `compute_content_digest` (`safeevidence-pack/src/format.rs`) to 8-byte BE length-prefixed framing including `PackArtifactKind`, switched `pack_signing_payload` (`trust.rs`) to 8-byte BE length-prefixed framing covering `runtime_requirements` and `benchmark_links`, blocked `':'` (NTFS ADS) and ASCII-case-insensitive duplicate `relative_path`s, and enforced `!manifest.artifacts.is_empty()` and `!art.kind.is_forbidden_by_default()` in `PackStore::admit` (`store.rs`). Covered by `rejects_artifact_kind_swap_metadata_tamper_and_colon_ads_paths` in `pack_signer_026.rs`.
- **`B-3` (`T09` FHIR JSON Duplicate-Key Bypass via UTF-16 Surrogate Pairs):**
  - Implemented full RFC 8259 UTF-16 high/low surrogate pair decoding (`0xD800..=0xDBFF` + `0xDC00..=0xDFFF` -> astral Unicode scalar) in `scan_string` (`safeevidence-fhir/src/lexical.rs`), rejecting unpaired surrogates, unescaped control bytes `< 0x20`, and invalid backslash escapes. Covered by `duplicate_keys_via_utf16_surrogate_pairs_and_invalid_escapes_rejected` in `fhir_interchange_020.rs`.
- **`B-4` (`T16` SafeOCR `engine_score: None` Bypass, Empty-Span Indexing & `DecisionMismatch`):**
  - Required explicit `s.engine_score.is_some_and(|sc| sc.is_finite() && (0.0..=1.0).contains(&sc) && sc >= min_score)` for `visual_grounded` in `safeocr_verify.rs`, added `CandidateSpan::validate`, `LabFieldCandidate::validate`, and `EvidenceRecord::validate` (checking `self.decision == decide(&self.signals, self.field.criticality)`), replaced raw `[0]` indexing with `.first().ok_or(EmptySourceSpans)?`, and enforced `evidence.validate().is_ok()` in `export_allowed` and `build_safeocr_audit_report`. Covered in `t16_safeocr_verification.rs`.
- **`B-5` (`TA-15` Native PDF `"stream"` Substring Truncation, `/Kids` Page Ordering & BiDi Controls):**
  - Restricted `find_stream_keyword` (`safeevidence-docs/src/native_pdf.rs`) to ISO 32000-1 §7.3.8.1 `>>` + optional PDF whitespace/comments + `stream` + `\r\n`/`\n`, traversed `/Catalog -> /Pages -> /Kids` with a visited-node cycle guard (`resolve_ordered_page_ids`), and quarantined decoded PDF text containing `is_forbidden_bidi_control` or disallowed control chars. Covered by `preserves_kids_page_order_ignores_stream_substring_in_dict_and_quarantines_bidi_override` in `ta15_native_pdf_and_ocr.rs`.
- **`NB-1` (`macos_app_sandbox.rs` Key-Adjacent Entitlements Check):** Verified `<true/>` directly follows `<key>com.apple.security.app-sandbox</key>` and rejected `<true/>` on `com.apple.security.network.client` or `network.server`.
- **`NB-2` (`windows_appcontainer.rs` Child Timeout Cleanup & `WSAGetLastError`):** Added `TerminateProcess` cleanup when `WaitForSingleObject != 0` and checked `WSAGetLastError` (excluding `WSAETIMEDOUT = 10060`) in `appcontainer_lpac_net_child_exit_code`.
- **`NB-3` (`safeevidence-network/src/lib.rs` Constant-Time Digest Check):** Implemented explicit 32-byte XOR accumulator without early exit in `integrity_matches`.
- **`NB-4` (`safeevidence-fhir/src/lexical.rs` `extract_patient_identifiers` Gate):** Gated `extract_patient_identifiers` through `gate_fhir_json` before `serde_json::from_slice`.
- **`NB-5` (`native_pdf.rs` Huffman Kraft Inequality):** Enforced $\sum_{\text{bits}=1}^{15} \text{count}[\text{bits}] \cdot 2^{15-\text{bits}} \le 2^{15}$ in `HuffmanTree::build`.

---

## 3. Alibaba Open Code Review (`ocr v1.14.4` Delegated Host-Agent Review) & Exact-Head Verification

- **Rule Group 1 (`**/*.json`):** `docs/evidence/source_admissions.json` (`ADM-0010`, `ADM-0011`, `ADM-0015`..`ADM-0018`, `ADM-0020`) validated structurally (`source_admission_check.py` `PASS`, `210/210` governance unit tests `OK`).
- **Rule Group 2 (`**/*.rs`):**
  - `#![forbid(unsafe_code)]` enforced on all 4 new crates (`safeevidence-network`, `safeevidence-pack`, `safeevidence-fhir`, `safeevidence-docs`).
  - Audited OS-sandbox FFI (`os_sandbox/*.rs`) isolated to kernel-boundary primitives (`setrlimit`, `prctl`/`seccomp`/Landlock, `sandbox_init`, Win32 Job Object & AppContainer/LPAC) with explicit handle/SID/attribute-list cleanup on every exit path and live Windows 11 Job Object + AppContainer + LPAC probes verified green.
  - Zero prohibited socket/HTTP client imports in library code (`core_no_sockets.py` `PASS` across Windows, Linux, macOS; `ta29_dependency_denial.py` `PASS`).
- **Rule Group 3 (`**/*.py`):** Prefix-based `T14` and `T27b`/`T28b`/`T34`/`T35` guards verified in `source_admission_check.py`.
- **PStack `/ps-review` 4-Bar Panel & Independent Exact-Head Verifier (`300f2d67`):**
  - **Round 1 Findings Resolved (`9/9`):**
    1. `B-1`: Removed `SAFEEVIDENCE_TA03_ISOLATED` fallback from `apply_seatbelt_macos` (`macos_seatbelt.rs`), added pre-isolation `macos-15` `os_sandbox_031` step in `.github/workflows/product-ci.yml`, and asserted fail-closed nested refusal when `SAFEEVIDENCE_TA03_ISOLATED=1` in `os_sandbox_031.rs`.
    2. `B-2`: Enforced `token_is_app_container() == Ok(true)` pre-gate at entry of `appcontainer_fs_child_exit_code`, `appcontainer_net_child_exit_code`, and `appcontainer_lpac_net_child_exit_code` (`windows_appcontainer.rs`), and restricted LPAC `connect` error codes to `matches!(err, 10013 | 10022 | 10043 | 10044 | 10106)`.
    3. `B-3`: Added `classify_stream_filters` in `native_pdf.rs` rejecting `/DecodeParms`/`/DP` and any `/Filter`/`/F` other than single `/FlateDecode`/`/Fl` (`Err(PdfExtractError::MalformedPdf)`).
    4. `B-4`: Enforced canonical untrimmed strings and strictly lowercase 64/128-char hex in `safeevidence-pack` (`format.rs`, `store.rs`, `trust.rs`), plus `'/'`-segment validation (`//`, trailing `/`, trailing `.`, Windows reserved DOS stems `CON`/`PRN`/`AUX`/`NUL`/`COM1..9`/`LPT1..9`) and file-vs-directory prefix collision rejection.
    5. `B-5`: Bound `tests/test_foundation_contracts.py` -> `product/crates/safeevidence-docs/tests/t16_foundation_contracts.rs` (`modification: "adapted"`) in `ADM-0020` (`docs/evidence/source_admissions.json`) and updated `docs/IMPLEMENTATION_LEDGER.md` header/milestone rows.
    6. `NB-1`..`NB-4`: Multi-entry `evaluate_allowlist` scan + `enabled`-only `EmptyAllowlist`/`doctor_status` + `!b.is_ascii_graphic()` URL path & reserved/numeric TLD rejection; added `safeevidence-docs`, `safeevidence-fhir`, `safeevidence-pack` to `CORE` in `tools/ci/core_no_sockets.py`; tightened `fhirVersion`/`version_hint`/`resourceType` checks in `safeevidence-fhir/src/lexical.rs`; fixed glob listing in `safeevidence-contracts/PROVENANCE.md`.
  - **Correctness:** `PASS` — RFC 8032 §7.1 Ed25519 vectors, RFC 1950/1951 bounded `FlateDecode` decompression + strict `/Filter` refusal, 9/9 `SafeEvidenceBench` splits deterministic & green.
  - **Parsimony:** `PASS` — Clean single-purpose workspace crates matching frozen `SOURCE_TRANSPLANT_MATRIX_V1` boundaries (`runtime.rs` excluded per F8; `ureq` excluded per `TA-29`).
  - **Product (`plan-v1.7` Alignment):** `PASS` — Delivers Wave 3 (`TA-06`, `TA-15`, `TA-21`, `TA-26`, `TA-28`, `TA-30`, `T09` non-clinical FHIR R4) while preserving `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`, `OS_CA_CODE_SIGNED = FALSE`, `ACTUAL_CLINICAL_VALIDATION = FALSE`, `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`.
  - **Security:** `PASS` — All 10 EGM (`827a8139`) findings (`PASS` verified in Round 2) and all 9 independent verifier (`300f2d67`) findings resolved with regression tests.

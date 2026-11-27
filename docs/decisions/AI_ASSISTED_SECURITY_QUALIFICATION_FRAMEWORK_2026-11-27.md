# SafeEvidence Independent AI-Assisted Security Qualification Framework

State: **ACTIVE (`AI_ASSISTED_SECURITY_QUALIFICATION_V1`)**
Date: `2026-11-27`
Authority: 2026-11-27 Founder Directive (`docs/plan/PLAN_AMENDMENT_V1_7.md`, `docs/adr/0002-ai-assisted-security-qualification-framework.md`)

---

## 1. Purpose and Honesty Invariant

This framework replaces mandatory internal human engineering and security review gates (`EXT-06`, `D12`, `PR #43`, `Issue #17`) as prerequisites for SafeEvidence V1 engineering completion and V1 research release qualification, while strictly upholding truth-in-provenance:

- **No self-review:** The authoring implementation agent is never the sole reviewer of its own changes.
- **No fabricated human sign-off:** AI reviews and automated verifications are recorded transparently as **`AI_ASSISTED_SECURITY_QUALIFICATION = TRUE`** alongside **`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`**.

---

## 2. Mandatory Multi-Layer Verification Stack

Every security-relevant or milestone PR must satisfy all five layers on the **exact evaluated Git `HEAD` SHA** before qualification is recorded:

1. **Multi-Agent Fresh-Context Review Panel:**
   - Zero-shared-context Google EGM Goldfish security/architecture/readiness reviewers (`egm-design`, `egm-zoom-out`, `egm-codebase-details`, `egm-implementation-readiness`) and/or zero-context independent Antigravity security auditor subagents;
   - Local Alibaba Open Code Review (`ocr delegate preview` + `ocr delegate rule`) with 100% file accounting;
   - PStack fresh-context diff review panel (`/ps-review` correctness, parsimony, product, and security bars);
   - `jev` deterministic checks where applicable;
   - Self-contained **ChatGPT Independent Technical & Security Review Packet** (`docs/reviews/CHATGPT_INDEPENDENT_REVIEW_PACKET_V1.md`) prepared with exact commit SHA, threat model, critical source surfaces, test evidence, residual risks, and offline reproduction commands.
2. **Static, Dependency, and Network-Isolation Gates:**
   - `cargo fmt --all -- --check` and `cargo clippy --offline --locked --workspace --all-targets -- -D warnings`;
   - `cargo deny check` across `product/` and `product/apps/desktop/src-tauri/` (`TA-03`);
   - Lockfile SHA-256 & SPDX allowlist closure checks (`source_admission_check.py`, `TA-01`) + deterministic CycloneDX 1.5 SBOM verification (`TA-02`);
   - Dependency-tree HTTP-client and core zero-socket gates (`ta29_dependency_denial.py`, `core_no_sockets.py`, `ta29_desktop_denial.py`, `TA-29`) across Windows, Linux, and macOS.
3. **Cryptographic, Storage, and Intake Adversarial Testing:**
   - `SAFEVD-v1` domain separation, SQLCipher `4.14.0` HMAC tamper detection, `RUSTSEC-2026-0459` pre-open WAL page-size guard, 8-point kill durability, `PRAGMA max_page_count` disk-full rollback, Argon2id key-loss recovery, B505 fresh-device backup restore, and WAL/temp/`Crashpad` zero-plaintext scans (`TA-05`);
   - Hostile-MIME, polyglot (`HTML`/`XML`/`PDF` active actions, container magic), UTF-8 BOM, and Trojan-Source BiDi/control-byte intake quarantine (`TA-15`).
4. **Deterministic Property-Based, Structure-Aware Fuzz, and Prompt-Injection Testing:**
   - Seeded multi-thousand-iteration property/mutation suites across `document_intake`, `span_audit`, `bilingual`/`offset_projection`, `perturbation`, `staging`, and stateful `proofstore` immutability triggers;
   - Retrieved-document and FTS5/homoglyph/BiDi query prompt-injection immunity (`TA-27`).
5. **Live Cross-Platform Workstation End-to-End Verification:**
   - Real Tauri 2 WebView2 (Windows) and WebKitGTK (Ubuntu) end-to-end suites verifying CSP (`default-src 'none'; style-src 'self'`), capability refusal, clipboard non-mutation, zero non-loopback sockets, and post-kill zero-plaintext residue (`TA-20`, `TA-21`).

---

## 3. Finding Disposition Rule

Every blocking security or correctness finding raised by any review layer must be:
1. Investigated against exact file/line evidence;
2. Fixed with a dedicated regression test; and
3. Independently re-verified on the new exact `HEAD` SHA (`0` open blocking findings) before merge.

# Antigravity Recovery Report

Status: `RECOVERY_VERIFIED`
Recovery timestamp: `2026-11-26T16:00:55+03:00`
Repository: `https://github.com/TheHalfMoon/SafeEvidence`
Canonical branch: `main`
Recovered `HEAD`: `5ccecd7688f1d10fa8474a697d6b6670d8eafec8` (`2026-11-09T04:52:06Z`)

Status words in this report apply strictly to engineering state. Nothing in this file claims clinical validation, patient safety, source-rights expansion beyond recorded founder decisions, release qualification, or regulatory approval.

---

## 1. Development Host Authorization

The handoff prompt initially specified macOS for local development. Inspection of the active workstation established:

- Host OS: Windows 11 (`x86_64-pc-windows-msvc`, host `Abdulaziz`).
- Prior local SafeEvidence checkouts on `C:` and `D:`: none (`0` pre-existing checkouts, worktrees, stashes, or uncommitted files existed to lose).
- Explicit founder override on `2026-11-26T16:00:55+03:00`: `"use this pc , dont use mac"`.
- Active local checkout cloned cleanly at `C:\Users\Shehr\.gemini\antigravity\scratch\SafeEvidence` with Cargo build artifacts isolated off-tree (`CARGO_TARGET_DIR=D:\safeevidence-target`) to preserve disk headroom and clean-tree SBOM invariants.
- Hosted GitHub Actions across `ubuntu-latest`, `ubuntu-24.04`, `windows-latest`, and `macos-15` remain mandatory cross-platform verification gates for every PR and `main` merge.

---

## 2. Git & GitHub State at Recovery

### 2.1 Git state

| Property | Observed value |
|---|---|
| `origin` | `https://github.com/TheHalfMoon/SafeEvidence.git` (fetch & push) |
| `HEAD` (`main`) | `5ccecd7688f1d10fa8474a697d6b6670d8eafec8` |
| Local vs `origin/main` | Identical (`0` ahead, `0` behind) |
| Tags | `plan-v1.0.0` |
| Worktrees / stashes / untracked | Clean (`1` worktree, `0` stashes, `0` untracked files) |
| Commit signing | SSH (`gpg.format=ssh`, `commit.gpgsign=true`, verified GitHub signing key) |

### 2.2 Delta from `docs/IMPLEMENTATION_LEDGER.md` (`dcbf3f3`) to `HEAD` (`5ccecd7`)

`docs/IMPLEMENTATION_LEDGER.md` was last updated at `dcbf3f3e425081e459a676ec5d085259c868e68c` (`2026-11-07`) in its header table while several defect notes inside the file already referenced commits through `2026-11-09`. Commits on `main` after `dcbf3f3` through `5ccecd7` include:

- Linux Secret Service isolation into `safeevidence-linux-keyring-helper` over `stdin`/`stdout` (`ADM-0009`) and `tauri.linux.conf.json` external-binary staging.
- WebView data-directory residue tripwire scans (`ask_e2e.mjs`, `ask_e2e_linux.mjs`).
- Linux `strace -ff` socket/DNS capture (`tools/ci/network_trace_report.py`) on both `e2e` and shipped-style desktop builds.
- Windows WebView2 background-service suppression switches (`WEBVIEW2_ARGS` in `product/apps/desktop/src-tauri/src/main.rs`), `netstat` socket polling (`tools/ci/windows_socket_poll.ps1`, `tools/ci/windows_socket_report.py`), Ubuntu 24.04 pin for `webkit2gtk-driver` (PR #90, `f10fe80`), and loopback port-80 zero-byte listener verification during idle and Ask execution (PR #89, `5ccecd7`).

### 2.3 GitHub Issues, Pull Requests, Releases, and Branch Protection

- **Open Issues:**
  - [#3](https://github.com/TheHalfMoon/SafeEvidence/issues/3): P01 phase ownership and entry authorization (`EXT-04`).
  - [#4](https://github.com/TheHalfMoon/SafeEvidence/issues/4): Clinical intended-use and evaluation charter (`EXT-03`).
  - [#5](https://github.com/TheHalfMoon/SafeEvidence/issues/5): Exact-source rights and release trust (`EXT-01`, `EXT-05`, `EXT-08`), including founder D2/D4 decisions (`#5#issuecomment-6647500204`) authorizing `T01`, `T03`, `T11`, `T12`, `T13`, `T30`, `T36` as rights owner and `T17` + crates via their public-license route.
  - [#17](https://github.com/TheHalfMoon/SafeEvidence/issues/17): G01a independent technical review (`EXT-06`) and `EXT-02` implementation ratifications (`#17#issuecomment-6647499829`).
- **Open Pull Requests:**
  - [#43](https://github.com/TheHalfMoon/SafeEvidence/pull/43): `security: add coordinated security disclosure policy` — remains open and unmerged pending authenticated independent human review.
- **Published GitHub Releases:** `0` (none).
- **Branch Protection on `main`:**
  - `required_signatures: true`, `enforce_admins: true`, `strict: true`, `required_conversation_resolution: true`, `allow_force_pushes: false`.
  - 13 required status checks: `foundation-documents`, plus `preentry structure`, `synthetic-only`, `product`, and `desktop` across `ubuntu-latest`, `windows-latest`, and `macos-15`.
  - 2 additional E2E workflows: `Desktop End-to-End` (`windows-latest`) and `Desktop End-to-End Linux` (`ubuntu-24.04`).

---

## 3. Baseline Verification & Newly Surfaced Advisory Defect

Local baseline verification at `5ccecd7688f1d10fa8474a697d6b6670d8eafec8` produced:

| Check | Result |
|---|---|
| `python -m unittest discover -s tools/governance/tests -v` | `PASS` (`202` run, `21` symlink tests skipped on Windows) |
| `python tools/governance/plan_baseline_check.py` | `PASS` (`FROZEN`) |
| `python tools/governance/p01_preentry_check.py --expected-sha 5ccecd7...` | `PASS` (`P01-G01` `BLOCKED`) |
| `python tools/governance/p01_candidate_integrity.py` | `PASS` (`11` candidates, `source_imports` `BLOCKED`) |
| `python tools/governance/g01a_synthetic_check.py` | `PASS` |
| `python tools/governance/source_admission_check.py` | `PASS` |
| `python tools/governance/donor/tool_audit.py` | `PASS` (`12` files) |
| Root G01a `cargo +1.97.1 test --offline --locked --workspace --all-targets` | `PASS` (`3/3`) |
| Desktop frontend `npm ci --ignore-scripts && npm test && npm run build` | `PASS` (`15/15` tests, Vite bundle built) |
| `cargo deny --offline check` (`product/` and `src-tauri/`) | **`FAIL` (`RUSTSEC-2026-0459` on `libsqlite3-sys 0.38.2`; plus `RUSTSEC-2026-0594` on `cookie 0.18.2` and `RUSTSEC-2026-0592` on `url 2.5.8` in `src-tauri/`)** |

### Analysis of Post-Baseline RustSec Advisories

- `RUSTSEC-2026-0594` (`cookie 0.18.2`) and `RUSTSEC-2026-0592` (`url 2.5.8` nested `blob:` stack overflow) in `product/apps/desktop/src-tauri/Cargo.lock`: resolved directly in PR 1 by upgrading `cookie` to `0.18.3` and `url` to `2.5.9` (`form_urlencoded 1.2.3`).
- `RUSTSEC-2026-0459` (`CVE-2026-119375`, published after the `2026-11-09` CI green run): SQLite versions prior to `3.54.0` can return uninitialized page-cache memory when opening a database alongside a sibling `-wal` file whose header page size differs from the database page size.
- Upgrading `rusqlite`/`libsqlite3-sys` to `>= 0.39` pulls in `sqlcipher-src` `419.0.6` (which still bundles SQLite `3.53.4 < 3.54.0`) under `MIT AND BSD-3-Clause AND blessing AND WTFPL`, violating SafeEvidence's approved SPDX license allowlist (`WTFPL` and `blessing` are unadmitted) and breaking the audited `T03` runtime identity pin (`SQLCipher 4.14.0 community` / `SQLite 3.51.3`).
- Remediation implemented in PR 1: enforce a fail-closed pre-open filesystem guard in `safeevidence-vault` (`open_reviewed_connection`, `stage_sqlcipher_generation`, and `key_opens_healthy_database`) that inspects `<db>` and any sibling `<db>-wal` header (`0..32`, plaintext in SQLCipher 4) via lossless `OsString` paths before SQLite opens the database, rejecting symlinks/non-files, non-empty `-wal` files shorter than `32` bytes, and any `-wal` header carrying a page size other than `4096` bytes, while pinning codec `cipher_page_size == 4096` (so `sqlite3Codec` HMAC-SHA512 zeroes unauthenticated 4096-byte page buffers on read), paired with adversarial regression tests and scoped `deny.toml` advisory documentation (`safeevidence-ask` uses only `Connection::open_in_memory()`).

---

## 4. Authorized Engineering Queue vs External Gates

### Authorized engineering execution order (`EXT-02` + Issue #5 D2 + `GREENFIELD_JUSTIFIED` §5)

1. **Priority A — Complete M0 Admission & Supply-Chain Controls:**
   - Mitigate `RUSTSEC-2026-0459` in `safeevidence-vault` + `deny.toml`.
   - Resolve `plan-v1.1` B6 crate-closure records (`ADM-0010` `CRATE-product-cargo`, `ADM-0011` `CRATE-desktop-cargo`, `ADM-0012` `CRATE-desktop-npm`) in `source_admission_check.py`, `source_admissions.json`, and `THIRD_PARTY_NOTICES.md`.
   - Extend `safeevidence-release` (`TA-02` CycloneDX 1.5 SBOM) to cover `product/apps/desktop/src-tauri/Cargo.lock` native/Rust dependencies and `product/apps/desktop/package-lock.json` npm packages.
   - Harden `T30` `tool_audit.py` and update `p01_preentry_check.py` so issue-bound owner assignments do not break CI while keeping `p01_g01_activation = "BLOCKED"`.
   - Gate `T01` inert contract defects (`scale_corpus_generator_present: false` and proposal-only `confidence` rejection on assured V1 surfaces).
2. **Priority A/C — Separate Vault Cryptographic Domains & Harden Durability:**
   - Replace `HIMSAT/...` with 6-byte `SAFEVD/...` domain constants across `safeevidence-vault` and `safeevidence-linux-keyring-helper` without shifting fixed wire offsets, recompute independent non-Rust test vectors, prove cross-product envelope rejection, isolate desktop store directory keys by domain version, and expand `TA-05` reopen/contention/restore durability tests.
3. **Priority B — Finish M1 VS-1 Synthetic Ask Journey & Exit Reviews:**
   - Add append-only `assertions` lineage and superseding-free retraction in `safeevidence-proofstore` (`plan-v1.3`).
   - Verify `EvidenceSpan` bounds against stored source bytes on commit and reconcile `CommitUnknown` idempotently in `ask_command.rs`.
   - Complete all Ask outcomes (`ANSWER`, `ANSWER_WITH_CAUTION`, `ASK_MORE` only when missing population can change the decision, `CONFLICT`, `ABSTAIN`, `ESCALATE`, `BLOCKED`), expose typed exclusion reason codes in the UI, expand WebView2/WebKitGTK E2E checks, and execute M0 + M1 exit reviews.
4. **Priority C/D/F — Privacy, Localization, Accessibility, Evidence V1, Deep Review & SafeEvidenceBench:**
   - Qualify EN/AR bilingual UI localization, RTL rendering, keyboard/ARIA/contrast accessibility (`TA-22`), and local privacy probes (`TA-20`).
   - Implement authorized `GREENFIELD_JUSTIFIED` M2/M3/M4 subsystems (`SOURCE_TRANSPLANT_MATRIX_V1.md` §5): multi-report study deduplication & overlap guard (`WP-05`, `TA-07`), deterministic validity delta overlay & living alerts (`WP-04`/`WP-17` synthetic/overlay subset, `TA-06`/`TA-19`), Arabic normalization & harder BM25 benchmark (`WP-06`/`WP-07`, `TA-08`/`TA-09`), deterministic numeric/unit/negation claim verifier (`WP-08`, `TA-10`), GRADE/RoB structured appraisal with human confirmation (`WP-10`, `TA-12`), SafeEvidence-owned protocol/audit & quote-anchored extraction proposal contracts (`WP-14` protocol slice, `WP-15`, `TA-17`; while `T15` `litdb` screening/PRISMA and `WP-23a`/`T18`/`T19` worker slices remain `BLOCKED_EXTERNAL` under `EXT-01`), full multi-pane Desktop workstation (`WP-18`), and reproducible `SafeEvidenceBench` synthetic harness (`WP-20`, `TA-23`) + resource baseline (`WP-M0`).

### Unresolved external gates (`BLOCKED_EXTERNAL` — never fabricated)

- `EXT-01` / Issue #5: Founder donor slices outside D2 (`T05`, `T07`, `T09`, `T10`, `T14`, `T15`, `T16`) and non-synthetic medical corpora.
- `EXT-03` / Issue #4: Signed clinical intended-use and evaluation charter.
- `EXT-04` / Issue #3: Named human sign-off across the 41 P00 P1 findings.
- `EXT-05` / Issue #5: Release-pack/installer signing keys and trust ceremony.
- `EXT-06` / Issue #17 & PR #43: Authenticated independent human review of G01a and coordinated security disclosure policy.
- `EXT-07`: Approved local model weights and licenses.
- `EXT-09`: Regulatory/compliance review and clinical deployment authorization.

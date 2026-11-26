# SafeEvidence Measured Runtime Budget Baseline (`WP-M0` / `TA-M0`)

Status: `SYNTHETIC_BASELINE_MEASURED` (`EXT-02` synthetic scope; non-clinical)
Date: `2026-11-26`
Policy authority: `docs/RUNTIME_BUDGET.md` (section 5 Desktop baseline & section 8 Candidate promotion)

## 1. Scope and Honesty Boundary

`docs/RUNTIME_BUDGET.md` section 5 specifies:

> *"The desktop architecture is optimized first for a CPU-only 16 GB-class machine. Exact latency/RAM/disk targets are frozen after measurement, not invented in planning."*

This document records the measured synthetic desktop and benchmark resource baseline on a 16 GB-class CPU-only Windows 11 workstation for the `EXT-02` synthetic build (FTS5 BM25 retrieval, deterministic claim verification, SQLCipher `4.14.0` + OpenSSL `3.6.3` encrypted proof store under real Windows DPAPI, Tauri `2.12.0` + React `19.3.0` multi-pane bilingual workstation).

**Important scope limits:**
- These measurements cover the **synthetic, deterministic, model-free** runtime (`VS-1a` + `M2`/`M3`/`M4` greenfield contracts and workstation panes).
- Local ONNX / LLM / OCR worker memory, thermal, and latency budgets (`MedCPT`, `SciFact` cross-encoder, `PaddleOCR`, `llama.cpp`) remain **`BLOCKED_EXTERNAL`** on `EXT-01` + `EXT-07` + `WP-23a` and must be re-measured before promoting any neural challenger (`docs/RUNTIME_BUDGET.md` section 4, section 8, section 10).

---

## 2. Reference Measurement Environment

| Attribute | Measured Value |
|---|---|
| CPU | 13th Gen Intel Core i5-13420H (8 cores / 12 logical processors, CPU-only path) |
| Physical RAM | `15.7 GiB` (16 GB-class target per `docs/RUNTIME_BUDGET.md` section 5) |
| Operating System | Microsoft Windows 11 Home (Build `26300`) |
| WebView Runtime | Microsoft Edge WebView2 Runtime `158.0.4370.45` |
| Rust Toolchain | `1.98.1` (`product/rust-toolchain.toml`, locked offline build) |
| Frontend Toolchain | Node.js `v24.19.0`, TypeScript `7.0.2`, Vite `8.3.1` |
| Network Mode | `NETWORK_LOCKED` (`--offline` build; WebView2 background services disabled via `WEBVIEW2_ARGS`; strict CSP `default-src 'none'`) |

---

## 3. Measured Desktop & Benchmark Metrics (`TA-M0`)

| Metric | Build / Profile | Measured Value | Proposed Synthetic Ceiling (`section 5` Baseline) |
|---|---|---|---|
| Shipped-profile desktop binary (`safeevidence-desktop.exe`) | `--release --features custom-protocol` (embeds frontend `dist/`, SQLCipher `4.14.0`, OpenSSL `3.6.3`) | `14,681,600 B` (`14.00 MiB`) | `<= 25 MiB` |
| Debug E2E desktop binary (`safeevidence-desktop.exe`) | `dev` `--features custom-protocol,e2e` | `21,931,520 B` (`20.92 MiB`) | `<= 35 MiB` |
| Frontend production asset bundle (`dist/`) | `tsc --noEmit && vite build` (uncompressed raw / gzipped) | `252,249 B` (`246.3 KiB` raw / `~78.6 KiB` gzip) | `<= 512 KiB` raw |
| Encrypted local vault footprint after proof commit | `vault.db` + WAL + Windows `dpapi` key blob + `vault-identity.bin` + `store-established` | `296,853 B` (`289.9 KiB`) | `<= 2 MiB` (synthetic fixture store) |
| Cold offline launch to interactive `#question` DOM | Spawn -> WebView2 page ready (`#question` interactive) | `2,503.9 ms` (`2.50 s`) | `<= 5,000 ms` |
| Cold first-commit `ask_question` IPC round-trip | DPAPI root-key creation + SQLCipher `ProofStore::open` + FTS5 BM25 + durable `commit` + readback | `41.3 ms` | `<= 250 ms` |
| Warm `ask_question` IPC round-trip (`n = 30`) | Full Ask guards + FTS5 BM25 + durable replay readback + citation span extraction | `p50 = 3.8 ms`, `p95 = 5.1 ms`, `max = 6.3 ms` | `p95 <= 25 ms` |
| Warm `workstation_overview` IPC round-trip (`n = 30`) | Corpus linkage + locked `ReviewProtocol` + hash-chained audit bundle + quote-anchored extractions + GRADE validation + admissible pack build | `p50 = 3.3 ms`, `p95 = 4.3 ms`, `max = 4.3 ms` | `p95 <= 25 ms` |
| Native Rust Tauri host working set (RSS) | `safeevidence-desktop.exe` (`--release --features custom-protocol`) | `25.58 MiB` | `<= 64 MiB` |
| Total desktop + WebView2 process-tree working set (RSS) | `safeevidence-desktop.exe` + child `msedgewebview2.exe` processes (`incognito(true)`) | `364.70 MiB` | `<= 600 MiB` |
| `SafeEvidenceBench` full 6-split evaluation (`TA-23`) | `cargo run --release -p safeevidence-ask --bin safeevidence_bench` (incl. 20,000 bootstrap resamples) | `2,975 ms` (`2.98 s`) | `<= 15,000 ms` |

---

## 4. Candidate Promotion Baseline (`docs/RUNTIME_BUDGET.md` section 8)

For the incumbent synthetic lexical + deterministic stack:
- **Correctness / task metric:** `TA-09` hard-set BM25 `nDCG@10 = 0.4146` (`95% CI [0.3611, 0.4732]`), `study-level recall@50 = 0.9852` (`95% CI [0.9729, 0.9951]`); `TA-10` deterministic perturbation flag rate `1.0000` (`25/25`); `TA-08` parallel EN/AR `recall@20` ratio `1.0000`; `TA-07` study dedup `precision = recall = 1.0000`.
- **Latency:** `p50 = 3.8 ms` / `p95 = 5.1 ms` warm Ask IPC; `41.3 ms` cold vault-initializing Ask IPC.
- **Peak RSS:** `25.58 MiB` Rust host / `364.70 MiB` total WebView2 process tree.
- **Disk / artifact size:** `14.00 MiB` release executable; `289.9 KiB` initialized encrypted vault store.
- **Startup cost:** `2.50 s` cold offline WebView2 start.
- **License / redistribution:** 100% allowlisted SPDX closure (`ADM-0010`..`ADM-0012`, `613` CycloneDX 1.5 SBOM components).
- **Failure & offline behavior:** 100% offline (`NETWORK_LOCKED`), zero silent model or corpus downloads, fail-closed `TerminalOutcome` + `ReasonCode` on every storage/verification fault.

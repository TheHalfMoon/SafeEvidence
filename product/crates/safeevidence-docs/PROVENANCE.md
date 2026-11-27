# `safeevidence-docs` Provenance

- **Admission:** `ADM-0020` (`T16`) + SafeEvidence-owned native deterministic PDF extractor (`src/native_pdf.rs`)
- **Upstream Donor (`T16`):** `AbdulazizShehri/safeOCR` @ `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4` (`Apache-2.0`; verbatim `LICENSE` and `NOTICE` preserved in `tests/fixtures/t16/`)
- **Authorization Basis:** `PUBLIC_LICENSE` under `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`
- **Adaptations:** Ported `contracts.py`, `verification.py`, `report.py`, `test_foundation_contracts.py`, and `test_verification.py` into `#![forbid(unsafe_code)]` safe Rust (`ocr.py` / `test_ocr_adapters.py` excluded per F11), paired with SafeEvidence-owned `native_pdf.rs` (bounded RFC 1950/1951 `FlateDecode` decompression + hostile-PDF intake pre-gate + bilingual EN/AR Unicode scalar page spans + degraded-scan abstain gate, `TA-15`).

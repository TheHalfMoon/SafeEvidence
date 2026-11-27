# `safeevidence-review` Provenance

- **Admissions:** `ADM-0019` (`T15`) and `ADM-0021` (`T18`)
- **Upstream Donors:**
  1. `ADM-0019` (`T15`): `TheHalfMoon/MedOrigin` @ `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8` (`Apache-2.0`) — adapted `src/medscale/litdb/{records,screening,dedupe,review}.py` and `tests/test_litdb_{dedupe,review}.py` into `#![forbid(unsafe_code)]` Rust (`src/{records,screening,dedupe,prisma_review}.rs`, `tests/t15_litdb_{dedupe,prisma_review}.rs`).
  2. `ADM-0021` (`T18`): `asreview/asreview` @ `79d568212b2b0a78f9fd7be3c5117dfb890489f9` (`Apache-2.0`; verbatim `LICENSE` preserved in `tests/fixtures/t18/LICENSE`) — adapted `asreview/metrics.py`, `asreview/models/{classifiers,queriers,stoppers}.py`, and `asreview/simulation/simulate.py` into `#![forbid(unsafe_code)]` Rust (`src/{active_metrics,classifiers,queriers,stoppers}.rs`, `tests/t18_asreview_screening.rs`) with zero scikit-learn/Python runtime dependencies and mandatory human stopping-rule enforcement (`TA-16`).
- **Authorization Basis:** `PUBLIC_LICENSE` under `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`

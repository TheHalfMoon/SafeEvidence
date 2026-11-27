# `safeevidence-meta` Provenance

- **Admission:** `ADM-0022` (`T19`)
- **Upstream Donor:** `statsmodels/statsmodels` @ `b7ec3a7c1a448ed79d75489da4cde6c304c79a21` (`BSD-3-Clause`, Copyright (C) 2006, Jonathan E. Taylor; Copyright (c) 2006-2008 Scipy Developers; Copyright (c) 2009-2018 Developers of statsmodels; Josef Perktold)
- **Authorization Basis:** `PUBLIC_LICENSE` under `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`
- **Adaptations:** Ported `statsmodels/stats/meta_analysis.py` (`src/lib.rs`) and `statsmodels/stats/tests/test_meta.py` (`tests/t19_meta_analysis.rs`) into `#![forbid(unsafe_code)]` pure safe Rust with zero Python/NumPy/SciPy runtime dependencies, paired with SafeEvidence's mandatory `decide_pooling` (`P00_STUDY_INDEPENDENCE_CONTRACT`, `TA-07`, `TA-18`) pre-gate refusing duplicate study reports, overlapping participant cohorts, and secondary syntheses before pooling.

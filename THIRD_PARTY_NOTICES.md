# SafeEvidence Third-Party Notices

Status: `FOUNDATION_INVENTORY`

SafeEvidence is licensed under Apache-2.0 for SafeEvidence-owned code unless an
individual file or component states otherwise.

This file is the public aggregation point for third-party code, libraries,
model artifacts, datasets, terminology, fonts, document assets, and other
redistributed material that require attribution or additional notices.

Planning/admission authority is recorded separately in
`docs/DONOR_RIGHTS_REGISTER.md`. A founder permission assertion is not itself
a substitute for the exact public license or documentary grant required by an
individual external source.

## Rules

1. Permission or an open-source repository license makes a source eligible for
   review; it does not make every nested dependency, model, dataset, font, or
   asset redistributable.
2. Every admitted copied/vendored component must record exact repository,
   revision, source paths, original license/permission basis, modifications,
   required notices, transitive material, and removal/update strategy.
3. Runtime dependencies remain under their own licenses and must be represented
   in the generated SBOM/notice bundle.
4. Model weights and datasets are reviewed independently from the repository
   source-code license.
5. Licensed medical terminology and copyrighted literature are never covered
   merely because adapter code is open source.
6. This file must describe what ships. Planning candidates are recorded in
   `docs/SOURCE_LEDGER.md`, not falsely listed here as distributed components.

## Currently distributed third-party material

None. SafeEvidence is still in P00 foundation planning.

This section must be updated as part of the first source-admission/transplant PR.


## Reconciliation admission rule

Before any third-party bytes are copied or redistributed, the exact slice must
have an allowed disposition in `docs/DONOR_RIGHTS_REGISTER.md`.

Code rights do not automatically cover:
- model weights;
- datasets;
- publication text/abstracts;
- medical terminology;
- fonts/assets;
- native binaries;
- transitive vendored code.

Copyleft/custom sources remain under their actual terms unless a separately
verified permission/relicense record is attached.

## P00 repair admission freeze

The discovery table in the source ledger is not an allowlist. The exact
component import ledger in `docs/DONOR_RIGHTS_REGISTER.md` is empty at P00:
no third-party component is claimed to have been copied as part of this
documentation repair.

A founder-stated permission alone does not certify other rightsholders'
code or nested assets. If permission evidence is pending, code copying and
distribution must wait. No source is silently relicensed into Apache-2.0.

## Admitted copied components

| Admission | Component | Source | License | Destination |
|---|---|---|---|---|
| ADM-0001 | T01 contracts | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/crates/safeevidence-contracts` |
| ADM-0002 | T11 `deny.toml` and SBOM generator (adapted) | same revision | Apache-2.0 | `product/deny.toml`, `product/crates/safeevidence-release` |
| ADM-0003 | T03 private vault | `TheHalfMoon/ottari` @ `73706029849bcbe51243624e37f03a1969dc74ca` | Apache-2.0 | `product/crates/safeevidence-vault` |
| ADM-0004 | T17 span logic, fixtures, and audit tests (Rust port + fixtures) | `maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86` | Apache-2.0 | `product/crates/safeevidence-contracts` |
| ADM-0005 | T13 precedence mechanics (port, generated vectors and fixture question texts) | `TheHalfMoon/commandMed` @ `51f73ec05750137e5bd94ffa0765f6383f475fee` | Apache-2.0 | `product/crates/safeevidence-assurance` |
| ADM-0006 | T36 desktop shell (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/apps/desktop` |
| ADM-0007 | T12 privacy probes, doctor axes, and hostile-MIME tests (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/tests/privacy` |
| ADM-0008 | T30 tool-source audit (adapted) | `TheHalfMoon/ottari` @ `73706029849bcbe51243624e37f03a1969dc74ca` | Apache-2.0 | `tools/governance/donor/tool_audit.py` |
| ADM-0009 | T03 Linux Secret Service calls, as a helper process (adapted) | `TheHalfMoon/ottari` @ `73706029849bcbe51243624e37f03a1969dc74ca` | Apache-2.0 | `product/crates/safeevidence-linux-keyring-helper` |
| ADM-0010 | Product Rust dependency closure (`CRATE-product-cargo`, 181 packages) | `crates.io` (`product/Cargo.lock`) | SPDX allowlist (`product/deny.toml`) | `product/Cargo.lock` |
| ADM-0011 | Desktop Rust dependency closure (`CRATE-desktop-cargo`, 464 packages) | `crates.io` (`product/apps/desktop/src-tauri/Cargo.lock`) | SPDX allowlist (`product/apps/desktop/src-tauri/deny.toml`) | `product/apps/desktop/src-tauri/Cargo.lock` |
| ADM-0012 | Desktop npm dependency closure (`CRATE-desktop-npm`, 82 packages; `--ignore-scripts`) | `registry.npmjs.org` (`product/apps/desktop/package-lock.json`) | MIT, Apache-2.0, Apache-2.0 OR MIT, BSD-3-Clause, ISC, MPL-2.0 | `product/apps/desktop/package-lock.json` |
| ADM-0015 | T05 network broker, SSRF URL/IP defense, and `TA-30` preview receipt (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/crates/safeevidence-contracts`, `product/crates/safeevidence-network` |
| ADM-0016 | T07 content-addressed Pack v0 format, store, and monotonic anti-rollback (adapted; `runtime.rs` excluded) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/crates/safeevidence-contracts`, `product/crates/safeevidence-pack` |
| ADM-0017 | T09 FHIR R4 lexical gate, UCUM subset pin, and closed extractors for synthetic research fixtures (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/crates/safeevidence-contracts`, `product/crates/safeevidence-fhir` |
| ADM-0018 | T10 OS worker sandbox plans, probes, and deny-by-default supervision policy (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/crates/safeevidence-contracts` |
| ADM-0019 | T15 PRISMA 2020 screening log replay and 2-pass conflict-safe bibliographic deduplication (Rust port) | `TheHalfMoon/MedOrigin` @ `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8` | Apache-2.0 | `product/crates/safeevidence-review` |
| ADM-0020 | T16 SafeOCR critical-number, decimal, unit, and negation verification (Rust port + verbatim notices) | `AbdulazizShehri/safeOCR` @ `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4` | Apache-2.0 | `product/crates/safeevidence-docs` |
| ADM-0021 | T18 ASReview active-learning screening classifiers, queriers, stoppers, and `WSS@95` metrics (Rust port + verbatim LICENSE) | `asreview/asreview` @ `79d568212b2b0a78f9fd7be3c5117dfb890489f9` | Apache-2.0 | `product/crates/safeevidence-review` |
| ADM-0022 | T19 quantitative meta-analysis (`Hedges' g`, `DL`, `Paule-Mandel`, `HKSJ`, `I^2`, prediction interval; Rust port) | `statsmodels/statsmodels` @ `b7ec3a7c1a448ed79d75489da4cde6c304c79a21` | BSD-3-Clause | `product/crates/safeevidence-meta` |
| ADM-0030 | T27 SciFact benchmark-only sentence/abstract F1 evaluator (stdlib port + verbatim LICENSE.md; never shipped in product) | `allenai/scifact` @ `68b98a56d93e0f9da0d2aab4e6c3294699a0f72e` | Apache-2.0 | `bench/scifact` |
| ADM-0032 | T28 Evidence-Inference benchmark-only PICO span & 3-class macro-F1 evaluator (stdlib port + verbatim LICENSE; never shipped in product) | `jayded/evidence-inference` @ `a661e8c14f973398380c8865cf2f27a535aaaf6d` | MIT | `bench/evidence_inference` |

Runtime Rust and npm dependencies keep their own licenses. `product/Cargo.lock`,
`product/apps/desktop/src-tauri/Cargo.lock`, and `product/apps/desktop/package-lock.json`
are the exact closures validated in CI by `source_admission_check.py`, `cargo deny check`,
and the CycloneDX 1.5 SBOM generator (`safeevidence-release`, TA-02).

Native code built into the vault through its Rust dependencies, each under its own license:
SQLCipher (BSD-style, via `libsqlite3-sys`) and OpenSSL (Apache-2.0, via `openssl-src`).

### BSD-3-Clause Notice for `ADM-0022` (`statsmodels/statsmodels`)

Copyright (C) 2006, Jonathan E. Taylor  
All rights reserved.  
Copyright (c) 2006-2008 Scipy Developers.  
All rights reserved.  
Copyright (c) 2009-2018 Developers of statsmodels  
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of statsmodels nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### MIT Notice for `ADM-0032` (`jayded/evidence-inference` — Benchmark-Only)

Copyright (c) 2019 Eric Lehman, Jay DeYoung, Regina Barzilay, Byron C. Wallace (`bench/evidence_inference/LICENSE`). Strictly confined to `bench/evidence_inference/` and never distributed in shipped binaries.

### Apache-2.0 Notices for `ADM-0021` (`asreview/asreview`) & `ADM-0030` (`allenai/scifact`)

- `asreview/asreview`: Copyright ASReview Developers (`product/crates/safeevidence-review/tests/fixtures/t18/LICENSE`, Apache-2.0).
- `allenai/scifact`: Copyright Allen Institute for AI (`bench/scifact/LICENSE.md`, Apache-2.0 for evaluator code; external claims CC-BY-4.0 and abstracts ODC-By-1.0 are not copied in-tree).

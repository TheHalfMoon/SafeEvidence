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
| ADM-0004 | T17 span fixture | `maziyarpanahi/openmed` @ `8440bdac59621981372d318f43c8bfb2d6625b86` | Apache-2.0 | `product/crates/safeevidence-contracts/tests/fixtures/t17` |
| ADM-0005 | T13 precedence mechanics (port and generated vectors) | `TheHalfMoon/commandMed` @ `51f73ec05750137e5bd94ffa0765f6383f475fee` | Apache-2.0 | `product/crates/safeevidence-assurance` |
| ADM-0006 | T36 desktop shell (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/apps/desktop` |
| ADM-0007 | T12 privacy probes (adapted) | `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` | Apache-2.0 | `product/tests/privacy` |

Runtime Rust dependencies keep their own licenses. `product/Cargo.lock` is the exact
closure; `cargo deny check` enforces the allowlist in `product/deny.toml` in CI. A
CycloneDX SBOM is generated and checked in CI (TA-02).

Native code built into the vault through its Rust dependencies, each under its own license:
SQLCipher (BSD-style, via `libsqlite3-sys`) and OpenSSL (Apache-2.0, via `openssl-src`).

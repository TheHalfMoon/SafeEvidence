# SafeEvidence Plan Freeze Manifest — V1

Freeze state: `FROZEN`

Baseline version: `plan-v1.0.0` (the annotated tag is applied to the final
freeze-record merge commit; the planning baseline merger is identified below).

Freeze tag: `plan-v1.0.0`
Freeze commit: `dfea5e59330a6cfda40da56b1a2c435fc1012a3b`

The **Freeze commit** field identifies the normal merge commit that introduced
the immutable planning artifacts, not the subsequent self-referential freeze
record commit. The annotated tag is placed on the freeze-record merge commit
after its required checks pass.

## 1. What a freeze means here

A freeze means no further fundamental architecture research or redesign is
required before beginning **authorized** implementation. It does **not** mean
source code has been imported, any feature is built, any benchmark has run, or
any clinical, rights, release or regulatory gate has passed. Changes to frozen
decisions require a versioned amendment (`plan-v1.x`), a stated reason, and
review under `docs/GAP_REVIEW.md`. Implementation-level choices inside a work
packet remain with the implementation team.

`FREEZE_PENDING` → `FROZEN` requires, on one exact commit:

1. `python tools/governance/plan_baseline_check.py --root .` → PASS (digests below match).
2. Existing required checks pass (P00 docs, P01 pre-entry ×3 OS, G01a ×3 OS).
3. Independent agent/automated review findings are documented and resolved.
   **Founder governance decision (2026-10-19): no human approving GitHub review is
   required for the planning freeze.** The human-review branch rule may be
   changed by the repository administrator; required CI and normal PR merges
   remain mandatory. This is an explicit policy change, not an approval review.
4. Normally merge the validated planning PR to `main` (record the merge SHA),
   then submit a small freeze-record PR changing this file to
   the freeze state to `FROZEN`, the freeze tag to `plan-v1.0.0`, and
   the baseline commit to the first planning PR merge SHA. After its CI passes,
   normally merge that record PR and push an annotated tag on its final merge
   commit. The tag therefore captures the **FROZEN manifest** as well as all
   the original content-digested planning artifacts.

This founder waiver concerns the **GitHub human-review requirement for the
planning freeze only**. It does not approve any donor import, model/data
license, clinical evaluation, regulatory claim, or release gate.

## 2. Frozen artifacts and content digests

SHA-256 over LF-normalized bytes (`plan_baseline_check.normalized_digest`).

| Artifact | SHA-256 |
|---|---|
| `docs/plan/SAFEEVIDENCE_MASTER_PLAN_V1.md` | `eb4ae242914ee1d90627d15890d0daf0eb9a539bd02823fc9809f30a88dc90c9` |
| `docs/plan/ARCHITECTURE_SPEC_V1.md` | `4404480e6f9e1edf6dd294fed89fef396bdef9c374fd1617520479278beb7283` |
| `docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md` | `77fce3380cba41fe273a79bc1f6e52794c771a7e2bdde5269cb4e8813ca7f915` |
| `docs/plan/FEATURE_COVERAGE_MATRIX_V1.md` | `ab45642209f1a4362fa1fd4f20410087c8fb72a4e5c598b4859d3af619b83605` |
| `docs/plan/IMPLEMENTATION_WORK_PACKETS_V1.md` | `93e42c265dd5b559566c57bdd961cb694e920d8dfd57105c7b9e2678ff894492` |
| `docs/plan/TEST_ACCEPTANCE_MATRIX_V1.md` | `d7257e79516344988204d931088f76896d42ffb561270e07d6d122397538f5e3` |
| `docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md` | `9ca6e847c09d92c27f3ced7e36faf0ede8eb28b2b667366c806f04f5f867d168` |
| `docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md` | `76fb45297e537af99a6ea8071b96e1641bfa5e2740ecd01c14bb85ebc966896b` |
| `docs/evidence/source_transplant_pins_2026-10-19.json` | `e1393814a2a1193da380ad382b58503be293e30ba63cd80d963f75a1dbaeb46b` |

Raw REA evidence: `docs/research/rea-2026-10-19-windows/SHA256SUMS` (7 REA JSON captures + browser observation log)
and PR #44's `docs/research/rea-2026-10-19/` (11 files).

## 3. Source pins and decisions

- 39 pinned transplant packets (T01–T36 incl. sub-packets) / 332 files pinned by Git blob OID (283 listed publicly; 49 in private repositories published only as SHA-256 commitments) at the heads
  observed 2026-10-19 (`docs/evidence/source_transplant_pins_2026-10-19.json`).
  Founder heads: MedScale `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, ottari
  `73706029849bcbe51243624e37f03a1969dc74ca`, commandMed
  `51f73ec05750137e5bd94ffa0765f6383f475fee`, DAL
  `e460e766566d233c79b1270d6e425cb2005d9514`, MedOrigin
  `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8`, SafeOCR
  `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4`, kernux
  `2085b6ed1121b1a94c66c076bdd6b578da4dad0d`, Morize
  `62fc04d01d398da93b4dacf0ab2f33e3f1440462`.
- Frozen architecture decisions D-01 … D-16: `docs/plan/ARCHITECTURE_SPEC_V1.md` §3.
- Conflict resolutions C1 … C21: `docs/plan/SAFEEVIDENCE_MASTER_PLAN_V1.md` §4.
- Admission state: **NO_ADMISSIONS** (unchanged; `docs/DONOR_RIGHTS_REGISTER.md`).

## 4. Readiness classification of every work packet

| Class | Meaning | Packets |
|---|---|---|
| `SPEC_READY_AWAITING_ADMISSION` | Fully specified; may start the moment its T## rights rows are `VERIFIED_ALLOWED` and the founder signs a synthetic-engineering scope extension beyond stdlib-only G01a | WP-00 … WP-20 (incl. WP-11a, WP-18a), WP-22, WP-23a, WP-23, WP-M0 |
| `SPEC_READY_AWAITING_CLINICAL` | Additionally needs Issue #4 charter and named owners | WP-21 (patient context); clinician holdouts inside WP-08 and WP-20; any real-PHI use |
| `SPEC_READY_AWAITING_TRUST` | Additionally needs release/key-custody owner | WP-24 |
| `DEFERRED` | Planned, outside V1 | P13 computable guidelines, P17 sync, P19 voice, citation-context signal |
| Authorized today | Only the existing G01a synthetic stdlib baseline and documentation work | — |

## 5. External approvals and qualification dependencies (not closable by engineering)

| ID | Dependency | Owner needed | Evidence that closes it | Blocks |
|---|---|---|---|---|
| EXT-01 | Per-slice rights admission for VS-1 donors and crates | Rights owner (Issue #5) | Signed `VERIFIED_ALLOWED` rows citing a non-sensitive grant reference; confidential documents stay private | all WPs |
| EXT-02 | Synthetic-engineering scope extension beyond stdlib-only G01a (dependencies + founder-owned copies, synthetic data only) | Founder + accountable engineering owner (Issue #17 pattern) | Signed governance PR re-pinning G01a manifest/toolchain (C16) | WP-01 onward |
| EXT-03 | Intended-use wedge, clinical evaluation charter, adjudicator recruitment | Founder + qualified clinical safety owner (Issue #4) | Signed charter | clinical holdouts, WP-21, any clinical release |
| EXT-04 | Owners for the 41 original P1 findings | Phase owners (Issue #3) | Named owner per row in `P01_P1_GATE_TRACKER` | P01 closure |
| EXT-05 | Pack/app signing key custody, TUF roles | Release/security owner (Issue #5) | Signed key-custody record | WP-24 |
| EXT-06 | Independent technical review of G01a | External reviewer (Issue #17) | Review report | P01 closure |
| EXT-07 | Model-weight terms: MedCPT (`license: other`), PaddleOCR models, MultiVerS checkpoint, generator weights | Rights owner | Model-card review rows | WP-07, WP-08, WP-12, WP-13 |
| EXT-08 | Public-repo disclosure: this baseline states the private status of DAL, ottari, kernux, Morize, Inercative, Signthos, Wispral, Sentrdel and Ecra and publishes their pinned commit SHAs; path-level pins for those repositories are **withheld** (public SHA-256 commitments only; full list is a founder-held private record). Identities were already public in `SOURCE_LEDGER.md`; other private repositories inspected are not named | Founder | **APPROVED 2026-10-19** by the founder in the planning session: "EXT-08 approved: PR #45 may state the private repositories' status and commit SHAs with file paths withheld." | — (closed) |
| EXT-09 | Regulatory determination for any jurisdiction | Regulatory owner | Not planned for V1 | any clinical marketing |

Optional research follow-ups (do not block the freeze): REA-FOLLOWUP-01..06
authenticated observations of OpenEvidence, Elicit, GRADEpro, Scite, DynaMed
and Consensus Medical Mode by an authorized account holder
(`docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md` §5).

## 6. Review evidence bound to this baseline

`docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md` (independent
reviewer report, Alibaba Open Code Review delegation run, d1-local advisory
triage, baseline checker and unit-test results, and the fix log).

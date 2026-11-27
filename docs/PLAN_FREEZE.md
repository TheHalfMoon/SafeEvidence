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

Amendments, by pointer: `docs/plan/PLAN_AMENDMENT_V1_1.md` (`plan-v1.1`), `docs/plan/PLAN_AMENDMENT_V1_2.md` (`plan-v1.2`), `docs/plan/PLAN_AMENDMENT_V1_3.md` (`plan-v1.3`), `docs/plan/PLAN_AMENDMENT_V1_4.md` (`plan-v1.4`), `docs/plan/PLAN_AMENDMENT_V1_5.md` (`plan-v1.5`), `docs/plan/PLAN_AMENDMENT_V1_6.md` (`plan-v1.6`), `docs/plan/PLAN_AMENDMENT_V1_7.md` (`plan-v1.7`).

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
| `docs/plan/SAFEEVIDENCE_MASTER_PLAN_V1.md` | `08270459493dbe9fc50ca1d9795d7baa0a8f8b848a06dbcbb5bd61d5b5dff37c` |
| `docs/plan/ARCHITECTURE_SPEC_V1.md` | `bead21326756d67ca9af6fb4eac9b88974d8a379db78873028cab5697434ada5` |
| `docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md` | `52ff15f82266bd947f65a099994cde0293e7bd405ddb29639fc9d16e916a190e` |
| `docs/plan/FEATURE_COVERAGE_MATRIX_V1.md` | `8c16e902acbca091d7c2d2eab4ae9f47704828e130426966404111141c824152` |
| `docs/plan/IMPLEMENTATION_WORK_PACKETS_V1.md` | `dbf930ff60246cb041fe24272b36b9866220076c435bbddd59dc53dd330bf728` |
| `docs/plan/TEST_ACCEPTANCE_MATRIX_V1.md` | `8571fb86bd5e58a6c57fb360ebc061e0c12cc54d64b1292e022156cbc00351f8` |
| `docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md` | `9ca6e847c09d92c27f3ced7e36faf0ede8eb28b2b667366c806f04f5f867d168` |
| `docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md` | `76fb45297e537af99a6ea8071b96e1641bfa5e2740ecd01c14bb85ebc966896b` |
| `docs/evidence/source_transplant_pins_2026-10-19.json` | `9f1cba22b4ab069209ef439cb01459d9689be68d6e2e7e87c61540481a69879e` |

Raw REA evidence: `docs/research/rea-2026-10-19-windows/SHA256SUMS` (7 REA JSON captures + browser observation log)
and PR #44's `docs/research/rea-2026-10-19/` (11 files).

## 3. Source pins and decisions

- 38 pinned transplant packets (T01–T36 incl. sub-packets; `T14` / `DAL` permanently removed per 2026-11-27 Founder Directive `plan-v1.7`) / 327 files pinned by Git blob OID (283 listed publicly; 44 in private repositories published only as SHA-256 commitments) at the heads
  observed 2026-10-19 (`docs/evidence/source_transplant_pins_2026-10-19.json`).
  Founder heads: MedScale `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, ottari
  `73706029849bcbe51243624e37f03a1969dc74ca`, commandMed
  `51f73ec05750137e5bd94ffa0765f6383f475fee`, MedOrigin
  `ec8b1b6f7392b09ecbb023600b3a83cfff6f14a8`, SafeOCR
  `d2e2ea815b17a7a3f0e59ce43dbdd160966e73a4`, kernux
  `2085b6ed1121b1a94c66c076bdd6b578da4dad0d`, Morize
  `62fc04d01d398da93b4dacf0ab2f33e3f1440462` (`DAL` permanently removed per `plan-v1.7`).
- Frozen architecture decisions D-01 … D-16: `docs/plan/ARCHITECTURE_SPEC_V1.md` §3.
- Conflict resolutions C1 … C21: `docs/plan/SAFEEVIDENCE_MASTER_PLAN_V1.md` §4.
- Admission state at freeze: **NO_ADMISSIONS** (`docs/DONOR_RIGHTS_REGISTER.md`). Later
  product rows: `docs/evidence/source_admissions.json`.

## 4. Readiness classification of every work packet

| Class | Meaning | Packets |
|---|---|---|
| `SPEC_READY_AWAITING_ADMISSION` | Fully specified; may start the moment its T## rights rows are `VERIFIED_ALLOWED` and the founder signs a synthetic-engineering scope extension beyond stdlib-only G01a | WP-00 … WP-20 (incl. WP-11a, WP-18a), WP-22, WP-23a, WP-23, WP-M0 |
| `SPEC_READY_AWAITING_CLINICAL` | Additionally needs Issue #4 charter and named owners | WP-21 (patient context); clinician holdouts inside WP-08 and WP-20; any real-PHI use |
| `SPEC_READY_AWAITING_TRUST` | Additionally needs release/key-custody owner | WP-24 |
| `DEFERRED` | Planned, outside V1 | P13 computable guidelines, P17 sync, P19 voice, citation-context signal |
| Authorized today | Only the existing G01a synthetic stdlib baseline and documentation work | — |

Update 2026-11-05: EXT-02 is ratified in `docs/decisions/M0_EXT02_RATIFICATION_2026-11-05.md`, which also authorizes synthetic work in `product/`. EXT-01 rows remain per component.

Update 2026-11-27 (`plan-v1.7`): The Founder permanently removed `DAL` (`T14`), replaced mandatory human engineering/security review (`EXT-06`) with `AI_ASSISTED_SECURITY_QUALIFICATION` (`ADR-0002`), scoped V1 strictly as a Research & Evidence-Analysis Workstation (`V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md`, `ADR-0003`) qualified via Automated Scientific Evaluation (`WP-21` deferred; `ACTUAL_CLINICAL_VALIDATION = FALSE`, `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`), and simplified zero-cost research release and permissive `PUBLIC_LICENSE` admissions (`ADR-0004`).

## 5. External approvals and qualification boundaries

| ID | Dependency | Owner needed | Evidence that closes it | Blocks |
|---|---|---|---|---|
| EXT-01 | Per-slice rights admission for donors, crates, and benchmarks | Rights owner (Issue #5) / `ADR-0004` for verified permissive public repos | `VERIFIED_ALLOWED` rows in `source_admissions.json` (`PUBLIC_LICENSE` or owner grant; `GPL`/`NOASSERTION`/private repos denied) | non-public / copyleft imports |
| EXT-02 | Synthetic & research-workstation engineering scope beyond stdlib-only G01a | Founder (`M0_EXT02_RATIFICATION_2026-11-05.md` + `plan-v1.7`) | **RATIFIED** (`2026-11-05` & `2026-11-27`) | — (closed for V1 research scope) |
| EXT-03 | Patient-specific clinical intended-use & clinician trial charter (`Issue #4`) | Founder + clinical safety owner (Issue #4) | Signed clinical charter (`V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md` governs V1 research release with `ACTUAL_CLINICAL_VALIDATION = FALSE`) | WP-21, real PHI, any clinical-use claim |
| EXT-04 | Traceability & ownership of the 41 original P1 findings | Founder engineering owner (`EXT-02` + `plan-v1.7` §6) | Executable `TA-01`..`TA-30` traceability for in-scope V1 technical rows; clinical `P01-G01` stays `BLOCKED` | full clinical P01 closure |
| EXT-05 | Commercial OS CA signing & production offline TUF root private keys | Release/security owner (Issue #5) | Signed key-custody record (`RESEARCH_RELEASE_QUALIFIED` bundles ship at $0 with `OS_CA_CODE_SIGNED = FALSE`) | commercial OS-signed installers & prod TUF root |
| EXT-06 | Security & technical qualification (`Issue #17`) | Independent AI-Assisted Security Qualification (`ADR-0002`) / optional human auditor | Multi-agent + `ocr` + property/fuzz/E2E qualification (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE` unless human audit filed) | human-audit claim only (does not block V1 research release) |
| EXT-07 | Model-weight terms: MedCPT, PaddleOCR, NLI, optional generator | Rights review (`ADR-0004`) | Pinned SHA-256 + permissive (`Apache-2.0`/`MIT`/`US-PD`) model-card rows (`T27b` dropped) | optional neural ModelPacks |
| EXT-08 | Private-repository non-disclosure (`DAL` permanently banned; `kernux`, `Morize`, `Inercative`, `Signthos`, `Wispral`, `Sentrdel`, `Ecra` paths withheld; `ottari` `T03`/`T30` approved via D4) | Founder | **APPROVED 2026-10-19** & hardened `2026-11-27` (`ADR-0001`: `DAL` permanently banned) | — (enforced) |
| EXT-09 | Regulatory determination for any jurisdiction | Regulatory owner | Not planned for V1 (`ACTUAL_REGULATORY_AUTHORIZATION = FALSE`) | any medical-device / clinical marketing |

Optional research follow-ups (do not block the freeze): REA-FOLLOWUP-01..06
authenticated observations of OpenEvidence, Elicit, GRADEpro, Scite, DynaMed
and Consensus Medical Mode by an authorized account holder
(`docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md` §5).

## 6. Review evidence bound to this baseline

`docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md` (independent
reviewer report, Alibaba Open Code Review delegation run, d1-local advisory
triage, baseline checker and unit-test results, and the fix log).

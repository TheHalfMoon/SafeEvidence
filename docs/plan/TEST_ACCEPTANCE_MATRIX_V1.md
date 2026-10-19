# SafeEvidence Test and Acceptance Matrix — V1

Status: **PLANNING_BASELINE_V1** — freeze state is recorded only in `docs/PLAN_FREEZE.md`. Every row has a binary pass/fail rule
evaluated on one exact commit in CI (Windows + Ubuntu minimum; macOS where
listed). "Engineering pass" never implies clinical validity; rows marked
`CLINICAL` additionally require the Issue #4 owner and evaluation charter.

Level: U = unit, I = integration, S = security/privacy, E = end-to-end,
Q = research-quality evaluation, R = release.

| ID | Level | WP | What is tested | Pass rule (objective) | Tooling / donor tests |
|---|---|---|---|---|---|
| TA-01 | U | WP-00 | Admission-row schema and pin integrity | Validator rejects: missing SHA, non-40-hex commit, blob/byte mismatch, duplicate keys, `copy_authorized=true` without `VERIFIED_ALLOWED`; accepts the reviewed fixture | extend `tools/governance/p01_candidate_integrity.py` |
| TA-02 | R | WP-00 | SBOM + notices | SBOM lists 100% of Cargo.lock packages and native libs; every copied file has a NOTICE/attribution entry | T11 `release_sbom_054.rs` |
| TA-03 | I | WP-01 | Fresh-checkout reproducibility | `cargo fmt --check`, `clippy -D warnings`, `cargo test --locked`, `cargo deny check` all exit 0 on 3 OSes with network disabled after fetch | existing exact-head workflows |
| TA-04 | U | WP-02 | Contract round-trip, no coercion, span coordinates, study independence | 100% donor tests pass; study-independence fixtures from `P00_STUDY_INDEPENDENCE_CONTRACT.md` 100% | T01 tests, T17 `expected_spans.json` |
| TA-05 | S/I | WP-03 | Vault durability & residue | Kill at every commit point → restart yields last committed state; disk-full → no partial commit; restore into clean dir verifies; plaintext residue scan of WAL/temp = 0 hits; donor tests pass unchanged except the adapted journal-kill test | T03 vault tests (6); T12 probes |
| TA-06 | I | WP-04 | Corpus replay & rights | Same fixture inputs → identical store digest twice; retracted/deleted IDs absent from active index; rights-unknown item never in a built pack | T15 `test_litdb_*` + new replay fixtures |
| TA-07 | Q | WP-05 | Study-level dedup | On synthetic multi-report set: precision = recall = 1.0; zero double counts in any aggregate | new fixtures modelled on R-CO-2 / R-EP-2 |
| TA-08 | U/Q | WP-06 | Arabic/English text & query parity | VS-1 gate: Arabic offsets round-trip 100% **and** every Arabic query whose language path is not yet promoted returns a reason-coded `ASK_MORE`/`ABSTAIN` (100%). V1 promotion gate for Arabic Ask: parallel-query recall@20 AR/EN ratio ≥ 0.90 on the pre-registered parallel set | T17 span tests; new parallel set |
| TA-09 | Q | WP-07 | Retrieval quality & promotion | BM25 measured on held-out set; dense/rerank promoted only if nDCG@10 **and** study-level recall@50 improve with non-overlapping 95% bootstrap CIs; funnel counts in 100% traces | BEIR harness, MedCPT `evals/` |
| TA-10 | Q | WP-08 | Claim support | Gating: numeric/unit/negation perturbation set 100% flagged; with the operating point fixed on a pre-registered half of SciFact dev, label macro-F1 on the other half ≥ 0.70 and unsupported-claim rate on the engineering holdout ≤ 5%. Reported, non-gating: MultiVerS oracle score on the same split. `CLINICAL`: clinician-adjudicated holdout threshold set by Issue #4 | T27, T27b |
| TA-11 | Q | WP-09 | Applicability | Population/intervention mismatch fixture: 100% mismatched sources excluded or downgraded with reason code | new fixtures |
| TA-12 | U | WP-10 | Appraisal structures | 100% ratings have per-domain reasons; CONFIRMED requires human actor id; exports validate against pinned EBM-derived schemas | T26 |
| TA-13 | U/I | WP-11a, WP-11 | Assurance determinism | Rust port = commandMed spec006 **P00-conformant subset** 100% (excluded and listed: `emergency-keyword-en`, `emergency-keyword-ar-msa` and any lexical-symptom EMERGENCY case; a dedicated test asserts lexical symptoms never yield EMERGENCY_NOTICE in V1); exactly one TerminalOutcome; DAL metric vectors reproduced to 1e-12 (WP-11); UI renders no percentage | T13 fixtures, T14 tests |
| TA-14 | I | WP-12 | Proof admission | Generator off ⇒ template brief; every committed claim has span + support label + validity epoch; crash/timeout ⇒ reason-coded outcome; streamed draft never labelled committed | `P00_PROOF_ADMISSION_CONTRACT.md` fixtures |
| TA-15 | S/Q | WP-13 | Documents & OCR | 24 h fuzz: 0 crashes escape worker; coordinates preserved on fixture PDFs; critical-number set: 0 silent wrong values; character error rate ≤ 0.05 on the pre-registered printed English and printed Arabic synthetic fixtures (handwriting non-gating) | T16 tests, cargo-fuzz |
| TA-16 | I/Q | WP-14 | Screening & PRISMA | Event-log replay ⇒ identical PRISMA counts; ASReview WSS@95 within ±2 pts of upstream at same seed on SYNERGY subset; no auto-exclusion | T15, T18, SYNERGY |
| TA-17 | Q | WP-15 | Extraction | Gating: 100% values have a quote span; state remains PROPOSED until a human confirms. Report-only, non-gating: accuracy on the Evidence Inference test split | T28 |
| TA-18 | U | WP-16 | Meta-analysis | Matches statsmodels + metafor golden outputs ≤ 1e-6; pooling refused when independence unknown | T19 `test_meta.py` |
| TA-19 | I | WP-17 | Living updates | Injected retraction/new-trial fixture changes validity epoch + emits cause-named alert in one cycle; historical answer bytes unchanged | WP-04 fixtures |
| TA-20 | E | WP-18a, WP-18 | Desktop E2E | Ask flow, span jump, abstention display, Deep Review open, pack import pass in E2E suite (spec format derived from `tester-army/e2e`, Apache-2.0); shell checklist (cache, crash dump, clipboard, WebView storage, CSP, capability allowlist) 100% | T36 tests |
| TA-21 | S | all runtime WPs | No silent egress | Packet capture / OS firewall audit during full E2E suite in `NETWORK_LOCKED`: 0 bytes to non-loopback; `EVIDENCE_UPDATE_ONLY`: only allowlisted hosts | T05 `network_broker_013.rs` |
| TA-22 | E | WP-19 | Accessibility & RTL | axe-core 0 serious/critical; keyboard-only Ask completes; RTL snapshot tests pass for every view | — |
| TA-23 | R | WP-20 | Benchmark reproducibility | Two clean builds of SafeEvidenceBench produce identical input/output digests; packet includes split identity | T14 |
| TA-24 | I | WP-21 | Patient context | Donor FHIR tests pass; answer lists every context fact used with source; write APIs absent | T09 |
| TA-25 | E | WP-22 | Mobile offline | iOS/Android: vault open, pack ≤ 500 MB load, offline Ask within ceilings; app-switch/screenshot privacy tests pass | T03 protectors |
| TA-26 | S | WP-23a, WP-23 | Sandbox | Documents, research and generator workers cannot open sockets, read outside their job dir or the vault keys, or spawn processes (attempts denied and logged) on all tier-1 OS | T10 tests |
| TA-27 | S | WP-23 | Prompt injection | Injected instructions inside retrieved abstracts/PDFs never change TerminalOutcome, never invoke tools/network | new adversarial fixtures |
| TA-28 | R | WP-24 | Release | Signed Windows installer; offline install; pack update via TUF metadata; rollback to previous pack epoch | T11, T25 |
| TA-29 | S | WP-01, WP-13 | Dependency-tree denial | `cargo tree -e normal` for every shipped binary except `safeevidence-network` contains none of `reqwest`, `ureq`, `hyper`, `hf-hub`, `liter-llm`; Xberg is resolved with exactly the admitted feature set; `xberg-ffi` and `docling.rs` default features absent | cargo-deny bans + script |
| TA-30 | S/E | WP-04, WP-17 | Outbound-query disclosure (P00 D7) | 100% of outbound requests are preceded by a user-visible preview of the exact query; request payloads contain no free-text narrative or patient-context fields (fixture with synthetic narrative asserts absence); saved queries are never sent without their own opt-in; query-derived records land only in the private vault | broker fixture transport (T05) |
| TA-M0 | Q | WP-M0 | Budgets | Every §5 ceiling measured on reference machine; result committed as versioned budget amendment | T36/MedScale perf harness pattern |

## Research-quality and safety evaluation protocol (summary)

1. **Pre-registration:** each Q-row's dataset split, metric, operating point
   and promotion threshold is committed before the run (commit SHA recorded).
2. **Splits:** benchmark train/dev/test identities frozen; no tuning on test;
   SafeEvidence holdout created only under the Issue #4 charter.
3. **Uncertainty:** bootstrap 95% CIs for all reported rates; promotion needs
   non-overlapping CIs versus incumbent.
4. **Abstention:** report unsafe-commit rate, over-abstention, risk–coverage
   and AURC (T14) — never accuracy alone.
5. **Bilingual:** every Q-row reports English and Arabic slices where the
   input language varies.
6. **Negative results** are committed as evidence, not discarded.
7. **No comparative claim** against any competitor without matched, dated
   conditions (`AGENTS.md` claim rule).

# SafeEvidence Implementation Ledger

Durable progress record. Status words apply only to the engineering scope named.
Nothing here implies clinical validation, regulatory status or product readiness.

Vocabulary: `NOT_STARTED`, `IMPLEMENTED_UNTESTED`, `TESTED_FAILED`, `TESTED_PASSED`,
`BLOCKED_EXTERNAL`, `ENGINEERING_COMPLETE`, `CLINICALLY_EVALUATED`, `RELEASE_QUALIFIED`.

## Current state (2026-11-26)

| Field | Value |
|---|---|
| `main` at last update | `55ce7276c6460b63c358b7620546549e8dfb1e92` (PR #94; updating in PR #95) |
| Milestone | All `EXT-02`-authorized engineering slices across M0, M1 (`VS-1a`), M2, M3, M4, `WP-20` (`SafeEvidenceBench`), and `WP-M0` (`TA-M0`) implemented and verified; external gates (`EXT-01`, `EXT-03`, `EXT-04`, `EXT-05`, `EXT-06`, `EXT-07`, `EXT-09`) remain `BLOCKED_EXTERNAL` |
| Active packet | M3/M4 closeout: `WP-14`/`WP-15` protocol & quote-anchored extraction (`TA-17`), `WP-18`/`WP-19` multi-pane bilingual EN/AR + RTL + WCAG AA workstation (`TA-20`, `TA-22`), `WP-20` `SafeEvidenceBench` (`TA-23`), `WP-M0` runtime budget baseline (`TA-M0`), and final qualification dossier (`docs/handoff/SAFEEVIDENCE_FINAL_QUALIFICATION.md`) |
| Admissions | ADM-0001 (T01), ADM-0002 (T11 `deny.toml` and SBOM generator), ADM-0003 (T03, separated to `SAFEVD/`), ADM-0004 (T17 fixture), ADM-0005 (T13, no code copied), ADM-0006 (T36), ADM-0007 (T12), ADM-0008 (T30), ADM-0009 (T03's Linux helper), ADM-0010 (`CRATE-product-cargo`), ADM-0011 (`CRATE-desktop-cargo`), ADM-0012 (`CRATE-desktop-npm`); G01a baseline holds `NO_ADMISSIONS` |
| Product code | T01 contracts with P00 confidence/proposal gates; WP-02 decision vocabulary, proof states and pooling guard; `WP-05` `study_linkage` (`TA-07`); `WP-10` `appraisal` (`RoB 2`, `ROBINS-I`, `QUADAS-2`, `AMSTAR 2`, `GRADE`, `EBMonFHIR`, `TA-12`); `WP-06` `bilingual` + `bilingual_ask` (`TA-08`); `WP-04`/`WP-17` `overlay` + `surveillance` (`TA-06`, `TA-19`, local `TA-30`); `WP-07` `bench/ta09_hard/` (`TA-09`); `WP-08`/`WP-09` `perturbation` (`TA-10`, `TA-11`); `WP-14`/`WP-15` `review_protocol` (`ReviewProtocol` + hash-chained `ProtocolAuditBundle` + quote-anchored `StructuredEffectExtraction`, `TA-17`); `WP-20` `SafeEvidenceBench` (`bench_runner` + `safeevidence_bench`, `TA-23`); T03 vault separated to `SAFEVD/` domains (`RUSTSEC-2026-0459` WAL guard); `safeevidence-proofstore` (`plan-v1.3` assertion lineage & `retract_source`); M4 bilingual EN/AR + RTL + WCAG AA desktop workstation (`Ask`, `Evidence & Sources`, `Deep Review`, `Packs & Validity`, `Privacy & Diagnostics`; `19/19` Windows WebView2 E2E verified locally, `18`-check Ubuntu WebKitGTK E2E gated in PR #95 CI); `WP-M0` measured baseline (`docs/RUNTIME_BUDGET_BASELINE_2026-11-26.md`) |
| Next executable task | Zero remaining `EXT-02` greenfield engineering tasks; next steps await external founder/human/rights/clinical/signing gates: `EXT-01` & `EXT-07` (`Issue #5` donor/dataset/model-weight rows), `EXT-03` (`Issue #4` clinical charter), `EXT-04` (`Issue #3` P01 P1 owners), `EXT-05` (`Issue #5` release signing keys), `EXT-06` (`Issue #17` & PR #43 human review) |

Required checks on `main` (founder decisions, 2026-11-05 and 2026-11-06): `foundation-documents`, `preentry structure`,
`synthetic-only`, `product` and `desktop`, the last four on Ubuntu, Windows and macOS.

## Milestones

| Milestone | Status | Blocked by |
|---|---|---|
| M0 Admission | `ENGINEERING_COMPLETE` (AI exit-reviewed in `docs/reviews/M0_M1_EXIT_REVIEW_2026-11-26.md`; `EXT-06` human review open): TA-01, TA-02, TA-03 (under `plan-v1.2`), TA-04 (under `plan-v1.3` + assertion lineage), and TA-29 HTTP-client/socket tree checks `TESTED_PASSED` across Ubuntu, Windows, and macOS | `EXT-06` independent human security/technical review before any release claim |
| M1 VS-1 (synthetic) | VS-1a synthetic engineering `TESTED_PASSED` (AI exit-reviewed under `plan-v1.5`; `EXT-06` open): steps 1–4 of `plan-v1.1` §C `TESTED_PASSED` (`17/17` Windows WebView2 E2E checks locally + in CI and `16/16` Ubuntu WebKitGTK E2E checks in hosted `desktop-e2e-linux.yml` CI across the 6 fixture-reachable V1 outcomes; `ANSWER` verified in headless Rust + TS unit tests; `EMERGENCY_NOTICE` disabled in V1; `desktop-e2e*.yml` remain non-required branch-protection checks). Full VS-1 milestone closure remains gated on `T05` / `TA-21` (`BLOCKED_EXTERNAL` under `EXT-01`); `TA-08` RTL snapshots, `TA-10` full perturbation set, `TA-20` shell checklist & shipped Linux incognito E2E, and `WP-M0` resource baseline remain at M2/M4 | `EXT-01` (`T05` network broker admission for full `TA-21`); `EXT-06` human review |
| M2 Evidence V1 | `GREENFIELD_JUSTIFIED` synthetic slices `TESTED_PASSED` (PR #94 `55ce727`: `WP-04` local overlay `TA-06`, `WP-05` study/overlap linkage `TA-07`, `WP-06` bilingual span/Ask `TA-08`, `WP-07` harder BM25 `TA-09`, `WP-08` deterministic perturbation set `TA-10`, `WP-09` PICO applicability `TA-11`, `WP-10` RoB/GRADE/EBMonFHIR `TA-12`, `WP-17` local surveillance `TA-19`); full M2 closure remains `BLOCKED_EXTERNAL` | `EXT-01` (`T05`, `T07`, `T09`, `T10`, `T14`, `T15`, `T16`, `T17` worker, `T20`–`T23`, `T27`); `EXT-03` (`WP-21` patient context & clinical holdout); `EXT-07` (NLI / MedCPT / OCR model weights) |
| M3 Deep Review | `GREENFIELD_JUSTIFIED` synthetic slices `TESTED_PASSED` (`WP-14` `ReviewProtocol` & hash-chained `ProtocolAuditBundle`, `WP-15` quote-anchored `PROPOSED` -> human `CONFIRMED` `StructuredEffectExtraction` `TA-17`, `WP-16` `decide_pooling` independence gate, `WP-17` local surveillance); full M3 worker closure remains `BLOCKED_EXTERNAL` | `EXT-01` (`T15` `litdb` screening/PRISMA, `T18` `ASReview` worker, `T19` `statsmodels` meta-analysis worker, `T28` Evidence Inference split); `WP-23a` (`T10` sandbox) |
| M4 Desktop V1 | `GREENFIELD_JUSTIFIED` synthetic workstation & benchmark `TESTED_PASSED` (`WP-18`/`WP-19` multi-pane `Ask`/`Evidence`/`Deep Review`/`Packs`/`Privacy` desktop shell, `EN`/`AR` + `RTL` WAI-ARIA keyboarding, WCAG 2.1 AA light/dark contrast, `19/19` Windows WebView2 E2E verified locally and `18`-check Ubuntu WebKitGTK E2E gated in PR #95 CI; `WP-20` `SafeEvidenceBench` `TA-23`; `WP-M0` measured baseline `TA-M0`); full M4 closure remains `BLOCKED_EXTERNAL` | `EXT-01` (`T05` `TA-21` OS network broker, `T07` signed pack import, `T13`/`T14` full DAL metrics); `WP-13` (`T16`/`T20` document worker); full `TA-20` crash-dump/clipboard/shipped-Linux-incognito & `TA-22` axe-core browser runner |
| M5 Mobile | `NOT_STARTED` | M4; EGM finding V5 |
| M6 Release candidate | `NOT_STARTED` | EXT-05 |
| Clinical evaluation | Not an engineering milestone | EXT-03 (Issue #4) |

## Verified on `1a10bc5` (Windows, local, 2026-11-05)

| Check | Result |
|---|---|
| `plan_baseline_check.py` | PASS, freeze state FROZEN |
| `p01_preentry_check.py` | Structural PASS; P01-G01 BLOCKED |
| `p01_candidate_integrity.py` | structure PASS; `source_imports` BLOCKED |
| Governance unit tests | 145 run, OK, 21 skipped |
| `cargo test --offline --locked --all-targets` | 3 passed |
| Hosted post-merge CI at `1a10bc5` | P00, P01, G01a all success |
| `cargo fmt`, `cargo clippy` locally | **Not run.** Local 1.97.1 toolchain lacks `cargo-fmt.exe` and `cargo-clippy.exe`; hosted CI covers both |

## Known defects

**TA-09, TA-11 and TA-14 for VS-1a** (2026-11-07), each at its own scope and on invented data only:
- **TA-09** `TESTED_PASSED` as `plan-v1.5` scopes it. BM25 is measured on the synthetic set registered in `bench/ta09/REGISTRATION.md`, with results in `bench/ta09/RESULTS.md`: nDCG@10 0.8493, study-level recall@50 0.9333, funnel counts in 30 of 30 traces. Not a retrieval-quality claim. **The set is easy by construction:** no distractor is retrieved and the cutoffs never bind, so it shows that the harness works, and little more. A harder registered set, and then rights-admitted data, stay owed before any promotion. The funnel clause is read narrowly, as each trace's count matching retrieval.
- **TA-11** `TESTED_PASSED` on the invented fixture (PR #74 + PR-B1). Each excluded source carries both a typed `ReasonCode` (`reasonCode`) and human-readable `detail` (`reason`), and the desktop view renders both. Population, condition and intervention mismatches are excluded, and so are near populations. It rests on metadata labels, not source text. "Every retrieved source is cited or excluded" holds for this fixture only: a mismatched report that retrieval never returns gets no code. A report both retracted and rights-denied shows only the rights code.
- **TA-14** `TESTED_PASSED` with injected faults, as `plan-v1.1` §C allows while no worker exists (PR #74 + PR-B1). Crash and timeout at the brief, verification and commit boundaries are reason-coded refusals with no text. Text must cite exactly the admitted claims. `tests/answer_faults.rs` also covers the other clauses: generator off gives the template brief, each claim has a span, support label and validity epoch, and nothing from Ask is labelled committed. `ask_command.rs` reconciles `CommitUnknown` by reading back `ProofStore::read` (recovering durable writes and withholding unwritten ones) and tests post-commit `read()` error mappings. Real worker process kills return with WP-12's generator (`EXT-07`).

**TA-05 for VS-1** `TESTED_PASSED` under `plan-v1.5`'s reading (an engineering reading the founder can overrule), on invented data:
- Kills just after each of eight acknowledged commits, through both `ProofStore::open` and `ProofStore::open_existing`, lose no acknowledged answer and leave nothing partial.
- Cross-process `IMMEDIATE` writer lock contention returns `StoreError::Busy` while concurrent WAL reads proceed, and `snapshot_quiesced_sqlcipher_database` (`PRAGMA wal_checkpoint(TRUNCATE)`) restores cleanly into an isolated directory while rejecting wrong keys without mutating bytes; post-checkpoint hot-WAL kills recover both main-file and WAL answers.
- A plaintext scan looks for answer text in every file a killed store left, its WAL included, before anything reopens it. The live and closed scans also cover sources, the brief and identifiers.
- Every donor test changed since admission is named in the vault's `PROVENANCE.md`. A redaction check the move to the helper dropped is restored.
- Not covered: a kill before the first acknowledged commit, a kill inside SQLite's own C commit syscall, a crash during an active checkpoint, disk-full injection, key-loss recovery, and physical power loss (`CommitUnknown` reconciliation is tested in `ask_command.rs`).

**No-socket capture, Linux** (evidence for VS-1a, `plan-v1.1` §C, not a TA-21 pass): in a few runs under `strace -ff`, the app, the keyring helper and WebKit's processes made no internet-family call outside loopback and no direct DNS lookup. On each launch the test build binds a loopback listening socket, in the app's own process, which it and its web process connect to. A build as it ships, without WebDriver automation and with incognito, made no internet-family bind, connect or accept and no send to an address over 30 seconds of startup and idle (run 42414388764). That is consistent with the listener coming from the automation setup, but the runs differ in more than automation, and the shipped-style run asked no question. The test runs with WebDriver automation on and without incognito. Processes outside the traced tree, packets and io_uring are not covered. Windows and macOS are not captured by strace.

**No-socket capture, Windows** (evidence for VS-1a, not a TA-21 pass): in the test build's end-to-end run 42440486315 (`3236796`), a WebView2 process held a TCP connection to 150.171.22.17 port 443, an address range ARIN registers to Microsoft, and run 42442779313 (`21fe1eb`) one to 52.123.250.172 port 443, also Microsoft's; an earlier run also saw a port 443 connection outside loopback, address not recorded, and a UDP socket bound outside loopback, whose destination netstat cannot show. The service and what was sent are unknown. **Privacy finding, mitigated, not closed:** the founder approved trying WebView2 switches, and every Windows build now passes WebView2 switches that turn off its background services. In run 42485847303 (`0cc6f74`) neither the test build through an Ask nor the shipped-style build over 30 seconds idle held a socket outside loopback. Both held an unexplained loopback TCP connection to port 80, the shipped-style build in 172 of 173 samples against 1 of 192 before the switches, so the switches may have caused it. Run 42521709468 names the listener as `System` (PID 4; on port 80 normally HTTP.sys); the pages' origin `http://tauri.localhost` is on loopback port 80, which may explain it. Run 42530898719, with the runner's HTTP service stopped and a silent listener on the port, saw one connection from `::1` carrying 0 bytes over startup and 30 seconds idle; a control request was recorded. Run 42537385684 (`aef7f4d`), with IPv4 and IPv6 controls, saw it held from launch until the app closed, again 0 bytes. Two runs, no question asked; the listener does not name the connecting process. During an Ask in the e2e build (run 42555157901, `e6693a0`), two short connections from `::1` carried 0 bytes and the typed nonce never reached the port; one run. One run each; switches are requests, not a guarantee; the runtime's own updater is outside the app. Before the switches, a build as it ships, captured over startup and 30 seconds idle (run 42450610768), held no TCP connection outside loopback but kept a UDP socket bound outside loopback, destination unknown; it asked no question. macOS is not captured.

**WebView storage, before M1 exit** (`plan-v1.5`): on Windows the shipped incognito window leaves none of the answer, cited span or proof id in the web view's data directory. The page writes no web storage today, so the test is a tripwire, not proof that incognito prevents storage. One-off manual runs showed incognito keeping a page's `localStorage` write off disk, and the scan finding it with incognito off. Linux's test window is not incognito, and its scan reads only the data directory.

**Retrieval selects the cited evidence, under `plan-v1.6`** (founder decision, 2026-11-07). Only reports lexical retrieval found can be cited. The guards still see the whole corpus, so a contradiction retrieval misses still stops the answer. A missed applicable report is listed with `EVIDENCE_INSUFFICIENT`, and missing-population `ASK_MORE` fires only when at least one citable population has a retrieved report (abstaining with `EVIDENCE_INSUFFICIENT` when lexical retrieval missed every citable report across all populations).

**Open, from the 2026-11-08 security review:** conflict detection trusts author-asserted direction labels. The loader's word-list check catches simple mislabels only: an improved finding with an incidental "no" or "similar" cannot carry its honest label, and unlisted wording can carry a wrong one, which can hide a contradiction. Corpus trust (WP-04) and claim verification (WP-08) are the real controls, and owed before any imported corpus.

**VS-1 scope is set by `plan-v1.5`** (founder rulings, 2026-11-07): `plan-v1.1` is in force with no independent human review, TA-20 is the Ask flow, a labelled synthetic set serves TA-09, and the M1 exit review is AI-only. EXT-06 stays open. TA-21 and T05 are unchanged and still owed before VS-1 is done.

**TA-13 for VS-1 is narrowed by `plan-v1.4`** (founder decisions, 2026-11-06). Its VS-1 clauses have tests: 1,329 mechanics vectors, 12 of 17 donor fixture cases at resolution level, all 17 questions
through `ask`, and the lexical-emergency test. This shows little beyond the vectors, because no case runs through V1 to a matching outcome, and the amendment states that. TA-13 as a whole is not met: its DAL vectors are
owed at WP-11. Ask also uses `EVIDENCE_INSUFFICIENT` for a question it could not parse, before retrieval runs, because no allowed code fits better.

**Sockets in the core's tree:** the founder chose a separate helper process (2026-11-06). `safeevidence-linux-keyring-helper` now holds the Secret Service and D-Bus code, and the vault reaches it over stdin and stdout.
`tools/ci/core_no_sockets.py` checks the core crates' normal dependencies on each desktop target, and `ta29_desktop_denial.py` holds the desktop shell, the process that hosts the core, to a list of known socket crates. `tokio` remains there for Tauri,
without its `net` feature, on the three desktop targets. These read dependency trees, so they do not detect a socket opened through `std::net`, and TA-21 has not observed the running process. **The helper beside the app:** every Linux build now places it, from `tauri.linux.conf.json`, which meets what M1 needed: the Linux app finds it. No installer carries it, because bundles stay off. That belongs with signed releases under EXT-05 at M6, not M1. TA-29's tree check covers normal dependencies. Build-only crates such as `cc` and `openssl-src` are covered by the
`cargo deny` bans.

**T30 is narrower than WP-00 names:** only the tool-source audit is adapted. The donor's registry and its notice and SBOM generators are not copied, because
`source_admission_check.py`, the T11 SBOM generator and `cargo deny` already do that work, and a second registry would have to be kept in sync. The audit runs in
the governance tests and covers third-party HTTP/FFI/importlib modules (`requests`, `httpx`, `urllib3`, `aiohttp`, `ctypes`, `importlib`, `builtins`), bare dynamic-execution references (`eval`, `exec`, `compile`, `__import__`), and `os.system`/`popen`/`spawn*`/`exec*` helpers across `tools/ci` and `tools/governance`. It does not cover shell scripts; npm packages are audited separately by `ADM-0012` in `source_admission_check.py`.

**Crate closures (`plan-v1.1` B6):** `ADM-0010` (`CRATE-product-cargo`), `ADM-0011` (`CRATE-desktop-cargo`), and `ADM-0012` (`CRATE-desktop-npm`) in `docs/evidence/source_admissions.json` bind exact LF lockfile SHA-256 digests, package counts, registry sources, SPDX license allowlists, and `THIRD_PARTY_NOTICES.md` rows, validated fail-closed by `source_admission_check.py`.

**T12:** the residue scan covers one store directory, live and closed, so `TA-05` is not claimed. Its MIME test returns at WP-13.

**Desktop shell:** the Ask store's key is held by the OS protector, and answers survive a restart. Key loss is refused and has no recovery path yet, and only Windows runs its real protector in the native desktop tests. Native tests use Tauri's mock runtime. The end-to-end tests use real windows and real protectors on Windows and Ubuntu. TA-20, TA-21 and TA-22 are not claimed. Both `product/apps/desktop/src-tauri/Cargo.lock` and `product/apps/desktop/package-lock.json` are covered by `TA-02`'s CycloneDX SBOM and `src-tauri/deny.toml` (`desktop-ci.yml`). Tauri pulls `reqwest` and `hyper` on Android and iOS: resolve before M5.

**`plan-v1.3` immutability:** tested against the keyed vault store in `safeevidence-proofstore`, with triggers and guarded SQL.
**`plan-v1.3` lineage, for sources and assertions.** `ProofStore::amend` appends `AmendmentRecord` for sources while `ProofStore::put_assertion`, `assertion`, `amend_assertion`, and `assertion_amendment_records` store promoted `ClinicalAssertion` objects (validated by `validate_p00_contract()`) and append assertion lineage keeping prior assertion bytes unchanged across reopen. `ProofStore::retract_source` records source retractions without requiring a fake superseding source and invalidates committed answers citing the retracted source. `ProofStore::commit` verifies UTF-8 scalar bounds of every cited `EvidenceSpan` against stored source bytes. Answers are invalidated, not amended, as P00 asks. The desktop keys its store folder on the schema and `VAULT_DOMAIN_VERSION` as well as the fixture, so a schema or domain change gets a new store rather than a refused one. The old folder stays behind.
This guards against bugs, not malicious in-process code, and covers process kills, not power loss. `CommitUnknown` reconciles in `ask_command.rs` via `ProofStore::read`. The guard's fixtures test declared structure only, not extraction or statistics.

**TA-03:** Linux (empty network namespace) and macOS (sandbox profile) run all checks under OS-level denial.
Windows blocks named programs only, because default-deny outbound lost the hosted runner. Its build and build
scripts run before the block, and unlisted programs are not blocked. Post-merge CI passed at `e06f7ea`, so TA-03 passes
under `plan-v1.2`. TA-03 and A4 require isolation on all three
OSes. The founder accepted the Windows form for now (`docs/plan/PLAN_AMENDMENT_V1_2.md`), to be revisited before
any release. TA-03 passes only when its controls pass in CI on all three OSes on the exact commit.

**Historical sequencing breach (resolved functionally):** T03 merged before TA-03 and TA-04 passed, ahead of the frozen WP-01 and WP-02
exits it depended on. That git-history ordering cannot be undone; both `TA-03` (`plan-v1.2`) and `TA-04` (`plan-v1.3` + vault-backed source and assertion immutability/lineage) have since passed across all three OSes, and `M0_M1_EXIT_REVIEW_2026-11-26.md` records the AI-only exit review (`EXT-06` human review remains open).

**Vault cryptographic domain separation (`ADM-0003`):** all `HIMSAT/...` domain separators and wire-magic strings across `safeevidence-vault` have been separated to the equal-length 6-byte `SAFEVD/...` namespace (`VAULT_DOMAIN_VERSION = "SAFEVD-v1"`), preserving fixed wire offsets, with independent non-Rust test vectors and cross-product rejection tests (`tests/domain_separation.rs`) covering HKDF purpose/backup keys, bounded blobs, freshness manifests, Argon2id recovery envelopes, Android Keystore records, and live Windows DPAPI entropy/records. Desktop synthetic store directories include `VAULT_DOMAIN_VERSION` in `store_key()` so pre-migration local folders stay untouched.

**WP-02 T01 gating:** `evidence/mod.rs` now sets `scale_corpus_generator_present: false` with `validate_non_clinical()`, and `Proposal`, `ClinicalAssertion`, and `IdentityAssertion` enforce `P00_DECISION_ASSURANCE_CONTRACT` via `validate_assured_surface()` / `validate_p00_contract()` so unpromoted proposals and heuristic `confidence` fields are rejected fail-closed on assured V1 surfaces.

See `docs/reviews/EGM_PLAN_CHALLENGE_2026-11-05.md`. Six P0 plan and tooling defects
are verified. `product/`, `product-ci.yml` and `plan-v1.1` A3, B1, B2 and B6 address them, and `tools/governance/p01_preentry_check.py` now accepts issue-comment-bound `ASSIGNED — @<owner> (https://github.com/TheHalfMoon/SafeEvidence/issues/<3|4|5>#issuecomment-<id>)` rows while keeping `p01_g01_activation = "BLOCKED"` and rejecting bare `APPROVED` states.

## Source imports

See `docs/evidence/source_admissions.json`.

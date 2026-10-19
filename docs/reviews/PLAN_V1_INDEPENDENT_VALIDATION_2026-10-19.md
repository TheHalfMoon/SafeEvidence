# Plan V1 Independent Validation — 2026-10-19

Scope: the V1 planning baseline indexed in `docs/PLAN_FREEZE.md` (branch
`planning/copy-first-plan-freeze-20261019`). Planning documents and one
stdlib governance checker only; no product code, no donor bytes.

## 1. Reviews actually performed

| Review | Tool / reviewer | Input | Result |
|---|---|---|---|
| R1 Independent architecture, security and rights review | Separate Claude agent, cold start, read-only, adversarial brief; verified claims against donor clones and `gh api` | commits `789167f` / `eefdb34` | **READY_AFTER_FIXES**; 21 findings (7 × P1, 12 × P2, 2 × P3); no P0 |
| R2 Alibaba Open Code Review | `ocr` v1.13.1 (`8eb8334`), delegation mode (`ocr delegate preview --from origin/main --to HEAD`, `ocr delegate rule`), host agent applied the rule set | 21 reviewable files; Markdown excluded by OCR as unsupported; executable scope `tools/governance/plan_baseline_check.py` | 0 High; 1 Medium (malformed pin JSON could raise instead of reporting FAIL) — fixed |
| R3 d1-local advisory triage | `d1_review_change`, model `d1-omni-600M-Q8_0` | compact checker diff | security_risk = medium (p 0.52, confidence 0.28), needs_review 0.65 — **advisory only**; not used to approve anything |
| R4 Deterministic checks | `plan_baseline_check.py`, `p01_preentry_check.py`, `p01_candidate_integrity.py`, `unittest discover -s tools/governance/tests` | final head | see §4 |

Not run, with reason: **Graft** (installed locally) builds code-context
graphs and reports anonymous telemetry; it adds no evidence for a
documentation change and would send usage data, so it was not run.
**PStack** is not installed in this environment. **Jev** (remote) was not
used: no access configured in this session. **tester-army/e2e**
(Apache-2.0, verified at GitHub) is referenced as the E2E spec format for
TA-20; there is no application yet to run it against.

## 2. R1 findings and disposition

| ID | Sev | Finding (short) | Disposition |
|---|---|---|---|
| F1 | P1 | TA-13 demanded 100% parity with commandMed fixtures that include lexical EMERGENCY cases disabled by P00 | Fixed: parity on the P00-conformant subset with the excluded fixtures named; `safety_policy.json` oracle-only; dedicated "lexical symptoms never yield EMERGENCY_NOTICE" test (T13, TA-13) |
| F2 | P1 | Generator shown in-process (in-proc FFI) | Fixed: generator is a sandboxed out-of-process worker without keys or network; trust rule added; TA-26 covers it (ARCH §2, D-06) |
| F3 | P1 | "Xberg network-free" true only for core crate; OCR presets pull hf-hub/reqwest/ureq; `xberg-ffi` defaults include remote LLM/URL ingestion | Fixed and independently confirmed: exact admitted feature set (`xberg` `pdf-native` + `xberg-paddle-ocr`), `xberg-ffi` not admitted, new TA-29 dependency-tree denial (T20, D-02, WP-01, WP-13) |
| F4 | P1 | P00 D7 (outbound-query visibility, no narrative, private results) missing; surveillance would auto-send | Fixed: new decision D-16, private query-derived store, per-query opt-in surveillance, TA-30 (ARCH §3/§4, WP-04, WP-17) |
| F5 | P1 | Dependency/execution-order contradictions (WP-11 needed WP-10; WP-18 needed WP-13/14) | Fixed: VS-1 sub-packets WP-11a and WP-18a; execution order rewritten; checker now rejects dependency cycles |
| F6 | P1 | Feature matrix cited this report while it was a stub | Fixed by this report; the claim is now backed by R1 §3 below |
| F7 | P1 | Public disclosure of private-repo status and path pins | Fixed conservatively: the 49 path pins of private repositories (T03, T06, T14, T30, T32) were removed from the public pins JSON and replaced by SHA-256 commitments; the full list is a founder-held private record; prose no longer names new private file paths. Remaining founder decision EXT-08: whether stating the repositories' private status is acceptable |
| F8 | P2 | `pack_runtime.rs` imports excluded runtimes | Fixed: removed from T07 and from pins |
| F9 | P2 | Donor journal-kill test depends on an excluded vault module | Fixed: marked adapted (T03, TA-05) |
| F10 | P2 | `_layout.py` missing from T15 closure; "unchanged" wording | Fixed: pinned; wording now "import-path, rename and broker-fetch adaptations only" |
| F11 | P2 | SafeOCR `ocr.py` adds a second OCR route with subprocess | Fixed: `ocr.py` and its test removed from copy scope (REFERENCE) |
| F12 | P2 | Key/trust overlap T02/T03/T07/T25 | Fixed: T03 single key hierarchy; T02 reference with bounded fallback; one pack-trust path (T07 digests + T25 TUF) |
| F13 | P2 | `ort` exact-pin conflict (rc.13 vs rc.14) | Mitigated: docs worker in its own Cargo workspace; WP-01 tries alignment first. Not proven by a build (planning only) |
| F14 | P2 | T10 sandbox is partial; CPython-in-sandbox unproven | Fixed: T10 marked partial; launcher is greenfield in WP-23; early spike WP-23a before M2 |
| F15 | P2 | Rotated version labels; "live head" wording | Fixed and confirmed: Xberg 1.3.11 (release v1.3.10), docling.rs v2.42.0, fastembed-rs v7.1.1; "pinned heads", re-verify at admission (Xberg upstream has moved past the pin) |
| F16 | P2 | VS-1a claimed no rights dependency though NLI weights needed | Fixed: VS-1a deterministic checks only; NLI joins VS-1b after EXT-07 |
| F17 | P2 | TA-08/10/15/17 lacked objective gates | Fixed: VS-1 and V1 gates for TA-08; pre-registered split + thresholds for TA-10; CER ≤ 0.05 for TA-15; TA-17 accuracy explicitly report-only |
| F18 | P2 | EMERGENCY_NOTICE V1 status; plaintext worker scratch | Fixed: "disabled in V1" note; in-memory or per-job-key encrypted scratch |
| F19 | P2 | Browser observations lacked a captured artifact | Fixed within copyright limits: contemporaneous `BROWSER_OBSERVATION_LOG.md` with SHA-256; third-party page text not redistributed, rows are reproducible from recorded URL/query |
| F20 | P3 | Count/ID drift ("13 slices", L6→WP-13, D-08 "qualified") | Fixed |
| F21 | P3 | Checker gaps | Fixed: matrix-vs-pins commit check and dependency-cycle check with unit tests |

## 3. What R1 verified (evidence summary)

- All 334 original pins (332 after F8/F11/F10; 283 public + 49 redacted to commitments after F7) matched `git
  ls-tree` blob OIDs in the donor clones; 10 OIDs re-checked via the GitHub
  contents API; every packet commit equals the inspected HEAD; transplant
  matrix commits equal the pins JSON.
- Functional claims confirmed by opening files: ottari vault (SQLCipher via
  `rusqlite =0.40.1` `bundled-sqlcipher-vendored-openssl`, lease, backup
  create/verify/restore/publication, rotation, deletion, four OS protectors,
  six named tests, `rust-version 1.98.1`); MedOrigin `litdb` (screening log,
  `ExclusionReason`, PRISMA summary, dedupe/uncertain, stdlib + urllib);
  MedScale Tauri shell (strict CSP except `style-src 'unsafe-inline'`,
  named-command capability allowlist, Tauri 2.12.0 / React 19.3.0); MedScale
  `retrieval.rs` 142-line scorer; `medscale-pack` ~26.8 kLoC with tract;
  docling.rs and fastembed-rs network defaults; RRnlp weights GPL-2.0;
  RobotReviewer GPL-3.0; MedCPT code public-domain notice.
- REA raw evidence: `sha256sum -c` passes; all 7 `ev_` identifiers present.
- P00 alignment: ControlAction/TerminalOutcome vocabularies, no V1
  percentage, ottari vault choice. No clinical, legal or regulatory approval
  claim found.
- Not verified by R1: trialstreamer pins against GitHub, HL7 IG licence
  terms, MedCPT weight terms, actual `ort` co-resolution.

## 4. Deterministic results on the final baseline

Recorded in the PR description for the exact head SHA (the head is not known
until this file is committed). Required: `plan_baseline_check.py` PASS,
`p01_preentry_check.py` PASS, `p01_candidate_integrity.py` PASS, all
`tools/governance/tests` OK, plus the seven required GitHub checks.

## 5. Conclusion

All P1 and P2 findings are resolved in the documents; F7 is resolved by
redaction with a residual founder decision (EXT-08), and F13 which is mitigated by design but
can only be proven by a build in WP-01. No P0 finding was raised. The
planning baseline is consistent for freeze subject to EXT-08 and the human
approving review required by branch protection.

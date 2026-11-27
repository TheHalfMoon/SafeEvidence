# Security Policy

## Project status, scope, and supported versions

SafeEvidence V1 is a **local-first, evidence-grounded biomedical research and
systematic-review workstation** governed by `plan-v1.7`
([ADR-0001](docs/adr/0001-permanently-remove-dal-and-adopt-clean-room-calibration-math.md)
through
[ADR-0004](docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md)).

This coordinated disclosure policy covers:

- The root G01a synthetic reproducibility, source-admission, and governance
  validation suite (`tools/governance/`, `tools/ci/`, `src/safeevidence/`).
- The `product/` Rust workspace (`safeevidence-contracts`, `safeevidence-vault`,
  `safeevidence-assurance`, `safeevidence-proofstore`, `safeevidence-ask`,
  `safeevidence-release`, `safeevidence-keyring-wire`,
  `safeevidence-linux-keyring-helper`, and `safeevidence-privacy-probes`, plus
  subsequent `plan-v1.7` workspace crates).
- The local-first Tauri 2.12 + React 19.3 desktop research workstation
  (`product/apps/desktop/`).

**Truthful qualification posture (`ResearchReleaseManifest` 7-axis status):**

- SafeEvidence V1 is **not** a clinical medical device, diagnostic engine,
  prescribing system, triage tool, or patient-record platform
  ([V1 Research Intended-Use Charter](docs/decisions/V1_RESEARCH_INTENDED_USE_CHARTER_2026-11-27.md)).
- Patient Health Information (PHI) processing, live clinical deployment, and
  regulatory claims are **not authorized** (`ACTUAL_CLINICAL_VALIDATION = FALSE`,
  `ACTUAL_REGULATORY_AUTHORIZATION = FALSE`).
- Internal engineering qualification uses automated cryptographic, adversarial,
  property-based, end-to-end, and multi-agent AI security verification
  ([ADR-0002](docs/adr/0002-ai-assisted-security-qualification-framework.md);
  [AI-Assisted Security Qualification Framework](docs/decisions/AI_ASSISTED_SECURITY_QUALIFICATION_FRAMEWORK_2026-11-27.md)).
  Passing CI or AI-assisted security qualification **never** asserts external
  human security certification (`HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`) or
  operating-system certificate-authority code signing
  (`OS_CA_CODE_SIGNED = FALSE` unless signed by an OS-trusted CA).
- Security fixes apply to the tip of `main`; no backport branches or legacy
  release lines are maintained.

## Report a suspected vulnerability privately

Use the repository's zero-cost **GitHub private vulnerability reporting**
workflow:

1. Open [SafeEvidence's Security page](https://github.com/TheHalfMoon/SafeEvidence/security).
2. Choose **Report a vulnerability** and submit the private advisory report.
3. Include the exact 40-character Git commit SHA, affected crates or files,
   threat boundary violated (for example SQLCipher vault custody, Tauri IPC
   capability boundary, hostile-document intake quarantine, zero-egress core
   invariant, proof-admission fail-closed gate, or lockfile/source admission),
   a minimal deterministic reproduction using **synthetic, non-sensitive input
   only**, impact assessment, and any proposed mitigation.

Private vulnerability reporting is enabled on this public repository. Do **not**
post exploit details, bypass payloads, or undisclosed vulnerability specifics in
public issues, pull requests, discussions, or review comments.

Do not include patient information (PHI/PII), real clinical records, secrets,
credentials, private documents, or third-party restricted content in any report.
Do not conduct network attacks, social engineering, tests against third-party
services, or invasive testing against systems you do not own. Public source code
may be audited and tested offline in isolated local environments using synthetic
fixtures.

If you cannot access the GitHub private vulnerability reporting form, open a
**public issue requesting only an alternate private contact arrangement** and
omit all technical vulnerability details. Do not assume any unverified email
address is monitored.

## Handling, remediation, and disclosure

Maintainers evaluate private reports against the exact cited Git revision,
reproduce valid findings with deterministic regression or property tests, and
coordinate disclosure once a verified fix is merged to `main` (or document why a
report falls outside threat scope). Because SafeEvidence operates under a
zero-cost (`$0`) open-source research governance model
([ADR-0004](docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md)),
no paid bug bounty, commercial SLA, or paid external audit engagement is
offered.

Every security remediation landing on `main` requires:

- Ordinary DCO-signed commits (`Signed-off-by`) with no force-pushes or history
  rewrites on shared branches.
- Deterministic regression coverage proving the defect is closed.
- Independent exact-head security and engineering review plus passing protected
  GitHub Actions checks across Linux, macOS, and Windows.

## Relationship to governance records and optional external review

- **Issue [#3](https://github.com/TheHalfMoon/SafeEvidence/issues/3) &
  Issue [#4](https://github.com/TheHalfMoon/SafeEvidence/issues/4):** V1
  research-workstation intended use and automated `SafeEvidenceBench` scientific
  evaluation are ratified under [ADR-0003](docs/adr/0003-v1-research-workstation-scope-and-automated-scientific-evaluation.md);
  clinical validation and patient-data use remain out of scope (`FALSE`).
- **Issue [#5](https://github.com/TheHalfMoon/SafeEvidence/issues/5):** Public
  permissive-license slice admissions are governed by
  [ADR-0004](docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md)
  and enforced fail-closed by `tools/governance/source_admission_check.py`; DAL
  (`T14`) is permanently excluded under
  [ADR-0001](docs/adr/0001-permanently-remove-dal-and-adopt-clean-room-calibration-math.md).
- **Issue [#17](https://github.com/TheHalfMoon/SafeEvidence/issues/17):**
  Mandatory internal human review gates are superseded by
  [ADR-0002](docs/adr/0002-ai-assisted-security-qualification-framework.md).
  Qualified external human security researchers may still voluntarily share
  non-sensitive review interest in Issue #17 (or submit private vulnerability
  reports via GitHub Security Advisories); until an independent human security
  audit is formally completed and recorded, SafeEvidence continues to report
  `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`.

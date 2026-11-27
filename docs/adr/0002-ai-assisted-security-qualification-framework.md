# 0002. Replace Mandatory Human Engineering Review with AI-Assisted Security Qualification and Executable Evidence

Status: accepted (2026-11-27)

## Context
SafeEvidence previously held `EXT-06`, `D12`, `Issue #17`, and `PR #43` (`SECURITY.md`) open on recruiting an external unpaid human security reviewer, creating an indefinite governance deadlock on a zero-cost, solo-founder open-source project (`Apache-2.0`). On 2026-11-27, the Founder superseded mandatory human engineering and security review requirements with a rigorous, evidence-based independent AI review and executable verification framework while prohibiting forged human signatures or misrepresentation of AI reviewers.

## Decision
Mandatory human review is removed as a prerequisite for SafeEvidence V1 engineering completion, `SECURITY.md` (`PR #43`) integration, and V1 research release qualification. Every material engineering and security change is qualified under **Independent AI-Assisted Security Qualification Supported by Executable Evidence**, requiring: (1) multi-perspective fresh-context reviews distinct from the authoring agent (Google EGM Goldfish reviewers, Alibaba `ocr` local delegation, `jev`, PStack `/ps-review`, and independent Antigravity review agents, plus an exported ChatGPT independent review packet at major milestones), (2) static analysis (`clippy -D warnings`), supply-chain/socket gates (`cargo deny`, CycloneDX 1.5 SBOM, `TA-29`, `core_no_sockets.py`), threat modeling, deterministic structure-aware property/fuzz and adversarial suites (`TA-05`, `TA-15`, `TA-21`, `TA-26`, `TA-27`), and real WebView2/WebKitGTK end-to-end tests (`TA-20`), and (3) exact-head verification of all blocking findings before merge. Qualification records always report `AI_ASSISTED_SECURITY_QUALIFICATION = TRUE` separately from `HUMAN_INDEPENDENT_SECURITY_REVIEW = FALSE`.

## Consequences
+ Unblocks `PR #43` (`SECURITY.md` via $0 GitHub Private Vulnerability Reporting) and V1 security qualification with stronger automated adversarial, property, and multi-agent verification.
- Never claims third-party human security certification; if an external institution later requires a human audit, that audit is tracked on its own axis without blocking research engineering.

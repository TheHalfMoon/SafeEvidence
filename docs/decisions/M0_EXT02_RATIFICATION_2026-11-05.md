# EXT-02 Synthetic Scope Extension — Ratification (2026-11-05)

State: **EFFECTIVE ON NORMAL MERGE WITH POST-MERGE CI PASS.** Scope below only.

## Decision

Founder decision D1 and D3, in response to
`docs/decisions/M0_FOUNDER_DECISION_PACKET_2026-11-05.md`, recorded verbatim at
<https://github.com/TheHalfMoon/SafeEvidence/issues/17#issuecomment-6647499829>.

Accountable engineering owner: the founder.

## Allowed

- Third-party dependencies, and copies admitted by a `VERIFIED_ALLOWED` row in
  `docs/evidence/source_admissions.json`.
- Synthetic data and fixtures only.
- The `product/` Cargo workspace with its own toolchain pin (Rust 1.98.1, C16).

## Still excluded

Patient data, clinical claims, model weights, real corpora, signed packs, live
network fetch and release. Issues #3 and #4, the 41 P1 findings, EXT-05, EXT-06,
EXT-07 and EXT-09 are unchanged.

## Implementation PR merge rule (D3)

Required CI on the exact head, plus recorded tool and agent review on the PR. This
extends the planning-freeze waiver to implementation PRs. Agent review is not human
review and does not satisfy EXT-06.

## Admissions

This PR adds the validator and an empty ledger. **`NO_ADMISSIONS` remains true.** D2
and D4 (Issue #5) take effect row by row through later signed PRs.

## Deviations from the frozen plan, to carry into `plan-v1.1`

- C16 and EXT-02 describe re-pinning the G01a manifest and toolchain. G01a is instead
  left unchanged at the repository root, and product code uses the nested `product/`
  workspace. This keeps the qualified baseline intact and changes no G01a checker.
- Transplant destinations written as `crates/...` become `product/crates/...`.
- TA-01 is implemented by a new `tools/governance/source_admission_check.py`, because
  `p01_candidate_integrity.py` correctly rejects all admissions and stays as it is.
- This status record does not alter the frozen plan artifacts or their digests.

# Provenance: safeevidence-assurance

Admission `ADM-0005` (T13) in `docs/evidence/source_admissions.json`.

- Source: `TheHalfMoon/commandMed` @ `51f73ec05750137e5bd94ffa0765f6383f475fee`, `src/commandmed/spec006/policy.py`, Apache-2.0. Its Rust port is
  of mechanics only. **No donor files are copied**; every T13 file in the row is `not_copied`.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- `tests/fixtures/t13_precedence_vectors.json` holds outputs of the donor's `evaluate_precedence` over all combinations of
  up to three rules, from `bench/oracles/commandmed_spec006/generate_vectors.py`. It keeps the donor's first-of-agreeing-leaders
  behaviour.

## Deliberate differences from the donor

- No rules fired returns `NoRuleFired`, not `ANSWER`: a commit needs its own proof (P00).
- An emergency requirement fails closed to `ABSTAIN` at any precedence, even beside a rule requiring `ESCALATE`, where the
  donor would escalate. P00 disables `EMERGENCY_NOTICE` in V1.
- Equal-precedence conflicts fail toward P00's guard order: `BLOCKED`, `ESCALATE`, `CONFLICT`, then `ABSTAIN`. The donor has
  no `BLOCKED` or `CONFLICT` state, so the vectors do not cover these two.
- Only a blank rule ID is rejected as malformed. The donor's bundle validation is not ported, so unlike the donor, any
  precedence number is accepted, including out-of-range ones.

## Not covered

The donor's 17 fixture cases are not run. They need its tool registry and slot layer, use a patient-caregiver role V1 does not
serve, and 4 are lexical emergency cases P00 excludes. This is mechanics parity only, so **TA-13 is not met**: its fixture subset does not run, and this crate alone cannot
give exactly one `TerminalOutcome`, since it can return `NoRuleFired` or an action. Ask carries the lexical-emergency test today. `safeevidence-ask` calls it to resolve evidence-based guards only.

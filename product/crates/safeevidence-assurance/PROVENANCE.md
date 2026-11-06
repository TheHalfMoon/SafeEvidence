# Provenance: safeevidence-assurance

Admission `ADM-0005` (T13) in `docs/evidence/source_admissions.json`.

- Source: `TheHalfMoon/commandMed` @ `51f73ec05750137e5bd94ffa0765f6383f475fee`, `src/commandmed/spec006/policy.py`, Apache-2.0. Its Rust port is
  of mechanics only. **No donor code is copied.** Question texts from three donor fixture files are, so those are `adapted` in the row, and the other T13 files are `not_copied`.
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

## Fixture subset

`tests/fixtures/t13_cases_*.json` hold the question text of the donor's 17 fixture cases, the rules its pipeline fired and its final state, from
`bench/oracles/commandmed_spec006/generate_case_vectors.py`, which runs the donor's `spec006` code and data at generation time. The 5 excluded cases keep their text and reason only. The texts are test
inputs with no names or identifiers, not medical information. One is Arabic, as donor test input.

## Not covered

Under `plan-v1.4`, the subset is resolution only: the port resolves the rules the donor's pipeline chose, and does not detect them. It shows little beyond the mechanics vectors, as that amendment states. This crate alone cannot give exactly one `TerminalOutcome`, since it can return `NoRuleFired`
or an action. `safeevidence-ask` calls it to resolve evidence-based guards only. TA-13's DAL vectors are owed at WP-11.

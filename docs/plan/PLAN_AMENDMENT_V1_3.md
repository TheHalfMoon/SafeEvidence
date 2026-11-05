# Plan Amendment `plan-v1.3` (2026-11-05)

Amends TA-04 by pointer. Frozen artifacts and digests are unchanged.

## Declared narrowing

TA-04 says 100% of donor tests pass. Two pinned T01 tests in `record_semantics_019.rs` are excluded from WP-02:

- `amendment_lineage_append_only`
- `doctor_record_semantics_axis`

Both drive the donor's `CoreFacade`, a 259 KB module tied to donor runtime features that this slice does not import.
Importing it to run two tests would add far more than they verify.

`source_immutability.rs` is adapted rather than excluded. Its digest property is tested directly, including tampering.
The donor's overwrite stub always failed, so nothing is lost by having no overwrite API.

## Obligations this creates

- Append-only amendment lineage must be tested against the real vault-backed authority store before M1 exit.
- A record-semantics doctor check is owed by WP-18 if a doctor surface ships.

## Limits

This narrows only those two tests. Every other TA-04 clause is unchanged, and nothing here passes TA-04 by itself.

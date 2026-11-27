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

Tracked in `docs/IMPLEMENTATION_LEDGER.md`:

- **WP-03 or WP-12, before M1 exit:** a test against the real vault-backed store shows that an amendment appends
  a record and leaves the prior assertion's bytes unchanged. No such store exists yet. `amendment_record_round_trips_with_both_lineage_ids` covers shape only.
- **WP-03 or WP-12, before M1 exit:** a test shows stored source bytes cannot be replaced under an existing ID. Today's
  test covers digest checks only, and a record with new bytes and a recomputed digest still validates.
- **WP-18:** a record-semantics doctor check is required if a doctor surface ships.

## Status of this amendment

An engineering amendment, without a separate founder decision. It narrows exactly two tests and changes one by
rewriting it, as stated above. Every other TA-04 clause is unchanged, and nothing here passes TA-04 by itself.

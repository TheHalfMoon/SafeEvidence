# Provenance: safeevidence-proofstore

SafeEvidence-written from `docs/P00_PROOF_ADMISSION_CONTRACT.md` (GREENFIELD_JUSTIFIED, transplant matrix §5). No donor code.
It stores data through the T03 vault's lease-guarded handle.

Not covered: power loss, disk full, restore (a stale `-wal` beside a restored file would replay; handle this before restore ships),
a kill aimed inside a checkpoint, more than one writing process (no one-writer guard yet), retraction with no replacement, and
cross-store `EvidenceSnapshot` or outbox work. Commit does not check span locations or `source_version`; verification owns those.
A wrong key against a live WAL can merge that WAL into the main file while failing to open. TA-05 and TA-14 are not claimed.

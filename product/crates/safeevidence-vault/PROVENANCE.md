# Provenance: safeevidence-vault

Admission `ADM-0003` (T03) in `docs/evidence/source_admissions.json`.

- Source: `TheHalfMoon/ottari` @ `73706029849bcbe51243624e37f03a1969dc74ca`, `crates/himsat-core/`, Apache-2.0.
- Rights and publication decisions (D2, D4): https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- File list verified against the freeze commitment
  `f24789f513b17f79bf65bfc720b8fe4513861b6ee07f47581b948d08a33fe5dd` (37 files, 1,130,618 bytes).
- Copied and renamed: 29 `src/vault*.rs` modules and 5 tests. Product identifiers are renamed,
  including the Linux Secret Service namespace. Android's is a test constant, Apple's service name
  is caller-supplied, and Windows has no namespace, so the rename adds no separation on those three.
- Not renamed, deliberately: `HIMSAT/...` byte strings. They are cryptographic domain separators and
  wire magic. Binary formats use fixed offsets, and independent test vectors depend on these bytes.
- **Known limit: domains are shared with the donor product.** Separation relies on independent keys,
  and is not complete. Windows DPAPI uses the same user master key and entropy formula in both
  products. Recovery keys derive from passphrase and salt, with compatible envelopes, so a passphrase
  reused across products crosses them. Tracked in `docs/IMPLEMENTATION_LEDGER.md`.
- Not copied: `crates/himsat-events/src/lib.rs` (no slice code uses it) and
  `tests/b005d_journal_kill.rs` (tests the excluded media journal).
- Added: `tests/sqlcipher_kill_recovery.rs`, written for SafeEvidence. It tests hard process kills against
  SQLCipher in WAL and rollback-journal modes, with its own connection settings. It does not cover
  power loss, or the vault open API and its settings.
- `src/lib.rs` and `Cargo.toml` are adapted from the donor's, without its unrelated modules and audio dependencies; `src/lib.rs` keeps the donor's
  `forbid(unsafe_code)`, and is listed in the row but lies outside the 37-file commitment. One synthetic
  test marker was reworded.
- Not carried: native keystore tests and probes, which are not run here.
- SafeEvidence addition in `src/vault_sqlcipher.rs`: `immediate_transaction` and `deferred_transaction` with `GuardedTransaction`, `install_schema`,
  `configure_durable_store` and `durable_settings_hold`, the routes `safeevidence-proofstore` uses. `open_reviewed_connection` also
  turns recursive triggers on for every connection. Guarded calls run under a SQLite authorizer, using rusqlite's `hooks` feature,
  which adds no dependency. They limit statements to guard against bugs, not malicious
  in-process code.
- Two donor tests are corrected, for the same reason. `staged_byte_identity_mismatch_fails_before_sqlcipher_acceptance`
  and `staging_mutation_after_b505q_fails_before_local_copy_or_anchor` each wrote a fixed `0xff` over a random salt
  byte, so each failed about 1 run in 256 when the byte already held that value. Both now invert the byte.
- Donor tests changed after admission, when the Secret Service calls moved to the helper (see below):
  - `baseline_policy_is_same_user_session_without_presence_or_hardware_claim` stays here, now built through a
    `protector()` helper. Its assertions are unchanged.
  - `provider_errors_are_mapped_fail_closed`, `provider_metadata_is_fixed_plus_one_opaque_identifier` and
    `secret_service_transport_is_always_diffie_hellman_encrypted` moved to the helper's `src/secret_service_backend.rs`.
    The first now expects `WireError` where it expected `ProtectorError`. The second lost its assertion that the
    protector id prints as `LinuxProtectorId([OPAQUE; 16 bytes])`, which is kept here instead as
    `the_protector_id_is_opaque_in_debug_output`. The third is unchanged.
  - The real-provider tests `native_gnome_keyring_phase_1_store_and_inspect` and
    `native_gnome_keyring_phase_2_restart_unlock_delete_and_lock` became the helper's
    `tests/native_keyring.rs`, as `native_keyring_phase_1_store_and_inspect` and
    `native_keyring_phase_2_restart_unlock_delete_and_lock`, with a new phase 1b between them.
  - `src/lib.rs` dropped the donor's `build_identity_is_deterministic` at admission, with the identity it tested.
- **TA-05 for VS-1, under `plan-v1.5`'s reading:** kills just after each of eight acknowledged commits, through the
  vault open API, in `safeevidence-proofstore`'s `kill_during_commits_loses_no_acknowledged_answer`. That test also
  scans every file a killed store left, its WAL included, for answer text before anything reopens it. Not covered:
  a kill inside SQLite's own commit or before the first acknowledged commit, a crash during a checkpoint (none happens
  in the test), recovery to `COMMIT_UNKNOWN`, lock contention between processes, and power loss. The restart uses
  `ProofStore::open`, while the app reopens with `open_existing`. Disk-full, restore-to-clean and key loss are not
  carried, and stay owed at WP-03's full TA-05.

SafeEvidence change to `src/vault_linux_secret_service.rs`: the founder chose a separate helper process (2026-11-06), so that the core stays socket-free. The record format, binding and policy
checks stay here, and now compile on every OS. The Secret Service calls moved to `safeevidence-linux-keyring-helper`, reached over stdin and stdout through `safeevidence-keyring-wire`. Its tests
against a real provider moved with them.

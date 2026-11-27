# Provenance: safeevidence-vault

Admission `ADM-0003` (T03) in `docs/evidence/source_admissions.json`.

- Source: `TheHalfMoon/ottari` @ `73706029849bcbe51243624e37f03a1969dc74ca`, `crates/himsat-core/`, Apache-2.0.
- Rights and publication decisions (D2, D4): https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- File list verified against the freeze commitment
  `f24789f513b17f79bf65bfc720b8fe4513861b6ee07f47581b948d08a33fe5dd` (37 files, 1,130,618 bytes).
- Copied and renamed: 29 `src/vault*.rs` modules and 5 tests. Product identifiers and all cryptographic
  domain separators / wire-magic prefixes are separated from `HIMSAT/...` to the equal-length 6-byte
  `SAFEVD/...` namespace (`VAULT_DOMAIN_VERSION = "SAFEVD-v1"`), preserving every fixed wire offset across
  HKDF purpose/backup keys, bounded blobs, freshness manifests, Argon2id recovery envelopes, portable
  backups, Android Keystore, Apple Keychain, Linux Secret Service, and Windows DPAPI records/entropy.
  Independent deterministic vectors were recomputed outside Rust (`hmac`/`hashlib`/`cryptography` RFC 5869,
  `HChaCha20` + `ChaCha20Poly1305`, and `Argon2id` 64 MiB/3/4) after verifying 8/8 bit-for-bit reproduction
  of the donor vectors, and `tests/domain_separation.rs` (plus OS-record unit tests) proves authentic donor
  `HIMSAT/...` envelopes, forged-header envelopes, and same-user Windows DPAPI ciphertexts fail closed.
  Recovery envelopes preserve the fixed 16-byte raw salt layout (`SALT_OFFSET = 75`), so separation is
  enforced pre-KDF by `ENVELOPE_DOMAIN_PREFIX` (`InvalidDomain`) and cryptographically under header forgery
  by XChaCha20-Poly1305's `AAD_DOMAIN_PREFIX` (`RecoveryAuthenticationFailed`). Desktop synthetic stores
  bind `VAULT_DOMAIN_VERSION` into `store_key()` so pre-migration local folders remain untouched.
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
- SafeEvidence security hardening in `src/vault_sqlcipher.rs` (`RUSTSEC-2026-0459` / `CVE-2026-119375`):
  `validate_preopen_wal_page_size` inspects `<path>` and any sibling `<path>-wal` (via lossless `OsString` sidecar
  paths) before `Connection::open_with_flags` and `ATTACH DATABASE`, rejecting symlinks/non-files, non-empty `< 32`-byte
  WALs, and any `-wal` header whose big-endian page size (`bytes 8..12`) is not `4096`; snapshot/rotation target
  resolution also rejects dangling symlinks and pre-existing `-wal`/`-shm`/`-journal` sidecars; and
  `enforce_b303_provider_and_temp_posture` pins codec `cipher_page_size == 4096` (`SqlCipherOpenError::PageSizePosture`),
  so SQLCipher's page-level HMAC-SHA512 zeroes unauthenticated 4096-byte page buffers even across SQLite's lazy `-wal` open.
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
- **TA-05 durability, contention, disk-full, key-loss, and B505 restore evidence (`safeevidence-proofstore/tests/proof_commit.rs` and `safeevidence-proofstore/tests/ta05_diskfull_and_recovery.rs`):** kills just
  after each of eight acknowledged commits through `ProofStore::open` and `ProofStore::open_existing`,
  pre-reopen plaintext scans across `vault.db` and `-wal`, cross-process `IMMEDIATE` writer lock contention
  returning `StoreError::Busy` while concurrent WAL reads proceed, `snapshot_quiesced_sqlcipher_database`
  (`PRAGMA wal_checkpoint(TRUNCATE)`) followed by clean-directory restore + wrong-key rejection, post-checkpoint
  hot-WAL kill recovery, deterministic `PRAGMA max_page_count` (`SQLITE_FULL` -> `StoreError::DiskFull`) rollback
  across all write paths (`put_source`, `commit`, `put_assertion`, `amend_assertion`, `retract_source`),
  `ProofStore::verify_record_semantics_doctor` (`11` tables, `22` append-only triggers), Argon2id
  `SAFEVD/RECOVERY/ENVELOPE/v1` key-loss recovery (including live Windows DPAPI recovery in desktop `custody.rs`),
  and end-to-end B505 portable backup creation + tamper rejection + clean-directory fresh-device restore. Still not
  covered: physical power loss (`CommitUnknown` reconciliation is verified in desktop `ask_command.rs`).

SafeEvidence change to `src/vault_linux_secret_service.rs`: the founder chose a separate helper process (2026-11-06), so that the core stays socket-free. The record format, binding and policy
checks stay here, and now compile on every OS. The Secret Service calls moved to `safeevidence-linux-keyring-helper`, reached over stdin and stdout through `safeevidence-keyring-wire`. Its tests
against a real provider moved with them.

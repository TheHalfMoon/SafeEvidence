//! SafeEvidence private vault. Admission T03; see `PROVENANCE.md`.
//! Module declarations follow the donor crate root, without its unrelated modules.

#![forbid(unsafe_code)]

/// Provider-neutral vault identity, freshness, lease identity, capability, and
/// secret-protector contract surface.
pub mod vault;
/// B402 Android Keystore policy adapter over an injected native backend.
pub mod vault_android_keystore;
/// B401 Apple data-protection Keychain adapter with bounded B501D freshness state.
#[cfg(target_os = "macos")]
pub mod vault_apple_keychain;
/// B505 opaque portable-backup provider codec/key foundation.
pub mod vault_backup;
/// B505 recovery-bootstrap outer privacy/authentication boundary.
pub mod vault_backup_bootstrap;
/// B505 end-to-end portable backup creation coordination.
pub mod vault_backup_creation;
/// B505 encrypted portable-backup index codec and authenticated binding.
pub mod vault_backup_index;
pub mod vault_backup_packaging;
/// B505 immutable provider publication and reread-acceptance boundary.
pub mod vault_backup_provider;
/// Portable-backup fresh-device restore preparation.
pub mod vault_backup_restore;
/// B505 fresh-device durable local publication and protected-genesis commit.
pub mod vault_backup_restore_publication;
/// Canonical staged SQLCipher verification for authenticated portable backups.
pub mod vault_backup_sqlcipher;
/// B505 provider reconstruction and pre-SQLCipher semantic verification.
pub mod vault_backup_verify;
/// B202 versioned bounded-blob XChaCha20-Poly1305 envelope execution/parsing.
pub mod vault_blob;
/// B506 bounded active-vault deletion coordinator and retention limits.
pub mod vault_deletion;
/// B501 portable freshness open/genesis decision logic.
pub mod vault_freshness;
/// B105 lease-gated database/blob read/write wrappers and stale-handle proof.
pub mod vault_io;
/// B104/B201 portable key-domain, derivation, and secret-lifetime contracts.
pub mod vault_keys;
/// B102 in-process revocable keyed-handle lease and typed access errors.
pub mod vault_lease;
/// B404 Linux Secret Service adapter using an encrypted session and opaque lookup metadata.
#[cfg(target_os = "linux")]
pub mod vault_linux_secret_service;
/// B501A canonical authenticated freshness-manifest codec.
pub mod vault_manifest;
/// B307 bounded copy-verify-publish migration sequencing.
pub mod vault_migration;
/// B203 OS-CSPRNG nonce generation, reservation, retry, restore, and collision policy.
pub mod vault_nonce;
/// B103 portable secret-protector policy, capability, and binding validation.
pub mod vault_protector;
/// B204 fixed Argon2id v1 recovery-envelope execution/parsing.
pub mod vault_recovery;
/// B502 explicit older-backup and fresh-device restore state transitions.
pub mod vault_restore;
/// B503A full-VRK rotation identities, backend boundary, and quiescence proof.
pub mod vault_rotation;
/// B301 exact reviewed SQLCipher provider integration behind the B105 lease gate.
pub mod vault_sqlcipher;
/// B403 Windows current-user DPAPI adapter with ACL-restricted ciphertext storage.
#[cfg(target_os = "windows")]
pub mod vault_windows_dpapi;

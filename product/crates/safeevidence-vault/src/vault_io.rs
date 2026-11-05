//! Lease-gated database/blob I/O wrappers for Specification 004B1 B105.
//!
//! B105 proves that a previously obtained keyed database/blob handle cannot
//! reach its backend read/write operation after the owning vault lease becomes
//! terminal. The operation-scoped B102 permit is retained for the complete
//! backend call, so revocation publishes a terminal state, rejects new work, and
//! drains already-authorized work before returning.
//!
//! This module does not implement SQLCipher, blob encryption, HKDF, AEAD,
//! Argon2id, entropy acquisition, persistence, native secret stores, or a raw
//! storage provider. Those remain owned by later Specification 004 leaves. A
//! future concrete provider must stay behind an equivalent lease gate and must
//! not expose an ungated keyed backend that bypasses these semantics.
//!
//! Residual risk remains explicit: ordinary process teardown or abort may prevent
//! cleanup code from running; runtime/compiler/register/allocator copies, swap or
//! pagefile content, crash dumps, kernel memory, and physical media are outside
//! this in-process authorization proof. A fully compromised process while the
//! vault is unlocked can observe resident plaintext/key material and is not made
//! safe by this gate.

use crate::vault::VaultLeaseIdentity;
use crate::vault_lease::{KeyedHandleError, KeyedHandleLease};
use std::error::Error;
use std::fmt;

/// Error returned by a lease-gated database/blob operation.
#[derive(Debug, Eq, PartialEq)]
pub enum KeyedIoError<E> {
    /// The vault lease rejected the operation before the backend was invoked.
    Access(KeyedHandleError),
    /// The live lease authorized the operation and the backend itself failed.
    Backend(E),
}

impl<E> fmt::Display for KeyedIoError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Access(error) => write!(f, "keyed I/O access rejected: {error}"),
            Self::Backend(error) => write!(f, "keyed I/O backend failed: {error}"),
        }
    }
}

impl<E> Error for KeyedIoError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Access(error) => Some(error),
            Self::Backend(error) => Some(error),
        }
    }
}

struct LeaseBoundHandle<B> {
    lease: KeyedHandleLease,
    backend: B,
}

impl<B> LeaseBoundHandle<B> {
    fn new(lease: KeyedHandleLease, backend: B) -> Self {
        Self { lease, backend }
    }

    fn identity(&self) -> VaultLeaseIdentity {
        self.lease.identity()
    }

    fn read<T, E, F>(&self, operation: F) -> Result<T, KeyedIoError<E>>
    where
        F: FnOnce(&B) -> Result<T, E>,
    {
        let _permit = self.lease.authorize().map_err(KeyedIoError::Access)?;
        operation(&self.backend).map_err(KeyedIoError::Backend)
    }

    fn write<T, E, F>(&mut self, operation: F) -> Result<T, KeyedIoError<E>>
    where
        F: FnOnce(&mut B) -> Result<T, E>,
    {
        let _permit = self.lease.authorize().map_err(KeyedIoError::Access)?;
        operation(&mut self.backend).map_err(KeyedIoError::Backend)
    }
}

/// Previously obtainable keyed structured-database handle whose every operation
/// is guarded by the live vault lease.
///
/// The backend stays private so callers cannot obtain a raw mutable reference or
/// consume this wrapper to bypass the lease gate. Later SQLCipher integration may
/// place its concrete database backend behind this boundary only when B301 is
/// separately authorized.
pub struct LeaseBoundDatabaseHandle<B> {
    inner: LeaseBoundHandle<B>,
}

impl<B> LeaseBoundDatabaseHandle<B> {
    /// Binds one database backend to an already-issued keyed-handle lease.
    #[must_use]
    pub fn new(lease: KeyedHandleLease, backend: B) -> Self {
        Self {
            inner: LeaseBoundHandle::new(lease, backend),
        }
    }

    /// Returns the immutable vault/generation identity authorized for this handle.
    #[must_use]
    pub fn identity(&self) -> VaultLeaseIdentity {
        self.inner.identity()
    }

    /// Executes one database read while retaining an operation-scoped lease permit.
    ///
    /// If the lease is terminal, `operation` is not invoked.
    pub fn read<T, E, F>(&self, operation: F) -> Result<T, KeyedIoError<E>>
    where
        F: FnOnce(&B) -> Result<T, E>,
    {
        self.inner.read(operation)
    }

    /// Executes one database write while retaining an operation-scoped lease permit.
    ///
    /// If the lease is terminal, `operation` is not invoked.
    pub fn write<T, E, F>(&mut self, operation: F) -> Result<T, KeyedIoError<E>>
    where
        F: FnOnce(&mut B) -> Result<T, E>,
    {
        self.inner.write(operation)
    }
}

impl<B> fmt::Debug for LeaseBoundDatabaseHandle<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseBoundDatabaseHandle")
            .field("identity", &self.identity())
            .field("backend", &"[REDACTED]")
            .finish()
    }
}

/// Previously obtainable keyed bounded-blob handle whose every operation is
/// guarded by the live vault lease.
///
/// The backend stays private so callers cannot obtain a raw mutable reference or
/// consume this wrapper to bypass the lease gate. Later B202 blob-envelope work
/// may place its concrete encrypted backend behind this boundary only when that
/// leaf is separately authorized.
pub struct LeaseBoundBlobHandle<B> {
    inner: LeaseBoundHandle<B>,
}

impl<B> LeaseBoundBlobHandle<B> {
    /// Binds one blob backend to an already-issued keyed-handle lease.
    #[must_use]
    pub fn new(lease: KeyedHandleLease, backend: B) -> Self {
        Self {
            inner: LeaseBoundHandle::new(lease, backend),
        }
    }

    /// Returns the immutable vault/generation identity authorized for this handle.
    #[must_use]
    pub fn identity(&self) -> VaultLeaseIdentity {
        self.inner.identity()
    }

    /// Executes one blob read while retaining an operation-scoped lease permit.
    ///
    /// If the lease is terminal, `operation` is not invoked.
    pub fn read<T, E, F>(&self, operation: F) -> Result<T, KeyedIoError<E>>
    where
        F: FnOnce(&B) -> Result<T, E>,
    {
        self.inner.read(operation)
    }

    /// Executes one blob write while retaining an operation-scoped lease permit.
    ///
    /// If the lease is terminal, `operation` is not invoked.
    pub fn write<T, E, F>(&mut self, operation: F) -> Result<T, KeyedIoError<E>>
    where
        F: FnOnce(&mut B) -> Result<T, E>,
    {
        self.inner.write(operation)
    }
}

impl<B> fmt::Debug for LeaseBoundBlobHandle<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseBoundBlobHandle")
            .field("identity", &self.identity())
            .field("backend", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyedIoError, LeaseBoundBlobHandle, LeaseBoundDatabaseHandle};
    use crate::vault::{
        KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity, VaultLeaseState,
    };
    use crate::vault_keys::{
        KEY_MATERIAL_BYTES, KeyedHandleCloser, OwnedKeyMaterial, PlaintextCache, VaultKeyMaterial,
        VaultSessionLifetime, VaultTeardownReason,
    };
    use crate::vault_lease::{KeyedHandleError, VaultLease};
    use std::convert::Infallible;
    use std::error::Error;
    use std::fmt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn identity() -> VaultLeaseIdentity {
        VaultLeaseIdentity::new(
            VaultId::from_bytes([0x42; VAULT_ID_BYTES]),
            KeyGeneration::new(7).expect("test generation is non-zero"),
        )
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ProbeError(&'static str);

    impl fmt::Display for ProbeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for ProbeError {}

    #[derive(Debug, Default)]
    struct ProbeState {
        reads: AtomicUsize,
        writes: AtomicUsize,
    }

    struct ProbeBackend {
        state: Arc<ProbeState>,
        value: u64,
    }

    impl ProbeBackend {
        fn new(state: Arc<ProbeState>, value: u64) -> Self {
            Self { state, value }
        }

        fn read(&self) -> Result<u64, ProbeError> {
            self.state.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.value)
        }

        fn write(&mut self, value: u64) -> Result<(), ProbeError> {
            self.state.writes.fetch_add(1, Ordering::SeqCst);
            self.value = value;
            Ok(())
        }
    }

    struct NoopCloser;

    impl KeyedHandleCloser for NoopCloser {
        type Error = Infallible;

        fn close_keyed_handles(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct NoopCache;

    impl PlaintextCache for NoopCache {
        fn discard_plaintext(&mut self) {}
    }

    fn lifetime() -> VaultSessionLifetime<NoopCloser, NoopCache> {
        VaultSessionLifetime::new(
            VaultLease::new(identity()),
            NoopCloser,
            VaultKeyMaterial::new(OwnedKeyMaterial::from_bytes([0x11; KEY_MATERIAL_BYTES])),
            NoopCache,
        )
    }

    #[test]
    fn active_database_and_blob_handles_reach_their_backends_under_a_live_permit() {
        let lifetime = lifetime();
        let database_state = Arc::new(ProbeState::default());
        let blob_state = Arc::new(ProbeState::default());
        let mut database = LeaseBoundDatabaseHandle::new(
            lifetime.keyed_handle_lease(),
            ProbeBackend::new(Arc::clone(&database_state), 10),
        );
        let mut blob = LeaseBoundBlobHandle::new(
            lifetime.keyed_handle_lease(),
            ProbeBackend::new(Arc::clone(&blob_state), 20),
        );

        assert_eq!(database.identity(), identity());
        assert_eq!(blob.identity(), identity());
        assert_eq!(database.read(ProbeBackend::read), Ok(10));
        assert_eq!(blob.read(ProbeBackend::read), Ok(20));
        assert_eq!(database.write(|backend| backend.write(11)), Ok(()));
        assert_eq!(blob.write(|backend| backend.write(21)), Ok(()));
        assert_eq!(database.read(ProbeBackend::read), Ok(11));
        assert_eq!(blob.read(ProbeBackend::read), Ok(21));
        assert_eq!(database_state.reads.load(Ordering::SeqCst), 2);
        assert_eq!(database_state.writes.load(Ordering::SeqCst), 1);
        assert_eq!(blob_state.reads.load(Ordering::SeqCst), 2);
        assert_eq!(blob_state.writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn previously_obtained_database_and_blob_handles_reject_all_terminal_reasons() {
        let cases = [
            (VaultTeardownReason::Lock, KeyedHandleError::Locked),
            (VaultTeardownReason::Revocation, KeyedHandleError::Revoked),
            (VaultTeardownReason::FatalFailure, KeyedHandleError::Revoked),
            (VaultTeardownReason::Rotation, KeyedHandleError::Revoked),
        ];

        for (reason, expected_error) in cases {
            let mut lifetime = lifetime();
            let database_state = Arc::new(ProbeState::default());
            let blob_state = Arc::new(ProbeState::default());
            let mut database = LeaseBoundDatabaseHandle::new(
                lifetime.keyed_handle_lease(),
                ProbeBackend::new(Arc::clone(&database_state), 10),
            );
            let mut blob = LeaseBoundBlobHandle::new(
                lifetime.keyed_handle_lease(),
                ProbeBackend::new(Arc::clone(&blob_state), 20),
            );

            assert_eq!(database.read(ProbeBackend::read), Ok(10));
            assert_eq!(blob.write(|backend| backend.write(21)), Ok(()));
            let database_reads_before = database_state.reads.load(Ordering::SeqCst);
            let database_writes_before = database_state.writes.load(Ordering::SeqCst);
            let blob_reads_before = blob_state.reads.load(Ordering::SeqCst);
            let blob_writes_before = blob_state.writes.load(Ordering::SeqCst);

            lifetime
                .teardown(reason)
                .expect("noop closer cannot fail during B105 fixture teardown");
            assert_eq!(lifetime.lease_state(), VaultLeaseState::Revoked);

            assert_eq!(
                database.read(ProbeBackend::read),
                Err(KeyedIoError::Access(expected_error))
            );
            assert_eq!(
                database.write(|backend| backend.write(12)),
                Err(KeyedIoError::Access(expected_error))
            );
            assert_eq!(
                blob.read(ProbeBackend::read),
                Err(KeyedIoError::Access(expected_error))
            );
            assert_eq!(
                blob.write(|backend| backend.write(22)),
                Err(KeyedIoError::Access(expected_error))
            );

            assert_eq!(
                database_state.reads.load(Ordering::SeqCst),
                database_reads_before
            );
            assert_eq!(
                database_state.writes.load(Ordering::SeqCst),
                database_writes_before
            );
            assert_eq!(blob_state.reads.load(Ordering::SeqCst), blob_reads_before);
            assert_eq!(blob_state.writes.load(Ordering::SeqCst), blob_writes_before);
        }
    }

    #[test]
    fn backend_failure_remains_distinct_from_lease_rejection() {
        let lifetime = lifetime();
        let state = Arc::new(ProbeState::default());
        let database = LeaseBoundDatabaseHandle::new(
            lifetime.keyed_handle_lease(),
            ProbeBackend::new(state, 10),
        );

        let error = database
            .read(|_| Err::<(), _>(ProbeError("synthetic backend failure")))
            .expect_err("live lease must preserve backend failure");
        assert_eq!(
            error,
            KeyedIoError::Backend(ProbeError("synthetic backend failure"))
        );
    }

    #[test]
    fn wrapper_debug_does_not_expose_backend_debug_content() {
        #[derive(Debug)]
        struct SecretMarkerBackend(&'static str);

        let lease = VaultLease::new(identity());
        let database = LeaseBoundDatabaseHandle::new(
            lease.keyed_handle_lease(),
            SecretMarkerBackend("B105_SECRET_MARKER"),
        );
        let blob = LeaseBoundBlobHandle::new(
            lease.keyed_handle_lease(),
            SecretMarkerBackend("B105_SECRET_MARKER"),
        );

        let database_debug = format!("{database:?}");
        let blob_debug = format!("{blob:?}");
        assert!(!database_debug.contains("B105_SECRET_MARKER"));
        assert!(!blob_debug.contains("B105_SECRET_MARKER"));
        assert!(database_debug.contains("REDACTED"));
        assert!(blob_debug.contains("REDACTED"));

        let _ = database.inner.backend.0;
        let _ = blob.inner.backend.0;
    }

    #[test]
    fn revocation_waits_for_a_database_operation_holding_the_concrete_gate() {
        let lease = Arc::new(VaultLease::new(identity()));
        let operation_state = Arc::new(ProbeState::default());
        let database = LeaseBoundDatabaseHandle::new(
            lease.keyed_handle_lease(),
            ProbeBackend::new(operation_state, 10),
        );
        let stale_blob_state = Arc::new(ProbeState::default());
        let stale_blob = LeaseBoundBlobHandle::new(
            lease.keyed_handle_lease(),
            ProbeBackend::new(Arc::clone(&stale_blob_state), 20),
        );
        let (operation_started_tx, operation_started_rx) = std::sync::mpsc::channel();
        let (release_operation_tx, release_operation_rx) = std::sync::mpsc::channel();

        let operation = std::thread::spawn(move || {
            database
                .read(|backend| {
                    backend.state.reads.fetch_add(1, Ordering::SeqCst);
                    operation_started_tx
                        .send(())
                        .expect("test must publish operation start");
                    release_operation_rx
                        .recv()
                        .expect("test must release the in-flight operation");
                    Ok::<_, ProbeError>(backend.value)
                })
                .expect("operation beginning before revocation remains authorized")
        });

        operation_started_rx
            .recv()
            .expect("database operation must acquire its permit");

        let revoking_lease = Arc::clone(&lease);
        let (revocation_done_tx, revocation_done_rx) = std::sync::mpsc::channel();
        let revoker = std::thread::spawn(move || {
            let first_transition = revoking_lease.revoke();
            revocation_done_tx
                .send(first_transition)
                .expect("test must publish revocation completion");
        });

        while lease.state() == VaultLeaseState::Active {
            std::thread::yield_now();
        }

        assert_eq!(
            stale_blob.read(ProbeBackend::read),
            Err(KeyedIoError::Access(KeyedHandleError::Revoked))
        );
        assert_eq!(stale_blob_state.reads.load(Ordering::SeqCst), 0);
        assert_eq!(
            revocation_done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        );

        release_operation_tx
            .send(())
            .expect("test must release the in-flight operation");
        assert!(
            revocation_done_rx
                .recv()
                .expect("revocation must finish after the operation drains")
        );
        assert_eq!(
            operation
                .join()
                .expect("database operation thread must finish"),
            10
        );
        revoker.join().expect("revocation thread must finish");
    }
}

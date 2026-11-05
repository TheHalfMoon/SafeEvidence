//! Revocable keyed-handle lease and typed access errors for Specification 004B1 B102.
//!
//! This module implements only in-process lease revocation and portable error
//! propagation. It performs no cryptographic operation, entropy acquisition, key
//! destruction, persistence, protector behavior, database/blob I/O, or platform
//! secure-store work.

use crate::vault::{ProtectorError, VaultLeaseIdentity, VaultLeaseState};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard};

const LEASE_ACTIVE: u8 = 0;
const LEASE_LOCKED: u8 = 1;
const LEASE_REVOKED: u8 = 2;

/// Typed rejection returned by an existing keyed handle at its operation gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyedHandleError {
    /// The owning vault was explicitly locked.
    Locked,
    /// The owning lease was revoked for another fail-closed lifecycle reason.
    Revoked,
}

impl fmt::Display for KeyedHandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("vault is locked"),
            Self::Revoked => f.write_str("vault lease is revoked"),
        }
    }
}

impl Error for KeyedHandleError {}

/// Higher-level typed access error for portable vault behavior.
///
/// Protector errors remain nested without string conversion, including the
/// reviewed freshness-specific variants such as `AnchorConflict` and
/// `AnchorUpdateFailed`. B102 does not invent a second freshness state machine.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultAccessError {
    /// The vault has been locked and the keyed-handle lease no longer authorizes
    /// operations.
    Locked,
    /// The live keyed-handle lease was revoked for a non-lock lifecycle reason.
    Revoked,
    /// A provider-neutral protector operation failed. The exact typed
    /// `ProtectorError` is preserved.
    Protector(ProtectorError),
}

impl fmt::Display for VaultAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("vault is locked"),
            Self::Revoked => f.write_str("vault lease is revoked"),
            Self::Protector(error) => write!(f, "vault protector failure: {error}"),
        }
    }
}

impl Error for VaultAccessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Locked | Self::Revoked => None,
            Self::Protector(error) => Some(error),
        }
    }
}

impl From<KeyedHandleError> for VaultAccessError {
    fn from(error: KeyedHandleError) -> Self {
        match error {
            KeyedHandleError::Locked => Self::Locked,
            KeyedHandleError::Revoked => Self::Revoked,
        }
    }
}

impl From<ProtectorError> for VaultAccessError {
    fn from(error: ProtectorError) -> Self {
        Self::Protector(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseLifecycle {
    Active,
    Locked,
    Revoked,
}

impl LeaseLifecycle {
    const fn from_raw(raw: u8) -> Self {
        match raw {
            LEASE_ACTIVE => Self::Active,
            LEASE_LOCKED => Self::Locked,
            _ => Self::Revoked,
        }
    }

    const fn as_raw(self) -> u8 {
        match self {
            Self::Active => LEASE_ACTIVE,
            Self::Locked => LEASE_LOCKED,
            Self::Revoked => LEASE_REVOKED,
        }
    }

    const fn public_state(self) -> VaultLeaseState {
        match self {
            Self::Active => VaultLeaseState::Active,
            Self::Locked | Self::Revoked => VaultLeaseState::Revoked,
        }
    }

    const fn access_error(self) -> Option<KeyedHandleError> {
        match self {
            Self::Active => None,
            Self::Locked => Some(KeyedHandleError::Locked),
            Self::Revoked => Some(KeyedHandleError::Revoked),
        }
    }
}

#[derive(Debug)]
struct LeaseShared {
    lifecycle: AtomicU8,
    operation_barrier: RwLock<()>,
}

impl LeaseShared {
    fn new() -> Self {
        Self {
            lifecycle: AtomicU8::new(LEASE_ACTIVE),
            operation_barrier: RwLock::new(()),
        }
    }

    fn lifecycle(&self) -> LeaseLifecycle {
        LeaseLifecycle::from_raw(self.lifecycle.load(Ordering::Acquire))
    }

    fn fail_closed_if_poisoned(&self) {
        if self.operation_barrier.is_poisoned() {
            let _ = self.lifecycle.compare_exchange(
                LEASE_ACTIVE,
                LEASE_REVOKED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

/// Controller for one in-process vault lease.
///
/// The controller is intentionally not `Clone`: keyed consumers receive
/// `KeyedHandleLease` values that can authorize operations but cannot revoke or
/// reactivate the shared lease. A terminal lease never becomes active again.
#[derive(Debug)]
pub struct VaultLease {
    identity: VaultLeaseIdentity,
    shared: Arc<LeaseShared>,
}

impl VaultLease {
    /// Creates one active in-process lease bound to exactly one vault and key
    /// generation.
    #[must_use]
    pub fn new(identity: VaultLeaseIdentity) -> Self {
        Self {
            identity,
            shared: Arc::new(LeaseShared::new()),
        }
    }

    /// Returns the immutable vault/generation identity bound to this lease.
    #[must_use]
    pub const fn identity(&self) -> VaultLeaseIdentity {
        self.identity
    }

    /// Returns the externally visible active/revoked state.
    ///
    /// A poisoned synchronization primitive is converted to terminal revoked
    /// state so a panic cannot silently preserve authorization.
    #[must_use]
    pub fn state(&self) -> VaultLeaseState {
        self.shared.fail_closed_if_poisoned();
        self.shared.lifecycle().public_state()
    }

    /// Creates a non-revoking authorization token for a keyed handle.
    #[must_use]
    pub fn keyed_handle_lease(&self) -> KeyedHandleLease {
        KeyedHandleLease {
            identity: self.identity,
            shared: Arc::clone(&self.shared),
        }
    }

    /// Revokes the lease because the vault is being locked.
    ///
    /// The terminal state is published before waiting for already-authorized
    /// operations to drain, so no operation beginning after publication can
    /// obtain a new permit. Returns `true` only for the first terminal transition.
    pub fn revoke_for_lock(&self) -> bool {
        self.terminate(LeaseLifecycle::Locked)
    }

    /// Revokes the lease for a non-lock lifecycle failure such as protector
    /// revocation, rotation quiescence, authentication failure, or fatal
    /// integrity/freshness failure.
    ///
    /// This method establishes only the lease barrier. Later authorized leaves
    /// own concrete handle closure, key-object release, and reviewed zeroization.
    pub fn revoke(&self) -> bool {
        self.terminate(LeaseLifecycle::Revoked)
    }

    fn terminate(&self, requested: LeaseLifecycle) -> bool {
        self.shared.fail_closed_if_poisoned();

        let first_transition = self
            .shared
            .lifecycle
            .compare_exchange(
                LEASE_ACTIVE,
                requested.as_raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();

        // Every revocation caller crosses the exclusive barrier before returning,
        // including repeated callers. Therefore return from `revoke*` means any
        // operation permit granted before the terminal publication has drained.
        match self.shared.operation_barrier.write() {
            Ok(_guard) => {}
            Err(poisoned) => {
                self.shared.fail_closed_if_poisoned();
                drop(poisoned.into_inner());
            }
        }

        first_transition
    }
}

/// Cloneable lease reference held by a keyed database/blob handle.
///
/// It cannot change lifecycle state. Callers must acquire an authorization
/// permit immediately around each keyed operation; retaining only this token is
/// not evidence that the lease remains active.
#[derive(Clone, Debug)]
pub struct KeyedHandleLease {
    identity: VaultLeaseIdentity,
    shared: Arc<LeaseShared>,
}

impl KeyedHandleLease {
    /// Returns the immutable vault/generation identity this handle must match.
    #[must_use]
    pub const fn identity(&self) -> VaultLeaseIdentity {
        self.identity
    }

    /// Acquires an operation-scoped authorization permit.
    ///
    /// Authorization checks lifecycle both before and after acquiring the shared
    /// operation barrier. A revocation race therefore either becomes an
    /// already-authorized in-flight operation that the revoker drains, or fails
    /// before a permit is returned. Poisoning fails closed as `Revoked`.
    pub fn authorize(&self) -> Result<KeyedHandlePermit<'_>, KeyedHandleError> {
        if let Some(error) = self.shared.lifecycle().access_error() {
            return Err(error);
        }

        let guard = match self.shared.operation_barrier.read() {
            Ok(guard) => guard,
            Err(_) => {
                self.shared.fail_closed_if_poisoned();
                return Err(KeyedHandleError::Revoked);
            }
        };

        if let Some(error) = self.shared.lifecycle().access_error() {
            return Err(error);
        }

        Ok(KeyedHandlePermit {
            identity: self.identity,
            _guard: guard,
        })
    }
}

/// Operation-scoped evidence that a keyed handle observed a live lease.
///
/// The permit must not be cached across operations. Its held read guard is the
/// synchronization barrier paired with `VaultLease` revocation.
#[must_use = "keep the permit alive for the complete keyed operation"]
pub struct KeyedHandlePermit<'a> {
    identity: VaultLeaseIdentity,
    _guard: RwLockReadGuard<'a, ()>,
}

impl KeyedHandlePermit<'_> {
    /// Returns the immutable vault/generation identity authorized by this permit.
    #[must_use]
    pub const fn identity(&self) -> VaultLeaseIdentity {
        self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyedHandleError, VaultAccessError, VaultLease};
    use crate::vault::{
        KeyGeneration, ProtectorError, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity, VaultLeaseState,
    };
    use std::error::Error;

    fn identity() -> VaultLeaseIdentity {
        VaultLeaseIdentity::new(
            VaultId::from_bytes([0x42; VAULT_ID_BYTES]),
            KeyGeneration::new(7).expect("test generation is non-zero"),
        )
    }

    #[test]
    fn active_lease_authorizes_identity_bound_handle() {
        let identity = identity();
        let lease = VaultLease::new(identity);
        let handle = lease.keyed_handle_lease();

        assert_eq!(lease.identity(), identity);
        assert_eq!(lease.state(), VaultLeaseState::Active);
        assert_eq!(handle.identity(), identity);

        let permit = handle.authorize().expect("active lease must authorize");
        assert_eq!(permit.identity(), identity);
    }

    #[test]
    fn lock_revocation_rejects_existing_and_future_handle_tokens() {
        let lease = VaultLease::new(identity());
        let existing = lease.keyed_handle_lease();

        assert!(lease.revoke_for_lock());
        assert_eq!(lease.state(), VaultLeaseState::Revoked);
        assert_eq!(existing.authorize().err(), Some(KeyedHandleError::Locked));

        let future = lease.keyed_handle_lease();
        assert_eq!(future.authorize().err(), Some(KeyedHandleError::Locked));
        assert!(!lease.revoke());
    }

    #[test]
    fn non_lock_revocation_rejects_stale_handles_as_revoked() {
        let lease = VaultLease::new(identity());
        let handle = lease.keyed_handle_lease();

        assert!(lease.revoke());
        assert_eq!(handle.authorize().err(), Some(KeyedHandleError::Revoked));
        assert!(!lease.revoke_for_lock());
    }

    #[test]
    fn first_terminal_reason_wins_and_lease_never_reactivates() {
        let lease = VaultLease::new(identity());
        let handle = lease.keyed_handle_lease();

        assert!(lease.revoke_for_lock());
        assert!(!lease.revoke_for_lock());
        assert!(!lease.revoke());
        assert_eq!(lease.state(), VaultLeaseState::Revoked);
        assert_eq!(handle.authorize().err(), Some(KeyedHandleError::Locked));
    }

    #[test]
    fn revocation_publishes_terminal_state_before_in_flight_permit_drains() {
        let lease = std::sync::Arc::new(VaultLease::new(identity()));
        let handle = lease.keyed_handle_lease();
        let in_flight_handle = handle.clone();
        let (permit_ready_tx, permit_ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let operation = std::thread::spawn(move || {
            let _permit = in_flight_handle
                .authorize()
                .expect("operation must start before revocation");
            permit_ready_tx
                .send(())
                .expect("test must publish permit readiness");
            release_rx
                .recv()
                .expect("test must release the in-flight operation");
        });

        permit_ready_rx
            .recv()
            .expect("in-flight operation must acquire its permit");

        let revoking_lease = std::sync::Arc::clone(&lease);
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

        assert_eq!(handle.authorize().err(), Some(KeyedHandleError::Revoked));
        assert_eq!(
            revocation_done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        );

        release_tx
            .send(())
            .expect("test must release the in-flight operation");
        assert!(
            revocation_done_rx
                .recv()
                .expect("revocation must complete after permit drains")
        );

        operation.join().expect("in-flight operation must finish");
        revoker.join().expect("revocation thread must finish");
    }

    #[test]
    fn synchronization_poisoning_fails_closed() {
        let lease = VaultLease::new(identity());
        let handle = lease.keyed_handle_lease();
        let shared = std::sync::Arc::clone(&lease.shared);

        let poison_result = std::thread::spawn(move || {
            let _guard = shared
                .operation_barrier
                .write()
                .expect("fresh lease synchronization must start healthy");
            panic!("intentional B102 synchronization poison fixture");
        })
        .join();

        assert!(poison_result.is_err());
        assert_eq!(lease.state(), VaultLeaseState::Revoked);
        assert_eq!(handle.authorize().err(), Some(KeyedHandleError::Revoked));
        assert!(!lease.revoke());
    }

    #[test]
    fn access_error_preserves_handle_and_protector_error_classes() {
        assert_eq!(
            VaultAccessError::from(KeyedHandleError::Locked),
            VaultAccessError::Locked
        );
        assert_eq!(
            VaultAccessError::from(KeyedHandleError::Revoked),
            VaultAccessError::Revoked
        );
        assert_eq!(
            VaultAccessError::from(ProtectorError::Locked),
            VaultAccessError::Protector(ProtectorError::Locked)
        );
        assert_eq!(
            VaultAccessError::from(ProtectorError::AnchorConflict),
            VaultAccessError::Protector(ProtectorError::AnchorConflict)
        );
        assert_eq!(
            VaultAccessError::from(ProtectorError::AnchorUpdateFailed),
            VaultAccessError::Protector(ProtectorError::AnchorUpdateFailed)
        );
    }

    #[test]
    fn wrapped_protector_error_remains_a_typed_source() {
        let access = VaultAccessError::from(ProtectorError::AnchorConflict);
        assert!(access.source().is_some());
    }
}

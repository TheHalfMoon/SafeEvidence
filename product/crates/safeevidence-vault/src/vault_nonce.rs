//! Reviewed nonce-generation and reservation lifecycle for Specification 004 B203.
//!
//! This module owns only nonce lifecycle policy. It does not serialize or authenticate
//! manifests, choose canonical storage objects, advance freshness anchors, or implement
//! recovery. Callers hydrate the ledger only from already authenticated canonical
//! inventory/history and later persist accepted reservations through separately
//! authorized manifest/freshness work.

use crate::vault::{KeyGeneration, VaultId};
use crate::vault_blob::{
    BOUNDED_BLOB_NONCE_BYTES, BoundedBlobContext, BoundedBlobError, encrypt_bounded_blob,
};
use crate::vault_keys::OwnedKeyMaterial;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// Exact v1 XChaCha20-Poly1305 nonce length used by B202/B203.
pub const VAULT_NONCE_BYTES: usize = BOUNDED_BLOB_NONCE_BYTES;

/// Purpose-key domain whose nonce uniqueness is tracked independently.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NoncePurpose {
    /// B201 bounded-blob purpose key.
    BoundedBlob,
    /// B201 freshness-manifest purpose key.
    FreshnessManifest,
}

/// One public nonce reservation bound to the exact vault, purpose, and generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NonceReservation {
    vault_id: VaultId,
    purpose: NoncePurpose,
    key_generation: KeyGeneration,
    nonce: [u8; VAULT_NONCE_BYTES],
}

impl NonceReservation {
    /// Creates a reservation from already validated public cryptographic metadata.
    #[must_use]
    pub const fn new(
        vault_id: VaultId,
        purpose: NoncePurpose,
        key_generation: KeyGeneration,
        nonce: [u8; VAULT_NONCE_BYTES],
    ) -> Self {
        Self {
            vault_id,
            purpose,
            key_generation,
            nonce,
        }
    }

    /// Returns the vault identity in the nonce uniqueness domain.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns the purpose-key domain in the nonce uniqueness domain.
    #[must_use]
    pub const fn purpose(self) -> NoncePurpose {
        self.purpose
    }

    /// Returns the key generation in the nonce uniqueness domain.
    #[must_use]
    pub const fn key_generation(self) -> KeyGeneration {
        self.key_generation
    }

    /// Returns the exact public 24-byte nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; VAULT_NONCE_BYTES] {
        self.nonce
    }
}

/// Fail-closed B203 nonce lifecycle failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceLifecycleError {
    /// The approved OS-CSPRNG provider failed to fill the complete nonce.
    RandomnessUnavailable,
    /// A reservation belongs to a different vault than this ledger.
    VaultMismatch,
    /// Authenticated canonical inventory/history contains a duplicate reservation.
    CorruptOrTampered,
}

impl fmt::Display for NonceLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RandomnessUnavailable => "approved OS-CSPRNG nonce generation failed",
            Self::VaultMismatch => "nonce reservation belongs to a different vault",
            Self::CorruptOrTampered => {
                "authenticated canonical nonce inventory contains a duplicate"
            }
        };
        f.write_str(message)
    }
}

impl Error for NonceLifecycleError {}

/// Failure returned by the B203 production bounded-blob encryption path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshBoundedBlobError {
    /// Nonce generation or reservation failed before encryption could complete.
    Nonce(NonceLifecycleError),
    /// The already reviewed B202 bounded-blob envelope operation failed.
    Envelope(BoundedBlobError),
}

impl fmt::Display for FreshBoundedBlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nonce(error) => write!(f, "bounded-blob nonce lifecycle failed: {error}"),
            Self::Envelope(error) => write!(f, "bounded-blob envelope operation failed: {error}"),
        }
    }
}

impl Error for FreshBoundedBlobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Nonce(error) => Some(error),
            Self::Envelope(error) => Some(error),
        }
    }
}

/// One freshly encrypted B202 envelope plus the exact B203 reservation that must
/// be represented by the later authenticated canonical inventory before publication.
#[derive(Debug, Eq, PartialEq)]
pub struct FreshBoundedBlob {
    reservation: NonceReservation,
    envelope: Vec<u8>,
}

impl FreshBoundedBlob {
    fn new(reservation: NonceReservation, envelope: Vec<u8>) -> Self {
        Self {
            reservation,
            envelope,
        }
    }

    /// Returns the exact nonce reservation associated with this candidate envelope.
    #[must_use]
    pub const fn reservation(&self) -> NonceReservation {
        self.reservation
    }

    /// Returns the complete canonical B202 envelope bytes.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Consumes the candidate and returns its reservation and canonical envelope.
    #[must_use]
    pub fn into_parts(self) -> (NonceReservation, Vec<u8>) {
        (self.reservation, self.envelope)
    }
}

/// In-process view of authenticated canonical reservations plus every candidate
/// consumed by the current write/retry lifecycle.
///
/// The ledger is deliberately not a persistence format. B501 owns authenticated
/// manifest serialization/publication and freshness-anchor state. Keeping abandoned
/// candidates in this ledger ensures that retries in the same operation cannot reuse
/// an earlier candidate even when publication outcome is ambiguous.
#[derive(Debug)]
pub struct NonceReservationLedger {
    vault_id: VaultId,
    reservations: BTreeSet<NonceReservation>,
}

impl NonceReservationLedger {
    /// Creates an empty ledger for one vault.
    #[must_use]
    pub fn new(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            reservations: BTreeSet::new(),
        }
    }

    /// Hydrates a ledger only from nonce metadata whose enclosing inventory/history
    /// has already been authenticated and canonically parsed by its owning layer.
    ///
    /// # Errors
    ///
    /// Returns `VaultMismatch` for cross-vault metadata or `CorruptOrTampered` when
    /// the same vault/purpose/generation/nonce reservation appears more than once.
    pub fn from_authenticated_canonical_reservations<I>(
        vault_id: VaultId,
        reservations: I,
    ) -> Result<Self, NonceLifecycleError>
    where
        I: IntoIterator<Item = NonceReservation>,
    {
        let mut ledger = Self::new(vault_id);
        for reservation in reservations {
            ledger.record_authenticated_canonical_reservation(reservation)?;
        }
        Ok(ledger)
    }

    /// Returns the vault identity bound to this ledger.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the number of canonical, pending, or abandoned reservations that
    /// this ledger currently protects from reuse.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Returns whether the exact reservation is currently protected from reuse.
    #[must_use]
    pub fn contains(&self, reservation: NonceReservation) -> bool {
        self.reservations.contains(&reservation)
    }

    /// Records one exact nonce from an already authenticated canonical envelope or
    /// retained manifest history without generating or changing that nonce.
    ///
    /// This is the B203 restore/copy boundary: existing authenticated ciphertext is
    /// preserved byte-for-byte, while a duplicate canonical reservation in the same
    /// uniqueness domain fails closed.
    ///
    /// # Errors
    ///
    /// Returns `VaultMismatch` for cross-vault metadata and `CorruptOrTampered` for
    /// an exact duplicate reservation.
    pub fn record_authenticated_canonical_reservation(
        &mut self,
        reservation: NonceReservation,
    ) -> Result<(), NonceLifecycleError> {
        if reservation.vault_id != self.vault_id {
            return Err(NonceLifecycleError::VaultMismatch);
        }
        if !self.reservations.insert(reservation) {
            return Err(NonceLifecycleError::CorruptOrTampered);
        }
        Ok(())
    }

    /// Generates and immediately reserves a fresh nonce for one bounded-blob
    /// encryption attempt.
    ///
    /// A collision with authenticated, pending, or abandoned reservations is
    /// discarded and a new OS-CSPRNG candidate is generated. A provider failure
    /// returns before a candidate is added.
    ///
    /// # Errors
    ///
    /// Returns `VaultMismatch` when the blob context belongs to another vault, or
    /// `RandomnessUnavailable` when the approved OS source fails.
    pub fn reserve_fresh_blob_nonce(
        &mut self,
        context: BoundedBlobContext,
    ) -> Result<NonceReservation, NonceLifecycleError> {
        if context.vault_id() != self.vault_id {
            return Err(NonceLifecycleError::VaultMismatch);
        }
        self.reserve_fresh_with(
            NoncePurpose::BoundedBlob,
            context.key_generation(),
            |nonce| getrandom::fill(nonce).map_err(|_| ()),
        )
    }

    /// Generates and immediately reserves a fresh nonce for one manifest encryption
    /// attempt. Retained authenticated manifest-history nonces must be loaded into
    /// this ledger before generation so collision scanning covers that history.
    ///
    /// # Errors
    ///
    /// Returns `VaultMismatch` when the supplied vault identity differs from the
    /// ledger, or `RandomnessUnavailable` when the approved OS source fails.
    pub fn reserve_fresh_manifest_nonce(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
    ) -> Result<NonceReservation, NonceLifecycleError> {
        if vault_id != self.vault_id {
            return Err(NonceLifecycleError::VaultMismatch);
        }
        self.reserve_fresh_with(NoncePurpose::FreshnessManifest, key_generation, |nonce| {
            getrandom::fill(nonce).map_err(|_| ())
        })
    }

    /// Generates and reserves a fresh manifest nonce while excluding one exact
    /// authenticated source reservation from the candidate space without adding
    /// that source reservation to this ledger.
    pub(crate) fn reserve_fresh_manifest_nonce_avoiding(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
        forbidden: NonceReservation,
    ) -> Result<NonceReservation, NonceLifecycleError> {
        if vault_id != self.vault_id || forbidden.vault_id() != vault_id {
            return Err(NonceLifecycleError::VaultMismatch);
        }
        if forbidden.purpose() != NoncePurpose::FreshnessManifest
            || forbidden.key_generation() != key_generation
        {
            return Err(NonceLifecycleError::CorruptOrTampered);
        }
        self.reserve_fresh_with_excluding(
            NoncePurpose::FreshnessManifest,
            key_generation,
            Some(forbidden),
            |nonce| getrandom::fill(nonce).map_err(|_| ()),
        )
    }

    /// Production B203 entry point for a new bounded-blob encryption attempt.
    ///
    /// The nonce is reserved before B202 encryption. If B202 then fails, the nonce
    /// intentionally remains reserved as an abandoned candidate so a retry cannot
    /// reuse it. Successful publication remains the responsibility of the later
    /// authenticated manifest/inventory layer.
    ///
    /// # Errors
    ///
    /// Returns the exact nonce-lifecycle or B202 envelope failure. No fallback nonce
    /// source is attempted.
    pub fn encrypt_fresh_bounded_blob(
        &mut self,
        vrk: &OwnedKeyMaterial,
        context: BoundedBlobContext,
        plaintext: &[u8],
    ) -> Result<FreshBoundedBlob, FreshBoundedBlobError> {
        let reservation = self
            .reserve_fresh_blob_nonce(context)
            .map_err(FreshBoundedBlobError::Nonce)?;
        let envelope = encrypt_bounded_blob(vrk, context, reservation.nonce(), plaintext)
            .map_err(FreshBoundedBlobError::Envelope)?;
        Ok(FreshBoundedBlob::new(reservation, envelope))
    }

    fn reserve_fresh_with<F>(
        &mut self,
        purpose: NoncePurpose,
        key_generation: KeyGeneration,
        fill: F,
    ) -> Result<NonceReservation, NonceLifecycleError>
    where
        F: FnMut(&mut [u8; VAULT_NONCE_BYTES]) -> Result<(), ()>,
    {
        self.reserve_fresh_with_excluding(purpose, key_generation, None, fill)
    }

    fn reserve_fresh_with_excluding<F>(
        &mut self,
        purpose: NoncePurpose,
        key_generation: KeyGeneration,
        forbidden: Option<NonceReservation>,
        mut fill: F,
    ) -> Result<NonceReservation, NonceLifecycleError>
    where
        F: FnMut(&mut [u8; VAULT_NONCE_BYTES]) -> Result<(), ()>,
    {
        loop {
            let mut nonce = [0_u8; VAULT_NONCE_BYTES];
            fill(&mut nonce).map_err(|()| NonceLifecycleError::RandomnessUnavailable)?;
            let reservation = NonceReservation::new(self.vault_id, purpose, key_generation, nonce);
            if forbidden == Some(reservation) {
                continue;
            }
            if self.reservations.insert(reservation) {
                return Ok(reservation);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_blob::decrypt_bounded_blob;
    use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};

    const VAULT_A: [u8; 16] = [0x11; 16];
    const VAULT_B: [u8; 16] = [0x22; 16];
    const ARTIFACT: [u8; 16] = [0x33; 16];
    const NONCE_A: [u8; VAULT_NONCE_BYTES] = [0x44; VAULT_NONCE_BYTES];
    const NONCE_B: [u8; VAULT_NONCE_BYTES] = [0x55; VAULT_NONCE_BYTES];

    fn vault_a() -> VaultId {
        VaultId::from_bytes(VAULT_A)
    }

    fn vault_b() -> VaultId {
        VaultId::from_bytes(VAULT_B)
    }

    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).expect("fixture generation is non-zero")
    }

    fn blob_context(value: u64) -> BoundedBlobContext {
        BoundedBlobContext::new(vault_a(), ARTIFACT, generation(value))
    }

    #[test]
    fn production_blob_path_reserves_one_os_generated_nonce() {
        let mut ledger = NonceReservationLedger::new(vault_a());
        let reservation = ledger.reserve_fresh_blob_nonce(blob_context(1)).unwrap();

        assert_eq!(reservation.vault_id(), vault_a());
        assert_eq!(reservation.purpose(), NoncePurpose::BoundedBlob);
        assert_eq!(reservation.key_generation(), generation(1));
        assert!(ledger.contains(reservation));
        assert_eq!(ledger.reservation_count(), 1);
    }

    #[test]
    fn production_encrypt_path_uses_a_reserved_fresh_nonce() {
        let vrk = OwnedKeyMaterial::from_bytes([0x66; KEY_MATERIAL_BYTES]);
        let context = blob_context(1);
        let mut ledger = NonceReservationLedger::new(vault_a());
        let candidate = ledger
            .encrypt_fresh_bounded_blob(&vrk, context, b"b203 production path")
            .unwrap();

        assert!(ledger.contains(candidate.reservation()));
        assert_eq!(candidate.reservation().purpose(), NoncePurpose::BoundedBlob);
        assert_eq!(
            decrypt_bounded_blob(&vrk, context, candidate.envelope()).unwrap(),
            b"b203 production path"
        );
    }

    #[test]
    fn randomness_failure_is_fail_closed_and_does_not_reserve_partial_candidate() {
        let mut ledger = NonceReservationLedger::new(vault_a());
        let result = ledger.reserve_fresh_with(NoncePurpose::BoundedBlob, generation(1), |nonce| {
            nonce[..8].fill(0xaa);
            Err(())
        });

        assert_eq!(result, Err(NonceLifecycleError::RandomnessUnavailable));
        assert_eq!(ledger.reservation_count(), 0);
    }

    #[test]
    fn collision_is_discarded_and_regenerated_before_reservation() {
        let existing =
            NonceReservation::new(vault_a(), NoncePurpose::BoundedBlob, generation(1), NONCE_A);
        let mut ledger = NonceReservationLedger::from_authenticated_canonical_reservations(
            vault_a(),
            [existing],
        )
        .unwrap();
        let candidates = [NONCE_A, NONCE_B];
        let mut index = 0_usize;

        let reserved = ledger
            .reserve_fresh_with(NoncePurpose::BoundedBlob, generation(1), |nonce| {
                *nonce = candidates[index];
                index += 1;
                Ok(())
            })
            .unwrap();

        assert_eq!(reserved.nonce(), NONCE_B);
        assert_eq!(index, 2);
        assert_eq!(ledger.reservation_count(), 2);
    }

    #[test]
    fn retry_keeps_abandoned_candidate_reserved_and_never_reuses_it() {
        let mut ledger = NonceReservationLedger::new(vault_a());
        let first = ledger
            .reserve_fresh_with(NoncePurpose::BoundedBlob, generation(1), |nonce| {
                *nonce = NONCE_A;
                Ok(())
            })
            .unwrap();
        let candidates = [NONCE_A, NONCE_B];
        let mut index = 0_usize;
        let retry = ledger
            .reserve_fresh_with(NoncePurpose::BoundedBlob, generation(1), |nonce| {
                *nonce = candidates[index];
                index += 1;
                Ok(())
            })
            .unwrap();

        assert_eq!(first.nonce(), NONCE_A);
        assert_eq!(retry.nonce(), NONCE_B);
        assert_eq!(index, 2);
        assert_eq!(ledger.reservation_count(), 2);
    }

    #[test]
    fn restore_records_exact_authenticated_nonce_without_generation() {
        let restored =
            NonceReservation::new(vault_a(), NoncePurpose::BoundedBlob, generation(7), NONCE_A);
        let mut ledger = NonceReservationLedger::new(vault_a());

        ledger
            .record_authenticated_canonical_reservation(restored)
            .unwrap();

        assert!(ledger.contains(restored));
        assert_eq!(restored.nonce(), NONCE_A);
        assert_eq!(ledger.reservation_count(), 1);
    }

    #[test]
    fn exact_duplicate_canonical_blob_nonce_is_corrupt_or_tampered() {
        let duplicate =
            NonceReservation::new(vault_a(), NoncePurpose::BoundedBlob, generation(1), NONCE_A);

        assert_eq!(
            NonceReservationLedger::from_authenticated_canonical_reservations(
                vault_a(),
                [duplicate, duplicate],
            )
            .unwrap_err(),
            NonceLifecycleError::CorruptOrTampered
        );
    }

    #[test]
    fn exact_duplicate_retained_manifest_nonce_is_corrupt_or_tampered() {
        let duplicate = NonceReservation::new(
            vault_a(),
            NoncePurpose::FreshnessManifest,
            generation(2),
            NONCE_A,
        );

        assert_eq!(
            NonceReservationLedger::from_authenticated_canonical_reservations(
                vault_a(),
                [duplicate, duplicate],
            )
            .unwrap_err(),
            NonceLifecycleError::CorruptOrTampered
        );
    }

    #[test]
    fn manifest_collision_is_discarded_and_regenerated() {
        let existing = NonceReservation::new(
            vault_a(),
            NoncePurpose::FreshnessManifest,
            generation(3),
            NONCE_A,
        );
        let mut ledger = NonceReservationLedger::from_authenticated_canonical_reservations(
            vault_a(),
            [existing],
        )
        .unwrap();
        let candidates = [NONCE_A, NONCE_B];
        let mut index = 0_usize;

        let reservation = ledger
            .reserve_fresh_with(NoncePurpose::FreshnessManifest, generation(3), |nonce| {
                *nonce = candidates[index];
                index += 1;
                Ok(())
            })
            .unwrap();

        assert_eq!(reservation.nonce(), NONCE_B);
        assert_eq!(index, 2);
    }

    #[test]
    fn explicit_forbidden_manifest_nonce_is_discarded_without_ledger_insertion() {
        let forbidden = NonceReservation::new(
            vault_a(),
            NoncePurpose::FreshnessManifest,
            generation(3),
            NONCE_A,
        );
        let mut ledger = NonceReservationLedger::new(vault_a());
        let candidates = [NONCE_A, NONCE_B];
        let mut index = 0_usize;

        let reservation = ledger
            .reserve_fresh_with_excluding(
                NoncePurpose::FreshnessManifest,
                generation(3),
                Some(forbidden),
                |nonce| {
                    *nonce = candidates[index];
                    index += 1;
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(reservation.nonce(), NONCE_B);
        assert!(!ledger.contains(forbidden));
        assert!(ledger.contains(reservation));
        assert_eq!(ledger.reservation_count(), 1);
        assert_eq!(index, 2);
    }

    #[test]
    fn same_nonce_is_allowed_across_distinct_generation_or_purpose_keys() {
        let reservations = [
            NonceReservation::new(vault_a(), NoncePurpose::BoundedBlob, generation(1), NONCE_A),
            NonceReservation::new(vault_a(), NoncePurpose::BoundedBlob, generation(2), NONCE_A),
            NonceReservation::new(
                vault_a(),
                NoncePurpose::FreshnessManifest,
                generation(1),
                NONCE_A,
            ),
        ];

        let ledger = NonceReservationLedger::from_authenticated_canonical_reservations(
            vault_a(),
            reservations,
        )
        .unwrap();
        assert_eq!(ledger.reservation_count(), 3);
    }

    #[test]
    fn cross_vault_reservation_fails_closed() {
        let reservation =
            NonceReservation::new(vault_b(), NoncePurpose::BoundedBlob, generation(1), NONCE_A);
        let mut ledger = NonceReservationLedger::new(vault_a());

        assert_eq!(
            ledger.record_authenticated_canonical_reservation(reservation),
            Err(NonceLifecycleError::VaultMismatch)
        );
        assert_eq!(ledger.reservation_count(), 0);
    }

    #[test]
    fn blob_and_manifest_generation_reject_cross_vault_requests() {
        let mut ledger = NonceReservationLedger::new(vault_a());
        let wrong_blob = BoundedBlobContext::new(vault_b(), ARTIFACT, generation(1));

        assert_eq!(
            ledger.reserve_fresh_blob_nonce(wrong_blob),
            Err(NonceLifecycleError::VaultMismatch)
        );
        assert_eq!(
            ledger.reserve_fresh_manifest_nonce(vault_b(), generation(1)),
            Err(NonceLifecycleError::VaultMismatch)
        );
        assert_eq!(ledger.reservation_count(), 0);
    }
}

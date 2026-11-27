//! Portable authenticated freshness decisions for Specification 004 B501.

use crate::vault::{FreshnessAnchor, ManifestHash, ProtectedFreshnessState, VaultId};
use crate::vault_keys::OwnedKeyMaterial;
use crate::vault_manifest::{
    ManifestError, ManifestPlaintext, decrypt_manifest, manifest_context, manifest_hash,
};
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessDecision {
    Current,
    RecoverInterruptedPublication {
        expected_old: FreshnessAnchor,
        new_anchor: FreshnessAnchor,
    },
    InstallGenesis {
        new_anchor: FreshnessAnchor,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessError {
    Manifest(ManifestError),
    CorruptOrTampered,
    RollbackDetected,
    FreshnessGap,
    AnchorAlreadyInitialized,
}

impl From<ManifestError> for FreshnessError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Manifest(_) => "freshness manifest failed authentication or canonical parsing",
            Self::CorruptOrTampered => "freshness chain is corrupt or tampered",
            Self::RollbackDetected => "manifest freshness epoch is older than the protected anchor",
            Self::FreshnessGap => "manifest freshness epoch has an unexplained gap",
            Self::AnchorAlreadyInitialized => "freshness genesis is already initialized",
        })
    }
}
impl Error for FreshnessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedFreshnessManifest {
    manifest: ManifestPlaintext,
    hash: ManifestHash,
    decision: FreshnessDecision,
}

impl AuthenticatedFreshnessManifest {
    #[must_use]
    pub const fn manifest(&self) -> &ManifestPlaintext {
        &self.manifest
    }
    #[must_use]
    pub const fn hash(&self) -> ManifestHash {
        self.hash
    }
    #[must_use]
    pub const fn decision(&self) -> FreshnessDecision {
        self.decision
    }
}

pub fn authenticate_for_open(
    vrk: &OwnedKeyMaterial,
    anchor: FreshnessAnchor,
    envelope: &[u8],
) -> Result<AuthenticatedFreshnessManifest, FreshnessError> {
    let context = manifest_context(envelope)?;
    let manifest = decrypt_manifest(vrk, context, envelope)?;
    if context.vault_id() != anchor.vault_id() {
        return Err(FreshnessError::CorruptOrTampered);
    }
    let hash = manifest_hash(envelope);
    let epoch = manifest.freshness_epoch();
    let decision = match epoch.cmp(&anchor.highest_epoch()) {
        Ordering::Less => return Err(FreshnessError::RollbackDetected),
        Ordering::Equal => {
            if hash != anchor.manifest_hash() {
                return Err(FreshnessError::CorruptOrTampered);
            }
            FreshnessDecision::Current
        }
        Ordering::Greater => {
            let next = anchor
                .highest_epoch()
                .get()
                .checked_add(1)
                .ok_or(FreshnessError::FreshnessGap)?;
            if epoch.get() != next {
                return Err(FreshnessError::FreshnessGap);
            }
            if manifest.previous_manifest_hash() != anchor.manifest_hash() {
                return Err(FreshnessError::CorruptOrTampered);
            }
            FreshnessDecision::RecoverInterruptedPublication {
                expected_old: anchor,
                new_anchor: FreshnessAnchor::new(anchor.vault_id(), epoch, hash),
            }
        }
    };
    Ok(AuthenticatedFreshnessManifest {
        manifest,
        hash,
        decision,
    })
}

pub fn authenticate_genesis_candidate(
    vrk: &OwnedKeyMaterial,
    expected_vault_id: VaultId,
    state: ProtectedFreshnessState,
    envelope: &[u8],
) -> Result<AuthenticatedFreshnessManifest, FreshnessError> {
    let context = manifest_context(envelope)?;
    let manifest = decrypt_manifest(vrk, context, envelope)?;
    if context.vault_id() != expected_vault_id || context.freshness_epoch().get() != 1 {
        return Err(FreshnessError::CorruptOrTampered);
    }
    if matches!(state, ProtectedFreshnessState::Present(_)) {
        return Err(FreshnessError::AnchorAlreadyInitialized);
    }
    let hash = manifest_hash(envelope);
    let anchor = FreshnessAnchor::new(context.vault_id(), context.freshness_epoch(), hash);
    Ok(AuthenticatedFreshnessManifest {
        manifest,
        hash,
        decision: FreshnessDecision::InstallGenesis { new_anchor: anchor },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{FreshnessEpoch, KeyGeneration, VaultId};
    use crate::vault_manifest::{
        GenerationState, ManifestAuthMetadata, ManifestContext, ManifestGeneration, ManifestObject,
        RotationPhase, encrypt_fresh_manifest,
    };
    use crate::vault_nonce::NonceReservationLedger;

    fn vault() -> VaultId {
        VaultId::from_bytes([0x11; 16])
    }
    fn generation() -> KeyGeneration {
        KeyGeneration::new(1).expect("generation")
    }
    fn epoch(value: u64) -> FreshnessEpoch {
        FreshnessEpoch::new(value).expect("epoch")
    }
    fn key() -> OwnedKeyMaterial {
        OwnedKeyMaterial::from_bytes([0x22; 32])
    }
    fn manifest(value: u64, previous: ManifestHash) -> ManifestPlaintext {
        ManifestPlaintext::new(
            vault(),
            epoch(value),
            previous,
            generation(),
            (RotationPhase::None, None),
            vec![ManifestGeneration::new(
                generation(),
                GenerationState::Active,
            )],
            vec![ManifestObject::new(
                [0; 16],
                [0x33; 16],
                generation(),
                4096,
                [0x44; 32],
                ManifestAuthMetadata::StructuredStore,
            )],
        )
        .expect("valid manifest")
    }
    fn envelope(value: u64, previous: ManifestHash, _nonce: u8) -> Vec<u8> {
        let context = ManifestContext::new(vault(), generation(), epoch(value));
        let mut ledger = NonceReservationLedger::new(vault());
        let (_reservation, envelope) =
            encrypt_fresh_manifest(&mut ledger, &key(), context, &manifest(value, previous))
                .expect("encrypt");
        envelope
    }

    #[test]
    fn current_rollback_chain_mismatch_and_gap_fail_closed() {
        let current = envelope(2, ManifestHash::from_bytes([0x77; 32]), 1);
        let anchor = FreshnessAnchor::new(vault(), epoch(2), manifest_hash(&current));
        assert_eq!(
            authenticate_for_open(&key(), anchor, &current)
                .expect("current")
                .decision(),
            FreshnessDecision::Current
        );
        let old = envelope(1, ManifestHash::from_bytes([0; 32]), 2);
        assert_eq!(
            authenticate_for_open(&key(), anchor, &old),
            Err(FreshnessError::RollbackDetected)
        );
        let wrong = FreshnessAnchor::new(vault(), epoch(2), ManifestHash::from_bytes([9; 32]));
        assert_eq!(
            authenticate_for_open(&key(), wrong, &current),
            Err(FreshnessError::CorruptOrTampered)
        );
        let wrong_vault = FreshnessAnchor::new(
            VaultId::from_bytes([0x99; 16]),
            epoch(2),
            manifest_hash(&current),
        );
        assert_eq!(
            authenticate_for_open(&key(), wrong_vault, &current),
            Err(FreshnessError::CorruptOrTampered)
        );
        let gap = envelope(4, manifest_hash(&current), 3);
        assert_eq!(
            authenticate_for_open(&key(), anchor, &gap),
            Err(FreshnessError::FreshnessGap)
        );
    }

    #[test]
    fn authentication_precedes_open_and_genesis_decisions() {
        let current = envelope(2, ManifestHash::from_bytes([0x77; 32]), 8);
        let wrong_vault_anchor = FreshnessAnchor::new(
            VaultId::from_bytes([0x99; 16]),
            epoch(2),
            manifest_hash(&current),
        );
        let mut tampered_open = current.clone();
        let last = tampered_open.len() - 1;
        tampered_open[last] ^= 1;
        assert_eq!(
            authenticate_for_open(&key(), wrong_vault_anchor, &tampered_open),
            Err(FreshnessError::Manifest(
                ManifestError::AuthenticationFailed
            ))
        );

        let genesis = envelope(1, ManifestHash::from_bytes([0; 32]), 9);
        let present = FreshnessAnchor::new(vault(), epoch(2), manifest_hash(&current));
        let mut tampered_genesis = genesis;
        let last = tampered_genesis.len() - 1;
        tampered_genesis[last] ^= 1;
        assert_eq!(
            authenticate_genesis_candidate(
                &key(),
                vault(),
                ProtectedFreshnessState::Present(present),
                &tampered_genesis,
            ),
            Err(FreshnessError::Manifest(
                ManifestError::AuthenticationFailed
            ))
        );
    }

    #[test]
    fn exactly_next_link_is_recoverable_and_genesis_is_explicit() {
        let current = envelope(2, ManifestHash::from_bytes([0x77; 32]), 4);
        let anchor = FreshnessAnchor::new(vault(), epoch(2), manifest_hash(&current));
        let next = envelope(3, anchor.manifest_hash(), 5);
        assert!(matches!(
            authenticate_for_open(&key(), anchor, &next).expect("recoverable").decision(),
            FreshnessDecision::RecoverInterruptedPublication { expected_old, new_anchor }
                if expected_old == anchor && new_anchor.highest_epoch() == epoch(3)
        ));
        let broken_link = envelope(3, ManifestHash::from_bytes([0x88; 32]), 7);
        assert_eq!(
            authenticate_for_open(&key(), anchor, &broken_link),
            Err(FreshnessError::CorruptOrTampered)
        );
        let genesis = envelope(1, ManifestHash::from_bytes([0; 32]), 6);
        assert!(
            authenticate_genesis_candidate(
                &key(),
                vault(),
                ProtectedFreshnessState::Uninitialized,
                &genesis
            )
            .is_ok()
        );
        assert_eq!(
            authenticate_genesis_candidate(
                &key(),
                vault(),
                ProtectedFreshnessState::Present(anchor),
                &genesis
            ),
            Err(FreshnessError::AnchorAlreadyInitialized)
        );
        assert_eq!(
            authenticate_genesis_candidate(
                &key(),
                VaultId::from_bytes([0x99; 16]),
                ProtectedFreshnessState::Uninitialized,
                &genesis,
            ),
            Err(FreshnessError::CorruptOrTampered)
        );
    }
}

//! B307 copy-verify-publish migration sequencing.
//!
//! This module owns only the bounded migration coordinator required before the
//! platform-protector and full-rotation leaves. The source side is exposed only
//! through shared references, and this API intentionally contains no source
//! retirement or deletion operation. B503/B506 own later retirement semantics.

use std::error::Error;
use std::fmt;

/// Durable B307 boundaries whose failure must leave the prior verified source
/// available for recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyVerifyPublishStage {
    /// Re-prove the already-existing encrypted source before copying it.
    SourceVerification,
    /// Copy the verified source into non-canonical staged target state.
    Copy,
    /// Authenticate and integrity-check the complete staged target.
    StagedVerification,
    /// Publish the already-verified target without retiring the source.
    Publication,
    /// Bind the published target through the caller's separately authorized anchor.
    Anchor,
    /// Reopen the exact published target through its production path.
    Reopen,
    /// Integrity-check the reopened published target.
    ReopenedVerification,
}

impl fmt::Display for CopyVerifyPublishStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SourceVerification => "source verification",
            Self::Copy => "copy",
            Self::StagedVerification => "staged verification",
            Self::Publication => "publication",
            Self::Anchor => "anchor",
            Self::Reopen => "reopen",
            Self::ReopenedVerification => "reopened verification",
        };
        f.write_str(label)
    }
}

/// Read-only source boundary for B307 migration.
///
/// Implementations must not destroy, rekey in place, rename away, or otherwise
/// make the source unrecoverable. Both operations receive `&self`; the B307
/// coordinator has no retirement capability by construction.
pub trait EncryptedMigrationSource<Target> {
    /// Caller-defined failure type shared with the bounded target adapter.
    type Error;

    /// Re-proves that the prior encrypted source is a known-good recovery state.
    fn verify_source(&self) -> Result<(), Self::Error>;

    /// Copies the verified source into the target's non-canonical staged state.
    fn copy_into(&self, target: &mut Target) -> Result<(), Self::Error>;
}

/// Target-side operations required by the bounded B307 coordinator.
pub trait EncryptedMigrationTarget {
    /// Caller-defined failure type shared with the source adapter.
    type Error;

    /// Authenticates and integrity-checks the complete staged target.
    fn verify_staged_copy(&mut self) -> Result<(), Self::Error>;

    /// Publishes the already-verified target while the prior source remains intact.
    fn publish_verified_copy(&mut self) -> Result<(), Self::Error>;

    /// Anchors the exact published target through a separately authorized mechanism.
    fn anchor_published_copy(&mut self) -> Result<(), Self::Error>;

    /// Reopens the exact published target through its production open path.
    fn reopen_published_copy(&mut self) -> Result<(), Self::Error>;

    /// Integrity-checks the reopened target after publication and anchoring.
    fn verify_reopened_copy(&mut self) -> Result<(), Self::Error>;
}

/// B307 failure bound to the exact durable boundary that rejected the migration.
#[derive(Debug, Eq, PartialEq)]
pub struct CopyVerifyPublishError<E> {
    stage: CopyVerifyPublishStage,
    source: E,
}

impl<E> CopyVerifyPublishError<E> {
    fn new(stage: CopyVerifyPublishStage, source: E) -> Self {
        Self { stage, source }
    }

    /// Exact B307 boundary that failed.
    #[must_use]
    pub const fn stage(&self) -> CopyVerifyPublishStage {
        self.stage
    }

    /// Caller-defined underlying failure.
    #[must_use]
    pub const fn source_error(&self) -> &E {
        &self.source
    }
}

impl<E: fmt::Display> fmt::Display for CopyVerifyPublishError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B307 {} failed: {}", self.stage, self.source)
    }
}

impl<E: Error + 'static> Error for CopyVerifyPublishError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Proof marker returned only after the published target was anchored, reopened,
/// and integrity-verified. It does not retire or authorize destruction of source
/// state; later leaves own those semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyVerifyPublishComplete {
    _private: (),
}

/// Executes the bounded B307 copy-verify-publish sequence.
///
/// The coordinator never receives mutable access to the source and exposes no
/// source-retirement operation. Any failure returns immediately at its exact
/// boundary, so later target steps are not attempted.
pub fn run_copy_verify_publish<Source, Target, E>(
    source: &Source,
    target: &mut Target,
) -> Result<CopyVerifyPublishComplete, CopyVerifyPublishError<E>>
where
    Source: EncryptedMigrationSource<Target, Error = E>,
    Target: EncryptedMigrationTarget<Error = E>,
{
    source.verify_source().map_err(|error| {
        CopyVerifyPublishError::new(CopyVerifyPublishStage::SourceVerification, error)
    })?;
    source
        .copy_into(target)
        .map_err(|error| CopyVerifyPublishError::new(CopyVerifyPublishStage::Copy, error))?;
    target.verify_staged_copy().map_err(|error| {
        CopyVerifyPublishError::new(CopyVerifyPublishStage::StagedVerification, error)
    })?;
    target
        .publish_verified_copy()
        .map_err(|error| CopyVerifyPublishError::new(CopyVerifyPublishStage::Publication, error))?;
    target
        .anchor_published_copy()
        .map_err(|error| CopyVerifyPublishError::new(CopyVerifyPublishStage::Anchor, error))?;
    target
        .reopen_published_copy()
        .map_err(|error| CopyVerifyPublishError::new(CopyVerifyPublishStage::Reopen, error))?;
    target.verify_reopened_copy().map_err(|error| {
        CopyVerifyPublishError::new(CopyVerifyPublishStage::ReopenedVerification, error)
    })?;

    Ok(CopyVerifyPublishComplete { _private: () })
}

#[cfg(test)]
mod tests {
    use super::{
        CopyVerifyPublishStage, EncryptedMigrationSource, EncryptedMigrationTarget,
        run_copy_verify_publish,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestError(CopyVerifyPublishStage);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "injected {} failure", self.0)
        }
    }

    impl std::error::Error for TestError {}

    struct RecordingSource {
        ciphertext: Vec<u8>,
        fail_at: Option<CopyVerifyPublishStage>,
    }

    struct RecordingTarget {
        fail_at: Option<CopyVerifyPublishStage>,
        events: Vec<CopyVerifyPublishStage>,
        staged_ciphertext: Vec<u8>,
    }

    impl EncryptedMigrationSource<RecordingTarget> for RecordingSource {
        type Error = TestError;

        fn verify_source(&self) -> Result<(), Self::Error> {
            if self.fail_at == Some(CopyVerifyPublishStage::SourceVerification) {
                return Err(TestError(CopyVerifyPublishStage::SourceVerification));
            }
            Ok(())
        }

        fn copy_into(&self, target: &mut RecordingTarget) -> Result<(), Self::Error> {
            target.events.push(CopyVerifyPublishStage::Copy);
            if self.fail_at == Some(CopyVerifyPublishStage::Copy)
                || target.fail_at == Some(CopyVerifyPublishStage::Copy)
            {
                return Err(TestError(CopyVerifyPublishStage::Copy));
            }
            target.staged_ciphertext.clone_from(&self.ciphertext);
            Ok(())
        }
    }

    impl EncryptedMigrationTarget for RecordingTarget {
        type Error = TestError;

        fn verify_staged_copy(&mut self) -> Result<(), Self::Error> {
            self.record(CopyVerifyPublishStage::StagedVerification)
        }

        fn publish_verified_copy(&mut self) -> Result<(), Self::Error> {
            self.record(CopyVerifyPublishStage::Publication)
        }

        fn anchor_published_copy(&mut self) -> Result<(), Self::Error> {
            self.record(CopyVerifyPublishStage::Anchor)
        }

        fn reopen_published_copy(&mut self) -> Result<(), Self::Error> {
            self.record(CopyVerifyPublishStage::Reopen)
        }

        fn verify_reopened_copy(&mut self) -> Result<(), Self::Error> {
            self.record(CopyVerifyPublishStage::ReopenedVerification)
        }
    }

    impl RecordingTarget {
        fn record(&mut self, stage: CopyVerifyPublishStage) -> Result<(), TestError> {
            self.events.push(stage);
            if self.fail_at == Some(stage) {
                Err(TestError(stage))
            } else {
                Ok(())
            }
        }
    }

    fn target(fail_at: Option<CopyVerifyPublishStage>) -> RecordingTarget {
        RecordingTarget {
            fail_at,
            events: Vec::new(),
            staged_ciphertext: Vec::new(),
        }
    }

    #[test]
    fn success_preserves_source_and_executes_every_target_boundary_in_order() {
        let source = RecordingSource {
            ciphertext: vec![0xA5; 64],
            fail_at: None,
        };
        let original = source.ciphertext.clone();
        let mut target = target(None);

        let result = run_copy_verify_publish(&source, &mut target);

        assert!(result.is_ok());
        assert_eq!(source.ciphertext, original);
        assert_eq!(target.staged_ciphertext, original);
        assert_eq!(
            target.events,
            vec![
                CopyVerifyPublishStage::Copy,
                CopyVerifyPublishStage::StagedVerification,
                CopyVerifyPublishStage::Publication,
                CopyVerifyPublishStage::Anchor,
                CopyVerifyPublishStage::Reopen,
                CopyVerifyPublishStage::ReopenedVerification,
            ]
        );
    }

    #[test]
    fn every_failure_boundary_stops_forward_progress_and_preserves_source() {
        let failure_stages = [
            CopyVerifyPublishStage::SourceVerification,
            CopyVerifyPublishStage::Copy,
            CopyVerifyPublishStage::StagedVerification,
            CopyVerifyPublishStage::Publication,
            CopyVerifyPublishStage::Anchor,
            CopyVerifyPublishStage::Reopen,
            CopyVerifyPublishStage::ReopenedVerification,
        ];

        for failure_stage in failure_stages {
            let source = RecordingSource {
                ciphertext: vec![0x3C; 64],
                fail_at: (failure_stage == CopyVerifyPublishStage::SourceVerification)
                    .then_some(failure_stage),
            };
            let original = source.ciphertext.clone();
            let mut target = target(
                (failure_stage != CopyVerifyPublishStage::SourceVerification)
                    .then_some(failure_stage),
            );

            let error = run_copy_verify_publish(&source, &mut target)
                .expect_err("injected B307 boundary must fail");

            assert_eq!(error.stage(), failure_stage);
            assert_eq!(source.ciphertext, original);
            if failure_stage == CopyVerifyPublishStage::SourceVerification {
                assert!(target.events.is_empty());
            } else {
                assert_eq!(target.events.last(), Some(&failure_stage));
            }
        }
    }
}

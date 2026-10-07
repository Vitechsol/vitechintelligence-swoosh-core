#![forbid(unsafe_code)]

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub use trust_kernel::{
    ActionReceiptV2, ActionReceiptV3, ActionRequestV2, ActionRequestV3, Decision, DecisionReason,
    DecisionReceipt, FreshnessAssurance, TrustError, TrustPackMetadata, MAX_ACTION_WIRE_BYTES,
    MAX_CLAIM_WIRE_BYTES, MAX_TRUST_PACK_WIRE_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdkError {
    ClockBeforeUnixEpoch,
    Action(trust_kernel::ActionError),
    NewerEpochRequired,
    Trust(TrustError),
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockBeforeUnixEpoch => {
                formatter.write_str("host clock is before the Unix epoch")
            }
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Action(error) => write!(formatter, "{error}"),
            Self::NewerEpochRequired => {
                formatter.write_str("authoritative newer state requires synchronization")
            }
        }
    }
}

impl std::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Trust(error) => Some(error),
            Self::ClockBeforeUnixEpoch => None,
            Self::Action(_) | Self::NewerEpochRequired => None,
        }
    }
}

/// An installed, pinned state handle. Only the trusted host owns this value.
/// Persistence, authentication, monotonic epoch storage and process isolation remain host duties.
pub struct InstalledTrustContext {
    pack: Vec<u8>,
    metadata: TrustPackMetadata,
    minimum_epoch: u64,
}
impl InstalledTrustContext {
    pub fn install_at(pack: &[u8], checkpoint: &[u8; 32], now: u64) -> Result<Self, SdkError> {
        let metadata = trust_kernel::verify_initial_trust_pack(pack, checkpoint, now)?;
        let minimum_epoch = metadata.trust_epoch;
        Ok(Self {
            pack: pack.to_vec(),
            metadata,
            minimum_epoch,
        })
    }
    pub fn update_at(&mut self, candidate: &[u8], now: u64) -> Result<(), SdkError> {
        let metadata = trust_kernel::verify_trust_pack_transition(&self.pack, candidate, now)?;
        self.pack = candidate.to_vec();
        self.metadata = metadata;
        Ok(())
    }
    /// Call only after authenticating a publisher's epoch announcement.
    pub fn note_authoritative_epoch(&mut self, epoch: u64) {
        self.minimum_epoch = self.minimum_epoch.max(epoch);
    }
    pub fn metadata(&self) -> &TrustPackMetadata {
        &self.metadata
    }
    /// Evaluate a canonical claim only after this context has been installed from an
    /// externally pinned checkpoint and any authoritative epoch floor has been applied.
    pub fn evaluate_claim_at(
        &self,
        claim: &[u8],
        now: u64,
    ) -> Result<DecisionReceipt, SdkError> {
        if self.metadata.trust_epoch < self.minimum_epoch {
            return Err(SdkError::NewerEpochRequired);
        }
        trust_kernel::evaluate_claim(claim, &self.pack, now).map_err(Into::into)
    }
    pub fn evaluate_action_at(
        &self,
        action: &[u8],
        request: &trust_kernel::ActionRequestV2,
        now: u64,
    ) -> Result<trust_kernel::ActionReceiptV2, SdkError> {
        if self.metadata.trust_epoch < self.minimum_epoch {
            return Err(SdkError::NewerEpochRequired);
        }
        trust_kernel::evaluate_action_v2(action, &self.pack, now, request).map_err(SdkError::Action)
    }

    pub fn evaluate_action_v3_at(
        &self,
        action: &[u8],
        request: &trust_kernel::ActionRequestV3,
        now: u64,
    ) -> Result<trust_kernel::ActionReceiptV3, SdkError> {
        if self.metadata.trust_epoch < self.minimum_epoch {
            return Err(SdkError::NewerEpochRequired);
        }
        trust_kernel::evaluate_action_v3(action, &self.pack, now, request).map_err(SdkError::Action)
    }
}

impl From<TrustError> for SdkError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

/// Evaluates raw canonical claim and TrustPack buffers using the host's current Unix clock.
///
/// The SDK intentionally forwards the borrowed buffers to the canonical kernel. It does not
/// reproduce parsing, cryptographic verification, freshness, revocation, or policy semantics.
pub fn evaluate_claim(claim_bytes: &[u8], trust_pack: &[u8]) -> Result<DecisionReceipt, SdkError> {
    let evaluation_time = unix_time_now()?;
    trust_kernel::evaluate_claim(claim_bytes, trust_pack, evaluation_time).map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TrustPackManager;

impl TrustPackManager {
    pub fn verify_initial(
        candidate: &[u8],
        expected_checkpoint: &[u8; 32],
    ) -> Result<TrustPackMetadata, SdkError> {
        let evaluation_time = unix_time_now()?;
        trust_kernel::verify_initial_trust_pack(candidate, expected_checkpoint, evaluation_time)
            .map_err(Into::into)
    }

    pub fn verify_update(current: &[u8], candidate: &[u8]) -> Result<TrustPackMetadata, SdkError> {
        let evaluation_time = unix_time_now()?;
        trust_kernel::verify_trust_pack_transition(current, candidate, evaluation_time)
            .map_err(Into::into)
    }

    pub fn inspect(trust_pack: &[u8]) -> Result<TrustPackMetadata, SdkError> {
        let evaluation_time = unix_time_now()?;
        trust_kernel::inspect_trust_pack(trust_pack, evaluation_time).map_err(Into::into)
    }
}

fn unix_time_now() -> Result<u64, SdkError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SdkError::ClockBeforeUnixEpoch)?;
    Ok(duration.as_secs())
}

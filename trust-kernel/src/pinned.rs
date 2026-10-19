//! Pin-enforcing evaluation handle.
//!
//! The raw `evaluate_claim` and `evaluate_action_v2/v3` functions verify a TrustPack against
//! the root embedded in that same pack. They therefore prove integrity, not authority: whoever
//! controls the pack bytes also controls the embedded root. `PinnedTrustPack` binds the initial
//! pack to an out-of-band checkpoint and accepts later packs only through a verified transition.
//! This type is `no_std + alloc` and performs no I/O.
use alloc::vec::Vec;

use crate::{
    evaluate_action_v2, evaluate_action_v3, evaluate_claim, verify_initial_trust_pack,
    verify_trust_pack_transition, ActionError, ActionReceiptV2, ActionReceiptV3, ActionRequestV2,
    ActionRequestV3, DecisionReceipt, TrustError, TrustPackMetadata,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedTrustPack {
    bytes: Vec<u8>,
    metadata: TrustPackMetadata,
}

impl PinnedTrustPack {
    /// Accepts `bytes` only if its checkpoint equals the out-of-band `expected_checkpoint`.
    pub fn verify_initial(
        bytes: &[u8],
        expected_checkpoint: &[u8; 32],
        now: u64,
    ) -> Result<Self, TrustError> {
        let metadata = verify_initial_trust_pack(bytes, expected_checkpoint, now)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            metadata,
        })
    }

    /// Accepts `candidate` only as a valid, strictly newer successor of this pinned pack.
    pub fn verify_update(&self, candidate: &[u8], now: u64) -> Result<Self, TrustError> {
        let metadata = verify_trust_pack_transition(&self.bytes, candidate, now)?;
        Ok(Self {
            bytes: candidate.to_vec(),
            metadata,
        })
    }

    #[must_use]
    pub fn metadata(&self) -> &TrustPackMetadata {
        &self.metadata
    }

    pub fn evaluate_claim(&self, claim: &[u8], now: u64) -> Result<DecisionReceipt, TrustError> {
        evaluate_claim(claim, &self.bytes, now)
    }

    pub fn evaluate_action_v2(
        &self,
        action: &[u8],
        request: &ActionRequestV2,
        now: u64,
    ) -> Result<ActionReceiptV2, ActionError> {
        evaluate_action_v2(action, &self.bytes, now, request)
    }

    pub fn evaluate_action_v3(
        &self,
        action: &[u8],
        request: &ActionRequestV3,
        now: u64,
    ) -> Result<ActionReceiptV3, ActionError> {
        evaluate_action_v3(action, &self.bytes, now, request)
    }
}

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod action;
mod canonical;
mod error;
mod kernel;
mod state;
mod types;

pub use action::{
    encode_action_v2, evaluate_action_v2, ActionBindingV2, ActionError, ActionReceiptV2,
    ActionRequestV2, SignedActionV2, ACTION_PROFILE_VERSION, MAX_ACTION_WIRE_BYTES,
};
pub use error::{IdentifierField, InputKind, TrustError};
pub use kernel::{encode_claim, evaluate_claim, scoped_revocation_id};
pub use state::{
    encode_trust_pack, inspect_trust_pack, verify_initial_trust_pack, verify_trust_pack_transition,
    MAX_CLAIM_WIRE_BYTES, MAX_TRUST_PACK_WIRE_BYTES,
};
pub use types::{
    ActionId, AssuranceLevel, CapabilityId, ClaimId, Decision, DecisionReason, DecisionReceipt,
    FreshnessAssurance, FreshnessPolicy, IssuerId, KeyId, KeyPurpose, KeyState, PackId,
    PolicyGrant, PolicyId, ResourceId, SignatureAlgorithm, SignedClaim, SignedClaimProfileV1,
    SignedTrustPack, StatusManifest, TrustAnchor, TrustAnchorRoot, TrustDomainId, TrustPack,
    TrustPackMetadata, TrustPolicy, DECISION_RECEIPT_VERSION, ENGINE_VERSION,
    SIGNED_CLAIM_PROFILE_VERSION, TRUST_PACK_FORMAT_VERSION,
};

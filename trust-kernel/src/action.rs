//! Additive signed action profile. Profile v1 claim bytes and decisions remain unchanged.
use crate::{DecisionReceipt, SignedClaim, TrustError};
use alloc::{string::String, vec::Vec};
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ACTION_PROFILE_VERSION: u16 = 2;
pub const ACTION_PROFILE_V3_VERSION: u16 = 3;
pub const MAX_ACTION_WIRE_BYTES: usize = 16_384;
const ACTION_DOMAIN: &[u8] = b"SWOOSH\0action-binding\0v2\0";
const ACTION_V3_DOMAIN: &[u8] = b"SWOOSH\0action-binding\0v3\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBindingV2 {
    pub workflow_id: String,
    pub task_id: String,
    pub generation: u64,
    pub purpose: String,
    pub destination: String,
    pub effect_digest: [u8; 32],
    pub policy_version: u64,
    pub trust_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionV2 {
    pub profile_version: u16,
    pub authority: SignedClaim,
    pub binding: ActionBindingV2,
    #[serde(with = "crate::types::signature_serde")]
    pub signature: [u8; 64],
}

/// Supplied by the authenticated host, never taken as authority from model JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequestV2 {
    pub authenticated_subject: [u8; 32],
    pub action: String,
    pub resource: String,
    pub binding: ActionBindingV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionReceiptV2 {
    pub profile_version: u16,
    pub action_digest: [u8; 32],
    pub trust: DecisionReceipt,
}

/// Additive role-bound action profile. V2 remains supported for compatibility.
///
/// The trusted host supplies `authenticated_role`; model output is never a role source.
/// The same authorized action signer cryptographically binds the role and cognitive-profile digest
/// to workflow, task, generation, purpose, destination, exact effect, policy version and trust epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBindingV3 {
    pub workflow_id: String,
    pub task_id: String,
    pub generation: u64,
    pub role_id: String,
    pub cognitive_profile_digest: [u8; 32],
    pub purpose: String,
    pub destination: String,
    pub effect_digest: [u8; 32],
    pub policy_version: u64,
    pub trust_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionV3 {
    pub profile_version: u16,
    pub authority: SignedClaim,
    pub binding: ActionBindingV3,
    #[serde(with = "crate::types::signature_serde")]
    pub signature: [u8; 64],
}

/// Trusted host context for role-bound evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequestV3 {
    pub authenticated_subject: [u8; 32],
    pub authenticated_role: String,
    pub action: String,
    pub resource: String,
    pub binding: ActionBindingV3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionReceiptV3 {
    pub profile_version: u16,
    pub action_digest: [u8; 32],
    pub trust: DecisionReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionError {
    InputTooLarge,
    Malformed,
    UnsupportedVersion,
    InvalidBinding,
    SubjectMismatch,
    RoleMismatch,
    ScopeMismatch,
    StateChanged,
    Trust(TrustError),
}
impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "action denied: {self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for ActionError {}
impl From<TrustError> for ActionError {
    fn from(value: TrustError) -> Self {
        Self::Trust(value)
    }
}

impl SignedActionV2 {
    /// Standard Ed25519 signing is performed by an authorized signer outside this kernel.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ActionError> {
        if self.profile_version != ACTION_PROFILE_VERSION {
            return Err(ActionError::UnsupportedVersion);
        }
        validate_binding(&self.binding)?;
        let mut bytes = Vec::with_capacity(640);
        bytes.extend_from_slice(ACTION_DOMAIN);
        bytes.extend_from_slice(&self.profile_version.to_be_bytes());
        bytes.extend_from_slice(&self.authority.fingerprint()?);
        for value in [
            &self.binding.workflow_id,
            &self.binding.task_id,
            &self.binding.purpose,
            &self.binding.destination,
        ] {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.extend_from_slice(&self.binding.generation.to_be_bytes());
        bytes.extend_from_slice(&self.binding.effect_digest);
        bytes.extend_from_slice(&self.binding.policy_version.to_be_bytes());
        bytes.extend_from_slice(&self.binding.trust_epoch.to_be_bytes());
        Ok(bytes)
    }
}

impl SignedActionV3 {
    /// Standard Ed25519 signing is performed by an authorized RBAC/action signer outside this kernel.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ActionError> {
        if self.profile_version != ACTION_PROFILE_V3_VERSION {
            return Err(ActionError::UnsupportedVersion);
        }
        validate_binding_v3(&self.binding)?;
        let mut bytes = Vec::with_capacity(704);
        bytes.extend_from_slice(ACTION_V3_DOMAIN);
        bytes.extend_from_slice(&self.profile_version.to_be_bytes());
        bytes.extend_from_slice(&self.authority.fingerprint()?);
        for value in [
            &self.binding.workflow_id,
            &self.binding.task_id,
            &self.binding.role_id,
            &self.binding.purpose,
            &self.binding.destination,
        ] {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.extend_from_slice(&self.binding.generation.to_be_bytes());
        bytes.extend_from_slice(&self.binding.cognitive_profile_digest);
        bytes.extend_from_slice(&self.binding.effect_digest);
        bytes.extend_from_slice(&self.binding.policy_version.to_be_bytes());
        bytes.extend_from_slice(&self.binding.trust_epoch.to_be_bytes());
        Ok(bytes)
    }
}

pub fn encode_action_v2(action: &SignedActionV2) -> Result<Vec<u8>, ActionError> {
    action.signing_bytes()?;
    let bytes = postcard::to_allocvec(action).map_err(|_| ActionError::Malformed)?;
    if bytes.len() > MAX_ACTION_WIRE_BYTES {
        return Err(ActionError::InputTooLarge);
    }
    Ok(bytes)
}

pub fn evaluate_action_v2(
    bytes: &[u8],
    pack: &[u8],
    now: u64,
    request: &ActionRequestV2,
) -> Result<ActionReceiptV2, ActionError> {
    if bytes.len() > MAX_ACTION_WIRE_BYTES {
        return Err(ActionError::InputTooLarge);
    }
    let (action, remaining): (SignedActionV2, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ActionError::Malformed)?;
    if !remaining.is_empty() {
        return Err(ActionError::Malformed);
    }
    let signed = action.signing_bytes()?;
    // Reuse all canonical v1 issuer, key, policy, expiry, freshness, and revocation checks.
    let receipt = crate::evaluate_claim(&crate::encode_claim(&action.authority)?, pack, now)?;
    let installed = crate::state::decode_trust_pack(pack)?;
    let claim = &action.authority.claim;
    let anchor = crate::state::resolve_claim_anchor(
        &installed.pack,
        &claim.issuer_id,
        &claim.key_id,
        claim.issued_at,
        now,
    )?;
    crate::state::verify_ed25519(anchor, &signed, &action.signature)?;
    if request.authenticated_subject.iter().all(|byte| *byte == 0)
        || claim.subject_commitment != request.authenticated_subject
    {
        return Err(ActionError::SubjectMismatch);
    }
    if request.binding != action.binding
        || request.action != claim.action.as_str()
        || request.resource != claim.resource.as_str()
    {
        return Err(ActionError::ScopeMismatch);
    }
    if action.binding.policy_version != receipt.policy_version
        || action.binding.trust_epoch != receipt.trust_epoch
    {
        return Err(ActionError::StateChanged);
    }
    Ok(ActionReceiptV2 {
        profile_version: ACTION_PROFILE_VERSION,
        action_digest: Sha256::digest(&signed).into(),
        trust: receipt,
    })
}

pub fn encode_action_v3(action: &SignedActionV3) -> Result<Vec<u8>, ActionError> {
    action.signing_bytes()?;
    let bytes = postcard::to_allocvec(action).map_err(|_| ActionError::Malformed)?;
    if bytes.len() > MAX_ACTION_WIRE_BYTES {
        return Err(ActionError::InputTooLarge);
    }
    Ok(bytes)
}

pub fn evaluate_action_v3(
    bytes: &[u8],
    pack: &[u8],
    now: u64,
    request: &ActionRequestV3,
) -> Result<ActionReceiptV3, ActionError> {
    if bytes.len() > MAX_ACTION_WIRE_BYTES {
        return Err(ActionError::InputTooLarge);
    }
    let (action, remaining): (SignedActionV3, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ActionError::Malformed)?;
    if !remaining.is_empty() {
        return Err(ActionError::Malformed);
    }
    let signed = action.signing_bytes()?;
    // Reuse all canonical v1 issuer, key, policy, expiry, freshness, revocation and grant checks.
    let receipt = crate::evaluate_claim(&crate::encode_claim(&action.authority)?, pack, now)?;
    let installed = crate::state::decode_trust_pack(pack)?;
    let claim = &action.authority.claim;
    let anchor = crate::state::resolve_claim_anchor(
        &installed.pack,
        &claim.issuer_id,
        &claim.key_id,
        claim.issued_at,
        now,
    )?;
    crate::state::verify_ed25519(anchor, &signed, &action.signature)?;
    if request.authenticated_subject.iter().all(|byte| *byte == 0)
        || claim.subject_commitment != request.authenticated_subject
    {
        return Err(ActionError::SubjectMismatch);
    }
    if request.authenticated_role != action.binding.role_id {
        return Err(ActionError::RoleMismatch);
    }
    if request.binding != action.binding
        || request.action != claim.action.as_str()
        || request.resource != claim.resource.as_str()
    {
        return Err(ActionError::ScopeMismatch);
    }
    if action.binding.policy_version != receipt.policy_version
        || action.binding.trust_epoch != receipt.trust_epoch
    {
        return Err(ActionError::StateChanged);
    }
    Ok(ActionReceiptV3 {
        profile_version: ACTION_PROFILE_V3_VERSION,
        action_digest: Sha256::digest(&signed).into(),
        trust: receipt,
    })
}

fn validate_binding(binding: &ActionBindingV2) -> Result<(), ActionError> {
    for value in [
        &binding.workflow_id,
        &binding.task_id,
        &binding.purpose,
        &binding.destination,
    ] {
        if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
            return Err(ActionError::InvalidBinding);
        }
    }
    if binding.generation == 0
        || binding.policy_version == 0
        || binding.trust_epoch == 0
        || binding.cognitive_profile_digest.iter().all(|byte| *byte == 0)
        || binding.effect_digest.iter().all(|byte| *byte == 0)
    {
        return Err(ActionError::InvalidBinding);
    }
    Ok(())
}

fn validate_binding_v3(binding: &ActionBindingV3) -> Result<(), ActionError> {
    for value in [
        &binding.workflow_id,
        &binding.task_id,
        &binding.role_id,
        &binding.purpose,
        &binding.destination,
    ] {
        if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
            return Err(ActionError::InvalidBinding);
        }
    }
    if binding.generation == 0
        || binding.policy_version == 0
        || binding.trust_epoch == 0
        || binding.effect_digest.iter().all(|byte| *byte == 0)
    {
        return Err(ActionError::InvalidBinding);
    }
    Ok(())
}

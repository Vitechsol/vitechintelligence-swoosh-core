use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::fmt::Write;

use sha2::{Digest, Sha256};

use crate::{
    canonical::receipt_identifier,
    state::{
        decode_trust_pack, resolve_claim_anchor, validate_identifier, validate_pack_at,
        verify_ed25519, MAX_CLAIM_WIRE_BYTES,
    },
    Decision, DecisionReason, DecisionReceipt, FreshnessAssurance, IdentifierField, InputKind,
    KeyState, SignedClaim, TrustError, TrustPack, DECISION_RECEIPT_VERSION, ENGINE_VERSION,
    SIGNED_CLAIM_PROFILE_VERSION,
};

const REVOCATION_ID_DOMAIN: &[u8] = b"SWOOSH\0revocation-id\0v1\0";

#[must_use]
pub fn scoped_revocation_id(
    issuer_id: &crate::IssuerId,
    claim_id: &crate::ClaimId,
) -> crate::ClaimId {
    let issuer = issuer_id.as_str().as_bytes();
    let claim = claim_id.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(REVOCATION_ID_DOMAIN);
    hasher.update((issuer.len() as u32).to_be_bytes());
    hasher.update(issuer);
    hasher.update((claim.len() as u32).to_be_bytes());
    hasher.update(claim);
    let digest = hasher.finalize();

    let mut value = String::with_capacity(69);
    value.push_str("rev1:");
    for byte in digest {
        let _ = write!(&mut value, "{byte:02x}");
    }
    crate::ClaimId::new(value)
}

pub fn evaluate_claim(
    claim_bytes: &[u8],
    trust_pack_bytes: &[u8],
    evaluation_time: u64,
) -> Result<DecisionReceipt, TrustError> {
    let signed_pack = decode_trust_pack(trust_pack_bytes)?;
    validate_pack_at(&signed_pack, evaluation_time)?;

    let signed_claim = decode_claim(claim_bytes)?;
    validate_claim_structure(&signed_claim)?;

    evaluate_decoded_claim(
        &signed_claim,
        &signed_pack.pack,
        &signed_pack,
        evaluation_time,
    )
}

pub fn encode_claim(claim: &SignedClaim) -> Result<Vec<u8>, TrustError> {
    postcard::to_allocvec(claim).map_err(|_| TrustError::SerializationFailed)
}

fn decode_claim(bytes: &[u8]) -> Result<SignedClaim, TrustError> {
    if bytes.len() > MAX_CLAIM_WIRE_BYTES {
        return Err(TrustError::InputTooLarge {
            kind: InputKind::Claim,
            limit: MAX_CLAIM_WIRE_BYTES,
        });
    }
    postcard::from_bytes(bytes).map_err(|_| TrustError::MalformedClaim)
}

fn evaluate_decoded_claim(
    signed_claim: &SignedClaim,
    pack: &TrustPack,
    signed_pack: &crate::SignedTrustPack,
    evaluation_time: u64,
) -> Result<DecisionReceipt, TrustError> {
    let claim = &signed_claim.claim;

    if claim.trust_domain != pack.trust_domain {
        return Err(TrustError::TrustDomainMismatch);
    }

    // 1. Issuer trust and strict Ed25519 signature verification.
    let anchor = resolve_claim_anchor(
        pack,
        &claim.issuer_id,
        &claim.key_id,
        claim.issued_at,
        evaluation_time,
    )?;
    let signing_bytes = claim.signing_bytes()?;
    verify_ed25519(anchor, &signing_bytes, &signed_claim.signature)?;

    // 2. Crisp embedded status/revocation lookup. Revocations are scoped by issuer
    // and issuer-local claim ID through a domain-separated digest, preventing
    // collisions even when identifiers themselves contain separators.
    let revocation_id = scoped_revocation_id(&claim.issuer_id, &claim.claim_id);
    if pack
        .status
        .revoked_claims
        .binary_search(&revocation_id)
        .is_ok()
    {
        return Err(TrustError::ClaimRevoked);
    }

    // 3. Claim expiry.
    if evaluation_time >= claim.not_after {
        return Err(TrustError::ClaimExpired);
    }

    // 4. Claim freshness and future-clock bounds.
    let latest_acceptable_issue_time = evaluation_time
        .checked_add(pack.policy.freshness.max_clock_skew_seconds)
        .ok_or(TrustError::ArithmeticOverflow)?;
    if claim.issued_at > latest_acceptable_issue_time {
        return Err(TrustError::ClaimIssuedInFuture);
    }
    let claim_age = evaluation_time.saturating_sub(claim.issued_at);
    if claim_age > pack.policy.freshness.max_claim_age_seconds {
        return Err(TrustError::ClaimStale);
    }

    // Default-deny relying-party policy binding.
    let authorized = pack.policy.grants.iter().any(|grant| {
        grant.issuer_id == claim.issuer_id
            && grant.capability == claim.capability
            && grant.action == claim.action
            && grant.resource == claim.resource
            && claim.assurance_level >= grant.minimum_assurance
    });
    if !authorized {
        return Err(TrustError::PolicyDenied);
    }

    let trust_state_age = evaluation_time
        .checked_sub(pack.generated_at)
        .ok_or(TrustError::TrustPackNotYetValid)?;
    let (assurance, reason) = if trust_state_age <= pack.policy.freshness.current_state_age_seconds
    {
        (
            FreshnessAssurance::Current,
            DecisionReason::AuthorizedCurrent,
        )
    } else {
        (
            FreshnessAssurance::OfflineWithinPolicy,
            DecisionReason::AuthorizedOfflineWithinPolicy,
        )
    };

    let freshness_deadline = claim
        .issued_at
        .checked_add(pack.policy.freshness.max_claim_age_seconds)
        .ok_or(TrustError::ArithmeticOverflow)?;
    let mut valid_until = claim
        .not_after
        .min(pack.valid_until)
        .min(anchor.not_after)
        .min(freshness_deadline);
    if let KeyState::Deprecated { accept_until, .. } = anchor.state {
        valid_until = valid_until.min(accept_until);
    }

    let claim_fingerprint = signed_claim.fingerprint()?;
    let trust_state_fingerprint = signed_pack.checkpoint()?;
    let mut receipt = DecisionReceipt {
        receipt_version: DECISION_RECEIPT_VERSION,
        engine_version: ENGINE_VERSION.to_owned(),
        receipt_id: [0_u8; 32],
        claim_fingerprint,
        trust_state_fingerprint,
        trust_domain: pack.trust_domain.clone(),
        decision: Decision::Allow,
        reason,
        assurance,
        evaluated_at: evaluation_time,
        valid_until,
        trust_epoch: pack.trust_epoch,
        root_generation: pack.root.generation,
        status_sequence: pack.status.sequence,
        policy_id: pack.policy.policy_id.clone(),
        policy_version: pack.policy.version,
    };
    receipt.receipt_id = receipt_identifier(&receipt)?;
    Ok(receipt)
}

fn validate_claim_structure(signed_claim: &SignedClaim) -> Result<(), TrustError> {
    let claim = &signed_claim.claim;
    if claim.profile_version != SIGNED_CLAIM_PROFILE_VERSION {
        return Err(TrustError::UnsupportedClaimVersion {
            found: claim.profile_version,
        });
    }
    validate_identifier(IdentifierField::Claim, claim.claim_id.as_str(), 96)?;
    validate_identifier(
        IdentifierField::TrustDomain,
        claim.trust_domain.as_str(),
        96,
    )?;
    validate_identifier(IdentifierField::Issuer, claim.issuer_id.as_str(), 96)?;
    validate_identifier(IdentifierField::Key, claim.key_id.as_str(), 96)?;
    validate_identifier(IdentifierField::Action, claim.action.as_str(), 96)?;
    validate_identifier(IdentifierField::Resource, claim.resource.as_str(), 96)?;
    validate_identifier(IdentifierField::Capability, claim.capability.as_str(), 96)?;

    if claim.issued_at >= claim.not_after {
        return Err(TrustError::InvalidClaimWindow);
    }
    if claim.subject_commitment.iter().all(|byte| *byte == 0) {
        return Err(TrustError::InvalidSubjectCommitment);
    }
    if claim.evidence_digest.iter().all(|byte| *byte == 0) {
        return Err(TrustError::InvalidEvidenceDigest);
    }
    Ok(())
}

use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    IdentifierField, IssuerId, KeyId, KeyPurpose, KeyState, PolicyGrant, SignatureAlgorithm,
    SignedTrustPack, TrustAnchor, TrustError, TrustPack, TrustPackMetadata,
    TRUST_PACK_FORMAT_VERSION,
};

pub const MAX_CLAIM_WIRE_BYTES: usize = 4 * 1024;
pub const MAX_TRUST_PACK_WIRE_BYTES: usize = 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 96;
const MAX_REVOCATION_IDENTIFIER_BYTES: usize = 69;
const MAX_ROOT_ID_BYTES: usize = 128;
const MAX_ANCHORS: usize = 4_096;
const MAX_REVOCATIONS: usize = 250_000;
const MAX_POLICY_GRANTS: usize = 8_192;

pub(crate) fn validate_pack_at(
    signed_pack: &SignedTrustPack,
    evaluation_time: u64,
) -> Result<(), TrustError> {
    validate_pack_structure(&signed_pack.pack)?;

    if evaluation_time < signed_pack.pack.valid_from {
        return Err(TrustError::TrustPackNotYetValid);
    }
    if evaluation_time >= signed_pack.pack.valid_until {
        return Err(TrustError::TrustPackExpired);
    }

    verify_pack_signature_with_root(
        signed_pack,
        &signed_pack.pack.root.anchors,
        signed_pack.pack.generated_at,
        evaluation_time,
    )
}

pub(crate) fn validate_pack_structure(pack: &TrustPack) -> Result<(), TrustError> {
    if pack.format_version != TRUST_PACK_FORMAT_VERSION {
        return Err(TrustError::UnsupportedTrustPackVersion {
            found: pack.format_version,
        });
    }

    validate_identifier(
        IdentifierField::Pack,
        pack.pack_id.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_identifier(
        IdentifierField::TrustDomain,
        pack.trust_domain.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_identifier(IdentifierField::Root, &pack.root.root_id, MAX_ROOT_ID_BYTES)?;
    validate_identifier(
        IdentifierField::Policy,
        pack.policy.policy_id.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;

    if pack.trust_epoch == 0
        || pack.root.generation == 0
        || pack.status.sequence == 0
        || pack.policy.version == 0
    {
        return Err(TrustError::InvalidTrustPackWindow);
    }

    if pack.generated_at > pack.valid_from || pack.valid_from >= pack.valid_until {
        return Err(TrustError::InvalidTrustPackWindow);
    }

    if pack.root.trust_domain != pack.trust_domain {
        return Err(TrustError::TrustPackRootMismatch);
    }

    if pack.root.anchors.is_empty() {
        return Err(TrustError::EmptyTrustAnchorRoot);
    }
    if pack.root.anchors.len() > MAX_ANCHORS {
        return Err(TrustError::InputTooLarge {
            kind: crate::InputKind::TrustPack,
            limit: MAX_TRUST_PACK_WIRE_BYTES,
        });
    }

    let mut has_claim_signer = false;
    let mut has_pack_signer = false;
    for anchor in &pack.root.anchors {
        validate_anchor(anchor, &pack.trust_domain)?;
        match anchor.purpose {
            KeyPurpose::ClaimSigning => has_claim_signer = true,
            KeyPurpose::TrustPackSigning => has_pack_signer = true,
        }
    }
    if !has_claim_signer {
        return Err(TrustError::MissingClaimSigningAnchor);
    }
    if !has_pack_signer {
        return Err(TrustError::MissingTrustPackSigningAnchor);
    }
    if !strictly_sorted_by(&pack.root.anchors, |left, right| {
        (&left.issuer_id, &left.key_id) < (&right.issuer_id, &right.key_id)
    }) {
        return Err(TrustError::DuplicateOrUnsortedAnchors);
    }

    if pack.status.issued_at > pack.generated_at || pack.status.issued_at >= pack.status.not_after {
        return Err(TrustError::InvalidStatusWindow);
    }
    if pack.status.not_after < pack.valid_until {
        return Err(TrustError::TrustPackStatusCoverageInsufficient);
    }
    if pack.status.revoked_claims.len() > MAX_REVOCATIONS {
        return Err(TrustError::InputTooLarge {
            kind: crate::InputKind::TrustPack,
            limit: MAX_TRUST_PACK_WIRE_BYTES,
        });
    }
    for revocation_id in &pack.status.revoked_claims {
        validate_revocation_identifier(revocation_id.as_str())?;
    }
    if !strictly_sorted_by(&pack.status.revoked_claims, |left, right| left < right) {
        return Err(TrustError::DuplicateOrUnsortedRevocations);
    }

    if pack.policy.effective_from > pack.valid_from
        || pack.policy.effective_from >= pack.policy.effective_until
    {
        return Err(TrustError::InvalidPolicyWindow);
    }
    if pack.policy.effective_until < pack.valid_until {
        return Err(TrustError::TrustPackPolicyCoverageInsufficient);
    }

    let freshness = pack.policy.freshness;
    if freshness.max_claim_age_seconds == 0
        || freshness.max_offline_age_seconds == 0
        || freshness.current_state_age_seconds > freshness.max_offline_age_seconds
    {
        return Err(TrustError::InvalidPolicyWindow);
    }
    let maximum_pack_end = pack
        .generated_at
        .checked_add(freshness.max_offline_age_seconds)
        .ok_or(TrustError::ArithmeticOverflow)?;
    if pack.valid_until > maximum_pack_end {
        return Err(TrustError::TrustPackOfflineWindowExceeded);
    }

    if pack.policy.grants.is_empty() || pack.policy.grants.len() > MAX_POLICY_GRANTS {
        return Err(TrustError::PolicyDenied);
    }
    for grant in &pack.policy.grants {
        validate_grant(grant)?;
        let issuer_exists = pack.root.anchors.iter().any(|anchor| {
            anchor.issuer_id == grant.issuer_id && anchor.purpose == KeyPurpose::ClaimSigning
        });
        if !issuer_exists {
            return Err(TrustError::UnknownIssuer);
        }
    }
    if !strictly_sorted_by(&pack.policy.grants, grant_less_than) {
        return Err(TrustError::DuplicateOrUnsortedPolicyGrants);
    }

    Ok(())
}

pub(crate) fn resolve_claim_anchor<'a>(
    pack: &'a TrustPack,
    issuer_id: &IssuerId,
    key_id: &KeyId,
    issued_at: u64,
    evaluation_time: u64,
) -> Result<&'a TrustAnchor, TrustError> {
    if !pack
        .root
        .anchors
        .iter()
        .any(|anchor| anchor.issuer_id == *issuer_id)
    {
        return Err(TrustError::UnknownIssuer);
    }

    let anchor = pack
        .root
        .anchors
        .iter()
        .find(|anchor| anchor.issuer_id == *issuer_id && anchor.key_id == *key_id)
        .ok_or(TrustError::UnknownKey)?;

    authorize_anchor(anchor, KeyPurpose::ClaimSigning, issued_at, evaluation_time)?;
    Ok(anchor)
}

pub(crate) fn verify_ed25519(
    anchor: &TrustAnchor,
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), TrustError> {
    let verifying_key =
        VerifyingKey::from_bytes(&anchor.public_key).map_err(|_| TrustError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| TrustError::InvalidSignature)
}

pub fn verify_initial_trust_pack(
    trust_pack_bytes: &[u8],
    expected_checkpoint: &[u8; 32],
    evaluation_time: u64,
) -> Result<TrustPackMetadata, TrustError> {
    let signed_pack = decode_trust_pack(trust_pack_bytes)?;
    validate_pack_at(&signed_pack, evaluation_time)?;
    let checkpoint = signed_pack.checkpoint()?;
    if checkpoint != *expected_checkpoint {
        return Err(TrustError::CheckpointMismatch);
    }
    Ok(metadata(&signed_pack, checkpoint))
}

pub fn inspect_trust_pack(
    trust_pack_bytes: &[u8],
    evaluation_time: u64,
) -> Result<TrustPackMetadata, TrustError> {
    let signed_pack = decode_trust_pack(trust_pack_bytes)?;
    validate_pack_at(&signed_pack, evaluation_time)?;
    let checkpoint = signed_pack.checkpoint()?;
    Ok(metadata(&signed_pack, checkpoint))
}

pub fn verify_trust_pack_transition(
    current_bytes: &[u8],
    candidate_bytes: &[u8],
    evaluation_time: u64,
) -> Result<TrustPackMetadata, TrustError> {
    let current = decode_trust_pack(current_bytes)?;
    validate_pack_at(&current, evaluation_time)?;

    let candidate = decode_trust_pack(candidate_bytes)?;
    validate_pack_at(&candidate, evaluation_time)?;

    if candidate.pack.trust_epoch <= current.pack.trust_epoch {
        return Err(TrustError::TrustEpochRollback {
            current: current.pack.trust_epoch,
            candidate: candidate.pack.trust_epoch,
        });
    }
    if candidate.pack.generated_at < current.pack.generated_at {
        return Err(TrustError::InvalidTrustPackWindow);
    }
    if candidate.pack.trust_domain != current.pack.trust_domain {
        return Err(TrustError::TrustDomainMismatch);
    }
    if candidate.pack.root.root_id != current.pack.root.root_id {
        return Err(TrustError::RootIdentityChanged);
    }
    if candidate.pack.root.generation < current.pack.root.generation {
        return Err(TrustError::RootGenerationRollback {
            current: current.pack.root.generation,
            candidate: candidate.pack.root.generation,
        });
    }
    let maximum_root_generation = current
        .pack
        .root
        .generation
        .checked_add(1)
        .ok_or(TrustError::ArithmeticOverflow)?;
    if candidate.pack.root.generation > maximum_root_generation {
        return Err(TrustError::RootGenerationJump {
            current: current.pack.root.generation,
            candidate: candidate.pack.root.generation,
        });
    }
    if candidate.pack.root.anchors != current.pack.root.anchors
        && candidate.pack.root.generation == current.pack.root.generation
    {
        return Err(TrustError::RootChangedWithoutGeneration);
    }
    if candidate.pack.status.sequence < current.pack.status.sequence
        || (candidate.pack.status != current.pack.status
            && candidate.pack.status.sequence == current.pack.status.sequence)
    {
        return Err(TrustError::StatusSequenceRollback {
            current: current.pack.status.sequence,
            candidate: candidate.pack.status.sequence,
        });
    }
    if current
        .pack
        .status
        .revoked_claims
        .iter()
        .any(|revocation_id| {
            candidate
                .pack
                .status
                .revoked_claims
                .binary_search(revocation_id)
                .is_err()
        })
    {
        return Err(TrustError::RevocationRollback);
    }
    if candidate.pack.policy.version < current.pack.policy.version
        || (candidate.pack.policy != current.pack.policy
            && candidate.pack.policy.version == current.pack.policy.version)
    {
        return Err(TrustError::PolicyVersionRollback {
            current: current.pack.policy.version,
            candidate: candidate.pack.policy.version,
        });
    }

    verify_pack_signature_with_root(
        &candidate,
        &current.pack.root.anchors,
        candidate.pack.generated_at,
        evaluation_time,
    )?;

    let checkpoint = candidate.checkpoint()?;
    Ok(metadata(&candidate, checkpoint))
}

pub(crate) fn decode_trust_pack(bytes: &[u8]) -> Result<SignedTrustPack, TrustError> {
    if bytes.len() > MAX_TRUST_PACK_WIRE_BYTES {
        return Err(TrustError::InputTooLarge {
            kind: crate::InputKind::TrustPack,
            limit: MAX_TRUST_PACK_WIRE_BYTES,
        });
    }
    let (pack, remainder) =
        postcard::take_from_bytes(bytes).map_err(|_| TrustError::MalformedTrustPack)?;
    if !remainder.is_empty() {
        return Err(TrustError::MalformedTrustPack);
    }
    Ok(pack)
}

pub fn encode_trust_pack(pack: &SignedTrustPack) -> Result<Vec<u8>, TrustError> {
    postcard::to_allocvec(pack).map_err(|_| TrustError::SerializationFailed)
}

fn validate_anchor(
    anchor: &TrustAnchor,
    trust_domain: &crate::TrustDomainId,
) -> Result<(), TrustError> {
    if anchor.trust_domain != *trust_domain {
        return Err(TrustError::TrustDomainMismatch);
    }
    validate_identifier(
        IdentifierField::Issuer,
        anchor.issuer_id.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_identifier(
        IdentifierField::Key,
        anchor.key_id.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    if anchor.not_before >= anchor.not_after {
        return Err(TrustError::InvalidAnchorWindow);
    }
    if anchor.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(TrustError::InvalidPublicKey);
    }
    VerifyingKey::from_bytes(&anchor.public_key).map_err(|_| TrustError::InvalidPublicKey)?;
    match anchor.state {
        KeyState::Active => {}
        KeyState::Deprecated {
            deprecated_at,
            accept_until,
        } => {
            if deprecated_at < anchor.not_before
                || deprecated_at >= accept_until
                || accept_until > anchor.not_after
            {
                return Err(TrustError::InvalidKeyState);
            }
        }
        KeyState::Revoked { revoked_at } => {
            if revoked_at < anchor.not_before || revoked_at > anchor.not_after {
                return Err(TrustError::InvalidKeyState);
            }
        }
    }
    Ok(())
}

fn validate_grant(grant: &PolicyGrant) -> Result<(), TrustError> {
    validate_identifier(
        IdentifierField::Issuer,
        grant.issuer_id.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_identifier(
        IdentifierField::Capability,
        grant.capability.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_identifier(
        IdentifierField::Action,
        grant.action.as_str(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_identifier(
        IdentifierField::Resource,
        grant.resource.as_str(),
        MAX_IDENTIFIER_BYTES,
    )
}

fn validate_revocation_identifier(value: &str) -> Result<(), TrustError> {
    validate_identifier(
        IdentifierField::Claim,
        value,
        MAX_REVOCATION_IDENTIFIER_BYTES,
    )?;
    let digest = value
        .strip_prefix("rev1:")
        .ok_or(TrustError::InvalidIdentifier {
            field: IdentifierField::Claim,
        })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(TrustError::InvalidIdentifier {
            field: IdentifierField::Claim,
        });
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    field: IdentifierField,
    value: &str,
    maximum_length: usize,
) -> Result<(), TrustError> {
    if value.is_empty()
        || value.len() > maximum_length
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(TrustError::InvalidIdentifier { field });
    }
    Ok(())
}

fn authorize_anchor(
    anchor: &TrustAnchor,
    expected_purpose: KeyPurpose,
    issued_at: u64,
    evaluation_time: u64,
) -> Result<(), TrustError> {
    if anchor.purpose != expected_purpose {
        return Err(TrustError::KeyPurposeDenied);
    }
    if issued_at < anchor.not_before {
        return Err(TrustError::KeyNotYetValid);
    }
    if issued_at >= anchor.not_after || evaluation_time >= anchor.not_after {
        return Err(TrustError::KeyExpired);
    }

    match anchor.state {
        KeyState::Active => Ok(()),
        KeyState::Deprecated {
            deprecated_at,
            accept_until,
        } => {
            if issued_at > deprecated_at {
                return Err(TrustError::KeyDeprecatedForIssuance);
            }
            if evaluation_time >= accept_until {
                return Err(TrustError::KeyDeprecationWindowExpired);
            }
            Ok(())
        }
        KeyState::Revoked { .. } => Err(TrustError::KeyRevoked),
    }
}

fn verify_pack_signature_with_root(
    signed_pack: &SignedTrustPack,
    anchors: &[TrustAnchor],
    issued_at: u64,
    evaluation_time: u64,
) -> Result<(), TrustError> {
    let anchor = anchors
        .iter()
        .find(|anchor| {
            anchor.issuer_id == signed_pack.signer_issuer_id
                && anchor.key_id == signed_pack.signer_key_id
        })
        .ok_or(TrustError::TrustPackSignerUnauthorized)?;

    authorize_anchor(
        anchor,
        KeyPurpose::TrustPackSigning,
        issued_at,
        evaluation_time,
    )
    .map_err(|_| TrustError::TrustPackSignerUnauthorized)?;

    let message = signed_pack.signing_bytes()?;
    verify_ed25519(anchor, &message, &signed_pack.signature)
        .map_err(|_| TrustError::TrustPackSignatureInvalid)
}

fn metadata(signed_pack: &SignedTrustPack, checkpoint: [u8; 32]) -> TrustPackMetadata {
    TrustPackMetadata {
        pack_id: signed_pack.pack.pack_id.clone(),
        trust_domain: signed_pack.pack.trust_domain.clone(),
        trust_epoch: signed_pack.pack.trust_epoch,
        root_generation: signed_pack.pack.root.generation,
        status_sequence: signed_pack.pack.status.sequence,
        policy_id: signed_pack.pack.policy.policy_id.clone(),
        policy_version: signed_pack.pack.policy.version,
        valid_from: signed_pack.pack.valid_from,
        valid_until: signed_pack.pack.valid_until,
        checkpoint,
    }
}

fn strictly_sorted_by<T>(values: &[T], less_than: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less_than(&pair[0], &pair[1]))
}

fn grant_less_than(left: &PolicyGrant, right: &PolicyGrant) -> bool {
    (
        &left.issuer_id,
        &left.capability,
        &left.action,
        &left.resource,
        left.minimum_assurance,
    ) < (
        &right.issuer_id,
        &right.capability,
        &right.action,
        &right.resource,
        right.minimum_assurance,
    )
}

use std::error::Error;

use proof_pack::{
    claim_signing_key, fixture, make_claim, make_claim_at, pack_signing_key, sign_claim, sign_pack,
    EVALUATION_TIME,
};
use proptest::prelude::*;
use trust_kernel::{
    encode_claim, encode_trust_pack, evaluate_claim, scoped_revocation_id,
    verify_trust_pack_transition, ClaimId, DecisionReason, FreshnessAssurance, IssuerId, KeyId,
    KeyPurpose, KeyState, PackId, SignatureAlgorithm, TrustAnchor, TrustDomainId, TrustError,
    MAX_CLAIM_WIRE_BYTES,
};

#[test]
fn tampered_signature_is_rejected() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut tampered = base.signed_claim;
    tampered.signature[0] ^= 0x80;
    let result = evaluate_claim(&encode_claim(&tampered)?, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(result, Err(TrustError::InvalidSignature));
    Ok(())
}

#[test]
fn unknown_issuer_fails_before_signature_acceptance() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut claim = base.signed_claim.claim;
    claim.issuer_id = IssuerId::new("unknown-issuer");
    let signed = sign_claim(claim, &claim_signing_key())?;
    let result = evaluate_claim(&encode_claim(&signed)?, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(result, Err(TrustError::UnknownIssuer));
    Ok(())
}

#[test]
fn expired_claim_is_rejected() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let result = evaluate_claim(&base.claim_bytes, &base.pack_bytes, EVALUATION_TIME + 240);
    assert_eq!(result, Err(TrustError::ClaimExpired));
    Ok(())
}

#[test]
fn stale_claim_is_rejected() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let claim = make_claim(
        ClaimId::new("claim-stale"),
        KeyId::new("claim-key-1"),
        EVALUATION_TIME - 200,
    );
    let signed = sign_claim(claim, &claim_signing_key())?;
    let result = evaluate_claim(
        &encode_claim(&signed)?,
        &base.pack_bytes,
        EVALUATION_TIME + 200,
    );
    assert_eq!(result, Err(TrustError::ClaimStale));
    Ok(())
}

#[test]
fn cross_domain_claim_is_rejected() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut claim = base.signed_claim.claim;
    claim.trust_domain = TrustDomainId::new("another.domain");
    let signed = sign_claim(claim, &claim_signing_key())?;
    let result = evaluate_claim(&encode_claim(&signed)?, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(result, Err(TrustError::TrustDomainMismatch));
    Ok(())
}

#[test]
fn default_deny_policy_rejects_wrong_resource() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut claim = base.signed_claim.claim;
    claim.resource = trust_kernel::ResourceId::new("factory-b");
    let signed = sign_claim(claim, &claim_signing_key())?;
    let result = evaluate_claim(&encode_claim(&signed)?, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(result, Err(TrustError::PolicyDenied));
    Ok(())
}

#[test]
fn old_trust_epoch_cannot_replace_newer_state() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut newer_pack = base.signed_pack.pack.clone();
    newer_pack.pack_id = PackId::new("industrial-pack-2");
    newer_pack.trust_epoch = 2;
    newer_pack.status.sequence = 2;
    let signed_newer = sign_pack(
        newer_pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let newer_bytes = encode_trust_pack(&signed_newer)?;

    let result = verify_trust_pack_transition(&newer_bytes, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(
        result,
        Err(TrustError::TrustEpochRollback {
            current: 2,
            candidate: 1,
        })
    );
    Ok(())
}

#[test]
fn invalid_signature_precedes_revocation_lookup() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut revoked_pack = base.signed_pack.pack.clone();
    revoked_pack.pack_id = PackId::new("industrial-pack-revoked-order");
    revoked_pack.trust_epoch = 2;
    revoked_pack.status.sequence = 2;
    revoked_pack
        .status
        .revoked_claims
        .push(scoped_revocation_id(
            &base.signed_claim.claim.issuer_id,
            &base.signed_claim.claim.claim_id,
        ));
    let signed_pack = sign_pack(
        revoked_pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;

    let mut tampered_claim = base.signed_claim;
    tampered_claim.signature[0] ^= 0x01;
    let result = evaluate_claim(
        &encode_claim(&tampered_claim)?,
        &encode_trust_pack(&signed_pack)?,
        EVALUATION_TIME,
    );
    assert_eq!(result, Err(TrustError::InvalidSignature));
    Ok(())
}

#[test]
fn revocation_precedes_expiry() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut revoked_pack = base.signed_pack.pack.clone();
    revoked_pack.pack_id = PackId::new("industrial-pack-revoked-before-expiry");
    revoked_pack.trust_epoch = 2;
    revoked_pack.status.sequence = 2;
    revoked_pack
        .status
        .revoked_claims
        .push(scoped_revocation_id(
            &base.signed_claim.claim.issuer_id,
            &base.signed_claim.claim.claim_id,
        ));
    let signed_pack = sign_pack(
        revoked_pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;

    let result = evaluate_claim(
        &base.claim_bytes,
        &encode_trust_pack(&signed_pack)?,
        EVALUATION_TIME + 250,
    );
    assert_eq!(result, Err(TrustError::ClaimRevoked));
    Ok(())
}

#[test]
fn status_changes_require_sequence_advance() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut candidate = base.signed_pack.pack.clone();
    candidate.pack_id = PackId::new("industrial-pack-status-same-sequence");
    candidate.trust_epoch = 2;
    candidate.status.revoked_claims.push(scoped_revocation_id(
        &base.signed_claim.claim.issuer_id,
        &base.signed_claim.claim.claim_id,
    ));
    let signed = sign_pack(
        candidate,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let candidate_bytes = encode_trust_pack(&signed)?;

    let result = verify_trust_pack_transition(&base.pack_bytes, &candidate_bytes, EVALUATION_TIME);
    assert_eq!(
        result,
        Err(TrustError::StatusSequenceRollback {
            current: 1,
            candidate: 1,
        })
    );
    Ok(())
}

#[test]
fn policy_changes_require_version_advance() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut candidate = base.signed_pack.pack.clone();
    candidate.pack_id = PackId::new("industrial-pack-policy-same-version");
    candidate.trust_epoch = 2;
    candidate.policy.grants[0].resource = trust_kernel::ResourceId::new("factory-b");
    let signed = sign_pack(
        candidate,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let candidate_bytes = encode_trust_pack(&signed)?;

    let result = verify_trust_pack_transition(&base.pack_bytes, &candidate_bytes, EVALUATION_TIME);
    assert_eq!(
        result,
        Err(TrustError::PolicyVersionRollback {
            current: 1,
            candidate: 1,
        })
    );
    Ok(())
}

#[test]
fn anchor_changes_require_root_generation_advance() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let claim_key = claim_signing_key();
    let mut candidate = base.signed_pack.pack.clone();
    candidate.pack_id = PackId::new("industrial-pack-root-same-generation");
    candidate.trust_epoch = 2;
    candidate.root.anchors.insert(
        1,
        TrustAnchor {
            trust_domain: TrustDomainId::new("industrial.demo"),
            issuer_id: IssuerId::new("employer-a"),
            key_id: KeyId::new("claim-key-2"),
            algorithm: SignatureAlgorithm::Ed25519,
            purpose: KeyPurpose::ClaimSigning,
            public_key: claim_key.verifying_key().to_bytes(),
            not_before: EVALUATION_TIME - 10_000,
            not_after: EVALUATION_TIME + 10_000,
            state: KeyState::Active,
        },
    );
    let signed = sign_pack(
        candidate,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let candidate_bytes = encode_trust_pack(&signed)?;

    let result = verify_trust_pack_transition(&base.pack_bytes, &candidate_bytes, EVALUATION_TIME);
    assert_eq!(result, Err(TrustError::RootChangedWithoutGeneration));
    Ok(())
}

#[test]
fn oversized_claim_is_rejected_before_parsing() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let oversized = vec![0_u8; MAX_CLAIM_WIRE_BYTES + 1];
    let result = evaluate_claim(&oversized, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(
        result,
        Err(TrustError::InputTooLarge {
            kind: trust_kernel::InputKind::Claim,
            limit: MAX_CLAIM_WIRE_BYTES,
        })
    );
    Ok(())
}

#[test]
fn future_claim_within_clock_skew_is_accepted() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let claim = make_claim(
        ClaimId::new("claim-future-within-skew"),
        KeyId::new("claim-key-1"),
        EVALUATION_TIME + 4,
    );
    let signed = sign_claim(claim, &claim_signing_key())?;
    let receipt = evaluate_claim(&encode_claim(&signed)?, &base.pack_bytes, EVALUATION_TIME)?;
    assert_eq!(receipt.decision, trust_kernel::Decision::Allow);
    Ok(())
}

#[test]
fn future_claim_exceeding_clock_skew_is_rejected() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let claim = make_claim(
        ClaimId::new("claim-future-beyond-skew"),
        KeyId::new("claim-key-1"),
        EVALUATION_TIME + 6,
    );
    let signed = sign_claim(claim, &claim_signing_key())?;
    let result = evaluate_claim(&encode_claim(&signed)?, &base.pack_bytes, EVALUATION_TIME);
    assert_eq!(result, Err(TrustError::ClaimIssuedInFuture));
    Ok(())
}

#[test]
fn decision_reason_transitions_from_current_to_offline() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let claim = make_claim_at(
        ClaimId::new("claim-freshness-transition"),
        KeyId::new("claim-key-1"),
        EVALUATION_TIME - 110,
        EVALUATION_TIME + 200,
    );
    let signed = sign_claim(claim, &claim_signing_key())?;
    let bytes = encode_claim(&signed)?;

    let current = evaluate_claim(&bytes, &base.pack_bytes, EVALUATION_TIME - 100)?;
    assert_eq!(current.reason, DecisionReason::AuthorizedCurrent);
    assert_eq!(current.assurance, FreshnessAssurance::Current);

    let offline = evaluate_claim(&bytes, &base.pack_bytes, EVALUATION_TIME - 80)?;
    assert_eq!(
        offline.reason,
        DecisionReason::AuthorizedOfflineWithinPolicy
    );
    assert_eq!(offline.assurance, FreshnessAssurance::OfflineWithinPolicy);
    Ok(())
}

#[test]
fn deprecated_key_fails_after_acceptance_window() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut pack = base.signed_pack.pack.clone();
    pack.pack_id = PackId::new("industrial-pack-deprecation-expired");
    pack.trust_epoch = 2;
    pack.root.generation = 2;
    let anchor = pack
        .root
        .anchors
        .iter_mut()
        .find(|anchor| anchor.key_id.as_str() == "claim-key-1")
        .ok_or_else(|| std::io::Error::other("fixture claim anchor missing"))?;
    anchor.state = KeyState::Deprecated {
        deprecated_at: EVALUATION_TIME,
        accept_until: EVALUATION_TIME + 100,
    };
    let signed_pack = sign_pack(
        pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let result = evaluate_claim(
        &base.claim_bytes,
        &encode_trust_pack(&signed_pack)?,
        EVALUATION_TIME + 100,
    );
    assert_eq!(result, Err(TrustError::KeyDeprecationWindowExpired));
    Ok(())
}

#[test]
fn revoked_key_is_rejected_immediately() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut pack = base.signed_pack.pack.clone();
    pack.pack_id = PackId::new("industrial-pack-key-revoked");
    pack.trust_epoch = 2;
    pack.root.generation = 2;
    let anchor = pack
        .root
        .anchors
        .iter_mut()
        .find(|anchor| anchor.key_id.as_str() == "claim-key-1")
        .ok_or_else(|| std::io::Error::other("fixture claim anchor missing"))?;
    anchor.state = KeyState::Revoked {
        revoked_at: EVALUATION_TIME - 30,
    };
    let signed_pack = sign_pack(
        pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let result = evaluate_claim(
        &base.claim_bytes,
        &encode_trust_pack(&signed_pack)?,
        EVALUATION_TIME,
    );
    assert_eq!(result, Err(TrustError::KeyRevoked));
    Ok(())
}

#[test]
fn later_status_manifest_cannot_remove_existing_revocation() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let revocation_id = scoped_revocation_id(
        &base.signed_claim.claim.issuer_id,
        &base.signed_claim.claim.claim_id,
    );

    let mut current_pack = base.signed_pack.pack.clone();
    current_pack.pack_id = PackId::new("industrial-pack-revoked-current");
    current_pack.trust_epoch = 2;
    current_pack.status.sequence = 2;
    current_pack.status.revoked_claims = vec![revocation_id];
    let signed_current = sign_pack(
        current_pack.clone(),
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;

    let mut candidate_pack = current_pack;
    candidate_pack.pack_id = PackId::new("industrial-pack-revoked-rollback");
    candidate_pack.trust_epoch = 3;
    candidate_pack.status.sequence = 3;
    candidate_pack.status.revoked_claims.clear();
    let signed_candidate = sign_pack(
        candidate_pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;

    let result = verify_trust_pack_transition(
        &encode_trust_pack(&signed_current)?,
        &encode_trust_pack(&signed_candidate)?,
        EVALUATION_TIME,
    );
    assert_eq!(result, Err(TrustError::RevocationRollback));
    Ok(())
}

#[test]
fn revocation_is_scoped_to_issuer_and_claim_id() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut pack = base.signed_pack.pack.clone();
    pack.pack_id = PackId::new("industrial-pack-issuer-scoped-revocation");
    pack.trust_epoch = 2;
    pack.status.sequence = 2;
    pack.status.revoked_claims = vec![scoped_revocation_id(
        &base.signed_claim.claim.issuer_id,
        &base.signed_claim.claim.claim_id,
    )];

    let second_issuer = IssuerId::new("employer-b");
    let second_key = KeyId::new("claim-key-b");
    pack.root.anchors.insert(
        1,
        TrustAnchor {
            trust_domain: TrustDomainId::new("industrial.demo"),
            issuer_id: second_issuer.clone(),
            key_id: second_key.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            purpose: KeyPurpose::ClaimSigning,
            public_key: claim_signing_key().verifying_key().to_bytes(),
            not_before: EVALUATION_TIME - 10_000,
            not_after: EVALUATION_TIME + 10_000,
            state: KeyState::Active,
        },
    );
    let mut second_grant = pack.policy.grants[0].clone();
    second_grant.issuer_id = second_issuer.clone();
    pack.policy.grants.push(second_grant);

    let signed_pack = sign_pack(
        pack,
        &pack_signing_key(),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let pack_bytes = encode_trust_pack(&signed_pack)?;

    assert_eq!(
        evaluate_claim(&base.claim_bytes, &pack_bytes, EVALUATION_TIME),
        Err(TrustError::ClaimRevoked)
    );

    let mut second_claim = base.signed_claim.claim.clone();
    second_claim.issuer_id = second_issuer;
    second_claim.key_id = second_key;
    let signed_second_claim = sign_claim(second_claim, &claim_signing_key())?;
    let receipt = evaluate_claim(
        &encode_claim(&signed_second_claim)?,
        &pack_bytes,
        EVALUATION_TIME,
    )?;
    assert_eq!(receipt.decision, trust_kernel::Decision::Allow);
    Ok(())
}

#[test]
fn single_byte_claim_corruption_never_authorizes() -> Result<(), Box<dyn Error>> {
    let base = fixture()?;
    let mut corrupted = base.claim_bytes.clone();
    let index = corrupted.len() / 2;
    corrupted[index] ^= 0x01;
    assert!(evaluate_claim(&corrupted, &base.pack_bytes, EVALUATION_TIME).is_err());
    Ok(())
}

proptest! {
    #[test]
    fn arbitrary_wire_inputs_never_panic(
        claim in proptest::collection::vec(any::<u8>(), 0..8192),
        pack in proptest::collection::vec(any::<u8>(), 0..16384),
        evaluation_time in any::<u64>(),
    ) {
        let _ = evaluate_claim(&claim, &pack, evaluation_time);
    }
}

#![forbid(unsafe_code)]

use std::{fmt, fs, io, path::Path};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use trust_kernel::{
    encode_claim, encode_trust_pack, evaluate_claim, scoped_revocation_id,
    verify_initial_trust_pack, verify_trust_pack_transition, ActionId, AssuranceLevel,
    CapabilityId, ClaimId, FreshnessPolicy, IssuerId, KeyId, KeyPurpose, KeyState, PackId,
    PolicyGrant, PolicyId, ResourceId, SignatureAlgorithm, SignedClaim, SignedClaimProfileV1,
    SignedTrustPack, StatusManifest, TrustAnchor, TrustAnchorRoot, TrustDomainId, TrustError,
    TrustPack, TrustPolicy, SIGNED_CLAIM_PROFILE_VERSION, TRUST_PACK_FORMAT_VERSION,
};

pub const EVALUATION_TIME: u64 = 1_900_000_000;

const CLAIM_KEY_BYTES: [u8; 32] = [7_u8; 32];
const ROTATED_CLAIM_KEY_BYTES: [u8; 32] = [23_u8; 32];
const PACK_KEY_BYTES: [u8; 32] = [11_u8; 32];

#[derive(Debug)]
pub enum ProofError {
    Trust(TrustError),
    Io(io::Error),
    ExpectedFailure(&'static str),
    UnexpectedError {
        expected: &'static str,
        actual: TrustError,
    },
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::ExpectedFailure(name) => write!(formatter, "expected {name} failure"),
            Self::UnexpectedError { expected, actual } => {
                write!(formatter, "expected {expected}, received {actual}")
            }
        }
    }
}

impl std::error::Error for ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Trust(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::ExpectedFailure(_) | Self::UnexpectedError { .. } => None,
        }
    }
}

impl From<TrustError> for ProofError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<io::Error> for ProofError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone)]
pub struct Fixture {
    pub signed_claim: SignedClaim,
    pub signed_pack: SignedTrustPack,
    pub claim_bytes: Vec<u8>,
    pub pack_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DrillResult {
    pub drill: &'static str,
    pub passed: bool,
    pub evidence: String,
}

pub fn fixture() -> Result<Fixture, ProofError> {
    fixture_at(EVALUATION_TIME)
}

pub fn fixture_at(evaluation_time: u64) -> Result<Fixture, ProofError> {
    let claim_key = SigningKey::from_bytes(&CLAIM_KEY_BYTES);
    let pack_key = SigningKey::from_bytes(&PACK_KEY_BYTES);
    let trust_domain = TrustDomainId::new("industrial.demo");
    let issuer_id = IssuerId::new("employer-a");
    let claim_key_id = KeyId::new("claim-key-1");
    let pack_issuer_id = IssuerId::new("swoosh-root");
    let pack_key_id = KeyId::new("pack-key-1");

    let claim_anchor = TrustAnchor {
        trust_domain: trust_domain.clone(),
        issuer_id: issuer_id.clone(),
        key_id: claim_key_id.clone(),
        algorithm: SignatureAlgorithm::Ed25519,
        purpose: KeyPurpose::ClaimSigning,
        public_key: claim_key.verifying_key().to_bytes(),
        not_before: evaluation_time - 10_000,
        not_after: evaluation_time + 10_000,
        state: KeyState::Active,
    };
    let pack_anchor = TrustAnchor {
        trust_domain: trust_domain.clone(),
        issuer_id: pack_issuer_id.clone(),
        key_id: pack_key_id.clone(),
        algorithm: SignatureAlgorithm::Ed25519,
        purpose: KeyPurpose::TrustPackSigning,
        public_key: pack_key.verifying_key().to_bytes(),
        not_before: evaluation_time - 10_000,
        not_after: evaluation_time + 10_000,
        state: KeyState::Active,
    };

    let pack = TrustPack {
        format_version: TRUST_PACK_FORMAT_VERSION,
        pack_id: PackId::new("industrial-pack-1"),
        trust_domain: trust_domain.clone(),
        trust_epoch: 1,
        generated_at: evaluation_time - 120,
        valid_from: evaluation_time - 120,
        valid_until: evaluation_time + 300,
        root: TrustAnchorRoot {
            root_id: "industrial-root".to_owned(),
            trust_domain: trust_domain.clone(),
            generation: 1,
            anchors: vec![claim_anchor, pack_anchor],
        },
        status: StatusManifest {
            sequence: 1,
            issued_at: evaluation_time - 120,
            not_after: evaluation_time + 300,
            revoked_claims: Vec::new(),
        },
        policy: TrustPolicy {
            policy_id: PolicyId::new("factory-access"),
            version: 1,
            effective_from: evaluation_time - 120,
            effective_until: evaluation_time + 300,
            freshness: FreshnessPolicy {
                max_claim_age_seconds: 360,
                max_clock_skew_seconds: 5,
                current_state_age_seconds: 30,
                max_offline_age_seconds: 420,
            },
            grants: vec![PolicyGrant {
                issuer_id: issuer_id.clone(),
                capability: CapabilityId::new("active-contractor"),
                action: ActionId::new("enter-site"),
                resource: ResourceId::new("factory-a"),
                minimum_assurance: AssuranceLevel::Substantial,
            }],
        },
    };

    let signed_pack = sign_pack(pack, &pack_key, pack_issuer_id, pack_key_id)?;
    let signed_claim = sign_claim(
        make_claim_at(
            ClaimId::new("claim-0001"),
            claim_key_id,
            evaluation_time - 60,
            evaluation_time + 240,
        ),
        &claim_key,
    )?;
    let claim_bytes = encode_claim(&signed_claim)?;
    let pack_bytes = encode_trust_pack(&signed_pack)?;

    Ok(Fixture {
        signed_claim,
        signed_pack,
        claim_bytes,
        pack_bytes,
    })
}

pub fn run_revocation_drill() -> Result<DrillResult, ProofError> {
    let base = fixture()?;
    evaluate_claim(&base.claim_bytes, &base.pack_bytes, EVALUATION_TIME)?;

    let mut revoked_pack = base.signed_pack.pack.clone();
    revoked_pack.pack_id = PackId::new("industrial-pack-2-revoked");
    revoked_pack.trust_epoch = 2;
    revoked_pack.generated_at = EVALUATION_TIME - 30;
    revoked_pack.valid_from = EVALUATION_TIME - 30;
    revoked_pack.status.sequence = 2;
    revoked_pack.status.issued_at = EVALUATION_TIME - 30;
    revoked_pack.status.revoked_claims = vec![scoped_revocation_id(
        &base.signed_claim.claim.issuer_id,
        &base.signed_claim.claim.claim_id,
    )];

    let signed = sign_pack(
        revoked_pack,
        &SigningKey::from_bytes(&PACK_KEY_BYTES),
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let bytes = encode_trust_pack(&signed)?;

    match evaluate_claim(&base.claim_bytes, &bytes, EVALUATION_TIME) {
        Err(TrustError::ClaimRevoked) => Ok(DrillResult {
            drill: "revocation",
            passed: true,
            evidence:
                "active claim was denied after its issuer-scoped ID entered status sequence 2"
                    .to_owned(),
        }),
        Err(actual) => Err(ProofError::UnexpectedError {
            expected: "ClaimRevoked",
            actual,
        }),
        Ok(_) => Err(ProofError::ExpectedFailure("ClaimRevoked")),
    }
}

pub fn run_offline_drill() -> Result<DrillResult, ProofError> {
    let base = fixture()?;
    let receipt = evaluate_claim(&base.claim_bytes, &base.pack_bytes, EVALUATION_TIME)?;

    match evaluate_claim(
        b"claim parsing must not run after the pack boundary",
        &base.pack_bytes,
        base.signed_pack.pack.valid_until,
    ) {
        Err(TrustError::TrustPackExpired) => Ok(DrillResult {
            drill: "offline",
            passed: true,
            evidence: format!(
                "offline receipt {} accepted within policy; pack boundary failed closed at {}",
                hex::encode(receipt.receipt_id),
                base.signed_pack.pack.valid_until
            ),
        }),
        Err(actual) => Err(ProofError::UnexpectedError {
            expected: "TrustPackExpired",
            actual,
        }),
        Ok(_) => Err(ProofError::ExpectedFailure("TrustPackExpired")),
    }
}

pub fn run_recovery_drill() -> Result<DrillResult, ProofError> {
    let base = fixture()?;
    let temporary = tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    let state_path = state_directory.join("current.tpack");
    fs::write(&state_path, &base.pack_bytes)?;
    evaluate_from_files(&base.claim_bytes, &state_path)?;

    fs::remove_dir_all(&state_directory)?;
    fs::create_dir(&state_directory)?;

    let checkpoint = base.signed_pack.checkpoint()?;
    verify_initial_trust_pack(&base.pack_bytes, &checkpoint, EVALUATION_TIME)?;
    fs::write(&state_path, &base.pack_bytes)?;
    let recovered_receipt = evaluate_from_files(&base.claim_bytes, &state_path)?;

    Ok(DrillResult {
        drill: "recovery",
        passed: true,
        evidence: format!(
            "purged state was rebuilt from pinned checkpoint {}; recovered receipt {}",
            hex::encode(checkpoint),
            hex::encode(recovered_receipt.receipt_id)
        ),
    })
}

pub fn run_key_rotation_drill() -> Result<DrillResult, ProofError> {
    let base = fixture()?;
    let old_claim_key = SigningKey::from_bytes(&CLAIM_KEY_BYTES);
    let new_claim_key = SigningKey::from_bytes(&ROTATED_CLAIM_KEY_BYTES);
    let pack_key = SigningKey::from_bytes(&PACK_KEY_BYTES);

    let mut rotated_pack = base.signed_pack.pack.clone();
    rotated_pack.pack_id = PackId::new("industrial-pack-2-rotated");
    rotated_pack.trust_epoch = 2;
    rotated_pack.generated_at = EVALUATION_TIME;
    rotated_pack.valid_from = EVALUATION_TIME;
    rotated_pack.root.generation = 2;
    rotated_pack.status.sequence = 2;
    rotated_pack.status.issued_at = EVALUATION_TIME;

    let old_anchor = rotated_pack
        .root
        .anchors
        .iter_mut()
        .find(|anchor| anchor.key_id.as_str() == "claim-key-1")
        .ok_or(ProofError::ExpectedFailure("old anchor fixture"))?;
    old_anchor.state = KeyState::Deprecated {
        deprecated_at: EVALUATION_TIME,
        accept_until: EVALUATION_TIME + 300,
    };

    let new_anchor = TrustAnchor {
        trust_domain: TrustDomainId::new("industrial.demo"),
        issuer_id: IssuerId::new("employer-a"),
        key_id: KeyId::new("claim-key-2"),
        algorithm: SignatureAlgorithm::Ed25519,
        purpose: KeyPurpose::ClaimSigning,
        public_key: new_claim_key.verifying_key().to_bytes(),
        not_before: EVALUATION_TIME,
        not_after: EVALUATION_TIME + 10_000,
        state: KeyState::Active,
    };
    rotated_pack.root.anchors.insert(1, new_anchor);

    let signed_rotated_pack = sign_pack(
        rotated_pack,
        &pack_key,
        IssuerId::new("swoosh-root"),
        KeyId::new("pack-key-1"),
    )?;
    let rotated_bytes = encode_trust_pack(&signed_rotated_pack)?;
    verify_trust_pack_transition(&base.pack_bytes, &rotated_bytes, EVALUATION_TIME + 10)?;

    evaluate_claim(&base.claim_bytes, &rotated_bytes, EVALUATION_TIME + 10)?;

    let new_claim = sign_claim(
        make_claim(
            ClaimId::new("claim-rotated-accepted"),
            KeyId::new("claim-key-2"),
            EVALUATION_TIME + 5,
        ),
        &new_claim_key,
    )?;
    evaluate_claim(
        &encode_claim(&new_claim)?,
        &rotated_bytes,
        EVALUATION_TIME + 10,
    )?;

    let invalid_old_issuance = sign_claim(
        make_claim(
            ClaimId::new("claim-old-key-rejected"),
            KeyId::new("claim-key-1"),
            EVALUATION_TIME + 5,
        ),
        &old_claim_key,
    )?;
    match evaluate_claim(
        &encode_claim(&invalid_old_issuance)?,
        &rotated_bytes,
        EVALUATION_TIME + 10,
    ) {
        Err(TrustError::KeyDeprecatedForIssuance) => Ok(DrillResult {
            drill: "key_rotation",
            passed: true,
            evidence:
                "pre-rotation claim remained valid, rotated key was accepted, and new old-key issuance was denied"
                    .to_owned(),
        }),
        Err(actual) => Err(ProofError::UnexpectedError {
            expected: "KeyDeprecatedForIssuance",
            actual,
        }),
        Ok(_) => Err(ProofError::ExpectedFailure(
            "KeyDeprecatedForIssuance",
        )),
    }
}

pub fn run_all_drills() -> Result<Vec<DrillResult>, ProofError> {
    Ok(vec![
        run_revocation_drill()?,
        run_offline_drill()?,
        run_recovery_drill()?,
        run_key_rotation_drill()?,
    ])
}

pub fn sign_claim(
    claim: SignedClaimProfileV1,
    signing_key: &SigningKey,
) -> Result<SignedClaim, TrustError> {
    let signature = signing_key.sign(&claim.signing_bytes()?).to_bytes();
    Ok(SignedClaim { claim, signature })
}

pub fn sign_pack(
    pack: TrustPack,
    signing_key: &SigningKey,
    signer_issuer_id: IssuerId,
    signer_key_id: KeyId,
) -> Result<SignedTrustPack, TrustError> {
    let mut signed = SignedTrustPack {
        pack,
        signer_issuer_id,
        signer_key_id,
        signature: [0_u8; 64],
    };
    signed.signature = signing_key.sign(&signed.signing_bytes()?).to_bytes();
    Ok(signed)
}

pub fn make_claim(claim_id: ClaimId, key_id: KeyId, issued_at: u64) -> SignedClaimProfileV1 {
    make_claim_at(claim_id, key_id, issued_at, EVALUATION_TIME + 240)
}

pub fn make_claim_at(
    claim_id: ClaimId,
    key_id: KeyId,
    issued_at: u64,
    not_after: u64,
) -> SignedClaimProfileV1 {
    SignedClaimProfileV1 {
        profile_version: SIGNED_CLAIM_PROFILE_VERSION,
        claim_id,
        trust_domain: TrustDomainId::new("industrial.demo"),
        issuer_id: IssuerId::new("employer-a"),
        key_id,
        subject_commitment: digest(b"pseudonymous-subject-001"),
        issued_at,
        not_after,
        action: ActionId::new("enter-site"),
        resource: ResourceId::new("factory-a"),
        capability: CapabilityId::new("active-contractor"),
        assurance_level: AssuranceLevel::Substantial,
        evidence_digest: digest(b"fixture-evidence"),
    }
}

pub fn claim_signing_key() -> SigningKey {
    SigningKey::from_bytes(&CLAIM_KEY_BYTES)
}

pub fn pack_signing_key() -> SigningKey {
    SigningKey::from_bytes(&PACK_KEY_BYTES)
}

fn evaluate_from_files(
    claim_bytes: &[u8],
    pack_path: &Path,
) -> Result<trust_kernel::DecisionReceipt, ProofError> {
    let pack_bytes = fs::read(pack_path)?;
    evaluate_claim(claim_bytes, &pack_bytes, EVALUATION_TIME).map_err(Into::into)
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

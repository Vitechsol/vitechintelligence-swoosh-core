use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{
    AssuranceLevel, Decision, DecisionReason, DecisionReceipt, FreshnessAssurance, KeyPurpose,
    KeyState, PolicyGrant, SignatureAlgorithm, SignedClaim, SignedClaimProfileV1, SignedTrustPack,
    TrustAnchor, TrustError, TrustPack,
};

const CLAIM_DOMAIN: &[u8] = b"SWOOSH-SIGNED-CLAIM-PROFILE-V1\0";
const PACK_DOMAIN: &[u8] = b"SWOOSH-TRUST-PACK-V1\0";
const PACK_CHECKPOINT_DOMAIN: &[u8] = b"SWOOSH-TRUST-PACK-CHECKPOINT-V1\0";
const CLAIM_FINGERPRINT_DOMAIN: &[u8] = b"SWOOSH-CLAIM-FINGERPRINT-V1\0";
const RECEIPT_DOMAIN: &[u8] = b"SWOOSH-DECISION-RECEIPT-V1\0";

struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn new(domain: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(domain.len() + 512);
        bytes.extend_from_slice(domain);
        Self { bytes }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn length(&mut self, value: usize) -> Result<(), TrustError> {
        let length = u32::try_from(value).map_err(|_| TrustError::CanonicalLengthOverflow)?;
        self.u32(length);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), TrustError> {
        self.length(value.len())?;
        self.fixed(value.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl SignedClaimProfileV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustError> {
        let mut writer = CanonicalWriter::new(CLAIM_DOMAIN);
        writer.u16(self.profile_version);
        writer.string(self.claim_id.as_str())?;
        writer.string(self.trust_domain.as_str())?;
        writer.string(self.issuer_id.as_str())?;
        writer.string(self.key_id.as_str())?;
        writer.fixed(&self.subject_commitment);
        writer.u64(self.issued_at);
        writer.u64(self.not_after);
        writer.string(self.action.as_str())?;
        writer.string(self.resource.as_str())?;
        writer.string(self.capability.as_str())?;
        write_assurance(&mut writer, self.assurance_level);
        writer.fixed(&self.evidence_digest);
        Ok(writer.finish())
    }
}

impl SignedTrustPack {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustError> {
        trust_pack_signing_bytes(
            &self.pack,
            self.signer_issuer_id.as_str(),
            self.signer_key_id.as_str(),
        )
    }

    pub fn checkpoint(&self) -> Result<[u8; 32], TrustError> {
        let signing_bytes = self.signing_bytes()?;
        Ok(hash_parts(
            PACK_CHECKPOINT_DOMAIN,
            &[&signing_bytes, &self.signature],
        ))
    }
}

impl SignedClaim {
    pub fn fingerprint(&self) -> Result<[u8; 32], TrustError> {
        let signing_bytes = self.claim.signing_bytes()?;
        Ok(hash_parts(
            CLAIM_FINGERPRINT_DOMAIN,
            &[&signing_bytes, &self.signature],
        ))
    }
}

pub(crate) fn receipt_identifier(receipt: &DecisionReceipt) -> Result<[u8; 32], TrustError> {
    let mut writer = CanonicalWriter::new(RECEIPT_DOMAIN);
    writer.u16(receipt.receipt_version);
    writer.string(&receipt.engine_version)?;
    writer.fixed(&receipt.claim_fingerprint);
    writer.fixed(&receipt.trust_state_fingerprint);
    writer.string(receipt.trust_domain.as_str())?;
    write_decision(&mut writer, receipt.decision);
    write_reason(&mut writer, receipt.reason);
    write_freshness(&mut writer, receipt.assurance);
    writer.u64(receipt.evaluated_at);
    writer.u64(receipt.valid_until);
    writer.u64(receipt.trust_epoch);
    writer.u64(receipt.root_generation);
    writer.u64(receipt.status_sequence);
    writer.string(receipt.policy_id.as_str())?;
    writer.u64(receipt.policy_version);
    Ok(hash_parts(RECEIPT_DOMAIN, &[&writer.finish()]))
}

fn trust_pack_signing_bytes(
    pack: &TrustPack,
    signer_issuer_id: &str,
    signer_key_id: &str,
) -> Result<Vec<u8>, TrustError> {
    let mut writer = CanonicalWriter::new(PACK_DOMAIN);
    writer.string(signer_issuer_id)?;
    writer.string(signer_key_id)?;
    writer.u16(pack.format_version);
    writer.string(pack.pack_id.as_str())?;
    writer.string(pack.trust_domain.as_str())?;
    writer.u64(pack.trust_epoch);
    writer.u64(pack.generated_at);
    writer.u64(pack.valid_from);
    writer.u64(pack.valid_until);

    writer.string(&pack.root.root_id)?;
    writer.string(pack.root.trust_domain.as_str())?;
    writer.u64(pack.root.generation);
    writer.length(pack.root.anchors.len())?;
    for anchor in &pack.root.anchors {
        write_anchor(&mut writer, anchor)?;
    }

    writer.u64(pack.status.sequence);
    writer.u64(pack.status.issued_at);
    writer.u64(pack.status.not_after);
    writer.length(pack.status.revoked_claims.len())?;
    for claim_id in &pack.status.revoked_claims {
        writer.string(claim_id.as_str())?;
    }

    writer.string(pack.policy.policy_id.as_str())?;
    writer.u64(pack.policy.version);
    writer.u64(pack.policy.effective_from);
    writer.u64(pack.policy.effective_until);
    writer.u64(pack.policy.freshness.max_claim_age_seconds);
    writer.u64(pack.policy.freshness.max_clock_skew_seconds);
    writer.u64(pack.policy.freshness.current_state_age_seconds);
    writer.u64(pack.policy.freshness.max_offline_age_seconds);
    writer.length(pack.policy.grants.len())?;
    for grant in &pack.policy.grants {
        write_grant(&mut writer, grant)?;
    }

    Ok(writer.finish())
}

fn write_anchor(writer: &mut CanonicalWriter, anchor: &TrustAnchor) -> Result<(), TrustError> {
    writer.string(anchor.trust_domain.as_str())?;
    writer.string(anchor.issuer_id.as_str())?;
    writer.string(anchor.key_id.as_str())?;
    match anchor.algorithm {
        SignatureAlgorithm::Ed25519 => writer.u8(1),
    }
    match anchor.purpose {
        KeyPurpose::ClaimSigning => writer.u8(1),
        KeyPurpose::TrustPackSigning => writer.u8(2),
    }
    writer.fixed(&anchor.public_key);
    writer.u64(anchor.not_before);
    writer.u64(anchor.not_after);
    match anchor.state {
        KeyState::Active => writer.u8(1),
        KeyState::Deprecated {
            deprecated_at,
            accept_until,
        } => {
            writer.u8(2);
            writer.u64(deprecated_at);
            writer.u64(accept_until);
        }
        KeyState::Revoked { revoked_at } => {
            writer.u8(3);
            writer.u64(revoked_at);
        }
    }
    Ok(())
}

fn write_grant(writer: &mut CanonicalWriter, grant: &PolicyGrant) -> Result<(), TrustError> {
    writer.string(grant.issuer_id.as_str())?;
    writer.string(grant.capability.as_str())?;
    writer.string(grant.action.as_str())?;
    writer.string(grant.resource.as_str())?;
    write_assurance(writer, grant.minimum_assurance);
    Ok(())
}

fn write_assurance(writer: &mut CanonicalWriter, assurance: AssuranceLevel) {
    match assurance {
        AssuranceLevel::Basic => writer.u8(1),
        AssuranceLevel::Substantial => writer.u8(2),
        AssuranceLevel::High => writer.u8(3),
    }
}

fn write_decision(writer: &mut CanonicalWriter, decision: Decision) {
    match decision {
        Decision::Allow => writer.u8(1),
    }
}

fn write_reason(writer: &mut CanonicalWriter, reason: DecisionReason) {
    match reason {
        DecisionReason::AuthorizedCurrent => writer.u8(1),
        DecisionReason::AuthorizedOfflineWithinPolicy => writer.u8(2),
    }
}

fn write_freshness(writer: &mut CanonicalWriter, assurance: FreshnessAssurance) {
    match assurance {
        FreshnessAssurance::Current => writer.u8(1),
        FreshnessAssurance::OfflineWithinPolicy => writer.u8(2),
    }
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

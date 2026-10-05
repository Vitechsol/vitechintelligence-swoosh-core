use alloc::{string::String, vec::Vec};
use core::fmt;
use serde::{Deserialize, Serialize};

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        pub struct $name(pub String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier!(ActionId);
identifier!(CapabilityId);
identifier!(ClaimId);
identifier!(IssuerId);
identifier!(KeyId);
identifier!(PackId);
identifier!(PolicyId);
identifier!(ResourceId);
identifier!(TrustDomainId);

pub const SIGNED_CLAIM_PROFILE_VERSION: u16 = 1;
pub const TRUST_PACK_FORMAT_VERSION: u16 = 1;
pub const DECISION_RECEIPT_VERSION: u16 = 1;
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyPurpose {
    ClaimSigning,
    TrustPackSigning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyState {
    Active,
    Deprecated {
        deprecated_at: u64,
        accept_until: u64,
    },
    Revoked {
        revoked_at: u64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AssuranceLevel {
    Basic,
    Substantial,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedClaimProfileV1 {
    pub profile_version: u16,
    pub claim_id: ClaimId,
    pub trust_domain: TrustDomainId,
    pub issuer_id: IssuerId,
    pub key_id: KeyId,
    pub subject_commitment: [u8; 32],
    pub issued_at: u64,
    pub not_after: u64,
    pub action: ActionId,
    pub resource: ResourceId,
    pub capability: CapabilityId,
    pub assurance_level: AssuranceLevel,
    pub evidence_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedClaim {
    pub claim: SignedClaimProfileV1,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchor {
    pub trust_domain: TrustDomainId,
    pub issuer_id: IssuerId,
    pub key_id: KeyId,
    pub algorithm: SignatureAlgorithm,
    pub purpose: KeyPurpose,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub state: KeyState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorRoot {
    pub root_id: String,
    pub trust_domain: TrustDomainId,
    pub generation: u64,
    pub anchors: Vec<TrustAnchor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusManifest {
    pub sequence: u64,
    pub issued_at: u64,
    pub not_after: u64,
    pub revoked_claims: Vec<ClaimId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyGrant {
    pub issuer_id: IssuerId,
    pub capability: CapabilityId,
    pub action: ActionId,
    pub resource: ResourceId,
    pub minimum_assurance: AssuranceLevel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FreshnessPolicy {
    pub max_claim_age_seconds: u64,
    pub max_clock_skew_seconds: u64,
    pub current_state_age_seconds: u64,
    pub max_offline_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustPolicy {
    pub policy_id: PolicyId,
    pub version: u64,
    pub effective_from: u64,
    pub effective_until: u64,
    pub freshness: FreshnessPolicy,
    pub grants: Vec<PolicyGrant>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustPack {
    pub format_version: u16,
    pub pack_id: PackId,
    pub trust_domain: TrustDomainId,
    pub trust_epoch: u64,
    pub generated_at: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub root: TrustAnchorRoot,
    pub status: StatusManifest,
    pub policy: TrustPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedTrustPack {
    pub pack: TrustPack,
    pub signer_issuer_id: IssuerId,
    pub signer_key_id: KeyId,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    AuthorizedCurrent,
    AuthorizedOfflineWithinPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshnessAssurance {
    Current,
    OfflineWithinPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecisionReceipt {
    pub receipt_version: u16,
    pub engine_version: String,
    pub receipt_id: [u8; 32],
    pub claim_fingerprint: [u8; 32],
    pub trust_state_fingerprint: [u8; 32],
    pub trust_domain: TrustDomainId,
    pub decision: Decision,
    pub reason: DecisionReason,
    pub assurance: FreshnessAssurance,
    pub evaluated_at: u64,
    pub valid_until: u64,
    pub trust_epoch: u64,
    pub root_generation: u64,
    pub status_sequence: u64,
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustPackMetadata {
    pub pack_id: PackId,
    pub trust_domain: TrustDomainId,
    pub trust_epoch: u64,
    pub root_generation: u64,
    pub status_sequence: u64,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub checkpoint: [u8; 32],
}

pub(crate) mod signature_serde {
    use alloc::vec::Vec;
    use core::fmt;
    use serde::{
        de::{Error as _, SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserializer, Serializer,
    };

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(64)?;
        for byte in value {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 64 signature bytes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(64);
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == 64 {
                        return Err(A::Error::custom("signature exceeds 64 bytes"));
                    }
                    bytes.push(byte);
                }
                bytes.try_into().map_err(|value: Vec<u8>| {
                    A::Error::custom(alloc::format!(
                        "signature has {} bytes; expected 64",
                        value.len()
                    ))
                })
            }
        }

        deserializer.deserialize_tuple(64, SignatureVisitor)
    }
}

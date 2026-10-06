use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputKind {
    Claim,
    TrustPack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierField {
    Action,
    Capability,
    Claim,
    Issuer,
    Key,
    Pack,
    Policy,
    Resource,
    Root,
    TrustDomain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustError {
    InputTooLarge { kind: InputKind, limit: usize },
    MalformedClaim,
    MalformedTrustPack,
    UnsupportedClaimVersion { found: u16 },
    UnsupportedTrustPackVersion { found: u16 },
    InvalidIdentifier { field: IdentifierField },
    InvalidClaimWindow,
    InvalidTrustPackWindow,
    InvalidPolicyWindow,
    InvalidStatusWindow,
    InvalidAnchorWindow,
    InvalidKeyState,
    InvalidPublicKey,
    InvalidSubjectCommitment,
    InvalidEvidenceDigest,
    EmptyTrustAnchorRoot,
    MissingClaimSigningAnchor,
    MissingTrustPackSigningAnchor,
    DuplicateOrUnsortedAnchors,
    DuplicateOrUnsortedRevocations,
    DuplicateOrUnsortedPolicyGrants,
    TrustDomainMismatch,
    TrustPackRootMismatch,
    TrustPackStatusCoverageInsufficient,
    TrustPackPolicyCoverageInsufficient,
    TrustPackOfflineWindowExceeded,
    TrustPackNotYetValid,
    TrustPackExpired,
    TrustPackSignerUnauthorized,
    TrustPackSignatureInvalid,
    CanonicalLengthOverflow,
    CheckpointMismatch,
    TrustEpochRollback { current: u64, candidate: u64 },
    RootGenerationRollback { current: u64, candidate: u64 },
    RootGenerationJump { current: u64, candidate: u64 },
    StatusSequenceRollback { current: u64, candidate: u64 },
    RevocationRollback,
    PolicyVersionRollback { current: u64, candidate: u64 },
    RootIdentityChanged,
    RootChangedWithoutGeneration,
    UnknownIssuer,
    UnknownKey,
    KeyPurposeDenied,
    KeyNotYetValid,
    KeyExpired,
    KeyRevoked,
    KeyDeprecatedForIssuance,
    KeyDeprecationWindowExpired,
    InvalidSignature,
    ClaimRevoked,
    ClaimExpired,
    ClaimIssuedInFuture,
    ClaimStale,
    PolicyDenied,
    ArithmeticOverflow,
    SerializationFailed,
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { kind, limit } => {
                write!(formatter, "{kind:?} input exceeds the {limit}-byte limit")
            }
            Self::MalformedClaim => formatter.write_str("claim encoding is malformed"),
            Self::MalformedTrustPack => formatter.write_str("TrustPack encoding is malformed"),
            Self::UnsupportedClaimVersion { found } => {
                write!(
                    formatter,
                    "unsupported signed-claim profile version {found}"
                )
            }
            Self::UnsupportedTrustPackVersion { found } => {
                write!(formatter, "unsupported TrustPack format version {found}")
            }
            Self::InvalidIdentifier { field } => {
                write!(formatter, "invalid {field:?} identifier")
            }
            Self::InvalidClaimWindow => formatter.write_str("claim validity window is invalid"),
            Self::InvalidTrustPackWindow => {
                formatter.write_str("TrustPack validity window is invalid")
            }
            Self::InvalidPolicyWindow => formatter.write_str("policy validity window is invalid"),
            Self::InvalidStatusWindow => {
                formatter.write_str("status-manifest validity window is invalid")
            }
            Self::InvalidAnchorWindow => formatter.write_str("trust-anchor window is invalid"),
            Self::InvalidKeyState => formatter.write_str("trust-anchor key state is invalid"),
            Self::InvalidPublicKey => formatter.write_str("Ed25519 public key is invalid"),
            Self::InvalidSubjectCommitment => {
                formatter.write_str("subject commitment must not be all zeroes")
            }
            Self::InvalidEvidenceDigest => {
                formatter.write_str("evidence digest must not be all zeroes")
            }
            Self::EmptyTrustAnchorRoot => formatter.write_str("TrustAnchorRoot is empty"),
            Self::MissingClaimSigningAnchor => {
                formatter.write_str("TrustAnchorRoot has no claim-signing anchor")
            }
            Self::MissingTrustPackSigningAnchor => {
                formatter.write_str("TrustAnchorRoot has no TrustPack-signing anchor")
            }
            Self::DuplicateOrUnsortedAnchors => {
                formatter.write_str("trust anchors must be unique and canonically sorted")
            }
            Self::DuplicateOrUnsortedRevocations => {
                formatter.write_str("revocations must be unique and canonically sorted")
            }
            Self::DuplicateOrUnsortedPolicyGrants => {
                formatter.write_str("policy grants must be unique and canonically sorted")
            }
            Self::TrustDomainMismatch => formatter.write_str("trust domain does not match"),
            Self::TrustPackRootMismatch => {
                formatter.write_str("TrustPack and TrustAnchorRoot domains do not match")
            }
            Self::TrustPackStatusCoverageInsufficient => {
                formatter.write_str("status manifest does not cover the TrustPack lifetime")
            }
            Self::TrustPackPolicyCoverageInsufficient => {
                formatter.write_str("policy does not cover the TrustPack lifetime")
            }
            Self::TrustPackOfflineWindowExceeded => {
                formatter.write_str("TrustPack exceeds its signed maximum offline age")
            }
            Self::TrustPackNotYetValid => formatter.write_str("TrustPack is not yet valid"),
            Self::TrustPackExpired => {
                formatter.write_str("TrustPack freshness boundary has expired")
            }
            Self::TrustPackSignerUnauthorized => {
                formatter.write_str("TrustPack signer is not authorized")
            }
            Self::TrustPackSignatureInvalid => {
                formatter.write_str("TrustPack signature verification failed")
            }
            Self::CanonicalLengthOverflow => {
                formatter.write_str("canonical field length exceeds the format limit")
            }
            Self::CheckpointMismatch => {
                formatter.write_str("TrustPack checkpoint does not match the pinned value")
            }
            Self::TrustEpochRollback { current, candidate } => write!(
                formatter,
                "TrustPack epoch rollback rejected: current={current}, candidate={candidate}"
            ),
            Self::RootGenerationRollback { current, candidate } => write!(
                formatter,
                "root generation rollback rejected: current={current}, candidate={candidate}"
            ),
            Self::RootGenerationJump { current, candidate } => write!(
                formatter,
                "root generation jump rejected: current={current}, candidate={candidate}"
            ),
            Self::StatusSequenceRollback { current, candidate } => write!(
                formatter,
                "status sequence rollback rejected: current={current}, candidate={candidate}"
            ),
            Self::RevocationRollback => {
                formatter.write_str("revoked claims cannot be removed from a later status manifest")
            }
            Self::PolicyVersionRollback { current, candidate } => write!(
                formatter,
                "policy version rollback rejected: current={current}, candidate={candidate}"
            ),
            Self::RootIdentityChanged => formatter.write_str("TrustAnchorRoot identity changed"),
            Self::RootChangedWithoutGeneration => {
                formatter.write_str("trust anchors changed without advancing root generation")
            }
            Self::UnknownIssuer => formatter.write_str("issuer is not trusted"),
            Self::UnknownKey => formatter.write_str("issuer key is not trusted"),
            Self::KeyPurposeDenied => formatter.write_str("key purpose is not authorized"),
            Self::KeyNotYetValid => formatter.write_str("issuer key is not yet valid"),
            Self::KeyExpired => formatter.write_str("issuer key has expired"),
            Self::KeyRevoked => formatter.write_str("issuer key is revoked"),
            Self::KeyDeprecatedForIssuance => {
                formatter.write_str("deprecated key cannot issue this claim")
            }
            Self::KeyDeprecationWindowExpired => {
                formatter.write_str("deprecated key acceptance window has expired")
            }
            Self::InvalidSignature => formatter.write_str("claim signature verification failed"),
            Self::ClaimRevoked => formatter.write_str("claim is revoked"),
            Self::ClaimExpired => formatter.write_str("claim has expired"),
            Self::ClaimIssuedInFuture => formatter.write_str("claim issue time is in the future"),
            Self::ClaimStale => formatter.write_str("claim exceeds the maximum permitted age"),
            Self::PolicyDenied => formatter.write_str("claim is not authorized by policy"),
            Self::ArithmeticOverflow => formatter.write_str("time arithmetic overflow"),
            Self::SerializationFailed => formatter.write_str("canonical serialization failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TrustError {}

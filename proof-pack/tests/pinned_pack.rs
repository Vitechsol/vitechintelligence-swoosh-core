#![forbid(unsafe_code)]
//! Regression tests for the "integrity is not authority" boundary: a TrustPack an attacker
//! built and signed with their own keys must not be accepted through a pinned entry point.
use proof_pack::{fixture, fixture_with_keys_at, EVALUATION_TIME};
use std::error::Error;
use trust_kernel::{evaluate_claim, Decision, PinnedTrustPack, TrustError};
use trust_sdk::InstalledTrustContext;

const ATTACKER_CLAIM_KEY: [u8; 32] = [0xA1; 32];
const ATTACKER_PACK_KEY: [u8; 32] = [0xB2; 32];

/// Characterizes the raw compatibility API hazard. This is expected to succeed today, and is
/// not an endorsement of that API. Delete or invert this test when raw APIs are restricted.
#[test]
fn unpinned_entry_point_accepts_attacker_built_self_signed_pack() -> Result<(), Box<dyn Error>> {
    let attacker = fixture_with_keys_at(EVALUATION_TIME, ATTACKER_CLAIM_KEY, ATTACKER_PACK_KEY)?;
    let receipt = evaluate_claim(&attacker.claim_bytes, &attacker.pack_bytes, EVALUATION_TIME)?;
    assert_eq!(receipt.decision, Decision::Allow);
    Ok(())
}

#[test]
fn pinned_handle_rejects_attacker_pack_under_the_legitimate_checkpoint(
) -> Result<(), Box<dyn Error>> {
    let legitimate = fixture()?;
    let attacker = fixture_with_keys_at(EVALUATION_TIME, ATTACKER_CLAIM_KEY, ATTACKER_PACK_KEY)?;
    let pin = legitimate.signed_pack.checkpoint()?;

    assert_eq!(
        PinnedTrustPack::verify_initial(&attacker.pack_bytes, &pin, EVALUATION_TIME).err(),
        Some(TrustError::CheckpointMismatch)
    );
    assert!(InstalledTrustContext::install_at(&attacker.pack_bytes, &pin, EVALUATION_TIME).is_err());
    Ok(())
}

#[test]
fn pinned_handle_allows_legitimate_claim_and_rejects_attacker_claim(
) -> Result<(), Box<dyn Error>> {
    let legitimate = fixture()?;
    let attacker = fixture_with_keys_at(EVALUATION_TIME, ATTACKER_CLAIM_KEY, ATTACKER_PACK_KEY)?;
    let pin = legitimate.signed_pack.checkpoint()?;
    let pinned = PinnedTrustPack::verify_initial(&legitimate.pack_bytes, &pin, EVALUATION_TIME)?;

    let receipt = pinned.evaluate_claim(&legitimate.claim_bytes, EVALUATION_TIME)?;
    assert_eq!(receipt.decision, Decision::Allow);

    // Same issuer/key identifiers and policy shape, but signed by the attacker's key.
    assert_eq!(
        pinned.evaluate_claim(&attacker.claim_bytes, EVALUATION_TIME).err(),
        Some(TrustError::InvalidSignature)
    );
    Ok(())
}

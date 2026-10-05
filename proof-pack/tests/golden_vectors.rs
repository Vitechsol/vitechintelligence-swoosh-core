#![forbid(unsafe_code)]

use std::error::Error;

use proof_pack::{fixture, EVALUATION_TIME};
use trust_kernel::evaluate_claim;

#[test]
fn canonical_fixture_matches_golden_receipt_and_checkpoint() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let receipt = evaluate_claim(&fixture.claim_bytes, &fixture.pack_bytes, EVALUATION_TIME)?;

    assert_eq!(
        hex::encode(receipt.receipt_id),
        "1c5c049a12d60f5a1ae9a39169734bb2e3d123a20ebf6585c55027bea54cfb73"
    );
    assert_eq!(
        hex::encode(fixture.signed_pack.checkpoint()?),
        "eb6ddae9fe24e0529095f6510a178394d674b13a05be98b875fa4dca1ec63a11"
    );

    Ok(())
}

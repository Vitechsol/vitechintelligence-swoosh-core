#![forbid(unsafe_code)]
use ed25519_dalek::{Signer, SigningKey};
use proof_pack::{fixture, EVALUATION_TIME};
use std::error::Error;
use trust_kernel::{
    encode_action_v3, evaluate_action_v3, ActionBindingV3, ActionError, ActionRequestV3,
    SignedActionV3, ACTION_PROFILE_V3_VERSION,
};
use trust_sdk::InstalledTrustContext;

#[test]
fn internally_valid_attacker_root_cannot_replace_external_pin() -> Result<(), Box<dyn Error>> {
    let original = fixture()?;
    let attacker = SigningKey::from_bytes(&[43; 32]);
    let mut pack = original.signed_pack.pack.clone();
    pack.trust_epoch = 2;
    pack.status.sequence = 2;
    for anchor in &mut pack.root.anchors {
        if anchor.purpose == trust_kernel::KeyPurpose::TrustPackSigning {
            anchor.public_key = attacker.verifying_key().to_bytes();
        }
    }
    let signed = proof_pack::sign_pack(
        pack,
        &attacker,
        original.signed_pack.signer_issuer_id.clone(),
        original.signed_pack.signer_key_id.clone(),
    )?;
    let bytes = trust_kernel::encode_trust_pack(&signed)?;
    // Positive control: the attacker pack is well-formed and internally signed.
    assert!(trust_kernel::inspect_trust_pack(&bytes, EVALUATION_TIME).is_ok());
    let checkpoint = original.signed_pack.checkpoint()?;
    assert!(InstalledTrustContext::install_at(&bytes, &checkpoint, EVALUATION_TIME).is_err());
    let mut installed =
        InstalledTrustContext::install_at(&original.pack_bytes, &checkpoint, EVALUATION_TIME)?;
    assert!(installed.update_at(&bytes, EVALUATION_TIME).is_err());
    assert_eq!(installed.metadata().trust_epoch, 1);
    assert!(installed
        .evaluate_claim_at(&original.claim_bytes, EVALUATION_TIME)
        .is_ok());
    Ok(())
}

fn signed_action() -> Result<(proof_pack::Fixture, SignedActionV3, ActionRequestV3), Box<dyn Error>>
{
    let fixture = fixture()?;
    let binding = ActionBindingV3 {
        workflow_id: "contractor-access".into(),
        task_id: "entry-1".into(),
        generation: 1,
        role_id: "site-entry-worker".into(),
        cognitive_profile_digest: [31; 32],
        purpose: "site-entry".into(),
        destination: "local:factory-a".into(),
        effect_digest: [23; 32],
        policy_version: 1,
        trust_epoch: 1,
    };
    let mut action = SignedActionV3 {
        profile_version: ACTION_PROFILE_V3_VERSION,
        authority: fixture.signed_claim.clone(),
        binding: binding.clone(),
        signature: [0; 64],
    };
    action.signature = SigningKey::from_bytes(&[7; 32])
        .sign(&action.signing_bytes()?)
        .to_bytes();
    let request = ActionRequestV3 {
        authenticated_subject: action.authority.claim.subject_commitment,
        authenticated_role: "site-entry-worker".into(),
        action: "enter-site".into(),
        resource: "factory-a".into(),
        binding,
    };
    Ok((fixture, action, request))
}

#[test]
fn role_bound_action_v3_authorizes_only_matching_authenticated_role() -> Result<(), Box<dyn Error>>
{
    let (fixture, action, request) = signed_action()?;
    let context = InstalledTrustContext::install_at(
        &fixture.pack_bytes,
        &fixture.signed_pack.checkpoint()?,
        EVALUATION_TIME,
    )?;
    let receipt =
        context.evaluate_action_v3_at(&encode_action_v3(&action)?, &request, EVALUATION_TIME)?;
    assert_eq!(receipt.profile_version, ACTION_PROFILE_V3_VERSION);
    assert_eq!(receipt.trust.trust_epoch, 1);
    Ok(())
}

#[test]
fn forged_host_role_denies_even_when_subject_and_capability_match() -> Result<(), Box<dyn Error>> {
    let (fixture, action, mut request) = signed_action()?;
    request.authenticated_role = "site-admin".into();
    assert_eq!(
        evaluate_action_v3(
            &encode_action_v3(&action)?,
            &fixture.pack_bytes,
            EVALUATION_TIME,
            &request,
        ),
        Err(ActionError::RoleMismatch)
    );
    Ok(())
}

#[test]
fn tampered_signed_role_cannot_reuse_valid_signature() -> Result<(), Box<dyn Error>> {
    let (fixture, mut action, mut request) = signed_action()?;
    action.binding.role_id = "site-admin".into();
    request.binding.role_id = "site-admin".into();
    request.authenticated_role = "site-admin".into();
    assert!(evaluate_action_v3(
        &encode_action_v3(&action)?,
        &fixture.pack_bytes,
        EVALUATION_TIME,
        &request,
    )
    .is_err());
    Ok(())
}

#[test]
fn signed_role_must_match_host_binding_exactly() -> Result<(), Box<dyn Error>> {
    let (fixture, action, mut request) = signed_action()?;
    request.binding.role_id = "site-admin".into();
    assert_eq!(
        evaluate_action_v3(
            &encode_action_v3(&action)?,
            &fixture.pack_bytes,
            EVALUATION_TIME,
            &request,
        ),
        Err(ActionError::ScopeMismatch)
    );
    Ok(())
}

#[test]
fn invalid_role_identifier_fails_closed() -> Result<(), Box<dyn Error>> {
    let (_, mut action, _) = signed_action()?;
    action.binding.role_id = "bad\nrole".into();
    assert_eq!(encode_action_v3(&action), Err(ActionError::InvalidBinding));
    Ok(())
}

#[test]
fn cognitive_profile_digest_is_part_of_the_signed_authority_context() -> Result<(), Box<dyn Error>>
{
    let (fixture, action, mut request) = signed_action()?;
    request.binding.cognitive_profile_digest = [77; 32];
    assert_eq!(
        evaluate_action_v3(
            &encode_action_v3(&action)?,
            &fixture.pack_bytes,
            EVALUATION_TIME,
            &request,
        ),
        Err(ActionError::ScopeMismatch)
    );
    Ok(())
}

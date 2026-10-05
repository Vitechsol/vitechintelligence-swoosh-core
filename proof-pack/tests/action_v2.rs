#![forbid(unsafe_code)]
use ed25519_dalek::{Signer, SigningKey};
use proof_pack::{fixture, sign_pack, EVALUATION_TIME};
use std::error::Error;
use trust_kernel::{
    encode_action_v2, evaluate_action_v2, ActionBindingV2, ActionError, ActionRequestV2,
    SignedActionV2, ACTION_PROFILE_VERSION,
};
use trust_sdk::{InstalledTrustContext, SdkError};

fn signed_action() -> Result<(proof_pack::Fixture, SignedActionV2, ActionRequestV2), Box<dyn Error>>
{
    let fixture = fixture()?;
    let binding = ActionBindingV2 {
        workflow_id: "contractor-access".into(),
        task_id: "entry-1".into(),
        generation: 1,
        purpose: "site-entry".into(),
        destination: "local:factory-a".into(),
        effect_digest: [19; 32],
        policy_version: 1,
        trust_epoch: 1,
    };
    let mut action = SignedActionV2 {
        profile_version: ACTION_PROFILE_VERSION,
        authority: fixture.signed_claim.clone(),
        binding: binding.clone(),
        signature: [0; 64],
    };
    action.signature = SigningKey::from_bytes(&[7; 32])
        .sign(&action.signing_bytes()?)
        .to_bytes();
    let request = ActionRequestV2 {
        authenticated_subject: action.authority.claim.subject_commitment,
        action: "enter-site".into(),
        resource: "factory-a".into(),
        binding,
    };
    Ok((fixture, action, request))
}

#[test]
fn action_v2_uses_the_canonical_verifier_and_trusted_context() -> Result<(), Box<dyn Error>> {
    let (f, a, r) = signed_action()?;
    let context = InstalledTrustContext::install_at(
        &f.pack_bytes,
        &f.signed_pack.checkpoint()?,
        EVALUATION_TIME,
    )?;
    let receipt = context.evaluate_action_at(&encode_action_v2(&a)?, &r, EVALUATION_TIME)?;
    assert_eq!(receipt.profile_version, 2);
    assert_eq!(receipt.trust.trust_epoch, 1);
    assert_eq!(
        hex::encode(receipt.action_digest),
        "085aa53c46f6e96f48afd60d4994992c6f79d2844d5b3aaa5c965fbebda0c9eb"
    );
    Ok(())
}

#[test]
fn signed_context_cannot_be_changed_by_worker() -> Result<(), Box<dyn Error>> {
    let (f, a, r) = signed_action()?;
    for index in 0..9 {
        let mut forged = r.clone();
        match index {
            0 => forged.authenticated_subject = [99; 32],
            1 => forged.action = "write".into(),
            2 => forged.resource = "other-site".into(),
            3 => forged.binding.generation = 2,
            4 => forged.binding.purpose = "other".into(),
            5 => forged.binding.destination = "https://remote".into(),
            6 => forged.binding.effect_digest = [99; 32],
            7 => forged.binding.task_id = "other".into(),
            _ => forged.binding.workflow_id = "other".into(),
        }
        assert!(evaluate_action_v2(
            &encode_action_v2(&a)?,
            &f.pack_bytes,
            EVALUATION_TIME,
            &forged
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn tampering_or_unknown_profiles_deny() -> Result<(), Box<dyn Error>> {
    let (f, mut a, r) = signed_action()?;
    let mut trailing = encode_action_v2(&a)?;
    trailing.push(0);
    assert_eq!(
        evaluate_action_v2(&trailing, &f.pack_bytes, EVALUATION_TIME, &r),
        Err(ActionError::Malformed)
    );
    a.signature[0] ^= 1;
    assert!(
        evaluate_action_v2(&encode_action_v2(&a)?, &f.pack_bytes, EVALUATION_TIME, &r).is_err()
    );
    a.profile_version = 3;
    assert_eq!(encode_action_v2(&a), Err(ActionError::UnsupportedVersion));
    assert_eq!(
        evaluate_action_v2(&[0; 16_385], &f.pack_bytes, EVALUATION_TIME, &r),
        Err(ActionError::InputTooLarge)
    );
    Ok(())
}

#[test]
fn pin_and_known_newer_epoch_fail_closed() -> Result<(), Box<dyn Error>> {
    let (f, a, r) = signed_action()?;
    assert!(InstalledTrustContext::install_at(&f.pack_bytes, &[0; 32], EVALUATION_TIME).is_err());
    let mut context = InstalledTrustContext::install_at(
        &f.pack_bytes,
        &f.signed_pack.checkpoint()?,
        EVALUATION_TIME,
    )?;
    context.note_authoritative_epoch(2);
    assert_eq!(
        context.evaluate_action_at(&encode_action_v2(&a)?, &r, EVALUATION_TIME),
        Err(SdkError::NewerEpochRequired)
    );
    Ok(())
}

#[test]
fn changed_policy_epoch_invalidates_old_action_and_failed_update_preserves_installed_state(
) -> Result<(), Box<dyn Error>> {
    let (f, a, r) = signed_action()?;
    let mut context = InstalledTrustContext::install_at(
        &f.pack_bytes,
        &f.signed_pack.checkpoint()?,
        EVALUATION_TIME,
    )?;
    assert!(context.update_at(&[0; 1], EVALUATION_TIME).is_err());
    assert_eq!(context.metadata().trust_epoch, 1);
    let mut pack = f.signed_pack.pack.clone();
    pack.trust_epoch = 2;
    pack.policy.version = 2;
    pack.status.sequence = 2;
    let updated = sign_pack(
        pack,
        &SigningKey::from_bytes(&[11; 32]),
        f.signed_pack.signer_issuer_id,
        f.signed_pack.signer_key_id,
    )?;
    context.update_at(&trust_kernel::encode_trust_pack(&updated)?, EVALUATION_TIME)?;
    assert_eq!(
        context.evaluate_action_at(&encode_action_v2(&a)?, &r, EVALUATION_TIME),
        Err(SdkError::Action(ActionError::StateChanged))
    );
    assert!(context.update_at(&f.pack_bytes, EVALUATION_TIME).is_err());
    Ok(())
}

#[test]
fn zero_or_control_character_bindings_are_rejected() -> Result<(), Box<dyn Error>> {
    let (_, mut a, _) = signed_action()?;
    a.binding.generation = 0;
    assert_eq!(encode_action_v2(&a), Err(ActionError::InvalidBinding));
    a.binding.generation = 1;
    a.binding.purpose = "forged\nline".into();
    assert_eq!(encode_action_v2(&a), Err(ActionError::InvalidBinding));
    Ok(())
}

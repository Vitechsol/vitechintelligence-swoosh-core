//! Synthetic short-lived local integration material. Never use these test keys in deployment.
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use trust_kernel::{
    encode_action_v3, ActionBindingV3, ActionRequestV3, SignedActionV3, ACTION_PROFILE_V3_VERSION,
};
fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(std::env::args().nth(1).ok_or("output directory required")?);
    fs::create_dir_all(&directory)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fixture = proof_pack::fixture_at(now)?;
    let effect = b"{\"entry\":\"factory-a\",\"subject\":\"synthetic-contractor\"}";
    let binding = ActionBindingV3 {
        workflow_id: "contractor-access".into(),
        task_id: "entry-1".into(),
        generation: 1,
        role_id: "site-entry-worker".into(),
        cognitive_profile_digest: Sha256::digest(b"{\"methodology_digest\":\"1ccb6aa3f381ce135dc5dff94848a53e7abb8782a35d2f61bbdef753c543e74b\",\"profile_id\":\"site-entry-worker.default\",\"role_id\":\"site-entry-worker\",\"version\":1}").into(),
        purpose: "site-entry".into(),
        destination: "local:factory-a".into(),
        effect_digest: Sha256::digest(effect).into(),
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
    fs::write(directory.join("action.bin"), encode_action_v3(&action)?)?;
    fs::write(directory.join("current.tpack"), fixture.pack_bytes)?;
    fs::write(
        directory.join("checkpoint.txt"),
        hex::encode(fixture.signed_pack.checkpoint()?),
    )?;
    fs::write(
        directory.join("host-request.json"),
        serde_json::to_vec_pretty(&request)?,
    )?;
    fs::write(directory.join("effect.json"), effect)?;
    println!("Synthetic fixture created; it expires within five minutes.");
    Ok(())
}

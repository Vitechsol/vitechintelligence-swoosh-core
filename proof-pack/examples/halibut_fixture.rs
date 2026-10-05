//! Synthetic short-lived local integration material. Never use these test keys in deployment.
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use trust_kernel::{encode_action_v2, ActionBindingV2, ActionRequestV2, SignedActionV2};
fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(std::env::args().nth(1).ok_or("output directory required")?);
    fs::create_dir_all(&directory)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fixture = proof_pack::fixture_at(now)?;
    let effect = b"{\"entry\":\"factory-a\",\"subject\":\"synthetic-contractor\"}";
    let binding = ActionBindingV2 {
        workflow_id: "contractor-access".into(),
        task_id: "entry-1".into(),
        generation: 1,
        purpose: "site-entry".into(),
        destination: "local:factory-a".into(),
        effect_digest: Sha256::digest(effect).into(),
        policy_version: 1,
        trust_epoch: 1,
    };
    let mut action = SignedActionV2 {
        profile_version: 2,
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
    fs::write(directory.join("action.bin"), encode_action_v2(&action)?)?;
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

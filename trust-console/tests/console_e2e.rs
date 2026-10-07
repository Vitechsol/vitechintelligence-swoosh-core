#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use proof_pack::fixture_at;
use serde_json::Value;
use tempfile::tempdir;

fn run(command: &mut Command) -> Result<Output, Box<dyn Error>> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "command failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

#[test]
fn console_installs_inspects_and_evaluates_real_sdk_state() -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fixture = fixture_at(now)?;
    let temporary = tempdir()?;
    let candidate = temporary.path().join("candidate.tpack");
    let store = temporary.path().join("state/current.tpack");
    let claim = temporary.path().join("claim.sclaim");
    fs::write(&candidate, &fixture.pack_bytes)?;
    fs::write(&claim, &fixture.claim_bytes)?;

    let binary = env!("CARGO_BIN_EXE_trust-console");
    let checkpoint = hex::encode(fixture.signed_pack.checkpoint()?);

    let install = run(Command::new(binary)
        .arg("trust-pack")
        .arg("install")
        .arg("--candidate")
        .arg(&candidate)
        .arg("--store")
        .arg(&store)
        .arg("--expected-checkpoint")
        .arg(&checkpoint))?;
    let installed: Value = serde_json::from_slice(&install.stdout)?;
    assert_eq!(installed["ok"], true);
    assert_eq!(installed["operation"], "installed");
    assert_eq!(installed["trust_epoch"], 1);

    let inspect = run(Command::new(binary)
        .arg("trust-pack")
        .arg("inspect")
        .arg("--store")
        .arg(&store))?;
    let inspected: Value = serde_json::from_slice(&inspect.stdout)?;
    assert_eq!(inspected["ok"], true);
    assert_eq!(inspected["operation"], "inspected");
    assert_eq!(inspected["checkpoint"], installed["checkpoint"]);

    let evaluate = run(Command::new(binary)
        .arg("evaluate")
        .arg("--claim")
        .arg(&claim)
        .arg("--trust-pack")
        .arg(&store)
        .arg("--expected-checkpoint")
        .arg(&checkpoint)
        .arg("--minimum-epoch")
        .arg("1"))?;
    let receipt: Value = serde_json::from_slice(&evaluate.stdout)?;
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["decision"], "ALLOW");
    assert_eq!(receipt["trust_domain"], "industrial.demo");
    assert_eq!(receipt["policy_id"], "factory-access");
    assert!(receipt.get("subject_commitment").is_none());
    assert!(receipt.get("evidence_digest").is_none());

    Ok(())
}


#[test]
fn console_claim_evaluation_enforces_persisted_pin_and_epoch_floor() -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fixture = fixture_at(now)?;
    let temporary = tempdir()?;
    let pack = temporary.path().join("current.tpack");
    let claim = temporary.path().join("claim.sclaim");
    fs::write(&pack, &fixture.pack_bytes)?;
    fs::write(&claim, &fixture.claim_bytes)?;

    let binary = env!("CARGO_BIN_EXE_trust-console");
    let checkpoint = hex::encode(fixture.signed_pack.checkpoint()?);

    let wrong_pin = Command::new(binary)
        .arg("evaluate")
        .arg("--claim")
        .arg(&claim)
        .arg("--trust-pack")
        .arg(&pack)
        .arg("--expected-checkpoint")
        .arg("0".repeat(64))
        .arg("--minimum-epoch")
        .arg("1")
        .output()?;
    assert!(!wrong_pin.status.success());

    let stale_epoch = Command::new(binary)
        .arg("evaluate")
        .arg("--claim")
        .arg(&claim)
        .arg("--trust-pack")
        .arg(&pack)
        .arg("--expected-checkpoint")
        .arg(&checkpoint)
        .arg("--minimum-epoch")
        .arg("2")
        .output()?;
    assert!(!stale_epoch.status.success());
    let error: Value = serde_json::from_slice(&stale_epoch.stderr)?;
    assert_eq!(error["ok"], false);
    assert!(error["error"]
        .as_str()
        .unwrap_or_default()
        .contains("newer state"));

    Ok(())
}

#[test]
fn stale_lock_file_does_not_block_recovery() -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fixture = fixture_at(now)?;
    let temporary = tempdir()?;
    let candidate = temporary.path().join("candidate.tpack");
    let state_directory = temporary.path().join("state");
    let store = state_directory.join("current.tpack");
    let lock = state_directory.join(".current.tpack.lock");
    fs::create_dir_all(&state_directory)?;
    fs::write(&candidate, &fixture.pack_bytes)?;
    fs::write(&lock, b"stale metadata from a terminated updater")?;

    let checkpoint = hex::encode(fixture.signed_pack.checkpoint()?);
    let output = run(Command::new(env!("CARGO_BIN_EXE_trust-console"))
        .arg("trust-pack")
        .arg("install")
        .arg("--candidate")
        .arg(&candidate)
        .arg("--store")
        .arg(&store)
        .arg("--expected-checkpoint")
        .arg(checkpoint))?;

    let installed: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(installed["ok"], true);
    assert_eq!(installed["operation"], "installed");
    assert!(store.exists());
    Ok(())
}

#[test]
fn console_refuses_store_mutation_while_another_process_holds_lock() -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fixture = fixture_at(now)?;
    let temporary = tempdir()?;
    let candidate = temporary.path().join("candidate.tpack");
    let state_directory = temporary.path().join("state");
    let store = state_directory.join("current.tpack");
    let lock = state_directory.join(".current.tpack.lock");
    fs::create_dir_all(&state_directory)?;
    fs::write(&candidate, &fixture.pack_bytes)?;

    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock)?;
    FileExt::lock_exclusive(&lock_file)?;

    let checkpoint = hex::encode(fixture.signed_pack.checkpoint()?);
    let output = Command::new(env!("CARGO_BIN_EXE_trust-console"))
        .arg("trust-pack")
        .arg("install")
        .arg("--candidate")
        .arg(&candidate)
        .arg("--store")
        .arg(&store)
        .arg("--expected-checkpoint")
        .arg(checkpoint)
        .output()?;

    FileExt::unlock(&lock_file)?;
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["ok"], false);
    assert!(error["error"]
        .as_str()
        .unwrap_or_default()
        .contains("update is already in progress"));
    assert!(!store.exists());
    Ok(())
}

#[test]
fn oversized_host_input_is_rejected_before_decoding() -> Result<(), Box<dyn Error>> {
    let temporary = tempdir()?;
    let pack = temporary.path().join("oversized.tpack");
    fs::write(&pack, vec![0; trust_sdk::MAX_TRUST_PACK_WIRE_BYTES + 1])?;
    let output = Command::new(env!("CARGO_BIN_EXE_trust-console"))
        .args(["evaluate-action-v2", "--trust-pack"])
        .arg(pack)
        .args([
            "--envelope",
            "unused",
            "--host-request",
            "unused",
            "--minimum-epoch",
            "1",
            "--expected-checkpoint",
        ])
        .arg("0".repeat(64))
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("profile byte limit"));
    Ok(())
}

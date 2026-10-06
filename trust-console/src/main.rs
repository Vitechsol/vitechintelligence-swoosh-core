#![forbid(unsafe_code)]

use std::{
    ffi::OsStr,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use fs2::FileExt;
use serde::Serialize;
use tempfile::NamedTempFile;
use trust_sdk::{
    evaluate_claim, Decision, DecisionReason, DecisionReceipt, FreshnessAssurance,
    InstalledTrustContext, SdkError, TrustPackManager, TrustPackMetadata, MAX_ACTION_WIRE_BYTES,
    MAX_CLAIM_WIRE_BYTES, MAX_TRUST_PACK_WIRE_BYTES,
};

#[derive(Debug, Parser)]
#[command(
    name = "trust-console",
    version,
    about = "Reference console for the canonical SWOOSH trust SDK"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Evaluate the additive v2 action profile against a trusted host context and pinned pack.
    EvaluateActionV2 {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long = "trust-pack")]
        trust_pack: PathBuf,
        /// Trusted host JSON; never accept this file path or its identity from model output.
        #[arg(long = "host-request")]
        host_request: PathBuf,
        #[arg(long = "expected-checkpoint")]
        expected_checkpoint: String,
        #[arg(long = "minimum-epoch")]
        minimum_epoch: u64,
    },
    /// Evaluate the additive v3 role-bound action profile against trusted host RBAC context.
    EvaluateActionV3 {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long = "trust-pack")]
        trust_pack: PathBuf,
        /// Trusted host JSON; subject and role must come from authenticated host state, never model output.
        #[arg(long = "host-request")]
        host_request: PathBuf,
        #[arg(long = "expected-checkpoint")]
        expected_checkpoint: String,
        #[arg(long = "minimum-epoch")]
        minimum_epoch: u64,
    },
    /// Evaluate a raw canonical claim against an installed TrustPack.
    Evaluate {
        /// Claim file, or '-' to read the raw claim from standard input.
        #[arg(long)]
        claim: PathBuf,
        /// Signed canonical TrustPack file.
        #[arg(long = "trust-pack")]
        trust_pack: PathBuf,
    },
    /// Install, update, or inspect a local signed TrustPack.
    TrustPack {
        #[command(subcommand)]
        command: TrustPackCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TrustPackCommand {
    /// Bootstrap a local store using an out-of-band pinned checkpoint.
    Install {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        store: PathBuf,
        /// Expected 32-byte SHA-256 checkpoint in hexadecimal.
        #[arg(long = "expected-checkpoint")]
        expected_checkpoint: String,
    },
    /// Atomically replace the store after signature and anti-rollback validation.
    Update {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
    /// Validate and print privacy-minimized TrustPack metadata.
    Inspect {
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Debug)]
enum ConsoleError {
    Io(io::Error),
    Sdk(SdkError),
    InvalidCheckpoint,
    StoreAlreadyExists,
    StoreMissing,
    StoreBusy,
    Json(serde_json::Error),
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O failure: {error}"),
            Self::Sdk(error) => write!(formatter, "trust evaluation failed: {error}"),
            Self::InvalidCheckpoint => {
                formatter.write_str("expected checkpoint must be exactly 64 hexadecimal characters")
            }
            Self::StoreAlreadyExists => {
                formatter.write_str("TrustPack store already exists; use the update command")
            }
            Self::StoreMissing => {
                formatter.write_str("TrustPack store does not exist; use the install command")
            }
            Self::StoreBusy => formatter.write_str(
                "TrustPack store update is already in progress; retry after the current updater exits",
            ),
            Self::Json(error) => write!(formatter, "JSON serialization failed: {error}"),
        }
    }
}

impl std::error::Error for ConsoleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sdk(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::InvalidCheckpoint
            | Self::StoreAlreadyExists
            | Self::StoreMissing
            | Self::StoreBusy => None,
        }
    }
}

impl From<io::Error> for ConsoleError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<SdkError> for ConsoleError {
    fn from(error: SdkError) -> Self {
        Self::Sdk(error)
    }
}

impl From<serde_json::Error> for ConsoleError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

struct StoreLock {
    file: fs::File,
}

impl StoreLock {
    fn acquire(store: &Path) -> Result<Self, ConsoleError> {
        let parent = store.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let file_name = store
            .file_name()
            .unwrap_or_else(|| OsStr::new("trust-pack"))
            .to_string_lossy();
        let path = parent.join(format!(".{file_name}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ConsoleError::StoreBusy
            } else {
                ConsoleError::Io(error)
            }
        })?;
        Ok(Self { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[derive(Serialize)]
struct JsonReceipt<'a> {
    ok: bool,
    receipt_version: u16,
    engine_version: &'a str,
    receipt_id: String,
    claim_fingerprint: String,
    trust_state_fingerprint: String,
    trust_domain: &'a str,
    decision: &'a Decision,
    reason: &'a DecisionReason,
    assurance: &'a FreshnessAssurance,
    evaluated_at: u64,
    valid_until: u64,
    trust_epoch: u64,
    root_generation: u64,
    status_sequence: u64,
    policy_id: &'a str,
    policy_version: u64,
}

#[derive(Serialize)]
struct JsonPackMetadata<'a> {
    ok: bool,
    operation: &'a str,
    pack_id: &'a str,
    trust_domain: &'a str,
    trust_epoch: u64,
    root_generation: u64,
    status_sequence: u64,
    policy_id: &'a str,
    policy_version: u64,
    valid_from: u64,
    valid_until: u64,
    checkpoint: String,
}

#[derive(Serialize)]
struct JsonError<'a> {
    ok: bool,
    error: &'a str,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let error_message = error.to_string();
            let payload = JsonError {
                ok: false,
                error: &error_message,
            };
            match serde_json::to_string_pretty(&payload) {
                Ok(json) => eprintln!("{json}"),
                Err(_) => eprintln!("{{\"ok\":false,\"error\":\"console failure\"}}"),
            }
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<(), ConsoleError> {
    match cli.command {
        Command::EvaluateActionV2 {
            envelope,
            trust_pack,
            host_request,
            expected_checkpoint,
            minimum_epoch,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SdkError::ClockBeforeUnixEpoch)?
                .as_secs();
            let pack = read_limited(&trust_pack, MAX_TRUST_PACK_WIRE_BYTES)?;
            let checkpoint = parse_checkpoint(&expected_checkpoint)?;
            let mut context = InstalledTrustContext::install_at(&pack, &checkpoint, now)?;
            context.note_authoritative_epoch(minimum_epoch);
            let request: trust_sdk::ActionRequestV2 =
                serde_json::from_slice(&read_limited(&host_request, MAX_ACTION_WIRE_BYTES)?)?;
            let bytes = read_limited(&envelope, MAX_ACTION_WIRE_BYTES)?;
            let receipt = context.evaluate_action_at(&bytes, &request, now)?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::EvaluateActionV3 {
            envelope,
            trust_pack,
            host_request,
            expected_checkpoint,
            minimum_epoch,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SdkError::ClockBeforeUnixEpoch)?
                .as_secs();
            let pack = read_limited(&trust_pack, MAX_TRUST_PACK_WIRE_BYTES)?;
            let checkpoint = parse_checkpoint(&expected_checkpoint)?;
            let mut context = InstalledTrustContext::install_at(&pack, &checkpoint, now)?;
            context.note_authoritative_epoch(minimum_epoch);
            let request: trust_sdk::ActionRequestV3 =
                serde_json::from_slice(&read_limited(&host_request, MAX_ACTION_WIRE_BYTES)?)?;
            let bytes = read_limited(&envelope, MAX_ACTION_WIRE_BYTES)?;
            let receipt = context.evaluate_action_v3_at(&bytes, &request, now)?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::Evaluate { claim, trust_pack } => {
            let claim_bytes = read_raw(&claim)?;
            let trust_pack_bytes = read_limited(&trust_pack, MAX_TRUST_PACK_WIRE_BYTES)?;
            let receipt = evaluate_claim(&claim_bytes, &trust_pack_bytes)?;
            print_receipt(&receipt)
        }
        Command::TrustPack { command } => match command {
            TrustPackCommand::Install {
                candidate,
                store,
                expected_checkpoint,
            } => {
                let _lock = StoreLock::acquire(&store)?;
                if store.exists() {
                    return Err(ConsoleError::StoreAlreadyExists);
                }
                let candidate_bytes = read_limited(&candidate, MAX_TRUST_PACK_WIRE_BYTES)?;
                let checkpoint = parse_checkpoint(&expected_checkpoint)?;
                let metadata = TrustPackManager::verify_initial(&candidate_bytes, &checkpoint)?;
                atomic_write(&store, &candidate_bytes)?;
                print_metadata("installed", &metadata)
            }
            TrustPackCommand::Update { candidate, store } => {
                let _lock = StoreLock::acquire(&store)?;
                if !store.exists() {
                    return Err(ConsoleError::StoreMissing);
                }
                let current_bytes = read_limited(&store, MAX_TRUST_PACK_WIRE_BYTES)?;
                let candidate_bytes = read_limited(&candidate, MAX_TRUST_PACK_WIRE_BYTES)?;
                let metadata = TrustPackManager::verify_update(&current_bytes, &candidate_bytes)?;
                atomic_write(&store, &candidate_bytes)?;
                print_metadata("updated", &metadata)
            }
            TrustPackCommand::Inspect { store } => {
                if !store.exists() {
                    return Err(ConsoleError::StoreMissing);
                }
                let bytes = read_limited(&store, MAX_TRUST_PACK_WIRE_BYTES)?;
                let metadata = TrustPackManager::inspect(&bytes)?;
                print_metadata("inspected", &metadata)
            }
        },
    }
}

fn read_raw(path: &Path) -> Result<Vec<u8>, ConsoleError> {
    read_limited(path, MAX_CLAIM_WIRE_BYTES)
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, ConsoleError> {
    let reader: Box<dyn Read> = if path.as_os_str() == OsStr::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    };
    let mut bytes = Vec::new();
    reader.take((limit as u64) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds the profile byte limit",
        )
        .into());
    }
    Ok(bytes)
}

fn parse_checkpoint(value: &str) -> Result<[u8; 32], ConsoleError> {
    let bytes = hex::decode(value).map_err(|_| ConsoleError::InvalidCheckpoint)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ConsoleError::InvalidCheckpoint)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ConsoleError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let persisted = temporary.persist(path).map_err(|error| error.error)?;
    persisted.sync_all()?;

    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;

    Ok(())
}

fn print_receipt(receipt: &DecisionReceipt) -> Result<(), ConsoleError> {
    let payload = JsonReceipt {
        ok: true,
        receipt_version: receipt.receipt_version,
        engine_version: &receipt.engine_version,
        receipt_id: hex::encode(receipt.receipt_id),
        claim_fingerprint: hex::encode(receipt.claim_fingerprint),
        trust_state_fingerprint: hex::encode(receipt.trust_state_fingerprint),
        trust_domain: receipt.trust_domain.as_str(),
        decision: &receipt.decision,
        reason: &receipt.reason,
        assurance: &receipt.assurance,
        evaluated_at: receipt.evaluated_at,
        valid_until: receipt.valid_until,
        trust_epoch: receipt.trust_epoch,
        root_generation: receipt.root_generation,
        status_sequence: receipt.status_sequence,
        policy_id: receipt.policy_id.as_str(),
        policy_version: receipt.policy_version,
    };
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn print_metadata(operation: &str, metadata: &TrustPackMetadata) -> Result<(), ConsoleError> {
    let payload = JsonPackMetadata {
        ok: true,
        operation,
        pack_id: metadata.pack_id.as_str(),
        trust_domain: metadata.trust_domain.as_str(),
        trust_epoch: metadata.trust_epoch,
        root_generation: metadata.root_generation,
        status_sequence: metadata.status_sequence,
        policy_id: metadata.policy_id.as_str(),
        policy_version: metadata.policy_version,
        valid_from: metadata.valid_from,
        valid_until: metadata.valid_until,
        checkpoint: hex::encode(metadata.checkpoint),
    };
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

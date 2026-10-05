#![forbid(unsafe_code)]

use std::process::ExitCode;

use serde::Serialize;

#[derive(Serialize)]
struct ProofPackReport {
    schema_version: u16,
    evaluation_time: u64,
    all_passed: bool,
    drills: Vec<proof_pack::DrillResult>,
}

#[derive(Serialize)]
struct FailureReport<'a> {
    schema_version: u16,
    all_passed: bool,
    error: &'a str,
}

fn main() -> ExitCode {
    match proof_pack::run_all_drills() {
        Ok(drills) => {
            let report = ProofPackReport {
                schema_version: 1,
                evaluation_time: proof_pack::EVALUATION_TIME,
                all_passed: drills.iter().all(|drill| drill.passed),
                drills,
            };
            match serde_json::to_string_pretty(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("proof report serialization failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            let message = error.to_string();
            let report = FailureReport {
                schema_version: 1,
                all_passed: false,
                error: &message,
            };
            match serde_json::to_string_pretty(&report) {
                Ok(json) => eprintln!("{json}"),
                Err(_) => eprintln!("proof pack failed"),
            }
            ExitCode::from(1)
        }
    }
}

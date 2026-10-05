use proof_pack::{
    run_key_rotation_drill, run_offline_drill, run_recovery_drill, run_revocation_drill,
};

#[test]
fn revocation_drill() -> Result<(), proof_pack::ProofError> {
    let result = run_revocation_drill()?;
    assert!(result.passed);
    Ok(())
}

#[test]
fn offline_drill() -> Result<(), proof_pack::ProofError> {
    let result = run_offline_drill()?;
    assert!(result.passed);
    Ok(())
}

#[test]
fn recovery_drill() -> Result<(), proof_pack::ProofError> {
    let result = run_recovery_drill()?;
    assert!(result.passed);
    Ok(())
}

#[test]
fn key_rotation_drill() -> Result<(), proof_pack::ProofError> {
    let result = run_key_rotation_drill()?;
    assert!(result.passed);
    Ok(())
}

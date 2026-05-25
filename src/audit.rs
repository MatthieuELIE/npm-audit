use crate::models::AuditReport;
use anyhow::Context;
use serde_json;
use std::process::Command;

pub fn run() -> anyhow::Result<AuditReport> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .output()
        .context("Failed to execute 'npm audit'. Is npm installed and available in your PATH?")?;
    let report: AuditReport =
        serde_json::from_slice(&output.stdout).context("Failed to parse npm audit JSON output")?;

    Ok(report)
}

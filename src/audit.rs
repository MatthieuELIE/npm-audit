use crate::models::AuditReport;
use anyhow::Context;
use serde_json;
use std::process::Command;

pub fn run() -> anyhow::Result<AuditReport> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .output()
        .context("Failed to execute 'npm audit'. Is npm installed and available in your PATH?")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: AuditReport = serde_json::from_str(&stdout).context("Output isn't a JSON!")?;

    Ok(report)
}

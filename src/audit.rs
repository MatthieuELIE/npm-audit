use crate::models::AuditReport;

use serde_json;
use std::process::Command;

pub fn run() -> Result<AuditReport, Box<dyn std::error::Error>> {
    let output = Command::new("npm").args(["audit", "--json"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: AuditReport = serde_json::from_str(&stdout)?;

    Ok(report)
}

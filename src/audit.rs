use crate::models::AuditReport;
use anyhow::Context;
use std::process::Command;

fn parse_report(stdout: &[u8], stderr: &[u8]) -> anyhow::Result<AuditReport> {
    if stdout.is_empty() {
        anyhow::bail!(
            "npm audit produced no output: {}",
            String::from_utf8_lossy(stderr)
        )
    }

    serde_json::from_slice(stdout).context("Failed to parse npm audit JSON output")
}

pub fn run() -> anyhow::Result<AuditReport> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .output()
        .context("Failed to execute 'npm audit'. Is npm installed and available in your PATH?")?;

    let report: AuditReport = parse_report(&output.stdout, &output.stderr)?;

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_report_is_err() {
        let stdout = b"not json";
        let stderr = b"";

        let result = parse_report(stdout, stderr);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_report_stdout_empty() {
        let stdout = b"";
        let stderr = b"npm error";

        let result = parse_report(stdout, stderr);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("npm error"));
    }
}

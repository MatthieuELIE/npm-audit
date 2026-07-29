use crate::models::{AuditReport, OutdatedEntry};
use anyhow::Context;
use std::{
    collections::HashMap,
    process::{Command, Output},
};

fn parse_report(stdout: &[u8], stderr: &[u8]) -> anyhow::Result<AuditReport> {
    if stdout.is_empty() {
        anyhow::bail!(
            "npm audit produced no output: {}",
            String::from_utf8_lossy(stderr)
        )
    }

    serde_json::from_slice(stdout).with_context(|| {
        format!(
            "Failed to parse npm audit JSON output {}",
            String::from_utf8_lossy(stdout)
        )
    })
}

fn parse_outdated(stdout: &[u8]) -> anyhow::Result<HashMap<String, OutdatedEntry>> {
    if stdout.is_empty() {
        return Ok(HashMap::new());
    }

    serde_json::from_slice(stdout).with_context(|| {
        format!(
            "Failed to parse npm outdated JSON output {}",
            String::from_utf8_lossy(stdout)
        )
    })
}

fn run_npm_audit(program: &str) -> anyhow::Result<std::process::Output> {
    Command::new(program)
        .args(["audit", "--json"])
        .output()
        .context("Failed to execute 'npm audit'. Is npm installed and available in your PATH?")
}

fn run_npm_outdated(program: &str) -> anyhow::Result<Output> {
    Command::new(program)
        .args(["outdated", "--json"])
        .output()
        .context("Failed to execute 'npm outdated'. Is npm installed and available in your PATH?")
}

pub fn run() -> anyhow::Result<AuditReport> {
    let output = run_npm_audit("npm")?;

    parse_report(&output.stdout, &output.stderr)
}

pub fn run_outdated() -> anyhow::Result<HashMap<String, OutdatedEntry>> {
    let output = run_npm_outdated("npm")?;

    parse_outdated(&output.stdout)
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

    #[test]
    fn test_run_npm_audit_missing_binary_errors() {
        let result = run_npm_audit("definitely-not-a-real-binary-xyz");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to execute")
        );
    }

    #[test]
    fn test_parse_outdated_empty_stdout_returns_empty_map() {
        let result = parse_outdated(b"");

        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_outdated_invalid_json_is_err() {
        let result = parse_outdated(b"not json");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_outdated_missing_current_defaults_to_none() {
        let stdout = br#"{"lodash": {"latest": "4.18.1"}}"#;

        let result = parse_outdated(stdout).unwrap();

        assert_eq!(result.get("lodash").unwrap().current, None);
        assert_eq!(result.get("lodash").unwrap().latest, "4.18.1");
    }
}

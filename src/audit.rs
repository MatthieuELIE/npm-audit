use crate::models::{AuditReport, DependencyTree, OutdatedEntry};
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

fn parse_tree(stdout: &[u8]) -> anyhow::Result<DependencyTree> {
    if stdout.is_empty() {
        return Ok(DependencyTree::default());
    }

    serde_json::from_slice(stdout).with_context(|| {
        format!(
            "Failed to parse the dependencies tree {}",
            String::from_utf8_lossy(stdout)
        )
    })
}

fn run_npm(program: &str, args: &[&str]) -> anyhow::Result<Output> {
    Command::new(program).args(args).output().with_context(|| {
        format!(
            "Failed to execute 'npm {}'. Is npm installed and available in your PATH?",
            args[0]
        )
    })
}

pub fn run() -> anyhow::Result<AuditReport> {
    let output = run_npm("npm", &["audit", "--json"])?;

    parse_report(&output.stdout, &output.stderr)
}

pub fn run_outdated() -> anyhow::Result<HashMap<String, OutdatedEntry>> {
    let output = run_npm("npm", &["outdated", "--json"])?;

    parse_outdated(&output.stdout)
}

pub fn run_tree() -> anyhow::Result<DependencyTree, anyhow::Error> {
    let output = run_npm("npm", &["ls", "--all", "--json"])?;

    parse_tree(&output.stdout)
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
    fn test_run_npm_missing_binary_errors() {
        let result = run_npm("definitely-not-a-real-binary-xyz", &["audit", "--json"]);

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

    #[test]
    fn test_parse_tree_empty_stdout_returns_default_tree() {
        let result = parse_tree(b"");

        assert!(result.unwrap().dependencies.is_empty());
    }

    #[test]
    fn test_parse_tree_invalid_json_is_err() {
        let result = parse_tree(b"not json");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tree_nested_example() {
        let stdout = br#"{
            "dependencies": {
                "eslint": {
                    "version": "8.0.0",
                    "dependencies": {
                        "minimatch": {
                            "version": "3.0.0"
                        }
                    }
                }
            }
        }"#;

        let result = parse_tree(stdout).unwrap();

        assert!(result.dependencies.contains_key("eslint"));
        assert!(
            result.dependencies["eslint"]
                .dependencies
                .contains_key("minimatch")
        );
    }
}

use colored::{Color, ColoredString, Colorize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct AuditReport {
    pub vulnerabilities: HashMap<String, Vulnerability>,
    pub metadata: Metadata,
}

impl AuditReport {
    pub fn filtered_vulnerabilities(&self) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .values()
            .filter(|v| matches!(v.severity, Severity::Critical | Severity::High))
            .collect()
    }

    pub fn sorted_vulnerabilities(&self) -> Vec<&Vulnerability> {
        let mut filtered = self.filtered_vulnerabilities();
        filtered.sort_by(|a, b| b.severity.cmp(&a.severity));

        filtered
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub name: String,
    pub severity: Severity,
    pub is_direct: bool,
    pub via: Vec<Via>,
    effects: Vec<String>,
    range: String,
    pub fix_available: FixAvailable,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub vulnerabilities: VulnCount,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Via {
    Advisory(Advisory),
    Reference(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FixAvailable {
    Bool(bool),
    Fix(Fix),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VulnCount {
    pub info: u32,
    pub low: u32,
    pub moderate: u32,
    pub high: u32,
    pub critical: u32,
    pub total: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Advisory {
    source: u64,
    name: String,
    pub title: String,
    pub url: String,
    severity: Severity,
    range: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub name: String,
    pub version: String,
    is_sem_ver_major: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Moderate => "moderate",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn to_colored_string(&self) -> ColoredString {
        let text = self.as_str().to_uppercase().black();

        match self {
            Severity::Critical => text.on_color(Color::Red),
            Severity::High => text.on_color(Color::Yellow),
            _ => text.on_color(Color::White),
        }
    }
}

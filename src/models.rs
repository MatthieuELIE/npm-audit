use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct AuditReport {
    pub vulnerabilities: HashMap<String, Vulnerability>,
    pub metadata: Metadata,
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
}

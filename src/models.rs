use clap::ValueEnum;
use colored::{Color, ColoredString, Colorize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct AuditReport {
    pub vulnerabilities: HashMap<String, Vulnerability>,
    pub metadata: Metadata,
}

impl AuditReport {
    pub fn filtered_vulnerabilities(&self, min_severity: Option<Severity>) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .values()
            .filter(|v| v.severity >= min_severity.unwrap_or(Severity::Info))
            .collect()
    }

    pub fn sorted_vulnerabilities(&self, min_severity: Option<Severity>) -> Vec<&Vulnerability> {
        let mut filtered = self.filtered_vulnerabilities(min_severity);
        filtered.sort_by(|a, b| a.severity.cmp(&b.severity));

        filtered
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub name: String,
    pub severity: Severity,
    pub is_direct: DependencyType,
    pub via: Vec<Via>,
    pub effects: Vec<String>,
    pub range: String,
    pub fix_available: FixAvailable,
}

#[derive(Debug, Deserialize, Serialize, Default)]
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

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct VulnCount {
    pub info: u32,
    pub low: u32,
    pub moderate: u32,
    pub high: u32,
    pub critical: u32,
    pub total: u32,
}

impl<'a> FromIterator<&'a Vulnerability> for VulnCount {
    fn from_iter<T: IntoIterator<Item = &'a Vulnerability>>(iter: T) -> Self {
        let mut accumulator = VulnCount::default();
        for vuln in iter {
            match vuln.severity {
                Severity::Info => accumulator.info += 1,
                Severity::Low => accumulator.low += 1,
                Severity::Moderate => accumulator.moderate += 1,
                Severity::High => accumulator.high += 1,
                Severity::Critical => accumulator.critical += 1,
            }
            accumulator.total += 1;
        }

        accumulator
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Advisory {
    pub title: String,
    pub url: String,
    pub range: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, ValueEnum)]
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
            Severity::High => text.on_color(Color::TrueColor {
                r: 255,
                g: 165,
                b: 0,
            }),
            Severity::Moderate => text.on_color(Color::Yellow),
            Severity::Low => text.on_color(Color::Green),
            Severity::Info => text.on_color(Color::Cyan),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(from = "bool")]
pub enum DependencyType {
    Direct,
    Indirect,
}

impl DependencyType {
    pub fn as_str(&self) -> &str {
        match self {
            DependencyType::Direct => "direct",
            DependencyType::Indirect => "indirect",
        }
    }
}

impl From<bool> for DependencyType {
    fn from(is_direct: bool) -> Self {
        match is_direct {
            true => DependencyType::Direct,
            false => DependencyType::Indirect,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_vuln(name: &str, severity: Severity) -> Vulnerability {
        Vulnerability {
            name: name.to_string(),
            severity,
            is_direct: DependencyType::Direct,
            via: vec![],
            effects: vec![],
            range: "1.0.0".to_string(),
            fix_available: FixAvailable::Bool(false),
        }
    }

    #[test]
    fn test_dependency_type_from_bool() {
        assert_eq!(DependencyType::from(true), DependencyType::Direct);
        assert_eq!(DependencyType::from(false), DependencyType::Indirect);
    }

    #[test]
    fn test_filtered_vulnerabilities() {
        let mut vulns = HashMap::new();
        vulns.insert("v1".to_string(), create_vuln("v1", Severity::Low));
        vulns.insert("v2".to_string(), create_vuln("v2", Severity::High));
        vulns.insert("v3".to_string(), create_vuln("v3", Severity::Critical));

        let report = AuditReport {
            vulnerabilities: vulns,
            metadata: Metadata::default(),
        };

        let result = report.filtered_vulnerabilities(Some(Severity::High));
        assert_eq!(result.len(), 2)
    }
}

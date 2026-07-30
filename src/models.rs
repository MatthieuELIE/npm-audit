use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
        filtered.sort_by_key(|v| v.severity);

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

#[derive(Debug, Deserialize, Serialize)]
pub struct OutdatedEntry {
    pub current: Option<String>,
    pub latest: String,
}

#[derive(Default, Debug, Deserialize)]
pub struct DependencyTree {
    #[serde(default)]
    pub dependencies: HashMap<String, DependencyTree>,
}

impl DependencyTree {
    pub fn collect_chains(&self, names: &HashSet<String>) -> HashMap<String, Vec<Vec<String>>> {
        let mut result = HashMap::new();
        let mut path = Vec::new();
        self.walk(names, &mut path, &mut result);

        result
    }

    fn walk(
        &self,
        names: &HashSet<String>,
        path: &mut Vec<String>,
        result: &mut HashMap<String, Vec<Vec<String>>>,
    ) {
        for (name, child) in &self.dependencies {
            path.push(name.clone());
            if names.contains(name) {
                result.entry(name.clone()).or_default().push(path.clone());
            }

            child.walk(names, path, result);
            path.pop();
        }
    }
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
        if is_direct {
            DependencyType::Direct
        } else {
            DependencyType::Indirect
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf() -> DependencyTree {
        DependencyTree::default()
    }

    #[test]
    fn test_collect_chains_single_chain() {
        let tree = DependencyTree {
            dependencies: HashMap::from([(
                "a".to_string(),
                DependencyTree {
                    dependencies: HashMap::from([(
                        "b".to_string(),
                        DependencyTree {
                            dependencies: HashMap::from([("target".to_string(), leaf())]),
                        },
                    )]),
                },
            )]),
        };

        let names = HashSet::from(["target".to_string()]);
        let result = tree.collect_chains(&names);

        assert_eq!(
            result.get("target").unwrap(),
            &vec![vec!["a".to_string(), "b".to_string(), "target".to_string()]]
        );
    }

    #[test]
    fn test_collect_chains_diamond_returns_all_paths() {
        let tree = DependencyTree {
            dependencies: HashMap::from([(
                "a".to_string(),
                DependencyTree {
                    dependencies: HashMap::from([
                        (
                            "b".to_string(),
                            DependencyTree {
                                dependencies: HashMap::from([("target".to_string(), leaf())]),
                            },
                        ),
                        (
                            "c".to_string(),
                            DependencyTree {
                                dependencies: HashMap::from([("target".to_string(), leaf())]),
                            },
                        ),
                    ]),
                },
            )]),
        };

        let names = HashSet::from(["target".to_string()]);
        let mut result = tree.collect_chains(&names).remove("target").unwrap();
        result.sort();

        let mut expected = vec![
            vec!["a".to_string(), "b".to_string(), "target".to_string()],
            vec!["a".to_string(), "c".to_string(), "target".to_string()],
        ];
        expected.sort();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_collect_chains_absent_name_returns_no_entry() {
        let tree = DependencyTree {
            dependencies: HashMap::from([("a".to_string(), leaf())]),
        };

        let names = HashSet::from(["missing".to_string()]);
        let result = tree.collect_chains(&names);

        assert!(!result.contains_key("missing"));
    }

    fn create_vuln(name: &str, severity: Severity) -> Vulnerability {
        Vulnerability {
            name: name.to_string(),
            severity,
            is_direct: DependencyType::Direct,
            via: vec![],
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

    #[test]
    fn test_vuln_count_from_iter() {
        let vulns = [
            create_vuln("v1", Severity::Low),
            create_vuln("v2", Severity::Moderate),
            create_vuln("v3", Severity::Moderate),
        ];

        let count: VulnCount = vulns.iter().collect();
        assert_eq!(count.low, 1);
        assert_eq!(count.moderate, 2);
        assert_eq!(count.total, 3);
    }
}

use std::collections::HashMap;

use crate::models::{FixAvailable, OutdatedEntry, Severity, Via, VulnCount, Vulnerability};
use colored::{Color, ColoredString, Colorize};

fn format_severity(severity: Severity) -> ColoredString {
    let text = severity.as_str().to_uppercase().black();

    match severity {
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

pub fn format_fix(fix: &FixAvailable) -> String {
    match fix {
        FixAvailable::Bool(true) => "npm audit fix".to_string(),
        FixAvailable::Bool(false) => "no fix available".to_string(),
        FixAvailable::Fix(f) => format!("npm install {}@{} (major bump)", f.name, f.version),
    }
}

fn format_outdated(outdated: &OutdatedEntry) -> String {
    format!(
        "installed: {}, latest: {}",
        outdated.current.as_deref().unwrap_or("unknown"),
        outdated.latest
    )
}

fn format_chain(chain: &[String]) -> String {
    chain.join(" → ")
}

fn format_fix_line(fix: &FixAvailable) -> ColoredString {
    let text = format!("Fix: {}", format_fix(fix)).bold();
    match fix {
        FixAvailable::Bool(false) => text.red(),
        _ => text.green(),
    }
}

pub fn format_vulnerability_header(vuln: &Vulnerability) -> String {
    format!(
        "[{}] {} ({}) [{}]",
        format_severity(vuln.severity),
        vuln.name.as_str().bold(),
        vuln.range.dimmed(),
        vuln.is_direct.as_str().cyan(),
    )
}

pub fn print_vulnerability(
    vuln: &Vulnerability,
    outdated: &HashMap<String, OutdatedEntry>,
    chains: &HashMap<String, Vec<Vec<String>>>,
) {
    println!("{}", format_vulnerability_header(vuln));
    println!("{}", format_fix_line(&vuln.fix_available));

    for via in &vuln.via {
        match via {
            Via::Advisory(a) => {
                println!(
                    "{}",
                    format!("  Advisory: {} ({})", a.title, a.range).dimmed()
                );
                println!("{}", format!("    {}", a.url).dimmed());
            }
            Via::Reference(r) => {
                println!("{}", format!("  Via: {}", r).dimmed());
            }
        }
    }

    if let Some(entry) = outdated.get(&vuln.name) {
        println!(
            "{}",
            format!("  Outdated: {}", format_outdated(entry)).dimmed()
        );
    }

    if let Some(paths) = chains.get(&vuln.name) {
        let multi_hop: Vec<&Vec<String>> = paths.iter().filter(|p| p.len() > 1).collect();
        match multi_hop.as_slice() {
            [] => {}
            [single] => println!("{}", format!("  Path: {}", format_chain(single)).dimmed()),
            multiple => {
                println!("{}", "  Paths:".dimmed());
                for path in multiple {
                    println!("{}", format!("    - {}", format_chain(path)).dimmed());
                }
            }
        }
    }

    println!();
}

pub fn format_summary(counts: &VulnCount, total: Option<u32>) -> String {
    let summary = [
        ("🔴", "Critical", counts.critical),
        ("🟠", "High", counts.high),
        ("🟡", "Moderate", counts.moderate),
        ("🟢", "Low", counts.low),
    ]
    .iter()
    .filter(|(_emoji, _text, count)| *count > 0)
    .map(|(emoji, text, count)| format!("{} {} {}", emoji, count, text))
    .collect::<Vec<String>>()
    .join(", ");

    let total_text = total
        .map(|n| format!(" out of {n} total"))
        .unwrap_or_default();

    format!(
        "Found {}, (Total: {}{})!\n",
        summary, counts.total, total_text
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DependencyType, Severity};

    #[test]
    fn test_format_summary_filters_zero_severities_and_total_text() {
        let counts = VulnCount {
            critical: 1,
            low: 2,
            total: 3,
            ..Default::default()
        };

        let result = format_summary(&counts, Some(3));
        let result_without_total_text = format_summary(&counts, None);

        assert!(result.contains("Critical"));
        assert!(!result.contains("High"));
        assert!(result.contains("3"));
        assert!(!result_without_total_text.contains("out of"));
    }

    #[test]
    fn test_format_vulnerability_header() {
        let vuln = Vulnerability {
            name: "lodash".to_string(),
            severity: Severity::Critical,
            is_direct: DependencyType::Direct,
            via: vec![],
            range: ">= 4.0.0".to_string(),
            fix_available: FixAvailable::Bool(true),
        };

        let result = format_vulnerability_header(&vuln);

        assert!(result.contains("lodash"));
        assert!(result.contains("CRITICAL"));
        assert!(result.contains(">= 4.0.0"));
        assert!(result.contains("direct"));
    }

    #[test]
    fn test_format_outdated_with_current() {
        let entry = OutdatedEntry {
            current: Some("4.0.0".to_string()),
            latest: "4.18.1".to_string(),
        };

        let result = format_outdated(&entry);

        assert!(result.contains("4.0.0"));
        assert!(result.contains("4.18.1"));
    }

    #[test]
    fn test_format_outdated_missing_current_shows_unknown() {
        let entry = OutdatedEntry {
            current: None,
            latest: "4.18.1".to_string(),
        };

        let result = format_outdated(&entry);

        assert!(result.contains("unknown"));
        assert!(result.contains("4.18.1"));
    }

    #[test]
    fn test_format_chain() {
        let entry = ["1".to_string(), "2".to_string()];

        let result = format_chain(&entry);

        assert!(result.contains("1 → 2"));
    }
}

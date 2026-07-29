use crate::models::{FixAvailable, Via, VulnCount, Vulnerability};
use colored::Colorize;

pub fn format_fix(fix: &FixAvailable) -> String {
    match fix {
        FixAvailable::Bool(true) => "npm audit fix".to_string(),
        FixAvailable::Bool(false) => "no fix available".to_string(),
        FixAvailable::Fix(f) => format!("npm install {}@{} (major bump)", f.name, f.version),
    }
}

pub fn format_vulnerability_header(vuln: &Vulnerability) -> String {
    format!(
        "[{}] {} ({}) [{}]",
        vuln.severity.to_colored_string(),
        vuln.name.as_str().bold(),
        vuln.range.dimmed(),
        vuln.is_direct.as_str().cyan(),
    )
}

pub fn print_vulnerability(vuln: &Vulnerability) {
    println!("{}", format_vulnerability_header(vuln));

    for via in &vuln.via {
        match via {
            Via::Advisory(a) => {
                println!(" ├─ • {} ({})", a.title, a.range.dimmed());
                println!(" │  └─   {}", a.url);
            }
            Via::Reference(r) => {
                println!(" ├─ • via {}", r);
            }
        }
    }

    println!(" └─ → {}", format_fix(&vuln.fix_available));
    println!();
}

pub fn print_summary(counts: &VulnCount, total: Option<u32>) {
    let total_text = total
        .map(|n| format!(" out of {n} total"))
        .unwrap_or_default();

    let severities = [
        ("🔴", "Critical", counts.critical),
        ("🟠", "High", counts.high),
        ("🟡", "Moderate", counts.moderate),
        ("🟢", "Low", counts.low),
    ];

    let result = severities
        .iter()
        .filter(|(_emoji, _text, count)| *count > 0)
        .map(|(emoji, text, count)| format!("{} {} {}", emoji, count, text))
        .collect::<Vec<String>>()
        .join(", ");

    println!(
        "Found {}, (Total: {}{})!\n",
        result, counts.total, total_text
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DependencyType, Severity};

    #[test]
    fn test_format_vulnerability_header() {
        let vuln = Vulnerability {
            name: "lodash".to_string(),
            severity: Severity::Critical,
            is_direct: DependencyType::Direct,
            via: vec![],
            effects: vec![],
            range: ">= 4.0.0".to_string(),
            fix_available: FixAvailable::Bool(true),
        };

        let result = format_vulnerability_header(&vuln);

        assert!(result.contains("lodash"));
        assert!(result.contains("CRITICAL"));
        assert!(result.contains(">= 4.0.0"));
        assert!(result.contains("direct"));
    }
}

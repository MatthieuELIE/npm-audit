mod audit;
mod display;
mod models;

use crate::{
    display::{print_vulnerability, severity_order},
    models::{AuditReport, Vulnerability},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report: AuditReport = audit::run()?;

    let mut filtered: Vec<&Vulnerability> = report
        .vulnerabilities
        .values()
        .filter(|v| matches!(v.severity.to_lowercase().as_str(), "high" | "critical"))
        .collect();

    let meta = &report.metadata.vulnerabilities;
    println!(
        "found {} high, {} critical (total: {})\n",
        meta.high, meta.critical, meta.total
    );

    filtered.sort_by_key(|v| severity_order(&v.severity));
    for vuln in filtered {
        print_vulnerability(vuln);
    }

    Ok(())
}

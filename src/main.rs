mod audit;
mod display;
mod models;

use crate::{
    display::print_vulnerability,
    models::{AuditReport, Severity, Vulnerability},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report: AuditReport = audit::run()?;

    let mut filtered: Vec<&Vulnerability> = report
        .vulnerabilities
        .values()
        .filter(|v| matches!(v.severity, Severity::Critical | Severity::High))
        .collect();

    let meta = &report.metadata.vulnerabilities;
    println!(
        "found {} high, {} critical (total: {})\n",
        meta.high, meta.critical, meta.total
    );

    filtered.sort_by(|a, b| b.severity.cmp(&a.severity));
    for vuln in filtered {
        print_vulnerability(vuln);
    }

    Ok(())
}

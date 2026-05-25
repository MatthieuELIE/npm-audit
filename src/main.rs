mod audit;
mod display;
mod models;

use crate::{display::print_vulnerability, models::AuditReport};

fn main() -> anyhow::Result<()> {
    let report: AuditReport = audit::run()?;

    let meta = &report.metadata.vulnerabilities;
    println!(
        "found {} high, {} critical (total: {})\n",
        meta.high, meta.critical, meta.total
    );

    let vulnerabilities = report.sorted_vulnerabilities();
    for vuln in vulnerabilities {
        print_vulnerability(vuln);
    }

    Ok(())
}

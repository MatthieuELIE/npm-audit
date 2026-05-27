mod audit;
mod display;
mod models;

use crate::{
    display::{print_summary, print_vulnerability},
    models::AuditReport,
};

fn main() -> anyhow::Result<()> {
    let report: AuditReport = audit::run()?;

    let vulnerabilities = report.sorted_vulnerabilities();
    if vulnerabilities.is_empty() {
        println!("No vulnerabilities found!")
    } else {
        for vuln in vulnerabilities {
            print_vulnerability(vuln);
        }

        print_summary(&report.metadata);
    }

    Ok(())
}

mod args;
mod audit;
mod display;
mod models;

use crate::{
    args::Args,
    display::{print_summary, print_vulnerability},
    models::{AuditReport, VulnCount},
};
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report: AuditReport = audit::run()?;

    let vulnerabilities = report.sorted_vulnerabilities(args.severity);
    let counts: VulnCount = vulnerabilities.iter().copied().collect();
    let total = args.severity.map(|_| report.metadata.vulnerabilities.total);

    if vulnerabilities.is_empty() {
        println!("No vulnerabilities found!")
    } else {
        for vuln in vulnerabilities {
            print_vulnerability(vuln);
        }

        print_summary(&counts, total);
    }

    Ok(())
}

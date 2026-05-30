mod args;
mod audit;
mod display;
mod models;
use crate::{
    args::Args,
    display::{print_summary, print_vulnerability},
    models::AuditReport,
};
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let report: AuditReport = audit::run()?;
    let args = Args::parse();

    let vulnerabilities = report.sorted_vulnerabilities(args.severity);
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

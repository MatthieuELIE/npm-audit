mod args;
mod audit;
mod display;
mod models;

use crate::{
    args::Args,
    display::{format_summary, print_vulnerability},
};
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report = audit::run()?;
    let outdated = audit::run_outdated().unwrap_or_default();

    let vulnerabilities = report.sorted_vulnerabilities(args.severity);
    let counts = vulnerabilities.iter().copied().collect();
    let total = args.severity.map(|_| report.metadata.vulnerabilities.total);

    if vulnerabilities.is_empty() {
        println!("No vulnerabilities found!")
    } else {
        for vuln in vulnerabilities {
            print_vulnerability(vuln, &outdated);
        }

        println!("{}", format_summary(&counts, total));
    }

    Ok(())
}

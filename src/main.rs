mod args;
mod audit;
mod display;
mod models;

use crate::{
    args::Args,
    display::{format_summary, print_vulnerability},
    models::{DependencyTree, OutdatedEntry},
};
use clap::Parser;
use std::collections::{HashMap, HashSet};

fn resolve_outdated(
    result: anyhow::Result<HashMap<String, OutdatedEntry>>,
) -> HashMap<String, OutdatedEntry> {
    result.unwrap_or_else(|e| {
        eprintln!("Warning: failed to fetch outdated info: {e:#}");
        HashMap::new()
    })
}

fn resolve_tree(result: anyhow::Result<DependencyTree>) -> DependencyTree {
    result.unwrap_or_else(|e| {
        eprintln!("Warning: failed to fetch dependency tree: {e:#}");
        DependencyTree::default()
    })
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report = audit::run()?;

    let outdated = resolve_outdated(audit::run_outdated());
    let tree = resolve_tree(audit::run_tree());

    let vulnerabilities = report.sorted_vulnerabilities(args.severity);
    let counts = vulnerabilities.iter().copied().collect();
    let total = args.severity.map(|_| report.metadata.vulnerabilities.total);
    let names: HashSet<String> = vulnerabilities.iter().map(|v| v.name.clone()).collect();
    let chains = tree.collect_chains(&names);

    if vulnerabilities.is_empty() {
        println!("No vulnerabilities found!")
    } else {
        for vuln in vulnerabilities {
            print_vulnerability(vuln, &outdated, &chains);
        }

        println!("{}", format_summary(&counts, total));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_outdated_ok_passes_through() {
        let mut map = HashMap::new();
        map.insert(
            "lodash".to_string(),
            OutdatedEntry {
                current: Some("4.0.0".to_string()),
                latest: "4.18.1".to_string(),
            },
        );

        let result = resolve_outdated(Ok(map));

        assert_eq!(result.len(), 1);
        assert_eq!(result.get("lodash").unwrap().latest, "4.18.1");
    }

    #[test]
    fn test_resolve_outdated_err_returns_empty_map() {
        let result = resolve_outdated(Err(anyhow::anyhow!("npm outdated failed")));

        assert!(result.is_empty());
    }

    #[test]
    fn test_resolve_tree_ok_passes_through() {
        let tree = DependencyTree {
            dependencies: HashMap::from([("lodash".to_string(), DependencyTree::default())]),
        };

        let result = resolve_tree(Ok(tree));

        assert!(result.dependencies.contains_key("lodash"));
    }

    #[test]
    fn test_resolve_tree_err_returns_default_tree() {
        let result = resolve_tree(Err(anyhow::anyhow!("npm ls failed")));

        assert!(result.dependencies.is_empty());
    }
}

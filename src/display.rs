use crate::models::{FixAvailable, Via, Vulnerability};
use colored::Colorize;

pub fn format_fix(fix: &FixAvailable) -> String {
    match fix {
        FixAvailable::Bool(true) => "npm audit fix".to_string(),
        FixAvailable::Bool(false) => "no fix available".to_string(),
        FixAvailable::Fix(f) => format!("npm install {}@{} (major bump)", f.name, f.version),
    }
}

pub fn print_vulnerability(vuln: &Vulnerability) {
    println!(
        "[{}] {} ({})",
        vuln.severity.to_colored_string(),
        vuln.name.as_str().bold(),
        vuln.is_direct.as_str()
    );

    for via in &vuln.via {
        match via {
            Via::Advisory(a) => {
                println!("  • {}", a.title);
                println!("    {}", a.url);
            }
            Via::Reference(r) => {
                println!("  • via {}", r);
            }
        }
    }

    println!("  → {}", format_fix(&vuln.fix_available));
    println!();
}

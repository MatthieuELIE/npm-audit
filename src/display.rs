use crate::models::{FixAvailable, Via, Vulnerability};

pub fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "moderate" => 2,
        "low" => 3,
        _ => 4,
    }
}

pub fn format_fix(fix: &FixAvailable) -> String {
    match fix {
        FixAvailable::Bool(true) => "npm audit fix".to_string(),
        FixAvailable::Bool(false) => "no fix available".to_string(),
        FixAvailable::Fix(f) => format!("npm install {}@{} (major bump)", f.name, f.version),
    }
}

pub fn print_vulnerability(vuln: &Vulnerability) {
    let direct = if vuln.is_direct {
        "direct"
    } else {
        "transitive"
    };

    println!(
        "[{}] {} ({})",
        vuln.severity.to_uppercase(),
        vuln.name,
        direct
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

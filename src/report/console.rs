use crate::findings::{Finding, Severity, TrustSource};
use crate::scanner::ScanStats;
use colored::Colorize;

fn sev_colored(sev: Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => sev.as_str().bright_red().bold(),
        Severity::High => sev.as_str().red().bold(),
        Severity::Medium => sev.as_str().yellow().bold(),
        Severity::Low => sev.as_str().cyan(),
        Severity::Info => sev.as_str().white(),
    }
}

pub fn print(findings: &[Finding], stats: &ScanStats, baseline_suppressed: usize) {
    println!();
    println!("{}", "  javscan — Java SAST".bold());
    println!("{}", "  ─────────────────────────────────────────────".dimmed());

    if findings.is_empty() {
        println!("  {}", "No security issues found.".green().bold());
    }

    let mut current_file = "";
    for f in findings {
        if f.file != current_file {
            current_file = &f.file;
            println!();
            println!("  {}", current_file.underline().bold());
        }
        let source = match f.source {
            TrustSource::Unknown => String::new(),
            s => format!(", source {}", s.as_str()),
        };
        println!(
            "  {}:{}  {}  {} [{}] {}",
            f.line.to_string().dimmed(),
            f.column.to_string().dimmed(),
            sev_colored(f.severity),
            f.rule_id.bold(),
            f.rule_name,
            format!("({} confidence, {}{})", f.confidence.as_str(), f.cwe, source).dimmed(),
        );
        println!("      {}", f.message);
        println!("      {}", format!("> {}", f.snippet).dimmed());
    }

    println!();
    println!("{}", "  ─────────────────────────────────────────────".dimmed());
    let c = super::count_by_severity(findings);
    println!(
        "  {} finding(s): {} critical, {} high, {} medium, {} low, {} info",
        findings.len().to_string().bold(),
        c.critical.to_string().bright_red(),
        c.high.to_string().red(),
        c.medium.to_string().yellow(),
        c.low.to_string().cyan(),
        c.info,
    );
    let mut extras = vec![format!(
        "{} files, {} lines in {} ms",
        stats.files_scanned, stats.lines_scanned, stats.duration_ms
    )];
    if stats.suppressed > 0 {
        extras.push(format!("{} inline-suppressed", stats.suppressed));
    }
    if baseline_suppressed > 0 {
        extras.push(format!("{} baseline-suppressed", baseline_suppressed));
    }
    if stats.parse_failures > 0 {
        extras.push(format!("{} files failed to parse", stats.parse_failures));
    }
    println!("  {}", extras.join(" · ").dimmed());
    println!();
}

pub fn print_rules() {
    println!("{}", "Available rules:".bold());
    for rule in crate::rules::all_rules() {
        println!(
            "  {}  {:<28} {:<9} {:<9} {}",
            rule.meta.id.bold(),
            rule.meta.name,
            rule.meta.severity.as_str(),
            rule.meta.cwe,
            rule.meta.description.dimmed()
        );
    }
}

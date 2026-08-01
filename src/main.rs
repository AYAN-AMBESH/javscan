use clap::{Parser, ValueEnum};
use colored::Colorize;
use javscan::findings::Severity;
use javscan::{baseline, config, report, scanner};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Console,
    Json,
    Sarif,
    Html,
}

#[derive(Parser)]
#[command(
    name = "javscan",
    version,
    about = "Advanced Java SAST: AST-based vulnerability scanning with taint analysis",
    after_help = "EXAMPLES:\n  javscan src/\n  javscan . --format sarif --output results.sarif\n  javscan . --format html --output report.html\n  javscan . --min-severity high --fail-on high\n  javscan . --write-baseline .javscan-baseline.json\n  javscan . --baseline .javscan-baseline.json\n\nSUPPRESSION:\n  // nosec                      suppress all findings on the line\n  // javscan:ignore JS101       suppress specific rules\n\nCONFIG:\n  .javscan.json in the project root: {\"exclude\": [...], \"disabled_rules\": [...],\n  \"min_severity\": \"low\", \"include_tests\": false, \"fail_on\": \"high\"}"
)]
struct Cli {
    /// Files or directories to scan
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "console")]
    format: Format,

    /// Write the report to a file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Minimum severity to report (info|low|medium|high|critical)
    #[arg(long)]
    min_severity: Option<String>,

    /// Exit with code 1 if a finding at or above this severity exists
    /// (info|low|medium|high|critical|never) [default: high]
    #[arg(long)]
    fail_on: Option<String>,

    /// Glob patterns to exclude (repeatable), e.g. --exclude "**/generated/**"
    #[arg(long)]
    exclude: Vec<String>,

    /// Disable specific rules by ID or name (repeatable)
    #[arg(long)]
    disable: Vec<String>,

    /// Also scan test sources (src/test, *Test.java) — skipped by default
    #[arg(long)]
    include_tests: bool,

    /// Disable parallel scanning
    #[arg(long)]
    no_parallel: bool,

    /// Suppress findings recorded in this baseline file
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Write current findings to a baseline file and exit
    #[arg(long)]
    write_baseline: Option<PathBuf>,

    /// List all rules and exit
    #[arg(long)]
    rules: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    if cli.rules {
        report::console::print_rules();
        return ExitCode::SUCCESS;
    }

    let root = cli.paths.first().cloned().unwrap_or_else(|| PathBuf::from("."));
    let (config, config_path) = config::Config::load(&root);
    if let Some(p) = &config_path {
        eprintln!("{}", format!("using config {}", p.display()).dimmed());
    }

    let mut exclude = config.exclude.clone();
    exclude.extend(cli.exclude.clone());
    let mut disabled = config.disabled_rules.clone();
    disabled.extend(cli.disable.clone());

    let opts = scanner::ScanOptions {
        paths: cli.paths.clone(),
        exclude,
        include_tests: cli.include_tests || config.include_tests,
        parallel: !cli.no_parallel,
        disabled_rules: disabled,
    };

    let (mut findings, stats) = scanner::scan(&opts, &config);

    // severity filter: CLI overrides config
    let min_sev = cli
        .min_severity
        .as_deref()
        .and_then(Severity::parse)
        .or_else(|| config.min_severity());
    if let Some(min) = min_sev {
        findings.retain(|f| f.severity >= min);
    }

    if let Some(path) = &cli.write_baseline {
        if let Err(e) = baseline::write(path, &findings) {
            eprintln!("error: failed to write baseline: {e}");
            return ExitCode::from(2);
        }
        println!(
            "Baseline with {} finding(s) written to {}",
            findings.len(),
            path.display()
        );
        return ExitCode::SUCCESS;
    }

    let mut baseline_suppressed = 0;
    if let Some(path) = &cli.baseline {
        match baseline::apply(path, findings) {
            Ok((kept, suppressed)) => {
                findings = kept;
                baseline_suppressed = suppressed;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let rendered = match cli.format {
        Format::Console => {
            report::console::print(&findings, &stats, baseline_suppressed);
            None
        }
        Format::Json => Some(report::json::render(&findings, &stats)),
        Format::Sarif => Some(report::sarif::render(&findings)),
        Format::Html => Some(report::html::render(&findings, &stats)),
    };

    if let Some(content) = rendered {
        match &cli.output {
            Some(path) => {
                if let Err(e) = std::fs::write(path, &content) {
                    eprintln!("error: failed to write {}: {e}", path.display());
                    return ExitCode::from(2);
                }
                eprintln!("Report written to {}", path.display());
            }
            None => println!("{content}"),
        }
    } else if let Some(path) = &cli.output {
        // console format with -o writes a plain-text-ish JSON fallback
        let _ = std::fs::write(path, report::json::render(&findings, &stats));
        eprintln!("Report written to {}", path.display());
    }

    // exit code policy
    let fail_on_str = cli
        .fail_on
        .clone()
        .or_else(|| config.fail_on().map(|s| s.as_str().to_string()));
    let threshold = match fail_on_str.as_deref() {
        Some("never") | Some("none") => None,
        Some(s) => Severity::parse(s).or(Some(Severity::High)),
        None => Some(Severity::High),
    };
    if let Some(t) = threshold {
        if findings.iter().any(|f| f.severity >= t) {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

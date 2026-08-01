//! File discovery and parallel scan orchestration.

use crate::config::Config;
use crate::findings::Finding;
use crate::parser::{AstIndex, ParsedFile};
use crate::project::ProjectContext;
use crate::rules::{all_rules, RuleCtx, RuleDef};
use crate::suppress;
use crate::taint::TaintEngine;
use crate::types::TypeIndex;
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

pub struct ScanOptions {
    pub paths: Vec<PathBuf>,
    pub exclude: Vec<String>,
    pub include_tests: bool,
    pub parallel: bool,
    pub disabled_rules: Vec<String>,
}

pub struct ScanStats {
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub parse_failures: usize,
    pub suppressed: usize,
    pub duration_ms: u128,
}

const SKIP_DIRS: &[&str] = &[
    "target", "build", "out", "bin", ".git", ".gradle", ".idea", ".mvn",
    "node_modules", "generated", "generated-sources",
];

fn is_test_path(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    // `/tests/` covers layouts that predate the Maven convention, e.g.
    // OpenRefine's `extensions/<name>/tests/src/...`.
    if p.contains("/src/test/")
        || p.contains("/test/java/")
        || p.contains("/androidTest/")
        || p.contains("/tests/")
        || p.contains("/test/")
        || p.contains("/src/it/")
    {
        return true;
    }
    let stem = path.file_stem().map(|s| s.to_string_lossy()).unwrap_or_default();
    stem.ends_with("Test") || stem.ends_with("Tests") || stem.ends_with("IT") || stem.starts_with("Test")
}

fn build_globset(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        // make bare patterns match anywhere in the tree
        let pat = if p.contains('/') || p.contains('\\') {
            p.clone()
        } else {
            format!("**/{p}")
        };
        match Glob::new(&pat.replace('\\', "/")) {
            Ok(g) => {
                builder.add(g);
            }
            Err(e) => eprintln!("warning: invalid exclude glob `{p}`: {e}"),
        }
    }
    builder.build().ok()
}

pub fn discover_files(opts: &ScanOptions) -> Vec<PathBuf> {
    let excludes = build_globset(&opts.exclude);
    let mut files = Vec::new();
    for root in &opts.paths {
        if root.is_file() {
            if root.extension().map(|e| e == "java").unwrap_or(false) {
                files.push(root.clone());
            }
            continue;
        }
        let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
            !(e.file_type().is_dir()
                && SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
        });
        for entry in walker.flatten() {
            let path = entry.path();
            if !entry.file_type().is_file()
                || path.extension().map(|e| e != "java").unwrap_or(true)
            {
                continue;
            }
            if !opts.include_tests && is_test_path(path) {
                continue;
            }
            if let Some(gs) = &excludes {
                let norm = path.to_string_lossy().replace('\\', "/");
                if gs.is_match(norm.as_str()) {
                    continue;
                }
            }
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    files.dedup();
    files
}

fn active_rules(disabled: &[String]) -> Vec<RuleDef> {
    all_rules()
        .into_iter()
        .filter(|r| {
            !disabled.iter().any(|d| {
                d.eq_ignore_ascii_case(r.meta.id) || d.eq_ignore_ascii_case(r.meta.name)
            })
        })
        .collect()
}

fn scan_one(
    path: &Path,
    rules: &[RuleDef],
    project: &ProjectContext,
    suppressed_counter: &AtomicUsize,
) -> (Vec<Finding>, usize, bool) {
    let Ok(source) = std::fs::read_to_string(path) else {
        return (Vec::new(), 0, true);
    };
    let lines = source.lines().count();
    let display = path.to_string_lossy().replace('\\', "/");
    let Some(parsed) = ParsedFile::parse(display, source) else {
        return (Vec::new(), lines, true);
    };
    let index = AstIndex::build(&parsed);
    let taint = TaintEngine::new(&parsed);
    let types = TypeIndex::build(&parsed, &index);
    let suppressions = suppress::collect(&parsed, &index);
    let ctx = RuleCtx {
        file: &parsed,
        index: &index,
        taint: &taint,
        types: &types,
        project,
    };
    let mut findings = Vec::new();
    for rule in rules {
        for f in (rule.check)(&ctx, &rule.meta) {
            if suppress::is_suppressed(&suppressions, f.line, &f.rule_id) {
                suppressed_counter.fetch_add(1, Ordering::Relaxed);
            } else {
                findings.push(f);
            }
        }
    }
    (findings, lines, false)
}

pub fn scan(opts: &ScanOptions, _config: &Config) -> (Vec<Finding>, ScanStats) {
    let start = std::time::Instant::now();
    let files = discover_files(opts);
    let rules = active_rules(&opts.disabled_rules);
    let project = ProjectContext::discover(&opts.paths);
    let suppressed = AtomicUsize::new(0);

    let results: Vec<(Vec<Finding>, usize, bool)> = if opts.parallel {
        files
            .par_iter()
            .map(|f| scan_one(f, &rules, &project, &suppressed))
            .collect()
    } else {
        files
            .iter()
            .map(|f| scan_one(f, &rules, &project, &suppressed))
            .collect()
    };

    let mut findings = Vec::new();
    let mut lines_total = 0;
    let mut failures = 0;
    for (fs, lines, failed) in results {
        findings.extend(fs);
        lines_total += lines;
        if failed {
            failures += 1;
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    // Two detection paths in one rule can hit the same line (e.g. a secret
    // matched by both name and token pattern); keep the highest-severity one.
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.rule_id.clone(), f.file.clone(), f.line)));
    let stats = ScanStats {
        files_scanned: files.len(),
        lines_scanned: lines_total,
        parse_failures: failures,
        suppressed: suppressed.load(Ordering::Relaxed),
        duration_ms: start.elapsed().as_millis(),
    };
    (findings, stats)
}

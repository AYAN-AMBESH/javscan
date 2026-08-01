//! Project-level context shared by every file in a scan.
//!
//! Some rules are only correct when they know which version of a library is
//! actually on the classpath — SnakeYAML < 2.0 accepts global type tags by
//! default while >= 2.0 rejects them, so the same `.load()` call is a finding
//! in one project and a non-issue in the next.
//!
//! This reads declared versions out of build files near the scan roots. It is
//! a heuristic, not a dependency resolver: it will not see versions that come
//! from a parent POM, a BOM, or a version catalog variable. Rules therefore
//! use it only to *relax* severity, never to raise it, so a missed version
//! degrades to the previous (stricter) behaviour.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use regex::Regex;
use std::sync::OnceLock;

/// Artifacts whose version changes a rule's verdict.
const TRACKED: &[&str] = &["snakeyaml", "jackson-databind", "xstream", "commons-collections"];

const BUILD_FILES: &[&str] = &[
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "libs.versions.toml",
    "dependencies.gradle",
];

#[derive(Debug, Default)]
pub struct ProjectContext {
    /// artifact id -> (major, minor) of the highest declared version found.
    versions: HashMap<String, (u32, u32)>,
}

fn version_re(artifact: &str) -> Regex {
    // `snakeyaml` followed (within a short window, across at most a couple of
    // lines of XML/Groovy/TOML noise) by a dotted version.
    Regex::new(&format!(
        r"(?is){}\b.{{0,120}}?(\d+)\.(\d+)(?:\.\d+)?",
        regex::escape(artifact)
    ))
    .unwrap()
}

fn tracked_res() -> &'static [(&'static str, Regex)] {
    static RES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    RES.get_or_init(|| TRACKED.iter().map(|a| (*a, version_re(a))).collect())
}

impl ProjectContext {
    /// Search each scan root (and up to `MAX_DEPTH` levels below it) for build
    /// files and extract versions of the tracked artifacts.
    pub fn discover(roots: &[PathBuf]) -> ProjectContext {
        const MAX_DEPTH: usize = 3;
        let mut ctx = ProjectContext::default();
        let mut visited: Vec<PathBuf> = Vec::new();

        for root in roots {
            let base = if root.is_dir() {
                root.clone()
            } else {
                root.parent().map(|p| p.to_path_buf()).unwrap_or_default()
            };
            // Walk up from the scan root too: `javscan src/main/java` should
            // still find the pom.xml at the module root.
            let mut ancestor = Some(base.as_path());
            let mut up = 0;
            while let Some(dir) = ancestor {
                ctx.scan_dir(dir, &mut visited);
                up += 1;
                if up > 4 {
                    break;
                }
                ancestor = dir.parent();
            }
            ctx.scan_below(&base, MAX_DEPTH, &mut visited);
        }
        ctx
    }

    fn scan_dir(&mut self, dir: &Path, visited: &mut Vec<PathBuf>) {
        for name in BUILD_FILES {
            let path = dir.join(name);
            if !path.is_file() || visited.contains(&path) {
                continue;
            }
            visited.push(path.clone());
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            self.absorb(&text);
        }
    }

    fn scan_below(&mut self, dir: &Path, depth: usize, visited: &mut Vec<PathBuf>) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || matches!(name.as_ref(), "target" | "build" | "node_modules")
            {
                continue;
            }
            self.scan_dir(&path, visited);
            self.scan_below(&path, depth - 1, visited);
        }
    }

    fn absorb(&mut self, text: &str) {
        for (artifact, re) in tracked_res() {
            let Some(caps) = re.captures(text) else {
                continue;
            };
            let (Some(major), Some(minor)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let (Ok(major), Ok(minor)) = (major.as_str().parse(), minor.as_str().parse()) else {
                continue;
            };
            let entry = self.versions.entry((*artifact).to_string()).or_insert((major, minor));
            if (major, minor) > *entry {
                *entry = (major, minor);
            }
        }
    }

    pub fn version_of(&self, artifact: &str) -> Option<(u32, u32)> {
        self.versions.get(artifact).copied()
    }

    /// True only when a version was actually found *and* it is >= the bound.
    /// An unknown version returns false, keeping the stricter behaviour.
    pub fn at_least(&self, artifact: &str, major: u32, minor: u32) -> bool {
        matches!(self.version_of(artifact), Some(v) if v >= (major, minor))
    }
}

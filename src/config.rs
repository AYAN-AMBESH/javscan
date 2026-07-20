use crate::findings::Severity;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Project configuration loaded from `.javscan.json` (searched upward from
/// the scan root).
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Glob patterns of paths to exclude, e.g. ["**/generated/**"].
    pub exclude: Vec<String>,
    /// Rule IDs (JS101) or names (sql-injection) to disable.
    pub disabled_rules: Vec<String>,
    /// Minimum severity to report: info|low|medium|high|critical.
    pub min_severity: Option<String>,
    /// Scan test sources too (default false).
    pub include_tests: bool,
    /// Severity that causes a non-zero exit code (default high).
    pub fail_on: Option<String>,
}

impl Config {
    pub fn load(root: &Path) -> (Config, Option<PathBuf>) {
        let mut dir = if root.is_dir() {
            Some(root.to_path_buf())
        } else {
            root.parent().map(|p| p.to_path_buf())
        };
        while let Some(d) = dir {
            let candidate = d.join(".javscan.json");
            if candidate.is_file() {
                match std::fs::read_to_string(&candidate)
                    .map_err(|e| e.to_string())
                    .and_then(|s| serde_json::from_str::<Config>(&s).map_err(|e| e.to_string()))
                {
                    Ok(cfg) => return (cfg, Some(candidate)),
                    Err(e) => {
                        eprintln!("warning: failed to parse {}: {e}", candidate.display());
                        return (Config::default(), None);
                    }
                }
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
        (Config::default(), None)
    }

    pub fn min_severity(&self) -> Option<Severity> {
        self.min_severity.as_deref().and_then(Severity::parse)
    }

    pub fn fail_on(&self) -> Option<Severity> {
        self.fail_on.as_deref().and_then(Severity::parse)
    }
}

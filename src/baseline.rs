//! Baseline support: snapshot current findings, then suppress known ones in
//! later scans so CI only fails on newly introduced issues.

use crate::findings::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub generated: String,
    pub fingerprints: Vec<BaselineEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub file: String,
}

pub fn write(path: &Path, findings: &[Finding]) -> std::io::Result<()> {
    let baseline = Baseline {
        version: 1,
        generated: chrono::Local::now().to_rfc3339(),
        fingerprints: findings
            .iter()
            .map(|f| BaselineEntry {
                fingerprint: f.fingerprint.clone(),
                rule_id: f.rule_id.clone(),
                file: f.file.clone(),
            })
            .collect(),
    };
    std::fs::write(path, serde_json::to_string_pretty(&baseline)?)
}

/// Returns (kept, suppressed_count).
pub fn apply(path: &Path, findings: Vec<Finding>) -> Result<(Vec<Finding>, usize), String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
    let baseline: Baseline =
        serde_json::from_str(&data).map_err(|e| format!("invalid baseline file: {e}"))?;
    let known: HashSet<&str> = baseline
        .fingerprints
        .iter()
        .map(|e| e.fingerprint.as_str())
        .collect();
    let before = findings.len();
    let kept: Vec<Finding> = findings
        .into_iter()
        .filter(|f| !known.contains(f.fingerprint.as_str()))
        .collect();
    let suppressed = before - kept.len();
    Ok((kept, suppressed))
}

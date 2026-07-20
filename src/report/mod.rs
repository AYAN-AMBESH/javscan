pub mod console;
pub mod html;
pub mod json;
pub mod sarif;

use crate::findings::{Finding, Severity};
use std::collections::BTreeMap;

pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

pub fn count_by_severity(findings: &[Finding]) -> SeverityCounts {
    let mut c = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    for f in findings {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
        }
    }
    c
}

pub fn count_by_rule(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for f in findings {
        *map.entry(format!("{} {}", f.rule_id, f.rule_name)).or_insert(0) += 1;
    }
    map
}

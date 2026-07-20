use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// SARIF level mapping.
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Info => "note",
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High => "error",
            Severity::Critical => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub snippet: String,
    pub cwe: String,
    pub owasp: String,
    pub remediation: String,
    pub fingerprint: String,
}

impl Finding {
    /// Stable fingerprint independent of line numbers, so baselines survive
    /// unrelated edits that shift code up or down.
    pub fn compute_fingerprint(rule_id: &str, file: &str, snippet: &str) -> String {
        let normalized: String = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
        let file_norm = file.replace('\\', "/");
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in rule_id
            .bytes()
            .chain([0u8])
            .chain(file_norm.bytes())
            .chain([0u8])
            .chain(normalized.bytes())
        {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
}

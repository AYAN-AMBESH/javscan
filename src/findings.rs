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

    /// Move `n` steps down the severity ladder, saturating at `Info`.
    pub fn step_down(&self, n: u8) -> Severity {
        let ladder = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let idx = ladder.iter().position(|s| s == self).unwrap_or(0);
        ladder[idx.saturating_sub(n as usize)]
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

/// Where the data reaching a dangerous API comes from.
///
/// A dangerous API is only a vulnerability if an attacker can reach it. This
/// coarse classification lets rules keep firing on genuinely dangerous calls
/// while ranking them by who can actually influence the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustSource {
    /// Attacker-controlled: HTTP request, socket, or anything the taint
    /// engine traced back to a request source.
    Network,
    /// Files on the local filesystem — requires local write access first.
    LocalFs,
    /// Data from an installed plugin's own descriptor or classpath.
    Plugin,
    /// Data from a theme/template authored by an operator.
    Theme,
    /// Application configuration or environment.
    Config,
    /// A compile-time constant in the source itself.
    Constant,
    /// Could not be determined.
    Unknown,
}

impl TrustSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustSource::Network => "NETWORK",
            TrustSource::LocalFs => "LOCAL_FS",
            TrustSource::Plugin => "PLUGIN",
            TrustSource::Theme => "THEME",
            TrustSource::Config => "CONFIG",
            TrustSource::Constant => "CONSTANT",
            TrustSource::Unknown => "UNKNOWN",
        }
    }

    /// How many severity steps to drop for this source. Only `Network` (and an
    /// undetermined source, which may yet be network) keeps full severity.
    pub fn severity_penalty(&self) -> u8 {
        match self {
            TrustSource::Network | TrustSource::Unknown => 0,
            TrustSource::LocalFs | TrustSource::Plugin | TrustSource::Theme => 2,
            TrustSource::Config => 2,
            TrustSource::Constant => 3,
        }
    }

    /// Human-readable note appended to the finding message.
    pub fn note(&self) -> Option<&'static str> {
        match self {
            TrustSource::Network | TrustSource::Unknown => None,
            TrustSource::LocalFs => {
                Some("Trusted input: the data is read from the local filesystem, so an attacker needs local write access first.")
            }
            TrustSource::Plugin => {
                Some("Trusted input: the data comes from an installed plugin, which is already trusted code.")
            }
            TrustSource::Theme => {
                Some("Trusted input: the data comes from a theme/template authored by an operator.")
            }
            TrustSource::Config => {
                Some("Trusted input: the data comes from application configuration.")
            }
            TrustSource::Constant => {
                Some("Trusted input: the value is a compile-time constant in this source file.")
            }
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
    /// Trust classification of the input reaching the flagged API.
    #[serde(default = "default_source")]
    pub source: TrustSource,
}

fn default_source() -> TrustSource {
    TrustSource::Unknown
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

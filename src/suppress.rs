//! Inline finding suppression via comments:
//!   `// nosec`                       — suppress everything on this line
//!   `// javscan:ignore`              — same
//!   `// javscan:ignore JS101,JS201`  — suppress specific rules
//! A suppression comment on the line directly above a finding also applies.

use crate::parser::{AstIndex, ParsedFile};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Suppression {
    All,
    Rules(Vec<String>),
}

/// Map of 1-based line number -> suppression directive.
pub fn collect(file: &ParsedFile, index: &AstIndex) -> HashMap<usize, Suppression> {
    let mut map = HashMap::new();
    for comment in &index.line_comments {
        let text = file.text(*comment);
        let lower = text.to_lowercase();
        let line = comment.start_position().row + 1;
        if lower.contains("nosec") {
            map.insert(line, Suppression::All);
            continue;
        }
        if let Some(idx) = lower.find("javscan:") {
            let rest = &text[idx + "javscan:".len()..];
            let rest = rest.trim_start();
            if let Some(args) = rest.strip_prefix("ignore") {
                let rules: Vec<String> = args
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_uppercase())
                    .collect();
                if rules.is_empty() {
                    map.insert(line, Suppression::All);
                } else {
                    map.insert(line, Suppression::Rules(rules));
                }
            }
        }
    }
    map
}

pub fn is_suppressed(
    map: &HashMap<usize, Suppression>,
    line: usize,
    rule_id: &str,
) -> bool {
    for l in [line, line.saturating_sub(1)] {
        if let Some(s) = map.get(&l) {
            match s {
                Suppression::All => return true,
                Suppression::Rules(rules) => {
                    if rules.iter().any(|r| r.eq_ignore_ascii_case(rule_id)) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub mod crypto;
pub mod deser;
pub mod files;
pub mod injection;
pub mod misc;
pub mod secrets;
pub mod web;

use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{AstIndex, ParsedFile};
use crate::taint::TaintEngine;
use tree_sitter::Node;

pub struct RuleCtx<'f, 't> {
    pub file: &'f ParsedFile,
    pub index: &'t AstIndex<'t>,
    pub taint: &'t TaintEngine<'f>,
}

impl<'f, 't> RuleCtx<'f, 't> {
    /// Build a finding anchored at `node`.
    pub fn finding(
        &self,
        meta: &RuleMeta,
        node: Node,
        message: String,
        confidence: Confidence,
        severity: Option<Severity>,
    ) -> Finding {
        let snippet = self.file.line_snippet(node);
        let severity = severity.unwrap_or(meta.severity);
        Finding {
            fingerprint: Finding::compute_fingerprint(meta.id, &self.file.path, &snippet),
            rule_id: meta.id.to_string(),
            rule_name: meta.name.to_string(),
            severity,
            confidence,
            message,
            file: self.file.path.clone(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            end_line: node.end_position().row + 1,
            snippet,
            cwe: meta.cwe.to_string(),
            owasp: meta.owasp.to_string(),
            remediation: meta.remediation.to_string(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct RuleMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub cwe: &'static str,
    pub owasp: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
}

pub struct RuleDef {
    pub meta: RuleMeta,
    pub check: fn(&RuleCtx, &RuleMeta) -> Vec<Finding>,
}

/// The full rule registry.
pub fn all_rules() -> Vec<RuleDef> {
    let mut rules = Vec::new();
    injection::register(&mut rules);
    web::register(&mut rules);
    crypto::register(&mut rules);
    secrets::register(&mut rules);
    deser::register(&mut rules);
    files::register(&mut rules);
    misc::register(&mut rules);
    rules
}

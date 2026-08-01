pub mod crypto;
pub mod deser;
pub mod files;
pub mod injection;
pub mod misc;
pub mod secrets;
pub mod web;

use crate::findings::{Confidence, Finding, Severity, TrustSource};
use crate::parser::{AstIndex, ParsedFile};
use crate::project::ProjectContext;
use crate::taint::TaintEngine;
use crate::types::TypeIndex;
use tree_sitter::Node;

pub struct RuleCtx<'f, 't> {
    pub file: &'f ParsedFile,
    pub index: &'t AstIndex<'t>,
    pub taint: &'t TaintEngine<'f>,
    /// Per-file type resolution: imports, declared types, construction sites.
    pub types: &'t TypeIndex<'t>,
    /// Whole-project context, chiefly declared dependency versions.
    pub project: &'t ProjectContext,
}

impl<'f, 't> RuleCtx<'f, 't> {
    /// Build a finding anchored at `node`, with an undetermined input source.
    pub fn finding(
        &self,
        meta: &RuleMeta,
        node: Node,
        message: String,
        confidence: Confidence,
        severity: Option<Severity>,
    ) -> Finding {
        self.build(meta, node, message, confidence, severity, TrustSource::Unknown)
    }

    /// Build a finding whose input source has been classified. Sources that
    /// are not attacker-reachable drop the severity and carry a note
    /// explaining why, instead of being suppressed outright — the API is still
    /// dangerous, it just is not currently exposed.
    pub fn finding_from(
        &self,
        meta: &RuleMeta,
        node: Node,
        message: String,
        confidence: Confidence,
        severity: Option<Severity>,
        source: TrustSource,
    ) -> Finding {
        self.build(meta, node, message, confidence, severity, source)
    }

    fn build(
        &self,
        meta: &RuleMeta,
        node: Node,
        message: String,
        confidence: Confidence,
        severity: Option<Severity>,
        source: TrustSource,
    ) -> Finding {
        // Anchor at the invoked method name rather than the start of the
        // receiver chain. `DatabaseService.get(cfg)\n  .executeQuery(q)` starts
        // two lines above its sink, so the reported line and snippet showed the
        // wrong statement — the one thing a reader checks first.
        let anchor = anchor_node(node);
        let snippet = self.file.line_snippet(anchor);
        let base = severity.unwrap_or(meta.severity);
        // A trusted source deprioritizes a finding; it does not erase it. The
        // API is still dangerous, so the penalty floors at LOW rather than
        // sinking into INFO — a rule that genuinely means INFO says so itself
        // (and does so with an unpenalised source).
        let penalty = source.severity_penalty();
        let severity = if penalty > 0 {
            base.step_down(penalty).max(Severity::Low)
        } else {
            base
        };
        let message = match source.note() {
            Some(note) => format!("{message} {note}"),
            None => message,
        };
        Finding {
            fingerprint: Finding::compute_fingerprint(meta.id, &self.file.path, &snippet),
            rule_id: meta.id.to_string(),
            rule_name: meta.name.to_string(),
            severity,
            confidence,
            message,
            file: self.file.path.clone(),
            line: anchor.start_position().row + 1,
            column: anchor.start_position().column + 1,
            end_line: node.end_position().row + 1,
            snippet,
            cwe: meta.cwe.to_string(),
            owasp: meta.owasp.to_string(),
            remediation: meta.remediation.to_string(),
            source,
        }
    }
}

/// The node a finding should point at: for a call, the invoked method's name,
/// which is where the dangerous operation actually is.
fn anchor_node<'t>(node: Node<'t>) -> Node<'t> {
    match node.kind() {
        "method_invocation" => node.child_by_field_name("name").unwrap_or(node),
        "object_creation_expression" => node.child_by_field_name("type").unwrap_or(node),
        _ => node,
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

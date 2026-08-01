//! Miscellaneous rules: ReDoS-prone regexes and dangerous reflection.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, receiver_text};
use regex::Regex;
use std::sync::OnceLock;

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS701",
            name: "redos",
            severity: Severity::Medium,
            cwe: "CWE-1333",
            owasp: "A05:2021-Security Misconfiguration",
            description: "Regex with nested quantifiers prone to catastrophic backtracking (ReDoS)",
            remediation: "Rewrite the pattern to avoid nested quantifiers like (a+)+, cap input length before matching, or use a linear-time engine (RE2/j).",
        },
        check: check_redos,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS702",
            name: "unsafe-reflection",
            severity: Severity::High,
            cwe: "CWE-470",
            owasp: "A03:2021-Injection",
            description: "Class loaded via reflection from untrusted input",
            remediation: "Map user input to an allow-list of permitted class names instead of passing it to Class.forName/loadClass.",
        },
        check: check_reflection,
    });
}

/// Nested-quantifier heuristic: a quantified group that itself contains a
/// quantifier, e.g. (a+)+, (\w*)* or (a|aa)+.
fn redos_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,)(?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,)")
            .unwrap()
    })
}

/// Nested quantifiers only backtrack catastrophically when the two levels can
/// match the *same* input — `(a+)+`. When the outer group begins with a
/// mandatory literal that the inner quantified atom cannot match, each
/// repetition is anchored to that separator and there is exactly one way to
/// split the input: `(/[A-Za-z]+)*` is linear, not exponential.
///
/// Detects that shape by checking whether every quantified group starts with a
/// literal separator absent from the group's remaining character classes.
fn is_ambiguous(pattern: &str) -> bool {
    for (start, _) in pattern.match_indices('(') {
        let Some(rel_end) = pattern[start..].find(')') else {
            continue;
        };
        let end = start + rel_end;
        // Only groups that are themselves quantified can nest.
        let quantified = pattern[end + 1..]
            .chars()
            .next()
            .is_some_and(|c| c == '+' || c == '*' || c == '{');
        if !quantified {
            continue;
        }
        let body = &pattern[start + 1..end];
        let body = body.strip_prefix("?:").unwrap_or(body);
        // Leading mandatory literal: a plain character that is not a
        // metacharacter and is not itself quantified.
        let mut chars = body.chars();
        let Some(first) = chars.next() else { continue };
        if "[](){}.*+?^$|\\".contains(first) {
            return true; // starts with a class/escape — assume ambiguous
        }
        if chars.clone().next().is_some_and(|c| "*?{".contains(c)) {
            return true; // the leading literal is itself optional
        }
        // Unambiguous only if the separator cannot recur inside the rest.
        if !chars.as_str().contains(first) {
            continue;
        }
        return true;
    }
    false
}

const REGEX_SINKS: &[&str] = &["compile", "matches", "replaceAll", "replaceFirst", "split"];

fn check_redos(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if !REGEX_SINKS.contains(&name) {
            continue;
        }
        if name == "compile" && !receiver_text(ctx.file, *call).ends_with("Pattern") {
            continue;
        }
        let Some(arg) = call_args(*call).into_iter().next() else {
            continue;
        };
        if arg.kind() != "string_literal" {
            continue;
        }
        let pattern = ctx.file.text(arg).trim_matches('"');
        if pattern.len() > 4 && redos_re().is_match(pattern) && is_ambiguous(pattern) {
            out.push(ctx.finding(
                meta,
                *call,
                format!("Regex `{}` has nested quantifiers; crafted input can cause exponential backtracking.",
                    pattern.chars().take(60).collect::<String>()),
                Confidence::Medium,
                None,
            ));
        }
    }
    out
}

fn check_reflection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name != "forName" && name != "loadClass" {
            continue;
        }
        if name == "forName" && !receiver_text(ctx.file, *call).ends_with("Class") {
            continue;
        }
        let Some(arg) = call_args(*call).into_iter().next() else {
            continue;
        };
        if ctx.taint.expr_tainted(arg) {
            out.push(ctx.finding(
                meta,
                *call,
                format!("User-controlled class name passed to `{name}()`; attacker can instantiate arbitrary classes."),
                Confidence::High,
                None,
            ));
        } else if !crate::parser::is_constant_expr(ctx.file, arg) {
            // A class name that comes from a plugin descriptor or the local
            // filesystem is not attacker-reachable in the way a request
            // parameter is; tag the source so the severity reflects that.
            let source = crate::trust::classify(ctx, arg);
            out.push(ctx.finding_from(
                meta,
                *call,
                format!("Dynamic class name passed to `{name}()`; verify it cannot be attacker-controlled."),
                Confidence::Low,
                Some(Severity::Low),
                source,
            ));
        }
    }
    out
}

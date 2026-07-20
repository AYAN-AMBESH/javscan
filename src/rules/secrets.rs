//! Secret detection: hardcoded credentials, credential-looking literals,
//! JWT signing key flaws.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, descendants, receiver_text};
use regex::Regex;
use std::sync::OnceLock;

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS401",
            name: "hardcoded-secret",
            severity: Severity::High,
            cwe: "CWE-798",
            owasp: "A07:2021-Identification and Authentication Failures",
            description: "Hardcoded password, API key, token, or credential",
            remediation: "Load secrets from environment variables, a vault (HashiCorp Vault, AWS Secrets Manager), or encrypted configuration — never from source code.",
        },
        check: check_hardcoded_secret,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS402",
            name: "jwt-weak-signing",
            severity: Severity::High,
            cwe: "CWE-347",
            owasp: "A02:2021-Cryptographic Failures",
            description: "JWT signed or verified with a hardcoded/weak secret",
            remediation: "Load JWT keys from secure configuration, use strong random secrets (>= 256 bits) or asymmetric keys, and never accept the 'none' algorithm.",
        },
        check: check_jwt,
    });
}

fn secret_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|credential|private[_-]?key|client[_-]?secret|encryption[_-]?key)",
        )
        .unwrap()
    })
}

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(\s*|\$\{.*\}|%s|\{\}|<.*>|changeme|change_me|todo|fixme|xxx+|dummy|example|sample|test|placeholder|your[_-].*|none|null|\*+)$",
        )
        .unwrap()
    })
}

/// High-signal token patterns found inside string literals.
fn token_patterns() -> &'static [(&'static Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    static REFS: OnceLock<Vec<(&'static Regex, &'static str)>> = OnceLock::new();
    REFS.get_or_init(|| {
        let pats = PATTERNS.get_or_init(|| {
            vec![
                (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS access key ID"),
                (Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY").unwrap(), "private key material"),
                (Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,}").unwrap(), "Slack token"),
                (Regex::new(r"ghp_[0-9A-Za-z]{36}").unwrap(), "GitHub personal access token"),
                (Regex::new(r"github_pat_[0-9A-Za-z_]{22,}").unwrap(), "GitHub fine-grained token"),
                (Regex::new(r"sk-[0-9A-Za-z]{32,}").unwrap(), "API secret key"),
                (Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.").unwrap(), "hardcoded JWT"),
                (Regex::new(r"(?i)jdbc:[a-z0-9]+://[^\s]*password=[^\s&;\x22]+").unwrap(), "JDBC URL with embedded password"),
            ]
        });
        pats.iter().map(|(r, d)| (r, *d)).collect()
    })
}

fn check_hardcoded_secret(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    // 1) suspicious-name = "literal"  (covers fields and locals)
    for decl in &ctx.index.variable_declarators {
        let (Some(name), Some(value)) = (
            decl.child_by_field_name("name"),
            decl.child_by_field_name("value"),
        ) else {
            continue;
        };
        push_if_secret(ctx, meta, &mut out, ctx.file.text(name), value);
    }
    for assign in &ctx.index.assignments {
        let (Some(left), Some(right)) = (
            assign.child_by_field_name("left"),
            assign.child_by_field_name("right"),
        ) else {
            continue;
        };
        push_if_secret(ctx, meta, &mut out, ctx.file.text(left), right);
    }
    // 2) high-signal token literals anywhere
    for lit in &ctx.index.string_literals {
        let text = ctx.file.text(*lit);
        for (re, what) in token_patterns() {
            if re.is_match(text) {
                out.push(ctx.finding(
                    meta,
                    *lit,
                    format!("String literal contains {what}."),
                    Confidence::High,
                    Some(Severity::Critical),
                ));
                break;
            }
        }
    }
    // 3) DriverManager.getConnection(url, user, "literal-password")
    for call in &ctx.index.method_invocations {
        if call_name(ctx.file, *call) == "getConnection"
            && receiver_text(ctx.file, *call).ends_with("DriverManager")
        {
            let args = call_args(*call);
            if args.len() >= 3 && args[2].kind() == "string_literal" {
                let pw = ctx.file.text(args[2]).trim_matches('"').to_string();
                if !pw.is_empty() && !placeholder_re().is_match(&pw) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "Database password hardcoded in `DriverManager.getConnection(...)`.".into(),
                        Confidence::High,
                        None,
                    ));
                }
            }
        }
    }
    out
}

fn push_if_secret(
    ctx: &RuleCtx,
    meta: &RuleMeta,
    out: &mut Vec<Finding>,
    name: &str,
    value: tree_sitter::Node,
) {
    if value.kind() != "string_literal" {
        return;
    }
    if !secret_name_re().is_match(name) {
        return;
    }
    let inner = ctx.file.text(value).trim_matches('"').to_string();
    if inner.len() < 4 || placeholder_re().is_match(&inner) {
        return;
    }
    // names like "passwordField", "tokenName", "secretQuestion" are usually not secrets
    let lname = name.to_lowercase();
    if lname.ends_with("name") || lname.ends_with("field") || lname.ends_with("label")
        || lname.ends_with("param") || lname.ends_with("header") || lname.ends_with("prompt")
    {
        return;
    }
    out.push(ctx.finding(
        meta,
        value,
        format!("Hardcoded credential assigned to `{name}`."),
        Confidence::Medium,
        None,
    ));
}

fn check_jwt(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        match name {
            // jjwt: .signWith(alg, "secret") / .setSigningKey("secret")
            "signWith" | "setSigningKey" | "verifyWith" => {
                let args = call_args(*call);
                let has_literal = args.iter().any(|a| {
                    !descendants(*a, &|n| n.kind() == "string_literal").is_empty()
                });
                if has_literal {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        format!("JWT `{name}()` uses a hardcoded string secret; tokens can be forged by anyone with the source."),
                        Confidence::High,
                        None,
                    ));
                }
            }
            // auth0 java-jwt: Algorithm.HMAC256("secret")
            "HMAC256" | "HMAC384" | "HMAC512" => {
                if receiver_text(ctx.file, *call).ends_with("Algorithm") {
                    let args = call_args(*call);
                    if args.iter().any(|a| a.kind() == "string_literal") {
                        out.push(ctx.finding(
                            meta,
                            *call,
                            format!("`Algorithm.{name}(...)` called with a hardcoded secret string."),
                            Confidence::High,
                            None,
                        ));
                    }
                }
            }
            "none" => {
                if receiver_text(ctx.file, *call).ends_with("Algorithm") {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "JWT 'none' algorithm accepts unsigned tokens — signature verification is disabled.".into(),
                        Confidence::High,
                        Some(Severity::Critical),
                    ));
                }
            }
            _ => {}
        }
    }
    out
}

//! Secret detection: hardcoded credentials, credential-looking literals,
//! JWT signing key flaws.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, descendants, modifiers, receiver_text};
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

/// Words that, when they appear as a segment of the identifier, mean the
/// `secret`/`token`/`password` in the name is a *domain noun* describing what
/// a value is about — not a claim that the value is key material.
///
/// `SECRET_TYPE_OPAQUE`, `PASSWORD_REGEX` and `PAT_TOKEN_PREFIX` all name a
/// discriminator, a validation pattern and a namespace prefix respectively.
const NON_SECRET_ROLES: &[&str] = &[
    "type", "types", "kind", "prefix", "suffix", "regex", "regexp", "pattern", "reason",
    "name", "names", "field", "label", "param", "params", "header", "headers", "prompt",
    "question", "hint", "description", "title", "message", "msg", "error", "code", "format",
    "template", "attr", "attribute", "claim", "algorithm", "algo", "scope", "role", "uri",
    "url", "path", "id", "column", "property", "env", "event", "action", "category", "group",
    "mode", "status", "state", "class", "table", "index", "key_name", "placeholder", "default",
    "example", "doc", "docs", "link", "namespace", "annotation", "qualifier", "bean",
];

/// Exact values that are well-known public labels rather than credentials.
const LABEL_VOCABULARY: &[&str] = &[
    "opaque", "bearer", "basic", "digest", "negotiate", "ntlm", "none", "null", "default",
    "kubernetes.io/basic-auth", "kubernetes.io/ssh-auth", "kubernetes.io/tls",
    "kubernetes.io/dockerconfigjson", "kubernetes.io/service-account-token",
    "application/json", "text/plain", "password", "secret", "token", "credential",
    "authorization", "x-api-key", "plain", "login", "user", "username",
];

fn uri_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[a-z][a-z0-9+.\-]*:(//|/|\s)").unwrap())
}

/// A value that is a regular expression, not a secret: anchored, escaped, or
/// built from a character class plus a quantifier.
fn regex_shaped(v: &str) -> bool {
    if v.starts_with('^') || v.ends_with('$') {
        return true;
    }
    if v.contains("\\d") || v.contains("\\w") || v.contains("\\s") || v.contains("\\.") {
        return true;
    }
    let has_class = v.contains('[') && v.contains(']');
    let has_quantifier = v.contains('+') || v.contains('*') || v.contains("{,") || v.contains(",}");
    has_class && has_quantifier
}

/// Lowercase kebab/snake identifier, e.g. `reset-password-by-email`.
fn identifier_shaped(v: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]+([-_.][a-z0-9]+)*$").unwrap())
        .is_match(v)
}

/// Charset a random key or token is drawn from (base64/hex/url-safe).
fn keylike_charset(v: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9+/=_.\-]+$").unwrap())
        .is_match(v)
}

/// Shannon entropy of the value, in bits per character.
pub fn shannon_entropy(v: &str) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in v.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let len = v.chars().count() as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// How many of {lowercase, uppercase, digit, symbol} the value draws on.
fn character_classes(v: &str) -> usize {
    let lower = v.chars().any(|c| c.is_ascii_lowercase());
    let upper = v.chars().any(|c| c.is_ascii_uppercase());
    let digit = v.chars().any(|c| c.is_ascii_digit());
    let symbol = v.chars().any(|c| !c.is_ascii_alphanumeric());
    [lower, upper, digit, symbol].iter().filter(|b| **b).count()
}

/// A separator-joined run of lowercase words — `reset-password-by-email`,
/// `user.account.locked`. Event ids and reason codes look like this; generated
/// key material effectively never does, because it carries digits or mixed
/// case. Long word phrases clear the entropy bar on their own, so this shape
/// check is what actually separates them from real keys.
///
/// The trade-off is a diceware-style passphrase (`correct-horse-battery-staple`)
/// would be treated as a phrase. That is far rarer in Java source than event
/// identifiers, and the name-role gate is an independent line of defence.
fn dictionary_phrase(v: &str) -> bool {
    let segments: Vec<&str> = v.split(['-', '_', '.']).collect();
    segments.len() >= 3
        && segments
            .iter()
            .all(|s| s.len() >= 2 && s.chars().all(|c| c.is_ascii_lowercase()))
}

/// Looks like key material rather than a label. Two accepting shapes:
///
/// 1. long, high-entropy and drawn from a base64/hex/url-safe charset — a
///    generated API key or token;
/// 2. shorter but drawing on three or more character classes — a
///    human-chosen password like `SuperS3cretPass!`, which never has the
///    charset of a generated key but is just as much a credential.
///
/// A phrase of lowercase words is excluded from both: event ids clear the
/// entropy bar on length alone.
pub fn is_keylike(v: &str) -> bool {
    if dictionary_phrase(v) {
        return false;
    }
    let entropy = shannon_entropy(v);
    let generated = v.len() >= 16 && keylike_charset(v) && entropy > 3.5;
    let chosen = v.len() >= 12 && character_classes(v) >= 3 && entropy >= 3.0;
    generated || chosen
}

/// Names whose role word is strong enough that even a short value is worth
/// reporting (`password = "admin"`).
fn strong_credential_name(lname: &str) -> bool {
    ["password", "passwd", "pwd", "secret", "apikey", "api_key", "privatekey", "private_key"]
        .iter()
        .any(|r| lname.contains(r))
}

/// Split an identifier into lowercase words across `_`, `-`, `.` and camelCase
/// boundaries, so both `PAT_TOKEN_PREFIX` and `patTokenPrefix` yield
/// `["pat", "token", "prefix"]`.
fn name_segments(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if c == '_' || c == '-' || c == '.' {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Does the identifier name a *role* (a type, prefix, regex, reason…) rather
/// than claim to hold a credential?
pub fn has_non_secret_role(name: &str) -> bool {
    let segments = name_segments(name);
    segments
        .iter()
        .any(|w| NON_SECRET_ROLES.contains(&w.as_str()))
}

/// Verdict of the value-shape gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueVerdict {
    /// Structurally cannot be key material — a URI, regex, label, prefix.
    NotSecret,
    /// Plausible credential, but low entropy — report with lower confidence.
    Weak,
    /// Long, high-entropy, key-charset — report at full strength.
    Keylike,
}

/// Classify a string literal's *value*, independently of the name it was
/// assigned to. This is the gate the report calls out as the highest-ROI fix:
/// a name match alone is not evidence of a secret.
pub fn classify_value(value: &str, strong_name: bool) -> ValueVerdict {
    let v = value.trim();

    // --- Structural rejects: these shapes are never key material, however
    // high their entropy. A character-class regex scores as well as a
    // generated key, so these must be checked before the entropy signal.
    if v.len() < 4 || placeholder_re().is_match(v) {
        return ValueVerdict::NotSecret;
    }
    // URIs and RFC-7807 problem-detail types.
    if uri_re().is_match(v) {
        return ValueVerdict::NotSecret;
    }
    if regex_shaped(v) {
        return ValueVerdict::NotSecret;
    }
    // Namespace prefixes: `pat_`, `sk-`, `svc.`
    if v.ends_with('_') || v.ends_with('-') || v.ends_with('.') || v.ends_with(':') || v.ends_with('/') {
        return ValueVerdict::NotSecret;
    }
    // Prose or a format template, not a credential.
    if v.contains(' ') || v.contains('\\') || v.contains("%s") || v.contains("{}") {
        return ValueVerdict::NotSecret;
    }
    // A comma- or semicolon-separated list is configuration (a set of field
    // names to mask, a cipher suite list), not a single credential. Real keys
    // never contain a separator, and such lists otherwise clear the entropy
    // bar on length and mixed case alone.
    if v.split([',', ';'])
        .filter(|part| !part.trim().is_empty())
        .count()
        > 1
    {
        return ValueVerdict::NotSecret;
    }

    // --- Positive signal: does the value look like key material?
    if is_keylike(v) {
        return ValueVerdict::Keylike;
    }

    // --- Remaining rejects for values that failed the key-material test.
    if LABEL_VOCABULARY.contains(&v.to_ascii_lowercase().as_str()) {
        return ValueVerdict::NotSecret;
    }
    // Short values are labels unless the name is strongly credential-flavoured
    // or the value mixes character classes the way generated keys do.
    if v.len() <= 6 && !strong_name && character_classes(v) < 3 {
        return ValueVerdict::NotSecret;
    }
    // Lowercase kebab/snake identifiers are event ids, reason codes and enum
    // names. Anything reaching here already failed `is_keylike`, so it is
    // short, low-entropy, or a phrase of words — none of which is key material.
    if identifier_shaped(v) {
        return ValueVerdict::NotSecret;
    }
    ValueVerdict::Weak
}

/// High-signal token patterns found inside string literals.
fn token_patterns() -> &'static [(&'static Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    static REFS: OnceLock<Vec<(&'static Regex, &'static str)>> = OnceLock::new();
    REFS.get_or_init(|| {
        let pats = PATTERNS.get_or_init(|| {
            vec![
                (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS access key ID"),
                // The header alone is a *parsing constant* — every PEM reader
                // declares one. Require an actual base64 body after it before
                // claiming the literal embeds a key.
                (Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[^A-Za-z0-9+/]{0,8}[A-Za-z0-9+/]{40,}").unwrap(), "private key material"),
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
    // The name matched, but a name is not evidence. `SECRET_TYPE_OPAQUE`,
    // `PASSWORD_REGEX` and `PAT_TOKEN_PREFIX` all match the name pattern while
    // naming a discriminator, a validation pattern and a namespace prefix.
    if has_non_secret_role(name) {
        return;
    }
    let inner = ctx.file.text(value).trim_matches('"').to_string();
    let lname = name.to_lowercase();
    let verdict = classify_value(&inner, strong_credential_name(&lname));
    let (confidence, severity) = match verdict {
        ValueVerdict::NotSecret => return,
        ValueVerdict::Keylike => (Confidence::High, None),
        // Credential-shaped but low entropy: still worth reporting (a weak
        // hardcoded password is a real finding) at a lower rank.
        ValueVerdict::Weak => (Confidence::Medium, Some(Severity::Medium)),
    };

    // A `public static final` constant in an API/model package is a shared
    // discriminator far more often than embedded key material.
    let (confidence, severity) = if is_public_api_constant(ctx, value) {
        (
            Confidence::Low,
            Some(severity.unwrap_or(meta.severity).step_down(1)),
        )
    } else {
        (confidence, severity)
    };

    let detail = match verdict {
        ValueVerdict::Keylike => "the value is long, high-entropy key material",
        _ => "verify the value is not a real credential",
    };
    out.push(ctx.finding(
        meta,
        value,
        format!("Hardcoded credential assigned to `{name}` — {detail}."),
        confidence,
        severity,
    ));
}

/// Is this literal the initialiser of a `public static final` field in a
/// package that looks like an API/model surface?
fn is_public_api_constant(ctx: &RuleCtx, value: tree_sitter::Node) -> bool {
    let Some(declarator) = value.parent().filter(|p| p.kind() == "variable_declarator") else {
        return false;
    };
    let Some(field) = declarator.parent().filter(|p| p.kind() == "field_declaration") else {
        return false;
    };
    let mods = modifiers(ctx.file, field);
    let is_constant = mods.contains(&"public") && mods.contains(&"static") && mods.contains(&"final");
    if !is_constant {
        return false;
    }
    let package = ctx.types.package().unwrap_or("").to_lowercase();
    ["api", "model", "dto", "constant", "extension", "core"]
        .iter()
        .any(|seg| package.split('.').any(|p| p == *seg))
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

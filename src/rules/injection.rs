//! Injection rules: SQL, command, LDAP, XPath, SpEL, script engine, log.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, creation_type, is_dynamic_concat, receiver_text};
use crate::trust;

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS101",
            name: "sql-injection",
            severity: Severity::Critical,
            cwe: "CWE-89",
            owasp: "A03:2021-Injection",
            description: "SQL query built from untrusted input or string concatenation",
            remediation: "Use PreparedStatement with parameterized placeholders (?) and bind values with setString/setInt; never concatenate input into SQL.",
        },
        check: check_sql_injection,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS102",
            name: "command-injection",
            severity: Severity::Critical,
            cwe: "CWE-78",
            owasp: "A03:2021-Injection",
            description: "OS command constructed from untrusted input",
            remediation: "Avoid shelling out with user input. Use ProcessBuilder with a fixed argument list, validate against an allow-list, and never pass input through 'sh -c' or 'cmd /c'.",
        },
        check: check_command_injection,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS103",
            name: "ldap-injection",
            severity: Severity::High,
            cwe: "CWE-90",
            owasp: "A03:2021-Injection",
            description: "LDAP search filter built from untrusted input",
            remediation: "Escape LDAP special characters (e.g. OWASP ESAPI encodeForLDAP) or use parameterized LDAP filter APIs.",
        },
        check: check_ldap_injection,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS104",
            name: "xpath-injection",
            severity: Severity::High,
            cwe: "CWE-643",
            owasp: "A03:2021-Injection",
            description: "XPath expression built from untrusted input",
            remediation: "Use XPath variable resolvers (XPathVariableResolver) instead of concatenating input into expressions.",
        },
        check: check_xpath_injection,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS105",
            name: "spel-injection",
            severity: Severity::Critical,
            cwe: "CWE-917",
            owasp: "A03:2021-Injection",
            description: "Spring Expression Language (SpEL) parsed from untrusted input",
            remediation: "Never parse user input as SpEL. If unavoidable, use SimpleEvaluationContext instead of StandardEvaluationContext.",
        },
        check: check_spel_injection,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS106",
            name: "script-engine-injection",
            severity: Severity::Critical,
            cwe: "CWE-94",
            owasp: "A03:2021-Injection",
            description: "ScriptEngine.eval() executed on untrusted input (code injection)",
            remediation: "Do not eval user input. If scripting is required, use a sandboxed engine (e.g. GraalJS with restricted Context) and an allow-list.",
        },
        check: check_script_injection,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS107",
            name: "log-injection",
            severity: Severity::Low,
            cwe: "CWE-117",
            owasp: "A09:2021-Security Logging and Monitoring Failures",
            description: "Untrusted input concatenated into log messages (log forging / CRLF injection)",
            remediation: "Use parameterized logging (logger.info(\"user {}\", name)) and strip CR/LF from user input before logging.",
        },
        check: check_log_injection,
    });
}

const SQL_SINKS: &[&str] = &[
    "executeQuery",
    "executeUpdate",
    "executeLargeUpdate",
    "addBatch",
    "prepareStatement",
    "prepareCall",
    "createQuery",
    "createNativeQuery",
    "createSQLQuery",
    "nativeQuery",
    "queryForObject",
    "queryForList",
    "queryForMap",
    "queryForRowSet",
    "batchUpdate",
];

/// Generic names that are only SQL sinks when the receiver looks like a
/// Statement / JdbcTemplate.
const SQL_GENERIC_SINKS: &[&str] = &["execute", "query", "update"];

fn looks_like_sql(text: &str) -> bool {
    let upper = text.to_uppercase();
    ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "MERGE", "FROM", "WHERE"]
        .iter()
        .any(|kw| upper.contains(kw))
}

/// Does this SQL text carry JDBC bind placeholders?
///
/// Concatenation into a query string is only a finding when the *values* are
/// concatenated. A query assembled from constants and column names but with
/// every value bound through `?` is the correct pattern, and it is extremely
/// common: DAOs build `where` clauses dynamically and pass the values as a
/// separate parameter array. Counting only placeholders that sit outside
/// string content we already know is dynamic keeps this cheap and textual.
fn has_bind_placeholders(text: &str) -> bool {
    // `?` inside a string literal in the source ("... = ?") is the placeholder;
    // `?` as a Java ternary operator always has surrounding whitespace and no
    // quotes, so require the character to appear within a quoted run.
    let mut in_string = false;
    let mut prev_escape = false;
    for ch in text.chars() {
        match ch {
            '\\' if in_string => prev_escape = !prev_escape,
            '"' if !prev_escape => in_string = !in_string,
            '?' if in_string => return true,
            _ => prev_escape = false,
        }
    }
    false
}

/// Does this code bind values onto a `PreparedStatement`?
fn binds_parameters(scope: &str) -> bool {
    const SETTERS: &[&str] = &[
        ".setString(", ".setInt(", ".setLong(", ".setObject(", ".setDouble(",
        ".setFloat(", ".setShort(", ".setBoolean(", ".setBytes(", ".setDate(",
        ".setTimestamp(", ".setBigDecimal(", ".setNull(", ".setArray(",
    ];
    SETTERS.iter().any(|s| scope.contains(s))
}

fn check_sql_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let recv = receiver_text(ctx.file, *call).to_lowercase();
        let is_sink = SQL_SINKS.contains(&name)
            || (SQL_GENERIC_SINKS.contains(&name)
                && (recv.contains("stmt")
                    || recv.contains("statement")
                    || recv.contains("jdbc")
                    || recv.contains("template")
                    || recv.contains("session")
                    || recv.contains("entitymanager")
                    || recv.contains("em")));
        if !is_sink {
            continue;
        }
        let args = call_args(*call);
        let Some(arg) = args.first().copied() else {
            continue;
        };
        let arg_text = ctx.file.text(arg);
        // Values bound through `?` alongside a concatenated skeleton is the
        // *correct* pattern, and by far the most common shape in real DAOs:
        // the `where` clause is assembled from column names while the values
        // travel separately. Look for placeholders in the expression itself,
        // then in the enclosing method (StringBuilder `.append(" and x = ?")`),
        // then in the file (a `buildQuery` helper next door) — widening only
        // while the sink call also receives the bound values as extra
        // arguments, which is what makes the placeholders meaningful.
        //
        // A single-argument sink (`prepareStatement(sql)`, bound later via
        // setX) keeps a finding, ranked below true concatenation of values.
        let concat_severity = |ctx: &RuleCtx, expr: tree_sitter::Node| -> Option<Severity> {
            if args.len() <= 1 {
                if !has_bind_placeholders(ctx.file.text(expr)) {
                    return Some(Severity::High);
                }
                // `prepareStatement(sql)` followed by `stmt.setString(1, v)` in
                // the same method *is* the parameterized form; the values just
                // arrive on a later statement.
                let scope = crate::parser::enclosing_method(*call)
                    .map(|m| ctx.file.text(m))
                    .unwrap_or("");
                return if binds_parameters(scope) {
                    None
                } else {
                    Some(Severity::Medium)
                };
            }
            let scope = crate::parser::enclosing_method(*call)
                .map(|m| ctx.file.text(m))
                .unwrap_or("");
            if has_bind_placeholders(ctx.file.text(expr))
                || has_bind_placeholders(scope)
                || has_bind_placeholders(&ctx.file.source)
            {
                None
            } else {
                Some(Severity::High)
            }
        };
        if ctx.taint.expr_tainted(arg) {
            out.push(ctx.finding(
                meta,
                *call,
                format!("User-controlled data reaches SQL sink `{name}()`; the query is attacker-influenced."),
                Confidence::High,
                None,
            ));
        } else if is_dynamic_concat(ctx.file, arg) && looks_like_sql(arg_text) {
            if let Some(sev) = concat_severity(ctx, arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("SQL passed to `{name}()` is built with string concatenation; use bind parameters instead."),
                    Confidence::Medium,
                    Some(sev),
                ));
            }
        } else if arg.kind() == "identifier" {
            // variable that was built via tainted concat is caught by taint;
            // check concat-built (but untainted) SQL vars too
            if let Some(decl) = find_declaration(ctx, arg) {
                let built = ctx.file.text(decl);
                if !(is_dynamic_concat(ctx.file, decl) && looks_like_sql(built)) {
                    continue;
                }
                if let Some(sev) = concat_severity(ctx, decl) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        format!("SQL passed to `{name}()` was built with string concatenation; use bind parameters instead."),
                        Confidence::Medium,
                        Some(sev),
                    ));
                }
            }
        }
    }
    out
}

/// Find the initializer expression for an identifier, if declared in this file.
///
/// Matching purely by name across the whole file attributes an unrelated
/// method's `String sql = ...` to this use site. Prefer the nearest declaration
/// that is in scope: same enclosing method and textually before the use;
/// fall back to a field (declared outside any method) otherwise.
fn find_declaration<'t>(
    ctx: &RuleCtx<'_, 't>,
    ident: tree_sitter::Node<'t>,
) -> Option<tree_sitter::Node<'t>> {
    let name = ctx.file.text(ident);
    let use_offset = ident.start_byte();
    let scope = crate::parser::enclosing_method(ident);
    let mut local: Option<tree_sitter::Node<'t>> = None;
    let mut field: Option<tree_sitter::Node<'t>> = None;

    for decl in &ctx.index.variable_declarators {
        let (Some(n), Some(v)) = (
            decl.child_by_field_name("name"),
            decl.child_by_field_name("value"),
        ) else {
            continue;
        };
        if ctx.file.text(n) != name {
            continue;
        }
        let decl_scope = crate::parser::enclosing_method(*decl);
        match (decl_scope, scope) {
            // Local to the same method, declared before this use: take the
            // latest such declaration (the one actually in effect).
            (Some(d), Some(s)) if d.id() == s.id() && decl.start_byte() <= use_offset => {
                if local.map(|p| p.start_byte() < decl.start_byte()).unwrap_or(true) {
                    local = Some(v);
                }
            }
            // A field: usable from anywhere in the class.
            (None, _) => field = field.or(Some(v)),
            _ => {}
        }
    }
    local.or(field)
}

fn check_command_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let recv = receiver_text(ctx.file, *call);
        if name == "exec" && (recv.contains("Runtime") || recv.to_lowercase().contains("runtime")) {
            for arg in call_args(*call) {
                if ctx.taint.expr_tainted(arg) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "User-controlled data reaches `Runtime.exec()`; attacker can run arbitrary OS commands.".into(),
                        Confidence::High,
                        None,
                    ));
                    break;
                } else if is_dynamic_concat(ctx.file, arg) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "Command for `Runtime.exec()` is built with string concatenation.".into(),
                        Confidence::Medium,
                        Some(Severity::High),
                    ));
                    break;
                }
            }
        }
    }
    for creation in &ctx.index.object_creations {
        if creation_type(ctx.file, *creation) != "ProcessBuilder" {
            continue;
        }
        for arg in call_args(*creation) {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *creation,
                    "User-controlled data reaches `ProcessBuilder`; attacker can influence the executed command.".into(),
                    Confidence::High,
                    None,
                ));
                break;
            }
        }
        // shell wrapper pattern: new ProcessBuilder("sh", "-c", anything-dynamic)
        let args = call_args(*creation);
        let texts: Vec<&str> = args.iter().map(|a| ctx.file.text(*a)).collect();
        if texts.iter().any(|t| t.contains("\"-c\"") || *t == "\"-c\"" || *t == "\"/c\"")
            && args.iter().any(|a| !crate::parser::is_constant_expr(ctx.file, *a))
        {
            out.push(ctx.finding(
                meta,
                *creation,
                "`ProcessBuilder` invokes a shell (-c) with a dynamically built command string.".into(),
                Confidence::Medium,
                Some(Severity::High),
            ));
        }
    }
    out
}

fn check_ldap_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        if call_name(ctx.file, *call) != "search" {
            continue;
        }
        let recv = receiver_text(ctx.file, *call).to_lowercase();
        if !(recv.contains("ctx") || recv.contains("context") || recv.contains("ldap") || recv.contains("dir")) {
            continue;
        }
        for arg in call_args(*call) {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "User-controlled data reaches LDAP `search()` filter; attacker can alter the filter logic.".into(),
                    Confidence::High,
                    None,
                ));
                break;
            } else if is_dynamic_concat(ctx.file, arg) && ctx.file.text(arg).contains('=') {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "LDAP search filter is built with string concatenation.".into(),
                    Confidence::Medium,
                    Some(Severity::Medium),
                ));
                break;
            }
        }
    }
    out
}

fn check_xpath_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name != "compile" && name != "evaluate" {
            continue;
        }
        let recv = receiver_text(ctx.file, *call).to_lowercase();
        if !recv.contains("xpath") {
            continue;
        }
        if let Some(arg) = call_args(*call).into_iter().next() {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("User-controlled data reaches XPath `{name}()`; attacker can alter the query."),
                    Confidence::High,
                    None,
                ));
            } else if is_dynamic_concat(ctx.file, arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("XPath expression passed to `{name}()` is built with string concatenation."),
                    Confidence::Medium,
                    Some(Severity::Medium),
                ));
            }
        }
    }
    out
}

fn check_spel_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    // SpEL is only an RCE primitive when the expression is evaluated against a
    // context that permits `T(...)` type references and constructor calls.
    // `SimpleEvaluationContext` permits neither, so parsing untrusted text
    // against it is a data-binding concern, not code execution.
    let eval_context = trust::spel_context(ctx);
    if eval_context == trust::SpelContext::Simple {
        return out;
    }

    for call in &ctx.index.method_invocations {
        if call_name(ctx.file, *call) != "parseExpression" {
            continue;
        }
        let Some(arg) = call_args(*call).into_iter().next() else {
            continue;
        };
        let source = trust::classify(ctx, arg);
        if source == crate::findings::TrustSource::Network {
            out.push(ctx.finding_from(
                meta,
                *call,
                "User-controlled data is parsed as a SpEL expression; this allows remote code execution.".into(),
                Confidence::High,
                None,
                source,
            ));
        } else if !crate::parser::is_constant_expr(ctx.file, arg) {
            out.push(ctx.finding_from(
                meta,
                *call,
                "Dynamic (non-constant) expression parsed as SpEL; verify the input cannot be attacker-controlled.".into(),
                Confidence::Low,
                Some(Severity::Medium),
                source,
            ));
        }
    }
    out
}

fn check_script_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        if call_name(ctx.file, *call) != "eval" {
            continue;
        }
        let recv = receiver_text(ctx.file, *call).to_lowercase();
        if !(recv.contains("engine") || recv.contains("script") || recv.contains("nashorn")) {
            continue;
        }
        if let Some(arg) = call_args(*call).into_iter().next() {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "User-controlled data reaches `ScriptEngine.eval()`; this is code injection.".into(),
                    Confidence::High,
                    None,
                ));
            } else if !crate::parser::is_constant_expr(ctx.file, arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "Dynamic script executed via `ScriptEngine.eval()`; verify the source is trusted.".into(),
                    Confidence::Low,
                    Some(Severity::Medium),
                ));
            }
        }
    }
    out
}

const LOG_METHODS: &[&str] = &["info", "warn", "error", "debug", "trace", "fatal", "log"];

fn check_log_injection(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if !LOG_METHODS.contains(&name) {
            continue;
        }
        let recv = receiver_text(ctx.file, *call).to_lowercase();
        if !(recv.contains("log") || recv == "logger") {
            continue;
        }
        for arg in call_args(*call) {
            if is_dynamic_concat(ctx.file, arg) && ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "User-controlled data concatenated into a log message; use parameterized logging and sanitize CR/LF.".into(),
                    Confidence::Medium,
                    None,
                ));
                break;
            }
        }
    }
    out
}

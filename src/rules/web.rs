//! Web application rules: XSS, open redirect, SSRF, cookies, CSRF, CORS,
//! cleartext transport.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, creation_type, enclosing_method, receiver_text};
use std::collections::HashSet;

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS201",
            name: "cross-site-scripting",
            severity: Severity::High,
            cwe: "CWE-79",
            owasp: "A03:2021-Injection",
            description: "Untrusted input written to the HTTP response without encoding",
            remediation: "HTML-encode output with OWASP Java Encoder (Encode.forHtml) or a templating engine with auto-escaping; never write raw request data to the response.",
        },
        check: check_xss,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS202",
            name: "open-redirect",
            severity: Severity::Medium,
            cwe: "CWE-601",
            owasp: "A01:2021-Broken Access Control",
            description: "Redirect target taken from untrusted input",
            remediation: "Validate redirect targets against an allow-list of internal paths, or use fixed mapping keys instead of raw URLs.",
        },
        check: check_open_redirect,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS203",
            name: "ssrf",
            severity: Severity::High,
            cwe: "CWE-918",
            owasp: "A10:2021-SSRF",
            description: "Server-side request to a URL derived from untrusted input",
            remediation: "Validate URLs against an allow-list of hosts/schemes, resolve and check the IP is not internal, and disable redirects.",
        },
        check: check_ssrf,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS204",
            name: "insecure-cookie",
            severity: Severity::Medium,
            cwe: "CWE-614",
            owasp: "A05:2021-Security Misconfiguration",
            description: "Cookie created without Secure/HttpOnly flags",
            remediation: "Call cookie.setSecure(true) and cookie.setHttpOnly(true) on every session or sensitive cookie.",
        },
        check: check_insecure_cookie,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS205",
            name: "csrf-disabled",
            severity: Severity::High,
            cwe: "CWE-352",
            owasp: "A01:2021-Broken Access Control",
            description: "Spring Security CSRF protection explicitly disabled",
            remediation: "Keep CSRF protection enabled for browser-facing endpoints; only disable it for stateless token-authenticated APIs, and document why.",
        },
        check: check_csrf_disabled,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS206",
            name: "permissive-cors",
            severity: Severity::Medium,
            cwe: "CWE-942",
            owasp: "A05:2021-Security Misconfiguration",
            description: "CORS configured to allow any origin (*)",
            remediation: "List explicit trusted origins instead of '*', especially when credentials are allowed.",
        },
        check: check_permissive_cors,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS207",
            name: "cleartext-http",
            severity: Severity::Low,
            cwe: "CWE-319",
            owasp: "A02:2021-Cryptographic Failures",
            description: "Hardcoded cleartext http:// URL",
            remediation: "Use https:// for all external communication; cleartext HTTP exposes data to interception.",
        },
        check: check_cleartext_http,
    });
}

/// Variables assigned from response.getWriter()/getOutputStream().
fn writer_vars(ctx: &RuleCtx) -> HashSet<String> {
    let mut vars = HashSet::new();
    for decl in &ctx.index.variable_declarators {
        if let (Some(name), Some(value)) = (
            decl.child_by_field_name("name"),
            decl.child_by_field_name("value"),
        ) {
            let vt = ctx.file.text(value);
            if vt.contains(".getWriter()") || vt.contains(".getOutputStream()") {
                vars.insert(ctx.file.text(name).to_string());
            }
        }
    }
    vars
}

fn check_xss(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    let writers = writer_vars(ctx);
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if !matches!(name, "print" | "println" | "write" | "append" | "format" | "printf") {
            continue;
        }
        let recv = receiver_text(ctx.file, *call);
        let is_response_writer = recv.contains(".getWriter()")
            || recv.contains(".getOutputStream()")
            || writers.contains(recv);
        if !is_response_writer {
            continue;
        }
        for arg in call_args(*call) {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "User-controlled data written to the HTTP response without HTML encoding (reflected XSS).".into(),
                    Confidence::High,
                    None,
                ));
                break;
            }
        }
    }
    out
}

fn check_open_redirect(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let args = call_args(*call);
        if name == "sendRedirect" {
            if let Some(arg) = args.first() {
                if ctx.taint.expr_tainted(*arg) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "Redirect target comes from user-controlled input (open redirect).".into(),
                        Confidence::High,
                        None,
                    ));
                }
            }
        } else if (name == "setHeader" || name == "addHeader") && args.len() == 2 {
            let header = ctx.file.text(args[0]).to_lowercase();
            if header.contains("location") && ctx.taint.expr_tainted(args[1]) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "Location header set from user-controlled input (open redirect).".into(),
                    Confidence::High,
                    None,
                ));
            }
        }
    }
    out
}

const SSRF_CLIENT_CALLS: &[&str] = &[
    "getForObject",
    "getForEntity",
    "postForObject",
    "postForEntity",
    "postForLocation",
    "getForLocation",
    "exchange",
    "openConnection",
    "openStream",
];

/// Types whose `openStream()` / `openConnection()` really does make a network
/// request. `openStream` is also the Commons FileUpload API for reading an
/// uploaded part, which is not an outbound request at all.
const URL_TYPES: &[&str] = &["URL", "URI", "java.net.URL", "java.net.URI"];

/// Is the receiver of an `openStream`/`openConnection` call a URL?
///
/// Returns false when the receiver resolves to some other declared type, and
/// true when it resolves to a URL *or* cannot be resolved at all but the file
/// imports `java.net.URL` — the latter keeps coverage for call chains like
/// `new URL(s).openStream()` without firing on `fileItem.openStream()`.
fn receiver_is_url(ctx: &RuleCtx, recv: tree_sitter::Node) -> bool {
    match ctx.types.type_of(ctx.file, recv) {
        Some(ty) => ctx.types.is_a(&ty, URL_TYPES),
        None => {
            let text = ctx.file.text(recv);
            text.contains("new URL(") || text.contains("new URI(") || text.contains("toURL()")
        }
    }
}

fn check_ssrf(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for creation in &ctx.index.object_creations {
        let ty = creation_type(ctx.file, *creation);
        if !matches!(ty, "URL" | "URI" | "HttpGet" | "HttpPost" | "HttpPut" | "HttpDelete") {
            continue;
        }
        for arg in call_args(*creation) {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *creation,
                    format!("User-controlled data flows into `new {ty}(...)` used for server-side requests (SSRF)."),
                    Confidence::High,
                    None,
                ));
                break;
            }
        }
    }
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name == "create" && receiver_text(ctx.file, *call).ends_with("URI") {
            if let Some(arg) = call_args(*call).into_iter().next() {
                if ctx.taint.expr_tainted(arg) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "User-controlled data flows into `URI.create()` used for server-side requests (SSRF).".into(),
                        Confidence::High,
                        None,
                    ));
                }
            }
            continue;
        }
        if !SSRF_CLIENT_CALLS.contains(&name) {
            continue;
        }
        if name == "openConnection" || name == "openStream" {
            // sink is the receiver URL itself
            if let Some(obj) = call.child_by_field_name("object") {
                if receiver_is_url(ctx, obj) && ctx.taint.expr_tainted(obj) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        format!("`{name}()` invoked on a URL derived from user input (SSRF)."),
                        Confidence::High,
                        None,
                    ));
                }
            }
            continue;
        }
        if let Some(arg) = call_args(*call).into_iter().next() {
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("User-controlled URL passed to HTTP client call `{name}()` (SSRF)."),
                    Confidence::High,
                    None,
                ));
            }
        }
    }
    out
}

fn check_insecure_cookie(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name != "setSecure" && name != "setHttpOnly" {
            continue;
        }
        if let Some(arg) = call_args(*call).into_iter().next() {
            if ctx.file.text(arg) == "false" {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("Cookie flag explicitly disabled via `{name}(false)`."),
                    Confidence::High,
                    None,
                ));
            }
        }
    }
    for creation in &ctx.index.object_creations {
        if creation_type(ctx.file, *creation) != "Cookie" {
            continue;
        }
        let scope_text = enclosing_method(*creation)
            .map(|m| ctx.file.text(m).to_string())
            .unwrap_or_default();
        // A `new Cookie(...)` that never reaches the client carries no flags
        // to get wrong. Servlet code also builds Cookie objects to *send* on
        // an outbound HTTP call (e.g. re-using a login session upstream);
        // those are inputs to a client library, not Set-Cookie headers.
        if !scope_text.contains("addCookie") && !scope_text.contains("Set-Cookie") {
            continue;
        }
        let missing_secure = !scope_text.contains("setSecure(true)");
        let missing_httponly = !scope_text.contains("setHttpOnly(true)");
        if missing_secure || missing_httponly {
            let mut missing = Vec::new();
            if missing_secure {
                missing.push("Secure");
            }
            if missing_httponly {
                missing.push("HttpOnly");
            }
            out.push(ctx.finding(
                meta,
                *creation,
                format!("Cookie created without the {} flag(s).", missing.join(" and ")),
                Confidence::Medium,
                None,
            ));
        }
    }
    out
}

fn check_csrf_disabled(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name == "disable" && receiver_text(ctx.file, *call).contains("csrf") {
            out.push(ctx.finding(
                meta,
                *call,
                "Spring Security CSRF protection is disabled (`.csrf().disable()`).".into(),
                Confidence::High,
                None,
            ));
        } else if name == "csrf" {
            let args = call_args(*call);
            if args
                .iter()
                .any(|a| ctx.file.text(*a).contains("::disable"))
            {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "Spring Security CSRF protection is disabled (`csrf(AbstractHttpConfigurer::disable)`).".into(),
                    Confidence::High,
                    None,
                ));
            }
        }
    }
    out
}

fn check_permissive_cors(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let args = call_args(*call);
        if (name == "setHeader" || name == "addHeader") && args.len() == 2 {
            let header = ctx.file.text(args[0]);
            let value = ctx.file.text(args[1]);
            if header.contains("Access-Control-Allow-Origin") && value.contains('*') {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "Access-Control-Allow-Origin set to '*' — any website can call this endpoint.".into(),
                    Confidence::High,
                    None,
                ));
            }
        } else if matches!(name, "allowedOrigins" | "addAllowedOrigin" | "allowedOriginPatterns" | "setAllowedOrigins") {
            if args.iter().any(|a| ctx.file.text(*a).contains("\"*\"")) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "CORS configuration allows any origin ('*').".into(),
                    Confidence::High,
                    None,
                ));
            }
        }
    }
    out
}

/// Is this literal an argument to a string comparison (`startsWith`, `equals`,
/// `contains`, …) or an operand of `==`/`!=`, rather than a URL being used?
fn is_comparison_operand(ctx: &RuleCtx, lit: tree_sitter::Node) -> bool {
    const COMPARISONS: &[&str] = &[
        "startsWith", "endsWith", "equals", "equalsIgnoreCase", "contains",
        "indexOf", "lastIndexOf", "matches", "replace", "replaceAll",
        "replaceFirst", "split", "regionMatches", "compareTo",
    ];
    let mut cur = lit.parent();
    while let Some(n) = cur {
        match n.kind() {
            "argument_list" | "parenthesized_expression" => cur = n.parent(),
            "method_invocation" => {
                return COMPARISONS.contains(&call_name(ctx.file, n));
            }
            "binary_expression" => {
                let op = n
                    .child_by_field_name("operator")
                    .map(|o| ctx.file.text(o))
                    .unwrap_or("");
                return op == "==" || op == "!=";
            }
            _ => return false,
        }
    }
    false
}

/// XML/RDF namespace URIs: opaque identifiers that happen to be spelled as
/// http URLs and must be compared byte-for-byte.
fn is_namespace_uri(url: &str) -> bool {
    const NAMESPACE_HOSTS: &[&str] = &[
        "www.wikidata.org/entity/",
        "www.wikidata.org/prop/",
        "rdf.freebase.com/",
        "purl.org/",
        "xmlns.com/",
        "www.opengis.net/",
        "www.openlinksw.com/",
    ];
    NAMESPACE_HOSTS.iter().any(|h| url.contains(h))
        || url.ends_with('#')
        || url.contains("/ns#")
}

fn check_cleartext_http(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    const ALLOWED: &[&str] = &[
        "localhost", "127.0.0.1", "[::1]", "0.0.0.0", "w3.org", "xmlns", "apache.org",
        "example.com", "example.org", "schemas.", "maven.", "java.sun.com", ".dtd",
    ];
    for lit in &ctx.index.string_literals {
        let text = ctx.file.text(*lit);
        let inner = text.trim_matches('"');
        if !inner.starts_with("http://") {
            continue;
        }
        if ALLOWED.iter().any(|a| inner.contains(a)) {
            continue;
        }
        // A bare scheme with no host is never an endpoint. It is the argument
        // to `url.startsWith("http://")` or the prefix in `"http://" + host` —
        // scheme *handling*, which is what code that upgrades to HTTPS looks
        // like, not a hardcoded cleartext destination.
        if inner.trim_end_matches('/') == "http:" || inner == "http://" {
            continue;
        }
        // Likewise when the literal is being compared rather than dialled.
        if is_comparison_operand(ctx, *lit) {
            continue;
        }
        // RDF/XML namespace URIs are identifiers, not fetch targets: they are
        // defined to be compared verbatim, and "fixing" one to https breaks
        // interoperability.
        if is_namespace_uri(inner) {
            continue;
        }
        out.push(ctx.finding(
            meta,
            *lit,
            format!("Cleartext HTTP URL `{}`; prefer HTTPS.", inner.chars().take(80).collect::<String>()),
            Confidence::Medium,
            None,
        ));
    }
    out
}

//! Coarse trust-boundary classification for the data reaching a sink.
//!
//! The taint engine answers "is this attacker-controlled?" but only for HTTP
//! request sources it recognises. Everything else comes back untainted, which
//! is not the same as *safe* — it may be a local file, a plugin descriptor, a
//! theme template, or a compile-time constant. Rules that flag genuinely
//! dangerous APIs (native deserialization, SpEL, reflection) need to tell
//! those apart so they can rank a self-serialized on-disk round trip below a
//! socket read.
//!
//! This is a textual/structural heuristic over the enclosing method, not a
//! dataflow analysis. It is only ever used to *lower* severity, so a
//! misclassification toward `Unknown` costs nothing.

use crate::findings::TrustSource;
use crate::parser::{enclosing_method, is_constant_expr};
use crate::rules::RuleCtx;
use tree_sitter::Node;

/// Markers that identify where a value came from, most specific first.
const LOCAL_FS_MARKERS: &[&str] = &[
    "FileInputStream",
    "FileReader",
    "RandomAccessFile",
    "FileChannel",
    "Files.newInputStream",
    "Files.newBufferedReader",
    "Files.readAllBytes",
    "Files.readString",
    "Files.newDirectoryStream",
    "Paths.get",
    "Path.of",
    "FSDirectory",
    "IndexInput",
    "DirectoryReader",
    "FileSystemResource",
    "ClassPathResource",
    "getResourceAsStream",
];

const PLUGIN_MARKERS: &[&str] = &[
    "PluginWrapper",
    "PluginManager",
    "PluginDescriptor",
    "PluginClassLoader",
    "pluginId",
    "getPluginId",
    "ExtensionPoint",
];

const THEME_MARKERS: &[&str] = &[
    "ITemplateContext",
    "IExpressionContext",
    "ITemplateEvent",
    "IProcessableElementTag",
    "AttributeName",
    "TemplateMode",
    "ThemeContext",
    "getTheme",
];

const CONFIG_MARKERS: &[&str] = &[
    "Environment",
    "getProperty",
    "ConfigurableEnvironment",
    "ApplicationProperties",
    "@Value",
    "System.getenv",
    "System.getProperty",
];

/// Path segments that make a whole file plugin- or theme-scoped.
const PLUGIN_PATH_HINTS: &[&str] = &["/plugin/", "/plugins/", "/pf4j/"];
const THEME_PATH_HINTS: &[&str] = &["/theme/", "/themes/", "/dialect/", "/thymeleaf/"];

/// Classify the origin of `expr`, the value flowing into a dangerous sink.
pub fn classify(ctx: &RuleCtx, expr: Node) -> TrustSource {
    if ctx.taint.expr_tainted(expr) {
        return TrustSource::Network;
    }
    if is_constant_expr(ctx.file, expr) {
        return TrustSource::Constant;
    }

    let scope = origin_text(ctx, expr);

    // Order matters: a plugin/theme marker is more specific than the generic
    // filesystem reads those subsystems also perform.
    if contains_any(&scope, PLUGIN_MARKERS) {
        return TrustSource::Plugin;
    }
    if contains_any(&scope, THEME_MARKERS) {
        return TrustSource::Theme;
    }
    if contains_any(&scope, LOCAL_FS_MARKERS) {
        return TrustSource::LocalFs;
    }
    if contains_any(&scope, CONFIG_MARKERS) {
        return TrustSource::Config;
    }

    // Fall back to the file's location in the tree.
    let path = ctx.file.path.replace('\\', "/").to_lowercase();
    if PLUGIN_PATH_HINTS.iter().any(|h| path.contains(h)) {
        return TrustSource::Plugin;
    }
    if THEME_PATH_HINTS.iter().any(|h| path.contains(h)) {
        return TrustSource::Theme;
    }

    TrustSource::Unknown
}

/// The text we search for origin markers: the expression itself, the receiver
/// chain it hangs off, and the enclosing method (which is where the stream or
/// reader it reads from was opened).
fn origin_text(ctx: &RuleCtx, expr: Node) -> String {
    let mut text = String::new();
    text.push_str(ctx.file.text(expr));
    text.push('\n');
    if let Some(parent) = expr.parent() {
        text.push_str(ctx.file.text(parent));
        text.push('\n');
    }
    if let Some(method) = enclosing_method(expr) {
        text.push_str(ctx.file.text(method));
    }
    text
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// True when the bytes read here were written by an `ObjectOutputStream` in
/// the same file — a self-serialized round trip rather than an untrusted feed.
///
/// This is the pattern behind caches and on-disk indexes: the process writes
/// its own objects and reads them back, so the only way to poison the stream
/// is to already have write access to the file.
pub fn is_self_serialized_roundtrip(ctx: &RuleCtx) -> bool {
    let writes = ctx.index.method_invocations.iter().any(|call| {
        matches!(
            crate::parser::call_name(ctx.file, *call),
            "writeObject" | "writeUnshared"
        )
    });
    let constructs_output = ctx.index.object_creations.iter().any(|c| {
        crate::parser::creation_type(ctx.file, *c).contains("ObjectOutputStream")
    });
    writes && constructs_output
}

/// True when the SpEL expression at this call is evaluated against a
/// `SimpleEvaluationContext`, which forbids the `T(...)` type references and
/// constructor invocations SpEL RCE depends on.
///
/// Resolved by looking for the context type actually constructed in the same
/// class. `StandardEvaluationContext` anywhere in the file wins, because we
/// cannot tell which context a given expression is handed to.
pub fn spel_context(ctx: &RuleCtx) -> SpelContext {
    let mut simple = false;
    let mut standard = false;

    for c in &ctx.index.object_creations {
        match crate::parser::creation_type(ctx.file, *c) {
            t if t.contains("SimpleEvaluationContext") => simple = true,
            t if t.contains("StandardEvaluationContext") => standard = true,
            _ => {}
        }
    }
    // SimpleEvaluationContext is normally obtained from a static factory
    // (`forReadOnlyDataBinding()`), not `new`.
    for call in &ctx.index.method_invocations {
        let recv = crate::parser::receiver_text(ctx.file, *call);
        if recv.ends_with("SimpleEvaluationContext") {
            simple = true;
        } else if recv.ends_with("StandardEvaluationContext") {
            standard = true;
        }
    }
    // Builder chains: SimpleEvaluationContext.forReadOnlyDataBinding().build()
    if ctx.file.source.contains("SimpleEvaluationContext") {
        simple = true;
    }
    if ctx.file.source.contains("StandardEvaluationContext") {
        standard = true;
    }

    match (simple, standard) {
        (true, false) => SpelContext::Simple,
        (_, true) => SpelContext::Standard,
        (false, false) => SpelContext::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpelContext {
    /// Only `SimpleEvaluationContext` is used — RCE primitives unavailable.
    Simple,
    /// A `StandardEvaluationContext` is present — full SpEL is reachable.
    Standard,
    /// No context construction visible in this file.
    Unknown,
}

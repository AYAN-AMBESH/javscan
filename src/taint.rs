//! Intraprocedural taint analysis.
//!
//! Sources: servlet request accessors, Spring MVC annotated parameters,
//! servlet handler parameters, `main(String[] args)`, console/stdin reads.
//! Taint propagates through assignments, string concatenation,
//! StringBuilder/StringBuffer, and common String transformations, and is
//! killed by known sanitizers (OWASP encoder, Apache commons-text escapes,
//! URLEncoder, numeric parsing, UUID parsing, FilenameUtils.getName).

use crate::parser::{enclosing_method, ParsedFile};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

const SOURCE_CALLS: &[&str] = &[
    "getParameter",
    "getParameterValues",
    "getParameterMap",
    "getParameterNames",
    "getHeader",
    "getHeaders",
    "getQueryString",
    "getCookies",
    "getRequestURI",
    "getRequestURL",
    "getPathInfo",
    "getPathTranslated",
    "getRemoteUser",
    "getReader",
    "getPart",
    "getParts",
    "readLine",
    "nextLine",
];

const PARAM_SOURCE_ANNOTATIONS: &[&str] = &[
    "RequestParam",
    "PathVariable",
    "RequestBody",
    "RequestHeader",
    "CookieValue",
    "ModelAttribute",
    "MatrixVariable",
];

const HANDLER_ANNOTATIONS: &[&str] = &[
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
];

/// Methods that pass taint from receiver to return value.
const PROPAGATING_METHODS: &[&str] = &[
    "substring", "trim", "strip", "stripLeading", "stripTrailing", "toLowerCase",
    "toUpperCase", "concat", "replace", "replaceAll", "replaceFirst", "split",
    "toString", "append", "insert", "getBytes", "toCharArray", "intern", "repeat",
    "formatted", "lines", "chars", "next", "get", "orElse", "orElseGet", "text",
    "asText", "getValue", "getName", "getString",
];

/// (receiver, method) pairs that kill taint.
const SANITIZERS: &[(&str, &str)] = &[
    ("", "escapeHtml4"),
    ("", "escapeHtml3"),
    ("", "escapeHtml"),
    ("", "escapeEcmaScript"),
    ("", "escapeJavaScript"),
    ("", "escapeXml"),
    ("", "escapeXml10"),
    ("", "escapeXml11"),
    ("", "escapeJson"),
    ("", "escapeJava"),
    ("Encode", "forHtml"),
    ("Encode", "forHtmlContent"),
    ("Encode", "forHtmlAttribute"),
    ("Encode", "forJavaScript"),
    ("Encode", "forUriComponent"),
    ("Encode", "forCssString"),
    ("", "encodeForHTML"),
    ("", "encodeForHTMLAttribute"),
    ("", "encodeForJavaScript"),
    ("", "encodeForSQL"),
    ("", "encodeForLDAP"),
    ("", "encodeForOS"),
    ("URLEncoder", "encode"),
    ("Integer", "parseInt"),
    ("Integer", "parseUnsignedInt"),
    ("Integer", "valueOf"),
    ("Long", "parseLong"),
    ("Long", "valueOf"),
    ("Short", "parseShort"),
    ("Double", "parseDouble"),
    ("Float", "parseFloat"),
    ("Boolean", "parseBoolean"),
    ("UUID", "fromString"),
    ("FilenameUtils", "getName"),
    ("Pattern", "quote"),
    ("Matcher", "quoteReplacement"),
];

fn is_sanitizer(receiver: &str, name: &str) -> bool {
    let recv_last = receiver.rsplit('.').next().unwrap_or(receiver);
    SANITIZERS.iter().any(|(r, m)| {
        *m == name && (r.is_empty() || *r == recv_last)
    })
}

pub struct TaintEngine<'f> {
    file: &'f ParsedFile,
    /// method node id -> set of tainted variable names in that method
    cache: RefCell<HashMap<usize, HashSet<String>>>,
}

impl<'f> TaintEngine<'f> {
    pub fn new(file: &'f ParsedFile) -> TaintEngine<'f> {
        TaintEngine {
            file,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Is the given expression node tainted by user-controlled input?
    pub fn expr_tainted(&self, node: Node) -> bool {
        let Some(method) = enclosing_method(node) else {
            return false;
        };
        let set = self.method_taint_set(method);
        self.eval(node, &set)
    }

    fn method_taint_set(&self, method: Node) -> HashSet<String> {
        if let Some(cached) = self.cache.borrow().get(&method.id()) {
            return cached.clone();
        }
        let mut set = self.initial_params(method);
        // Fixpoint over declarations, assignments and builder appends.
        for _ in 0..10 {
            let before = set.len();
            self.propagate_pass(method, &mut set);
            if set.len() == before {
                break;
            }
        }
        for v in self.regex_validated(method) {
            set.remove(&v);
        }
        self.cache.borrow_mut().insert(method.id(), set.clone());
        set
    }

    /// Variables checked against a whole-string regex inside this method:
    /// `pattern.matcher(cb).matches()` or `cb.matches("[a-zA-Z0-9_]+")`.
    ///
    /// `matches()` anchors at both ends, so a developer who writes it has
    /// declared the accepted alphabet — the same evidence a human reviewer
    /// accepts when deciding a reflected value is safe. `find()` and
    /// `lookingAt()` are deliberately excluded: they match a substring and
    /// validate nothing.
    fn regex_validated(&self, method: Node) -> Vec<String> {
        let file = self.file;
        let mut out = Vec::new();
        let mut stack = vec![method];
        while let Some(n) = stack.pop() {
            if n.kind() == "method_invocation"
                && n.child_by_field_name("name").map(|x| file.text(x)) == Some("matches")
            {
                // `<pattern>.matcher(v).matches()`
                if let Some(inner) = n.child_by_field_name("object") {
                    if inner.kind() == "method_invocation"
                        && inner.child_by_field_name("name").map(|x| file.text(x)) == Some("matcher")
                    {
                        for a in crate::parser::call_args(inner) {
                            if a.kind() == "identifier" {
                                out.push(file.text(a).to_string());
                            }
                        }
                    } else if inner.kind() == "identifier" {
                        // `v.matches("regex")` — only a literal pattern counts.
                        let literal_pattern = crate::parser::call_args(n)
                            .first()
                            .map(|a| a.kind() == "string_literal")
                            .unwrap_or(false);
                        if literal_pattern {
                            out.push(file.text(inner).to_string());
                        }
                    }
                }
            }
            for i in (0..n.child_count()).rev() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        out
    }

    fn initial_params(&self, method: Node) -> HashSet<String> {
        let file = self.file;
        let mut set = HashSet::new();
        let method_name = method
            .child_by_field_name("name")
            .map(|n| file.text(n))
            .unwrap_or("");
        let method_annotations = self.node_annotations(method);
        let is_handler = method_annotations
            .iter()
            .any(|a| HANDLER_ANNOTATIONS.contains(&a.as_str()));
        let is_main = method_name == "main";

        let Some(params) = method.child_by_field_name("parameters") else {
            return set;
        };
        let mut cursor = params.walk();
        for p in params.named_children(&mut cursor) {
            if p.kind() != "formal_parameter" && p.kind() != "spread_parameter" {
                continue;
            }
            let Some(name_node) = p.child_by_field_name("name") else {
                continue;
            };
            let pname = file.text(name_node).to_string();
            let ptype = p
                .child_by_field_name("type")
                .map(|t| file.text(t))
                .unwrap_or("");
            let annotations = self.node_annotations(p);
            let annotated_source = annotations
                .iter()
                .any(|a| PARAM_SOURCE_ANNOTATIONS.contains(&a.as_str()));
            let request_typed = ptype.contains("HttpServletRequest");
            // No separate servlet-entry clause: an HttpServletRequest
            // parameter is a source wherever it appears, doGet/doPost included,
            // which `request_typed` already covers.
            if annotated_source
                || request_typed
                || (is_handler && !ptype.contains("HttpServletResponse") && !ptype.contains("Model"))
                || (is_main && ptype.contains("String"))
            {
                set.insert(pname);
            }
        }
        set
    }

    /// Simple names of annotations attached to a node's modifiers.
    fn node_annotations(&self, node: Node) -> Vec<String> {
        let file = self.file;
        let mut out = Vec::new();
        for i in 0..node.child_count() {
            let Some(c) = node.child(i) else { continue };
            if c.kind() != "modifiers" {
                continue;
            }
            for j in 0..c.child_count() {
                let Some(a) = c.child(j) else { continue };
                if a.kind() == "marker_annotation" || a.kind() == "annotation" {
                    if let Some(name) = a.child_by_field_name("name") {
                        out.push(file.text(name).rsplit('.').next().unwrap_or("").to_string());
                    }
                }
            }
        }
        out
    }

    fn propagate_pass(&self, method: Node, set: &mut HashSet<String>) {
        let file = self.file;
        let mut stack = vec![method];
        let mut newly: Vec<String> = Vec::new();
        while let Some(n) = stack.pop() {
            match n.kind() {
                "variable_declarator" => {
                    if let (Some(name), Some(value)) =
                        (n.child_by_field_name("name"), n.child_by_field_name("value"))
                    {
                        if self.eval(value, set) {
                            newly.push(file.text(name).to_string());
                        }
                    }
                }
                "assignment_expression" => {
                    if let (Some(left), Some(right)) =
                        (n.child_by_field_name("left"), n.child_by_field_name("right"))
                    {
                        if self.eval(right, set) {
                            newly.push(file.text(left).to_string());
                        }
                    }
                }
                "enhanced_for_statement" => {
                    // for (String s : taintedCollection) taints s
                    if let (Some(name), Some(value)) =
                        (n.child_by_field_name("name"), n.child_by_field_name("value"))
                    {
                        if self.eval(value, set) {
                            newly.push(file.text(name).to_string());
                        }
                    }
                }
                "method_invocation" => {
                    // sb.append(tainted) taints sb
                    let name = n
                        .child_by_field_name("name")
                        .map(|x| file.text(x))
                        .unwrap_or("");
                    if matches!(name, "append" | "insert" | "add" | "put" | "write") {
                        if let Some(obj) = n.child_by_field_name("object") {
                            if obj.kind() == "identifier" {
                                let args_tainted = crate::parser::call_args(n)
                                    .iter()
                                    .any(|a| self.eval(*a, set));
                                if args_tainted {
                                    newly.push(file.text(obj).to_string());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            for i in (0..n.child_count()).rev() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        for v in newly {
            set.insert(v);
        }
    }

    fn eval(&self, node: Node, set: &HashSet<String>) -> bool {
        let file = self.file;
        match node.kind() {
            "identifier" => set.contains(file.text(node)),
            "field_access" => {
                let full = file.text(node);
                if set.contains(full) {
                    return true;
                }
                node.child_by_field_name("object")
                    .map(|o| self.eval(o, set))
                    .unwrap_or(false)
            }
            "method_invocation" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| file.text(n))
                    .unwrap_or("");
                let receiver = node.child_by_field_name("object");
                let receiver_text = receiver.map(|r| file.text(r)).unwrap_or("");
                if is_sanitizer(receiver_text, name) {
                    return false;
                }
                if SOURCE_CALLS.contains(&name) {
                    return true;
                }
                let recv_tainted = receiver.map(|r| self.eval(r, set)).unwrap_or(false);
                if recv_tainted && PROPAGATING_METHODS.contains(&name) {
                    return true;
                }
                // String.format / String.join / valueOf / decode etc. and any
                // unknown call: taint flows through arguments (heuristic).
                crate::parser::call_args(node).iter().any(|a| self.eval(*a, set))
            }
            "binary_expression" => {
                let l = node.child_by_field_name("left");
                let r = node.child_by_field_name("right");
                l.map(|n| self.eval(n, set)).unwrap_or(false)
                    || r.map(|n| self.eval(n, set)).unwrap_or(false)
            }
            "ternary_expression" => {
                let cons = node.child_by_field_name("consequence");
                let alt = node.child_by_field_name("alternative");
                cons.map(|n| self.eval(n, set)).unwrap_or(false)
                    || alt.map(|n| self.eval(n, set)).unwrap_or(false)
            }
            "parenthesized_expression" | "cast_expression" | "unary_expression" => node
                .named_child(node.named_child_count().saturating_sub(1))
                .map(|c| self.eval(c, set))
                .unwrap_or(false),
            "object_creation_expression" => crate::parser::call_args(node)
                .iter()
                .any(|a| self.eval(*a, set)),
            "array_access" => node
                .child_by_field_name("array")
                .map(|a| self.eval(a, set))
                .unwrap_or(false),
            "template_expression" => {
                // Java 21 string templates: STR."\{name}"
                let mut cursor = node.walk();
                let children: Vec<Node> = node.named_children(&mut cursor).collect();
                children.iter().any(|c| self.eval(*c, set))
            }
            _ => false,
        }
    }
}
